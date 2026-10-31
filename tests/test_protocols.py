"""URL-протоколы приложения: перенос и перенаправление в портатив.

Жалоба, ради которой появился этот файл: портатив Figma запускается, вход в
аккаунт проходит в браузере, но «Открыть Figma» открывает УСТАНОВЛЕННОЕ
приложение (``C:\\Users\\masortim\\AppData\\Local\\Figma\\app-126.10.11\\Figma.exe``),
а не портатив. Причина — браузер передаёт ``figma://`` через протокол, который
Windows разрешает через ``Software\Classes``, а переносимый реестр его не
ловил: протоколы жили в категории «интеграция» и попадали в портатив только
со ``--shell-integration``.

Проверяется:

* протокол находится в diff (по значению ``URL Protocol`` и по
  дочернему ``shell\open\command``);
* файловые ассоциации и COM-классы не путаются с протоколами;
* измененные потомки протокола (команда открытия) попадают в набор ключей;
* команда открытия переписывается на каталог ``App`` портатива;
* ``_capture_registry`` переносит протоколы ВСЕГДА (не только с
  ``--shell-integration``);
* команда в ``portable.reg`` носит маркер ``@@PORTABLE_ROOT@@`` (работает с
  любой буквой диска).
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from portablizer.core import registry as reg_mod
from portablizer.core import launcher as launcher_mod
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer

#: Команда открытия, как ставит установщик Figma (Electron).
FIGMA_COMMAND = (
    r'"C:\Users\me\AppData\Local\Figma\app-126.10.11\Figma.exe" '
    r'--open "%1"'
)

#: Команда открытия без кавычек: первый токен должен явно заканчиваться
#: на .exe, иначе путь «C:\Program Files\...» разорвался бы на слове.
UNQUOTED_COMMAND = r'C:\Program Files\Figma\Figma.exe --open "%1"'


def _figma_snapshot() -> dict:
    """Снимок реестра с регистрацией figma:// (как делает Electron)."""
    return {
        r"HKCU\Software\Classes\figma": {
            "": (reg_mod.REG_SZ, repr("figma Protocol")),
            "URL Protocol": (reg_mod.REG_SZ, repr("")),
        },
        r"HKCU\Software\Classes\figma\shell\open\command": {
            "": (reg_mod.REG_SZ, repr(FIGMA_COMMAND)),
        },
    }


class ProtocolDetectionTests(unittest.TestCase):
    def test_protocol_with_url_protocol_marker_is_detected(self):
        after = {r"HKCU\Software\Classes\figma": {
            "URL Protocol": (reg_mod.REG_SZ, repr("")),
        }}
        diff = reg_mod.compute_diff({}, after)
        self.assertEqual(
            reg_mod.protocol_keys_of(diff, after),
            [r"HKCU\Software\Classes\figma"])

    def test_protocol_with_only_open_command_is_detected(self):
        # Некоторые регистрации протокола пропускают значение
        # URL Protocol — остаётся только shell\open\command.
        after = {
            r"HKCU\Software\Classes\discord": {
                "": (reg_mod.REG_SZ, repr("Discord Protocol")),
            },
            r"HKCU\Software\Classes\discord\shell\open\command": {
                "": (reg_mod.REG_SZ, repr(r'"C:\Program Files\Discord\Discord.exe"')),
            },
        }
        diff = reg_mod.compute_diff({}, after)
        protos = reg_mod.protocol_keys_of(diff, after)
        self.assertIn(r"HKCU\Software\Classes\discord", protos)
        # Сам ключ схемы — без значений — не попадает сам по себе.
        self.assertIn(
            r"HKCU\Software\Classes\discord\shell\open\command", protos)

    def test_file_extensions_and_com_classes_are_not_protocols(self):
        after = {
            r"HKCU\Software\Classes\.fig": {
                "": (reg_mod.REG_SZ, repr("Figma.Figure")),
            },
            r"HKCU\Software\Classes\CLSID": {
                "": (reg_mod.REG_SZ, repr("Figma")),
            },
            r"HKCU\Software\Classes\Word.Document.12": {
                "": (reg_mod.REG_SZ, repr("Word.Document.12")),
            },
            r"HKLM\Software\Classes\VirtualStore\MACHINE\SOFTWARE\Figma": {
                "": (reg_mod.REG_SZ, repr("virtualstore")),
            },
        }
        diff = reg_mod.compute_diff({}, after)
        self.assertEqual(reg_mod.protocol_keys_of(diff, after), [])

    def test_protocol_scheme_children_are_included(self):
        after = _figma_snapshot()
        diff = reg_mod.compute_diff({}, after)
        protos = reg_mod.protocol_keys_of(diff, after)
        self.assertEqual(protos, [
            r"HKCU\Software\Classes\figma",
            r"HKCU\Software\Classes\figma\shell\open\command",
        ])

    def test_protocol_registered_under_hklm_is_detected(self):
        after = {r"HKLM\Software\Classes\figma": {
            "URL Protocol": (reg_mod.REG_SZ, repr("")),
        }}
        diff = reg_mod.compute_diff({}, after)
        self.assertEqual(
            reg_mod.protocol_keys_of(diff, after),
            [r"HKLM\Software\Classes\figma"])

    def test_external_web_and_browser_handlers_are_not_app_protocols(self):
        handlers = (
            "http", "https", "ChromeHTML", "MSEdgeHTM",
            "FirefoxURL-308046B0AF4A39CB", "BraveHTML", "OperaGXStable",
        )
        for handler in handlers:
            with self.subTest(handler=handler):
                after = {
                    rf"HKCU\Software\Classes\{handler}": {
                        "URL Protocol": (reg_mod.REG_SZ, repr("")),
                    },
                    rf"HKCU\Software\Classes\{handler}\shell\open\command": {
                        "": (reg_mod.REG_SZ,
                             repr(r'"C:\Browser\browser.exe" "%1"')),
                    },
                }
                diff = reg_mod.compute_diff({}, after)
                self.assertTrue(reg_mod.is_external_browser_key(
                    rf"HKCU\Software\Classes\{handler}\shell\open\command"))
                self.assertEqual(reg_mod.protocol_keys_of(diff, after), [])

    def test_external_browser_filter_does_not_hide_custom_deep_link(self):
        after = _figma_snapshot()
        after.update({
            r"HKCU\Software\Classes\https": {
                "URL Protocol": (reg_mod.REG_SZ, repr("")),
            },
            r"HKCU\Software\Classes\https\shell\open\command": {
                "": (reg_mod.REG_SZ, repr(r'"C:\Browser\browser.exe" "%1"')),
            },
        })
        diff = reg_mod.compute_diff({}, after)
        self.assertEqual(reg_mod.protocol_keys_of(diff, after), [
            r"HKCU\Software\Classes\figma",
            r"HKCU\Software\Classes\figma\shell\open\command",
        ])


class ProtocolRetargetTests(unittest.TestCase):
    def test_default_icon_path_is_retargeted(self):
        # DefaultIcon указывает не version-дир, а родительский каталог
        # (C:\Users\me\AppData\Local\Figma\Figma.exe,0): его корень тоже
        # должен переписаться на App.
        after = {
            r"HKCU\Software\Classes\figma": {"URL Protocol": (reg_mod.REG_SZ, repr(""))},
            r"HKCU\Software\Classes\figma\DefaultIcon": {
                "": (reg_mod.REG_SZ,
                     repr('"C:\\Users\\me\\AppData\\Local\\Figma\\Figma.exe",0')),
            },
            r"HKCU\Software\Classes\figma\shell\open\command": {
                "": (reg_mod.REG_SZ, repr(FIGMA_COMMAND)),
            },
        }
        protos = [r"HKCU\Software\Classes\figma",
                  r"HKCU\Software\Classes\figma\shell\open\command"]
        out = reg_mod.retarget_protocol_paths(
            after, protos, r"C:\Portable\Figma_Portable\App")
        icon = reg_mod._entry_value(
            out[r"HKCU\Software\Classes\figma\DefaultIcon"][""])
        self.assertIn(r"C:\Portable\Figma_Portable\App\Figma.exe", icon)
        self.assertNotIn(r"C:\Users\me\AppData\Local\Figma", icon)

    def test_command_is_retargeted_to_the_app_dir(self):
        after = _figma_snapshot()
        protos = [
            r"HKCU\Software\Classes\figma",
            r"HKCU\Software\Classes\figma\shell\open\command",
        ]
        out = reg_mod.retarget_protocol_paths(
            after, protos, r"C:\Portable\Figma_Portable\App")
        command = reg_mod._entry_value(
            out[r"HKCU\Software\Classes\figma\shell\open\command"][""])
        self.assertIn(r"C:\Portable\Figma_Portable\App\Figma.exe", command)
        # Аргументы не трогаются: браузер ждёт --open и URL.
        self.assertIn("--open", command)
        self.assertIn('"%1"', command)

    def test_retarget_never_rewrites_external_browser_command(self):
        after = _figma_snapshot()
        browser_key = r"HKCU\Software\Classes\https\shell\open\command"
        browser_command = r'"C:\Users\me\AppData\Local\Browser\browser.exe" "%1"'
        after[browser_key] = {"": (reg_mod.REG_SZ, repr(browser_command))}
        out = reg_mod.retarget_protocol_paths(
            after, [browser_key, r"HKCU\Software\Classes\figma"],
            r"C:\Portable\Figma_Portable\App")
        self.assertEqual(
            reg_mod._entry_value(out[browser_key][""]), browser_command)
        self.assertIn(
            r"C:\Portable\Figma_Portable\App\Figma.exe",
            reg_mod._entry_value(out[
                r"HKCU\Software\Classes\figma\shell\open\command"][""]))

    def test_old_install_root_does_not_survive(self):
        after = _figma_snapshot()
        protos = [
            r"HKCU\Software\Classes\figma",
            r"HKCU\Software\Classes\figma\shell\open\command",
        ]
        out = reg_mod.retarget_protocol_paths(
            after, protos, r"C:\Portable\Figma_Portable\App")
        text = "".join(
            str(v) for values in out.values() for v in values.values())
        self.assertNotIn(r"C:\Users\me\AppData\Local\Figma", text)

    def test_unquoted_path_with_spaces_is_left_alone(self):
        # Без кавычек путь с пробелами не разобрать: лучше ничего не менять,
        # чем написать неверный путь.
        after = {
            r"HKCU\Software\Classes\figma": {"URL Protocol": (reg_mod.REG_SZ, repr(""))},
            r"HKCU\Software\Classes\figma\shell\open\command": {
                "": (reg_mod.REG_SZ, repr(UNQUOTED_COMMAND)),
            },
        }
        protos = [r"HKCU\Software\Classes\figma",
                  r"HKCU\Software\Classes\figma\shell\open\command"]
        out = reg_mod.retarget_protocol_paths(after, protos, r"C:\Portable\App")
        command = reg_mod._entry_value(
            out[r"HKCU\Software\Classes\figma\shell\open\command"][""])
        self.assertEqual(command, UNQUOTED_COMMAND)

    def test_unquoted_path_without_spaces_is_retargeted(self):
        # Без кавычек, но без пробелов в пути — путь токенизируем: первый
        # токен — exe. Аргумент в кавычках («"%1"») не проваливается в
        # выбор кандидата.
        after = {
            r"HKCU\Software\Classes\figma": {"URL Protocol": (reg_mod.REG_SZ, repr(""))},
            r"HKCU\Software\Classes\figma\shell\open\command": {
                "": (reg_mod.REG_SZ,
                     repr(r'C:\Users\me\Figma\Figma.exe --open "%1"')),
            },
        }
        protos = [r"HKCU\Software\Classes\figma",
                  r"HKCU\Software\Classes\figma\shell\open\command"]
        out = reg_mod.retarget_protocol_paths(after, protos, r"C:\Portable\App")
        command = reg_mod._entry_value(
            out[r"HKCU\Software\Classes\figma\shell\open\command"][""])
        # Пути без пробелов — команда остаётся без кавычек.
        self.assertEqual(
            command, r'C:\Portable\App\Figma.exe --open "%1"')

    def test_unquoted_command_with_spaces_in_root_is_quoted(self):
        # Корень портативной папки с пробелами: команда без кавычек
        # разобьётся на слове, поэтому путь в ней закавычиваем.
        after = {
            r"HKCU\Software\Classes\figma": {"URL Protocol": (reg_mod.REG_SZ, repr(""))},
            r"HKCU\Software\Classes\figma\shell\open\command": {
                "": (reg_mod.REG_SZ,
                     repr(r'C:\Users\me\Figma\Figma.exe --open "%1"')),
            },
        }
        protos = [r"HKCU\Software\Classes\figma",
                  r"HKCU\Software\Classes\figma\shell\open\command"]
        out = reg_mod.retarget_protocol_paths(
            after, protos, r"C:\My Portable\App")
        command = reg_mod._entry_value(
            out[r"HKCU\Software\Classes\figma\shell\open\command"][""])
        self.assertEqual(
            command, r'"C:\My Portable\App\Figma.exe" --open "%1"')

    def test_quoted_args_before_exe_are_handled(self):
        # Аргументы стоят перед командой: первый quoted-фрагмент — %1, а
        # exe — второй. Поиск по «первый фрагмент, заканчивающийся на .exe»
        # должен взять именно его.
        after = {
            r"HKCU\Software\Classes\figma": {"URL Protocol": (reg_mod.REG_SZ, repr(""))},
            r"HKCU\Software\Classes\figma\shell\open\command": {
                "": (reg_mod.REG_SZ,
                     repr(r'C:\Users\me\Figma\Figma.exe --open "%1" --origin=%1')),
            },
        }
        protos = [r"HKCU\Software\Classes\figma",
                  r"HKCU\Software\Classes\figma\shell\open\command"]
        out = reg_mod.retarget_protocol_paths(after, protos, r"C:\Portable\App")
        command = reg_mod._entry_value(
            out[r"HKCU\Software\Classes\figma\shell\open\command"][""])
        self.assertEqual(
            command,
            r'C:\Portable\App\Figma.exe --open "%1" --origin=%1')

    def test_unrelated_keys_are_not_retargeted(self):
        after = _figma_snapshot()
        after[r"HKCU\Software\Vendor\MyApp"] = {
            "InstallDir": (reg_mod.REG_SZ, repr(r"C:\Program Files\MyApp")),
        }
        protos = [r"HKCU\Software\Classes\figma",
                  r"HKCU\Software\Classes\figma\shell\open\command"]
        out = reg_mod.retarget_protocol_paths(
            after, protos, r"C:\Portable\Figma_Portable\App")
        app_dir = reg_mod._entry_value(out[r"HKCU\Software\Vendor\MyApp"]["InstallDir"])
        self.assertEqual(app_dir, r"C:\Program Files\MyApp")


class ProtocolCaptureTests(unittest.TestCase):
    """_capture_registry: протоколы переносятся ВСЕГДА, без --shell-integration."""

    def setUp(self):
        self.engine = Portablizer(Logger())
        self.temp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.temp, ignore_errors=True))
        self.portable = Path(self.temp, "MyApp_Portable")
        self.portable.mkdir()

    def _capture(self, include_shell_integration=False):
        after = {
            r"HKCU\Software\Vendor\MyApp": {
                "InstallDir": (reg_mod.REG_SZ,
                               repr(str(self.portable / "App"))),
            },
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp": {
                "DisplayName": (reg_mod.REG_SZ, repr("My Application")),
                "InstallLocation": (reg_mod.REG_SZ,
                                    repr(str(self.portable / "App"))),
            },
            r"HKLM\Software\Classes\.myext": {
                "": (reg_mod.REG_SZ, repr("MyApp.File")),
            },
            r"HKCU\Software\Classes\figma": {
                "": (reg_mod.REG_SZ, repr("figma Protocol")),
                "URL Protocol": (reg_mod.REG_SZ, repr("")),
            },
            r"HKCU\Software\Classes\figma\shell\open\command": {
                "": (reg_mod.REG_SZ, repr(FIGMA_COMMAND)),
            },
            # Изменение браузера по умолчанию во время сборки не является
            # регистрацией deep link самого приложения.
            r"HKCU\Software\Classes\http": {
                "URL Protocol": (reg_mod.REG_SZ, repr("")),
            },
            r"HKCU\Software\Classes\http\shell\open\command": {
                "": (reg_mod.REG_SZ, repr(r'"C:\Browser\browser.exe" "%1"')),
            },
            r"HKCU\Software\Classes\ChromeHTML\shell\open\command": {
                "": (reg_mod.REG_SZ, repr(r'"C:\Browser\browser.exe" "%1"')),
            },
        }
        opts = PortableOptions(
            installer_path="x", output_dir=self.temp,
            app_name="My Application",
            include_shell_integration=include_shell_integration)
        capture = self.engine._capture_registry(
            str(self.portable), {}, after, opts)
        files = {p.name: p.read_text(encoding="utf-16")
                 for p in self.portable.glob("*.reg")}
        return capture, files

    def test_protocols_are_captured_by_default(self):
        capture, files = self._capture()
        self.assertIn(r"HKCU\Software\Classes\figma", capture.keys)
        # Лончер получает только родительский ключ: дочерний
        # shell\open\command покрывается рекурсивным экспортом. Это важно
        # ещё и для sync_external_changes: у него нет шанса «впитать»
        # команду установленного приложения из реестра хоста.
        self.assertNotIn(
            r"HKCU\Software\Classes\figma\shell\open\command",
            capture.keys)
        self.assertIn("portable.reg", files)
        text = files["portable.reg"]
        # Команда открытия лежит в portable.reg с маркером портатива.
        self.assertIn("shell\\open\\command", text)
        self.assertIn("@@PORTABLE_ROOT@@", text)
        self.assertIn("Figma.exe", text)
        self.assertIn("%1", text)
        # Путь установщика этого ПК не остаётся.
        self.assertNotIn(r"C:\Users\me\AppData\Local\Figma", text)

    def test_protocols_are_not_counted_as_skipped_integration(self):
        # Путём проверки: протокол лежит в portable.reg, а файловая
        # ассоциация (.myext) — только со --shell-integration.
        capture, files = self._capture()
        text = files["portable.reg"]
        self.assertIn(r"HKEY_CURRENT_USER\Software\Classes\figma", text)
        self.assertNotIn(".myext", text)
        self.assertNotIn(r"HKLM\Software\Classes\.myext", capture.keys)

    def test_protocols_captured_with_shell_integration_too(self):
        capture, files = self._capture(include_shell_integration=True)
        self.assertIn(r"HKCU\Software\Classes\figma", capture.keys)
        self.assertIn(r"HKLM\Software\Classes\.myext", capture.keys)

    def test_external_browser_handlers_are_never_captured(self):
        capture, files = self._capture(include_shell_integration=True)
        self.assertFalse(any(
            reg_mod.is_external_browser_key(key) for key in capture.keys))
        text = files["portable.reg"]
        self.assertNotIn(r"Software\Classes\http", text)
        self.assertNotIn("ChromeHTML", text)
        self.assertNotIn("browser.exe", text)
        # Пользовательский deep link приложения по-прежнему переносится.
        self.assertIn(r"Software\Classes\figma", text)
        self.assertIn("Figma.exe", text)

    def test_protocol_without_installer_registration_is_not_invented(self):
        # Установщик не регистрировал протокол — nothing to capture.
        after = {
            r"HKCU\Software\Vendor\MyApp": {
                "InstallDir": (reg_mod.REG_SZ,
                               repr(str(self.portable / "App"))),
            },
        }
        opts = PortableOptions(installer_path="x", output_dir=self.temp,
                               app_name="My Application")
        capture = self.engine._capture_registry(
            str(self.portable), {}, after, opts)
        self.assertNotIn(r"HKCU\Software\Classes\figma", capture.keys)


class ProtocolLauncherConfigTests(unittest.TestCase):
    def test_registry_keys_are_consolidated_for_the_launcher(self):
        # Лончер экспортирует родительский ключ рекурсивно: дочерний
        # shell\open\command не должен быть отдельной записью.
        keys = launcher_mod.consolidate_root_keys([
            r"HKCU\Software\Classes\figma",
            r"HKCU\Software\Classes\figma\shell\open\command",
        ])
        self.assertEqual(keys, [r"HKCU\Software\Classes\figma"])


if __name__ == "__main__":
    unittest.main()
