"""Ассоциации файлов: портатив не меняет их ни при сборке, ни при запуске.

Жалоба, ради которой появился этот модуль:

    Нужно сделать так, чтобы созданный портатив не затрагивал системный
    реестр, а то мне каждый раз приходится переназначать программы для
    расширений файлов.

Ассоциация — настройка КОНКРЕТНОГО компьютера. Импорт ключа расширения
переписывает выбор программы, а ``reg delete`` при выходе оставляет
расширение без обработчика: Windows снова спрашивает «чем открыть?», и
человек заново назначает программы. Поэтому проверяется:

* классификация: ``.pdf``/``FileExts``/``Shell\\Associations`` — ассоциации,
  а кастомный протокол ``figma`` и обычные настройки программы — нет;
* сборщик никогда не кладёт ассоциации в список «удалить после выхода»;
* снимок ассоциаций до сборки и восстановление изменённых значений после;
* лончер вырезает секции ассоциаций из любого ``.reg`` перед импортом и не
  удаляет такие ключи при выходе (и умеет отключиться флагом
  ``registry.keep_host_associations``).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as entry
from portablizer.core import launcher as launcher_mod
from portablizer.core import portablizer as portablizer_mod
from portablizer.core import registry

HKCU = "HKEY_CURRENT_USER"
FILE_EXTS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
CLASSES = r"Software\Classes"


# --- подделка winreg ---------------------------------------------------------

class _Key:
    """Открытый ключ поддельного реестра."""

    def __init__(self, fake: "FakeRegistry", path: str) -> None:
        self.fake = fake
        self.path = path

    def __enter__(self) -> "_Key":
        return self

    def __exit__(self, *_exc) -> bool:
        return False


class FakeRegistry:
    """Мини-реестр: ровно те вызовы, которые делает снимок ассоциаций."""

    HKEY_CURRENT_USER = 1
    HKEY_LOCAL_MACHINE = 2
    KEY_READ = 0x20019
    KEY_WRITE = 0x20006
    KEY_SET_VALUE = 0x0002
    REG_SZ = 1

    def __init__(self) -> None:
        #: путь (нижний регистр) -> {имя значения: (тип, значение)}
        self.keys: dict = {}

    # -- содержимое ---------------------------------------------------------
    def set_values(self, path: str, values: dict) -> None:
        self.keys[path.casefold()] = dict(values)

    def values_of(self, path: str) -> dict:
        return self.keys.get(path.casefold(), {})

    # -- API winreg ---------------------------------------------------------
    def OpenKey(self, _hive, subkey, _reserved=0, _access=0) -> _Key:
        name = subkey.casefold()
        exists = name in self.keys or any(
            stored.startswith(name + "\\") for stored in self.keys)
        if not exists:
            raise FileNotFoundError(subkey)
        return _Key(self, subkey)

    def CreateKeyEx(self, _hive, subkey, _reserved=0, _access=0) -> _Key:
        self.keys.setdefault(subkey.casefold(), {})
        return _Key(self, subkey)

    def CloseKey(self, _key) -> None:
        return None

    def EnumKey(self, key: _Key, index: int) -> str:
        prefix = key.path.casefold() + "\\"
        children = sorted(
            name[len(prefix):].split("\\", 1)[0]
            for name in self.keys
            if name.startswith(prefix)
        )
        children = [name for name in children if name]
        if index >= len(children):
            raise OSError("no more subkeys")
        return children[index]

    def EnumValue(self, key: _Key, index: int):
        values = list(self.values_of(key.path).items())
        if index >= len(values):
            raise OSError("no more values")
        name, (typ, data) = values[index]
        return name, data, typ

    def QueryValueEx(self, key: _Key, name: str):
        values = self.values_of(key.path)
        if name not in values:
            raise FileNotFoundError(name)
        typ, data = values[name]
        return data, typ

    def SetValueEx(self, key: _Key, name, _reserved, typ, data) -> None:
        self.keys.setdefault(key.path.casefold(), {})[name] = (typ, data)


def _association_registry() -> FakeRegistry:
    fake = FakeRegistry()
    fake.set_values(f"{FILE_EXTS}\\.pdf\\UserChoice", {
        "ProgId": (1, "Mozilla.Firefox.pdf"),
        "Hash": (1, "abc123"),
    })
    fake.set_values(f"{CLASSES}\\.pdf", {"": (1, "Mozilla.Firefox.pdf")})
    fake.set_values(f"{FILE_EXTS}\\.txt\\UserChoice", {
        "ProgId": (1, "Notepad++"),
        "Hash": (1, "def456"),
    })
    return fake


class AssociationKeyTests(unittest.TestCase):
    """Какие ключи реестра задают ассоциации файлов."""

    def test_extensions_and_user_choice_are_associations(self):
        for key in (r"HKCU\Software\Classes\.pdf",
                    r"HKLM\Software\Classes\.png\OpenWithProgids",
                    r"HKLM\Software\WOW6432Node\Classes\.zip",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer"
                    r"\FileExts\.txt\UserChoice",
                    r"HKCU\Software\Microsoft\Windows\Shell\Associations"
                    r"\UrlAssociations\https\UserChoice",
                    r"HKCU\Software\RegisteredApplications",
                    r"HKCU\Software\Classes\*\shell\open",
                    r"HKCU\Software\Classes\SystemFileAssociations\.txt"):
            self.assertTrue(registry.is_file_association_key(key), key)

    def test_app_protocols_and_settings_are_not_associations(self):
        for key in (r"HKLM\Software\Classes\figma",
                    r"HKLM\Software\Classes\figma\shell\open\command",
                    r"HKCU\Software\Vendor\MyApp",
                    r"HKLM\Software\Vendor\MyApp\InstallDir"):
            self.assertFalse(registry.is_file_association_key(key), key)

    def test_associations_stay_shell_integration(self):
        self.assertEqual(registry.categorize(r"HKLM\Software\Classes\.myext"),
                         registry.CATEGORY_INTEGRATION)


class AssociationSnapshotTests(unittest.TestCase):
    """Снимок до сборки и возврат прежних программ после неё."""

    def test_snapshot_remembers_progid_hash_and_class(self):
        fake = _association_registry()
        snapshot = registry.snapshot_file_associations(reg=fake)
        choice = snapshot[r"HKCU\Software\Microsoft\Windows\CurrentVersion"
                          r"\Explorer\FileExts\.pdf\UserChoice"]
        self.assertEqual(choice["ProgId"], (1, repr("Mozilla.Firefox.pdf")))
        self.assertEqual(choice["Hash"], (1, repr("abc123")))
        self.assertEqual(
            snapshot[r"HKCU\Software\Classes\.pdf"][""],
            (1, repr("Mozilla.Firefox.pdf")))

    def test_installer_changes_are_rolled_back(self):
        fake = _association_registry()
        before = registry.snapshot_file_associations(reg=fake)
        # Установщик забрал .pdf себе и переписал класс.
        fake.set_values(f"{FILE_EXTS}\\.pdf\\UserChoice",
                        {"ProgId": (1, "OtherPlayer.pdf"),
                         "Hash": (1, "zzz999")})
        fake.set_values(f"{CLASSES}\\.pdf", {"": (1, "OtherPlayer.pdf")})

        restored = registry.restore_file_associations(before, reg=fake)

        self.assertIn(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer"
                      r"\FileExts\.pdf\UserChoice", restored)
        self.assertEqual(
            fake.values_of(f"{FILE_EXTS}\\.pdf\\UserChoice"),
            {"ProgId": (1, "Mozilla.Firefox.pdf"),
             "Hash": (1, "abc123")})
        self.assertEqual(fake.values_of(f"{CLASSES}\\.pdf"),
                         {"": (1, "Mozilla.Firefox.pdf")})

    def test_untouched_associations_are_not_rewritten(self):
        fake = _association_registry()
        before = registry.snapshot_file_associations(reg=fake)
        with mock.patch.object(fake, "SetValueEx") as setter:
            restored = registry.restore_file_associations(before, reg=fake)
        self.assertEqual(restored, [])
        setter.assert_not_called()

    def test_deleted_choice_is_recreated(self):
        fake = _association_registry()
        before = registry.snapshot_file_associations(reg=fake)
        fake.keys.pop(f"{FILE_EXTS}\\.txt\\UserChoice".casefold())
        restored = registry.restore_file_associations(before, reg=fake)
        self.assertTrue(restored)
        self.assertEqual(fake.values_of(f"{FILE_EXTS}\\.txt\\UserChoice"),
                         {"ProgId": (1, "Notepad++"),
                          "Hash": (1, "def456")})

    def test_outside_windows_nothing_is_read_or_written(self):
        """Без Windows реестра нет: снимок пуст, восстанавливать нечего.

        ``IS_WINDOWS`` подменяется явно: на настоящей Windows этот тест иначе
        снял бы снимок НАСТОЯЩИХ ассоциаций раннера и (во второй части) полез
        бы писать в них — тест не должен трогать живой реестр.
        """
        before = {r"HKCU\Software\Classes\.pdf": {"": (1, repr("x"))}}
        with mock.patch.object(registry, "IS_WINDOWS", False):
            self.assertEqual(registry.snapshot_file_associations(), {})
            self.assertEqual(registry.restore_file_associations(before), [])


class BuilderKeepsAssociationsTests(unittest.TestCase):
    """Сборщик не переносит ассоциации в портатив и не удаляет их с ПК."""

    def _capture(self, **opts):
        engine = portablizer_mod.Portablizer(portablizer_mod.Logger())
        temp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            temp, ignore_errors=True))
        portable = Path(temp, "MyApp_Portable")
        portable.mkdir()
        after = {
            r"HKCU\Software\Vendor\MyApp": {
                "InstallDir": (registry.REG_SZ, repr(str(portable / "App"))),
            },
            r"HKCU\Software\Classes\.myext": {
                "": (registry.REG_SZ, repr("MyApp.File")),
            },
        }
        # IS_WINDOWS=False: сборщик на настоящей Windows сразу импортирует
        # захваченные ключи в реестр раннера, а тест не должен писать в живой
        # реестр — тем более в ассоциации файлов.
        with mock.patch.object(portablizer_mod, "IS_WINDOWS", False):
            capture = engine._capture_registry(
                str(portable), {}, after,
                portablizer_mod.PortableOptions(
                    installer_path="x", output_dir=temp,
                    app_name="My Application", **opts))
        return capture

    def test_association_keys_are_never_deleted_after_exit(self):
        capture = self._capture(include_shell_integration=True)
        self.assertTrue(capture.keys, "захват с интеграцией должен работать")
        self.assertNotIn(r"HKCU\Software\Classes\.myext", capture.created_keys)

    def test_app_settings_still_restore(self):
        capture = self._capture()
        self.assertIn(r"HKCU\Software\Vendor\MyApp", capture.created_keys)


class LauncherAssociationTests(unittest.TestCase):
    """Лончер вырезает ассоциации из .reg и не удаляет их с этого ПК."""

    REG_TEXT = (
        "Windows Registry Editor Version 5.00\n\n"
        "[HKEY_CURRENT_USER\\Software\\Classes\\.pdf]\n"
        "@=\"MyApp.File\"\n\n"
        "[HKEY_CURRENT_USER\\Software\\Vendor\\MyApp]\n"
        "\"Theme\"=\"dark\"\n\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion"
        "\\Explorer\\FileExts\\.pdf\\UserChoice]\n"
        "\"ProgId\"=\"MyApp.File\"\n"
    )

    def test_sanitizer_drops_association_sections(self):
        text, dropped = entry.sanitize_reg_text(self.REG_TEXT)
        self.assertIn(r"Software\Vendor\MyApp", text)
        self.assertNotIn(".pdf", text)
        self.assertEqual(len(dropped), 2, dropped)

    def test_sanitizer_can_keep_associations_on_request(self):
        text, _dropped = entry.sanitize_reg_text(self.REG_TEXT,
                                                 keep_associations=False)
        self.assertIn(".pdf", text)

    def test_rewrite_uses_the_same_rule(self):
        self.assertTrue(entry._reg_section_is_association(
            r"HKCU\Software\Classes\.txt"))
        self.assertTrue(entry._reg_section_is_association(
            r"HKEY_USERS\S-1-5-21\Software\Classes\.txt"))
        self.assertFalse(entry._reg_section_is_association(
            r"HKCU\Software\Classes\figma\shell\open\command"))

    def _session(self, cfg):
        """Сессия лончера во временной папке: журнал не должен пачкать репозиторий."""
        temp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            temp, ignore_errors=True))
        return entry.RegistrySession(Path(temp), cfg)

    def test_session_ignores_association_keys(self):
        session = self._session({
            "registry": {
                "enabled": True,
                "keys": [r"HKCU\Software\Vendor\MyApp",
                         r"HKCU\Software\Classes\.myext"],
                "created_keys": [r"HKCU\Software\Classes\.myext"],
            }
        })
        self.assertEqual(session.keys, [r"HKCU\Software\Vendor\MyApp"])
        self.assertNotIn(r"hkcu\software\classes\.myext", session.created)

    def test_session_can_keep_associations_when_asked(self):
        session = self._session({
            "registry": {
                "enabled": True,
                "keep_host_associations": False,
                "keys": [r"HKCU\Software\Classes\.myext"],
            }
        })
        self.assertEqual(session.keys, [r"HKCU\Software\Classes\.myext"])

    def test_exit_never_deletes_an_association_key(self):
        session = self._session({
            "registry": {
                "enabled": True,
                "keys": [r"HKCU\Software\Classes\.myext"],
                "created_keys": [r"HKCU\Software\Classes\.myext"],
            }
        })
        # Ключ мог попасть в конфиг прежней сборкой: удалять его нельзя.
        session.keys = [r"HKCU\Software\Classes\.myext"]
        session.created = {r"hkcu\software\classes\.myext"}
        session.active = True
        session.started = True
        with mock.patch.object(entry, "export_registry_text", return_value=""), \
                mock.patch.object(entry, "import_registry_file",
                                  return_value=True), \
                mock.patch.object(entry, "delete_key_tree") as deleter, \
                mock.patch.object(entry, "_reg", return_value=0):
            session.save_and_restore()
        deleter.assert_not_called()


class LauncherConfigAssociationTests(unittest.TestCase):
    """Флаг виден в launcher_config.json и работает в Launch.bat."""

    def test_config_json_defaults_to_keeping_associations(self):
        cfg = launcher_mod.LauncherConfig(app_name="App",
                                          target_exe_rel="App/a.exe")
        data = __import__("json").loads(launcher_mod.render_config_json(cfg))
        self.assertTrue(data["registry"]["keep_host_associations"])

    def test_bat_keeps_association_keys_out_of_the_import(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="App", target_exe_rel="App/a.exe",
            registry_keys=[r"HKCU\Software\Vendor\MyApp",
                           r"HKCU\Software\Classes\.myext"],
            registry_created_keys=[r"HKCU\Software\Classes\.myext"])
        block = launcher_mod._registry_load_block(cfg)
        self.assertIn(r"Software\Vendor\MyApp", block)
        self.assertNotIn(".myext", block)

    def test_bat_can_keep_associations_when_asked(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="App", target_exe_rel="App/a.exe",
            keep_host_associations=False,
            registry_keys=[r"HKCU\Software\Classes\.myext"])
        block = launcher_mod._registry_load_block(cfg)
        self.assertIn(".myext", block)


if __name__ == "__main__":
    unittest.main()
