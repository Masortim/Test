"""Сохранение системных ассоциаций при сборке и запуске портатива.

Регрессии закрывают три разных источника проблемы:

* сборщик больше не импортирует portable-REG обратно в реестр хоста;
* установщик меняет Classes/FileExts только до точечного возврата снимка;
* created_keys с машины сборки не приводит к удалению существующего ключа на
  компьютере, где запускают готовый портатив.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import batsim
import portable_launcher_entry as entry
from portablizer.core import launcher as launcher_mod
from portablizer.core import portablizer as portablizer_mod
from portablizer.core import registry as reg
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import (
    PortableOptions,
    PortableResult,
    Portablizer,
)

EXT = r"HKCU\Software\Classes\.portablizer-demo"
CHOICE = (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer"
          r"\FileExts\.portablizer-demo\UserChoice")
OLD_COMMAND = (r"HKCU\Software\Classes\Before.ProgID\shell\open\command")
NEW_ROOT = r"HKCU\Software\Classes\After.ProgID"
NEW_COMMAND = NEW_ROOT + r"\shell\open\command"
UNRELATED = r"HKCU\Software\Vendor\Sentinel"
FULL_EXT = "HKEY_CURRENT_USER" + EXT[len("HKCU"):]
FULL_CHOICE = "HKEY_CURRENT_USER" + CHOICE[len("HKCU"):]


def sz(value: str):
    return reg.REG_SZ, repr(value)


def snapshots():
    before = {
        EXT: {"": sz("Before.ProgID"), "Keep": sz("same")},
        CHOICE: {"ProgId": sz("Before.ProgID"), "Hash": sz("old-hash")},
        OLD_COMMAND: {"": sz(r'"C:\Before\before.exe" "%1"')},
        UNRELATED: {"Theme": sz("before")},
    }
    after = {
        EXT: {"": sz("After.ProgID"), "Keep": sz("same"),
              "Added": sz("remove-me")},
        CHOICE: {"ProgId": sz("After.ProgID"), "Hash": sz("new-hash"),
                 "Added": sz("remove-me")},
        NEW_ROOT: {"": sz("After.ProgID")},
        NEW_COMMAND: {"": sz(r'"C:\After\after.exe" "%1"')},
        UNRELATED: {"Theme": sz("after")},
    }
    return before, after


class AssociationRestoreRenderTests(unittest.TestCase):
    def test_file_exts_is_protected_but_start_menu_is_still_volatile(self):
        self.assertFalse(reg.is_volatile(CHOICE))
        self.assertTrue(reg.is_volatile(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2"))

    def test_full_snapshot_reaches_only_file_exts_below_explorer(self):
        explorer = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
        start_page = explorer + r"\StartPage2"
        tree = {
            explorer: ["FileExts", "StartPage2"],
            explorer + r"\FileExts": [".portablizer-demo"],
            explorer + r"\FileExts\.portablizer-demo": ["UserChoice"],
            CHOICE.split("\\", 1)[1]: [],
            start_page: [],
        }

        class FakeWinreg:
            KEY_READ = 0

            @staticmethod
            def OpenKey(_hive, path, _reserved, _access):
                if path not in tree:
                    raise FileNotFoundError(path)
                return path

            @staticmethod
            def EnumValue(_key, _index):
                raise OSError("no values")

            @staticmethod
            def EnumKey(key, index):
                try:
                    return tree[key][index]
                except (IndexError, KeyError):
                    raise OSError("no more keys")

            @staticmethod
            def CloseKey(_key):
                return None

        out = {}
        with mock.patch.object(reg, "winreg", FakeWinreg, create=True):
            reg._walk(0, explorer, "HKCU", out, max_depth=12, depth=1)
        self.assertIn(CHOICE, out)
        self.assertNotIn("HKCU\\" + start_page, out)
        self.assertNotIn("HKCU\\" + explorer, out)

    def test_restore_covers_changed_added_and_deleted_keys_and_values(self):
        before, after = snapshots()
        text = reg.render_association_restore(before, after)

        self.assertIn(r"[-HKEY_CURRENT_USER\Software\Classes\After.ProgID]", text)
        self.assertNotIn(
            r"[-HKEY_CURRENT_USER\Software\Classes\After.ProgID\shell", text)
        self.assertIn(r"[HKEY_CURRENT_USER\Software\Classes\Before.ProgID"
                      r"\shell\open\command]", text)
        self.assertIn("before.exe", text)
        self.assertIn('"Added"=-', text)
        self.assertIn('"ProgId"="Before.ProgID"', text)
        self.assertIn('"Hash"="old-hash"', text)
        self.assertNotIn("new-hash", text)
        self.assertNotIn("Vendor", text, "общий реестр откатывать нельзя")

    def test_verification_ignores_unrelated_changes(self):
        before, after = snapshots()
        self.assertEqual(reg.association_restore_mismatches(
            before, after, before), [])
        current = dict(before)
        current[EXT] = after[EXT]
        self.assertEqual(reg.association_restore_mismatches(
            before, after, current), [EXT])


class BuilderRegistrySafetyTests(unittest.TestCase):
    def test_capture_never_imports_back_into_host_and_drops_user_choice(self):
        before, after = snapshots()
        after[EXT] = {"": sz("After.ProgID")}
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Demo_Portable")
            portable.mkdir()
            engine = Portablizer(Logger())
            opts = PortableOptions(
                installer_path="x", output_dir=temp, app_name="Demo",
                include_shell_integration=True, cleanup_host=False)
            with mock.patch.object(portablizer_mod, "IS_WINDOWS", True), \
                    mock.patch.object(portablizer_mod.subprocess, "run") as run:
                capture = engine._capture_registry(
                    str(portable), before, after, opts)
            run.assert_not_called()
            self.assertNotIn(CHOICE, capture.keys)
            self.assertIn(EXT, capture.keys)
            reg_text = "\n".join(
                path.read_text(encoding="utf-16")
                for path in portable.glob("portable*.reg"))
            self.assertNotIn("FileExts", reg_text)
            self.assertNotIn("UserChoice", reg_text)

    def test_builder_restore_is_verified_and_does_not_touch_app_settings(self):
        before, after = snapshots()
        engine = Portablizer(Logger())
        result = PortableResult(success=False)
        imported = []

        def fake_import(path: str) -> int:
            imported.append(Path(path).read_text(encoding="utf-16"))
            return 0

        with mock.patch.object(portablizer_mod, "IS_WINDOWS", True), \
                mock.patch.object(engine, "_reg_import", side_effect=fake_import), \
                mock.patch.object(reg, "snapshot_associations", return_value=before):
            engine._restore_host_associations(before, after, result)

        self.assertEqual(len(imported), 1)
        self.assertIn("Before.ProgID", imported[0])
        self.assertNotIn("Vendor", imported[0])
        self.assertGreater(result.association_changes_restored, 0)
        self.assertFalse(result.association_restore_pending)


class ExeLauncherRegistrySafetyTests(unittest.TestCase):
    BACKUP_TEXT = (
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_CURRENT_USER\\Software\\Classes\\.portablizer-demo]\r\n"
        "@=\"Before.ProgID\"\r\n"
    )

    def _session(self, root: Path):
        cfg = {"data_dir_name": "PortableData", "registry": {
            "enabled": True, "restore_on_exit": True,
            "file": "portable.reg", "machine_file": "portable_machine.reg",
            "keys": [EXT], "created_keys": [EXT],
        }}
        session = entry.RegistrySession(root, cfg)
        session.active = True
        session.backup.mkdir(parents=True, exist_ok=True)
        return session

    def test_preexisting_created_key_is_restored_not_deleted(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            deleted = []
            imported = []
            with mock.patch.object(entry, "export_registry_text",
                                   return_value=self.BACKUP_TEXT), \
                    mock.patch.object(entry, "registry_key_state", return_value=True):
                session._snapshot_host()
                state = session._read_host_state()
                self.assertEqual(state["present"], [EXT])
                self.assertEqual(state["absent"], [])
                session.started = True
                with mock.patch.object(entry, "_pack_reg"), \
                        mock.patch.object(
                            entry, "import_registry_file",
                            side_effect=lambda path, _root=None:
                            imported.append(path.name) or True), \
                        mock.patch.object(
                            entry, "delete_key_tree",
                            side_effect=lambda key: deleted.append(key) or True):
                    session.save_and_restore()
            self.assertEqual(deleted, [])
            self.assertIn(entry.REGISTRY_SNAPSHOT_NAME, imported)

    def test_added_values_and_subkeys_are_removed_before_baseline_import(self):
        current = self.BACKUP_TEXT + (
            "\r\n[HKEY_CURRENT_USER\\Software\\Classes\\.portablizer-demo"
            "\\NewChild]\r\n\"Value\"=\"x\"\r\n")
        current = current.replace(
            "@=\"Before.ProgID\"",
            "@=\"Before.ProgID\"\r\n\"Added\"=\"remove-me\"")
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            deleted_values = []
            deleted_keys = []
            with mock.patch.object(
                    entry, "delete_registry_value",
                    side_effect=lambda key, name:
                    deleted_values.append((key, name)) or True), \
                    mock.patch.object(
                        entry, "delete_key_tree",
                        side_effect=lambda key: deleted_keys.append(key) or True):
                ok = session._prune_to_baseline(
                    {"present": [EXT], "absent": [], "unknown": []},
                    self.BACKUP_TEXT, current)
            self.assertTrue(ok)
            self.assertEqual(deleted_values, [(
                r"HKEY_CURRENT_USER\Software\Classes\.portablizer-demo",
                "Added")])
            self.assertEqual(deleted_keys, [
                r"HKEY_CURRENT_USER\Software\Classes\.portablizer-demo\NewChild"])

    def test_unknown_baseline_sections_are_not_imported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            session = self._session(root)
            session._write_host_state(
                {"present": [], "absent": [], "unknown": [EXT]})
            (root / "portable.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                f"[{FULL_EXT}]\r\n@=\"After.ProgID\"\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Vendor\\Safe]\r\n"
                "\"Setting\"=\"kept\"\r\n",
                encoding="utf-16", newline="\r\n")
            imported = []
            with mock.patch.object(
                    entry, "import_registry_text",
                    side_effect=lambda text: imported.append(text) or True):
                session.apply()
            self.assertEqual(len(imported), 1)
            self.assertNotIn(".portablizer-demo", imported[0])
            self.assertIn(r"Vendor\Safe", imported[0])
            self.assertIn("Setting", imported[0])

    def test_empty_current_export_does_not_validate_pruning(self):
        session_state = {"present": [EXT], "absent": [], "unknown": []}
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            with mock.patch.object(entry, "registry_key_state", return_value=True):
                self.assertFalse(session._prune_to_baseline(
                    session_state, self.BACKUP_TEXT, ""))
            with mock.patch.object(entry, "registry_key_state", return_value=False):
                self.assertTrue(session._prune_to_baseline(
                    session_state, self.BACKUP_TEXT, ""))

    def test_absent_key_is_deleted_after_the_session(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            deleted = []
            with mock.patch.object(entry, "export_registry_text", return_value=""), \
                    mock.patch.object(entry, "registry_key_state", return_value=False):
                session._snapshot_host()
                self.assertEqual(session._read_host_state()["absent"], [EXT])
                session.started = True
                with mock.patch.object(
                        entry, "delete_key_tree",
                        side_effect=lambda key: deleted.append(key) or True):
                    session.save_and_restore()
            self.assertEqual(deleted, [EXT])

    def test_unknown_original_state_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            deleted = []
            with mock.patch.object(entry, "export_registry_text", return_value=""), \
                    mock.patch.object(entry, "registry_key_state", return_value=None):
                session._snapshot_host()
                self.assertEqual(session._read_host_state()["unknown"], [EXT])
                session.started = True
                with mock.patch.object(
                        entry, "delete_key_tree",
                        side_effect=lambda key: deleted.append(key) or True):
                    session.save_and_restore()
            self.assertEqual(deleted, [])


class ExternalBrowserRegistrySafetyTests(unittest.TestCase):
    def test_legacy_reg_is_sanitized_but_custom_deep_link_survives(self):
        text = (
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Classes\\http]\r\n"
            '"URL Protocol"=""\r\n\r\n'
            "[HKEY_CURRENT_USER\\Software\\Classes\\https\\shell\\open\\command]\r\n"
            '@="\\"C:\\\\Browser\\\\browser.exe\\" \\"%1\\""\r\n\r\n'
            "[HKEY_CURRENT_USER\\Software\\Classes\\ChromeHTML\\shell\\open\\command]\r\n"
            '@="\\"C:\\\\Browser\\\\browser.exe\\" \\"%1\\""\r\n\r\n'
            "[HKEY_CURRENT_USER\\Software\\Classes\\FirefoxURL-308046B0AF4A39CB]\r\n"
            '"URL Protocol"=""\r\n\r\n'
            "[HKEY_CURRENT_USER\\Software\\Classes\\figma\\shell\\open\\command]\r\n"
            '@="\\"@@PORTABLE_ROOT@@\\\\App\\\\Figma.exe\\" --open \\"%1\\""\r\n'
        )
        sanitized, dropped = entry.sanitize_reg_text(text)
        self.assertGreaterEqual(len(dropped), 4)
        self.assertNotIn(r"Software\Classes\http", sanitized)
        self.assertNotIn(r"Software\Classes\https", sanitized)
        self.assertNotIn("ChromeHTML", sanitized)
        self.assertNotIn("FirefoxURL", sanitized)
        self.assertNotIn("browser.exe", sanitized)
        self.assertIn(r"Software\Classes\figma", sanitized)
        self.assertIn("Figma.exe", sanitized)

    def test_runtime_session_forgets_legacy_browser_keys(self):
        browser = r"HKCU\Software\Classes\https"
        progid = r"HKCU\Software\Classes\MSEdgeHTM"
        custom = r"HKCU\Software\Classes\figma"
        with tempfile.TemporaryDirectory() as temp:
            session = entry.RegistrySession(Path(temp), {
                "registry": {
                    "enabled": True,
                    "keys": [browser, progid, custom],
                    "created_keys": [browser, progid, custom],
                },
            })
            self.assertEqual(session.keys, [custom])
            self.assertEqual(session.created, {custom.casefold()})
            self.assertEqual(session._tracked_keys(), [custom])


class BatLauncherRegistrySafetyTests(unittest.TestCase):
    ROOT = r"E:\Demo_Portable"

    def _run(self, missing=False):
        cfg = launcher_mod.LauncherConfig(
            app_name="Demo", target_exe_rel="App/Demo.exe",
            apply_registry=True, registry_keys=[EXT],
            registry_created_keys=[EXT], registry_has_root_token=True)
        bat = launcher_mod.render_bat(cfg)
        fs = batsim.FakeFS()
        fs.add_dir(self.ROOT)
        fs.add_file(self.ROOT + r"\App\Demo.exe", "MZ")
        fs.add_file(self.ROOT + r"\portable.reg", "portable")
        fs.add_file(self.ROOT + r"\Launch.bat", bat)
        env = {"BATSIM_MISSING_REG": EXT} if missing else {}
        return bat, batsim.run_batch(
            bat, self.ROOT + r"\Launch.bat", fs, env=env)

    def test_existing_association_is_restored_even_if_created_on_build_pc(self):
        _bat, result = self._run(missing=False)
        commands = "\n".join(result.reg_commands)
        self.assertNotIn("reg query", commands,
                         "успешного export достаточно, лишний probe не нужен")
        self.assertIn("RegistryHostBackup", commands)
        self.assertIn("portable_prune", commands,
                      "добавленные значения удаляются до baseline import")
        self.assertNotIn("reg delete", commands)

    def test_only_confirmed_absent_association_is_deleted(self):
        _bat, result = self._run(missing=True)
        commands = "\n".join(result.reg_commands)
        self.assertIn("reg query", commands)
        self.assertIn("reg delete", commands)

    def test_bat_rewrite_filters_legacy_file_exts_sections(self):
        bat, _result = self._run()
        self.assertIn("Explorer\\\\FileExts", bat)
        self.assertIn("$skip", bat)
        self.assertIn("$browserPrefixes", bat)
        self.assertIn("'http','https'", bat)
        self.assertIn("Software(?:\\\\Wow6432Node)?\\\\Classes", bat)


class PythonFallbackRegistrySafetyTests(unittest.TestCase):
    def _namespace(self):
        namespace = {"__name__": "portable_fallback_test"}
        source = launcher_mod.render_py_launcher(None)
        exec(compile(source, "<fallback-test>", "exec"), namespace)
        return namespace

    def test_generated_fallback_filters_browser_sections_on_import(self):
        namespace = self._namespace()
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp, "portable.reg")
            source.write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Classes\\https]\r\n"
                '"URL Protocol"=""\r\n\r\n'
                "[HKEY_CURRENT_USER\\Software\\Classes\\ChromeHTML\\shell\\open\\command]\r\n"
                '@="\\"C:\\\\Browser\\\\browser.exe\\" \\"%1\\""\r\n\r\n'
                "[HKEY_CURRENT_USER\\Software\\Classes\\figma]\r\n"
                '"URL Protocol"=""\r\n', encoding="utf-16")
            imported = []

            def fake_reg(*args):
                self.assertEqual(args[0], "import")
                imported.append(Path(args[1]).read_text(encoding="utf-16"))
                return 0

            namespace["reg"] = fake_reg
            self.assertEqual(namespace["reg_import"](
                str(source), r"C:\Portable", "", temp), 0)
            self.assertEqual(len(imported), 1)
            self.assertNotIn("ChromeHTML", imported[0])
            self.assertNotIn(r"Classes\https", imported[0])
            self.assertIn(r"Classes\figma", imported[0])

    def test_generated_fallback_filters_browser_sections_on_export(self):
        namespace = self._namespace()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp, "session.reg")

            def fake_reg(*args):
                Path(args[2]).write_text(
                    "Windows Registry Editor Version 5.00\r\n\r\n"
                    "[HKEY_CURRENT_USER\\Software\\Classes\\http]\r\n"
                    '"URL Protocol"=""\r\n\r\n'
                    "[HKEY_CURRENT_USER\\Software\\Classes\\figma]\r\n"
                    '"URL Protocol"=""\r\n', encoding="utf-16")
                return 0

            namespace["reg"] = fake_reg
            self.assertEqual(namespace["reg_export"](
                "HKCU\\Software\\Classes", str(output),
                r"C:\Portable", "@@PORTABLE_ROOT@@"), 0)
            text = output.read_text(encoding="utf-16")
            self.assertNotIn(r"Classes\http", text)
            self.assertIn(r"Classes\figma", text)

    def test_generated_fallback_builds_deletion_only_restore(self):
        namespace = self._namespace()
        with tempfile.TemporaryDirectory() as temp:
            baseline = Path(temp, "baseline.reg")
            current = Path(temp, "current.reg")
            output = Path(temp, "prune.reg")
            baseline.write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                f"[{FULL_EXT}]\r\n@=\"Before\"\r\n",
                encoding="utf-16", newline="\r\n")
            current.write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                f"[{FULL_EXT}]\r\n@=\"After\"\r\n\"Added\"=\"x\"\r\n\r\n"
                f"[{FULL_EXT}\\NewChild]\r\n@=\"new\"\r\n",
                encoding="utf-16", newline="\r\n")
            self.assertTrue(namespace["prune_added_registry_values"](
                str(baseline), str(current), str(output)))
            text = output.read_text(encoding="utf-16")
            self.assertIn(f"[-{FULL_EXT}\\NewChild]", text)
            self.assertIn('"Added"=-', text)
            self.assertNotIn('"After"', text)

    def test_generated_fallback_exports_key_to_the_session_file(self):
        namespace = self._namespace()
        calls = []
        namespace["reg"] = lambda *args: calls.append(args) or 0
        self.assertEqual(namespace["reg_export"](
            EXT, "session.reg", "E:/Demo", ""), 0)
        self.assertEqual(calls, [("export", EXT, "session.reg", "/y")])


class UpdateAssociationGuardTests(unittest.TestCase):
    def test_restore_text_removes_additions_and_restores_old_values(self):
        before = (
            "Windows Registry Editor Version 5.00\r\n\r\n"
            f"[{FULL_EXT}]\r\n"
            "@=\"Before.ProgID\"\r\n"
            "\"Keep\"=\"same\"\r\n\r\n"
            f"[{FULL_CHOICE}]\r\n"
            "\"ProgId\"=\"Before.ProgID\"\r\n"
            "\"Hash\"=\"old-hash\"\r\n"
        )
        after = (
            "Windows Registry Editor Version 5.00\r\n\r\n"
            f"[{FULL_EXT}]\r\n"
            "@=\"After.ProgID\"\r\n"
            "\"Keep\"=\"same\"\r\n"
            "\"Added\"=\"remove-me\"\r\n\r\n"
            f"[{FULL_EXT}\\NewChild]\r\n"
            "@=\"new\"\r\n\r\n"
            f"[{FULL_CHOICE}]\r\n"
            "\"ProgId\"=\"After.ProgID\"\r\n"
            "\"Hash\"=\"new-hash\"\r\n"
        )
        restore = entry._association_restore_text(before, after)
        self.assertIn(f"[-{FULL_EXT}\\NewChild]", restore)
        self.assertIn('"Added"=-', restore)
        self.assertIn('"ProgId"="Before.ProgID"', restore)
        self.assertIn('"Hash"="old-hash"', restore)
        self.assertEqual(entry._association_mismatches(before, after, before), [])
        self.assertIn(FULL_CHOICE, entry._association_mismatches(
            before, after, after))

    def test_update_does_not_run_installer_without_a_baseline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "App").mkdir()
            installer = root / "setup.exe"
            installer.write_bytes(b"installer")
            guard = mock.Mock()
            guard.snapshot.return_value = False
            guard.restore.return_value = []
            runner = mock.Mock()
            with mock.patch.object(entry, "HostAssociationGuard",
                                   return_value=guard):
                result = entry.apply_update(root, {}, installer, runner=runner)
            self.assertFalse(result.ok)
            self.assertIn("Установщик не запускался", result.message)
            runner.assert_not_called()

    def test_heal_never_rewrites_an_association_tree(self):
        fake_reg = mock.Mock()
        fake_reg.HKEY_CURRENT_USER = object()
        fake_reg.HKEY_LOCAL_MACHINE = object()
        changed = entry._heal_registry_tree(
            fake_reg, fake_reg.HKEY_CURRENT_USER,
            r"Software\Classes\.demo", 0, (), Path("E:/Demo"), (), [10])
        self.assertEqual(changed, [])
        fake_reg.OpenKey.assert_not_called()


class LegacyImportSafetyTests(unittest.TestCase):
    def test_import_reg_fallback_sanitizes_user_choice(self):
        text = (
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Vendor\\Demo]\r\n"
            "\"Setting\"=\"1\"\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion"
            "\\Explorer\\FileExts\\.demo\\UserChoice]\r\n"
            "\"ProgId\"=\"Other.ProgID\"\r\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "old.reg"
            source.write_text(text, encoding="utf-16")
            imported = []

            def fake_import(path: Path, _root=None):
                imported.append(path.read_text(encoding="utf-16"))
                return True

            with mock.patch.object(entry, "import_registry_file",
                                   side_effect=fake_import):
                self.assertEqual(entry.import_reg_command(root, str(source)), 0)
            self.assertEqual(len(imported), 1)
            self.assertIn("Vendor", imported[0])
            self.assertNotIn("FileExts", imported[0])


@unittest.skipUnless(os.name == "nt", "реальный HKCU доступен только на Windows")
class WindowsRegistryIntegrationTests(unittest.TestCase):
    """Реальный HKCU, без моков; используются только уникальные ветки теста."""

    def _delete(self, key: str) -> None:
        import subprocess
        subprocess.run(["reg", "delete", key, "/f"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _write(self, key: str, values: dict) -> None:
        import winreg
        hive, path = key.split("\\", 1)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0,
                                winreg.KEY_WRITE) as handle:
            for name, value in values.items():
                winreg.SetValueEx(handle, name, 0, winreg.REG_SZ, value)

    def _read(self, key: str, name: str = "") -> str:
        import winreg
        _hive, path = key.split("\\", 1)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                            winreg.KEY_READ) as handle:
            value, _kind = winreg.QueryValueEx(handle, name)
            return value

    def test_installer_changes_to_classes_and_user_choice_are_rolled_back(self):
        suffix = f".pbt{os.getpid()}"
        ext = r"HKCU\Software\Classes" + "\\" + suffix
        choice = (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer"
                  r"\FileExts" + "\\" + suffix + r"\UserChoice")
        old_root = r"HKCU\Software\Classes\Before.PBT" + str(os.getpid())
        new_root = r"HKCU\Software\Classes\After.PBT" + str(os.getpid())
        unrelated = r"HKCU\Software\PortablizerSafety" + str(os.getpid())
        cleanup = [ext, choice.rsplit("\\", 1)[0], old_root, new_root, unrelated]
        self.addCleanup(lambda: [self._delete(key) for key in cleanup])
        for key in cleanup:
            self._delete(key)
        # Только уникальные ветки теста: полный Classes на машине разработчика
        # не экспортируется и параллельные изменения пользователя не откатываются.
        roots = tuple(("HKCU", key.split("\\", 1)[1])
                      for key in (ext, choice, old_root, new_root))
        roots_patch = mock.patch.object(reg, "_ASSOCIATION_ROOTS", roots)
        roots_patch.start()
        self.addCleanup(roots_patch.stop)

        self._write(ext, {"": "Before.ProgID"})
        self._write(old_root + r"\shell\open\command",
                    {"": r'"C:\Before\before.exe" "%1"'})
        self._write(choice, {"ProgId": "Before.ProgID", "Hash": "old-hash"})
        self._write(unrelated, {"Theme": "before"})
        before = reg.snapshot_associations()
        self.assertIn(choice, before, "FileExts не попал в реальный снимок")

        self._write(ext, {"": "After.ProgID", "Added": "remove-me"})
        self._write(choice, {"ProgId": "After.ProgID", "Hash": "new-hash",
                             "Added": "remove-me"})
        self._delete(old_root)
        self._write(new_root + r"\shell\open\command",
                    {"": r'"C:\After\after.exe" "%1"'})
        self._write(unrelated, {"Theme": "after"})
        after = reg.snapshot_associations()
        restore = reg.render_association_restore(before, after)
        self.assertNotIn("PortablizerSafety", restore)

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "restore.reg")
            reg.write_reg_file(str(path), restore)
            import subprocess
            completed = subprocess.run(
                ["reg", "import", str(path)], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + completed.stderr)
        current = reg.snapshot_associations()
        self.assertEqual(reg.association_restore_mismatches(
            before, after, current), [])
        self.assertEqual(self._read(ext), "Before.ProgID")
        self.assertEqual(self._read(choice, "ProgId"), "Before.ProgID")
        self.assertEqual(self._read(choice, "Hash"), "old-hash")
        self.assertEqual(self._read(unrelated, "Theme"), "after")

    def test_real_cmd_powershell_prunes_added_values_before_restore(self):
        suffix = f".pbc{os.getpid()}"
        key = r"HKCU\Software\Classes" + "\\" + suffix
        full = "HKEY_CURRENT_USER" + key[len("HKCU"):]
        self._delete(key)
        self.addCleanup(lambda: self._delete(key))
        self._write(key, {"": "Before.ProgID", "Keep": "same"})

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "baseline.reg"
            current = root / "current.reg"
            prune = root / "prune.reg"
            import subprocess
            self.assertEqual(subprocess.run(
                ["reg", "export", key, str(baseline), "/y"], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode, 0)
            self._write(key, {"": "After.ProgID", "Added": "remove-me"})
            self._write(key + r"\NewChild", {"": "new"})
            self.assertEqual(subprocess.run(
                ["reg", "export", key, str(current), "/y"], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode, 0)

            bat = launcher_mod.render_bat(launcher_mod.LauncherConfig(
                app_name="Demo", target_exe_rel="App/Demo.exe"))
            helper = ":" + bat.split(":portable_registry_prune", 1)[1].split(
                ":portable_registry_rewrite", 1)[0]
            script = root / "restore.cmd"
            script.write_text(
                "@echo off\r\n"
                f"set \"PORTABLE_REG_BASE={baseline}\"\r\n"
                f"set \"PORTABLE_REG_CURRENT={current}\"\r\n"
                f"set \"PORTABLE_REG_PRUNE={prune}\"\r\n"
                "call :portable_registry_prune\r\n"
                "if errorlevel 1 exit /b 1\r\n"
                "reg import \"%PORTABLE_REG_PRUNE%\"\r\n"
                "if errorlevel 1 exit /b 1\r\n"
                "reg import \"%PORTABLE_REG_BASE%\"\r\n"
                "exit /b %errorlevel%\r\n" + helper,
                encoding="ascii", newline="\r\n")
            completed = subprocess.run(
                [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(script)],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60)
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + completed.stderr)

        self.assertEqual(self._read(key), "Before.ProgID")
        self.assertEqual(self._read(key, "Keep"), "same")
        import winreg
        with self.assertRaises(FileNotFoundError):
            self._read(key, "Added")
        with self.assertRaises(FileNotFoundError):
            self._read(key + r"\NewChild")

    def test_real_cmd_rewrite_drops_browser_handlers_without_registry_writes(self):
        """BAT fallback фильтрует REG сам, не импортируя его в HKCU."""
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "legacy.reg"
            output = root / "filtered.reg"
            source.write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Classes\\http]\r\n"
                '"URL Protocol"=""\r\n\r\n'
                "[HKEY_CURRENT_USER\\Software\\Classes\\ChromeHTML\\shell\\open\\command]\r\n"
                '@="\\"C:\\\\Browser\\\\browser.exe\\" \\"%1\\""\r\n\r\n'
                "[HKEY_CURRENT_USER\\Software\\Classes\\figma]\r\n"
                '"URL Protocol"=""\r\n\r\n'
                "[HKEY_CURRENT_USER\\Software\\Vendor\\Demo]\r\n"
                '"Keep"="yes"\r\n', encoding="utf-16")
            bat = launcher_mod.render_bat(launcher_mod.LauncherConfig(
                app_name="Demo", target_exe_rel="App/Demo.exe",
                apply_registry=True))
            helper = ":" + bat.split(":portable_registry_rewrite", 1)[1]
            script = root / "rewrite.cmd"
            script.write_text(
                "@echo off\r\n"
                f"set \"PORTABLE_ROOT={root}\"\r\n"
                "set \"PORTABLE_REG_MARKER=@@PORTABLE_ROOT@@\"\r\n"
                f"set \"PORTABLE_REG_SRC={source}\"\r\n"
                f"set \"PORTABLE_REG_OUT={output}\"\r\n"
                "call :portable_registry_rewrite unpack\r\n"
                "if errorlevel 1 exit /b 1\r\n"
                "exit /b 0\r\n" + helper,
                encoding="ascii", newline="\r\n")
            completed = subprocess.run(
                [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(script)],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60)
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + completed.stderr)
            text = output.read_text(encoding="utf-16")
            self.assertNotIn(r"Classes\http", text)
            self.assertNotIn("ChromeHTML", text)
            self.assertNotIn("browser.exe", text)
            self.assertIn(r"Classes\figma", text)
            self.assertIn(r"Vendor\Demo", text)

    def test_update_guard_restores_real_hkcu_associations(self):
        suffix = f".pbu{os.getpid()}"
        ext = r"HKCU\Software\Classes" + "\\" + suffix
        choice = (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer"
                  r"\FileExts" + "\\" + suffix + r"\UserChoice")
        new_root = r"HKCU\Software\Classes\After.PBU" + str(os.getpid())
        unrelated = r"HKCU\Software\PortablizerUpdateSafety" + str(os.getpid())
        cleanup = [ext, choice.rsplit("\\", 1)[0], new_root, unrelated]
        self.addCleanup(lambda: [self._delete(key) for key in cleanup])
        for key in cleanup:
            self._delete(key)
        self._write(ext, {"": "Before.ProgID", "Keep": "same"})
        self._write(choice, {"ProgId": "Before.ProgID", "Hash": "old-hash"})
        self._write(unrelated, {"Theme": "before"})

        with tempfile.TemporaryDirectory() as temp:
            guard = entry.HostAssociationGuard(Path(temp))
            with mock.patch.object(entry, "_ASSOCIATION_EXPORT_ROOTS",
                                   (ext, choice, new_root)):
                self.assertTrue(guard.snapshot())
                self._write(ext, {"": "After.ProgID", "Added": "remove-me"})
                self._write(ext + r"\NewChild", {"": "new"})
                self._write(choice, {"ProgId": "After.ProgID",
                                     "Hash": "new-hash", "Added": "remove-me"})
                self._write(new_root + r"\shell\open\command",
                            {"": r'"C:\After\after.exe" "%1"'})
                self._write(unrelated, {"Theme": "after"})
                self.assertEqual(guard.restore(), [])
            self.assertFalse(guard.directory.exists())

        self.assertEqual(self._read(ext), "Before.ProgID")
        self.assertEqual(self._read(ext, "Keep"), "same")
        self.assertEqual(self._read(choice, "ProgId"), "Before.ProgID")
        self.assertEqual(self._read(choice, "Hash"), "old-hash")
        self.assertEqual(self._read(unrelated, "Theme"), "after")
        import winreg
        with self.assertRaises(FileNotFoundError):
            self._read(ext, "Added")
        with self.assertRaises(FileNotFoundError):
            self._read(ext + r"\NewChild")
        with self.assertRaises(FileNotFoundError):
            self._read(new_root + r"\shell\open\command")

    def test_launcher_restores_preexisting_association_and_removes_added_value(self):
        suffix = f".pbl{os.getpid()}"
        key = r"HKCU\Software\Classes" + "\\" + suffix
        full = "HKEY_CURRENT_USER" + key[len("HKCU"):]
        self._delete(key)
        self.addCleanup(lambda: self._delete(key))
        self._write(key, {"": "Before.ProgID"})

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "portable.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                f"[{full}]\r\n"
                "@=\"After.ProgID\"\r\n"
                "\"Added\"=\"remove-me\"\r\n",
                encoding="utf-16", newline="\r\n")
            cfg = {"data_dir_name": "PortableData", "registry": {
                "enabled": True, "file": "portable.reg", "machine_file": "",
                "restore_on_exit": True,
                "keys": [key], "created_keys": [key],
            }}
            session = entry.RegistrySession(root, cfg)
            session.load()
            self.assertEqual(self._read(key), "After.ProgID")
            self.assertEqual(self._read(key, "Added"), "remove-me")
            session.save_and_restore()

        self.assertEqual(self._read(key), "Before.ProgID")
        import winreg
        with self.assertRaises(FileNotFoundError):
            self._read(key, "Added")


if __name__ == "__main__":
    unittest.main()
