"""Скорость запуска: лончер не должен делать дорогую работу до старта программы.

Жалоба, ради которой появился этот модуль (повторная, после 1.29.0):

    Портатив Cursor (CursorUserSetup-x64-3.27.14.exe). Запускаю Launch.bat —
    появляется фоновый LaunchPortable.exe, а сам Cursor стартует очень-очень
    медленно, не в пример почти мгновенному прямому запуску Cursor.exe.

Разбор по шагам показал, что до появления окна тратилось время на работу,
программе ненужную:

* ``LaunchPortable.exe`` был собран «одним файлом» (onefile) и при КАЖДОМ
  запуске распаковывал себя во ``%TEMP%`` — десятки новых файлов, которые
  антивирус проверял заново;
* уборка временных папок прошлого сеанса выполнялась до старта программы;
* поиск «кто держит файл» открывал на монопольный доступ КАЖДЫЙ файл всего
  портатива (у Cursor — сотни тысяч);
* «свежие файлы прежнего места» искались обходом всего прежнего ``App`` при
  каждом запуске, даже если туда ничего не писали;
* реестр хоста «лечился» (перебор до 4000 значений winreg) всегда, хотя
  править было нечего;
* ``sync_external_changes`` разбирал ``portable*.reg`` до трёх раз за запуск.

Здесь проверяется, что всё это либо не делается, либо делается в фоне.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as entry
from portablizer.core import portablizer as portablizer_mod


def make_portable(root: Path) -> Path:
    app = root / "App"
    app.mkdir(parents=True, exist_ok=True)
    (app / "Cursor.exe").write_bytes(b"MZ" + b"\x00" * 64)
    (root / "PortableData").mkdir(parents=True, exist_ok=True)
    return root


class LauncherPackagingTests(unittest.TestCase):
    """Лончер собран папкой, а не «одним файлом»: нет распаковки при запуске."""

    def test_onedir_is_reported_as_fast(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            (root / "App" / "LaunchPortable.exe").write_bytes(b"MZ")
            payload = root / "App" / "_internal"
            payload.mkdir()
            (payload / "python311.dll").write_bytes(b"MZ")
            text = entry.launcher_packaging_reason(root)
            self.assertIn("папкой", text)
            self.assertNotIn("ОДНИМ ФАЙЛОМ", text)

    def test_onefile_is_named_as_the_reason_of_a_slow_start(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            (root / "App" / "LaunchPortable.exe").write_bytes(b"MZ")
            text = entry.launcher_packaging_reason(root)
            self.assertIn("ОДНИМ ФАЙЛОМ", text)
            self.assertIn("распаковывается", text)

    def test_diagnose_mentions_the_packaging(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            (root / "App" / "LaunchPortable.exe").write_bytes(b"MZ")
            (root / "launcher_config.json").write_text(json.dumps({
                "app_name": "Cursor", "target_exe_rel": "App/Cursor.exe",
                "data_dir_name": "PortableData", "registry": {"enabled": False},
            }), encoding="utf-8")
            with mock.patch.object(entry, "IS_WINDOWS", False):
                entry.diagnose(root)
            report = (root / "PortableData" / "diagnostics.txt").read_text(
                encoding="utf-8")
            self.assertIn("Сам лончер", report)
            self.assertIn("ОДНИМ ФАЙЛОМ", report)

    def test_launcher_payload_is_bundled_into_the_portable(self):
        """Portablizer кладёт рядом с exe папку содержимого (без распаковки)."""
        with tempfile.TemporaryDirectory() as temp:
            resources = Path(temp, "resources", "portable_launcher")
            (resources / "_internal").mkdir(parents=True)
            (resources / "PortableLauncher.exe").write_bytes(b"MZ onedir")
            (resources / "_internal" / "python311.dll").write_bytes(b"MZ dll")
            portable = Path(temp, "Portable")
            (portable / "App").mkdir(parents=True)

            engine = portablizer_mod.Portablizer.__new__(
                portablizer_mod.Portablizer)
            engine._log = mock.MagicMock()
            engine.log = mock.MagicMock()

            with mock.patch.object(portablizer_mod, "bundled_exe_launcher_dir",
                                   return_value=str(resources)):
                rel = engine._copy_exe_launcher(str(portable))

            self.assertTrue(rel)
            self.assertEqual((portable / "App" / "LaunchPortable.exe")
                             .read_bytes(), b"MZ onedir")
            payload = portable / "App" / "_internal"
            self.assertTrue((payload / "python311.dll").is_file())
            self.assertTrue((payload
                             / portablizer_mod.LAUNCHER_PAYLOAD_MARKER).is_file())

    def test_payload_is_not_copied_twice(self):
        with tempfile.TemporaryDirectory() as temp:
            resources = Path(temp, "resources", "portable_launcher")
            (resources / "_internal").mkdir(parents=True)
            (resources / "PortableLauncher.exe").write_bytes(b"MZ onedir")
            (resources / "_internal" / "python311.dll").write_bytes(b"MZ dll")
            portable = Path(temp, "Portable")
            (portable / "App").mkdir(parents=True)
            engine = portablizer_mod.Portablizer.__new__(
                portablizer_mod.Portablizer)
            engine.log = mock.MagicMock()
            self.assertTrue(engine._copy_launcher_payload(
                str(resources), str(portable)))
            marker = (portable / "App" / "_internal"
                      / portablizer_mod.LAUNCHER_PAYLOAD_MARKER)
            self.assertTrue(marker.is_file())
            # Второй вызов (копии лончера под другими именами) папку не трогает.
            with mock.patch.object(portablizer_mod.shutil,
                                   "copytree") as copytree:
                self.assertTrue(engine._copy_launcher_payload(
                    str(resources), str(portable)))
            copytree.assert_not_called()

    def test_onefile_is_used_when_the_payload_cannot_be_copied(self):
        with tempfile.TemporaryDirectory() as temp:
            resources = Path(temp, "resources", "portable_launcher")
            (resources / "_internal").mkdir(parents=True)
            (resources / "PortableLauncher.exe").write_bytes(b"MZ onedir")
            (resources / "_internal" / "x.dll").write_bytes(b"MZ")
            onefile = Path(temp, "resources", "portable_launcher.exe")
            onefile.write_bytes(b"MZ onefile")
            portable = Path(temp, "Portable")
            (portable / "App").mkdir(parents=True)
            engine = portablizer_mod.Portablizer.__new__(
                portablizer_mod.Portablizer)
            engine.log = mock.MagicMock()
            with mock.patch.object(portablizer_mod, "bundled_exe_launcher_dir",
                                   return_value=str(resources)), \
                    mock.patch.object(portablizer_mod, "bundled_exe_launcher_path",
                                      return_value=str(onefile)), \
                    mock.patch.object(engine, "_copy_launcher_payload",
                                      return_value=False):
                engine._copy_exe_launcher(str(portable))
            self.assertEqual((portable / "App" / "LaunchPortable.exe")
                             .read_bytes(), b"MZ onefile")


class DeferredStartupWorkTests(unittest.TestCase):
    """Остатки прошлого сеанса убираются после старта, а не до него."""

    def test_prepare_only_lists_and_run_deletes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            temp_dir = root / "PortableData" / "Temp"
            temp_dir.mkdir(parents=True)
            (temp_dir / "is-ABC.tmp").mkdir()
            (temp_dir / "is-ABC.tmp" / "f.dll").write_bytes(b"x")
            (temp_dir / "stale.log").write_text("x", encoding="utf-8")
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_portable_process_list",
                                      return_value=[]):
                sweep = entry.StaleSessionSweep(root, {})
                sweep.prepare()
                # До старта программы ничего не удалено — только посчитано.
                self.assertEqual(len(sweep.entries), 2)
                self.assertTrue((temp_dir / "is-ABC.tmp").is_dir())
                done = sweep.run()
            self.assertIn("очищена временная папка портатива (2)", done)
            self.assertFalse((temp_dir / "is-ABC.tmp").exists())

    def test_a_running_second_copy_keeps_its_temporary_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            temp_dir = root / "PortableData" / "Temp"
            temp_dir.mkdir(parents=True)
            (temp_dir / "is-1.tmp").mkdir()
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_portable_process_list",
                                      return_value=[(7, r"C:\P\App\Cursor.exe")]):
                sweep = entry.StaleSessionSweep(root, {})
                sweep.prepare()
                done = sweep.run()
            self.assertEqual(done, [])
            self.assertTrue((temp_dir / "is-1.tmp").is_dir())

    def test_lock_scan_is_limited_to_the_temporary_folders(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            temp_dir = root / "PortableData" / "Temp"
            temp_dir.mkdir(parents=True)
            (temp_dir / "busy.tmp").write_bytes(b"x")
            seen = []

            def fake_release(_root, _settings=None, roots=None):
                seen.extend(str(item) for item in (roots or []))
                return []

            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_portable_process_list",
                                      return_value=[]), \
                    mock.patch.object(entry, "release_leftover_handles",
                                      side_effect=fake_release), \
                    mock.patch.object(entry.shutil, "rmtree"), \
                    mock.patch.object(Path, "unlink",
                                      side_effect=OSError("занят")):
                sweep = entry.StaleSessionSweep(root, {})
                sweep.prepare()
                sweep.run()
            self.assertTrue(seen)
            # Ни одного пути из App: обход всего портатива на старте недопустим.
            self.assertTrue(all("Temp" in item for item in seen))


class PreviousLocationTests(unittest.TestCase):
    """Прежнее место портатива не обходится, если туда ничего не писали."""

    def _make_previous(self, temp: str):
        old_root = Path(temp, "Old", "Cursor_Portable")
        (old_root / "App").mkdir(parents=True)
        (old_root / "App" / "Cursor.exe").write_bytes(b"MZ")
        (old_root / "App" / "resources").mkdir()
        (old_root / "App" / "resources" / "app.json").write_text("{}",
                                                                encoding="utf-8")
        return old_root

    def test_untouched_previous_folder_is_not_walked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp, "New"))
            old_root = self._make_previous(temp)
            cfg = {"relative_paths": {"previous_roots": [str(old_root)]}}
            since = time.time() + 60  # «сеанс начался позже всего, что там есть»
            with mock.patch.object(entry, "IS_WINDOWS", False), \
                    mock.patch.object(entry.os, "walk") as walk:
                adopted = entry.adopt_updates_from_previous_locations(
                    root, cfg, since=since)
            walk.assert_not_called()
            self.assertEqual(adopted, [])

    def test_fresh_files_of_the_previous_folder_are_still_adopted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp, "New"))
            old_root = self._make_previous(temp)
            cfg = {"relative_paths": {"previous_roots": [str(old_root)]}}
            since = time.time() - 3600
            with mock.patch.object(entry, "IS_WINDOWS", False):
                adopted = entry.adopt_updates_from_previous_locations(
                    root, cfg, since=since)
            self.assertIn("Cursor.exe", adopted)
            self.assertTrue((root / "App" / "Cursor.exe").is_file())


class RegistryWorkTests(unittest.TestCase):
    """Реестр: ничего не делаем, если делать нечего."""

    def test_heal_is_skipped_when_nothing_can_be_stale(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "remembered_roots", return_value=[]), \
                    mock.patch.object(entry, "_winreg") as winreg_call:
                changed = entry.heal_host_registry(root, {"registry": {
                    "keys": [r"HKCU\Software\Cursor"]}})
            winreg_call.assert_not_called()
            self.assertEqual(changed, [])

    def test_heal_still_runs_after_a_move(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "remembered_roots",
                                      return_value=[r"D:\Old\Cursor"]), \
                    mock.patch.object(entry, "retarget_host_install_records",
                                      return_value=["запись"]) as retarget, \
                    mock.patch.object(entry, "_winreg",
                                      return_value=mock.MagicMock()), \
                    mock.patch.object(entry, "_captured_registry_views",
                                      return_value=[]):
                changed = entry.heal_host_registry(root, {})
            retarget.assert_called_once()
            self.assertIn("запись", changed)

    def test_registry_sync_is_not_repeated_for_unchanged_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            (root / "portable.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Cursor]\r\n\"a\"=\"b\"\r\n",
                encoding="utf-16", newline="\r\n")
            cfg = {"registry": {"enabled": True, "keys": [],
                                "file": "portable.reg",
                                "machine_file": "portable_machine.reg"}}
            session = entry.RegistrySession(root, cfg)
            session.active = True
            entry._REGISTRY_SYNC_CACHE.pop(str(root), None)
            with mock.patch.object(entry, "_parse_reg_sections",
                                   wraps=entry._parse_reg_sections) as parse:
                first = session.sync_external_changes()
                calls_after_first = parse.call_count
                second = session.sync_external_changes()
            self.assertEqual(first, second)
            # Второй вызов не разбирал файлы заново.
            self.assertEqual(parse.call_count, calls_after_first)


if __name__ == "__main__":
    unittest.main()
