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



class PrelaunchBudgetTests(unittest.TestCase):
    """Потолок времени на предстартовые шаги (1.31.0).

    Жалоба осталась прежней: окно программы появляется поздно, хотя сам
    лончер больше не распаковывается. Значит время уходит на шаги до старта
    (импорт сотен ключей реестра, обход файлов на медленном диске), и у них
    должен быть потолок: не успели — доделываем в фоне, параллельно с
    запущенной программой.
    """

    def test_default_budget_is_a_couple_of_seconds(self):
        self.assertGreater(entry.PRELAUNCH_BUDGET_SECONDS, 0.5)
        self.assertLessEqual(entry.PRELAUNCH_BUDGET_SECONDS, 5.0)
        self.assertEqual(entry.prelaunch_budget({}),
                         entry.PRELAUNCH_BUDGET_SECONDS)

    def test_the_budget_can_be_configured_and_disabled(self):
        self.assertEqual(entry.prelaunch_budget(
            {"prelaunch_budget_seconds": 1.5}), 1.5)
        self.assertEqual(entry.prelaunch_budget(
            {"prelaunch_budget_seconds": 0}), 0.0)
        # Мусор в конфиге не должен ни отключать потолок, ни ронять запуск.
        self.assertEqual(entry.prelaunch_budget(
            {"prelaunch_budget_seconds": "много"}),
            entry.PRELAUNCH_BUDGET_SECONDS)
        self.assertEqual(entry.prelaunch_budget(
            {"prelaunch_budget_seconds": -3}), 0.0)

    def test_a_zero_budget_means_no_ceiling(self):
        timer = entry._StageTimer(Path(tempfile.gettempdir()))
        self.assertFalse(timer.exceeded(0.0))

    def test_time_is_counted_from_the_process_start(self):
        timer = entry._StageTimer(Path(tempfile.gettempdir()))
        timer.add_startup(1.25)
        self.assertGreaterEqual(timer.spent, 1.25)
        self.assertTrue(timer.exceeded(1.0))
        self.assertFalse(timer.exceeded(30.0))
        # «exe boot» — первой строкой отчёта, как и раньше.
        self.assertEqual(timer.steps[0][0], "exe boot")

    def test_the_report_lists_the_deferred_steps(self):
        """По отчёту видно, что не успело до старта и ушло в фон."""
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp)
            timer = entry._StageTimer(data)
            timer.tick("profile self-check")
            timer.note_deferred("path repair")
            timer.note_deferred("path repair")  # повтор не задваивает список
            timer.finish(data)
            payload = json.loads(
                (data / entry.LAUNCH_TIMING_NAME).read_text(encoding="utf-8"))
            self.assertEqual(payload["deferred"], ["path repair"])
            lines = entry._last_launch_timing(data)
            self.assertTrue(any("в фоне уже после старта" in line
                                and "path repair" in line for line in lines),
                            lines)

    def test_the_build_writes_the_budget_into_the_config(self):
        """Сборка кладёт потолок в launcher_config.json — его видно и можно
        поднять или обнулить для конкретного портатива."""
        from portablizer.core import launcher as launcher_mod

        cfg = launcher_mod.LauncherConfig(app_name="Cursor",
                                          target_exe_rel="App/Cursor.exe")
        data = json.loads(launcher_mod.render_config_json(cfg))
        self.assertEqual(data["prelaunch_budget_seconds"],
                         entry.PRELAUNCH_BUDGET_SECONDS)
        # И обратно: разбор конфига возвращает то же значение.
        restored = launcher_mod.config_from_dict(
            dict(data, prelaunch_budget_seconds=0))
        self.assertEqual(restored.prelaunch_budget_seconds, 0.0)

    def test_a_deferred_step_is_logged_by_its_own_lines(self):
        """Отложенный шаг пишет журнал так же, как выполняемый на месте."""
        logged = []
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            work = entry._BackgroundWork(root, "pre-launch work")
            with mock.patch.object(entry, "_run_log",
                                   side_effect=lambda _root, line:
                                   logged.append(line)):
                work.submit(lambda: ["registry: previous location fixed"],
                            name="install records", prefix=False)
                work.wait(timeout=5.0)
        self.assertIn("registry: previous location fixed", logged)
        self.assertFalse([line for line in logged
                          if line.startswith("install records:")])


class RegistrySplitTests(unittest.TestCase):
    """Снимок машины — до старта; импорт настроек — можно и после (1.31.0)."""

    def _session(self, root: Path):
        cfg = {"registry": {"enabled": True, "keys": [], "file": "portable.reg",
                            "machine_file": "portable_machine.reg"}}
        (root / "portable.reg").write_text(
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Cursor]\r\n\"a\"=\"b\"\r\n",
            encoding="utf-16", newline="\r\n")
        session = entry.RegistrySession(root, cfg)
        session.active = True
        return session

    def test_prepare_only_snapshots_and_apply_imports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            session = self._session(root)
            with mock.patch.object(session, "_snapshot_host",
                                   return_value=([], [])) as snapshot, \
                    mock.patch.object(entry, "import_registry_text",
                                      return_value=True) as import_text:
                session.prepare()
                self.assertEqual(snapshot.call_count, 1)
                self.assertEqual(import_text.call_count, 0)
                self.assertFalse(session.started)
                session.apply()
                self.assertEqual(import_text.call_count, 1)
                self.assertTrue(session.started)
                # Повторный apply ничего не импортирует заново.
                session.apply()
                self.assertEqual(import_text.call_count, 1)
                self.assertEqual(snapshot.call_count, 1)

    def test_apply_alone_snapshots_first(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            session = self._session(root)
            with mock.patch.object(session, "_snapshot_host",
                                   return_value=([], [])) as snapshot, \
                    mock.patch.object(entry, "import_registry_text",
                                      return_value=True):
                session.apply()
            self.assertEqual(snapshot.call_count, 1)
            self.assertTrue(session.prepared)


class InstallRecordNameTests(unittest.TestCase):
    """Запись ``{GUID}}_is1`` из конфига сборки должна находиться и удаляться."""

    DOUBLED = "{DADADADA-ADAD-ADAD-ADAD-ADADADADADAD}}_is1"
    FIXED = "{DADADADA-ADAD-ADAD-ADAD-ADADADADADAD}_is1"

    def test_the_fixed_name_is_tried_too(self):
        variants = entry.uninstall_name_variants(self.DOUBLED)
        self.assertIn(self.FIXED, variants)

    def test_a_plain_name_is_not_duplicated(self):
        self.assertEqual(entry.uninstall_name_variants("Cursor"), ["Cursor"])

    def test_the_record_is_found_under_the_real_name(self):
        reg = _fake_reg({self.FIXED: {"DisplayName": "Cursor"}})
        found = entry._read_uninstall_entry_variant(
            reg, "HKCU", 0, self.DOUBLED)
        self.assertIsNotNone(found)
        name, values = found
        self.assertEqual(name, self.FIXED)
        self.assertEqual(values.get("DisplayName"), "Cursor")

    def _report(self, entries, record_path):
        cfg = {"app_name": "Cursor",
               "host_cleanup": {"records": [
                   {"hive": "HKCU", "path": record_path, "display": "Cursor"}]}}
        reg = _fake_reg(entries)
        with mock.patch.object(entry, "_winreg", return_value=reg), \
                mock.patch.object(entry, "IS_WINDOWS", True), \
                mock.patch.object(entry, "_uninstall_registry_views",
                                  return_value=[]):
            return entry.describe_install_records(Path(tempfile.gettempdir()),
                                                  cfg)

    def test_diagnose_says_the_record_is_still_there(self):
        """Запись из сборки с лишней скобкой находится и называется в отчёте."""
        path = ("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
                + self.DOUBLED)
        lines = self._report({self.FIXED: {"DisplayName": "Cursor"}}, path)
        self.assertEqual(len([line for line in lines
                              if "корни этого портатива" in line]), 1)
        text = "\n".join(lines)
        self.assertIn(self.FIXED, text)
        self.assertIn("будет удалена", text)
        # Запись считается найденной: «записей нет» больше не пишем.
        self.assertNotIn("в списке установленных программ нет", text)

    def test_diagnose_says_the_record_is_already_gone(self):
        path = ("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
                + self.DOUBLED)
        text = "\n".join(self._report({}, path))
        self.assertIn("ключа на этом ПК нет", text)

    def test_a_missing_record_is_reported_as_missing(self):
        reg = _fake_reg({})
        self.assertIsNone(entry._read_uninstall_entry_variant(
            reg, "HKCU", 0, self.DOUBLED))


class RootDedupTests(unittest.TestCase):
    """Один и тот же корень не должен печататься дважды (``--diagnose``)."""

    def test_the_same_root_written_differently_is_shown_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            for variant in (str(root).replace(os.sep, "/"),
                            str(root) + os.sep,
                            str(root).upper()):
                (root / "PortableData" / "portable-root.json").write_text(
                    json.dumps({"root": variant, "previous": variant}),
                    encoding="utf-8")
                self.assertEqual(entry._record_roots(root, {}), [str(root)],
                                 f"корень задвоился при написании {variant}")

    def test_the_long_path_prefix_is_the_same_root(self):
        self.assertEqual(entry._root_key(r"\\?\D:\Apps\Cursor_Portable"),
                         entry._root_key(r"d:/apps/cursor_portable/"))

    def test_a_real_previous_location_is_kept(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            (root / "PortableData" / "portable-root.json").write_text(
                json.dumps({"root": str(root),
                            "previous": r"D:\Old\Cursor_Portable"}),
                encoding="utf-8")
            roots = entry._record_roots(root, {})
            self.assertEqual(len(roots), 2)
            self.assertIn(r"D:\Old\Cursor_Portable", roots)


class _FakeKey:
    """Ключ реестра для winreg-мока: только перечисление строковых значений."""

    def __init__(self, values):
        self.items = list(values.items())


def _fake_reg(entries):
    """Мини-подделка winreg: только то, что нужно чтению записи Uninstall."""
    reg = mock.MagicMock()

    def open_key(_hive, path, _reserved=0, _access=0):
        name = str(path).rsplit("\\", 1)[-1]
        if name not in entries:
            raise OSError(2, "key not found")
        context = mock.MagicMock()
        context.__enter__ = lambda _self: _FakeKey(entries[name])
        context.__exit__ = lambda _self, *_args: False
        return context

    def enum(key, index):
        if index < len(key.items):
            value_name, value = key.items[index]
            return value_name, value, 1
        raise OSError(259, "no more data")

    reg.OpenKey.side_effect = open_key
    reg.EnumValue.side_effect = enum
    return reg


if __name__ == "__main__":
    unittest.main()
