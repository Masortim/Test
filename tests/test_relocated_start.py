"""Портатив после переноса на другой диск: быстрый старт и чистый список приложений.

Две жалобы, ради которых появился этот модуль:

    Переношу портатив Cursor на другой диск. В «Установленные программы»
    висит «Cursor», хотя это портатив. А Launch.bat запускает Cursor
    очень-очень медленно — не в пример прямому запуску Cursor.exe.

Обе причины — в том, что лончер делал лишнюю работу при каждом запуске:

* штамп переноса помнит прежние места папки НАВСЕГДА (на них смотрит
  установщик обновления), поэтому починка путей обходила дерево и читала
  до 6000 файлов при каждом старте — включая ``node_modules``, где у
  Cursor/VS Code десятки тысяч ``package.json``;
* запись установщика в ``Uninstall`` оставалась на компьютере: портатив
  «устанавливался» сам, а после переезда ещё и указывал в никуда.

Здесь проверяется, что обход выполняется один раз на положение папки,
``node_modules`` не читается даже с конфигом старой сборки, а запись
«Установленные программы» удаляется только по доказанному пути внутрь
портатива.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as entry
from portablizer.core import launcher as launcher_mod
from portablizer.core import portablizer as portablizer_mod
from portablizer.core import registry as reg_mod
from portablizer.core import relpaths

OLD_ROOT = r"D:\Old\Cursor_Portable"
OLDER_ROOT = r"E:\Older\Cursor_Portable"


def make_portable(root: Path, previous: str = OLD_ROOT) -> Path:
    """Минимальный портатив Cursor с отметкой о переезде."""
    app = root / "App"
    (app / "resources" / "app").mkdir(parents=True, exist_ok=True)
    (app / "Cursor.exe").write_bytes(b"MZ" + b"\x00" * 2048)
    (app / "resources" / "app" / "package.json").write_text(
        '{"name": "cursor"}', encoding="utf-8")
    (app / "resources" / "app" / "product.json").write_text(
        json.dumps({"nameShort": "Cursor", "dataFolderName": ".cursor",
                    "target": "user"}), encoding="utf-8")
    data = root / "PortableData"
    data.mkdir(parents=True, exist_ok=True)
    (data / "portable-root.json").write_text(json.dumps({
        "schema": 2, "root": str(root), "previous": previous,
    }), encoding="utf-8")
    return root


def settings_file(root: Path, value: str) -> Path:
    path = (root / "PortableData" / "AppData" / "Roaming" / "Cursor" / "User"
            / "settings.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"lastRoot": value}), encoding="utf-8")
    return path


class CountingIter:
    """Считает обходы дерева: по нему видно, платит ли запуск за перенос."""

    def __init__(self) -> None:
        self.calls = 0
        self._real = entry._iter_paths_files

    def __enter__(self) -> "CountingIter":
        real = self._real

        def wrapper(root, settings, deep=False):
            self.calls += 1
            return real(root, settings, deep=deep)

        entry._iter_paths_files = wrapper
        return self

    def __exit__(self, *exc_info) -> None:
        entry._iter_paths_files = self._real


class ScanOnceTests(unittest.TestCase):
    """Обход дерева после переезда выполняется один раз, а не каждый запуск."""

    def test_the_first_launch_repairs_and_the_next_one_skips_the_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            target = settings_file(root, OLD_ROOT + r"\App\Cursor.exe")

            with CountingIter() as counter:
                first = entry.repair_paths(root, {})
            self.assertEqual(counter.calls, 1)
            self.assertTrue(first, "первый запуск обязан починить путь")
            self.assertIn(str(root), target.read_text(encoding="utf-8"))

            with CountingIter() as counter:
                second = entry.repair_paths(root, {})
            self.assertEqual(counter.calls, 0,
                             "повторный запуск не должен обходить дерево")
            self.assertEqual(second, [])

    def test_a_new_move_starts_the_scan_again(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            entry.repair_paths(root, {})

            # Папку перенесли ещё раз: в штампе новое прежнее место, а в
            # настройках — путь оттуда.
            (root / "PortableData" / "portable-root.json").write_text(
                json.dumps({"schema": 2, "root": str(root),
                            "previous": OLDER_ROOT}), encoding="utf-8")
            target = settings_file(root, OLDER_ROOT + r"\App\Cursor.exe")

            with CountingIter() as counter:
                report = entry.repair_paths(root, {})
            self.assertEqual(counter.calls, 1)
            self.assertTrue(report)
            self.assertIn(str(root), target.read_text(encoding="utf-8"))

    def test_force_rescans_on_demand(self):
        """``--repair-paths`` и обновление не полагаются на отметку."""
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            entry.repair_paths(root, {})

            with CountingIter() as counter:
                entry.repair_paths(root, {}, force=True, deep=True)
            self.assertEqual(counter.calls, 1)

    def test_stamp_keeps_the_history_for_the_updater(self):
        """Отметка «смотрели» не должна стирать прежние места папки."""
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            entry.repair_paths(root, {})

            stamp = json.loads((root / "PortableData" / "portable-root.json")
                               .read_text(encoding="utf-8"))
            self.assertEqual(stamp["root"], str(root))
            self.assertEqual(stamp["previous"], OLD_ROOT)
            self.assertEqual(stamp["scan"]["root"], str(root))


class ScanCostTests(unittest.TestCase):
    """Новые исключения действуют и на портатив, собранный прежней версией."""

    def test_node_modules_is_skipped_even_with_an_old_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            deep = (root / "PortableData" / "User" / ".cursor" / "extensions"
                    / "ext" / "node_modules" / "pkg")
            deep.mkdir(parents=True)
            for index in range(20):
                (deep / f"package{index}.json").write_text(
                    json.dumps({"root": OLD_ROOT}), encoding="utf-8")

            # Конфиг старой сборки: свой список исключений без node_modules.
            settings = entry._paths_settings(
                {"relative_paths": {"skip_dirs": ["temp", "cache"]}})
            found = list(entry._iter_paths_files(root, settings))

            self.assertFalse(
                [path for path in found if "node_modules" in str(path)],
                "node_modules не должен попадать в обход даже со старым конфигом")

    def test_total_byte_budget_stops_the_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "App"
            root.mkdir()
            for index in range(5):
                (root / f"file{index}.json").write_text("x" * 400,
                                                        encoding="utf-8")

            found = list(entry._iter_paths_files(
                root, {"max_total_bytes": 900, "max_bytes": 400}))

            self.assertEqual(len(found), 2,
                             "проход обязан остановиться на бюджете чтения")


class InstalledProgramRecordTests(unittest.TestCase):
    """«Установленные программы»: удаляется только своя запись."""

    def test_the_own_portable_path_is_recognized(self):
        root = Path(r"D:\Apps\Cursor_Portable")
        for value in (
            r"D:\Apps\Cursor_Portable\App\Cursor.exe",
            r'"D:\Apps\Cursor_Portable\App\Cursor.exe",0',
            r'"D:\Apps\Cursor_Portable\App\unins000.exe" /SILENT',
            r"d:/apps/cursor_portable/app",
        ):
            self.assertTrue(
                entry.path_points_into_portable(value, [str(root)]),
                f"не распознан свой путь: {value}")

    def test_a_separate_installation_is_left_alone(self):
        root = Path(r"D:\Apps\Cursor_Portable")
        for value in (
            r"C:\Users\me\AppData\Local\Programs\cursor\Cursor.exe",
            r"%LOCALAPPDATA%\Programs\cursor\Cursor.exe",
            r"MsiExec.exe /X{12345678-1234-1234-1234-1234567890AB}",
            r"D:\Apps\Cursor_Portable2\App\Cursor.exe",
        ):
            self.assertFalse(
                entry.path_points_into_portable(value, [str(root)]),
                f"чужая установка принята за портатив: {value}")

    def test_a_previous_location_is_also_ours(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            roots = entry._record_roots(root, {})

            self.assertTrue(entry.path_points_into_portable(
                OLD_ROOT + r"\App\Cursor.exe", roots))
            self.assertTrue(entry.path_points_into_portable(
                str(root) + r"\App\Cursor.exe", roots))

    def test_the_root_marker_marks_our_own_record(self):
        self.assertTrue(entry.path_points_into_portable(
            entry.ROOT_TOKEN + r"\App\Cursor.exe", [r"D:\Anything"]))

    def test_a_record_with_a_foreign_path_is_not_ours(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Cursor",
                "InstallLocation": r"C:\Users\me\AppData\Local\Programs\cursor",
            }
            self.assertFalse(entry._record_looks_like_this_portable(
                values, entry._record_roots(root, {}), "Cursor", "Cursor"))

    def test_another_program_inside_a_wide_folder_is_not_ours(self):
        """Портатив может лежать в D:\Apps — чужие записи это не делает нашими."""
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Notepad++",
                "InstallLocation": str(root) + r"\App\notepad",
            }
            self.assertFalse(entry._record_looks_like_this_portable(
                values, entry._record_roots(root, {}), "Cursor", "Notepad++"))

    def test_our_record_is_recognized_by_name_and_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Cursor",
                "Inno Setup: App Path": str(root) + r"\App",
            }
            self.assertTrue(entry._record_looks_like_this_portable(
                values, entry._record_roots(root, {}), "Cursor", "Cursor"))

    def test_display_name_with_a_version_still_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Cursor 0.44.11",
                "UninstallString": '"' + str(root) + r'\App\unins000.exe"',
            }
            self.assertTrue(entry._record_looks_like_this_portable(
                values, entry._record_roots(root, {}), "Cursor", "{GUID}"))

    def test_switching_the_cleanup_off_is_honoured(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            self.assertEqual(entry.clean_installed_programs(
                root, {"host_cleanup": {"hide_installed_entry": False}}), [])

    def test_nothing_happens_where_there_is_no_windows_registry(self):
        if sys.platform.startswith("win"):
            self.skipTest("на Windows проверяется живой реестр")
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            self.assertEqual(entry.portable_install_records(root, {}), [])
            self.assertEqual(entry.remove_portable_install_records(root, {}),
                             ([], False))
            self.assertEqual(entry.clean_installed_programs(root, {}), [])

    def test_uninstall_sections_never_reach_the_registry(self):
        """Старый portable.reg мог содержать запись — импорт её вырезает."""
        text = (
            "Windows Registry Editor Version 5.00\n\n"
            "[HKEY_CURRENT_USER\\Software\\Vendor\\App]\n"
            '"Setting"="1"\n\n'
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion"
            "\\Uninstall\\Cursor]\n"
            '"DisplayName"="Cursor"\n\n'
            "[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion"
            "\\Uninstall\\Cursor]\n"
            '"DisplayName"="Cursor"\n'
        )

        cleaned, dropped = entry.sanitize_reg_text(text)

        self.assertIn("Vendor", cleaned)
        self.assertIn("Setting", cleaned)
        self.assertNotIn("Uninstall", cleaned)
        self.assertEqual(len(dropped), 2)


class BuilderDefaultsTests(unittest.TestCase):
    """Установщик по умолчанию не оставляет запись «установлено»."""

    def test_cleanup_is_on_by_default(self):
        options = portablizer_mod.PortableOptions(
            installer_path="Setup.exe", output_dir="out")
        self.assertTrue(options.cleanup_host)
        self.assertTrue(launcher_mod.LauncherConfig(
            app_name="Cursor", target_exe_rel="App/Cursor.exe"
        ).hide_installed_entry)

    def test_the_config_tells_the_launcher_to_hide_the_record(self):
        payload = json.loads(launcher_mod.render_config_json(
            launcher_mod.LauncherConfig(app_name="Cursor",
                                        target_exe_rel="App/Cursor.exe")))
        self.assertTrue(payload["host_cleanup"]["hide_installed_entry"])

        off = json.loads(launcher_mod.render_config_json(
            launcher_mod.LauncherConfig(app_name="Cursor",
                                        target_exe_rel="App/Cursor.exe",
                                        hide_installed_entry=False)))
        self.assertFalse(off["host_cleanup"]["hide_installed_entry"])

    def test_package_trees_are_excluded_from_the_start(self):
        self.assertIn("node_modules", relpaths.SKIP_DIRS)
        self.assertIn("node_modules",
                      relpaths.launcher_section()["skip_dirs"])
        self.assertIn("node_modules", entry.PATHS_SKIP_DIRS)

    def test_inno_setup_app_path_counts_as_a_portable_path(self):
        """Inno (Cursor, VS Code) пишет каталог не в InstallLocation."""
        key = (r"HKCU\Software\Microsoft\Windows\CurrentVersion"
               r"\Uninstall\Cursor")
        portable = r"D:\Apps\Cursor_Portable"
        diff = reg_mod.RegistryDiff(new_keys={key})
        after = {key: {
            "DisplayName": (reg_mod.REG_SZ, repr("Cursor")),
            "Inno Setup: App Path": (
                reg_mod.REG_SZ, repr(portable + r"\App")),
        }}

        entries = reg_mod.safe_uninstall_entries(
            diff, after, app_name="Cursor", portable_dir=portable)

        self.assertEqual([item[0] for item in entries], [key])

    def test_a_separate_installation_is_not_cleaned_by_the_builder(self):
        key = (r"HKCU\Software\Microsoft\Windows\CurrentVersion"
               r"\Uninstall\Cursor")
        diff = reg_mod.RegistryDiff(new_keys={key})
        after = {key: {
            "DisplayName": (reg_mod.REG_SZ, repr("Cursor")),
            "InstallLocation": (
                reg_mod.REG_SZ, repr(r"C:\Users\me\Programs\cursor")),
        }}

        self.assertEqual(reg_mod.safe_uninstall_entries(
            diff, after, app_name="Cursor",
            portable_dir=r"D:\Apps\Cursor_Portable"), [])


class LaunchTimingTests(unittest.TestCase):
    """Замеры предстартовых шагов: по ним видно, что задерживает запуск."""

    def test_steps_are_written_to_the_journal_and_to_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = root / "PortableData"
            timer = entry._StageTimer(data)
            timer.tick("paths")
            timer.tick("registry")
            timer.finish(root)

            payload = json.loads((data / entry.LAUNCH_TIMING_NAME)
                                 .read_text(encoding="utf-8"))
            names = [name for name, _seconds in payload["steps"]]
            # Последний tick закрывается в finish(): он и есть «до старта».
            self.assertEqual(names, ["paths", "registry"])
            self.assertIn("pre-launch", (data / "launcher-run.log")
                          .read_text(encoding="utf-8"))

            lines = entry._last_launch_timing(data)
            self.assertIn("paths", "\n".join(lines))


if __name__ == "__main__":
    unittest.main()
