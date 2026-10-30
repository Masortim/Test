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
from unittest import mock
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
            # Сравниваем разобранное значение, а не текст файла: в JSON
            # обратные слэши Windows экранированы (``\\``) и строкой пути
            # подстрока не находится.
            self.assertIn(str(root), json.loads(
                target.read_text(encoding="utf-8"))["lastRoot"])

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
            self.assertIn(str(root), json.loads(
                target.read_text(encoding="utf-8"))["lastRoot"])

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

    def test_a_live_foreign_installation_is_not_ours(self):
        """Настоящая установка той же программы остаётся нетронутой."""
        with tempfile.TemporaryDirectory() as temp:
            real = Path(temp) / "Local" / "Programs" / "cursor"
            real.mkdir(parents=True)
            (real / "Cursor.exe").write_bytes(b"MZ")
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Cursor",
                "InstallLocation": str(real),
            }
            self.assertFalse(entry._record_looks_like_this_portable(
                values, entry._record_roots(root, {}), "Cursor", "Cursor"))

    def test_a_dead_foreign_path_is_a_leftover_record(self):
        """След установки внутри портатива: путь есть, программы по нему нет."""
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Cursor",
                "InstallLocation": str(Path(temp) / "never-existed" / "cursor"),
            }
            roots = entry._record_roots(root, {})
            self.assertTrue(entry._record_is_orphan(values, roots))
            self.assertTrue(entry._record_looks_like_this_portable(
                values, roots, "Cursor", "Cursor"))

    def test_leftover_records_can_be_kept_on_request(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Cursor",
                "InstallLocation": str(Path(temp) / "never-existed" / "cursor"),
            }
            self.assertFalse(entry._record_looks_like_this_portable(
                values, entry._record_roots(root, {}), "Cursor", "Cursor",
                remove_orphans=False))

    def test_portable_profile_variables_count_as_the_portable(self):
        """%LOCALAPPDATA% внутри портатива — это путь внутрь портатива."""
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            env = entry._portable_env(root, {})
            values = {
                "DisplayName": "Cursor",
                "InstallLocation": r"%LOCALAPPDATA%\Programs\cursor",
            }
            roots = entry._record_roots(root, {})
            self.assertTrue(entry._record_points_into_portable(
                values, roots, env))
            self.assertTrue(entry._record_looks_like_this_portable(
                values, roots, "Cursor", "Cursor", extra_env=env))

    def test_a_variable_record_with_a_live_real_profile_is_kept(self):
        """%LOCALAPPDATA% раскрывается и в портатив, и в настоящий профиль.

        Если по настоящему адресу лежат файлы — программа действительно
        установлена, и запись трогать нельзя.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            real = Path(temp) / "Local" / "Programs" / "cursor"
            real.mkdir(parents=True)
            (real / "Cursor.exe").write_bytes(b"MZ")
            values = {
                "DisplayName": "Cursor",
                "InstallLocation": r"%LOCALAPPDATA%\Programs\cursor",
            }
            roots = entry._record_roots(root, {})
            env = entry._portable_env(root, {})
            with mock.patch.dict("os.environ",
                                 {"LOCALAPPDATA": str(real.parent.parent)}):
                self.assertFalse(entry._record_looks_like_this_portable(
                    values, roots, "Cursor", "Cursor", extra_env=env))
                self.assertIn("настоящую установку",
                              entry._record_reason(values, roots, env, True))

    def test_a_variable_record_without_files_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Cursor",
                "InstallLocation": r"%LOCALAPPDATA%\Programs\cursor",
            }
            roots = entry._record_roots(root, {})
            env = entry._portable_env(root, {})
            with mock.patch.dict("os.environ",
                                 {"LOCALAPPDATA": str(Path(temp) / "nowhere")}):
                self.assertTrue(entry._record_looks_like_this_portable(
                    values, roots, "Cursor", "Cursor", extra_env=env))
                self.assertIn("внутрь портатива",
                              entry._record_reason(values, roots, env, True))

    def test_a_system_component_record_is_left_alone(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp) / "Cursor_Portable")
            values = {
                "DisplayName": "Cursor",
                "SystemComponent": "1",
                "InstallLocation": str(Path(temp) / "never-existed"),
            }
            self.assertTrue(entry._record_hidden_by_system(values))
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


class _FakeKey:
    """Открытый ключ поддельного реестра: контекстный менеджер и описание."""

    def __init__(self, registry: "_FakeRegistry", hive, path: str,
                 access: int) -> None:
        self.registry = registry
        self.hive = hive
        self.path = path
        self.access = access

    def __enter__(self) -> "_FakeKey":
        return self

    def __exit__(self, *exc_info) -> None:
        return None


class _FakeRegistry:
    """Минимальный winreg: ровно те вызовы, которые делает лончер.

    Нужен, чтобы проверять уборку записи «Установленные программы» на Linux:
    правила (имя, путь, мёртвый путь, ключ из конфига сборки) от платформы не
    зависят, а живой реестр есть только на Windows.
    """

    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 1
    KEY_WRITE = 2
    DELETE = 4
    KEY_WOW64_64KEY = 0
    KEY_WOW64_32KEY = 0
    REG_SZ = 1

    def __init__(self, entries) -> None:
        #: (куст, полный путь ключа) -> {имя значения: значение}
        self.entries = {key: dict(values) for key, values in entries.items()}

    def _names(self, hive, path: str):
        prefix = path + "\\"
        names = []
        for (entry_hive, entry_path) in self.entries:
            if entry_hive == hive and entry_path.startswith(prefix):
                names.append(entry_path[len(prefix):])
        return sorted(names)

    def OpenKey(self, hive, path: str, reserved: int = 0, access: int = 0):
        full = (hive, path)
        if full in self.entries:
            return _FakeKey(self, hive, path, access)
        if self._names(hive, path):
            return _FakeKey(self, hive, path, access)
        raise FileNotFoundError(path)

    def EnumKey(self, key: _FakeKey, index: int) -> str:
        names = self._names(key.hive, key.path)
        if index >= len(names):
            raise OSError("no more data")
        return names[index]

    def EnumValue(self, key: _FakeKey, index: int):
        values = list(self.entries[(key.hive, key.path)].items())
        if index >= len(values):
            raise OSError("no more data")
        name, value = values[index]
        return name, value, self.REG_SZ

    def DeleteKey(self, key: _FakeKey, name: str) -> None:
        full = (key.hive, key.path + "\\" + name)
        if full not in self.entries:
            raise FileNotFoundError(name)
        del self.entries[full]


class InstalledEntryRemovalTests(unittest.TestCase):
    """Запись «Cursor» из Панели управления действительно уходит."""

    UNINSTALL = entry.UNINSTALL_KEY_PATH

    def setUp(self) -> None:
        self._real_winreg = entry._winreg
        self._real_is_windows = entry.IS_WINDOWS

    def tearDown(self) -> None:
        entry._winreg = self._real_winreg
        entry.IS_WINDOWS = self._real_is_windows

    def _portable(self, temp: str) -> Path:
        return make_portable(Path(temp) / "Cursor_Portable")

    def _install_fake(self, entries) -> _FakeRegistry:
        registry = _FakeRegistry(entries)
        entry._winreg = lambda: registry
        entry.IS_WINDOWS = True
        return registry

    def test_a_leftover_cursor_record_is_removed(self):
        """Так выглядит настоящая причина: путь записи никогда не существовал."""
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            key = (self.UNINSTALL + "\\{6F1E}_is1")
            registry = self._install_fake({("HKCU", key): {
                "DisplayName": "Cursor",
                "Inno Setup: App Path": (
                    r"C:\Users\me\AppData\Local\Programs\cursor"),
                "InstallLocation": (
                    r"C:\Users\me\AppData\Local\Programs\cursor"),
            }})

            lines, needs_admin = entry.remove_portable_install_records(
                root, {"app_name": "Cursor"})

            self.assertFalse(needs_admin)
            self.assertEqual(registry.entries, {})
            self.assertIn("удалена", " ".join(lines))

    def test_a_live_cursor_installation_survives(self):
        with tempfile.TemporaryDirectory() as temp:
            real = Path(temp) / "Programs" / "cursor"
            real.mkdir(parents=True)
            (real / "Cursor.exe").write_bytes(b"MZ")
            root = self._portable(temp)
            key = self.UNINSTALL + "\\Cursor"
            registry = self._install_fake({("HKCU", key): {
                "DisplayName": "Cursor",
                "InstallLocation": str(real),
            }})

            entry.remove_portable_install_records(root, {"app_name": "Cursor"})

            self.assertIn(("HKCU", key), registry.entries)

    def test_a_record_without_any_path_is_removed_from_the_build_list(self):
        """Pure-MSI запись: значений с путём нет, но ключ помнит сборка."""
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            key = self.UNINSTALL + "\\{9C2A}"
            registry = self._install_fake({("HKCU", key): {
                "DisplayName": "Cursor",
                "WindowsInstaller": "1",
            }})
            cfg = {"app_name": "Cursor", "host_cleanup": {"records": [{
                "hive": "HKCU",
                "path": "Software\\Microsoft\\Windows\\CurrentVersion"
                        "\\Uninstall\\{9C2A}",
                "display": "Cursor",
            }]}}

            entry.remove_portable_install_records(root, cfg)

            self.assertEqual(registry.entries, {})

    def test_a_system_component_record_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            key = self.UNINSTALL + "\\Cursor"
            registry = self._install_fake({("HKCU", key): {
                "DisplayName": "Cursor",
                "SystemComponent": "1",
                "InstallLocation": r"C:\nowhere\cursor",
            }})

            entry.remove_portable_install_records(root, {"app_name": "Cursor"})

            self.assertIn(("HKCU", key), registry.entries)

    def test_another_program_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            key = self.UNINSTALL + "\\Notepad++"
            registry = self._install_fake({("HKCU", key): {
                "DisplayName": "Notepad++",
                "InstallLocation": str(root) + "\\App\\notepad",
            }})

            entry.remove_portable_install_records(root, {"app_name": "Cursor"})

            self.assertIn(("HKCU", key), registry.entries)

    def test_switching_the_cleanup_off_keeps_the_record(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            key = self.UNINSTALL + "\\Cursor"
            registry = self._install_fake({("HKCU", key): {
                "DisplayName": "Cursor",
                "InstallLocation": r"C:\nowhere\cursor",
            }})

            lines = entry.clean_installed_programs(
                root, {"app_name": "Cursor",
                       "host_cleanup": {"hide_installed_entry": False}})

            self.assertEqual(lines, [])
            self.assertIn(("HKCU", key), registry.entries)

    def test_diagnose_names_the_record_and_the_reason(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            key = self.UNINSTALL + "\\Cursor"
            self._install_fake({("HKCU", key): {
                "DisplayName": "Cursor 0.44.11",
                "InstallLocation": r"C:\nowhere\cursor",
            }})

            report = "\n".join(entry.describe_install_records(
                root, {"app_name": "Cursor"}))

            self.assertIn("Cursor 0.44.11", report)
            self.assertIn("будет удалена", report)
            self.assertIn("отсутствуют", report)

    def test_the_manual_command_removes_a_record_by_name(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            key = self.UNINSTALL + "\\{GUID}_is1"
            registry = self._install_fake({("HKCU", key): {
                "DisplayName": "Cursor",
                "WindowsInstaller": "1",
            }})

            lines = entry.forget_installed_entry("Cursor", root,
                                                 {"app_name": "Cursor"})

            self.assertEqual(registry.entries, {})
            self.assertIn("удалена", " ".join(lines))


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
        """Живая установка той же программы не трогается даже новым ключом."""
        with tempfile.TemporaryDirectory() as temp:
            real = Path(temp) / "Programs" / "cursor"
            real.mkdir(parents=True)
            (real / "Cursor.exe").write_bytes(b"MZ")
            key = (r"HKCU\Software\Microsoft\Windows\CurrentVersion"
                   r"\Uninstall\Cursor")
            diff = reg_mod.RegistryDiff(new_keys={key})
            after = {key: {
                "DisplayName": (reg_mod.REG_SZ, repr("Cursor")),
                "InstallLocation": (reg_mod.REG_SZ, repr(str(real))),
            }}

            self.assertEqual(reg_mod.safe_uninstall_entries(
                diff, after, app_name="Cursor",
                portable_dir=r"D:\Apps\Cursor_Portable"), [])

    def test_a_new_record_with_a_dead_path_is_cleaned_by_the_builder(self):
        """Ключ появился за эту установку — он наш, даже если путь «чужой»."""
        key = (r"HKCU\Software\Microsoft\Windows\CurrentVersion"
               r"\Uninstall\{GUID}_is1")
        diff = reg_mod.RegistryDiff(new_keys={key})
        after = {key: {
            "DisplayName": (reg_mod.REG_SZ, repr("Cursor 0.44.11")),
            "InstallLocation": (
                reg_mod.REG_SZ,
                repr(r"C:\Users\me\AppData\Local\Programs\cursor")),
        }}

        entries = reg_mod.safe_uninstall_entries(
            diff, after, app_name="Cursor",
            portable_dir=r"D:\Apps\Cursor_Portable")

        self.assertEqual([item[0] for item in entries], [key])

    def test_direct_deletion_does_nothing_without_windows(self):
        if sys.platform.startswith("win"):
            self.skipTest("на Windows проверяется живой реестр")
        key = (r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion"
               r"\Uninstall\Cursor")
        self.assertEqual(reg_mod.delete_uninstall_keys([key]), ([], []))

    def test_the_build_records_the_keys_for_the_launcher(self):
        """launcher_config.json помнит ключи: их удалит лончер на месте."""
        key = (r"HKCU\Software\Microsoft\Windows\CurrentVersion"
               r"\Uninstall\{GUID}_is1")
        records = launcher_mod.installed_entry_records([key], ["Cursor"])

        self.assertEqual(records, [{
            "hive": "HKCU",
            "path": (r"Software\Microsoft\Windows\CurrentVersion"
                     r"\Uninstall\{GUID}_is1"),
            "display": "Cursor",
        }])
        payload = json.loads(launcher_mod.render_config_json(
            launcher_mod.LauncherConfig(
                app_name="Cursor", target_exe_rel="App/Cursor.exe",
                host_cleanup_records=records)))
        self.assertEqual(payload["host_cleanup"]["records"], records)
        self.assertTrue(payload["host_cleanup"]["remove_orphan_entries"])

    def test_refreshing_the_launcher_keeps_the_cleanup_settings(self):
        """«Обновить лончер» переписывает конфиг — настройки не теряются."""
        cfg = launcher_mod.LauncherConfig(
            app_name="Cursor", target_exe_rel="App/Cursor.exe",
            hide_installed_entry=False, remove_orphan_entries=False,
            host_cleanup_records=[{
                "hive": "HKCU",
                "path": (r"Software\Microsoft\Windows\CurrentVersion"
                         r"\Uninstall\{GUID}_is1"),
                "display": "Cursor",
            }])
        restored = launcher_mod.config_from_dict(
            json.loads(launcher_mod.render_config_json(cfg)))

        self.assertFalse(restored.hide_installed_entry)
        self.assertFalse(restored.remove_orphan_entries)
        self.assertEqual(restored.host_cleanup_records,
                         cfg.host_cleanup_records)

    def test_a_key_outside_uninstall_is_never_recorded(self):
        records = launcher_mod.installed_entry_records(
            [r"HKCU\Software\Vendor\App"], ["App"])
        self.assertEqual(records, [])

    def test_the_launcher_accepts_only_uninstall_records_from_the_config(self):
        good = {
            "hive": "HKCU",
            "path": (r"Software\Microsoft\Windows\CurrentVersion"
                     r"\Uninstall\{GUID}_is1"),
        }
        bad = {"hive": "HKCU", "path": r"Software\Vendor\Run"}
        parsed = entry.configured_install_records(
            {"host_cleanup": {"records": [good, bad]}})

        self.assertEqual([item["name"] for item in parsed], ["{GUID}_is1"])
        self.assertEqual(parsed[0]["hive"], "HKEY_CURRENT_USER")


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


class _SnapshotKey:
    """Ключ поддельного winreg для снимка реестра."""

    def __init__(self, values, children) -> None:
        self.values = values
        self.children = children

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> bool:
        return False


class _SnapshotReg:
    """Мини-реестр в памяти: только то, что нужно export_registry_text."""

    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019

    def __init__(self, tree) -> None:
        self.tree = tree
        self.opened = 0

    def _node(self, hive, path: str):
        node = self.tree.get(hive) or {}
        for part in path.split("\\"):
            node = (node.get("__children__") or {}).get(part) or {}
            if not node:
                return None
        return node

    def OpenKey(self, hive, path, reserved, access):
        self.opened += 1
        node = self._node(hive, path)
        if node is None:
            raise FileNotFoundError(path)
        return _SnapshotKey(node.get("__values__") or {}, node.get("__children__") or {})

    def EnumValue(self, key, index: int):
        items = list(key.values.items())
        if index >= len(items):
            raise OSError("no more data")
        name, (value, kind) = items[index]
        return name, value, kind

    def EnumKey(self, key, index: int):
        names = list(key.children)
        if index >= len(names):
            raise OSError("no more data")
        return names[index]


def snapshot_tree():
    return {
        "HKCU": {
            "__values__": {},
            "__children__": {
                "Software": {
                    "__values__": {},
                    "__children__": {
                        "Cursor": {
                            "__values__": {
                                "Path": (r"D:\Apps\Cursor", entry.REG_TYPE_SZ),
                                "Update": (1, entry.REG_TYPE_DWORD),
                                "Boost": (b"\x01\x02", entry.REG_TYPE_BINARY),
                                "Exe": (r"D:\Apps\Cursor\Cursor.exe",
                                        entry.REG_TYPE_EXPAND_SZ),
                            },
                            "__children__": {},
                        },
                    },
                },
            },
        },
    }


class RegistrySnapshotTests(unittest.TestCase):
    """Реестр снимается одним проходом winreg, а не процессом на каждый ключ."""

    def test_snapshot_is_one_importable_document(self):
        fake = _SnapshotReg(snapshot_tree())
        with mock.patch.object(entry, "_winreg", return_value=fake):
            text = entry.export_registry_text([r"HKCU\Software\Cursor"])
        self.assertIn("Windows Registry Editor Version 5.00", text)
        self.assertIn(r"[HKEY_CURRENT_USER\Software\Cursor]", text)
        self.assertIn('"Path"="D:\\\\Apps\\\\Cursor"', text)
        self.assertIn('"Update"=dword:00000001', text)
        self.assertIn('"Boost"=hex:01,02', text)
        self.assertIn('"Exe"=hex(2):', text)
        # Строки в hex(2) — UTF-16: иначе reg import усечёт значение.
        self.assertIn("44,00,3a,00,", text.lower())

    def test_snapshot_text_parses_back_into_the_same_keys(self):
        fake = _SnapshotReg(snapshot_tree())
        with mock.patch.object(entry, "_winreg", return_value=fake):
            text = entry.export_registry_text([r"HKCU\Software\Cursor"])
        sections = entry._parse_reg_sections(text)
        self.assertIn(r"HKEY_CURRENT_USER\Software\Cursor", sections)
        self.assertEqual(sections[r"HKEY_CURRENT_USER\Software\Cursor"]["Update"],
                         "dword:00000001")

    def test_empty_key_is_kept_in_the_snapshot(self):
        tree = {"HKCU": {"__values__": {}, "__children__": {
            "Software": {"__values__": {}, "__children__": {
                "Cursor": {"__values__": {}, "__children__": {
                    "Empty": {"__values__": {}, "__children__": {}}}}}}}}}
        fake = _SnapshotReg(tree)
        with mock.patch.object(entry, "_winreg", return_value=fake):
            text = entry.export_registry_text([r"HKCU\Software\Cursor"])
        self.assertIn(r"[HKEY_CURRENT_USER\Software\Cursor\Empty]", text)

    def test_missing_key_is_skipped_quietly(self):
        fake = _SnapshotReg(snapshot_tree())
        with mock.patch.object(entry, "_winreg", return_value=fake):
            self.assertEqual(entry.export_registry_text([r"HKCU\Software\Absent"]), "")

    def test_file_is_utf16_with_crlf_and_no_leftovers(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "backup" / "all-keys.reg"
            self.assertTrue(entry.write_reg_file(target, "a\r\nb"))
            raw = target.read_bytes()
            self.assertTrue(raw.startswith(b"\xff\xfe"))
            self.assertIn("a\r\nb".encode("utf-16-le"), raw)
            self.assertEqual(list(target.parent.glob("*.tmp")), [])
            self.assertFalse(entry.write_reg_file(target, ""))

    def test_session_snapshot_replaces_one_process_per_key(self):
        """Бэкап машины — один файл и ни одного вызова reg.exe."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cfg = {"registry": {"enabled": True, "keys": [
                r"HKCU\Software\Cursor", r"HKCU\Software\Cursor2"],
                "created_keys": []}}
            session = entry.RegistrySession(root, cfg)
            session.active = True
            calls = []
            snapshot_text = (
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Cursor]\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Cursor2]\r\n")
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "export_registry_text",
                                      return_value=snapshot_text), \
                    mock.patch.object(entry, "registry_key_state",
                                      return_value=True), \
                    mock.patch.object(entry, "_reg",
                                      side_effect=lambda args: calls.append(args) or 0):
                baseline, created = session._snapshot_host()
            self.assertEqual([p.name for p in baseline],
                             [entry.REGISTRY_SNAPSHOT_NAME])
            self.assertTrue(baseline[0].is_file())
            self.assertEqual(created, [])
            self.assertEqual([c for c in calls if c[0] == "export"], [])

    def test_previous_snapshot_is_reused_instead_of_overwritten(self):
        """Снимок от упавшего сеанса — это исходное состояние машины."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cfg = {"registry": {"enabled": True, "keys": [r"HKCU\Software\Cursor"]}}
            session = entry.RegistrySession(root, cfg)
            session.active = True
            session.backup.mkdir(parents=True, exist_ok=True)
            marker = session.backup / entry.REGISTRY_SNAPSHOT_NAME
            marker.write_bytes(b"old")
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "export_registry_text") as exporter:
                baseline, _created = session._snapshot_host()
            exporter.assert_not_called()
            self.assertEqual(baseline, [marker])
            self.assertEqual(marker.read_bytes(), b"old")

    def test_created_key_is_deleted_only_if_absent_on_this_pc(self):
        """created_keys с машины сборки не заменяет состояние текущего ПК."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cfg = {"registry": {
                "enabled": True,
                "keys": [r"HKCU\Software\Cursor", r"HKCU\Software\Cursor\Install"],
                "created_keys": [r"HKCU\Software\Cursor\Install",
                                 r"HKCU\Software\Microsoft\Windows\CurrentVersion"
                                 r"\Uninstall\cursor"],
            }}
            session = entry.RegistrySession(root, cfg)
            self.assertEqual(session._split_keys(), (
                [r"HKCU\Software\Cursor"], [r"HKCU\Software\Cursor\Install"]))

            session.active = True
            session.started = True
            deleted = []
            with mock.patch.object(entry, "export_registry_text",
                                   return_value="Windows Registry Editor Version 5.00\r\n"), \
                    mock.patch.object(entry, "_pack_reg"), \
                    mock.patch.object(entry, "_reg", return_value=0), \
                    mock.patch.object(
                        entry, "registry_key_state",
                        side_effect=lambda key: key == r"HKCU\Software\Cursor"), \
                    mock.patch.object(entry, "delete_key_tree",
                                      side_effect=lambda key: deleted.append(key) or True):
                session._snapshot_host()
                session.save_and_restore()
            # Подключ исходного ключа и ключ Uninstall (его нет в списке keys).
            self.assertEqual(deleted, [r"HKCU\Software\Cursor\Install",
                                       r"HKCU\Software\Microsoft\Windows"
                                       r"\CurrentVersion\Uninstall\cursor"])


class BackgroundCleanupTests(unittest.TestCase):
    """Уборка на стороне Windows не должна задерживать появление окна."""

    def test_work_runs_and_is_logged_after_the_program_starts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "PortableData").mkdir(parents=True, exist_ok=True)
            work = entry._BackgroundWork(root, "installed programs")
            work.submit(lambda: ["removed a record", ""])
            work.wait(timeout=10)
            log = (root / "PortableData" / "launcher-run.log").read_text(
                encoding="utf-8")
            self.assertIn("installed programs: removed a record", log)

    def test_failure_in_background_is_logged_but_not_raised(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "PortableData").mkdir(parents=True, exist_ok=True)

            def boom():
                raise RuntimeError("registry is busy")

            work = entry._BackgroundWork(root, "shortcuts")
            work.submit(boom)
            work.wait(timeout=10)
            log = (root / "PortableData" / "launcher-run.log").read_text(
                encoding="utf-8")
            self.assertIn("registry is busy", log)


    def test_every_submitted_step_is_waited_for(self):
        """Оба шага (записи установки и ярлыки) доходят до конца."""
        import time as _time

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "PortableData").mkdir(parents=True, exist_ok=True)
            done = []
            work = entry._BackgroundWork(root, "installed programs")

            def first():
                _time.sleep(0.05)
                done.append("first")
                return []

            def second():
                _time.sleep(0.05)
                done.append("second")
                return []

            work.submit(first)
            work.submit(second, name="shortcuts")
            work.wait(timeout=10)
            self.assertEqual(sorted(done), ["first", "second"])


class AppRegistryCacheTests(unittest.TestCase):
    """Поиск .reg в App кэшируется: у Cursor там десятки тысяч файлов."""

    def test_second_launch_reuses_the_cached_list(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            reg_file = root / "App" / "extra" / "settings.reg"
            reg_file.parent.mkdir(parents=True, exist_ok=True)
            reg_file.write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Cursor]\r\n\"a\"=\"b\"\r\n",
                encoding="utf-16", newline="\r\n")
            entry._APP_REG_CACHE.clear()
            found = entry._discover_app_reg_files(root, {})
            self.assertEqual([path.name for path, _s, _l in found],
                             ["settings.reg"])
            cache_file = root / "PortableData" / entry.APP_REG_CACHE_NAME
            self.assertTrue(cache_file.is_file())

            # Второй запуск: файл кэша читается, дерево App не обходится.
            entry._APP_REG_CACHE.clear()
            with mock.patch.object(entry.os, "walk",
                                   side_effect=AssertionError("App was walked")):
                second = entry._discover_app_reg_files(root, {})
            self.assertEqual([path.name for path, _s, _l in second],
                             ["settings.reg"])

    def test_new_reg_file_invalidates_the_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_portable(Path(temp))
            entry._APP_REG_CACHE.clear()
            self.assertEqual(entry._discover_app_reg_files(root, {}), [])
            added = root / "App" / "later.reg"
            added.write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Cursor]\r\n\"b\"=\"c\"\r\n",
                encoding="utf-16", newline="\r\n")
            # Windows хранит время каталога с точностью ~10 мс; в тесте
            # поднимаем mtime явно, чтобы изменение было видно.
            stamp = os.stat(root / "App").st_mtime_ns
            os.utime(root / "App", ns=(stamp + 10_000_000, stamp + 10_000_000))
            entry._APP_REG_CACHE.clear()
            self.assertEqual([path.name for path, _s, _l in
                              entry._discover_app_reg_files(root, {})],
                             ["later.reg"])


class BootTimingTests(unittest.TestCase):
    """Отчёт показывает и распаковку exe: иначе «медленно» некуда отнести."""

    def test_boot_stage_comes_first_and_counts_towards_the_total(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = root / "PortableData"
            timer = entry._StageTimer(data)
            timer.add_startup(1.5)
            timer.tick("paths")
            timer.finish(root)
            payload = json.loads((data / entry.LAUNCH_TIMING_NAME)
                                 .read_text(encoding="utf-8"))
            self.assertEqual(payload["steps"][0][0], "exe boot")
            self.assertGreaterEqual(payload["total_seconds"], 1.5)
            lines = entry._last_launch_timing(data)
            self.assertIn("exe boot", "\n".join(lines))

    def test_tiny_startup_overhead_is_not_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            timer = entry._StageTimer(Path(temp))
            timer.add_startup(0.001)
            self.assertEqual(timer.steps, [])


if __name__ == "__main__":
    unittest.main()
