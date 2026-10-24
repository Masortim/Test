"""Меню «Пуск», чужой профиль и мусор в профиле пользователя.

Жалоба, которую закрывают эти тесты:

* после запуска Portablizer «от имени администратора» сломался кэш меню
  «Пуск» Windows 11;
* в ``C:\\Users\\<user>\\`` появились десятки временных каталогов;
* в Диспетчере задач непонятно, какую программу запускает
  ``LaunchPortable.exe``, и процесс не исчезает после закрытия программы.

Проверяется не «на словах», а на поведении: какие секции реестра нельзя
импортировать, какие ветки не попадают в снимок, что удаляет уборка мусора и
какое имя получает копия лончера.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as entry  # noqa: E402
from portablizer.core import registry as reg  # noqa: E402
from portablizer.core import startmenu  # noqa: E402
from portablizer.core.portablizer import (  # noqa: E402
    Portablizer, _cleanup_stale_temp_dirs,
)


class ShellRegistryProtectionTests(unittest.TestCase):
    """Ветки оболочки не должны ни захватываться, ни импортироваться."""

    def test_start_menu_keys_are_volatile(self) -> None:
        for key in (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPins",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartCache",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Start2",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        ):
            self.assertTrue(reg.is_volatile(key), key)

    def test_start_menu_changes_never_reach_the_diff(self) -> None:
        key = (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer"
               r"\StartPage2")
        before = {key: {"Pinned": (reg.REG_BINARY, repr(b"old"))}}
        after = {key: {"Pinned": (reg.REG_BINARY, repr(b"new"))}}
        diff = reg.compute_diff(before, after)
        self.assertTrue(diff.is_empty())

    def test_app_settings_are_still_captured(self) -> None:
        key = r"HKCU\Software\Vendor\App"
        diff = reg.compute_diff({}, {key: {"x": (reg.REG_SZ, repr("1"))}})
        self.assertEqual(diff.touched_keys, [key])

    def test_launcher_drops_shell_sections_before_import(self) -> None:
        text = (
            "Windows Registry Editor Version 5.00\n\n"
            "[HKEY_CURRENT_USER\\Software\\Vendor\\App]\n"
            '"Setting"="1"\n\n'
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion"
            "\\Explorer\\StartPage2]\n"
            '"Pinned"="broken"\n\n'
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion"
            "\\Explorer\\User Shell Folders]\n"
            '"Personal"="D:\\\\elsewhere"\n'
        )
        cleaned, dropped = entry.sanitize_reg_text(text)
        self.assertIn("Vendor", cleaned)
        self.assertIn("Setting", cleaned)
        self.assertNotIn("StartPage2", cleaned)
        self.assertNotIn("User Shell Folders", cleaned)
        self.assertEqual(len(dropped), 2)

    def test_sections_of_other_hives_are_kept(self) -> None:
        text = ("Windows Registry Editor Version 5.00\n\n"
                "[HKEY_LOCAL_MACHINE\\Software\\Vendor\\App]\n"
                '"Old"="1"\n')
        cleaned, dropped = entry.sanitize_reg_text(text)
        self.assertIn("HKEY_LOCAL_MACHINE", cleaned)
        self.assertEqual(dropped, [])

    def test_import_of_a_shell_only_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "portable.reg"
            source.write_text(
                "Windows Registry Editor Version 5.00\n\n"
                "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion"
                "\\Explorer\\StartPins]\n\"x\"=\"y\"\n",
                encoding="utf-16")
            result = entry._unpacked_reg(source, root / "runtime", root, 0)
            # Импортировать нечего — возвращается None, и лончер НЕ вызывает
            # reg import. Раньше в этом случае импортировался исходный файл,
            # а он как раз и содержит опасные секции.
            self.assertIsNone(result)

    def test_snapshot_can_skip_the_user_hive(self) -> None:
        """Сборка под чужим пользователем не снимает HKCU."""
        import inspect

        self.assertIn("include_user", inspect.signature(reg.snapshot).parameters)


class PortableRegistrySanitizeTests(unittest.TestCase):
    """Старый portable.reg нельзя импортировать «как есть»."""

    def test_shell_sections_are_removed_from_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "portable.reg").write_text(
                "Windows Registry Editor Version 5.00\n\n"
                "[HKEY_CURRENT_USER\\Software\\Vendor\\App]\n"
                '"Setting"="1"\n\n'
                "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
                "\\CurrentVersion\\Explorer\\StartPage2]\n"
                '"Pinned"="broken"\n',
                encoding="utf-16")

            cleaned = entry.sanitize_portable_registry_files(root)
            self.assertEqual(len(cleaned), 1)
            text = (root / "portable.reg").read_text(encoding="utf-16")
            self.assertIn("Vendor", text)
            self.assertNotIn("StartPage2", text)

    def test_registry_with_only_shell_sections_is_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "portable_machine.reg").write_text(
                "Windows Registry Editor Version 5.00\n\n"
                "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
                "\\CurrentVersion\\Explorer\\StartPins]\n"
                '"x"="y"\n',
                encoding="utf-16")

            cleaned = entry.sanitize_portable_registry_files(root)
            self.assertEqual(len(cleaned), 1)
            self.assertFalse((root / "portable_machine.reg").exists())

    def test_clean_file_is_left_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = ("Windows Registry Editor Version 5.00\n\n"
                       "[HKEY_CURRENT_USER\\Software\\Vendor\\App]\n"
                       '"Setting"="1"\n')
            path = root / "portable.reg"
            path.write_text(payload, encoding="utf-16")
            before = path.stat().st_mtime_ns

            self.assertEqual(entry.sanitize_portable_registry_files(root), [])
            self.assertEqual(path.stat().st_mtime_ns, before)


class CliRepairCommandTests(unittest.TestCase):
    def test_subcommand_is_registered(self) -> None:
        from portablizer.cli import build_parser

        ns = build_parser().parse_args(["repair-start-menu"])
        self.assertEqual(ns.command, "repair-start-menu")

    def test_repair_reports_non_windows_honestly(self) -> None:
        import contextlib
        import io

        from portablizer.cli import cmd_repair_start_menu, build_parser

        if sys.platform.startswith("win"):
            self.skipTest("проверка относится к не-Windows")
        ns = build_parser().parse_args(["repair-start-menu"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cmd_repair_start_menu(ns), 1)


class SwitchedUserTests(unittest.TestCase):
    def test_no_warning_outside_windows(self) -> None:
        from portablizer.core import elevate

        if elevate.IS_WINDOWS:
            self.skipTest("проверка относится к не-Windows")
        self.assertEqual(elevate.switched_user_warning(), "")
        self.assertTrue(elevate.same_user_as_shell())


class StartMenuRepairTests(unittest.TestCase):
    def test_portable_documents_marker(self) -> None:
        self.assertTrue(startmenu.redirect_marker(
            r"D:\Portable\App_Portable\PortableData\User\Documents"))
        self.assertFalse(startmenu.redirect_marker(
            r"C:\Users\me\Documents"))

    def test_missing_target_is_detected(self) -> None:
        missing = os.path.join(tempfile.gettempdir(),
                               "no-such-portable", "PortableData", "User",
                               "Documents")
        self.assertTrue(startmenu.documents_folder_broken(missing))

    def test_existing_target_is_not_a_problem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "PortableData", "User", "Documents")
            os.makedirs(path)
            self.assertFalse(startmenu.documents_folder_broken(path))

    def test_ordinary_missing_folder_is_not_touched(self) -> None:
        # Отключённый сетевой диск — не наша поломка.
        self.assertFalse(startmenu.documents_folder_broken(
            r"Z:\Archive\Documents"))

    def test_cache_reset_removes_only_temporary_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package = os.path.join(
                tmp, "Packages",
                "Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy")
            temp_state = os.path.join(package, "TempState")
            local_state = os.path.join(package, "LocalState")
            os.makedirs(temp_state)
            os.makedirs(local_state)
            for name in ("cache1.bin", "cache2.bin"):
                Path(temp_state, name).write_bytes(b"x")
            Path(local_state, "pinned.json").write_text("{}", encoding="utf-8")

            removed = startmenu.clear_start_menu_cache(tmp)
            self.assertEqual(removed, 2)
            self.assertTrue(os.path.isdir(local_state))
            self.assertTrue(Path(local_state, "pinned.json").is_file())

    def test_repair_is_a_noop_outside_windows(self) -> None:
        if startmenu.IS_WINDOWS:
            self.skipTest("проверка относится к не-Windows")
        self.assertEqual(startmenu.repair_start_menu(), [])


class TaskManagerNameTests(unittest.TestCase):
    """Имя процесса в Диспетчере задач должно говорить, что запущено."""

    def test_name_is_built_from_the_app(self) -> None:
        self.assertEqual(Portablizer._task_manager_name(
            r"D:\Portable\Ollama_Portable"), "Launch Ollama")
        self.assertEqual(Portablizer._task_manager_name(
            "C:/p/SketchUp Pro 2026_Portable"), "Launch SketchUp Pro 2026")

    def test_invalid_characters_are_removed(self) -> None:
        self.assertEqual(Portablizer._task_manager_name(
            "/tmp/Weird: name*_Portable"), "Launch Weird name")

    def test_named_copy_is_created_next_to_the_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            portable = os.path.join(tmp, "My App_Portable")
            app = os.path.join(portable, "App")
            os.makedirs(app)
            launcher = os.path.join(app, "LaunchPortable.exe")
            Path(launcher).write_bytes(b"MZ" + b"\x00" * 64)

            engine = Portablizer(logger=_quiet_logger(), progress=None)
            rel = engine._copy_named_exe_launcher(portable, launcher)

            self.assertTrue(rel)
            self.assertEqual(rel, os.path.join("App", "Launch My App.exe"))
            self.assertTrue(os.path.isfile(os.path.join(portable, rel)))
            # Оригинальный лончер остаётся: его ищут Launch.bat/VBS/скрипты.
            self.assertTrue(os.path.isfile(launcher))

    def test_named_copy_never_overwrites_the_program(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            portable = os.path.join(tmp, "Game_Portable")
            app = os.path.join(portable, "App")
            os.makedirs(app)
            launcher = os.path.join(app, "LaunchPortable.exe")
            Path(launcher).write_bytes(b"MZ" + b"\x00" * 64)
            real = os.path.join(app, "Game.exe")
            Path(real).write_bytes(b"real program")

            engine = Portablizer(logger=_quiet_logger(), progress=None)
            rel = engine._copy_named_exe_launcher(portable, launcher)

            self.assertNotEqual(os.path.basename(rel).casefold(), "game.exe")
            self.assertEqual(Path(real).read_bytes(), b"real program")


class ElevationMemoryTests(unittest.TestCase):
    """Отказ от UAC не должен превращаться в вопрос при каждом запуске."""

    def test_refusal_is_remembered_and_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertFalse(entry.elevation_recently_refused(root))
            entry.mark_elevation_refused(root, "declined")
            self.assertTrue(entry.elevation_recently_refused(root))
            self.assertFalse(entry.elevation_recently_refused(root, memory=0.0))
            entry.clear_elevation_refusal(root)
            self.assertFalse(entry.elevation_recently_refused(root))

    def test_stamp_from_a_slightly_wrong_clock_is_still_recent(self) -> None:
        """Часы могли уйти назад после записи — отметка всё равно свежая.

        На Windows-раннере служба времени уже подводила часы между записью
        файла и чтением, и лончер снова спрашивал UAC в тот же запуск.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry.mark_elevation_refused(root, "declined")
            entry._elevation_stamp(root).write_text(
                json.dumps({"when": time.time() + 30.0, "reason": "declined"}),
                encoding="utf-8")
            self.assertTrue(entry.elevation_recently_refused(root))
            self.assertFalse(entry.elevation_recently_refused(root, memory=0.0))

    def test_stamp_is_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry.mark_elevation_refused(root, "timeout")
            data = json.loads(entry._elevation_stamp(root).read_text(
                encoding="utf-8"))
            self.assertEqual(data["reason"], "timeout")
            self.assertGreater(data["when"], 0)

    def test_elevated_launch_is_bounded(self) -> None:
        """Ожидание повышенной копии не должно быть бесконечным."""
        import inspect

        source = inspect.getsource(entry._run_elevated)
        self.assertIn("timeout_ms", inspect.signature(
            entry._run_elevated).parameters)
        self.assertNotIn("0xFFFFFFFF", source)


class StaleTempCleanupTests(unittest.TestCase):
    """Каталоги, из-за которых в C:\\Users\\<user> появлялся мусор."""

    def test_old_portablizer_dirs_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            removed_dir = Path(tmp, "Portablizer-Game-Temp")
            removed_dir.mkdir()
            Path(removed_dir, "leftover.bin").write_bytes(b"x")
            fresh_dir = Path(tmp, "Portablizer-New-Temp")
            fresh_dir.mkdir()
            unrelated = Path(tmp, "MyDocuments")
            unrelated.mkdir()

            old = time.time() - 2 * 3600
            os.utime(removed_dir, (old, old))
            os.utime(unrelated, (old, old))

            removed = _cleanup_stale_temp_dirs(None, roots=[tmp],
                                               min_age=3600, now=time.time())
            self.assertEqual([os.path.basename(p) for p in removed],
                             ["Portablizer-Game-Temp"])
            self.assertFalse(removed_dir.exists())
            self.assertTrue(fresh_dir.exists())
            self.assertTrue(unrelated.exists())

    def test_current_unpack_directory_is_never_deleted(self) -> None:
        own = getattr(sys, "_MEIPASS", "")
        if not own or not os.path.isdir(own):
            self.skipTest("тест имеет смысл только внутри собранного EXE")
        self.assertTrue(entry._mine_temp_directory(own))


def _quiet_logger():
    from portablizer.core.logutil import Logger

    return Logger()


if __name__ == "__main__":
    unittest.main()
