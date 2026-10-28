"""Тесты 1.32.0: почему запуск съедал 461-551 секунду (шаг `saves`)."""

import json
import os
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as entry

CURSOR_KEYS = [
    r"Software\Classes\Cursor.plist\shell\open",
    r"Software\Classes\Cursor.py\shell\open\command",
    r"Software\Classes\Cursor.r\shell\open",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    r"\{DADADADA-ADAD-ADAD-ADAD-ADADADADADAD}_is1",
]

CURSOR_REG = (
    "Windows Registry Editor Version 5.00\r\n\r\n"
    "[HKEY_CURRENT_USER\\Software\\Classes\\Cursor.py\\shell\\open\\command]\r\n"
    "\"@\"=\"\\\"%PORTABLE_ROOT%\\\\App\\\\Cursor.exe\\\" \\\"%1\\\"\"\r\n"
    "[HKEY_CURRENT_USER\\Software\\Cursor\\UserData]\r\n"
    "\"dir\"=\"%LOCALAPPDATA%\\\\Programs\\\\cursor\"\r\n"
)


def _no_app_reads(self: Path, *args, **kwargs):
    """``read_bytes`` для теста: файлы App читать не нужно, остальные — можно."""
    if "App" in str(self).replace(os.sep, "/").split("/"):
        raise AssertionError("файл App прочитан: " + str(self))
    with open(self, "rb") as handle:
        return handle.read()


def fake_pe(size: int, tail: bytes = b"") -> bytes:
    """PE-заголовок без подписи: проходит проверку `_pe_unsigned_checksum_offset`."""
    data = bytearray(b"\x00" * size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x80 + 24, 0x20B)
    return bytes(data) + tail


def make_tree(temp: Path, *, reg_text: str, keys, files=("Cursor.dll",),
              app_name="Cursor") -> Path:
    root = temp / "Cursor_Portable"
    app = root / "App"
    app.mkdir(parents=True)
    (root / "PortableData").mkdir()
    for name in files:
        (app / name).write_bytes(fake_pe(4096))
    if reg_text is not None:
        (root / "portable.reg").write_text(reg_text, encoding="utf-16",
                                           newline="")
    return root


def cursor_config(keys=CURSOR_KEYS):
    return {"app_name": "Cursor",
            "registry": {"enabled": True, "keys": list(keys),
                         "file": "portable.reg",
                         "machine_file": "portable_machine.reg"}}


class DriveRootTokenTests(unittest.TestCase):
    """Слова из путей реестра не должны становиться «папками в корне диска».

    Именно из-за них проход по всем exe/dll выполнялся 23 раза за запуск:
    каждый токен — отдельный регулярный поиск по каждому файлу папки App.
    """

    def test_registry_path_words_are_not_folders(self):
        for word in ("shell", "open", "Classes", "command", "CurrentVersion",
                     "Uninstall", "Microsoft", "Icon"):
            self.assertFalse(entry._drive_root_token_ok(word), word)

    def test_file_class_names_are_not_folders(self):
        for word in ("Cursor.py", "Cursor.plist", "Cursor.r", "Cursor.pm6"):
            self.assertFalse(entry._drive_root_token_ok(word), word)

    def test_guid_record_names_are_not_folders(self):
        self.assertFalse(entry._drive_root_token_ok(
            "{DADADADA-ADAD-ADAD-ADAD-ADADADADADAD}_is1"))

    def test_real_program_folders_are_kept(self):
        for word in ("Multitran", "FreeTrainSimulator", "GTA San Andreas"):
            self.assertTrue(entry._drive_root_token_ok(word), word)

    def test_a_cursor_like_config_yields_a_single_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_tree(Path(temp), reg_text=CURSOR_REG, keys=CURSOR_KEYS)
            session = entry.DriveRootDataSession(root, cursor_config())
            self.assertEqual(session._candidate_folders(), ["Cursor"])


class DriveRootScanTests(unittest.TestCase):
    """Проход по файлам App должен быть почти бесплатным и однократным."""

    def test_nothing_is_read_when_the_registry_has_no_drive_path(self):
        """Cursor в корень диска не пишет — файлы App не читаются вовсе."""
        with tempfile.TemporaryDirectory() as temp:
            root = make_tree(Path(temp), reg_text=CURSOR_REG, keys=CURSOR_KEYS,
                             files=("Cursor.dll", "dxcompiler.dll",
                                    "libGLESv2.dll"))
            session = entry.DriveRootDataSession(root, cursor_config())
            with mock.patch.object(Path, "read_bytes",
                                   autospec=True,
                                   side_effect=_no_app_reads) as read:
                started = time.perf_counter()
                report = session.before()
                spent = time.perf_counter() - started
            self.assertEqual([line for line in report if "neutralized" in line],
                             [])
            self.assertLess(spent, 1.0)
            self.assertFalse([call for call in read.call_args_list
                              if "App" in str(call)])

    def test_a_hardcoded_drive_path_is_still_neutralized(self):
        """Multitran-подобный случай: `C:\\Multitran` в реестре -> правка exe."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "Multitran_Portable"
            (root / "App").mkdir(parents=True)
            (root / "PortableData").mkdir()
            exe = root / "App" / "mt.exe"
            exe.write_bytes(fake_pe(4096, b"C:\\Multitran\x00"))
            (root / "portable.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Multitran]\r\n"
                "\"Path\"=\"C:\\\\Multitran\"\r\n",
                encoding="utf-16", newline="")
            cfg = {"app_name": "Multitran",
                   "registry": {"enabled": True, "keys": [],
                                "file": "portable.reg", "machine_file": ""}}
            session = entry.DriveRootDataSession(root, cfg)
            report = session.before()
            self.assertTrue(any("neutralized" in line for line in report), report)
            self.assertIn(b"..\\Multitran", exe.read_bytes())

    def test_a_checked_file_is_not_read_again(self):
        """Повторный запуск не перечитывает гигабайты папки App."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "Multitran_Portable"
            (root / "App").mkdir(parents=True)
            (root / "PortableData").mkdir()
            (root / "App" / "mt.exe").write_bytes(
                fake_pe(4096, b"C:\\Multitran\x00"))
            (root / "App" / "other.dll").write_bytes(fake_pe(4096))
            (root / "portable.reg").write_text(
                "[HKEY_CURRENT_USER\\Software\\Multitran]\r\n"
                "\"Path\"=\"C:\\\\Multitran\"\r\n",
                encoding="utf-16", newline="")
            cfg = {"app_name": "Multitran",
                   "registry": {"enabled": True, "keys": [],
                                "file": "portable.reg", "machine_file": ""}}
            session = entry.DriveRootDataSession(root, cfg)
            session.before()
            stamp = json.loads(
                (root / "PortableData" / "drive-root-patch.json").read_text(
                    encoding="utf-8"))
            self.assertEqual(sorted(stamp["files"]),
                             ["App/mt.exe", "App/other.dll"])
            # Второй запуск: ни один файл App не читается с диска.
            with mock.patch.object(Path, "read_bytes", autospec=True,
                                   side_effect=_no_app_reads) as read:
                session.before()
            self.assertFalse([call for call in read.call_args_list
                              if "App" in str(call)])

    def test_a_changed_file_is_checked_again(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "Multitran_Portable"
            (root / "App").mkdir(parents=True)
            (root / "PortableData").mkdir()
            exe = root / "App" / "mt.exe"
            exe.write_bytes(fake_pe(4096, b"C:\\Multitran\x00"))
            (root / "portable.reg").write_text(
                "\"Path\"=\"C:\\\\Multitran\"\r\n", encoding="utf-16",
                newline="")
            cfg = {"app_name": "Multitran",
                   "registry": {"enabled": True, "keys": [],
                                "file": "portable.reg", "machine_file": ""}}
            entry.DriveRootDataSession(root, cfg).before()
            # Программа обновилась — файл другой, его надо проверить заново.
            exe.write_bytes(fake_pe(4096, b"C:\\Multitran\x00"))
            stat = exe.stat()
            os.utime(exe, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
            session = entry.DriveRootDataSession(root, cfg)
            self.assertEqual(
                session._neutralize_app_binaries_and_configs(
                    session._justified_tokens(session._candidate_folders())), 1)

    def test_diagnose_describes_the_step(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_tree(Path(temp), reg_text=CURSOR_REG, keys=CURSOR_KEYS)
            lines = entry.DriveRootDataSession(root, cursor_config()).describe()
            self.assertTrue(any("папки в корне диска: Cursor" in line
                                for line in lines), lines)


class ElevationTests(unittest.TestCase):
    """UAC не должен задерживать запуск программы на минуты."""

    def test_the_wait_for_uac_is_short(self):
        self.assertLessEqual(entry.ELEVATED_WAIT_MS, 60_000)

    def test_import_only_mode_is_a_separate_flag(self):
        self.assertTrue(entry.ELEVATION_IMPORT_ONLY.startswith("--"))

    def test_no_machine_file_imports_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_tree(Path(temp), reg_text=CURSOR_REG, keys=CURSOR_KEYS)
            cfg = cursor_config()
            with mock.patch.object(entry, "_run_log"):
                self.assertEqual(
                    entry.import_machine_registry_command(root, cfg), 0)

    def test_the_elevated_hop_imports_the_machine_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_tree(Path(temp), reg_text=CURSOR_REG, keys=CURSOR_KEYS)
            machine = root / "portable_machine.reg"
            machine.write_text(
                "[HKEY_LOCAL_MACHINE\\Software\\Cursor]\r\n"
                "\"InstallDir\"=\"C:\\\\Cursor\"\r\n",
                encoding="utf-16", newline="")
            with mock.patch.object(entry, "_run_log"), \
                    mock.patch.object(entry, "import_registry_text",
                                      return_value=True) as import_text:
                code = entry.import_machine_registry_command(
                    root, cursor_config())
            self.assertEqual(code, 0)
            self.assertEqual(import_text.call_count, 1)

    def test_a_failed_import_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_tree(Path(temp), reg_text=CURSOR_REG, keys=CURSOR_KEYS)
            (root / "portable_machine.reg").write_text(
                "[HKEY_LOCAL_MACHINE\\Software\\Cursor]\r\n",
                encoding="utf-16", newline="")
            with mock.patch.object(entry, "_run_log"), \
                    mock.patch.object(entry, "import_registry_text",
                                      return_value=False), \
                    mock.patch.object(entry, "_reg", return_value=1):
                code = entry.import_machine_registry_command(
                    root, cursor_config())
            self.assertEqual(code, 1)


class ElevatedFollowTests(unittest.TestCase):
    """Полный повышенный сеанс не должен запускать вторую копию программы."""

    def test_follow_window_is_longer_than_the_prompt(self):
        self.assertGreater(entry.ELEVATED_FOLLOW_MS, entry.ELEVATED_WAIT_MS / 1000)
        self.assertGreaterEqual(entry.ELEVATED_FOLLOW_MS, 3600)

    def test_the_full_session_is_followed_after_the_prompt(self):
        """``follow=True`` — ждём повышенную копию, а не стартуем вторую."""
        import inspect

        params = inspect.signature(entry._run_elevated).parameters
        self.assertIn("follow", params)
        self.assertFalse(params["follow"].default)


class MachineRegistrySkipTests(unittest.TestCase):
    """Машинный .reg без прав администратора больше не дёргается зря."""

    def test_it_is_skipped_without_elevation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_tree(Path(temp), reg_text=CURSOR_REG, keys=CURSOR_KEYS)
            machine = root / "portable_machine.reg"
            machine.write_text("[HKEY_LOCAL_MACHINE\\Software\\Cursor]\r\n",
                               encoding="utf-16", newline="")
            cfg = cursor_config()
            session = entry.RegistrySession(root, cfg)
            session.active = True
            logged = []
            with mock.patch.object(entry, "_is_elevated", return_value=False), \
                    mock.patch.object(entry, "_reg") as reg, \
                    mock.patch.object(entry, "_run_log",
                                      side_effect=lambda _root, line:
                                      logged.append(line)), \
                    mock.patch.object(session, "_snapshot_host",
                                      return_value=([], [])):
                session.apply()
            imported_paths = [str(call.args[0][1]) if len(call.args) > 1
                              else str(call.args) for call in reg.call_args_list]
            self.assertFalse([path for path in imported_paths
                              if "portable_machine.reg" in path],
                             imported_paths)
            self.assertTrue(any("needs administrator rights" in line
                                for line in logged), logged)


if __name__ == "__main__":
    unittest.main()
