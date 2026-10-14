"""Распаковка установщика БЕЗ запуска: что делать, когда он падает.

Регрессия, ради которой написан этот модуль:

    Установщик, который аварийно завершается (0xC000041D и родственные
    коды), не отвечает ни на один ключ тишины — запускать его снова
    бессмысленно. Но Inno Setup и NSIS — это обычные упакованные контейнеры:
    установленный на компьютере 7-Zip читает их напрямую, не выполняя код
    установщика. Системе это не делает ничего, прав администратора не
    требует и реестр не трогает.

Проверяется, что:
  * распаковщик ищется там, где он реально бывает (каталоги 7-Zip, затем
    PATH), и что его отсутствие — не ошибка, а честное «нечем»;
  * файлы программы достаются из ``{app}``, а ``{tmp}``/``{sys}`` и прочие
    «корни» Inno в портатив не попадают: подменять системные файлы чужого ПК
    — это не портативность;
  * предупреждение распаковщика (код 1 у 7-Zip) не считается отказом, а
    настоящая ошибка объясняется словами.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import unpacker as unpacker_mod


def _file(path: Path, content: str = "x") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return str(path)


class FindUnpackerTests(unittest.TestCase):
    def test_standard_7zip_folder_is_found(self):
        with tempfile.TemporaryDirectory() as temp:
            seven = _file(Path(temp, "7-Zip", "7z.exe"))
            found = unpacker_mod.find_unpacker(
                env={"ProgramFiles": temp}, which=lambda name: None,
                isfile=os.path.isfile)
            self.assertEqual(found, seven)

    def test_unpacker_from_path_is_found_when_not_installed_normally(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = _file(Path(temp, "7za.exe"))
            found = unpacker_mod.find_unpacker(
                env={}, which=lambda name: portable if name == "7za.exe" else None,
                isfile=os.path.isfile)
            self.assertEqual(found, portable)

    def test_absent_unpacker_is_not_an_error(self):
        self.assertEqual(unpacker_mod.find_unpacker(env={},
                                                    which=lambda name: None,
                                                    isfile=lambda p: False),
                         "")


class UnpackerCommandTests(unittest.TestCase):
    def test_command_extracts_into_the_work_folder(self):
        cmd = unpacker_mod.unpacker_argv("/usr/bin/7z", "setup.exe",
                                         "/tmp/work")
        self.assertEqual(cmd[0], "/usr/bin/7z")
        self.assertIn("x", cmd)
        self.assertIn("-y", cmd)
        self.assertIn("-o/tmp/work", cmd)
        # «--» закрывает разбор ключей: имя установщика может начинаться с
        # дефиса, и тогда 7-Zip принял бы его за свой параметр.
        self.assertEqual(cmd[-1], "setup.exe")
        self.assertEqual(cmd[-2], "--")


class PromotePayloadTests(unittest.TestCase):
    def test_app_root_becomes_the_portable_app_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp, "work")
            app = Path(temp, "app")
            app.mkdir()
            _file(work / "{app}" / "Hatred.exe", "game")
            _file(work / "{app}" / "data" / "level.pak", "level")
            copied = unpacker_mod.promote_payload(str(work), str(app))
            self.assertEqual(copied, 2)
            self.assertTrue((app / "Hatred.exe").is_file())
            self.assertTrue((app / "data" / "level.pak").is_file())

    def test_other_inno_roots_are_not_moved_into_the_portable(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp, "work")
            app = Path(temp, "app")
            app.mkdir()
            _file(work / "{app}" / "Game.exe")
            _file(work / "{tmp}" / "setup.tmp")
            _file(work / "{sys}" / "kernel32.dll", "системная библиотека")
            _file(work / "{userappdata}" / "settings.ini")
            unpacker_mod.promote_payload(str(work), str(app))
            self.assertTrue((app / "Game.exe").is_file())
            self.assertFalse((app / "setup.tmp").exists())
            self.assertFalse((app / "kernel32.dll").exists())
            self.assertFalse((app / "settings.ini").exists())

    def test_flat_archive_is_moved_as_is(self):
        """NSIS и простые SFX раскладывают файлы без «корней» Inno."""
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp, "work")
            app = Path(temp, "app")
            app.mkdir()
            _file(work / "Game.exe")
            _file(work / "assets" / "a.pak")
            copied = unpacker_mod.promote_payload(str(work), str(app))
            self.assertEqual(copied, 2)
            self.assertTrue((app / "Game.exe").is_file())
            self.assertTrue((app / "assets" / "a.pak").is_file())

    def test_existing_files_are_replaced_not_duplicated(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp, "work")
            app = Path(temp, "app")
            app.mkdir()
            _file(Path(app, "Game.exe"), "старый огрызок")
            _file(work / "{app}" / "Game.exe", "новая версия")
            unpacker_mod.promote_payload(str(work), str(app))
            with open(Path(app, "Game.exe"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "новая версия")

    def test_missing_folders_are_not_an_error(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(unpacker_mod.promote_payload(
                os.path.join(temp, "нет"), temp), 0)


class UnpackInstallerTests(unittest.TestCase):
    def _setup(self, temp: str):
        installer = _file(Path(temp, "setup_hatred.exe"), "installer")
        app = Path(temp, "app")
        app.mkdir()
        work = Path(temp, "work")
        return installer, app, work

    def test_successful_unpack_promotes_the_program(self):
        with tempfile.TemporaryDirectory() as temp:
            installer, app, work = self._setup(temp)

            def runner(cmd, timeout):
                target = [a for a in cmd if a.startswith("-o")][0][2:]
                _file(Path(target, "{app}", "Hatred.exe"))
                _file(Path(target, "{tmp}", "setup.tmp"))
                return 0, "Everything is Ok"

            ok, message = unpacker_mod.unpack_installer(
                "/usr/bin/7z", installer, str(app), str(work), runner=runner)
            self.assertTrue(ok, message)
            self.assertTrue((app / "Hatred.exe").is_file())
            self.assertFalse((app / "setup.tmp").exists())

    def test_warning_code_is_not_a_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            installer, app, work = self._setup(temp)

            def runner(cmd, timeout):
                target = [a for a in cmd if a.startswith("-o")][0][2:]
                _file(Path(target, "{app}", "Hatred.exe"))
                return 1, "Warning: some files could not be unpacked"

            ok, _message = unpacker_mod.unpack_installer(
                "/usr/bin/7z", installer, str(app), str(work), runner=runner)
            self.assertTrue(ok)

    def test_error_code_is_explained_in_words(self):
        with tempfile.TemporaryDirectory() as temp:
            installer, app, work = self._setup(temp)
            ok, message = unpacker_mod.unpack_installer(
                "/usr/bin/7z", installer, str(app), str(work),
                runner=lambda cmd, t: (2, "Can not open the file as archive"))
            self.assertFalse(ok)
            self.assertIn("кодом 2", message)
            self.assertIn("Can not open the file", message)

    def test_archive_without_program_files_is_reported_honestly(self):
        with tempfile.TemporaryDirectory() as temp:
            installer, app, work = self._setup(temp)

            def runner(cmd, timeout):
                target = [a for a in cmd if a.startswith("-o")][0][2:]
                _file(Path(target, "{tmp}", "setup.tmp"))
                return 0, ""

            ok, message = unpacker_mod.unpack_installer(
                "/usr/bin/7z", installer, str(app), str(work), runner=runner)
            self.assertFalse(ok)
            self.assertIn("не нашлось файлов программы", message)

    def test_absent_unpacker_and_missing_installer_are_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "app")
            app.mkdir()
            ok, message = unpacker_mod.unpack_installer(
                "", "setup.exe", str(app), str(Path(temp, "work")))
            self.assertFalse(ok)
            self.assertIn("не найден", message)
            ok, message = unpacker_mod.unpack_installer(
                "/usr/bin/7z", os.path.join(temp, "нет.exe"), str(app),
                str(Path(temp, "work")), runner=lambda cmd, t: (0, ""))
            self.assertFalse(ok)
            self.assertIn("недоступен", message)

    def test_runner_crash_does_not_break_the_build(self):
        with tempfile.TemporaryDirectory() as temp:
            installer, app, work = self._setup(temp)

            def broken_runner(cmd, timeout):
                raise OSError("7z не запускается")

            ok, message = unpacker_mod.unpack_installer(
                "/usr/bin/7z", installer, str(app), str(work),
                runner=broken_runner)
            self.assertFalse(ok)
            self.assertIn("не запустился", message)


if __name__ == "__main__":
    unittest.main()
