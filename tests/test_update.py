"""Обновление программы внутри портатива (Ollama: «перезапуск для обновления»).

Жалоба: Ollama предложила обновиться, пользователь нажал «перезапустить»,
программа зависла, после принудительного закрытия вылетала при каждом старте.

Проверяется то, что можно проверить без Windows: настоящую файловую логику
(подмена файлов, откат, журнал, перехват следов родного апдейтера), а сам
установщик заменяется двойником, который кладёт файлы в запрошенную папку.
"""
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as exe_launcher
from portablizer.core import launcher as launcher_mod
from portablizer.core import maintenance

OLLAMA_CFG = {
    "app_name": "Ollama",
    "target_exe_rel": "App/ollama app.exe",
    "data_dir_name": "PortableData",
}

OPENCODE_CFG = {
    "app_name": "OpenCode",
    "target_exe_rel": "App/OpenCode.exe",
    "data_dir_name": "PortableData",
}


def _write(path: Path, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def make_portable(tmp: str, cfg=None) -> Path:
    root = Path(tmp) / "Ollama_Portable"
    (root / "App").mkdir(parents=True)
    _write(root / "launcher_config.json", json.dumps(cfg or OLLAMA_CFG))
    _write(root / "App" / "ollama app.exe", "old-app")
    _write(root / "App" / "ollama.exe", "old-cli")
    _write(root / "App" / "lib" / "ollama" / "old.dll", "old-lib")
    _write(root / "App" / "obsolete-dir" / "a.txt", "o")
    _write(root / "App" / "LaunchPortable.exe", "launcher")
    _write(root / "App" / "Saves" / "slot1.sav", "my-save")
    _write(root / "PortableData" / "User" / ".ollama" / "id_ed25519", "key")
    return root


def make_opencode_portable(tmp: str, cfg=None) -> Path:
    root = Path(tmp) / "OpenCode_Portable"
    (root / "App").mkdir(parents=True)
    _write(root / "launcher_config.json", json.dumps(cfg or OPENCODE_CFG))
    _write(root / "App" / "OpenCode.exe", "old-app")
    _write(root / "App" / "LaunchPortable.exe", "launcher")
    _write(root / "App" / "Saves" / "slot1.sav", "my-save")
    return root


def make_lnk(path: Path, target: str) -> Path:
    """Настоящий ``.lnk`` с блоком LinkInfo — так его пишет установщик."""
    raw = str(target).encode("latin-1", errors="replace") + b"\0"
    size = 0x1C + len(raw) + 1
    info = struct.pack("<IIIIIII", size, 0x1C, 1, 0, 0x1C, 0, 0x1C + len(raw))
    info += raw + b"\0"
    header = bytearray(0x4C)
    header[0:4] = b"L\x00\x00\x00"
    header[0x14:0x18] = struct.pack("<I", 0x2)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(header) + info)
    return path


def fake_installer(files, code=0, record=None):
    """Двойник установщика: кладёт ``files`` в папку из ключа /DIR=."""
    def runner(command, env, cwd, timeout):
        if record is not None:
            record.append(command)
        match = re.search(r"/DIR=(\S+)", command)
        if match and files:
            target = Path(match.group(1))
            for rel, text in files.items():
                _write(target / rel, text)
        return code
    return runner


NEW_FILES = {
    "ollama app.exe": "new-app",
    "ollama.exe": "new-cli",
    "lib/ollama/new.dll": "new-lib",
    "unins000.exe": "unins",
}


class UpdateSettingsTests(unittest.TestCase):
    def test_ollama_profile_enables_watch(self):
        settings = exe_launcher.update_settings(OLLAMA_CFG)
        self.assertTrue(settings["watch"])
        self.assertEqual(settings["engine"], "inno")
        self.assertIn("ollamasetup*", settings["installer_names"])
        self.assertTrue(settings["source_url"].startswith("https://ollama.com/"))

    def test_opencode_profile_treats_the_download_as_consent(self):
        settings = exe_launcher.update_settings(OPENCODE_CFG)
        self.assertTrue(settings["watch"])
        self.assertTrue(settings["download_is_consent"])
        self.assertEqual(settings["engine"], "nsis")
        self.assertIn("opencode-desktop-win-*.exe", settings["installer_names"])
        self.assertTrue(settings["source_url"].startswith("https://github.com/"))
        # Скачанное лежит в кэше electron-updater (pending), а не запускается
        # программой напрямую - отдельного файла-маркера нет.
        self.assertTrue(settings["staged"])
        self.assertFalse(settings["handoff"])
        self.assertFalse(settings["markers"])

    def test_download_is_consent_can_be_switched_off(self):
        cfg = dict(OPENCODE_CFG, update={"download_is_consent": False,
                                         "staged": ["AppData/Local/x/*.exe"]})
        settings = exe_launcher.update_settings(cfg)
        self.assertFalse(settings["download_is_consent"])
        self.assertFalse(settings["watch"],
                         "без меток и согласия-скачивания следить не за чем")

    def test_other_program_has_no_watch_but_manual_update_works(self):
        settings = exe_launcher.update_settings(
            {"app_name": "Game", "target_exe_rel": "App/game.exe"})
        self.assertFalse(settings["watch"])
        self.assertTrue(settings["enabled"])

    def test_block_overrides_profile(self):
        cfg = dict(OLLAMA_CFG, update={"enabled": False, "source_url": "https://x/y.exe"})
        settings = exe_launcher.update_settings(cfg)
        self.assertFalse(settings["enabled"])
        self.assertEqual(settings["source_url"], "https://x/y.exe")

    def test_builder_writes_update_block_only_for_known_programs(self):
        ollama = launcher_mod.LauncherConfig(
            app_name="Ollama", target_exe_rel="App/ollama app.exe")
        data = json.loads(launcher_mod.render_config_json(ollama))
        self.assertIn("update", data)
        game = launcher_mod.LauncherConfig(
            app_name="Game", target_exe_rel="App/game.exe")
        self.assertNotIn("update", json.loads(launcher_mod.render_config_json(game)))

    def test_builder_writes_update_block_for_opencode(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="OpenCode", target_exe_rel="App/OpenCode.exe")
        data = json.loads(launcher_mod.render_config_json(cfg))
        self.assertEqual(data["update"]["engine"], "nsis")
        self.assertTrue(data["update"]["download_is_consent"])
        self.assertTrue(data["update"]["staged"])

    def test_refresh_keeps_update_block(self):
        cfg = launcher_mod.config_from_dict(dict(
            OLLAMA_CFG, update={"source_url": "https://a/b.exe", "keep_backup": False}))
        data = json.loads(launcher_mod.render_config_json(cfg))
        self.assertEqual(data["update"]["source_url"], "https://a/b.exe")
        self.assertFalse(data["update"]["keep_backup"])


class InstallerCommandTests(unittest.TestCase):
    def test_engine_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            inno = _write(Path(tmp) / "a.exe", "MZ" + "\0" * 100
                          + "This installation was built with Inno Setup.")
            nsis = _write(Path(tmp) / "b.exe", "MZ Nullsoft Install System v3")
            msi = _write(Path(tmp) / "c.msi", "x")
            other = _write(Path(tmp) / "d.exe", "MZ nothing here")
            self.assertEqual(exe_launcher.installer_engine(inno), "inno")
            self.assertEqual(exe_launcher.installer_engine(nsis), "nsis")
            self.assertEqual(exe_launcher.installer_engine(msi), "msi")
            self.assertEqual(exe_launcher.installer_engine(other), "unknown")

    def test_inno_command_targets_the_stage_folder(self):
        label, command = exe_launcher.install_commands(
            Path("C:/dl/OllamaSetup.exe"), Path("C:/p/Updates/stage"), "inno")[0]
        self.assertIn("/VERYSILENT", command)
        self.assertIn("/DIR=", command)
        self.assertIn("stage", command)
        self.assertIn("/NOICONS", command)

    def test_nsis_dir_is_last_and_unquoted(self):
        _label, command = exe_launcher.install_commands(
            Path("C:/dl/S.exe"), Path("C:/p/My Stage"), "nsis")[0]
        self.assertTrue(command.endswith("/D=" + str(Path("C:/p/My Stage"))))

    def test_nsis_command_suppresses_desktop_shortcuts(self):
        """Обновление не должно оставлять ярлык на рабочем столе чужого ПК."""
        _label, command = exe_launcher.install_commands(
            Path("C:/dl/opencode-desktop-win-x64.exe"),
            Path("C:/p/Updates/stage"), "nsis")[0]
        self.assertIn("--no-desktop-shortcut", command)
        self.assertIn("/S", command)
        self.assertTrue(command.endswith("/D=" + str(Path("C:/p/Updates/stage"))))

    def test_msi_and_unknown_ladders(self):
        msi = exe_launcher.install_commands(Path("a.msi"), Path("s"), "msi")
        self.assertEqual(len(msi), 2)
        self.assertIn("TARGETDIR=", msi[0][1])
        unknown = exe_launcher.install_commands(Path("a.exe"), Path("s"), "unknown")
        self.assertEqual(len(unknown), 2)

    def test_custom_args_replace_the_ladder(self):
        commands = exe_launcher.install_commands(
            Path("a.exe"), Path("stage"), "inno",
            {"installer_args": ["--silent", "--dir", "{DIR}"]})
        self.assertEqual(len(commands), 1)
        self.assertIn("--silent", commands[0][1])
        self.assertIn("stage", commands[0][1])

    def test_custom_args_without_a_folder_still_get_the_current_target(self):
        """Свои ключи не должны лишать обновление привязки к портативу."""
        stage = Path("C:/p/Updates/stage")
        command = exe_launcher.install_commands(
            Path("a.exe"), stage, "inno",
            {"installer_args": ["/SILENT"]})[0][1]
        # Разделители зависят от ОС: на Windows Path печатается с "\".
        self.assertIn("/DIR=" + str(stage), command)
        self.assertIn("/NOICONS", command)

    def test_custom_args_with_the_previous_root_point_to_the_current_portable(self):
        """Перенос на другой диск: установщик не должен ставить по старому пути."""
        old = "C:\\Old\\App_Portable"
        stage = Path("C:/p/Updates/stage")
        command = exe_launcher.install_commands(
            Path("a.exe"), stage, "nsis",
            {"installer_args": ["/D=" + old + "\\App",
                                "--config=" + old + "\\PortableData\\x.ini"]},
            stale_roots=[old], portable_root=Path("C:/p"))[0][1]
        self.assertNotIn("Old", command)
        self.assertIn(str(stage), command)
        self.assertIn(str(Path("C:/p")), command)
        self.assertTrue(command.endswith("/D=" + str(stage)))

    def test_similar_folder_name_is_not_rewritten(self):
        """Границы пути: ``Foo`` не должен испортить соседнюю ``FooBar``."""
        command = exe_launcher.install_commands(
            Path("a.exe"), Path("C:/p/Updates/stage"), "nsis",
            {"installer_args": ["--x=C:\\\\Apps\\\\FooBar\\\\app.ini"]},
            stale_roots=["C:\\\\Apps\\\\Foo"], portable_root=Path("C:/p"))[0][1]
        self.assertIn("FooBar", command)


class StaleShortcutTests(unittest.TestCase):
    """«Пустой» ярлык: файл .lnk остался, цели больше нет."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_portable(self._tmp.name)
        self.desktop = Path(self._tmp.name) / "Desktop"
        self.desktop.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _names(self):
        return exe_launcher.app_name_candidates("Ollama", "OllamaSetup.exe")

    def test_lnk_target_is_read_without_com(self):
        link = make_lnk(self.desktop / "Ollama.lnk",
                        str(self.root / "App" / "ollama app.exe"))
        self.assertEqual(exe_launcher.lnk_target(link),
                         str(self.root / "App" / "ollama app.exe"))

    def test_empty_shortcut_of_the_program_is_removed(self):
        link = make_lnk(self.desktop / "Ollama.lnk",
                        str(Path(self._tmp.name) / "gone" / "Ollama.exe"))
        removed = exe_launcher.remove_stale_shortcuts(
            self._names(), roots=[str(self.root)], folders=[self.desktop])
        self.assertEqual(removed, [str(link)])
        self.assertFalse(link.exists())

    def test_foreign_and_working_shortcuts_are_kept(self):
        exe = _write(Path(self._tmp.name) / "Programs" / "Ollama" / "Ollama.exe")
        working = make_lnk(self.desktop / "Ollama.lnk", str(exe))
        foreign = make_lnk(self.desktop / "Telegram.lnk",
                           str(Path(self._tmp.name) / "gone" / "Telegram.exe"))
        self.assertEqual(exe_launcher.remove_stale_shortcuts(
            self._names(), roots=[str(self.root)], folders=[self.desktop]), [])
        self.assertTrue(working.exists())
        self.assertTrue(foreign.exists())

    def test_update_removes_the_empty_shortcut(self):
        empty = make_lnk(self.desktop / "Ollama.lnk",
                         str(Path(self._tmp.name) / "gone" / "Ollama.exe"))
        installer = _write(Path(self._tmp.name) / "OllamaSetup.exe", "installer")
        with mock.patch.object(exe_launcher, "shortcut_folders",
                               lambda *a, **k: [self.desktop]):
            result = exe_launcher.apply_update(
                self.root, OLLAMA_CFG, installer,
                runner=fake_installer(NEW_FILES))
        self.assertTrue(result.ok, result.message)
        self.assertFalse(empty.exists(), "пустой ярлык убран при обновлении")


class InstallRecordRetargetTests(unittest.TestCase):
    """Записи об установке на этом ПК ведут в текущую папку портатива.

    Жалоба: портатив создан на диске ``D:``, папку перенесли на ``E:``, а
    обновление поставилось по адресу ``D:...`` — установщик нашёл «прошлую
    установку» в реестре этого ПК.
    """

    def test_previous_root_in_a_record_is_replaced(self):
        old = "D:\\Apps\\Foo_Portable"
        new = "E:\\Backup\\Foo_Portable"
        value = old + "\\App\\Foo.exe"
        self.assertEqual(
            exe_launcher.retarget_record_text(value, [old], new),
            new + "\\App\\Foo.exe")
        self.assertEqual(
            exe_launcher.retarget_record_text(
                "\"C:\\Program Files\\Foo\\unins000.exe\" /S", [old], new),
            "\"C:\\Program Files\\Foo\\unins000.exe\" /S",
            "чужие пути не меняются")

    def test_forward_slash_and_doubled_forms_are_replaced(self):
        old = "D:\\Apps\\Foo_Portable"
        new = "E:\\Foo"
        for spelling in (old, old.replace("\\", "/"), old.replace("\\", "\\\\")):
            self.assertEqual(
                exe_launcher.retarget_record_text(spelling + "\\App",
                                                 [old], new),
                new + "\\App", spelling)

    def test_neighbour_folder_is_not_touched(self):
        self.assertEqual(
            exe_launcher.retarget_record_text(
                "D:\\Apps\\Foo_Portable2\\App", ["D:\\Apps\\Foo_Portable"],
                "E:\\Foo"),
            "D:\\Apps\\Foo_Portable2\\App")

    def test_no_previous_roots_means_no_changes(self):
        self.assertEqual(
            exe_launcher.retarget_record_text("D:\\A\\App", [], "E:\\Foo"),
            "D:\\A\\App")

    def test_registry_scan_is_a_noop_without_windows(self):
        with mock.patch.object(exe_launcher, "IS_WINDOWS", False):
            self.assertEqual(exe_launcher.retarget_host_install_records(
                ["D:\\Apps\\Foo"], Path("E:/Foo")), [])

    def test_app_prefix_is_replaced_for_a_missing_folder(self):
        names = exe_launcher.app_name_candidates("Baalda", "Baalda_0.1.87")
        # Ожидание строится через Path: на Windows разделитель — «\\».
        root = Path("E:/Backup/Apps/Portable/Baalda_0.1.87_Portable")
        expected = str(root) + "\\App\\Baalda.exe"
        self.assertEqual(
            exe_launcher.replace_app_prefix(
                "D:\\Portable\\Baalda_0.1.87_Portable\\App\\Baalda.exe",
                root, names),
            expected)

    def test_existing_foreign_prefix_is_kept(self):
        names = exe_launcher.app_name_candidates("Baalda")
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "Other"
            prefix.mkdir()
            value = str(prefix) + "\\App\\x.exe"
            self.assertEqual(
                exe_launcher.replace_app_prefix(value, Path("E:/Foo"), names),
                value)


class PortableMarkerTests(unittest.TestCase):
    """Маркер ``@@PORTABLE_ROOT@@`` не должен доживать до установщика.

    Жалоба (скриншот): установщик обновления показывает каталог
    ``@@PORTABLE_ROOT@@\\App`` и падает с «Error opening file for writing» —
    такого пути нет. Маркер утёк в реестр или в настройки программы, поэтому
    лончер разворачивает его в текущий корень при каждом запуске.
    """

    ROOT = r"E:\Backup\Apps\Baalda_0.1.87_Portable"

    def test_marker_is_replaced_by_the_current_root(self):
        self.assertEqual(
            exe_launcher.expand_root_token_text(
                r"@@PORTABLE_ROOT@@\App\desktop.exe", self.ROOT),
            self.ROOT + r"\App\desktop.exe")

    def test_doubled_backslashes_stay_doubled(self):
        # Значения .reg внутри JSON-подобных настроек бывают с «\\».
        fixed = exe_launcher.expand_root_token_text(
            "@@PORTABLE_ROOT@@\\\\App\\\\desktop.exe", self.ROOT)
        self.assertEqual(fixed, self.ROOT.replace("\\", "\\\\")
                         + "\\\\App\\\\desktop.exe")

    def test_forward_slashes_are_kept(self):
        fixed = exe_launcher.expand_root_token_text(
            "@@PORTABLE_ROOT@@/App/desktop.exe", self.ROOT)
        self.assertEqual(fixed, self.ROOT.replace("\\", "/") + "/App/desktop.exe")

    def test_case_does_not_matter(self):
        self.assertIn(self.ROOT, exe_launcher.expand_root_token_text(
            "@@portable_root@@\\App", self.ROOT))

    def test_retarget_record_text_expands_the_marker(self):
        value = r"@@PORTABLE_ROOT@@\App\desktop.exe"
        self.assertEqual(
            exe_launcher.retarget_record_text(value, [], self.ROOT),
            self.ROOT + r"\App\desktop.exe")

    def test_text_without_the_marker_is_untouched(self):
        value = r"C:\Program Files\Other\app.exe"
        self.assertEqual(
            exe_launcher.expand_root_token_text(value, self.ROOT), value)

    def test_marker_in_a_config_file_is_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_portable(tmp)
            path = _write(root / "App" / "installer.ini",
                          "InstallDir=@@PORTABLE_ROOT@@\\App")
            fixed = exe_launcher.expand_root_token_in_files(
                root, OLLAMA_CFG, deep=True)
            self.assertIn("App/installer.ini", [item.replace("\\", "/")
                                                for item in fixed])
            self.assertNotIn("@@PORTABLE_ROOT@@", path.read_text())

    def test_one_off_sweep_runs_once_per_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_portable(tmp)
            _write(root / "App" / "installer.ini",
                   "InstallDir=@@PORTABLE_ROOT@@\\App")
            first = exe_launcher.sweep_root_token_once(root, OLLAMA_CFG)
            self.assertTrue(first)
            _write(root / "App" / "second.ini",
                   "InstallDir=@@PORTABLE_ROOT@@\\App")
            # Отметка помнит это положение папки: второй раз проход не нужен.
            self.assertEqual(
                exe_launcher.sweep_root_token_once(root, OLLAMA_CFG), [])

    def test_registry_healing_is_a_noop_outside_windows(self):
        with mock.patch.object(exe_launcher, "IS_WINDOWS", False):
            self.assertEqual(exe_launcher.heal_host_registry(
                Path("E:/Baalda"), OLLAMA_CFG), [])


class PreviousLocationAdoptionTests(unittest.TestCase):
    """Обновление поставилось в ПРЕЖНЕЕ место — файлы забираются в текущее.

    Сценарий из жалобы: портатив собран в ``D:\\Portable\\Baalda_0.1.87_Portable``,
    папку перенесли в ``E:\\Backup\\Apps\\Portable``, а обновление (его
    запускает сама программа) поставило новую версию по прежнему адресу.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_portable(self._tmp.name)
        self.previous = Path(self._tmp.name) / "D" / "Ollama_Portable"
        (self.previous / "App").mkdir(parents=True)
        _write(self.previous / "launcher_config.json", json.dumps(OLLAMA_CFG))
        exe_launcher.write_paths_stamp(self.root, previous=str(self.previous))

    def tearDown(self):
        self._tmp.cleanup()

    def _touch(self, relative: str, text: str) -> Path:
        return _write(self.previous / "App" / relative, text)

    def test_fresh_files_from_the_previous_location_are_copied(self):
        import time

        started = time.time() - 1
        self._touch("ollama app.exe", "new-app")
        self._touch("lib/ollama/new.dll", "new-lib")
        copied = exe_launcher.adopt_updates_from_previous_locations(
            self.root, OLLAMA_CFG, since=started)
        self.assertEqual(sorted(copied), ["lib/ollama/new.dll", "ollama app.exe"])
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(),
                         "new-app")
        self.assertTrue((self.root / "App" / "lib" / "ollama" / "new.dll").is_file())

    def test_old_files_of_the_previous_copy_are_ignored(self):
        # Файл лежит в прежней папке давно: это не результат обновления.
        self._touch("ollama app.exe", "ancient")
        copied = exe_launcher.adopt_updates_from_previous_locations(
            self.root, OLLAMA_CFG, since=9_999_999_999)
        self.assertEqual(copied, [])
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(),
                         "old-app")

    def test_replaced_files_are_backed_up(self):
        import time

        self._touch("ollama app.exe", "new-app")
        exe_launcher.adopt_updates_from_previous_locations(
            self.root, OLLAMA_CFG, since=time.time() - 1)
        backup = self.root / "Updates" / "backup-previous" / "ollama app.exe"
        self.assertEqual(backup.read_text(), "old-app", "прежняя версия сохранена")

    def test_launcher_is_never_overwritten(self):
        import time

        self._touch("LaunchPortable.exe", "hijacked")
        copied = exe_launcher.adopt_updates_from_previous_locations(
            self.root, OLLAMA_CFG, since=time.time() - 1)
        self.assertNotIn("LaunchPortable.exe", copied)
        self.assertEqual((self.root / "App" / "LaunchPortable.exe").read_text(),
                         "launcher")

    def test_a_neighbouring_portable_is_not_a_source(self):
        import shutil

        shutil.rmtree(self.previous)
        neighbour = Path(self._tmp.name) / "Other" / "Ollama_Tools"
        (neighbour / "App").mkdir(parents=True)
        _write(neighbour / "launcher_config.json",
               json.dumps({"app_name": "Ollama Tools",
                           "target_exe_rel": "App/ollama tools.exe"}))
        _write(neighbour / "App" / "ollama app.exe", "neighbour")
        exe_launcher.write_paths_stamp(self.root, previous=str(neighbour))
        self.assertEqual(exe_launcher.stale_app_dirs(self.root, OLLAMA_CFG),
                         [])

    def test_same_program_previous_location_is_a_source(self):
        self.assertEqual([str(item) for item in
                          exe_launcher.stale_app_dirs(self.root, OLLAMA_CFG)],
                         [str(self.previous / "App")])

    def test_session_marker_roundtrip(self):
        started = exe_launcher.write_session_start(self.root)
        self.assertGreater(started, 0)
        self.assertEqual(exe_launcher._read_session_start(self.root), started)

    def test_previous_location_of_another_program_is_ignored(self):
        other = Path(self._tmp.name) / "Other" / "Other_Portable"
        (other / "App").mkdir(parents=True)
        _write(other / "launcher_config.json", json.dumps(OPENCODE_CFG))
        _write(other / "App" / "ollama app.exe", "foreign")
        exe_launcher.write_paths_stamp(self.root, previous=str(other))
        copied = exe_launcher.adopt_updates_from_previous_locations(
            self.root, OLLAMA_CFG, since=1.0)
        self.assertEqual(copied, [], "чужая папка не источник обновления")


class UpdatePortabilityTests(unittest.TestCase):
    """Обновление ставится в папку портатива на том диске, где он лежит сейчас."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_portable(self._tmp.name)
        self.installer = _write(Path(self._tmp.name) / "OllamaSetup.exe",
                                "installer")

    def tearDown(self):
        self._tmp.cleanup()

    def _previous_location(self) -> Path:
        """Прежнее место этой же папки + штамп переноса."""
        old = Path(self._tmp.name) / "OldDrive" / "Ollama_Portable"
        (old / "App").mkdir(parents=True)
        _write(old / "launcher_config.json", json.dumps(OLLAMA_CFG))
        _write(old / "App" / "ollama app.exe", "old-copy")
        exe_launcher.write_paths_stamp(self.root, previous=str(old))
        self.assertEqual(exe_launcher.remembered_roots(self.root), [str(old)])
        return old

    def _apply(self, runner):
        return exe_launcher.apply_update(self.root, OLLAMA_CFG, self.installer,
                                         runner=runner)

    def test_paths_of_the_previous_root_are_repaired_before_the_installer(self):
        old = self._previous_location()
        settings = _write(
            self.root / "PortableData" / "AppData" / "Roaming" / "Ollama"
            / "settings.json",
            json.dumps({"install_dir": str(old / "App")}))

        def installer(command, env, cwd, timeout):
            # Установщик читает каталог из настроек программы.
            seen.append(settings.read_text(encoding="utf-8"))
            return fake_installer(NEW_FILES)(command, env, cwd, timeout)

        seen = []
        result = self._apply(installer)
        self.assertTrue(result.ok, result.message)
        self.assertEqual(len(seen), 1)
        self.assertNotIn("OldDrive", seen[0], "путь починен до установки")
        # Значение проверяем после разбора JSON: в тексте .json обратные
        # слэши удвоены, и сравнивать строку «как есть» нельзя.
        self.assertEqual(json.loads(seen[0])["install_dir"],
                         str(self.root / "App"))

    def test_install_into_the_previous_location_is_adopted(self):
        """Упрямый установщик: новая версия всё равно попадает в портатив."""
        old = self._previous_location()

        def stubborn(command, env, cwd, timeout):
            for rel, text in NEW_FILES.items():
                _write(old / "App" / rel, text)
            return 0

        result = self._apply(stubborn)
        self.assertTrue(result.ok, result.message)
        app = self.root / "App"
        self.assertEqual((app / "ollama app.exe").read_text(), "new-app")
        self.assertTrue((app / "lib" / "ollama" / "new.dll").is_file())
        self.assertFalse((self.root / "Updates" / "stage").exists())
        # Прежнюю папку Portablizer не удаляет: это решает пользователь.
        self.assertTrue((old / "App" / "ollama app.exe").is_file())

    def test_unrelated_previous_folder_is_not_adopted(self):
        old = Path(self._tmp.name) / "OtherDrive" / "Ollama_Portable"
        (old / "App").mkdir(parents=True)
        _write(old / "launcher_config.json",
               json.dumps(dict(OLLAMA_CFG, app_name="Something Else")))
        _write(old / "App" / "ollama app.exe", "foreign")
        exe_launcher.write_paths_stamp(self.root, previous=str(old))

        def stubborn(command, env, cwd, timeout):
            _write(old / "App" / "ollama app.exe", "foreign-new")
            return 0

        result = self._apply(stubborn)
        self.assertFalse(result.ok)
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(),
                         "old-app", "чужая папка в портатив не попадает")

    def test_history_of_locations_is_used(self):
        """Папку переносят не один раз: помнится вся короткая история."""
        older = Path(self._tmp.name) / "F" / "Ollama_Portable"
        older.mkdir(parents=True)
        exe_launcher.write_paths_stamp(self.root, previous=str(older))
        newer = Path(self._tmp.name) / "G" / "Ollama_Portable"
        newer.mkdir(parents=True)
        exe_launcher.write_paths_stamp(self.root, previous=str(newer))
        roots = exe_launcher.remembered_roots(self.root)
        self.assertIn(str(newer), roots)
        self.assertIn(str(older), roots, "прежнее место не забыто")

    def test_config_inside_app_is_repaired_before_the_installer(self):
        """Установщик читает каталог установки из конфига в глубине App."""
        old = self._previous_location()
        # Отключаем починку PortableData, чтобы проверить именно App.
        _write(self.root / "PortableData" / "portable-root.json",
               json.dumps({"schema": 1, "root": str(self.root),
                           "previous": str(old)}))
        settings = _write(
            self.root / "App" / "data" / "conf" / "deep" / "settings.json",
            json.dumps({"install_dir": str(old / "App")}))
        seen = []

        def installer(command, env, cwd, timeout):
            seen.append(json.loads(settings.read_text(encoding="utf-8")))
            return fake_installer(NEW_FILES)(command, env, cwd, timeout)

        result = self._apply(installer)
        self.assertTrue(result.ok, result.message)
        self.assertEqual(seen[0]["install_dir"], str(self.root / "App"))

    def test_install_ignoring_the_folder_is_adopted_from_the_portable_profile(self):
        """Установщик не понял ключ каталога — файлы всё равно внутри портатива."""
        target = (self.root / "PortableData" / "AppData" / "Local" / "Programs"
                  / "Ollama" / "ollama app.exe")

        def installer(command, env, cwd, timeout):
            _write(target, "new-app")
            _write(target.parent / "ollama.exe", "new-cli")
            return 0

        result = self._apply(installer)
        self.assertTrue(result.ok, result.message)
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(),
                         "new-app")
        self.assertEqual((self.root / "App" / "ollama.exe").read_text(),
                         "new-cli")

    def test_shortcut_created_by_the_update_is_removed(self):
        desktop = Path(self._tmp.name) / "Desktop"
        desktop.mkdir()

        def installer(command, env, cwd, timeout):
            code = fake_installer(NEW_FILES)(command, env, cwd, timeout)
            link = desktop / "Ollama.lnk"
            link.write_bytes(str(self.root / "App" / "ollama app.exe")
                             .encode("utf-16-le"))
            return code

        with mock.patch.object(exe_launcher, "shortcut_folders",
                               lambda *a, **k: [desktop]):
            result = self._apply(installer)
        self.assertTrue(result.ok, result.message)
        self.assertFalse((desktop / "Ollama.lnk").exists(),
                         "статичный ярлык установщика убран")


class PayloadTests(unittest.TestCase):
    def test_direct_and_nested_layouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            _write(stage / "ollama app.exe")
            self.assertEqual(exe_launcher.locate_payload(stage, OLLAMA_CFG), stage)
            shutil.rmtree(stage)
            _write(stage / "Ollama" / "ollama app.exe")
            self.assertEqual(exe_launcher.locate_payload(stage, OLLAMA_CFG),
                             stage / "Ollama")

    def test_empty_stage_is_not_an_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            _write(stage / "readme.txt")
            self.assertIsNone(exe_launcher.locate_payload(stage, OLLAMA_CFG))


class InterceptTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_portable(self._tmp.name)
        local = self.root / "PortableData" / "AppData" / "Local" / "Ollama"
        self.staged = _write(local / "updates_v2" / "0.99.0" / "OllamaSetup.exe", "new")
        self.running = local / "OllamaSetup.exe"
        self.marker = local / "upgraded"

    def tearDown(self):
        self._tmp.cleanup()

    def test_quarantine_moves_installer_and_clears_traces(self):
        _write(self.marker, "")
        kept, clean = exe_launcher.quarantine_staged_update(self.root, OLLAMA_CFG)
        self.assertTrue(clean)
        self.assertEqual(kept, self.root / "Updates" / "OllamaSetup.exe")
        self.assertEqual(kept.read_text(), "new")
        self.assertFalse(self.staged.exists())
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.staged.parent.exists(), "пустая папка версии осталась")

    def test_newest_installer_wins(self):
        os.utime(self.staged, (1, 1))
        _write(self.running, "newer")
        kept, _clean = exe_launcher.quarantine_staged_update(self.root, OLLAMA_CFG)
        self.assertEqual(kept.read_text(), "newer")
        self.assertFalse(self.running.exists())
        self.assertFalse(self.staged.exists())

    def test_watch_ignores_a_plain_download(self):
        watch = exe_launcher.UpdateWatch(self.root, OLLAMA_CFG)
        self.assertFalse(watch.poll())
        self.assertTrue(self.staged.exists(), "скачанное трогать нельзя, пока "
                        "пользователь не нажал «перезапустить»")

    def test_watch_intercepts_the_restart_for_update(self):
        # Родной апдейтер: переименовал установщик и поставил метку.
        os.replace(self.staged, self.running)
        _write(self.marker, "")
        watch = exe_launcher.UpdateWatch(self.root, OLLAMA_CFG)
        stopped = []
        with mock.patch.object(exe_launcher, "stop_stray_installers",
                               side_effect=lambda r, c: stopped.append(1) or []):
            self.assertTrue(watch.poll())
        self.assertTrue(watch.handoff)
        self.assertEqual(watch.installer, self.root / "Updates" / "OllamaSetup.exe")
        self.assertFalse(self.running.exists())
        self.assertFalse(self.marker.exists())
        self.assertEqual(watch.take(), watch.installer)
        self.assertEqual(exe_launcher.pending_installer(self.root), watch.installer)

    def test_watch_retries_while_the_native_installer_still_runs(self):
        os.replace(self.staged, self.running)
        watch = exe_launcher.UpdateWatch(self.root, OLLAMA_CFG)
        with mock.patch.object(exe_launcher, "stop_stray_installers",
                               return_value=["OllamaSetup.exe"]):
            watch.poll()
        self.assertTrue(self.running.exists(), "файл занят процессом - ждём")
        self.assertIsNone(watch.installer)
        watch.poll()  # процесса больше нет
        self.assertIsNotNone(watch.installer)

    def test_program_without_profile_is_not_watched(self):
        cfg = {"app_name": "Game", "target_exe_rel": "App/game.exe"}
        self.assertFalse(exe_launcher.UpdateWatch(self.root, cfg).active)

    def test_wait_target_polls_the_watch(self):
        class Proc:
            calls = 0

            def wait(self, timeout=None):
                Proc.calls += 1
                if Proc.calls < 3:
                    raise subprocess.TimeoutExpired("x", timeout)
                return 7

        polls = []
        watch = exe_launcher.UpdateWatch(self.root, OLLAMA_CFG)
        watch.poll = lambda: polls.append(1) or False
        self.assertEqual(exe_launcher._wait_target(Proc(), watch), 7)
        self.assertEqual(len(polls), 2)

    def test_wait_target_without_watch_is_plain_wait(self):
        proc = mock.Mock()
        proc.wait.return_value = 3
        self.assertEqual(exe_launcher._wait_target(proc, None), 3)
        proc.wait.assert_called_once_with()


class OpenCodeInterceptTests(unittest.TestCase):
    """OpenCode Desktop: кнопка «Обновить» = согласие на обновление.

    Программа сама скачивает установщик (electron-updater кладёт его в
    pending) и по «Перезапустить» запускает его отдельным процессом - мимо
    папки App. Лончер обязан забрать установщик себе и поставить его внутрь
    портатива, как только пользователь согласился.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_opencode_portable(self._tmp.name)
        self.pending = (
            self.root / "PortableData" / "AppData" / "Local"
            / "opencode-updater" / "pending" / "opencode-desktop-win-x64.exe")
        _write(self.pending, "installer")

    def tearDown(self):
        self._tmp.cleanup()

    def test_downloaded_installer_triggers_the_intercept(self):
        watch = exe_launcher.UpdateWatch(self.root, OPENCODE_CFG)
        self.assertTrue(watch.poll())
        self.assertTrue(watch.handoff)
        taken = watch.take()
        self.assertEqual(taken, self.root / "Updates" / "opencode-desktop-win-x64.exe")
        self.assertTrue(taken.is_file())
        self.assertEqual(taken.read_text(), "installer")
        self.assertFalse(self.pending.exists(), "установщик забран из кэша апдейтера")

    def test_intercept_retries_while_the_installer_holds_the_file(self):
        watch = exe_launcher.UpdateWatch(self.root, OPENCODE_CFG)
        real = exe_launcher.quarantine_staged_update
        calls = {"n": 0}

        def flaky(root, cfg):
            calls["n"] += 1
            if calls["n"] == 1:
                return None, False  # файл занят запущенным установщиком
            return real(root, cfg)

        with mock.patch.object(exe_launcher, "stop_stray_installers",
                               return_value=["opencode-desktop-win-x64.exe"]):
            watch.poll()
        self.assertIsNone(watch.installer, "занятый файл не переименовывается")
        with mock.patch.object(exe_launcher, "quarantine_staged_update", flaky):
            watch.poll()
        self.assertIsNotNone(watch.installer)
        self.assertEqual(calls["n"], 2)

    def test_pending_state_is_kept_for_the_next_start(self):
        watch = exe_launcher.UpdateWatch(self.root, OPENCODE_CFG)
        watch.poll()
        pending = exe_launcher.pending_installer(self.root)
        self.assertEqual(pending, watch.take())

    def test_another_program_downloading_silently_is_not_touched(self):
        """У Ollama скачанное в фоне лежит нетронутым до «перезапуска»."""
        root = make_portable(self._tmp.name)
        staged = _write(root / "PortableData" / "AppData" / "Local" / "Ollama"
                        / "updates_v2" / "2" / "OllamaSetup.exe", "new")
        watch = exe_launcher.UpdateWatch(root, OLLAMA_CFG)
        self.assertFalse(watch.poll())
        self.assertTrue(staged.exists())


class HostShortcutSafetyTests(unittest.TestCase):
    """Уборка только своих ярлыков: ярлык пользователя и чужие остаются.

    Жалоба: после портирования на рабочем столе оставался ярлык установщика
    со статичным абсолютным путём, а после переноса папки на другой диск он
    вёл в прежнее место.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_opencode_portable(self._tmp.name)
        self.desktop = Path(self._tmp.name) / "Desktop"
        self.desktop.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _guard(self, extra_roots=()):
        return exe_launcher.ShortcutGuard(
            self.root, extra_roots=extra_roots, folders=[self.desktop])

    @staticmethod
    def _link(path: Path, target: Path) -> Path:
        """Ярлык на Windows хранит цель в UTF-16LE — так же и пишем."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(str(target).encode("utf-16-le"))
        return path

    def test_shortcut_created_during_the_update_is_removed(self):
        guard = self._guard()
        guard.snapshot()
        link = self._link(self.desktop / "OpenCode.lnk",
                          self.root / "App" / "OpenCode.exe")
        self.assertEqual(guard.cleanup(), [str(link)])
        self.assertFalse(link.exists())
        self.assertEqual(guard.cleanup(), [], "вторая уборка ничего не находит")

    def test_shortcut_that_existed_before_the_update_is_kept(self):
        link = self._link(self.desktop / "OpenCode.lnk",
                          self.root / "App" / "OpenCode.exe")
        guard = self._guard()
        guard.snapshot()
        self.assertEqual(guard.cleanup(), [])
        self.assertTrue(link.exists())

    def test_new_shortcut_to_another_program_is_kept(self):
        guard = self._guard()
        guard.snapshot()
        link = self._link(self.desktop / "Other.lnk",
                          Path("C:/Program Files/Other/Other.exe"))
        self.assertEqual(guard.cleanup(), [])
        self.assertTrue(link.exists())

    def test_shortcut_pointing_to_the_previous_location_is_removed(self):
        previous = Path(self._tmp.name) / "OldDrive" / "OpenCode_Portable"
        guard = self._guard(extra_roots=[str(previous)])
        guard.snapshot()
        link = self._link(self.desktop / "OpenCode.lnk",
                          previous / "App" / "OpenCode.exe")
        self.assertEqual(guard.cleanup(), [str(link)])
        self.assertFalse(link.exists())

    def test_url_link_naming_the_portable_is_removed(self):
        guard = self._guard()
        guard.snapshot()
        link = _write(self.desktop / "OpenCode.url",
                      "[InternetShortcut]\nURL=file:///" +
                      str(self.root / "App" / "OpenCode.exe").replace("\\", "/"))
        self.assertEqual(guard.cleanup(), [str(link)])
        self.assertFalse(link.exists())

    def test_removal_without_a_snapshot_does_nothing(self):
        link = self._link(self.desktop / "OpenCode.lnk",
                          self.root / "App" / "OpenCode.exe")
        removed = exe_launcher.remove_host_app_shortcuts(
            self.root, OPENCODE_CFG, folders=[self.desktop], programs_dir=None)
        self.assertEqual(removed, [])
        self.assertTrue(link.exists())


class HostTraceGuardSafetyTests(unittest.TestCase):
    def test_legacy_guard_restore_is_a_noop(self):
        guard = exe_launcher.HostTraceGuard()
        guard.snapshot()
        self.assertEqual(guard.restore(), [])
        self.assertFalse(guard.active)


class ApplyUpdateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_portable(self._tmp.name)
        self.installer = _write(Path(self._tmp.name) / "OllamaSetup.exe", "installer")

    def tearDown(self):
        self._tmp.cleanup()

    def apply(self, runner=None, cfg=None):
        return exe_launcher.apply_update(
            self.root, cfg or OLLAMA_CFG, self.installer,
            runner=runner or fake_installer(NEW_FILES))

    def test_new_version_replaces_old_one_and_data_survives(self):
        result = self.apply()
        self.assertTrue(result.ok, result.message)
        app = self.root / "App"
        self.assertEqual((app / "ollama app.exe").read_text(), "new-app")
        self.assertEqual((app / "ollama.exe").read_text(), "new-cli")
        self.assertTrue((app / "lib" / "ollama" / "new.dll").is_file())
        self.assertFalse((app / "lib" / "ollama" / "old.dll").exists(),
                         "каталог заменяется целиком: старые DLL не остаются")
        # Лончер, сохранения и данные профиля - на месте.
        self.assertEqual((app / "LaunchPortable.exe").read_text(), "launcher")
        self.assertEqual((app / "Saves" / "slot1.sav").read_text(), "my-save")
        self.assertEqual((self.root / "PortableData" / "User" / ".ollama"
                          / "id_ed25519").read_text(), "key")
        self.assertFalse((self.root / "Updates" / "stage").exists())

    def test_old_version_is_kept_for_rollback(self):
        result = self.apply()
        backup = self.root / "Updates" / "backup"
        self.assertEqual(result.backup, backup)
        self.assertEqual((backup / "ollama app.exe").read_text(), "old-app")
        self.assertEqual((backup / "lib" / "ollama" / "old.dll").read_text(), "old-lib")
        journal = json.loads((self.root / "Updates" / "journal.json").read_text())
        self.assertEqual(journal["state"], "done")

        rollback = exe_launcher.rollback_update(self.root, OLLAMA_CFG)
        self.assertTrue(rollback.ok, rollback.message)
        app = self.root / "App"
        self.assertEqual((app / "ollama app.exe").read_text(), "old-app")
        self.assertTrue((app / "lib" / "ollama" / "old.dll").is_file())
        self.assertFalse((app / "lib" / "ollama" / "new.dll").exists())
        self.assertFalse((app / "unins000.exe").exists(), "добавленное при обновлении убирается")
        self.assertFalse(exe_launcher.rollback_update(self.root, OLLAMA_CFG).ok)

    def test_rollback_command_is_quiet_with_yes(self):
        self.assertTrue(self.apply().ok)
        with mock.patch.object(exe_launcher, "_show_info") as info:
            self.assertEqual(exe_launcher.rollback_command(
                self.root, ["--rollback", "--yes"]), 0)
        info.assert_not_called()
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(), "old-app")

    def test_keep_backup_false_removes_it(self):
        cfg = dict(OLLAMA_CFG, update={"keep_backup": False})
        result = self.apply(cfg=cfg)
        self.assertTrue(result.ok)
        self.assertFalse((self.root / "Updates" / "backup").exists())

    def test_failed_install_leaves_the_portable_untouched(self):
        result = self.apply(runner=fake_installer({}, code=2))
        self.assertFalse(result.ok)
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(), "old-app")
        self.assertTrue((self.root / "App" / "lib" / "ollama" / "old.dll").is_file())
        self.assertFalse((self.root / "Updates" / "stage").exists())

    def test_installer_with_error_code_is_not_accepted_even_if_files_appeared(self):
        result = self.apply(runner=fake_installer(NEW_FILES, code=1))
        self.assertFalse(result.ok)
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(), "old-app")

    def test_reboot_required_code_counts_as_success(self):
        self.assertTrue(self.apply(runner=fake_installer(NEW_FILES, code=3010)).ok)

    def test_failure_in_the_middle_of_the_swap_rolls_back(self):
        real = exe_launcher._move_with_retry
        calls = {"n": 0}

        def flaky(source, destination, attempts=6):
            calls["n"] += 1
            if calls["n"] == 5:
                raise PermissionError("locked by antivirus")
            return real(source, destination, attempts)

        with mock.patch.object(exe_launcher, "_move_with_retry", flaky):
            result = self.apply()
        self.assertFalse(result.ok)
        self.assertIn("возвращена", result.message)
        app = self.root / "App"
        self.assertEqual((app / "ollama app.exe").read_text(), "old-app")
        self.assertEqual((app / "ollama.exe").read_text(), "old-cli")
        self.assertTrue((app / "lib" / "ollama" / "old.dll").is_file())
        self.assertFalse((app / "lib" / "ollama" / "new.dll").exists())
        self.assertFalse((app / "unins000.exe").exists())
        self.assertEqual((app / "Saves" / "slot1.sav").read_text(), "my-save")

    def test_interrupted_swap_is_finished_by_the_next_start(self):
        """Принудительное завершение посреди подмены: App наполовину новый."""
        real = exe_launcher._move_with_retry
        calls = {"n": 0}

        class Killed(BaseException):
            """Процесс убили: ни отката, ни finally, только журнал на диске."""

        def die(source, destination, attempts=6):
            calls["n"] += 1
            if calls["n"] == 6:
                raise Killed()
            return real(source, destination, attempts)

        with mock.patch.object(exe_launcher, "_move_with_retry", die):
            with self.assertRaises(Killed):
                self.apply()
        journal = json.loads((self.root / "Updates" / "journal.json").read_text())
        self.assertEqual(journal["state"], "swapping")
        message = exe_launcher.recover_interrupted_update(self.root, OLLAMA_CFG)
        self.assertIn("возвращена", message)
        app = self.root / "App"
        self.assertEqual((app / "ollama app.exe").read_text(), "old-app")
        self.assertEqual((app / "ollama.exe").read_text(), "old-cli")
        self.assertTrue((app / "lib" / "ollama" / "old.dll").is_file())
        self.assertFalse((app / "lib" / "ollama" / "new.dll").exists())
        self.assertIsNone(exe_launcher.recover_interrupted_update(self.root, OLLAMA_CFG),
                          "второй раз откатывать нечего")

    def test_update_running_in_another_process_is_not_rolled_back(self):
        """UpdatePortable.cmd работает, а пользователь запустил программу."""
        stage = self.root / "Updates" / "stage"
        _write(stage / "half.bin")
        (self.root / "Updates" / "journal.json").write_text(
            json.dumps({"state": "swapping", "pid": os.getppid(),
                        "replaced": ["ollama.exe"], "added": []}))
        self.assertIsNone(
            exe_launcher.recover_interrupted_update(self.root, OLLAMA_CFG))
        self.assertTrue(stage.exists())

    def test_interrupted_installation_only_cleans_the_stage(self):
        stage = self.root / "Updates" / "stage"
        _write(stage / "half.bin")
        (self.root / "Updates" / "journal.json").write_text(
            json.dumps({"state": "installing"}))
        message = exe_launcher.recover_interrupted_update(self.root, OLLAMA_CFG)
        self.assertIn("не изменён", message)
        self.assertFalse(stage.exists())
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(), "old-app")

    def test_missing_installer_or_app_is_reported(self):
        self.installer.unlink()
        self.assertFalse(self.apply().ok)

    def test_used_installer_in_updates_is_removed_after_success(self):
        kept = _write(self.root / "Updates" / "OllamaSetup.exe", "installer")
        result = exe_launcher.apply_update(
            self.root, OLLAMA_CFG, kept, runner=fake_installer(NEW_FILES))
        self.assertTrue(result.ok)
        self.assertFalse(kept.exists())

    def test_installer_uses_portable_profile_not_the_real_one(self):
        seen = {}

        def runner(command, env, cwd, timeout):
            seen.update(env)
            return fake_installer(NEW_FILES)(command, env, cwd, timeout)

        self.assertTrue(self.apply(runner=runner).ok)
        data = str(self.root / "PortableData")
        self.assertTrue(seen["LOCALAPPDATA"].startswith(data))
        self.assertTrue(seen["TEMP"].startswith(data))

    def test_leftover_native_update_state_is_cleared_after_success(self):
        local = self.root / "PortableData" / "AppData" / "Local" / "Ollama"
        _write(local / "upgraded", "")
        _write(local / "updates_v2" / "1" / "OllamaSetup.exe")
        self.assertTrue(self.apply().ok)
        self.assertFalse((local / "upgraded").exists())
        self.assertFalse((local / "updates_v2" / "1" / "OllamaSetup.exe").exists())


class RecoveryTests(unittest.TestCase):
    """Состояние пользователя: зависло, закрыто через диспетчер задач."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_portable(self._tmp.name)
        self.local = self.root / "PortableData" / "AppData" / "Local" / "Ollama"

    def tearDown(self):
        self._tmp.cleanup()

    def test_clean_portable_is_left_alone(self):
        asked = []
        note = exe_launcher.offer_recovery(
            self.root, OLLAMA_CFG, ask=lambda q: asked.append(q) or True)
        self.assertIsNone(note)
        self.assertEqual(asked, [])

    def test_interrupted_update_is_cleaned_and_offered_again(self):
        _write(self.local / "OllamaSetup.exe", "half-installed")
        _write(self.local / "upgraded", "")
        asked, updated = [], []

        class Done:
            ok = True
            message = "обновлено"

        note = exe_launcher.offer_recovery(
            self.root, OLLAMA_CFG,
            ask=lambda q: asked.append(q) or True,
            updater=lambda root, cfg, source, **kw: updated.append(source) or Done())
        self.assertEqual(len(asked), 1)
        self.assertIn("прервано", asked[0])
        # Следы убраны, установщик сохранён и отдан обновлению.
        self.assertFalse((self.local / "upgraded").exists())
        self.assertFalse((self.local / "OllamaSetup.exe").exists())
        self.assertEqual(updated, [str(self.root / "Updates" / "OllamaSetup.exe")])
        self.assertIn("обновлено", note)

    def test_declining_still_removes_the_crash_causing_traces(self):
        _write(self.local / "OllamaSetup.exe", "half-installed")
        _write(self.local / "upgraded", "")
        exe_launcher.offer_recovery(self.root, OLLAMA_CFG, ask=lambda q: False)
        self.assertFalse((self.local / "upgraded").exists())
        self.assertFalse((self.local / "OllamaSetup.exe").exists())
        self.assertTrue((self.root / "Updates" / "OllamaSetup.exe").is_file(),
                        "установщик не пропадает")

    def test_marker_without_installer_offers_a_fresh_download(self):
        _write(self.local / "upgraded", "")
        asked, sources = [], []

        class Done:
            ok = True
            message = "ok"

        exe_launcher.offer_recovery(
            self.root, OLLAMA_CFG, ask=lambda q: asked.append(q) or True,
            updater=lambda root, cfg, source, **kw: sources.append(source) or Done())
        self.assertIn("Скачать", asked[0])
        self.assertEqual(sources, [""], "пустой источник = адрес из настроек")

    def test_downloaded_update_is_asked_once(self):
        _write(self.local / "updates_v2" / "2" / "OllamaSetup.exe", "new")
        asked = []
        exe_launcher.offer_recovery(self.root, OLLAMA_CFG,
                                    ask=lambda q: asked.append(q) or False)
        self.assertEqual(len(asked), 1)
        self.assertIn("скачала новую версию", asked[0])
        exe_launcher.offer_recovery(self.root, OLLAMA_CFG,
                                    ask=lambda q: asked.append(q) or False)
        self.assertEqual(len(asked), 1, "отказ запоминается: не спрашиваем каждый запуск")

    def test_without_a_desktop_nothing_is_installed_silently(self):
        _write(self.local / "OllamaSetup.exe", "half")
        with mock.patch.object(exe_launcher, "IS_WINDOWS", False):
            exe_launcher.offer_recovery(self.root, OLLAMA_CFG)
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(), "old-app")


class RunUpdateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_portable(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_update_from_a_given_file(self):
        installer = _write(Path(self._tmp.name) / "New.exe", "i")
        result = exe_launcher.run_update(
            self.root, OLLAMA_CFG, str(installer), interactive=False,
            runner=fake_installer(NEW_FILES))
        self.assertTrue(result.ok, result.message)
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(), "new-app")

    def test_missing_file_is_an_error(self):
        result = exe_launcher.run_update(
            self.root, OLLAMA_CFG, str(Path(self._tmp.name) / "nope.exe"),
            interactive=False)
        self.assertFalse(result.ok)

    def test_uses_installer_left_in_updates(self):
        _write(self.root / "Updates" / "OllamaSetup.exe", "i")
        result = exe_launcher.run_update(
            self.root, OLLAMA_CFG, "", interactive=False,
            runner=fake_installer(NEW_FILES))
        self.assertTrue(result.ok, result.message)

    def test_downloads_from_the_configured_url(self):
        urls = []

        def downloader(url, destination, progress):
            urls.append(url)
            _write(destination, "downloaded")
            progress(5, 10)
            return destination

        result = exe_launcher.run_update(
            self.root, OLLAMA_CFG, "", interactive=False,
            confirm_download=False, runner=fake_installer(NEW_FILES),
            downloader=downloader)
        self.assertTrue(result.ok, result.message)
        self.assertEqual(urls, [exe_launcher.update_settings(OLLAMA_CFG)["source_url"]])

    def test_download_needs_confirmation(self):
        with mock.patch.object(exe_launcher, "_ask_yes_no", return_value=False):
            result = exe_launcher.run_update(
                self.root, OLLAMA_CFG, "", interactive=True,
                downloader=lambda *a: self.fail("не должно скачивать"))
        self.assertFalse(result.ok)
        self.assertEqual(result.message, "Обновление отменено.")

    def test_download_failure_is_reported_and_changes_nothing(self):
        def broken(url, destination, progress):
            raise OSError("нет сети")

        result = exe_launcher.run_update(
            self.root, OLLAMA_CFG, "", interactive=False,
            confirm_download=False, downloader=broken)
        self.assertFalse(result.ok)
        self.assertIn("нет сети", result.message)
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(), "old-app")

    def test_no_source_at_all(self):
        cfg = {"app_name": "Game", "target_exe_rel": "App/game.exe"}
        result = exe_launcher.run_update(self.root, cfg, "", interactive=False)
        self.assertFalse(result.ok)
        self.assertIn("UpdatePortable.cmd", result.message)

    def test_command_line_entry(self):
        installer = _write(Path(self._tmp.name) / "New.exe", "i")
        with mock.patch.object(exe_launcher, "_show_info"), \
                mock.patch.object(exe_launcher._BusyNotice, "start"), \
                mock.patch.object(exe_launcher, "_default_installer_runner",
                                  fake_installer(NEW_FILES)):
            code = exe_launcher.update_command(
                self.root, ["--update", str(installer), "--yes"])
        self.assertEqual(code, 0)
        self.assertEqual((self.root / "App" / "ollama app.exe").read_text(), "new-app")


class DownloadTests(unittest.TestCase):
    class Response:
        def __init__(self, chunks, length):
            self._chunks = list(chunks)
            self.headers = {"Content-Length": str(length)}

        def read(self, size):
            return self._chunks.pop(0) if self._chunks else b""

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_download_writes_file_and_reports_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            seen = []
            target = Path(tmp) / "d" / "S.exe"
            exe_launcher.download_installer(
                "https://x/S.exe", target, lambda d, t: seen.append((d, t)),
                opener=lambda req, timeout: self.Response([b"ab", b"cd"], 4))
            self.assertEqual(target.read_bytes(), b"abcd")
            self.assertEqual(seen[-1], (4, 4))
            self.assertFalse(target.with_name("S.exe.part").exists())

    def test_truncated_download_never_becomes_an_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "S.exe"
            with self.assertRaises(OSError):
                exe_launcher.download_installer(
                    "https://x/S.exe", target,
                    opener=lambda req, timeout: self.Response([b"ab"], 10))
            self.assertFalse(target.exists())
            self.assertFalse(target.with_name("S.exe.part").exists())

    def test_download_name(self):
        self.assertEqual(exe_launcher._download_name(
            "https://ollama.com/download/OllamaSetup.exe"), "OllamaSetup.exe")
        self.assertEqual(exe_launcher._download_name("https://x/y?id=1"), "Update.exe")


class PortablizerSideTests(unittest.TestCase):
    def test_update_script_runs_the_launcher(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Ollama", target_exe_rel="App/ollama app.exe")
        text = launcher_mod.render_update_cmd(cfg)
        self.assertTrue(text.isascii())
        self.assertIn("--update", text)
        self.assertIn("LaunchPortable.exe", text)
        self.assertIn("%*", text)
        self.assertIn("\r\n", text.replace("\n", "\r\n"))

    def test_update_script_refuses_targets_outside_app(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Autodesk Fusion",
            target_exe_rel=(
                "PortableData/AppData/Local/Autodesk/webdeploy/production/"
                "build/Fusion.exe"),
        )
        text = launcher_mod.render_update_cmd(cfg)
        self.assertTrue(text.isascii())
        self.assertIn("disabled here", text)
        self.assertIn("Use the application's own supported updater", text)
        self.assertIn("webdeploy", text)
        self.assertNotIn("--update", text)

    def test_refresh_writes_update_script_and_keeps_update_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_portable(tmp, dict(
                OLLAMA_CFG, update={"source_url": "https://a/b.exe"}))
            report = maintenance.refresh(str(root), shared_saves=False)
            self.assertTrue(report.success)
            self.assertTrue((root / launcher_mod.UPDATE_SCRIPT_NAME).is_file())
            self.assertIn(launcher_mod.UPDATE_SCRIPT_NAME, report.updated)
            data = json.loads((root / "launcher_config.json").read_text())
            self.assertEqual(data["update"]["source_url"], "https://a/b.exe")

    def test_profiles_of_builder_and_launcher_do_not_drift(self):
        self.assertEqual(dict(launcher_mod.UPDATE_PROFILES),
                         dict(exe_launcher.UPDATE_PROFILES))

    def test_maintenance_update_runs_launcher_and_maps_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_portable(tmp)
            commands = []
            for code, success in ((0, True), (3, False), (1, False)):
                report = maintenance.update_app(
                    str(root), "C:/dl/Setup.exe",
                    runner=lambda cmd, c=code: commands.append(cmd) or c)
                self.assertEqual(report.success, success, code)
                self.assertTrue(report.messages)
            self.assertEqual(commands[0][1:], ["--update", "C:/dl/Setup.exe", "--yes"])
            report = maintenance.update_app(str(root), runner=lambda cmd: 0)
            self.assertTrue(report.success)

    def test_maintenance_update_reports_missing_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_portable(tmp)
            (root / "App" / "LaunchPortable.exe").unlink()
            report = maintenance.update_app(str(root))
            self.assertFalse(report.success)
            self.assertTrue(report.messages)


if __name__ == "__main__":
    unittest.main()
