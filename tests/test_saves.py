"""Сквозные портативные сохранения.

Проверяется ровно та жалоба, ради которой писался ``core/saves.py``:

    запускаю ``App\\FalloutNV.exe`` или ``App\\launcher.exe`` — одни сейвы,
    запускаю ``App\\LaunchPortable.exe`` / ``Launch.bat`` — другие, и друг
    друга они не видят.

Тесты идут от конца к началу: сначала поведение (видит ли каждый способ
запуска общий набор сохранений), затем механика (INI, синхронизация, конфиг,
BAT) и лечение уже готовой папки без пересборки.
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import batsim
import portable_launcher_entry as exe_launcher
from portablizer.core import launcher as launcher_mod
from portablizer.core import maintenance
from portablizer.core import procutil
from portablizer.core import saves
from portablizer.core.logutil import Logger


def _write(path: Path, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _touch(path: Path, when: float) -> None:
    os.utime(path, (when, when))


FALLOUT_DEFAULT_INI = (
    b"[General]\r\n"
    b"SStartingCell=\r\n"
    b"bUseMyGamesDirectory=1\r\n"
    b"SLocalSavePath=Saves\\\r\n"
    b"\r\n"
    b"[Display]\r\n"
    b"iSize W=1024\r\n"
)


class FalloutPortable:
    """Портатив Fallout: New Vegas и профиль ПК рядом с ним."""

    def __init__(self, temp: str, with_launcher: bool = True) -> None:
        self.temp = Path(temp)
        self.root = self.temp / "Fallout_New_Vegas_Portable"
        self.app = self.root / "App"
        self.app.mkdir(parents=True)
        (self.app / "FalloutNV.exe").write_bytes(b"MZ")
        if with_launcher:
            (self.app / "launcher.exe").write_bytes(b"MZ")
        (self.app / "Fallout_default.ini").write_bytes(FALLOUT_DEFAULT_INI)

        self.profile = self.temp / "Users" / "Player"
        self.documents = self.profile / "Documents"
        self.host_game = self.documents / "My Games" / "FalloutNV"
        self.host_saves = self.host_game / "Saves"
        self.host_saves.mkdir(parents=True)

        self.portable_game = (self.root / "PortableData" / "User" /
                              "Documents" / "My Games" / "FalloutNV")
        self.portable_saves = self.portable_game / "Saves"
        self.portable_saves.mkdir(parents=True)

    @property
    def env(self):
        return {"PORTABLE_HOST_PROFILE": str(self.profile),
                "PORTABLE_HOST_DOCUMENTS": str(self.documents),
                "USERPROFILE": str(self.profile)}

    def plan(self):
        return saves.plan(str(self.root), "Fallout New Vegas",
                          ["App/FalloutNV.exe", "App/launcher.exe"],
                          profile_dir=str(self.profile),
                          documents_dir=str(self.documents))

    def apply(self, setup=None):
        setup = setup or self.plan()
        return saves.apply(str(self.root), setup, Logger(),
                           profile_dir=str(self.profile),
                           documents_dir=str(self.documents))


class SharedSavesForFalloutTests(unittest.TestCase):
    """Главный сценарий жалобы: одни и те же сейвы при любом запуске."""

    def test_saves_of_both_launch_methods_end_up_in_one_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            _write(game.host_saves / "DirectStart.fos", "прямой запуск exe")
            _write(game.portable_saves / "FromLauncher.fos", "через лончер")

            setup = game.apply()

            self.assertEqual(setup.mode, "inplace")
            self.assertEqual(setup.store, "App")
            self.assertEqual(
                sorted(p.name for p in (game.app / "Saves").iterdir()),
                ["DirectStart.fos", "FromLauncher.fos"])
            # Ни один сейв не потерян: исходники остались на месте.
            self.assertTrue((game.host_saves / "DirectStart.fos").is_file())
            self.assertTrue(
                (game.portable_saves / "FromLauncher.fos").is_file())

    def test_the_game_is_told_to_keep_everything_next_to_the_exe(self):
        """``bUseMyGamesDirectory=0`` — то, что делает сейвы сквозными."""
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()

            text = (game.app / "Fallout_default.ini").read_bytes()
            self.assertIn(b"bUseMyGamesDirectory=0", text)
            self.assertIn(b"SLocalSavePath=Saves\\", text)
            self.assertNotIn(b"bUseMyGamesDirectory=1", text)
            # Формат файла не испорчен: CRLF на месте, BOM не дописан,
            # остальные секции и ключи не тронуты.
            self.assertTrue(text.startswith(b"[General]"))
            self.assertIn(b"\r\n", text)
            self.assertIn(b"iSize W=1024", text)
            self.assertIn(b"SStartingCell=", text)

    def test_runtime_sync_rules_include_saves_but_not_game_inis(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            setup = game.plan()

            self.assertEqual(setup.entries[0].patterns, ["Saves"])
            # Настройки всё ещё переносятся при сборке; правило runtime
            # отвечает только за данные сохранений.
            _write(game.host_game / "Fallout.ini", "[Audio]\niAudioCacheSize=8192\n")
            game.apply(setup)
            self.assertTrue((game.app / "Fallout.ini").is_file())

    def test_result_explains_the_canonical_manual_ini_location(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            description = "\n".join(saves.describe(game.apply()))

            self.assertIn("редактируйте прямо в App", description)
            self.assertIn("не является активной", description)
            self.assertIn("не синхронизируются при каждом запуске", description)

    def test_read_only_default_ini_is_patched_too(self):
        """У установленной игры этот файл часто помечен «только чтение»."""
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            ini = game.app / "Fallout_default.ini"
            os.chmod(ini, 0o444)

            game.apply()

            self.assertIn(b"bUseMyGamesDirectory=0", ini.read_bytes())

    def test_settings_chosen_earlier_are_carried_over_not_reset(self):
        """Переезд не должен сбрасывать графику и язык из My Games."""
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            _write(game.host_game / "Fallout.ini",
                   "[General]\nSLanguage=russian\nbUseMyGamesDirectory=1\n")
            _write(game.host_game / "FalloutPrefs.ini",
                   "[Display]\niSize W=1920\n")

            game.apply()

            moved = (game.app / "Fallout.ini").read_text(encoding="utf-8")
            self.assertIn("SLanguage=russian", moved)
            self.assertIn("bUseMyGamesDirectory=0", moved)
            self.assertIn("iSize W=1920",
                          (game.app / "FalloutPrefs.ini").read_text(
                              encoding="utf-8"))

    def test_the_through_config_file_is_created_next_to_the_exe(self):
        """Жалоба: «рядом с FalloutNV.exe в App не оказалось Fallout.ini».

        Шаблон ``Fallout_default.ini`` — только значения по умолчанию: движок
        читает пользовательские ``Fallout.ini``/``FalloutPrefs.ini``. Пока их
        нет рядом с exe, сквозного конфигурационного файла не существует,
        игра кладёт свой INI в профиль, а пользователь копирует его руками.
        """
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            setup = game.apply()

            self.assertEqual(setup.mode, "inplace")
            for name in ("Fallout.ini", "FalloutPrefs.ini",
                         "FalloutCustom.ini"):
                config = game.app / name
                self.assertTrue(config.is_file(), name)
                text = config.read_text(encoding="utf-8")
                # Созданный файл — не пустой шаблон: в нём уже включено
                # хранение данных внутри портатива.
                self.assertIn("bUseMyGamesDirectory=0", text, name)
                self.assertIn("SLocalSavePath=Saves\\", text, name)
                # Остальные настройки шаблона не потеряны.
                self.assertIn("iSize W=1024", text, name)
            self.assertTrue(any("создаётся рядом с exe" in note
                                for note in saves.describe(setup)))

    def test_the_created_config_file_stays_writable(self):
        """Установщики игр помечают INI «только для чтения» — копия тоже.

        Именно недоступный для записи конфиг заставляет лаунчер Bethesda
        зацикливаться: закрылся — открылся — закрылся…
        """
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            os.chmod(game.app / "Fallout_default.ini", 0o444)

            game.apply()

            for name in ("Fallout_default.ini", "Fallout.ini",
                         "FalloutPrefs.ini", "FalloutCustom.ini"):
                config = game.app / name
                self.assertTrue(config.is_file(), name)
                self.assertTrue(config.stat().st_mode & stat.S_IWUSR, name)

    def test_a_read_only_ini_inside_the_game_folder_is_unlocked(self):
        """INI, который сборка не трогала, тоже должен стать записываемым."""
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            nested = game.app / "Data" / "INI" / "Tweaks.ini"
            _write(nested, "[Audio]\niAudioCacheSize=4096\n")
            os.chmod(nested, 0o444)

            game.apply()

            self.assertTrue(nested.stat().st_mode & stat.S_IWUSR)

    def test_read_only_inis_in_the_portable_profile_are_unlocked_too(self):
        r"""Лаунчер Bethesda пишет свои настройки в перенаправленный профиль.

        «Только для чтение» в PortableData\User\Documents\My Games даёт тот
        же бесконечный цикл, что и в папке игры. Настоящий профиль этого ПК
        при этом не трогаем.
        """
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            copy = _write(game.portable_game / "Fallout.ini",
                          "[General]\nSLanguage=russian\n")
            os.chmod(copy, 0o444)

            game.apply()

            self.assertTrue(copy.stat().st_mode & stat.S_IWUSR)
            # Файлы пользователя вне портатива не меняются.
            self.assertFalse((game.host_game / "Fallout.ini").exists())

    def test_user_settings_are_never_replaced_by_the_template(self):
        """Если пользовательский INI уже есть — он остаётся собой."""
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            _write(game.app / "Fallout.ini",
                   "[General]\nSLanguage=russian\n")
            _write(game.app / "FalloutPrefs.ini",
                   "[Display]\niSize W=1920\n")

            game.apply()

            self.assertIn("SLanguage=russian",
                          (game.app / "Fallout.ini").read_text(
                              encoding="utf-8"))
            self.assertIn("iSize W=1920",
                          (game.app / "FalloutPrefs.ini").read_text(
                              encoding="utf-8"))

    def test_foreign_games_in_my_games_are_never_touched(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            foreign = game.documents / "My Games" / "Skyrim" / "Saves"
            _write(foreign / "Save1.ess", "чужая игра")

            setup = game.apply()

            self.assertEqual([e.name for e in setup.entries], ["FalloutNV"])
            self.assertFalse((game.app / "Saves" / "Save1.ess").exists())

    def test_the_result_is_reported_to_the_user(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            setup = game.apply()
            text = " ".join(saves.describe(setup))
            self.assertIn("Fallout: New Vegas", text)
            self.assertIn("App", text)


class GameDetectionTests(unittest.TestCase):
    def test_detects_fallout_new_vegas(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            detected = saves.detect_game(str(game.app))
            self.assertIsNotNone(detected)
            self.assertEqual(detected.profile.id, "gamebryo-falloutnv")
            self.assertEqual(Path(detected.game_dir), game.app)

    def test_detects_a_game_moved_into_a_subfolder_by_a_repack(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "P", "App", "Game")
            app.mkdir(parents=True)
            (app / "FalloutNV.exe").write_bytes(b"MZ")
            (app / "Fallout_default.ini").write_bytes(FALLOUT_DEFAULT_INI)
            detected = saves.detect_game(str(Path(temp, "P", "App")))
            self.assertIsNotNone(detected)
            self.assertEqual(Path(detected.game_dir), app)

    def test_detects_the_engine_even_when_the_exe_was_renamed(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "game.exe").write_bytes(b"MZ")
            (app / "Fallout_default.ini").write_bytes(FALLOUT_DEFAULT_INI)
            detected = saves.detect_game(str(app))
            self.assertIsNotNone(detected)
            self.assertEqual(detected.profile.id, "gamebryo-falloutnv")

    def test_detects_an_unknown_gamebryo_game_by_its_template(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "Nehrim.exe").write_bytes(b"MZ")
            (app / "Nehrim_default.ini").write_bytes(
                b"[General]\r\nSLocalSavePath=Saves\\\r\n")
            detected = saves.detect_game(str(app))
            self.assertIsNotNone(detected)
            self.assertEqual(detected.profile.id, saves.GENERIC_GAMEBRYO_ID)
            self.assertEqual(detected.profile.my_games, ("Nehrim",))

    def test_an_ordinary_program_is_not_mistaken_for_a_game(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "editor.exe").write_bytes(b"MZ")
            (app / "settings.ini").write_text("[General]\n", encoding="utf-8")
            self.assertIsNone(saves.detect_game(str(app)))


class IniPatchTests(unittest.TestCase):
    SETTINGS = (("General", "bUseMyGamesDirectory", "0"),)

    def test_replaces_an_existing_value(self):
        text, changed = saves.patch_ini_text(
            "[General]\r\nbUseMyGamesDirectory=1\r\n", self.SETTINGS)
        self.assertTrue(changed)
        self.assertIn("bUseMyGamesDirectory=0", text)
        self.assertIn("\r\n", text)

    def test_adds_the_key_to_an_existing_section(self):
        text, changed = saves.patch_ini_text(
            "[General]\nSStartingCell=\n\n[Display]\niSize W=800\n",
            self.SETTINGS)
        self.assertTrue(changed)
        general = text.split("[Display]")[0]
        self.assertIn("bUseMyGamesDirectory=0", general)
        self.assertIn("iSize W=800", text)

    def test_adds_the_section_when_it_is_missing(self):
        text, changed = saves.patch_ini_text("[Display]\niSize W=800\n",
                                             self.SETTINGS)
        self.assertTrue(changed)
        self.assertIn("[General]", text)
        self.assertIn("bUseMyGamesDirectory=0", text)

    def test_a_key_of_another_section_is_not_confused_with_ours(self):
        text, _ = saves.patch_ini_text(
            "[Display]\nbUseMyGamesDirectory=1\n", self.SETTINGS)
        display = text.split("[General]")[0]
        self.assertIn("bUseMyGamesDirectory=1", display)
        self.assertIn("[General]", text)

    def test_nothing_is_rewritten_when_the_value_is_already_right(self):
        original = "[General]\r\nbUseMyGamesDirectory=0\r\n"
        text, changed = saves.patch_ini_text(original, self.SETTINGS)
        self.assertFalse(changed)
        self.assertEqual(text, original)

    def test_already_correct_readonly_ini_is_made_editable(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "Fallout.ini")
            path.write_text("[General]\nbUseMyGamesDirectory=0\n",
                            encoding="utf-8")
            os.chmod(path, 0o444)

            changed = saves.patch_ini_file(str(path), self.SETTINGS)

            self.assertFalse(changed)
            self.assertTrue(path.stat().st_mode & stat.S_IWUSR)

    def test_comments_and_duplicates_survive(self):
        text, _ = saves.patch_ini_text(
            "; комментарий\n[General]\n;bUseMyGamesDirectory=1\n"
            "SCharGenQuest=00102037\n", self.SETTINGS)
        self.assertIn("; комментарий", text)
        self.assertIn(";bUseMyGamesDirectory=1", text)
        self.assertIn("SCharGenQuest=00102037", text)
        self.assertIn("\nbUseMyGamesDirectory=0", text)

    def test_a_non_utf8_file_is_written_back_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "Fallout_default.ini")
            path.write_bytes(b"[General]\r\nSTitle=\xd2\xe5\xf1\xf2\r\n")
            self.assertTrue(saves.patch_ini_file(str(path), self.SETTINGS))
            raw = path.read_bytes()
            self.assertIn(b"\xd2\xe5\xf1\xf2", raw)
            self.assertIn(b"bUseMyGamesDirectory=0", raw)
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))

    def test_an_existing_bom_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "x.ini")
            path.write_bytes(b"\xef\xbb\xbf[General]\r\n")
            saves.patch_ini_file(str(path), self.SETTINGS)
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))


class MergeTests(unittest.TestCase):
    def test_newer_file_wins_and_nothing_is_deleted(self):
        with tempfile.TemporaryDirectory() as temp:
            source, destination = Path(temp, "a"), Path(temp, "b")
            _touch(_write(source / "save.fos", "новая версия"), 20000)
            _touch(_write(destination / "save.fos", "старая версия"), 10000)
            _write(destination / "only-here.fos", "остаться")

            copied = saves.merge_tree(str(source), str(destination))

            self.assertEqual(copied, 1)
            self.assertEqual(
                (destination / "save.fos").read_text(encoding="utf-8"),
                "новая версия")
            self.assertTrue((destination / "only-here.fos").is_file())

    def test_an_older_file_never_overwrites_a_newer_one(self):
        with tempfile.TemporaryDirectory() as temp:
            source, destination = Path(temp, "a"), Path(temp, "b")
            _touch(_write(source / "save.fos", "старая"), 10000)
            _touch(_write(destination / "save.fos", "новая"), 20000)

            self.assertEqual(saves.merge_tree(str(source), str(destination)),
                             0)
            self.assertEqual(
                (destination / "save.fos").read_text(encoding="utf-8"),
                "новая")

    def test_copied_readonly_settings_are_writable_in_the_portable_store(self):
        with tempfile.TemporaryDirectory() as temp:
            source, destination = Path(temp, "profile"), Path(temp, "App")
            ini = _write(source / "Fallout.ini", "[Audio]\niAudioCacheSize=8192\n")
            os.chmod(ini, 0o444)

            self.assertEqual(saves.merge_tree(str(source), str(destination),
                                              ["*.ini"]), 1)

            copied = destination / "Fallout.ini"
            self.assertEqual(copied.read_text(encoding="utf-8"),
                             "[Audio]\niAudioCacheSize=8192\n")
            self.assertTrue(copied.stat().st_mode & stat.S_IWUSR)

    def test_patterns_limit_what_is_merged(self):
        with tempfile.TemporaryDirectory() as temp:
            source, destination = Path(temp, "a"), Path(temp, "b")
            _write(source / "Saves" / "s.fos")
            _write(source / "Fallout.ini")
            _write(source / "Data" / "huge.bsa")
            _write(source / "Data" / "mod.ini")

            saves.merge_tree(str(source), str(destination),
                             patterns=["Saves", "*.ini"])

            self.assertTrue((destination / "Saves" / "s.fos").is_file())
            self.assertTrue((destination / "Fallout.ini").is_file())
            self.assertFalse((destination / "Data" / "huge.bsa").exists())
            # «*» не перепрыгивает через разделитель каталогов.
            self.assertFalse((destination / "Data" / "mod.ini").exists())

    def test_nested_folders_are_merged(self):
        with tempfile.TemporaryDirectory() as temp:
            source, destination = Path(temp, "a"), Path(temp, "b")
            _write(source / "Saves" / "Player1" / "s.fos")
            saves.merge_tree(str(source), str(destination), ["Saves"])
            self.assertTrue(
                (destination / "Saves" / "Player1" / "s.fos").is_file())

    def test_a_folder_is_never_merged_into_itself(self):
        with tempfile.TemporaryDirectory() as temp:
            inner = Path(temp, "a", "b")
            _write(inner / "s.fos")
            self.assertEqual(
                saves.merge_tree(str(Path(temp, "a")), str(inner)), 0)
            self.assertEqual(
                saves.merge_tree(str(inner), str(Path(temp, "a"))), 0)


class SavePlanTests(unittest.TestCase):
    def test_mirror_mode_for_a_program_without_a_known_engine(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Witcher_Portable")
            (root / "App").mkdir(parents=True)
            (root / "App" / "witcher2.exe").write_bytes(b"MZ")
            profile = Path(temp, "Users", "Player")
            _write(profile / "Documents" / "My Games" / "Witcher2" /
                   "Config" / "User.ini")

            setup = saves.plan(str(root), "The Witcher 2",
                               ["App/witcher2.exe"],
                               profile_dir=str(profile),
                               documents_dir=str(profile / "Documents"))

            self.assertEqual(setup.mode, "mirror")
            self.assertEqual(len(setup.entries), 1)
            entry = setup.entries[0]
            self.assertEqual(entry.direction, "both")
            self.assertEqual(entry.host, "Documents/My Games/Witcher2")
            self.assertEqual(
                entry.store,
                "PortableData/User/Documents/My Games/Witcher2")

    def test_saved_games_folders_are_covered_as_well(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            (root / "App" / "DarkSouls.exe").write_bytes(b"MZ")
            profile = Path(temp, "Users", "Player")
            _write(profile / "Saved Games" / "DarkSouls" / "save.sl2")

            setup = saves.plan(str(root), "DarkSouls", ["App/DarkSouls.exe"],
                               profile_dir=str(profile),
                               documents_dir=str(profile / "Documents"))

            self.assertEqual([e.host for e in setup.entries],
                             ["Saved Games/DarkSouls"])

    def test_nothing_to_share_means_the_feature_stays_quiet(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            (root / "App" / "notepad.exe").write_bytes(b"MZ")
            profile = Path(temp, "Users", "Player")
            profile.mkdir(parents=True)

            setup = saves.plan(str(root), "Notepad", ["App/notepad.exe"],
                               profile_dir=str(profile),
                               documents_dir=str(profile / "Documents"))

            self.assertFalse(setup.enabled)
            self.assertEqual(setup.mode, "off")
            self.assertEqual(setup.entries, [])

    def test_generic_executable_names_do_not_grab_foreign_folders(self):
        tokens = saves.name_tokens("Fallout New Vegas",
                                   ["App/launcher.exe", "App/setup.exe",
                                    "App/FalloutNV.exe"])
        self.assertIn("falloutnv", tokens)
        self.assertNotIn("launcher", tokens)
        self.assertNotIn("setup", tokens)
        self.assertFalse(saves.matches_tokens("Launcher", tokens))
        self.assertTrue(saves.matches_tokens("FalloutNV", tokens))
        self.assertTrue(saves.matches_tokens("FalloutNVGOTY", tokens))


class LauncherConfigSavesTests(unittest.TestCase):
    def test_setup_survives_the_json_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            setup = game.apply()
            cfg = launcher_mod.LauncherConfig(
                app_name="Fallout New Vegas",
                target_exe_rel="App/FalloutNV.exe",
                shared_saves=setup.to_dict())

            data = json.loads(launcher_mod.render_config_json(cfg))
            restored = launcher_mod.config_from_dict(data)
            again = saves.SaveSetup.from_dict(restored.shared_saves)

            self.assertEqual(again.mode, "inplace")
            self.assertEqual(again.store, "App")
            self.assertEqual(again.profile, "gamebryo-falloutnv")
            self.assertEqual([e.to_dict() for e in again.entries],
                             [e.to_dict() for e in setup.entries])
            self.assertEqual(again.tokens, setup.tokens)

    def test_an_old_config_without_the_section_still_loads(self):
        cfg = launcher_mod.LauncherConfig(app_name="A",
                                          target_exe_rel="App/a.exe")
        data = json.loads(launcher_mod.render_config_json(cfg))
        data.pop("shared_saves", None)
        restored = launcher_mod.config_from_dict(data)
        self.assertEqual(restored.shared_saves, {})
        self.assertFalse(saves.SaveSetup.from_dict(
            restored.shared_saves).enabled)


class RuntimeSyncTests(unittest.TestCase):
    """Поведение ``LaunchPortable.exe`` вокруг запуска программы."""

    def _session(self, game: FalloutPortable, setup=None):
        setup = setup or game.plan()
        cfg = {"app_name": "Fallout New Vegas",
               "target_exe_rel": "App/FalloutNV.exe",
               "data_dir_name": "PortableData",
               "shared_saves": setup.to_dict()}
        with mock.patch.dict(os.environ, game.env):
            return exe_launcher.SharedSaveSession(game.root, cfg)

    def test_saves_made_by_a_direct_exe_start_are_pulled_in_before_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            # Пользователь поиграл, запустив App\FalloutNV.exe напрямую -
            # сейв лёг в настоящий профиль Windows.
            _write(game.host_saves / "AfterDirectStart.fos", "сейв")

            session = self._session(game)
            report = session.before()

            self.assertTrue(report)
            self.assertTrue(
                (game.app / "Saves" / "AfterDirectStart.fos").is_file())

    def test_inplace_mode_writes_nothing_into_the_host_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            _write(game.app / "Saves" / "Portable.fos", "сейв из портатива")

            session = self._session(game)
            session.before()
            session.after()

            self.assertFalse((game.host_saves / "Portable.fos").exists())

    def test_game_ini_edits_are_not_overwritten_during_startup_sync(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            active = _write(game.app / "Fallout.ini",
                            "[Audio]\niAudioCacheSize=8192\n")
            legacy = _write(game.portable_game / "Fallout.ini",
                            "[Audio]\niAudioCacheSize=2048\n")
            _touch(active, 20000)
            _touch(legacy, 30000)  # even a newer duplicate must not win
            os.chmod(legacy, 0o444)

            session = self._session(game)
            session.before()
            session.after()

            self.assertIn("iAudioCacheSize=8192",
                          active.read_text(encoding="utf-8"))
            self.assertTrue(active.stat().st_mode & stat.S_IWUSR)
            self.assertTrue(legacy.stat().st_mode & stat.S_IWUSR)

    def test_legacy_ini_mirror_is_imported_once_then_never_overwrites_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            legacy_setup = game.plan()
            legacy_setup.entries[0].patterns = ["Saves", "*.ini"]
            active = _write(game.app / "Fallout.ini",
                            "[Audio]\niAudioCacheSize=1024\n")
            legacy = _write(game.portable_game / "Fallout.ini",
                            "[Audio]\niAudioCacheSize=8192\n")
            _touch(active, 10000)
            _touch(legacy, 20000)
            os.chmod(legacy, 0o444)

            first = self._session(game, legacy_setup)
            report = first.before()

            self.assertIn("iAudioCacheSize=8192",
                          active.read_text(encoding="utf-8"))
            self.assertTrue(any("imported 1 INI file(s) once" in line
                                for line in report))
            state = json.loads((game.root / "PortableData" / "SharedSaves" /
                                "state.json").read_text(encoding="utf-8"))
            self.assertTrue(state["settings_imported"])

            _write(active, "[Audio]\niAudioCacheSize=16384\n")
            _write(legacy, "[Audio]\niAudioCacheSize=2048\n")
            _touch(active, 30000)
            _touch(legacy, 40000)  # deliberately newer, but it is obsolete
            second = self._session(game, legacy_setup)
            second.before()

            self.assertIn("iAudioCacheSize=16384",
                          active.read_text(encoding="utf-8"))

    def test_a_program_that_ignores_the_ini_switches_to_two_way_sync(self):
        """Страховка: если игра всё равно пишет в My Games, сводим обе папки.

        Иначе прямой запуск так и не увидел бы сейвы, сделанные через лончер.
        """
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            session = self._session(game)
            session.before()

            # «Игра» в ходе сеанса записала сейв в профиль, а не в App.
            _write(game.host_saves / "Stubborn.fos", "сейв мимо портатива")
            report = session.after()

            self.assertTrue((game.app / "Saves" / "Stubborn.fos").is_file())
            self.assertIn("FalloutNV", session.two_way)
            self.assertTrue(any("kept in sync" in line for line in report))

            # Следующий сеанс уже двусторонний: сделанное в портативе
            # возвращается наружу, и прямой запуск это видит.
            _write(game.app / "Saves" / "FromPortable.fos", "новый сейв")
            again = self._session(game)
            again.after()
            self.assertTrue((game.host_saves / "FromPortable.fos").is_file())

    def test_mirror_mode_synchronises_both_ways(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            (root / "App" / "witcher2.exe").write_bytes(b"MZ")
            profile = Path(temp, "Users", "Player")
            documents = profile / "Documents"
            host_dir = documents / "My Games" / "Witcher2"
            _write(host_dir / "user.ini", "сделано прямым запуском")
            setup = saves.plan(str(root), "The Witcher 2",
                               ["App/witcher2.exe"],
                               profile_dir=str(profile),
                               documents_dir=str(documents))
            cfg = {"data_dir_name": "PortableData",
                   "shared_saves": setup.to_dict()}
            env = {"PORTABLE_HOST_PROFILE": str(profile),
                   "PORTABLE_HOST_DOCUMENTS": str(documents),
                   "USERPROFILE": str(profile)}
            store = root / "PortableData" / "User" / "Documents" / \
                "My Games" / "Witcher2"

            with mock.patch.dict(os.environ, env):
                session = exe_launcher.SharedSaveSession(root, cfg)
                session.before()
                self.assertTrue((store / "user.ini").is_file())
                # Сеанс в портативе создал новый файл.
                _write(store / "savegame.sav", "сделано через лончер")
                session.after()

            self.assertTrue((host_dir / "savegame.sav").is_file())

    def test_a_folder_created_later_is_found_without_rebuilding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            (root / "App" / "Stalker.exe").write_bytes(b"MZ")
            profile = Path(temp, "Users", "Player")
            documents = profile / "Documents"
            documents.mkdir(parents=True)
            setup = saves.plan(str(root), "Stalker", ["App/Stalker.exe"],
                               profile_dir=str(profile),
                               documents_dir=str(documents))
            setup.enabled = True
            setup.mode = "mirror"           # папок ещё нет, но игра их создаст
            cfg = {"data_dir_name": "PortableData",
                   "shared_saves": setup.to_dict()}
            _write(documents / "My Games" / "Stalker" / "s.sav", "сейв")

            with mock.patch.dict(os.environ, {
                    "PORTABLE_HOST_PROFILE": str(profile),
                    "PORTABLE_HOST_DOCUMENTS": str(documents),
                    "USERPROFILE": str(profile)}):
                session = exe_launcher.SharedSaveSession(root, cfg)
                session.before()

            self.assertTrue((root / "PortableData" / "User" / "Documents" /
                             "My Games" / "Stalker" / "s.sav").is_file())

    def test_a_leftover_redirect_is_not_mistaken_for_the_host_profile(self):
        """Прерванный сеанс мог оставить «Документы» внутри портатива."""
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            inside = game.root / "PortableData" / "User" / "Documents"
            with mock.patch.dict(os.environ, {
                    "PORTABLE_HOST_PROFILE": str(game.root / "PortableData"
                                                 / "User"),
                    "PORTABLE_HOST_DOCUMENTS": str(inside),
                    "USERPROFILE": str(game.root / "PortableData" / "User")}):
                session = exe_launcher.SharedSaveSession(
                    game.root,
                    {"data_dir_name": "PortableData",
                     "shared_saves": game.plan().to_dict()})

            self.assertIsNone(session.host_profile)
            self.assertIsNone(session.host_documents)
            self.assertEqual(session.before(), [])

    def test_the_feature_can_be_switched_off_completely(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            _write(game.host_saves / "s.fos")
            with mock.patch.dict(os.environ, game.env):
                session = exe_launcher.SharedSaveSession(
                    game.root, {"data_dir_name": "PortableData",
                                "shared_saves": {"enabled": False}})
            self.assertFalse(session.enabled)
            self.assertEqual(session.before(), [])
            self.assertEqual(session.after(), [])

    def test_a_config_from_an_older_portable_does_not_break_the_launcher(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            session = exe_launcher.SharedSaveSession(
                game.root, {"data_dir_name": "PortableData"})
            self.assertFalse(session.enabled)
            self.assertEqual(session.before(), [])


class ReadOnlySettingsTests(unittest.TestCase):
    """Настроечный INI никогда не должен оставаться «только для чтения».

    Лаунчеры Bethesda переписывают свои INI при каждом нажатии «Играть».
    Если файл недоступен для записи, запись не удаётся — и лаунчер уходит в
    бесконечный цикл: закрылся, открылся, закрылся… Флаг приходит откуда
    угодно: от установщика, от самой игры (Bethesda'вские движки помечают
    настройки «только для чтения» при выходе) или от копии, которую
    пользователь сделал руками.
    """

    def _session(self, game: FalloutPortable, setup=None):
        setup = setup or game.plan()
        cfg = {"app_name": "Fallout New Vegas",
               "target_exe_rel": "App/FalloutNV.exe",
               "data_dir_name": "PortableData",
               "shared_saves": setup.to_dict()}
        with mock.patch.dict(os.environ, game.env):
            return exe_launcher.SharedSaveSession(game.root, cfg)

    def test_a_read_only_ini_is_unlocked_before_the_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            # Пользователь скопировал Fallout.ini из PortableData в App
            # руками — копия принесла флаг «только для чтения».
            config = _write(game.app / "Fallout.ini",
                            "[General]\nbUseMyGamesDirectory=1\n")
            os.chmod(config, 0o444)

            report = self._session(game).before()

            self.assertTrue(config.stat().st_mode & stat.S_IWUSR)
            self.assertTrue(any("read-only" in line for line in report))
            self.assertTrue(any("endless loop" in line for line in report))

    def test_the_flag_the_game_left_behind_is_removed_after_the_session(self):
        """Игра пометила настройки «только для чтения» при выходе.

        Если не снять флаг сразу, следующий запуск — в том числе прямой
        двойной клик по оригинальному ``FalloutNVLauncher.exe`` — упрётся в
        недоступный для записи конфиг и зациклится.
        """
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            config = game.app / "Fallout.ini"
            os.chmod(config, 0o444)

            report = self._session(game).after()

            self.assertTrue(config.stat().st_mode & stat.S_IWUSR)
            self.assertTrue(any("read-only" in line for line in report))

    def test_a_read_only_ini_in_a_subfolder_is_unlocked_too(self):
        """Репаки кладут INI не только в корень: обходим и вложенные папки."""
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            nested = _write(game.app / "Data" / "INI" / "Tweaks.ini",
                            "[Audio]\niAudioCacheSize=4096\n")
            os.chmod(nested, 0o444)

            self._session(game).before()

            self.assertTrue(nested.stat().st_mode & stat.S_IWUSR)

    def test_nothing_is_reported_when_no_file_was_locked(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            game.apply()
            self.assertEqual(self._session(game).before(), [])
            self.assertEqual(self._session(game).after(), [])


class LauncherRunIntegrationTests(unittest.TestCase):
    """Сведение сейвов встроено в сам запуск, а не живёт отдельной кнопкой."""

    def _portable(self, temp):
        game = FalloutPortable(temp)
        setup = game.apply()
        config = {
            "app_name": "Fallout New Vegas",
            "target_exe_rel": "App/FalloutNV.exe",
            "data_dir_name": "PortableData",
            "registry": {"enabled": False},
            "shared_saves": setup.to_dict(),
        }
        (game.root / "launcher_config.json").write_text(
            json.dumps(config), encoding="utf-8")
        (game.root / "Launch.bat").write_text("@echo off", encoding="ascii")
        return game

    def test_run_pulls_before_the_start_and_pushes_after_the_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            game = self._portable(temp)
            _write(game.host_saves / "BeforeRun.fos", "сделано прямым запуском")
            seen = {}

            child = mock.Mock(**{"wait.return_value": 0})

            def spawn(command, cwd, env, job):
                seen["saves"] = sorted(
                    p.name for p in (game.app / "Saves").iterdir())
                return child

            with mock.patch.dict(os.environ, game.env), \
                    mock.patch.object(exe_launcher, "find_portable_root",
                                      return_value=game.root), \
                    mock.patch.object(exe_launcher, "_spawn_target",
                                      side_effect=spawn), \
                    mock.patch.object(exe_launcher,
                                      "_wait_for_portable_processes",
                                      return_value=0), \
                    mock.patch.object(exe_launcher, "release_portable_folder",
                                      return_value=[]), \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[]):
                rc = exe_launcher.run([])

            self.assertEqual(rc, 0)
            # Программа стартовала, уже видя сейв прямого запуска.
            self.assertIn("BeforeRun.fos", seen["saves"])
            log = (game.root / "PortableData" / "launcher-run.log").read_text(
                encoding="utf-8")
            self.assertIn("shared saves:", log)

    def test_sync_saves_command_works_without_starting_the_program(self):
        with tempfile.TemporaryDirectory() as temp:
            game = self._portable(temp)
            _write(game.host_saves / "Manual.fos", "сейв")

            with mock.patch.dict(os.environ, game.env):
                rc = exe_launcher.sync_saves(game.root)

            self.assertEqual(rc, 0)
            self.assertTrue((game.app / "Saves" / "Manual.fos").is_file())


class LaunchBatSavesTests(unittest.TestCase):
    """Запасной консольный лончер обязан делать то же самое."""

    def _cfg(self, setup):
        return launcher_mod.LauncherConfig(
            app_name="Fallout New Vegas",
            target_exe_rel="App/FalloutNV.exe",
            targets=[launcher_mod.TargetInfo(name="FalloutNV",
                                             rel_path="App/FalloutNV.exe")],
            shared_saves=setup.to_dict())

    def test_legacy_inplace_config_does_not_resync_inis_in_bat(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            setup = game.plan()
            setup.entries[0].patterns = ["Saves", "*.ini"]

            bat = launcher_mod.render_bat(self._cfg(setup))

            self.assertNotIn("*.ini", bat)

    def test_the_bat_remembers_the_real_profile_before_redirecting(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            bat = launcher_mod.render_bat(self._cfg(game.apply()))

            self.assertIn('set "PORTABLE_HOST_PROFILE=%USERPROFILE%"', bat)
            self.assertLess(
                bat.index('set "PORTABLE_HOST_PROFILE=%USERPROFILE%"'),
                bat.index('set "USERPROFILE=%PORTABLE_DATA%\\User"'),
                "настоящий профиль надо запомнить ДО перенаправления")
            self.assertTrue(bat.isascii())

    def test_the_bat_imports_saves_before_the_program_starts(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            bat = launcher_mod.render_bat(self._cfg(game.apply()))

            launch = '"%PORTABLE_TARGET%" %PORTABLE_ARGS%'
            self.assertIn(launch, bat)
            self.assertIn("call :portable_saves_import", bat)
            self.assertIn("call :portable_saves_export", bat)
            self.assertNotIn("*.ini", bat,
                             "fallback launcher must not resync Gamebryo INIs")
            self.assertLess(bat.index("call :portable_saves_import"),
                            bat.index(launch),
                            "сейвы надо забрать ДО старта программы")
            self.assertGreater(bat.index("call :portable_saves_export"),
                               bat.index(launch),
                               "вернуть их наружу можно только после выхода")
            body = bat.split("\n:portable_saves_import", 1)[1]
            self.assertIn("xcopy", body.split("goto :eof")[0])

    def test_the_bat_clears_the_read_only_flag_before_copying(self):
        """xcopy молча не переписывает файл «только для чтения».

        В режиме mirror лончер сводит папки целиком, включая настроечные
        INI. Игра при выходе снова помечает их «только для чтения» — без
        attrib такие файлы навсегда остались бы в портативе устаревшими.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            (root / "App" / "witcher2.exe").write_bytes(b"MZ")
            profile = Path(temp, "Users", "Player")
            _write(profile / "Documents" / "My Games" / "Witcher2" /
                   "User.ini")
            setup = saves.plan(str(root), "The Witcher 2",
                               ["App/witcher2.exe"],
                               profile_dir=str(profile),
                               documents_dir=str(profile / "Documents"))
            self.assertEqual(setup.mode, "mirror")

            bat = launcher_mod.render_bat(self._cfg(setup))

            self.assertIn("attrib -r", bat)
            self.assertIn("*.ini", bat)

    def test_the_bat_actually_copies_the_saves_when_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            setup = game.apply()
            bat = launcher_mod.render_bat(self._cfg(setup))

            fs = batsim.FakeFS()
            root = r"E:\Fallout_New_Vegas_Portable"
            fs.add_file(root + r"\App\FalloutNV.exe", "MZ")
            fs.add_file(root + r"\Launch.bat", bat)
            fs.add_file(
                r"C:\Users\Player\Documents\My Games\FalloutNV\Saves\d.fos",
                "сейв прямого запуска")
            result = batsim.run_batch(
                bat, root + r"\Launch.bat", fs, argv=["--nopause"],
                env={"USERPROFILE": r"C:\Users\Player",
                     "SystemRoot": r"C:\Windows"})

            self.assertTrue(result.launched)
            self.assertTrue(fs.exists(root + r"\App\Saves\d.fos"),
                            "сейв прямого запуска не попал в портатив")
            # И копирование произошло ДО запуска программы.
            self.assertTrue(result.copies)

    def test_documents_moved_into_onedrive_are_still_found(self):
        """На современной Windows «Документы» часто живут в OneDrive."""
        with tempfile.TemporaryDirectory() as temp:
            game = FalloutPortable(temp)
            bat = launcher_mod.render_bat(self._cfg(game.apply()))

            fs = batsim.FakeFS()
            root = r"E:\Fallout_New_Vegas_Portable"
            fs.add_file(root + r"\App\FalloutNV.exe", "MZ")
            fs.add_file(root + r"\Launch.bat", bat)
            fs.add_file(r"C:\Users\Player\OneDrive\Documents\My Games"
                        r"\FalloutNV\Saves\cloud.fos", "сейв в OneDrive")
            result = batsim.run_batch(
                bat, root + r"\Launch.bat", fs, argv=["--nopause"],
                env={"USERPROFILE": r"C:\Users\Player",
                     "SystemRoot": r"C:\Windows"})

            self.assertTrue(result.launched)
            self.assertTrue(fs.exists(root + r"\App\Saves\cloud.fos"))

    def test_nothing_is_generated_when_the_feature_is_off(self):
        cfg = launcher_mod.LauncherConfig(app_name="A",
                                          target_exe_rel="App/a.exe")
        bat = launcher_mod.render_bat(cfg)
        self.assertIn(":portable_saves_import\ngoto :eof", bat)
        self.assertNotIn("xcopy", bat)


class ExistingPortableSavesTests(unittest.TestCase):
    """Готовый портатив лечится обновлением, без пересборки."""

    def _old_portable(self, temp):
        game = FalloutPortable(temp)
        cfg = launcher_mod.LauncherConfig(
            app_name="Fallout New Vegas",
            target_exe_rel="App/FalloutNV.exe",
            targets=[
                launcher_mod.TargetInfo(name="FalloutNV",
                                        rel_path="App/FalloutNV.exe"),
                launcher_mod.TargetInfo(name="launcher",
                                        rel_path="App/launcher.exe",
                                        role="launcher",
                                        bat_name="Launch_Launcher.bat"),
            ])
        data = json.loads(launcher_mod.render_config_json(cfg))
        data.pop("shared_saves", None)      # так выглядел конфиг до этой версии
        (game.root / "launcher_config.json").write_text(
            json.dumps(data), encoding="utf-8")
        (game.root / "Launch.bat").write_text("@echo off\nrem old",
                                              encoding="ascii")
        return game

    def test_refresh_merges_both_save_stores_and_rewires_the_game(self):
        with tempfile.TemporaryDirectory() as temp:
            game = self._old_portable(temp)
            _write(game.host_saves / "DirectStart.fos", "прямой запуск")
            _write(game.portable_saves / "FromLauncher.fos", "через лончер")

            with mock.patch.dict(os.environ, game.env), \
                    mock.patch.object(procutil, "release_folder",
                                      return_value=[]):
                report = maintenance.refresh(str(game.root), Logger(),
                                             copy_exe=lambda f, rel: rel)

            self.assertTrue(report.success)
            self.assertEqual(report.saves_mode, "inplace")
            self.assertEqual(report.saves_migrated, 2)
            self.assertEqual(
                sorted(p.name for p in (game.app / "Saves").iterdir()),
                ["DirectStart.fos", "FromLauncher.fos"])
            self.assertIn(b"bUseMyGamesDirectory=0",
                          (game.app / "Fallout_default.ini").read_bytes())
            data = json.loads(
                (game.root / "launcher_config.json").read_text(
                    encoding="utf-8-sig"))
            self.assertTrue(data["shared_saves"]["enabled"])
            self.assertEqual(data["shared_saves"]["mode"], "inplace")
            bat = (game.root / "Launch.bat").read_text(encoding="ascii")
            self.assertIn(":portable_saves_import", bat)

    def test_refresh_creates_the_through_config_file_next_to_the_exe(self):
        """Старый портатив лечится без пересборки — включая конфиг.

        Жалоба: «рядом с FalloutNV.exe в App не оказалось Fallout.ini».
        Обновление лончера создаёт его рядом с exe, и пользователю больше не
        нужно копировать INI из PortableData руками.
        """
        with tempfile.TemporaryDirectory() as temp:
            game = self._old_portable(temp)
            self.assertFalse((game.app / "Fallout.ini").exists())

            with mock.patch.dict(os.environ, game.env), \
                    mock.patch.object(procutil, "release_folder",
                                      return_value=[]):
                report = maintenance.refresh(str(game.root), Logger(),
                                             copy_exe=lambda f, rel: rel)

            self.assertTrue(report.success)
            self.assertTrue((game.app / "Fallout.ini").is_file())
            self.assertTrue((game.app / "FalloutPrefs.ini").is_file())
            text = (game.app / "Fallout.ini").read_text(encoding="utf-8")
            self.assertIn("bUseMyGamesDirectory=0", text)
            self.assertTrue((game.app / "Fallout.ini").stat().st_mode
                            & stat.S_IWUSR)

    def test_refresh_can_leave_the_saves_alone_on_request(self):
        with tempfile.TemporaryDirectory() as temp:
            game = self._old_portable(temp)
            with mock.patch.dict(os.environ, game.env), \
                    mock.patch.object(procutil, "release_folder",
                                      return_value=[]):
                report = maintenance.refresh(str(game.root), Logger(),
                                             copy_exe=lambda f, rel: rel,
                                             shared_saves=False)

            self.assertTrue(report.success)
            self.assertEqual(report.saves_mode, "")
            self.assertIn(b"bUseMyGamesDirectory=1",
                          (game.app / "Fallout_default.ini").read_bytes())


class BuildPipelineSavesTests(unittest.TestCase):
    """Сборка портатива из установщика сразу делает сейвы сквозными."""

    def _build(self, temp, **options):
        from portablizer.core.portablizer import PortableOptions, Portablizer

        profile = Path(temp, "Users", "Player")
        documents = profile / "Documents"
        host_saves = documents / "My Games" / "FalloutNV" / "Saves"
        _write(host_saves / "OldDirectStart.fos", "сейв до портатива")

        class FakePortablizer(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                Path(app_dir, "FalloutNV.exe").write_bytes(b"MZ application")
                Path(app_dir, "FalloutNVLauncher.exe").write_bytes(b"MZ")
                Path(app_dir, "Fallout_default.ini").write_bytes(
                    FALLOUT_DEFAULT_INI)
                return 0

        installer = Path(temp, "FalloutNVSetup.exe")
        installer.write_bytes(b"MZ Inno Setup")
        env = {"PORTABLE_HOST_PROFILE": str(profile),
               "PORTABLE_HOST_DOCUMENTS": str(documents),
               "USERPROFILE": str(profile)}
        with mock.patch.dict(os.environ, env), \
                mock.patch("portablizer.core.portablizer.IS_WINDOWS", False):
            result = FakePortablizer(Logger()).run(PortableOptions(
                installer_path=str(installer), output_dir=temp,
                app_name="Fallout New Vegas", capture_registry=False,
                **options))
        return result, Path(temp, "Fallout New Vegas_Portable"), host_saves

    def test_a_fresh_build_collects_the_saves_of_the_installed_game(self):
        with tempfile.TemporaryDirectory() as temp:
            result, portable, host_saves = self._build(temp)

            self.assertTrue(result.success)
            self.assertEqual(result.saves_mode, "inplace")
            self.assertEqual(result.saves_store_rel, "App")
            self.assertGreaterEqual(result.saves_migrated, 1)
            self.assertTrue(result.saves_notes)
            self.assertTrue(
                (portable / "App" / "Saves" / "OldDirectStart.fos").is_file())
            self.assertIn(b"bUseMyGamesDirectory=0",
                          (portable / "App" /
                           "Fallout_default.ini").read_bytes())
            # Исходная папка игрока осталась нетронутой.
            self.assertTrue((host_saves / "OldDirectStart.fos").is_file())
            # Сквозной конфигурационный файл создаётся рядом с exe сразу:
            # копировать Fallout.ini из PortableData вручную не нужно.
            for name in ("Fallout.ini", "FalloutPrefs.ini"):
                config = portable / "App" / name
                self.assertTrue(config.is_file(), name)
                self.assertIn("bUseMyGamesDirectory=0",
                              config.read_text(encoding="utf-8"), name)
                self.assertTrue(config.stat().st_mode & stat.S_IWUSR, name)

    def test_the_build_explains_the_shared_saves_in_the_readme(self):
        with tempfile.TemporaryDirectory() as temp:
            _result, portable, _host = self._build(temp)
            readme = (portable / "README_PORTABLE.txt").read_text(
                encoding="utf-8-sig")
            self.assertIn("Сохранения", readme)
            self.assertIn("App", readme)
            self.assertIn("Fallout.ini", readme)
            self.assertIn("Fallout_default.ini", readme)
            self.assertIn("редактируйте прямо в App", readme)
            self.assertIn("не синхронизируются", readme)
            self.assertIn("уже создан рядом с exe", readme)
            self.assertIn("бесконечный цикл", readme)

    def test_the_launcher_config_carries_the_setup(self):
        with tempfile.TemporaryDirectory() as temp:
            _result, portable, _host = self._build(temp)
            data = json.loads(
                (portable / "launcher_config.json").read_text(
                    encoding="utf-8-sig"))
            setup = saves.SaveSetup.from_dict(data["shared_saves"])
            self.assertTrue(setup.enabled)
            self.assertEqual(setup.mode, "inplace")
            self.assertEqual([e.name for e in setup.entries], ["FalloutNV"])
            self.assertEqual(setup.entries[0].patterns, ["Saves"])
            bat = (portable / "Launch.bat").read_text(encoding="ascii")
            self.assertIn(":portable_saves_import", bat)

    def test_the_option_can_be_turned_off(self):
        with tempfile.TemporaryDirectory() as temp:
            result, portable, _host = self._build(temp, shared_saves=False)
            self.assertEqual(result.saves_mode, "off")
            self.assertIn(b"bUseMyGamesDirectory=1",
                          (portable / "App" /
                           "Fallout_default.ini").read_bytes())
            data = json.loads(
                (portable / "launcher_config.json").read_text(
                    encoding="utf-8-sig"))
            self.assertFalse(data.get("shared_saves", {}).get("enabled"))


class SharedSavesGuiTests(unittest.TestCase):
    """Режимом можно управлять из окна, а не только из кода."""

    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "portablizer", "gui", "main_window.py"),
                  encoding="utf-8") as handle:
            cls.window = handle.read()

    def test_window_has_the_shared_saves_checkbox(self):
        self.assertIn("self.cb_shared_saves = QCheckBox(", self.window)
        self.assertIn("shared_saves=self.cb_shared_saves.isChecked()",
                      self.window)
        self.assertIn("self.cb_shared_saves.setChecked(True)", self.window)

    def test_the_result_dialog_tells_where_the_saves_are(self):
        self.assertIn("result.saves_notes", self.window)


if __name__ == "__main__":
    unittest.main()
