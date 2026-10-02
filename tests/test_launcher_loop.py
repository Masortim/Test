"""Бесконечный цикл лаунчера игры: «закрылся — открылся — закрылся…».

Жалоба, ради которой появился этот файл:

    Портировал Fallout: New Vegas. Запускаю лончер ``launcher.exe``, нажимаю
    «Играть» — лончер закрывается и открывается снова. И так до бесконечности.

Причина не в портативе, а в лаунчере Bethesda: он переписывает свои
``Fallout.ini``/``FalloutPrefs.ini`` при каждом нажатии «Играть», и как только
запись перестаёт удаваться (файл «только для чтения», каталог запрещён для
записи, INI негде создать), лаунчер закрывается и запускается снова.

Здесь проверяются обе половины лечения:

* **до цикла** — ``GameSettingsGuard`` создаёт сквозные INI рядом с exe,
  подтверждает ``bUseMyGamesDirectory=0``, снимает «только для чтения» и
  называет причину, если запись всё ещё невозможна;
* **во время цикла** — наблюдатель считает самопроизвольные перезапуски
  лаунчера и, когда их слишком много, прерывает «карусель»: настройки лечатся
  заново, а игра запускается напрямую, без зациклившегося посредника.
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
from portablizer.core import portablizer as portablizer_mod
from portablizer.core import saves as saves_mod
from portablizer.core.logutil import Logger


GAME_SETTINGS = {
    "enabled": True,
    "title": "Fallout: New Vegas",
    "profile": "gamebryo-falloutnv",
    "store": "App",
    "default_ini": "Fallout_default.ini",
    "user_inis": ["Fallout.ini", "FalloutPrefs.ini", "FalloutCustom.ini"],
    "ini_settings": [["General", "bUseMyGamesDirectory", "0"],
                     ["General", "SLocalSavePath", "Saves\\"]],
    "saves_dir": "Saves",
    "profile_dirs": ["PortableData/User/Documents/My Games/FalloutNV"],
}

DEFAULT_INI = (
    b"[General]\r\n"
    b"bUseMyGamesDirectory=1\r\n"
    b"SLocalSavePath=Saves\\\r\n"
    b"\r\n"
    b"[Display]\r\n"
    b"iSize W=1024\r\n"
)


class LauncherLoopPortable:
    """Портатив Fallout: New Vegas, у которого лончер уходит в цикл."""

    def __init__(self, temp: str) -> None:
        self.root = Path(temp, "Fallout_New_Vegas_Portable")
        self.app = self.root / "App"
        self.app.mkdir(parents=True)
        (self.app / "FalloutNV.exe").write_bytes(b"MZ game")
        (self.app / "launcher.exe").write_bytes(b"MZ launcher")
        (self.app / "Fallout_default.ini").write_bytes(DEFAULT_INI)
        self.profile = (self.root / "PortableData" / "User" / "Documents"
                        / "My Games" / "FalloutNV")
        self.profile.mkdir(parents=True)

    def write_config(self, **overrides) -> Path:
        config = {
            "app_name": "Fallout New Vegas",
            "target_exe_rel": "App/FalloutNV.exe",
            "launcher_target_rel": "App/launcher.exe",
            "target_args": [],
            "data_dir_name": "PortableData",
            "path_prepend": [],
            "extra_env": {},
            "registry": {"enabled": False},
            "shared_saves": {
                "enabled": True,
                "mode": "inplace",
                "profile": "gamebryo-falloutnv",
                "store": "App",
                "entries": [{
                    "name": "FalloutNV",
                    "store": "App",
                    "host": "Documents/My Games/FalloutNV",
                    "portable":
                        "PortableData/User/Documents/My Games/FalloutNV",
                    "patterns": ["Saves"],
                    "direction": "in",
                }],
            },
            "game_settings": dict(GAME_SETTINGS),
        }
        config.update(overrides)
        path = self.root / "launcher_config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        (self.root / "Launch.bat").write_text("@echo off", encoding="ascii")
        return path

    def cfg(self) -> dict:
        return json.loads((self.root / "launcher_config.json").read_text(
            encoding="utf-8"))

    def guard(self) -> "exe_launcher.GameSettingsGuard":
        return exe_launcher.GameSettingsGuard(self.root, self.cfg())


class SettingsGuardTests(unittest.TestCase):
    """Настройки игры должны быть записываемыми ДО первого нажатия «Играть»."""

    def test_missing_through_config_is_created_next_to_the_exe(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()

            lines = portable.guard().repair()

            for name in ("Fallout.ini", "FalloutPrefs.ini",
                         "FalloutCustom.ini"):
                config = portable.app / name
                self.assertTrue(config.is_file(), name)
                text = config.read_text(encoding="utf-8")
                self.assertIn("bUseMyGamesDirectory=0", text)
                self.assertIn("SLocalSavePath=Saves\\", text)
            self.assertTrue(any("created the portable configuration" in line
                                for line in lines), lines)

    def test_read_only_settings_are_unlocked_and_named_in_the_log(self):
        """Файл «только для чтения» — имя причины цикла в журнале."""
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            (portable.app / "Fallout.ini").write_text(
                "[General]\nSLanguage=russian\n", encoding="utf-8")
            os.chmod(portable.app / "Fallout.ini", 0o444)

            lines = portable.guard().repair()

            self.assertTrue(portable.app.joinpath("Fallout.ini").stat().st_mode
                            & stat.S_IWUSR)
            self.assertTrue(any("read-only" in line for line in lines), lines)

    def test_the_profile_copy_the_launcher_writes_to_is_prepared(self):
        r"""Лаунчер Bethesda пишет настройки в перенаправленный профиль.

        Если копии там нет, а создать её не удаётся — это ровно тот же цикл,
        поэтому копия готовится заранее.
        """
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()

            portable.guard().repair()

            copy = portable.profile / "Fallout.ini"
            self.assertTrue(copy.is_file())
            self.assertIn("bUseMyGamesDirectory=0",
                          copy.read_text(encoding="utf-8"))

    def test_a_settings_file_that_cannot_be_written_names_the_loop_cause(self):
        """Файл, который нельзя перезаписать, называется прямо в журнале."""
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            # Так выглядит «запись невозможна» в самом неприятном случае:
            # на месте файла — каталог, и ни один инструмент его не откроет.
            (portable.app / "Fallout.ini").mkdir()

            guard = portable.guard()
            lines = guard.repair()

            self.assertTrue(guard.blockers, lines)
            self.assertTrue(any("cannot be written" in line for line in lines),
                            lines)
            self.assertTrue(any("loop" in line for line in lines), lines)

    def test_old_portable_without_the_section_is_repaired_from_shared_saves(
            self):
        """Портатив, собранный прежней версией, лечится без пересборки."""
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            config = portable.cfg()
            del config["game_settings"]
            (portable.root / "launcher_config.json").write_text(
                json.dumps(config), encoding="utf-8")

            guard = portable.guard()

            self.assertTrue(guard.enabled)
            self.assertEqual(guard.default_ini, "Fallout_default.ini")
            guard.repair()
            self.assertTrue((portable.app / "Fallout.ini").is_file())
            self.assertIn(
                "bUseMyGamesDirectory=0",
                (portable.app / "Fallout.ini").read_text(encoding="utf-8"))

    def test_settings_chosen_in_the_launcher_are_adopted_next_to_the_exe(self):
        """Настройки, записанные лаунчером в профиль, доходят до игры."""
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            (portable.app / "Fallout.ini").write_text(
                "[Display]\niSize W=1024\n", encoding="utf-8")
            launcher_copy = portable.profile / "Fallout.ini"
            launcher_copy.write_text(
                "[General]\nbUseMyGamesDirectory=1\n"
                "[Display]\niSize W=1920\n", encoding="utf-8")

            lines = portable.guard().adopt(since=0.0)

            adopted = (portable.app / "Fallout.ini").read_text(encoding="utf-8")
            self.assertIn("iSize W=1920", adopted)
            # Portable-ключи подтверждены заново: лаунчер пишет файл целиком,
            # из своих внутренних значений.
            self.assertIn("bUseMyGamesDirectory=0", adopted)
            self.assertTrue(any("chosen in the launcher" in line
                                for line in lines), lines)

    def test_a_manual_edit_next_to_the_exe_is_not_overwritten(self):
        """Устаревшая копия из профиля не заменяет ручные правки."""
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            (portable.app / "Fallout.ini").write_text(
                "[Display]\niSize W=1280\n", encoding="utf-8")
            old = portable.profile / "Fallout.ini"
            old.write_text("[Display]\niSize W=1920\n", encoding="utf-8")
            os.utime(old, (1000, 1000))

            lines = portable.guard().adopt(since=5000.0)

            self.assertIn("iSize W=1280",
                          (portable.app / "Fallout.ini").read_text(
                              encoding="utf-8"))
            self.assertEqual(lines, [])

    def test_doctor_reports_a_healthy_portable(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            with mock.patch.object(exe_launcher, "_show_warning") as warning:
                code = exe_launcher.doctor(portable.root, quiet=False)

            self.assertEqual(code, 0)
            self.assertTrue(warning.called)
            log = (portable.root / "PortableData" / "launcher-run.log")
            self.assertIn("--doctor", log.read_text(encoding="utf-8"))

    def test_doctor_reports_a_settings_file_that_cannot_be_written(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            (portable.app / "Fallout.ini").mkdir()
            with mock.patch.object(exe_launcher, "_show_error") as error:
                code = exe_launcher.doctor(portable.root, quiet=False)

            self.assertEqual(code, 1)
            message = error.call_args.args[0]
            self.assertIn("записать", message)


class LauncherRestartWatcherTests(unittest.TestCase):
    """Счётчик самопроизвольных перезапусков лаунчера."""

    def _watcher(self, **kwargs):
        self.now = 0.0
        return exe_launcher.LauncherRestartWatcher(
            max_restarts=kwargs.pop("max_restarts", 3),
            window=kwargs.pop("window", 120.0),
            relaunch_grace=kwargs.pop("relaunch_grace", 10.0),
            clock=lambda: self.now), kwargs

    def test_quick_relaunches_are_counted_as_a_loop(self):
        watcher, _ = self._watcher()
        watcher.opened()
        for _ in range(3):
            self.now += 0.5
            watcher.closed()
            self.now += 0.2
            watcher.opened()

        self.assertEqual(watcher.restarts(), 3)
        self.assertTrue(watcher.loop_detected())

    def test_a_slow_manual_reopen_is_not_a_loop(self):
        """Пользователь сам открывает лончер повторно — это не «карусель»."""
        watcher, _ = self._watcher()
        watcher.opened()
        for _ in range(5):
            self.now += 60.0
            watcher.closed()
            self.now += 30.0
            watcher.opened()

        self.assertEqual(watcher.restarts(), 0)
        self.assertFalse(watcher.loop_detected())

    def test_a_started_game_disables_the_loop_verdict(self):
        watcher, _ = self._watcher()
        watcher.opened()
        for _ in range(5):
            self.now += 0.5
            watcher.closed()
            self.now += 0.2
            watcher.opened()
        watcher.note_game_started()

        self.assertFalse(watcher.loop_detected())


class FakeProcess:
    """Мини-процесс для наблюдателя: завершается, когда разрешит сценарий."""

    def __init__(self, code: int = 0,
                 exit_after: "int | None" = None) -> None:
        self.pid = 100
        self.returncode = None
        self._code = code
        self._exit_after = exit_after
        self._polls = 0
        self.killed = False

    def wait(self) -> int:
        if self.returncode is None:
            self.returncode = self._code
        return self.returncode

    def poll(self):
        self._polls += 1
        if self._exit_after is not None and self._polls >= self._exit_after:
            self.returncode = self._code
        return self.returncode

    def kill(self) -> None:
        self.killed = True


class FakeClock:
    def __init__(self, step: float = 1.0) -> None:
        self.now = 0.0
        self.step = step

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(seconds, self.step)


class ScriptedLister:
    """Отдаёт заранее записанные снимки процессов (последний — бесконечно)."""

    def __init__(self, snapshots) -> None:
        self.snapshots = list(snapshots)
        self.index = 0

    def __call__(self, root=None):
        snapshot = self.snapshots[min(self.index, len(self.snapshots) - 1)]
        self.index += 1
        return list(snapshot)


class LauncherSupervisorTests(unittest.TestCase):
    """Наблюдатель за сеансом лаунчера."""

    def _images(self, launcher: Path, pid: int, extra=()):
        return [(pid, str(launcher)), *extra]

    def test_a_loop_is_broken_and_reported(self):
        launcher = Path("C:/Portable/App/launcher.exe")
        game = Path("C:/Portable/App/FalloutNV.exe")
        snapshots = [[(1, str(launcher))], [], [(2, str(launcher))], [],
                     [(3, str(launcher))], [],
                     [(4, str(launcher))], []]
        clock = FakeClock()
        outcome = exe_launcher._supervise_launcher(
            FakeProcess(0), target=launcher, main_target=game,
            settings={"enabled": True, "max_restarts": 3, "window": 120.0,
                      "relaunch_grace": 10.0, "poll_interval": 0.5},
            lister=ScriptedLister(snapshots), clock=clock,
            sleep=clock.sleep)

        self.assertTrue(outcome.loop_broken)
        self.assertFalse(outcome.game_started)
        self.assertEqual(outcome.restarts, 3)
        self.assertTrue(any("without FalloutNV.exe" in note
                            for note in outcome.notes), outcome.notes)

    def test_the_game_that_started_stops_the_supervision(self):
        launcher = Path("C:/Portable/App/launcher.exe")
        game = Path("C:/Portable/App/FalloutNV.exe")
        snapshots = [[(1, str(launcher))],
                     [(1, str(launcher)), (2, str(game))]]
        clock = FakeClock()
        process = FakeProcess(0, exit_after=2)
        outcome = exe_launcher._supervise_launcher(
            process, target=launcher, main_target=game,
            settings={"enabled": True, "max_restarts": 3, "poll_interval": 0.5},
            lister=ScriptedLister(snapshots), clock=clock, sleep=clock.sleep)

        self.assertFalse(outcome.loop_broken)
        self.assertTrue(outcome.game_started)

    def test_the_main_executable_is_never_supervised_as_a_launcher(self):
        game = Path("C:/Portable/App/FalloutNV.exe")
        process = FakeProcess(7)
        outcome = exe_launcher._supervise_launcher(
            process, target=game, main_target=game,
            settings={"enabled": True},
            lister=lambda: [], clock=FakeClock(), sleep=lambda _s: None)

        self.assertEqual(outcome.code, 7)
        self.assertFalse(outcome.loop_broken)

    def test_the_guard_can_be_switched_off_for_manual_work(self):
        settings = exe_launcher._loop_guard_settings({}, ["--no-loop-break"])
        self.assertFalse(settings["enabled"])
        settings = exe_launcher._loop_guard_settings({}, ["--user-argument"])
        self.assertTrue(settings["enabled"])
        self.assertEqual(
            exe_launcher._select_target(
                {"target_exe_rel": "App/Game.exe"},
                ["--no-loop-break", "--user-argument"])[1],
            ["--user-argument"])


class LauncherLoopEndToEndTests(unittest.TestCase):
    """Полный сценарий жалобы: нажали «Играть» — лончер зациклился."""

    def _run(self, portable: LauncherLoopPortable, snapshots, codes,
             exit_after: "int | None" = None):
        processes = [FakeProcess(code, exit_after=exit_after)
                     for code in codes]
        spawned: list = []

        def fake_spawn(command, cwd, env, job=None):
            spawned.append(list(command))
            return processes[min(len(spawned) - 1, len(processes) - 1)]

        clock = FakeClock(step=0.5)
        with mock.patch.object(exe_launcher, "find_portable_root",
                               return_value=portable.root), \
                mock.patch.object(exe_launcher, "_spawn_target",
                                  side_effect=fake_spawn), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  ScriptedLister(snapshots)), \
                mock.patch.object(exe_launcher, "_wait_for_portable_processes",
                                  return_value=0), \
                mock.patch.object(exe_launcher, "release_portable_folder",
                                  return_value=[]), \
                mock.patch.object(exe_launcher, "_show_warning") as warning, \
                mock.patch.object(exe_launcher.time, "sleep",
                                  side_effect=clock.sleep):
            code = exe_launcher.run(["--launcher"])
        return code, spawned, warning

    def test_the_loop_is_broken_and_the_game_is_started_directly(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            launcher = str(portable.app / "launcher.exe")
            snapshots = [[(1, launcher)], [], [(2, launcher)], [],
                         [(3, launcher)], [], [(4, launcher)], []]

            code, spawned, warning = self._run(portable, snapshots, [0, 0])

            self.assertEqual(code, 0)
            # Первым запущен лончер игры, вторым — сама игра, напрямую.
            self.assertEqual(Path(spawned[0][0]).name, "launcher.exe")
            self.assertEqual(Path(spawned[1][0]).name, "FalloutNV.exe")
            self.assertTrue(warning.called)
            log = (portable.root / "PortableData" / "launcher-run.log")
            text = log.read_text(encoding="utf-8")
            self.assertIn("the launcher restart loop is detected", text)
            self.assertIn("breaking the loop", text)
            # Сквозные настройки к этому моменту созданы заново.
            self.assertTrue((portable.app / "Fallout.ini").is_file())
            self.assertIn("bUseMyGamesDirectory=0",
                          (portable.app / "Fallout.ini").read_text(
                              encoding="utf-8"))

    def test_a_normal_launcher_run_is_left_alone(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            portable.write_config()
            launcher = str(portable.app / "launcher.exe")
            game = str(portable.app / "FalloutNV.exe")
            # Лончер один раз поднялся, запустил игру и закрылся.
            snapshots = [[(1, launcher)], [(1, launcher), (2, game)],
                         [(2, game)]]

            code, spawned, warning = self._run(portable, snapshots, [0],
                                               exit_after=3)

            self.assertEqual(code, 0)
            self.assertEqual(len(spawned), 1)
            self.assertFalse(warning.called)


class BuiltPortableTests(unittest.TestCase):
    """Сборка портатива: секции конфига и запасной Launch.bat."""

    def _cfg(self, **overrides):
        options = {
            "app_name": "Fallout New Vegas",
            "target_exe_rel": "App/FalloutNV.exe",
            "game_settings": dict(GAME_SETTINGS),
        }
        options.update(overrides)
        return launcher_mod.LauncherConfig(**options)

    def test_the_config_carries_the_settings_and_the_loop_guard(self):
        data = json.loads(launcher_mod.render_config_json(self._cfg()))

        self.assertEqual(data["game_settings"]["default_ini"],
                         "Fallout_default.ini")
        self.assertEqual(data["game_settings"]["user_inis"],
                         GAME_SETTINGS["user_inis"])
        self.assertTrue(data["loop_guard"]["enabled"])
        self.assertEqual(data["loop_guard"]["max_restarts"], 3)

        restored = launcher_mod.config_from_dict(data)
        self.assertEqual(restored.game_settings["user_inis"],
                         GAME_SETTINGS["user_inis"])
        guard = exe_launcher._loop_guard_settings(data, [])
        self.assertTrue(guard["enabled"])
        self.assertEqual(guard["max_restarts"], 3)

    def test_the_loop_guard_can_be_tuned_and_switched_off(self):
        data = json.loads(launcher_mod.render_config_json(self._cfg(
            loop_guard_enabled=False, loop_guard_max_restarts=6,
            loop_guard_window=300.0, loop_guard_relaunch_grace=15.0)))

        self.assertFalse(data["loop_guard"]["enabled"])
        restored = launcher_mod.config_from_dict(data)
        self.assertFalse(restored.loop_guard_enabled)
        self.assertEqual(restored.loop_guard_max_restarts, 6)
        self.assertEqual(restored.loop_guard_window, 300.0)
        self.assertEqual(restored.loop_guard_relaunch_grace, 15.0)

    def test_the_bat_clears_the_read_only_flag_even_without_the_exe(self):
        """Запасной путь обязан снять «только для чтения» без EXE-лончера."""
        bat = launcher_mod.render_bat(self._cfg())

        self.assertIn("call :portable_settings_repair", bat)
        self.assertIn("attrib -r", bat)
        self.assertIn(r"App\Fallout.ini", bat)

        fs = batsim.FakeFS()
        root = r"E:\Fallout_New_Vegas_Portable"
        fs.add_file(root + r"\App\FalloutNV.exe", "MZ")
        fs.add_file(root + r"\App\Fallout_default.ini", "[General]\n")
        fs.add_file(root + r"\Launch.bat", bat)
        result = batsim.run_batch(
            bat, root + r"\Launch.bat", fs,
            argv=["--bat-fallback", "--nopause"],
            env={"USERPROFILE": r"C:\Users\Player",
                 "SystemRoot": r"C:\Windows"})

        self.assertTrue(result.launched)
        self.assertTrue(result.attrib_calls)
        # Отсутствующий Fallout.ini создан из шаблона ещё до запуска игры.
        self.assertTrue(fs.exists(root + r"\App\Fallout.ini"))

    def test_the_build_writes_the_settings_section_the_launcher_reads(self):
        """Сборка и лончер договариваются через launcher_config.json."""
        with tempfile.TemporaryDirectory() as temp:
            portable = LauncherLoopPortable(temp)
            setup = saves_mod.plan(str(portable.root), "Fallout New Vegas",
                                   ["App/FalloutNV.exe", "App/launcher.exe"])
            saves_mod.apply(str(portable.root), setup, Logger())
            self.assertEqual(setup.mode, "inplace")
            self.assertTrue(setup.game_settings.get("enabled"))

            engine = portablizer_mod.Portablizer(Logger())
            options = portablizer_mod.PortableOptions(
                installer_path="fake.exe", output_dir=temp,
                app_name="Fallout New Vegas")
            engine._write_launcher(
                str(portable.root), "Fallout New Vegas", "App/FalloutNV.exe",
                options, [],
                targets=[launcher_mod.TargetInfo(name="FalloutNV",
                                                 rel_path="App/FalloutNV.exe")],
                save_setup=setup)

            data = portable.cfg()
            self.assertTrue(data["game_settings"]["enabled"])
            self.assertEqual(data["game_settings"]["default_ini"],
                             "Fallout_default.ini")
            self.assertEqual(data["game_settings"]["user_inis"],
                             ["Fallout.ini", "FalloutPrefs.ini",
                              "FalloutCustom.ini"])
            self.assertTrue(data["loop_guard"]["enabled"])
            # Тот же конфиг читает рантайм: защита работает без правок.
            guard = exe_launcher.GameSettingsGuard(portable.root, data)
            self.assertTrue(guard.enabled)
            self.assertEqual(guard.default_ini, "Fallout_default.ini")
            self.assertEqual(guard.ini_settings[0][1],
                             "bUseMyGamesDirectory")

            bat = (portable.root / "Launch.bat").read_text(encoding="ascii")
            self.assertIn("attrib -r", bat)
            self.assertIn("call :portable_settings_repair", bat)
            readme = (portable.root / "README_PORTABLE.txt").read_text(
                encoding="utf-8")
            self.assertIn("--doctor", readme)

    def test_no_settings_block_when_the_game_has_no_config_file(self):
        bat = launcher_mod.render_bat(self._cfg(game_settings={}))
        self.assertIn(":portable_settings_repair\ngoto :eof", bat)


if __name__ == "__main__":
    unittest.main()
