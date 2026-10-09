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
