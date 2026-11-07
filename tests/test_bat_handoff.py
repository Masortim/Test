"""Регрессии безопасной передачи запуска от Launch.bat к EXE-лончеру."""
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from portablizer.core import launcher as launcher_mod
import portable_launcher_entry as launcher_entry


class ExeHandoffTests(unittest.TestCase):
    def _bat(self) -> str:
        return launcher_mod.render_bat(launcher_mod.LauncherConfig(
            app_name="Delta", target_exe_rel="App/delta-app.exe"))

    def test_exe_handoff_waits_for_target_start_and_checks_its_own_pid(self):
        bat = self._bat()
        handoff = bat.split(
            'if defined PORTABLE_USE_EXE_LAUNCHER if exist', 1)[1]
        handoff = handoff.split(
            'rem ===========================================================================',
            1)[0]

        # Per-attempt files keep unrelated LaunchPortable.exe processes from
        # claiming success. The first marker contains this PID; the second is
        # written only after the configured target process has been spawned.
        self.assertIn("PORTABLE_EXE_HANDOFF_TOKEN=%RANDOM%", bat)
        self.assertIn("PORTABLIZER_LAUNCH_HANDOFF_ID=%PORTABLE_EXE_HANDOFF_TOKEN%",
                      handoff)
        self.assertIn("launcher-exe-started-%PORTABLE_EXE_HANDOFF_TOKEN%.txt",
                      bat)
        self.assertIn("launcher-exe-target-%PORTABLE_EXE_HANDOFF_TOKEN%.txt",
                      bat)
        self.assertIn("if errorlevel 1 set \"PORTABLE_EXE_HANDOFF_START_FAILED=1\"",
                      handoff)
        self.assertIn("tasklist.exe", bat)
        self.assertIn("PID eq %PORTABLE_EXE_HANDOFF_PID%", bat)
        self.assertIn("findstr.exe", bat)
        self.assertIn("if defined PORTABLE_EXE_HANDOFF_OK", handoff)
        self.assertIn("Launch.bat is continuing", bat)
        self.assertIn("set \"PORTABLE_USE_EXE_LAUNCHER=\"", handoff)
        self.assertIn("exit /b 0", handoff)
        self.assertIn("waiting to avoid a duplicate launch", bat)

    def test_target_ack_is_written_only_after_spawn_returns(self):
        source = inspect.getsource(launcher_entry._run_session)
        spawn = source.index("process = _spawn_target(")
        acknowledgement = source.index(
            "_write_bat_handoff_target_marker(", spawn)
        self.assertGreater(acknowledgement, spawn)

    def test_elevated_child_inherits_private_token_without_parent_leak(self):
        env_key = launcher_entry.BATCH_HANDOFF_ENV
        with mock.patch.dict(os.environ, {env_key: "parent-token"}, clear=False):
            observed = []

            def fake_elevated(arguments, **kwargs):
                observed.append(os.environ.get(env_key))
                return 7

            with mock.patch.object(launcher_entry, "_run_elevated",
                                   side_effect=fake_elevated) as elevated:
                result = launcher_entry._run_elevated_with_handoff(
                    ["--launcher"], "child-token", follow=True)

            self.assertEqual(result, 7)
            self.assertEqual(observed, ["child-token"])
            self.assertEqual(os.environ.get(env_key), "parent-token")
            elevated.assert_called_once_with(["--launcher"], follow=True)

    def test_failed_watch_exposes_launcher_log_then_falls_back(self):
        bat = self._bat()
        self.assertIn("launcher-exe-error.log", bat)
        self.assertIn("Full journal:", bat)
        self.assertIn("Launch.bat is continuing with its own visible console launch path.",
                      bat)
        self.assertIn("exited without confirming that it started the target", bat)

    def test_explicit_console_fallback_is_still_available(self):
        bat = self._bat()
        self.assertIn('if /i "%~1" == "--bat-fallback"', bat)
        self.assertIn('set "PORTABLE_USE_EXE_LAUNCHER="', bat)


class ExeHandoffMarkerTests(unittest.TestCase):
    def test_started_marker_records_pid_and_target_marker_is_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cfg = {"data_dir_name": "PortableData"}
            token = "123_456_789"

            self.assertTrue(launcher_entry._write_bat_handoff_started_marker(
                root, cfg, token, 54321))
            self.assertTrue(launcher_entry._write_bat_handoff_target_marker(
                root, cfg, token))
            started = root / "PortableData" / (
                launcher_entry.BATCH_HANDOFF_STARTED_PREFIX + token + ".txt")
            target = root / "PortableData" / (
                launcher_entry.BATCH_HANDOFF_TARGET_PREFIX + token + ".txt")
            self.assertEqual(started.read_text(encoding="ascii"), "54321\n")
            self.assertEqual(target.read_text(encoding="ascii"), token + "\n")

    def test_non_ascii_data_dir_uses_same_ascii_fallback_as_batch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            token = "432_765_098"

            self.assertTrue(launcher_entry._write_bat_handoff_started_marker(
                root, {"data_dir_name": "Данные"}, token, 12345))
            self.assertTrue((root / "PortableData" / (
                launcher_entry.BATCH_HANDOFF_STARTED_PREFIX + token + ".txt"
            )).is_file())

    def test_invalid_token_and_path_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            self.assertFalse(launcher_entry._write_bat_handoff_started_marker(
                root, {"data_dir_name": "PortableData"}, "../outside", 123))
            self.assertFalse(launcher_entry._write_bat_handoff_target_marker(
                root, {"data_dir_name": "PortableData"}, "../outside"))
            self.assertFalse(launcher_entry._write_bat_handoff_started_marker(
                root, {"data_dir_name": "../outside"}, "123_456", 123))
            self.assertFalse((Path(temp).parent / "outside").exists())

    def test_main_records_pid_and_forwards_private_token_without_env_leak(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cfg = {"data_dir_name": "PortableData"}
            token = "246_810_357"
            env_key = launcher_entry.BATCH_HANDOFF_ENV

            with mock.patch.object(launcher_entry, "find_portable_root",
                                   return_value=root), \
                    mock.patch.object(launcher_entry, "read_launcher_config",
                                      return_value=cfg), \
                    mock.patch.object(launcher_entry, "run", return_value=0) as run_mock, \
                    mock.patch.object(launcher_entry.sys, "argv",
                                      ["LaunchPortable.exe"]), \
                    mock.patch.dict(os.environ, {env_key: token}, clear=False):
                self.assertEqual(launcher_entry.main(), 0)
                self.assertNotIn(env_key, os.environ)

            run_mock.assert_called_once_with(handoff_token=token)
            marker = root / "PortableData" / (
                launcher_entry.BATCH_HANDOFF_STARTED_PREFIX + token + ".txt")
            self.assertEqual(marker.read_text(encoding="ascii"),
                             str(os.getpid()) + "\n")


class PyCharmTargetRepairTests(unittest.TestCase):
    def test_runtime_replaces_old_default_with_bin_pycharm_exe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "App" / "PyCharm2026.2" / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "pycharm64.exe").write_bytes(b"MZ")
            (bin_dir / "pycharm.exe").write_bytes(b"MZ")
            cfg = {
                "app_name": "PyCharm",
                "target_exe_rel": "App/PyCharm2026.2/bin/pycharm64.exe",
            }
            config_path = root / "launcher_config.json"
            config_path.write_text(json.dumps(cfg), encoding="utf-8")

            selected = launcher_entry._prefer_pycharm_target(
                root, cfg, cfg["target_exe_rel"])

            expected = "App/PyCharm2026.2/bin/pycharm.exe"
            self.assertEqual(selected, expected)
            self.assertEqual(cfg["target_exe_rel"], expected)
            saved = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["target_exe_rel"], expected)

    def test_explicit_alternate_target_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "App" / "PyCharm2026.2" / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "pycharm.exe").write_bytes(b"MZ")
            cfg = {
                "app_name": "PyCharm",
                "target_exe_rel": "App/PyCharm2026.2/bin/pycharm64.exe",
            }
            alternate = "App/tools/custom.exe"

            selected = launcher_entry._prefer_pycharm_target(
                root, cfg, alternate)

            self.assertEqual(selected, alternate)


if __name__ == "__main__":
    unittest.main()
