"""Регрессии безопасной передачи запуска от Launch.bat к EXE-лончеру."""
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

    def test_exe_handoff_requires_a_per_attempt_startup_marker(self):
        bat = self._bat()
        handoff = bat.split(
            'if defined PORTABLE_USE_EXE_LAUNCHER if exist', 1)[1]
        handoff = handoff.split(
            'rem ===========================================================================',
            1)[0]

        # Маркер уникален для этого запуска (в отличие от tasklist по имени
        # образа) и не даёт второму EXE или другому portable скрыть ошибку.
        self.assertIn("PORTABLE_EXE_HANDOFF_TOKEN=%RANDOM%", bat)
        self.assertIn("PORTABLIZER_LAUNCH_HANDOFF_ID=%PORTABLE_EXE_HANDOFF_TOKEN%",
                      handoff)
        self.assertIn("launcher-exe-started-%PORTABLE_EXE_HANDOFF_TOKEN%.txt",
                      bat)
        self.assertIn("if errorlevel 1 set \"PORTABLE_EXE_HANDOFF_START_FAILED=1\"",
                      handoff)
        self.assertIn("if defined PORTABLE_EXE_HANDOFF_OK", handoff)
        self.assertIn("Launch.bat is continuing", bat)
        self.assertIn("set \"PORTABLE_USE_EXE_LAUNCHER=\"", handoff)
        self.assertIn("exit /b 0", handoff)

    def test_failed_watch_exposes_launcher_log_then_falls_back(self):
        bat = self._bat()
        self.assertIn("launcher-exe-error.log", bat)
        self.assertIn("Full journal:", bat)
        self.assertIn("Launch.bat is continuing with its own visible console launch path.",
                      bat)
        self.assertNotIn("No second copy is started", bat)

    def test_explicit_console_fallback_is_still_available(self):
        bat = self._bat()
        self.assertIn('if /i "%~1" == "--bat-fallback"', bat)
        self.assertIn('set "PORTABLE_USE_EXE_LAUNCHER="', bat)


class ExeHandoffMarkerTests(unittest.TestCase):
    def test_marker_is_written_inside_configured_portable_data_dir(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cfg = {"data_dir_name": "PortableData"}
            token = "123_456_789"

            self.assertTrue(launcher_entry._write_bat_handoff_marker(
                root, cfg, token))
            marker = root / "PortableData" / (
                launcher_entry.BATCH_HANDOFF_MARKER_PREFIX + token + ".txt")
            self.assertEqual(marker.read_text(encoding="ascii"), token + "\n")

    def test_non_ascii_data_dir_uses_same_ascii_fallback_as_batch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            token = "432_765_098"

            self.assertTrue(launcher_entry._write_bat_handoff_marker(
                root, {"data_dir_name": "Данные"}, token))
            self.assertTrue((root / "PortableData" / (
                launcher_entry.BATCH_HANDOFF_MARKER_PREFIX + token + ".txt"
            )).is_file())

    def test_invalid_token_and_path_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            self.assertFalse(launcher_entry._write_bat_handoff_marker(
                root, {"data_dir_name": "PortableData"}, "../outside"))
            self.assertFalse(launcher_entry._write_bat_handoff_marker(
                root, {"data_dir_name": "../outside"}, "123_456"))
            self.assertFalse((Path(temp).parent / "outside").exists())

    def test_main_writes_its_marker_and_consumes_the_private_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cfg = {"data_dir_name": "PortableData"}
            token = "246_810_357"
            env_key = launcher_entry.BATCH_HANDOFF_ENV

            with mock.patch.object(launcher_entry, "find_portable_root",
                                   return_value=root), \
                    mock.patch.object(launcher_entry, "read_launcher_config",
                                      return_value=cfg), \
                    mock.patch.object(launcher_entry, "run", return_value=0), \
                    mock.patch.object(launcher_entry.sys, "argv",
                                      ["LaunchPortable.exe"]), \
                    mock.patch.dict(os.environ, {env_key: token}, clear=False):
                self.assertEqual(launcher_entry.main(), 0)
                self.assertNotIn(env_key, os.environ)

            marker = root / "PortableData" / (
                launcher_entry.BATCH_HANDOFF_MARKER_PREFIX + token + ".txt")
            self.assertTrue(marker.is_file())


if __name__ == "__main__":
    unittest.main()
