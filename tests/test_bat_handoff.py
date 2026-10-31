"""Регрессии безопасной передачи запуска от Launch.bat к EXE-лончеру."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from portablizer.core import launcher as launcher_mod


class ExeHandoffTests(unittest.TestCase):
    def _bat(self) -> str:
        return launcher_mod.render_bat(launcher_mod.LauncherConfig(
            app_name="Delta", target_exe_rel="App/delta-app.exe"))

    def test_normal_exe_launch_never_falls_through_to_console(self):
        bat = self._bat()
        handoff = bat.split(
            'if defined PORTABLE_USE_EXE_LAUNCHER if exist', 1)[1]
        handoff = handoff.split(
            'rem ===========================================================================',
            1)[0]

        # Нельзя запускать второй экземпляр только потому, что tasklist не
        # увидел оконный лончер за короткий промежуток времени.
        self.assertNotIn("PORTABLE_EXE_ALIVE", handoff)
        self.assertNotIn("goto portable_parsed", handoff)
        self.assertIn("exit /b 0", handoff)
        self.assertIn("Launch.bat --bat-fallback", handoff)

    def test_failed_watch_does_not_claim_to_start_console_copy(self):
        bat = self._bat()
        self.assertIn("No second copy is started", bat)
        self.assertNotIn(
            "The program is started by this console launcher instead", bat)

    def test_explicit_console_fallback_is_still_available(self):
        bat = self._bat()
        self.assertIn('if /i "%~1" == "--bat-fallback"', bat)
        self.assertIn('set "PORTABLE_USE_EXE_LAUNCHER="', bat)


if __name__ == "__main__":
    unittest.main()
