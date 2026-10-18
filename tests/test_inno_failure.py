"""Engine-specific diagnostics must not interpret Inno codes as Win32 errors."""
import unittest

from portablizer.core.detect import DetectionResult, InstallerType
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import (
    PortableOptions, PortableResult, Portablizer, _exit_code_hint,
)


class InnoFailureTests(unittest.TestCase):
    def test_preparation_failure(self):
        hint = _exit_code_hint(7, InstallerType.INNO)
        self.assertIn("подготовка", hint)
        self.assertIn("install.log", hint)
        self.assertEqual(_exit_code_hint(7), "")
        self.assertEqual(_exit_code_hint(7, InstallerType.NSIS), "")

    def test_engine_codes_override_win32(self):
        self.assertIn("отменена", _exit_code_hint(5, InstallerType.INNO))
        self.assertIn("доступе", _exit_code_hint(5))
        self.assertIn("перезагрузка", _exit_code_hint(8, InstallerType.INNO))

    def test_final_failure_explains_preparation_and_points_to_real_log(self):
        engine = Portablizer(Logger())
        det = DetectionResult(installer_type=InstallerType.INNO, confidence=1.0)
        hints = engine._failure_hints(det, 7, PortableOptions(installer_path="planetvpn.exe", output_dir="portable"))
        text = " ".join(hints)
        self.assertIn("PrepareToInstall", text)
        self.assertIn("install.log", text)
        self.assertIn("драйвер", text)
        self.assertNotIn("портативной сделать нельзя", text)
        result = PortableResult(success=False)
        result.hints = hints
        self.assertIn("подготовка", engine._failure_message(det, 7, result))


if __name__ == "__main__":
    unittest.main()
