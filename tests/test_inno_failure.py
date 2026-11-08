"""Engine-specific diagnostics must not interpret Inno codes as Win32 errors."""
import unittest
import tempfile
from pathlib import Path

from portablizer.core import inno_log

from portablizer.core.detect import DetectionResult, InstallerType
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import (
    PortableOptions, PortableResult, Portablizer, _exit_code_hint,
)


class InnoFailureTests(unittest.TestCase):
    def test_single_file_mode_warns_about_missing_adjacent_parts(self):
        engine = Portablizer(Logger())
        det = DetectionResult(installer_type=InstallerType.INNO, confidence=1.0)
        opts = PortableOptions(installer_path="setup.exe", output_dir="portable", single_file=True)
        text = " ".join(engine._failure_hints(det, 5, opts))
        self.assertIn("единичного файла", text)
        self.assertIn("снимите этот флажок", text)
        self.assertIn("Разрешить окно мастера", text)

    def test_code_5_reports_suppressed_abort_from_log(self):
        engine = Portablizer(Logger())
        det = DetectionResult(installer_type=InstallerType.INNO, confidence=1.0)
        opts = PortableOptions(installer_path="setup.exe", output_dir="portable")
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, 'install.log').write_text(
                '[11:22:33.400] Defaulting to Abort for suppressed message box (Abort/Retry/Ignore):\n'
                'Error writing file example.dll\nAccess denied\n'
                '[11:22:34.500] Rolling back changes.\n'
                '[11:22:35.000] Setup exit code: 5\n', encoding='utf-8-sig')
            text = " ".join(engine._failure_hints(det, 5, opts, temp))
        self.assertIn('автоматически выбран Abort', text)
        self.assertIn('Error writing file example.dll Access denied', text)
        self.assertNotIn('Rolling back changes', text)
        self.assertIn('во время установки', text)
        self.assertNotIn('до начала установки файлов', text)

    def test_dialog_parser_does_not_invent_abort_for_retry_or_missing_log(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, 'install.log')
            self.assertIsNone(inno_log.read_dialog(str(path)))
            path.write_text('[10:00:00.000] Message box (Abort/Retry/Ignore):\n'
                            'Some error\n[10:00:01.000] User chose Retry.\n', encoding='utf-8')
            self.assertIsNone(inno_log.read_dialog(str(path)))

    def test_dialog_parser_handles_utf16_and_manual_abort(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, 'install.log')
            path.write_text('[10:00:00.000] Message box (Abort/Retry/Ignore):\n'
                            'Ошибка записи\n[10:00:01.000] User chose Abort.\n', encoding='utf-16')
            detail = inno_log.read_dialog(str(path))
            self.assertFalse(detail.suppressed)
            self.assertEqual(detail.text, 'Ошибка записи')

    def test_preparation_failure(self):
        hint = _exit_code_hint(7, InstallerType.INNO)
        self.assertIn("подготовка", hint)
        self.assertIn("install.log", hint)
        self.assertEqual(_exit_code_hint(7), "")
        self.assertEqual(_exit_code_hint(7, InstallerType.NSIS), "")

    def test_engine_codes_override_win32(self):
        self.assertIn("во время", _exit_code_hint(5, InstallerType.INNO))
        self.assertIn("отладчик", _exit_code_hint(6, InstallerType.INNO))
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
