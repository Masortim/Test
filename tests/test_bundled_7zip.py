"""Offline 7-Zip resource and Windows integration regression tests."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from portablizer.core import unpacker
from portablizer.core.detect import DetectionResult, InstallerType
from portablizer.core.silentargs import build_attempts


class BundledExtractorTests(unittest.TestCase):
    def test_bundled_is_preferred_and_installed_is_still_available(self):
        with tempfile.TemporaryDirectory() as temp:
            bundled = Path(temp, 'resources', '7zip', 'x64')
            bundled.mkdir(parents=True)
            (bundled / '7z.exe').touch()
            (bundled / '7z.dll').touch()
            installed = Path(temp, 'Program Files', '7-Zip', '7z.exe')
            installed.parent.mkdir(parents=True)
            installed.touch()
            with mock.patch.object(unpacker, 'IS_WINDOWS', True), \
                 mock.patch.object(sys, '_MEIPASS', temp, create=True):
                found = unpacker.find_extractors(
                    env={'ProgramFiles': str(installed.parent.parent)},
                    which=lambda name: None)
            self.assertEqual([e.path for e in found], [str(bundled / '7z.exe'), str(installed)])

    def test_bundled_exe_without_dll_is_not_used(self):
        with tempfile.TemporaryDirectory() as temp:
            bundled = Path(temp, 'resources', '7zip', 'x64')
            bundled.mkdir(parents=True)
            (bundled / '7z.exe').touch()
            with mock.patch.object(unpacker, 'IS_WINDOWS', True), \
                 mock.patch.object(sys, '_MEIPASS', temp, create=True):
                self.assertEqual(unpacker.find_extractors(env={}, which=lambda name: None), [])

    def test_inno_manual_wizard_is_only_offered_with_consent(self):
        det = DetectionResult(installer_type=InstallerType.INNO, confidence=1.0)
        kwargs = dict(detection=det, installer_path='setup.exe', target_dir='C:\\Test App', log_dir='C:\\logs')
        self.assertFalse(any(p.interactive for p in build_attempts(**kwargs)))
        plans = build_attempts(**kwargs, allow_assisted=True)
        manual = plans[-1]
        self.assertTrue(manual.interactive)
        self.assertTrue(manual.label.startswith('Inno Setup: мастер'))
        self.assertTrue(any(a.startswith('/DIR=') for a in manual.args))
        self.assertTrue(any('install-interactive.log' in a for a in manual.args))
        self.assertFalse(any(a.upper() in ('/SILENT', '/VERYSILENT', '/SUPPRESSMSGBOXES') for a in manual.args))


@unittest.skipUnless(sys.platform == 'win32', 'Windows integration test')
class WindowsBundled7ZipTests(unittest.TestCase):
    def test_bundled_7zip_extracts_zip_offline(self):
        seven = Path(__file__).resolve().parents[1] / 'portablizer/resources/7zip/x64/7z.exe'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / 'example.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('Example.exe', 'test payload')
            app = root / 'app'
            app.mkdir()
            ok, message = unpacker.unpack_installer(str(seven), str(archive), str(app), str(root / 'work'),
                                                     accept_warnings=False)
            self.assertTrue(ok, message)
            self.assertEqual((app / 'Example.exe').read_text(), 'test payload')

    def test_real_inno_installer_is_extracted_or_honestly_rejected(self):
        compiler = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
                        'Inno Setup 6', 'ISCC.exe')
        if not compiler.is_file():
            self.skipTest('Inno Setup 6 compiler is not installed')
        seven = Path(__file__).resolve().parents[1] / 'portablizer/resources/7zip/x64/7z.exe'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copyfile(os.environ['ComSpec'], root / 'Example.exe')
            (root / 'secret.tmp').write_text('not application data', encoding='ascii')
            script = root / 'test.iss'
            script.write_text('''[Setup]\nAppName=Example\nAppVersion=1.0\nDefaultDirName={autopf}\\Example\nOutputBaseFilename=fixture\nCompression=lzma2\nSolidCompression=yes\n[Files]\nSource: "Example.exe"; DestDir: "{app}"\nSource: "secret.tmp"; DestDir: "{tmp}"\n''', encoding='ascii')
            compiled = subprocess.run([str(compiler), '/Q', str(script)], capture_output=True, timeout=120)
            self.assertEqual(compiled.returncode, 0, compiled.stdout.decode(errors='replace'))
            setup = root / 'Output/fixture.exe'
            app = root / 'app'
            app.mkdir()
            ok, message = unpacker.unpack_installer(str(seven), str(setup), str(app), str(root / 'work'),
                                                     accept_warnings=False)
            if ok:
                self.assertTrue((app / 'Example.exe').is_file(), list(app.rglob('*')))
                self.assertFalse((app / 'secret.tmp').exists())
            else:
                # 7-Zip 26.05 does not support the current 6.7.1 Inno format.
                # Failure must not be reported as success or promote partial files.
                self.assertIn('кодом', message)
                self.assertFalse((app / 'Example.exe').exists())
                print('Inno fixture rejected by 7-Zip:', message)
