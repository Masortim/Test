import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from portablizer.core import registry
from portablizer.core.detect import InstallerType, detect_installer
from portablizer.core.launcher import LauncherConfig, render_bat
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer
from portablizer.core.silentargs import build_silent_plan


class PortablizerOutputTests(unittest.TestCase):
    def setUp(self):
        self.engine = Portablizer(Logger())

    def test_prepare_output_removes_stale_launcher_but_keeps_user_data(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            (app / "Old.exe").write_bytes(b"old")
            (data / "settings.json").write_text("{}", encoding="utf-8")
            (portable / "Launch.bat").write_text("broken", encoding="utf-8")

            self.engine._prepare_output(str(portable), str(app), str(data))

            self.assertTrue(app.is_dir())
            self.assertEqual(list(app.iterdir()), [])
            self.assertFalse((portable / "Launch.bat").exists())
            self.assertTrue((data / "settings.json").exists())

    def test_recovers_program_written_to_redirected_local_appdata(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            before = self.engine._snapshot_install_locations(str(data))

            installed = data / "AppData" / "Local" / "Programs" / "Type"
            installed.mkdir(parents=True)
            (installed / "Type.exe").write_bytes(b"MZ" + b"x" * 32)
            (installed / "Type.dll").write_bytes(b"dependency")

            recovered = self.engine._recover_installed_app(
                app_dir=str(app),
                data_dir=str(data),
                app_name="Type",
                installer_path=str(Path(temp, "TypeSetup.exe")),
                before=before,
            )

            self.assertTrue(recovered)
            self.assertTrue((app / "Type.exe").exists())
            self.assertTrue((app / "Type.dll").exists())

    def test_empty_install_does_not_create_broken_launcher(self):
        # Подменяем платформу, чтобы тест никогда не запускал dummy exe, в том
        # числе на Windows-раннере сборки.
        with tempfile.TemporaryDirectory() as temp, mock.patch(
            "portablizer.core.portablizer.IS_WINDOWS", False
        ):
            installer = Path(temp, "Type.exe")
            installer.write_bytes(b"MZ dummy installer")
            result = self.engine.run(PortableOptions(
                installer_path=str(installer),
                output_dir=temp,
                app_name="Type",
                capture_registry=False,
            ))

            portable = Path(temp, "Type_Portable")
            self.assertFalse(result.success)
            self.assertFalse((portable / "Launch.bat").exists())
            self.assertTrue((portable / "portablizer.log").exists())
            self.assertTrue(any("не найден ни один" in msg for msg in result.messages))

    def test_only_uninstaller_is_not_treated_as_main_program(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "unins000.exe").write_bytes(b"MZ")
            self.assertIsNone(self.engine._find_main_exe(str(app), "Type"))

    def test_successful_install_writes_launcher_for_existing_exe(self):
        class FakePortablizer(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir):
                Path(app_dir, "Type.exe").write_bytes(b"MZ application")
                return 0

        with tempfile.TemporaryDirectory() as temp, mock.patch(
            "portablizer.core.portablizer.IS_WINDOWS", False
        ):
            installer = Path(temp, "TypeSetup.exe")
            installer.write_bytes(b"MZ Inno Setup")
            engine = FakePortablizer(Logger())
            result = engine.run(PortableOptions(
                installer_path=str(installer),
                output_dir=temp,
                app_name="Type",
                capture_registry=False,
            ))

            portable = Path(temp, "Type_Portable")
            self.assertTrue(result.success)
            self.assertEqual(result.main_exe_rel, os.path.join("App", "Type.exe"))
            bat = (portable / "Launch.bat").read_bytes()
            self.assertFalse(bat.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\n", bat.replace(b"\r\n", b""))
            config = json.loads(
                (portable / "launcher_config.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                config["target_exe_rel"].replace("\\", "/"), "App/Type.exe"
            )


class InstallerDetectionTests(unittest.TestCase):
    def test_finds_signature_in_middle_of_large_installer(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "TypeSetup.exe")
            with installer.open("wb") as fh:
                fh.seek(7 * 1024 * 1024)
                fh.write(b"This installation was built with Inno Setup")
                fh.truncate(15 * 1024 * 1024)

            result = detect_installer(str(installer))
            self.assertEqual(result.installer_type, InstallerType.INNO)


class InstallerPlanTests(unittest.TestCase):
    def test_msi_uses_administrative_extraction(self):
        plan = build_silent_plan(
            InstallerType.MSI,
            r"C:\Downloads\Type.msi",
            r"E:\Type_Portable\App",
            is_msi=True,
            log_file=r"E:\Type_Portable\install.log",
        )
        self.assertEqual(plan.program, "msiexec.exe")
        self.assertIn("/a", plan.args)
        self.assertNotIn("/i", plan.args)
        self.assertIn(r"TARGETDIR=E:\Type_Portable\App", plan.args)


class RegistryLocationTests(unittest.TestCase):
    def test_extracts_new_install_location_and_display_icon(self):
        before = {
            r"HKCU\Software\Old": {"InstallLocation": repr(r"C:\Old")},
        }
        after = {
            **before,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Type": {
                "DisplayName": repr("Type"),
                "InstallLocation": repr(r"C:\Program Files\Type"),
                "DisplayIcon": repr(r'"C:\Program Files\Type\Type.exe",0'),
            },
        }
        locations = registry.changed_install_locations(before, after)
        self.assertIn(r"C:\Program Files\Type", locations)
        self.assertIn(r"C:\Program Files\Type\Type.exe", locations)


class LauncherTests(unittest.TestCase):
    def test_batch_switches_to_utf8_before_non_ascii_output(self):
        bat = render_bat(LauncherConfig(
            app_name="Тест",
            target_exe_rel="App/Тест.exe",
        ))
        lines = bat.splitlines()
        self.assertEqual(lines[0], "@echo off")
        self.assertEqual(lines[1], "chcp 65001 >nul 2>&1")
        self.assertIn('set "TARGET=%PORTABLE_ROOT%\\App\\Тест.exe"', bat)


if __name__ == "__main__":
    unittest.main()
