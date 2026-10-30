import ast
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import batsim
import portable_launcher_entry as exe_launcher
from portablizer.core import elevate as elevate_mod
from portablizer.core import launcher as launcher_mod
from portablizer.core import maintenance as maintenance_mod
from portablizer.core import maintenance
from portablizer.core import procutil
from portablizer.core import registry
from portablizer.core.detect import (
    TRUSTED_CONFIDENCE, DetectionResult, InstallerType, InstallShieldGeneration,
    detect_installer, scan_media_layout,
)
from portablizer.core.launcher import (
    LauncherConfig, ensure_ascii_bat, render_bat, render_config_json,
    render_vbs,
)
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import (
    PortableOptions, PortableResult, Portablizer, _burn_layout_payloads,
    _exit_code_hint, _format_exit_code, read_installshield_result,
    retarget_response_file, _stage_single_file,
)
from portablizer.core.silentargs import (
    SilentPlan, build_attempts, build_burn_layout_plan, build_custom_cli_plan,
    build_installscript_plan, build_installshield_msi_plan, build_silent_plan,
)


def _labels(bat: str):
    return {line[1:].strip() for line in bat.splitlines()
            if line.startswith(":") and not line.startswith("::")}


def _jump_targets(bat: str):
    targets = set(re.findall(r"goto\s+:?([A-Za-z_]\w*)", bat))
    targets |= set(re.findall(r"call\s+:(\w+)", bat))
    return {t for t in targets if t.lower() != "eof"}


class PortablizerOutputTests(unittest.TestCase):
    def setUp(self):
        self.engine = Portablizer(Logger())

    def test_single_file_staging_contains_only_selected_installer(self):
        with tempfile.TemporaryDirectory() as temp:
            source_dir = Path(temp, "media")
            source_dir.mkdir()
            installer = source_dir / "setup.exe"
            installer.write_bytes(b"selected installer")
            (source_dir / "setup-1.bin").write_bytes(b"neighbor part")
            (source_dir / "payloads").mkdir()

            staging, copied = _stage_single_file(str(installer))
            try:
                self.assertEqual(Path(copied).name, "setup.exe")
                self.assertEqual(Path(copied).read_bytes(), b"selected installer")
                self.assertEqual([p.name for p in Path(staging).iterdir()],
                                 ["setup.exe"])
            finally:
                shutil.rmtree(staging, ignore_errors=True)

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
            (portable / "cleanup_host.reg").write_text("x", encoding="utf-8")

            self.engine._prepare_output(str(portable), str(app), str(data))

            self.assertTrue(app.is_dir())
            self.assertEqual(list(app.iterdir()), [])
            self.assertFalse((portable / "Launch.bat").exists())
            self.assertFalse((portable / "cleanup_host.reg").exists())
            self.assertTrue((data / "settings.json").exists())

    def test_detection_failure_does_not_clear_existing_output(self):
        """Старый App удаляется только после успешного распознавания входа."""
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "ExampleSetup.exe")
            installer.write_bytes(b"not a real installer")
            portable = Path(temp, "ExampleSetup_Portable")
            app = portable / "App"
            app.mkdir(parents=True)
            (portable / "PortableData").mkdir()
            existing = app / "ExistingApp.exe"
            existing.write_bytes(b"keep this build")
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp)

            with mock.patch(
                "portablizer.core.portablizer.detect_installer",
                side_effect=RuntimeError("synthetic detection failure"),
            ):
                result = self.engine.run(opts)

            self.assertFalse(result.success)
            self.assertEqual(existing.read_bytes(), b"keep this build")

    def test_prepare_output_frees_the_folder_before_deleting_anything(self):
        """Живой процесс из прошлого запуска не должен ронять пересборку.

        Симптом до исправления: пользователь запускал портатив, закрывал
        его, но фоновый помощник продолжал держать App — и следующая сборка
        обрывалась сообщением «не удалось очистить старый файл результата».
        """
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            released = []

            with mock.patch.object(procutil, "release_folder",
                                   side_effect=lambda root, **_k:
                                   released.append(root) or ["helper.exe"]):
                self.engine._prepare_output(str(portable), str(app), str(data))

            self.assertIn(str(portable), released)
            self.assertIn("helper.exe", self.engine.log.text)

    def test_remove_path_retries_while_the_file_is_locked(self):
        """Секундная блокировка (антивирус, индексатор) — не повод падать."""
        with tempfile.TemporaryDirectory() as temp:
            victim = Path(temp, "locked.log")
            victim.write_text("x", encoding="ascii")
            attempts = {"n": 0}
            real_remove = os.remove

            def flaky(path):
                attempts["n"] += 1
                if attempts["n"] < 3:
                    raise OSError(32, "used by another process")
                real_remove(path)

            with mock.patch("os.remove", side_effect=flaky), \
                    mock.patch.object(procutil, "release_folder",
                                      return_value=[]), \
                    mock.patch("time.sleep"):
                self.engine._remove_path(str(victim))

            self.assertEqual(attempts["n"], 3)
            self.assertFalse(victim.exists())

    def test_remove_path_gives_up_with_the_original_error(self):
        with tempfile.TemporaryDirectory() as temp:
            victim = Path(temp, "locked.log")
            victim.write_text("x", encoding="ascii")
            with mock.patch("os.remove",
                            side_effect=OSError(32, "used by another process")), \
                    mock.patch.object(procutil, "release_folder",
                                      return_value=[]), \
                    mock.patch("time.sleep"):
                with self.assertRaises(OSError):
                    self.engine._remove_path(str(victim))

    def test_prepare_output_removes_stale_per_target_launchers(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            for name in ("Launch_PerformanceTester.bat",
                         "Launch_userContentManager.vbs", "Launch_Configurator.exe",
                         "Launch_Menu.bat"):
                (portable / name).write_text("stale", encoding="ascii")

            self.engine._prepare_output(str(portable), str(app), str(data))

            self.assertFalse(any(portable.glob("Launch_*.*")))

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

    def test_recovers_new_app_inside_existing_vendor_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            vendor = data / "AppData" / "Local" / "Programs" / "Vendor"
            app.mkdir(parents=True)
            vendor.mkdir(parents=True)
            before = self.engine._snapshot_install_locations(str(data))

            installed = vendor / "Type"
            installed.mkdir()
            (installed / "Type.exe").write_bytes(b"MZ application")

            recovered = self.engine._recover_installed_app(
                app_dir=str(app),
                data_dir=str(data),
                app_name="Type",
                installer_path=str(Path(temp, "Type.exe")),
                before=before,
            )

            self.assertTrue(recovered)
            self.assertTrue((app / "Type.exe").exists())

    def test_recovery_does_not_take_similarly_named_preinstalled_program(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            host = Path(temp, "ProgramFiles")
            unrelated = host / "TypeScript"
            app.mkdir(parents=True)
            data.mkdir()
            unrelated.mkdir(parents=True)
            (unrelated / "TypeScript.exe").write_bytes(b"MZ unrelated")

            roots = [(str(host), 110, False)]
            before = {
                os.path.normcase(os.path.abspath(str(host))): {
                    os.path.normcase(os.path.abspath(str(unrelated))),
                    os.path.normcase(os.path.abspath(
                        str(unrelated / "TypeScript.exe"))),
                }
            }
            with mock.patch.object(
                self.engine, "_install_search_roots", return_value=roots
            ):
                recovered = self.engine._recover_installed_app(
                    app_dir=str(app), data_dir=str(data), app_name="Type",
                    installer_path=str(Path(temp, "TypeSetup.exe")),
                    before=before,
                )

            self.assertFalse(recovered)
            self.assertEqual(list(app.iterdir()), [])

    def test_recovery_never_promotes_installer_directory_or_its_ancestor(self):
        with tempfile.TemporaryDirectory() as temp:
            downloads = Path(temp, "Downloads")
            downloads.mkdir()
            installer = downloads / "delta-windows-x86_64-setup.exe"
            installer.write_bytes(b"installer")
            for name in ("delta.exe", "other.exe", "old.zip", "new.mp4", "photo.jpg"):
                (downloads / name).write_bytes(b"unrelated")
            (downloads / "other-folder").mkdir()
            (downloads / "other-folder" / "another.exe").write_bytes(b"unrelated")
            app = Path(temp, "portable", "App")
            data = app.parent / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            with mock.patch.object(self.engine, "_install_search_roots", return_value=[]):
                for location in (str(downloads), str(downloads / "delta.exe"), temp):
                    recovered = self.engine._recover_installed_app(
                        str(app), str(data), "delta", str(installer), {},
                        registry_locations=[location], shortcut_locations=[location])
                    self.assertFalse(recovered)
                    self.assertEqual(list(app.iterdir()), [])
            with self.assertRaises(OSError):
                self.engine._copy_recovered_tree(str(downloads), str(app), str(data), str(installer))

    def test_recovery_prefers_separate_installation_over_downloads(self):
        with tempfile.TemporaryDirectory() as temp:
            downloads = Path(temp, "Downloads")
            installed = Path(temp, "Installed", "delta")
            downloads.mkdir()
            installed.mkdir(parents=True)
            installer = downloads / "delta-windows-x86_64-setup.exe"
            installer.write_bytes(b"installer")
            for name in ("old.zip", "movie.mp4", "picture.png", "other.exe"):
                (downloads / name).write_bytes(b"unrelated")
            (installed / "delta.exe").write_bytes(b"MZ application")
            (installed / "data.dll").write_bytes(b"dependency")
            app = Path(temp, "portable", "App")
            data = app.parent / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            with mock.patch.object(self.engine, "_install_search_roots", return_value=[]), \
                    mock.patch.object(self.engine, "_remove_recovered_source"):
                self.assertTrue(self.engine._recover_installed_app(
                    str(app), str(data), "delta", str(installer), {},
                    registry_locations=[str(downloads), str(installed)]))
            self.engine._supplement_recovered_from_registry(
                str(app), "delta", str(installer), [str(downloads)])
            self.assertEqual({x.name for x in app.iterdir()}, {"delta.exe", "data.dll"})
            self.assertTrue((downloads / "other.exe").exists())

    def test_search_does_not_treat_new_download_as_installed_app(self):
        with tempfile.TemporaryDirectory() as temp:
            downloads = Path(temp, "Downloads")
            downloads.mkdir()
            installer = downloads / "delta-windows-x86_64-setup.exe"
            installer.write_bytes(b"installer")
            (downloads / "delta.exe").write_bytes(b"unrelated")
            app = Path(temp, "portable", "App")
            data = app.parent / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            with mock.patch.object(self.engine, "_install_search_roots",
                                   return_value=[(str(downloads), 100, False)]):
                self.assertFalse(self.engine._recover_installed_app(
                    str(app), str(data), "delta", str(installer), {}))
            self.assertEqual(list(app.iterdir()), [])

    def test_registry_supplement_copies_only_specific_referenced_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            downloads = Path(temp, "Downloads")
            downloads.mkdir()
            installer = downloads / "delta-windows-x86_64-setup.exe"
            installer.write_bytes(b"installer")
            (downloads / "data.bin").write_bytes(b"needed")
            (downloads / "other.exe").write_bytes(b"unrelated")
            (downloads / "photo.jpg").write_bytes(b"unrelated")
            assets = downloads / "assets"
            assets.mkdir()
            (assets / "required.dat").write_bytes(b"needed")
            app = Path(temp, "portable", "App")
            app.mkdir(parents=True)
            (app / "delta.exe").write_bytes(b"installed")
            (app / "assets").mkdir()
            (app / "assets" / "required.dat").write_bytes(b"already installed")
            self.engine._supplement_recovered_from_registry(
                str(app), "delta", str(installer),
                [str(downloads), str(installer), str(downloads / "data.bin"), str(assets)])
            self.assertEqual((app / "data.bin").read_bytes(), b"needed")
            self.assertEqual((app / "assets" / "required.dat").read_bytes(), b"already installed")
            self.assertFalse((app / "other.exe").exists())
            self.assertFalse((app / "photo.jpg").exists())
            self.assertFalse((app / installer.name).exists())

    def test_registry_supplement_ignores_directory_only_reference(self):
        with tempfile.TemporaryDirectory() as temp:
            downloads = Path(temp, "Downloads")
            downloads.mkdir()
            installer = downloads / "delta.msi"
            installer.write_bytes(b"installer")
            (downloads / "delta.exe").write_bytes(b"unrelated")
            (downloads / "archive.zip").write_bytes(b"unrelated")
            app = Path(temp, "portable", "App")
            app.mkdir(parents=True)
            (app / "delta.exe").write_bytes(b"installed")
            self.engine._supplement_recovered_from_registry(
                str(app), "delta", str(installer), [str(downloads)])
            self.assertEqual((app / "delta.exe").read_bytes(), b"installed")
            self.assertEqual({x.name for x in app.iterdir()}, {"delta.exe"})
            self.assertNotIn(str(downloads), self.engine._recovered_sources)

    def test_empty_install_does_not_create_broken_launcher(self):
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
            self.assertTrue(any("не найден ни один" in m for m in result.messages))

    def test_only_uninstaller_is_not_treated_as_main_program(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "unins000.exe").write_bytes(b"MZ")
            self.assertIsNone(self.engine._find_main_exe(str(app), "Type"))

    def test_successful_install_writes_portable_launcher_set(self):
        class FakePortablizer(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
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
            # Главная причина «мигающего окна» — не-ASCII байты в .bat.
            self.assertTrue(all(b < 128 for b in bat))

            self.assertTrue((portable / "LaunchHidden.vbs").exists())
            exe_launcher_path = portable / "App" / "LaunchPortable.exe"
            self.assertTrue(exe_launcher_path.is_file())
            self.assertEqual(exe_launcher_path.read_bytes()[:2], b"MZ")
            self.assertEqual(
                result.portable_launcher_exe_rel,
                os.path.join("App", "LaunchPortable.exe"),
            )
            config = json.loads(
                (portable / "launcher_config.json").read_text(encoding="utf-8"))
            self.assertEqual(
                config["target_exe_rel"].replace("\\", "/"), "App/Type.exe")
            # Реестр не захватывался — лончер не должен его трогать.
            self.assertFalse(config["registry"]["enabled"])

    def test_readme_promises_no_installation_on_other_pc(self):
        class FakePortablizer(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                Path(app_dir, "Type.exe").write_bytes(b"MZ application")
                return 0

        with tempfile.TemporaryDirectory() as temp, mock.patch(
            "portablizer.core.portablizer.IS_WINDOWS", False
        ):
            installer = Path(temp, "TypeSetup.exe")
            installer.write_bytes(b"MZ Inno Setup")
            FakePortablizer(Logger()).run(PortableOptions(
                installer_path=str(installer), output_dir=temp,
                app_name="Type", capture_registry=False))
            readme = Path(temp, "Type_Portable", "README_PORTABLE.txt")
            text = readme.read_text(encoding="utf-8")
            self.assertIn("Установленные программы", text)
            self.assertIn("--nopause", text)

    def test_ready_exe_launcher_is_copied_into_app(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            app.mkdir(parents=True)
            template = Path(temp, "PortableLauncher.exe")
            template.write_bytes(b"MZ" + b"portable launcher")

            with mock.patch(
                "portablizer.core.portablizer.bundled_exe_launcher_path",
                return_value=str(template),
            ), mock.patch(
                # На CI рядом лежит и onedir-сборка лончера; тест про onefile.
                "portablizer.core.portablizer.bundled_exe_launcher_dir",
                return_value="",
            ):
                rel = self.engine._copy_exe_launcher(str(portable))

            generated = app / "LaunchPortable.exe"
            self.assertEqual(rel, os.path.join("App", "LaunchPortable.exe"))
            self.assertEqual(generated.read_bytes(), template.read_bytes())

    def test_invalid_exe_launcher_resource_is_not_copied(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            (portable / "App").mkdir(parents=True)
            template = Path(temp, "not-an-exe.bin")
            template.write_bytes(b"invalid")

            with mock.patch(
                "portablizer.core.portablizer.bundled_exe_launcher_path",
                return_value=str(template),
            ), mock.patch(
                "portablizer.core.portablizer.bundled_exe_launcher_dir",
                return_value="",
            ):
                rel = self.engine._copy_exe_launcher(str(portable))

            self.assertEqual(rel, "")
            self.assertFalse((portable / "App" / "LaunchPortable.exe").exists())


class PortableExeLauncherTests(unittest.TestCase):
    """The App EXE must find the root and launch with the portable profile."""

    def _portable(self, temp):
        root = Path(temp, "My App_Portable")
        app = root / "App"
        app.mkdir(parents=True)
        target = app / "Program.exe"
        target.write_bytes(b"MZ target")
        config = {
            "app_name": "Program",
            "target_exe_rel": "App/Program.exe",
            "target_args": ["--from-config"],
            "data_dir_name": "PortableData",
            "path_prepend": ["App"],
            "extra_env": {"PROGRAM_HOME": "%PORTABLE_ROOT%/App"},
            "registry": {"enabled": False},
        }
        (root / "launcher_config.json").write_text(
            json.dumps(config), encoding="utf-8"
        )
        (root / "Launch.bat").write_text("@echo off", encoding="ascii")
        return root, app, target

    def test_finds_root_from_exe_inside_app(self):
        with tempfile.TemporaryDirectory() as temp:
            root, app, _target = self._portable(temp)
            self.assertEqual(exe_launcher.find_portable_root(app), root.resolve())

    def test_launches_real_program_with_portable_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            root, app, target = self._portable(temp)
            child = mock.Mock(**{"wait.return_value": 17})
            with mock.patch.object(exe_launcher, "find_portable_root",
                                   return_value=root), mock.patch.object(
                exe_launcher, "_spawn_target", return_value=child
            ) as run_process:
                rc = exe_launcher.run(["--user-argument"])

            self.assertEqual(rc, 17)
            args, _kwargs = run_process.call_args
            self.assertEqual(
                list(args[0]),
                [str(target), "--from-config", "--user-argument"],
            )
            self.assertEqual(args[1], str(app))
            env = args[2]
            for key in ("APPDATA", "LOCALAPPDATA", "USERPROFILE", "TEMP",
                        "PROGRAMDATA", "PUBLIC"):
                self.assertTrue(env[key].startswith(str(root)), key)
            self.assertEqual(env["PORTABLE_ROOT"], str(root))
            self.assertEqual(
                env["PORTABLE_DOCUMENTS"],
                str(root / "PortableData" / "User" / "Documents"),
            )
            self.assertEqual(env["PROGRAM_HOME"], f"{root}/App")
            self.assertTrue((root / "PortableData" / "User" /
                             "Documents" / "My Games").is_dir())

    def test_session_end_releases_the_portable_folder(self):
        """Главная жалоба: папку нельзя удалить после закрытия программы.

        Сеанс обязан закончиться освобождением папки — иначе фоновые
        помощники программы переживают лончер и держат её файлы.
        """
        with tempfile.TemporaryDirectory() as temp:
            root, _app, _target = self._portable(temp)
            child = mock.Mock(**{"wait.return_value": 0})
            with mock.patch.object(exe_launcher, "find_portable_root",
                                   return_value=root), \
                    mock.patch.object(exe_launcher, "_spawn_target",
                                      return_value=child), \
                    mock.patch.object(exe_launcher,
                                      "_wait_for_portable_processes",
                                      return_value=0), \
                    mock.patch.object(exe_launcher, "release_portable_folder",
                                      return_value=["updater.exe"]) as release, \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[]):
                exe_launcher.run([])

            # Основная уборка — внутри песочницы, плюс страховочный проход
            # в самом конце.
            self.assertEqual(release.call_count, 2)
            log = (root / "PortableData" / "launcher-run.log").read_text(
                encoding="utf-8")
            self.assertIn("updater.exe", log)
            self.assertIn("portable folder released", log)

    def test_program_really_starts_when_there_is_no_job_object(self):
        """Без job-объекта (не Windows, старая ОС) запуск обычный."""
        process = exe_launcher._spawn_target(
            [sys.executable, "-c", "import sys; sys.exit(7)"],
            os.getcwd(), dict(os.environ), exe_launcher._JobObject())
        self.assertEqual(process.wait(), 7)

    def test_unresumable_child_is_restarted_instead_of_hanging_frozen(self):
        """Если поток не удалось разморозить — стартуем обычным способом.

        Иначе пользователь смотрел бы на пустой экран: процесс создан, но
        навсегда приостановлен.
        """
        job = exe_launcher._JobObject()
        job.handle = 1234  # как будто job создан
        started = []

        class FakeProcess:
            _handle = 4321
            pid = 999

            def __init__(self, marker):
                started.append(marker)

            def kill(self):
                pass

            def wait(self, timeout=None):
                return 0

        calls = {"n": 0}

        def fake_popen(*_args, **kwargs):
            calls["n"] += 1
            return FakeProcess(kwargs.get("creationflags", 0))

        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher.subprocess, "Popen",
                                  side_effect=fake_popen), \
                mock.patch.object(exe_launcher, "_resume_process_threads",
                                  return_value=0), \
                mock.patch.object(exe_launcher._JobObject, "assign",
                                  return_value=True):
            exe_launcher._spawn_target(["prog.exe"], ".", {}, job)

        self.assertEqual(calls["n"], 2, "повторный запуск не состоялся")
        self.assertEqual(started[0], 0x00000004)   # CREATE_SUSPENDED
        self.assertEqual(started[1], 0)            # обычный запуск

    def test_saved_user_settings_do_not_hide_required_machine_registry_seed(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _app, _target = self._portable(temp)
            session = root / "PortableData" / "Registry"
            session.mkdir(parents=True)
            machine = root / "portable_machine.reg"
            saved = session / "k01.reg"
            machine.write_text("machine", encoding="utf-8")
            saved.write_text("saved", encoding="utf-8")
            cfg = {
                "data_dir_name": "PortableData",
                "registry": {
                    "enabled": True,
                    "machine_file": machine.name,
                    "keys": [],
                },
            }
            calls = []

            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(
                        exe_launcher, "_unpacked_reg",
                        side_effect=lambda source, *_args: source,
                    ), mock.patch.object(
                        exe_launcher, "_reg",
                        side_effect=lambda args: calls.append(tuple(args)) or 0,
                    ):
                exe_launcher.RegistrySession(root, cfg).load()

            imports = [call for call in calls if call[0] == "import"]
            self.assertEqual(Path(imports[0][1]), machine)
            self.assertEqual(Path(imports[1][1]), saved)

    def test_named_exe_copy_selects_configurator_without_forwarding_alias(self):
        cfg = {
            "target_exe_rel": "App/Game.exe",
            "launcher_aliases": {
                "Launch_Configurator.exe": "App/bin/Configurator.exe",
            },
            "targets": [
                {"rel_path": "App/Game.exe", "role": "main"},
                {"rel_path": "App/bin/Configurator.exe", "role": "config"},
            ],
        }
        arguments = exe_launcher._arguments_with_executable_alias(
            cfg, ["--user-option"], "launch_configurator.EXE"
        )
        target, forwarded, needs_machine = exe_launcher._select_target(
            cfg, arguments
        )

        self.assertEqual(target, "App/bin/Configurator.exe")
        self.assertEqual(forwarded, ["--user-option"])
        self.assertTrue(needs_machine)

    def test_explicit_target_overrides_named_exe_copy(self):
        cfg = {
            "target_exe_rel": "App/Game.exe",
            "launcher_aliases": {
                "Launch_Configurator.exe": "App/bin/Configurator.exe",
            },
        }
        arguments = exe_launcher._arguments_with_executable_alias(
            cfg, ["--target", "App/Other.exe"], "Launch_Configurator.exe"
        )
        self.assertEqual(arguments, ["--target", "App/Other.exe"])

    def test_config_switch_runs_configurator_in_the_same_portable_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            root, app, _target = self._portable(temp)
            configurator = app / "bin" / "Configurator.exe"
            configurator.parent.mkdir()
            configurator.write_bytes(b"MZ config")
            config_path = root / "launcher_config.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config.update({
                "config_target_rel": "App/bin/Configurator.exe",
                "targets": [
                    {"rel_path": "App/Program.exe", "role": "main"},
                    {"rel_path": "App/bin/Configurator.exe", "role": "config"},
                ],
            })
            config_path.write_text(json.dumps(config), encoding="utf-8")
            child = mock.Mock(**{"wait.return_value": 0})

            with mock.patch.object(exe_launcher, "find_portable_root",
                                   return_value=root), mock.patch.object(
                exe_launcher, "_spawn_target", return_value=child
            ) as run_process:
                rc = exe_launcher.run(["--config"])

            self.assertEqual(rc, 0)
            command = list(run_process.call_args.args[0])
            self.assertEqual(command[0], str(configurator))
            self.assertNotIn("--config", command)
            self.assertEqual(run_process.call_args.args[1],
                             str(configurator.parent))



    SXS_ITEM = {
        "dll": "msvcr80.dll",
        "manifest": "Microsoft.VC80.CRT.manifest",
        "sxs_family": "x86_microsoft.vc80.crt_",
        "title": "Microsoft Visual C++ 2005 SP1 Redistributable",
    }

    def test_launch_rejected_with_14001_gets_a_friendly_message(self):
        with tempfile.TemporaryDirectory() as temp:
            root, app, _target = self._portable(temp)
            error = OSError("side-by-side configuration is incorrect")
            error.winerror = 14001  # ERROR_SXS_CANT_GEN_ACTCTX
            shown = []

            with mock.patch.object(exe_launcher, "find_portable_root",
                                   return_value=root), \
                    mock.patch.object(exe_launcher, "_show_error",
                                      side_effect=shown.append), \
                    mock.patch.object(exe_launcher, "_spawn_target",
                                      side_effect=error):
                rc = exe_launcher.run([])

            # Симптом из жалобы «Ведьмака»: без пакета VC++ 2005/2008 Windows
            # не запускает программу и показывает криптичное окно. Теперь —
            # понятное сообщение и код выхода, равный коду ошибки.
            self.assertEqual(rc, 14001)
            self.assertTrue(shown, "пользователь не получил объяснение")
            self.assertIn("14001", shown[0])
            self.assertIn("Visual C++", shown[0])
            self.assertIn("Install-Redist.cmd", shown[0])

    def test_other_oserror_is_not_disguised_as_14001(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _app, _target = self._portable(temp)
            error = OSError("access denied")
            error.winerror = 5
            with mock.patch.object(exe_launcher, "find_portable_root",
                                   return_value=root), \
                    mock.patch.object(exe_launcher, "_show_error",
                                      side_effect=lambda _msg: None), \
                    mock.patch.object(exe_launcher, "_spawn_target",
                                      side_effect=error):
                with self.assertRaises(OSError):
                    exe_launcher.run([])

    # -- то же правило side-by-side, что и в Launch.bat ----------------------
    def test_bare_sxs_dll_without_manifest_counts_as_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Game_Portable")
            app = root / "App"
            app.mkdir(parents=True)
            (app / "game.exe").write_bytes(b"MZ")
            (app / "msvcr80.dll").write_bytes(b"MZ")
            cfg = {"runtime_requirements": [self.SXS_ITEM]}
            env = {"SystemRoot": str(Path(temp, "Windows"))}

            # «dll же лежит рядом!» — да, но без private-манифеста Windows
            # её игнорирует и вылетает с 14001: считаем недостающей.
            missing = exe_launcher.missing_runtime_components(
                root, cfg, app / "game.exe", env)
            self.assertEqual([item["dll"] for item in missing],
                             ["msvcr80.dll"])

            (app / "Microsoft.VC80.CRT.manifest").write_text(
                "<assembly/>", encoding="utf-8")
            missing = exe_launcher.missing_runtime_components(
                root, cfg, app / "game.exe", env)
            self.assertEqual(missing, [])

    def test_sxs_requirement_is_met_by_the_winsxs_family_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Game_Portable")
            app = root / "App"
            app.mkdir(parents=True)
            (app / "game.exe").write_bytes(b"MZ")
            windir = Path(temp, "Windows")
            family = windir / "WinSxS" / (
                "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_"
                "8.0.50727.6195_none_4ff29c7c0b2f2a62")
            family.mkdir(parents=True)
            cfg = {"runtime_requirements": [self.SXS_ITEM]}

            # Система «видна» только через WinSxS: System32 пуст — и это
            # не должно считаться отсутствием рантайма.
            missing = exe_launcher.missing_runtime_components(
                root, cfg, app / "game.exe", {"SystemRoot": str(windir)})
            self.assertEqual(missing, [])

    def test_runtime_install_helper_never_runs_system_installer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Game_Portable")
            root.mkdir()
            cfg = {"runtime_installers": [{
                "file": "Redist/vcredist_x86.exe", "title": "VC++ 2005",
                "kind": "vcredist_legacy", "args": "/q",
                "dlls": "msvcr80.dll", "arch": "x86"}]}
            missing = [self.SXS_ITEM]

            with mock.patch.object(exe_launcher.subprocess, "run",
                                   side_effect=AssertionError("must not run")) as run:
                still = exe_launcher.install_missing_runtime(root, cfg, missing)

            self.assertEqual(still, missing)
            run.assert_not_called()
            self.assertTrue((root / "PortableData" / "launcher-run.log").is_file())

    def test_uppercase_env_keys_do_not_leak_the_real_windows(self):
        # dict(os.environ) на Windows хранит ключи в ВЕРХНЕМ регистре:
        # «SYSTEMROOT», а не «SystemRoot». Регистрозависимый поиск молча
        # пропускал подменённый SystemRoot и проваливался на WINDIR —
        # с настоящим C:\Windows сборочной машины. Проверяем, что
        # SYSTEMROOT в любом регистре важнее WINDIR.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Game_Portable")
            app = root / "App"
            app.mkdir(parents=True)
            (app / "game.exe").write_bytes(b"MZ")
            fake = Path(temp, "FakeWindows")
            fake.mkdir()
            real = Path(temp, "RealWindows", "WinSxS", (
                "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_"
                "8.0.50727.6195_none_4ff29c7c0b2f2a62"))
            real.mkdir(parents=True)
            cfg = {"runtime_requirements": [self.SXS_ITEM]}
            env = {"SYSTEMROOT": str(fake), "WINDIR": str(
                Path(temp, "RealWindows"))}
            missing = exe_launcher.missing_runtime_components(
                root, cfg, app / "game.exe", env)
            self.assertEqual([item["dll"] for item in missing],
                             ["msvcr80.dll"])


class LaunchBatSafetyTests(unittest.TestCase):
    """Регрессии на «окно мигнуло и закрылось»."""

    def _bat(self, **kwargs):
        cfg = LauncherConfig(
            app_name=kwargs.pop("app_name", "Тестовое приложение"),
            target_exe_rel=kwargs.pop("target_exe_rel", "App/Type.exe"),
            **kwargs)
        return render_bat(cfg)

    def test_bat_is_pure_ascii_even_for_cyrillic_app_name(self):
        bat = self._bat(app_name="Программа «Тест» & Ко")
        self.assertTrue(bat.isascii(), "не-ASCII байт ломает разбор .bat")

    def test_bat_never_switches_codepage(self):
        # chcp внутри .bat сбивает байтовое смещение чтения — окно закрывается.
        executable = [line for line in self._bat().splitlines()
                      if line.strip().lower().startswith("chcp")]
        self.assertEqual(executable, [])

    def test_non_ascii_dependency_paths_are_not_written_literally(self):
        bat = self._bat(path_prepend=["App", "App/Библиотеки"],
                        extra_env={"КЛЮЧ": "значение", "OK": "1"})
        self.assertTrue(bat.isascii())
        self.assertIn('set "PATH=%PORTABLE_ROOT%\\App;%PATH%"', bat)
        self.assertIn('set "OK=1"', bat)

    def test_non_ascii_executable_is_resolved_through_wildcard(self):
        bat = self._bat(target_exe_rel="App/Программа.exe")
        self.assertTrue(bat.isascii())
        self.assertIn("PORTABLE_TARGET", bat)
        self.assertIn("?", bat)

    def test_every_jump_has_a_label(self):
        bat = self._bat(registry_keys=[r"HKCU\Software\V\A"],
                        registry_created_keys=[r"HKCU\Software\V\A"],
                        registry_has_root_token=True)
        self.assertEqual(_jump_targets(bat) - _labels(bat), set())

    def test_parentheses_are_balanced(self):
        bat = self._bat(registry_keys=[r"HKCU\Software\V\A"])
        depth = 0
        for line in bat.splitlines():
            stripped, in_quotes = "", False
            for ch in line:
                if ch == '"':
                    in_quotes = not in_quotes
                elif not in_quotes:
                    stripped += ch
            if stripped.strip().startswith(("rem", "echo")):
                continue
            depth += stripped.count("(") - stripped.count(")")
            self.assertGreaterEqual(depth, 0, f"лишняя ) в строке: {line}")
        self.assertEqual(depth, 0)

    def test_paths_with_ampersand_are_not_broken_by_escaping(self):
        # Значение внутри set "K=V" не нуждается в ^-экранировании: лишний ^
        # попал бы прямо в путь и лончер искал бы несуществующий каталог.
        bat = self._bat(path_prepend=["App&Tools"])
        self.assertIn('set "PATH=%PORTABLE_ROOT%\\App&Tools;%PATH%"', bat)
        self.assertNotIn("^&", bat)

    def test_ensure_ascii_bat_rejects_non_ascii(self):
        with self.assertRaises(ValueError):
            ensure_ascii_bat("echo привет")

    def test_vbs_wrapper_is_ascii_and_prefers_exe_launcher(self):
        vbs = render_vbs()
        self.assertTrue(vbs.isascii())
        self.assertIn("App\\LaunchPortable.exe", vbs)
        self.assertIn("Launch.bat", vbs)
        self.assertIn("--nopause", vbs)

    def test_launch_bat_prefers_windowed_exe_launcher_when_available(self):
        bat = self._bat()
        self.assertIn('if exist "%~dp0App\\LaunchPortable.exe"', bat)
        self.assertIn('start "" "%~dp0App\\LaunchPortable.exe" %*', bat)
        self.assertIn("--bat-fallback", bat)

    def test_launcher_help_and_switches_exist(self):
        bat = self._bat()
        for switch in ("--nopause", "--pause", "--no-registry",
                       "--keep-registry", "--reset", "--bat-fallback",
                       "--help"):
            self.assertIn(switch, bat)

    def test_generated_game_launcher_redirects_windows_documents_known_folder(self):
        bat = self._bat(redirect_known_folders=True)
        self.assertIn("User Shell Folders", bat)
        self.assertIn("PORTABLE_DOCUMENTS", bat)
        self.assertIn("shell-user.reg", bat)
        # The host value is restored after the child process exits.
        self.assertIn('reg import "%PORTABLE_DOC_USER_BACKUP%"', bat)

    def test_auxiliary_target_can_request_machine_registry_through_uac(self):
        target = launcher_mod.TargetInfo(
            name="Configurator", rel_path="App/bin/Configurator.exe",
            role="config")
        cfg = LauncherConfig(
            app_name="Game", target_exe_rel="App/bin/Game.exe",
            targets=[target], config_target_rel=target.rel_path)
        bat = render_bat(cfg)
        companion = launcher_mod.render_companion_bat(cfg, target)
        self.assertIn("--machine-registry", companion)
        self.assertIn('call "%PORTABLE_LAUNCHER_DIR%\\Launch.bat"', companion)
        self.assertIn("Start-Process", bat)
        self.assertIn("-Verb RunAs", bat)
        # A .bat file is not a process that ShellExecuteEx can reliably wait
        # for or report an exit code from. Elevate cmd.exe and call the batch
        # file explicitly; otherwise the UAC branch reports a failure even
        # after the user approved the prompt.
        self.assertIn("-FilePath $env:ComSpec", bat)
        self.assertIn("/d /c call ", bat)

    def test_powershell_helpers_do_not_shadow_builtin_aliases(self):
        # PowerShell has a built-in alias "gp" for Get-ItemProperty. Function
        # names are resolved case-insensitively, so a generated helper named
        # Gp() was ignored and PowerShell prompted the user for Path[0] after
        # the game launch instead of checking leftover portable processes.
        bat = render_bat(LauncherConfig(app_name="App", target_exe_rel="App/Game.exe"))
        stop = launcher_mod.render_stop_cmd(
            LauncherConfig(app_name="App", target_exe_rel="App/Game.exe"))
        combined = bat + "\n" + stop
        self.assertNotIn("function Gp()", combined)
        self.assertNotIn("@(Gp)", combined)
        self.assertIn("function GetPortableProcesses()", combined)
        self.assertIn("@(GetPortableProcesses)", combined)


class LaunchBatExecutionTests(unittest.TestCase):
    """Launch.bat реально исполняется до запуска программы.

    Проверяется мини-интерпретатором cmd.exe (tests/batsim.py): именно этот
    сценарий («окно мигнуло и закрылось») и был исходной жалобой.
    """

    ROOT = r"E:\MyApp_Portable"

    def _fs(self, exe_rel=r"App\MyApp.exe", extra=()):
        fs = batsim.FakeFS()
        fs.add_dir(self.ROOT)
        fs.add_file(f"{self.ROOT}\\{exe_rel}", "MZ")
        for path in extra:
            fs.add_file(f"{self.ROOT}\\{path}", "data")
        return fs

    def _run(self, cfg, fs=None, argv=None, program_exit_code=0, env=None):
        bat = render_bat(cfg)
        fs = fs or self._fs()
        fs.add_file(f"{self.ROOT}\\Launch.bat", bat)
        return batsim.run_batch(bat, f"{self.ROOT}\\Launch.bat", fs,
                                argv=argv or [], env=env,
                                program_exit_code=program_exit_code)

    def test_launcher_actually_starts_the_program(self):
        res = self._run(LauncherConfig(app_name="Моя Программа",
                                       target_exe_rel="App/MyApp.exe"))
        self.assertTrue(res.launched, "лончер не дошёл до запуска программы")
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.launches[0].command,
                         rf"{self.ROOT}\App\MyApp.exe")

    def test_program_runs_with_its_own_folder_as_working_directory(self):
        res = self._run(LauncherConfig(app_name="App",
                                       target_exe_rel="App/MyApp.exe"))
        self.assertTrue(res.launches[0].cwd.rstrip("\\").lower()
                        .endswith("myapp_portable\\app"))

    def test_user_directories_are_redirected_into_the_portable_folder(self):
        res = self._run(LauncherConfig(app_name="App",
                                       target_exe_rel="App/MyApp.exe"))
        for var in ("APPDATA", "LOCALAPPDATA", "TEMP", "USERPROFILE",
                    "PROGRAMDATA"):
            self.assertTrue(res.env[var].startswith(self.ROOT),
                            f"{var} указывает наружу: {res.env[var]}")

    def test_public_and_my_games_directories_are_created(self):
        # Регрессия на «Internal error 0x06: System error!»: программы (в т.ч.
        # игровые Steam-эмуляторы) падают, если их каталог данных лежит внутри
        # ещё не созданной папки профиля. Лончер должен создать дерево заранее.
        fs = self._fs()
        self._run(LauncherConfig(app_name="App",
                                 target_exe_rel="App/MyApp.exe"), fs=fs)
        for expected in (
            rf"{self.ROOT}\PortableData\Public\Documents",
            rf"{self.ROOT}\PortableData\User\Documents\My Games",
            rf"{self.ROOT}\PortableData\User\Saved Games",
        ):
            self.assertTrue(fs.exists(expected),
                            f"лончер не создал каталог {expected}")

    def test_no_pause_when_the_program_exits_successfully(self):
        res = self._run(LauncherConfig(app_name="App",
                                       target_exe_rel="App/MyApp.exe"))
        self.assertEqual(res.paused, 0)

    def test_pause_when_the_program_fails_so_the_user_can_read_the_error(self):
        res = self._run(LauncherConfig(app_name="App",
                                       target_exe_rel="App/MyApp.exe"),
                        program_exit_code=1)
        self.assertEqual(res.exit_code, 1)
        self.assertGreaterEqual(res.paused, 1)

    def test_nopause_switch_suppresses_the_pause(self):
        res = self._run(LauncherConfig(app_name="App",
                                       target_exe_rel="App/MyApp.exe"),
                        argv=["--nopause"], program_exit_code=1)
        self.assertEqual(res.paused, 0)

    def test_missing_executable_reports_a_readable_error(self):
        fs = batsim.FakeFS()
        fs.add_dir(self.ROOT)  # App/MyApp.exe отсутствует
        res = self._run(LauncherConfig(app_name="App",
                                       target_exe_rel="App/MyApp.exe"), fs=fs)
        self.assertFalse(res.launched)
        self.assertEqual(res.exit_code, 1)
        self.assertIn("not found", res.text.lower())
        self.assertGreaterEqual(res.paused, 1)

    def test_help_switch_exits_without_launching(self):
        res = self._run(LauncherConfig(app_name="App",
                                       target_exe_rel="App/MyApp.exe"),
                        argv=["--help"])
        self.assertFalse(res.launched)
        self.assertEqual(res.exit_code, 0)

    def test_registry_is_backed_up_before_and_restored_after_the_run(self):
        cfg = LauncherConfig(
            app_name="App", target_exe_rel="App/MyApp.exe",
            apply_registry=True,
            registry_keys=[r"HKCU\Software\Vendor\MyApp"],
            registry_created_keys=[r"HKCU\Software\Vendor\MyApp"],
            registry_has_root_token=True)
        res = self._run(cfg, fs=self._fs(extra=["portable.reg"]))
        joined = " | ".join(res.reg_commands)
        self.assertIn("RegistryHostBackup", joined)   # состояние чужого ПК
        self.assertIn("reg import", joined)           # настройки применены
        self.assertIn("PortableData\\Registry", joined)  # сохранены обратно
        self.assertIn("reg delete", joined)           # ключ убран из системы
        self.assertTrue(res.launched)

    def test_settings_with_the_marker_are_never_imported_verbatim(self):
        """PowerShell недоступен: маркер не попадает в реестр чужого ПК.

        Импорт файла «как есть» записал бы значение
        ``@@PORTABLE_ROOT@@\\App`` — и установщик обновления программы
        попытался бы писать в такую папку («Error opening file for
        writing»). Лучше пропустить импорт и оставить запись в журнале.
        """
        cfg = LauncherConfig(
            app_name="App", target_exe_rel="App/MyApp.exe",
            apply_registry=True,
            registry_keys=[r"HKCU\Software\Vendor\MyApp"],
            registry_has_root_token=True)
        res = self._run(cfg, fs=self._fs(extra=["portable.reg"]),
                        env={"BATSIM_NO_POWERSHELL": "1"})
        joined = " | ".join(res.reg_commands).lower()
        self.assertNotIn("reg import", joined,
                         "файл с маркером импортирован без подстановки корня")
        self.assertIn("skipped the import", res.text.lower())
        self.assertTrue(res.launched)

    def test_no_registry_switch_leaves_the_registry_untouched(self):
        cfg = LauncherConfig(
            app_name="App", target_exe_rel="App/MyApp.exe",
            apply_registry=True,
            registry_keys=[r"HKCU\Software\Vendor\MyApp"])
        res = self._run(cfg, fs=self._fs(extra=["portable.reg"]),
                        argv=["--no-registry"])
        self.assertEqual(res.reg_commands, [])
        self.assertTrue(res.launched)

    def test_launcher_works_from_any_drive_letter(self):
        cfg = LauncherConfig(app_name="App", target_exe_rel="App/MyApp.exe")
        bat = render_bat(cfg)
        for root in (r"D:\Stick\App_Portable", r"X:\App_Portable"):
            fs = batsim.FakeFS()
            fs.add_dir(root)
            fs.add_file(rf"{root}\App\MyApp.exe", "MZ")
            fs.add_file(rf"{root}\Launch.bat", bat)
            res = batsim.run_batch(bat, rf"{root}\Launch.bat", fs)
            self.assertTrue(res.launched, root)
            self.assertEqual(res.launches[0].command, rf"{root}\App\MyApp.exe")

    def test_folder_with_spaces_and_ampersand_still_launches(self):
        root = r"F:\Portable Apps & Tools\App_Portable"
        cfg = LauncherConfig(app_name="App", target_exe_rel="App/MyApp.exe",
                             path_prepend=["App"])
        bat = render_bat(cfg)
        fs = batsim.FakeFS()
        fs.add_dir(root)
        fs.add_file(rf"{root}\App\MyApp.exe", "MZ")
        fs.add_file(rf"{root}\Launch.bat", bat)
        res = batsim.run_batch(bat, rf"{root}\Launch.bat", fs)
        self.assertTrue(res.launched)
        self.assertEqual(res.launches[0].command, rf"{root}\App\MyApp.exe")

    def test_old_launcher_with_chcp_and_cyrillic_is_rejected(self):
        """Гарантия, что тест поймал бы исходную регрессию."""
        broken = (
            "@echo off\n"
            "chcp 65001 >nul 2>&1\n"
            "rem (локальные зависимости для PATH не заданы)\n"
            'set "TARGET=%~dp0App\\MyApp.exe"\n'
            '"%TARGET%"\n'
        )
        with self.assertRaises(batsim.BatError):
            batsim.run_batch(broken, rf"{self.ROOT}\Launch.bat", self._fs())



    # -- сценарий из жалобы: «Ведьмак», machine-реестр, UAC, ошибка 14001 -----
    def _witcher_cfg(self):
        return LauncherConfig(
            app_name="The Witcher", target_exe_rel="App/witcher.exe",
            apply_registry=True,
            registry_keys=[r"HKLM\\SOFTWARE\\CD Projekt Red\\The Witcher"],
            registry_created_keys=[
                r"HKLM\\SOFTWARE\\CD Projekt Red\\The Witcher"],
            machine_reg_file_name="portable_machine.reg")

    def _witcher_env(self, uac="allow"):
        # На целевом ПК захваченных HKLM-ключей нет (как и должно быть на
        # чистой машине): reg query вернёт ошибку — пойдём за правами.
        return {"BATSIM_MISSING_REG": r"HKLM\\SOFTWARE\\CD Projekt Red",
                "BATSIM_UAC": uac}

    def _witcher_fs(self):
        return self._fs(exe_rel=r"App\witcher.exe",
                        extra=["portable_machine.reg"])

    def test_frozen_import_does_not_need_source_files(self):
        """Portablizer.exe не должен зависеть от ``inspect.getsource``.

        Собранный PyInstaller-EXE не содержит исходников: попытка достать текст
        функции на импорте роняла приложение с
        ``OSError: could not get source code`` ещё до появления окна.
        """
        source = pathlib.Path(launcher_mod.__file__).read_text(encoding="utf-8")
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            self.assertNotIn("getsource", stripped,
                             "импорт снова зависит от исходников на диске")

    def test_import_works_when_source_access_is_broken(self):
        """Тот же импорт в окружении, где исходников «нет» (как в EXE)."""
        code = "\n".join([
            "import inspect",
            "def _boom(*a, **k):",
            "    raise OSError('could not get source code')",
            "inspect.getsource = _boom",
            "inspect.getsourcelines = _boom",
            "inspect.findsource = _boom",
            "import portablizer.core.launcher as L",
            "import portablizer.core.portablizer as P",
            "import portablizer.core.maintenance as M",
            "assert L.repair_json_escapes('{\"a\": \"E:\\\\B\"}')",
            "print('ok')",
        ])
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(pathlib.Path(__file__).resolve().parents[1]),
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr[-1500:])
        self.assertIn("ok", completed.stdout)

    def test_shared_source_text_matches_the_module_function(self):
        """Текст для портатива и модульная функция — одно и то же."""
        namespace: dict = {}
        exec(compile(launcher_mod._REPAIR_JSON_SOURCE, "<test>", "exec"),
             namespace)
        case = '{"p": "E:\\Backup\\Apps"}'
        self.assertEqual(namespace["repair_json_escapes"](case),
                         launcher_mod.repair_json_escapes(case))
        self.assertEqual(json.loads(namespace["repair_json_escapes"](case)),
                         json.loads(launcher_mod.repair_json_escapes(case)))

    def test_fallback_python_launcher_repairs_a_broken_config(self):
        """``launcher.py`` (запасной лончер) не падает на «Invalid \\escape»."""
        ns = {"__name__": "launcher_fallback"}
        exec(compile(launcher_mod._PY_LAUNCHER, "launcher.py", "exec"), ns)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "launcher_config.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"root_token": "E:\\Backup\\Apps", '
                         '"target_exe_rel": "App/app.exe"}')
            cfg = ns["load_config"](tmp)
            self.assertEqual(cfg["target_exe_rel"], "App/app.exe")
            with open(path, "r", encoding="utf-8") as fh:
                json.loads(fh.read())  # файл на диске снова читается

    def test_maintenance_reads_a_broken_config(self):
        """Обновление портатива не отказывает из-за испорченного конфига."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "launcher_config.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"data_dir_name": "E:\\Apps\\PortableData"}')
            data = maintenance_mod.read_config(path)
            self.assertTrue(data["data_dir_name"].endswith("PortableData"))

    def test_declined_uac_is_named_as_declined_not_as_generic_failure(self):
        res = self._run(self._witcher_cfg(), fs=self._witcher_fs(),
                        env=self._witcher_env(uac="deny"))
        # Раньше здесь было «Administrator rights were not granted or the
        # tool failed» — непонятно, кто виноват: пользователь или программа.
        self.assertIn("Administrator rights were declined at the UAC prompt",
                      res.text)
        self.assertNotIn("were not granted or the tool failed", res.text)
        self.assertEqual(res.exit_code, 1223)
        self.assertFalse(res.launched)

    def test_elevated_child_crash_14001_points_to_the_redist_fix(self):
        res = self._run(self._witcher_cfg(), fs=self._witcher_fs(),
                        program_exit_code=14001,
                        env=self._witcher_env())
        # Исходная жалоба: дочернее окно с «параллельная конфигурация
        # неправильна», а родитель сообщал «права не получены». Теперь лончер
        # различает отказ в правах и ошибку запуска — и даёт рецепт.
        self.assertIn("error 14001", res.text)
        self.assertIn("side-by-side", res.text)
        self.assertIn(r"Redist\Install-Redist.cmd", res.text)
        self.assertNotIn("were declined", res.text)
        self.assertNotIn("were not granted", res.text)
        self.assertEqual(res.exit_code, 14001)
        self.assertTrue(res.launched)

    def test_elevated_child_failure_is_not_blamed_on_permissions(self):
        res = self._run(self._witcher_cfg(), fs=self._witcher_fs(),
                        program_exit_code=1, env=self._witcher_env())
        self.assertIn("finished with exit code 1", res.text)
        self.assertIn("WERE granted", res.text)
        self.assertEqual(res.exit_code, 1)

    def test_elevated_run_imports_machine_registry_once_and_starts_game(self):
        res = self._run(self._witcher_cfg(), fs=self._witcher_fs(),
                        env=self._witcher_env())
        self.assertEqual(res.exit_code, 0)
        self.assertTrue(res.launched)
        self.assertEqual(len(res.launches), 1,
                         "игра стартует один раз — в поднятом окне")
        self.assertEqual(res.launches[0].command,
                         rf"{self.ROOT}\App\witcher.exe")
        joined = " | ".join(res.reg_commands).lower()
        self.assertIn("reg import", joined)
        # Импортируется копия с подставленным корнем, а не исходный файл с
        # маркером @@PORTABLE_ROOT@@: иначе установщик обновления игры искал бы
        # папку с таким именем.
        self.assertIn("portable_import_", joined)

    def test_direct_launch_exit_14001_explains_the_sxs_fix(self):
        cfg = LauncherConfig(app_name="The Witcher",
                             target_exe_rel="App/witcher.exe")
        res = self._run(cfg, fs=self._fs(exe_rel=r"App\witcher.exe"),
                        program_exit_code=14001)
        self.assertIn("[ERROR 14001]", res.text)
        self.assertIn("Visual C++ 2005/2008", res.text)
        self.assertIn(r"Redist\Install-Redist.cmd", res.text)
        self.assertEqual(res.exit_code, 14001)
        self.assertGreaterEqual(res.paused, 1)


class RegistryPortabilityTests(unittest.TestCase):
    """Портатив не должен «устанавливаться» на чужом компьютере."""

    def test_uninstall_and_autorun_keys_are_classified_as_traces(self):
        trace = [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MyApp",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\Folders",
        ]
        for key in trace:
            self.assertEqual(registry.categorize(key), registry.CATEGORY_TRACE,
                             key)

    def test_app_settings_are_classified_as_portable(self):
        self.assertEqual(
            registry.categorize(r"HKCU\Software\Vendor\MyApp"),
            registry.CATEGORY_APP)

    def test_file_associations_are_integration_not_app(self):
        for key in (r"HKLM\Software\Classes\.myext",
                    r"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\a.exe"):
            self.assertEqual(registry.categorize(key),
                             registry.CATEGORY_INTEGRATION, key)

    def test_installed_programs_entry_is_detected(self):
        before = {}
        after = {
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp": {
                "DisplayName": (registry.REG_SZ, repr("My Application")),
            },
        }
        diff = registry.compute_diff(before, after)
        entries = registry.installed_program_entries(diff, after)
        self.assertEqual([name for _k, name in entries], ["My Application"])

    def test_portable_reg_excludes_uninstall_entry(self):
        after = {
            r"HKCU\Software\Vendor\MyApp": {
                "Lang": (registry.REG_SZ, repr("ru")),
            },
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp": {
                "DisplayName": (registry.REG_SZ, repr("My Application")),
            },
        }
        diff = registry.compute_diff({}, after)
        portable_keys = diff.keys_of(registry.CATEGORY_APP)
        text = registry.render_keys(after, portable_keys)
        self.assertIn(r"HKEY_CURRENT_USER\Software\Vendor\MyApp", text)
        self.assertNotIn("Uninstall", text)

    def test_activation_office_and_edge_webview2_keys_are_protected(self):
        protected = {
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Activation": {},
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\SL\Activation": {},
            r"HKLM\Software\Microsoft\Office\16.0\Common\Licensing": {},
            r"HKCU\Software\Microsoft\OfficeSoftwareProtectionPlatform": {},
            r"HKCU\Software\Microsoft\EdgeWebView\BLBeacon": {},
            r"HKLM\Software\Microsoft\EdgeUpdate\Clients\{1234}": {},
        }
        diff = registry.compute_diff({}, protected)
        self.assertEqual(diff.touched_keys, [])
        for key, values in protected.items():
            self.assertTrue(registry.is_protected(key, values), key)

    def test_taskbar_pins_and_file_associations_are_not_app_settings(self):
        pins = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
        file_exts = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice"
        association = r"HKCU\Software\Classes\.example"
        after = {key: {"Setting": (registry.REG_SZ, repr("x"))}
                 for key in (pins, file_exts, association)}
        diff = registry.compute_diff({}, after)
        portable_keys = diff.keys_of(registry.CATEGORY_APP)
        self.assertEqual(portable_keys, [])
        self.assertEqual(registry.categorize(association),
                         registry.CATEGORY_INTEGRATION)

    def test_host_cleanup_only_deletes_a_confirmed_app_uninstall_entry(self):
        before = {r"HKCU\Software\Vendor\Existing": {
            "Theme": (registry.REG_SZ, repr("dark"))}}
        after = {
            r"HKCU\Software\Vendor\Existing": {
                "Theme": (registry.REG_SZ, repr("light")),
                "New": (registry.REG_DWORD, repr(1)),
            },
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp": {
                "DisplayName": (registry.REG_SZ, repr("My Application")),
                "InstallLocation": (registry.REG_SZ, repr(r"C:\P\App")),
            },
        }
        diff = registry.compute_diff(before, after)
        text = registry.render_host_cleanup(
            diff, after, app_name="My Application", portable_dir=r"C:\P")
        self.assertIn(
            r"[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion"
            r"\Uninstall\MyApp]", text)
        # Changed app settings are never restored/deleted by host cleanup.
        self.assertNotIn("Vendor\\\\Existing", text)
        self.assertNotIn('"New"=-', text)
        self.assertNotIn('"Theme"="dark"', text)

    def test_cleanup_cmd_self_elevates_and_imports_the_reg(self):
        cmd = registry.render_host_cleanup_cmd("cleanup_host.reg")
        self.assertTrue(cmd.isascii(), "cleanup_host.cmd должен быть ASCII")
        # Запрашивает права администратора через UAC и импортирует .reg.
        self.assertIn("net session", cmd)
        self.assertIn("-Verb RunAs", cmd)
        self.assertIn('reg import "cleanup_host.reg"', cmd)

    def test_cleanup_cmd_avoids_the_errorlevel_in_block_trap(self):
        # %ERRORLEVEL% раскрывается при разборе блока в скобках, поэтому внутри
        # блоков используется только «if errorlevel», иначе проверка прав
        # всегда срабатывала бы ложно.
        cmd = registry.render_host_cleanup_cmd("cleanup_host.reg")
        self.assertNotIn("%ERRORLEVEL%", cmd)
        self.assertIn("if errorlevel 1", cmd)

    def test_launcher_undo_never_restores_build_machine_values(self):
        before = {r"HKCU\Software\Vendor\App": {
            "Theme": (registry.REG_SZ, repr("dark"))}}
        after = {r"HKCU\Software\Vendor\App": {
            "Theme": (registry.REG_SZ, repr("light")),
            "Added": (registry.REG_SZ, repr("x"))}}
        diff = registry.compute_diff(before, after)
        text = registry.render_launcher_undo(diff, diff.touched_keys)
        self.assertIn('"Added"=-', text)
        self.assertNotIn("dark", text)

    def test_portable_root_is_replaced_by_marker(self):
        after = {r"HKCU\Software\Vendor\App": {
            "Path": (registry.REG_SZ, repr(r"D:\Stick\App_Portable\App\a.exe")),
        }}
        text = registry.render_keys(
            after, [r"HKCU\Software\Vendor\App"],
            [(r"D:\Stick\App_Portable", registry.ROOT_TOKEN)])
        self.assertIn(registry.ROOT_TOKEN, text)
        self.assertNotIn("D:\\\\Stick", text)

    def test_volatile_windows_noise_is_ignored(self):
        after = {
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Foo": {
                "x": (registry.REG_DWORD, repr(1))},
        }
        diff = registry.compute_diff({}, after)
        self.assertTrue(diff.is_empty())

    def test_reg_values_round_trip_into_valid_syntax(self):
        after = {r"HKCU\Software\V\A": {
            "s": (registry.REG_SZ, repr("text")),
            "d": (registry.REG_DWORD, repr(42)),
            "m": (registry.REG_MULTI_SZ, repr(["a", "b"])),
            "b": (registry.REG_BINARY, repr(b"\x01\x02")),
            "e": (registry.REG_EXPAND_SZ, repr("%TEMP%\\x")),
        }}
        text = registry.render_keys(after, [r"HKCU\Software\V\A"])
        self.assertTrue(text.startswith("Windows Registry Editor Version 5.00"))
        self.assertIn('"s"="text"', text)
        self.assertIn('"d"=dword:0000002a', text)
        self.assertIn('"m"=hex(7):', text)
        self.assertIn('"b"=hex:01,02', text)
        self.assertIn('"e"=hex(2):', text)

    def test_install_folder_is_retargeted_after_program_files_recovery(self):
        key = r"HKLM\Software\Wow6432Node\CD Projekt RED\The Witcher 2"
        old = r"C:\Program Files (x86)\The Witcher 2"
        snapshot = {key: {
            "InstallFolder": (registry.REG_SZ, repr(old)),
            "Launcher": (registry.REG_SZ, repr(old + r"\Launcher.exe")),
            "Language": (registry.REG_SZ, repr("RU")),
        }}
        moved = registry.retarget_install_paths(
            snapshot, [key], r"E:\Portable\Witcher2_Portable\App")
        text = registry.render_keys(moved, [key])
        self.assertIn(
            '"InstallFolder"="E:\\\\Portable\\\\Witcher2_Portable\\\\App"',
            text)
        self.assertIn("App\\\\Launcher.exe", text)
        self.assertNotIn("Program Files", text)
        self.assertIn('"Language"="RU"', text)


class RegistryCaptureIntegrationTests(unittest.TestCase):
    """Захват реестра целиком: что уедет на флешку, а что вычистится."""

    def _capture(self, **opts):
        engine = Portablizer(Logger())
        temp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(temp,
                                                            ignore_errors=True))
        portable = Path(temp, "MyApp_Portable")
        portable.mkdir()
        before = {}
        after = {
            r"HKCU\Software\Vendor\MyApp": {
                # Путь установки указывает внутрь портативной папки: именно он
                # должен превратиться в переносимый маркер.
                "InstallDir": (registry.REG_SZ, repr(str(portable / "App"))),
            },
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp": {
                "DisplayName": (registry.REG_SZ, repr("My Application")),
                "InstallLocation": (registry.REG_SZ,
                                    repr(str(portable / "App"))),
            },
            r"HKLM\Software\Classes\.myext": {
                "": (registry.REG_SZ, repr("MyApp.File")),
            },
        }
        capture = engine._capture_registry(
            str(portable), before, after,
            PortableOptions(installer_path="x", output_dir=temp,
                            app_name="My Application", **opts))
        files = {p.name: p.read_text(encoding="utf-16")
                 for p in portable.glob("*.reg")}
        return capture, files

    def test_installed_programs_entry_never_reaches_the_portable(self):
        capture, files = self._capture()
        self.assertEqual(capture.uninstall_entries, ["My Application"])
        self.assertNotIn(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp",
            capture.keys)
        for name, text in files.items():
            if name != "cleanup_host.reg":
                self.assertNotIn("Uninstall", text, name)

    def test_cleanup_file_is_generated_by_default(self):
        """Портатив не устанавливается — запись убирается без отдельной галочки."""
        capture, files = self._capture()
        self.assertIn("cleanup_host.reg", files)
        self.assertTrue(capture.cleanup_file)
        self.assertTrue(capture.cleanup_cmd_file.endswith("cleanup_host.cmd"))

    def test_cleanup_can_be_switched_off(self):
        capture, files = self._capture(cleanup_host=False)
        self.assertNotIn("cleanup_host.reg", files)
        self.assertFalse(capture.cleanup_file)
        self.assertFalse(capture.cleanup_cmd_file)

    def test_cleanup_file_only_removes_the_confirmed_uninstall_entry(self):
        capture, files = self._capture(cleanup_host=True)
        self.assertIn("cleanup_host.reg", files)
        self.assertIn("Uninstall", files["cleanup_host.reg"])
        self.assertNotIn("Classes", files["cleanup_host.reg"])

    def test_self_elevating_cleanup_cmd_is_written_next_to_the_reg(self):
        capture, _files = self._capture(cleanup_host=True)
        self.assertTrue(capture.cleanup_cmd_file.endswith("cleanup_host.cmd"))
        text = Path(capture.cleanup_cmd_file).read_text(encoding="ascii")
        self.assertIn("-Verb RunAs", text)
        self.assertIn('reg import "cleanup_host.reg"', text)

    def test_shell_integration_is_skipped_by_default(self):
        capture, _files = self._capture()
        self.assertNotIn(r"HKLM\Software\Classes\.myext", capture.keys)

    def test_shell_integration_can_be_enabled(self):
        capture, _files = self._capture(include_shell_integration=True)
        self.assertIn(r"HKLM\Software\Classes\.myext", capture.keys)

    def test_build_folder_path_is_tokenized_for_other_machines(self):
        capture, files = self._capture()
        self.assertTrue(capture.has_root_token)
        self.assertIn(registry.ROOT_TOKEN, files["portable.reg"])


class LauncherConfigTests(unittest.TestCase):
    def test_config_json_reports_registry_contract(self):
        cfg = LauncherConfig(
            app_name="App", target_exe_rel="App/a.exe",
            apply_registry=True,
            registry_keys=[r"HKCU\Software\V\A"],
            registry_created_keys=[r"HKCU\Software\V\A"],
            registry_has_root_token=True)
        data = json.loads(render_config_json(cfg))
        self.assertTrue(data["registry"]["enabled"])
        self.assertTrue(data["registry"]["restore_on_exit"])
        self.assertEqual(data["registry"]["root_token"], registry.ROOT_TOKEN)
        self.assertEqual(data["registry"]["keys"], [r"HKCU\Software\V\A"])

    def test_registry_keys_with_dangerous_characters_are_dropped(self):
        keys = launcher_mod.usable_registry_keys(
            [r"HKCU\Software\Ключ", r'HKCU\Software\A"B', r"HKCU\Software\Good"])
        self.assertEqual(keys, [r"HKCU\Software\Good"])

    def test_registry_key_count_is_capped(self):
        keys = launcher_mod.usable_registry_keys(
            [rf"HKCU\Software\K{i}" for i in range(100)])
        self.assertLessEqual(len(keys), launcher_mod.MAX_REGISTRY_KEYS)

    def test_disabled_registry_produces_no_reg_commands(self):
        bat = render_bat(LauncherConfig(
            app_name="App", target_exe_rel="App/a.exe", apply_registry=False))
        self.assertNotIn("reg import", bat)
        self.assertNotIn("reg export", bat)


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
    def test_nsis_target_uses_only_windows_separators(self):
        plan = build_silent_plan(
            InstallerType.NSIS,
            "C:/Users/test/Downloads/Type.exe",
            r"E:/Type\Type_Portable\App",
        )
        self.assertEqual(plan.program, r"C:\Users\test\Downloads\Type.exe")
        self.assertEqual(plan.raw_tail, r"/D=E:\Type\Type_Portable\App")

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


class BurnPlanTests(unittest.TestCase):
    def test_burn_plan_sets_folder_and_writes_log(self):
        plan = build_silent_plan(
            InstallerType.WIX_BURN,
            r"C:\Downloads\Type.exe",
            r"E:\Type_Portable\App",
            log_file=r"E:\Type_Portable\install.log",
        )
        self.assertIn("/install", plan.args)
        self.assertIn("/quiet", plan.args)
        self.assertIn("InstallFolder=E:\\Type_Portable\\App", plan.args)
        log_index = plan.args.index("/log")
        self.assertEqual(plan.args[log_index + 1], r"E:\Type_Portable\install.log")

    def test_burn_layout_is_first_and_assisted_never_repeats_install(self):
        """Delta: повторный Install после Apply даёт 0x8007139f.

        Поэтому безопасная распаковка идёт до любого /install, а галочка
        assisted (нужная InstallShield) не добавляет для Burn штатное окно.
        """
        detection = DetectionResult(InstallerType.WIX_BURN, 0.97)
        kwargs = dict(
            installer_path=r"C:\Downloads\DeltaSetup.exe",
            target_dir=r"D:\Portable\Delta\App",
            log_dir=r"D:\Portable\Delta",
            layout_dir=r"D:\Portable\Delta\_bundle_layout",
        )
        normal = build_attempts(detection, **kwargs)
        assisted = build_attempts(detection, allow_assisted=True, **kwargs)

        for attempts in (normal, assisted):
            self.assertEqual(len(attempts), 3)
            self.assertIn("/layout", attempts[0].args)
            self.assertNotIn("/install", attempts[0].args)
            self.assertTrue(attempts[0].extracts_only)
            self.assertIn("/install", attempts[1].args)
            self.assertIn("/install", attempts[2].args)
            self.assertFalse(any(plan.interactive for plan in attempts))
            self.assertFalse(any(
                "install-interactive.log" in arg
                for plan in attempts for arg in plan.args))

    def test_burn_plan_can_drop_install_folder_override(self):
        plan = build_silent_plan(
            InstallerType.WIX_BURN,
            r"C:\Downloads\Type.exe",
            r"E:\Type_Portable\App",
            override_install_folder=False,
        )
        self.assertFalse(
            any(a.startswith("InstallFolder=") for a in plan.args))

    def test_burn_layout_plan_extracts_without_installing(self):
        plan = build_burn_layout_plan(
            r"C:\Downloads\Type.exe",
            r"E:\Type_Portable\_bundle_layout",
            log_file=r"E:\Type_Portable\install-layout.log",
        )
        self.assertEqual(plan.args[0], "/layout")
        self.assertEqual(plan.args[1], r"E:\Type_Portable\_bundle_layout")
        self.assertIn("/quiet", plan.args)
        self.assertIn("/norestart", plan.args)
        self.assertNotIn("/install", plan.args)


class ExitCodeTests(unittest.TestCase):
    def test_unsigned_codes_are_decoded_to_signed_and_hex(self):
        self.assertEqual(
            _format_exit_code(4294967295), "4294967295 (-1, 0xFFFFFFFF)")
        self.assertIn("администратора", _exit_code_hint(4294967295))

    def test_known_windows_codes_have_hints(self):
        self.assertEqual(_format_exit_code(740), "740")
        self.assertIn("администратора", _exit_code_hint(740))
        self.assertIn("UAC", _exit_code_hint(1223))
        # Ошибка из жалобы о «Ведьмаке»: битая/отсутствующая параллельная
        # сборка VC++ — отдельная подсказка, а не «неизвестный код».
        self.assertIn("side-by-side", _exit_code_hint(14001))
        self.assertIn("Install-Redist.cmd", _exit_code_hint(14001))

    def test_burn_state_error_is_not_reported_as_missing_admin_rights(self):
        hint = _exit_code_hint(0x8007139F)
        self.assertIn("Apply", hint)
        self.assertIn("Detect", hint)
        self.assertIn("/layout", hint)
        self.assertNotIn("администратора", hint)

    def test_success_and_unknown_codes_have_no_hint(self):
        self.assertEqual(_format_exit_code(None), "неизвестен")
        self.assertEqual(_exit_code_hint(None), "")
        self.assertEqual(_exit_code_hint(0), "")
        self.assertEqual(_exit_code_hint(1), "")
        self.assertEqual(_format_exit_code(3010), "3010")


class BurnFallbackTests(unittest.TestCase):
    def setUp(self):
        self.engine = Portablizer(Logger())

    def test_layout_payloads_rank_msis_by_size(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = Path(temp, "_bundle_layout")
            (layout / "redist").mkdir(parents=True)
            (layout / "app.msi").write_bytes(b"x" * 100)
            (layout / "redist" / "vc.msi").write_bytes(b"x" * 10)
            (layout / "redist" / "tool.exe").write_bytes(b"MZ")

            msis, others = _burn_layout_payloads(str(layout))

            self.assertEqual([Path(m).name for m in msis],
                             ["app.msi", "vc.msi"])
            self.assertEqual([Path(o).name for o in others], ["tool.exe"])

    def test_layout_payloads_of_missing_folder(self):
        msis, others = _burn_layout_payloads(r"C:\nowhere\_bundle_layout")
        self.assertEqual(msis, [])
        self.assertEqual(others, [])

    def test_burn_fallback_recovers_app_from_layout_msi(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "TypeSetup.exe")
            # Структурно валидный Burn-бандл: опознаётся по секции .wixburn
            # с высокой уверенностью, поэтому лестница — только сценарии Burn.
            _fake_pe(str(installer), [".text", ".rsrc", ".wixburn"],
                     b"WixBurn wixstdba")
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir(parents=True)

            class FakeBurn(Portablizer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.calls = []

                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    self.calls.append(plan)
                    if "/layout" in plan.args:
                        layout = portable / "_bundle_layout"
                        layout.mkdir(parents=True, exist_ok=True)
                        (layout / "app.msi").write_bytes(b"MZ fake msi payload")
                    elif plan.program == "msiexec.exe":
                        Path(app_dir, "Type.exe").write_bytes(b"MZ application")
                    return 0

            engine = FakeBurn(Logger())
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Type")
            attempts = build_attempts(
                detect_installer(str(installer)), str(installer), str(app),
                log_dir=str(portable),
                layout_dir=str(portable / "_bundle_layout"))
            rc, used = engine._run_attempts(attempts, opts, str(app),
                                            str(data), str(portable), "Type")

            # /layout идёт ПЕРВЫМ и не регистрирует bundle; затем msiexec /a.
            # До настоящего /install дело даже не доходит.
            self.assertEqual(len(engine.calls), 2)
            self.assertIn("/layout", engine.calls[0].args)
            self.assertNotIn("/install", engine.calls[0].args)
            self.assertEqual(engine.calls[1].program, "msiexec.exe")
            self.assertIn("/a", engine.calls[1].args)
            self.assertNotIn("/i", engine.calls[1].args)
            self.assertEqual(rc, 0)
            self.assertIn("/layout", used.args)
            self.assertTrue((app / "Type.exe").exists())
            # Временная распаковка бандла удалена.
            self.assertFalse((portable / "_bundle_layout").exists())

    def test_burn_does_not_relaunch_identical_embedded_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "delta-windows-x86_64-setup.exe")
            installer.write_bytes(b"same Burn bundle binary")
            portable = Path(temp, "Delta_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            layout = portable / "_bundle_layout"
            app.mkdir(parents=True)
            data.mkdir()
            layout.mkdir()
            (layout / "DeltaSetup.exe").write_bytes(installer.read_bytes())
            engine = Portablizer(Logger())
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Delta")

            ok = engine._install_layout_packages(
                str(layout), opts, str(app), str(data), "Delta")

            self.assertFalse(ok)
            self.assertTrue(engine._burn_cycle_detected)
            self.assertEqual(list(app.iterdir()), [])
            self.assertIn("Повторно запускать тот же бандл",
                          engine.log.text)

    def test_burn_does_not_repeat_nested_bundle_name_with_new_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "DeltaSetup.exe")
            installer.write_bytes(b"parent Burn bundle")
            payload = Path(temp, "layout", "DeltaSetup.exe")
            payload.parent.mkdir()
            payload.write_bytes(b"different nested Burn bundle")
            engine = Portablizer(Logger())
            engine._detection = DetectionResult(InstallerType.WIX_BURN, 0.97)
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Delta")
            burn = DetectionResult(InstallerType.WIX_BURN, 0.97)

            with mock.patch(
                    "portablizer.core.portablizer.detect_installer",
                    return_value=burn) as detect:
                ok = engine._run_burn_embedded_installers(
                    [str(payload)], opts, str(temp), str(temp), temp, "Delta")

            self.assertFalse(ok)
            self.assertTrue(engine._burn_cycle_detected)
            detect.assert_called_once_with(str(payload))
            self.assertIn("тем же именем", engine.log.text)

    def test_burn_fallback_runs_matching_embedded_product_setup(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "delta-windows-x86_64-setup.exe")
            installer.write_bytes(b"outer bundle")
            portable = Path(temp, "Delta_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            layout = portable / "_bundle_layout"
            app.mkdir(parents=True)
            data.mkdir()
            layout.mkdir()
            nested = layout / "DeltaSetup.exe"
            _fake_pe(str(nested), [".text", ".rsrc"], b"Inno Setup")

            class FakeBurn(Portablizer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.calls = []

                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    self.calls.append(plan)
                    if plan.program.endswith(nested.name):
                        Path(app_dir, "Delta.exe").write_bytes(b"MZ application")
                        return 0
                    return 1

            engine = FakeBurn(Logger())
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Delta")
            ok = engine._install_layout_packages(
                str(layout), opts, str(app), str(data), "Delta",
                console_log=str(portable / "installer-output.log"))

            self.assertTrue(ok)
            self.assertTrue((app / "Delta.exe").is_file())
            self.assertEqual(len(engine.calls), 1)
            self.assertTrue(engine.calls[0].program.endswith(nested.name))
            self.assertIn("В WiX Burn найден установщик самого приложения",
                          engine.log.text)

    def test_nested_burn_uses_layout_without_registering_an_install(self):
        """Вложенный Burn тоже начинается с собственного /layout.

        Когда layout действительно содержит новый Delta.msi, успешной цепочке
        не нужен /install и не создаётся состояние Present. Случай, где layout
        возвращает лишь копию того же bundle, проверяется отдельным тестом.
        """
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "delta-windows-x86_64-setup.exe")
            installer.write_bytes(b"outer bundle")
            portable = Path(temp, "Delta_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            layout = portable / "_bundle_layout"
            app.mkdir(parents=True)
            data.mkdir()
            layout.mkdir()
            nested = layout / "DeltaSetup.exe"
            _fake_pe(str(nested), [".text", ".rsrc", ".wixburn"],
                     b"wixstdba without legacy WixBurn marker")

            class FakeBurn(Portablizer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.calls = []

                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    self.calls.append(plan)
                    if "/layout" in plan.args:
                        out = Path(plan.output_dir)
                        out.mkdir(parents=True, exist_ok=True)
                        (out / "Delta.msi").write_bytes(b"MSI payload")
                        return 0
                    if plan.program == "msiexec.exe":
                        Path(app_dir, "Delta.exe").write_bytes(b"MZ application")
                        return 0
                    return 0x8007139F

            engine = FakeBurn(Logger())
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Delta",
                                   allow_assisted_install=True)

            ok = engine._install_layout_packages(
                str(layout), opts, str(app), str(data), "Delta",
                console_log=str(portable / "installer-output.log"))

            self.assertTrue(ok)
            self.assertTrue((app / "Delta.exe").is_file())
            self.assertEqual(len(engine.calls), 2)
            self.assertIn("/layout", engine.calls[0].args)
            self.assertEqual(engine.calls[1].program, "msiexec.exe")
            self.assertIn("/a", engine.calls[1].args)
            self.assertFalse(any("/install" in plan.args
                                 for plan in engine.calls))
            self.assertFalse(any(plan.interactive for plan in engine.calls))
            self.assertFalse(layout.exists())

    def test_delta_self_layout_recovers_msi_from_redirected_package_cache(self):
        """Реальный журнал 1.41.0: /layout вернул тот же bundle, MSI — в cache.

        Первый quiet /install с InstallFolder ничего не даёт, второй без него
        кэширует Delta.msi. Его нужно распаковать через msiexec /a, а не
        копировать Package Cache или запускать одинаковый setup.exe рекурсивно.
        """
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "delta-windows-x86_64-setup.exe")
            installer.write_bytes(b"same Delta Burn bundle")
            portable = Path(temp, "Delta_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            cache = (data / "User" / "AppData" / "Local" /
                     "Package Cache" / "{delta-package-guid}")
            detection = DetectionResult(InstallerType.WIX_BURN, 0.97)

            class FakeBurn(Portablizer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.calls = []

                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    self.calls.append(plan)
                    if "/layout" in plan.args:
                        out = Path(plan.output_dir)
                        out.mkdir(parents=True, exist_ok=True)
                        (out / "DeltaSetup.exe").write_bytes(
                            installer.read_bytes())
                    elif plan.program == "msiexec.exe":
                        Path(app_dir, "Delta.exe").write_bytes(b"MZ application")
                    elif ("/install" in plan.args
                          and not any(arg.startswith("InstallFolder=")
                                      for arg in plan.args)):
                        cache.mkdir(parents=True, exist_ok=True)
                        (cache / "Delta.msi").write_bytes(b"real MSI payload")
                    return 0

            engine = FakeBurn(Logger())
            engine._detection = detection
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Delta")
            attempts = build_attempts(
                detection, str(installer), str(app), log_dir=str(portable),
                layout_dir=str(portable / "_bundle_layout"))

            rc, used = engine._run_attempts(
                attempts, opts, str(app), str(data), str(portable), "Delta")

            self.assertEqual(rc, 0)
            self.assertIsNotNone(used)
            self.assertIn("/install", used.args)
            self.assertTrue((app / "Delta.exe").is_file())
            self.assertEqual(len(engine.calls), 4)
            self.assertIn("/layout", engine.calls[0].args)
            self.assertIn("/install", engine.calls[1].args)
            self.assertIn("/install", engine.calls[2].args)
            self.assertEqual(engine.calls[3].program, "msiexec.exe")
            self.assertIn("/a", engine.calls[3].args)
            self.assertIn("Delta.msi", engine.calls[3].display())
            self.assertFalse((app / "DeltaSetup.exe").exists())
            self.assertFalse((app / "Delta.msi").exists())
            self.assertFalse(cache.exists())
            self.assertFalse((portable / "_bundle_layout").exists())
            self.assertIn("сам кэш как программу не использую",
                          engine.log.text)

    def test_burn_reuses_matching_cached_msi_from_previous_failed_build(self):
        """Повторная сборка не зависит от перезаписи уже Present-пакета."""
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "DeltaSetup.exe")
            installer.write_bytes(b"same Delta Burn bundle")
            portable = Path(temp, "Delta_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            cache = (data / "ProgramData" / "Package Cache" /
                     "{delta-package-guid}")
            cache.mkdir(parents=True)
            (cache / "Delta.msi").write_bytes(b"cached MSI from 1.41.0")
            detection = DetectionResult(InstallerType.WIX_BURN, 0.97)

            class FakeBurn(Portablizer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.calls = []

                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    self.calls.append(plan)
                    if "/layout" in plan.args:
                        out = Path(plan.output_dir)
                        out.mkdir(parents=True, exist_ok=True)
                        (out / "DeltaSetup.exe").write_bytes(
                            installer.read_bytes())
                    elif plan.program == "msiexec.exe":
                        Path(app_dir, "Delta.exe").write_bytes(b"MZ application")
                    # /install завершается нулём, но Present-пакет не пишет MSI
                    # повторно: кэш остаётся байт-в-байт прежним.
                    return 0

            engine = FakeBurn(Logger())
            engine._detection = detection
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Delta")
            attempts = build_attempts(
                detection, str(installer), str(app), log_dir=str(portable),
                layout_dir=str(portable / "_bundle_layout"))

            rc, used = engine._run_attempts(
                attempts, opts, str(app), str(data), str(portable), "Delta")

            self.assertEqual(rc, 0)
            self.assertIsNotNone(used)
            self.assertTrue((app / "Delta.exe").is_file())
            # /layout, один /install, затем msiexec /a сохранённого Delta.msi.
            self.assertEqual(len(engine.calls), 3)
            self.assertEqual(engine.calls[-1].program, "msiexec.exe")
            self.assertIn("сохранённый MSI-пакет", engine.log.text)
            self.assertFalse(cache.exists())

    def test_burn_does_not_retry_unchanged_cached_msi_after_failure(self):
        """Неизменный MSI после ошибки не запускается заново на каждом плане."""
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "DeltaSetup.exe")
            installer.write_bytes(b"same Delta Burn bundle")
            portable = Path(temp, "Delta_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            cache = (data / "ProgramData" / "Package Cache" /
                     "{delta-package-guid}")
            cache.mkdir(parents=True)
            cached_msi = cache / "Delta.msi"
            cached_msi.write_bytes(b"cached MSI from a previous build")
            detection = DetectionResult(InstallerType.WIX_BURN, 0.97)

            class FakeBurn(Portablizer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.calls = []

                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    self.calls.append(plan)
                    if "/layout" in plan.args:
                        out = Path(plan.output_dir)
                        out.mkdir(parents=True, exist_ok=True)
                        (out / "DeltaSetup.exe").write_bytes(
                            installer.read_bytes())
                    # Present-пакет ничего не ставит; msiexec тоже не даёт
                    # payload. Повтор того же MSI уже ничего изменить не может.
                    return 0

            engine = FakeBurn(Logger())
            engine._detection = detection
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Delta")
            attempts = build_attempts(
                detection, str(installer), str(app), log_dir=str(portable),
                layout_dir=str(portable / "_bundle_layout"))

            _rc, used = engine._run_attempts(
                attempts, opts, str(app), str(data), str(portable), "Delta")

            self.assertIsNone(used)
            msi_calls = [call for call in engine.calls
                         if call.program == "msiexec.exe"]
            self.assertEqual(len(msi_calls), 1)
            self.assertEqual(len(engine.calls), 4)
            self.assertTrue(msi_calls[0].progress_logs[0].endswith(
                "burn-cache-msi-1.log"))
            self.assertTrue(cached_msi.is_file())
            self.assertFalse(any(app.iterdir()))

    def test_burn_does_not_use_unrelated_stale_cached_msi(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "DeltaSetup.exe")
            installer.write_bytes(b"Delta Burn bundle")
            portable = Path(temp, "Delta_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            cache = data / "ProgramData" / "Package Cache" / "{other-guid}"
            cache.mkdir(parents=True)
            other_msi = cache / "OtherProduct.msi"
            other_msi.write_bytes(b"unrelated old MSI")
            detection = DetectionResult(InstallerType.WIX_BURN, 0.97)

            class FakeBurn(Portablizer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.calls = []

                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    self.calls.append(plan)
                    return 0

            engine = FakeBurn(Logger())
            engine._detection = detection
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Delta")
            attempts = build_attempts(
                detection, str(installer), str(app), log_dir=str(portable),
                layout_dir=str(portable / "_bundle_layout"))

            _rc, used = engine._run_attempts(
                attempts, opts, str(app), str(data), str(portable), "Delta")

            self.assertIsNone(used)
            self.assertEqual(len(engine.calls), 3)
            self.assertFalse(any(call.program == "msiexec.exe"
                                 for call in engine.calls))
            self.assertTrue(other_msi.is_file())
            self.assertEqual(list(app.iterdir()), [])

    def test_burn_package_cache_is_not_recovered_as_application(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "delta-windows-x86_64-setup.exe")
            installer.write_bytes(b"outer bundle")
            cache = Path(temp, "ProgramData", "Package Cache", "{bundle-guid}")
            cache.mkdir(parents=True)
            (cache / "DeltaSetup.exe").write_bytes(b"MZ maintenance")
            app = Path(temp, "Delta_Portable", "App")
            data = Path(temp, "Delta_Portable", "PortableData")
            app.mkdir(parents=True)
            data.mkdir()
            engine = Portablizer(Logger())

            # Не сканируем реальные Program Files/корни дисков в Windows CI:
            # здесь проверяется только отбрасывание cache-пути из реестра.
            with mock.patch.object(engine, "_install_search_roots",
                                   return_value=[]):
                recovered = engine._recover_installed_app(
                    str(app), str(data), "Delta", str(installer), {},
                    registry_locations=[str(cache)])

            self.assertFalse(recovered)
            self.assertEqual(list(app.iterdir()), [])

    def test_setup_executable_is_not_accepted_as_main_program(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "DeltaSetup.exe").write_bytes(b"MZ setup")
            self.assertIsNone(Portablizer(Logger())._find_main_exe(
                str(app), "Delta"))

    def test_burn_fallback_keeps_layout_when_no_msi_found(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "TypeSetup.exe")
            # Структурно валидный Burn-бандл: опознаётся по секции .wixburn
            # с высокой уверенностью, поэтому лестница — только сценарии Burn.
            _fake_pe(str(installer), [".text", ".rsrc", ".wixburn"],
                     b"WixBurn wixstdba")
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir(parents=True)

            class FakeBurn(Portablizer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.calls = []

                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    self.calls.append(plan)
                    if "/layout" in plan.args:
                        layout = portable / "_bundle_layout"
                        layout.mkdir(parents=True, exist_ok=True)
                        (layout / "tool.exe").write_bytes(b"MZ exe payload")
                    return 5

            engine = FakeBurn(Logger())
            opts = PortableOptions(installer_path=str(installer),
                                   output_dir=temp, app_name="Type")
            attempts = build_attempts(
                detect_installer(str(installer)), str(installer), str(app),
                log_dir=str(portable),
                layout_dir=str(portable / "_bundle_layout"))
            rc, used = engine._run_attempts(attempts, opts, str(app),
                                            str(data), str(portable), "Type")

            # Обе команды установки и /layout: MSI не было, msiexec не вызывался.
            self.assertEqual(len(engine.calls), 3)
            self.assertIsNone(used)
            self.assertEqual(rc, 5)
            self.assertFalse((app / "Type.exe").exists())
            layout = portable / "_bundle_layout"
            self.assertTrue(layout.is_dir())
            self.assertTrue((layout / "tool.exe").exists())

    def test_run_triggers_burn_fallback_when_primary_fails(self):
        # Сценарий со скриншота: WiX Burn, тихая установка возвращает -1
        # (беззнаковое 4294967295), App пуста — резервный сценарий спасает.
        class FakeBurn(Portablizer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = []

            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                self.calls.append(plan)
                if any(a.startswith("InstallFolder=") for a in plan.args):
                    # Даже когда сам /install уже положил приложение в App,
                    # его установочные layout/cache должны быть удалены общим
                    # успешным путём, а не только веткой recovery из MSI.
                    portable = Path(data_dir).parent
                    layout = portable / "_bundle_layout"
                    cache = (Path(data_dir) / "User" / "AppData" / "Local" /
                             "Package Cache" / "{type-package}")
                    layout.mkdir(parents=True, exist_ok=True)
                    cache.mkdir(parents=True, exist_ok=True)
                    (layout / "TypeSetup.exe").write_bytes(b"MZ setup")
                    (cache / "Type.msi").write_bytes(b"cached installer")
                    return 4294967295
                Path(app_dir, "Type.exe").write_bytes(b"MZ application")
                return 0

        with tempfile.TemporaryDirectory() as temp, mock.patch(
                "portablizer.core.portablizer.IS_WINDOWS", True):
            installer = Path(temp, "TypeSetup.exe")
            # Структурно валидный Burn-бандл: опознаётся по секции .wixburn
            # с высокой уверенностью, поэтому лестница — только сценарии Burn.
            _fake_pe(str(installer), [".text", ".rsrc", ".wixburn"],
                     b"WixBurn wixstdba")
            engine = FakeBurn(Logger())
            result = engine.run(PortableOptions(
                installer_path=str(installer), output_dir=temp,
                app_name="Type", capture_registry=False, cleanup_host=False,
            ))

            self.assertTrue(result.success)
            self.assertEqual(len(engine.calls), 2)
            self.assertEqual(result.main_exe_rel,
                             os.path.join("App", "Type.exe"))
            self.assertIn("Сработал запасной сценарий", engine.log.text)
            # Собранный портатив сразу переносим: корень запомнен, отчёт о
            # путях лежит в корне, а в конфиге лончера нет абсолютного пути.
            portable = Path(temp, "Type_Portable")
            self.assertFalse((portable / "_bundle_layout").exists())
            self.assertFalse(any(portable.rglob("Package Cache")))
            self.assertTrue((portable / "portability-report.txt").is_file())
            self.assertTrue(Path(portable, "PortableData",
                                 "portable-root.json").is_file())
            config_text = (portable / "launcher_config.json").read_text(
                encoding="utf-8")
            self.assertNotIn(str(portable), config_text)
            self.assertTrue(json.loads(config_text)["relative_paths"]["enabled"])
            self.assertEqual(result.portability_report_rel,
                             "portability-report.txt")

    def test_failed_burn_reports_decoded_exit_code(self):
        # Даже резервные сценарии не помогли: ошибка обязана расшифровать
        # беззнаковый код 4294967295 как -1 и подсказать причину.
        class FakeBurn(Portablizer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = []

            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                self.calls.append(plan)
                return 4294967295

        with tempfile.TemporaryDirectory() as temp, mock.patch(
                "portablizer.core.portablizer.IS_WINDOWS", True):
            installer = Path(temp, "TypeSetup.exe")
            # Структурно валидный Burn-бандл: опознаётся по секции .wixburn
            # с высокой уверенностью, поэтому лестница — только сценарии Burn.
            _fake_pe(str(installer), [".text", ".rsrc", ".wixburn"],
                     b"WixBurn wixstdba")
            engine = FakeBurn(Logger())
            result = engine.run(PortableOptions(
                installer_path=str(installer), output_dir=temp,
                app_name="Type", capture_registry=False, cleanup_host=False,
            ))

            self.assertFalse(result.success)
            self.assertFalse(Path(temp, "Type_Portable", "Launch.bat").exists())
            # /layout + две запасные тихие команды установки.
            self.assertEqual(len(engine.calls), 3)
            message = "; ".join(result.messages)
            self.assertIn("4294967295 (-1, 0xFFFFFFFF)", message)
            self.assertIn("администратора", message)
            self.assertIn("не найден ни один", message)


class RegistryLocationTests(unittest.TestCase):
    def test_extracts_new_install_location_and_display_icon(self):
        before = {
            r"HKCU\Software\Old": {
                "InstallLocation": (registry.REG_SZ, repr(r"C:\Old"))},
        }
        after = {
            **before,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Type": {
                "DisplayName": (registry.REG_SZ, repr("Type")),
                "InstallLocation": (registry.REG_SZ,
                                    repr(r"C:\Program Files\Type")),
                "DisplayIcon": (registry.REG_SZ,
                                repr(r'"C:\Program Files\Type\Type.exe",0')),
            },
        }
        locations = registry.changed_install_locations(before, after)
        self.assertIn(r"C:\Program Files\Type", locations)
        self.assertIn(r"C:\Program Files\Type\Type.exe", locations)

    def test_legacy_snapshot_format_is_still_readable(self):
        before = {}
        after = {r"HKCU\Software\X": {"InstallLocation": repr(r"C:\X")}}
        self.assertIn(r"C:\X", registry.changed_install_locations(before, after))

    def test_extracts_local_paths_from_custom_app_registry_keys(self):
        before = {}
        after = {
            r"HKCU\Software\Multitran\Directories": {
                "MainDir": (registry.REG_SZ, repr(r"E:\Backup\Apps\Portable\Multitran 03.11.2023")),
                "ExeFile": (registry.REG_SZ, repr(r"C:\Multitran\network.exe")),
            },
        }
        locations = registry.changed_install_locations(before, after)
        self.assertIn(r"E:\Backup\Apps\Portable\Multitran 03.11.2023", locations)
        self.assertIn(r"C:\Multitran\network.exe", locations)

    def test_retarget_install_paths_rewrites_extra_recovered_roots(self):
        key = r"HKCU\Software\Multitran\Directories"
        old_src = r"E:\Backup\Apps\Portable\Multitran 03.11.2023"
        old_c = r"C:\Multitran"
        app_dir = r"E:\Backup\Apps\Portable\Multitran 03.11.2023\Multitran_Portable\App"
        snapshot = {
            key: {
                "DictPath": (registry.REG_SZ, repr(old_src + r"\eng.erd")),
                "ShellExe": (registry.REG_SZ, repr(old_c + r"\network.exe")),
            },
        }
        moved = registry.retarget_install_paths(
            snapshot, [key], app_dir, extra_roots=[old_src, old_c]
        )
        text = registry.render_keys(moved, [key])
        self.assertIn(r"Multitran_Portable\\App\\eng.erd", text)
        self.assertIn(r"Multitran_Portable\\App\\network.exe", text)

    def test_generic_setup_does_not_copy_unverified_distribution_folder(self):
        class FakeMultitran(Portablizer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = []

            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                self.calls.append(plan)
                return 0

        with tempfile.TemporaryDirectory() as temp:
            dist = Path(temp, "Multitran 03.11.2023")
            dist.mkdir(parents=True)
            setup = dist / "setup.exe"
            _fake_pe(str(setup), [".text", ".rdata", ".data", ".rsrc"], b"custom setup")
            (dist / "network.exe").write_bytes(b"MZ" + b"x" * 2048)
            (dist / "eng.erd").write_bytes(b"dictionary-payload")

            engine = FakeMultitran(Logger())
            opts = PortableOptions(
                installer_path=str(setup),
                output_dir=str(dist),
                app_name="Multitran",
                capture_registry=False,
                bundle_runtimes=False,
            )
            res = engine.run(opts)
            self.assertFalse(res.success)
            app_dir = Path(res.portable_dir, "App")
            self.assertFalse((app_dir / "network.exe").exists())
            self.assertFalse((app_dir / "eng.erd").exists())
            self.assertFalse((app_dir / "setup.exe").exists())
            self.assertFalse((app_dir / "Multitran_Portable").exists())
            # Исходная папка пользователя не должна быть удалена!
            self.assertTrue(dist.is_dir())
            self.assertTrue(setup.is_file())
            self.assertTrue((dist / "network.exe").is_file())


def _fake_pe(path, sections, payload=b"", dotnet=False):
    """Пишет минимальный, но структурно валидный PE-файл.

    Нужен, чтобы проверять разбор секций и признака .NET без настоящих
    установщиков в репозитории.
    """
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    optional_size = 240
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0,
                       optional_size, 0x2102)
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x10B)      # PE32
    struct.pack_into("<I", optional, 92, 16)        # NumberOfRvaAndSizes
    if dotnet:
        struct.pack_into("<II", optional, 96 + 14 * 8, 0x2000, 0x48)
    table = b"".join(name.encode().ljust(8, b"\0") + b"\0" * 32
                     for name in sections)
    Path(path).write_bytes(bytes(dos) + b"PE\0\0" + coff + bytes(optional)
                           + table + payload)


class InstallArgumentParsingTests(unittest.TestCase):
    """Разбор поля «Доп. аргументы установки».

    Именно сюда пользователя отправляет сообщение об ошибке, поэтому поле
    обязано работать безупречно. Раньше разделителями считалась строка
    ``" \\t"`` — пробел, обратный слеш и буква «t», — и любой аргумент с «t»
    рвался на куски (``--silent`` -> ``--silen``).
    """

    @staticmethod
    def _parse(raw):
        # Импортируем парсер без Qt: в окружении сборки нет libGL.
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "portablizer", "gui", "main_window.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and \
                    node.name == "_parse_install_args":
                node.decorator_list = []
                module = ast.Module(body=[node], type_ignores=[])
                namespace: dict = {}
                exec(compile(module, path, "exec"), namespace)  # noqa: S102
                return namespace["_parse_install_args"](raw)
        raise AssertionError("парсер аргументов не найден")

    def test_switch_containing_letter_t_is_not_split(self):
        self.assertEqual(self._parse("--silent"), ["--silent"])
        self.assertEqual(self._parse("/VERYSILENT"), ["/VERYSILENT"])

    def test_quoted_value_with_url_survives(self):
        self.assertEqual(
            self._parse('--silent --accept-license-agreement='
                        '"https://zennolab.com/terms-of-service/"'),
            ["--silent",
             "--accept-license-agreement=https://zennolab.com/terms-of-service/"],
        )

    def test_quoted_path_with_spaces_stays_one_argument(self):
        self.assertEqual(
            self._parse('/DIR="C:\\Program Files\\App" /NOICONS'),
            ["/DIR=C:\\Program Files\\App", "/NOICONS"],
        )

    def test_tab_separates_arguments(self):
        self.assertEqual(self._parse("/VERYSILENT\t/NORESTART"),
                         ["/VERYSILENT", "/NORESTART"])

    def test_empty_input_yields_no_arguments(self):
        self.assertEqual(self._parse("   "), [])


class CustomBootstrapperDetectionTests(unittest.TestCase):
    """Регрессия на журнал пользователя: код -1 и пустая папка App.

    Установщик лишь УПОМИНАЛ WixBurn, но настоящим Burn-бандлом не был.
    Portablizer верил строке, слал ``/quiet /install`` и получал -1.
    """

    def _installer(self, temp, payload, sections=(".text", ".rsrc"),
                   dotnet=True, name="ZennoPosterLite-RU-v7.9.2.0.exe"):
        path = os.path.join(temp, name)
        _fake_pe(path, list(sections), payload, dotnet=dotnet)
        return path

    ZENNO_PAYLOAD = (
        b"WixBurn .wixburn wixstdba "
        b"--silent --hidden --accept-license-agreement= --installPath "
        b"--installType https://zennolab.com/terms-of-service/ "
        b"requireAdministrator"
    )

    def test_burn_strings_without_section_are_not_a_burn_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(self._installer(temp, self.ZENNO_PAYLOAD))
            self.assertNotEqual(det.installer_type, InstallerType.WIX_BURN)
            self.assertEqual(det.installer_type, InstallerType.CUSTOM_CLI)

    def test_real_burn_bundle_is_still_detected_by_pe_section(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self._installer(
                temp, b"WixBurn wixstdba",
                sections=(".text", ".rdata", ".wixburn"), dotnet=False,
                name="RealBundle.exe")
            det = detect_installer(path)
            self.assertEqual(det.installer_type, InstallerType.WIX_BURN)
            self.assertGreater(det.confidence, 0.9)

    def test_license_url_and_admin_requirement_are_extracted(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(self._installer(temp, self.ZENNO_PAYLOAD))
            self.assertEqual(det.license_url,
                             "https://zennolab.com/terms-of-service/")
            self.assertTrue(det.requires_admin)
            self.assertTrue(det.is_dotnet)

    def test_plan_uses_the_switches_found_inside_the_installer(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(temp, self.ZENNO_PAYLOAD)
            det = detect_installer(installer)
            plan = build_custom_cli_plan(installer, r"E:\P\App", detection=det)
            self.assertIn("--silent", plan.args)
            self.assertIn(
                "--accept-license-agreement=https://zennolab.com/terms-of-service/",
                plan.args)
            self.assertIn(r"--installPath=E:\P\App", plan.args)
            # Ключи классических движков сюда попасть не должны.
            self.assertNotIn("/quiet", plan.args)
            self.assertNotIn("/install", plan.args)

    def test_attempt_ladder_offers_several_variants(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(temp, self.ZENNO_PAYLOAD)
            attempts = build_attempts(detect_installer(installer), installer,
                                      r"E:\P\App", log_dir=r"E:\P")
            self.assertGreaterEqual(len(attempts), 2)
            # Первый вариант — самый точный, с путём установки.
            self.assertTrue(any(a.startswith("--installPath=")
                                for a in attempts[0].args))
            # Дальше — без пути, на случай если установщик его не принимает.
            self.assertFalse(any(a.startswith("--installPath=")
                                 for a in attempts[1].args))

    def test_unknown_installer_falls_back_to_generic_switch_ladder(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(temp, b"nothing recognisable here",
                                        dotnet=False, name="Mystery.exe")
            det = detect_installer(installer)
            self.assertEqual(det.installer_type, InstallerType.UNKNOWN)
            attempts = build_attempts(det, installer, r"E:\P\App")
            self.assertGreaterEqual(len(attempts), 3)
            joined = [" ".join(a.args) for a in attempts]
            self.assertTrue(any("/S" in a for a in joined))
            self.assertTrue(any("/VERYSILENT" in a for a in joined))


class WeakSignatureDetectionTests(unittest.TestCase):
    """Одиночная слабая подстрока («nsis») — не доказательство движка.

    Регрессия на журнал пользователя: установщик, в котором из сигнатур
    совпала лишь подстрока «nsis», получал уверенность 70 %, единственную
    команду ``/S /D=…`` и код -1 — настоящий установщик (ZennoLab) этих
    ключей не понимает.
    """

    # Содержимое повторяет свидетельства из журнала: только слабое «nsis»
    # и ключи с одним слешем, ни одного «--», никаких URL.
    PACKED_PAYLOAD = (
        b"/quiet /passive /layout /qn /qb /uninstall /NORESTART /SILENT "
        b"bootstrapper mentions nsis internally "
        b"requireAdministrator"
    )

    def _installer(self, temp, payload, name="Mystery.exe"):
        path = os.path.join(temp, name)
        _fake_pe(path, [".text", ".rsrc"], payload)
        return path

    def test_lone_nsis_substring_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(
                self._installer(temp, self.PACKED_PAYLOAD))
            self.assertEqual(det.installer_type, InstallerType.NSIS)
            self.assertLess(det.confidence, TRUSTED_CONFIDENCE)
            self.assertTrue(any("слаб" in e for e in det.evidence))

    def test_low_confidence_detection_gets_generic_fallback_ladder(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(temp, self.PACKED_PAYLOAD)
            attempts = build_attempts(detect_installer(installer), installer,
                                      r"E:\P\App")
            self.assertGreaterEqual(len(attempts), 3)
            # Первой идёт команда предполагаемого движка…
            self.assertEqual(attempts[0].args[:1], ["/S"])
            self.assertEqual(attempts[0].raw_tail, r"/D=E:\P\App")
            # …а за ней — универсальные варианты, если предположение неверно.
            joined = [" ".join(a.args) for a in attempts[1:]]
            self.assertTrue(any("/VERYSILENT" in a for a in joined))
            self.assertTrue(any("/quiet" in a for a in joined))

    def test_strong_nsis_signature_keeps_trusted_single_scenario(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(
                temp, b"Nullsoft Install System " + self.PACKED_PAYLOAD)
            det = detect_installer(installer)
            self.assertEqual(det.installer_type, InstallerType.NSIS)
            self.assertGreaterEqual(det.confidence, TRUSTED_CONFIDENCE)
            attempts = build_attempts(det, installer, r"E:\P\App")
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0].label, "NSIS: /S /D")


class VendorProfileTests(unittest.TestCase):
    """Упакованный установщик ZennoLab узнаётся по имени файла продукта.

    Регрессия на журнал пользователя: ZennoPosterLite-RU-v7.9.2.0.exe был
    опознан как NSIS по слабой подстроке и упал с кодом -1 на ключах /S /D.
    Строк внутри сборки не видно, но ZennoLab публикует точную команду:
    ``--silent --hidden --accept-license-agreement="…" --installPath=…``.
    """

    ZENNO_NAME = "ZennoPosterLite-RU-v7.9.2.0.exe"
    ZENNO_LICENSE = "https://zennolab.com/terms-of-service/"

    def _zennolite(self, temp, payload=WeakSignatureDetectionTests.PACKED_PAYLOAD,
                   name=ZENNO_NAME):
        path = os.path.join(temp, name)
        _fake_pe(path, [".text", ".rsrc"], payload, dotnet=True)
        return path

    def test_packed_installer_is_recognized_by_vendor_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(self._zennolite(temp))
            self.assertEqual(det.installer_type, InstallerType.CUSTOM_CLI)
            self.assertEqual(det.license_url, self.ZENNO_LICENSE)
            self.assertEqual(det.vendor_args, ["--installType=StandAlone"])
            self.assertTrue(det.has_switch("--silent"))
            self.assertTrue(det.has_switch("--accept-license-agreement"))
            self.assertTrue(det.has_switch("--installPath"))
            self.assertTrue(det.requires_admin)
            self.assertTrue(any("ZennoLab" in e for e in det.evidence))
            # В журнале видно, чей это установщик, а не абстрактный тип.
            self.assertEqual(det.vendor_name, "ZennoLab")
            self.assertTrue(det.human.startswith("ZennoLab: "))
            self.assertIn("Custom CLI bootstrapper", det.human)

    def test_command_line_matches_zennolab_documentation(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._zennolite(temp)
            attempts = build_attempts(detect_installer(installer), installer,
                                      r"E:\Portable\ZP_Portable\App")
            self.assertGreaterEqual(len(attempts), 2)
            first = attempts[0].args
            self.assertIn("--silent", first)
            self.assertIn("--hidden", first)
            self.assertIn(
                f"--accept-license-agreement={self.ZENNO_LICENSE}", first)
            self.assertIn(r"--installPath=E:\Portable\ZP_Portable\App", first)
            # StandAlone: не трогаем уже установленную на этом ПК копию.
            self.assertIn("--installType=StandAlone", first)
            # Запасной вариант без пути всё равно принимает лицензию и не
            # обновляет существующие копии.
            second = attempts[1].args
            self.assertFalse(any(a.startswith("--installPath=")
                                 for a in second))
            self.assertIn("--installType=StandAlone", second)

    def test_unrelated_filename_is_not_hijacked(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(self._zennolite(temp, name="Mystery.exe"))
            self.assertNotEqual(det.installer_type, InstallerType.CUSTOM_CLI)

    def test_strong_engine_beats_vendor_filename(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._zennolite(
                temp,
                payload=b"This installation was built with Inno Setup "
                        + WeakSignatureDetectionTests.PACKED_PAYLOAD)
            det = detect_installer(installer)
            self.assertEqual(det.installer_type, InstallerType.INNO)

    def test_run_succeeds_with_documented_command_line(self):
        # Сквозной сценарий журнала пользователя — теперь он должен РАБОТАТЬ.
        class ZennoInstaller(Portablizer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = []

            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                self.calls.append(plan.args)
                if not any(a == "--accept-license-agreement="
                                + VendorProfileTests.ZENNO_LICENSE
                           for a in plan.args):
                    # Как в журнале: без принятой лицензии установщик падает.
                    return 4294967295
                Path(app_dir, "ZennoPoster.exe").write_bytes(b"MZ app")
                return 0

        with tempfile.TemporaryDirectory() as temp:
            installer = self._zennolite(temp)
            engine = ZennoInstaller(Logger())
            result = engine.run(PortableOptions(
                installer_path=installer, output_dir=temp,
                app_name="ZennoPoster", capture_registry=False,
                cleanup_host=False))
            self.assertTrue(result.success, "; ".join(result.messages))
            self.assertEqual(len(engine.calls), 1)
            self.assertEqual(result.attempts_made, 1)
            self.assertTrue(Path(result.portable_dir, "Launch.bat").exists())


class FailureLogArtifactsTests(unittest.TestCase):
    """Артефакты диагностики: вывод установщика и очистка прошлых запусков."""

    def test_installer_output_log_is_cleaned_before_rerun(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            app = portable / "App"
            data = portable / "PortableData"
            app.mkdir(parents=True)
            data.mkdir()
            (portable / "installer-output.log").write_text(
                "old output", encoding="utf-8")
            Portablizer(Logger())._prepare_output(
                str(portable), str(app), str(data))
            self.assertFalse((portable / "installer-output.log").exists())

    def test_failure_message_points_at_installer_output_log(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, "installer-output.log").write_text(
                "Error: license agreement not accepted", encoding="utf-8")
            engine = Portablizer(Logger())
            result = PortableResult(success=False, portable_dir=temp,
                                    attempts_made=1)
            det = DetectionResult(InstallerType.NSIS, 0.7)
            message = engine._failure_message(det, 4294967295, result)
            self.assertIn("installer-output.log", message)

    def test_failure_message_without_output_log_stays_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            engine = Portablizer(Logger())
            result = PortableResult(success=False, portable_dir=temp,
                                    attempts_made=1)
            det = DetectionResult(InstallerType.NSIS, 0.7)
            message = engine._failure_message(det, 4294967295, result)
            self.assertNotIn("installer-output.log", message)


class AttemptLadderTests(unittest.TestCase):
    """Оркестратор обязан идти по лестнице до фактического результата."""

    def _engine(self, succeed_on):
        class Fake(Portablizer):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.calls = []

            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                self.calls.append(plan.label)
                if len(self.calls) == succeed_on:
                    Path(app_dir, "Type.exe").write_bytes(b"MZ application")
                    return 0
                return 4294967295

        return Fake(Logger())

    def _plans(self, count):
        return [SilentPlan(program="setup.exe", args=[f"/v{i}"],
                           label=f"вариант {i}", output_dir="")
                for i in range(count)]

    def test_stops_at_the_first_attempt_that_produces_files(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            engine = self._engine(succeed_on=2)
            rc, used = engine._run_attempts(
                self._plans(4),
                PortableOptions(installer_path="x", output_dir=temp),
                str(app), str(Path(temp, "Data")), temp, "Type")
            self.assertEqual(len(engine.calls), 2)
            self.assertEqual(rc, 0)
            self.assertEqual(used.label, "вариант 1")

    def test_exhausts_every_attempt_before_giving_up(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            engine = self._engine(succeed_on=99)
            rc, used = engine._run_attempts(
                self._plans(3),
                PortableOptions(installer_path="x", output_dir=temp),
                str(app), str(Path(temp, "Data")), temp, "Type")
            self.assertEqual(len(engine.calls), 3)
            self.assertIsNone(used)
            self.assertEqual(rc, 4294967295)

    def test_zero_exit_code_with_empty_folder_is_not_success(self):
        """Код 0 сам по себе ничего не значит — важны файлы на диске."""
        class Liar(Portablizer):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.calls = []

            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                self.calls.append(plan.label)
                return 0

        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            engine = Liar(Logger())
            _rc, used = engine._run_attempts(
                self._plans(3),
                PortableOptions(installer_path="x", output_dir=temp),
                str(app), str(Path(temp, "Data")), temp, "Type")
            self.assertIsNone(used)
            self.assertEqual(len(engine.calls), 3)


class ZipPayloadTests(unittest.TestCase):
    """Установщик с приклеенным ZIP можно распаковать без установки."""

    def _installer_with_zip(self, path, names):
        with open(path, "wb") as fh:
            fh.write(b"MZ" + b"\x00" * 512)
        with zipfile.ZipFile(path, "a") as archive:
            for name in names:
                archive.writestr(name, "MZ payload" * 10)

    def test_zip_payload_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = os.path.join(temp, "Setup.exe")
            self._installer_with_zip(installer, ["Type.exe"])
            self.assertTrue(detect_installer(installer).has_zip_payload)

    def test_program_is_extracted_from_the_embedded_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = os.path.join(temp, "Setup.exe")
            self._installer_with_zip(installer, ["Type.exe", "lib/helper.dll"])
            app = Path(temp, "App")
            app.mkdir()
            engine = Portablizer(Logger())
            self.assertTrue(
                engine._extract_zip_payload(installer, str(app), "Type"))
            self.assertTrue((app / "Type.exe").exists())
            self.assertTrue((app / "lib" / "helper.dll").exists())

    def test_archive_cannot_escape_the_app_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = os.path.join(temp, "Setup.exe")
            self._installer_with_zip(installer,
                                     ["../escaped.exe", "Type.exe"])
            app = Path(temp, "App")
            app.mkdir()
            engine = Portablizer(Logger())
            engine._extract_zip_payload(installer, str(app), "Type")
            self.assertFalse(Path(temp, "escaped.exe").exists())


class FailureDiagnosticsTests(unittest.TestCase):
    """Вместо «смотрите журнал» пользователь должен получать план действий."""

    def _failed_result(self, payload, extra_args=()):
        class AlwaysFails(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                return 4294967295

        temp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(temp, ignore_errors=True))
        installer = os.path.join(temp, "ZennoPosterLite-RU-v7.9.2.0.exe")
        _fake_pe(installer, [".text", ".rsrc"], payload, dotnet=True)
        with mock.patch("portablizer.core.portablizer.IS_WINDOWS", True), \
                mock.patch("portablizer.core.portablizer.is_elevated",
                           return_value=False):
            return AlwaysFails(Logger()).run(PortableOptions(
                installer_path=installer, output_dir=temp, app_name="Type",
                capture_registry=False, cleanup_host=False,
                extra_install_args=list(extra_args),
            ))

    def test_failure_explains_admin_rights_and_license_switch(self):
        result = self._failed_result(
            CustomBootstrapperDetectionTests.ZENNO_PAYLOAD)
        self.assertFalse(result.success)
        message = "; ".join(result.messages)
        self.assertIn("4294967295 (-1, 0xFFFFFFFF)", message)
        self.assertIn("администратора", message)
        self.assertIn("--accept-license-agreement", message)
        self.assertIn("zennolab.com", message)

    def test_failure_reports_how_many_variants_were_tried(self):
        result = self._failed_result(
            CustomBootstrapperDetectionTests.ZENNO_PAYLOAD)
        self.assertGreater(result.attempts_made, 1)
        self.assertEqual(result.attempts_made, result.attempts_planned)
        self.assertIn("Испробовано вариантов", "; ".join(result.messages))

    def test_user_supplied_arguments_are_mentioned_in_the_advice(self):
        result = self._failed_result(
            CustomBootstrapperDetectionTests.ZENNO_PAYLOAD,
            extra_args=["/WRONGSWITCH"])
        self.assertIn("/WRONGSWITCH", "; ".join(result.messages))

    def test_no_broken_launcher_is_left_behind_on_failure(self):
        result = self._failed_result(
            CustomBootstrapperDetectionTests.ZENNO_PAYLOAD)
        portable = Path(result.portable_dir)
        self.assertFalse((portable / "Launch.bat").exists())
        self.assertTrue((portable / "portablizer.log").exists())

    def test_failure_lists_outcome_of_every_attempt(self):
        # Кода возврата одной последней попытки мало: итог нужен по каждой.
        result = self._failed_result(
            CustomBootstrapperDetectionTests.ZENNO_PAYLOAD)
        message = "; ".join(result.messages)
        self.assertIn("Итог каждой команды", message)
        # Заголовки всех трёх сценариев лестницы присутствуют в отчёте.
        self.assertIn("Собственные ключи установщика", message)
        self.assertIn("Собственные ключи без пути установки", message)
        self.assertIn("Собственные ключи без --hidden", message)
        self.assertEqual(len(result.attempt_outcomes), result.attempts_made)
        self.assertTrue(all(rc == 4294967295
                            for _label, rc in result.attempt_outcomes))

    def test_success_code_with_no_files_is_spelled_out(self):
        self.assertIn(
            "код 0, но файлов",
            Portablizer(Logger())._failure_message(
                DetectionResult(InstallerType.NSIS, 0.7), 0,
                PortableResult(
                    success=False, attempts_made=2,
                    attempt_outcomes=[("NSIS: /S /D", 4294967295),
                                      ("Универсальные ключи: /S", 0)],
                )))


class InstallShieldGenerationTests(unittest.TestCase):
    """Регрессия на журнал пользователя: диск «American McGee's Alice».

    Portablizer опознал InstallShield (85%) и отправил в него команду
    современной обёртки над MSI — ``/s /v"/qn INSTALLDIR=…"``. Классический
    InstallScript 5/6 ключа ``/v`` не знает: setup.exe вышел через две
    секунды с кодом 0, папка App осталась пустой.
    """

    LEGACY_STRINGS = (b"InstallShield\x00_isres.dll\x00_setup.dll\x00"
                      b"setup.ins\x00IKernel\x00")
    MSI_STRINGS = (b"InstallShield\x00ISSetup.dll\x00MsiExec.exe\x00"
                   b"Windows Installer\x00")

    def _disc(self, temp, files, payload=LEGACY_STRINGS, name="Setup.exe"):
        """Собирает раскладку установочного диска вокруг setup.exe."""
        media = Path(temp, "disc")
        media.mkdir(exist_ok=True)
        _fake_pe(str(media / name), [".text", ".rsrc"], payload)
        for filename in files:
            (media / filename).write_bytes(b"payload" * 8)
        return str(media / name)

    def test_installscript_disc_is_recognized_by_its_media_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(self._disc(
                temp, ["data1.hdr", "data1.cab", "data2.cab", "setup.ins",
                       "_setup.dll", "setup.ini"]))

            self.assertEqual(det.installer_type, InstallerType.INSTALLSHIELD)
            self.assertEqual(det.installshield_generation,
                             InstallShieldGeneration.INSTALLSCRIPT)
            self.assertTrue(det.is_legacy_installshield)
            self.assertGreaterEqual(det.confidence, TRUSTED_CONFIDENCE)
            self.assertIn("InstallScript", det.human)

    def test_msi_wrapper_is_not_mistaken_for_installscript(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(self._disc(
                temp, ["ISSetup.dll", "Application.msi", "setup.ini"],
                payload=self.MSI_STRINGS))

            self.assertEqual(det.installshield_generation,
                             InstallShieldGeneration.MSI)
            self.assertFalse(det.is_legacy_installshield)

    def test_lone_signature_leaves_the_generation_open(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(self._disc(
                temp, [], payload=b"InstallShield Wizard"))

            self.assertEqual(det.installshield_generation,
                             InstallShieldGeneration.UNKNOWN)

    def test_response_file_next_to_the_installer_is_found(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._disc(
                temp, ["data1.hdr", "setup.ins", "other.iss", "setup.iss"])
            det = detect_installer(installer)

            self.assertEqual(os.path.basename(det.response_file), "setup.iss")
            self.assertEqual(len(det.response_files), 2)

    def test_media_layout_of_a_missing_folder_is_empty(self):
        layout = scan_media_layout(os.path.join("/nowhere", "Setup.exe"))
        self.assertEqual(layout.files, [])
        self.assertEqual(layout.legacy_score, 0)


class InstallShieldLadderTests(unittest.TestCase):
    """Команды каждого поколения строятся по документации Revenera."""

    APP = r"E:\Portable\Alice_Portable\App"
    LOG = r"E:\Portable\Alice_Portable\setup-installshield.log"
    ISS = r"E:\Portable\Alice_Portable\setup.iss"

    def _detection(self, generation, response_files=()):
        return DetectionResult(
            InstallerType.INSTALLSHIELD, 0.9,
            installshield_generation=generation,
            response_files=list(response_files))

    def test_installscript_never_receives_the_msi_switch(self):
        plans = build_attempts(
            self._detection(InstallShieldGeneration.INSTALLSCRIPT),
            r"J:\Setup.exe", self.APP,
            log_dir=r"E:\Portable\Alice_Portable")

        self.assertTrue(plans)
        for plan in plans:
            self.assertNotIn("/v", plan.display(),
                             "InstallScript 5/6 не понимает ключ /v")
            self.assertNotIn("INSTALLDIR", plan.display())

    def test_installscript_points_response_and_log_off_the_disc(self):
        plan = build_installscript_plan(
            r"J:\Setup.exe", self.APP, response_file=self.ISS,
            log_file=self.LOG)

        self.assertEqual(plan.args, ["/s"])
        self.assertEqual(
            plan.raw_tail,
            f'/f1"{self.ISS}" /f2"{self.LOG}" /SMS')
        self.assertTrue(plan.ignores_target_dir)
        self.assertFalse(plan.interactive)
        self.assertEqual(plan.result_log, self.LOG)

    def test_msi_wrapper_quotes_exactly_as_documented(self):
        plan = build_installshield_msi_plan(r"J:\Setup.exe", self.APP)

        # Документированная форма: /v вне кавычек, внутренние экранированы.
        self.assertEqual(
            plan.raw_tail,
            '/v"/qn INSTALLDIR=\\"E:\\Portable\\Alice_Portable\\App\\" /norestart"')
        self.assertEqual(plan.args, ["/s"])

    def test_unknown_generation_tries_both_dialects(self):
        plans = build_attempts(
            self._detection(InstallShieldGeneration.UNKNOWN),
            r"J:\Setup.exe", self.APP,
            log_dir=r"E:\Portable\Alice_Portable")
        rendered = [p.display() for p in plans]

        self.assertTrue(any("/v" in line for line in rendered))
        self.assertTrue(any("/f2" in line for line in rendered))

    def test_msi_generation_falls_back_to_extraction(self):
        det = self._detection(InstallShieldGeneration.MSI)
        det.switch_hints = ["/extract_all"]

        plans = build_attempts(
            det, r"J:\setup.exe", self.APP,
            log_dir=r"E:\Portable\Alice_Portable",
            layout_dir=r"E:\Portable\Alice_Portable\_bundle_layout")

        self.assertIn("INSTALLDIR", plans[0].display())
        self.assertNotIn("INSTALLDIR", plans[1].display())
        # Распаковку забирает msiexec /a — система остаётся нетронутой.
        self.assertTrue(plans[-1].extracts_only)
        self.assertIn("/extract_all:", plans[-1].display())

    def test_wizard_attempt_is_opt_in_and_always_last(self):
        without = build_attempts(
            self._detection(InstallShieldGeneration.INSTALLSCRIPT),
            r"J:\Setup.exe", self.APP, log_dir=r"E:\Portable\Alice_Portable")
        self.assertFalse(any(p.interactive for p in without))

        with_wizard = build_attempts(
            self._detection(InstallShieldGeneration.INSTALLSCRIPT),
            r"J:\Setup.exe", self.APP, log_dir=r"E:\Portable\Alice_Portable",
            response_file=self.ISS, allow_assisted=True)

        self.assertTrue(with_wizard[-1].interactive)
        self.assertIn("/r", with_wizard[-1].args)
        self.assertEqual(sum(p.interactive for p in with_wizard), 1)
        self.assertTrue(with_wizard[-1].instructions)


class InstallShieldResponseFileTests(unittest.TestCase):
    """Файл ответов — единственный способ задать папку у InstallScript."""

    RESPONSE = (
        "[InstallShield Silent]\r\n"
        "Version=v6.00.000\r\n"
        "File=Response File\r\n"
        "[SdAskDestPath-0]\r\n"
        "szDir=C:\\Program Files\\EA GAMES\\Alice\r\n"
        "Result=1\r\n"
        "[SdSelectFolder-0]\r\n"
        "szFolder=EA GAMES\r\n"
    )

    def test_only_the_install_path_is_retargeted(self):
        patched, replaced = retarget_response_file(
            self.RESPONSE, r"E:\Portable\Alice_Portable\App")

        self.assertEqual(replaced, 1)
        self.assertIn(r"szDir=E:\Portable\Alice_Portable\App", patched)
        # Группа меню «Пуск» — не путь, её трогать нельзя.
        self.assertIn("szFolder=EA GAMES", patched)
        self.assertIn("Version=v6.00.000", patched)
        self.assertTrue(patched.endswith("\r\n"))

    def test_disc_copy_is_written_into_the_portable_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            media = Path(temp, "disc")
            media.mkdir()
            (media / "setup.iss").write_text(self.RESPONSE, encoding="cp1251")
            portable = Path(temp, "Alice_Portable")
            app = portable / "App"
            app.mkdir(parents=True)
            det = DetectionResult(
                InstallerType.INSTALLSHIELD, 0.9,
                installshield_generation=InstallShieldGeneration.INSTALLSCRIPT,
                response_files=[str(media / "setup.iss")],
                media_dir=str(media))

            engine = Portablizer(Logger())
            prepared = engine._prepare_response_file(
                det, str(portable), str(app),
                PortableOptions(installer_path=str(media / "Setup.exe"),
                                output_dir=temp))

            self.assertEqual(prepared, str(portable / "setup.iss"))
            text = (portable / "setup.iss").read_text(encoding="cp1251")
            self.assertIn(f"szDir={app}", text)
            # Оригинал на диске остаётся нетронутым.
            self.assertIn("szDir=C:\\Program Files", (media / "setup.iss")
                          .read_text(encoding="cp1251"))

    def test_recorded_answers_survive_a_rebuild(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Alice_Portable")
            app = portable / "App"
            app.mkdir(parents=True)
            (portable / "setup.iss").write_text(self.RESPONSE, encoding="cp1251")
            (portable / "Launch.bat").write_text("old", encoding="ascii")

            engine = Portablizer(Logger())
            engine._prepare_output(str(portable), str(app),
                                   str(portable / "PortableData"))

            self.assertTrue((portable / "setup.iss").is_file(),
                            "записанные ответы нельзя удалять между сборками")
            self.assertFalse((portable / "Launch.bat").exists())

    def test_setup_log_result_code_is_read_and_decoded(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp, "setup-installshield.log")
            log.write_text("[InstallShield Silent]\r\nVersion=v6.00.000\r\n"
                           "[ResponseResult]\r\nResultCode=-3\r\n",
                           encoding="cp1251")

            self.assertEqual(read_installshield_result(str(log)), -3)
            self.assertIsNone(read_installshield_result(
                str(Path(temp, "missing.log"))))

            engine = Portablizer(Logger())
            engine._report_installshield_log(
                SilentPlan(program="Setup.exe", result_log=str(log)))
            self.assertIn("ResultCode=-3", engine.log.text)
            self.assertIn("файле ответов", engine.log.text)


class InstallShieldRunTests(unittest.TestCase):
    """Сквозные сценарии старого InstallShield внутри run()."""

    def _disc(self, temp):
        media = Path(temp, "AliceCD")
        media.mkdir()
        _fake_pe(str(media / "Setup.exe"), [".text", ".rsrc"],
                 InstallShieldGenerationTests.LEGACY_STRINGS)
        for name in ("data1.hdr", "data1.cab", "setup.ins", "_setup.dll"):
            (media / name).write_bytes(b"payload" * 8)
        return str(media / "Setup.exe")

    def test_program_installed_into_the_default_folder_is_recovered(self):
        """InstallScript не принимает папку — файлы нужно забрать самим."""

        class FakeInstallScript(Portablizer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = []

            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                self.calls.append(plan)
                # Движок ставит игру в каталог по умолчанию, а не в App.
                default = Path(data_dir, "AppData", "Local", "Programs",
                               "Alice")
                default.mkdir(parents=True, exist_ok=True)
                (default / "Alice.exe").write_bytes(b"MZ game")
                (default / "data.dll").write_bytes(b"MZ data")
                return 0

        with tempfile.TemporaryDirectory() as temp:
            installer = self._disc(temp)
            output = Path(temp, "out")
            output.mkdir()
            engine = FakeInstallScript(Logger())
            result = engine.run(PortableOptions(
                installer_path=installer, output_dir=str(output),
                app_name="Alice", capture_registry=False, cleanup_host=False))

            self.assertTrue(result.success, "; ".join(result.messages))
            self.assertEqual(len(engine.calls), 1,
                             "после успеха лестница обязана остановиться")
            self.assertEqual(result.main_exe_rel, os.path.join("App", "Alice.exe"))
            self.assertTrue(Path(result.portable_dir, "App", "data.dll").is_file())
            self.assertTrue(Path(result.portable_dir, "Launch.bat").is_file())

    def test_failure_explains_the_response_file_instead_of_blaming_licenses(self):
        class AlwaysEmpty(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                # Ровно как в журнале пользователя: код 0, папка пуста,
                # а движок записал причину в свой setup.log.
                if plan.result_log:
                    Path(plan.result_log).write_text(
                        "[ResponseResult]\r\nResultCode=-3\r\n",
                        encoding="cp1251")
                return 0

        with tempfile.TemporaryDirectory() as temp:
            installer = self._disc(temp)
            output = Path(temp, "out")
            output.mkdir()
            result = AlwaysEmpty(Logger()).run(PortableOptions(
                installer_path=installer, output_dir=str(output),
                app_name="Alice", capture_registry=False, cleanup_host=False))

            self.assertFalse(result.success)
            message = "; ".join(result.messages)
            self.assertIn("ResultCode=-3", message)
            self.assertIn("setup.iss", message)
            self.assertIn("/r", message)
            self.assertIn("окно мастера", message)
            self.assertFalse(Path(result.portable_dir, "Launch.bat").exists())

    def test_wizard_attempt_runs_only_when_allowed(self):
        class Recorder(Portablizer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = []

            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                self.calls.append(plan)
                if plan.interactive:
                    Path(app_dir, "Alice.exe").write_bytes(b"MZ game")
                    Path(plan.response_file).write_text(
                        "[SdAskDestPath-0]\r\nszDir=X\r\n", encoding="cp1251")
                return 0

        with tempfile.TemporaryDirectory() as temp:
            installer = self._disc(temp)
            output = Path(temp, "out")
            output.mkdir()

            quiet = Recorder(Logger())
            quiet.run(PortableOptions(
                installer_path=installer, output_dir=str(output),
                app_name="Alice", capture_registry=False, cleanup_host=False))
            self.assertFalse(any(p.interactive for p in quiet.calls))

            assisted = Recorder(Logger())
            result = assisted.run(PortableOptions(
                installer_path=installer, output_dir=str(output),
                app_name="Alice", capture_registry=False, cleanup_host=False,
                allow_assisted_install=True))

            self.assertTrue(result.success, "; ".join(result.messages))
            self.assertTrue(assisted.calls[-1].interactive)
            self.assertIn("Ваши ответы сохранены", assisted.log.text)
            self.assertTrue(Path(result.portable_dir, "setup.iss").is_file())


class MultiExecutableDetectionTests(unittest.TestCase):
    """Тесты распознавания и классификации главного exe, лаунчера и конфигуратора."""

    def test_witcher_layout_classifies_main_launcher_config_and_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            app_dir = Path(temp, "App")
            bin_dir = app_dir / "bin"
            bin_dir.mkdir(parents=True)

            (bin_dir / "WITCHER2.EXE").write_bytes(b"MZ" + b"\x00" * 20000)
            (app_dir / "Launcher.exe").write_bytes(b"MZ" + b"\x00" * 5000)
            (bin_dir / "Configurator.exe").write_bytes(b"MZ" + b"\x00" * 3000)
            (bin_dir / "UserContentManager.exe").write_bytes(b"MZ" + b"\x00" * 2000)
            (app_dir / "unins000.exe").write_bytes(b"MZ" + b"\x00" * 1000)

            port = Portablizer(Logger())
            main_exe, targets = port._discover_app_executables(str(app_dir), "The Witcher 2")

            self.assertIsNotNone(main_exe)
            self.assertTrue(main_exe.lower().endswith("witcher2.exe"))

            roles = {t.name.lower(): t.role for t in targets}
            self.assertEqual(roles.get("witcher2"), "main")
            self.assertEqual(roles.get("launcher"), "launcher")
            self.assertEqual(roles.get("configurator"), "config")
            self.assertEqual(roles.get("usercontentmanager"), "tool")
            self.assertNotIn("unins000", roles)

    def test_classic_game_with_language_setup(self):
        with tempfile.TemporaryDirectory() as temp:
            app_dir = Path(temp, "App")
            app_dir.mkdir()
            (app_dir / "Game.exe").write_bytes(b"MZ" + b"\x00" * 15000)
            (app_dir / "Language_Setup.exe").write_bytes(b"MZ" + b"\x00" * 4000)
            (app_dir / "Graphic_Setup.exe").write_bytes(b"MZ" + b"\x00" * 4000)

            port = Portablizer(Logger())
            main_exe, targets = port._discover_app_executables(str(app_dir), "Game")

            self.assertIsNotNone(main_exe)
            self.assertTrue(main_exe.lower().endswith("game.exe"))

            roles = {t.name.lower(): t.role for t in targets}
            self.assertEqual(roles.get("game"), "main")
            self.assertEqual(roles.get("language_setup"), "config")
            self.assertEqual(roles.get("graphic_setup"), "config")

    def test_witcher1_djinni_editor_is_not_the_default_launch(self):
        """GOG Witcher EE: Launch.bat must be the game or launcher, not Djini.

        ``djinni.exe`` (sometimes shown as Djini) is the adventure/mod editor
        sitting next to ``witcher.exe`` in System\\ and is often *larger*,
        so a size-first heuristic used to make it the portable default.
        """
        with tempfile.TemporaryDirectory() as temp:
            app_dir = Path(temp, "App")
            system = app_dir / "System"
            system.mkdir(parents=True)
            (app_dir / "launcher.exe").write_bytes(b"MZ" + b"\x00" * 4000)
            (system / "witcher.exe").write_bytes(b"MZ" + b"\x00" * 8000)
            (system / "djinni.exe").write_bytes(b"MZ" + b"\x00" * 50000)
            (system / "djini.exe").write_bytes(b"MZ" + b"\x00" * 40000)
            (app_dir / "unins000.exe").write_bytes(b"MZ" + b"\x00" * 1000)

            port = Portablizer(Logger())
            main_exe, targets = port._discover_app_executables(
                str(app_dir),
                "The Witcher Enhanced Edition Directors Cut",
            )
            self.assertIsNotNone(main_exe)
            self.assertTrue(main_exe.lower().endswith("witcher.exe"), main_exe)
            roles = {t.name.lower(): t.role for t in targets}
            self.assertEqual(roles.get("witcher"), "main")
            self.assertEqual(roles.get("launcher"), "launcher")
            self.assertEqual(roles.get("djinni"), "tool")
            self.assertEqual(roles.get("djini"), "tool")
            self.assertNotIn("unins000", roles)


class CompanionLauncherGenerationTests(unittest.TestCase):
    """Тесты создания сопутствующих лончеров (Launch_Launcher.bat, Launch_Configurator.bat, Launch_Menu.bat)."""

    def test_companion_launchers_and_menu_are_generated(self):
        with tempfile.TemporaryDirectory() as temp:
            app_dir = Path(temp, "App")
            bin_dir = app_dir / "bin"
            bin_dir.mkdir(parents=True)

            (bin_dir / "WITCHER2.EXE").write_bytes(b"MZ" + b"\x00" * 20000)
            (app_dir / "Launcher.exe").write_bytes(b"MZ" + b"\x00" * 5000)
            (bin_dir / "Configurator.exe").write_bytes(b"MZ" + b"\x00" * 3000)
            (bin_dir / "PerformanceTester.exe").write_bytes(
                b"MZ" + b"\x00" * 2000)
            (bin_dir / "userContentManager.exe").write_bytes(
                b"MZ" + b"\x00" * 2000)

            port = Portablizer(Logger())
            main_exe, targets = port._discover_app_executables(str(app_dir), "The Witcher 2")

            opts = PortableOptions(
                installer_path="fake.exe",
                output_dir=temp,
                app_name="The Witcher 2",
            )
            companion_files = port._write_launcher(
                temp, "The Witcher 2", os.path.relpath(main_exe, temp),
                opts, ["App/bin"], capture=None, targets=targets
            )

            self.assertIn("Launch.bat", companion_files)
            self.assertIn("Launch_Launcher.bat", companion_files)
            self.assertIn("Launch_Configurator.bat", companion_files)
            self.assertIn("Launch_Launcher.exe", companion_files)
            self.assertIn("Launch_Configurator.exe", companion_files)
            self.assertIn("Launch_Menu.bat", companion_files)
            # Для редких tools больше не создаётся по паре однотипных файлов:
            # они доступны из общего меню.
            self.assertNotIn("Launch_PerformanceTester.bat", companion_files)
            self.assertNotIn("Launch_userContentManager.bat", companion_files)
            self.assertFalse(Path(temp, "Launch_PerformanceTester.bat").exists())
            self.assertFalse(Path(temp, "Launch_userContentManager.vbs").exists())

            # Текстовые лончеры остаются чистым ASCII, а отдельные EXE являются
            # готовыми MZ-копиями универсального портативного лончера.
            for fname in companion_files:
                fpath = Path(temp, fname)
                self.assertTrue(fpath.is_file(), f"{fname} is missing")
                if fname.lower().endswith(".exe"):
                    self.assertEqual(fpath.read_bytes()[:2], b"MZ")
                else:
                    text = fpath.read_text(encoding="ascii")
                    self.assertTrue(text.isascii())

            # Проверяем launcher_config.json
            cfg_path = Path(temp, "launcher_config.json")
            self.assertTrue(cfg_path.is_file())
            import json
            with open(cfg_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(len(data["targets"]), 5)
            self.assertTrue(data["redirect_known_folders"])
            self.assertTrue(any(t["role"] == "launcher" for t in data["targets"]))
            self.assertTrue(any(t["role"] == "config" for t in data["targets"]))
            self.assertEqual(
                data["launcher_aliases"]["Launch_Launcher.exe"],
                "App/Launcher.exe",
            )
            self.assertEqual(
                data["launcher_aliases"]["Launch_Configurator.exe"],
                "App/bin/Configurator.exe",
            )


class CompanionLauncherExecutionTests(unittest.TestCase):
    """Тесты исполнения Launch.bat с флагами --target, --launcher, --config, --menu в симуляторе."""

    def test_launch_with_target_switch(self):
        targets = [
            launcher_mod.TargetInfo(name="WITCHER2", rel_path="App/bin/WITCHER2.EXE", role="main"),
            launcher_mod.TargetInfo(name="Configurator", rel_path="App/bin/Configurator.exe", role="config"),
        ]
        cfg = launcher_mod.LauncherConfig(
            app_name="The Witcher 2",
            target_exe_rel="App/bin/WITCHER2.EXE",
            targets=targets,
            config_target_rel="App/bin/Configurator.exe",
        )
        bat = launcher_mod.render_bat(cfg)

        fs = batsim.FakeFS()
        fs.add_file(r"E:\Portable\App\bin\WITCHER2.EXE")
        fs.add_file(r"E:\Portable\App\bin\Configurator.exe")

        res = batsim.run_batch(bat, r"E:\Portable\Launch.bat", fs,
                               argv=["--nopause", "--target", r"App\bin\Configurator.exe"])
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(len(res.launches), 1)
        self.assertTrue(res.launches[0].command.lower().endswith("configurator.exe"))
        self.assertTrue(res.launches[0].cwd.rstrip("\\").lower().endswith(r"app\bin"))

    def test_launch_with_config_switch(self):
        targets = [
            launcher_mod.TargetInfo(name="WITCHER2", rel_path="App/bin/WITCHER2.EXE", role="main"),
            launcher_mod.TargetInfo(name="Configurator", rel_path="App/bin/Configurator.exe", role="config"),
        ]
        cfg = launcher_mod.LauncherConfig(
            app_name="The Witcher 2",
            target_exe_rel="App/bin/WITCHER2.EXE",
            targets=targets,
            config_target_rel="App/bin/Configurator.exe",
        )
        bat = launcher_mod.render_bat(cfg)

        fs = batsim.FakeFS()
        fs.add_file(r"E:\Portable\App\bin\WITCHER2.EXE")
        fs.add_file(r"E:\Portable\App\bin\Configurator.exe")

        res = batsim.run_batch(bat, r"E:\Portable\Launch.bat", fs,
                               argv=["--nopause", "--config"])
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(len(res.launches), 1)
        self.assertTrue(res.launches[0].command.lower().endswith("configurator.exe"))

    def test_companion_bat_delegates_to_launch_bat(self):
        targets = [
            launcher_mod.TargetInfo(name="WITCHER2", rel_path="App/bin/WITCHER2.EXE", role="main", bat_name="Launch.bat"),
            launcher_mod.TargetInfo(name="Launcher", rel_path="App/Launcher.exe", role="launcher", bat_name="Launch_Launcher.bat"),
        ]
        cfg = launcher_mod.LauncherConfig(
            app_name="The Witcher 2",
            target_exe_rel="App/bin/WITCHER2.EXE",
            targets=targets,
            launcher_target_rel="App/Launcher.exe",
        )
        main_bat = launcher_mod.render_bat(cfg)
        comp_bat = launcher_mod.render_companion_bat(cfg, targets[1])

        fs = batsim.FakeFS()
        fs.add_file(r"E:\Portable\App\bin\WITCHER2.EXE")
        fs.add_file(r"E:\Portable\App\Launcher.exe")
        fs.add_file(r"E:\Portable\Launch.bat", main_bat)

        res = batsim.run_batch(comp_bat, r"E:\Portable\Launch_Launcher.bat", fs,
                               argv=["--nopause"])
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(len(res.launches), 1)
        self.assertTrue(res.launches[0].command.lower().endswith("launcher.exe"))
        self.assertTrue(res.launches[0].cwd.rstrip("\\").lower().endswith("app"))


class GameLauncherHandoffTests(unittest.TestCase):
    """Игра, запущенная официальным лаунчером, и её ключи HKLM.

    The Witcher (GOG) читает путь установки из HKLM и молча выходит с кодом 1,
    если ключа нет, а его Launcher.exe стартует игру и сразу завершается.
    """

    #: Пути-образцы: игра с окном и безоконный фоновый помощник.
    GAME_IMAGE = r"C:\Games\Portable\App\game.exe"
    HELPER_IMAGE = r"C:\Games\Portable\App\helper.exe"

    def _witcher_cfg(self):
        return launcher_mod.LauncherConfig(
            app_name="The Witcher",
            target_exe_rel="App/System/witcher.exe",
            launcher_target_rel="App/Launcher.exe",
            registry_keys=[
                r"HKLM\Software\Wow6432Node\CD Projekt Red\The Witcher",
                r"HKCU\Software\CD Projekt Red\The Witcher",
            ],
        )

    def test_bat_waits_for_programs_started_by_the_official_launcher(self):
        bat = launcher_mod.render_bat(self._witcher_cfg())
        self.assertIn("call :portable_wait_children", bat)
        # Ожидание обязано стоять до восстановления реестра, иначе игра
        # теряет ключи установки сразу после выхода лаунчера.
        self.assertLess(bat.index("call :portable_wait_children"),
                        bat.index("call :portable_registry_save"))
        self.assertTrue(bat.isascii())

    def test_missing_hklm_key_triggers_elevation_for_the_game_itself(self):
        bat = launcher_mod.render_bat(self._witcher_cfg())
        self.assertIn(
            'reg query "HKLM\\Software\\Wow6432Node\\CD Projekt Red\\The Witcher"',
            bat,
        )
        self.assertIn('set "PORTABLE_MACHINE_REGISTRY=1"', bat)

    def test_no_hklm_keys_means_no_extra_uac_probe(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Alice", target_exe_rel="App/alice.exe",
            registry_keys=[r"HKCU\Software\Alice"],
        )
        self.assertNotIn("reg query", launcher_mod.render_bat(cfg))

    def test_machine_file_without_hklm_section_needs_no_admin(self):
        with tempfile.TemporaryDirectory() as temp:
            user_only = Path(temp, "user.reg")
            user_only.write_text(
                "Windows Registry Editor Version 5.00\n\n"
                "[HKEY_CURRENT_USER\\Software\\Alice]\n", encoding="utf-8")
            machine = Path(temp, "portable_machine.reg")
            machine.write_text(
                "Windows Registry Editor Version 5.00\n\n"
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\CD Projekt Red]\n",
                encoding="utf-8")

            self.assertFalse(exe_launcher._machine_file_needs_admin(user_only))
            self.assertTrue(exe_launcher._machine_file_needs_admin(machine))

    def test_launcher_does_not_wait_for_its_own_bootloader(self):
        """Ожидание не должно ловить сам LaunchPortable.exe.

        Однофайловый EXE всегда живёт двумя процессами: загрузчик
        PyInstaller и порождённый им Python. Загрузчик лежит в той же папке
        App, поэтому наивный подсчёт «процессов из портатива» находит самого
        себя и ждёт вечно: реестр не восстанавливается, окно не закрывается,
        а сборочный прогон CI висит часами.
        """
        prefix = (r"c:\games\portable" + "\\").casefold()
        own = r"c:\games\portable\app\launchportable.exe"

        self.assertFalse(exe_launcher._counts_as_portable_process(
            r"C:\Games\Portable\App\LaunchPortable.exe", prefix, own))
        # Настоящая игра, запущенная официальным лаунчером, — ждём её.
        self.assertTrue(exe_launcher._counts_as_portable_process(
            r"C:\Games\Portable\App\System\witcher.exe", prefix, own))
        # Посторонние программы компьютера нас не касаются.
        self.assertFalse(exe_launcher._counts_as_portable_process(
            r"C:\Windows\System32\notepad.exe", prefix, own))
        # Тот же EXE может быть виден и по подставленному диску.
        both = (own, r"x:\portable\app\launchportable.exe")
        self.assertFalse(exe_launcher._counts_as_portable_process(
            r"C:\Games\Portable\App\LaunchPortable.exe", prefix, both))
        self.assertTrue(exe_launcher._counts_as_portable_process(
            r"C:\Games\Portable\App\game.exe", prefix, both))
        # Запуск из исходников: своего EXE нет, ждём всё, что нашли.
        self.assertTrue(exe_launcher._counts_as_portable_process(
            r"C:\Games\Portable\App\game.exe", prefix, ()))

    def test_waiting_stops_as_soon_as_the_program_is_gone(self):
        # (pid, image) списками: первый вызов отвечает на «уже запустилось?»,
        # дальше идёт сам цикл ожидания.
        snapshots = [[(10, self.GAME_IMAGE)], [(10, self.GAME_IMAGE)], []]

        def fake_list(_root):
            return snapshots.pop(0) if snapshots else []

        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  side_effect=fake_list), \
                mock.patch.object(exe_launcher, "_visible_window_pids",
                                  return_value={10}), \
                mock.patch("time.sleep"):
            waited = exe_launcher._wait_for_portable_processes(
                Path(r"C:\Games\Portable"))
        self.assertEqual(waited, 1)
        self.assertEqual(snapshots, [])

    def test_visible_program_is_never_treated_as_a_leftover(self):
        """Окно на экране — пользователь работает: ждём сколько угодно."""
        calls = {"n": 0}

        def fake_list(_root):
            calls["n"] += 1
            # Игра идёт 100 циклов подряд, потом пользователь её закрывает.
            return [(10, self.GAME_IMAGE)] if calls["n"] < 100 else []

        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  side_effect=fake_list), \
                mock.patch.object(exe_launcher, "_visible_window_pids",
                                  return_value={10}), \
                mock.patch("time.sleep"):
            waited = exe_launcher._wait_for_portable_processes(
                Path(r"C:\Games\Portable"),
                settings={"spawn_grace": 0.0, "idle_grace": 3.0,
                          "max_wait": 86400.0})

        # Ни одного досрочного выхода: полоса ожидания честно дошла до конца.
        self.assertGreaterEqual(waited, 90)

    def test_hidden_tray_window_is_not_a_leftover(self):
        """Ollama-style tray icon: no visible main window, but a hidden HWND.

        The user is still using the app (Open Ollama, quit, …).  Killing it
        after idle_grace froze the tray and made the menu do nothing.
        """
        calls = {"n": 0}

        def fake_list(_root):
            calls["n"] += 1
            return [(10, self.GAME_IMAGE)] if calls["n"] < 40 else []

        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  side_effect=fake_list), \
                mock.patch.object(exe_launcher, "_visible_window_pids",
                                  return_value={10}), \
                mock.patch("time.sleep"):
            waited = exe_launcher._wait_for_portable_processes(
                Path(r"C:\Games\Portable"),
                settings={"spawn_grace": 0.0, "idle_grace": 3.0,
                          "max_wait": 86400.0})
        self.assertGreaterEqual(waited, 30)

    def test_job_object_allows_electron_to_break_away(self):
        source = Path(exe_launcher.__file__).read_text(encoding="utf-8")
        self.assertIn("JOB_OBJECT_LIMIT_BREAKAWAY_OK", source)
        self.assertIn("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", source)

    def test_electron_host_gets_sandbox_off_flags(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "chrome_elf.dll").write_bytes(b"MZ")
            (app / "resources").mkdir()
            (app / "resources" / "app.asar").write_bytes(b"")
            gui = app / "ollama app.exe"
            gui.write_bytes(b"MZ" + b"\x00" * (9 * 1024 * 1024))
            cli = app / "ollama.exe"
            cli.write_bytes(b"MZ" + b"\x00" * 4096)
            self.assertTrue(exe_launcher.needs_electron_sandbox_off(gui))
            self.assertFalse(exe_launcher.needs_electron_sandbox_off(cli))
            command = exe_launcher.with_electron_flags([str(gui)], gui)
            self.assertEqual(command[0], str(gui))
            self.assertIn("--no-sandbox", command)
            self.assertIn("--disable-gpu-sandbox", command)
            skipped = exe_launcher.with_electron_flags([str(cli)], cli)
            self.assertEqual(skipped, [str(cli)])

    def test_real_ollama_gui_is_webview2_not_electron(self):
        """OllamaSetup.exe ships a Go+WebView2 tray, not chrome_elf.

        Passing --no-sandbox to ollama app.exe is what left the tray icon
        alive while Open / Logs / Settings / Quit did nothing.
        """
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            gui = app / "ollama app.exe"
            gui.write_bytes(b"MZ" + b"\x00" * (9 * 1024 * 1024))
            (app / "ollama.exe").write_bytes(b"MZ")
            self.assertFalse(exe_launcher.is_electron_tree(app))
            self.assertFalse(exe_launcher.needs_electron_sandbox_off(gui))
            self.assertEqual(
                exe_launcher.with_electron_flags([str(gui)], gui), [str(gui)])
            self.assertTrue(exe_launcher.needs_webview2_bridge(gui))
            self.assertFalse(exe_launcher.should_use_job(gui))

    def test_webview2_bridge_points_at_host_edge_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            host = Path(temp, "HostLocal")
            runtime = host / "Microsoft" / "EdgeWebView" / "Application" / "9.9.9"
            runtime.mkdir(parents=True)
            (runtime / "msedgewebview2.exe").write_bytes(b"MZ")
            portable = Path(temp, "Ollama_Portable")
            local = portable / "PortableData" / "AppData" / "Local"
            local.mkdir(parents=True)
            gui = Path(temp, "App", "ollama app.exe")
            gui.parent.mkdir(parents=True, exist_ok=True)
            gui.write_bytes(b"MZ")
            env = {
                "PORTABLE_ROOT": str(portable),
                "LOCALAPPDATA": str(local),
            }
            with mock.patch.object(exe_launcher, "_junction_directory",
                                   return_value=True) as junction, \
                    mock.patch.dict(os.environ, {
                        "ProgramFiles": str(Path(temp, "no-pf")),
                        "ProgramFiles(x86)": str(Path(temp, "no-pf86")),
                        "ProgramW6432": str(Path(temp, "no-pf64")),
                    }, clear=False):
                patched = exe_launcher.apply_webview2_bridge(
                    env, gui, host_localappdata=host)
            self.assertEqual(
                patched["WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"], str(runtime))
            self.assertTrue(
                patched["WEBVIEW2_USER_DATA_FOLDER"].endswith("WebView2"))
            self.assertTrue(junction.called)

    def test_launch_bat_bridges_host_webview2(self):
        bat = render_bat(LauncherConfig(
            app_name="Ollama", target_exe_rel="App/ollama app.exe"))
        self.assertIn("PORTABLE_HOST_LOCALAPPDATA", bat)
        self.assertIn("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", bat)
        self.assertIn("mklink /J", bat)

    def test_electron_and_ollama_do_not_join_the_kill_job(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "chrome_elf.dll").write_bytes(b"MZ")
            (app / "resources").mkdir()
            (app / "resources" / "app.asar").write_bytes(b"")
            (app / "ollama app.exe").write_bytes(b"MZ")
            self.assertTrue(exe_launcher.is_electron_tree(app))
            self.assertFalse(exe_launcher.should_use_job(app / "ollama app.exe"))
            self.assertFalse(exe_launcher.should_use_job(app / "ollama.exe"))
            plain = Path(temp, "Game")
            plain.mkdir()
            (plain / "game.exe").write_bytes(b"MZ")
            self.assertTrue(exe_launcher.should_use_job(plain / "game.exe"))

    def test_ollama_without_a_window_is_still_interactive(self):
        """Quit-from-tray must be the user's choice, not idle_grace."""
        image = r"C:\Games\Ollama_Portable\App\ollama app.exe"
        self.assertTrue(exe_launcher._is_interactive_image(image))
        self.assertFalse(exe_launcher._is_interactive_image(
            r"C:\Games\Ollama_Portable\App\crashpad_handler.exe"))
        clock = iter(float(n) for n in range(0, 100000))
        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  return_value=[(10, image)]), \
                mock.patch.object(exe_launcher, "_visible_window_pids",
                                  return_value=set()), \
                mock.patch("time.monotonic", side_effect=lambda: next(clock)), \
                mock.patch("time.sleep"):
            waited = exe_launcher._wait_for_portable_processes(
                Path(r"C:\Games\Ollama_Portable"),
                settings={"spawn_grace": 0.0, "idle_grace": 3.0,
                          "max_wait": 40.0})
        self.assertGreaterEqual(waited, 20)

    def test_windowless_leftover_only_gets_the_idle_grace(self):
        """Фоновый процесс без окна не должен держать папку сутками.

        Это ровно тот баг, из-за которого папку портатива нельзя было
        удалить: программа закрыта, а её апдейтер/крэш-хендлер продолжал
        жить, и лончер (лежащий внутри App) ждал его до 24 часов.
        """
        clock = iter(float(n) for n in range(0, 100000))
        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  return_value=[(11, self.HELPER_IMAGE)]), \
                mock.patch.object(exe_launcher, "_visible_window_pids",
                                  return_value=set()), \
                mock.patch("time.monotonic", side_effect=lambda: next(clock)), \
                mock.patch("time.sleep"):
            waited = exe_launcher._wait_for_portable_processes(
                Path(r"C:\Games\Portable"),
                settings={"spawn_grace": 0.0, "idle_grace": 5.0,
                          "max_wait": 86400.0})

        # Досрочный выход по idle_grace, а не «ждём вечно».
        self.assertLess(waited, 20)

    def test_release_closes_politely_and_then_terminates(self):
        calls = {"posted": [], "killed": []}
        # Процесс игнорирует WM_CLOSE и остаётся висеть.
        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  return_value=[(11, self.HELPER_IMAGE)]), \
                mock.patch.object(
                    exe_launcher, "_post_close_to_windows",
                    side_effect=lambda pids: calls["posted"].extend(pids)), \
                mock.patch.object(
                    exe_launcher, "_terminate_pids",
                    side_effect=lambda pids: calls["killed"].extend(pids)), \
                mock.patch("time.sleep"):
            stopped = exe_launcher.release_portable_folder(
                Path(r"C:\Games\Portable"),
                {"close_grace": 1.0, "kill_leftovers": 1.0})

        self.assertEqual(stopped, ["helper.exe"])
        self.assertEqual(calls["posted"], [11])
        self.assertEqual(calls["killed"], [11])

    def test_release_does_not_kill_when_the_process_obeys_wm_close(self):
        states = [[(11, self.HELPER_IMAGE)], []]

        def fake_list(_root):
            return states.pop(0) if states else []

        killed = []
        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  side_effect=fake_list), \
                mock.patch.object(exe_launcher, "_post_close_to_windows",
                                  return_value=1), \
                mock.patch.object(exe_launcher, "_terminate_pids",
                                  side_effect=killed.append), \
                mock.patch("time.sleep"):
            stopped = exe_launcher.release_portable_folder(
                Path(r"C:\Games\Portable"), {"close_grace": 5.0})

        self.assertEqual(stopped, ["helper.exe"])
        self.assertEqual(killed, [], "процесс закрылся сам — убивать нечего")

    def test_shutdown_settings_are_clamped_and_defaulted(self):
        default = exe_launcher.shutdown_settings({})
        # 5 секунд, а не 20: жалоба «LaunchPortable.exe висит в Диспетчере
        # задач после закрытия программы». Программа с окном под таймер не
        # попадает (это проверяется отдельно), а безымянные фоновые помощники
        # получают короткую паузу и затем закрываются.
        self.assertEqual(default["idle_grace"], 5.0)
        self.assertEqual(default["kill_leftovers"], 1.0)

        custom = exe_launcher.shutdown_settings(
            {"shutdown": {"idle_grace": 45, "kill_leftovers": False,
                          "max_wait": "nonsense", "close_grace": -7}})
        self.assertEqual(custom["idle_grace"], 45.0)
        self.assertEqual(custom["kill_leftovers"], 0.0)
        self.assertEqual(custom["max_wait"], 86400.0)
        self.assertEqual(custom["close_grace"], 0.0)

    def test_stop_switch_releases_the_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "App_Portable")
            (root / "App").mkdir(parents=True)
            (root / "launcher_config.json").write_text(
                json.dumps({"shutdown": {"idle_grace": 9}}), encoding="utf-8")
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "release_portable_folder",
                                      return_value=["helper.exe"]) as release, \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[]):
                rc = exe_launcher.stop(root)

            self.assertEqual(rc, 0)
            self.assertEqual(release.call_args.args[1]["idle_grace"], 9.0)
            log = (root / "PortableData" / "launcher-run.log").read_text(
                encoding="utf-8")
            self.assertIn("helper.exe", log)

    def test_stop_reports_processes_it_could_not_release(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "App_Portable")
            (root / "App").mkdir(parents=True)
            shown = []
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "release_portable_folder",
                                      return_value=["admin.exe"]), \
                    mock.patch.object(exe_launcher, "_show_warning",
                                      side_effect=shown.append), \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[(12, r"C:\\Games\\Portable\\App\\admin.exe")]):
                rc = exe_launcher.stop(root)

            self.assertEqual(rc, 1)
            self.assertIn("admin.exe", shown[0])


class RegistryVirtualizationTests(unittest.TestCase):
    """Тесты UAC-виртуализации и слияния machine-настроек в HKCU."""

    def test_virtualize_machine_snapshot_creates_virtualstore_and_hkcu(self):
        snapshot = {
            r"HKLM\Software\CD Projekt RED\The Witcher 2": {
                "InstallDirectory": (1, r"'E:\Portable\App'"),
                "Language": (1, "'RU'"),
                "Speech": (1, "'RU'"),
            }
        }
        machine_keys = [r"HKLM\Software\CD Projekt RED\The Witcher 2"]

        v_snap, v_keys = registry.virtualize_machine_snapshot(snapshot, machine_keys)

        vs_key = r"HKCU\Software\Classes\VirtualStore\MACHINE\SOFTWARE\CD Projekt RED\The Witcher 2"
        hkcu_key = r"HKCU\Software\CD Projekt RED\The Witcher 2"

        self.assertIn(vs_key, v_snap)
        self.assertIn(hkcu_key, v_snap)
        self.assertEqual(v_snap[vs_key]["Language"], (1, "'RU'"))
        self.assertEqual(v_snap[hkcu_key]["InstallDirectory"], (1, r"'E:\Portable\App'"))

    def test_consolidate_root_keys(self):
        keys = [
            r"HKCU\Software\CD Projekt RED\The Witcher 2",
            r"HKCU\Software\CD Projekt RED\The Witcher 2\Audio",
            r"HKCU\Software\CD Projekt RED\The Witcher 2\Video",
            r"HKCU\Software\Classes\VirtualStore\MACHINE\SOFTWARE\CD Projekt RED\The Witcher 2",
            r"HKCU\Software\Classes\VirtualStore\MACHINE\SOFTWARE\CD Projekt RED\The Witcher 2\DLC",
        ]
        roots = launcher_mod.consolidate_root_keys(keys)
        self.assertEqual(len(roots), 2)
        self.assertIn(r"HKCU\Software\CD Projekt RED\The Witcher 2", roots)
        self.assertIn(r"HKCU\Software\Classes\VirtualStore\MACHINE\SOFTWARE\CD Projekt RED\The Witcher 2", roots)


class CallWithTimeoutTests(unittest.TestCase):
    """Один больной вызов WinAPI не должен морозить сборку навсегда.

    Регрессия: после падения установщика Hatred (0xC000041D) сборка
    зависала на произвольном проценте без единой новой строки в журнале.
    Причина — в ``procutil``: «бюджет времени» на обход таблицы дескрипторов
    и на проверку занятых файлов проверялся только МЕЖДУ вызовами
    ``DuplicateHandle``/``GetFinalPathNameByHandleW``/``CreateFileW``, а не
    внутри них. Единственный дескриптор, завязший на зависшем антивирусном
    фильтре или недоступной сетевой папке, останавливал весь обход
    навсегда — ни один внешний таймаут это не замечал.
    """

    def test_returns_promptly_when_the_call_never_finishes(self):
        released = threading.Event()

        def never_returns():
            released.wait()  # как будто завис в DuplicateHandle/GetFileType
            return "too-late"

        started = time.monotonic()
        result = procutil._call_with_timeout(never_returns, timeout=0.2,
                                             default="timed-out")
        elapsed = time.monotonic() - started
        self.assertEqual(result, "timed-out")
        self.assertLess(elapsed, 1.0)
        released.set()  # не оставляем поток висеть дольше необходимого

    def test_returns_the_real_result_when_the_call_is_fast(self):
        self.assertEqual(
            procutil._call_with_timeout(lambda: "ok", timeout=1.0,
                                        default="fallback"),
            "ok")

    def test_swallows_exceptions_from_the_wrapped_call(self):
        def boom():
            raise RuntimeError("дескриптор уже закрыт")

        self.assertEqual(
            procutil._call_with_timeout(boom, timeout=1.0, default="safe"),
            "safe")


class FolderReleaseTests(unittest.TestCase):
    """Готовая папка портатива обязана удаляться сразу после закрытия."""

    ROOT = r"C:\Games\Type_Portable"

    def test_is_inside_does_not_confuse_sibling_folders(self):
        self.assertTrue(procutil.is_inside(
            r"C:\Games\Type_Portable\App\game.exe", self.ROOT))
        # Соседняя папка с похожим именем — чужая, её процессы не трогаем.
        self.assertFalse(procutil.is_inside(
            r"C:\Games\Type_Portable2\App\game.exe", self.ROOT))
        self.assertFalse(procutil.is_inside(
            r"C:\Windows\System32\notepad.exe", self.ROOT))
        self.assertFalse(procutil.is_inside("", self.ROOT))

    def test_processes_in_filters_the_system_snapshot(self):
        snapshot = [
            (1, r"C:\Windows\explorer.exe"),
            (2, r"C:\Games\Type_Portable\App\updater.exe"),
            (3, r"C:\Games\Type_Portable\App\bin\game.exe"),
        ]
        found = procutil.processes_in(self.ROOT, snapshot)
        self.assertEqual([pid for pid, _ in found], [2, 3])

    def test_release_folder_closes_then_kills(self):
        posted, killed = [], []
        with mock.patch.object(procutil, "IS_WINDOWS", True), \
                mock.patch.object(
                    procutil, "processes_in",
                    return_value=[(2, r"C:\Games\Type_Portable\App\up.exe")]), \
                mock.patch.object(procutil, "_post_close",
                                  side_effect=lambda pids: posted.extend(pids)), \
                mock.patch.object(procutil, "_terminate",
                                  side_effect=lambda pids: killed.extend(pids)), \
                mock.patch("time.sleep"):
            stopped = procutil.release_folder(self.ROOT, close_grace=1.0,
                                              kill_grace=1.0)

        self.assertEqual(stopped, ["up.exe"])
        self.assertEqual(posted, [2])
        self.assertEqual(killed, [2])

    def test_release_folder_is_a_no_op_outside_windows(self):
        with mock.patch.object(procutil, "IS_WINDOWS", False):
            self.assertEqual(procutil.release_folder(self.ROOT), [])

    def test_config_carries_the_shutdown_policy(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Type", target_exe_rel="App/Type.exe")
        data = json.loads(launcher_mod.render_config_json(cfg))["shutdown"]
        self.assertEqual(data["idle_grace"], 20.0)
        self.assertTrue(data["kill_leftovers"])
        # Ровно эти значения читает готовый EXE-лончер.
        settings = exe_launcher.shutdown_settings(
            json.loads(launcher_mod.render_config_json(cfg)))
        self.assertEqual(settings["idle_grace"], 20.0)

    def test_bat_wait_routine_has_a_bounded_idle_grace(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Type", target_exe_rel="App/Type.exe",
            shutdown_idle_grace=30.0)
        bat = launcher_mod.render_bat(cfg)
        self.assertIn('set "PORTABLE_IDLE_GRACE=30"', bat)
        # Фоновые остатки закрываются, а не переживают лончер.
        self.assertIn("CloseMainWindow", bat)
        self.assertIn("$p.Kill()", bat)
        self.assertIn("PortableWins", bat)
        self.assertIn("HasUi", bat)
        self.assertIn("FindWindowEx", bat)
        self.assertIn("ollama", bat)
        self.assertNotIn("USERNAME=Portable", bat)

    def test_stop_script_is_ascii_and_prefers_the_exe_launcher(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Тип (кириллица)", target_exe_rel="App/Type.exe")
        script = launcher_mod.render_stop_cmd(cfg)
        self.assertTrue(script.isascii())
        self.assertIn("LaunchPortable.exe\" --stop", script)
        self.assertIn("CloseMainWindow", script)
        self.assertIn("$p.Kill()", script)

    def test_launcher_writes_the_stop_script_next_to_launch_bat(self):
        engine = Portablizer(Logger())
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            (portable / "App").mkdir(parents=True)
            created = engine._write_launcher(
                str(portable), "Type", "App\\Type.exe",
                PortableOptions(installer_path="setup.exe", output_dir=temp,
                                build_exe_launcher=False),
                [], None, [], None)

            stop = portable / launcher_mod.STOP_SCRIPT_NAME
            self.assertTrue(stop.is_file())
            self.assertIn(launcher_mod.STOP_SCRIPT_NAME, created)
            readme = (portable / "README_PORTABLE.txt").read_text(
                encoding="utf-8-sig")
            self.assertIn(launcher_mod.STOP_SCRIPT_NAME, readme)


class FolderLockDiagnosticsTests(unittest.TestCase):
    """Кто ещё может держать папку: чужая DLL, служба, открытый файл."""

    ROOT = r"C:\Games\Type_Portable"

    def test_module_holder_is_found_when_no_process_lives_in_the_folder(self):
        """Программа закрыта, а её DLL подгрузил проводник — папка занята.

        Сравнение путей процессов такой случай не ловит: из папки не
        запущено ничего, но файл внутри открыт.
        """
        snapshot = [
            (11, r"C:\Windows\explorer.exe"),
            (12, r"C:\Windows\notepad.exe"),
        ]
        modules = {
            11: [r"C:\Windows\explorer.exe",
                 r"C:\Games\Type_Portable\App\shellext.dll"],
            12: [r"C:\Windows\notepad.exe"],
        }
        with mock.patch.object(procutil, "modules_of",
                               side_effect=lambda pid: modules[pid]):
            found = procutil.holders(self.ROOT, snapshot)

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].kind, "module")
        self.assertEqual(found[0].name, "explorer.exe")
        self.assertEqual(procutil.image_name(found[0].detail), "shellext.dll")
        # Проводник трогать нельзя — только назвать.
        self.assertTrue(found[0].protected)

    def test_process_from_the_folder_is_reported_without_a_module_scan(self):
        snapshot = [(13, r"C:\Games\Type_Portable\App\game.exe")]
        with mock.patch.object(procutil, "modules_of",
                               side_effect=AssertionError("не нужен")):
            found = procutil.holders(self.ROOT, snapshot, deep=False)
        self.assertEqual([h.kind for h in found], ["exe"])
        self.assertFalse(found[0].protected)

    def test_folder_is_free_probe_renames_and_restores(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            (portable / "App").mkdir(parents=True)
            (portable / "App" / "game.exe").write_bytes(b"MZ")

            self.assertTrue(procutil.folder_is_free(str(portable)))
            # Папка обязана остаться на месте и в целости.
            self.assertTrue((portable / "App" / "game.exe").is_file())
            self.assertEqual(
                [p.name for p in Path(temp).iterdir()], ["Type_Portable"])

    def test_folder_is_not_free_when_windows_refuses_to_rename(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            portable.mkdir()
            with mock.patch("os.rename",
                            side_effect=OSError(32, "used by another process")):
                self.assertFalse(procutil.folder_is_free(str(portable)))
            self.assertTrue(portable.is_dir())

    def test_service_image_path_understands_every_spelling(self):
        cases = {
            r'"C:\P\App\guard.exe" -service': r"C:\P\App\guard.exe",
            r"C:\P\App\guard.exe -k netsvcs": r"C:\P\App\guard.exe",
            r"\??\C:\P\App\driver.sys": r"C:\P\App\driver.sys",
            r"\SystemRoot\System32\drivers\http.sys": "",
        }
        for raw, expected in cases.items():
            self.assertEqual(procutil.service_image_path(raw), expected, raw)

    def test_release_folder_leaves_registered_services_untouched(self):
        """A path match alone is not permission to stop or delete a service."""
        with mock.patch.object(procutil, "IS_WINDOWS", True), \
                mock.patch.object(procutil, "services_in",
                                  return_value=["GameGuard"]), \
                mock.patch.object(procutil, "stop_service",
                                  side_effect=AssertionError("must not stop")) as stop, \
                mock.patch.object(procutil, "processes_in",
                                  side_effect=AssertionError("must not kill")):
            stopped = procutil.release_folder(self.ROOT)

        self.assertEqual(stopped, [])
        stop.assert_not_called()


class BuildFolderVerdictTests(unittest.TestCase):
    """Сборка обязана доказать, что папку можно удалить."""

    def setUp(self):
        self.engine = Portablizer(Logger())

    def _result(self):
        return PortableResult(success=True)

    def test_free_folder_is_reported_as_such(self):
        result = self._result()
        with mock.patch("portablizer.core.portablizer.IS_WINDOWS", True), \
                mock.patch.object(procutil, "folder_is_free",
                                  return_value=True):
            free = self.engine._verify_folder_is_free(r"C:\P", result)

        self.assertTrue(free)
        self.assertIn("можно удалить", self.engine.log.text)

    def test_locked_folder_names_the_culprit(self):
        result = self._result()
        holders = [procutil.Holder(11, r"C:\Windows\explorer.exe", "module",
                                   r"C:\P\App\shellext.dll")]
        with mock.patch("portablizer.core.portablizer.IS_WINDOWS", True), \
                mock.patch.object(procutil, "folder_is_free",
                                  return_value=False), \
                mock.patch.object(procutil, "holders", return_value=holders):
            free = self.engine._verify_folder_is_free(r"C:\P", result)

        self.assertFalse(free)
        self.assertFalse(result.folder_is_free is False and not
                         result.folder_holders)
        self.assertIn("explorer.exe", " ".join(result.folder_holders))
        self.assertIn("shellext.dll", " ".join(result.folder_holders))
        # Системный процесс — подсказываем закрыть окна, а не убивать его.
        self.assertIn("окно проводника", self.engine.log.text)

    def test_registered_service_is_reported_without_stopping_or_removing_it(self):
        result = self._result()
        with mock.patch("portablizer.core.portablizer.IS_WINDOWS", True), \
                mock.patch.object(procutil, "services_in",
                                  return_value=["GameGuard"]), \
                mock.patch.object(procutil, "stop_service",
                                  side_effect=AssertionError("must not stop")) as stop:
            self.engine._report_portable_services(r"C:\P", result)

        self.assertEqual(result.registered_services, ["GameGuard"])
        self.assertEqual(result.removed_services, [])
        self.assertIn("GameGuard", self.engine.log.text)
        self.assertIn("не останавливает и не удаляет", self.engine.log.text)
        stop.assert_not_called()


class LauncherFolderVerdictTests(unittest.TestCase):
    """Лончер пишет в журнал, свободна ли папка, и называет виновника."""

    def test_describe_holders_is_human_readable(self):
        text = exe_launcher.describe_holders([
            (11, r"C:\Windows\explorer.exe", r"C:\P\App\ext.dll")])
        self.assertEqual(text, "explorer.exe (держит ext.dll)")

    def test_verdict_names_the_outside_program_holding_a_dll(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            with mock.patch.object(exe_launcher, "_portable_process_list",
                                   return_value=[]), \
                    mock.patch.object(
                        exe_launcher, "module_holders",
                        return_value=[(11, r"C:\Windows\explorer.exe",
                                       r"C:\P\App\ext.dll")]):
                exe_launcher._report_folder_state(root, {"deep_check": 1.0})

            log = (root / "PortableData" / "launcher-run.log").read_text(
                encoding="utf-8")
            self.assertIn("explorer.exe", log)
            self.assertIn("still held", log)

    def test_verdict_confirms_a_released_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            with mock.patch.object(exe_launcher, "_portable_process_list",
                                   return_value=[]), \
                    mock.patch.object(exe_launcher, "module_holders",
                                      return_value=[]):
                exe_launcher._report_folder_state(root, {"deep_check": 1.0})

            log = (root / "PortableData" / "launcher-run.log").read_text(
                encoding="utf-8")
            self.assertIn("portable folder released", log)

    def test_deep_check_can_be_switched_off_in_the_config(self):
        settings = exe_launcher.shutdown_settings(
            {"shutdown": {"deep_check": False}})
        self.assertEqual(settings["deep_check"], 0.0)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            with mock.patch.object(exe_launcher, "_portable_process_list",
                                   return_value=[]), \
                    mock.patch.object(exe_launcher, "module_holders",
                                      side_effect=AssertionError("не нужен")):
                exe_launcher._report_folder_state(root, settings)


class HandsOffGuiTests(unittest.TestCase):
    """Меньше кликов: перетаскивание, память о папке, автооткрытие."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "portablizer", "gui", "main_window.py")
        with open(path, encoding="utf-8") as handle:
            cls.source = handle.read()

    def test_installer_can_be_dropped_onto_the_window(self):
        self.assertIn("self.setAcceptDrops(True)", self.source)
        self.assertIn("def dragEnterEvent", self.source)
        self.assertIn("def dropEvent", self.source)

    def test_output_folder_is_remembered_between_runs(self):
        self.assertIn("QSettings", self.source)
        self.assertIn('self.settings.setValue("output_dir"', self.source)
        self.assertIn('self.settings.value("output_dir"', self.source)

    def test_result_folder_opens_by_itself(self):
        self.assertIn("self.cb_autoopen = QCheckBox(", self.source)
        self.assertIn("self.cb_autoopen.setChecked(True)", self.source)
        self.assertIn("if self.cb_autoopen.isChecked():", self.source)

    def test_dropped_installer_accepts_only_installers(self):
        tree = ast.parse(self.source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and \
                    node.name == "_dropped_installer":
                node.decorator_list = []
                module = ast.Module(body=[node], type_ignores=[])
                namespace = {"os": os}
                exec(compile(module, "<gui>", "exec"), namespace)  # noqa: S102
                picker = namespace["_dropped_installer"]
                break
        else:  # pragma: no cover
            self.fail("_dropped_installer не найден")

        class FakeUrl:
            def __init__(self, path):
                self._path = path

            def toLocalFile(self):
                return self._path

        with tempfile.TemporaryDirectory() as temp:
            text = Path(temp, "readme.txt")
            text.write_text("x", encoding="ascii")
            setup = Path(temp, "Setup.exe")
            setup.write_bytes(b"MZ")
            self.assertEqual(
                picker([FakeUrl(str(text)), FakeUrl(str(setup))]), str(setup))
            self.assertEqual(picker([FakeUrl(str(text))]), "")


class ExistingPortableMaintenanceTests(unittest.TestCase):
    """Портатив, собранный ПРЕЖНЕЙ версией, лечится без пересборки.

    Исправления живут внутри каждой готовой папки: там своя копия
    LaunchPortable.exe и свой Launch.bat. Обновление самого Portablizer
    ничего не меняет в уже созданных портативах — их нужно либо пересобрать,
    либо обновить на месте.
    """

    def _old_portable(self, temp, app_name="Old Game"):
        root = Path(temp, "Old_Portable")
        (root / "App").mkdir(parents=True)
        (root / "App" / "game.exe").write_bytes(b"MZ")
        cfg = launcher_mod.LauncherConfig(
            app_name=app_name, target_exe_rel="App/game.exe",
            extra_env={"GAME_HOME": "%PORTABLE_ROOT%/App"},
            path_prepend=["App"],
            targets=[launcher_mod.TargetInfo(name="game",
                                             rel_path="App/game.exe")],
            launcher_aliases={"Launch_Config.exe": "App/cfg.exe"},
        )
        data = json.loads(launcher_mod.render_config_json(cfg))
        # Так выглядел конфиг до появления политики завершения сеанса.
        data.pop("shutdown")
        (root / "launcher_config.json").write_text(
            json.dumps(data), encoding="utf-8")
        (root / "Launch.bat").write_text("@echo off\nrem old", encoding="ascii")
        return root

    def test_refresh_reissues_launchers_and_adds_the_shutdown_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._old_portable(temp)
            copied = []

            report = maintenance.refresh(
                str(root), Logger(),
                copy_exe=lambda folder, rel: copied.append(rel) or rel)

            self.assertTrue(report.success)
            config = json.loads((root / "launcher_config.json").read_text(
                encoding="utf-8-sig"))
            # Главное: новый лончер знает, когда отпускать папку.
            self.assertEqual(config["shutdown"]["idle_grace"], 20.0)
            self.assertTrue(config["shutdown"]["kill_leftovers"])
            # И появился аварийный «отпускатель».
            self.assertTrue((root / launcher_mod.STOP_SCRIPT_NAME).is_file())
            bat = (root / "Launch.bat").read_text(encoding="ascii")
            self.assertIn("PORTABLE_IDLE_GRACE", bat)
            self.assertIn("CloseMainWindow", bat)
            # EXE-лончер и его именованные копии перевыпущены.
            self.assertIn(os.path.join("App", "LaunchPortable.exe"), copied)
            self.assertIn("Launch_Config.exe", copied)

    def test_refresh_keeps_every_setting_of_the_portable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._old_portable(temp, app_name="Игра")
            maintenance.refresh(str(root), Logger(),
                                copy_exe=lambda folder, rel: rel)

            config = json.loads((root / "launcher_config.json").read_text(
                encoding="utf-8-sig"))
            self.assertEqual(config["app_name"], "Игра")
            self.assertEqual(config["target_exe_rel"], "App/game.exe")
            self.assertEqual(config["extra_env"],
                             {"GAME_HOME": "%PORTABLE_ROOT%/App"})
            self.assertEqual(config["path_prepend"], ["App"])
            self.assertEqual(config["launcher_aliases"],
                             {"Launch_Config.exe": "App/cfg.exe"})
            self.assertEqual(len(config["targets"]), 1)

    def test_refresh_stops_the_old_launcher_before_overwriting_it(self):
        """Работающий старый лончер нельзя перезаписать — сначала закрыть."""
        with tempfile.TemporaryDirectory() as temp:
            root = self._old_portable(temp)
            order = []
            with mock.patch.object(
                    procutil, "release_folder",
                    side_effect=lambda folder, **_k:
                    order.append("release") or ["LaunchPortable.exe"]):
                report = maintenance.refresh(
                    str(root), Logger(), copy_exe=lambda folder, rel: rel)

            self.assertEqual(order, ["release"])
            self.assertEqual(report.stopped, ["LaunchPortable.exe"])

    def test_refresh_refuses_a_folder_that_is_not_a_portable(self):
        with tempfile.TemporaryDirectory() as temp:
            report = maintenance.refresh(temp, Logger())
            self.assertFalse(report.success)
            self.assertIn("launcher_config.json", " ".join(report.messages))

    def test_release_reports_a_free_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._old_portable(temp)
            with mock.patch.object(procutil, "release_folder",
                                   return_value=["updater.exe"]):
                report = maintenance.release(str(root), Logger())

            self.assertTrue(report.success)
            self.assertEqual(report.stopped, ["updater.exe"])
            self.assertIn("можно удалить", " ".join(report.messages))

    def test_release_names_the_program_holding_the_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._old_portable(temp)
            holders = [procutil.Holder(11, r"C:\Windows\explorer.exe",
                                       "module", r"C:\P\App\ext.dll")]
            with mock.patch.object(procutil, "release_folder",
                                   return_value=[]), \
                    mock.patch.object(procutil, "folder_is_free",
                                      return_value=False), \
                    mock.patch.object(procutil, "holders",
                                      return_value=holders):
                report = maintenance.release(str(root), Logger())

            self.assertFalse(report.success)
            self.assertIn("explorer.exe (держит ext.dll)", report.holders)
            self.assertIn("Закройте окна", " ".join(report.messages))

    def test_release_works_on_any_folder_not_only_portables(self):
        with tempfile.TemporaryDirectory() as temp:
            plain = Path(temp, "just a folder")
            plain.mkdir()
            with mock.patch.object(procutil, "release_folder",
                                   return_value=[]):
                report = maintenance.release(str(plain), Logger())
            self.assertTrue(report.success)

    def test_config_round_trip_survives_a_config_without_shutdown(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="A", target_exe_rel="App/a.exe",
            apply_registry=True, registry_keys=[r"HKCU\Software\A"])
        data = json.loads(launcher_mod.render_config_json(cfg))
        data.pop("shutdown")
        restored = launcher_mod.config_from_dict(data)

        self.assertEqual(restored.app_name, "A")
        self.assertTrue(restored.apply_registry)
        self.assertEqual(restored.registry_keys, [r"HKCU\Software\A"])
        # Значения по умолчанию подставляются, а не теряются.
        self.assertEqual(restored.shutdown_idle_grace, 20.0)
        self.assertTrue(restored.shutdown_kill_leftovers)


class MaintenanceGuiTests(unittest.TestCase):
    """Обслуживание доступно из окна, а не только из кода."""

    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "portablizer", "gui", "main_window.py"),
                  encoding="utf-8") as handle:
            cls.window = handle.read()
        with open(os.path.join(root, "portablizer", "gui", "worker.py"),
                  encoding="utf-8") as handle:
            cls.worker = handle.read()

    def test_window_has_release_and_refresh_buttons(self):
        self.assertIn("self.release_btn = QPushButton(", self.window)
        self.assertIn("self.refresh_btn = QPushButton(", self.window)
        self.assertIn('self._maintenance("release")', self.window)
        self.assertIn('self._maintenance("refresh")', self.window)

    def test_maintenance_runs_in_a_background_thread(self):
        self.assertIn("class MaintenanceWorker(QThread):", self.worker)
        self.assertIn("maintenance.release", self.worker)
        self.assertIn("maintenance.refresh", self.worker)

    def test_built_folder_is_offered_for_maintenance(self):
        self.assertIn("self.maintenance_edit.setText(result.portable_dir)",
                      self.window)


class ElevationTests(unittest.TestCase):
    """Права администратора запрашиваются сами, один раз, при запуске."""

    def test_relaunch_command_for_the_frozen_exe(self):
        program, args = elevate_mod.relaunch_arguments(
            ["C:\\setup.exe"], frozen=True, executable="C:\\Portablizer.exe")
        self.assertEqual(program, "C:\\Portablizer.exe")
        self.assertEqual(args, ["C:\\setup.exe", elevate_mod.NO_ELEVATE_FLAG])

    def test_relaunch_command_from_sources_keeps_the_script(self):
        program, args = elevate_mod.relaunch_arguments(
            [], frozen=False, executable="python.exe", script="app.py")
        self.assertEqual(program, "python.exe")
        self.assertEqual(args, ["app.py", elevate_mod.NO_ELEVATE_FLAG])

    def test_second_copy_never_tries_to_elevate_again(self):
        """Предохранитель от бесконечного круга перезапусков."""
        self.assertTrue(elevate_mod.elevation_disabled(
            [elevate_mod.NO_ELEVATE_FLAG], {}))
        self.assertTrue(elevate_mod.elevation_disabled(
            [], {elevate_mod.NO_ELEVATE_ENV: "1"}))
        self.assertFalse(elevate_mod.elevation_disabled([], {}))

    def test_refused_uac_lets_the_build_continue_unelevated(self):
        with mock.patch.object(elevate_mod, "IS_WINDOWS", True), \
                mock.patch.object(elevate_mod, "is_elevated",
                                  return_value=False), \
                mock.patch.object(elevate_mod, "_shell_execute_runas",
                                  return_value=5):  # SE_ERR_ACCESSDENIED
            self.assertFalse(elevate_mod.ensure_elevated([]))

    def test_successful_elevation_asks_this_copy_to_exit(self):
        with mock.patch.object(elevate_mod, "IS_WINDOWS", True), \
                mock.patch.object(elevate_mod, "is_elevated",
                                  return_value=False), \
                mock.patch.object(elevate_mod, "_shell_execute_runas",
                                  return_value=42):
            self.assertTrue(elevate_mod.ensure_elevated([]))

    def test_already_elevated_process_does_not_restart_itself(self):
        with mock.patch.object(elevate_mod, "IS_WINDOWS", True), \
                mock.patch.object(elevate_mod, "is_elevated",
                                  return_value=True):
            self.assertFalse(elevate_mod.ensure_elevated([]))



class OpenFileHolderTests(unittest.TestCase):
    """Папку держит открытый ФАЙЛ, а не процесс: главный случай жалоб.

    Пользовательский сценарий целиком: портатив не запущен, процессов из
    папки нет, а два системных процесса держат шрифты из
    ``PortableData\\Temp\\is-XXXX.tmp`` — и папка не удаляется, хотя
    программа бодро рапортует «папка свободна».
    """

    ROOT = r"D:\Portable\Fallout_New_Vegas_Portable"
    FONT = (r"D:\Portable\Fallout_New_Vegas_Portable\PortableData\Temp"
            r"\is-UQUS2.tmp\OpenSans-Semibold.ttf")

    def test_holders_report_the_open_file_and_its_owner(self):
        opened = [procutil.OpenFile(17208, 900, self.FONT,
                                    r"C:\Windows\System32\svchost.exe")]
        with mock.patch.object(procutil, "_snapshot", return_value=[]), \
                mock.patch.object(procutil, "open_files_in",
                                  return_value=opened):
            found = procutil.holders(self.ROOT)

        self.assertEqual([item.kind for item in found], ["file"])
        self.assertEqual(found[0].handle, 900)
        self.assertEqual(
            procutil.describe_holders(found),
            ["svchost.exe (pid 17208, открыт файл OpenSans-Semibold.ttf)"])

    def test_folder_is_free_is_not_fooled_by_a_successful_rename(self):
        """Переименование проходит, а файл внутри открыт — папка занята.

        Файл, открытый с FILE_SHARE_DELETE (шрифты, отображённые в память
        файлы), не мешает переименовать каталог. Раньше именно поэтому
        пользователю говорили «папка свободна», а удаление падало.
        """
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Type_Portable")
            portable.mkdir()
            with mock.patch.object(procutil, "busy_files",
                                   return_value=[self.FONT]):
                errors = []
                self.assertFalse(procutil.folder_is_free(str(portable), errors))
                self.assertIn("OpenSans-Semibold.ttf", " ".join(errors))
                # Быстрая проба по-прежнему доступна явным флагом.
                self.assertTrue(
                    procutil.folder_is_free(str(portable), deep=False))
            self.assertTrue(portable.is_dir())

    def test_release_open_files_kills_background_and_frees_system_handles(self):
        """Фон — завершить, системный процесс — закрыть его дескриптор."""
        items = [
            procutil.OpenFile(17208, 900, self.FONT,
                              r"C:\Windows\System32\svchost.exe"),
            procutil.OpenFile(321, 7, self.FONT,
                              r"D:\Other\updater.exe"),
            procutil.OpenFile(555, 8, self.FONT,
                              r"C:\Program Files\Editor\editor.exe"),
        ]
        killed, closed = [], []
        with mock.patch.object(procutil, "IS_WINDOWS", True), \
                mock.patch.object(procutil, "open_files_in",
                                  return_value=items), \
                mock.patch.object(procutil, "visible_window_pids",
                                  return_value={555}), \
                mock.patch.object(procutil, "_post_close"), \
                mock.patch.object(procutil, "_terminate",
                                  side_effect=lambda pids: killed.extend(pids)), \
                mock.patch.object(
                    procutil, "close_remote_handle",
                    side_effect=lambda pid, handle:
                    closed.append((pid, handle)) or True), \
                mock.patch("time.sleep"):
            stopped = procutil.release_open_files(self.ROOT, close_grace=0.0)

        # Фоновый держатель завершён, окно пользователя не тронуто.
        self.assertEqual(killed, [321])
        # Дескрипторы закрыты у всех, кто пережил завершение.
        self.assertIn((17208, 900), closed)
        self.assertIn((555, 8), closed)
        self.assertTrue(any("updater.exe" in line for line in stopped))
        self.assertTrue(any("OpenSans-Semibold.ttf" in line
                            for line in stopped))

    def test_release_folder_also_frees_open_files_and_fonts(self):
        order = []
        with mock.patch.object(procutil, "IS_WINDOWS", True), \
                mock.patch.object(procutil, "services_in", return_value=[]), \
                mock.patch.object(procutil, "processes_in", return_value=[]), \
                mock.patch.object(procutil, "busy_files",
                                  return_value=[self.FONT]), \
                mock.patch.object(
                    procutil, "forget_fonts",
                    side_effect=lambda root, **_k: order.append("fonts") or 1), \
                mock.patch.object(
                    procutil, "release_open_files",
                    side_effect=lambda root, **_k:
                    order.append("handles") or ["svchost.exe: освобождён файл"]):
            stopped = procutil.release_folder(self.ROOT)

        self.assertEqual(order, ["fonts", "handles"])
        self.assertEqual(stopped, ["svchost.exe: освобождён файл"])

    def test_release_folder_can_skip_the_expensive_handle_scan(self):
        with mock.patch.object(procutil, "IS_WINDOWS", True), \
                mock.patch.object(procutil, "services_in", return_value=[]), \
                mock.patch.object(procutil, "processes_in", return_value=[]), \
                mock.patch.object(procutil, "release_open_files",
                                  side_effect=AssertionError("не нужен")):
            self.assertEqual(procutil.release_folder(self.ROOT, deep=False), [])

    def test_release_folder_does_not_scan_handles_of_a_free_folder(self):
        """Ничего не занято - значит и разбирать нечего: сборка не ждёт."""
        with mock.patch.object(procutil, "IS_WINDOWS", True), \
                mock.patch.object(procutil, "services_in", return_value=[]), \
                mock.patch.object(procutil, "processes_in", return_value=[]), \
                mock.patch.object(procutil, "busy_files", return_value=[]), \
                mock.patch.object(procutil, "release_open_files",
                                  side_effect=AssertionError("не нужен")), \
                mock.patch.object(procutil, "forget_fonts",
                                  side_effect=AssertionError("не нужен")):
            self.assertEqual(procutil.release_folder(self.ROOT), [])

    def test_maintenance_names_the_locked_files_instead_of_shrugging(self):
        """Вместо «виновника определить не удалось» — имена файлов и совет."""
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp, "Fallout_New_Vegas_Portable")
            folder.mkdir()
            with mock.patch.object(procutil, "release_folder",
                                   return_value=[]), \
                    mock.patch.object(procutil, "folder_is_free",
                                      return_value=False), \
                    mock.patch.object(procutil, "holders", return_value=[]), \
                    mock.patch.object(procutil, "busy_files",
                                      return_value=[self.FONT]):
                report = maintenance.release(str(folder), Logger())

            self.assertFalse(report.success)
            text = " ".join(report.messages)
            self.assertIn("OpenSans-Semibold.ttf", text)
            self.assertIn("администратора", text)
            self.assertNotIn("виновника определить не удалось", text)


class InstallerShortcutCleanupTests(unittest.TestCase):
    """Сборка не оставляет ярлык установщика на рабочем столе.

    Жалоба: после портирования на рабочем столе оставался ярлык со статичным
    абсолютным путём, и после переноса папки он вёл в прежнее место.
    Убираются только ярлыки, появившиеся за время сборки и ведущие внутрь
    портатива; чужое не трогается.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "App_Portable"
        (self.root / "App").mkdir(parents=True)
        self.desktop = self.base / "Desktop"
        self.desktop.mkdir()
        self.engine = Portablizer(Logger())

    def _guard(self):
        from portablizer.core import shortcuts

        return shortcuts.ShortcutGuard(
            self.root, folders=[self.desktop],
            app_names=shortcuts.app_name_candidates(
                "App", "AppSetup.exe", self.root.name))

    def test_shortcut_of_the_installer_is_removed_and_logged(self):
        guard = self._guard()
        guard.snapshot()
        link = self.desktop / "App.lnk"
        link.write_bytes(str(self.root / "App" / "app.exe")
                         .encode("utf-16-le"))
        removed = self.engine._report_own_shortcuts(guard)
        self.assertEqual(removed, [str(link)])
        self.assertFalse(link.exists())
        self.assertIn("Убрано ярлыков", self.engine.log.text)

    def test_empty_shortcut_is_removed_even_if_it_existed_before(self):
        """«Пустой» ярлык: файл остался, цель установщика уже удалена."""
        import struct

        from portablizer.core import shortcuts

        raw = str(self.base / "gone" / "App.exe").encode("latin-1") + b"\0"
        size = 0x1C + len(raw) + 1
        info = struct.pack("<IIIIIII", size, 0x1C, 1, 0, 0x1C, 0, 0x1C + len(raw))
        info += raw + b"\0"
        header = bytearray(0x4C)
        header[0:4] = b"L\x00\x00\x00"
        header[0x14:0x18] = struct.pack("<I", 0x2)
        link = self.desktop / "App.lnk"
        link.write_bytes(bytes(header) + info)

        guard = self._guard()
        guard.snapshot()          # ярлык уже был: обычная уборка его не тронет
        self.assertEqual(self.engine._report_own_shortcuts(guard), [])
        self.assertTrue(link.exists())

        removed = self.engine._report_own_shortcuts(guard, sweep=True)
        self.assertEqual(removed, [str(link)])
        self.assertFalse(link.exists())
        self.assertIn("Убрано ярлыков", self.engine.log.text)

    def test_user_shortcut_survives_the_build(self):
        link = self.desktop / "App.lnk"
        link.write_bytes(str(self.root / "App" / "app.exe")
                         .encode("utf-16-le"))
        guard = self._guard()
        guard.snapshot()
        self.assertEqual(self.engine._report_own_shortcuts(guard), [])
        self.assertTrue(link.exists())


class LauncherLeftoverCleanupTests(unittest.TestCase):
    """Портатив не запущен — значит и фоновых остатков быть не должно."""

    FONT = r"D:\P\PortableData\Temp\is-UQUS2.tmp\OpenSans-Regular.ttf"

    def test_open_files_are_described_with_pid_and_file_name(self):
        text = exe_launcher.describe_open_files([
            (17208, 900, self.FONT, r"C:\Windows\System32\svchost.exe")])
        self.assertEqual(text, "svchost.exe (pid 17208): OpenSans-Regular.ttf")

    def test_temp_leftovers_are_wiped_between_sessions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            stale = root / "PortableData" / "Temp" / "is-UQUS2.tmp"
            stale.mkdir(parents=True)
            (stale / "OpenSans-Regular.ttf").write_bytes(b"font")
            (root / "PortableData" / "Temp" / "note.tmp").write_bytes(b"x")
            keep = root / "PortableData" / "User"
            keep.mkdir(parents=True)
            (keep / "save.dat").write_bytes(b"save")

            removed = exe_launcher.purge_portable_temp(root, {})

            self.assertEqual(removed, 2)
            self.assertFalse(stale.exists())
            self.assertTrue((root / "PortableData" / "Temp").is_dir())
            # Пользовательские данные портатива остаются нетронутыми.
            self.assertTrue((keep / "save.dat").is_file())

    def test_temp_cleanup_can_be_switched_off_in_the_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            stale = root / "PortableData" / "Temp" / "is-UQUS2.tmp"
            stale.mkdir(parents=True)
            removed = exe_launcher.purge_portable_temp(
                root, {"shutdown": {"purge_temp": False}})
            self.assertEqual(removed, 0)
            self.assertTrue(stale.is_dir())

    def test_startup_sweep_leaves_a_running_second_copy_alone(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "PortableData" / "Temp" / "is-1.tmp").mkdir(parents=True)
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[(7, r"D:\P\App\game.exe")]), \
                    mock.patch.object(exe_launcher, "release_leftover_handles",
                                      side_effect=AssertionError("не трогаем")):
                self.assertEqual(exe_launcher.sweep_stale_session(root, {}), [])
            # Второй экземпляр программы не должен потерять свою временную папку.
            self.assertTrue((root / "PortableData" / "Temp" / "is-1.tmp").is_dir())

    def test_startup_sweep_clears_the_previous_session(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "PortableData" / "Temp" / "is-1.tmp").mkdir(parents=True)
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[]), \
                    mock.patch.object(exe_launcher, "release_leftover_handles",
                                      side_effect=AssertionError(
                                          "нечего разбирать")):
                done = exe_launcher.sweep_stale_session(root, {})

            self.assertIn("очищена временная папка портатива (1)", done)
            self.assertFalse((root / "PortableData" / "Temp" / "is-1.tmp").exists())

    def test_startup_sweep_forces_an_undeletable_leftover(self):
        """Временную папку не удалить — значит её держат, и это разбирается."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "PortableData" / "Temp" / "is-1.tmp").mkdir(parents=True)
            calls = []

            def fake_release(_root, _settings=None, roots=None):
                # Разбор ограничен временными папками: обход всего портатива
                # (у Cursor — десятки тысяч файлов) на старте недопустим.
                calls.append([str(item) for item in (roots or [])])
                return ["svchost.exe: файл"]

            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[]), \
                    mock.patch.object(exe_launcher, "release_leftover_handles",
                                      side_effect=fake_release), \
                    mock.patch.object(exe_launcher.shutil, "rmtree",
                                      side_effect=OSError("файл занят")), \
                    mock.patch.object(Path, "unlink",
                                      side_effect=OSError("файл занят")):
                done = exe_launcher.sweep_stale_session(root, {})

            self.assertIn("svchost.exe: файл", done)
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0])
            self.assertTrue(all("Temp" in item for item in calls[0]))

    def test_verdict_refuses_to_call_a_locked_folder_free(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            with mock.patch.object(exe_launcher, "_portable_process_list",
                                   return_value=[]), \
                    mock.patch.object(exe_launcher, "folder_looks_clean",
                                      return_value=False), \
                    mock.patch.object(exe_launcher, "busy_files",
                                      return_value=[self.FONT]), \
                    mock.patch.object(
                        exe_launcher, "open_files_in",
                        return_value=[(17208, 900, self.FONT,
                                       r"C:\Windows\System32\svchost.exe")]):
                exe_launcher._report_folder_state(root, {"deep_check": 1.0})

            log = (root / "PortableData" / "launcher-run.log").read_text(
                encoding="utf-8")
            self.assertIn("still locked", log)
            self.assertIn("OpenSans-Regular.ttf", log)
            self.assertNotIn("portable folder released", log)

    def test_stop_asks_for_administrator_rights_before_giving_up(self):
        """Чужой дескриптор закрывает только администратор — и лончер это знает."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "release_portable_folder",
                                      return_value=[]), \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[]), \
                    mock.patch.object(exe_launcher, "busy_files",
                                      return_value=[self.FONT]), \
                    mock.patch.object(exe_launcher, "open_files_in",
                                      return_value=[]), \
                    mock.patch.object(exe_launcher, "_is_elevated",
                                      return_value=False), \
                    mock.patch.object(exe_launcher, "_run_elevated",
                                      return_value=0) as elevated, \
                    mock.patch.object(exe_launcher, "_show_warning") as warned:
                code = exe_launcher.stop(root)

            self.assertEqual(code, 0)
            elevated.assert_called_once_with(["--stop"])
            warned.assert_not_called()

    def test_stop_reports_the_locked_files_when_even_admin_cannot_help(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "P")
            (root / "App").mkdir(parents=True)
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "release_portable_folder",
                                      return_value=[]), \
                    mock.patch.object(exe_launcher, "_portable_process_list",
                                      return_value=[]), \
                    mock.patch.object(exe_launcher, "busy_files",
                                      return_value=[self.FONT]), \
                    mock.patch.object(
                        exe_launcher, "open_files_in",
                        return_value=[(17208, 900, self.FONT,
                                       r"C:\Windows\System32\svchost.exe")]), \
                    mock.patch.object(exe_launcher, "_is_elevated",
                                      return_value=True), \
                    mock.patch.object(exe_launcher, "_show_warning") as warned:
                code = exe_launcher.stop(root)

            self.assertEqual(code, 1)
            message = warned.call_args[0][0]
            self.assertIn("svchost.exe (pid 17208): OpenSans-Regular.ttf",
                          message)
            self.assertIn("администратора", message)

    def test_release_sweeps_handles_even_without_processes(self):
        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher, "_portable_process_list",
                                  return_value=[]), \
                mock.patch.object(exe_launcher, "release_leftover_handles",
                                  return_value=["svchost.exe: файл"]):
            stopped = exe_launcher.release_portable_folder(
                Path(r"D:\P"), {"close_grace": 0.0})
        self.assertEqual(stopped, ["svchost.exe: файл"])

    def test_stop_script_verifies_the_result_and_elevates_itself(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Fallout New Vegas", target_exe_rel="App/game.exe")
        script = launcher_mod.render_stop_cmd(cfg)

        self.assertTrue(script.isascii())
        # Вердикт лончера окончателен: раньше при его отказе запускался
        # слабый PowerShell-запасной вариант, который видел только процессы
        # и радостно сообщал «The folder is free».
        self.assertIn('"%PORTABLE_ROOT%\\App\\LaunchPortable.exe" --stop',
                      script)
        self.assertIn("--stop\nif errorlevel 1 goto stillbusy", script)
        # Запасной вариант (портатив без EXE-лончера) при неудаче ещё
        # попросит права администратора.
        self.assertIn("if errorlevel 1 goto locked", script)
        # Запасной вариант теперь тоже проверяет результат делом.
        self.assertIn("[IO.File]::Open", script)
        self.assertIn("These files are still open", script)
        # И умеет попросить права администратора.
        self.assertIn("-Verb RunAs", script)
        self.assertIn("exit /b %STOP_RC%", script)

    def test_config_carries_the_new_cleanup_policy(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Type", target_exe_rel="App/Type.exe")
        data = json.loads(launcher_mod.render_config_json(cfg))["shutdown"]
        self.assertTrue(data["deep_check"])
        self.assertTrue(data["purge_temp"])
        self.assertEqual(data["handle_budget"], 8.0)
        settings = exe_launcher.shutdown_settings(
            json.loads(launcher_mod.render_config_json(cfg)))
        self.assertEqual(settings["handle_budget"], 8.0)
        self.assertEqual(settings["purge_temp"], 1.0)
        # Старый конфиг без новых полей читается со значениями по умолчанию.
        restored = launcher_mod.config_from_dict(
            {"app_name": "Type", "target_exe_rel": "App/Type.exe"})
        self.assertTrue(restored.shutdown_deep_check)
        self.assertTrue(restored.shutdown_purge_temp)


class IexpressOverwriteDialogTests(unittest.TestCase):
    """VC++ 2005 IExpress overwrite prompt during portable build."""

    def test_yes_to_all_is_preferred_confirm(self):
        from portablizer.core import redist as redist_mod
        self.assertTrue(redist_mod.installer_button_is_confirm_all("&Yes To All"))
        self.assertTrue(redist_mod.installer_button_is_confirm_all("Да для всех"))
        self.assertTrue(redist_mod.installer_button_is_confirm("Yes"))
        self.assertTrue(redist_mod.installer_button_is_confirm("OK"))
        self.assertTrue(redist_mod.installer_button_is_confirm("ОК"))
        self.assertFalse(redist_mod.installer_button_is_confirm("No"))
        self.assertFalse(redist_mod.installer_button_is_confirm("Cancel"))

    def test_overwrite_prompt_from_screenshot_is_recognised(self):
        from portablizer.core import redist as redist_mod
        body = (
            "Do you want to overwrite the file "
            r"D:\Portable\opencode-desktop-win-x64_Portable\_redist_cache"
            r"\vc2005\x86\eula.1028.txt?"
        )
        self.assertTrue(
            redist_mod.installer_prompt_looks_like_overwrite("", body))
        self.assertFalse(
            redist_mod.installer_prompt_looks_like_overwrite("Notepad", "hello"))

    def test_directx_command_line_error_from_screenshot_is_recognised(self):
        """Окно «Установка DirectX / Неверная операция командной строки»."""
        from portablizer.core import redist as redist_mod
        title = "Установка DirectX"
        body = "Неверная операция командной строки."
        self.assertTrue(
            redist_mod.installer_prompt_looks_like_command_error(title, body))
        self.assertTrue(
            redist_mod.installer_prompt_looks_like_directx_notice(title))
        self.assertTrue(redist_mod.installer_prompt_should_dismiss(title, body))
        self.assertTrue(redist_mod.installer_prompt_looks_like_command_error(
            "DirectX Setup", "Invalid command line operation."))
        self.assertTrue(redist_mod.installer_prompt_looks_like_command_error(
            "Microsoft Visual C++ 2005 Redistributable",
            "Command line option syntax error. Type Command /? for Help"))
        self.assertFalse(
            redist_mod.installer_prompt_looks_like_command_error(
                "Notepad", "hello"))
        self.assertFalse(
            redist_mod.installer_prompt_should_dismiss("Notepad", "hello"))
        self.assertFalse(
            redist_mod.installer_prompt_looks_like_directx_notice(
                "Portablizer"))

    def test_dismiss_is_a_noop_off_windows(self):
        from portablizer.core import redist as redist_mod
        self.assertEqual(redist_mod._dismiss_installer_dialogs(), 0)


class SketchUpRepackTests(unittest.TestCase):
    """SketchUp Pro RePack by KpoJIuK: документированная команда /S /RU /D.

    Регрессия на журнал пользователя: установщик — Inno Setup со СВОИМ
    разбором командной строки. Стандартные ключи Inno (/VERYSILENT /DIR=)
    он не понимает, показывает мастер «Выберите язык» и «Выберите папку
    установки» (по умолчанию C:\\Program Files\\SketchUp) и ждёт мышку.
    Каждая следующая попытка универсальной лестницы открывала мастер заново,
    поэтому один и тот же вопрос появлялся несколько раз, а сборка стояла на
    38 %.
    """

    NAME = "SketchUp Pro v26.1.189.exe"

    @staticmethod
    def _installer(temp, name=NAME,
                   payload=b"Inno Setup " + b"https://www.sketchup.com/ "):
        path = os.path.join(temp, name)
        _fake_pe(path, [".text", ".rsrc"], payload, dotnet=False)
        return path

    def test_repack_is_recognized_by_product_filename(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(self._installer(temp))
            self.assertIsNotNone(det.repack_profile)
            self.assertEqual(det.repack_profile.name, "KpoJIuK")
            self.assertEqual(det.vendor_name, "KpoJIuK")
            self.assertTrue(any("перепак KpoJIuK" in e for e in det.evidence))
            self.assertTrue(det.has_switch("/RU"))
            self.assertTrue(det.has_switch("/D="))

    def test_documented_command_comes_first_and_keeps_the_path_last(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(temp)
            attempts = build_attempts(detect_installer(installer), installer,
                                      r"E:\Portable\SketchUp_Portable\App",
                                      language="ru")
            self.assertGreaterEqual(len(attempts), 4)
            first = attempts[0]
            self.assertEqual(first.args, ["/S", "/RU"])
            self.assertEqual(first.raw_tail,
                             r"/D=E:\Portable\SketchUp_Portable\App")
            # Ключ пути — последним и без кавычек: так его разбирает скрипт
            # репака (как NSIS /D=).
            self.assertFalse(first.raw_tail.startswith('"'))
            self.assertTrue(first.display().endswith(first.raw_tail))
            self.assertFalse(first.ignores_target_dir)

    def test_chosen_language_selects_its_short_switch(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(temp)
            attempts = build_attempts(detect_installer(installer), installer,
                                      r"E:\P\App", language="en")
            self.assertEqual(attempts[0].args, ["/S", "/EN"])
            self.assertIn(["/S", "/RU"],
                          [plan.args for plan in attempts])

    def test_attempt_without_path_is_marked_for_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(temp)
            attempts = build_attempts(detect_installer(installer), installer,
                                      r"E:\P\App", language="ru")
            no_path = [plan for plan in attempts if plan.raw_tail is None]
            self.assertTrue(no_path)
            # Без /D= установщик ставит программу в Program Files: результат
            # обязан быть найден и перенесён в App (и оригинал удалён).
            self.assertTrue(all(plan.ignores_target_dir for plan in no_path))

    def test_generic_verysilent_is_only_a_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(temp)
            attempts = build_attempts(detect_installer(installer), installer,
                                      r"E:\P\App", language="ru")
            self.assertNotIn("/VERYSILENT", attempts[0].args)
            self.assertTrue(any("/VERYSILENT" in plan.args
                                for plan in attempts[1:]))

    def test_official_burn_bundle_is_not_hijacked(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = self._installer(
                temp,
                payload=b"WixBurn .wixburn wixstdba https://www.sketchup.com/")
            det = detect_installer(installer)
            self.assertEqual(det.installer_type, InstallerType.WIX_BURN)
            self.assertIsNone(det.repack_profile)
            attempts = build_attempts(det, installer, r"E:\P\App")
            self.assertNotEqual(attempts[0].args[:2], ["/S", "/RU"])

    def test_lookalike_filename_does_not_get_the_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            det = detect_installer(
                self._installer(temp, name="NotSketchUp Pro v26.1.189.exe"))
            self.assertIsNone(det.repack_profile)


class ChromiumFlagsTests(unittest.TestCase):
    """Chromium-ключи — только настоящему Electron, не CEF-программе."""

    def test_cef_distribution_with_chrome_elf_is_not_electron(self):
        """CEF кладёт chrome_elf.dll — сам по себе он ничего не значит."""
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "libcef.dll").write_bytes(b"MZ")
            (app / "chrome_elf.dll").write_bytes(b"MZ")
            (app / "icudtl.dat").write_bytes(b"")
            target = app / "SketchUp.exe"
            target.write_bytes(b"MZ" + b"\x00" * (12 * 1024 * 1024))
            self.assertFalse(launcher_mod.is_electron_app(str(target)))
            self.assertFalse(exe_launcher.needs_electron_sandbox_off(target))

    def test_cef_program_is_not_an_electron_host(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "libcef.dll").write_bytes(b"MZ")
            # CEF-программа держит рядом icudtl.dat/snapshot_blob.bin — это
            # НЕ признак Electron (их же кладёт Steam и другие CEF-хосты).
            (app / "icudtl.dat").write_bytes(b"")
            (app / "snapshot_blob.bin").write_bytes(b"")
            sketchup = app / "SketchUp.exe"
            sketchup.write_bytes(b"MZ" + b"\x00" * (9 * 1024 * 1024))
            self.assertFalse(launcher_mod.is_electron_app(str(sketchup)))
            self.assertFalse(exe_launcher.needs_electron_sandbox_off(sketchup))

    def test_real_electron_exe_is_recognized_by_its_own_markers(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            target = app / "SomeApp.exe"
            target.write_bytes(b"MZ ... ELECTRON_RUN_AS_NODE ...")
            self.assertTrue(launcher_mod.is_electron_app(str(target)))
            self.assertTrue(exe_launcher.needs_electron_sandbox_off(target))

    def test_stale_chromium_flags_are_stripped_for_a_cef_program(self):
        """Старый launcher_config.json содержал --no-sandbox у SketchUp."""
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "libcef.dll").write_bytes(b"MZ")
            target = app / "SketchUp.exe"
            target.write_bytes(b"MZ" + b"\x00" * 4096)
            command = exe_launcher.with_electron_flags(
                [str(target), "--no-sandbox", "--disable-gpu-sandbox",
                 "--disable-features=RendererCodeIntegrity", "-noload"],
                target)
            self.assertEqual(command, [str(target), "-noload"])

    def test_cef_host_stays_out_of_the_kill_job(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "libcef.dll").write_bytes(b"MZ")
            target = app / "SketchUp.exe"
            target.write_bytes(b"MZ")
            self.assertTrue(exe_launcher.is_chromium_tree(app))
            self.assertFalse(exe_launcher.should_use_job(target))


class ProductNameMatchingTests(unittest.TestCase):
    """Каталог «SketchUp» должен совпадать с «SketchUp Pro v26.1.189»."""

    NAME = "SketchUp Pro v26.1.189"

    def test_version_suffix_does_not_hide_the_product_name(self):
        keys = Portablizer._name_keys(self.NAME, self.NAME + ".exe")
        self.assertIn("sketchup", keys)
        self.assertGreaterEqual(Portablizer._name_score("SketchUp", keys), 200)

    def test_year_edition_folder_is_the_same_product(self):
        keys = Portablizer._name_keys(self.NAME, self.NAME + ".exe")
        self.assertGreaterEqual(
            Portablizer._name_score("SketchUp 2026", keys), 200)
        self.assertGreaterEqual(
            Portablizer._name_score("SketchUp Pro", keys), 200)

    def test_unrelated_folder_is_not_matched(self):
        keys = Portablizer._name_keys(self.NAME, self.NAME + ".exe")
        self.assertLess(Portablizer._name_score("LayOut", keys), 200)
        self.assertLess(Portablizer._name_score("SketchyApp", keys), 200)

    def _options(self, root: Path) -> PortableOptions:
        return PortableOptions(installer_path=str(root / (self.NAME + ".exe")),
                               output_dir=str(root))

    def test_new_program_files_copy_is_removed_after_recovery(self):
        import portablizer.core.portablizer as engine_mod
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            program_files = root / "Program Files"
            program_files.mkdir()
            app_dir = root / "SketchUp_Portable" / "App"
            app_dir.mkdir(parents=True)
            engine = Portablizer(Logger())
            with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                    mock.patch.dict(os.environ, {
                        # Windows сравнивает имена переменных без учёта
                        # регистра, Linux — с учётом: задаём оба написания,
                        # потому что поиск мест установки и уборка читают
                        # их разными именами.
                        "PROGRAMFILES": str(program_files),
                        "ProgramFiles": str(program_files),
                        "PROGRAMFILES(X86)": "",
                        "ProgramFiles(x86)": "",
                        "PROGRAMW6432": "",
                        "ProgramW6432": "",
                        "PROGRAMDATA": "",
                        "ProgramData": "",
                        "LOCALAPPDATA": "",
                        "APPDATA": "",
                    }):
                # Снимок делается ДО установщика — ровно как в run().
                before = engine._snapshot_install_locations("")
                target = program_files / "SketchUp"
                target.mkdir()
                (target / "SketchUp.exe").write_bytes(b"MZ")
                removed = engine._cleanup_leftover_install_dirs(
                    self.NAME, str(root / (self.NAME + ".exe")),
                    self._options(root), "", before=before,
                    app_dir=str(app_dir))
            self.assertEqual(removed, [str(target)])
            self.assertFalse(target.exists())

    def test_preexisting_program_is_never_deleted(self):
        import portablizer.core.portablizer as engine_mod
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            program_files = root / "Program Files"
            target = program_files / "SketchUp"
            target.mkdir(parents=True)
            (target / "SketchUp.exe").write_bytes(b"MZ")
            app_dir = root / "SketchUp_Portable" / "App"
            app_dir.mkdir(parents=True)
            before = {
                os.path.normcase(os.path.abspath(str(program_files))):
                    {os.path.normcase(os.path.abspath(str(target)))},
            }
            engine = Portablizer(Logger())
            with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                    mock.patch.dict(os.environ, {
                        # Windows сравнивает имена переменных без учёта
                        # регистра, Linux — с учётом: задаём оба написания,
                        # потому что поиск мест установки и уборка читают
                        # их разными именами.
                        "PROGRAMFILES": str(program_files),
                        "ProgramFiles": str(program_files),
                        "PROGRAMFILES(X86)": "",
                        "ProgramFiles(x86)": "",
                        "PROGRAMW6432": "",
                        "ProgramW6432": "",
                        "PROGRAMDATA": "",
                        "ProgramData": "",
                        "LOCALAPPDATA": "",
                        "LOCALAPPDATA": "",
                        "APPDATA": "",
                    }):
                removed = engine._cleanup_leftover_install_dirs(
                    self.NAME, str(root / (self.NAME + ".exe")),
                    self._options(root), "", before=before,
                    app_dir=str(app_dir))
            self.assertEqual(removed, [])
            self.assertTrue(target.exists())


class InstallerPathDialogTests(unittest.TestCase):
    """Диалоги мастера репака: язык и папка установки."""

    def test_russian_path_page_is_recognised(self):
        from portablizer.core import redist as redist_mod
        title = "Установка SketchUp Pro 2026"
        body = ("Выберите папку установки. Папка установки: "
                r"C:\Program Files\SketchUp  Папка установки должна быть пустой.")
        self.assertTrue(
            redist_mod.installer_prompt_looks_like_path_consent(title, body))

    def test_language_page_is_recognised(self):
        from portablizer.core import redist as redist_mod
        self.assertTrue(
            redist_mod.installer_prompt_looks_like_language_selection(
                "Установка SketchUp Pro 2026",
                "Выберите язык установки: Русский English"))
        self.assertTrue(
            redist_mod.installer_prompt_looks_like_language_selection(
                "Setup", "Select Setup Language"))

    def test_back_and_cancel_are_never_clicked(self):
        from portablizer.core import redist as redist_mod
        self.assertTrue(redist_mod.installer_button_is_proceed("Далее >"))
        self.assertTrue(redist_mod.installer_button_is_proceed("Установить"))
        self.assertFalse(redist_mod.installer_button_is_proceed("Назад"))
        self.assertFalse(redist_mod.installer_button_is_proceed("Отмена"))

    def test_automation_is_a_noop_off_windows(self):
        from portablizer.core import redist as redist_mod
        counter = {}
        self.assertEqual(redist_mod._dismiss_installer_dialogs(
            counter, target_dir=r"C:\P\App", pids=[1], state={}), 0)


class MultitranDriveRootPortableTests(unittest.TestCase):
    """Рабочая папка C:\\multitran переносится внутрь портатива и переезжает с ним."""

    @staticmethod
    def _build_minimal_unsigned_pe(payload: bytes) -> bytes:
        header = bytearray(0x200)
        header[0:2] = b"MZ"
        e_lfanew = 0x80
        struct.pack_into("<I", header, 0x3C, e_lfanew)
        header[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
        struct.pack_into("<H", header, e_lfanew + 20, 0xE0)  # SizeOfOptionalHeader
        optional = e_lfanew + 24
        struct.pack_into("<H", header, optional, 0x10B)  # PE32
        struct.pack_into("<I", header, optional + 64, 0x12345678)  # CheckSum
        struct.pack_into("<I", header, optional + 92, 16)  # NumberOfRvaAndSizes
        # Security directory at optional + 96 + 32 = optional + 128 (0, 0 -> unsigned)
        struct.pack_into("<II", header, optional + 128, 0, 0)
        return bytes(header) + payload

    def test_retarget_install_paths_rewrites_c_multitran_to_portable_root(self):
        with tempfile.TemporaryDirectory() as temp:
            portable_dir = Path(temp, "Multitran_Portable")
            app_dir = portable_dir / "App"
            (app_dir / "network").mkdir(parents=True)
            (app_dir / "network" / "dict.ert").write_bytes(b"DICT")
            dist_dir = r"E:\Backup\Apps\Portable\Multitran 03.11.2023"

            key = r"HKCU\Software\Multitran"
            snap = {
                key: {
                    "Dictionary Path": (registry.REG_SZ, repr(dist_dir + r"\network")),
                    "Work Path": (registry.REG_SZ, repr(r"c:\multitran")),
                    "History": (registry.REG_SZ, repr(r"c:\multitran\DESKTOP-PC\history.txt")),
                },
            }
            moved = registry.retarget_install_paths(
                snap,
                [key],
                str(app_dir),
                extra_roots=[dist_dir],
                portable_dir=str(portable_dir),
                app_names=["Multitran", "mt"],
            )
            tokens = [(str(portable_dir), registry.ROOT_TOKEN)]
            tokenized = registry.render_keys(moved, [key], tokens=tokens)
            self.assertIn(
                f'"{registry.ROOT_TOKEN}\\\\App\\\\network"',
                tokenized,
            )
            self.assertIn(
                f'"{registry.ROOT_TOKEN}\\\\multitran"',
                tokenized,
            )
            self.assertIn(
                f'"{registry.ROOT_TOKEN}\\\\multitran\\\\DESKTOP-PC\\\\history.txt"',
                tokenized,
            )

    def test_matching_existing_app_keys_captures_preexisting_multitran_key(self):
        snap = {
            r"HKCU\Software\Multitran": {
                "Work Path": (registry.REG_SZ, repr(r"c:\multitran")),
            },
            r"HKCU\Software\UnrelatedVendor": {
                "Path": (registry.REG_SZ, repr(r"c:\unrelated")),
            },
        }
        matched = registry.matching_existing_app_keys(
            snap, app_names=["Multitran"], source_roots=[]
        )
        self.assertEqual(matched, [r"HKCU\Software\Multitran"])

    def test_neutralize_hardcoded_drive_app_paths_patches_pe_and_ini(self):
        with tempfile.TemporaryDirectory() as temp:
            portable_dir = Path(temp, "Multitran_Portable")
            app_dir = portable_dir / "App"
            app_dir.mkdir(parents=True)

            utf16_path = "c:\\multitran\\history.txt".encode("utf-16le") + b"\x00\x00"
            ascii_path = b'c:\\multitran\\usertra.reu\x00'
            pe_path = app_dir / "mt.exe"
            orig_pe = self._build_minimal_unsigned_pe(ascii_path + utf16_path)
            pe_path.write_bytes(orig_pe)

            ini_path = app_dir / "mt.ini"
            ini_path.write_text("WorkDir=C:\\multitran\\DESKTOP\r\n", encoding="utf-8")

            engine = Portablizer(Logger())
            matched = engine._neutralize_hardcoded_drive_app_paths(
                str(portable_dir), str(app_dir), app_names=["Multitran"]
            )
            self.assertTrue(any(m.casefold() == "multitran" for m in matched), matched)

            new_pe = pe_path.read_bytes()
            self.assertEqual(len(new_pe), len(orig_pe))
            self.assertIn(b"..\\multitran\\usertra.reu\x00", new_pe)
            self.assertIn("..\\multitran\\history.txt".encode("utf-16le"), new_pe)
            self.assertNotIn(b"c:\\multitran", new_pe.lower())
            # PE CheckSum reset to 0
            e_lfanew = struct.unpack_from("<I", new_pe, 0x3C)[0]
            csum = struct.unpack_from("<I", new_pe, e_lfanew + 24 + 64)[0]
            self.assertEqual(csum, 0)

            self.assertIn("..\\multitran\\DESKTOP", ini_path.read_text(encoding="utf-8"))

    def test_relocate_drive_root_app_folders_and_sync_computer_profiles(self):
        with tempfile.TemporaryDirectory() as temp:
            fake_c = Path(temp, "FakeDriveC")
            old_pc_dir = fake_c / "multitran" / "OLD-PC"
            subj_dir = old_pc_dir / "Subject Profiles"
            subj_dir.mkdir(parents=True)
            (old_pc_dir / "history.txt").write_text("word1\nword2\n", encoding="utf-8")
            (old_pc_dir / "usertra.reu").write_bytes(b"USERTRA_DATA")
            (subj_dir / "subject.act").write_text("ACT", encoding="utf-8")
            (subj_dir / "subject.sel").write_text("SEL", encoding="utf-8")

            portable_dir = Path(temp, "D_Drive", "Multitran_Portable")
            app_dir = portable_dir / "App"
            app_dir.mkdir(parents=True)

            cfg = {
                "app_name": "Multitran",
                "registry": {
                    "enabled": True,
                    "file": "portable.reg",
                    "keys": [r"HKCU\Software\Multitran"],
                },
            }
            session = exe_launcher.DriveRootDataSession(portable_dir, cfg)
            with mock.patch.dict(
                os.environ,
                {"SystemDrive": str(fake_c), "COMPUTERNAME": "NEW-PC"},
            ):
                report = session.before()

            self.assertTrue(any("relocated" in r for r in report), report)
            self.assertFalse((fake_c / "multitran").exists())

            new_pc_dir = portable_dir / "multitran" / "NEW-PC"
            self.assertTrue((new_pc_dir / "history.txt").is_file())
            self.assertEqual(
                (new_pc_dir / "history.txt").read_text(encoding="utf-8"),
                "word1\nword2\n",
            )
            self.assertEqual(
                (new_pc_dir / "usertra.reu").read_bytes(),
                b"USERTRA_DATA",
            )
            self.assertEqual(
                (new_pc_dir / "Subject Profiles" / "subject.act").read_text(encoding="utf-8"),
                "ACT",
            )
            self.assertEqual(
                (new_pc_dir / "Subject Profiles" / "subject.sel").read_text(encoding="utf-8"),
                "SEL",
            )

    def test_launcher_sync_external_changes_never_overwrites_portable_root_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Multitran_Portable")
            root.mkdir(parents=True)
            (root / "portable.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Multitran]\r\n"
                '"Work Path"="@@PORTABLE_ROOT@@\\\\multitran"\r\n'
                '"Dictionary Path"="@@PORTABLE_ROOT@@\\\\App\\\\network"\r\n'
                '"Interface Language"="English"\r\n\r\n',
                encoding="utf-16",
            )
            cfg = {
                "data_dir_name": "PortableData",
                "registry": {
                    "enabled": True,
                    "file": "portable.reg",
                    "restore_on_exit": True,
                    "keys": [r"HKCU\Software\Multitran"],
                    "created_keys": [r"HKCU\Software\Multitran"],
                },
            }

            def fake_host_read(key: str):
                if "multitran" in key.casefold():
                    return {
                        "Work Path": '"c:\\\\multitran"',
                        "Dictionary Path": '"E:\\\\Dist\\\\network"',
                        "Interface Language": '"Russian"',
                    }
                return {}

            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(
                        exe_launcher,
                        "_read_host_key_reg_values",
                        side_effect=fake_host_read,
                    ):
                session = exe_launcher.RegistrySession(root, cfg)
                session.sync_external_changes()

            updated = (root / "portable.reg").read_text(encoding="utf-16")
            self.assertIn('"Work Path"="@@PORTABLE_ROOT@@\\\\multitran"', updated)
            self.assertIn('"Dictionary Path"="@@PORTABLE_ROOT@@\\\\App\\\\network"', updated)
            self.assertNotIn("c:\\\\multitran", updated.lower())
            self.assertIn('"Interface Language"="Russian"', updated)


if __name__ == "__main__":
    unittest.main()
