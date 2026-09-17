import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import batsim
from portablizer.core import launcher as launcher_mod
from portablizer.core import registry
from portablizer.core.detect import InstallerType, detect_installer
from portablizer.core.launcher import (
    LauncherConfig, ensure_ascii_bat, render_bat, render_config_json,
    render_vbs,
)
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer
from portablizer.core.silentargs import build_silent_plan


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
            # Главная причина «мигающего окна» — не-ASCII байты в .bat.
            self.assertTrue(all(b < 128 for b in bat))

            self.assertTrue((portable / "LaunchHidden.vbs").exists())
            config = json.loads(
                (portable / "launcher_config.json").read_text(encoding="utf-8"))
            self.assertEqual(
                config["target_exe_rel"].replace("\\", "/"), "App/Type.exe")
            # Реестр не захватывался — лончер не должен его трогать.
            self.assertFalse(config["registry"]["enabled"])

    def test_readme_promises_no_installation_on_other_pc(self):
        class FakePortablizer(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir):
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

    def test_vbs_wrapper_is_ascii_and_calls_launch_bat(self):
        vbs = render_vbs()
        self.assertTrue(vbs.isascii())
        self.assertIn("Launch.bat", vbs)
        self.assertIn("--nopause", vbs)

    def test_launcher_help_and_switches_exist(self):
        bat = self._bat()
        for switch in ("--nopause", "--pause", "--no-registry",
                       "--keep-registry", "--reset", "--help"):
            self.assertIn(switch, bat)


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

    def _run(self, cfg, fs=None, argv=None, program_exit_code=0):
        bat = render_bat(cfg)
        fs = fs or self._fs()
        fs.add_file(f"{self.ROOT}\\Launch.bat", bat)
        return batsim.run_batch(bat, f"{self.ROOT}\\Launch.bat", fs,
                                argv=argv or [],
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

    def test_host_cleanup_removes_created_keys_and_restores_changed(self):
        before = {r"HKCU\Software\Vendor\Existing": {
            "Theme": (registry.REG_SZ, repr("dark"))}}
        after = {
            r"HKCU\Software\Vendor\Existing": {
                "Theme": (registry.REG_SZ, repr("light")),
                "New": (registry.REG_DWORD, repr(1)),
            },
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyApp": {
                "DisplayName": (registry.REG_SZ, repr("My Application")),
            },
        }
        diff = registry.compute_diff(before, after)
        text = registry.render_host_cleanup(diff, diff.touched_keys)
        self.assertIn(
            r"[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion"
            r"\Uninstall\MyApp]", text)
        self.assertIn('"New"=-', text)          # добавленное значение убираем
        self.assertIn('"Theme"="dark"', text)   # прежнее возвращаем

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
            },
            r"HKLM\Software\Classes\.myext": {
                "": (registry.REG_SZ, repr("MyApp.File")),
            },
        }
        capture = engine._capture_registry(
            str(portable), before, after,
            PortableOptions(installer_path="x", output_dir=temp, **opts))
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

    def test_cleanup_file_removes_the_uninstall_entry_from_this_pc(self):
        capture, files = self._capture()
        self.assertIn("cleanup_host.reg", files)
        self.assertIn("Uninstall", files["cleanup_host.reg"])

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


if __name__ == "__main__":
    unittest.main()
