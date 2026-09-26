import ast
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import batsim
from portablizer.core import launcher as launcher_mod
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
    retarget_response_file,
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

    def test_self_elevating_cleanup_cmd_is_written_next_to_the_reg(self):
        capture, _files = self._capture()
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

            # С InstallFolder, без него, затем /layout, затем msiexec /a.
            self.assertEqual(len(engine.calls), 4)
            self.assertTrue(any(a.startswith("InstallFolder=")
                                for a in engine.calls[0].args))
            self.assertFalse(any(a.startswith("InstallFolder=")
                                 for a in engine.calls[1].args))
            self.assertIn("/layout", engine.calls[2].args)
            self.assertEqual(engine.calls[3].program, "msiexec.exe")
            self.assertIn("/a", engine.calls[3].args)
            self.assertNotIn("/i", engine.calls[3].args)
            self.assertEqual(rc, 0)
            self.assertIn("/layout", used.args)
            self.assertTrue((app / "Type.exe").exists())
            # Временная распаковка бандла удалена.
            self.assertFalse((portable / "_bundle_layout").exists())

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
            # Первая попытка + повтор + /layout.
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


if __name__ == "__main__":
    unittest.main()
