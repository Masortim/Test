"""Nested PyCharm launch selection, aliases and safe refresh."""
import json
import os
import shutil
import subprocess
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import portable_launcher_entry as entry
from portablizer.core import launcher, maintenance, pycharm
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import Portablizer, PortableOptions


def touch(path, data=b'MZ fake'):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def layout(root):
    app = Path(root) / 'App'
    main = touch(app / 'PyCharm2025.2/bin/pycharm64.exe')
    touch(app / 'PyCharm2025.2/bin/pycharm.exe')
    touch(app / 'PyCharm2025.2/plugins/python/helpers/launcher.exe', b'MZ' + b'X' * 20000)
    return main


class PyCharmSelectionTests(unittest.TestCase):
    def test_nested_pycharm64_beats_32bit_and_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            main = layout(temp)
            engine = Portablizer(Logger())
            selected, targets = engine._discover_app_executables(str(Path(temp) / 'App'),
                                                                 'PyCharm_2025.2.3_x64-(IDEa)')
            self.assertEqual(Path(selected), main)
            self.assertTrue(any(t.rel_path.endswith('/launcher.exe') for t in targets))
            self.assertTrue(any(t.role == 'main' and t.rel_path.endswith('/pycharm64.exe') for t in targets))

    def test_uses_official_metadata_if_directory_and_title_are_generic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'App' / 'IDE'
            target = touch(root / 'bin/pycharm64.exe')
            (root / 'product-info.json').write_text(json.dumps({'name': 'PyCharm', 'productCode': 'PY'}))
            self.assertEqual(Path(pycharm.find_pycharm_executable(str(root.parent), 'Installer')), target)

    def test_no_guess_for_multiple_versions_and_unrelated_similar_name(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp) / 'App'
            touch(app / 'Other/bin/pycharm64.exe')
            self.assertIsNone(pycharm.find_pycharm_executable(str(app), 'Other'))
            touch(app / 'PyCharm2024/bin/pycharm64.exe')
            touch(app / 'PyCharm2025/bin/pycharm64.exe')
            self.assertIsNone(pycharm.find_pycharm_executable(str(app), 'PyCharm'))

    def test_all_default_aliases_target_ide_and_other_launchers_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'P-xrutvbei'
            main = layout(root)
            engine = Portablizer(Logger())
            selected, targets = engine._discover_app_executables(str(root / 'App'), 'PyCharm_2025')
            opts = PortableOptions(installer_path='setup.exe', output_dir=temp, app_name='PyCharm_2025')
            generated = engine._write_launcher(str(root), opts.app_name, os.path.relpath(selected, root),
                                               opts, [], targets=targets)
            cfg = json.loads((root / 'launcher_config.json').read_text(encoding='utf8'))
            rel = 'App/PyCharm2025.2/bin/pycharm64.exe'
            self.assertEqual(cfg['target_exe_rel'], rel)
            self.assertEqual(cfg['launcher_target_rel'], rel)
            self.assertEqual(cfg['launcher_aliases']['Launch_Launcher.exe'], rel)
            self.assertIn('Launch_Launcher.bat', generated)
            self.assertIn('Launch_Launcher.exe', generated)
            self.assertIn('Launch_Launcher_2.exe', generated)
            self.assertTrue(cfg['launcher_aliases']['Launch_Launcher_2.exe'].endswith('/launcher.exe'))
            self.assertIn('call "%~dp0Launch.bat"', (root / 'Launch_Launcher.bat').read_text('ascii'))
            self.assertEqual(engine._task_manager_name(str(root)), 'Launch P-xrutvbei')
            self.assertTrue((root / 'App' / 'Launch P-xrutvbei.exe').is_file())
            self.assertEqual(Path(selected), main)

    def test_main_alias_does_not_request_machine_registry(self):
        cfg = {'target_exe_rel': 'App/PyCharm/bin/pycharm64.exe',
               'launcher_aliases': {'Launch_Launcher.exe': 'App/PyCharm/bin/pycharm64.exe'}}
        args = entry._arguments_with_executable_alias(cfg, [], 'Launch_Launcher.exe')
        self.assertEqual(args, ['--target', cfg['target_exe_rel']])
        self.assertEqual(entry._select_target(cfg, args)[2], False)


class PyCharmRefreshTests(unittest.TestCase):
    def _existing(self, root):
        layout(root)
        cfg = launcher.LauncherConfig(app_name='PyCharm2025',
                                      target_exe_rel='App/PyCharm2025.2/bin/pycharm.exe',
                                      launcher_aliases={'Launch_Launcher.exe': 'App/helper/launcher.exe'})
        (Path(root) / 'launcher_config.json').write_text(launcher.render_config_json(cfg), encoding='utf8')
        (Path(root) / 'Launch_Launcher.bat').write_text('rem companion portable launcher\n', encoding='ascii')
        (Path(root) / 'PortableData').mkdir(exist_ok=True)
        (Path(root) / 'PortableData' / 'keep.txt').write_text('keep')

    def test_refresh_updates_generated_aliases_and_keeps_data(self):
        with tempfile.TemporaryDirectory() as temp:
            self._existing(temp)
            calls = []
            def copy(root, rel):
                calls.append(rel)
                return rel
            with mock.patch.object(maintenance.procutil, 'release_folder', return_value=[]):
                result = maintenance.refresh(temp, copy_exe=copy, shared_saves=False)
            cfg = json.loads(Path(temp, 'launcher_config.json').read_text(encoding='utf8'))
            self.assertTrue(result.success)
            self.assertEqual(cfg['target_exe_rel'], 'App/PyCharm2025.2/bin/pycharm64.exe')
            self.assertEqual(cfg['launcher_aliases']['Launch_Launcher.exe'], cfg['target_exe_rel'])
            self.assertIn('Launch_Launcher.exe', calls)
            self.assertIn('Portablizer main launcher alias', Path(temp, 'Launch_Launcher.bat').read_text())
            self.assertEqual(Path(temp, 'PortableData/keep.txt').read_text(), 'keep')

    def test_refresh_never_overwrites_foreign_alias_files(self):
        with tempfile.TemporaryDirectory() as temp:
            self._existing(temp)
            cfgpath = Path(temp, 'launcher_config.json')
            cfg = json.loads(cfgpath.read_text())
            cfg['launcher_aliases'] = {}
            cfgpath.write_text(json.dumps(cfg))
            Path(temp, 'Launch_Launcher.bat').write_text('my own script')
            Path(temp, 'Launch_Launcher.exe').write_text('my own binary')
            calls = []
            with mock.patch.object(maintenance.procutil, 'release_folder', return_value=[]):
                maintenance.refresh(temp, copy_exe=lambda root, name: calls.append(name) or name,
                                    shared_saves=False)
            self.assertEqual(Path(temp, 'Launch_Launcher.bat').read_text(), 'my own script')
            self.assertEqual(Path(temp, 'Launch_Launcher.exe').read_text(), 'my own binary')
            self.assertNotIn('Launch_Launcher.exe', calls)


@unittest.skipUnless(sys.platform == 'win32', 'Windows launcher execution test')
class WindowsPyCharmLauncherSmokeTests(unittest.TestCase):
    def test_all_five_frozen_launchers_start_nested_exe_in_its_own_directory(self):
        # A native stand-in, not PyCharm itself: verifies real Windows process
        # startup, onedir/onefile packaging, BAT handoff, aliases and cwd.
        csc = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        self.assertTrue(csc.is_file(), 'Windows C# compiler required for the launcher smoke test')
        with tempfile.TemporaryDirectory(prefix='pycharm launch ', ignore_cleanup_errors=True) as temp:
            base = Path(temp)
            source = base / 'probe.cs'
            source.write_text(r"""
using System;
using System.IO;
using System.Reflection;
class Probe {
  static void Main() {
    var root = Environment.GetEnvironmentVariable("PORTABLE_ROOT");
    File.WriteAllText(Path.Combine(root, "PortableData", "probe.txt"),
      Assembly.GetExecutingAssembly().Location + "\n" + Environment.CurrentDirectory);
  }
}
""", encoding='ascii')
            fixture = base / 'fixture.exe'
            compiled = subprocess.run([str(csc), '/nologo', '/target:winexe', '/out:' + str(fixture),
                                       str(source)], capture_output=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout.decode(errors='replace') +
                             compiled.stderr.decode(errors='replace'))
            launch_names = ['Launch.bat', 'Launch_Launcher.bat', 'Launch_Launcher.exe',
                            'App/Launch P-case3.exe', 'App/LaunchPortable.exe']
            roots = []
            processes = []
            env = dict(os.environ, PORTABLE_LAUNCHER_NO_UI='1')
            for index, launch_name in enumerate(launch_names):
                root = base / f'P-case{index}'
                target = root / 'App/PyCharm2025.2/bin/pycharm64.exe'
                target.parent.mkdir(parents=True)
                shutil.copyfile(fixture, target)
                shutil.copyfile(fixture, target.parent / 'pycharm.exe')
                helper = root / 'App/PyCharm2025.2/plugins/python/launcher.exe'
                helper.parent.mkdir(parents=True)
                shutil.copyfile(fixture, helper)
                engine = Portablizer(Logger())
                main, targets = engine._discover_app_executables(str(root / 'App'), 'PyCharm2025')
                opts = PortableOptions(installer_path='setup.exe', output_dir=str(base), app_name='PyCharm2025')
                engine._write_launcher(str(root), opts.app_name, os.path.relpath(main, root), opts, [], targets=targets)
                config = root / 'launcher_config.json'
                data = json.loads(config.read_text(encoding='utf8'))
                data['shutdown'] = {'spawn_grace': 0, 'idle_grace': 1, 'close_grace': 0,
                                    'deep_check': False, 'handle_budget': 0}
                config.write_text(json.dumps(data), encoding='utf8')
                path = root / launch_name
                self.assertTrue(path.is_file(), str(path))
                cmd = [os.environ['COMSPEC'], '/d', '/c', str(path)] if path.suffix == '.bat' else [str(path)]
                processes.append(subprocess.Popen(cmd, env=env, cwd=str(base)))
                roots.append((root, target, launch_name))
            def marker_ready(root):
                try:
                    return len((root / 'PortableData/probe.txt').read_text(encoding='utf-8-sig').splitlines()) >= 2
                except (OSError, UnicodeError):
                    return False
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and any(not marker_ready(r) for r, _, _ in roots):
                time.sleep(0.25)
            for root, target, launch_name in roots:
                marker = root / 'PortableData/probe.txt'
                log = root / 'PortableData/launcher-run.log'
                diagnostic = log.read_text(encoding='utf8', errors='replace') if log.exists() else '(no launcher log)'
                self.assertTrue(marker_ready(root), f'{launch_name} did not start target: {diagnostic}')
                exe, cwd = marker.read_text(encoding='utf-8-sig').splitlines()
                # Windows may return a canonical long name where TEMP used an
                # 8.3 spelling (RUNNER~1). Compare filesystem identity, not text.
                self.assertTrue(os.path.samefile(exe, target), (launch_name, exe, str(target)))
                self.assertTrue(os.path.samefile(cwd, target.parent), (launch_name, cwd, str(target.parent)))
            # Wait for detached BAT handoffs and their cleanups before deleting
            # the test roots; each session writes this at the end.
            while time.monotonic() < deadline:
                done = True
                for root, _, _ in roots:
                    log = root / 'PortableData/launcher-run.log'
                    text = log.read_text(encoding='utf8', errors='replace') if log.exists() else ''
                    if 'portable folder released:' not in text and 'WARNING: still running' not in text:
                        done = False
                        break
                if done:
                    break
                time.sleep(0.5)
            for proc in processes:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)


class PyCharmRelocationPortabilityTests(unittest.TestCase):
    """Перенос портатива PyCharm / JetBrains между любыми папками, дисками и ПК."""

    def test_relocated_readonly_vmoptions_and_legacy_suffix_config_are_repaired(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            old_root = base / "E_Drive" / "PyCharm_2025.2.3_x64-(IDE'a)_Portable"
            main = layout(old_root)
            jar = touch(old_root / "App/PyCharm2025.2/bin/ja-netfilter/ja-netfilter.jar", b"PK\x03\x04")
            vmopt_bin = old_root / "App/PyCharm2025.2/bin/pycharm64.exe.vmoptions"
            vmopt_bin.write_text(
                "-Xms256m\n"
                "-Xmx2048m\n"
                f"-javaagent:{str(jar).replace(os.sep, '/')}=jetbrains\n",
                encoding="utf-8",
            )
            os.chmod(vmopt_bin, 0o444)

            vmopt_user = (
                old_root
                / "PortableData/User/AppData/Roaming/JetBrains/PyCharm2025.2/pycharm64.exe.vmoptions"
            )
            vmopt_user.parent.mkdir(parents=True, exist_ok=True)
            vmopt_user.write_text(
                f"-javaagent:{jar}=jetbrains\n",
                encoding="utf-8",
            )
            os.chmod(vmopt_user, 0o444)

            entry.write_paths_stamp(old_root)

            new_root = base / "D_Drive" / "My Apps (x64)" / "PyCharm_Moved"
            new_root.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old_root), str(new_root))
            try:
                # Старый конфиг без .vmoptions в suffixes не должен мешать починке.
                legacy_cfg = {"relative_paths": {"suffixes": [".ini", ".json", ".xml"]}}
                report = entry.repair_paths(new_root, legacy_cfg)
                self.assertTrue(report)

                new_jar = new_root / "App/PyCharm2025.2/bin/ja-netfilter/ja-netfilter.jar"
                bin_text = (new_root / "App/PyCharm2025.2/bin/pycharm64.exe.vmoptions").read_text("utf-8")
                user_text = (
                    new_root
                    / "PortableData/User/AppData/Roaming/JetBrains/PyCharm2025.2/pycharm64.exe.vmoptions"
                ).read_text("utf-8")
                self.assertIn(str(new_jar).replace(os.sep, "/") + "=jetbrains", bin_text)
                self.assertNotIn("E_Drive", bin_text)
                self.assertIn(f"{new_jar}=jetbrains", user_text)
                self.assertNotIn("E_Drive", user_text)
            finally:
                for p in new_root.rglob("*.vmoptions"):
                    try:
                        os.chmod(p, 0o666)
                    except OSError:
                        pass

    def test_portabledata_and_bin_are_repaired_even_when_plugins_exceed_file_cap(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            old_root = base / "Build" / "PyCharm_Portable"
            layout(old_root)
            plugins = old_root / "App/PyCharm2025.2/plugins/huge"
            plugins.mkdir(parents=True, exist_ok=True)
            for idx in range(40):
                (plugins / f"plug_{idx:03d}.xml").write_text("<plugin/>", encoding="utf-8")

            jar = touch(old_root / "App/PyCharm2025.2/ja-netfilter/ja-netfilter.jar", b"PK")
            vmopt = old_root / "App/PyCharm2025.2/bin/pycharm64.exe.vmoptions"
            vmopt.write_text(f"-javaagent:{jar}=jetbrains\n", encoding="utf-8")
            other_xml = (
                old_root
                / "PortableData/User/AppData/Roaming/JetBrains/PyCharm2025.2/options/other.xml"
            )
            other_xml.parent.mkdir(parents=True, exist_ok=True)
            other_xml.write_text(f'<opt path="{old_root}/App"/>\n', encoding="utf-8")
            entry.write_paths_stamp(old_root)

            moved = base / "USB" / "PyCharm_Portable"
            moved.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old_root), str(moved))

            cfg = {"relative_paths": {"max_files": 10}}
            lines = entry.repair_paths(moved, cfg)
            self.assertTrue(lines)
            self.assertIn(
                str(moved),
                (moved / "PortableData/User/AppData/Roaming/JetBrains/PyCharm2025.2/options/other.xml").read_text("utf-8"),
            )
            self.assertIn(
                str(moved),
                (moved / "App/PyCharm2025.2/bin/pycharm64.exe.vmoptions").read_text("utf-8"),
            )

    def test_java_properties_colon_escape_and_copy_suffix_idempotency(self):
        if os.name == "nt":
            old_win = r"E:\Portable\PyCharm"
            new_win = r"D:\Portable\PyCharm"
        else:
            old_win = "E:\\Portable\\PyCharm"
            new_win = "D:\\Portable\\PyCharm"
        from portablizer.core import relpaths

        prop = r"idea.config.path=E\:\\Portable\\PyCharm\\PortableData\\config"
        fixed = relpaths.repair_text(prop, old_win, new_win)
        self.assertEqual(
            fixed, r"idea.config.path=D\:\\Portable\\PyCharm\\PortableData\\config"
        )

        # Копирование в «PyCharm - Copy» и повторный запуск --repair-paths
        # никогда не должны удваивать « - Copy».
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            src = base / "PyCharm_Portable"
            layout(src)
            vm = src / "App/PyCharm2025.2/bin/pycharm64.exe.vmoptions"
            vm.write_text(f"-javaagent:{src}/App/ja-netfilter.jar=jetbrains\n", encoding="utf-8")
            entry.write_paths_stamp(src)

            copied = base / "PyCharm_Portable - Copy"
            shutil.move(str(src), str(copied))
            entry.repair_paths(copied, {})
            once = (copied / "App/PyCharm2025.2/bin/pycharm64.exe.vmoptions").read_text("utf-8")
            entry.repair_paths(copied, {}, force=True, deep=True)
            twice = (copied / "App/PyCharm2025.2/bin/pycharm64.exe.vmoptions").read_text("utf-8")
            self.assertEqual(once, twice)
            self.assertNotIn(" - Copy - Copy", twice)

    def test_installer_environment_capture_and_host_cleanup_plan(self):
        from portablizer.core import registry as reg_mod

        port_dir = r"E:\Portable\PyCharm_Portable"
        before = {
            reg_mod.ENV_USER_KEY: {
                "KEEP_ME": (reg_mod.REG_SZ, repr(r"C:\Tools\keep")),
                "Path": (reg_mod.REG_EXPAND_SZ, repr(r"C:\Windows\System32")),
            }
        }
        after = {
            reg_mod.ENV_USER_KEY: {
                "KEEP_ME": (reg_mod.REG_SZ, repr(r"C:\Tools\keep")),
                "PYCHARM_VM_OPTIONS": (
                    reg_mod.REG_SZ,
                    repr(r"E:\Portable\PyCharm_Portable\App\ja-netfilter\vmoptions\pycharm.vmoptions"),
                ),
                "Path": (
                    reg_mod.REG_EXPAND_SZ,
                    repr(r"C:\Windows\System32;E:\Portable\PyCharm_Portable\App\PyCharm2025.2\bin"),
                ),
            }
        }
        extra_env, path_prepend, cleanup = reg_mod.extract_portable_environment(
            before, after, port_dir
        )
        self.assertEqual(
            extra_env["PYCHARM_VM_OPTIONS"],
            r"%PORTABLE_ROOT%\App\ja-netfilter\vmoptions\pycharm.vmoptions",
        )
        self.assertNotIn("KEEP_ME", extra_env)
        self.assertIn(r"App\PyCharm2025.2\bin", path_prepend)
        cleaned_names = {item[1]: item[2] for item in cleanup}
        self.assertIsNone(cleaned_names["PYCHARM_VM_OPTIONS"])
        self.assertEqual(cleaned_names["Path"], (reg_mod.REG_EXPAND_SZ, r"C:\Windows\System32"))

    def test_host_vmoptions_env_retargeted_or_isolated_and_stampless_heal_works(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            moved = base / "DiskF" / "PyCharm_Portable"
            target = layout(moved)
            jar = touch(moved / "App/ja-netfilter/ja-netfilter.jar", b"PK\x03\x04")
            standalone_vm = moved / "App/ja-netfilter/vmoptions/pycharm.vmoptions"
            standalone_vm.parent.mkdir(parents=True, exist_ok=True)
            standalone_vm.write_text(
                "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED\n"
                "-javaagent:E:/DeletedOldBuild/PyCharm_Portable/App/ja-netfilter/ja-netfilter.jar=jetbrains\n",
                encoding="utf-8",
            )
            key_src = moved / "PortableData/AppData/Roaming/JetBrains/PyCharm2025.2/pycharm.key"
            key_src.parent.mkdir(parents=True, exist_ok=True)
            key_src.write_bytes(b"FAKE-KEY-DATA")

            # 1) На сборочном ПК в os.environ остался старый мёртвый путь PYCHARM_VM_OPTIONS:
            stale_env = "E:\\DeletedOldBuild\\PyCharm_Portable\\App\\ja-netfilter\\vmoptions\\pycharm.vmoptions"
            with mock.patch.dict(os.environ, {"PYCHARM_VM_OPTIONS": stale_env, "IDEA_VM_OPTIONS": r"C:\Foreign\idea.vmoptions"}):
                env = entry._prepare_environment(moved, {})
                notes = entry._apply_jetbrains_profile(moved, {}, target)
                env = entry._jetbrains_environment(env, moved, {}, target)

            self.assertEqual(Path(env["PYCHARM_VM_OPTIONS"]), standalone_vm)
            # Чужая переменная хоста для другой установки убрана:
            self.assertNotIn("IDEA_VM_OPTIONS", env)
            # Даже без portable-root.json путь к ja-netfilter.jar в .vmoptions исправлен:
            self.assertTrue(notes)
            healed_text = standalone_vm.read_text("utf-8")
            self.assertIn(str(jar).replace(os.sep, "/") + "=jetbrains", healed_text)
            self.assertNotIn("DeletedOldBuild", healed_text)
            # Лицензионный ключ синхронизирован и в User\AppData\Roaming:
            mirrored_key = (
                moved / "PortableData/User/AppData/Roaming/JetBrains/PyCharm2025.2/pycharm.key"
            )
            self.assertTrue(mirrored_key.is_file())
            self.assertEqual(mirrored_key.read_bytes(), b"FAKE-KEY-DATA")

            # 2) На чистом втором ПК (без PYCHARM_VM_OPTIONS в os.environ) лончер и сборщик
            #    сами подхватывают автономный vmoptions с -javaagent:
            clean_os_env = {k: v for k, v in os.environ.items() if not k.endswith("_VM_OPTIONS")}
            with mock.patch.dict(os.environ, clean_os_env, clear=True):
                env2 = entry._prepare_environment(moved, {})
                env2 = entry._jetbrains_environment(env2, moved, {}, target)
            self.assertEqual(Path(env2["PYCHARM_VM_OPTIONS"]), standalone_vm)

            jb_env, _ = launcher.prepare_jetbrains_portable(
                str(moved), "App/PyCharm2025.2/bin/pycharm64.exe"
            )
            self.assertEqual(
                jb_env.get("PYCHARM_VM_OPTIONS"),
                r"%PORTABLE_ROOT%\App\ja-netfilter\vmoptions\pycharm.vmoptions",
            )


if __name__ == '__main__':
    unittest.main()
