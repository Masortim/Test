"""Тесты распространяемых компонентов (VC++, DirectX и родственники).

Проверяемая жалоба пользователя: «Запуск программы невозможен, так как на
компьютере отсутствует XINPUT1_3.dll / d3dx9_38.dll / MSVCP110.dll /
MSVCR110.dll / d3dx9_39.dll / MSVCP100.dll / MSVCR100.dll». Такие ошибки не
должны возникать «изначально»: Portablizer обязан заранее выяснить, что нужно
программе, принести это в портатив, а остаток честно назвать по имени пакета.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import batsim
import portable_launcher_entry as exe_launcher
from pebuild import MACHINE_X64, MACHINE_X86, write_pe, write_runtime_dll
from portablizer.core import redist
from portablizer.core.launcher import (
    LauncherConfig, ensure_ascii_bat, render_bat, render_config_json,
)
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer

#: Ровно тот список, с которого начался разговор.
USER_REPORTED = (
    "XINPUT1_3.dll", "d3dx9_38.dll", "MSVCP110.dll", "MSVCR110.dll",
    "d3dx9_39.dll", "MSVCP100.dll", "MSVCR100.dll",
)


class PEImportTests(unittest.TestCase):
    """Список зависимостей берётся из PE, а не из догадок по именам."""

    def test_imports_and_delay_imports_are_read(self):
        with tempfile.TemporaryDirectory() as temp:
            path = write_pe(
                Path(temp, "game.exe"),
                imports=("KERNEL32.dll", "MSVCP110.dll", "d3dx9_39.dll"),
                delay_imports=("XINPUT1_3.dll",))
            info = redist.read_pe_imports(path)

            self.assertTrue(info.is_pe)
            self.assertEqual(info.machine, "x86")
            self.assertIn("msvcp110.dll", info.imports)
            self.assertIn("d3dx9_39.dll", info.imports)
            # Отложенный импорт отдельно: XInput почти всегда грузится так,
            # и ошибка всплывает уже в игре, а не при старте.
            self.assertEqual(info.delay_imports, ["xinput1_3.dll"])
            self.assertIn("xinput1_3.dll", info.all_imports)

    def test_64bit_binary_is_recognised(self):
        with tempfile.TemporaryDirectory() as temp:
            path = write_pe(Path(temp, "game64.exe"),
                            imports=("kernel32.dll", "msvcp140.dll"),
                            machine=MACHINE_X64)
            info = redist.read_pe_imports(path)
            self.assertEqual(info.machine, "x64")

    def test_dotnet_assembly_is_flagged(self):
        with tempfile.TemporaryDirectory() as temp:
            path = write_pe(Path(temp, "app.exe"), imports=("mscoree.dll",),
                            dotnet=True)
            self.assertTrue(redist.read_pe_imports(path).is_dotnet)

    def test_garbage_file_is_not_parsed_and_does_not_raise(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "broken.exe")
            path.write_bytes(b"MZ" + b"\xff" * 512)
            info = redist.read_pe_imports(str(path))
            self.assertFalse(info.imports)

    def test_embedded_manifest_is_extracted(self):
        manifest = (
            '<?xml version="1.0"?><assembly '
            'xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
            '<dependency><dependentAssembly><assemblyIdentity type="win32" '
            'name="Microsoft.VC90.CRT" version="9.0.21022.8" '
            'processorArchitecture="x86" publicKeyToken="1fc8b3b9a1e18e3b"/>'
            '</dependentAssembly></dependency></assembly>')
        with tempfile.TemporaryDirectory() as temp:
            path = write_pe(Path(temp, "old.exe"), imports=("msvcr90.dll",),
                            manifest=manifest)
            identity = redist.manifest_identity(
                redist.read_pe_manifest(path), "Microsoft.VC90.CRT")
            self.assertEqual(identity["version"], "9.0.21022.8")
            self.assertEqual(identity["publicKeyToken"], "1fc8b3b9a1e18e3b")


class RedistCatalogTests(unittest.TestCase):
    """Каталог обязан знать все библиотеки из жалобы — и их соседей."""

    def test_every_library_from_the_user_report_is_known(self):
        for name in USER_REPORTED:
            with self.subTest(dll=name):
                package = redist.find_package(name)
                self.assertIsNotNone(
                    package, f"{name} не опознана как часть пакета")
                self.assertTrue(package.title)
                self.assertTrue(package.url("x86").startswith("http")
                                or package.page.startswith("http"))

    def test_libraries_are_mapped_to_the_right_package(self):
        cases = {
            "msvcr100.dll": "vc2010", "msvcp100.dll": "vc2010",
            "msvcr110.dll": "vc2012", "msvcp110.dll": "vc2012",
            "msvcr120.dll": "vc2013", "msvcp120.dll": "vc2013",
            "msvcr90.dll": "vc2008", "msvcr80.dll": "vc2005",
            "msvcr71.dll": "vc_legacy",
            "vcruntime140.dll": "vc14", "msvcp140.dll": "vc14",
            "ucrtbase.dll": "vc14",
            "api-ms-win-crt-runtime-l1-1-0.dll": "vc14",
            "concrt140.dll": "vc14", "mfc120u.dll": "vc2013",
            "xinput1_3.dll": "directx_jun2010",
            "d3dx9_38.dll": "directx_jun2010",
            "d3dx9_39.dll": "directx_jun2010",
            "d3dx9_43.dll": "directx_jun2010",
            "d3dx10_43.dll": "directx_jun2010",
            "d3dx11_43.dll": "directx_jun2010",
            "xaudio2_7.dll": "directx_jun2010",
            "x3daudio1_7.dll": "directx_jun2010",
            "d3dcompiler_43.dll": "directx_jun2010",
            "openal32.dll": "openal",
            "physxloader.dll": "physx",
        }
        for dll, key in cases.items():
            with self.subTest(dll=dll):
                package = redist.find_package(dll)
                self.assertIsNotNone(package, dll)
                self.assertEqual(package.key, key)

    def test_case_and_path_do_not_matter(self):
        self.assertEqual(redist.normalize_dll(r"C:\Windows\XINPUT1_3.DLL"),
                         "xinput1_3.dll")
        self.assertIsNotNone(redist.find_package("XINPUT1_3.DLL"))

    def test_windows_own_libraries_are_not_treated_as_redistributable(self):
        for name in ("kernel32.dll", "user32.dll", "d3d9.dll", "dxgi.dll",
                     "xinput1_4.dll", "xinput9_1_0.dll", "msvcrt.dll",
                     "api-ms-win-core-file-l1-1-0.dll", "opengl32.dll"):
            with self.subTest(dll=name):
                self.assertEqual(redist.classify_dll(name), "system", name)

    def test_ucrt_stubs_belong_to_the_runtime_not_to_windows_apisets(self):
        # api-ms-win-crt-* приносит vcredist, а api-ms-win-core-* — Windows.
        self.assertEqual(
            redist.classify_dll("api-ms-win-crt-math-l1-1-0.dll"), "redist")
        self.assertEqual(
            redist.classify_dll("api-ms-win-core-synch-l1-2-0.dll"), "system")

    def test_unknown_library_stays_unknown(self):
        self.assertEqual(redist.classify_dll("binkw32.dll"), "unknown")

    def test_download_links_are_official_and_usable(self):
        for package in redist.REDIST_PACKAGES:
            for arch, url in package.downloads.items():
                with self.subTest(package=package.key, arch=arch):
                    self.assertTrue(url.startswith("https://"), url)
                    self.assertTrue(
                        url.split("/")[2].endswith(
                            ("microsoft.com", "aka.ms", "visualstudio.com")),
                        url)
                    # Ссылка попадает в .bat, поэтому только ASCII без
                    # символов, которые cmd.exe считает операторами.
                    self.assertTrue(url.isascii())
                    self.assertFalse(set(url) & set('"%&|<>^()'))

    def test_every_package_has_a_readable_ascii_name_for_the_bat(self):
        # Launch.bat обязан быть чистым ASCII, а «DirectX End-User Runtime
        # (июнь 2010)» после вырезания кириллицы превратится в огрызок.
        for package in redist.REDIST_PACKAGES:
            plain = package.plain_title()
            self.assertTrue(plain.isascii(), package.key)
            self.assertNotIn("  ", plain, package.key)
            self.assertGreater(len(plain), 5, package.key)

    def test_sxs_assembly_names(self):
        vc90 = redist.find_package("msvcr90.dll")
        self.assertEqual(redist.sxs_assembly_for("msvcr90.dll", vc90),
                         "Microsoft.VC90.CRT")
        self.assertEqual(redist.sxs_assembly_for("mfc90u.dll", vc90),
                         "Microsoft.VC90.MFC")


class RuntimeScanTests(unittest.TestCase):
    """Сканирование папки App: что нужно, что уже есть, что даёт Windows."""

    def _app(self, temp):
        app = Path(temp, "App")
        app.mkdir(parents=True)
        return app

    def test_requirements_are_split_by_status(self):
        with tempfile.TemporaryDirectory() as temp:
            app = self._app(temp)
            write_pe(app / "game.exe",
                     imports=("KERNEL32.dll", "MSVCP110.dll", "engine.dll",
                              "d3dx9_43.dll"),
                     delay_imports=("XINPUT1_3.dll",))
            write_pe(app / "engine.dll", imports=("kernel32.dll",))
            write_runtime_dll(app / "d3dx9_43.dll")

            scan = redist.scan_app_runtime(str(app))
            status = {r.dll: r.status for r in scan.requirements}

            self.assertEqual(status["kernel32.dll"], "system")
            self.assertEqual(status["engine.dll"], "bundled")
            self.assertEqual(status["d3dx9_43.dll"], "bundled")
            self.assertEqual(status["msvcp110.dll"], "missing")
            self.assertEqual(status["xinput1_3.dll"], "missing")
            self.assertEqual(scan.arch, "x86")
            self.assertEqual({r.dll for r in scan.needed},
                             {"msvcp110.dll", "xinput1_3.dll"})

    def test_delay_only_libraries_are_marked(self):
        with tempfile.TemporaryDirectory() as temp:
            app = self._app(temp)
            write_pe(app / "game.exe", imports=("msvcr110.dll",),
                     delay_imports=("xinput1_3.dll",))
            scan = redist.scan_app_runtime(str(app))
            flags = {r.dll: r.delay_only for r in scan.requirements}
            self.assertTrue(flags["xinput1_3.dll"])
            self.assertFalse(flags["msvcr110.dll"])

    def test_importers_are_remembered_for_the_report(self):
        with tempfile.TemporaryDirectory() as temp:
            app = self._app(temp)
            (app / "bin").mkdir()
            write_pe(app / "bin" / "tool.exe", imports=("msvcp100.dll",))
            scan = redist.scan_app_runtime(str(app))
            requirement = next(r for r in scan.requirements
                               if r.dll == "msvcp100.dll")
            self.assertEqual(requirement.importers, ["bin/tool.exe"])

    def test_our_own_launcher_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            app = self._app(temp)
            write_pe(app / "LaunchPortable.exe", imports=("msvcp140.dll",))
            write_pe(app / "game.exe", imports=("kernel32.dll",))
            scan = redist.scan_app_runtime(str(app))
            self.assertNotIn("msvcp140.dll",
                             {r.dll for r in scan.requirements})

    def test_bundled_copy_of_the_wrong_bitness_does_not_count(self):
        with tempfile.TemporaryDirectory() as temp:
            app = self._app(temp)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))
            (app / "redist" / "x64").mkdir(parents=True)
            write_runtime_dll(app / "redist" / "x64" / "msvcp110.dll",
                              machine=MACHINE_X64)

            scan = redist.scan_app_runtime(str(app))
            requirement = next(r for r in scan.requirements
                               if r.dll == "msvcp110.dll")
            self.assertEqual(requirement.status, "missing")

    def test_missing_app_directory_is_safe(self):
        scan = redist.scan_app_runtime("/definitely/not/here")
        self.assertEqual(scan.requirements, [])


class RuntimeProvisionTests(unittest.TestCase):
    """Лестница источников: комплект установщика → система → WinSxS."""

    def setUp(self):
        self.log = Logger()

    def _portable(self, temp):
        portable = Path(temp, "Game_Portable")
        app = portable / "App"
        app.mkdir(parents=True)
        return portable, app

    def test_files_from_system_folder_land_next_to_the_program(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe",
                     imports=("MSVCR110.dll", "MSVCP110.dll"),
                     delay_imports=("XINPUT1_3.dll",))
            system = Path(temp, "FakeSystem")
            system.mkdir()
            for name in ("msvcr110.dll", "msvcp110.dll", "xinput1_3.dll"):
                write_runtime_dll(system / name)

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[str(system)], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual(report.missing, [])
            self.assertEqual({r.dll for r in report.provided},
                             {"msvcr110.dll", "msvcp110.dll", "xinput1_3.dll"})
            for name in ("msvcr110.dll", "msvcp110.dll", "xinput1_3.dll"):
                self.assertTrue((app / name).is_file(), name)

    def test_wrong_architecture_is_never_copied(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("msvcp100.dll",),
                     machine=MACHINE_X86)
            system = Path(temp, "FakeSystem")
            system.mkdir()
            # 64-битная библиотека для 32-битной игры бесполезна и опасна:
            # Windows ответит «не является приложением Win32».
            write_runtime_dll(system / "msvcp100.dll", machine=MACHINE_X64)

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[str(system)], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game")

            self.assertFalse((app / "msvcp100.dll").exists())
            self.assertEqual([r.dll for r in report.missing], ["msvcp100.dll"])

    def test_redist_folder_shipped_with_the_installer_is_preferred(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("msvcr100.dll",))
            shipped = Path(temp, "_CommonRedist", "vcredist", "2010")
            shipped.mkdir(parents=True)
            write_runtime_dll(shipped / "msvcr100.dll")

            sources = redist.installer_source_dirs(
                str(Path(temp, "setup.exe")), str(app))
            self.assertTrue(sources)

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, source_dirs=sources, system_dirs=[], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual([r.dll for r in report.provided], ["msvcr100.dll"])
            self.assertEqual(report.provided[0].source, "комплект установщика")
            self.assertTrue((app / "msvcr100.dll").is_file())

    def test_library_is_copied_next_to_every_importer(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            (app / "bin").mkdir()
            write_pe(app / "game.exe", imports=("msvcr110.dll",))
            write_pe(app / "bin" / "tool.exe", imports=("msvcr110.dll",))
            system = Path(temp, "FakeSystem")
            system.mkdir()
            write_runtime_dll(system / "msvcr110.dll")

            scan = redist.scan_app_runtime(str(app))
            redist.RuntimeProvisioner(
                self.log, system_dirs=[str(system)], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game")

            self.assertTrue((app / "msvcr110.dll").is_file())
            self.assertTrue((app / "bin" / "msvcr110.dll").is_file())

    def test_library_hidden_in_a_service_folder_is_moved_next_to_the_exe(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("msvcr110.dll",))
            (app / "redist").mkdir()
            write_runtime_dll(app / "redist" / "msvcr110.dll")

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game")

            # Загрузчик Windows не заглядывает в App\redist: копия обязана
            # оказаться рядом с самим exe.
            self.assertTrue((app / "msvcr110.dll").is_file())
            self.assertEqual([r.dll for r in report.bundled], ["msvcr110.dll"])
            self.assertEqual(report.missing, [])

    def test_ucrt_base_follows_the_api_ms_stubs(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe",
                     imports=("api-ms-win-crt-runtime-l1-1-0.dll",
                              "vcruntime140.dll"))
            system = Path(temp, "FakeSystem")
            system.mkdir()
            for name in ("api-ms-win-crt-runtime-l1-1-0.dll",
                         "vcruntime140.dll", "ucrtbase.dll"):
                write_runtime_dll(system / name)

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[str(system)], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game")

            # Заглушка api-ms-win-crt-* сама по себе бесполезна: она лишь
            # переадресует вызовы в ucrtbase.dll, которого на Windows 7 нет.
            self.assertTrue((app / "ucrtbase.dll").is_file())
            self.assertIn("ucrtbase.dll", [r.dll for r in report.provided])

    def test_sxs_assembly_is_deployed_with_a_private_manifest(self):
        manifest = (
            '<?xml version="1.0"?><assembly '
            'xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
            '<dependency><dependentAssembly><assemblyIdentity type="win32" '
            'name="Microsoft.VC90.CRT" version="9.0.21022.8" '
            'processorArchitecture="x86" publicKeyToken="1fc8b3b9a1e18e3b"/>'
            '</dependentAssembly></dependency></assembly>')
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "old.exe", imports=("MSVCR90.dll",),
                     manifest=manifest)
            sxs = Path(temp, "WinSxS")
            folder = sxs / ("x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_"
                            "9.0.30729.9635_none_508ed732bcbc0e5a")
            folder.mkdir(parents=True)
            write_runtime_dll(folder / "msvcr90.dll")

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir=str(sxs),
            ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual([r.dll for r in report.provided], ["msvcr90.dll"])
            self.assertTrue((app / "msvcr90.dll").is_file())
            # Без private-манифеста Windows игнорирует копию рядом с exe и
            # сообщает «параллельная конфигурация неправильна».
            written = (app / "Microsoft.VC90.CRT.manifest").read_text(
                encoding="utf-8")
            self.assertIn('name="Microsoft.VC90.CRT"', written)
            self.assertIn('version="9.0.21022.8"', written)
            self.assertIn('<file name="msvcr90.dll"/>', written)

    def test_download_is_only_used_when_allowed(self):
        calls = []

        def downloader(url, destination):
            calls.append(url)
            return False

        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))
            scan = redist.scan_app_runtime(str(app))

            redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir="", allow_download=False,
                downloader=downloader,
            ).provision(scan, str(app), str(portable), "Game")
            self.assertEqual(calls, [])

            scan = redist.scan_app_runtime(str(app))
            redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir="", allow_download=True,
                downloader=downloader,
            ).provision(scan, str(app), str(portable), "Game")
            self.assertEqual(len(calls), 1)
            self.assertIn("vcredist_x86.exe", calls[0])

    def test_directx_package_is_unpacked_and_only_the_needed_cab_is_touched(self):
        """Из пакета DirectX достаётся ровно нужный кабинет.

        В ``directx_Jun2010_redist.exe`` около сотни кабинетов; разворачивать
        их все ради одной ``d3dx9_39.dll`` — минуты впустую. Имя библиотеки
        входит в имя кабинета, этим и пользуемся.
        """
        calls = []

        def runner(args):
            calls.append(list(args))
            if args[0].lower().endswith("directx_jun2010_redist.exe"):
                target = args[-1].split(":", 1)[1]
                os.makedirs(target, exist_ok=True)
                for cab in ("Jun2010_d3dx9_39_x86.cab",
                            "Jun2010_d3dx9_43_x86.cab",
                            "APR2007_xinput_x86.cab"):
                    Path(target, cab).write_bytes(b"MSCF fake cabinet")
                return 0
            if args[0] == "expand":
                cab = Path(args[-2])
                name = cab.name.lower().replace("jun2010_", "")
                write_runtime_dll(Path(args[-1],
                                       name.replace("_x86.cab", ".dll")))
                return 0
            return 1

        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("d3dx9_39.dll",))
            shipped = Path(temp, "_CommonRedist", "DirectX")
            shipped.mkdir(parents=True)
            (shipped / "directx_Jun2010_redist.exe").write_bytes(b"MZ self-x")

            scan = redist.scan_app_runtime(str(app))
            with mock.patch.object(redist, "IS_WINDOWS", True):
                report = redist.RuntimeProvisioner(
                    self.log, source_dirs=[str(shipped)], system_dirs=[],
                    sxs_dir="", runner=runner,
                ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual([r.dll for r in report.provided],
                             ["d3dx9_39.dll"])
            self.assertTrue((app / "d3dx9_39.dll").is_file())
            expanded = [c[-2] for c in calls if c[0] == "expand"]
            self.assertEqual(len(expanded), 1, expanded)
            self.assertIn("d3dx9_39", expanded[0])

    def test_downloaded_package_is_kept_as_an_offline_fallback(self):
        def downloader(url, destination):
            Path(destination).write_bytes(b"MZ fake vcredist")
            return True

        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))
            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir="", allow_download=True,
                downloader=downloader,
            ).provision(scan, str(app), str(portable), "Game")

            # Распаковать пакет без Windows нельзя, но сам он уже скачан:
            # пользователю остаётся запустить его на целевом ПК без интернета.
            self.assertEqual(report.packages, ["vcredist_x86.exe"])
            self.assertTrue((portable / redist.REDIST_DIR_NAME
                             / "vcredist_x86.exe").is_file())
            self.assertIn("Redist", redist.render_report(report))

    def test_report_names_the_package_and_the_link(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("MSVCP110.dll",),
                     delay_imports=("XINPUT1_3.dll",))
            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Игра")

            text = redist.render_report(report)
            self.assertIn("msvcp110.dll", text)
            self.assertIn("Visual C++ 2012", text)
            self.assertIn("xinput1_3.dll", text)
            self.assertIn("DirectX", text)
            self.assertIn("vcredist_x86.exe", text)

            requirements = redist.launcher_requirements(report)
            self.assertEqual({item["dll"] for item in requirements},
                             {"msvcp110.dll", "xinput1_3.dll"})
            for item in requirements:
                self.assertTrue(item["url"].startswith("https://"))

    def test_dotnet_program_gets_an_explanation_instead_of_a_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "app.exe", imports=("mscoree.dll",), dotnet=True)
            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir="",
            ).provision(scan, str(app), str(portable), "App")
            self.assertTrue(any(".NET" in note for note in report.notes))


class RuntimeLauncherTests(unittest.TestCase):
    """Предстартовая проверка в Launch.bat и в LaunchPortable.exe."""

    REQUIREMENTS = [
        {"dll": "msvcp110.dll",
         "title": "Microsoft Visual C++ 2012 Update 4 Redistributable",
         "url": "https://download.microsoft.com/download/1/6/B/vcredist_x86.exe",
         "arch": "x86"},
        {"dll": "xinput1_3.dll",
         "title": "DirectX End-User Runtime (June 2010)",
         "url": "https://download.microsoft.com/download/8/4/A/dx.exe",
         "arch": "x86"},
    ]
    ROOT = r"E:\Games\Game_Portable"

    def _cfg(self, requirements=None):
        return LauncherConfig(
            app_name="Тестовая игра",
            target_exe_rel="App/game.exe",
            apply_registry=False,
            runtime_requirements=(self.REQUIREMENTS if requirements is None
                                  else requirements),
        )

    def _fs(self, present=()):
        fs = batsim.FakeFS()
        fs.add_file(rf"{self.ROOT}\Launch.bat", "")
        fs.add_file(rf"{self.ROOT}\App\game.exe", "MZ")
        for name in present:
            fs.add_file(rf"{self.ROOT}\App\{name}", "MZ")
        return fs

    def _run(self, cfg, fs, argv=()):
        bat = render_bat(cfg)
        fs.add_file(rf"{self.ROOT}\Launch.bat", bat)
        return batsim.run_batch(bat, rf"{self.ROOT}\Launch.bat", fs,
                                argv=list(argv) + ["--nopause"])

    def test_bat_with_runtime_check_is_still_pure_ascii(self):
        bat = render_bat(self._cfg())
        self.assertTrue(bat.isascii())
        ensure_ascii_bat(bat)

    def test_missing_library_is_named_before_the_program_starts(self):
        result = self._run(self._cfg(), self._fs())
        self.assertIn("msvcp110.dll", result.text)
        self.assertIn("Visual C++ 2012", result.text)
        self.assertIn("xinput1_3.dll", result.text)
        self.assertIn("redistributables.txt", result.text)
        # Предупреждение не отменяет запуск: часть библиотек грузится по
        # требованию, и программа вполне может работать.
        self.assertTrue(result.launched)

    def test_no_warning_when_the_library_lies_next_to_the_program(self):
        fs = self._fs(present=("msvcp110.dll", "xinput1_3.dll"))
        result = self._run(self._cfg(), fs)
        self.assertNotIn("missing Microsoft runtime", result.text)
        self.assertTrue(result.launched)

    def test_no_warning_when_windows_provides_the_library(self):
        fs = self._fs()
        fs.add_file(r"C:\Windows\System32\msvcp110.dll", "MZ")
        fs.add_file(r"C:\Windows\SysWOW64\xinput1_3.dll", "MZ")
        bat = render_bat(self._cfg())
        fs.add_file(rf"{self.ROOT}\Launch.bat", bat)
        result = batsim.run_batch(bat, rf"{self.ROOT}\Launch.bat", fs,
                                  argv=["--nopause"],
                                  env={"SystemRoot": r"C:\Windows"})
        self.assertNotIn("missing Microsoft runtime", result.text)
        self.assertTrue(result.launched)

    def test_program_without_requirements_gets_no_check_calls(self):
        bat = render_bat(self._cfg(requirements=[]))
        self.assertIn("needs no extra Microsoft runtime", bat)
        result = self._run(self._cfg(requirements=[]), self._fs())
        self.assertTrue(result.launched)

    def test_requirements_travel_in_the_launcher_config(self):
        data = json.loads(render_config_json(self._cfg()))
        self.assertEqual(
            [item["dll"] for item in data["runtime_requirements"]],
            ["msvcp110.dll", "xinput1_3.dll"])

    def test_exe_launcher_reports_only_what_is_really_absent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Game_Portable")
            app = root / "App"
            app.mkdir(parents=True)
            (app / "game.exe").write_bytes(b"MZ")
            (app / "xinput1_3.dll").write_bytes(b"MZ")
            cfg = {"runtime_requirements": self.REQUIREMENTS}

            missing = exe_launcher.missing_runtime_components(
                root, cfg, app / "game.exe", {"PATH": ""})

            self.assertEqual([item["dll"] for item in missing],
                             ["msvcp110.dll"])

    def test_warning_is_shown_once_and_repeats_on_another_pc(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Game_Portable")
            (root / "PortableData").mkdir(parents=True)
            cfg = {"data_dir_name": "PortableData"}
            first = [{"dll": "msvcr110.dll"}, {"dll": "xinput1_3.dll"}]

            self.assertTrue(
                exe_launcher._runtime_warning_is_new(root, cfg, first))
            # Тот же портатив, тот же ПК: второй раз молчим.
            self.assertFalse(
                exe_launcher._runtime_warning_is_new(root, cfg, first))
            self.assertFalse(exe_launcher._runtime_warning_is_new(
                root, cfg, list(reversed(first))))
            # Другой компьютер — другой набор: предупреждаем снова.
            self.assertTrue(exe_launcher._runtime_warning_is_new(
                root, cfg, first + [{"dll": "d3dx9_39.dll"}]))

    def test_exe_launcher_accepts_libraries_found_through_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Game_Portable")
            app = root / "App"
            (app / "bin").mkdir(parents=True)
            (app / "game.exe").write_bytes(b"MZ")
            (app / "bin" / "msvcp110.dll").write_bytes(b"MZ")
            (app / "bin" / "xinput1_3.dll").write_bytes(b"MZ")
            cfg = {"runtime_requirements": self.REQUIREMENTS}

            missing = exe_launcher.missing_runtime_components(
                root, cfg, app / "game.exe", {"PATH": str(app / "bin")})

            self.assertEqual(missing, [])


class PortablizerRuntimeIntegrationTests(unittest.TestCase):
    """Полный проход: установка → перенос библиотек → лончер и отчёт."""

    class FakePortablizer(Portablizer):
        def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
            write_pe(Path(app_dir, "Game.exe"),
                     imports=("KERNEL32.dll", "MSVCR100.dll", "MSVCP110.dll"),
                     delay_imports=("XINPUT1_3.dll",))
            return 0

    def _build(self, temp, **options):
        installer = Path(temp, "GameSetup.exe")
        installer.write_bytes(b"MZ Inno Setup")
        engine = self.FakePortablizer(Logger())
        with mock.patch("portablizer.core.portablizer.IS_WINDOWS", False):
            result = engine.run(PortableOptions(
                installer_path=str(installer), output_dir=temp,
                app_name="Game", capture_registry=False, **options))
        return result, Path(temp, "Game_Portable")

    def test_bundled_library_is_copied_and_the_rest_is_documented(self):
        with tempfile.TemporaryDirectory() as temp:
            # Repack-сборка принесла с собой только VC++ 2010.
            shipped = Path(temp, "_CommonRedist", "vcredist", "2010")
            shipped.mkdir(parents=True)
            write_runtime_dll(shipped / "msvcr100.dll")

            result, portable = self._build(temp)

            self.assertTrue(result.success)
            self.assertIn("msvcr100.dll", result.runtime_provided)
            self.assertTrue((portable / "App" / "msvcr100.dll").is_file())
            self.assertEqual(sorted(result.runtime_missing),
                             ["msvcp110.dll", "xinput1_3.dll"])

            report = (portable / redist.REPORT_NAME).read_text(
                encoding="utf-8-sig")
            self.assertIn("msvcp110.dll", report)
            self.assertIn("Visual C++ 2012", report)

            config = json.loads(
                (portable / "launcher_config.json").read_text(encoding="utf-8"))
            self.assertEqual(
                sorted(item["dll"] for item in config["runtime_requirements"]),
                ["msvcp110.dll", "xinput1_3.dll"])

            bat = (portable / "Launch.bat").read_bytes()
            self.assertTrue(all(byte < 128 for byte in bat))
            self.assertIn(b"msvcp110.dll", bat)

            readme = (portable / "README_PORTABLE.txt").read_text(
                encoding="utf-8")
            self.assertIn(redist.REPORT_NAME, readme)

    def test_feature_can_be_switched_off(self):
        with tempfile.TemporaryDirectory() as temp:
            result, portable = self._build(temp, bundle_runtimes=False)
            self.assertTrue(result.success)
            self.assertEqual(result.runtime_provided, [])
            self.assertFalse((portable / redist.REPORT_NAME).exists())
            config = json.loads(
                (portable / "launcher_config.json").read_text(encoding="utf-8"))
            self.assertEqual(config["runtime_requirements"], [])

    def test_stale_report_is_removed_on_rebuild(self):
        with tempfile.TemporaryDirectory() as temp:
            _result, portable = self._build(temp)
            self.assertTrue((portable / redist.REPORT_NAME).is_file())

            class CleanPortablizer(Portablizer):
                def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                    Path(app_dir, "Game.exe").write_bytes(b"MZ plain")
                    return 0

            installer = Path(temp, "GameSetup.exe")
            with mock.patch("portablizer.core.portablizer.IS_WINDOWS", False):
                CleanPortablizer(Logger()).run(PortableOptions(
                    installer_path=str(installer), output_dir=temp,
                    app_name="Game", capture_registry=False))
            self.assertFalse((portable / redist.REPORT_NAME).exists())


class GuiWiringTests(unittest.TestCase):
    """Галочки окна должны действительно доходить до сборщика.

    Qt в окружении тестов нет (нет libGL), поэтому окно разбирается как
    исходный текст: важно, что опции существуют, включены по умолчанию там,
    где нужно, и передаются в ``PortableOptions``.
    """

    @classmethod
    def setUpClass(cls):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "portablizer", "gui", "main_window.py")
        with open(path, encoding="utf-8") as handle:
            cls.source = handle.read()

    def test_checkboxes_exist_and_runtimes_are_on_by_default(self):
        self.assertIn("self.cb_runtimes = QCheckBox(", self.source)
        self.assertIn("self.cb_runtimes.setChecked(True)", self.source)
        self.assertIn("self.cb_fetch_runtimes = QCheckBox(", self.source)
        # Скачивание — только по явному согласию пользователя.
        self.assertNotIn("self.cb_fetch_runtimes.setChecked(True)",
                         self.source)

    def test_options_are_passed_to_the_builder(self):
        self.assertIn("bundle_runtimes=self.cb_runtimes.isChecked()",
                      self.source)
        self.assertIn("download_runtimes=", self.source)
        self.assertIn("self.cb_fetch_runtimes.isChecked()", self.source)
        for name in ("PortableOptions", "bundle_runtimes",
                     "download_runtimes"):
            self.assertIn(name, self.source)

    def test_options_exist_in_the_builder_dataclass(self):
        names = PortableOptions.__dataclass_fields__
        self.assertIn("bundle_runtimes", names)
        self.assertIn("download_runtimes", names)
        defaults = PortableOptions(installer_path="x", output_dir="y")
        self.assertTrue(defaults.bundle_runtimes)
        self.assertFalse(defaults.download_runtimes)

    def test_result_of_the_build_is_shown_to_the_user(self):
        for name in ("result.runtime_provided", "result.runtime_missing",
                     "result.runtime_packages", "result.runtime_report_rel"):
            self.assertIn(name, self.source)


if __name__ == "__main__":
    unittest.main()
