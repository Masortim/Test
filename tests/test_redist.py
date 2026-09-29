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
from cabbuild import make_cabinet, make_self_extracting_exe
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
            # Основная ссылка не сработала - перебираются запасные, но
            # каждая ровно один раз и только в пределах этого пакета.
            self.assertGreaterEqual(len(calls), 1)
            self.assertIn("vcredist_x86.exe", calls[0])
            self.assertEqual(len(calls), len(set(calls)))

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
            # Правдоподобный по сигнатуре и размеру пакет, но без кабинета
            # внутри: распаковать его не выйдет ни одним способом.
            Path(destination).write_bytes(b"MZ" + b"\x00" * (128 * 1024))
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


class FullKitCatalogTests(unittest.TestCase):
    """Каталог полного комплекта: все варианты должны быть предусмотрены."""

    def test_every_library_from_the_user_report_is_in_the_kit(self):
        members = {r.dll for r in redist.full_kit_requirements(("x86", "x64"))}
        for name in USER_REPORTED:
            with self.subTest(dll=name):
                self.assertIn(redist.normalize_dll(name), members)

    def test_kit_names_are_recognised_by_their_own_packages(self):
        # Имя из комплекта обязано опознаваться каталогом: иначе классификация
        # и отчёт разойдутся с тем, что реально приносит провижинер.
        for requirement in redist.full_kit_requirements(("x86", "x64", "arm64")):
            with self.subTest(dll=requirement.dll, arch=requirement.arch):
                self.assertIs(requirement.package,
                              redist.find_package(requirement.dll))
                self.assertTrue(requirement.package.matches(requirement.dll))

    def test_kit_follows_package_architectures(self):
        arm64 = {(r.dll, r.arch) for r in redist.full_kit_requirements(("arm64",))}
        self.assertIn(("vcruntime140.dll", "arm64"), arm64)
        self.assertIn(("vcruntime140_1.dll", "arm64"), arm64)
        # Под arm64 этих пакетов не существует — синтезировать их бесполезно.
        self.assertNotIn(("msvcr110.dll", "arm64"), arm64)
        self.assertNotIn(("xinput1_3.dll", "arm64"), arm64)

        x86 = {(r.dll, r.arch) for r in redist.full_kit_requirements(("x86",))}
        self.assertIn(("msvcr110.dll", "x86"), x86)
        self.assertIn(("xinput1_3.dll", "x86"), x86)
        self.assertIn(("msvbvm60.dll", "x86"), x86)
        self.assertIn(("physx3core_x86.dll", "x86"), x86)
        # vcruntime140_1.dll для x86 не выпускалась, как и 64-битный VB6.
        self.assertNotIn(("vcruntime140_1.dll", "x86"), x86)
        x64 = {(r.dll, r.arch) for r in redist.full_kit_requirements(("x64",))}
        self.assertIn(("physx3core_x64.dll", "x64"), x64)
        self.assertNotIn(("msvbvm60.dll", "x64"), x64)
        self.assertNotIn(("physx3core_x86.dll", "x64"), x64)

    def test_kit_spans_the_whole_directx_family(self):
        x86 = {r.dll for r in redist.full_kit_requirements(("x86",))
               if r.package.key == "directx_jun2010"}
        for index in range(24, 44):
            self.assertIn(f"d3dx9_{index}.dll", x86)
        for name in ("d3dx10_33.dll", "d3dx10_43.dll", "d3dx11_43.dll",
                     "d3dcompiler_33.dll", "d3dcompiler_43.dll",
                     "xinput1_1.dll", "xinput1_2.dll", "xinput1_3.dll",
                     "xaudio2_0.dll", "xaudio2_7.dll",
                     "xactengine2_10.dll", "xactengine3_7.dll",
                     "x3daudio1_7.dll", "xapofx1_5.dll", "d3dcsx_43.dll"):
            self.assertIn(name, x86)

    def test_kit_requirements_are_proactive_and_anchor_aware(self):
        requirements = redist.full_kit_requirements(("x86",), ("bin/game.exe",))
        self.assertTrue(requirements)
        self.assertTrue(all(r.proactive for r in requirements))
        self.assertTrue(all(r.importers == ["bin/game.exe"] for r in requirements))
        # С полным набором архитектур комплект только растёт.
        both = redist.full_kit_requirements(("x86", "x64"))
        self.assertGreater(len(both), len(requirements))


class FullKitProvisionTests(unittest.TestCase):
    """Полный комплект «про запас»: все версии — заранее, ошибки — никогда."""

    def setUp(self):
        self.log = Logger()

    def _portable(self, temp):
        portable = Path(temp, "Game_Portable")
        app = portable / "App"
        app.mkdir(parents=True)
        return portable, app

    def test_kit_lands_next_to_the_main_exe_and_covers_dynamic_loads(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            # Программа импортирует только kernel32 — но игра может собрать
            # имя «d3dx9_%d.dll» строкой и грузить его LoadLibrary'ем:
            # таблица импорта этого не видит в принципе.
            write_pe(app / "bin" / "Game.exe", imports=("KERNEL32.dll",))
            system = Path(temp, "FakeSystem")
            system.mkdir()
            found = ("msvcp110.dll", "msvcr110.dll", "msvcr100.dll",
                     "xinput1_3.dll", "d3dx9_38.dll", "d3dx9_40.dll",
                     "openal32.dll", "msvbvm60.dll", "vcruntime140.dll")
            for name in found:
                write_runtime_dll(system / name)

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[str(system)], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game",
                        full_kit=True, anchors=["bin/Game.exe"])

            # Программа ничего не требовала — обязательных списков нет.
            self.assertEqual(report.missing, [])
            self.assertEqual(report.provided, [])
            stock = {r.dll for r in report.stock}
            for name in found:
                self.assertIn(name, stock)
                self.assertTrue((app / "bin" / name).is_file(), name)
            # Ненайденное «про запас» — не ошибка и не повод для лончера.
            self.assertTrue(report.stock_missing)
            self.assertIn("d3dx11_43.dll",
                          {r.dll for r in report.stock_missing})
            self.assertEqual(redist.launcher_requirements(report), [])
            text = redist.render_report(report)
            self.assertIn("про запас", text)
            self.assertIn("d3dx9_40.dll", text)

    def test_shortage_of_the_kit_is_advisory_and_never_blocks_the_launcher(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("KERNEL32.dll",))
            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game", full_kit=True)

            self.assertEqual(report.missing, [])
            self.assertEqual(report.provided, [])
            self.assertEqual(report.stock, [])
            self.assertTrue(report.stock_missing)
            for name in USER_REPORTED:
                self.assertIn(redist.normalize_dll(name),
                              {r.dll for r in report.stock_missing})
            self.assertEqual(redist.launcher_requirements(report), [])

    def test_detected_requirement_wins_over_the_kit_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("MSVCP110.dll",))
            system = Path(temp, "FakeSystem")
            system.mkdir()
            write_runtime_dll(system / "msvcp110.dll")

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[str(system)], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game", full_kit=True)

            # Обнаруженная таблицей импорта библиотека — обязательная, у неё
            # известны импортёры; дубликата «про запас» быть не должно.
            self.assertEqual([r.dll for r in report.provided], ["msvcp110.dll"])
            self.assertFalse(report.provided[0].proactive)
            self.assertEqual(report.provided[0].importers, ["game.exe"])
            self.assertNotIn("msvcp110.dll", {r.dll for r in report.stock})

    def test_kit_is_not_duplicated_when_already_next_to_the_exe(self):
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("KERNEL32.dll",))
            # Установщик сам положил пару библиотек рядом с exe.
            for name in ("msvcr100.dll", "xinput1_3.dll"):
                write_runtime_dll(app / name)
            system = Path(temp, "FakeSystem")
            system.mkdir()
            write_runtime_dll(system / "msvcr100.dll")

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[str(system)], sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game", full_kit=True)

            self.assertNotIn("msvcr100.dll", {r.dll for r in report.stock})
            self.assertNotIn("xinput1_3.dll", {r.dll for r in report.stock})
            self.assertNotIn("msvcr100.dll",
                             {r.dll for r in report.stock_missing})

    def test_second_dll_from_the_same_extracted_package_is_delivered(self):
        """Из одного пакета достаются обе библиотеки.

        Регрессия: пакет ``directx_Jun2010_redist.exe`` распаковывался ради
        первой ``d3dx9_38.dll``, а кабинет второй (``d3dx9_39``) оставался
        свёрнутым — и библиотека попадала в «отсутствующие», хотя пакет
        лежал рядом. То же касается полного комплекта: из одного пакета
        теперь достаются десятки файлов.
        """
        calls = []

        def runner(args):
            calls.append(list(args))
            if args[0].lower().endswith("directx_jun2010_redist.exe"):
                target = args[-1].split(":", 1)[1]
                os.makedirs(target, exist_ok=True)
                for cab in ("Jun2010_d3dx9_38_x86.cab",
                            "Jun2010_d3dx9_39_x86.cab"):
                    Path(target, cab).write_bytes(b"MSCF fake cabinet")
                return 0
            if args[0] == "expand":
                cab = Path(args[-2])
                name = cab.name.lower().replace("jun2010_", "") \
                                         .replace("_x86.cab", ".dll")
                write_runtime_dll(Path(args[-1], name))
                return 0
            return 1

        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe",
                     imports=("d3dx9_38.dll", "d3dx9_39.dll"))
            shipped = Path(temp, "_CommonRedist", "DirectX")
            shipped.mkdir(parents=True)
            (shipped / "directx_Jun2010_redist.exe").write_bytes(b"MZ self-x")

            scan = redist.scan_app_runtime(str(app))
            with mock.patch.object(redist, "IS_WINDOWS", True):
                report = redist.RuntimeProvisioner(
                    self.log, source_dirs=[str(shipped)], system_dirs=[],
                    sxs_dir="", runner=runner,
                ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual({r.dll for r in report.provided},
                             {"d3dx9_38.dll", "d3dx9_39.dll"})
            self.assertTrue((app / "d3dx9_38.dll").is_file())
            self.assertTrue((app / "d3dx9_39.dll").is_file())
            expanded = [c[-2] for c in calls if c[0] == "expand"]
            self.assertEqual(len(expanded), 2, expanded)


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

    def test_bat_installs_the_missing_package_silently_when_it_can(self):
        """Вместо «нажмите OK» — тихая установка из папки Redist."""
        cfg = self._cfg()
        cfg.runtime_installers = [
            {"file": "Redist/vcredist_x86.exe", "title": "Visual C++ 2012",
             "kind": "vcredist_legacy", "args": "/q /norestart",
             "dlls": "msvcp110.dll", "arch": "x86"},
        ]
        fs = self._fs()
        fs.add_file(rf"{self.ROOT}\Redist\{redist.SILENT_SCRIPT_NAME}",
                    "@echo off\r\necho redist installed silently\r\n")
        result = self._run(cfg, fs)

        self.assertIn("Installing the missing packages silently", result.text)
        self.assertIn("redist installed silently", result.text)
        self.assertTrue(result.launched)

    def test_without_the_script_the_user_is_told_what_to_install(self):
        cfg = self._cfg()
        cfg.runtime_installers = [
            {"file": "Redist/vcredist_x86.exe", "title": "Visual C++ 2012",
             "kind": "vcredist_legacy", "args": "/q /norestart",
             "dlls": "msvcp110.dll", "arch": "x86"},
        ]
        result = self._run(cfg, self._fs())
        self.assertIn("redistributables.txt", result.text)
        self.assertTrue(result.launched)

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

    def test_full_kit_is_on_by_default_and_brings_the_whole_family(self):
        with tempfile.TemporaryDirectory() as temp:
            # Рядом с установщиком лежит DirectX-пакет репака. Сама программа
            # просит только XINPUT1_3.dll, но полный комплект приносит всё,
            # что нашлось, — в том числе «ненужные» d3dx9_*.
            shipped = Path(temp, "_CommonRedist", "DirectX")
            shipped.mkdir(parents=True)
            for name in ("xinput1_3.dll", "d3dx9_39.dll", "d3dx9_38.dll"):
                write_runtime_dll(shipped / name)

            result, portable = self._build(temp)

            self.assertTrue(result.success)
            # Обязательное: программа сама просит (delay-load XInput).
            self.assertIn("xinput1_3.dll", result.runtime_provided)
            self.assertTrue((portable / "App" / "xinput1_3.dll").is_file())
            # «Про запас»: в таблицах импорта этих библиотек не было.
            self.assertIn("d3dx9_39.dll", result.runtime_stock)
            self.assertIn("d3dx9_38.dll", result.runtime_stock)
            self.assertTrue((portable / "App" / "d3dx9_39.dll").is_file())
            self.assertTrue((portable / "App" / "d3dx9_38.dll").is_file())
            # Недостающее осталось только обязательным: msvcp110 программа
            # импортирует, msvcr100 — тоже, их и ждёт целевой ПК.
            self.assertEqual(sorted(set(result.runtime_missing)),
                             ["msvcp110.dll", "msvcr100.dll"])
            config = json.loads(
                (portable / "launcher_config.json").read_text(encoding="utf-8"))
            # Предстартовая проверка лончера — только про обязательное.
            self.assertEqual(
                sorted(item["dll"] for item in config["runtime_requirements"]),
                ["msvcp110.dll", "msvcr100.dll"])
            report = (portable / redist.REPORT_NAME).read_text(
                encoding="utf-8-sig")
            self.assertIn("про запас", report)
            self.assertIn("d3dx9_38.dll", report)

    def test_full_kit_can_be_switched_off_for_a_lean_portable(self):
        with tempfile.TemporaryDirectory() as temp:
            shipped = Path(temp, "_CommonRedist", "DirectX")
            shipped.mkdir(parents=True)
            write_runtime_dll(shipped / "d3dx9_39.dll")

            result, portable = self._build(temp, full_runtimes=False)

            self.assertTrue(result.success)
            self.assertEqual(result.runtime_stock, [])
            # Точный режим: программу d3dx9_39 не интересует — файла нет.
            self.assertFalse((portable / "App" / "d3dx9_39.dll").exists())

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


class SilentInstallTests(unittest.TestCase):
    """Тихая установка пакетов: ни одного окна с «OK».

    Жалоба, с которой начался этот код: после установки первого «Ведьмака»
    и запуска лончера посыпались сообщения о нехватке redistributables, а
    сама установка требовала жать «OK» на каждый пакет. И то и другое
    лечится одним: пакеты ставятся заранее, сами и молча.
    """

    def setUp(self):
        self.log = Logger()

    # -- опознание установщиков ---------------------------------------------
    def test_only_known_redist_installers_are_recognised(self):
        for name in ("vcredist_x86.exe", "vc_redist.x64.exe", "DXSETUP.exe",
                     "directx_Jun2010_redist.exe", "oalinst.exe",
                     "PhysX_9.19_SystemSoftware.exe", "dotnetfx35.exe",
                     "xnafx40_redist.msi"):
            self.assertTrue(redist.is_redist_installer(name), name)
        # Чужой exe молча запускать нельзя ни при каких условиях.
        for name in ("setup.exe", "GameSetup.exe", "unins000.exe",
                     "witcher.exe", "install.exe"):
            self.assertFalse(redist.is_redist_installer(name), name)

    def test_every_engine_gets_its_own_silent_switches(self):
        with tempfile.TemporaryDirectory() as temp:
            def make(name, data=b"MZ"):
                path = Path(temp, name)
                path.write_bytes(data)
                return str(path)

            burn = make("vc_redist.x64.exe")
            self.assertEqual(redist.silent_commands(burn)[0][1:],
                             ["/install", "/quiet", "/norestart"])
            legacy = make("vcredist_x86.exe")
            self.assertEqual(redist.silent_commands(legacy)[0][1:],
                             ["/q", "/norestart"])
            dx = make("DXSETUP.exe")
            self.assertEqual(redist.silent_commands(dx)[0][1:], ["/silent"])
            msi = make("xnafx40_redist.msi")
            command = redist.silent_commands(msi)[0]
            self.assertEqual(command[0], "msiexec")
            self.assertIn("/qn", command)
            # Неизвестный движок опознаётся по сигнатуре внутри файла.
            inno = make("oddredist.exe", b"MZ ... Inno Setup Setup Data")
            self.assertEqual(redist.installer_kind(inno), "inno")
            self.assertIn("/VERYSILENT", redist.silent_commands(inno)[0])

    def test_exit_codes_are_read_the_way_microsoft_means_them(self):
        self.assertEqual(redist.classify_exit_code(0), "installed")
        self.assertEqual(redist.classify_exit_code(1638), "already")
        self.assertEqual(redist.classify_exit_code(5100), "already")
        self.assertEqual(redist.classify_exit_code(3010), "reboot")
        self.assertEqual(redist.classify_exit_code(1603), "failed")
        self.assertEqual(redist.classify_exit_code(None), "failed")

    def test_switches_are_tried_until_one_of_them_works(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "vcredist_x86.exe")
            path.write_bytes(b"MZ")
            seen = []

            def runner(args):
                seen.append(list(args))
                # Старый пакет не знает /norestart, зато понимает голое /q.
                return 0 if list(args)[1:] == ["/q"] else 1603

            outcome = redist.run_silent_install(str(path), runner=runner)

            self.assertEqual(outcome.status, "installed")
            self.assertEqual(seen[0][1:], ["/q", "/norestart"])
            self.assertEqual(seen[-1][1:], ["/q"])

    # -- предусловия дистрибутива -------------------------------------------
    def test_prerequisites_next_to_the_installer_are_installed_silently(self):
        """Это и есть шаг «установка компонентов» у первого «Ведьмака»."""
        with tempfile.TemporaryDirectory() as temp:
            redist_dir = Path(temp, "_CommonRedist")
            (redist_dir / "vcredist" / "2010").mkdir(parents=True)
            (redist_dir / "DirectX").mkdir(parents=True)
            (redist_dir / "vcredist" / "2010" / "vcredist_x86.exe").write_bytes(b"MZ")
            (redist_dir / "DirectX" / "DXSETUP.exe").write_bytes(b"MZ")
            # Чужой установщик в той же папке трогать нельзя.
            (redist_dir / "DirectX" / "GameSetup.exe").write_bytes(b"MZ")

            started = []

            def runner(args):
                started.append(list(args))
                return 0

            outcomes = redist.install_prerequisites([temp], self.log,
                                                    runner=runner)

            names = [os.path.basename(command[0]) for command in started]
            self.assertEqual(names, ["vcredist_x86.exe", "DXSETUP.exe"])
            self.assertTrue(all(item.ok for item in outcomes))
            # Каждый запуск — строго в тихом режиме.
            self.assertIn("/q", started[0])
            self.assertIn("/silent", started[1])

    def test_already_installed_package_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "vc_redist.x64.exe")
            path.write_bytes(b"MZ")
            outcome = redist.run_silent_install(str(path),
                                                runner=lambda args: 1638)
            self.assertEqual(outcome.status, "already")
            self.assertTrue(outcome.ok)

    # -- последняя ступень лестницы источников ------------------------------
    def test_package_is_installed_to_get_the_library_into_the_portable(self):
        """Файлов нет нигде — ставим пакет молча и забираем их из системы."""
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Game_Portable")
            app = portable / "App"
            app.mkdir(parents=True)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))
            system = Path(temp, "FakeSystem")
            system.mkdir()
            sources = Path(temp, "_CommonRedist")
            sources.mkdir()
            (sources / "vcredist_x86.exe").write_bytes(b"MZ")

            commands = []

            def installer_runner(args):
                commands.append(list(args))
                # «Установка»: пакет кладёт свои файлы в систему.
                write_runtime_dll(system / "msvcp110.dll")
                return 0

            scan = redist.scan_app_runtime(str(app))
            with mock.patch.object(redist, "IS_WINDOWS", True):
                report = redist.RuntimeProvisioner(
                    self.log, source_dirs=[str(sources)],
                    system_dirs=[str(system)], sxs_dir="",
                    allow_install=True,
                    runner=lambda args: 1,
                    installer_runner=installer_runner,
                ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual(report.missing, [])
            self.assertEqual([r.dll for r in report.provided],
                             ["msvcp110.dll"])
            self.assertTrue((app / "msvcp110.dll").is_file())
            self.assertTrue(commands, "пакет так и не был запущен")
            self.assertIn("/q", commands[0])
            self.assertTrue(report.installed[0].ok)
            self.assertIn("тихом режиме",
                          redist.render_report(report))

    def test_nothing_is_installed_without_the_permission(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Game_Portable")
            app = portable / "App"
            app.mkdir(parents=True)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))
            sources = Path(temp, "_CommonRedist")
            sources.mkdir()
            (sources / "vcredist_x86.exe").write_bytes(b"MZ")
            commands = []

            scan = redist.scan_app_runtime(str(app))
            with mock.patch.object(redist, "IS_WINDOWS", True):
                report = redist.RuntimeProvisioner(
                    self.log, source_dirs=[str(sources)], system_dirs=[],
                    sxs_dir="", allow_install=False,
                    runner=lambda args: 1,
                    installer_runner=lambda args: commands.append(list(args)) or 0,
                ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual(commands, [])
            self.assertEqual([r.dll for r in report.missing], ["msvcp110.dll"])
            self.assertEqual(report.installed, [])

    # -- страховка на целевом ПК --------------------------------------------
    def test_installer_of_a_missing_package_is_staged_for_the_target_pc(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Game_Portable")
            app = portable / "App"
            app.mkdir(parents=True)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))
            sources = Path(temp, "_CommonRedist")
            sources.mkdir()
            (sources / "vcredist_x86.exe").write_bytes(b"MZ")

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, source_dirs=[str(sources)], system_dirs=[],
                sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual([r.dll for r in report.missing], ["msvcp110.dll"])
            staged = portable / redist.REDIST_DIR_NAME / "vcredist_x86.exe"
            self.assertTrue(staged.is_file())
            script = portable / redist.REDIST_DIR_NAME / redist.SILENT_SCRIPT_NAME
            self.assertTrue(script.is_file())
            text = script.read_text(encoding="ascii")
            self.assertIn("vcredist_x86.exe", text)
            self.assertIn("/q", text)
            self.assertIn("RunAs", text)
            self.assertTrue(text.isascii())
            entries = redist.launcher_installers(report)
            self.assertEqual(entries[0]["file"],
                             "Redist/vcredist_x86.exe")
            self.assertIn("msvcp110.dll", entries[0]["dlls"])


class PackageExtractionTests(unittest.TestCase):
    """Распаковка пакетов: «скачан, но распаковать не удалось» — это баг.

    Жалобы пользователя: VC++ 2008/2010/2012 скачивались, но не
    распаковывались, DirectX отвечал окном «Неверная операция командной
    строки», а ``mfc80.dll`` не находился ни в одном источнике.
    """

    def setUp(self):
        self.log = Logger()

    def _portable(self, temp):
        portable = Path(temp, "Game_Portable")
        app = portable / "App"
        app.mkdir(parents=True)
        return portable, app

    # -- ключи распаковки ----------------------------------------------------
    def test_every_engine_gets_its_own_extraction_switches(self):
        with tempfile.TemporaryDirectory() as temp:
            def make(name, data=b"MZ"):
                path = Path(temp, name)
                path.write_bytes(data)
                return str(path)

            dest = str(Path(temp, "out"))
            legacy = redist.extraction_commands(make("vcredist_x86.exe"), dest)
            self.assertEqual(legacy[0][1:], ["/Q", "/C", f"/T:{dest}"])
            self.assertIn([legacy[0][0], "/q", f"/x:{dest}"], legacy)

            burn = redist.extraction_commands(make("vc_redist.x64.exe"), dest)
            # WiX Burn не знает ни /T:, ни /x: — только /layout.
            self.assertIn("/layout", burn[0])
            self.assertIn(dest, burn[0])

            msi = redist.extraction_commands(make("xnafx40_redist.msi"), dest)
            self.assertEqual(msi[0][0], "msiexec")
            self.assertIn("/a", msi[0])

            cab = redist.extraction_commands(make("Jun2010_d3dx9_43_x86.cab"),
                                             dest)
            self.assertEqual(cab[0][0], "expand")

    def test_extraction_falls_back_to_cab_tools(self):
        """Не помог ни один ключ — пакет вскрывается как CAB-контейнер."""
        with tempfile.TemporaryDirectory() as temp:
            archive = str(Path(temp, "vcredist_x86.exe"))
            Path(archive).write_bytes(b"MZ")
            tools = [command[0] for command
                     in redist.extraction_commands(archive, str(Path(temp, "o")))]
            self.assertIn("expand", tools)
            self.assertIn("extrac32", tools)

    def test_extraction_path_never_contains_spaces_or_cyrillic(self):
        """``/T:C:\\Мои игры\\…`` пакет разбирает неверно — путь готовим сами."""
        self.assertTrue(redist.is_cmdline_safe(r"C:\Temp\pblz"))
        self.assertFalse(redist.is_cmdline_safe(r"C:\Мои игры\pblz"))
        self.assertFalse(redist.is_cmdline_safe(r"C:\Program Files\pblz"))

        with tempfile.TemporaryDirectory() as temp:
            awkward = Path(temp, "Мои игры", "Портатив", "_redist cache")
            safe = redist.cmdline_safe_dir(str(awkward))
            self.assertTrue(safe, "безопасная папка не найдена")
            self.assertTrue(redist.is_cmdline_safe(safe), safe)
            self.assertTrue(awkward.is_dir())
            # Результат распаковки обязан переехать в запрошенную папку.
            Path(safe, "vc_red.cab").write_bytes(b"MSCF")
            redist.merge_tree(safe, str(awkward))
            self.assertTrue((awkward / "vc_red.cab").is_file())

            plain = Path(temp, "plain")
            self.assertTrue(redist.is_cmdline_safe(
                redist.cmdline_safe_dir(str(plain))))

    def test_downloaded_package_is_unpacked_into_a_safe_path(self):
        """Кириллица в пути портатива больше не срывает распаковку."""
        calls = []

        def downloader(url, destination):
            # Правдоподобный по сигнатуре и размеру пакет, но без кабинета
            # внутри: распаковать его не выйдет ни одним способом.
            Path(destination).write_bytes(b"MZ" + b"\x00" * (128 * 1024))
            return True

        def runner(args):
            calls.append(list(args))
            target = ""
            for item in list(args)[1:]:
                if item.startswith(("/T:", "/x:")):
                    target = item.split(":", 1)[1]
            if not target:
                return 1
            os.makedirs(target, exist_ok=True)
            write_runtime_dll(Path(target, "msvcp110.dll"))
            return 0

        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "Мои игры", "Игра Portable")
            app = portable / "App"
            app.mkdir(parents=True)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))

            scan = redist.scan_app_runtime(str(app))
            with mock.patch.object(redist, "IS_WINDOWS", True):
                report = redist.RuntimeProvisioner(
                    self.log, system_dirs=[], sxs_dir="", allow_download=True,
                    downloader=downloader, runner=runner,
                ).provision(scan, str(app), str(portable), "Игра")

            self.assertEqual(report.missing, [])
            self.assertTrue((app / "msvcp110.dll").is_file())
            for command in calls:
                for item in command:
                    if item.startswith(("/T:", "/x:")):
                        self.assertTrue(
                            redist.is_cmdline_safe(item.split(":", 1)[1]),
                            item)

    # -- mfc80.dll -----------------------------------------------------------
    def test_visual_cpp_2005_has_an_official_download(self):
        package = {p.key: p for p in redist.REDIST_PACKAGES}["vc2005"]
        self.assertTrue(package.downloads.get("x86", "").startswith("https://"))
        self.assertTrue(package.downloads.get("x64", "").startswith("https://"))
        self.assertTrue(package.matches("mfc80.dll"))

    def test_library_hidden_under_an_msi_name_is_found(self):
        """В ``vc_red.cab`` файлы лежат под именами таблицы File установщика."""
        with tempfile.TemporaryDirectory() as temp:
            write_runtime_dll(Path(
                temp, "FL_mfc80_dll_01_8.0.50727.762_x-ww_1b4fc1e7"))
            write_runtime_dll(Path(
                temp, "FL_mfc80u_dll_01_8.0.50727.762_x-ww_1b4fc1e7"))

            found = redist._find_file(temp, "mfc80.dll")
            self.assertTrue(found)
            self.assertIn("fl_mfc80_dll", os.path.basename(found).lower())
            # Соседний mfc80u.dll — другой файл, подменять его нельзя.
            other = redist._find_file(temp, "mfc80u.dll")
            self.assertIn("fl_mfc80u_dll", os.path.basename(other).lower())
            self.assertEqual(redist._find_file(temp, "msvcr80.dll"), "")

    def test_mfc80_is_delivered_with_a_private_manifest(self):
        """VC++ 2005 рядом с exe работает только вместе с манифестом сборки."""
        def downloader(url, destination):
            # Правдоподобный по сигнатуре и размеру пакет, но без кабинета
            # внутри: распаковать его не выйдет ни одним способом.
            Path(destination).write_bytes(b"MZ" + b"\x00" * (128 * 1024))
            return True

        def runner(args):
            target = ""
            for item in list(args)[1:]:
                if item.startswith(("/T:", "/x:")):
                    target = item.split(":", 1)[1]
            if not target:
                return 1
            os.makedirs(target, exist_ok=True)
            write_runtime_dll(Path(target, "FL_mfc80_dll_01_8.0.50727.762"))
            return 0

        manifest = (
            '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" '
            'manifestVersion="1.0"><dependency><dependentAssembly>'
            '<assemblyIdentity type="win32" name="Microsoft.VC80.MFC" '
            'version="8.0.50727.762" processorArchitecture="x86" '
            'publicKeyToken="1fc8b3b9a1e18e3b"/>'
            '</dependentAssembly></dependency></assembly>'
        )
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("mfc80.dll",),
                     manifest=manifest)

            scan = redist.scan_app_runtime(str(app))
            with mock.patch.object(redist, "IS_WINDOWS", True):
                report = redist.RuntimeProvisioner(
                    self.log, system_dirs=[], sxs_dir="", allow_download=True,
                    downloader=downloader, runner=runner,
                ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual([r.dll for r in report.provided], ["mfc80.dll"])
            self.assertTrue((app / "mfc80.dll").is_file())
            written = app / "Microsoft.VC80.MFC.manifest"
            self.assertTrue(written.is_file())
            self.assertIn("8.0.50727.762", written.read_text(encoding="utf-8"))

    # -- распаковка без внешних программ -------------------------------------
    def _package_bytes(self, files):
        """Настоящий самораспаковывающийся пакет: PE + кабинет."""
        return make_self_extracting_exe(files)

    def test_package_is_unpacked_without_running_anything(self):
        """Ни сам пакет, ни expand не запускаются — и всё равно распаковано.

        Ровно эта жалоба: «пакет скачан, но распаковать его автоматически
        не удалось». Теперь кабинет внутри пакета читается напрямую.
        """
        def runner(args):
            self.fail("внешняя программа не должна понадобиться: "
                      + " ".join(str(a) for a in args))

        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))
            source = Path(temp, "src")
            source.mkdir()
            write_runtime_dll(source / "msvcp110.dll")
            dll = (source / "msvcp110.dll").read_bytes()

            def downloader(url, destination):
                Path(destination).write_bytes(self._package_bytes({
                    "msvcp110.dll": dll,
                    "payload.bin": os.urandom(100 * 1024),
                }))
                return True

            scan = redist.scan_app_runtime(str(app))
            with mock.patch.object(redist, "IS_WINDOWS", True):
                report = redist.RuntimeProvisioner(
                    self.log, system_dirs=[], sxs_dir="", allow_download=True,
                    downloader=downloader, runner=runner,
                ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual(report.missing, [])
            self.assertEqual([r.dll for r in report.provided],
                             ["msvcp110.dll"])
            self.assertEqual((app / "msvcp110.dll").read_bytes(), dll)

    def test_nested_cabinet_of_the_legacy_vcredist_is_unpacked(self):
        """VC++ 2005-2010: exe → vc_red.cab → библиотека под именем MSI."""
        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            manifest = (
                '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" '
                'manifestVersion="1.0"><dependency><dependentAssembly>'
                '<assemblyIdentity type="win32" name="Microsoft.VC80.MFC" '
                'version="8.0.50727.762" processorArchitecture="x86" '
                'publicKeyToken="1fc8b3b9a1e18e3b"/>'
                '</dependentAssembly></dependency></assembly>'
            )
            write_pe(app / "game.exe", imports=("mfc80.dll",),
                     manifest=manifest)
            source = Path(temp, "src")
            source.mkdir()
            write_runtime_dll(source / "mfc80.dll")
            dll = (source / "mfc80.dll").read_bytes()

            inner = make_cabinet({
                "FL_mfc80_dll_01_8.0.50727.762_x-ww_1b4fc1e7": dll,
                "FL_mfc80u_dll_01_8.0.50727.762_x-ww_1b4fc1e7": dll,
            })
            shipped = Path(temp, "_CommonRedist", "vcredist", "2005")
            shipped.mkdir(parents=True)
            (shipped / "vcredist_x86.exe").write_bytes(
                self._package_bytes({"vc_red.cab": inner,
                                     "vc_red.msi": b"\xd0\xcf\x11\xe0" * 4096}))

            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, source_dirs=[str(shipped)], system_dirs=[],
                sxs_dir="",
            ).provision(scan, str(app), str(portable), "Game")

            self.assertEqual([r.dll for r in report.provided], ["mfc80.dll"])
            self.assertEqual((app / "mfc80.dll").read_bytes(), dll)
            self.assertTrue((app / "Microsoft.VC80.MFC.manifest").is_file())

    # -- проверка скачанного -------------------------------------------------
    def test_a_web_page_is_never_mistaken_for_a_package(self):
        with tempfile.TemporaryDirectory() as temp:
            page = Path(temp, "vcredist_x86.exe")
            page.write_bytes(b"<!DOCTYPE html><html>404</html>")
            self.assertIn("веб-страницу", redist.package_file_problem(str(page)))

            cut = Path(temp, "vcredist_x64.exe")
            cut.write_bytes(b"MZ" + b"\x00" * 1000)
            self.assertIn("мал", redist.package_file_problem(str(cut)))

            good = Path(temp, "ok.exe")
            good.write_bytes(b"MZ" + b"\x00" * (128 * 1024))
            self.assertEqual(redist.package_file_problem(str(good)), "")

    def test_broken_link_falls_back_to_a_mirror(self):
        """Ссылка отдала страницу-заглушку — берём пакет с запасной ссылки."""
        source = []

        def downloader(url, destination):
            source.append(url)
            if len(source) == 1:
                Path(destination).write_bytes(b"<html>gone</html>")
            else:
                Path(destination).write_bytes(b"MZ" + b"\x00" * (128 * 1024))
            return True

        with tempfile.TemporaryDirectory() as temp:
            portable, app = self._portable(temp)
            write_pe(app / "game.exe", imports=("msvcp110.dll",))
            scan = redist.scan_app_runtime(str(app))
            report = redist.RuntimeProvisioner(
                self.log, system_dirs=[], sxs_dir="", allow_download=True,
                downloader=downloader,
            ).provision(scan, str(app), str(portable), "Game")

            self.assertGreaterEqual(len(source), 2)
            self.assertNotEqual(source[0], source[1])
            # Страница-заглушка выброшена, в Redist лежит файл со второй
            # ссылки — на целевом ПК его можно поставить вручную.
            staged = portable / redist.REDIST_DIR_NAME / "vcredist_x86.exe"
            self.assertTrue(staged.is_file())
            self.assertEqual(staged.read_bytes()[:2], b"MZ")
            self.assertEqual(report.packages, ["vcredist_x86.exe"])

    def test_every_visual_cpp_package_has_a_spare_link(self):
        for package in redist.REDIST_PACKAGES:
            if not package.key.startswith("vc2"):
                continue
            for arch in ("x86", "x64"):
                self.assertGreaterEqual(
                    len(package.urls(arch)), 2,
                    f"{package.key}/{arch}: запасной ссылки нет")

    def test_system_tools_are_looked_up_by_absolute_path_on_windows(self):
        # На не-Windows имя остаётся именем: тесты и Linux-сборка не должны
        # зависеть от наличия System32.
        self.assertEqual(redist.system_tool("expand"), "expand")

    # -- DirectX -------------------------------------------------------------
    def test_directx_bundle_is_never_given_a_switch_it_cannot_parse(self):
        """«Установка DirectX — Неверная операция командной строки» — больше нет."""
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp, "directx_Jun2010_redist.exe")
            bundle.write_bytes(b"MZ")
            self.assertEqual(redist.installer_kind(str(bundle)),
                             "directx_bundle")
            # Бандл — архив, а не установщик: прямых команд у него нет.
            self.assertEqual(redist.silent_commands(str(bundle)), [])
            for command in redist.silent_commands(
                    str(Path(temp, "DXSETUP.exe").resolve())):
                self.assertEqual(command[1:], ["/silent"])

    def test_directx_bundle_is_unpacked_and_dxsetup_runs_silently(self):
        calls = []

        def runner(args):
            calls.append(list(args))
            args = list(args)
            if args[0].lower().endswith("directx_jun2010_redist.exe"):
                target = ""
                for item in args[1:]:
                    if item.startswith(("/T:", "/x:")):
                        target = item.split(":", 1)[1]
                if not target:
                    return 1
                os.makedirs(target, exist_ok=True)
                Path(target, "DXSETUP.exe").write_bytes(b"MZ")
                Path(target, "Jun2010_d3dx9_43_x86.cab").write_bytes(b"MSCF")
                return 0
            return 0

        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp, "directx_Jun2010_redist.exe")
            bundle.write_bytes(b"MZ")
            with mock.patch.object(redist, "IS_WINDOWS", True):
                outcome = redist.run_silent_install(str(bundle), runner=runner)

            self.assertEqual(outcome.status, "installed")
            self.assertTrue(outcome.command.lower().endswith("/silent"))
            self.assertIn("dxsetup.exe", outcome.command.lower())
            # Ни одна команда бандлу не передала ключ, которого он не знает.
            for command in calls:
                if command[0].lower().endswith("directx_jun2010_redist.exe"):
                    self.assertNotIn("/quiet", command)
                    self.assertNotIn("/silent", command)

    def test_directx_bundle_is_opened_by_the_built_in_reader(self):
        """Бандл не запускается: кабинет внутри него читается напрямую."""
        calls = []

        def runner(args):
            calls.append(list(args))
            return 0

        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp, "directx_Jun2010_redist.exe")
            bundle.write_bytes(make_self_extracting_exe({
                "DXSETUP.exe": b"MZ" + os.urandom(20000),
                "Jun2010_d3dx9_43_x86.cab": make_cabinet(
                    {"d3dx9_43.dll": b"MZ" + os.urandom(1000)}),
            }))

            with mock.patch.object(redist, "IS_WINDOWS", True):
                outcome = redist.run_silent_install(str(bundle), runner=runner)

            self.assertEqual(outcome.status, "installed")
            # Единственный запуск — DXSETUP с единственным ключом, который
            # он понимает.
            self.assertEqual(len(calls), 1, calls)
            self.assertTrue(calls[0][0].lower().endswith("dxsetup.exe"))
            self.assertEqual(calls[0][1:], ["/silent"])

    def test_target_pc_script_installs_directx_in_two_steps(self):
        text = redist.render_silent_install_script([
            {"file": "Redist/directx_Jun2010_redist.exe",
             "title": "DirectX End-User Runtime",
             "kind": "directx_bundle", "args": ""},
        ])
        self.assertIn("/T:", text)
        self.assertIn("DXSETUP.exe", text)
        self.assertIn("/silent", text)
        self.assertTrue(text.isascii())


class LauncherSilentInstallTests(unittest.TestCase):
    """LaunchPortable.exe: сначала поставить молча, и только потом жаловаться."""

    ROOT_NAME = "Game_Portable"

    def _portable(self, temp, *, with_script=True):
        root = Path(temp, self.ROOT_NAME)
        (root / "App").mkdir(parents=True)
        (root / "App" / "game.exe").write_bytes(b"MZ")
        (root / "Redist").mkdir()
        (root / "Redist" / "vcredist_x86.exe").write_bytes(b"MZ")
        if with_script:
            (root / "Redist" / redist.SILENT_SCRIPT_NAME).write_text(
                "@echo off\r\n", encoding="ascii")
        return root

    def _cfg(self, with_script=True):
        return {
            "runtime_requirements": [
                {"dll": "msvcp110.dll", "title": "Visual C++ 2012",
                 "url": "https://example.invalid/vcredist_x86.exe",
                 "arch": "x86"},
            ],
            "runtime_installers": [
                {"file": "Redist/vcredist_x86.exe", "title": "Visual C++ 2012",
                 "kind": "vcredist_legacy", "args": "/q /norestart",
                 "dlls": "msvcp110.dll", "arch": "x86"},
            ],
            "runtime_install_script": (
                f"Redist/{redist.SILENT_SCRIPT_NAME}" if with_script else ""),
            "data_dir_name": "PortableData",
        }

    def test_silent_script_is_used_before_any_message_box(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            calls = []

            def fake_hidden(command, timeout=900):
                calls.append(list(command))
                # «Установка»: библиотека появляется рядом с программой.
                (root / "App" / "msvcp110.dll").write_bytes(b"MZ")
                return 0

            missing = [{"dll": "msvcp110.dll", "title": "Visual C++ 2012"}]
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_hidden", fake_hidden), \
                    mock.patch.object(exe_launcher, "_is_elevated",
                                      lambda: True):
                left = exe_launcher.install_missing_runtime(
                    root, self._cfg(), missing)

            self.assertEqual(left, [])
            self.assertEqual(len(calls), 1)
            self.assertIn(redist.SILENT_SCRIPT_NAME, calls[0][-1])

    def test_without_the_script_each_package_is_still_installed_quietly(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp, with_script=False)
            calls = []

            def fake_hidden(command, timeout=900):
                calls.append(list(command))
                (root / "App" / "msvcp110.dll").write_bytes(b"MZ")
                return 0

            missing = [{"dll": "msvcp110.dll", "title": "Visual C++ 2012"}]
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_hidden", fake_hidden), \
                    mock.patch.object(exe_launcher, "_is_elevated",
                                      lambda: True):
                left = exe_launcher.install_missing_runtime(
                    root, self._cfg(with_script=False), missing)

            self.assertEqual(left, [])
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0][0].endswith("vcredist_x86.exe"))
            self.assertEqual(calls[0][1:], ["/q", "/norestart"])

    def test_failed_installation_still_warns_the_user_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._portable(temp)
            missing = [{"dll": "msvcp110.dll", "title": "Visual C++ 2012"}]
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_hidden",
                                      lambda command, timeout=900: 1603), \
                    mock.patch.object(exe_launcher, "_is_elevated",
                                      lambda: True):
                left = exe_launcher.install_missing_runtime(
                    root, self._cfg(), missing)
            self.assertEqual([item["dll"] for item in left], ["msvcp110.dll"])

    def test_bat_launcher_runs_the_silent_script_instead_of_nagging(self):
        cfg = LauncherConfig(
            app_name="Game", target_exe_rel="App/game.exe",
            apply_registry=False,
            runtime_requirements=[{"dll": "msvcp110.dll",
                                   "title": "Visual C++ 2012",
                                   "url": "https://example.invalid/x.exe",
                                   "arch": "x86"}],
            runtime_installers=[{"file": "Redist/vcredist_x86.exe",
                                 "title": "Visual C++ 2012",
                                 "kind": "vcredist_legacy",
                                 "args": "/q /norestart",
                                 "dlls": "msvcp110.dll", "arch": "x86"}],
        )
        bat = render_bat(cfg)
        self.assertTrue(bat.isascii())
        ensure_ascii_bat(bat)
        self.assertIn(redist.SILENT_SCRIPT_NAME, bat)
        config = json.loads(render_config_json(cfg))
        self.assertEqual(config["runtime_install_script"],
                         f"Redist/{redist.SILENT_SCRIPT_NAME}")
        self.assertEqual(config["runtime_installers"][0]["args"],
                         "/q /norestart")


class PrerequisiteStageTests(unittest.TestCase):
    """Предусловия ставятся ДО основного установщика и без единого окна."""

    def test_prerequisites_run_before_the_installer(self):
        order = []

        class Engine(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                order.append("installer")
                write_pe(Path(app_dir, "Game.exe"), imports=("kernel32.dll",))
                return 0

        def fake_prerequisites(dirs, log, **kwargs):
            order.append("prerequisites")
            return [redist.SilentInstall(path="vcredist_x86.exe",
                                         title="Visual C++ 2010",
                                         status="installed", code=0)]

        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "GameSetup.exe")
            installer.write_bytes(b"MZ Inno Setup")
            # Так выглядит диск/репак игры: пакеты лежат рядом с setup.exe.
            prereq = Path(temp, "_CommonRedist", "vcredist", "2010")
            prereq.mkdir(parents=True)
            (prereq / "vcredist_x86.exe").write_bytes(b"MZ")
            with mock.patch("portablizer.core.portablizer.IS_WINDOWS", True), \
                    mock.patch("portablizer.core.portablizer.is_elevated",
                               lambda: True), \
                    mock.patch.object(redist, "install_prerequisites",
                                      fake_prerequisites):
                result = Engine(Logger()).run(PortableOptions(
                    installer_path=str(installer), output_dir=temp,
                    app_name="Game", capture_registry=False,
                    cleanup_host=False, redirect_userdirs=False))

            self.assertTrue(result.success, result.messages)
            self.assertEqual(order, ["prerequisites", "installer"])
            self.assertIn("Visual C++ 2010", result.runtime_installed)

    def test_the_stage_is_skipped_when_the_user_says_so(self):
        class Engine(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                write_pe(Path(app_dir, "Game.exe"), imports=("kernel32.dll",))
                return 0

        called = []
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp, "GameSetup.exe")
            installer.write_bytes(b"MZ Inno Setup")
            with mock.patch("portablizer.core.portablizer.IS_WINDOWS", True), \
                    mock.patch("portablizer.core.portablizer.is_elevated",
                               lambda: True), \
                    mock.patch.object(
                        redist, "install_prerequisites",
                        lambda *a, **k: called.append(a) or []):
                Engine(Logger()).run(PortableOptions(
                    installer_path=str(installer), output_dir=temp,
                    app_name="Game", capture_registry=False,
                    cleanup_host=False, redirect_userdirs=False,
                    silent_runtime_install=False))
        self.assertEqual(called, [])


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
        # Полный комплект — включён сразу: ошибки «отсутствует XINPUT1_3.dll»
        # должны быть закрыты заранее, а не после жалобы.
        self.assertIn("self.cb_full_runtimes = QCheckBox(", self.source)
        self.assertIn("self.cb_full_runtimes.setChecked(True)", self.source)
        # Тихая установка redistributables — тоже сразу: ради неё всё и
        # затевалось, никаких окон с «OK» по ходу сборки.
        self.assertIn("self.cb_silent_redist = QCheckBox(", self.source)
        self.assertIn("self.cb_silent_redist.setChecked(True)", self.source)

    def test_options_are_passed_to_the_builder(self):
        self.assertIn("bundle_runtimes=self.cb_runtimes.isChecked()",
                      self.source)
        self.assertIn("download_runtimes=", self.source)
        self.assertIn("self.cb_fetch_runtimes.isChecked()", self.source)
        self.assertIn("full_runtimes=", self.source)
        self.assertIn("self.cb_full_runtimes.isChecked()", self.source)
        self.assertIn("silent_runtime_install=", self.source)
        self.assertIn("self.cb_silent_redist.isChecked()", self.source)
        for name in ("PortableOptions", "bundle_runtimes",
                     "download_runtimes", "full_runtimes"):
            self.assertIn(name, self.source)

    def test_options_exist_in_the_builder_dataclass(self):
        names = PortableOptions.__dataclass_fields__
        self.assertIn("bundle_runtimes", names)
        self.assertIn("download_runtimes", names)
        self.assertIn("full_runtimes", names)
        defaults = PortableOptions(installer_path="x", output_dir="y")
        self.assertTrue(defaults.bundle_runtimes)
        self.assertTrue(defaults.full_runtimes)
        self.assertFalse(defaults.download_runtimes)
        self.assertIn("silent_runtime_install", names)
        self.assertTrue(defaults.silent_runtime_install)

    def test_result_of_the_build_is_shown_to_the_user(self):
        for name in ("result.runtime_provided", "result.runtime_missing",
                     "result.runtime_packages", "result.runtime_report_rel",
                     "result.runtime_stock"):
            self.assertIn(name, self.source)


if __name__ == "__main__":
    unittest.main()
