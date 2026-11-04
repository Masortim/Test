"""Портатив должен собираться из установщика уже С РАБОЧИМ драйвером.

Жалоба: сборка честно предупреждала «пакет драйвера неполный», но портатив
от этого рабочим не становился. Причина — драйвер искали только в ``App`` и
в системе сборочного ПК, а если установщик его туда не поставил, брать было
неоткуда. При этом сам установщик несёт пакет внутри себя (NSIS
``$PLUGINSDIR``, вложенный ``tap-windows-9.x.exe``, Inno ``{tmp}``, MSI CAB).

Здесь проверяется весь путь: контейнер вскрывается БЕЗ запуска, вложенный
установщик драйвера вскрывается тоже, наружу отдаётся только полный пакет,
он доезжает до ``NetStack/Drivers``, а промежуточные папки не остаются.
Распаковщик подменён двойником на zipfile — ни 7-Zip, ни Windows не нужны.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from portablizer.core import driverpayload, netstack, unpacker

TAP_INF = """[Version]
Signature   = "$Chicago$"
Class       = Net
Provider    = %Prov%
CatalogFile = tap0901.cat
DriverVer   = 11/29/2019,9.24.2.1

[Manufacturer]
%Prov% = tapwindows6, NTamd64

[tapwindows6.NTamd64]
%Desc% = tap0901.ndis6, root\\tap0901

[tap0901.ndis6]
AddReg = tap0901.reg

[SourceDisksFiles]
tap0901.sys = 1

[Strings]
Prov = "TAP-Windows Provider V9"
Desc = "TAP-Windows Adapter V9"
"""


def _zip_runner(cmd, timeout=None):
    """Двойник распаковщика: читает контейнер как zip (7z-стиль argv)."""
    args = list(cmd)
    dest = next((a[2:] for a in args if a.startswith("-o")), None)
    archive = args[-1]
    dest = dest or args[-1]
    os.makedirs(dest, exist_ok=True)
    try:
        with zipfile.ZipFile(archive) as handle:
            handle.extractall(dest)
    except Exception as exc:  # noqa: BLE001
        return 2, str(exc)
    return 0, ""


def _fake_extractors():
    return [unpacker.Extractor(unpacker.STYLE_7ZIP, "fake-7z.exe")]


def _write_package(directory: Path, with_sys=True, with_cat=True) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
    if with_sys:
        (directory / "tap0901.sys").write_bytes(b"MZ")
    if with_cat:
        (directory / "tap0901.cat").write_bytes(b"cat")


def _zip_of(directory: Path, target: Path, prefix: str = "") -> Path:
    with zipfile.ZipFile(target, "w") as handle:
        for item in sorted(directory.iterdir()):
            handle.write(item, prefix + item.name)
    return target


class HarvestTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def _nested_installer(self) -> Path:
        """planeta_setup.exe со вложенным tap-windows-9.24.2.exe и полным пакетом."""
        payload = self.tmp / "payload"
        _write_package(payload)
        nested = _zip_of(payload, self.tmp / "tap-windows-9.24.2.exe")
        outer = self.tmp / "planeta_setup.exe"
        with zipfile.ZipFile(outer, "w") as handle:
            handle.write(nested, "$PLUGINSDIR/tap-windows-9.24.2.exe")
            handle.writestr("PlanetaVPN.exe", "MZ")
        return outer

    def test_driver_is_taken_from_inside_the_installer(self):
        installer = self._nested_installer()
        dest = self.tmp / "out"
        report = driverpayload.harvest_into(
            str(installer), str(dest), extractors=_fake_extractors(),
            runner=_zip_runner, arch="amd64")
        self.assertTrue(report.found, report.notes)
        package = report.packages[0]
        self.assertEqual(package.check_service, "tap0901")
        self.assertTrue(netstack.is_complete_driver_package(package))
        # Paths must point at the destination, not at a deleted temp dir.
        self.assertTrue(os.path.isfile(package.inf_path))
        self.assertTrue(str(package.inf_path).startswith(str(dest)))
        for path in package.file_paths:
            self.assertTrue(os.path.isfile(path), path)

    def test_flat_payload_inside_installer_is_found_without_nesting(self):
        payload = self.tmp / "flat"
        _write_package(payload)
        installer = self.tmp / "setup.exe"
        with zipfile.ZipFile(installer, "w") as handle:
            for item in sorted(payload.iterdir()):
                handle.write(item, "driver/" + item.name)
        report = driverpayload.harvest_into(
            str(installer), str(self.tmp / "out"),
            extractors=_fake_extractors(), runner=_zip_runner, arch="amd64")
        self.assertTrue(report.found, report.notes)
        self.assertEqual(report.packages[0].check_service, "tap0901")

    def test_only_package_files_are_copied_not_the_whole_payload(self):
        """INF в корне распаковки не должен тащить payload всей программы."""
        payload = self.tmp / "flat"
        _write_package(payload)
        installer = self.tmp / "setup.exe"
        with zipfile.ZipFile(installer, "w") as handle:
            # Драйвер лежит ПЛОСКО рядом с payload самой программы.
            for item in sorted(payload.iterdir()):
                handle.write(item, item.name)
            handle.writestr("planetvpn.exe", "MZ" + "\x00" * 5000)
            handle.writestr("resources/app.asar", "junk" * 500)
        dest = self.tmp / "out"
        report = driverpayload.harvest_into(
            str(installer), str(dest), extractors=_fake_extractors(),
            runner=_zip_runner, arch="amd64")
        self.assertTrue(report.found, report.notes)
        names = sorted(p.name for p in dest.rglob("*") if p.is_file())
        self.assertEqual(names, ["OemVista.inf", "tap0901.cat", "tap0901.sys"])

    def test_incomplete_package_inside_installer_is_not_returned(self):
        """INF без .sys/.cat — ровно то, из-за чего падал pnputil."""
        payload = self.tmp / "flat"
        _write_package(payload, with_sys=False, with_cat=False)
        installer = self.tmp / "setup.exe"
        with zipfile.ZipFile(installer, "w") as handle:
            for item in sorted(payload.iterdir()):
                handle.write(item, item.name)
        report = driverpayload.harvest_into(
            str(installer), str(self.tmp / "out"),
            extractors=_fake_extractors(), runner=_zip_runner, arch="amd64")
        self.assertFalse(report.found)

    def test_no_extractor_is_not_a_build_failure(self):
        installer = self._nested_installer()
        report = driverpayload.harvest_into(
            str(installer), str(self.tmp / "out"), extractors=[],
            runner=_zip_runner)
        self.assertFalse(report.found)
        self.assertTrue(any("распаковщик не найден" in n for n in report.notes))

    def test_unreadable_container_is_reported_not_raised(self):
        junk = self.tmp / "junk.exe"
        junk.write_bytes(b"not an archive at all")
        report = driverpayload.harvest_into(
            str(junk), str(self.tmp / "out"),
            extractors=_fake_extractors(), runner=_zip_runner)
        self.assertFalse(report.found)

    def test_missing_installer_is_reported(self):
        report = driverpayload.harvest_into(
            str(self.tmp / "absent.exe"), str(self.tmp / "out"),
            extractors=_fake_extractors(), runner=_zip_runner)
        self.assertFalse(report.found)
        self.assertTrue(any("недоступен" in n for n in report.notes))

    def test_nesting_depth_is_respected(self):
        installer = self._nested_installer()
        work = self.tmp / "work"
        work.mkdir()
        report = driverpayload.harvest_driver_packages(
            str(installer), str(work), extractors=_fake_extractors(),
            runner=_zip_runner, arch="amd64", max_depth=0)
        # Depth 0 must not open the nested tap-windows installer.
        self.assertFalse(report.found)

    def test_temp_work_dir_is_cleaned_after_harvest_into(self):
        installer = self._nested_installer()
        before = set(Path(tempfile.gettempdir()).glob("portablizer-drivers-*"))
        driverpayload.harvest_into(
            str(installer), str(self.tmp / "out"),
            extractors=_fake_extractors(), runner=_zip_runner, arch="amd64")
        after = set(Path(tempfile.gettempdir()).glob("portablizer-drivers-*"))
        self.assertEqual(before, after)

    def test_foreign_net_drivers_are_not_harvested(self):
        payload = self.tmp / "intel"
        payload.mkdir()
        (payload / "e1d.inf").write_text(
            "[Version]\nClass=Net\nProvider=%Intel%\n[Strings]\n"
            'Intel="Intel Corporation"\n', encoding="utf-8")
        (payload / "e1d.sys").write_bytes(b"MZ")
        (payload / "e1d.cat").write_bytes(b"cat")
        installer = self.tmp / "setup.exe"
        with zipfile.ZipFile(installer, "w") as handle:
            for item in sorted(payload.iterdir()):
                handle.write(item, item.name)
        report = driverpayload.harvest_into(
            str(installer), str(self.tmp / "out"),
            extractors=_fake_extractors(), runner=_zip_runner)
        self.assertFalse(report.found)


class CabinetHarvestTests(unittest.TestCase):
    """Настоящий CAB/SFX: работает даже БЕЗ 7-Zip, WinRAR и tar.exe.

    MSI и IExpress-установщики драйверов хранят файлы в кабинете, поэтому
    этот путь проверяется на честном ``MSCF`` (tests/cabbuild), а не на
    zip-двойнике.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.files = {
            "OemVista.inf": TAP_INF.encode("utf-8"),
            "tap0901.sys": b"MZ" * 100,
            "tap0901.cat": b"cat" * 50,
        }

    def test_plain_cabinet_yields_a_complete_package(self):
        import cabbuild
        cab = self.tmp / "tap-windows-9.24.2.cab"
        cab.write_bytes(cabbuild.make_cabinet(self.files))
        report = driverpayload.harvest_into(
            str(cab), str(self.tmp / "out"), extractors=[])
        self.assertTrue(report.found, report.notes)
        self.assertEqual(report.extractor_used, "cabinet")
        package = report.packages[0]
        self.assertEqual(package.check_service, "tap0901")
        self.assertTrue(netstack.is_complete_driver_package(package))
        self.assertTrue(os.path.isfile(package.inf_path))

    def test_self_extracting_exe_yields_a_complete_package(self):
        import cabbuild
        sfx = self.tmp / "tap-windows-9.24.2.exe"
        sfx.write_bytes(cabbuild.make_self_extracting_exe(self.files))
        report = driverpayload.harvest_into(
            str(sfx), str(self.tmp / "out"), extractors=[])
        self.assertTrue(report.found, report.notes)
        self.assertEqual(report.extractor_used, "cabinet")

    def test_incomplete_cabinet_is_rejected(self):
        import cabbuild
        cab = self.tmp / "driver.cab"
        cab.write_bytes(cabbuild.make_cabinet(
            {"OemVista.inf": TAP_INF.encode("utf-8")}))
        report = driverpayload.harvest_into(
            str(cab), str(self.tmp / "out"), extractors=[])
        self.assertFalse(report.found)


class BuildIntegrationTests(unittest.TestCase):
    """Сборка обязана дать рабочий NetStack, а не предупреждение."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "PlanetaVPN_Portable"
        self.app = self.root / "App"
        self.app.mkdir(parents=True)
        (self.app / "PlanetaVPN.exe").write_bytes(b"MZ")

        payload = self.tmp / "payload"
        _write_package(payload)
        nested = _zip_of(payload, self.tmp / "tap-windows-9.24.2.exe")
        self.installer = self.tmp / "planeta_setup.exe"
        with zipfile.ZipFile(self.installer, "w") as handle:
            handle.write(nested, "$PLUGINSDIR/tap-windows-9.24.2.exe")

    def _provision(self):
        from portablizer.core import portablizer as engine_mod
        from portablizer.core.logutil import Logger
        engine = engine_mod.Portablizer(Logger())
        opts = engine_mod.PortableOptions(
            installer_path=str(self.installer), output_dir=str(self.tmp))
        result = engine_mod.PortableResult(success=True)
        with mock.patch.object(engine_mod, "IS_WINDOWS", False), \
                mock.patch.object(unpacker, "find_extractors",
                                  return_value=_fake_extractors()), \
                mock.patch.object(unpacker, "_default_runner",
                                  side_effect=_zip_runner):
            report = engine._provision_netstack(
                str(self.root), str(self.app), opts, result, vpn_hint=True)
        return report, result, engine

    def test_portable_is_complete_when_driver_exists_only_in_installer(self):
        report, result, engine = self._provision()
        self.assertIsNotNone(report)
        self.assertTrue(report.written)
        # Главное assertion всей задачи: портатив ГОТОВ, а не «неполный».
        self.assertTrue(report.complete, report.notes)
        self.assertEqual(result.hints, [])
        driver_dir = self.root / "NetStack" / "Drivers" / "tap-windows"
        for name in ("OemVista.inf", "tap0901.sys", "tap0901.cat"):
            self.assertTrue((driver_dir / name).is_file(), name)
        manifest = json.loads(
            (self.root / "NetStack" / "netstack.json").read_text(
                encoding="utf-8"))
        entry = manifest["drivers"][0]
        self.assertEqual(entry["complete"], "1")
        self.assertEqual(entry["missing_files"], "")
        self.assertEqual(entry["service"], "tap0901")
        self.assertIn("извлечены из установщика", engine.log.text)

    def test_staging_directory_does_not_survive_the_build(self):
        self._provision()
        self.assertFalse((self.root / "NetStack" / ".payload").exists())

    def test_generated_setup_can_install_the_bundled_package(self):
        self._provision()
        setup = (self.root / "NetStack" / "Setup.cmd").read_text(
            encoding="ascii")
        self.assertIn("pnputil /add-driver", setup)
        self.assertIn("-Mode preflight", setup)
        ps1 = (self.root / "NetStack" / "NetStackServices.ps1").read_text(
            encoding="utf-8-sig")
        self.assertIn("UpdateDriverForPlugAndPlayDevices", ps1)


if __name__ == "__main__":
    unittest.main()
