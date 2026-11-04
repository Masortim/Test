"""Свежий TAP взамен заблокированного: «Ошибка установки драйвера адаптера».

Последняя причина отказа, которую не лечили прежние версии: комплект
драйвера ПОЛНЫЙ, разрядность верная, Hardware ID правильный — а Windows
всё равно отказывается ставить ``tap0901.sys``, потому что версия младше
9.27 содержит CVE-2024-1305. Тот же отказ видит и сам вендорский клиент:
он ставит ровно тот же старый файл. Лечится только заменой драйвера.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from portablizer.core import netstack, tapdriver


TAP_INF_TEMPLATE = """[Version]
Signature = "$Windows NT$"
Class = Net
ClassGuid = {{4d36e972-e325-11ce-bfc1-08002be10318}}
Provider = %Provider%
CatalogFile = tap0901.cat
DriverVer = {version}
[Manufacturer]
%Provider% = tap0901, NTamd64
[tap0901.NTamd64]
%DeviceDescription% = tap0901.ndi, tap0901
[tap0901.ndi]
AddReg = tap0901.reg
[SourceDisksFiles]
tap0901.sys = 1
[Strings]
Provider = "TAP-Windows Provider V9"
DeviceDescription = "TAP-Windows Adapter V9"
"""

OLD_VERSION = "11/29/2019,9.24.2.1"
NEW_VERSION = "03/19/2024,9.27.0.0"


class VulnerableVersionTests(unittest.TestCase):
    """Какие версии Windows отвергает как уязвимые."""

    def test_versions_shipped_by_vpn_clients_are_vulnerable(self):
        for value in ("11/29/2019,9.24.2.1", "04/21/2016,9.00.00.21",
                      "01/01/2021,9.26.0.0"):
            with self.subTest(value=value):
                self.assertTrue(tapdriver.is_vulnerable_tap(value))

    def test_fixed_version_is_not_vulnerable(self):
        for value in (NEW_VERSION, "01/01/2025,9.28.1.0", "9.27"):
            with self.subTest(value=value):
                self.assertFalse(tapdriver.is_vulnerable_tap(value))

    def test_unknown_version_is_not_accused(self):
        """Пустой DriverVer не повод менять рабочий вендорский комплект."""
        for value in ("", "   ", "garbage"):
            with self.subTest(value=value):
                self.assertEqual(tapdriver.version_tuple(value), ())
                self.assertFalse(tapdriver.is_vulnerable_tap(value))

    def test_date_before_version_is_not_mistaken_for_version(self):
        self.assertEqual(tapdriver.version_tuple(OLD_VERSION), (9, 24, 2, 1))

    def test_official_url_points_at_the_fixed_release(self):
        self.assertIn(tapdriver.OFFICIAL_TAP_VERSION, tapdriver.OFFICIAL_TAP_URL)
        self.assertTrue(tapdriver.OFFICIAL_TAP_URL.startswith("https://"))
        self.assertIn("OpenVPN/tap-windows6", tapdriver.OFFICIAL_TAP_URL)
        self.assertFalse(
            tapdriver.is_vulnerable_tap(tapdriver.OFFICIAL_TAP_VERSION),
            "официальная версия обязана быть уже исправленной")


class OutdatedStateTests(unittest.TestCase):
    """Починка обязана ВИДЕТЬ заблокированный драйвер, а не хвалить его."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))
        self.root = self.tmp / "portable"
        self.driver = self.root / "NetStack" / "Drivers" / "tap-windows"
        self.driver.mkdir(parents=True)
        self._write(OLD_VERSION)

    def _write(self, version):
        (self.driver / "OemVista.inf").write_text(
            TAP_INF_TEMPLATE.format(version=version), encoding="utf-8")
        (self.driver / "tap0901.sys").write_bytes(b"MZ")
        (self.driver / "tap0901.cat").write_bytes(b"cat")
        (self.root / "NetStack" / "netstack.json").write_text(json.dumps({
            "schema": 1, "isolation": "session",
            "root_token": "@@PORTABLE_ROOT@@",
            "drivers": [{
                "kind": "tap-windows", "service": "tap0901",
                "device_id": "tap0901", "needs_install": "1",
                "inf": "NetStack/Drivers/tap-windows/OemVista.inf",
                "required_files": "tap0901.sys;tap0901.cat",
                "driver_version": version}],
            "services": [], "state_dir": "PortableData/NetStack",
            "created_services_file": "created-services.txt"}), encoding="utf-8")

    def test_complete_but_blocked_package_is_reported(self):
        state = netstack.inspect_netstack(str(self.root))
        self.assertTrue(state.complete, "файлы на месте — комплект полный")
        self.assertEqual(len(state.outdated), 1, state.outdated)
        self.assertIn("tap0901", state.outdated[0])
        self.assertIn("9.24.2.1", state.outdated[0])

    def test_modern_package_is_not_reported(self):
        self._write(NEW_VERSION)
        state = netstack.inspect_netstack(str(self.root))
        self.assertTrue(state.complete)
        self.assertEqual(state.outdated, [])

    def test_old_manifest_without_version_asks_the_inf(self):
        """Манифест прежней сборки версии не знает — читать надо сам INF."""
        path = self.root / "NetStack" / "netstack.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        del manifest["drivers"][0]["driver_version"]
        path.write_text(json.dumps(manifest), encoding="utf-8")
        state = netstack.inspect_netstack(str(self.root))
        self.assertEqual(len(state.outdated), 1, state.outdated)


class OfficialReplacementTests(unittest.TestCase):
    """Замена комплекта целиком: старый драйвер вылечить нельзя."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))
        self.root = self.tmp / "portable"
        self.driver = self.root / "NetStack" / "Drivers" / "tap-windows"
        self.driver.mkdir(parents=True)
        (self.driver / "OemVista.inf").write_text(
            TAP_INF_TEMPLATE.format(version=OLD_VERSION), encoding="utf-8")
        (self.driver / "tap0901.sys").write_bytes(b"OLD-SYS")
        (self.driver / "tap0901.cat").write_bytes(b"OLD-CAT")
        (self.root / "NetStack" / "netstack.json").write_text(json.dumps({
            "schema": 1, "isolation": "session",
            "root_token": "@@PORTABLE_ROOT@@",
            "drivers": [{
                "kind": "tap-windows", "service": "tap0901",
                "device_id": "tap0901", "needs_install": "1",
                "inf": "NetStack/Drivers/tap-windows/OemVista.inf",
                "required_files": "tap0901.sys;tap0901.cat",
                "driver_version": OLD_VERSION}],
            "services": [], "state_dir": "PortableData/NetStack",
            "created_services_file": "created-services.txt"}), encoding="utf-8")
        # Распакованный «официальный архив»: своя разрядность и свой набор.
        self.official = self.tmp / "official" / "amd64"
        self.official.mkdir(parents=True)
        (self.official / "OemVista.inf").write_text(
            TAP_INF_TEMPLATE.format(version=NEW_VERSION), encoding="utf-8")
        (self.official / "tap0901.sys").write_bytes(b"NEW-SYS")
        (self.official / "tap0901.cat").write_bytes(b"NEW-CAT")

    def _refill(self, only_outdated=True):
        def fake_download(destination, log=None, **_kwargs):
            return str(self.official.parent)

        with mock.patch.object(tapdriver, "download_official_tap",
                               side_effect=fake_download), \
                mock.patch.object(tapdriver, "check_catalog_signature",
                                  return_value=(True, "подпись действительна")):
            return netstack.refill_netstack_from_official(
                str(self.root), arch="amd64", only_outdated=only_outdated)

    def test_blocked_set_is_replaced_as_a_whole(self):
        added = self._refill()
        self.assertTrue(added, "заблокированный комплект обязан быть заменён")
        self.assertEqual((self.driver / "tap0901.sys").read_bytes(), b"NEW-SYS")
        self.assertEqual((self.driver / "tap0901.cat").read_bytes(), b"NEW-CAT")
        self.assertNotIn(
            OLD_VERSION,
            (self.driver / "OemVista.inf").read_text(encoding="utf-8"))
        state = netstack.inspect_netstack(str(self.root))
        self.assertTrue(state.complete)
        self.assertEqual(state.outdated, [], "после замены блокировки нет")

    def test_manifest_gets_the_new_version(self):
        self._refill()
        manifest = json.loads(
            (self.root / "NetStack" / "netstack.json").read_text(
                encoding="utf-8"))
        self.assertEqual(manifest["drivers"][0]["driver_version"], NEW_VERSION)
        self.assertEqual(manifest["drivers"][0]["hardware_id"], "tap0901")

    def test_modern_set_is_left_alone(self):
        (self.driver / "OemVista.inf").write_text(
            TAP_INF_TEMPLATE.format(version=NEW_VERSION), encoding="utf-8")
        (self.driver / "tap0901.sys").write_bytes(b"VENDOR-SYS")
        path = self.root / "NetStack" / "netstack.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["drivers"][0]["driver_version"] = NEW_VERSION
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self._refill(), [])
        self.assertEqual((self.driver / "tap0901.sys").read_bytes(),
                         b"VENDOR-SYS")

    def test_unsigned_download_is_refused(self):
        with mock.patch.object(tapdriver, "download_official_tap",
                               return_value=str(self.official.parent)), \
                mock.patch.object(tapdriver, "check_catalog_signature",
                                  return_value=(False, "NotTrusted")):
            with self.assertRaises(ValueError):
                netstack.refill_netstack_from_official(
                    str(self.root), arch="amd64")
        self.assertEqual((self.driver / "tap0901.sys").read_bytes(), b"OLD-SYS")

    def test_staging_directory_is_removed(self):
        self._refill()
        self.assertFalse((self.root / "NetStack" / ".official").exists())

    def test_wrong_architecture_is_not_taken(self):
        (self.official / "OemVista.inf").unlink()
        arm = self.tmp / "official" / "arm64"
        arm.mkdir()
        (arm / "OemVista.inf").write_text(
            TAP_INF_TEMPLATE.format(version=NEW_VERSION), encoding="utf-8")
        (arm / "tap0901.sys").write_bytes(b"ARM")
        (arm / "tap0901.cat").write_bytes(b"ARM")
        packages = netstack.scan_downloaded_driver_packages(
            str(self.tmp / "official"), arch="arm64")
        self.assertEqual(len(packages), 1)
        self.assertEqual(Path(packages[0].inf_path).parent.name, "arm64")


class RepairSourcePolicyTests(unittest.TestCase):
    """Обычная починка НЕ ходит в сеть — скачивание только по выбору."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))
        self.root = self.tmp / "portable"
        driver = self.root / "NetStack" / "Drivers" / "tap-windows"
        driver.mkdir(parents=True)
        (driver / "OemVista.inf").write_text(
            TAP_INF_TEMPLATE.format(version=OLD_VERSION), encoding="utf-8")
        (driver / "tap0901.sys").write_bytes(b"MZ")
        (driver / "tap0901.cat").write_bytes(b"cat")
        (self.root / "NetStack" / "netstack.json").write_text(json.dumps({
            "schema": 1, "isolation": "session",
            "root_token": "@@PORTABLE_ROOT@@",
            "drivers": [{
                "kind": "tap-windows", "service": "tap0901",
                "device_id": "tap0901", "needs_install": "1",
                "inf": "NetStack/Drivers/tap-windows/OemVista.inf",
                "required_files": "tap0901.sys;tap0901.cat",
                "driver_version": OLD_VERSION}],
            "services": [], "state_dir": "PortableData/NetStack",
            "created_services_file": "created-services.txt"}), encoding="utf-8")

    def test_plain_repair_never_downloads_but_says_what_is_wrong(self):
        from portablizer.core import maintenance

        with mock.patch.object(tapdriver, "download_official_tap") as download:
            report = maintenance.repair_netstack(str(self.root))
        download.assert_not_called()
        self.assertFalse(report.success,
                         "заблокированный драйвер успехом не считается")
        text = " ".join(report.messages)
        self.assertIn("CVE-2024-1305", text)
        self.assertIn("9.27", text)

    def test_explicit_choice_downloads_and_repairs(self):
        from portablizer.core import maintenance

        official = self.tmp / "official" / "amd64"
        official.mkdir(parents=True)
        (official / "OemVista.inf").write_text(
            TAP_INF_TEMPLATE.format(version=NEW_VERSION), encoding="utf-8")
        (official / "tap0901.sys").write_bytes(b"NEW")
        (official / "tap0901.cat").write_bytes(b"NEW")
        with mock.patch.object(tapdriver, "download_official_tap",
                               return_value=str(official.parent)) as download, \
                mock.patch.object(tapdriver, "check_catalog_signature",
                                  return_value=(True, "подпись действительна")):
            report = maintenance.repair_netstack(
                str(self.root), maintenance.OFFICIAL_SOURCE)
        download.assert_called_once()
        self.assertTrue(report.success, report.messages)
        self.assertEqual(netstack.inspect_netstack(str(self.root)).outdated, [])


class ArchiveSafetyTests(unittest.TestCase):
    """Архив приходит из сети: распаковка не должна выйти за свою папку."""

    def test_path_traversal_is_refused(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "evil.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../../escaped.txt", "pwned")
            destination = Path(tmp) / "out"
            with mock.patch("urllib.request.urlopen") as urlopen:
                response = mock.MagicMock()
                response.headers = {}
                response.read.side_effect = [archive.read_bytes(), b""]
                response.__enter__ = lambda self_: response
                response.__exit__ = lambda *_a: False
                urlopen.return_value = response
                with self.assertRaises(ValueError):
                    tapdriver.download_official_tap(str(destination))
            self.assertFalse((Path(tmp) / "escaped.txt").exists())

    def test_signature_check_is_skipped_off_windows(self):
        if os.name == "nt":
            self.skipTest("проверка имеет смысл только вне Windows")
        signed, note = tapdriver.check_catalog_signature(".")
        self.assertIsNone(signed)
        self.assertTrue(note)


if __name__ == "__main__":
    unittest.main()
