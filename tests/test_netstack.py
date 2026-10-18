"""Тесты переноса системных сетевых компонентов (VPN: драйвер TAP, службы).

Покрывает весь путь надёжного портирования Planeta VPN:

* профиль производителя в детекторе (имя файла → движок NSIS);
* распознавание окна «Безопасность Windows — установить программное
  обеспечение для данного устройства?» (скриншот пользователя) и кнопок;
* разбор .inf и поиск пакетов драйверов в установленной программе;
* перенос служб-компаньонов (перепись ImagePath на маркер портатива);
* сборку папки NetStack: манифест, Setup.cmd, Teardown.cmd, .ps1;
* секцию netstack в конфиге лончера, блоки Launch.bat и рантайм-хелперы
  EXE-лончера.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import portable_launcher_entry as exe_launcher
from portablizer.core import netstack
from portablizer.core.detect import InstallerType, _vendor_profile
from portablizer.core.launcher import (
    LauncherConfig, config_from_dict, ensure_ascii_bat, render_bat,
    render_config_json,
)
from portablizer.core import redist as redist_mod

TAP_INF = """; TAP-Windows driver setup file (c) 2002-2019 OpenVPN Technologies
[Version]
Signature   = "$Chicago$"
Provider    = %TapProvider%
Class       = Net
ClassGUID   = {4d36e972-e325-11ce-bfc1-08002be10318}
DriverVer   = 11/29/2019,9.24.2.1
CatalogFile = tap-windows6.cat

[Manufacturer]
%TapProvider% = tapwindows6, NTamd64

[tapwindows6.NTamd64]
%TapDescription% = tap0901.ndis6, root\\tap0901
%TapDescription% = tap0901.ndis6, tap0901

[tap0901.ndis6]
Characteristics = 0x81
AddReg = tap0901.reg, TapAdapter_Basic_Settings

[Strings]
TapProvider = "TAP-Windows Provider V9"
TapDescription = "TAP-Windows Adapter V9"
"""

WINTUN_INF = """; Wintun driver
[Version]
Class = Net
Provider = %WintunProvider%
DriverVer = 01/09/2019,0.8.1.0

[Manufacturer]
%WintunProvider% = Standard,NTamd64

[Standard.NTamd64]
%WintunDesc% = Wintun, {4d36e972-e325-11ce-bfc1-08002be10318}\\wintun

[Strings]
WintunProvider = "Wintun Userspace Tunnel"
WintunDesc = "Wintun Tunnel"
"""

FOREIGN_INF = """[Version]
Class=Net
Provider=%Intel%
[Manufacturer]
%Intel% = Intel,NTamd64
[Strings]
Intel="Intel Corporation"
"""

SOUND_INF = """[Version]
Class=Media
Provider=%OpenVpnTrick%
[Strings]
OpenVpnTrick="Realtek tap-windows bait"
"""


class InfParsingTests(unittest.TestCase):
    def test_tap_windows_inf_is_recognised_with_provider_expanded(self):
        meta = netstack.parse_net_inf(TAP_INF)
        self.assertEqual(meta.kind, netstack.KIND_TAP_WINDOWS)
        self.assertEqual(meta.provider, "TAP-Windows Provider V9")
        self.assertEqual(meta.service, "tap0901")
        self.assertEqual(meta.device_id, "tap0901")
        self.assertTrue(meta.usable)
        self.assertTrue(meta.needs_install)

    def test_wintun_is_portable_but_installs_itself(self):
        meta = netstack.parse_net_inf(WINTUN_INF)
        self.assertEqual(meta.kind, netstack.KIND_WINTUN)
        self.assertTrue(meta.usable)
        # Адаптер wintun создаёт само приложение из своего DLL — ставить
        # в DriverStore нечего.
        self.assertFalse(meta.needs_install)

    def test_foreign_net_adapters_are_not_carried(self):
        self.assertEqual(netstack.parse_net_inf(FOREIGN_INF).kind,
                         netstack.KIND_OTHER)

    def test_wrong_class_bait_is_not_a_net_driver(self):
        meta = netstack.parse_net_inf(SOUND_INF)
        self.assertEqual(meta.kind, netstack.KIND_OTHER)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.app = os.path.join(self._tmp.name, "App")
        self.driver_dir = os.path.join(self.app, "driver", "tap-windows9")
        os.makedirs(self.driver_dir)

    def _write(self, base, name, text="x"):
        path = os.path.join(base, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_scan_finds_package_tools_and_installer(self):
        self._write(self.driver_dir, "OemVista.inf", TAP_INF)
        self._write(self.driver_dir, "tap0901.sys")
        self._write(self.driver_dir, "tap0901.cat")
        self._write(self.driver_dir, "tapinstall.exe", "MZ")
        self._write(self.app, "tap-windows-9.24.2.exe", "MZ")
        self._write(self.app, "Planeta VPN.exe", "MZ")
        packages = netstack.scan_net_driver_packages(self.app)
        self.assertEqual(len(packages), 1)
        package = packages[0]
        self.assertEqual(package.kind, netstack.KIND_TAP_WINDOWS)
        self.assertEqual(package.check_service, "tap0901")
        self.assertEqual(package.inf_rel,
                         "driver/tap-windows9/OemVista.inf")
        self.assertIn("driver/tap-windows9/tap0901.sys", package.files)
        self.assertEqual(package.tool_rel,
                         "driver/tap-windows9/tapinstall.exe")
        self.assertEqual(package.installer_rel, "tap-windows-9.24.2.exe")

    def test_foreign_apps_have_no_netstack(self):
        self._write(self.app, "readme.inf", FOREIGN_INF)
        self._write(self.app, "sound.inf", SOUND_INF)
        self.assertEqual(netstack.scan_net_driver_packages(self.app), [])

    def test_dedup_by_service(self):
        first = os.path.join(self.app, "a")
        second = os.path.join(self.app, "b")
        os.makedirs(first)
        os.makedirs(second)
        self._write(first, "OemVista.inf", TAP_INF)
        self._write(second, "OemVista2.inf", TAP_INF)
        packages = netstack.scan_net_driver_packages(self.app)
        self.assertEqual(len(packages), 1)


class ServiceRetargetTests(unittest.TestCase):
    def setUp(self):
        self.app = "C:\\Program Files\\Planeta VPN" \
            if os.name == "nt" else "/tmp/planeta/App"

    def _app(self):
        return self.app

    def test_quoted_image_with_args_is_rewritten(self):
        app = "C:\\Program Files\\Planeta VPN"
        got = netstack.retarget_service_image(
            '"C:\\Program Files\\Planeta VPN\\bin\\planeta-svc.exe" '
            "-service", app)
        self.assertEqual(got, ("@@PORTABLE_ROOT@@\\App\\bin\\planeta-svc.exe",
                               "-service"))

    def test_system_services_are_left_alone(self):
        app = "C:\\Program Files\\Planeta VPN"
        self.assertIsNone(netstack.retarget_service_image(
            "\\SystemRoot\\system32\\drivers\\tap0901.sys", app))
        self.assertIsNone(netstack.retarget_service_image(
            "C:\\Windows\\System32\\vpnikeapi.dll", app))

    def test_kernel_service_records_are_dropped(self):
        records = netstack.build_service_records(
            "C:\\pf\\p",
            [{"name": "tap0901", "image_path": "C:\\pf\\p\\x.exe",
              "start": 3, "type": 1}])
        self.assertEqual(records, [])

    def test_demand_service_becomes_portable_record(self):
        records = netstack.build_service_records(
            "C:\\pf\\p",
            [{"name": "PlanetaVPNSvc", "display_name": "Planeta VPN Service",
              "image_path": "C:\\pf\\p\\bin\\svc.exe --svc", "start": 3,
              "type": 16}])
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.name, "PlanetaVPNSvc")
        self.assertEqual(record.start, "demand")
        self.assertEqual(record.image,
                         "@@PORTABLE_ROOT@@\\App\\bin\\svc.exe")
        self.assertEqual(record.args, "--svc")


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "PlanetaVPN_Portable"
        self.root.mkdir()
        self.app = self.root / "App"
        driver = self.app / "driver" / "tap-windows9"
        driver.mkdir(parents=True)
        (driver / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (driver / "tap0901.sys").write_bytes(b"bin")
        (driver / "tapinstall.exe").write_bytes(b"MZ")
        self.packages = netstack.scan_net_driver_packages(str(self.app))
        self.records = netstack.build_service_records(
            str(self.app),
            [{"name": "PlanetaVPNSvc", "display_name": "Planeta VPN Service",
              "image_path": str(driver / "vpn-service.exe") + " --svc",
              "start": 3, "type": 16}])

    def test_bundle_layout_and_manifest(self):
        report = netstack.provision_netstack(str(self.root), str(self.app),
                                             self.packages, self.records)
        self.assertIsNotNone(report)
        self.assertTrue(report.written)
        netstack_dir = self.root / "NetStack"
        self.assertTrue((netstack_dir / "netstack.json").is_file())
        self.assertTrue((netstack_dir / "Setup.cmd").is_file())
        self.assertTrue((netstack_dir / "Teardown.cmd").is_file())
        self.assertTrue((netstack_dir / "NetStackServices.ps1").is_file())
        self.assertTrue((netstack_dir / "Drivers" / "tap-windows"
                         / "OemVista.inf").is_file())
        manifest = json.loads((netstack_dir / "netstack.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["drivers"][0]["service"], "tap0901")
        self.assertEqual(manifest["services"][0]["name"], "PlanetaVPNSvc")
        # Пакет в манифесте указывает уже на NetStack, а не на App
        self.assertTrue(manifest["drivers"][0]["inf"].startswith(
            "NetStack/Drivers/"))

    def test_scripts_are_ascii_crlf_and_idempotent(self):
        report = netstack.provision_netstack(str(self.root), str(self.app),
                                             self.packages, self.records)
        setup = (self.root / "NetStack" / "Setup.cmd").read_bytes().decode(
            "ascii")
        self.assertIn("\r\n", setup)
        # Идемпотентность: сначала «есть ли уже», потом установка.
        self.assertIn('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services'
                      '\\tap0901"', setup)
        self.assertIn("pnputil /add-driver", setup)
        self.assertIn("/install", setup)
        # tapinstall — запас, когда pnputil не создал корневое устройство.
        self.assertIn("tapinstall.exe", setup)
        # Службы создаёт PowerShell по манифесту (пути с кириллицей живут в
        # json, а .cmd остаётся ASCII).
        self.assertIn("NetStackServices.ps1", setup)
        self.assertIn("--check", setup)
        teardown = (self.root / "NetStack" / "Teardown.cmd").read_bytes()\
            .decode("ascii")
        self.assertIn("created-services.txt", teardown)
        self.assertIn("NetStackServices.ps1", teardown)
        # Ни один из скриптов не должен удалять драйвер без явного флага.
        self.assertNotIn("/delete-driver", setup)
        self.assertIn("--remove-device", teardown)
        self.assertTrue(report.to_config()["stop_on_exit"])

    def test_wintun_only_produces_info_note(self):
        app = self.root / "App2"
        wintun = app / "wintun"
        wintun.mkdir(parents=True)
        (wintun / "wintun.inf").write_text(WINTUN_INF, encoding="utf-8")
        (wintun / "wintun.dll").write_bytes(b"MZ")
        packages = netstack.scan_net_driver_packages(str(app))
        report = netstack.provision_netstack(str(self.root), str(app),
                                             packages, [])
        self.assertIsNotNone(report)
        setup = (self.root / "NetStack" / "Setup.cmd").read_text(
            encoding="ascii")
        self.assertIn("installed by the application itself", setup)
        # install-команд для wintun нет — и driver_services в конфиге тоже.
        self.assertNotIn("pnputil /add-driver", setup)
        self.assertEqual(report.to_config()["driver_services"], [])

    def test_nothing_found_no_bundle(self):
        other = self.root / "Empty"
        other.mkdir()
        self.assertIsNone(netstack.provision_netstack(str(other), str(other),
                                                       [], []))


class LauncherWiringTests(unittest.TestCase):
    def _cfg(self, netstack_section=None):
        return LauncherConfig(
            app_name="Planeta VPN",
            target_exe_rel="App/Planeta VPN.exe",
            netstack=netstack_section if netstack_section is not None else {
                "setup": "NetStack/Setup.cmd",
                "teardown": "NetStack/Teardown.cmd",
                "driver_services": ["tap0901"],
                "service_names": ["PlanetaVPNSvc"],
                "stop_on_exit": True,
            })

    def test_config_roundtrip(self):
        cfg = self._cfg()
        data = json.loads(render_config_json(cfg))
        self.assertEqual(data["netstack"]["driver_services"], ["tap0901"])
        back = config_from_dict(data)
        self.assertEqual(back.netstack, cfg.netstack)

    def test_old_config_without_netstack_still_parses(self):
        data = {"app_name": "Old", "target_exe_rel": "App/a.exe"}
        back = config_from_dict(data)
        self.assertEqual(back.netstack, {})

    def test_bat_contains_netstack_hooks(self):
        bat = render_bat(self._cfg())
        ensure_ascii_bat(bat)  # не должно бросить
        self.assertIn("call :portable_netstack_setup", bat)
        self.assertIn("call :portable_netstack_teardown", bat)
        self.assertIn(":portable_netstack_setup", bat)
        self.assertIn("NetStack\\Setup.cmd", bat)
        self.assertIn("--check", bat)
        self.assertIn("created-services.txt", bat)

    def test_bat_without_netstack_is_a_noop(self):
        bat = render_bat(self._cfg(netstack_section={}))
        self.assertIn("no network drivers or services", bat)
        self.assertIn("no companion services to unregister", bat)


class NetstackEntryRuntimeTests(unittest.TestCase):
    def test_missing_list_uses_service_probe(self):
        cfg = {"netstack": {"driver_services": ["tap0901", "Wintun"],
                            "service_names": ["PlanetaVPNSvc"]}}
        with mock.patch.object(exe_launcher, "_service_key_present",
                               lambda name: name == "Wintun"):
            missing = exe_launcher.netstack_missing(Path("/p"), cfg)
        self.assertEqual(missing, ["tap0901", "PlanetaVPNSvc"])

    def test_empty_section_short_circuits(self):
        self.assertEqual(exe_launcher.netstack_missing(Path("/p"), {}), [])
        self.assertEqual(exe_launcher.netstack_missing(
            Path("/p"), {"netstack": {}}), [])

    def test_non_windows_ensure_is_a_noop(self):
        with mock.patch.object(exe_launcher, "IS_WINDOWS", False):
            notes = exe_launcher.ensure_netstack(
                Path("/p"), {"netstack": {"setup": "NetStack/Setup.cmd"}})
            stops = exe_launcher.stop_netstack(Path("/p"), {})
        self.assertEqual(notes, [])
        self.assertEqual(stops, [])

    def test_stop_requires_created_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = {"netstack": {"teardown": "NetStack/Teardown.cmd",
                                "stop_on_exit": True}}
            fake = mock.Mock(return_value=0)
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_netstack_script",
                                      fake):
                self.assertEqual(exe_launcher.stop_netstack(root, cfg), [])
                self.assertEqual(fake.call_count, 0)
                marker = root / "PortableData" / "NetStack"
                marker.mkdir(parents=True)
                (marker / "created-services.txt").write_text(
                    "PlanetaVPNSvc", encoding="utf-8")
                notes = exe_launcher.stop_netstack(root, cfg)
                self.assertEqual(fake.call_count, 1)
                self.assertTrue(notes)

    def test_stop_can_be_switched_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "PortableData" / "NetStack"
            marker.mkdir(parents=True)
            (marker / "created-services.txt").write_text("x", encoding="utf-8")
            cfg = {"netstack": {"teardown": "NetStack/Teardown.cmd",
                                "stop_on_exit": False}}
            fake = mock.Mock(return_value=0)
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_netstack_script",
                                      fake):
                exe_launcher.stop_netstack(root, cfg)
            self.assertEqual(fake.call_count, 0)


class VendorProfileTests(unittest.TestCase):
    def test_planeta_installer_maps_to_nsis(self):
        for name in ("planeta_installer-4.15.0.exe", "PlanetaVPN.exe",
                     "Planeta.VPN.Setup.exe"):
            profile = _vendor_profile(name)
            self.assertIsNotNone(profile, name)
            self.assertEqual(profile.name, "Planeta VPN")
            self.assertEqual(profile.installer_hint, InstallerType.NSIS)
            self.assertIn("/S", profile.switches)
            self.assertEqual(profile.license_url, "")

    def test_zenno_profile_keeps_custom_cli_semantics(self):
        profile = _vendor_profile("ZennoPosterLite-RU-v7.9.2.0.exe")
        self.assertIsNotNone(profile)
        self.assertIsNone(profile.installer_hint)
        self.assertTrue(profile.license_url)

    def test_unrelated_names_get_no_profile(self):
        self.assertIsNone(_vendor_profile("setup_Alice_1.2.exe"))


class DevicePromptDialogTests(unittest.TestCase):
    """Окно со скриншота пользователя: «Безопасность Windows»."""

    RU_TITLE = "Безопасность Windows"
    RU_BODY = ("Установить программное обеспечение для данного устройства? "
               "Имя: TAP-Windows Provider V9 network adapters "
               "Издатель: OpenVPN Technologies, Inc.")
    EN_TITLE = "Windows Security"
    EN_BODY = ("You need to install software for this device. "
               "Publisher: OpenVPN Technologies, Inc.")

    def test_recognised_russian(self):
        self.assertTrue(redist_mod.installer_prompt_looks_like_device_driver(
            self.RU_TITLE, self.RU_BODY))

    def test_recognised_english(self):
        self.assertTrue(redist_mod.installer_prompt_looks_like_device_driver(
            self.EN_TITLE, self.EN_BODY))

    def test_other_security_windows_untouched(self):
        self.assertFalse(
            redist_mod.installer_prompt_looks_like_device_driver(
                self.RU_TITLE, "Приложение изменено другими пользователями"))
        # Чужое окно с «похожей» фразой, но без имени устройства — не трогаем.
        self.assertFalse(
            redist_mod.installer_prompt_looks_like_device_driver(
                "Браузер",
                "Установить программное обеспечение для данного устройства?"))
        # А вот окно дочернего tapinstall, у которого заголовок потерян,
        # узнаётся по паре «фраза согласия + имя адаптера» — иначе тихая
        # установка VPN зависала бы на нём навсегда.
        self.assertTrue(
            redist_mod.installer_prompt_looks_like_device_driver(
                "", self.RU_BODY))

    def test_should_dismiss_includes_device_family(self):
        self.assertTrue(redist_mod.installer_prompt_should_dismiss(
            self.RU_TITLE, self.RU_BODY))

    def test_install_button_never_the_refusal(self):
        self.assertTrue(redist_mod.installer_button_is_device_install(
            "Установить"))
        self.assertTrue(redist_mod.installer_button_is_device_install(
            "&Install"))
        self.assertFalse(redist_mod.installer_button_is_device_install(
            "Не устанавливать"))
        self.assertFalse(redist_mod.installer_button_is_device_install(
            "Do Not Install"))
        # обычные кнопки не путать с «установить»
        self.assertFalse(redist_mod.installer_button_is_device_install("OK"))

    def test_trust_checkbox_recognised(self):
        self.assertTrue(redist_mod.installer_checkbox_is_trust(
            'Всегда доверять программному обеспечению "OpenVPN Technologies, '
            'Inc."'))
        self.assertTrue(redist_mod.installer_checkbox_is_trust(
            "Always trust software from \"OpenVPN Technologies, Inc.\""))
        self.assertFalse(redist_mod.installer_checkbox_is_trust("Установить"))

    def test_dismiss_tallies_device_dialogs_without_windows(self):
        counter = {}
        self.assertEqual(redist_mod._dismiss_installer_dialogs(counter), 0)
        self.assertNotIn("device", counter)


class FailureHintTests(unittest.TestCase):
    def test_hint_mentions_device_consent_only_after_a_hit(self):
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import Portablizer, PortableOptions
        engine = Portablizer(Logger())
        opts = PortableOptions(installer_path="x.exe", output_dir=".")
        det = mock.Mock(installer_type=InstallerType.NSIS, is_msi=False,
                        requires_admin=False, confidence=0.9,
                        installshield_generation=None)
        det.has_switch.return_value = False
        det.license_url = ""
        hints = " ".join(engine._failure_hints(det, 0xC0000005, opts, "/p"))
        self.assertNotIn("Безопасность Windows", hints)
        engine._device_prompt_hits = 2
        hints = " ".join(engine._failure_hints(det, 2, opts, "/p"))
        self.assertIn("Безопасность Windows", hints)
        self.assertIn("NetStack", hints)


if __name__ == "__main__":
    unittest.main(verbosity=2)
