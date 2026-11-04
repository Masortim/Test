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

def _command_lines_with(text: str, needle: str):
    """Строки скрипта, где needle — команда, а не пояснение в rem."""
    found = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("rem"):
            continue
        if needle in stripped:
            found.append(stripped)
    return found


TAP_INF = """; TAP-Windows driver setup file (c) 2002-2019 OpenVPN Technologies
[Version]
Signature   = "$Chicago$"
Provider    = %TapProvider%
Class       = Net
ClassGUID   = {4d36e972-e325-11ce-bfc1-08002be10318}
DriverVer   = 11/29/2019,9.24.2.1
CatalogFile = tap0901.cat

[Manufacturer]
%TapProvider% = tapwindows6, NTamd64

[tapwindows6.NTamd64]
%TapDescription% = tap0901.ndis6, root\\tap0901
%TapDescription% = tap0901.ndis6, tap0901

[tap0901.ndis6]
Characteristics = 0x81
AddReg = tap0901.reg, TapAdapter_Basic_Settings

[SourceDisksNames]
1 = %TapDescription%, tap0901.sys

[SourceDisksFiles]
tap0901.sys = 1

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
        # Изоляция по умолчанию: сеанс владеет тем, что опубликовал.
        self.assertEqual(manifest["isolation"], "session")
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
        # pnputil НЕ умеет создавать устройства: команды /add-device у него
        # нет. Пакет публикуется им, а адаптер создаёт .ps1 (tapinstall или
        # встроенный установщик на SetupAPI) — именно этого не хватало,
        # чтобы портатив Planeta VPN видел адаптер.
        self.assertFalse(_command_lines_with(setup, "/add-device"))
        self.assertIn("/scan-devices", setup)
        self.assertIn("NetStackServices.ps1", setup)
        # Службы создаёт PowerShell по манифесту (пути с кириллицей живут в
        # json, а .cmd остаётся ASCII).
        self.assertIn("NetStackServices.ps1", setup)
        self.assertIn("--check", setup)
        # Изолированный режим: Setup обязан вести учёт владения — снимки INF
        # до/после публикации и hwid, которые портатив просил создать.
        self.assertIn("dir /b", setup)
        self.assertIn("ns_pre.tmp", setup)
        self.assertIn("ns_post.tmp", setup)
        self.assertIn("ns_ids.txt", setup)
        self.assertIn("-Mode ownership", setup)
        self.assertIn("echo tap0901>>", setup)
        teardown = (self.root / "NetStack" / "Teardown.cmd").read_bytes()\
            .decode("ascii")
        self.assertIn("created-services.txt", teardown)
        self.assertIn("NetStackServices.ps1", teardown)
        # Удаление драйвера живёт в .ps1 (там манифест и пути), cmd тонкий;
        # Setup сам ничего не удаляет ни при каком флаге.
        self.assertNotIn("/delete-driver", setup)
        self.assertIn("-Mode rollback", teardown)
        self.assertIn("--keep-driver", teardown)
        ps1 = (self.root / "NetStack" / "NetStackServices.ps1").read_bytes()\
            .decode("utf-8-sig")
        for needle in ("if ($Mode -eq 'ownership')", "if ($Mode -eq 'rollback')",
                       "/delete-driver", "/uninstall /force", "pending-driver.txt",
                       "driver-packages.txt", "/remove-device",
                       "Find-HwidDevices", "Ensure-NetAdapters",
                       "PortablizerNetStack.RootDevice",
                       "UpdateDriverForPlugAndPlayDevices", "tapinstall",
                       "created-devices.txt", "Remember-Device",
                       "Remove-RememberedDevices"):
            self.assertIn(needle.replace("tapinstall", "remove"), ps1, needle)
        self.assertTrue(report.to_config()["stop_on_exit"])
        self.assertEqual(report.to_config()["isolation"], "session")

    def test_shared_mode_keeps_old_politics(self):
        report = netstack.provision_netstack(str(self.root), str(self.app),
                                             self.packages, self.records,
                                             isolated=False)
        self.assertEqual(report.isolation, "shared")
        setup = (self.root / "NetStack" / "Setup.cmd").read_text(
            encoding="ascii")
        # Никакого учёта владения там, где драйвер остаётся общим.
        self.assertNotIn("ns_pre.tmp", setup)
        self.assertNotIn("-Mode ownership", setup)
        teardown = (self.root / "NetStack" / "Teardown.cmd").read_text(
            encoding="ascii")
        self.assertIn("--remove-device", teardown)
        self.assertNotIn("-Mode rollback", teardown)
        # Снимать по-прежнему нужно службы — для них стоп и включён.
        self.assertTrue(report.to_config()["stop_on_exit"])

    def test_isolation_stop_on_exit_without_services(self):
        # Один только драйвер, опубликованный портативом, уже обязан быть
        # убраным с хоста по завершении сеанса.
        report = netstack.NetStackReport(
            drivers=[{"kind": "tap-windows", "service": "tap0901",
                      "device_id": "tap0901", "needs_install": "1",
                      "inf": "NetStack/Drivers/tap-windows/OemVista.inf",
                      "tool": "", "installer": ""}],
            services=[], isolation="session")
        self.assertTrue(report.to_config()["stop_on_exit"])
        report.isolation = "shared"
        self.assertFalse(report.to_config()["stop_on_exit"])

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
        # Владеть нечем: единственного установщика у wintun нет, и тайм-аут
        # снимков INF срабатывать не на что — hwid-записей в Setup нет.
        self.assertNotIn("echo wintun>>", setup)
        self.assertFalse(report.to_config()["stop_on_exit"])

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
                "isolation": "session",
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
        # гейт teardown в bat учитывает все маркеры изолированного сеанса
        self.assertIn("driver-packages.txt", bat)
        self.assertIn("created-devices.txt", bat)

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

    def test_created_adapter_marker_alone_triggers_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "PortableData" / "NetStack"
            state.mkdir(parents=True)
            (state / "created-devices.txt").write_text(
                "tap0901 ROOT\\NET\\0003", encoding="utf-8")
            cfg = {"netstack": {"teardown": "NetStack/Teardown.cmd",
                                "stop_on_exit": True,
                                "isolation": "session"}}
            fake = mock.Mock(return_value=0)
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_netstack_script",
                                      fake):
                exe_launcher.stop_netstack(root, cfg)
            self.assertEqual(fake.call_count, 1)

    def test_driver_marker_alone_triggers_isolation_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "PortableData" / "NetStack"
            state.mkdir(parents=True)
            (state / "driver-packages.txt").write_text(
                "oem14.inf tap0901", encoding="utf-8")
            cfg = {"netstack": {"teardown": "NetStack/Teardown.cmd",
                                "stop_on_exit": True,
                                "isolation": "session"}}
            fake = mock.Mock(return_value=0)
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_netstack_script",
                                      fake):
                exe_launcher.stop_netstack(root, cfg)
            self.assertEqual(fake.call_count, 1)

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


#: Настоящий TAP-Windows кладёт рядом с .inf ещё и .sys/.cat: без них
#: pnputil пакет не примет, а Windows не подпишет установку драйвера.
class SystemCaptureTests(unittest.TestCase):
    """Драйвер, установленный установщиком В СИСТЕМУ, а не в папку App.

    Именно этого не хватало: Planeta VPN (как и почти все клиенты на
    OpenVPN) ставит TAP-Windows в DriverStore, поэтому сканирование одного
    App ничего не находило, портатив уезжал без драйвера, и на чужом ПК
    клиент показывал «не удалось обнаружить TAP-Windows Provider V9 Network
    adapter» и «Ошибка установки драйвера адаптера».
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.store = self.base / "DriverStore" / "FileRepository"
        self.store.mkdir(parents=True)

    def _driverstore_package(self, name, inf_text=TAP_INF, arch="amd64"):
        directory = self.store / f"oemvista.inf_{arch}_9f1c2e4a"
        directory.mkdir()
        (directory / "OemVista.inf").write_text(inf_text, encoding="utf-8")
        (directory / "tap0901.sys").write_bytes(b"MZ")
        (directory / "tap0901.cat").write_bytes(b"MZ")
        return directory

    def test_driverstore_package_is_found_with_absolute_paths(self):
        directory = self._driverstore_package("tap")
        packages = netstack.scan_driverstore_packages(str(self.store),
                                                      arch="amd64")
        self.assertEqual(len(packages), 1)
        package = packages[0]
        self.assertEqual(package.kind, netstack.KIND_TAP_WINDOWS)
        self.assertEqual(package.check_service, "tap0901")
        self.assertEqual(package.origin, "driverstore")
        self.assertEqual(Path(package.inf_path), directory / "OemVista.inf")
        names = {Path(path).name for path in package.file_paths}
        self.assertIn("tap0901.sys", names)
        self.assertIn("tap0901.cat", names)

    def test_foreign_drivers_are_not_captured(self):
        directory = self.store / "intelwifi.inf_amd64_1234"
        directory.mkdir()
        (directory / "intelwifi.inf").write_text(FOREIGN_INF, encoding="utf-8")
        self.assertEqual(netstack.scan_driverstore_packages(str(self.store)),
                         [])

    def test_prefers_package_of_the_os_architecture(self):
        x86 = self.store / "oemvista.inf_x86_aaaa"
        x86.mkdir()
        (x86 / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (x86 / "tap0901.sys").write_bytes(b"MZ")
        (x86 / "tap0901.cat").write_bytes(b"MZ")
        arm = self.store / "oemvista.inf_arm64_bbbb"
        arm.mkdir()
        (arm / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (arm / "tap0901.sys").write_bytes(b"MZ")
        (arm / "tap0901.cat").write_bytes(b"MZ")
        packages = netstack.scan_driverstore_packages(str(self.store),
                                                      arch="arm64")
        self.assertEqual(Path(packages[0].inf_path).parent, arm)

    def test_program_files_package_and_tapinstall_are_found(self):
        programs = self.base / "Program Files"
        driver = programs / "TAP-Windows" / "driver"
        driver.mkdir(parents=True)
        (driver / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (driver / "tap0901.sys").write_bytes(b"MZ")
        (driver / "tap0901.cat").write_bytes(b"MZ")
        binary = programs / "TAP-Windows" / "bin"
        binary.mkdir(parents=True)
        (binary / "tapinstall.exe").write_bytes(b"MZ")
        packages = netstack.scan_program_files_packages([str(programs)])
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0].origin, "program-files")
        tools = netstack.find_netstack_tools([str(programs)])
        self.assertEqual(Path(tools[0]).name, "tapinstall.exe")

    def test_system_scan_merges_both_sources(self):
        self._driverstore_package("tap")
        programs = self.base / "PF"
        driver = programs / "TAP-Windows" / "driver"
        driver.mkdir(parents=True)
        (driver / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (driver / "tap0901.sys").write_bytes(b"MZ")
        (driver / "tap0901.cat").write_bytes(b"MZ")
        packages = netstack.scan_system_driver_packages(
            store_dir=str(self.store), program_files=[str(programs)])
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0].origin, "driverstore")

    def test_incomplete_app_package_is_replaced_by_full_system_one(self):
        app = self.base / "App"
        app.mkdir()
        (app / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        app_packages = netstack.scan_net_driver_packages(str(app))
        self.assertEqual(len(app_packages), 1)
        self.assertFalse(netstack.is_complete_driver_package(app_packages[0]))
        system = [netstack.NetDriverPackage(
            kind=netstack.KIND_TAP_WINDOWS, service="tap0901",
            device_id="tap0901", inf_path=str(self.base / "x.inf"),
            file_paths=[str(self.base / "tap0901.sys"),
                        str(self.base / "tap.cat")],
            origin="driverstore")]
        merged = netstack.merge_driver_packages(app_packages, system)
        self.assertIs(merged[0], system[0])
        self.assertEqual(merged[0].origin, "driverstore")

    def test_complete_app_package_wins_and_gets_the_tool(self):
        app = self.base / "App2"
        app.mkdir()
        (app / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (app / "tap0901.sys").write_bytes(b"MZ")
        (app / "tap0901.cat").write_bytes(b"MZ")
        packages = netstack.scan_net_driver_packages(str(app))
        self.assertTrue(netstack.is_complete_driver_package(packages[0]))
        tool = self.base / "tapinstall.exe"
        tool.write_bytes(b"MZ")
        packages = netstack.attach_netstack_tools(packages, [str(tool)])
        self.assertEqual(packages[0].origin, "app")
        self.assertEqual(Path(packages[0].tool_path), tool)

    def test_vpn_hint(self):
        self.assertTrue(netstack.looks_like_vpn("Planeta VPN"))
        self.assertTrue(netstack.looks_like_vpn("", "planetvpn-setup.exe"))
        self.assertTrue(netstack.looks_like_vpn("WireGuard"))
        self.assertFalse(netstack.looks_like_vpn("Notepad++", "setup.exe"))


class SystemPackageProvisionTests(unittest.TestCase):
    """Пакет из системы должен доехать до NetStack целиком."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.root = self.base / "PlanetaVPN_Portable"
        self.app = self.root / "App"
        self.app.mkdir(parents=True)
        self.store = self.base / "store"
        package_dir = self.store / "oemvista.inf_amd64_1"
        package_dir.mkdir(parents=True)
        (package_dir / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (package_dir / "tap0901.sys").write_bytes(b"MZ")
        (package_dir / "tap0901.cat").write_bytes(b"MZ")
        self.packages = netstack.scan_driverstore_packages(str(self.store))

    def provision(self):
        report = netstack.provision_netstack(str(self.root), str(self.app),
                                             self.packages, [])
        self.assertIsNotNone(report)
        return report

    def test_system_package_is_copied_with_driver_and_catalog(self):
        report = self.provision()
        drivers = self.root / "NetStack" / "Drivers" / "tap-windows"
        self.assertTrue((drivers / "OemVista.inf").is_file())
        self.assertEqual((drivers / "tap0901.sys").read_bytes(), b"MZ")
        self.assertTrue((drivers / "tap0901.cat").is_file())
        manifest = json.loads((self.root / "NetStack" / "netstack.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(manifest["drivers"][0]["device_id"], "tap0901")
        self.assertTrue(manifest["drivers"][0]["inf"].startswith(
            "NetStack/Drivers/"))
        config = report.to_config()
        self.assertEqual(config["driver_services"], ["tap0901"])
        # Служба без устройства — не «готово»: лончер проверяет и адаптер.
        self.assertEqual(config["driver_devices"], ["tap0901"])

    def test_tool_from_the_system_is_copied_to_bin(self):
        tool = self.base / "tapinstall.exe"
        tool.write_bytes(b"MZ")
        self.packages = netstack.attach_netstack_tools(self.packages,
                                                       [str(tool)])
        report = self.provision()
        self.assertTrue((self.root / "NetStack" / "bin"
                         / "tapinstall.exe").is_file())
        manifest = json.loads((self.root / "NetStack" / "netstack.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(manifest["drivers"][0]["tool"],
                         "NetStack/bin/tapinstall.exe")
        setup = (self.root / "NetStack" / "Setup.cmd").read_text(
            encoding="ascii")
        self.assertIn("SetupAPI", setup)

    def test_setup_script_does_not_pretend_pnputil_can_add_devices(self):
        self.provision()
        setup = (self.root / "NetStack" / "Setup.cmd").read_text(
            encoding="ascii")
        self.assertFalse(_command_lines_with(setup, "/add-device"))
        self.assertIn("/scan-devices", setup)
        ps1 = (self.root / "NetStack" / "NetStackServices.ps1").read_text(
            encoding="utf-8-sig")
        self.assertIn("Find-HwidDevices", ps1)
        self.assertIn("RootDevice", ps1)
        # Проверка адаптера — отдельно от проверки службы.
        self.assertIn("exit 3", ps1)


class BuildIntegrationTests(unittest.TestCase):
    """Сборка портатива: драйвер с ПК-сборщика попадает в NetStack."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.root = self.base / "PlanetaVPN_Portable"
        self.app = self.root / "App"
        self.app.mkdir(parents=True)
        store = self.base / "store" / "tap0901.inf_amd64_1"
        store.mkdir(parents=True)
        (store / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (store / "tap0901.sys").write_bytes(b"MZ")
        (store / "tap0901.cat").write_bytes(b"MZ")
        tool = self.base / "tapinstall.exe"
        tool.write_bytes(b"MZ")
        self.store = self.base / "store"
        self.tool = tool

    def test_build_takes_the_driver_from_the_build_pc(self):
        from portablizer.core import portablizer as engine_mod
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import (PortableOptions,
                                                  PortableResult)
        engine = engine_mod.Portablizer(Logger())
        opts = PortableOptions(installer_path=str(self.base / "planetvpn.exe"),
                               output_dir=str(self.base))
        result = PortableResult(success=True)
        scanned = netstack.scan_driverstore_packages(str(self.store))
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(netstack, "scan_system_driver_packages",
                                  return_value=scanned), \
                mock.patch.object(netstack, "find_netstack_tools",
                                  return_value=[str(self.tool)]), \
                mock.patch.object(engine_mod.procutil, "services_in",
                                  return_value=[]):
            report = engine._provision_netstack(
                str(self.root), str(self.app), opts, result,
                vpn_hint=True)
        self.assertIsNotNone(report)
        self.assertTrue((self.root / "NetStack" / "Drivers" / "tap-windows"
                         / "tap0901.sys").is_file())
        self.assertTrue((self.root / "NetStack" / "bin"
                         / "tapinstall.exe").is_file())
        self.assertEqual(result.netstack_drivers, ["tap0901"])
        config = report.to_config()
        self.assertEqual(config["driver_services"], ["tap0901"])
        self.assertEqual(config["driver_devices"], ["tap0901"])
        # Изолированный сеанс снимает созданный адаптер при выходе, даже
        # когда служб-компаньонов нет.
        self.assertTrue(config["stop_on_exit"])
        self.assertEqual(config["isolation"], "session")
        # Драйвер взят не из App: об этом должна быть строка в отчёте.
        self.assertTrue(any("driverstore" in note for note in report.notes))

    def test_build_without_a_driver_still_succeeds_for_regular_apps(self):
        from portablizer.core import portablizer as engine_mod
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import (PortableOptions,
                                                  PortableResult)
        engine = engine_mod.Portablizer(Logger())
        opts = PortableOptions(installer_path=str(self.base / "setup.exe"),
                               output_dir=str(self.base))
        result = PortableResult(success=True)
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(netstack, "scan_system_driver_packages",
                                  return_value=[]), \
                mock.patch.object(netstack, "find_netstack_tools",
                                  return_value=[]), \
                mock.patch.object(engine_mod.procutil, "services_in",
                                  return_value=[]):
            report = engine._provision_netstack(
                str(self.root), str(self.app), opts, result, vpn_hint=False)
        self.assertIsNone(report)


class ServiceRepairScriptTests(unittest.TestCase):
    """Служба-компаньон должна работать, а не просто существовать.

    Жалоба: клиент писал «Не удалось подключиться ни по одному из протоколов»
    при том, что служба была зарегистрирована. Причина — путь в реестре вёл в
    прежнюю папку (или служба стояла), а проверки смотрели только на факт
    существования ключа.
    """

    def test_script_repairs_a_service_pointing_into_the_old_folder(self):
        ps1 = netstack.render_services_ps1()
        for needle in ("function Get-ServiceExePath",
                       "function Get-ServiceImagePath",
                       "function Test-SamePath",
                       "function Test-ForeignService",
                       "re-registering it for this folder",
                       "did not start",
                       "Write-NetStackStatus"):
            self.assertIn(needle, ps1)
        # Проверка больше не ограничивается наличием ключа службы.
        self.assertIn("Test-SamePath (Get-ServiceExePath $current) $exe", ps1)
        self.assertIn("StartPending", ps1)

    def test_foreign_installation_is_never_hijacked(self):
        ps1 = netstack.render_services_ps1()
        self.assertIn("belongs to another installation", ps1)
        # «Наша» копия узнаётся по PortableData рядом с папкой бинарника.
        self.assertIn("'PortableData'", ps1)

    def test_present_but_disabled_adapter_is_enabled(self):
        ps1 = netstack.render_services_ps1()
        self.assertIn("function Enable-HwidDevices", ps1)
        self.assertIn("Enable-PnpDevice", ps1)
        self.assertIn("/enable-device", ps1)

    def test_ensure_reports_a_service_that_did_not_start(self):
        report = netstack.NetStackReport(
            services=[{"name": "PlanetVPNService", "image": "x", "args": "",
                       "display": "PlanetVPN", "start": "demand"}])
        setup = netstack.render_setup_cmd(report)
        # Код .ps1 теперь авторитетен: 6 доходит до лончера без перетирания
        #.batch-предупреждениями про pnputil.
        self.assertIn('set "NETSTACK_RC=%ERRORLEVEL%"', setup)
        self.assertIn("6 = companion service did not start", setup)
        self.assertIn('if "!ERRORLEVEL!" == "4" if "!NETSTACK_RC!" == "0"', setup)

    def test_state_file_is_named_in_the_script(self):
        self.assertIn("status.txt", netstack.render_services_ps1())


class LauncherHelperAuditTests(unittest.TestCase):
    """В лончере не должно быть вызовов несуществующих функций.

    Именно такая опечатка (`_run_hidden`) отключала ВСЮ починку NetStack:
    ``NameError`` ловился общим ``except``, Setup.cmd не запускался, и клиент
    VPN оставался без адаптера и службы.
    """

    SOURCE_FILES = ("portable_launcher_entry.py",)

    @staticmethod
    def _undefined_names(source: str):
        import ast
        import builtins

        tree = ast.parse(source)
        defined = set(dir(builtins))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                defined.add(node.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    defined.add((alias.asname or alias.name).split(".")[0])
            elif isinstance(node, ast.arg):
                defined.add(node.arg)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                defined.add(node.name)
        return sorted({(node.lineno, node.id) for node in ast.walk(tree)
                       if isinstance(node, ast.Name)
                       and isinstance(node.ctx, ast.Load)
                       and node.id not in defined and node.id != "__file__"})

    def test_no_call_goes_to_a_name_the_launcher_does_not_have(self):
        for name in self.SOURCE_FILES:
            path = Path(__file__).resolve().parent.parent / name
            missing = self._undefined_names(path.read_text(encoding="utf-8"))
            self.assertEqual(missing, [], f"{name}: неизвестные имена {missing}")

    def test_hidden_runner_exists_and_returns_exit_codes(self):
        self.assertTrue(callable(exe_launcher._run_hidden))
        with mock.patch.object(exe_launcher, "IS_WINDOWS", False):
            self.assertIsNone(exe_launcher._run_hidden(["cmd.exe", "/c", "x"]))
        completed = mock.Mock(returncode=6)
        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher.subprocess, "run",
                                  return_value=completed) as run:
            code = exe_launcher._run_hidden(["cmd.exe", "/c", "x"])
        self.assertEqual(code, 6)
        self.assertEqual(run.call_args.args[0], ["cmd.exe", "/c", "x"])
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_hidden_runner_survives_a_missing_command(self):
        with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                mock.patch.object(exe_launcher.subprocess, "run",
                                  side_effect=OSError("no cmd")):
            self.assertIsNone(exe_launcher._run_hidden(["cmd.exe"]))

    def test_elevated_runner_delegates_to_the_scripts_own_elevation(self):
        with mock.patch.object(exe_launcher, "_run_hidden",
                               return_value=0) as hidden:
            code = exe_launcher._run_hidden_elevated(
                "cmd.exe", ["/c", "Setup.cmd"], timeout=30)
        self.assertEqual(code, 0)
        self.assertEqual(hidden.call_args.args[0], ["cmd.exe", "/c", "Setup.cmd"])

    def test_every_netstack_exit_code_is_explained(self):
        expected = {3: "adapter", 4: "service", 6: "did not start"}
        for code, needle in expected.items():
            self.assertIn(needle, exe_launcher._netstack_code_note(code).lower())
        self.assertEqual(exe_launcher._netstack_code_note(None), "")
        self.assertEqual(exe_launcher._netstack_code_note(0), "")


class NetstackVerifyRuntimeTests(unittest.TestCase):
    """Лончер обязан проверить результат, а не поверить коду возврата."""

    def _root(self, tmp: str) -> Path:
        root = Path(tmp)
        (root / "NetStack").mkdir(parents=True)
        (root / "NetStack" / "Setup.cmd").write_text("@echo off",
                                                     encoding="ascii")
        return root

    def test_verify_failure_is_reported_in_the_run_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            cfg = {"netstack": {"setup": "NetStack/Setup.cmd"}}
            codes = []

            def fake_hidden(arguments, **_kwargs):
                codes.append(arguments[-1])
                # --check до починки: служба остановлена; после: всё хорошо.
                return 4 if len(codes) == 1 else 0

            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_hidden",
                                      side_effect=fake_hidden), \
                    mock.patch.object(exe_launcher, "_run_netstack_script",
                                      return_value=6) as setup, \
                    mock.patch.object(exe_launcher, "netstack_missing",
                                      return_value=[]):
                notes = exe_launcher.ensure_netstack(root, cfg)

            self.assertTrue(setup.called)
            self.assertEqual(codes.count("--check") >= 1, True)
            text = "\n".join(notes)
            self.assertIn("exit code 6", text)
            self.assertIn("did not start", text)
            self.assertTrue(any("verify" in line.lower() for line in notes))

    def test_a_ready_machine_does_not_ask_for_rights(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            cfg = {"netstack": {"setup": "NetStack/Setup.cmd"}}
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(exe_launcher, "_run_hidden",
                                      return_value=0), \
                    mock.patch.object(exe_launcher, "_run_netstack_script",
                                      side_effect=AssertionError("must not run")), \
                    mock.patch.object(exe_launcher, "netstack_missing",
                                      return_value=[]):
                notes = exe_launcher.ensure_netstack(root, cfg)
            self.assertEqual(notes, [])


class CapturedServiceRetirementTests(unittest.TestCase):
    """Служба, уехавшая в NetStack, снимается со сборочного ПК."""

    def _engine(self):
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import Portablizer
        return Portablizer(Logger())

    def _report(self, isolation: str = "session"):
        return netstack.NetStackReport(
            services=[{"name": "PlanetVPNService"}],
            isolation=isolation)

    def test_service_from_the_manifest_is_removed_and_explained(self):
        from portablizer.core import portablizer as engine_mod
        engine = self._engine()
        ref = engine_mod.procutil.ServiceRef(
            "PlanetVPNService", r"E:\P\App\PlanetVPNService.exe")
        with mock.patch.object(engine_mod.procutil, "services_in_detail",
                               return_value=[ref]), \
                mock.patch.object(engine_mod.procutil, "remove_services",
                                  return_value=[]) as remove:
            engine._retire_captured_services(r"E:\P", self._report())

        remove.assert_called_once()
        text = engine.log.text
        self.assertIn("сняты с этого ПК", text)
        self.assertIn("PlanetVPNService", text)

    def test_stuck_service_is_not_hidden_from_the_user(self):
        from portablizer.core import portablizer as engine_mod
        engine = self._engine()
        ref = engine_mod.procutil.ServiceRef(
            "PlanetVPNService", r"E:\P\App\PlanetVPNService.exe")
        with mock.patch.object(engine_mod.procutil, "services_in_detail",
                               return_value=[ref]), \
                mock.patch.object(engine_mod.procutil, "remove_services",
                                  return_value=["PlanetVPNService"]):
            engine._retire_captured_services(r"E:\P", self._report())

        self.assertIn("права администратора", engine.log.text)

    def test_service_outside_the_manifest_is_not_touched(self):
        from portablizer.core import portablizer as engine_mod
        engine = self._engine()
        ref = engine_mod.procutil.ServiceRef(
            "SomebodyElse", r"E:\P\App\other.exe")
        with mock.patch.object(engine_mod.procutil, "services_in_detail",
                               return_value=[ref]), \
                mock.patch.object(engine_mod.procutil, "remove_services",
                                  side_effect=AssertionError("must not remove")):
            engine._retire_captured_services(r"E:\P", self._report())

    def test_shared_mode_is_not_reported_as_a_failure(self):
        """В общем режиме служба остаётся намеренно — и так и говорится."""
        from portablizer.core import portablizer as engine_mod
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import PortableResult
        engine = engine_mod.Portablizer(Logger())
        engine._netstack_shared = True
        result = PortableResult(success=True)
        result.netstack_services = ["PlanetVPNService"]
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(engine_mod.procutil, "services_in",
                                  return_value=["PlanetVPNService"]):
            engine._report_portable_services(r"E:\P", result)

        text = engine.log.text
        self.assertIn("намеренно", text)
        self.assertNotIn("не удалось", text)

    def test_shared_mode_keeps_the_service_for_other_programs(self):
        from portablizer.core import portablizer as engine_mod
        engine = self._engine()
        with mock.patch.object(engine_mod.procutil, "services_in_detail",
                               side_effect=AssertionError("must not look")):
            engine._retire_captured_services(r"E:\P", self._report("shared"))


class Tap0901RegressionTests(unittest.TestCase):
    """Жалоба: pnputil «не найден файл», Setup 3/3, check 2, healthy=True."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "planetvpn_Portable"
        self.app = self.root / "App"
        self.driver = self.app / "driver"
        self.driver.mkdir(parents=True)
        (self.driver / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")

    def test_inf_only_bundle_is_marked_incomplete_and_preflight_blocks_uac(self):
        packages = netstack.scan_net_driver_packages(str(self.app))
        report = netstack.provision_netstack(str(self.root), str(self.app),
                                             packages, [])
        self.assertIsNotNone(report)
        self.assertFalse(report.complete)
        entry = report.drivers[0]
        self.assertEqual(entry["complete"], "0")
        self.assertIn("tap0901.sys", entry["missing_files"])
        self.assertIn("tap0901.cat", entry["missing_files"])
        setup = (self.root / "NetStack" / "Setup.cmd").read_text(encoding="ascii")
        lines = setup.splitlines()
        preflight = next(i for i, line in enumerate(lines)
                         if "-Mode preflight" in line)
        uac = next(i for i, line in enumerate(lines)
                   if "Start-Process -Verb RunAs" in line)
        self.assertLess(preflight, uac)
        self.assertIn('if "%ERRORLEVEL%" == "2" (set "NETSTACK_RC=2"', setup)
        ps1 = (self.root / "NetStack" / "NetStackServices.ps1").read_text(
            encoding="utf-8-sig")
        self.assertIn("function Test-NetStackPackages", ps1)
        self.assertIn("DEVPKEY_Device_HardwareIds", ps1)
        self.assertFalse([line for line in ps1.splitlines()
                          if "$d.HardwareID" in line
                          and not line.strip().startswith("#")])
        self.assertIn("driver ' + $svcName + ': ' + $svcState", ps1)
        self.assertIn("$healthy = ($serviceHealthy -and $driverHealthy)", ps1)

    def test_required_files_keep_subdirectories_when_copied(self):
        nested = self.driver / "amd64"
        nested.mkdir()
        (nested / "tap0901.sys").write_bytes(b"MZ")
        (self.driver / "tap0901.cat").write_bytes(b"cat")
        inf = TAP_INF.replace("tap0901.sys = 1", "tap0901.sys = 1, amd64")
        (self.driver / "OemVista.inf").write_text(inf, encoding="utf-8")
        packages = netstack.scan_net_driver_packages(str(self.app))
        report = netstack.provision_netstack(str(self.root), str(self.app),
                                             packages, [])
        self.assertTrue(report.complete)
        copied = self.root / "NetStack" / "Drivers" / "tap-windows"
        self.assertTrue((copied / "amd64" / "tap0901.sys").is_file())
        self.assertTrue((copied / "tap0901.cat").is_file())

    def test_launcher_does_not_retry_missing_package_or_declined_uac(self):
        for code in (2, 5, 1223):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "NetStack").mkdir()
                (root / "NetStack" / "Setup.cmd").write_text("@echo off")
                cfg = {"netstack": {"setup": "NetStack/Setup.cmd"}}
                with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                        mock.patch.object(exe_launcher, "netstack_missing",
                                          return_value=["tap0901"]), \
                        mock.patch.object(exe_launcher, "_run_hidden",
                                          return_value=code), \
                        mock.patch.object(exe_launcher, "_run_netstack_script",
                                          return_value=code) as setup, \
                        mock.patch.object(exe_launcher, "_show_warning"):
                    notes = exe_launcher.ensure_netstack(root, cfg)
                self.assertEqual(setup.call_count, 1)
                self.assertFalse(any("retry" in note for note in notes))

    def test_refresh_regenerates_old_netstack_scripts_and_marks_missing(self):
        netstack_dir = self.root / "NetStack"
        netstack_dir.mkdir(parents=True)
        drivers = netstack_dir / "Drivers" / "tap-windows"
        drivers.mkdir(parents=True)
        (drivers / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        (netstack_dir / "netstack.json").write_text(json.dumps({
            "schema": 1, "isolation": "session", "root_token": "@@PORTABLE_ROOT@@",
            "drivers": [{"kind": "tap-windows", "service": "tap0901",
                         "device_id": "tap0901", "needs_install": "1",
                         "inf": "NetStack/Drivers/tap-windows/OemVista.inf"}],
            "services": [], "state_dir": "PortableData/NetStack",
            "created_services_file": "created-services.txt"}), encoding="utf-8")
        (netstack_dir / "Setup.cmd").write_text("@echo off\r\nrem old\r\n")
        updated = netstack.refresh_netstack_scripts(str(self.root))
        self.assertIn("NetStack/Setup.cmd", updated)
        manifest = json.loads((netstack_dir / "netstack.json").read_text())
        self.assertEqual(manifest["drivers"][0]["complete"], "0")
        self.assertEqual(manifest["drivers"][0]["hardware_id"], "root\\tap0901")
        setup = (netstack_dir / "Setup.cmd").read_text(encoding="ascii")
        self.assertIn("-Mode preflight", setup)


class DeviceEnumDepthTests(unittest.TestCase):
    """HardwareID живёт на уровне ЭКЗЕМПЛЯРА, а не устройства.

    Enum\\ROOT\\NET\\0000, а не Enum\\ROOT\\NET. Прежний обход читал
    значение на уровень выше, поэтому установленный адаптер не находился
    никогда: лончер считал tap0901 отсутствующим и просил UAC каждый запуск,
    а Teardown получал обрезанный Instance ID и не мог удалить устройство.
    """

    def test_python_probe_reads_the_instance_level(self):
        opened = []

        class FakeKey:
            def __init__(self, path):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

        tree = {
            "SYSTEM\\CurrentControlSet\\Enum": ["ROOT"],
            "SYSTEM\\CurrentControlSet\\Enum\\ROOT": ["NET"],
            "SYSTEM\\CurrentControlSet\\Enum\\ROOT\\NET": ["0000"],
        }

        class FakeWinreg:
            HKEY_LOCAL_MACHINE = "HKLM"

            @staticmethod
            def OpenKey(_root, path):
                opened.append(path)
                if path not in tree and not path.endswith("0000"):
                    raise OSError("no key")
                return FakeKey(path)

            @staticmethod
            def QueryInfoKey(key):
                return (len(tree.get(key.path, [])), 0)

            @staticmethod
            def EnumKey(key, index):
                names = tree.get(key.path, [])
                if index >= len(names):
                    raise OSError("no more keys")  # real winreg raises OSError
                return names[index]

            @staticmethod
            def QueryValueEx(key, name):
                # Only the instance key carries HardwareID.
                if key.path.endswith("NET\\0000") and name == "HardwareID":
                    return (["root\\tap0901"], 7)
                raise OSError("no value")

        with mock.patch.dict(sys.modules, {"winreg": FakeWinreg}), \
                mock.patch.object(exe_launcher, "IS_WINDOWS", True):
            self.assertTrue(exe_launcher._device_hwid_present("tap0901"))
        self.assertIn("SYSTEM\\CurrentControlSet\\Enum\\ROOT\\NET\\0000",
                      opened)

    def test_python_probe_rejects_a_similar_hardware_id(self):
        src = Path(exe_launcher.__file__).read_text(encoding="utf-8")
        body = src.split("def _device_hwid_present")[1].split("\ndef ")[0]
        self.assertIn("if text in wanted:", body)
        self.assertNotIn("if needle in ", body)

    def test_powershell_fallback_walks_three_levels_and_judges_readiness(self):
        ps1 = netstack.render_services_ps1()
        self.assertIn("foreach ($inst in @(Get-ChildItem -LiteralPath $dev.PSPath",
                      ps1)
        self.assertIn("$dev.PSChildName + '\\' + $inst.PSChildName", ps1)
        # Unknown is no longer hard-coded: Driver + ConfigFlags decide.
        self.assertIn("if ($props.Driver)", ps1)
        self.assertIn("CONFIGFLAG_DISABLED", ps1)
        self.assertNotIn("Status = 'Unknown'", ps1)

    def test_inf_validation_is_architecture_aware(self):
        inf = ("[Version]\nClass=Net\nCatalogFile=tap0901.cat\n"
               "CatalogFile.ntamd64=tap64.cat\n"
               "[SourceDisksFiles]\ntap0901.sys=1\n"
               "[SourceDisksFiles.amd64]\ntap64.sys=1\n"
               "[SourceDisksFiles.x86]\ntap32.sys=1\n")
        amd64 = netstack.inf_required_files(inf, "amd64")
        self.assertIn("tap64.sys", amd64)
        self.assertNotIn("tap32.sys", amd64)
        x86 = netstack.inf_required_files(inf, "x86")
        self.assertIn("tap32.sys", x86)
        self.assertNotIn("tap64.sys", x86)
        self.assertNotIn("tap64.cat", x86)


class PowerShellSyntaxGuardTests(unittest.TestCase):
    """Сгенерированные .ps1/.cmd должны хотя бы разбираться Windows.

    Тест выполняется только там, где есть powershell (то есть на Windows-
    раннере): на Linux он честно пропускается. Без него синтаксическая
    ошибка в C#-вставке Add-Type всплывала бы уже на компьютере пользователя.
    """

    def _powershell(self):
        import shutil
        return shutil.which("powershell") or shutil.which("pwsh")

    def test_generated_ps1_parses(self):
        import subprocess
        shell = self._powershell()
        if not shell:
            self.skipTest("PowerShell недоступен")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "NetStackServices.ps1"
            path.write_text(netstack.render_services_ps1(),
                            encoding="utf-8-sig")
            probe = ("$ErrorActionPreference='Stop'; "
                     "$null = [scriptblock]::Create("
                     "(Get-Content -Raw -LiteralPath '" + str(path) + "')); "
                     "exit 0")
            result = subprocess.run([shell, "-NoProfile", "-Command", probe],
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_ps1_runs_check_and_ensure_without_drivers(self):
        """Пустой манифест: скрипт обязан дойти до конца обоих режимов.

        Это ловит не только синтаксис, но и ошибки выполнения в новых
        функциях (Find-HwidDevices, Ensure-NetAdapters) — на Linux-машине
        без PowerShell тест честно пропускается.
        """
        import subprocess
        shell = self._powershell()
        if not shell:
            self.skipTest("PowerShell недоступен")
        with tempfile.TemporaryDirectory() as tmp:
            portable = Path(tmp) / "Планета VPN Portable"
            netstack_dir = portable / "NetStack"
            netstack_dir.mkdir(parents=True)
            (portable / "PortableData" / "NetStack").mkdir(parents=True)
            (netstack_dir / "NetStackServices.ps1").write_text(
                netstack.render_services_ps1(), encoding="utf-8-sig")
            manifest = {"schema": 1, "isolation": "session",
                        "root_token": "@@PORTABLE_ROOT@@",
                        "drivers": [], "services": [],
                        "state_dir": "PortableData/NetStack",
                        "created_services_file": "created-services.txt"}
            (netstack_dir / "netstack.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            for mode in ("check", "ensure"):
                result = subprocess.run(
                    [shell, "-NoProfile", "-ExecutionPolicy", "Bypass",
                     "-File", str(netstack_dir / "NetStackServices.ps1"),
                     "-Mode", mode],
                    capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0,
                                 mode + ": " + result.stderr)

    def test_embedded_csharp_compiles(self):
        """Add-Type-вставка должна компилироваться (иначе адаптер не создать)."""
        import re
        import subprocess
        shell = self._powershell()
        if not shell:
            self.skipTest("PowerShell недоступен")
        text = netstack.render_services_ps1()
        found = re.search(r"\$source = @'\r?\n(.*?)\r?\n'@", text, re.S)
        self.assertIsNotNone(found, "C#-вставка не найдена в .ps1")
        assert found is not None
        source = found.group(1)
        with tempfile.TemporaryDirectory() as tmp:
            cs = Path(tmp) / "RootDevice.cs"
            cs.write_text(source, encoding="utf-8")
            probe = ("$ErrorActionPreference='Stop'; "
                     "Add-Type -TypeDefinition (Get-Content -Raw -LiteralPath '"
                     + str(cs) + "') -ErrorAction Stop; "
                     "if (-not ('PortablizerNetStack.RootDevice' -as [type])) "
                     "{ exit 2 }; exit 0")
            result = subprocess.run([shell, "-NoProfile", "-Command", probe],
                                    capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
