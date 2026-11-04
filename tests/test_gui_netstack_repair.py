"""Починка драйверов VPN из интерфейса — вместо консольной команды.

Жалоба: лечить портатив приходилось вручную, набирая
``Portablizer.exe repair-netstack <папка> --from-installer <установщик>``.
Здесь проверяется, что то же самое делает кнопка «Починить драйверы VPN»:
показывает, каких файлов не хватает, спрашивает источник и чинит в фоне.

Тесты ядра (``RepairNetStackCoreTests``) идут всегда. Тесты окна
(``RepairNetStackGuiTests``) пропускаются, если PySide6 не установлен или Qt
не может создать приложение (машина без графики) — как в остальных
GUI-наборах этого репозитория.
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

try:  # pragma: no cover - зависит от окружения
    from PySide6.QtWidgets import QApplication, QMessageBox

    _QT_ERROR = ""
except Exception as exc:  # noqa: BLE001 - нет PySide6 или системных библиотек
    QApplication = None
    QMessageBox = None
    _QT_ERROR = f"{type(exc).__name__}: {exc}"

from portablizer.core import driverpayload, maintenance, netstack, unpacker
from test_driverpayload import (  # noqa: E402 - общий набор-помощник
    TAP_INF, _fake_extractors, _write_package, _zip_of, _zip_runner,
)


def _qt_app():
    """Единственный на процесс ``QApplication`` или ``None``."""
    if QApplication is None:
        return None
    app = QApplication.instance()
    if app is not None:
        return app
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        return QApplication([])
    except Exception:  # noqa: BLE001 - нет дисплея/библиотек
        return None


class _PortableFixture(unittest.TestCase):
    """Портатив с одним INF (собран до 1.45.0) + установщик с пакетом."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "portable"
        self.driver = self.root / "NetStack" / "Drivers" / "tap-windows"
        self.driver.mkdir(parents=True)
        (self.root / "App").mkdir()
        (self.driver / "OemVista.inf").write_text(TAP_INF, encoding="utf-8")
        self._manifest()
        payload = self.tmp / "payload"
        _write_package(payload)
        self.installer = _zip_of(payload, self.tmp / "planetvpn_setup.exe")

    def _manifest(self, drivers=None, isolation="session"):
        if drivers is None:
            drivers = [{
                "kind": "tap-windows", "service": "tap0901",
                "device_id": "tap0901", "needs_install": "1",
                "inf": "NetStack/Drivers/tap-windows/OemVista.inf",
                "required_files": "tap0901.sys;tap0901.cat",
                "complete": "0", "missing_files": "tap0901.sys;tap0901.cat",
            }]
        (self.root / "NetStack" / "netstack.json").write_text(json.dumps({
            "isolation": isolation, "drivers": drivers, "services": [],
        }), encoding="utf-8")

    def _fake_extraction(self):
        return (
            mock.patch.object(driverpayload.unpacker, "find_extractors",
                              return_value=_fake_extractors()),
            mock.patch.object(unpacker, "_default_runner",
                              side_effect=_zip_runner),
        )


class InspectNetStackTests(_PortableFixture):
    """Окно обязано видеть правду до починки, а не флажок в манифесте."""

    def test_missing_files_are_reported_by_name(self):
        state = netstack.inspect_netstack(str(self.root))
        self.assertTrue(state.present)
        self.assertTrue(state.has_installable)
        self.assertFalse(state.complete)
        self.assertEqual(len(state.missing), 1)
        self.assertIn("tap0901", state.missing[0])
        self.assertIn("tap0901.sys", state.missing[0])
        self.assertIn("tap0901.cat", state.missing[0])

    def test_stale_manifest_claiming_complete_is_not_believed(self):
        self._manifest([{
            "kind": "tap-windows", "service": "tap0901",
            "device_id": "tap0901", "needs_install": "1",
            "inf": "NetStack/Drivers/tap-windows/OemVista.inf",
            "required_files": "tap0901.sys;tap0901.cat",
            "complete": "1", "missing_files": "",
        }])
        state = netstack.inspect_netstack(str(self.root))
        self.assertFalse(state.complete)

    def test_complete_package_is_reported_ready(self):
        (self.driver / "tap0901.sys").write_bytes(b"MZ")
        (self.driver / "tap0901.cat").write_bytes(b"cat")
        state = netstack.inspect_netstack(str(self.root))
        self.assertTrue(state.complete)
        self.assertEqual(state.ready, ["tap0901"])

    def test_folder_without_netstack_is_not_an_error(self):
        state = netstack.inspect_netstack(str(self.tmp))
        self.assertFalse(state.present)
        self.assertFalse(state.complete)

    def test_wintun_only_portable_needs_no_repair(self):
        """Адаптер wintun создаёт приложение — портативу ставить нечего."""
        self._manifest([{
            "kind": "wintun", "service": "wintun", "needs_install": "",
            "inf": "", "complete": "1",
        }])
        state = netstack.inspect_netstack(str(self.root))
        self.assertTrue(state.present)
        self.assertFalse(state.has_installable)


class RepairNetStackCoreTests(_PortableFixture):
    """Та же операция, что запускает кнопка, но без Qt."""

    def test_installer_completes_the_package_and_refreshes_scripts(self):
        first, second = self._fake_extraction()
        with first, second:
            report = maintenance.repair_netstack(
                str(self.root), str(self.installer))
        self.assertTrue(report.success, report.messages)
        self.assertTrue(netstack.inspect_netstack(str(self.root)).complete)
        names = sorted(p.name for p in self.driver.iterdir())
        self.assertEqual(names, ["OemVista.inf", "tap0901.cat", "tap0901.sys"])
        self.assertIn("NetStack/Setup.cmd", report.updated)
        self.assertIn("Драйверы VPN укомплектованы", report.messages[-1])

    def test_existing_files_are_not_overwritten(self):
        (self.driver / "tap0901.sys").write_bytes(b"VENDOR-NEWER")
        first, second = self._fake_extraction()
        with first, second:
            maintenance.repair_netstack(str(self.root), str(self.installer))
        self.assertEqual((self.driver / "tap0901.sys").read_bytes(),
                         b"VENDOR-NEWER")

    def test_failure_is_reported_honestly_not_as_success(self):
        """Нет ни установщика, ни пакета в системе — успехом это не будет."""
        with mock.patch.object(netstack, "scan_system_driver_packages",
                               return_value=[]):
            report = maintenance.repair_netstack(str(self.root))
        self.assertFalse(report.success)
        self.assertIn("Не хватает", report.messages[-1])
        self.assertIn("tap0901.sys", report.messages[-1])

    def test_system_source_is_used_when_no_installer_given(self):
        package_dir = self.tmp / "system"
        _write_package(package_dir)
        package = netstack._package_from_directory(
            str(package_dir / "OemVista.inf"), "system")
        self.assertIsNotNone(package)
        with mock.patch.object(netstack, "scan_system_driver_packages",
                               return_value=[package]):
            report = maintenance.repair_netstack(str(self.root))
        self.assertTrue(report.success, report.messages)
        self.assertTrue((self.driver / "tap0901.sys").is_file())

    def test_missing_folder_fails_without_raising(self):
        report = maintenance.repair_netstack(str(self.tmp / "absent"))
        self.assertFalse(report.success)
        self.assertIn("Папка не найдена", report.messages[-1])

    def test_portable_without_netstack_is_left_alone(self):
        report = maintenance.repair_netstack(str(self.tmp))
        self.assertFalse(report.success)
        self.assertIn("нет NetStack", report.messages[-1])

    def test_nonexistent_installer_is_reported(self):
        report = maintenance.repair_netstack(
            str(self.root), str(self.tmp / "absent.exe"))
        self.assertFalse(report.success)
        self.assertIn("Установщик не найден", report.messages[-1])

    def test_already_complete_package_still_refreshes_scripts(self):
        (self.driver / "tap0901.sys").write_bytes(b"MZ")
        (self.driver / "tap0901.cat").write_bytes(b"cat")
        report = maintenance.repair_netstack(str(self.root))
        self.assertTrue(report.success, report.messages)
        self.assertIn("NetStack/Setup.cmd", report.updated)


@unittest.skipIf(QApplication is None, f"PySide6 недоступен: {_QT_ERROR}")
class RepairNetStackGuiTests(_PortableFixture):
    """Кнопка в окне: диалог с причиной, выбор источника, фон, блокировки."""

    def setUp(self):
        super().setUp()
        self.app = _qt_app()
        if self.app is None:
            self.skipTest("Qt не может создать приложение (нет графики)")
        from portablizer.gui.main_window import MainWindow

        self.window = MainWindow()
        self.addCleanup(self.window.close)
        self.window.maintenance_edit.setText(str(self.root))

    def _dialog(self, click: str = ""):
        """Показать диалог, нажав ``click`` (пусто — Отмена)."""
        holder = {}
        original = QMessageBox.addButton

        def capture(box, *args, **kwargs):
            button = original(box, *args, **kwargs)
            holder[button.text()] = button
            return button

        seen = {}

        def fake_exec(box):
            seen["text"] = box.text()
            seen["buttons"] = [b.text() for b in box.buttons()]
            return 0

        with mock.patch.object(QMessageBox, "addButton", capture), \
                mock.patch.object(QMessageBox, "exec", fake_exec), \
                mock.patch.object(QMessageBox, "clickedButton",
                                  lambda box: holder.get(click)), \
                mock.patch.object(self.window, "_maintenance") as run:
            self.window._repair_netstack()
        return seen, run

    def test_button_exists_in_the_maintenance_card(self):
        self.assertEqual(self.window.netstack_btn.text(),
                         "Починить драйверы VPN")
        self.assertTrue(self.window.netstack_btn.isVisibleTo(
            self.window.netstack_btn.parentWidget()))

    def test_dialog_names_the_missing_files_and_both_sources(self):
        seen, run = self._dialog()
        self.assertIn("tap0901.sys", seen["text"])
        self.assertIn("tap0901.cat", seen["text"])
        self.assertIn("не запускается", seen["text"])
        self.assertIn("Выбрать установщик…", seen["buttons"])
        self.assertIn("С этого компьютера", seen["buttons"])
        self.assertFalse(run.called, "Отмена не должна ничего запускать")

    def test_local_source_starts_the_netstack_action(self):
        _, run = self._dialog("С этого компьютера")
        run.assert_called_once_with("netstack", "")

    def test_chosen_installer_reaches_the_worker(self):
        with mock.patch("portablizer.gui.main_window.QFileDialog.getOpenFileName",
                        return_value=(str(self.installer), "")):
            _, run = self._dialog("Выбрать установщик…")
        run.assert_called_once_with("netstack", str(self.installer))

    def test_cancelling_the_file_picker_starts_nothing(self):
        with mock.patch("portablizer.gui.main_window.QFileDialog.getOpenFileName",
                        return_value=("", "")):
            _, run = self._dialog("Выбрать установщик…")
        self.assertFalse(run.called)

    def test_complete_package_asks_no_source_and_just_refreshes(self):
        (self.driver / "tap0901.sys").write_bytes(b"MZ")
        (self.driver / "tap0901.cat").write_bytes(b"cat")
        with mock.patch.object(QMessageBox, "information") as info, \
                mock.patch.object(self.window, "_maintenance") as run:
            self.window._repair_netstack()
        self.assertTrue(info.called)
        self.assertIn("уже укомплектован", info.call_args[0][2])
        run.assert_called_once_with("netstack", "")

    def test_portable_without_netstack_is_explained_not_repaired(self):
        self.window.maintenance_edit.setText(str(self.tmp))
        with mock.patch.object(QMessageBox, "information") as info, \
                mock.patch.object(self.window, "_maintenance") as run:
            self.window._repair_netstack()
        self.assertTrue(info.called)
        self.assertFalse(run.called)

    def test_absent_folder_is_rejected_before_any_dialog(self):
        self.window.maintenance_edit.setText(str(self.tmp / "absent"))
        with mock.patch.object(QMessageBox, "warning") as warn, \
                mock.patch.object(self.window, "_maintenance") as run:
            self.window._repair_netstack()
        self.assertTrue(warn.called)
        self.assertFalse(run.called)

    def test_worker_runs_the_repair_and_reports_success(self):
        from portablizer.gui.worker import MaintenanceWorker

        reports = []
        first, second = self._fake_extraction()
        with first, second:
            worker = MaintenanceWorker(str(self.root), "netstack",
                                       str(self.installer))
            worker.finished_report.connect(reports.append)
            worker.run()
        self.assertEqual(len(reports), 1)
        self.assertTrue(reports[0].success, reports[0].messages)
        self.assertTrue(netstack.inspect_netstack(str(self.root)).complete)

    def test_buttons_are_disabled_while_repair_is_running(self):
        with mock.patch("portablizer.gui.main_window.MaintenanceWorker") as cls:
            worker = cls.return_value
            worker.isRunning.return_value = False
            self.window._maintenance("netstack", "")
        self.assertFalse(self.window.netstack_btn.isEnabled())
        self.assertFalse(self.window.startmenu_btn.isEnabled())
        self.assertFalse(self.window.release_btn.isEnabled())

    def test_buttons_come_back_after_the_report(self):
        from portablizer.core.maintenance import MaintenanceReport

        self.window.netstack_btn.setEnabled(False)
        # Итог обслуживания показывается модальным окном: без подмены тест
        # остановится навсегда в ожидании клика.
        with mock.patch.object(QMessageBox, "information"):
            self.window._on_maintenance_done(
                MaintenanceReport(folder=str(self.root), success=True,
                                  messages=["готово"]))
        self.assertTrue(self.window.netstack_btn.isEnabled())


if __name__ == "__main__":
    unittest.main(verbosity=2)
