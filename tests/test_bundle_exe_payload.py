"""Бандл без MSI: установщик программы из ``/layout`` запускается сам.

Жалоба
------
Портатив из ``delta-windows-x86_64-setup.exe``. Установщик — WiX Burn Bundle.
Три штатных сценария (``/quiet /install`` с ``InstallFolder``, без неё и
распаковка ``/layout``) завершились кодом 0, но ``App`` остался пустым, а
сборка закончилась «не найден ни один исполняемый файл».

Причина
-------
В распакованном бандле лежал не MSI, а **exe-пакет** — собственный установщик
программы (``DeltaSetup.exe``). ``_burn_layout_payloads`` такие файлы относил к
«побочным пакетам» и только перечислял в журнале, поэтому шаг ``/layout``
всегда заканчивался сообщением «нет ни одного MSI-пакета — распаковывать
нечего».

Договор, который проверяют эти тесты
------------------------------------
1. exe-пакет бандла запускается его **собственными** ключами тишины (Inno,
   NSIS, InstallShield, вложенный Burn, универсальный набор) — так же, как
   установщик, найденный внутри SFX-контейнера.
2. Предусловия и деинсталляторы (``vcredist``, ``dxsetup``, ``dotnet``,
   ``unins*``) молча не запускаются: их в портатив не переносят.
3. Раскладка ``.msu``/``.msp`` без MSI и без exe-установщика по-прежнему
   считается «распаковывать нечего» — ложного успеха нет.
4. Успешная установка убирает временную папку ``_bundle_layout``.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import portablizer as portablizer_mod
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer


def _write(path: Path, size: int = 2048) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ" + b"x" * max(0, size - 2))
    return path


class _FakeInstall(Portablizer):
    """Portablizer без запуска процессов: установщик «ставит» delta.exe."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.calls = []
        self.produce = True

    def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
        self.calls.append(plan)
        if self.produce:
            _write(Path(app_dir) / "delta.exe", 1024)
        return 0


class BundleExePayloadTests(unittest.TestCase):
    def _opts(self, root: Path) -> PortableOptions:
        installer = _write(root / "Downloads" / "delta-windows-x86_64-setup.exe")
        return PortableOptions(
            installer_path=str(installer),
            output_dir=str(root / "Portable"),
            app_name="delta",
            capture_registry=False,
            bundle_runtimes=False,
        )

    def _paths(self, root: Path):
        app_dir = root / "Portable" / "App"
        data_dir = root / "Portable" / "PortableData"
        layout = root / "Portable" / "_bundle_layout"
        for path in (app_dir, data_dir, layout):
            path.mkdir(parents=True, exist_ok=True)
        return app_dir, data_dir, layout

    def test_prerequisites_are_never_run_silently(self):
        """vcredist/dxsetup/unins — не установщик программы."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = [
                str(_write(root / "vcredist_x64.exe")),
                str(_write(root / "DXSETUP.exe")),
                str(_write(root / "unins000.exe")),
                str(_write(root / "DeltaSetup.exe", 8192)),
                str(_write(root / "patch.msp")),
            ]
            installers = Portablizer._bundle_program_installers(files)
            self.assertEqual(
                [os.path.basename(path) for path in installers],
                ["DeltaSetup.exe"],
            )

    def test_largest_package_goes_first(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            small = str(_write(root / "helper_setup.exe", 1024))
            big = str(_write(root / "DeltaSetup.exe", 8192))
            installers = Portablizer._bundle_program_installers([small, big])
            self.assertEqual(os.path.basename(installers[0]), "DeltaSetup.exe")

    def test_exe_payload_from_layout_is_installed(self):
        """Главный сценарий: в /layout только exe-пакет — он запускается."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            opts = self._opts(root)
            app_dir, data_dir, layout = self._paths(root)
            _write(layout / "DeltaSetup.exe", 4096)
            _write(layout / "vcredist_x64.exe", 128)

            engine = _FakeInstall(Logger())
            with mock.patch.object(portablizer_mod, "IS_WINDOWS", False):
                ok = engine._install_layout_packages(
                    str(layout), opts, str(app_dir), str(data_dir), "delta")

            self.assertTrue(ok, "exe-пакет бандла должен ставиться в App")
            self.assertTrue((app_dir / "delta.exe").is_file())
            self.assertTrue(engine.calls, "установщик из бандла не запускался")
            self.assertIn("бандла", engine.calls[0].label)
            self.assertEqual(
                [os.path.basename(plan.program) for plan in engine.calls],
                ["DeltaSetup.exe"] * len(engine.calls),
                "предусловия запускать нельзя",
            )
            self.assertFalse(layout.exists(),
                             "временная распаковка бандла должна удаляться")

    def test_msu_only_layout_stays_a_failure(self):
        """Только .msu/.msp: по-прежнему «распаковывать нечего»."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            opts = self._opts(root)
            app_dir, data_dir, layout = self._paths(root)
            _write(layout / "kb1234.msu", 512)
            _write(layout / "patch.msp", 512)

            engine = _FakeInstall(Logger())
            with mock.patch.object(portablizer_mod, "IS_WINDOWS", False):
                ok = engine._install_layout_packages(
                    str(layout), opts, str(app_dir), str(data_dir), "delta")

            self.assertFalse(ok)
            self.assertEqual([], engine.calls)
            self.assertFalse((app_dir / "delta.exe").exists())
            self.assertTrue(layout.exists(),
                            "раскладку без установщика не удаляем — она нужна "
                            "для диагностики")

    def test_failed_exe_payload_keeps_layout_for_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            opts = self._opts(root)
            app_dir, data_dir, layout = self._paths(root)
            _write(layout / "DeltaSetup.exe", 4096)

            engine = _FakeInstall(Logger())
            engine.produce = False
            with mock.patch.object(portablizer_mod, "IS_WINDOWS", False):
                ok = engine._install_layout_packages(
                    str(layout), opts, str(app_dir), str(data_dir), "delta")

            self.assertFalse(ok)
            self.assertTrue(engine.calls)
            self.assertTrue(layout.exists())


class NestedPlanTests(unittest.TestCase):
    def test_nested_burn_bundle_gets_install_folder(self):
        """Вложенный Burn-бандл получает свои ключи, а не ключи обёртки."""
        with tempfile.TemporaryDirectory() as temp:
            nested = _write(Path(temp) / "DeltaSetup.exe", 64)
            engine = _FakeInstall(Logger())
            engine._nested_installer_kind = (
                lambda path: portablizer_mod.InstallerType.WIX_BURN)
            opts = PortableOptions(
                installer_path=str(nested), output_dir=temp, app_name="delta")
            plans = engine._plans_for_nested_setup(
                str(nested), os.path.join(temp, "App"), opts, container="бандла")
            self.assertTrue(plans)
            self.assertIn("/quiet", plans[0].args)
            self.assertIn("InstallFolder=", plans[0].raw_tail)
            self.assertIn("бандла", plans[0].label)
            self.assertFalse(plans[1].raw_tail,
                             "второй сценарий — без ключа папки")


if __name__ == "__main__":
    unittest.main(verbosity=2)
