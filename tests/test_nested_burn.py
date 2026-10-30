"""Бандл внутри бандла: WiX Burn не запускается установкой, а раскладывается.

Жалоба
------
Портатив из ``delta-windows-x86_64-setup.exe``. В процессе сборки всплывало
окно установщика, которое раз за разом выдавало ошибку, а после сборки
``Launch.bat`` вместо программы бесконечно запускал ``App\\LaunchPortable.exe``.

Из журнала самого установщика::

    path: ...\\_bundle_layout\\DeltaSetup.exe
    Command Line: '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=...\\App'
    Ignoring unknown argument: /VERYSILENT
    ...
    Detected package: DeltaPackage, state: Present, cached: Yes
    Error 0x8007139f: Plan requires a new successful Detect after calling Apply.

Причины
-------
1. Файл из ``/layout`` (``DeltaSetup.exe``) — **сам WiX Burn-бандл** (v7), но
   определялся он не по секции ``.wixburn``, а поиском строки ``WixBurn`` в
   байтах. У Burn v7 такой строки в первых мегабайтах нет, файл считался
   «неизвестным установщиком», и к нему применялись ключи Inno Setup.
   Burn их игнорировал, открывал окно и уходил в обслуживание.
2. Запущенный «как установщик» вложенный бандл пишет в реестр «установлено» и
   при следующем запуске считает программу уже стоящей — отсюда
   ``Error 0x8007139f`` по кругу и пустой ``App``.
3. Поиск пропавшей цели запуска в лончере находил в ``App`` сам лончер
   (``LaunchPortable.exe`` — самый крупный exe), записывал его в конфиг и
   запускал заново. Бесконечно.

Договор, который проверяют эти тесты
------------------------------------
1. Вложенный Burn определяется по структуре PE (``.wixburn``) и **не**
   получает ключи Inno/NSIS.
2. Вложенный бандл распаковывается через ``/layout``, а его MSI ставится
   административной распаковкой (``msiexec /a``) прямо в ``App`` — без записи
   «уже установлено» в системе.
3. Лончер никогда не выбирает сам себя ни целью, ни заменой пропавшей цели.
"""
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import portable_launcher_entry as exe_launcher
from portablizer.core import portablizer as portablizer_mod
from portablizer.core.detect import InstallerType
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer


def _fake_pe(path, sections, payload=b""):
    """Минимальный структурно валидный PE (как в test_portablizer)."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    optional_size = 240
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0,
                       optional_size, 0x2102)
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 92, 16)
    table = b"".join(name.encode().ljust(8, b"\0") + b"\0" * 32
                     for name in sections)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(bytes(dos) + b"PE\0\0" + coff + bytes(optional)
                       + table + payload)
    return str(target)


class _FakeBurnEngine(Portablizer):
    """Portablizer без процессов: имитирует вложенный бандл и msiexec."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.calls = []

    def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
        self.calls.append(plan)
        if "/layout" in plan.args:
            # Вложенный бандл раскладывает свой MSI рядом с собой.
            out = Path(plan.args[plan.args.index("/layout") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "Delta.msi").write_bytes(b"MSI payload")
            return 0
        if os.path.basename(plan.program).casefold() == "msiexec.exe":
            (Path(app_dir) / "delta.exe").write_bytes(b"MZ" + b"\0" * 128)
            return 0
        return 0


class NestedBundleTests(unittest.TestCase):
    def _paths(self, root: Path):
        app_dir = root / "Portable" / "App"
        data_dir = root / "Portable" / "PortableData"
        layout = root / "Portable" / "_bundle_layout"
        for path in (app_dir, data_dir, layout):
            path.mkdir(parents=True, exist_ok=True)
        return app_dir, data_dir, layout

    def _opts(self, root: Path) -> PortableOptions:
        return PortableOptions(
            installer_path=str(root / "delta-windows-x86_64-setup.exe"),
            output_dir=str(root / "Portable"),
            app_name="delta",
            capture_registry=False,
            bundle_runtimes=False,
        )

    def test_nested_burn_is_detected_by_pe_section(self):
        """Burn v7 узнаётся по секции .wixburn, а не по строке в байтах."""
        with tempfile.TemporaryDirectory() as temp:
            path = _fake_pe(Path(temp) / "DeltaSetup.exe",
                            [".text", ".rsrc", ".wixburn"], b"wixstdba")
            engine = _FakeBurnEngine(Logger())
            self.assertTrue(engine._nested_is_burn(path))
            self.assertEqual(engine._nested_installer_kind(path),
                             InstallerType.WIX_BURN)

    def test_plain_installer_is_not_burn(self):
        with tempfile.TemporaryDirectory() as temp:
            path = _fake_pe(Path(temp) / "setup.exe",
                            [".text", ".rdata", ".data"], b"Inno Setup")
            engine = _FakeBurnEngine(Logger())
            self.assertFalse(engine._nested_is_burn(path))

    def test_nested_burn_is_unpacked_not_installed(self):
        """Главный сценарий: /layout вложенного бандла, затем msiexec /a."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            opts = self._opts(root)
            app_dir, data_dir, layout = self._paths(root)
            _fake_pe(layout / "DeltaSetup.exe", [".text", ".wixburn"],
                     b"wixstdba")

            engine = _FakeBurnEngine(Logger())
            with mock.patch.object(portablizer_mod, "IS_WINDOWS", False):
                ok = engine._install_layout_packages(
                    str(layout), opts, str(app_dir), str(data_dir), "delta")

            self.assertTrue(ok)
            self.assertTrue((app_dir / "delta.exe").is_file())
            self.assertTrue(engine.calls, "вложенный бандл не раскладывался")
            first = engine.calls[0]
            self.assertEqual(os.path.basename(first.program), "DeltaSetup.exe")
            self.assertIn("/layout", first.args)
            self.assertNotIn("/VERYSILENT", first.args,
                             "Burn не понимает ключи Inno — из-за них "
                             "установщик открывал окно и зацикливался")
            self.assertNotIn("/DIR=", " ".join(first.args))
            msi_calls = [plan for plan in engine.calls
                         if os.path.basename(plan.program).casefold()
                         == "msiexec.exe"]
            self.assertTrue(msi_calls, "MSI из вложенного бандла не ставился")
            self.assertIn("/a", msi_calls[0].args)
            self.assertFalse(
                any("/quiet" in plan.args and "/install" in plan.args
                    for plan in engine.calls),
                "вложенный бандл нельзя запускать установкой: он пишет в "
                "реестр «уже установлено» и зацикливается на 0x8007139f",
            )
            self.assertFalse(layout.exists(),
                             "временная распаковка бандла должна удаляться")

    def test_nested_layout_is_removed_after_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            opts = self._opts(root)
            app_dir, data_dir, layout = self._paths(root)
            _fake_pe(layout / "DeltaSetup.exe", [".wixburn"], b"wixstdba")
            engine = _FakeBurnEngine(Logger())
            with mock.patch.object(portablizer_mod, "IS_WINDOWS", False):
                engine._install_layout_packages(
                    str(layout), opts, str(app_dir), str(data_dir), "delta")
            self.assertEqual([], list(layout.parent.glob("_bundle_layout/*"
                                                         "_nested_layout")))


class LauncherSelfTargetTests(unittest.TestCase):
    """Лончер не должен запускать сам себя (бесконечный цикл)."""

    def _app(self, root: Path) -> Path:
        app = root / "App"
        app.mkdir(parents=True, exist_ok=True)
        return app

    def test_launcher_is_never_a_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = self._app(root)
            # Лончер — самый крупный exe, как в реальной сборке.
            (app / "LaunchPortable.exe").write_bytes(b"MZ" + b"\0" * 8192)
            found = exe_launcher._find_replacement_target(root, "App/Missing.exe")
            self.assertIsNone(found,
                              "заменой не может быть сам лончер")

    def test_real_program_still_wins_over_launcher(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = self._app(root)
            (app / "LaunchPortable.exe").write_bytes(b"MZ" + b"\0" * 8192)
            (app / "delta.exe").write_bytes(b"MZ" + b"\0" * 64)
            found = exe_launcher._find_replacement_target(root, "App/Missing.exe")
            self.assertEqual(found, app / "delta.exe")

    def test_config_pointing_at_the_launcher_is_repaired(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = self._app(root)
            (app / "LaunchPortable.exe").write_bytes(b"MZ" + b"\0" * 8192)
            (app / "delta.exe").write_bytes(b"MZ" + b"\0" * 64)
            config = root / "launcher_config.json"
            config.write_text(json.dumps({
                "app_name": "delta",
                "target_exe_rel": "App/LaunchPortable.exe",
                "data_dir_name": "PortableData",
            }, indent=2), encoding="utf-8")
            cfg = exe_launcher.read_launcher_config(root)

            repaired = exe_launcher._repair_missing_target(
                root, cfg, cfg["target_exe_rel"])

            self.assertEqual(repaired, "App/delta.exe")

    def test_own_image_is_recognised(self):
        self.assertTrue(exe_launcher._is_own_image(
            Path("App") / "LaunchPortable.exe"))
        self.assertTrue(exe_launcher._is_own_image(
            Path("App") / "PortableLauncher.exe"))
        self.assertFalse(exe_launcher._is_own_image(Path("App") / "delta.exe"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
