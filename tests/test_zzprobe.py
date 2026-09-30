# -*- coding: utf-8 -*-
"""ВРЕМЕННАЯ диагностика Windows-раннера для расследования падения сборки.

Проба воспроизводит сценарий test_bundled_library_is_copied_and_the_rest_
is_documented против НАСТОЯЩЕЙ системы раннера и печатает, куда именно
классифицируются msvcr80.dll/msvcr90.dll (missing / stock / stock_missing)
и что лежит в WinSxS/System32. После диагноза файл удаляется.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pebuild import write_pe, write_runtime_dll
from portablizer.core import redist
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer


@unittest.skipUnless(sys.platform.startswith("win"), "проба только на Windows")
class RunnerProbeTests(unittest.TestCase):

    def test_runner_probe(self):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:  # noqa: BLE001
            pass
        out = []
        p = out.append
        p(f"platform={sys.platform} SystemRoot="
          f"{os.environ.get('SystemRoot')} WINDIR={os.environ.get('WINDIR')}")
        # Проверка гипотезы падения №1: обычный dict(os.environ) на Windows
        # держит ключи в ВЕРХНЕМ регистре — .get("SystemRoot") их не видит.
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\probe\fake"}):
            plain = dict(os.environ)
            p(f"case probe: plain.get('SystemRoot')="
              f"{plain.get('SystemRoot')!r} "
              f"winds keys={[k for k in plain if k.lower() == 'systemroot']} "
              f"plain.get('WINDIR')={plain.get('WINDIR')!r}")
        windir = os.environ.get("SystemRoot") or r"C:\Windows"
        p(f"system_dirs_for(x86)={redist.system_dirs_for('x86')}")
        p(f"winsxs_dir={redist.winsxs_dir()!r}")
        for folder in ("System32", "SysWOW64", "Sysnative"):
            d = os.path.join(windir, folder)
            hits = [n for n in ("msvcr80.dll", "msvcr90.dll", "msvcp80.dll",
                                "xinput1_3.dll", "d3dx9_39.dll")
                    if os.path.isfile(os.path.join(d, n))]
            p(f"{folder}: exists={os.path.isdir(d)} dlls={hits}")
        sxs = os.path.join(windir, "WinSxS")
        try:
            fam = [n for n in os.listdir(sxs)
                   if "vc80.crt" in n.lower() or "vc90.crt" in n.lower()]
        except OSError as exc:
            fam = []
            p(f"WinSxS listdir error: {exc}")
        p(f"WinSxS vc80/vc90 crt families: {len(fam)}")
        for n in sorted(fam)[:8]:
            try:
                inner = sorted(f for f in os.listdir(os.path.join(sxs, n))
                               if f.lower().endswith(".dll"))
            except OSError:
                inner = ["<listdir error>"]
            p(f"  {n} -> {inner[:6]}")

        # Эксперимент 1: provisioner против настоящей системы раннера.
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            write_pe(app / "Game.exe",
                     imports=("KERNEL32.dll", "MSVCR100.dll", "MSVCP110.dll"),
                     delay_imports=("XINPUT1_3.dll",))
            scan = redist.scan_app_runtime(str(app))
            p(f"scan: parsed={scan.parsed} arch={scan.arch} archs={scan.archs}")
            p(f"scan.reqs={[(r.dll, r.arch, r.status, r.proactive) for r in scan.requirements]}")
            log = Logger()
            report = redist.RuntimeProvisioner(log).provision(
                scan, str(app), temp, "Game", full_kit=True,
                anchors=["Game.exe"])
            for name in ("missing", "stock_missing", "stock", "provided"):
                items = getattr(report, name)
                sel = [(r.dll, r.arch, r.proactive, r.source)
                       for r in items
                       if "80" in r.dll or "90" in r.dll
                       or r.dll in ("msvcp110.dll", "xinput1_3.dll")]
                p(f"report.{name}={len(items)} vc80/90/req={sel[:12]}")
            p(f"report.installers={report.installers}")

        # Эксперимент 2: полный проход Portablizer, как в падающем тесте.
        class FakePortablizer(Portablizer):
            def _run_install(self, plan, opts, app_dir, data_dir, **kwargs):
                write_pe(Path(app_dir, "Game.exe"),
                         imports=("KERNEL32.dll", "MSVCR100.dll",
                                  "MSVCP110.dll"),
                         delay_imports=("XINPUT1_3.dll",))
                return 0

        with tempfile.TemporaryDirectory() as temp:
            shipped = Path(temp, "_CommonRedist", "vcredist", "2010")
            shipped.mkdir(parents=True)
            write_runtime_dll(shipped / "msvcr100.dll")
            installer = Path(temp, "GameSetup.exe")
            installer.write_bytes(b"MZ Inno Setup")
            log2 = Logger()
            engine = FakePortablizer(log2)
            with mock.patch("portablizer.core.portablizer.IS_WINDOWS", False):
                result = engine.run(PortableOptions(
                    installer_path=str(installer), output_dir=temp,
                    app_name="Game", capture_registry=False))
            p(f"integration: missing={sorted(result.runtime_missing)}")
            p(f"integration: provided={sorted(result.runtime_provided)}")
            p(f"integration: stock={sorted(set(result.runtime_stock))}")
            portable = Path(temp, "Game_Portable")
            appdir = portable / "App"
            p(f"App files at end: {sorted(os.listdir(appdir))[:20]}")
            cfg_path = portable / "launcher_config.json"
            if cfg_path.is_file():
                cfg = __import__("json").loads(
                    cfg_path.read_text(encoding="utf-8"))
                p(f"cfg.runtime_requirements={cfg.get('runtime_requirements')}")
                p(f"cfg.runtime_installers={cfg.get('runtime_installers')}")
            lines = log2.text.splitlines()
            p("--- engine log tail ---")
            out.extend(lines[-18:])

        print("\n".join(out))
        self.fail("PROBE (намеренно): вывод диагностики выше")
