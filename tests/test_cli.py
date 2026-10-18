"""Тесты командной строки Portablizer (усовершенствование Portablizer.exe).

CLI — это второе «лицо» того же exe: без аргументов окно, с аргументами —
сборка из консоли. Проверяется то, за что стоит держать отдельный режим:

* разбор аргументов в PortableOptions один-в-один с настройками окна
  (включая NetStack: изоляция по умолчанию, shared — по флагу);
* ``--dry-run``: план (папка результата по правилам движка, абсолютные пути,
  окружение запуска) печатается JSON, и НИЧЕГО не устанавливается;
* коды выхода: 0 — успех/версия, 1 — сборка не удалась, 2 — ошибка в
  командной строке (нет установщика, кривой ``--env``);
* ``--version`` и пустые аргументы (точка входа должна оставить GUI в покое);
* attach_console на не-Windows — безвредный no-op (в exe именно он возвращает
  stdout окну, запущенному из cmd).
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer import __version__, cli


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class ParserMappingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.installer = self.root / "PlanetaVPN.exe"
        self.installer.write_bytes(b"MZ fake")
        self.out = self.root / "out"

    def _opts(self, extra=()):
        ns = cli.build_parser().parse_args(
            ["build", str(self.installer), "--out", str(self.out), *extra])
        return cli.options_from_args(ns)

    def test_defaults_match_window(self):
        opts = self._opts()
        self.assertEqual(opts.installer_path, os.path.abspath(str(self.installer)))
        self.assertEqual(opts.output_dir, os.path.abspath(str(self.out)))
        self.assertTrue(opts.redirect_userdirs)
        self.assertTrue(opts.capture_registry)
        self.assertTrue(opts.build_exe_launcher)
        self.assertTrue(opts.cleanup_host)
        self.assertFalse(opts.include_shell_integration)
        self.assertTrue(opts.bundle_runtimes)
        self.assertTrue(opts.full_runtimes)
        self.assertFalse(opts.download_runtimes)
        self.assertTrue(opts.silent_runtime_install)
        self.assertTrue(opts.shared_saves)
        # VPN-компоненты — да; изоляция — по умолчанию.
        self.assertTrue(opts.netstack_components)
        self.assertTrue(opts.netstack_isolated)
        self.assertFalse(opts.allow_assisted_install)

    def test_toggles(self):
        opts = self._opts([
            "--no-registry", "--no-userdirs", "--no-cleanup",
            "--shell-integration", "--no-exe-launcher", "--no-runtimes",
            "--no-shared-saves", "--no-netstack", "--assisted",
            "--extra-args", "/FOO", "/BAR", "--env", "A=1", "--env", "B=x=y",
            "--idle-timeout", "77", "--hard-timeout", "9999",
            "--assisted-timeout", "120", "--lang", "ru", "--name", "Planeta VPN",
        ])
        self.assertFalse(opts.capture_registry)
        self.assertFalse(opts.redirect_userdirs)
        self.assertFalse(opts.cleanup_host)
        self.assertTrue(opts.include_shell_integration)
        self.assertFalse(opts.build_exe_launcher)
        self.assertFalse(opts.bundle_runtimes)
        self.assertFalse(opts.full_runtimes)          # таскается за bundle
        self.assertFalse(opts.download_runtimes)      # и он
        self.assertFalse(opts.silent_runtime_install)
        self.assertFalse(opts.shared_saves)
        self.assertFalse(opts.netstack_components)
        self.assertTrue(opts.allow_assisted_install)
        self.assertEqual(opts.extra_install_args, ["/FOO", "/BAR"])
        self.assertEqual(opts.extra_env, {"A": "1", "B": "x=y"})
        self.assertEqual(opts.install_timeout, 77)
        self.assertEqual(opts.install_deadline, 9999)
        self.assertEqual(opts.assisted_timeout, 120)
        self.assertEqual(opts.install_language, "ru")
        self.assertEqual(opts.app_name, "Planeta VPN")

    def test_shared_netstack_keeps_components_on(self):
        opts = self._opts(["--shared-netstack"])
        self.assertTrue(opts.netstack_components)
        self.assertFalse(opts.netstack_isolated)

    def test_lean_runtimes_only_trims_the_full_set(self):
        opts = self._opts(["--lean-runtimes", "--download-runtimes"])
        self.assertTrue(opts.bundle_runtimes)
        self.assertFalse(opts.full_runtimes)
        self.assertTrue(opts.download_runtimes)


class MainExitCodeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.installer = self.root / "Setup.exe"
        self.installer.write_bytes(b"MZ fake")

    def test_no_arguments_print_help_and_code_two(self):
        code, out, _ = _run([])
        self.assertEqual(code, 2)
        self.assertIn("usage", out.lower())

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx, redirect_stdout(io.StringIO()) as out:
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(__version__, out.getvalue())

    def test_missing_installer_is_a_usage_error(self):
        code, _, err = _run(["build", str(self.root / "nope.exe"),
                             "--out", str(self.root)])
        self.assertEqual(code, 2)
        self.assertIn("Установщик не найден", err)

    def test_bad_env_is_a_usage_error(self):
        code, _, err = _run(["build", str(self.installer), "--out",
                             str(self.root / "o"), "--env", "JUST-KEY"])
        self.assertEqual(code, 2)
        self.assertIn("KEY=VALUE", err)

    def test_dry_run_prints_plan_and_installs_nothing(self):
        out_dir = self.root / "o"
        code, out, err = _run(["build", str(self.installer), "--out",
                               str(out_dir), "--name", "Планета VPN",
                               "--shared-netstack", "--dry-run"])
        self.assertEqual(code, 0, err)
        plan = json.loads(out)
        self.assertEqual(plan["app_name"], "Планета VPN")
        self.assertEqual(plan["netstack_isolated"], False)
        # Папка результата — тем же правилом, что и у движка: <имя>_Portable.
        self.assertEqual(Path(plan["portable_dir"]).name,
                         "Планета VPN_Portable")
        self.assertEqual(plan["frozen"], False)
        self.assertEqual(Path(plan["installer_path"]).name, "Setup.exe")
        # «Ничего не установилось»: ни журнала, ни App внутри.
        self.assertFalse((out_dir / "portablizer-cli.log").exists())
        self.assertFalse((out_dir / "Планета VPN_Portable").exists())


class ConsoleAttachTests(unittest.TestCase):
    def test_attach_console_is_a_noop_off_windows(self):
        if os.name == "nt":  # pragma: no cover - проверяется на раннере
            self.skipTest("только для POSIX-среды")
        self.assertFalse(cli.attach_console())

    def test_stdout_survives_attach_attempt(self):
        # main() вызывает attach_console() всегда; на Linux это no-op, но
        # поток вывода не должен «сдохнуть» от попытки.
        code, out, _ = _run([])
        self.assertEqual(code, 2)
        self.assertTrue(out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
