"""Старт Portablizer: собранный exe не должен зависеть от исходников.

Жалоба: ``Portablizer.exe`` не запускался вовсе —
``OSError: could not get source code`` из ``inspect.getsource`` на импорте
``portablizer.core.launcher``. PyInstaller-сборка исходников не содержит.
"""
import contextlib
import inspect
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import app as app_entry  # noqa: E402


class FrozenStartupTests(unittest.TestCase):
    def test_launcher_import_survives_without_source_access(self):
        """Импорт ядра с «недоступными исходниками» — как в собранном exe."""
        code = "\n".join([
            "import inspect",
            "def _boom(*a, **k):",
            "    raise OSError('could not get source code')",
            "inspect.getsource = _boom",
            "inspect.getsourcelines = _boom",
            "inspect.findsource = _boom",
            "import portablizer.core.launcher as L",
            "import portablizer.core.portablizer as P",
            "import portablizer.core.maintenance as M",
            "print(L.repair_json_escapes('{\"a\": \"E:\\\\\\\\B\"}'))",
        ])
        completed = subprocess.run([sys.executable, "-c", code], cwd=str(REPO),
                                   capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr[-1500:])

    def test_core_has_no_runtime_getsource_calls(self):
        """Регрессия: ``inspect.getsource`` на импорте снова не появился."""
        offenders = []
        for path in list((REPO / "portablizer").rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8")
                                          .splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#") or "getsource" not in stripped:
                    continue
                if "``inspect.getsource``" in stripped:
                    continue  # пояснение в комментарии
                offenders.append(f"{path.name}:{number}: {stripped[:60]}")
        self.assertEqual(offenders, [])


class CrashReportTests(unittest.TestCase):
    """Падение при старте должно оставлять след, а не молчать."""

    def test_crash_log_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sub", "crash.log")
            path = app_entry.write_crash_log("boom", target)
            self.assertEqual(path, target)
            self.assertIn("boom", pathlib.Path(target).read_text("utf-8"))

    def test_unwritable_log_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "file")
            pathlib.Path(blocker).write_text("x", encoding="utf-8")
            # Каталог вместо файла: запись невозможна, но падения быть не должно.
            self.assertEqual(app_entry.write_crash_log("boom",
                                                       os.path.join(blocker,
                                                                    "x.log")),
                             "")

    def test_report_crash_logs_the_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "crash.log")
            os.environ[app_entry.CRASH_LOG_ENV] = target
            try:
                try:
                    raise RuntimeError("кофейня сломалась")
                except RuntimeError as error:
                    # Окно MessageBox и вывод в stderr в тесте не нужны:
                    # проверяем именно журнал.
                    with unittest.mock.patch.object(app_entry, "_show_error"), \
                            contextlib.redirect_stderr(io.StringIO()):
                        code = app_entry.report_crash(error)
            finally:
                os.environ.pop(app_entry.CRASH_LOG_ENV, None)
            self.assertEqual(code, 1)
            text = pathlib.Path(target).read_text("utf-8")
            self.assertIn("RuntimeError", text)
            self.assertIn("кофейня сломалась", text)
            self.assertIn("Traceback", text)

    def test_crash_log_path_uses_the_environment(self):
        os.environ[app_entry.CRASH_LOG_ENV] = "C:/logs/crash.log"
        try:
            self.assertEqual(app_entry.crash_log_path(), "C:/logs/crash.log")
        finally:
            os.environ.pop(app_entry.CRASH_LOG_ENV, None)

    def test_crash_log_path_has_a_default(self):
        os.environ.pop(app_entry.CRASH_LOG_ENV, None)
        path = app_entry.crash_log_path().replace("\\", "/")
        self.assertTrue(path.endswith("Portablizer/portablizer-crash.log"))


class EntryPointTests(unittest.TestCase):
    def test_version_switch_works(self):
        completed = subprocess.run([sys.executable, "app.py", "--version"],
                                   cwd=str(REPO), capture_output=True,
                                   text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr[-800:])
        self.assertIn("Portablizer", completed.stdout)

    def test_cli_does_not_load_the_gui(self):
        code = ("import sys, portablizer.cli\n"
                "print('portablizer.gui.main_window' in sys.modules)\n")
        completed = subprocess.run([sys.executable, "-c", code], cwd=str(REPO),
                                   capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr[-800:])
        self.assertIn("False", completed.stdout)


if __name__ == "__main__":
    unittest.main()
