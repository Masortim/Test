"""Долгая установка — не зависшая: проверки стража ожидания.

Регрессия, ради которой написан этот модуль:

    При попытке портировать BioShock Infinite в какой-то момент возникала
    ошибка «Превышено время ожидания установки» — хотя установщик в этот
    момент исправно распаковывал десятки гигабайт. У тихой установки был
    один общий потолок времени (30 минут), а большая игра ставится дольше.

Проверяется, что теперь:
  * предел ожидания относится к ПАУЗЕ в работе установщика, а не ко всему
    времени установки, и признаки работы видны по трём независимым каналам
    (ввод-вывод дерева процессов, рост целевой папки, журнал установщика);
  * «молчание» больше не обрывает сборку исключением и не мешает проверить
    то, что установщик всё-таки успел распаковать;
  * при затишье можно спросить человека («ждать ещё?»), и его ответ
    действительно продлевает ожидание;
  * поверх неполной установки лестница не запускает вторую установку.
"""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pebuild
from portablizer.core import portablizer as engine_mod
from portablizer.core import procutil
from portablizer.core.detect import InstallerType
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import (
    STALL_CANCEL, STALL_STOP, STALL_WAIT, InstallStall, PortableOptions,
    Portablizer, _InstallWatchdog, _stall_verdict, _tree_usage,
)
from portablizer.core.silentargs import SilentPlan, build_silent_plan


def _touch(root: str, name: str, size: int = 4096) -> str:
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"x" * size)
    return path


class _FakeProc:
    """Минимальный двойник ``subprocess.Popen`` для наблюдения за ожиданием."""

    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid
        self.returncode = None
        self.killed = False
        self.poll_calls = 0
        self.on_poll = None

    def poll(self):  # noqa: ANN201 - как у Popen
        self.poll_calls += 1
        if self.on_poll is not None:
            self.on_poll(self)
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        if self.returncode is None:
            self.returncode = -9

    def terminate(self) -> None:
        self.kill()

    def wait(self, timeout=None):  # noqa: ANN001, ANN201 - как у Popen
        return self.returncode


class TreeUsageTests(unittest.TestCase):
    def test_counts_files_and_bytes_recursively(self):
        with tempfile.TemporaryDirectory() as temp:
            _touch(temp, "a.bin", 10)
            _touch(temp, os.path.join("sub", "b.bin"), 20)
            files, size = _tree_usage(temp)
            self.assertEqual(files, 2)
            self.assertEqual(size, 30)

    def test_missing_folder_is_zero_and_does_not_raise(self):
        self.assertEqual(_tree_usage(os.path.join("no", "such", "dir")), (0, 0))

    def test_budget_stops_the_walk_without_an_error(self):
        with tempfile.TemporaryDirectory() as temp:
            for index in range(50):
                _touch(temp, f"f{index}.bin", 1)
            files, size = _tree_usage(temp, budget=0.0)
            self.assertGreaterEqual(files, 0)
            self.assertGreaterEqual(size, 0)


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name, "App")
        self.app.mkdir()

    def test_first_poll_counts_as_work(self):
        watch = _InstallWatchdog(1, roots=[str(self.app)],
                                 probe_seconds=0.0, dir_seconds=0.0)
        self.assertTrue(watch.poll())
        self.assertEqual(watch.samples, 1)

    def test_new_files_in_the_target_folder_are_progress(self):
        watch = _InstallWatchdog(1, roots=[str(self.app)],
                                 probe_seconds=0.05, dir_seconds=0.05)
        watch.poll()
        self.assertFalse(watch.poll())
        _touch(str(self.app), "game.bin", 1024)
        time.sleep(0.06)
        self.assertTrue(watch.poll())

    def test_nothing_changed_is_not_progress(self):
        watch = _InstallWatchdog(1, roots=[str(self.app)],
                                 probe_seconds=0.05, dir_seconds=0.05)
        watch.poll()
        time.sleep(0.06)
        self.assertFalse(watch.poll())
        time.sleep(0.06)
        self.assertFalse(watch.poll())

    def test_installer_log_growth_is_progress(self):
        log = Path(self.temp.name, "install.log")
        log.write_text("start\n", encoding="utf-8")
        watch = _InstallWatchdog(1, roots=[str(self.app)], logs=[str(log)],
                                 probe_seconds=0.05, dir_seconds=60.0)
        watch.poll()
        self.assertFalse(watch.poll())
        with open(log, "a", encoding="utf-8") as fh:
            fh.write("unpacked a file\n")
        time.sleep(0.06)
        self.assertTrue(watch.poll())

    def test_process_io_counters_are_progress_without_any_file(self):
        watch = _InstallWatchdog(1, roots=[str(self.app)],
                                 probe_seconds=0.05, dir_seconds=60.0)
        activity = [procutil.ProcessActivity((1,), 1000, 0.5)]
        with mock.patch.object(procutil, "process_activity",
                               side_effect=lambda _pid: activity[0]):
            watch.poll()
            self.assertFalse(watch.poll())
            activity[0] = procutil.ProcessActivity((1,), 999_000_000, 12.0)
            time.sleep(0.06)
            self.assertTrue(watch.poll())
        self.assertEqual(watch.io_bytes, 999_000_000)

    def test_summary_and_report_name_what_was_done(self):
        _touch(str(self.app), "game.bin", 2048)
        watch = _InstallWatchdog(7, roots=[str(self.app)],
                                 probe_seconds=0.0, dir_seconds=0.0)
        watch.poll()
        self.assertIn("2.0 КБ", watch.summary())
        stall = watch.report("Inno Setup: /VERYSILENT /DIR", elapsed=600.0,
                             idle=120.0, idle_limit=900.0, deadline=3600.0)
        self.assertEqual(stall.files, 1)
        self.assertEqual(stall.written, 2048)
        self.assertIn("Установка идёт 10 мин", stall.message())
        self.assertIn("нет признаков работы", stall.message())


class VerdictTests(unittest.TestCase):
    def test_known_answers_are_understood(self):
        self.assertEqual(_stall_verdict(STALL_WAIT), STALL_WAIT)
        self.assertEqual(_stall_verdict(True), STALL_WAIT)
        self.assertEqual(_stall_verdict("подождать"), STALL_WAIT)
        self.assertEqual(_stall_verdict("cancel"), STALL_CANCEL)
        self.assertEqual(_stall_verdict("отменить сборку"), STALL_CANCEL)
        self.assertEqual(_stall_verdict(STALL_STOP), STALL_STOP)

    def test_unclear_answers_stop_instead_of_waiting_forever(self):
        self.assertEqual(_stall_verdict(None), STALL_STOP)
        self.assertEqual(_stall_verdict(False), STALL_STOP)
        self.assertEqual(_stall_verdict("не знаю"), STALL_STOP)


class ProcessProbeTests(unittest.TestCase):
    def test_no_windows_means_no_counters_and_only_the_root_process(self):
        with mock.patch.object(procutil, "IS_WINDOWS", False):
            self.assertIsNone(procutil.process_activity(1))
            self.assertEqual(procutil.process_tree(1), [1])

    def test_tree_walks_children_and_grandchildren(self):
        parents = [(1, 0), (2, 1), (3, 1), (4, 3), (5, 99)]
        with mock.patch.object(procutil, "IS_WINDOWS", True), \
                mock.patch.object(procutil, "_parent_pids", return_value=parents):
            self.assertEqual(procutil.process_tree(1), [1, 2, 3, 4])


class InstallWaitTests(unittest.TestCase):
    """``_run_install`` целиком: с двойником установщика и быстрыми пределами."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.app = root / "App"
        self.app.mkdir()
        self.data = root / "PortableData"
        self.data.mkdir()
        self.console = str(root / "installer-output.log")
        self.engine = Portablizer(Logger())
        self.plan = SilentPlan(program="setup.exe", args=["/VERYSILENT"],
                               label="Inno Setup: /VERYSILENT /DIR")
        self.opts = PortableOptions(installer_path="setup.exe",
                                    output_dir=str(root))
        self.patches = [
            mock.patch.object(engine_mod, "IS_WINDOWS", True),
            mock.patch.object(engine_mod, "INSTALL_PROBE_SECONDS", 0.02),
            mock.patch.object(engine_mod, "INSTALL_DIR_SCAN_SECONDS", 0.02),
            mock.patch.object(engine_mod, "INSTALL_IDLE_FLOOR", 0.2),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def _run(self, proc, idle=0.4, deadline=0.0, engine=None):
        target = engine or self.engine
        target.opts_seen = None
        with mock.patch.object(engine_mod.subprocess, "Popen",
                               return_value=proc):
            return target._run_install(
                self.plan, PortableOptions(
                    installer_path="setup.exe",
                    output_dir=str(Path(self.temp.name)),
                    install_timeout=idle, install_deadline=deadline),
                str(self.app), str(self.data), console_log=self.console)

    def test_working_installer_is_never_interrupted_by_the_idle_limit(self):
        """Установщик пишет файлы дольше предела паузы — и не прерывается."""
        proc = _FakeProc()
        finished = threading.Event()

        def writer():  # noqa: D401 - фоновая «работа установщика»
            index = 0
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                _touch(str(self.app), f"part{index}.bin", 512)
                index += 1
                time.sleep(0.05)
            # Дольше трети секунды установщик молчит, но работу он делал:
            # прерывать его по общей паузе нельзя.
            time.sleep(0.15)
            proc.returncode = 0
            finished.set()

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        # Предел паузы — 0.4 с, а работа идёт 1.5 с: старый общий потолок
        # времени здесь бы сработал, страж работы — нет.
        rc = self._run(proc, idle=0.4)
        thread.join(timeout=5)
        self.assertTrue(finished.is_set())
        self.assertEqual(rc, 0)
        self.assertFalse(self.engine._install_stalled)
        self.assertFalse(proc.killed)

    def test_silence_is_reported_as_stall_and_the_installer_is_stopped(self):
        proc = _FakeProc()
        started = time.monotonic()
        rc = self._run(proc, idle=0.4)
        self.assertEqual(rc, engine_mod.redist_mod.TIMEOUT_EXIT_CODE)
        self.assertLess(time.monotonic() - started, 15.0)
        self.assertTrue(proc.killed)
        self.assertTrue(self.engine._install_stalled)
        self.assertIsNotNone(self.engine._install_stall)

    def test_stall_report_tells_how_much_was_unpacked(self):
        proc = _FakeProc()

        def payload(_proc):  # noqa: ANN001 - один файл, затем тишина
            if not os.path.exists(str(self.app / "big.dat")):
                _touch(str(self.app), "big.dat", 8192)

        proc.on_poll = payload
        self._run(proc, idle=0.4)
        stall = self.engine._install_stall
        self.assertIsNotNone(stall)
        self.assertGreaterEqual(stall.files, 1)
        self.assertGreaterEqual(stall.written, 8192)

    def test_a_question_can_extend_the_wait(self):
        proc = _FakeProc()
        asked = []

        def on_stall(stall: InstallStall) -> str:  # noqa: ANN001
            asked.append(stall)
            return STALL_WAIT if len(asked) < 3 else STALL_STOP

        engine = Portablizer(Logger(), on_stall=on_stall)
        rc = self._run(proc, idle=0.3, engine=engine)
        self.assertEqual(len(asked), 3)
        self.assertEqual(rc, engine_mod.redist_mod.TIMEOUT_EXIT_CODE)
        self.assertTrue(proc.killed)
        # Каждый вопрос — про новую паузу, а не про одно и то же время.
        self.assertLess(asked[0].elapsed, asked[-1].elapsed)
        self.assertGreaterEqual(asked[-1].elapsed, 0.5)

    def test_cancelling_from_the_question_aborts_the_build(self):
        proc = _FakeProc()
        engine = Portablizer(Logger(), on_stall=lambda _stall: STALL_CANCEL)
        with self.assertRaises(RuntimeError) as caught:
            self._run(proc, idle=0.3, engine=engine)
        self.assertIn("отменена", str(caught.exception))
        self.assertTrue(proc.killed)
        self.assertFalse(engine._install_stalled)

    def test_a_broken_question_does_not_break_the_build(self):
        proc = _FakeProc()

        def on_stall(_stall):  # noqa: ANN001 - интерфейс сломался
            raise RuntimeError("окно закрыли")

        engine = Portablizer(Logger(), on_stall=on_stall)
        rc = self._run(proc, idle=0.3, engine=engine)
        self.assertEqual(rc, engine_mod.redist_mod.TIMEOUT_EXIT_CODE)
        self.assertTrue(proc.killed)

    def test_the_hard_deadline_stops_even_a_busy_installer(self):
        """Потолок попытки — страховка от вечной работы, а не от тишины."""
        proc = _FakeProc()

        class _BusyWatchdog:
            """Стражник, который всегда видит работу (установщик зациклился)."""

            def __init__(self, *_args, **_kwargs) -> None:
                pass

            def poll(self, _now=None) -> bool:  # noqa: ANN001
                return True

            def summary(self) -> str:
                return "работа идёт"

            def report(self, attempt, elapsed, idle, idle_limit, deadline):
                return InstallStall(attempt=attempt, elapsed=elapsed, idle=idle,
                                    idle_limit=idle_limit, deadline=deadline)

        with mock.patch.object(engine_mod, "_InstallWatchdog", _BusyWatchdog):
            rc = self._run(proc, idle=60.0, deadline=0.4)
        self.assertEqual(rc, engine_mod.redist_mod.TIMEOUT_EXIT_CODE)
        self.assertTrue(self.engine._install_stalled)
        self.assertIn("предел времени", self.engine.log.text)


class LadderTests(unittest.TestCase):
    """Что делает лестница попыток, когда установка замолчала."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "App"
        self.data = self.root / "PortableData"
        self.app.mkdir()
        self.data.mkdir()
        self.engine = Portablizer(Logger())
        self.plans = [
            SilentPlan(program="setup.exe", args=[], label=f"сценарий {n}")
            for n in range(3)
        ]

    def _attempts(self, behaviour):  # noqa: ANN001
        with mock.patch.object(self.engine, "_run_install",
                               side_effect=behaviour):
            return self.engine._run_attempts(
                self.plans, PortableOptions(installer_path="setup.exe",
                                            output_dir=str(self.root)),
                str(self.app), str(self.data), str(self.root), "Game")

    def test_partial_install_stops_the_ladder_so_it_is_not_repeated(self):
        timeout = engine_mod.redist_mod.TIMEOUT_EXIT_CODE

        def stalled(_plan, _opts, app_dir, _data, **_kwargs):
            _touch(app_dir, "unpacked/levels.pak", 1024)
            return timeout

        rc, plan = self._attempts(stalled)
        self.assertEqual(rc, timeout)
        self.assertIsNone(plan)
        self.assertEqual(self.engine._attempts_made, 1)
        self.assertIn("Повторять установку другими ключами не буду",
                      self.engine.log.text)

    def test_empty_target_folder_keeps_trying_the_other_scenarios(self):
        timeout = engine_mod.redist_mod.TIMEOUT_EXIT_CODE

        def stalled(_plan, _opts, _app, _data, **_kwargs):
            return timeout

        rc, plan = self._attempts(stalled)
        self.assertEqual(rc, timeout)
        self.assertIsNone(plan)
        self.assertEqual(self.engine._attempts_made, 3)

    def test_a_successful_recovery_after_the_timeout_is_still_a_success(self):
        timeout = engine_mod.redist_mod.TIMEOUT_EXIT_CODE

        def stalled(_plan, _opts, app_dir, _data, **_kwargs):
            _touch(app_dir, "Game.exe", 1024)
            return timeout

        rc, plan = self._attempts(stalled)
        self.assertEqual(rc, timeout)
        self.assertIsNotNone(plan)
        self.assertEqual(plan.label, "сценарий 0")


class BuildEndToEndTests(unittest.TestCase):
    """Сборка целиком: старая ошибка «Превышено время ожидания установки».

    Это и есть исходная жалоба: установщик большой игры работает долго, и
    сборка падала с сообщением про длительное ожидание. Теперь такой сборки
    не существует: даже если установщик в самом деле замолчал, сборка
    завершается честной диагностикой и советом, что делать, а не обрывом на
    полуслове.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.installer = pebuild.write_pe(
            self.root / "setup.exe", imports=["kernel32.dll"],
            extra=b"Inno Setup Setup Data (5.5.0)")
        self.out = self.root / "out"
        self.out.mkdir()
        self.patches = [
            mock.patch.object(engine_mod, "IS_WINDOWS", True),
            mock.patch.object(engine_mod, "INSTALL_PROBE_SECONDS", 0.02),
            mock.patch.object(engine_mod, "INSTALL_DIR_SCAN_SECONDS", 0.02),
            mock.patch.object(engine_mod, "INSTALL_IDLE_FLOOR", 0.2),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_a_silent_installer_ends_with_advice_not_with_a_wait_error(self):
        opts = PortableOptions(
            installer_path=str(self.installer), output_dir=str(self.out),
            app_name="BioShockInfinite", install_timeout=0.3,
            install_deadline=0, capture_registry=False,
            bundle_runtimes=False, shared_saves=False,
            build_exe_launcher=False, cleanup_host=False,
            redirect_userdirs=True)
        engine = Portablizer(Logger())
        with mock.patch.object(engine_mod.subprocess, "Popen",
                               side_effect=lambda *_a, **_k: _FakeProc()):
            result = engine.run(opts)

        self.assertFalse(result.success)
        message = "\n".join(result.messages)
        self.assertNotIn("Превышено время ожидания установки", message)
        self.assertIn("предел ожидания", message.lower())
        self.assertIn("Долгие установки", "\n".join(result.hints))
        # Ни один сценарий не «завис» навсегда: попытки перебираются, потому
        # что пустая папка App означает «эти ключи не сработали».
        self.assertGreaterEqual(result.attempts_made, 1)
        self.assertTrue(engine._install_stalled)
        # Портатив не выдан: заведомо сломанного Launch.bat быть не должно.
        portable = Path(result.portable_dir)
        self.assertFalse((portable / "Launch.bat").exists())

    def test_a_slow_install_that_works_finishes_with_a_portable(self):
        """Медленная установка (как у больших игр) доводится до портатива."""
        opts = PortableOptions(
            installer_path=str(self.installer), output_dir=str(self.out),
            app_name="BigGame", install_timeout=0.4, install_deadline=0,
            capture_registry=False, bundle_runtimes=False, shared_saves=False,
            build_exe_launcher=False, cleanup_host=False)
        app_dir = Path(self.out, "BigGame_Portable", "App")
        game = pebuild.write_pe(self.root / "game.exe", imports=["kernel32.dll"])

        def installer(_args, **_kwargs):
            proc = _FakeProc()
            index = [0]

            def work(_proc):  # noqa: ANN001 - «распаковка» идёт и идёт
                index[0] += 1
                _touch(str(app_dir), f"data/level{index[0]:04d}.pak", 4096)
                if index[0] > 14:
                    _touch(str(app_dir), "Game.exe", 1024)
                    with open(game, "rb") as src, \
                            open(app_dir / "Game.exe", "wb") as dst:
                        dst.write(src.read())
                    _proc.returncode = 0

            proc.on_poll = work
            return proc

        engine = Portablizer(Logger())
        with mock.patch.object(engine_mod.subprocess, "Popen",
                               side_effect=installer), \
                mock.patch.object(engine_mod.time, "sleep", lambda _s: None):
            result = engine.run(opts)

        self.assertTrue(result.success, "\n".join(result.messages))
        self.assertFalse(engine._install_stalled)
        portable = Path(self.out, "BigGame_Portable")
        self.assertTrue((portable / "Launch.bat").exists())
        self.assertIn("Game.exe", result.main_exe_rel)


class DiagnosticsTests(unittest.TestCase):
    def test_stall_hints_explain_the_new_limit_and_the_surviving_files(self):
        engine = Portablizer(Logger())
        engine._install_stalled = True
        engine._install_stall = InstallStall(
            attempt="Inno Setup: /VERYSILENT /DIR", elapsed=5400.0,
            idle=900.0, idle_limit=900.0, deadline=0.0,
            written=18 * 1024 ** 3, files=120_000, processes=3)
        text = "\n".join(engine._stall_hints())
        self.assertIn("без предела", text)
        self.assertIn("120000", text.replace("_", "").replace(" ", ""))

    def test_final_message_says_that_partial_files_were_kept(self):
        engine = Portablizer(Logger())
        engine._install_stalled = True
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            _touch(str(app), "Game.exe", 10)
            result = engine_mod.PortableResult(success=False, portable_dir=temp)
            result.hints = ["подсказка"]
            message = engine._failure_message(mock.Mock(), None, result)
        self.assertIn("оставлены в папке App", message)


class PlanLogTests(unittest.TestCase):
    """Установщик пишет журнал по ходу — за ним и следим."""

    def test_inno_plan_exposes_its_log_as_a_progress_source(self):
        with tempfile.TemporaryDirectory() as temp:
            log = os.path.join(temp, "install.log")
            plan = build_silent_plan(InstallerType.INNO, "setup.exe",
                                     os.path.join(temp, "App"), log_file=log)
            self.assertEqual(len(plan.progress_logs), 1)
            self.assertTrue(plan.progress_logs[0].endswith("install.log"))

    def test_plan_without_a_log_has_no_progress_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            plan = build_silent_plan(InstallerType.NSIS, "setup.exe",
                                     os.path.join(temp, "App"))
            self.assertEqual(plan.progress_logs, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
