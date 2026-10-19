"""Что делает сборка, когда установщик ПАДАЕТ (а не «не понял ключи»).

Регрессия, ради которой написан этот модуль:

    Портирование Hatred (офлайн-установщик GOG) закончилось сообщением
    «Установщик вернул код 3221226525 (-1073740771, 0xC000041D). Похоже,
    процесс установщика аварийно завершился: как правило, не хватило прав
    администратора или тихий режим не поддерживается».

    Диагноз был неверным: 0xC000041D — STATUS_FATAL_USER_CALLBACK_EXCEPTION,
    установщик УЖЕ работал и был оборван исключением. И делать после такого
    падения нужно другое: проверить, не разовая ли это помеха (повторить ту
    же команду), пройти другой веткой кода установщика (окно прогресса
    вместо полной тишины), дать ему место на диске (GOG распаковывает данные
    в TEMP) и, если он падает в любом режиме, достать файлы БЕЗ его запуска.

Проверяется, что:
  * падение через секунды после старта повторяется ровно один раз, а
    падение после часовой работы — нет (это не помеха, а закономерность);
  * после падения в лестницу добавляется запуск с окном прогресса
    (/SILENT), причём без дублей того, что в лестнице уже есть;
  * TEMP установщика переносится на другой диск, когда на диске портатива
    для распаковки не хватает места, и обязательно убирается после сборки;
  * содержимое падающего установщика пробуют достать распаковщиком БЕЗ
    запуска, а итоговые подсказки говорят об этом честно.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import portablizer as engine_mod
from portablizer.core import space as space_mod
from portablizer.core import unpacker as unpacker_mod
from portablizer.core.detect import DetectionResult, InstallerType
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import (
    CRASH_RETRY_MAX_SECONDS, PortableOptions, Portablizer,
)
from portablizer.core.silentargs import build_silent_plan

CRASH = 0xC000041D


def _touch(root: str, name: str, content: str = "x") -> str:
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


class _ScriptedPortablizer(Portablizer):
    """Portablizer с подменённой установкой: коды возврата — по сценарию.

    Сам запуск установщика здесь не проверяется (для него нужен Windows),
    проверяется РЕШЕНИЕ сборки: какую команду она запускает следующей и что
    говорит пользователю после падения.
    """

    def __init__(self, codes, app_files=None, seconds=3.0):
        super().__init__(Logger())
        self.codes = list(codes)
        self.calls = []
        self.app_files = app_files or {}
        self.seconds = seconds

    def _run_install(self, plan, opts, app_dir, data_dir,  # noqa: D102
                     progress_from=30, progress_to=60, console_log=None):
        self.calls.append(plan)
        code = self.codes.pop(0) if self.codes else 0
        self._last_install_seconds = self.seconds
        if self.codes:  # файлы появляются только на последнем сценарии
            return code
        for name, content in self.app_files.items():
            _touch(app_dir, name, content)
        return code


class CrashRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.portable = str(root / "Hatred_Portable")
        self.app = str(root / "Hatred_Portable" / "App")
        self.data = str(root / "Hatred_Portable" / "PortableData")
        os.makedirs(self.app, exist_ok=True)
        os.makedirs(self.data, exist_ok=True)
        self.installer = _touch(self.temp.name, "setup_hatred_2.1.0.9_(1).exe")
        self.opts = PortableOptions(installer_path=self.installer,
                                    output_dir=self.temp.name)
        self.plan = build_silent_plan(InstallerType.INNO, self.installer,
                                      self.app)

    def _run(self, engine):
        return engine._run_attempts([self.plan], self.opts, self.app,
                                    self.data, self.portable, "Hatred")

    def test_fast_crash_repeats_the_same_command_exactly_once(self):
        engine = _ScriptedPortablizer([CRASH, CRASH, CRASH], app_files={})
        rc, used = self._run(engine)
        self.assertEqual(len(engine.calls), 3)
        self.assertEqual(engine.calls[0].args, engine.calls[1].args)
        self.assertIn("повтор после падения", engine.calls[1].label)
        self.assertIsNone(used)
        self.assertEqual(rc, CRASH)

    def test_slow_crash_is_not_repeated(self):
        """Установщик, упавший после часа работы, — не разовая помеха."""
        engine = _ScriptedPortablizer([CRASH, CRASH],
                                      seconds=CRASH_RETRY_MAX_SECONDS + 60)
        self._run(engine)
        labels = [plan.label for plan in engine.calls]
        self.assertFalse(any("повтор после падения" in label for label in labels))
        self.assertTrue(any("/SILENT" in plan.display() for plan in engine.calls))

    def test_crash_does_not_repeat_when_files_were_already_written(self):
        """Частично распакованную установку заново не запускают."""
        engine = _ScriptedPortablizer([CRASH, CRASH])
        original = engine._run_install

        def run_install(plan, opts, app_dir, data_dir, **kwargs):
            code = original(plan, opts, app_dir, data_dir, **kwargs)
            if len(engine.calls) == 1:
                _touch(app_dir, "partial.dat")
            return code

        engine._run_install = run_install
        self._run(engine)
        self.assertFalse(any("повтор после падения" in plan.label
                             for plan in engine.calls))
        self.assertTrue(os.path.isfile(os.path.join(self.app, "partial.dat")))

    def test_crash_is_not_mistaken_for_success_when_exe_already_extracted(self):
        """Регрессия: Hatred (0xC000041D) успел распаковать Hatred.exe ДО

        падения, и сборка принимала это за «Тихая установка прошла
        успешно», даже не пытаясь восстановиться. Крах должен быть замечен
        первым, а успех — только когда лестница восстановления либо нашла
        рабочий сценарий, либо честно исчерпалась.
        """
        engine = _ScriptedPortablizer([CRASH, 0])
        original = engine._run_install

        def run_install(plan, opts, app_dir, data_dir, **kwargs):
            code = original(plan, opts, app_dir, data_dir, **kwargs)
            if len(engine.calls) == 1:
                # Установщик успел записать главный exe ДО того, как упал
                # в отрисовке прогресса — это не одно и то же, что «успех».
                _touch(app_dir, "Hatred.exe", "game")
            return code

        engine._run_install = run_install
        rc, used = self._run(engine)
        self.assertEqual(len(engine.calls), 2)
        self.assertNotIn("Тихая установка прошла успешно",
                         engine.log.text)
        self.assertIn("/SILENT", engine.calls[1].args)
        self.assertEqual(rc, 0)
        self.assertIs(used, engine.calls[1])

    def test_crash_is_reported_honestly_when_recovery_is_exhausted(self):
        """Если восстановиться больше нечем, итог не красится в «успех»."""
        engine = _ScriptedPortablizer([CRASH, CRASH])
        original = engine._run_install

        def run_install(plan, opts, app_dir, data_dir, **kwargs):
            code = original(plan, opts, app_dir, data_dir, **kwargs)
            if len(engine.calls) == 1:
                _touch(app_dir, "Hatred.exe", "game")
            return code

        engine._run_install = run_install
        rc, used = self._run(engine)
        self.assertEqual(rc, CRASH)
        self.assertIsNotNone(used)
        self.assertNotIn("Тихая установка прошла успешно",
                         engine.log.text)
        self.assertIn("Установщик упал", engine.log.text)

    def test_progress_window_attempt_replaces_very_silent_switch(self):
        engine = _ScriptedPortablizer([CRASH, CRASH, 0],
                                      app_files={"Hatred.exe": "game"})
        rc, used = self._run(engine)
        self.assertEqual(len(engine.calls), 3)
        third = engine.calls[2]
        self.assertIn("/SILENT", third.args)
        self.assertNotIn("/VERYSILENT", third.args)
        self.assertIn("/DIR=", " ".join(third.args))
        self.assertEqual(used, third)
        self.assertEqual(rc, 0)

    def test_progress_window_attempt_is_not_duplicated(self):
        """Если /SILENT уже есть в лестнице, второй такой запуск не нужен."""
        silent = engine_mod.build_progress_window_attempt(self.plan)
        self.assertIsNotNone(silent)
        engine = _ScriptedPortablizer(
            [CRASH, 0], app_files={"Hatred.exe": "game"},
            seconds=CRASH_RETRY_MAX_SECONDS + 60)
        rc, used = engine._run_attempts(
            [self.plan, silent], self.opts, self.app, self.data,
            self.portable, "Hatred")
        self.assertEqual(len(engine.calls), 2)
        self.assertIs(used, silent)
        self.assertEqual(rc, 0)

    def test_enqueue_plan_detects_the_same_command(self):
        engine = _ScriptedPortablizer([CRASH, CRASH])
        queue = [self.plan]
        copy_of_plan = build_silent_plan(InstallerType.INNO, self.installer,
                                         self.app)
        self.assertFalse(engine._enqueue_plan(queue, 1, copy_of_plan))
        self.assertEqual(len(queue), 1)

    def test_attempt_history_keeps_every_outcome(self):
        engine = _ScriptedPortablizer([CRASH, CRASH, CRASH])
        self._run(engine)
        self.assertEqual(len(engine._attempt_history), 3)
        self.assertTrue(all(code == CRASH for _label, code
                            in engine._attempt_history))
        labels = [label for label, _code in engine._attempt_history]
        self.assertIn("повтор после падения", " ".join(labels))


class CrashDiagnosisTests(unittest.TestCase):
    """Подсказки после падения: числа, причины и что делать, а не «журнал»."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.portable = os.path.join(self.temp.name, "Hatred_Portable")
        self.app = os.path.join(self.portable, "App")
        os.makedirs(self.app, exist_ok=True)
        self.installer = _touch(self.temp.name,
                                "setup_hatred_2.1.0.9_(2069488821).exe")
        self.opts = PortableOptions(installer_path=self.installer,
                                    output_dir=self.temp.name)
        self.det = DetectionResult(installer_type=InstallerType.INNO,
                                   confidence=90, is_gog=True)

    def test_hints_explain_the_crash_and_name_concrete_causes(self):
        engine = Portablizer(Logger())
        engine._installer_name = self.installer
        engine._crash_history = [("Inno Setup: /VERYSILENT /DIR", CRASH)]
        engine._crash_retried = True
        engine._temp_space_note = "На диске «E:» свободно 1.5 ГБ, нужно 4.0 ГБ."
        hints = engine._failure_hints(self.det, CRASH, self.opts, self.portable)
        text = "\n".join(hints)
        self.assertIn("STATUS_FATAL_USER_CALLBACK_EXCEPTION", text)
        self.assertNotIn("не хватило прав администратора", text)
        self.assertIn("1.5 ГБ", text)
        self.assertIn(".bin", text)
        self.assertIn("7-Zip", text)
        self.assertIn("повторил ровно ту же команду", text)

    def test_generic_admin_advice_stays_for_command_line_codes(self):
        """Код -1 — не падение: для него прежняя расшифровка остаётся."""
        self.assertIn("администратора", engine_mod._exit_code_hint(0xFFFFFFFF))
        engine = Portablizer(Logger())
        hints = engine._failure_hints(self.det, 0xFFFFFFFF, self.opts,
                                      self.portable)
        # ... а разбора падения для него не появляется: это другой случай.
        self.assertNotIn("STATUS_", "\n".join(hints))

    def test_crash_report_is_written_next_to_the_installer_log(self):
        engine = Portablizer(Logger())
        engine._installer_name = os.path.basename(self.installer)
        engine._install_temp_dir = os.path.join(self.portable, "PortableData",
                                               "Temp")
        os.makedirs(engine._install_temp_dir, exist_ok=True)
        plan = build_silent_plan(InstallerType.INNO, self.installer, self.app)
        console_log = os.path.join(self.portable, "installer-output.log")
        with mock.patch.object(engine_mod.crash_mod, "read_crash_events",
                               return_value=[]):
            engine._note_crash(plan, CRASH, "setup.exe /VERYSILENT",
                               console_log)
        report = os.path.join(self.portable, "installer-crash.log")
        self.assertTrue(os.path.isfile(report))
        with open(report, encoding="utf-8-sig") as fh:
            text = fh.read()
        self.assertIn("3221226525", text)
        self.assertIn("STATUS_FATAL_USER_CALLBACK_EXCEPTION", text)
        self.assertIn("TEMP установщика", text)

    def test_crash_does_not_write_a_report_for_a_normal_exit_code(self):
        engine = Portablizer(Logger())
        plan = build_silent_plan(InstallerType.INNO, self.installer, self.app)
        console_log = os.path.join(self.portable, "installer-output.log")
        engine._note_crash(plan, 0, "setup.exe", console_log)
        engine._note_crash(plan, 1, "setup.exe", console_log)
        self.assertFalse(os.path.exists(
            os.path.join(self.portable, "installer-crash.log")))
        self.assertEqual(engine._crash_history, [])

    def test_engine_hint_of_the_warning_is_still_readable(self):
        """Ту же расшифровку видно и в односкрочном предупреждении."""
        hint = engine_mod._exit_code_hint(CRASH)
        self.assertIn("STATUS_FATAL_USER_CALLBACK_EXCEPTION", hint)


class TempRelocationTests(unittest.TestCase):
    """TEMP установщика: места на диске портатива может не хватить."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.portable = os.path.join(self.temp.name, "Hatred_Portable")
        self.app = os.path.join(self.portable, "App")
        self.data = os.path.join(self.portable, "PortableData")
        os.makedirs(self.app, exist_ok=True)
        os.makedirs(self.data, exist_ok=True)
        self.other_disk = os.path.join(self.temp.name, "большой-диск")
        os.makedirs(self.other_disk, exist_ok=True)
        self.installer = _touch(self.temp.name,
                                "setup_hatred_2.1.0.9_(2069488821).exe")
        self.opts = PortableOptions(installer_path=self.installer,
                                    output_dir=self.temp.name)
        self.det = DetectionResult(installer_type=InstallerType.INNO,
                                   confidence=90, is_gog=True)

    def test_temp_moves_when_the_portable_drive_is_too_small(self):
        engine = Portablizer(Logger())
        with mock.patch.object(space_mod, "media_bytes",
                               return_value=2 * 1024 ** 3), \
                mock.patch.object(space_mod, "free_space", return_value=10 ** 9), \
                mock.patch.object(space_mod, "pick_temp_root",
                                  return_value=self.other_disk):
            engine._prepare_install_temp(self.opts, self.portable, self.data,
                                         self.det)
        temp_dir = engine._install_temp_dir
        self.assertTrue(temp_dir.startswith(self.other_disk))
        self.assertTrue(os.path.isdir(temp_dir))
        self.assertIn(temp_dir, engine._build_isolated_env(
            self.opts, self.data)["TEMP"])
        self.assertIn("перенесён", engine._temp_line())
        engine._cleanup_install_temp()
        self.assertFalse(os.path.exists(temp_dir))

    def test_temp_stays_inside_the_portable_when_there_is_room(self):
        engine = Portablizer(Logger())
        with mock.patch.object(space_mod, "media_bytes",
                               return_value=2 * 1024 ** 3), \
                mock.patch.object(space_mod, "free_space",
                                  return_value=50 * 1024 ** 3):
            engine._prepare_install_temp(self.opts, self.portable, self.data,
                                         self.det)
        self.assertEqual(engine._install_temp_dir,
                         os.path.join(self.data, "Temp"))
        self.assertEqual(engine._external_temp_dirs, [])
        # Папка портатива — не чужая территория: её уборка не трогает.
        engine._cleanup_install_temp()
        self.assertEqual(engine._install_temp_dir, os.path.join(self.data, "Temp"))

    def test_redirected_profile_precreates_user_pinned_known_folder(self):
        """Autodesk CREATE_LAUNCH_ITEMS must resolve FOLDERID_UserPinned."""
        engine = Portablizer(Logger())
        env = engine._build_isolated_env(self.opts, self.data)
        pinned = os.path.join(
            env["APPDATA"], "Microsoft", "Internet Explorer",
            "Quick Launch", "User Pinned",
        )
        self.assertTrue(os.path.isdir(pinned))
        self.assertEqual(os.path.commonpath([self.data, pinned]), self.data)

    def test_shortage_without_another_disk_is_explained(self):
        engine = Portablizer(Logger())
        with mock.patch.object(space_mod, "media_bytes",
                               return_value=4 * 1024 ** 3), \
                mock.patch.object(space_mod, "free_space",
                                  return_value=1 * 1024 ** 3), \
                mock.patch.object(space_mod, "pick_temp_root",
                                  return_value=None):
            engine._prepare_install_temp(self.opts, self.portable, self.data,
                                         self.det)
        self.assertEqual(engine._install_temp_dir,
                         os.path.join(self.data, "Temp"))
        self.assertIn("ГБ", engine._temp_space_note)
        self.assertIn("TEMP", engine._temp_space_note)

    def test_unknown_sizes_do_not_scare_the_user(self):
        engine = Portablizer(Logger())
        with mock.patch.object(space_mod, "media_bytes", return_value=0):
            engine._prepare_install_temp(self.opts, self.portable, self.data,
                                         self.det)
        self.assertEqual(engine._temp_space_note, "")
        self.assertEqual(engine._install_temp_dir,
                         os.path.join(self.data, "Temp"))

    def test_stale_temporary_folder_of_a_previous_build_is_cleared(self):
        """Прошлая неудачная установка оставила в TEMP гигабайты."""
        stale = os.path.join(self.data, "Temp")
        _touch(stale, "setup.tmp", "мусор прошлой сборки")
        engine = Portablizer(Logger())
        engine._prepare_output(self.portable, self.app, self.data)
        self.assertTrue(os.path.isdir(stale))
        self.assertEqual(os.listdir(stale), [])

    def test_cleanup_survives_a_folder_that_is_already_gone(self):
        engine = Portablizer(Logger())
        engine._external_temp_dirs = [os.path.join(self.temp.name, "нет-такой")]
        engine._cleanup_install_temp()
        self.assertEqual(engine._external_temp_dirs, [])

    def test_crash_log_and_work_folder_are_not_left_from_a_previous_build(self):
        _touch(self.portable, "installer-crash.log", "старое падение")
        _touch(self.portable, "_unpacked/{app}/old.exe")
        engine = Portablizer(Logger())
        engine._prepare_output(self.portable, self.app, self.data)
        self.assertFalse(os.path.exists(
            os.path.join(self.portable, "installer-crash.log")))
        self.assertFalse(os.path.exists(
            os.path.join(self.portable, "_unpacked")))


class UnpackerFallbackTests(unittest.TestCase):
    """Падающий установщик можно распаковать, не запуская его."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.portable = os.path.join(self.temp.name, "Hatred_Portable")
        self.app = os.path.join(self.portable, "App")
        self.data = os.path.join(self.portable, "PortableData")
        os.makedirs(self.app, exist_ok=True)
        os.makedirs(self.data, exist_ok=True)
        self.installer = _touch(self.temp.name,
                                "setup_hatred_2.1.0.9_(2069488821).exe")
        self.opts = PortableOptions(installer_path=self.installer,
                                    output_dir=self.temp.name)
        self.det = DetectionResult(installer_type=InstallerType.INNO,
                                   confidence=90, is_gog=True)

    def test_payload_is_extracted_without_running_the_installer(self):
        engine = Portablizer(Logger())

        def fake_unpacker(cmd, console_log, opts):
            # Настоящий 7-Zip раскладывает файлы Inno по корням вида {app};
            # здесь это делает подстановка, а дальше работает настоящий код
            # раскладки (unpacker.promote_payload).
            target = [arg for arg in cmd if arg.startswith("-o")][0][2:]
            _touch(target, os.path.join("{app}", "Hatred.exe"), "game")
            _touch(target, os.path.join("{app}", "data", "pak.pak"), "data")
            _touch(target, os.path.join("{tmp}", "setup.tmp"), "tmp")
            return 0, "Everything is Ok"

        with mock.patch.object(unpacker_mod, "find_unpacker",
                               return_value="/usr/bin/7z"), \
                mock.patch.object(engine, "_run_unpacker_command",
                                  side_effect=fake_unpacker):
            ok = engine._try_unpacker_fallback(self.opts, self.app,
                                               self.portable, self.det, "Hatred")

        self.assertTrue(ok)
        self.assertTrue(os.path.isfile(os.path.join(self.app, "Hatred.exe")))
        self.assertTrue(os.path.isfile(
            os.path.join(self.app, "data", "pak.pak")))
        self.assertFalse(os.path.exists(os.path.join(self.app, "setup.tmp")))
        self.assertEqual(engine._unpacked_with, "/usr/bin/7z")
        # Рабочая папка распаковки не остаётся в портативе.
        self.assertFalse(os.path.exists(os.path.join(self.portable,
                                                     "_unpacked")))

    def test_missing_unpacker_is_not_a_failure_but_a_fact(self):
        engine = Portablizer(Logger())
        with mock.patch.object(unpacker_mod, "find_unpacker",
                               return_value=""):
            ok = engine._try_unpacker_fallback(self.opts, self.app,
                                               self.portable, self.det, "Hatred")
        self.assertFalse(ok)
        self.assertEqual(engine._unpacked_with, "")
        self.assertIn("7-Zip", engine.log.text)

    def test_unpackable_engines_only(self):
        engine = Portablizer(Logger())
        for itype in (InstallerType.MSI, InstallerType.WIX_BURN,
                      InstallerType.INSTALLSHIELD):
            det = DetectionResult(installer_type=itype, confidence=95)
            with mock.patch.object(unpacker_mod, "find_unpacker") as finder:
                self.assertFalse(engine._try_unpacker_fallback(
                    self.opts, self.app, self.portable, det, "Hatred"))
                finder.assert_not_called()

    def test_empty_result_is_honestly_reported(self):
        engine = Portablizer(Logger())

        def fake_unpacker(cmd, console_log, opts):
            target = [arg for arg in cmd if arg.startswith("-o")][0][2:]
            _touch(target, os.path.join("{tmp}", "setup.tmp"), "tmp")
            return 0, ""

        with mock.patch.object(unpacker_mod, "find_unpacker",
                               return_value="/usr/bin/7z"), \
                mock.patch.object(engine, "_run_unpacker_command",
                                  side_effect=fake_unpacker):
            ok = engine._try_unpacker_fallback(self.opts, self.app,
                                               self.portable, self.det, "Hatred")
        self.assertFalse(ok)
        self.assertIn("не дала файлов программы", engine._unpacker_result)

    def _stuck_run(self, deadline: float):
        """Прогон распаковщика, который запустился и не завершается.

        Возвращает ``(код, текст, был_ли_снят_процесс)``: время идёт
        подставными часами, поэтому тест не ждёт ни секунды.
        """
        engine = Portablizer(Logger())
        opts = PortableOptions(installer_path=self.installer,
                               output_dir=self.temp.name,
                               install_deadline=deadline)
        console_log = os.path.join(self.temp.name, "unpacker-output.log")

        class StuckProcess:
            pid = 4321
            returncode = None

            def poll(self):
                return None

        stopped = []
        with mock.patch.object(engine_mod.subprocess, "Popen",
                               lambda *a, **k: StuckProcess()), \
                mock.patch.object(engine, "_stop_installer",
                                  side_effect=lambda proc: stopped.append(proc)), \
                mock.patch.object(engine_mod.time, "sleep", lambda _s: None), \
                mock.patch.object(engine_mod.time, "monotonic",
                                  side_effect=[100.0, 100.0, 2000.0, 4000.0]):
            code, text = engine._run_unpacker_command(["7z", "x"], console_log,
                                                      opts)
        return code, text, stopped

    def test_a_stuck_unpacker_is_stopped_by_the_deadline(self):
        """Незавершающийся распаковщик не держит сборку вечно.

        Регрессия сборки на Windows: тест подменял ``subprocess.Popen``
        «вечно работающим» двойником, а распаковка без запуска ходит в тот же
        subprocess — и ждала этот двойник бесконечно. Прогон молчал 28 минут
        и был снят целиком. Ждать вечно распаковка не имеет права.
        """
        code, text, stopped = self._stuck_run(deadline=0.05)
        self.assertEqual(code, -1)
        self.assertIn("предел", text)
        self.assertEqual(len(stopped), 1)

    def test_unpacker_keeps_its_own_ceiling_when_the_install_limit_is_off(self):
        """Потолок установки снят (0) — у распаковки всё равно есть свой."""
        code, text, stopped = self._stuck_run(deadline=0)
        self.assertEqual(code, -1)
        self.assertIn("предел", text)
        self.assertEqual(len(stopped), 1)
        self.assertGreater(engine_mod.UNPACK_HARD_LIMIT, 0)


class EndToEndWiringTests(unittest.TestCase):
    """Связка целиком: run() доводит до подсказок всё, что узнал по пути."""

    def test_result_gets_temp_and_report_fields(self):
        engine = Portablizer(Logger())
        result = engine_mod.PortableResult(success=False)
        with tempfile.TemporaryDirectory() as temp:
            engine._install_temp_dir = os.path.join(temp, "PortableData", "Temp")
            engine._unpacked_with = "/usr/bin/7z"
            _touch(temp, "installer-crash.log", "отчёт")
            engine._fill_temp_fields(result, temp)
            self.assertEqual(result.installer_temp_dir,
                             engine._install_temp_dir)
            self.assertEqual(result.unpacked_with, "/usr/bin/7z")
            self.assertEqual(result.crash_report_rel, "installer-crash.log")

    def test_missing_report_is_not_advertised(self):
        engine = Portablizer(Logger())
        result = engine_mod.PortableResult(success=False)
        with tempfile.TemporaryDirectory() as temp:
            engine._fill_temp_fields(result, temp)
            self.assertEqual(result.crash_report_rel, "")


if __name__ == "__main__":
    unittest.main()
