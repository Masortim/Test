"""Падение установщика: правильный диагноз вместо «не хватило прав».

Регрессия, ради которой написан этот модуль:

    При попытке портировать Hatred (офлайн-установщик GOG) сборка
    завершилась предупреждением «Установщик вернул код 3221226525
    (-1073740771, 0xC000041D). Похоже, процесс установщика аварийно
    завершился: как правило, не хватило прав администратора или тихий режим
    не поддерживается».

    Код 0xC000041D — это STATUS_FATAL_USER_CALLBACK_EXCEPTION: установщик
    УЖЕ шёл и был оборван исключением внутри своего callback’а. Права
    администратора тут ни при чём (установщик вообще стартовал), и совет
    «повысьте права» уводит от настоящих причин: нехватки места в TEMP (GOG
    распаковывает данные во временную папку), недокачанных или
    переименованных частей .bin, антивируса, который влез в процесс.

Проверяется, что теперь:
  * коды NTSTATUS расшифровываются поимённо, а общая фраза про права
    администратора остаётся только для кодов, где она уместна;
  * у падения, случившегося сразу после старта, есть признак «разовое» —
    по нему оркестратор решает повторить ту же команду;
  * журнал событий Windows читается: модуль с ошибкой отделяет падение
    самого установщика от вмешательства постороннего кода;
  * подсказки говорят о месте на диске, целостности дистрибутива и 7-Zip,
    а не «смотрите журнал».
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import crashinfo as crash_mod
from portablizer.core import portablizer as engine_mod

CRASH_CALLBACK = 0xC000041D
CRASH_CALLBACK_SIGNED = -1073740771
CRASH_CALLBACK_UNSIGNED = 3221226525

#: Как выглядит запись «Ошибка приложения» (Event ID 1000) в выгрузке
#: ``wevtutil qe Application /f:xml``. Именно её Windows пишет после падения
#: процесса: имя упавшего приложения, модуль с ошибкой, код исключения.
EVENT_XML = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\
<System><Provider Name="Application Error"/>\
<EventID Qualifiers="0">1000</EventID><Level>2</Level>\
<TimeCreated SystemTime="2026-10-14T01:23:40.1234567Z"/>\
<EventRecordID>12345</EventRecordID><Channel>Application</Channel>\
<Computer>DESKTOP</Computer><Security/></System>\
<EventData>\
<Data Name="AppName">setup_hatred_2.1.0.9_(2069488821).exe</Data>\
<Data Name="AppVer">2.1.0.9</Data>\
<Data Name="AppTimestamp">0x5a1b2c3d</Data>\
<Data Name="ModName">ntdll.dll</Data>\
<Data Name="ModVer">10.0.19041.1</Data>\
<Data Name="ModTimestamp">0x0</Data>\
<Data Name="Offset">0xa1b2c</Data>\
<Data Name="ExceptionCode">0xc000041d</Data>\
<Data Name="ReportId">7c4b1a2c-1234-5678-9abc-def012345678</Data>\
</EventData></Event>
</Events>
"""

#: Та же запись, но без имён полей: так её отдают старые сборки Windows и
#: локализованные журналы. Поля читаются по порядку.
EVENT_XML_POSITIONAL = """<Events><Event>\
<System><Provider Name="Application Error"/><EventID>1000</EventID>\
<TimeCreated SystemTime="2026-10-14T01:23:41.0000000Z"/></System>\
<EventData>\
<Data>setup_hatred_2.1.0.9_(2069488821).exe</Data>\
<Data>2.1.0.9</Data><Data>0x5a1b2c3d</Data>\
<Data>unknown.dll</Data><Data>1.0.0.0</Data><Data>0x0</Data>\
<Data>0x1f2a3b</Data><Data>0xc000041d</Data>\
</EventData></Event></Events>
"""


class CrashCodeTests(unittest.TestCase):
    def test_callback_crash_is_recognised_in_any_sign(self):
        for value in (CRASH_CALLBACK, CRASH_CALLBACK_SIGNED,
                      CRASH_CALLBACK_UNSIGNED):
            with self.subTest(value=value):
                self.assertTrue(crash_mod.is_crash_code(value))

    def test_crash_code_is_explained_by_name(self):
        item = crash_mod.crash_code(CRASH_CALLBACK_UNSIGNED)
        self.assertIsNotNone(item)
        self.assertEqual(item.name, "STATUS_FATAL_USER_CALLBACK_EXCEPTION")
        self.assertEqual(item.kind, "callback")
        self.assertIn("callback", item.summary)

    def test_plain_exit_codes_are_not_crashes(self):
        for value in (0, 1, 5, 3010, 1603, None, 4294967295):
            with self.subTest(value=value):
                self.assertFalse(crash_mod.is_crash_code(value))

    def test_fast_failures_are_marked_retryable(self):
        self.assertTrue(crash_mod.is_retryable(CRASH_CALLBACK_UNSIGNED))
        self.assertTrue(crash_mod.is_retryable(0xC0000005))
        # Ошибка чтения носителя разовой не бывает: повтор её не лечит.
        self.assertFalse(crash_mod.is_retryable(0xC0000006))

    def test_engine_hint_names_the_crash_instead_of_admin_rights(self):
        for value in (CRASH_CALLBACK_UNSIGNED, CRASH_CALLBACK, CRASH_CALLBACK_SIGNED):
            with self.subTest(value=value):
                hint = engine_mod._exit_code_hint(value)
                self.assertIn("STATUS_FATAL_USER_CALLBACK_EXCEPTION", hint)
                self.assertNotIn("не хватило прав администратора", hint)

    def test_one_line_of_log_keeps_the_old_wording_for_minus_one(self):
        # Код -1 (0xFFFFFFFF) — не падение: для него прежняя расшифровка
        # остаётся, иначе придётся объяснять пользователю то же самое заново.
        hint = engine_mod._exit_code_hint(4294967295)
        self.assertIn("администратора", hint)
        self.assertIn("администратора", hint)

    def test_code_is_printed_in_all_three_forms(self):
        # Сообщение должно содержать и беззнаковый код, и знаковый, и
        # шестнадцатеричный: пользователь ищет их в разных источниках.
        text = engine_mod._format_exit_code(CRASH_CALLBACK_UNSIGNED)
        self.assertEqual(text, "3221226525 (-1073740771, 0xC000041D)")


class EventLogTests(unittest.TestCase):
    def test_windows_event_is_parsed_field_by_field(self):
        events = crash_mod.parse_application_errors(EVENT_XML)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.app, "setup_hatred_2.1.0.9_(2069488821).exe")
        self.assertEqual(event.module, "ntdll.dll")
        self.assertEqual(event.exception_code, "0xc000041d")
        self.assertEqual(event.offset, "0xa1b2c")
        self.assertTrue(event.report_id)

    def test_event_without_field_names_is_read_positionally(self):
        events = crash_mod.parse_application_errors(EVENT_XML_POSITIONAL)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].app,
                         "setup_hatred_2.1.0.9_(2069488821).exe")
        self.assertEqual(events[0].module, "unknown.dll")
        self.assertEqual(events[0].exception_code, "0xc000041d")

    def test_broken_or_empty_dump_is_not_an_error(self):
        for text in ("", "не xml", "<Events>", "<Events><Event>"):
            with self.subTest(text=text):
                self.assertEqual(crash_mod.parse_application_errors(text), [])

    def test_journal_is_queried_with_a_query_and_a_limit(self):
        calls = []

        def runner(cmd, timeout):
            calls.append((list(cmd), timeout))
            return 0, EVENT_XML

        events = crash_mod.read_crash_events(
            ["setup_hatred_2.1.0.9_(2069488821).exe"], runner=runner)
        self.assertEqual(len(events), 1)
        cmd = calls[0][0]
        self.assertIn("Application", cmd)
        self.assertTrue(any("EventID=1000" in part for part in cmd))
        self.assertTrue(any(part.startswith("/c:") for part in cmd))

    def test_events_of_other_programs_are_ignored(self):
        events = crash_mod.read_crash_events(["setup_other.exe"],
                                             runner=lambda cmd, t: (0, EVENT_XML))
        self.assertEqual(events, [])

    def test_old_events_do_not_masquerade_as_todays_crash(self):
        import datetime as dt

        # Падение случилось 2026-10-14 01:23:40 UTC.
        later = dt.datetime(2026, 10, 14, 2, 0, 0,
                            tzinfo=dt.timezone.utc).timestamp()
        earlier = dt.datetime(2026, 10, 14, 1, 0, 0,
                              tzinfo=dt.timezone.utc).timestamp()
        name = "setup_hatred_2.1.0.9_(2069488821).exe"
        runner = lambda cmd, t: (0, EVENT_XML)  # noqa: E731
        self.assertEqual(crash_mod.read_crash_events([name], since=later,
                                                     runner=runner), [])
        self.assertEqual(len(crash_mod.read_crash_events([name], since=earlier,
                                                         runner=runner)), 1)

    def test_journal_failure_is_not_a_build_failure(self):
        def broken_runner(cmd, timeout):
            raise OSError("wevtutil не найден")

        self.assertEqual(crash_mod.read_crash_events(["setup.exe"],
                                                     runner=broken_runner), [])
        self.assertEqual(crash_mod.read_crash_events(
            ["setup.exe"], runner=lambda cmd, t: (1, "")), [])


class ModuleVerdictTests(unittest.TestCase):
    def test_crash_inside_the_installer_is_named_as_such(self):
        verdict = crash_mod.module_verdict(
            "setup_hatred_2.1.0.9_(2069488821).exe", "",
            "D:/Games/setup_hatred_2.1.0.9_(2069488821).exe")
        self.assertIn("внутри самого установщика", verdict)

    def test_system_library_points_to_outside_interference(self):
        verdict = crash_mod.module_verdict("ntdll.dll",
                                           r"C:\Windows\System32\ntdll.dll")
        self.assertIn("системная библиотека", verdict)
        self.assertIn("антивирус", verdict)

    def test_third_party_module_is_named_by_path(self):
        verdict = crash_mod.module_verdict(
            "avhook.dll", r"C:\Program Files\Some AV\avhook.dll")
        self.assertIn("сторонняя библиотека", verdict)

    def test_empty_module_has_no_verdict(self):
        self.assertEqual(crash_mod.module_verdict("", ""), "")

    def test_windows_paths_are_split_the_same_on_any_platform(self):
        # В журнале событий имя процесса записано полностью, и разбирать его
        # нужно одинаково и на Windows, и в тестах на другой ОС.
        self.assertEqual(crash_mod.base_name(r"C:\Games\setup_hatred.exe"),
                         "setup_hatred.exe")
        self.assertEqual(crash_mod.base_name("D:/Games/setup_hatred.exe"),
                         "setup_hatred.exe")
        verdict = crash_mod.module_verdict(r"C:\Games\setup_hatred.exe", "",
                                           "setup_hatred.exe")
        self.assertIn("внутри самого установщика", verdict)

    def test_event_with_a_full_path_in_app_name_is_matched(self):
        xml = EVENT_XML.replace(
            "<Data Name=\"AppName\">setup_hatred_2.1.0.9_(2069488821).exe",
            "<Data Name=\"AppName\">C:\\Games\\setup_hatred_2.1.0.9_(2069488821).exe")
        events = crash_mod.read_crash_events(
            ["setup_hatred_2.1.0.9_(2069488821).exe"],
            runner=lambda cmd, t: (0, xml))
        self.assertEqual(len(events), 1)


class CrashReportTests(unittest.TestCase):
    def test_report_contains_code_module_and_temp_state(self):
        events = crash_mod.parse_application_errors(EVENT_XML)
        report = crash_mod.format_report(
            CRASH_CALLBACK_UNSIGNED, "Inno Setup: /VERYSILENT /DIR",
            "setup.exe /VERYSILENT", events,
            installer_path="setup_hatred_2.1.0.9_(2069488821).exe",
            temp_line="TEMP установщика: E:\\Hatred_Portable\\PortableData\\Temp")
        self.assertIn("STATUS_FATAL_USER_CALLBACK_EXCEPTION", report)
        self.assertIn("0xc000041d", report)
        self.assertIn("ntdll.dll", report)
        self.assertIn("Inno Setup: /VERYSILENT /DIR", report)
        self.assertIn("TEMP установщика", report)
        # Модуль — системный (ntdll.dll), поэтому вывод отчёта говорит о
        # вмешательстве извне, а не о «нехватке прав».
        self.assertIn("системная библиотека", report)

    def test_report_says_when_the_installer_itself_crashed(self):
        events = crash_mod.parse_application_errors(EVENT_XML)
        events[0].module = "setup_hatred_2.1.0.9_(2069488821).exe"
        events[0].module_path = ""
        report = crash_mod.format_report(
            CRASH_CALLBACK_UNSIGNED, "Inno Setup: /VERYSILENT /DIR",
            "setup.exe /VERYSILENT", events,
            installer_path="setup_hatred_2.1.0.9_(2069488821).exe")
        self.assertIn("падение произошло внутри самого установщика", report)

    def test_report_without_journal_entries_still_explains_the_code(self):
        report = crash_mod.format_report(CRASH_CALLBACK_UNSIGNED, "попытка",
                                         "setup.exe", [], temp_line="")
        self.assertIn("STATUS_FATAL_USER_CALLBACK_EXCEPTION", report)
        self.assertIn("журнал событий", report.lower())


class CrashHintTests(unittest.TestCase):
    def test_hatred_like_failure_gets_actionable_advice(self):
        """Главный сценарий: GOG-установщик упал на 0xC000041D."""
        events = crash_mod.parse_application_errors(EVENT_XML)
        hints = crash_mod.crash_hints(
            CRASH_CALLBACK_UNSIGNED,
            installer_path="setup_hatred_2.1.0.9_(2069488821).exe",
            event=events[0], is_gog=True, is_inno=True,
            space_note="На диске «E:» свободно 3.1 ГБ, а нужно около 4.0 ГБ.",
            suggest_unpacker=True)
        text = "\n".join(hints)
        self.assertIn("STATUS_FATAL_USER_CALLBACK_EXCEPTION", text)
        self.assertNotIn("не хватило прав администратора", text)
        self.assertIn("3.1 ГБ", text)              # конкретные числа
        self.assertIn(".bin", text)                # целостность дистрибутива GOG
        self.assertIn("антивирус", text)
        self.assertIn("7-Zip", text)
        self.assertIn("ntdll.dll", text)           # факт из журнала событий

    def test_admin_rights_are_never_blamed_for_a_crash(self):
        """Прежняя фраза «не хватило прав администратора» не должна вернуться."""
        for code in (CRASH_CALLBACK_UNSIGNED, 0xC0000005, 0xC0000017,
                     0xC0000135, 0xC00000FD):
            with self.subTest(code=code):
                text = " ".join(crash_mod.crash_hints(code)).lower()
                self.assertTrue(text)
                self.assertNotIn("не хватило прав", text)
                self.assertNotIn("от имени администратора", text)
                # О правах говорится только затем, чтобы снять ложный след.
                self.assertNotIn("запустите portablizer", text)

    def test_retry_and_progress_window_are_reported_honestly(self):
        hints = crash_mod.crash_hints(
            CRASH_CALLBACK_UNSIGNED, retried=True,
            progress_retry="Уже пробовал с окном прогресса.",
            unpacker_result="Распаковка без запуска не дала файлов.")
        text = "\n".join(hints)
        self.assertIn("повторил ровно ту же команду", text)
        self.assertIn("Уже пробовал с окном прогресса", text)
        self.assertIn("Распаковка без запуска", text)

    def test_plain_exit_code_produces_no_crash_hints(self):
        self.assertEqual(crash_mod.crash_hints(1), [])
        self.assertEqual(crash_mod.crash_hints(None), [])

    def test_gog_advice_is_absent_for_other_installers(self):
        text = "\n".join(crash_mod.crash_hints(CRASH_CALLBACK_UNSIGNED,
                                               is_gog=False))
        self.assertNotIn(".bin", text)


class TempLineTests(unittest.TestCase):
    def test_temp_line_shows_the_folder_and_free_space(self):
        with tempfile.TemporaryDirectory() as temp:
            engine = engine_mod.Portablizer(engine_mod.Logger())
            engine._install_temp_dir = temp
            line = engine._temp_line()
            self.assertIn(temp, line)
            self.assertIn("свободно", line)

    def test_temp_line_is_empty_before_the_folder_is_chosen(self):
        engine = engine_mod.Portablizer(engine_mod.Logger())
        self.assertEqual(engine._temp_line(), "")


class FolderDetectionTests(unittest.TestCase):
    def test_unpackable_engines_only(self):
        engine = engine_mod.Portablizer(engine_mod.Logger())
        from portablizer.core.detect import DetectionResult, InstallerType

        for itype, expected in ((InstallerType.INNO, True),
                                (InstallerType.NSIS, True),
                                (InstallerType.UNKNOWN, True),
                                (InstallerType.MSI, False),
                                (InstallerType.WIX_BURN, False),
                                (InstallerType.INSTALLSHIELD, False)):
            with self.subTest(itype=itype):
                det = DetectionResult(installer_type=itype, confidence=90)
                self.assertEqual(engine._unpacker_worth_trying(det), expected)


if __name__ == "__main__":
    unittest.main()
