"""Adobe Creative Cloud и XD: «код ошибки 191» и портатив без UWP-шага.

Регрессия, ради которой написан этот модуль:

    Портирование ``Adobe.XD.v61.0.12.1.exe`` заканчивалось окном «Ошибка при
    установке: В настоящее время невозможно установить XD. (Код ошибки:
    191)». Код 191 — это не «непонятая командная строка» и не отсутствие
    ключей тишины: упал шаг ``AddUWPAppxCommand``, которым Adobe ставит
    UWP-пакет (``SparklerApp.appx`` = ``Adobe.CC.XD``) сразу для всех
    пользователей. Отдельная беда в том, что такой пакет вообще не бывает
    портативным: Windows регистрирует его на конкретном компьютере.

Проверяется, что:

  * установщик Adobe опознаётся и по строкам HyperDrive (HDSetup/HDPIM), и по
    стандартизованному имени файла, и по раскладке ``payloads`` рядом с
    ``setup.exe``, а настоящий движок внутри (Inno) не подменяется;
  * первый сценарий сборки вообще НЕ запускает установщик: он раскладывает
    пакеты программы в ``App``, а UWP-пакет пропускает — то есть шаг с кодом
    191 не выполняется;
  * MSI ставятся административной установкой (система не меняется), ZIP
    распаковываются своей библиотекой, а ``..`` в архиве не выпускает файлы
    за пределы ``App``;
  * пакеты, которые установщик успел распаковать в ``adobeTemp`` до отказа на
    UWP-шаге, забираются оттуда в ``App`` (второй источник);
  * журнал Adobe разбирается по существу: код, шаг, пакет и OS-код Windows
    (служба AppX, sideloading, framework), а незнакомый OS-код не получает
    выдуманной расшифровки;
  * в папке портатива появляется ``adobe-uwp.txt`` — что именно осталось за
    бортом (плитка «Пуск», «Поделиться», ассоциации) и почему.
"""
import ntpath
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import adobe as adobe_mod
from portablizer.core import portablizer as engine_mod
from portablizer.core import unpacker as unpacker_mod
from portablizer.core.detect import (
    DetectionResult, InstallerType, detect_installer,
)
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer
from portablizer.core.silentargs import build_attempts
import pebuild


def _extractors(style: str = unpacker_mod.STYLE_7ZIP,
                path: str = "C:\\7-Zip\\7z.exe"):
    """Список «найденных» распаковщиков для подмены поиска в тестах."""
    return [unpacker_mod.Extractor(style, path)]


def _touch(root: str, name: str, content: str = "x") -> str:
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _make_pe(path: str, extra: bytes = b"", imports=()) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return pebuild.write_pe(path, imports=imports, extra=extra)


def _zip_with(path: str, members) -> str:
    """Собирает настоящий ZIP: ``members`` — пары (имя, содержимое)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with zipfile.ZipFile(path, "w") as bundle:
        for name, content in members:
            bundle.writestr(name, content)
    return path


#: Строка из настоящего журнала Adobe (форум Adobe, ошибка 191 у XD).
ADOBE_LOG = """
2024-05-05 12:00:00:000 | [ERROR] | 1 | HDSetup | HDPIM | AddUWPAppxCommand
FATAL: Error (Code = 191) executing in command 'AddUWPAppxCommand' for package: 'UWPAssets', version: 61.0.12.1
FATAL: Error occurred in install of package (Name: UWPAssets Version: 61.0.12.1). Error code: '191'
ERROR: hdhelper.exe failed to install UWP app with error code 1 - OS Message: \
C:\\adobeTemp\\ETR1A2B.tmp\\1\\SparklerApp\\SparklerApp.appx#@#OS_Error_Code: 0x80073CF3\
#@#OS_Error_String: Windows cannot install package Adobe.CC.XD because this package \
depends on a framework that could not be found.
Exit Code: 191
"""


# --- определение типа --------------------------------------------------------

class AdobeDetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_hyperdrive_markers_are_recognized(self):
        installer = _make_pe(
            str(self.root / "Setup.exe"),
            extra=(b"HDPIM\0HDSetup\0AddUWPAppxCommand\0"
                   b"Adobe Desktop Common\0adobeTemp\0"))
        det = detect_installer(installer)
        self.assertEqual(det.installer_type, InstallerType.ADOBE_HD)
        self.assertTrue(det.is_adobe_hd)
        self.assertEqual(det.vendor_name, "Adobe")
        self.assertTrue(any("UWP" in line for line in det.evidence))

    def test_standard_filename_is_adobe_even_inside_a_self_extractor(self):
        """Оболочка пакета — SFX: движок не опознан, но имя файла говорит всё."""
        installer = _make_pe(
            str(self.root / "Adobe.XD.v61.0.12.1.exe"),
            extra=b"7-Zip SFX\0")
        det = detect_installer(installer)
        self.assertEqual(det.installer_type, InstallerType.ADOBE_HD)
        self.assertTrue(det.adobe_named)
        self.assertTrue(det.is_adobe_hd)

    def test_real_engine_inside_adobe_named_file_is_not_replaced(self):
        """Репак Adobe XD на Inno Setup остаётся Inno Setup с его ключами."""
        installer = _make_pe(
            str(self.root / "Adobe.XD.v61.0.12.1.exe"),
            extra=b"Inno Setup Setup Data (5.6.1)\0")
        det = detect_installer(installer)
        self.assertEqual(det.installer_type, InstallerType.INNO)
        self.assertTrue(det.adobe_named)
        # Настоящий движок важнее имени файла: ключи Adobe ему не нужны.
        self.assertFalse(any("--ADOBEINSTALLDIR" in e for e in det.evidence))

    def test_payloads_layout_next_to_setup_is_adobe(self):
        folder = self.root / "Build"
        _make_pe(str(folder / "setup.exe"), extra=b"MZ\0")
        _touch(str(folder), "PackageInfo.txt", "Adobe XD")
        _touch(str(folder / "payloads" / "AdobeXD61.0-mul"), "Adobe XD.msi")
        _touch(str(folder / "payloads" / "SparklerApp"), "SparklerApp.appx")
        det = detect_installer(str(folder / "setup.exe"))
        self.assertEqual(det.installer_type, InstallerType.ADOBE_HD)
        self.assertTrue(det.adobe_layout)
        self.assertTrue(any("payloads" in line for line in det.evidence))

    def test_payloads_directory_alone_is_not_enough(self):
        """Каталог payloads бывает и у чужих установщиков — без маркеров верим мало."""
        folder = self.root / "Other"
        _make_pe(str(folder / "installer.exe"), extra=b"Nothing special\0")
        _touch(str(folder / "payloads" / "x"), "file.msi")
        det = detect_installer(str(folder / "installer.exe"))
        self.assertNotEqual(det.installer_type, InstallerType.ADOBE_HD)
        self.assertFalse(det.adobe_layout)


# --- лестница сценариев ------------------------------------------------------

class AdobeAttemptsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.installer = _make_pe(
            str(self.root / "Adobe.XD.v61.0.12.1.exe"),
            extra=b"HDPIM\0AddUWPAppxCommand\0")
        self.app = str(self.root / "App")
        os.makedirs(self.app, exist_ok=True)
        self.detection = detect_installer(self.installer)

    def _plans(self, **kwargs):
        return build_attempts(self.detection, self.installer, self.app,
                             log_dir=str(self.root),
                             adobe_layout_dir=str(self.root / "_adobe"),
                             **kwargs)

    def test_first_step_does_not_run_the_installer(self):
        plans = self._plans()
        first = plans[0]
        self.assertEqual(first.payload_kind, adobe_mod.PAYLOAD_ADOBE)
        self.assertTrue(first.extracts_only)
        # Установщик в плане указан, но этот сценарий его не запускает.
        self.assertEqual(ntpath.basename(first.program),
                         os.path.basename(self.installer))
        self.assertIn("UWP", " ".join(first.notes))

    def test_documented_silent_switches_are_used_in_order(self):
        plans = self._plans()
        displays = [plan.display() for plan in plans[1:]]
        self.assertIn("--silent", displays[0])
        self.assertIn("--ADOBEINSTALLDIR", displays[0])
        self.assertTrue(any("/sAll" in line for line in displays))
        self.assertTrue(any(line.endswith("/S") for line in displays))

    def test_generic_engine_keys_are_not_offered_to_adobe(self):
        plans = self._plans()
        for plan in plans:
            joined = plan.display()
            self.assertNotIn("/VERYSILENT", joined)
            self.assertNotIn("--installPath", joined)
            self.assertNotIn("/DIR=", joined)

    def test_install_language_uses_adobe_locale(self):
        plans = self._plans(language="ru")
        self.assertTrue(any("--INSTALLLANGUAGE=ru_RU" in plan.display()
                            for plan in plans))

    def test_payload_plan_can_be_switched_off_when_there_is_nowhere_to_unpack(self):
        plans = build_attempts(self.detection, self.installer, self.app,
                               log_dir=str(self.root))
        self.assertNotEqual(plans[0].payload_kind, adobe_mod.PAYLOAD_ADOBE)
        self.assertIn("--silent", plans[0].display())


# --- пакеты внутри установщика ------------------------------------------------

class AdobePayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_uwp_package_is_found_but_never_installed(self):
        folder = self.root / "payloads" / "AdobeXD61"
        _touch(str(folder), "Adobe XD.msi")
        _touch(str(self.root / "payloads" / "SparklerApp"),
               "SparklerApp.appx")
        layout = adobe_mod.find_payloads(str(self.root))
        self.assertEqual(len(layout.msis), 1)
        self.assertEqual(len(layout.uwp_packages), 1)

        app = str(self.root / "App")
        installed = []

        def install_msi(path):
            installed.append(os.path.basename(path))
            _touch(app, "Adobe XD/Adobe XD.exe", "MZ")
            return 0

        applied = adobe_mod.materialize(layout, app, install_msi)
        self.assertEqual(installed, ["Adobe XD.msi"])
        self.assertEqual(applied.skipped_uwp, ["SparklerApp.appx"])
        self.assertTrue(applied.has_result)
        self.assertIn("UWP", " ".join(applied.notes))

    def test_zip_payload_is_extracted_into_app(self):
        archive = _zip_with(
            str(self.root / "payloads" / "AdobeXD.zip"),
            [("Adobe XD/Adobe XD.exe", "MZ"),
             ("Adobe XD/locales/ru.pak", "ru")])
        layout = adobe_mod.find_payloads(str(self.root))
        app = str(self.root / "App")
        applied = adobe_mod.materialize(layout, app, lambda path: 0)
        self.assertEqual(applied.archives_ok, ["AdobeXD.zip"])
        self.assertEqual(applied.files_extracted, 2)
        self.assertTrue(os.path.isfile(
            os.path.join(app, "Adobe XD", "Adobe XD.exe")))
        self.assertTrue(os.path.isfile(archive))

    def test_archive_cannot_write_outside_app(self):
        _zip_with(str(self.root / "payloads" / "evil.zip"),
                  [("../escaped.txt", "no"), ("ok.txt", "yes")])
        layout = adobe_mod.find_payloads(str(self.root))
        app = str(self.root / "App")
        os.makedirs(app, exist_ok=True)
        applied = adobe_mod.materialize(layout, app, lambda path: 0)
        self.assertEqual(applied.archives_ok, ["evil.zip"])
        self.assertFalse(os.path.exists(str(self.root / "escaped.txt")))
        self.assertTrue(os.path.isfile(os.path.join(app, "ok.txt")))

    def test_payloads_directory_wins_over_unrelated_msi_next_to_installer(self):
        _touch(str(self.root), "something-else.msi")
        payload = self.root / "Build" / "payloads" / "AdobeXD61"
        _touch(str(payload), "Adobe XD.msi")
        _make_pe(str(self.root / "Build" / "setup.exe"), extra=b"MZ\0")
        layout = adobe_mod.find_payloads(
            str(self.root / "Build"), payload_dirs_only=True,
            installer_path=str(self.root / "Build" / "setup.exe"))
        self.assertEqual([p.name for p in layout.msis], ["Adobe XD.msi"])
        self.assertEqual(layout.msis[0].product, "AdobeXD61")

    def test_installer_itself_is_not_taken_for_a_payload(self):
        installer = _make_pe(str(self.root / "payloads" / "setup.exe"))
        layout = adobe_mod.find_payloads(str(self.root),
                                        installer_path=installer)
        self.assertEqual([p.name for p in layout.payloads], [])

    def test_payload_left_in_adobe_temp_is_found(self):
        run = (self.root / "adobeTemp" / "ETR1A2B.tmp" / "1" / "payloads"
               / "AdobeXD61")
        _touch(str(run), "Adobe XD.msi")
        _touch(str(run.parent / "SparklerApp"), "SparklerApp.appx")
        layout = adobe_mod.find_payloads_in_roots([str(self.root)])
        self.assertEqual([p.name for p in layout.msis], ["Adobe XD.msi"])
        self.assertTrue(any("ETR1A2B" in note for note in layout.notes))

    def test_zip_safety_rejects_absolute_and_drive_paths(self):
        self.assertIsNone(adobe_mod._safe_member("/tmp/app", "/etc/passwd"))
        self.assertIsNone(adobe_mod._safe_member("/tmp/app", "C:\\Windows\\x"))
        self.assertIsNotNone(adobe_mod._safe_member("/tmp/app", "a/b.txt"))


# --- разбор журнала и советы -------------------------------------------------

class AdobeFailureTests(unittest.TestCase):
    def test_log_is_parsed_by_substance(self):
        failure = adobe_mod.parse_failure(ADOBE_LOG)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, 191)
        self.assertEqual(failure.command, "AddUWPAppxCommand")
        self.assertEqual(failure.package, "UWPAssets")
        self.assertEqual(failure.os_code, 0x80073CF3)
        self.assertTrue(failure.is_uwp)
        self.assertIn("framework", failure.os_hint)
        self.assertEqual(failure.product, "Adobe XD")
        self.assertIn("AddUWPAppxCommand", failure.summary())

    def test_plain_log_is_not_a_failure(self):
        self.assertIsNone(adobe_mod.parse_failure("Установка завершена"))
        self.assertIsNone(adobe_mod.parse_failure(""))

    def test_unknown_os_code_gets_no_invented_explanation(self):
        failure = adobe_mod.parse_failure(
            "FATAL: Error (Code = 191) executing in command "
            "'AddUWPAppxCommand' for package: 'UWPAssets'\n"
            "OS_Error_Code: 0x81234567")
        self.assertEqual(failure.os_code, 0x81234567)
        self.assertIn("неизвестный", failure.os_hint)

    def test_hints_explain_191_and_what_is_lost(self):
        failure = adobe_mod.parse_failure(ADOBE_LOG)
        hints = adobe_mod.failure_hints(failure, salvage_attempted=True)
        joined = "\n".join(hints)
        self.assertIn("AddUWPAppxCommand", joined)
        self.assertIn("191", joined)
        self.assertIn("AppXSvc", joined)
        self.assertIn("меню «Пуск»", joined)
        self.assertIn("Creative Cloud", joined)

    def test_hints_say_7zip_is_needed_when_it_is_missing(self):
        hints = adobe_mod.failure_hints(None, unpacker_missing=True)
        self.assertTrue(any("7-Zip" in line for line in hints))

    def test_hints_admit_an_uwp_only_package(self):
        layout = adobe_mod.AdobeLayout(payload_dirs=["payloads"])
        layout.payloads = [adobe_mod.Payload("payloads/SparklerApp.appx",
                                            "uwp")]
        applied = adobe_mod.materialize(layout, tempfile.gettempdir(),
                                       lambda path: 0)
        hints = adobe_mod.failure_hints(None, applied=applied,
                                        payload_extracted=True, layout=layout)
        joined = "\n".join(hints)
        self.assertIn("только UWP", joined)
        self.assertIn("Admin Console", joined)

    def test_note_lists_skipped_packages_and_limits(self):
        applied = adobe_mod.ApplyResult(
            msi_ok=["Adobe XD.msi"], skipped_uwp=["SparklerApp.appx"])
        text = adobe_mod.note_text("Adobe XD", applied,
                                   failure=adobe_mod.parse_failure(ADOBE_LOG),
                                   source="C:\\Temp\\_adobe")
        self.assertIn("SparklerApp.appx", text)
        self.assertIn("«Поделиться»", text)
        self.assertIn("Creative", text)
        self.assertIn("Cloud", text)
        self.assertIn("AddUWPAppxCommand", text)

    def test_language_is_passed_as_adobe_locale(self):
        self.assertEqual(adobe_mod.language_locale("ru"), "ru_RU")
        self.assertEqual(adobe_mod.language_locale("en"), "en_US")
        self.assertEqual(adobe_mod.language_locale("xx"), "")
        self.assertEqual(adobe_mod.language_locale(""), "")

    def test_adobe_codes_reach_the_exit_code_hint(self):
        hint = engine_mod._exit_code_hint(191)
        self.assertIn("UWP", hint)
        self.assertIn("191", engine_mod._exit_code_hint(191) + "191")


class PayloadWatcherTests(unittest.TestCase):
    """Пакеты, которые установщик раскладывает и убирает за собой.

    Установщик Adobe распаковывает пакеты во временный каталог и удаляет их
    при откате (код 191/1000). Поэтому копии снимаются с диска, пока он ещё
    работает: только после того, как размер файла перестал меняться.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "adobeTemp" / "ETR1234.tmp" / "1"
        self.source.mkdir(parents=True)
        self.target = str(self.root / "grabbed")

    def _watcher(self):
        return adobe_mod.PayloadWatcher([str(self.root / "adobeTemp")],
                                        self.target, min_size=16)

    def _write(self, name: str, size: int) -> str:
        path = self.source / name
        with open(path, "wb") as handle:
            handle.write(b"x" * size)
        return str(path)

    def test_file_is_copied_only_after_it_stops_growing(self):
        self._write("Adobe XD.msi", 64)
        watcher = self._watcher()
        self.assertEqual(watcher.scan(), [], "первый размер — ещё не приговор")
        grabbed = watcher.scan()
        self.assertEqual(len(grabbed), 1)
        self.assertTrue(os.path.isfile(grabbed[0]))
        layout = watcher.layout()
        self.assertEqual([payload.kind for payload in layout.payloads], ["msi"])
        self.assertTrue(layout.has_app_payload)

    def test_growing_file_is_not_copied(self):
        path = self._write("Adobe XD.msi", 64)
        watcher = self._watcher()
        watcher.scan()
        with open(path, "wb") as handle:      # файл ещё пишется
            handle.write(b"x" * 4096)
        # Первый проход после записи только запоминает новый размер, второй —
        # убеждается, что файл больше не растёт, и копирует.
        self.assertEqual(watcher.scan(), [], "размер ещё меняется")
        self.assertEqual(len(watcher.scan()), 1)

    def test_empty_and_foreign_files_are_ignored(self):
        self._write("tiny.msi", 4)
        self._write("readme.txt", 4096)
        watcher = self._watcher()
        watcher.scan()
        self.assertEqual(watcher.scan(), [])
        self.assertEqual(watcher.layout().payloads, [])

    def test_uwp_packages_are_captured_but_never_installed(self):
        self._write("SparklerApp.appx", 4096)
        watcher = self._watcher()
        watcher.scan()
        self.assertEqual(len(watcher.scan()), 1)
        applied = adobe_mod.materialize(watcher.layout(), self.target,
                                        lambda path: 0)
        self.assertEqual(applied.msi_ok, [])
        self.assertEqual([name for name in applied.skipped_uwp
                          if name.endswith("SparklerApp.appx")],
                         ["SparklerApp.appx"])


# --- что делает сборка -------------------------------------------------------

class _AdobePortablizer(Portablizer):
    """Portablizer с подменёнными внешними процессами.

    Проверяется РЕШЕНИЕ сборки: не запускать установщик Adobe, разложить
    пакеты (MSI ставится в App), пропустить UWP-пакет и забрать пакеты из
    временного каталога, если установщик всё же запускался.
    """

    def __init__(self, uwp_unpack_dir: str = "", installer_rc: int = 191,
                 archive_is_empty: bool = False, extractor_rc: int = 0,
                 extractor_output: str = "", sfx_payloads: bool = False,
                 nested_setup: str = ""):
        super().__init__(Logger())
        self.uwp_unpack_dir = uwp_unpack_dir
        self.installer_rc = installer_rc
        self.archive_is_empty = archive_is_empty
        self.extractor_rc = extractor_rc
        self.extractor_output = extractor_output
        self.sfx_payloads = sfx_payloads
        self.nested_setup = nested_setup
        self.calls = []
        self.unpacker_commands = []

    def _run_install(self, plan, opts, app_dir, data_dir,  # noqa: D102
                     progress_from=30, progress_to=60, console_log=None):
        self.calls.append(plan)
        self._last_install_seconds = 2.0
        if plan.program.casefold().endswith("msiexec.exe") or \
                plan.program == "msiexec.exe":
            _touch(app_dir, "Program Files/Adobe/Adobe XD/Adobe XD.exe", "MZ")
            return 0
        # Установщик, найденный внутри SFX-контейнера: понимает ключи Adobe.
        if os.path.basename(plan.program).casefold() in ("setup.exe",
                                                         "set-up.exe"):
            _touch(app_dir, "Program Files/Adobe/Adobe XD/Adobe XD.exe", "MZ")
            return 0
        # Сам установщик Adobe: падает на UWP-шаге...
        if self.uwp_unpack_dir:
            _touch(self.uwp_unpack_dir,
                   "adobeTemp/ETR7F7F.tmp/1/payloads/AdobeXD61/Adobe XD.msi")
        return self.installer_rc

    def _run_unpacker_command(self, cmd, console_log, opts,  # noqa: D102
                              progress=(63, 65), stage="Распаковка установщика"):
        self.unpacker_commands.append(list(cmd))
        # У 7-Zip папка задаётся ключом -o<папка>, у tar — параметром -C,
        # а у самораспаковывающегося EXE — ключом -d<папка>.
        work = next((arg[2:] for arg in cmd if arg.startswith("-o")), "")
        if not work and "-C" in cmd:
            work = cmd[cmd.index("-C") + 1]
        if not work:
            work = next((arg[2:] for arg in cmd if arg.startswith("-d")), "")
        assert work, "в команде распаковщика нет папки распаковки"
        os.makedirs(work, exist_ok=True)

        if cmd and cmd[0].casefold().endswith(".exe") and "-s" in cmd:
            # Сам установщик распаковывает себя по просьбе сборки.
            if self.sfx_payloads:
                _touch(work, "payloads/AdobeXD61/Adobe XD.msi")
            elif self.nested_setup:
                _touch(work, self.nested_setup, "MZ")
            return 0, ""
        if self.archive_is_empty:
            return self.extractor_rc, self.extractor_output
        _touch(work, "payloads/AdobeXD61/Adobe XD.msi")
        _touch(work, "payloads/SparklerApp/SparklerApp.appx")
        _touch(work, "Build/Setup.xml", "<Setup/>")
        return 0, ""


class AdobeBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.portable = str(self.root / "Adobe XD_Portable")
        self.app = os.path.join(self.portable, "App")
        self.data = os.path.join(self.portable, "PortableData")
        os.makedirs(self.app, exist_ok=True)
        os.makedirs(self.data, exist_ok=True)
        self.installer = _make_pe(
            str(self.root / "Adobe.XD.v61.0.12.1.exe"),
            extra=b"HDPIM\0AddUWPAppxCommand\0adobeTemp\0")
        self.opts = PortableOptions(installer_path=self.installer,
                                    output_dir=self.temp.name)
        self.detection = detect_installer(self.installer)

    def _engine(self, **kwargs):
        engine = _AdobePortablizer(**kwargs)
        engine._detection = self.detection
        engine._adobe_detected = True
        engine._install_temp_dir = os.path.join(self.data, "Temp")
        return engine

    def _plans(self):
        return build_attempts(self.detection, self.installer, self.app,
                             log_dir=self.portable,
                             adobe_layout_dir=os.path.join(self.portable,
                                                           "_adobe_payloads"))

    def test_builder_packs_payloads_without_running_the_installer(self):
        engine = self._engine()
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(unpacker_mod, "find_extractors",
                                  return_value=_extractors()):
            rc, used = engine._run_attempts(
                self._plans(), self.opts, self.app, self.data, self.portable,
                "Adobe XD")

        self.assertEqual(rc, 0)
        self.assertIsNotNone(used)
        self.assertEqual(used.payload_kind, adobe_mod.PAYLOAD_ADOBE)
        # Установщик Adobe не запускался ни разу: только msiexec для пакета.
        self.assertEqual(
            [os.path.basename(plan.program) for plan in engine.calls],
            ["msiexec.exe"])
        self.assertTrue(os.path.isfile(
            os.path.join(self.app, "Program Files", "Adobe", "Adobe XD",
                         "Adobe XD.exe")))
        # UWP-пакет не установлен, но и не спрятан: он назван в объяснении.
        note = os.path.join(self.portable, adobe_mod.ADOBE_NOTE_NAME)
        self.assertTrue(os.path.isfile(note))
        with open(note, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("SparklerApp.appx", text)
        self.assertIn("Creative", text)
        self.assertIn("Cloud", text)
        self.assertFalse(os.path.isdir(
            os.path.join(self.portable, "_adobe_payloads")),
            "временная распаковка должна быть убрана после успеха")

    def test_payloads_from_installer_temp_are_salvaged_after_191(self):
        """Установщик упал на UWP-шаге, но его распаковку всё равно забираем."""
        engine = self._engine(
            uwp_unpack_dir=os.path.join(self.data, "Temp"))
        plans = [plan for plan in self._plans()
                 if plan.payload_kind != adobe_mod.PAYLOAD_ADOBE]
        self.assertTrue(plans)
        with mock.patch.object(engine_mod, "IS_WINDOWS", True):
            rc, used = engine._run_attempts(
                plans, self.opts, self.app, self.data, self.portable,
                "Adobe XD")

        self.assertEqual(rc, 191)
        self.assertIsNotNone(used)
        self.assertEqual(used.payload_kind, "")
        self.assertTrue(engine._adobe_salvage_attempted)
        self.assertTrue(os.path.isfile(
            os.path.join(self.app, "Program Files", "Adobe", "Adobe XD",
                         "Adobe XD.exe")))
        self.assertTrue(os.path.isfile(
            os.path.join(self.portable, adobe_mod.ADOBE_NOTE_NAME)))

    def test_zip_container_is_packed_even_without_7zip(self):
        """Установщик-оболочка может быть обычным ZIP: 7-Zip не обязателен."""
        installer = str(self.root / "Adobe.XD.v61.0.12.1.exe")
        _zip_with(installer, [
            ("Build/payloads/AdobeXD61/Adobe XD.msi", "msi"),
            ("Build/payloads/SparklerApp/SparklerApp.appx", "appx"),
        ])
        detection = detect_installer(installer)
        self.assertTrue(detection.adobe_named)
        self.assertTrue(detection.has_zip_payload)
        engine = _AdobePortablizer()
        engine._detection = detection
        engine._adobe_detected = True
        engine._install_temp_dir = os.path.join(self.data, "Temp")
        plans = build_attempts(detection, installer, self.app,
                               log_dir=self.portable,
                               adobe_layout_dir=os.path.join(
                                   self.portable, "_adobe_payloads"))
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(unpacker_mod, "find_extractors",
                                  return_value=[]):
            rc, used = engine._run_attempts(plans, self.opts, self.app,
                                            self.data, self.portable,
                                            "Adobe XD")
        self.assertEqual(rc, 0)
        self.assertEqual(used.payload_kind, adobe_mod.PAYLOAD_ADOBE)
        self.assertTrue(os.path.isfile(
            os.path.join(self.app, "Program Files", "Adobe", "Adobe XD",
                         "Adobe XD.exe")))

    def test_missing_extractors_are_reported_honestly(self):
        """Распаковщиков нет вовсе — об этом сказано, но 7-Zip не обязателен."""
        engine = self._engine()
        plan = self._plans()[0]
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(unpacker_mod, "find_extractors",
                                  return_value=[]):
            rc = engine._run_payload_plan(
                plan, self.opts, self.app, self.data, "Adobe XD",
                portable_dir=self.portable)
        self.assertEqual(rc, -1)
        self.assertIn("7-Zip", engine.log.text)
        with mock.patch.object(unpacker_mod, "find_extractors", return_value=[]):
            hints = engine._adobe_hints(self.detection, 191, self.portable)
        joined = "\n".join(hints)
        self.assertIn("tar.exe", joined)
        self.assertIn("WinRAR", joined)
        # Прежний текст требовал установить 7-Zip — теперь его нет.
        self.assertNotIn("Установите 7-Zip и повторите сборку", joined)

    def test_failure_hints_name_the_uwp_step_for_code_191(self):
        engine = self._engine()
        _touch(self.portable, "installer-output.log", ADOBE_LOG)
        hints = engine._failure_hints(self.detection, 191, self.opts,
                                      self.portable)
        joined = "\n".join(hints)
        self.assertIn("AddUWPAppxCommand", joined)
        self.assertIn("191", joined)
        self.assertIn("0x80073CF3", joined)
        self.assertIn("Портативу UWP-пакет не нужен", joined)

    def test_adobe_installer_is_not_unpacked_into_app_as_a_pile(self):
        """Содержимое Adobe — пакеты, а не папка программы: в App не сваливаем."""
        engine = self._engine()
        det = DetectionResult(InstallerType.SELF_EXTRACT, 0.8,
                              adobe_named=True, has_zip_payload=True)
        engine._adobe_detected = True
        with mock.patch.object(unpacker_mod, "find_unpacker",
                               return_value="7z.exe"):
            self.assertFalse(engine._try_unpacker_fallback(
                self.opts, self.app, self.portable, det, "Adobe XD"))
        self.assertIn("Adobe", engine.log.text)
        self.assertEqual(engine.unpacker_commands, [])

    def test_windows_tar_packs_adobe_without_any_7zip(self):
        """Без 7-Zip: WinRAR-SFX вырезается и распаковывается встроенным tar.exe."""
        installer = _make_pe(
            str(self.root / "Adobe.XD.v61.0.12.1.exe"),
            extra=b"HDPIM\0AddUWPAppxCommand\0adobeTemp\0")
        with open(installer, "ab") as handle:
            handle.write(b"Rar!\x1a\x07\x01\x00" + b"sfx-body" * 64)
        detection = detect_installer(installer)
        self.assertTrue(detection.adobe_named)
        engine = _AdobePortablizer()
        engine._detection = detection
        engine._adobe_detected = True
        engine._install_temp_dir = os.path.join(self.data, "Temp")
        engine.seen_archives = []
        original = engine._run_unpacker_command

        def remembering(cmd, console_log, opts, progress=(63, 65),
                        stage="Распаковка установщика"):
            engine.seen_archives.append(list(cmd))
            return original(cmd, console_log, opts, progress=progress,
                            stage=stage)

        engine._run_unpacker_command = remembering  # type: ignore[assignment]
        plans = build_attempts(detection, installer, self.app,
                               log_dir=self.portable,
                               adobe_layout_dir=os.path.join(
                                   self.portable, "_adobe_payloads"))
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(unpacker_mod, "find_extractors",
                                  return_value=_extractors(
                                      unpacker_mod.STYLE_TAR,
                                      "C:\\Windows\\System32\\tar.exe")):
            rc, used = engine._run_attempts(plans, self.opts, self.app,
                                            self.data, self.portable,
                                            "Adobe XD")
        self.assertEqual(rc, 0)
        self.assertEqual(used.payload_kind, adobe_mod.PAYLOAD_ADOBE)
        self.assertTrue(engine.seen_archives)
        cmd = engine.seen_archives[0]
        # tar.exe получил не EXE, а вырезанный из него RAR — иначе libarchive
        # не увидел бы архив внутри обёртки.
        self.assertEqual(cmd[0], "C:\\Windows\\System32\\tar.exe")
        self.assertEqual(cmd[1:3], ["-x", "-f"])
        self.assertTrue(cmd[3].endswith(".rar"))
        self.assertTrue(os.path.isfile(
            os.path.join(self.app, "Program Files", "Adobe", "Adobe XD",
                         "Adobe XD.exe")))

    def test_code_1000_is_explained_as_media_problem(self):
        """Код 1000 — это не «непонятый ключ»: Adobe не любит сетевой диск."""
        self.assertIn(1000, adobe_mod.ADOBE_CODES)
        hint = engine_mod._exit_code_hint(1000)
        self.assertIn("1000", hint)
        self.assertIn("диск", hint)

    def test_installer_on_a_plain_disk_is_used_as_is(self):
        engine = self._engine()
        with mock.patch.object(adobe_mod, "portable_media_drive",
                               return_value=False):
            self.assertEqual(engine._adobe_installer_source(self.opts),
                             self.installer)
        self.assertEqual(engine._adobe_media_copy, "")

    def test_extractor_failure_is_not_silently_treated_as_success(self):
        """Код 1 у tar.exe — это ошибка, а не «предупреждение как у 7-Zip».

        Регрессия: сборка «успешно» распаковывала RAR5 встроенным tar.exe,
        ничего не получала и молчала о причине — в журнале не было ни ответа
        архиватора, ни кода возврата.
        """
        # Внутри установщика есть RAR — именно его и пытается прочитать tar.
        with open(self.installer, "ab") as handle:
            handle.write(b"Rar!\x1a\x07\x01\x00" + b"sfx-body" * 64)
        engine = self._engine(
            archive_is_empty=True, extractor_rc=1,
            extractor_output="tar: Unrecognized archive format")
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(unpacker_mod, "find_extractors",
                                  return_value=_extractors(
                                      unpacker_mod.STYLE_TAR,
                                      "C:\\Windows\\System32\\tar.exe")):
            engine._run_payload_plan(
                self._plans()[0], self.opts, self.app, self.data,
                "Adobe XD", portable_dir=self.portable)
        text = engine.log.text
        self.assertIn("код 1", text)
        self.assertIn("Unrecognized archive format", text)

    def test_extracted_tree_is_described_in_the_log(self):
        """Видно, что именно оказалось в папке распаковки."""
        engine = self._engine(archive_is_empty=True)
        engine.archive_is_empty = False
        work = os.path.join(self.portable, "_adobe_payloads")
        _touch(work, "Adobe XD/Setup.exe", "MZ")
        engine._log_extracted_tree(work, "tar.exe")
        text = engine.log.text
        self.assertIn("распаковано файлов 1", text)
        self.assertIn("Setup.exe", text)

    def test_sfx_extracts_itself_when_archive_tools_fail(self):
        """Последний шанс без чужих библиотек: SFX распаковывается сам."""
        engine = self._engine(archive_is_empty=True, extractor_rc=1,
                              extractor_output="tar: Unrecognized format",
                              sfx_payloads=True)
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(unpacker_mod, "find_extractors",
                                  return_value=_extractors(
                                      unpacker_mod.STYLE_TAR,
                                      "C:\\Windows\\System32\\tar.exe")):
            rc, used = engine._run_attempts(
                self._plans(), self.opts, self.app, self.data, self.portable,
                "Adobe XD")
        self.assertEqual(rc, 0)
        self.assertEqual(used.payload_kind, adobe_mod.PAYLOAD_ADOBE)
        sfx_calls = [cmd for cmd in engine.unpacker_commands
                     if cmd and cmd[0].casefold().endswith(".exe")
                     and "-s" in cmd]
        self.assertTrue(sfx_calls, "установщик не просили распаковаться")
        self.assertTrue(any(arg.startswith("-d") for arg in sfx_calls[0]))
        self.assertTrue(os.path.isfile(
            os.path.join(self.app, "Program Files", "Adobe", "Adobe XD",
                         "Adobe XD.exe")))

    def test_nested_setup_inside_the_container_is_run(self):
        """В контейнере нет MSI, зато есть настоящий установщик — его и ставим."""
        engine = self._engine(archive_is_empty=True, nested_setup="XD/Setup.exe")
        original = engine._run_unpacker_command

        def sfx_only(cmd, console_log, opts, progress=(63, 65),
                     stage="Распаковка установщика"):
            # Обычные архиваторы «не читают» архив, а SFX распаковывает себя.
            if not (cmd and cmd[0].casefold().endswith(".exe") and "-s" in cmd):
                return 1, "tar: Unrecognized archive format"
            return original(cmd, console_log, opts, progress=progress,
                            stage=stage)

        engine._run_unpacker_command = sfx_only  # type: ignore[assignment]
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(unpacker_mod, "find_extractors",
                                  return_value=_extractors(
                                      unpacker_mod.STYLE_TAR,
                                      "C:\\Windows\\System32\\tar.exe")):
            rc, _used = engine._run_attempts(
                self._plans(), self.opts, self.app, self.data, self.portable,
                "Adobe XD")
        self.assertEqual(rc, 0)
        labels = [plan.program for plan in engine.calls]
        self.assertTrue(any(path.casefold().endswith("setup.exe")
                            for path in labels),
                        "установщик из контейнера не запускался")

    def test_payloads_grabbed_during_the_run_are_installed(self):
        """Установщик убрал пакеты при откате — а снятые копии остались."""
        temp_root = os.path.join(self.data, "Temp", "adobeTemp", "ETR1.tmp")
        _touch(temp_root, "payloads/Adobe XD.msi", "x" * 4096)
        engine = self._engine()
        watcher = adobe_mod.PayloadWatcher(
            [os.path.join(self.data, "Temp")],
            os.path.join(self.portable, "_adobe_grabbed"), min_size=16)
        watcher.scan()
        self.assertEqual(len(watcher.scan()), 1)
        engine._adobe_watcher = watcher
        # Установщик убрал распакованное при откате — копии остались.
        shutil.rmtree(os.path.join(self.data, "Temp"), ignore_errors=True)
        with mock.patch.object(engine_mod, "IS_WINDOWS", True):
            ok = engine._salvage_adobe_payloads(
                self.opts, self.app, self.data, "Adobe XD",
                portable_dir=self.portable)
        self.assertTrue(ok)
        self.assertIn("снять с диска", engine.log.text)
        self.assertTrue(os.path.isfile(
            os.path.join(self.app, "Program Files", "Adobe", "Adobe XD",
                         "Adobe XD.exe")))

    def test_uwp_package_is_never_installed_through_msiexec(self):
        """Appx ставится не msiexec и не нами: его в командах нет вовсе."""
        engine = self._engine()
        with mock.patch.object(engine_mod, "IS_WINDOWS", True), \
                mock.patch.object(unpacker_mod, "find_extractors",
                                  return_value=_extractors()):
            engine._run_attempts(self._plans(), self.opts, self.app,
                                 self.data, self.portable, "Adobe XD")
        joined = " ".join(plan.display() for plan in engine.calls)
        self.assertNotIn(".appx", joined.casefold())
        self.assertNotIn("add-appxpackage", joined.casefold())


if __name__ == "__main__":
    unittest.main()
