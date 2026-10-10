"""Выбор языка многоязычного установщика для портатива.

Главный сценарий: установка AC Brotherhood поставила английский текст, и
русские субтитры в игре не выводят букв. Значит, язык должен попадать в
команду установки ДО сборки — тем же ключом, которым человек выбрал бы его в
окне установщика. Здесь проверяется сама команда: синтаксис для каждого
движка, отказ от ключа там, где движок его не знает, и отсутствие дублей, если
пользователь уже задал язык в «Доп. аргументах».
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:  # pragma: no cover - зависит от окружения
    from PySide6.QtWidgets import QApplication

    _QT_ERROR = ""
except Exception as exc:  # noqa: BLE001 - нет PySide6 или системных библиотек
    QApplication = None
    _QT_ERROR = f"{type(exc).__name__}: {exc}"


def _qt_app():
    if QApplication is None:
        return None
    app = QApplication.instance()
    if app is not None:
        return app
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        return QApplication([])
    except Exception:  # noqa: BLE001 - нет дисплея: GUI-тесты пропускаем
        return None


_QT_READY = _qt_app() is not None

from portablizer.core.detect import (  # noqa: E402
    DetectionResult, InstallerType, InstallShieldGeneration,
)
from portablizer.core.languages import (  # noqa: E402
    LANGUAGES, find_language, has_language_switch, plan_language, switch_for,
)
from portablizer.core.portablizer import PortableOptions  # noqa: E402
from portablizer.core.silentargs import build_attempts  # noqa: E402


class LanguageCatalogTests(unittest.TestCase):
    def test_codes_and_switch_names_are_unique(self):
        self.assertEqual(len({lang.code.lower() for lang in LANGUAGES}),
                         len(LANGUAGES))
        self.assertEqual(len({lang.inno_name.lower() for lang in LANGUAGES}),
                         len(LANGUAGES))
        self.assertEqual(len({lang.lcid for lang in LANGUAGES}),
                         len(LANGUAGES))

    def test_russian_is_offered_first(self):
        self.assertEqual(LANGUAGES[0].code, "ru")
        self.assertEqual(LANGUAGES[0].title, "Русский")

    def test_lookup_is_case_insensitive(self):
        self.assertEqual(find_language("RU").lcid, 0x0419)
        self.assertEqual(find_language("pt-br").code, "pt-BR")
        self.assertIsNone(find_language("xx"))
        self.assertIsNone(find_language(""))

    def test_portable_options_default_keeps_installer_language(self):
        opts = PortableOptions(installer_path="a.exe", output_dir="out")
        self.assertEqual(opts.install_language, "")


class SwitchSyntaxTests(unittest.TestCase):
    def test_inno_takes_the_language_name(self):
        self.assertEqual(
            plan_language(InstallerType.INNO, "ru").args, ["/LANG=russian"])
        self.assertEqual(
            plan_language(InstallerType.INNO, "pt-BR").args,
            ["/LANG=brazilianportuguese"])

    def test_nsis_takes_the_decimal_lcid(self):
        self.assertEqual(
            plan_language(InstallerType.NSIS, "ru").args, ["/LANG=1049"])
        self.assertEqual(
            plan_language(InstallerType.NSIS, "en").args, ["/LANG=1033"])

    def test_installshield_takes_the_hex_lcid(self):
        self.assertEqual(
            plan_language(InstallerType.INSTALLSHIELD, "ru").args,
            ["/L0x0419"])
        self.assertEqual(
            plan_language(InstallerType.INSTALLSHIELD, "en").args,
            ["/L0x0409"])

    def test_switch_for_matches_plan(self):
        ru = find_language("ru")
        self.assertEqual(switch_for(InstallerType.INNO, ru), "/LANG=russian")
        self.assertIsNone(switch_for(InstallerType.WIX_BURN, ru))

    def test_empty_code_adds_nothing_and_logs_nothing(self):
        plan = plan_language(InstallerType.INNO, "")
        self.assertEqual(plan.args, [])
        self.assertEqual(plan.message, "")

    def test_unknown_code_is_reported_not_passed(self):
        plan = plan_language(InstallerType.INNO, "klingon")
        self.assertEqual(plan.args, [])
        self.assertEqual(plan.level, "warn")


class UnsupportedEngineTests(unittest.TestCase):
    def test_engines_without_a_language_switch_get_a_warning(self):
        for itype in (InstallerType.MSI, InstallerType.WIX_BURN,
                      InstallerType.CUSTOM_CLI, InstallerType.UNKNOWN,
                      InstallerType.ADVANCED_INSTALLER):
            with self.subTest(itype=itype):
                plan = plan_language(itype, "ru")
                self.assertEqual(plan.args, [])
                self.assertEqual(plan.level, "warn")
                self.assertIn("язык", plan.message)


class UserSwitchWinsTests(unittest.TestCase):
    def test_a_language_typed_by_hand_is_not_duplicated(self):
        for user in (["/LANG=english"], ["/L0x0409"], ["/LANG=1033"],
                     ["/langid=1049"]):
            with self.subTest(user=user):
                plan = plan_language(InstallerType.INNO, "ru", user)
                self.assertEqual(plan.args, [])
                self.assertEqual(plan.level, "warn")

    def test_other_user_arguments_do_not_block_the_choice(self):
        plan = plan_language(InstallerType.INNO, "ru",
                             ["/COMPONENTS=main", "/NOICONS"])
        self.assertEqual(plan.args, ["/LANG=russian"])

    def test_has_language_switch_recognises_common_forms(self):
        self.assertTrue(has_language_switch(["/LANG=russian"]))
        self.assertTrue(has_language_switch(["/L0x0419"]))
        self.assertFalse(has_language_switch(["/LANGUAGE_PACK"]))
        self.assertFalse(has_language_switch(["/S", "/D=C:\\Games"]))


class JournalTests(unittest.TestCase):
    """Выбор языка виден в журнале: что ушло в установщик и почему."""

    def _run_log(self, itype, language, user_args=()):
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import Portablizer

        lines = []
        logger = Logger()
        logger.add_sink(lambda level, message: lines.append((level, message)))
        engine = Portablizer(logger)
        opts = PortableOptions(installer_path="setup.exe", output_dir="out",
                               install_language=language,
                               extra_install_args=list(user_args))
        engine._log_language_choice(DetectionResult(itype, 1.0), opts)
        return lines

    def test_chosen_language_is_logged_as_ok(self):
        lines = self._run_log(InstallerType.INNO, "ru")
        self.assertEqual(len(lines), 1)
        self.assertIn("Русский", lines[0][1])
        self.assertIn("/LANG=russian", lines[0][1])
        self.assertNotEqual(lines[0][0], "WARN")

    def test_default_language_is_logged_as_info(self):
        lines = self._run_log(InstallerType.INNO, "")
        self.assertEqual(lines[0][0], "INFO")
        self.assertIn("по умолчанию", lines[0][1])

    def test_unsupported_engine_is_logged_as_warning(self):
        lines = self._run_log(InstallerType.WIX_BURN, "ru")
        self.assertEqual(lines[0][0], "WARN")


class AttemptLadderTests(unittest.TestCase):
    INSTALLER = r"E:\Setup\setup.exe"
    TARGET = r"E:\Portable\Game_Portable\App"

    def _detect(self, itype, confidence=1.0, **kwargs):
        return DetectionResult(itype, confidence, **kwargs)

    def test_inno_language_reaches_the_install_command(self):
        plans = build_attempts(self._detect(InstallerType.INNO),
                               self.INSTALLER, self.TARGET,
                               language="ru")
        self.assertTrue(plans)
        for plan in plans:
            self.assertIn("/LANG=russian", plan.args, plan.label)

    def test_no_language_gives_the_same_command_as_before(self):
        base = build_attempts(self._detect(InstallerType.INNO),
                              self.INSTALLER, self.TARGET)
        empty = build_attempts(self._detect(InstallerType.INNO),
                               self.INSTALLER, self.TARGET, language="")
        self.assertEqual([p.display() for p in base],
                         [p.display() for p in empty])
        self.assertFalse(any("/LANG" in p.display() for p in base))

    def test_language_is_not_repeated_when_user_gave_one(self):
        plans = build_attempts(self._detect(InstallerType.INNO),
                               self.INSTALLER, self.TARGET,
                               extra_args=["/LANG=english"], language="ru")
        for plan in plans:
            self.assertEqual(plan.display().count("/LANG="), 1, plan.label)
            self.assertIn("/LANG=english", plan.args)

    def test_nsis_gets_the_lcid_before_the_raw_directory_tail(self):
        plans = build_attempts(self._detect(InstallerType.NSIS),
                               self.INSTALLER, self.TARGET, language="ru")
        first = plans[0]
        self.assertIn("/LANG=1049", first.args)
        # /D= у NSIS обязан оставаться последним: язык идёт до него.
        self.assertTrue(first.raw_tail.startswith("/D="))

    def test_installshield_msi_wrapper_gets_the_language(self):
        det = self._detect(
            InstallerType.INSTALLSHIELD,
            installshield_generation=InstallShieldGeneration.MSI)
        plans = build_attempts(det, self.INSTALLER, self.TARGET,
                               language="ru")
        self.assertIn("/L0x0419", plans[0].args)
        self.assertIn("/v", plans[0].raw_tail)

    def test_generic_ladder_does_not_get_a_foreign_switch(self):
        # Слабое совпадение «nsis» даёт уверенность ниже порога: команда
        # строится по NSIS, но запасные универсальные наборы ключей не
        # должны получать чужой синтаксис языка.
        det = self._detect(InstallerType.NSIS, confidence=0.5)
        plans = build_attempts(det, self.INSTALLER, self.TARGET,
                               language="ru")
        generic = [p for p in plans if p.label.startswith("Универсальные")]
        self.assertTrue(generic)
        for plan in generic:
            self.assertNotIn("/LANG=1049", plan.args)

    def test_msi_package_ignores_the_language(self):
        det = self._detect(InstallerType.MSI, is_msi=True)
        plans = build_attempts(det, r"E:\Setup\game.msi", self.TARGET,
                               language="ru")
        self.assertEqual(plans[0].program, "msiexec.exe")
        self.assertFalse(any("/LANG" in a or "/L0x" in a
                             for a in plans[0].args))


@unittest.skipUnless(_QT_READY, f"PySide6/Qt недоступен: {_QT_ERROR}")
class LanguageInterfaceTests(unittest.TestCase):
    def setUp(self):
        from portablizer.gui import main_window

        self.main_window = main_window
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        with mock.patch.object(main_window, "QSettings", _MemorySettings):
            self.window = main_window.MainWindow()

    def _installer(self, name: str = "setup.exe") -> str:
        path = Path(self.temp.name, name)
        path.write_bytes(b"MZ")
        return str(path)

    def test_the_list_starts_with_the_installer_default(self):
        combo = self.window.language_combo
        self.assertEqual(combo.itemText(0), "Как в самом установщике")
        self.assertEqual(combo.itemData(0), "")
        codes = [combo.itemData(i) for i in range(combo.count())]
        self.assertEqual(codes[1:], [lang.code for lang in LANGUAGES])

    def test_the_chosen_language_reaches_the_options(self):
        self.window.installer_edit.setText(self._installer())
        self.window.output_edit.setText(self.temp.name)
        index = self.window.language_combo.findData("ru")
        self.window.language_combo.setCurrentIndex(index)
        opts = self.window._collect_options()
        self.assertIsInstance(opts, PortableOptions)
        self.assertEqual(opts.install_language, "ru")

    def test_default_choice_sends_no_language(self):
        self.window.installer_edit.setText(self._installer())
        self.window.output_edit.setText(self.temp.name)
        self.window.language_combo.setCurrentIndex(0)
        opts = self.window._collect_options()
        self.assertEqual(opts.install_language, "")

    def test_the_hint_explains_engines_without_a_switch(self):
        self.window._detected_type = InstallerType.MSI
        self.window.language_combo.setCurrentIndex(
            self.window.language_combo.findData("ru"))
        self.assertIn("не выбирает", self.window.language_hint.text())
        self.window._detected_type = InstallerType.INNO
        self.window._update_language_hint()
        self.assertIn("передаётся ключом", self.window.language_hint.text())
        self.window.language_combo.setCurrentIndex(0)
        self.assertEqual(self.window.language_hint.text(), "")

    def test_the_choice_is_remembered_between_launches(self):
        settings = _MemorySettings()
        settings.data["install_language"] = "uk"
        with mock.patch.object(self.main_window, "QSettings",
                               lambda *a, **k: settings):
            window = self.main_window.MainWindow()
        self.assertEqual(window.language_combo.currentData(), "uk")


class _MemorySettings:
    """Замена ``QSettings``: тесты не трогают реестр пользователя."""

    def __init__(self, *_args, **_kwargs) -> None:
        self.data = {}

    def value(self, key, default=None):  # noqa: ANN001
        return self.data.get(str(key), default)

    def setValue(self, key, value) -> None:  # noqa: N802 - API Qt
        self.data[str(key)] = value


if __name__ == "__main__":
    unittest.main()
