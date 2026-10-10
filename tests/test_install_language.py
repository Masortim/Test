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


class AssassinsCreedBrotherhoodLangSwTests(unittest.TestCase):
    """Сценарий [dixen18] Assassins Creed - Brotherhood:

    Репак в тихом режиме ставит ``"Language"="English"`` в
    ``HKLM\\Software\\WOW6432Node\\Ubisoft\\Assassin's Creed Brotherhood``, а
    файлы переключения языка кладёт в ``App\\_Lang_SW\\x64`` и ``App\\_Lang_SW\\x86``.
    Без русского ``Language`` в реестре игра грузит английский интерфейс и
    латинский атлас шрифтов, из-за чего русские субтитры отображают только
    знаки препинания.
    """

    ACB_WOW_KEY = (
        r"HKLM\Software\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood"
    )
    ACB_X86_KEY = (
        r"HKLM\Software\Ubisoft\Assassin's Creed Brotherhood"
    )

    def _populate_lang_sw(self, app_dir: Path) -> None:
        x64_dir = app_dir / "_Lang_SW" / "x64"
        x86_dir = app_dir / "_Lang_SW" / "x86"
        x64_dir.mkdir(parents=True, exist_ok=True)
        x86_dir.mkdir(parents=True, exist_ok=True)

        (x64_dir / "Rus.reg").write_text(
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Ubisoft\\"
            "Assassin's Creed Brotherhood]\r\n"
            '"Language"="Russian"\r\n',
            encoding="utf-16",
        )
        (x64_dir / "Eng.reg").write_text(
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Ubisoft\\"
            "Assassin's Creed Brotherhood]\r\n"
            '"Language"="English"\r\n',
            encoding="utf-16",
        )
        (x86_dir / "Rus.reg").write_text(
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Ubisoft\\"
            "Assassin's Creed Brotherhood]\r\n"
            '"Language"="Russian"\r\n',
            encoding="utf-16",
        )
        (x86_dir / "Eng.reg").write_text(
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Ubisoft\\"
            "Assassin's Creed Brotherhood]\r\n"
            '"Language"="English"\r\n',
            encoding="utf-16",
        )

    def test_capture_registry_applies_lang_sw_and_rewrites_english_to_russian(self):
        from portablizer.core import registry as reg_mod
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import Portablizer

        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "ACB_Portable")
            app_dir = portable / "App"
            self._populate_lang_sw(app_dir)

            before = {}
            after = {
                self.ACB_WOW_KEY: {
                    "InstallDir": (reg_mod.REG_SZ, repr(str(app_dir))),
                    "Language": (reg_mod.REG_SZ, repr("English")),
                },
            }
            engine = Portablizer(Logger())
            capture = engine._capture_registry(
                str(portable),
                before,
                after,
                PortableOptions(
                    installer_path="setup.exe",
                    output_dir=temp,
                    install_language="ru",
                ),
            )

            self.assertTrue(os.path.isfile(capture.reg_file))
            self.assertTrue(os.path.isfile(capture.machine_reg_file))

            user_reg = (portable / "portable.reg").read_text(encoding="utf-16")
            machine_reg = (portable / "portable_machine.reg").read_text(
                encoding="utf-16"
            )

            self.assertIn('"Language"="Russian"', user_reg)
            self.assertNotIn('"Language"="English"', user_reg)
            self.assertIn('"Language"="Russian"', machine_reg)
            self.assertNotIn('"Language"="English"', machine_reg)
            # И 32-битная (WOW6432Node), и 64-битная ветки присутствуют в machine_reg
            self.assertIn(
                "[HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Ubisoft\\"
                "Assassin's Creed Brotherhood]",
                machine_reg,
            )
            self.assertIn(
                "[HKEY_LOCAL_MACHINE\\Software\\Ubisoft\\"
                "Assassin's Creed Brotherhood]",
                machine_reg,
            )
            # И VirtualStore, и прямой HKCU присутствуют в portable.reg
            self.assertIn(
                "[HKEY_CURRENT_USER\\Software\\Classes\\VirtualStore\\MACHINE\\"
                "SOFTWARE\\WOW6432Node\\Ubisoft\\Assassin's Creed Brotherhood]",
                user_reg,
            )

    def test_capture_registry_works_even_if_key_already_existed_before_build(self):
        """Если пользователь уже запускал .reg или старую сборку до пересборки,
        ключ в before не должен помешать захвату в portable.reg.
        """
        from portablizer.core import registry as reg_mod
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import Portablizer

        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "ACB_Portable")
            app_dir = portable / "App"
            self._populate_lang_sw(app_dir)

            # На ПК до сборки уже висел ключ с тем же самым содержимым
            before = {
                self.ACB_WOW_KEY: {
                    "InstallDir": (reg_mod.REG_SZ, repr(str(app_dir))),
                    "Language": (reg_mod.REG_SZ, repr("Russian")),
                },
            }
            after = {
                self.ACB_WOW_KEY: {
                    "InstallDir": (reg_mod.REG_SZ, repr(str(app_dir))),
                    "Language": (reg_mod.REG_SZ, repr("English")),
                },
            }
            engine = Portablizer(Logger())
            capture = engine._capture_registry(
                str(portable),
                before,
                after,
                PortableOptions(
                    installer_path="setup.exe",
                    output_dir=temp,
                    install_language="ru",
                ),
            )
            self.assertTrue(os.path.isfile(capture.machine_reg_file))
            machine_reg = (portable / "portable_machine.reg").read_text(
                encoding="utf-16"
            )
            self.assertIn('"Language"="Russian"', machine_reg)

    def test_prepare_output_clears_stale_portable_data_registry_session(self):
        """При повторной сборке в ту же папку старый кэш PortableData\\Registry
        с английским языком удаляется, а пользовательские сейвы сохраняются.
        """
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import Portablizer

        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "ACB_Portable")
            app_dir = portable / "App"
            data_dir = portable / "PortableData"
            stale_reg = data_dir / "Registry" / "k00.reg"
            stale_reg.parent.mkdir(parents=True)
            stale_reg.write_text('"Language"="English"', encoding="utf-8")

            save_file = (
                data_dir / "User" / "Saved Games"
                / "Assassin's Creed Brotherhood" / "SAVES" / "OPTIONS"
            )
            save_file.parent.mkdir(parents=True)
            save_file.write_bytes(b"SAVEDATA")

            engine = Portablizer(Logger())
            engine._prepare_output(str(portable), str(app_dir), str(data_dir))

            self.assertFalse(stale_reg.exists())
            self.assertTrue(save_file.is_file())


class MaintenanceLanguageRefreshTests(unittest.TestCase):
    """Обновление лончера («Обновить лончер») чинит язык уже собранного портатива."""

    def test_refresh_applies_lang_sw_and_updates_cached_session_regs(self):
        from portablizer.core import launcher as launcher_mod
        from portablizer.core import maintenance
        from portablizer.core import registry as reg_mod

        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "ACB_Portable")
            app_dir = portable / "App"
            (app_dir / "_Lang_SW" / "x64").mkdir(parents=True)
            (app_dir / "ACBSP.exe").write_bytes(b"MZ")
            (app_dir / "_Lang_SW" / "x64" / "Rus.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Ubisoft\\"
                "Assassin's Creed Brotherhood]\r\n"
                '"Language"="Russian"\r\n',
                encoding="utf-16",
            )

            # Изначально в портативе захвачен английский язык и в portable.reg,
            # и в portable_machine.reg, и в сохранённой сессии PortableData\Registry
            reg_mod.write_reg_file(
                str(portable / "portable.reg"),
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Classes\\VirtualStore\\MACHINE\\"
                "SOFTWARE\\WOW6432Node\\Ubisoft\\Assassin's Creed Brotherhood]\r\n"
                '"Language"="English"\r\n\r\n',
            )
            reg_mod.write_reg_file(
                str(portable / "portable_machine.reg"),
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Ubisoft\\"
                "Assassin's Creed Brotherhood]\r\n"
                '"InstallDir"="@@PORTABLE_ROOT@@\\\\App"\r\n'
                '"Language"="English"\r\n\r\n',
            )
            session_dir = portable / "PortableData" / "Registry"
            session_dir.mkdir(parents=True)
            reg_mod.write_reg_file(
                str(session_dir / "k00.reg"),
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Classes\\VirtualStore\\MACHINE\\"
                "SOFTWARE\\WOW6432Node\\Ubisoft\\Assassin's Creed Brotherhood]\r\n"
                '"Language"="English"\r\n\r\n',
            )

            cfg = launcher_mod.LauncherConfig(
                app_name="Assassins Creed - Brotherhood",
                target_exe_rel="App/ACBSP.exe",
                apply_registry=True,
                registry_keys=[
                    r"HKCU\Software\Classes\VirtualStore\MACHINE\SOFTWARE\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood",
                    r"HKLM\Software\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood",
                ],
                registry_created_keys=[
                    r"HKCU\Software\Classes\VirtualStore\MACHINE\SOFTWARE\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood",
                    r"HKLM\Software\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood",
                ],
                registry_has_root_token=True,
            )
            (portable / "launcher_config.json").write_text(
                launcher_mod.render_config_json(cfg), encoding="utf-8"
            )

            report = maintenance.refresh(
                str(portable), shared_saves=False, language="ru"
            )
            self.assertTrue(report.success)

            for reg_file in (
                portable / "portable.reg",
                portable / "portable_machine.reg",
                session_dir / "k00.reg",
            ):
                content = reg_file.read_text(encoding="utf-16")
                self.assertIn('"Language"="Russian"', content, str(reg_file))
                self.assertNotIn('"Language"="English"', content, str(reg_file))

            # InstallDir в portable_machine.reg сохранён
            machine_content = (portable / "portable_machine.reg").read_text(
                encoding="utf-16"
            )
            self.assertIn('"InstallDir"="@@PORTABLE_ROOT@@\\\\App"', machine_content)


class LauncherExternalRegSwitchTests(unittest.TestCase):
    """Применение .reg-файла из _Lang_SW на хосте перед запуском лончера."""

    def test_launcher_absorbs_external_host_reg_switch_instead_of_overwriting_it(self):
        import portable_launcher_entry as exe_launcher

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "ACB_Portable")
            app_dir = root / "App"
            (app_dir / "_Lang_SW" / "x64").mkdir(parents=True)

            (root / "portable.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Classes\\VirtualStore\\MACHINE\\"
                "SOFTWARE\\WOW6432Node\\Ubisoft\\Assassin's Creed Brotherhood]\r\n"
                '"Language"="English"\r\n\r\n',
                encoding="utf-16",
            )
            (root / "portable_machine.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Ubisoft\\"
                "Assassin's Creed Brotherhood]\r\n"
                '"InstallDir"="@@PORTABLE_ROOT@@\\\\App"\r\n'
                '"Language"="English"\r\n\r\n',
                encoding="utf-16",
            )
            session_dir = root / "PortableData" / "Registry"
            session_dir.mkdir(parents=True)
            (session_dir / "k00.reg").write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\Classes\\VirtualStore\\MACHINE\\"
                "SOFTWARE\\WOW6432Node\\Ubisoft\\Assassin's Creed Brotherhood]\r\n"
                '"Language"="English"\r\n\r\n',
                encoding="utf-16",
            )

            cfg = {
                "data_dir_name": "PortableData",
                "registry": {
                    "enabled": True,
                    "file": "portable.reg",
                    "machine_file": "portable_machine.reg",
                    "restore_on_exit": True,
                    "keys": [
                        r"HKCU\Software\Classes\VirtualStore\MACHINE\SOFTWARE\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood",
                        r"HKLM\Software\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood",
                    ],
                    "created_keys": [
                        r"HKCU\Software\Classes\VirtualStore\MACHINE\SOFTWARE\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood",
                        r"HKLM\Software\WOW6432Node\Ubisoft\Assassin's Creed Brotherhood",
                    ],
                },
            }

            # Симулируем: пользователь кликнул _Lang_SW\x64\Rus.reg на хосте,
            # поэтому в HKLM на хосте сейчас лежит "Language"="Russian".
            def fake_host_read(key: str):
                if "assassin's creed brotherhood" in key.casefold() and key.upper().startswith("HKLM"):
                    return {"Language": '"Russian"'}
                return {}

            reg_calls = []

            def fake_reg(args):
                reg_calls.append(tuple(args))
                return 0

            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(
                        exe_launcher, "_read_host_key_reg_values",
                        side_effect=fake_host_read,
                    ), \
                    mock.patch.object(
                        exe_launcher, "_reg", side_effect=fake_reg
                    ):
                session = exe_launcher.RegistrySession(root, cfg)
                session.load()

                # Все файлы портатива (portable.reg, portable_machine.reg, k00.reg)
                # поглотили "Language"="Russian" с хоста и не перетёрли его обратно.
                for reg_file in (
                    root / "portable.reg",
                    root / "portable_machine.reg",
                    session_dir / "k00.reg",
                ):
                    text = reg_file.read_text(encoding="utf-16")
                    self.assertIn('"Language"="Russian"', text, str(reg_file))
                    self.assertNotIn('"Language"="English"', text, str(reg_file))
                    self.assertIn(
                        '"InstallDir"="@@PORTABLE_ROOT@@\\\\App"',
                        text,
                        str(reg_file),
                    )

                session.save_and_restore()

            # После выхода созданный ключ удаляется с хоста, а не восстанавливается
            deletes = [c for c in reg_calls if c[0] == "delete"]
            self.assertEqual(len(deletes), 2)

    def test_hklm_key_missing_detects_partial_lang_sw_key_without_installdir(self):
        import portable_launcher_entry as exe_launcher

        with tempfile.TemporaryDirectory() as temp:
            machine_path = Path(temp, "portable_machine.reg")
            machine_path.write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Ubisoft\\"
                "Assassin's Creed Brotherhood]\r\n"
                '"InstallDir"="@@PORTABLE_ROOT@@\\\\App"\r\n'
                '"Language"="Russian"\r\n\r\n',
                encoding="utf-16",
            )

            # На хосте есть только Language="Russian" (после клика по Rus.reg),
            # а InstallDir из portable_machine.reg ещё не импортирован.
            with mock.patch.object(exe_launcher, "IS_WINDOWS", True), \
                    mock.patch.object(
                        exe_launcher,
                        "_read_host_key_reg_values",
                        return_value={"Language": '"Russian"'},
                    ):
                self.assertTrue(
                    exe_launcher._hklm_key_missing([], machine_path)
                )



if __name__ == "__main__":
    unittest.main()
