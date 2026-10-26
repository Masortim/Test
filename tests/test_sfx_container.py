"""Самораспаковывающийся архив: содержимое достаётся ДО запуска обёртки.

Регрессия, ради которой написан модуль:

    MultiTran (``mt_2025-03-06.exe``, 3,7 ГБ) — WinRAR SFX поверх Inno Setup.
    Portablizer запускал обёртку с ключами ``/S /D=<App>``, которые она не
    разбирает: 47 минут, ни одного файла, ни секунды процессорного времени,
    и вопрос «ждать ещё?» каждые 15 минут.

Проверяется, что теперь для SFX порядок обратный:

  * содержимое достаётся любым доступным распаковщиком (7-Zip, WinRAR,
    встроенный ``tar.exe``) или самой обёрткой с документированным
    ``-s -d<папка>`` — код обёртки при этом не выполняется;
  * если внутри нашёлся настоящий установщик (Inno Setup, NSIS,
    InstallShield), запускается он и его собственными ключами тишины, а не
    ключами обёртки;
  * если установщика внутри нет, содержимое и есть программа: оно
    переносится в ``App`` как есть;
  * когда ничего не вышло, сборка не ломается, а возвращается к обычной
    лестнице ключей.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pebuild
from portablizer.core import portablizer as engine_mod
from portablizer.core import unpacker as unpacker_mod
from portablizer.core.detect import (
    DetectionResult, InstallerType, RepackProfile,
)
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import PortableOptions, Portablizer


def _write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return str(path)


class BaseCase(unittest.TestCase):
    """Общая песочница: папка сборки, App и портатив."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.portable = self.root / "MultiTran_Portable"
        self.app = self.portable / "App"
        self.data = self.portable / "PortableData"
        self.app.mkdir(parents=True)
        self.data.mkdir(parents=True)
        self.console = str(self.portable / "installer-output.log")
        self.engine = Portablizer(Logger())
        # Границы API берём такими, как в настоящей сборке: «на Windows».
        self.windows = mock.patch.object(engine_mod, "IS_WINDOWS", True)
        self.windows.start()
        self.addCleanup(self.windows.stop)


class DecisionTests(BaseCase):
    """Когда содержимое достаётся до запуска обёртки."""

    def _det(self, **kwargs):
        return DetectionResult(kwargs.pop("installer_type",
                                         InstallerType.SELF_EXTRACT),
                               0.7, **kwargs)

    def test_self_extracting_archive_is_unpacked_first(self):
        self.assertTrue(self.engine._container_first_worth_trying(self._det()))

    def test_known_engine_is_left_to_its_own_ladder(self):
        det = self._det(installer_type=InstallerType.INNO)
        self.assertFalse(self.engine._container_first_worth_trying(det))

    def test_repack_with_documented_switches_is_left_alone(self):
        """У перепака команда документирована: распаковка «в кучу» помешает."""
        repack = RepackProfile(name="KpoJIuK", product="SketchUp",
                               filename_re=None)
        det = self._det(repack_profile=repack)
        self.assertFalse(self.engine._container_first_worth_trying(det))

    def test_vendor_profile_is_left_alone(self):
        det = self._det(vendor_name="Trimble")
        self.assertFalse(self.engine._container_first_worth_trying(det))

    def test_network_downloader_is_not_a_container(self):
        det = self._det(is_downloader_stub=True)
        self.assertFalse(self.engine._container_first_worth_trying(det))

    def test_adobe_has_its_own_payload_scenario(self):
        self.engine._adobe_detected = True
        self.assertFalse(self.engine._container_first_worth_trying(self._det()))

    def test_nothing_happens_outside_windows(self):
        with mock.patch.object(engine_mod, "IS_WINDOWS", False):
            self.assertFalse(
                self.engine._container_first_worth_trying(self._det()))


class NestedKindTests(BaseCase):
    """Какой движок у установщика внутри архива."""

    def test_inno_is_recognised(self):
        path = _write(self.root / "inner" / "setup.exe",
                      b"MZ" + b"\0" * 512 + b"Inno Setup Setup Data")
        self.assertEqual(self.engine._nested_installer_kind(path),
                         InstallerType.INNO)

    def test_nsis_is_recognised(self):
        path = _write(self.root / "inner" / "setup.exe",
                      b"MZ" + b"\0" * 512 + b"Nullsoft Install System v3.08")
        self.assertEqual(self.engine._nested_installer_kind(path),
                         InstallerType.NSIS)

    def test_installshield_is_recognised(self):
        path = _write(self.root / "inner" / "setup.exe",
                      b"MZ" + b"\0" * 512 + b"InstallShield (R) Setup Launcher")
        self.assertEqual(self.engine._nested_installer_kind(path),
                         InstallerType.INSTALLSHIELD)

    def test_unknown_engine_is_not_guessed(self):
        path = _write(self.root / "inner" / "setup.exe",
                      b"MZ" + b"\0" * 512 + b"just a program")
        self.assertEqual(self.engine._nested_installer_kind(path),
                         InstallerType.UNKNOWN)

    def test_missing_file_does_not_raise(self):
        self.assertEqual(
            self.engine._nested_installer_kind(str(self.root / "no.exe")),
            InstallerType.UNKNOWN)


class NestedPlanTests(BaseCase):
    """Ключи для установщика изнутри: свои, а не ключи обёртки."""

    def _opts(self, language: str = "") -> PortableOptions:
        return PortableOptions(installer_path="mt.exe", output_dir=str(self.root),
                               install_language=language)

    def _nested(self, signature: bytes) -> str:
        return _write(self.root / "inner" / "setup.exe",
                      b"MZ" + b"\0" * 512 + signature)

    def test_inno_gets_verysilent_and_its_own_folder(self):
        plans = self.engine._plans_for_nested_setup(
            self._nested(b"Inno Setup"), str(self.app), self._opts())
        self.assertGreaterEqual(len(plans), 1)
        first = plans[0]
        self.assertIn("/VERYSILENT", first.args)
        self.assertIn("/SUPPRESSMSGBOXES", first.args)
        self.assertIn("/NORESTART", first.args)
        self.assertEqual(first.raw_tail, f'/DIR="{self.app}"')
        self.assertEqual(first.label.split(":")[0], "Inno Setup внутри SFX")
        self.assertFalse(first.ignores_target_dir)

    def test_inno_language_is_passed_only_when_chosen(self):
        plain = self.engine._plans_for_nested_setup(
            self._nested(b"Inno Setup"), str(self.app), self._opts())
        self.assertFalse(any(a.startswith("/LANG=") for a in plain[0].args))
        russian = self.engine._plans_for_nested_setup(
            self._nested(b"Inno Setup"), str(self.app), self._opts("ru"))
        self.assertTrue(any(a.startswith("/LANG=") for a in russian[0].args))

    def test_inno_second_plan_adopts_the_default_folder(self):
        plans = self.engine._plans_for_nested_setup(
            self._nested(b"Inno Setup"), str(self.app), self._opts())
        self.assertTrue(plans[1].ignores_target_dir)
        self.assertIn("без /DIR", plans[1].label)

    def test_inno_second_plan_lets_installer_pick_its_own_folder(self):
        # Внутренний мастер выбора папки (Multitran) отклоняет переданный
        # через командную строку путь и не пропускает страницу тишиной.
        # План без /DIR должен НЕ вбивать App во вкладку выбора каталога,
        # чтобы установщик прошёл с каталогом по умолчанию.
        plans = self.engine._plans_for_nested_setup(
            self._nested(b"Inno Setup"), str(self.app), self._opts())
        self.assertFalse(plans[0].prefers_installer_default_dir)
        self.assertTrue(plans[1].prefers_installer_default_dir)

    def test_nsis_gets_s_and_the_path_last_without_quotes(self):
        plans = self.engine._plans_for_nested_setup(
            self._nested(b"Nullsoft Install System"), str(self.app),
            self._opts())
        self.assertEqual(plans[0].args, ["/S"])
        self.assertEqual(plans[0].raw_tail, f"/D={self.app}")

    def test_unknown_engine_gets_inno_then_nsis(self):
        plans = self.engine._plans_for_nested_setup(
            self._nested(b"mystery setup"), str(self.app), self._opts())
        self.assertEqual(len(plans), 2)
        self.assertIn("/VERYSILENT", plans[0].args)
        self.assertEqual(plans[1].args, ["/S"])


class ExtractTests(BaseCase):
    """Достаёт содержимое: распаковщик, затем сама обёртка."""

    def _opts(self) -> PortableOptions:
        return PortableOptions(installer_path=str(self.root / "mt.exe"),
                               output_dir=str(self.root))

    def test_first_extractor_with_files_wins(self):
        work = self.root / "work"
        work.mkdir()

        def fake_run(cmd, _log, _opts, **_kwargs):  # noqa: ANN001
            _write(work / "files" / "setup.exe", b"MZ")
            _write(work / "files" / "data.bin", b"x" * 100)
            return 0, "ok"

        extractor = unpacker_mod.Extractor(unpacker_mod.STYLE_7ZIP, "7z.exe")
        with mock.patch.object(unpacker_mod, "find_extractors",
                               return_value=[extractor]), \
                mock.patch.object(self.engine, "_run_unpacker_command",
                                  side_effect=fake_run):
            files, method = self.engine._extract_container_to(
                str(self.root / "mt.exe"), str(work), self._opts(),
                self.console)
        self.assertEqual(files, 2)
        self.assertEqual(method, "7z.exe")

    def test_unsuccessful_extractor_falls_through_to_the_wrapper(self):
        work = self.root / "work"
        work.mkdir()

        def fake_run(*_args, **_kwargs):  # noqa: ANN001
            return 2, "cannot open"

        def fake_self_extract(_source, work_dir, _opts, _log, _progress=None):
            _write(Path(work_dir) / "setup.exe", b"MZ")
            return ""

        extractor = unpacker_mod.Extractor(unpacker_mod.STYLE_7ZIP, "7z.exe")
        with mock.patch.object(unpacker_mod, "find_extractors",
                               return_value=[extractor]), \
                mock.patch.object(self.engine, "_run_unpacker_command",
                                  side_effect=fake_run), \
                mock.patch.object(self.engine, "_sfx_self_extract",
                                  side_effect=fake_self_extract):
            files, method = self.engine._extract_container_to(
                str(self.root / "mt.exe"), str(work), self._opts(),
                self.console)
        self.assertEqual(files, 1)
        self.assertIn("-s -d", method)

    def test_nothing_works_returns_zero(self):
        work = self.root / "work"
        work.mkdir()
        with mock.patch.object(unpacker_mod, "find_extractors",
                               return_value=[]), \
                mock.patch.object(self.engine, "_sfx_self_extract",
                                  return_value=""):
            self.assertEqual(
                self.engine._extract_container_to(
                    str(self.root / "mt.exe"), str(work), self._opts(),
                    self.console),
                (0, ""))


class FlowTests(BaseCase):
    """Весь сценарий целиком: распаковка → установка изнутри или перенос."""

    def _opts(self) -> PortableOptions:
        return PortableOptions(installer_path=str(self.root / "mt.exe"),
                               output_dir=str(self.root))

    def test_payload_without_installer_is_moved_to_app(self):
        installer = _write(self.root / "mt.exe",
                           b"MZ" + b"WinRAR SFX" + b"\0" * 64)
        payload = {"exe": pebuild.write_pe(self.root / "src" / "MultiTran.exe",
                                           imports=["kernel32.dll"])}

        def fake_extract(_source, work_dir, *_args, **_kwargs):  # noqa: ANN001
            target = Path(work_dir) / "MultiTran.exe"
            target.write_bytes(Path(payload["exe"]).read_bytes())
            return 1, "7z.exe"

        with mock.patch.object(self.engine, "_extract_container_to",
                               side_effect=fake_extract):
            result = self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.SELF_EXTRACT, 0.7), "MultiTran")
        self.assertIsNotNone(result)
        code, plan = result
        self.assertEqual(code, 0)
        self.assertIsNone(plan)
        self.assertTrue((self.app / "MultiTran.exe").is_file())
        self.assertEqual(self.engine._unpacked_with, "7z.exe")
        self.assertFalse((self.portable / "_sfx_content").exists())
        _ = installer

    def test_nested_inno_is_installed_with_its_own_switches(self):
        _write(self.root / "mt.exe",
               b"MZ" + b"WinRAR SFX" + b"\0" * 64)
        seen = {}

        def fake_extract(_source, work_dir, *_args, **_kwargs):  # noqa: ANN001
            pebuild.write_pe(Path(work_dir) / "setup.exe",
                             imports=["kernel32.dll"],
                             extra=b"Inno Setup Setup Data (6.2.0)")
            return 1, "7z.exe"

        def fake_install(plan, _opts, app_dir, _data, **_kwargs):  # noqa: ANN001
            seen["plan"] = plan
            pebuild.write_pe(Path(app_dir) / "MultiTran.exe",
                             imports=["kernel32.dll"])
            return 0

        with mock.patch.object(self.engine, "_extract_container_to",
                               side_effect=fake_extract), \
                mock.patch.object(self.engine, "_run_install",
                                  side_effect=fake_install):
            result = self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.SELF_EXTRACT, 0.7), "MultiTran")
        self.assertIsNotNone(result)
        code, plan = result
        self.assertEqual(code, 0)
        self.assertIsNotNone(plan)
        self.assertIn("Inno Setup внутри SFX", plan.label)
        self.assertIn("/VERYSILENT", seen["plan"].args)
        self.assertEqual(seen["plan"].raw_tail, f'/DIR="{self.app}"')
        # Программа установлена — распакованное больше не нужно.
        self.assertFalse((self.portable / "_sfx_content").exists())
        self.assertIn("своими ключами тишины", self.engine.log.text)

    def test_nested_installer_without_result_keeps_the_ladder(self):
        _write(self.root / "mt.exe", b"MZ" + b"WinRAR SFX" + b"\0" * 64)

        def fake_extract(_source, work_dir, *_args, **_kwargs):  # noqa: ANN001
            pebuild.write_pe(Path(work_dir) / "setup.exe",
                             imports=["kernel32.dll"],
                             extra=b"Inno Setup Setup Data")
            return 1, "7z.exe"

        with mock.patch.object(self.engine, "_extract_container_to",
                               side_effect=fake_extract), \
                mock.patch.object(self.engine, "_run_install",
                                  return_value=0):
            self.assertIsNone(self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.SELF_EXTRACT, 0.7), "MultiTran"))
        # setup.exe не должен достаться App как «главная программа».
        self.assertFalse((self.app / "setup.exe").exists())
        self.assertFalse((self.portable / "_sfx_content").exists())
        self.assertIn("не дал файлов программы", self.engine.log.text)

    def test_nested_installer_failure_promotes_container_payload(self):
        _write(self.root / "mt.exe", b"MZ" + b"WinRAR SFX" + b"\0" * 64)
        exe = pebuild.write_pe(self.root / "src" / "MultiTran.exe",
                               imports=["kernel32.dll"])

        def fake_extract(_source, work_dir, *_args, **_kwargs):  # noqa: ANN001
            pebuild.write_pe(Path(work_dir) / "setup.exe",
                             imports=["kernel32.dll"],
                             extra=b"Inno Setup Setup Data")
            (Path(work_dir) / "MultiTran.exe").write_bytes(
                Path(exe).read_bytes())
            return 1, "7z.exe"

        # Установщик изнутри «не поставил» (клики не прошли), но содержимое
        # контейнера — это файлы программы: они должны переехать в App.
        with mock.patch.object(self.engine, "_extract_container_to",
                               side_effect=fake_extract), \
                mock.patch.object(self.engine, "_run_install",
                                  return_value=0), \
                mock.patch.object(unpacker_mod, "find_unpacker",
                                  return_value=None):
            result = self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.SELF_EXTRACT, 0.7), "MultiTran")
        self.assertIsNotNone(result)
        code, plan = result
        self.assertEqual(code, 0)
        self.assertIsNone(plan)
        self.assertTrue((self.app / "MultiTran.exe").is_file())
        self.assertFalse((self.app / "setup.exe").exists())

    def test_nested_installer_failure_extracts_nested_payload(self):
        _write(self.root / "mt.exe", b"MZ" + b"WinRAR SFX" + b"\0" * 64)

        def fake_extract(_source, work_dir, *_args, **_kwargs):  # noqa: ANN001
            pebuild.write_pe(Path(work_dir) / "setup.exe",
                             imports=["kernel32.dll"],
                             extra=b"Inno Setup Setup Data")
            return 1, "7z.exe"

        def fake_unpack(_unpacker, _installer, destination,
                        _work, **_kwargs):  # noqa: ANN001
            pebuild.write_pe(Path(destination) / "MultiTran.exe",
                             imports=["kernel32.dll"])
            return True, "перенесено файлов: 1"

        # Содержимого контейнера мало (только setup.exe), а payload внутри
        # вложенного Inno Setup — распаковщик его достаёт без запуска.
        with mock.patch.object(self.engine, "_extract_container_to",
                               side_effect=fake_extract), \
                mock.patch.object(self.engine, "_run_install",
                                  return_value=0), \
                mock.patch.object(unpacker_mod, "find_unpacker",
                                  return_value="7z.exe"), \
                mock.patch.object(unpacker_mod, "unpack_installer",
                                  side_effect=fake_unpack):
            result = self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.SELF_EXTRACT, 0.7), "MultiTran")
        self.assertIsNotNone(result)
        code, plan = result
        self.assertEqual(code, 0)
        self.assertIsNone(plan)
        self.assertTrue((self.app / "MultiTran.exe").is_file())

    def test_install_from_container_recovers_nonzero_exit(self):
        _write(self.root / "mt.exe", b"MZ" + b"WinRAR SFX" + b"\0" * 64)
        nested = _write(self.root / "setup.exe",
                        b"MZ" + b"\0" * 512 + b"Inno Setup")
        recover_calls = []

        def fake_install(_plan, _opts, _app, _data, **_kwargs):  # noqa: ANN001
            return 1

        def fake_recover():
            recover_calls.append(True)
            return True

        # Мастер пошёл, установщик поставил программу в каталог по
        # умолчанию и вышел с кодом 1 — recovery должен всё равно
        # перенести её в App.
        with mock.patch.object(self.engine, "_run_install",
                               side_effect=fake_install), \
                mock.patch.object(self.engine, "_find_main_exe",
                                  return_value=None):
            result = self.engine._install_from_container(
                nested, str(self.portable / "_sfx_content"), self._opts(),
                str(self.app), str(self.data), str(self.portable), "MultiTran",
                recover=fake_recover)
        self.assertIsNotNone(result)
        code, plan = result
        self.assertEqual(code, 1)
        self.assertIn("без /DIR", plan.label)
        self.assertEqual(len(recover_calls), 1)

    def test_data_only_archive_is_not_poured_into_app(self):
        _write(self.root / "mt.exe", b"MZ" + b"WinRAR SFX" + b"\0" * 64)

        def fake_extract(_source, work_dir, *_args, **_kwargs):  # noqa: ANN001
            _write(Path(work_dir) / "dictionary.dat", b"x" * 1024)
            return 1, "7z.exe"

        with mock.patch.object(self.engine, "_extract_container_to",
                               side_effect=fake_extract):
            self.assertIsNone(self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.SELF_EXTRACT, 0.7), "MultiTran"))
        self.assertEqual(list(self.app.iterdir()), [])
        self.assertIn("нет ни одного запускаемого exe", self.engine.log.text)

    def test_failed_extraction_falls_back_to_the_ladder(self):
        _write(self.root / "mt.exe", b"MZ" + b"WinRAR SFX" + b"\0" * 64)
        with mock.patch.object(self.engine, "_extract_container_to",
                               return_value=(0, "")):
            self.assertIsNone(self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.SELF_EXTRACT, 0.7), "MultiTran"))
        self.assertIn("обычной лестнице", self.engine.log.text)

    def test_known_engine_is_not_unpacked(self):
        with mock.patch.object(self.engine, "_extract_container_to") as extract:
            self.assertIsNone(self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.INNO, 0.9), "MultiTran"))
        extract.assert_not_called()

    def test_failed_tar_extractor_cleans_leftover_files_before_self_extract(self):
        """tar.exe на solid RAR оставляет обрывок файла — его надо убрать."""
        work = self.root / "_sfx_content"
        work.mkdir()

        def fake_tar(cmd, _log, _opts, **_kwargs):  # noqa: ANN001
            _write(work / "partial.dat", b"broken")
            return 1, "tar.exe: RAR solid archive support unavailable"

        def fake_self_extract(_source, work_dir, _opts, _log, _progress=None):
            self.assertFalse((Path(work_dir) / "partial.dat").exists())
            pebuild.write_pe(Path(work_dir) / "network.exe",
                             imports=["kernel32.dll"])
            return ""

        extractor = unpacker_mod.Extractor(unpacker_mod.STYLE_7ZIP, "tar.exe")
        extractor = unpacker_mod.Extractor(unpacker_mod.STYLE_TAR, "tar.exe")
        with mock.patch.object(unpacker_mod, "find_extractors",
                               return_value=[extractor]), \
                mock.patch.object(unpacker_mod, "carve_archive",
                                  return_value=(str(work / "carved.rar"), "rar")), \
                mock.patch.object(self.engine, "_run_unpacker_command",
                                  side_effect=fake_tar), \
                mock.patch.object(self.engine, "_sfx_self_extract",
                                  side_effect=fake_self_extract):
            files, method = self.engine._extract_container_to(
                str(self.root / "mt_2025-03-06.exe"), str(work), self._opts(),
                self.console)
        self.assertEqual(files, 1)
        self.assertIn("-s -d", method)
        self.assertTrue((work / "network.exe").is_file())
        self.assertFalse((work / "partial.dat").exists())

    def test_find_sfx_dirs_ignores_internal_sfx_temp_and_sfx_content(self):
        """Служебные папки _sfx_temp и _sfx_content не должны считаться RarSFX."""
        from portablizer.core import adobe as adobe_mod

        work = self.portable / "_sfx_content"
        sfx_temp = work / "_sfx_temp"
        rarsfx = sfx_temp / "RarSFX0"
        rarsfx.mkdir(parents=True)
        _write(rarsfx / "mt.exe", b"MZ")

        found = adobe_mod.find_sfx_dirs([str(sfx_temp), str(work)])
        self.assertEqual(found, [str(rarsfx)])

    def test_unknown_nested_setup_with_unpacked_program_exe_promotes_directly(self):
        """Если в архиве рядом с самописным setup.exe уже лежит exe программы,
        переносим файлы в App напрямую без запуска setup.exe с /DIR= и /D=."""
        _write(self.root / "mt.exe",
               b"MZ" + b"WinRAR SFX" + b"\0" * 64)
        exe = pebuild.write_pe(self.root / "src" / "network.exe",
                               imports=["kernel32.dll"])

        def fake_extract(_source, work_dir, *_args, **_kwargs):  # noqa: ANN001
            pebuild.write_pe(Path(work_dir) / "setup.exe",
                             imports=["kernel32.dll"],
                             extra=b"custom multitran copy helper")
            (Path(work_dir) / "network.exe").write_bytes(
                Path(exe).read_bytes())
            _write(Path(work_dir) / "dict.erd", b"x" * 2048)
            return 3, "сама обёртка (-s -d)"

        with mock.patch.object(self.engine, "_extract_container_to",
                               side_effect=fake_extract), \
                mock.patch.object(self.engine, "_install_from_container") as run_nested:
            result = self.engine._run_container_first(
                self._opts(), str(self.app), str(self.data),
                str(self.portable),
                DetectionResult(InstallerType.SELF_EXTRACT, 0.7), "Multitran")
        self.assertIsNotNone(result)
        code, plan = result
        self.assertEqual(code, 0)
        self.assertIsNone(plan)
        run_nested.assert_not_called()
        self.assertTrue((self.app / "network.exe").is_file())
        self.assertTrue((self.app / "dict.erd").is_file())
        self.assertFalse((self.app / "setup.exe").exists())

    def test_winrar_sfx_ladder_uses_minus_d_without_equals(self):
        """WinRAR SFX не должен получать /D=<App> или /DIR=<App> со знаком «=»."""
        from portablizer.core.silentargs import build_attempts

        det = DetectionResult(
            InstallerType.SELF_EXTRACT, 0.7,
            evidence=["найдена сигнатура: WinRAR SFX"],
        )
        plans = build_attempts(
            det, r"E:\Backup\mt_2025-03-06.exe",
            r"D:\Portable\Multitran_Portable\App",
        )
        self.assertTrue(plans)
        self.assertEqual(plans[0].args, ["-s"])
        self.assertEqual(
            plans[0].raw_tail, r"-dD:\Portable\Multitran_Portable\App")
        self.assertEqual(plans[1].args, ["/S"])
        self.assertEqual(
            plans[1].raw_tail, r"-dD:\Portable\Multitran_Portable\App")
        for plan in plans:
            tail = plan.raw_tail or ""
            self.assertFalse(
                tail.startswith("/D=") or tail.startswith("/DIR="),
                f"{plan.label} has '=' in raw_tail: {tail}",
            )

    def test_winrar_sfx_does_not_get_false_inno_languages_from_dictionary_words(self):
        """Слова english/russian внутри словаря WinRAR SFX — не языки Inno Setup."""
        from portablizer.core.detect import detect_installer

        installer = _write(
            self.root / "mt_2025-03-06.exe",
            b"MZ" + b"\0" * 128 + b"WinRAR SFX"
            + b"\0english\0russian\0german\0french\0spanish\0italian\0",
        )
        det = detect_installer(installer)
        self.assertEqual(det.installer_type, InstallerType.SELF_EXTRACT)
        self.assertEqual(det.inno_language_names, [])


if __name__ == "__main__":
    unittest.main()
