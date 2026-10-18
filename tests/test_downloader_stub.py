"""Сетевой загрузчик: когда программы внутри установщика нет вовсе.

Регрессия, ради которой написан этот модуль:

    Сборка портатива из ``Fusion_360_Setup.exe`` прошла все шесть сценариев
    лестницы и закончилась так:

        OK   Тип установщика: Self-extracting archive (уверенность 70%)
        DEBUG • найдена сигнатура: 7-Zip
        DEBUG • ключи внутри файла: /qn, /qb
        INFO  Тихая установка... идёт 0:00; распаковано 4.0 КБ в 1 файлах
        OK   Установка завершена (код 0).
        WARN  Целевая папка пуста. Установщик мог проигнорировать ключ папки…
        … (то же самое ещё пять раз: /VERYSILENT, /silent, /quiet, -s, --silent)
        ERROR Установщик завершился, но в папке App не найден ни один
              исполняемый файл. Испробовано вариантов команды: 6.

    Диагноз был неверным, и дело не в ключах. ``Fusion_360_Setup.exe`` — это
    «Fusion Client Downloader»: потоковый загрузчик на несколько мегабайт,
    который скачивает клиента из сети и раскладывает его в
    ``%LOCALAPPDATA%\\Autodesk\\webdeploy\\production\\<хеш сборки>``, а при
    каждом запуске сам себя обновляет и требует вход в аккаунт Autodesk.
    Документированный ключ тишины у него ``--quiet`` (строки внутри упаковки
    PyInstaller не видны, поэтому эвристика по ключам нашла только чужие
    ``/qn`` и ``/qb``), а ``--globalinstall`` дополнительно ставит клиент в
    ``Program Files`` ЭТОГО компьютера — для портатива он не годится вовсе.
    Единственные 4 КБ, которые видел наблюдатель, — журнал загрузчика.

Проверяется, что теперь:
  * загрузчик узнаётся ДО запуска — по профилю продукта (стандартизованное имя
    файла плюс малый вес) и по признакам внутри файла (API загрузки из сети +
    URL раздачи), и журнал говорит об этом сразу, а не после шести попыток;
  * настоящий офлайн-дистрибутив того же продукта, уверенно опознанный движок
    и GOG-установщик заглушкой НЕ считаются;
  * лестница сценариев для заглушки короче, но не обрывается на одной команде
    (признак мог и ошибиться), и не отменяет сценарии, которые файлы ДОСТАЮТ
    (Burn ``/layout``, ``msiexec /a``);
  * две «пустые» команды подряд (код 0, секунды работы, ни одного файла
    программы) останавливают лестницу, а служебные записи установщика за файлы
    программы не считаются;
  * итоговые подсказки называют причину словами и ведут к офлайн-дистрибутиву,
    а не к подбору ключей тишины.
"""
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import detect as detect_mod
from portablizer.core import portablizer as engine_mod
from portablizer.core import space as space_mod
from portablizer.core.detect import (
    DOWNLOADER_STUB_MAX_BYTES, DetectionResult, InstallerType, detect_installer,
)
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import (
    HOLLOW_ATTEMPTS_LIMIT, HOLLOW_ATTEMPT_MAX_SECONDS, PortableOptions,
    Portablizer,
)
from portablizer.core.silentargs import (
    MAX_ATTEMPTS, ONLINE_PRODUCT_MAX_ATTEMPTS, STUB_MAX_ATTEMPTS, SilentPlan,
    build_attempts,
)


def _fake_pe(path, sections, payload=b"", dotnet=False, size=0):
    """Минимальный, но структурно валидный PE (см. tests/test_portablizer)."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    optional_size = 240
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0,
                       optional_size, 0x2102)
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x10B)      # PE32
    struct.pack_into("<I", optional, 92, 16)        # NumberOfRvaAndSizes
    if dotnet:
        struct.pack_into("<II", optional, 96 + 14 * 8, 0x2000, 0x48)
    table = b"".join(name.encode().ljust(8, b"\0") + b"\0" * 32
                     for name in sections)
    Path(path).write_bytes(bytes(dos) + b"PE\0\0" + coff + bytes(optional)
                           + table + payload)
    if size:
        with open(path, "r+b") as fh:
            fh.truncate(size)
    return path


def _touch(root: str, name: str, size: int = 4096) -> str:
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"x" * size)
    return path


#: Содержимое, которое видел Portablizer в настоящем загрузчике Fusion:
#: сигнатура 7-Zip и чужие MSI-ключи внутри.
FUSION_PAYLOAD = b"7-Zip" + b"\0" * 512 + b"/qn /qb"

#: Признаки «честной» заглушки: API загрузки из сети и URL раздачи файлов.
GENERIC_STUB_PAYLOAD = (
    b"URLDownloadToFile WinHttpOpen "
    b"https://dl.appstreaming.example.com/production/installers/app.exe"
)


class DownloaderStubDetectionTests(unittest.TestCase):
    """Определение загрузчика до запуска установщика."""

    def test_fusion_downloader_is_recognised_by_product_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = _fake_pe(
                os.path.join(temp, "Fusion_360_Setup.exe"),
                [".text", ".rsrc"], FUSION_PAYLOAD, size=10 * 1024 * 1024)
            det = detect_installer(installer)
            # Тип движка определён ровно так же, как в журнале пользователя.
            self.assertEqual(det.installer_type, InstallerType.SELF_EXTRACT)
            self.assertTrue(det.is_downloader_stub)
            self.assertIsNotNone(det.online_product)
            self.assertEqual(det.online_product.name, "Autodesk Fusion")
            self.assertEqual(det.media_size, 10 * 1024 * 1024)
            self.assertIn("сетевой загрузчик", det.human)
            self.assertIn("webdeploy", det.online_product.reason)

    def test_documented_switch_is_user_scope_only(self):
        """--globalinstall ставит клиент в Program Files ЭТОГО ПК — его нет."""
        with tempfile.TemporaryDirectory() as temp:
            installer = _fake_pe(
                os.path.join(temp, "Fusion_360_Setup.exe"),
                [".text"], FUSION_PAYLOAD, size=1024)
            product = detect_installer(installer).online_product
            self.assertIsNotNone(product)
            self.assertIn("--quiet", product.switches)
            self.assertNotIn("--globalinstall", product.switches)

    def test_offline_distributor_of_the_same_product_is_not_a_stub(self):
        """Полный дистрибутив весит сотни мегабайт — профиль не срабатывает."""
        with tempfile.TemporaryDirectory() as temp:
            installer = _fake_pe(
                os.path.join(temp, "Fusion_360_Setup.exe"),
                [".text"], FUSION_PAYLOAD, size=1024)
            big = DOWNLOADER_STUB_MAX_BYTES + 1024
            with mock.patch.object(space_mod, "media_bytes", return_value=big):
                det = detect_installer(installer)
            self.assertFalse(det.is_downloader_stub)
            self.assertIsNone(det.online_product)

    def test_generic_stub_needs_both_download_api_and_url(self):
        """Одного признака мало: докачивать предусловия умеет и настоящий."""
        with tempfile.TemporaryDirectory() as temp:
            installer = _fake_pe(
                os.path.join(temp, "SomeAppSetup.exe"), [".text"],
                GENERIC_STUB_PAYLOAD, size=4 * 1024 * 1024)
            det = detect_installer(installer)
            self.assertTrue(det.is_downloader_stub)
            self.assertIsNone(det.online_product)
            self.assertTrue(det.downloader_evidence)
            self.assertIn("API загрузки", " ".join(det.downloader_evidence))

            only_api = _fake_pe(
                os.path.join(temp, "OnlyApiSetup.exe"), [".text"],
                b"URLDownloadToFile https://example.com/support/",
                size=4 * 1024 * 1024)
            self.assertFalse(detect_installer(only_api).is_downloader_stub)

            only_url = _fake_pe(
                os.path.join(temp, "OnlyUrlSetup.exe"), [".text"],
                b"https://dl.example.com/files/app.exe",
                size=4 * 1024 * 1024)
            self.assertFalse(detect_installer(only_url).is_downloader_stub)

    def test_zip_payload_inside_means_the_program_is_there(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = _fake_pe(
                os.path.join(temp, "BundledSetup.exe"), [".text"],
                GENERIC_STUB_PAYLOAD)
            with zipfile.ZipFile(installer, "a") as archive:
                archive.writestr("app/App.exe", b"MZ payload" * 64)
            det = detect_installer(installer)
            self.assertTrue(det.has_zip_payload)
            self.assertFalse(det.is_downloader_stub)

    def test_confidently_detected_engine_is_never_a_stub(self):
        """Inno Setup с isxdl докачивает предусловия, а не программу."""
        with tempfile.TemporaryDirectory() as temp:
            installer = _fake_pe(
                os.path.join(temp, "GoodSetup.exe"), [".text"],
                b"This installation was built with Inno Setup idp.dll "
                + GENERIC_STUB_PAYLOAD, size=6 * 1024 * 1024)
            det = detect_installer(installer)
            self.assertEqual(det.installer_type, InstallerType.INNO)
            self.assertGreaterEqual(det.confidence, detect_mod.TRUSTED_CONFIDENCE)
            self.assertFalse(det.is_downloader_stub)

    def test_gog_offline_installer_is_not_a_stub(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = _fake_pe(
                os.path.join(temp, "setup_hatred_2.1.0.9_(1).exe"), [".text"],
                b"gog.com goggame- " + GENERIC_STUB_PAYLOAD, size=1024)
            _touch(temp, "setup_hatred-1.bin", 1024)
            det = detect_installer(installer)
            self.assertTrue(det.is_gog)
            self.assertFalse(det.is_downloader_stub)

    def test_msi_is_not_a_stub(self):
        with tempfile.TemporaryDirectory() as temp:
            installer = os.path.join(temp, "Fusion_360_Setup.msi")
            _touch(temp, "Fusion_360_Setup.msi", 1024)
            det = detect_installer(installer)
            self.assertTrue(det.is_msi)
            self.assertFalse(det.is_downloader_stub)


class PayloadCountingTests(unittest.TestCase):
    """Служебные записи установщика — не файлы программы."""

    def test_logs_and_partial_downloads_are_not_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp, "PortableData")
            _touch(str(data), "Temp/autodesk.webdeploy.streamer.log", 4096)
            _touch(str(data), "Temp/download.tmp", 8192)
            files, total = space_mod.payload_files(str(data))
            self.assertEqual((files, total), (0, 0))

    def test_program_files_are_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            _touch(str(app), "Type.exe", 2048)
            _touch(str(app), "data/levels.pak", 4096)
            files, total = space_mod.payload_files(str(app))
            self.assertEqual(files, 2)
            self.assertEqual(total, 6144)

    def test_oversized_log_counts_as_data(self):
        """Журнал размером с дистрибутив — уже не служебная запись."""
        with tempfile.TemporaryDirectory() as temp:
            big_log = space_mod.SERVICE_FILE_MAX_BYTES + 1
            _touch(temp, "huge.log", big_log)
            files, _total = space_mod.payload_files(temp)
            self.assertEqual(files, 1)

    def test_missing_folder_is_not_an_error(self):
        self.assertEqual(space_mod.payload_files(""), (0, 0))
        self.assertEqual(
            space_mod.payload_files(os.path.join(tempfile.gettempdir(),
                                                 "нет-такой-папки")), (0, 0))


class StubLadderTests(unittest.TestCase):
    """Лестница сценариев для загрузчика короче, но не обрывается вовсе."""

    def _det(self, **kwargs) -> DetectionResult:
        base = dict(installer_type=InstallerType.SELF_EXTRACT, confidence=0.7)
        base.update(kwargs)
        return DetectionResult(**base)

    def _plans(self, det, installer="C:\\Setup.exe"):
        return build_attempts(det, installer, r"E:\\P\\App")

    def test_online_product_keeps_two_attempts(self):
        product = detect_mod._ONLINE_ONLY_PRODUCTS[0]
        plans = self._plans(self._det(is_downloader_stub=True,
                                      online_product=product))
        self.assertEqual(len(plans), ONLINE_PRODUCT_MAX_ATTEMPTS)

    def test_generic_stub_keeps_three_attempts(self):
        plans = self._plans(self._det(is_downloader_stub=True))
        self.assertEqual(len(plans), STUB_MAX_ATTEMPTS)

    def test_unknown_installer_without_stub_signs_keeps_the_full_ladder(self):
        plans = self._plans(self._det(installer_type=InstallerType.UNKNOWN,
                                      confidence=0.2))
        self.assertEqual(len(plans), MAX_ATTEMPTS)

    def test_cap_never_leaves_the_ladder_empty(self):
        """Укороченная лестница всё равно содержит рабочую команду."""
        product = detect_mod._ONLINE_ONLY_PRODUCTS[0]
        for det in (self._det(is_downloader_stub=True, online_product=product),
                    self._det(is_downloader_stub=True),
                    self._det(installer_type=InstallerType.UNKNOWN,
                              confidence=0.1, is_downloader_stub=True)):
            plans = self._plans(det)
            self.assertGreaterEqual(len(plans), 1)
            self.assertLessEqual(len(plans), MAX_ATTEMPTS)
            self.assertTrue(all(isinstance(p.label, str) and p.label
                                for p in plans))


class HollowLadderTests(unittest.TestCase):
    """Две «пустые» команды подряд останавливают перебор ключей."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.portable = str(self.root / "Fusion_Portable")
        self.app = str(self.root / "Fusion_Portable" / "App")
        self.data = str(self.root / "Fusion_Portable" / "PortableData")
        os.makedirs(self.app, exist_ok=True)
        os.makedirs(self.data, exist_ok=True)
        self.installer = _touch(self.temp.name, "Fusion_360_Setup.exe", 1024)
        self.opts = PortableOptions(installer_path=self.installer,
                                    output_dir=self.temp.name)
        self.plans = [
            SilentPlan(program=self.installer, args=[arg], label=f"ключ {arg}")
            for arg in ("/S", "/VERYSILENT", "/silent", "/quiet", "-s",
                        "--silent")
        ]

    def _engine(self, seconds=0.4, writes=None, det=None):
        """Двойник движка: установка «пишет» перечисленные файлы портатива.

        Пути в ``writes`` задаются относительно папки портатива, поэтому
        ``App/…`` и ``PortableData/…`` пишутся туда, куда их положил бы
        настоящий установщик.
        """
        writes = writes or {}
        portable = self.portable

        class Scripted(Portablizer):
            def __init__(inner):  # noqa: D107
                super().__init__(Logger())
                inner.calls = []

            def _run_install(inner, plan, opts, app_dir, data_dir, **kwargs):
                inner.calls.append(plan.label)
                inner._last_install_seconds = seconds
                for relative, size in writes.items():
                    root = os.path.dirname(os.path.join(portable, relative))
                    name = os.path.basename(relative)
                    _touch(root, name, size)
                return 0

        engine = Scripted()
        engine._detection = det
        return engine

    def _run(self, engine, plans=None):
        return engine._run_attempts(plans or self.plans, self.opts, self.app,
                                    self.data, self.portable, "Fusion")

    def test_two_empty_successes_stop_the_ladder(self):
        engine = self._engine()
        rc, used = self._run(engine)
        self.assertEqual(len(engine.calls), HOLLOW_ATTEMPTS_LIMIT)
        self.assertIsNone(used)
        self.assertEqual(rc, 0)
        self.assertTrue(engine._hollow_note)
        self.assertIn("Повторять установку другими ключами не буду",
                      engine.log.text)

    def test_product_profile_names_the_product_in_the_log(self):
        det = DetectionResult(InstallerType.SELF_EXTRACT, 0.7,
                              is_downloader_stub=True,
                              online_product=detect_mod._ONLINE_ONLY_PRODUCTS[0])
        engine = self._engine(det=det)
        self._run(engine)
        self.assertIn("Autodesk Fusion", engine._hollow_note)

    def test_service_log_in_the_profile_is_not_payload(self):
        """Ровно тот случай из журнала: 4 КБ журнала загрузчика в TEMP."""
        engine = self._engine(
            writes={"PortableData/Temp/autodesk.webdeploy.streamer.log":
                   4096})
        self._run(engine)
        self.assertEqual(len(engine.calls), HOLLOW_ATTEMPTS_LIMIT)

    def test_program_files_in_the_redirected_profile_keep_the_ladder(self):
        engine = self._engine(
            writes={"PortableData/User/AppData/Local/Programs/app/app.exe":
                   20480})
        _rc, used = self._run(engine)
        self.assertIsNone(used)     # exe ищется в App, а не в профиле
        self.assertEqual(len(engine.calls), len(self.plans))

    def test_slow_attempt_is_not_hollow(self):
        """Долгий выход с кодом 0 — установщик что-то делал (качал, ждал сеть)."""
        engine = self._engine(seconds=HOLLOW_ATTEMPT_MAX_SECONDS + 1)
        self._run(engine)
        self.assertEqual(len(engine.calls), len(self.plans))
        self.assertFalse(engine._hollow_note)

    def test_failure_code_is_not_hollow(self):
        class Failing(Portablizer):
            def __init__(inner):  # noqa: D107
                super().__init__(Logger())
                inner.calls = []

            def _run_install(inner, plan, opts, app_dir, data_dir, **kwargs):
                inner.calls.append(plan.label)
                inner._last_install_seconds = 0.4
                return 0xFFFFFFFF

        engine = Failing()
        self._run(engine)
        self.assertEqual(len(engine.calls), len(self.plans))
        self.assertFalse(engine._hollow_note)

    def test_extraction_fallback_is_not_cancelled(self):
        """Сценарий, который ДОСТАЁТ файлы, отменять нельзя."""
        layout = SilentPlan(program=self.installer, args=["/layout"],
                            label="распаковка /layout", extracts_only=True,
                            output_dir=str(self.root / "_bundle_layout"))
        plans = self.plans[:3] + [layout]
        engine = self._engine()
        self._run(engine, plans)
        self.assertIn("распаковка /layout", engine.calls)
        self.assertFalse(engine._hollow_note)

    def test_installscript_plan_is_not_counted_as_hollow(self):
        """У InstallShield свой диагноз: причина лежит в setup.log."""
        plans = [
            SilentPlan(program=self.installer, args=["/s"], label="InstallScript",
                       result_log=os.path.join(self.portable, "setup.log")),
            SilentPlan(program=self.installer, args=["/s"], label="без папки",
                       ignores_target_dir=True),
            SilentPlan(program=self.installer, args=["/quiet"], label="MSI"),
        ]
        engine = self._engine()
        self._run(engine, plans)
        self.assertEqual(len(engine.calls), 3)
        self.assertFalse(engine._hollow_note)


class DownloaderHintsTests(unittest.TestCase):
    """Итоговые подсказки ведут к офлайн-дистрибутиву, а не к ключам тишины."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.portable = os.path.join(self.temp.name, "Fusion_Portable")
        self.app = os.path.join(self.portable, "App")
        os.makedirs(self.app, exist_ok=True)
        self.installer = _touch(self.temp.name, "Fusion_360_Setup.exe", 1024)
        self.opts = PortableOptions(installer_path=self.installer,
                                    output_dir=self.temp.name)
        self.product = detect_mod._ONLINE_ONLY_PRODUCTS[0]
        self.det = DetectionResult(
            InstallerType.SELF_EXTRACT, 0.7, is_downloader_stub=True,
            online_product=self.product, media_size=10 * 1024 * 1024)

    def test_hints_explain_why_a_portable_is_impossible(self):
        engine = Portablizer(Logger())
        engine._installer_name = self.installer
        engine._detection = self.det
        engine._hollow_note = "Повторять установку другими ключами не буду."
        hints = engine._failure_hints(self.det, 0, self.opts, self.portable)
        text = "\n".join(hints)
        # Причина — первая подсказка: она важнее всех остальных версий.
        self.assertIn("webdeploy", hints[0])
        self.assertIn("--quiet", text)
        self.assertIn("аккаунт", text)
        # Ключи тишины подбирать бесполезно — и этого совет быть не должно.
        self.assertNotIn("Доп. аргументы установки» строку вида", text)

    def test_generic_stub_hints_lead_to_the_offline_distributor(self):
        engine = Portablizer(Logger())
        engine._installer_name = self.installer
        engine._hollow_note = "Повторять установку другими ключами не буду."
        det = DetectionResult(InstallerType.SELF_EXTRACT, 0.7,
                              is_downloader_stub=True,
                              downloader_evidence=["вес дистрибутива — 4.0 МБ"])
        hints = engine._failure_hints(det, 0, self.opts, self.portable)
        text = "\n".join(hints)
        self.assertIn("автономный", text)
        self.assertIn("ни одного файла программы", text)
        self.assertIn("части дистрибутива", text)

    def test_unpacker_is_not_offered_for_a_known_downloader(self):
        """Распаковка нашла бы сам загрузчик — и выдала бы его за программу."""
        engine = Portablizer(Logger())
        with mock.patch.object(engine_mod.unpacker_mod, "find_unpacker",
                               return_value="C:\\7-Zip\\7z.exe") as found:
            outcome = engine._try_unpacker_fallback(
                self.opts, self.app, self.portable, self.det, "Fusion")
        self.assertFalse(outcome)
        found.assert_not_called()
        self.assertIn("загрузчик", engine.log.text)

    def test_warning_is_logged_before_the_first_attempt(self):
        engine = Portablizer(Logger())
        engine._warn_downloader_stub(self.det)
        lines = engine.log.text
        self.assertIn("загрузчик Autodesk Fusion", lines)
        self.assertIn("10.0 МБ", lines)
        self.assertIn("webdeploy", lines)
        self.assertIn("--quiet", lines)
        # Ключ машины (--globalinstall) сборке не предлагается: он ставит
        # клиент в Program Files этого компьютера.
        self.assertNotIn("--globalinstall --quiet", lines)

    def test_no_warning_for_a_normal_installer(self):
        engine = Portablizer(Logger())
        engine._warn_downloader_stub(
            DetectionResult(InstallerType.INNO, 0.9))
        self.assertEqual(engine.log.text, "")


if __name__ == "__main__":
    unittest.main()
