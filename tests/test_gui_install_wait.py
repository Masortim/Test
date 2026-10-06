"""Интерфейс: режимы ожидания долгой установки и вопрос «ждать ещё?».

Проверяется ровно то, чего не видно из ядра: что выбранный в окне режим
попадает в ``PortableOptions`` и что на затишье в установке человека
спрашивают, а не молча снимают установщик.

Тесты пропускаются, если PySide6 не установлен (или Qt не может создать
приложение: например, на машине без графики) — ядро от интерфейса не зависит.
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

try:  # pragma: no cover - зависит от окружения
    from PySide6.QtWidgets import QApplication, QMessageBox

    _QT_ERROR = ""
except Exception as exc:  # noqa: BLE001 - нет PySide6 или системных библиотек
    QApplication = None
    QMessageBox = None
    _QT_ERROR = f"{type(exc).__name__}: {exc}"

from portablizer.core.portablizer import (
    STALL_CANCEL, STALL_STOP, STALL_WAIT, InstallStall, PortableOptions,
)


def _qt_app():
    """Единственный на процесс ``QApplication`` или ``None``, если Qt не готов."""
    if QApplication is None:
        return None
    app = QApplication.instance()
    if app is not None:
        return app
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        return QApplication([])
    except Exception:  # noqa: BLE001 - нет дисплея/библиотек: тесты пропускаем
        return None


_QT_APP = _qt_app()
_QT_READY = _QT_APP is not None


class _MemorySettings:
    """Замена ``QSettings``: тесты не трогают реестр пользователя."""

    def __init__(self, *_args, **_kwargs) -> None:
        self.data = {}

    def value(self, key, default=None):  # noqa: ANN001
        return self.data.get(str(key), default)

    def setValue(self, key, value) -> None:  # noqa: N802 - API Qt
        self.data[str(key)] = value


@unittest.skipUnless(_QT_READY, f"PySide6/Qt недоступен: {_QT_ERROR}")
class InstallWaitInterfaceTests(unittest.TestCase):
    def setUp(self):
        from portablizer.gui import main_window

        self.main_window = main_window
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        with mock.patch.object(main_window, "QSettings", _MemorySettings):
            self.window = main_window.MainWindow()

    def _installer(self) -> str:
        path = Path(self.temp.name, "setup.exe")
        path.write_bytes(b"MZ")
        return str(path)

    def test_the_modes_offer_a_real_choice_about_the_wait(self):
        combo = self.window.long_install_combo
        titles = [combo.itemText(index) for index in range(combo.count())]
        self.assertEqual(len(titles), len(self.main_window.LONG_INSTALL_MODES))
        self.assertIn("без предела", " ".join(titles))
        limits = []
        for index in range(combo.count()):
            combo.setCurrentIndex(index)
            limits.append(self.window._long_install_limits())
        self.assertEqual(limits[0], (900, 6 * 3600))
        self.assertEqual(limits[1][1], 0)          # без потолка попытки
        self.assertEqual(limits[2], (300, 1800))   # прежнее строгое поведение

    def test_the_chosen_mode_reaches_the_options(self):
        self.window.installer_edit.setText(self._installer())
        self.window.output_edit.setText(self.temp.name)
        self.window.long_install_combo.setCurrentIndex(1)
        opts = self.window._collect_options()
        self.assertIsInstance(opts, PortableOptions)
        self.assertEqual(opts.install_timeout, 900)
        self.assertEqual(opts.install_deadline, 0)

    def test_the_memory_of_the_mode_survives_the_build(self):
        self.window.long_install_combo.setCurrentIndex(2)
        self.window.installer_edit.setText(self._installer())
        self.window.output_edit.setText(self.temp.name)
        with mock.patch.object(self.main_window.PortableWorker, "start",
                               lambda _worker: None), \
                mock.patch.object(self.main_window.PortableWorker, "isRunning",
                                  lambda _worker: False):
            self.window._start()
        self.assertEqual(self.window.settings.data["long_install_mode"], 2)

    def _answer(self, prefix: str):
        """Нажимает в диалоге кнопку, начинающуюся с ``prefix``."""
        clicked = {}

        def fake_exec(box):
            for button in box.buttons():
                if button.text().startswith(prefix):
                    clicked["button"] = button
            return 0

        with mock.patch.object(QMessageBox, "exec", fake_exec), \
                mock.patch.object(QMessageBox, "clickedButton",
                                  lambda box: clicked.get("button")):
            self.window._on_stall(self._stall())

    @staticmethod
    def _stall() -> InstallStall:
        return InstallStall(attempt="Inno Setup: /VERYSILENT /DIR",
                            elapsed=5400.0, idle=900.0, idle_limit=900.0,
                            deadline=0.0, written=18 * 1024 ** 3,
                            files=120000, processes=3)

    def test_the_question_offers_all_three_outcomes(self):
        answers = []

        class _Worker:
            def answer_stall(self, verdict):  # noqa: ANN001
                answers.append(verdict)

        self.window.worker = _Worker()
        self._answer("Подождать")
        self._answer("Прекратить")
        self._answer("Отменить")
        self.assertEqual(answers, [STALL_WAIT, STALL_STOP, STALL_CANCEL])

    def test_a_closed_question_does_not_wait_forever(self):
        answers = []
        self.window.worker = type("W", (), {
            "answer_stall": lambda _self, verdict: answers.append(verdict)})()
        with mock.patch.object(QMessageBox, "exec", lambda box: 0), \
                mock.patch.object(QMessageBox, "clickedButton",
                                  lambda box: None):
            self.window._on_stall(self._stall())
        self.assertEqual(answers, [STALL_STOP])


@unittest.skipUnless(_QT_READY, f"PySide6/Qt недоступен: {_QT_ERROR}")
class WorkerQuestionTests(unittest.TestCase):
    """Рабочий поток действительно ждёт ответа интерфейса."""

    def setUp(self):
        from portablizer.gui.worker import PortableWorker

        self.worker = PortableWorker(PortableOptions(
            installer_path="setup.exe", output_dir=tempfile.gettempdir()))

    def _ask_in_background(self):
        result = {}
        stall = InstallStall(idle_limit=120.0, idle=120.0)

        def ask():
            result["verdict"] = self.worker._on_stall(stall)

        thread = threading.Thread(target=ask, daemon=True)
        thread.start()
        return thread, result

    def test_the_answer_is_delivered_to_the_waiting_thread(self):
        thread, result = self._ask_in_background()
        deadline = time.monotonic() + 5
        while "verdict" not in result and time.monotonic() < deadline:
            self.worker.answer_stall(STALL_WAIT)
            thread.join(timeout=0.05)
        self.assertEqual(result.get("verdict"), STALL_WAIT)

    def test_cancelling_the_build_frees_the_question(self):
        thread, result = self._ask_in_background()
        self.worker.cancel()
        thread.join(timeout=5)
        self.assertEqual(result.get("verdict"), STALL_CANCEL)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
