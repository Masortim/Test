"""QThread-обёртка для запуска ядра Portablizer без блокировки интерфейса."""
from __future__ import annotations

import threading
import time
from typing import Optional

from PySide6.QtCore import QThread, Signal

from ..core import maintenance
from ..core.logutil import Logger
from ..core.portablizer import (
    STALL_CANCEL, STALL_STOP, InstallStall, PortableOptions, PortableResult,
    Portablizer,
)

#: Сколько ждём ответа интерфейса на вопрос «ждать ещё?». Заведомо больше
#: любого человеческого раздумья: предел нужен лишь для того, чтобы сборка не
#: осталась ждать навсегда, если окно с вопросом потерялось.
STALL_ANSWER_TIMEOUT = 30 * 60


class PortableWorker(QThread):
    log_line = Signal(str, str)          # level, message
    progress = Signal(int, str)          # percent, stage
    detail = Signal(int, str)            # percent (-1 — неизвестен), операция
    #: Установка замолчала: «ждать ещё?» Ответ — ``answer_stall()``.
    stall = Signal(object)               # InstallStall
    finished_result = Signal(object)     # PortableResult

    def __init__(self, opts: PortableOptions) -> None:
        super().__init__()
        self.opts = opts
        self.cancel_event = threading.Event()
        self.logger = Logger()
        self.logger.add_sink(lambda lvl, msg: self.log_line.emit(lvl, msg))
        #: Ответ на вопрос о затишье (см. ``stall``) и признак его готовности.
        self._stall_answer: Optional[str] = None
        self._stall_ready = threading.Event()

    def cancel(self) -> None:
        self.cancel_event.set()

    def answer_stall(self, verdict: str) -> None:
        """Ответ интерфейса: ``STALL_WAIT``, ``STALL_STOP`` или ``STALL_CANCEL``."""
        self._stall_answer = verdict
        self._stall_ready.set()

    def _on_stall(self, stall: InstallStall) -> str:
        """Спрашивает человека, ждать ли ещё, и терпеливо ждёт его ответа.

        Вызывается из рабочего потока: интерфейсу уходит сигнал (слот
        отработает в главном потоке, окно не замерзает), а здесь ожидание идёт
        короткими шагами — чтобы кнопка «Отмена» работала, пока вопрос открыт.
        """
        self._stall_answer = None
        self._stall_ready.clear()
        self.stall.emit(stall)
        deadline = time.monotonic() + STALL_ANSWER_TIMEOUT
        while not self._stall_ready.wait(timeout=0.2):
            if self.cancel_event.is_set():
                return STALL_CANCEL
            if time.monotonic() > deadline:
                # Интерфейс так и не ответил (окно закрыли, диалог потерялся):
                # ждать дальше вслепую нельзя — считаем, что ждать не нужно.
                return STALL_STOP
        if self.cancel_event.is_set():
            return STALL_CANCEL
        return self._stall_answer or STALL_STOP

    def run(self) -> None:  # noqa: D401 - QThread entrypoint
        engine = Portablizer(
            logger=self.logger,
            progress=lambda p, s: self.progress.emit(p, s),
            cancel_event=self.cancel_event,
            detail=lambda p, s: self.detail.emit(p, s),
            on_stall=self._on_stall,
        )
        result: PortableResult = engine.run(self.opts)
        self.finished_result.emit(result)


class MaintenanceWorker(QThread):
    """Обслуживание готовой папки портатива в фоне.

    Освобождение папки может занять секунды (вежливое закрытие окон,
    остановка службы, поиск держателей), а интерфейс в это время обязан
    оставаться живым.
    """

    log_line = Signal(str, str)              # level, message
    finished_report = Signal(object)         # MaintenanceReport

    def __init__(self, folder: str, action: str, installer: str = "",
                 language: str = "") -> None:
        super().__init__()
        self.folder = folder
        self.action = action                 # "release" | "refresh" | "update"
        self.installer = installer           # для "update": файл или ссылка
        self.language = language             # для "refresh": код языка ("ru" и т.п.)
        self.logger = Logger()
        self.logger.add_sink(lambda lvl, msg: self.log_line.emit(lvl, msg))

    def run(self) -> None:  # noqa: D401 - QThread entrypoint
        if self.action == "refresh":
            engine = Portablizer(logger=self.logger)
            report = maintenance.refresh(
                self.folder, self.logger,
                copy_exe=lambda folder, rel: engine._copy_exe_launcher(
                    folder, rel),
                language=self.language,
            )
        elif self.action == "update":
            report = maintenance.update_app(
                self.folder, self.installer, self.logger)
        else:
            report = maintenance.release(self.folder, self.logger)
        self.finished_report.emit(report)
