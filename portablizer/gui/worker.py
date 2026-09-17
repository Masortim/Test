"""QThread-обёртка для запуска ядра Portablizer без блокировки интерфейса."""
from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Signal

from ..core.logutil import Logger
from ..core.portablizer import PortableOptions, PortableResult, Portablizer


class PortableWorker(QThread):
    log_line = Signal(str, str)          # level, message
    progress = Signal(int, str)          # percent, stage
    finished_result = Signal(object)     # PortableResult

    def __init__(self, opts: PortableOptions) -> None:
        super().__init__()
        self.opts = opts
        self.cancel_event = threading.Event()
        self.logger = Logger()
        self.logger.add_sink(lambda lvl, msg: self.log_line.emit(lvl, msg))

    def cancel(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:  # noqa: D401 - QThread entrypoint
        engine = Portablizer(
            logger=self.logger,
            progress=lambda p, s: self.progress.emit(p, s),
            cancel_event=self.cancel_event,
        )
        result: PortableResult = engine.run(self.opts)
        self.finished_result.emit(result)
