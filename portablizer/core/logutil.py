"""Простой потокобезопасный логгер с трансляцией сообщений в GUI.

Логика ядра ничего не знает о Qt: она лишь дергает callback `emit`, а GUI
подписывается на него. Это позволяет запускать ядро и из командной строки.
"""
from __future__ import annotations

import datetime as _dt
import threading
from typing import Callable, List, Optional

LogSink = Callable[[str, str], None]  # (level, message)


class Logger:
    """Минималистичный логгер: пишет в память, в файл и в подписчиков."""

    LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "OK")

    def __init__(self, logfile: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._sinks: List[LogSink] = []
        self._buffer: List[str] = []
        self._logfile = logfile

    def add_sink(self, sink: LogSink) -> None:
        with self._lock:
            self._sinks.append(sink)

    def _write(self, level: str, message: str) -> None:
        ts = _dt.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {level:<5} {message}"
        with self._lock:
            self._buffer.append(line)
            if self._logfile:
                try:
                    with open(self._logfile, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                except OSError:
                    pass
            sinks = list(self._sinks)
        for sink in sinks:
            try:
                sink(level, message)
            except Exception:  # noqa: BLE001 - GUI-подписчик не должен ронять ядро
                pass

    def debug(self, msg: str) -> None:
        self._write("DEBUG", msg)

    def info(self, msg: str) -> None:
        self._write("INFO", msg)

    def warn(self, msg: str) -> None:
        self._write("WARN", msg)

    def error(self, msg: str) -> None:
        self._write("ERROR", msg)

    def ok(self, msg: str) -> None:
        self._write("OK", msg)

    @property
    def text(self) -> str:
        with self._lock:
            return "\n".join(self._buffer)
