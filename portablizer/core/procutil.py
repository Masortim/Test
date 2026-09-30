"""Процессы, запущенные из папки: найти, вежливо закрыть, освободить папку.

Зачем это нужно сборщику
------------------------
Установщики любят закончить работу галочкой «Запустить программу сейчас», а
некоторые движки (InstallShield, NSIS-обёртки, игровые лаунчеры) оставляют
после себя фоновые помощники: апдейтер, служба защиты, «crash reporter».
Все они лежат уже ВНУТРИ будущего портатива, держат его файлы открытыми и
ломают сборку двумя способами:

* повторная сборка падает на очистке старого ``App`` («файл занят другим
  процессом»);
* готовая папка не удаляется и не копируется на флешку.

Поэтому Portablizer перед очисткой и после установки сам закрывает всё, что
запущено из папки результата. Модуль работает только на Windows и на любой
ошибке молча возвращает пустой результат: сборка не должна падать из-за
диагностики процессов.
"""
from __future__ import annotations

import os
import sys
import time
from typing import Iterable, List, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform.startswith("win")

#: (pid, полный путь к образу процесса)
ProcessInfo = Tuple[int, str]


def image_name(image: str) -> str:
    """Имя файла процесса, каким бы разделителем его ни вернула система."""
    return str(image).replace("/", "\\").rsplit("\\", 1)[-1]


def _snapshot() -> List[ProcessInfo]:
    """Все процессы системы: ``(pid, путь к exe)``. Пустой список вне Windows."""
    if not IS_WINDOWS:
        return []
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPPROCESS = 0x00000002
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap in (0, -1, None):
            return []
        own = os.getpid()
        found: List[ProcessInfo] = []
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            more = kernel32.Process32FirstW(snap, ctypes.byref(entry))
            while more:
                pid = int(entry.th32ProcessID)
                if pid not in (0, 4, own):
                    handle = kernel32.OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                    if handle:
                        try:
                            size = wintypes.DWORD(32768)
                            buffer = ctypes.create_unicode_buffer(size.value)
                            if kernel32.QueryFullProcessImageNameW(
                                    handle, 0, buffer, ctypes.byref(size)):
                                found.append((pid, buffer.value))
                        finally:
                            kernel32.CloseHandle(handle)
                more = kernel32.Process32NextW(snap, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snap)
        return found
    except Exception:  # noqa: BLE001 - диагностика не вправе ронять сборку
        return []


def is_inside(image: str, root: str) -> bool:
    """Лежит ли образ процесса внутри папки ``root``.

    Сравнение идёт по строке с явным разделителем в конце: иначе
    ``C:\\Games\\App_Portable2`` считался бы частью ``C:\\Games\\App_Portable``.
    """
    if not image or not root:
        return False
    # Сравниваем строками, а не os.path: путь может прийти из чужого
    # снимка процессов (в т.ч. в тестах на другой ОС), а разделитель в
    # Windows-пути всегда обратный слеш.
    prefix = str(root).replace("/", "\\").rstrip("\\").casefold() + "\\"
    normalized = str(image).replace("/", "\\").casefold()
    return normalized.startswith(prefix)


def processes_in(root: str,
                 snapshot: Optional[Sequence[ProcessInfo]] = None
                 ) -> List[ProcessInfo]:
    """Процессы, чей exe лежит внутри ``root``."""
    items = _snapshot() if snapshot is None else list(snapshot)
    return [(pid, image) for pid, image in items if is_inside(image, root)]


def _post_close(pids: Iterable[int]) -> int:
    """Вежливая просьба закрыться: WM_CLOSE во все окна этих процессов."""
    if not IS_WINDOWS:
        return 0
    wanted = {int(pid) for pid in pids}
    if not wanted:
        return 0
    try:
        import ctypes
        from ctypes import wintypes

        WM_CLOSE = 0x0010
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        sent = 0
        callback_type = ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def collect(hwnd, _lparam):  # pragma: no cover - нужен рабочий стол
            nonlocal sent
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if int(pid.value) in wanted:
                user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
                sent += 1
            return True

        user32.EnumWindows(callback_type(collect), 0)
        return sent
    except Exception:  # noqa: BLE001
        return 0


def _terminate(pids: Iterable[int]) -> List[int]:
    """Принудительное завершение. Возвращает то, что удалось завершить."""
    if not IS_WINDOWS:
        return []
    killed: List[int] = []
    try:
        import ctypes

        PROCESS_TERMINATE = 0x0001
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        for pid in {int(p) for p in pids}:
            handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if not handle:
                continue
            try:
                if kernel32.TerminateProcess(handle, 0):
                    killed.append(pid)
            finally:
                kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001
        return killed
    return killed


def release_folder(root: str, close_grace: float = 4.0,
                   kill_grace: float = 3.0) -> List[str]:
    """Остановить всё, что запущено из ``root``; вернуть имена процессов.

    Сначала окнам посылается ``WM_CLOSE`` — программа успевает сохранить
    настройки (для сборки это важно: именно эти настройки потом уезжают в
    портатив). Кто не ушёл сам — завершается принудительно.
    """
    if not IS_WINDOWS:
        return []
    running = processes_in(root)
    if not running:
        return []
    stopped = [image_name(image) for _, image in running]

    _post_close(pid for pid, _ in running)
    deadline = time.monotonic() + close_grace
    while time.monotonic() < deadline:
        if not processes_in(root):
            return stopped
        time.sleep(0.25)

    running = processes_in(root)
    if running:
        _terminate(pid for pid, _ in running)
        deadline = time.monotonic() + kill_grace
        while time.monotonic() < deadline and processes_in(root):
            time.sleep(0.25)
    return stopped
