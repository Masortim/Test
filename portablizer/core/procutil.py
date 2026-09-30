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
from typing import Iterable, List, NamedTuple, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform.startswith("win")

#: (pid, полный путь к образу процесса)
ProcessInfo = Tuple[int, str]

#: Процессы Windows, которые нельзя ни закрывать, ни завершать: снятие любого
#: из них равносильно порче сеанса пользователя. Если такой процесс держит
#: файл из портатива (обычно это подгруженная DLL-расширение оболочки или
#: индексатор), мы только называем его в отчёте.
PROTECTED_IMAGES = frozenset({
    "explorer.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "services.exe",
    "lsass.exe", "smss.exe", "svchost.exe", "dwm.exe", "taskhostw.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "sihost.exe", "fontdrvhost.exe", "runtimebroker.exe", "ctfmon.exe",
    "msmpeng.exe", "mssense.exe", "securityhealthservice.exe",
    "system", "registry", "memory compression", "idle",
})


class Holder(NamedTuple):
    """Кто и чем держит папку.

    ``kind``:
      * ``exe``     — сам процесс запущен из папки;
      * ``module``  — процесс живёт снаружи, но подгрузил DLL из папки
                      (расширение оболочки, хук, антивирусный сканер);
      * ``service`` — служба Windows, чей бинарник лежит в папке.
    """

    pid: int
    image: str
    kind: str
    detail: str = ""

    @property
    def name(self) -> str:
        return image_name(self.image)

    @property
    def protected(self) -> bool:
        return self.name.casefold() in PROTECTED_IMAGES


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
                   kill_grace: float = 3.0,
                   stop_services: bool = True) -> List[str]:
    """Остановить всё, что запущено из ``root``; вернуть имена остановленного.

    Порядок важен:

    1. **Службы.** Если бинарник службы лежит в папке, убивать процесс
       бесполезно — диспетчер служб поднимет его снова, и папка останется
       занятой навсегда. Службу нужно остановить и снять с регистрации.
    2. **Вежливое закрытие.** Окнам посылается ``WM_CLOSE``: программа
       успевает сохранить настройки (для сборки это важно — именно эти
       настройки потом уезжают в портатив).
    3. **Принудительное завершение** для тех, кто не ушёл сам.
    """
    if not IS_WINDOWS:
        return []
    stopped: List[str] = []

    if stop_services:
        for service in services_in(root):
            stop_service(service, remove=True)
            stopped.append(f"служба {service}")

    running = processes_in(root)
    if not running:
        return stopped
    stopped.extend(image_name(image) for _, image in running)

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


# --- кто ещё держит папку -----------------------------------------------------

def modules_of(pid: int) -> List[str]:
    """Пути всех модулей (DLL), загруженных процессом.

    Нужно для случая, который не ловится сравнением путей самих процессов:
    программа давно закрыта, но её DLL подгрузил кто-то снаружи — проводник
    (расширение контекстного меню), антивирус, хук ввода. Файл остаётся
    занятым, и папка не удаляется, хотя «процессов из папки» нет.
    """
    if not IS_WINDOWS:
        return []
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPMODULE = 0x00000008
        TH32CS_SNAPMODULE32 = 0x00000010
        MAX_PATH = 260

        class MODULEENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", wintypes.HMODULE),
                ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * MAX_PATH),
            ]

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        snap = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, int(pid))
        if snap in (0, -1, None):
            return []
        modules: List[str] = []
        try:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
            more = kernel32.Module32FirstW(snap, ctypes.byref(entry))
            while more and len(modules) < 4096:
                modules.append(entry.szExePath)
                more = kernel32.Module32NextW(snap, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snap)
        return modules
    except Exception:  # noqa: BLE001
        return []


def holders(root: str, snapshot: Optional[Sequence[ProcessInfo]] = None,
            deep: bool = True) -> List[Holder]:
    """Всё, что держит папку: процессы из неё, чужие процессы с её DLL, службы.

    ``deep=False`` отключает дорогой обход модулей (перебор всех процессов
    системы) — он нужен только тогда, когда папка действительно не
    освобождается.
    """
    items = _snapshot() if snapshot is None else list(snapshot)
    found = [Holder(pid, image, "exe") for pid, image in items
             if is_inside(image, root)]
    if not deep:
        return found

    known = {pid for pid, _, _, _ in found}
    for pid, image in items:
        if pid in known:
            continue
        for module in modules_of(pid):
            if is_inside(module, root):
                found.append(Holder(pid, image, "module", module))
                break
    return found


def service_image_path(raw: str) -> str:
    """Путь к бинарнику службы из значения ``ImagePath``.

    Значение приходит в самых разных видах: в кавычках, с аргументами
    командной строки, с NT-префиксом ``\\??\\`` у драйверов и с
    ``\\SystemRoot\\`` у системных служб. Нам нужен только путь к exe.
    """
    candidate = str(raw).strip()
    if candidate.startswith('"'):
        # Путь в кавычках: всё до закрывающей кавычки, остальное — аргументы.
        closing = candidate.find('"', 1)
        return candidate[1:closing] if closing > 1 else candidate.strip('"')
    candidate = candidate.replace("\\??\\", "")
    if candidate.casefold().startswith("\\systemroot"):
        return ""
    cut = candidate.casefold().find(".exe")
    if cut > 0:
        return candidate[:cut + 4]
    return candidate.split(" ")[0]


def services_in(root: str) -> List[str]:
    """Имена служб Windows, чей исполняемый файл лежит внутри папки.

    Игровая защита, «обновлятор» и подобное регистрируются службой. Убивать
    такой процесс бесполезно: диспетчер служб немедленно поднимет его снова,
    и папка останется занятой навсегда.
    """
    if not IS_WINDOWS:
        return []
    try:
        import winreg  # type: ignore

        names: List[str] = []
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services") as services:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(services, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(services, name) as key:
                        path, _type = winreg.QueryValueEx(key, "ImagePath")
                except OSError:
                    continue
                if is_inside(service_image_path(str(path)), root):
                    names.append(name)
        return names
    except Exception:  # noqa: BLE001
        return []


def stop_service(name: str, remove: bool = False, timeout: float = 15.0
                 ) -> bool:
    """Останавливает (и по желанию удаляет) службу. True — её больше нет."""
    if not IS_WINDOWS:
        return False
    import subprocess

    no_window = 0x08000000

    def run(args: Sequence[str]) -> int:
        try:
            return subprocess.run(["sc", *args], creationflags=no_window,
                                  capture_output=True, timeout=timeout).returncode
        except Exception:  # noqa: BLE001
            return 1

    run(["stop", name])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            probe = subprocess.run(["sc", "query", name], creationflags=no_window,
                                   capture_output=True, timeout=timeout)
        except Exception:  # noqa: BLE001
            break
        if b"STOPPED" in probe.stdout.upper() or probe.returncode != 0:
            break
        time.sleep(0.5)
    if remove:
        run(["delete", name])
    return True


def folder_is_free(root: str) -> bool:
    """Честная проверка «папку можно удалить»: пробное переименование.

    Windows не даёт переименовать каталог, внутри которого открыт хотя бы
    один файл, — то же самое условие, что и для удаления. Поэтому проба
    переименования отвечает на вопрос пользователя («я хочу удалить папку»)
    точнее любого перебора процессов и не зависит от того, кто именно её
    держит: процесс, служба или подгруженная DLL.

    Вызывающий не должен находиться внутри проверяемой папки.
    """
    if not root or not os.path.isdir(root):
        return True
    probe = os.path.join(os.path.dirname(os.path.normpath(root)),
                         "." + os.path.basename(os.path.normpath(root))
                         + ".free-probe")
    try:
        if os.path.exists(probe):
            return False
        os.rename(root, probe)
    except OSError:
        return False
    # Имя обязано вернуться на место при любом исходе: пользователь не должен
    # обнаружить свою папку переименованной из-за диагностики.
    for attempt in range(10):
        try:
            os.rename(probe, root)
            return True
        except OSError:  # pragma: no cover - крайне маловероятно
            time.sleep(0.2 * (attempt + 1))
    return False
