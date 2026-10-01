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
      * ``file``    — процесс держит открытым ФАЙЛ из папки (шрифт из
                      ``PortableData\\Temp``, лог, сохранение, база);
      * ``service`` — служба Windows, чей бинарник лежит в папке.

    ``handle`` заполняется только для ``file``: по этому номеру дескриптор
    можно закрыть прямо в чужом процессе, не убивая сам процесс.
    """

    pid: int
    image: str
    kind: str
    detail: str = ""
    handle: int = 0

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


# --- открытые файлы: кто держит папку на уровне дескрипторов ------------------
#
# Сравнение путей процессов и обход загруженных модулей отвечают только на
# вопрос «чей это exe/dll». Но папку держит ЛЮБОЙ открытый в ней файл: шрифт
# из `PortableData\Temp\is-XXXX.tmp`, который подхватила служба кэша шрифтов,
# лог, открытый антивирусом, сохранение, которое читает индексатор. Процесса
# «из папки» при этом нет вообще — пользователь видит «виновника определить
# не удалось», хотя папка намертво занята. Единственный честный ответ даёт
# таблица дескрипторов ядра: ниже она читается целиком, каждый файловый
# дескриптор превращается в обычный путь, и всё, что лежит внутри папки,
# становится видно по имени — с номером процесса и номером дескриптора.

#: NtQuerySystemInformation(SystemExtendedHandleInformation)
_SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_PROCESS_DUP_HANDLE = 0x0040
_DUPLICATE_SAME_ACCESS = 0x00000002
_DUPLICATE_CLOSE_SOURCE = 0x00000001
_FILE_TYPE_DISK = 0x0001
#: Код ошибки «файл занят другим процессом» и его «блокировочный» двойник.
_ERROR_SHARING_VIOLATION = 32
_ERROR_LOCK_VIOLATION = 33


class OpenFile(NamedTuple):
    """Открытый файл внутри папки: кто, каким дескриптором и что держит."""

    pid: int
    handle: int
    path: str
    image: str = ""

    @property
    def name(self) -> str:
        return image_name(self.image or "")

    @property
    def protected(self) -> bool:
        return self.name.casefold() in PROTECTED_IMAGES


def enable_debug_privilege() -> bool:
    """Включает SeDebugPrivilege: без него не видны дескрипторы чужих служб.

    Привилегия есть только у администратора; для обычного пользователя вызов
    молча возвращает False, и мы просто увидим меньше держателей.
    """
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD),
                        ("HighPart", ctypes.c_long)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
            return False
        try:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                                  ctypes.byref(luid)):
                return False
            privileges = TOKEN_PRIVILEGES()
            privileges.PrivilegeCount = 1
            privileges.Privileges[0].Luid = luid
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            if not advapi32.AdjustTokenPrivileges(
                    token, False, ctypes.byref(privileges), 0, None, None):
                return False
            return kernel32.GetLastError() == 0
        finally:
            kernel32.CloseHandle(token)
    except Exception:  # noqa: BLE001
        return False


def _handle_table() -> List[Tuple[int, int, int]]:
    """Вся таблица дескрипторов системы: ``(pid, дескриптор, тип)``."""
    if not IS_WINDOWS:
        return []
    try:
        import ctypes
        from ctypes import wintypes

        class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
            _fields_ = [
                ("Object", ctypes.c_void_p),
                ("UniqueProcessId", ctypes.c_size_t),
                ("HandleValue", ctypes.c_size_t),
                ("GrantedAccess", wintypes.ULONG),
                ("CreatorBackTraceIndex", wintypes.USHORT),
                ("ObjectTypeIndex", wintypes.USHORT),
                ("HandleAttributes", wintypes.ULONG),
                ("Reserved", wintypes.ULONG),
            ]

        class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
            _fields_ = [
                ("NumberOfHandles", ctypes.c_size_t),
                ("Reserved", ctypes.c_size_t),
                ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
            ]

        ntdll = ctypes.windll.ntdll  # type: ignore[attr-defined]
        size = 1 << 20
        for _attempt in range(12):
            buffer = ctypes.create_string_buffer(size)
            needed = wintypes.ULONG(0)
            status = ntdll.NtQuerySystemInformation(
                _SYSTEM_EXTENDED_HANDLE_INFORMATION, buffer, size,
                ctypes.byref(needed))
            if status == 0:
                break
            if status & 0xFFFFFFFF != _STATUS_INFO_LENGTH_MISMATCH:
                return []
            size = max(int(needed.value) + (1 << 20), size * 2)
        else:
            return []

        header = ctypes.cast(
            buffer, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION_EX)).contents
        count = int(header.NumberOfHandles)
        if count <= 0:
            return []
        offset = SYSTEM_HANDLE_INFORMATION_EX.Handles.offset
        entries = ctypes.cast(
            ctypes.byref(buffer, offset),
            ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * count)).contents
        return [(int(e.UniqueProcessId), int(e.HandleValue),
                 int(e.ObjectTypeIndex)) for e in entries]
    except Exception:  # noqa: BLE001
        return []


def _file_type_index(table: Sequence[Tuple[int, int, int]]) -> int:
    """Номер типа «File» в этой системе (он не постоянен между версиями).

    Определяется честно: открываем собственный файл и смотрим, какой тип
    у нашего же дескриптора в общей таблице. Так не нужен ни NtQueryObject,
    ни зашитая константа, которая меняется от сборки к сборке Windows.
    """
    if not IS_WINDOWS or not table:
        return -1
    try:
        import ctypes
        import tempfile

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        own = os.getpid()
        fd, path = tempfile.mkstemp(prefix="portablizer-probe-")
        try:
            handle = kernel32.CreateFileW(path, 0x80000000, 7, None, 3,
                                          0x80, None) or 0
            if not handle or handle == ctypes.c_void_p(-1).value:
                return -1
            try:
                for pid, value, kind in table:
                    if pid == own and value == int(handle):
                        return kind
            finally:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
        finally:
            os.close(fd)
            try:
                os.unlink(path)
            except OSError:
                pass
    except Exception:  # noqa: BLE001
        return -1
    return -1


def _path_of_handle(duplicate: int) -> str:
    """Обычный путь файла по дескриптору (``GetFinalPathNameByHandleW``)."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        if kernel32.GetFileType(duplicate) != _FILE_TYPE_DISK:
            # Каналы (pipe), сокеты и консоли папку не держат, а опрос их
            # имени умеет зависать намертво — такие дескрипторы пропускаем.
            return ""
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel32.GetFinalPathNameByHandleW(
            duplicate, buffer, 32767, 0)
        if not length or length > 32767:
            return ""
        path = buffer.value
        for prefix in ("\\\\?\\UNC\\", "\\\\?\\"):
            if path.startswith(prefix):
                path = ("\\\\" + path[len(prefix):]) if "UNC" in prefix \
                    else path[len(prefix):]
                break
        return path
    except Exception:  # noqa: BLE001
        return ""


def open_files_in(root: str, budget: float = 20.0) -> List[OpenFile]:
    """Все открытые файлы внутри ``root``: ``(pid, дескриптор, путь)``.

    Это и есть ответ на вопрос «почему папка не удаляется», когда из неё
    ничего не запущено. Обход таблицы дескрипторов системы стоит секунд,
    поэтому он ограничен бюджетом: неполный список лучше зависшей программы.
    """
    if not IS_WINDOWS or not root:
        return []
    enable_debug_privilege()
    table = _handle_table()
    if not table:
        return []
    wanted_type = _file_type_index(table)
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        own = os.getpid()
        # HANDLE шире int: без restype псевдодескриптор текущего процесса
        # приедет в DuplicateHandle обрезанным.
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.restype = ctypes.c_void_p
        current = ctypes.c_void_p(kernel32.GetCurrentProcess())
        deadline = time.monotonic() + budget
        found: List[OpenFile] = []
        opened: dict = {}
        try:
            for pid, value, kind in table:
                if time.monotonic() > deadline:
                    break
                if pid in (0, 4, own) or not value:
                    continue
                if wanted_type >= 0 and kind != wanted_type:
                    continue
                process = opened.get(pid, -1)
                if process == -1:
                    process = kernel32.OpenProcess(
                        _PROCESS_DUP_HANDLE, False, pid) or 0
                    opened[pid] = process
                if not process:
                    continue
                duplicate = ctypes.c_void_p()
                if not kernel32.DuplicateHandle(
                        ctypes.c_void_p(process), ctypes.c_void_p(value),
                        current, ctypes.byref(duplicate), 0, False,
                        _DUPLICATE_SAME_ACCESS):
                    continue
                try:
                    path = _path_of_handle(duplicate)
                finally:
                    kernel32.CloseHandle(duplicate)
                if path and is_inside(path, root):
                    found.append(OpenFile(pid, value, path))
        finally:
            for process in opened.values():
                if process:
                    kernel32.CloseHandle(ctypes.c_void_p(process))
        if not found:
            return []
        images = {pid: image for pid, image in _snapshot()}
        return [item._replace(image=images.get(item.pid, ""))
                for item in found]
    except Exception:  # noqa: BLE001
        return []


def close_remote_handle(pid: int, handle: int) -> bool:
    """Закрывает чужой дескриптор, не трогая сам процесс.

    Единственный способ отпустить файл, который держит системный процесс
    (служба кэша шрифтов, индексатор, проводник): убивать его нельзя, а
    файл обязан освободиться. Требует прав администратора.
    """
    if not IS_WINDOWS or not pid or not handle:
        return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.restype = ctypes.c_void_p
        process = kernel32.OpenProcess(_PROCESS_DUP_HANDLE, False, int(pid))
        if not process:
            return False
        try:
            duplicate = ctypes.c_void_p()
            return bool(kernel32.DuplicateHandle(
                ctypes.c_void_p(process), ctypes.c_void_p(int(handle)),
                ctypes.c_void_p(kernel32.GetCurrentProcess()),
                ctypes.byref(duplicate), 0, False,
                _DUPLICATE_CLOSE_SOURCE)) and bool(
                    kernel32.CloseHandle(duplicate))
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(process))
    except Exception:  # noqa: BLE001
        return False


def visible_window_pids() -> set:
    """PID-ы, у которых есть видимое окно: такие процессы — это пользователь.

    Их нельзя завершать молча: за окном может быть открытый документ. Всё
    остальное, что держит папку, — фон (апдейтер, служба, «помощник»).
    """
    if not IS_WINDOWS:
        return set()
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        found: set = set()
        callback_type = ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def collect(hwnd, _lparam):  # pragma: no cover - нужен рабочий стол
            if user32.IsWindowVisible(hwnd):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    found.add(int(pid.value))
            return True

        user32.EnumWindows(callback_type(collect), 0)
        return found
    except Exception:  # noqa: BLE001
        return set()


def installed_software_image(image: str) -> bool:
    """Лежит ли программа в системных каталогах или в Program Files.

    Такие программы — не «остатки портатива», а установленное на этом ПК
    хозяйство: антивирус, служба резервного копирования, синхронизация
    облака. Файл портатива они могут держать совершенно законно (сканируют
    или индексируют), и завершать их нельзя — у них нужно только отобрать
    дескриптор.
    """
    if not image:
        return True
    normalized = str(image).replace("/", "\\").casefold()
    roots = [os.environ.get(name, "") for name in
             ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)",
              "ProgramW6432", "windir")]
    roots.extend([r"c:\windows", r"c:\program files",
                  r"c:\program files (x86)"])
    for folder in roots:
        if folder and normalized.startswith(
                str(folder).replace("/", "\\").rstrip("\\").casefold() + "\\"):
            return True
    return False


def busy_files(root: str, budget: float = 8.0, limit: int = 20,
               recheck: float = 0.4) -> List[str]:
    """Файлы внутри папки, которые Windows прямо сейчас не отдаёт.

    Проверка делом и без всяких прав: файл открывается на монопольный
    доступ. ``ERROR_SHARING_VIOLATION`` означает ровно то, с чем приходит
    пользователь, — «файл открыт в другой программе», то есть папку не
    удалить. Мгновенные блокировки (антивирус пробежал по файлу) отсеиваются
    повторной проверкой через ``recheck`` секунд.
    """
    if not IS_WINDOWS or not root or not os.path.isdir(root):
        return []
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        invalid = ctypes.c_void_p(-1).value
        # Без явного restype ctypes обрежет HANDLE до 32-битного int, и
        # «не удалось открыть» станет неотличимо от удачи.
        kernel32.CreateFileW.restype = ctypes.c_void_p

        def locked(path: str) -> bool:
            handle = kernel32.CreateFileW(path, 0x80000000, 0, None, 3,
                                          0x80, None)
            # Код ошибки читается сразу: любое действие между вызовами
            # может его затереть.
            error = kernel32.GetLastError()
            if handle in (None, 0, invalid):
                return error in (_ERROR_SHARING_VIOLATION,
                                 _ERROR_LOCK_VIOLATION)
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return False

        deadline = time.monotonic() + budget
        suspects: List[str] = []
        for current, _dirs, files in os.walk(root):
            if time.monotonic() > deadline or len(suspects) >= limit:
                break
            for name in files:
                path = os.path.join(current, name)
                if locked(path):
                    suspects.append(path)
                    if len(suspects) >= limit:
                        break
                if time.monotonic() > deadline:
                    break
        if not suspects:
            return []
        time.sleep(recheck)
        return [path for path in suspects if locked(path)]
    except Exception:  # noqa: BLE001
        return []


def forget_fonts(root: str, budget: float = 4.0) -> int:
    """Снимает с регистрации шрифты, подключённые из этой папки.

    Установщики (Inno Setup и его `is-XXXX.tmp`) подключают свои шрифты
    через ``AddFontResource``. После выхода установщика файл остаётся
    открытым службой кэша шрифтов, и папка не удаляется — причём процесса
    «из папки» уже нет. ``RemoveFontResource`` снимает регистрацию, и
    система отпускает файл.
    """
    if not IS_WINDOWS or not root or not os.path.isdir(root):
        return 0
    try:
        import ctypes

        gdi32 = ctypes.windll.gdi32  # type: ignore[attr-defined]
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        HWND_BROADCAST = 0xFFFF
        WM_FONTCHANGE = 0x001D
        extensions = (".ttf", ".ttc", ".otf", ".fon", ".fnt")
        deadline = time.monotonic() + budget
        removed = 0
        for current, _dirs, files in os.walk(root):
            if time.monotonic() > deadline:
                break
            for name in files:
                if not name.casefold().endswith(extensions):
                    continue
                path = os.path.join(current, name)
                for _repeat in range(8):
                    if not gdi32.RemoveFontResourceW(path):
                        break
                    removed += 1
        if removed:
            user32.PostMessageW(HWND_BROADCAST, WM_FONTCHANGE, 0, 0)
        return removed
    except Exception:  # noqa: BLE001
        return 0


def release_open_files(root: str, close_grace: float = 2.0,
                       budget: float = 20.0) -> List[str]:
    """Отпускает файлы папки, открытые процессами снаружи.

    Правило простое и безопасное:

    * безымянный фоновый «помощник» (без окна, запущен не из системных
      папок) — завершаем: это и есть остаток портатива, ради которого всё
      затевалось;
    * системный процесс Windows или установленная программа (антивирус,
      индексатор, синхронизация облака) — не трогаем, но ЗАКРЫВАЕМ её
      дескриптор на наш файл: это переживают все, а папка освобождается;
    * окно пользователя (редактор, файловый менеджер) — не трогаем вообще,
      только называем в отчёте: за ним может быть несохранённый документ.
    """
    if not IS_WINDOWS:
        return []
    files = open_files_in(root, budget=budget)
    if not files:
        return []
    visible = visible_window_pids()
    stopped: List[str] = []

    background = sorted({item.pid for item in files
                         if not item.protected and item.pid not in visible
                         and not installed_software_image(item.image)})
    if background:
        names = sorted({image_name(item.image) or f"pid {item.pid}"
                        for item in files if item.pid in background})
        # Сначала вежливо, затем принудительно. Повторный обход таблицы
        # дескрипторов между этими шагами стоил бы секунд на каждый круг,
        # поэтому пауза фиксированная: кто успел уйти сам — уйдёт, кого
        # нет, тот будет завершён (его уже нет среди живых процессов).
        _post_close(background)
        if close_grace > 0:
            time.sleep(close_grace)
        _terminate(background)
        time.sleep(0.3)
        stopped.extend(f"{name} (держал файл)" for name in names)

    # Всё, что осталось: системные процессы и чужие окна. Процесс не трогаем,
    # закрываем только сам дескриптор нашего файла.
    for item in open_files_in(root, budget=min(budget, 10.0)):
        if close_remote_handle(item.pid, item.handle):
            stopped.append(
                f"{item.name or ('pid ' + str(item.pid))}: освобождён файл "
                f"{os.path.basename(item.path)}")
    return stopped


def release_folder(root: str, close_grace: float = 4.0,
                   kill_grace: float = 3.0,
                   stop_services: bool = True,
                   deep: bool = True,
                   budget: float = 20.0) -> List[str]:
    """Остановить всё, что запущено из ``root``; вернуть имена остановленного.

    Порядок важен:

    1. **Службы.** Если бинарник службы лежит в папке, убивать процесс
       бесполезно — диспетчер служб поднимет его снова, и папка останется
       занятой навсегда. Службу нужно остановить и снять с регистрации.
    2. **Вежливое закрытие.** Окнам посылается ``WM_CLOSE``: программа
       успевает сохранить настройки (для сборки это важно — именно эти
       настройки потом уезжают в портатив).
    3. **Принудительное завершение** для тех, кто не ушёл сам.
    4. **Открытые файлы.** Процессов из папки больше нет, а файлы внутри
       может держать кто угодно снаружи: служба кэша шрифтов подхватила
       шрифт из ``PortableData\\Temp``, антивирус читает лог, индексатор
       открыл сохранение. Фоновые держатели завершаются, системным
       закрывается только сам дескриптор (``deep=False`` отключает этот
       разбор, если нужна скорость).
    """
    if not IS_WINDOWS:
        return []
    stopped: List[str] = []

    if stop_services:
        for service in services_in(root):
            stop_service(service, remove=True)
            stopped.append(f"служба {service}")

    running = processes_in(root)
    if running:
        stopped.extend(image_name(image) for _, image in running)

        _post_close(pid for pid, _ in running)
        deadline = time.monotonic() + close_grace
        while time.monotonic() < deadline:
            if not processes_in(root):
                break
            time.sleep(0.25)

        running = processes_in(root)
        if running:
            _terminate(pid for pid, _ in running)
            deadline = time.monotonic() + kill_grace
            while time.monotonic() < deadline and processes_in(root):
                time.sleep(0.25)

    if deep and busy_files(root, budget=min(budget, 4.0)):
        # Дорогой разбор включается только по делу: если ни один файл в
        # папке не занят, обходить таблицу дескрипторов системы незачем.
        # Шрифты снимаются с регистрации первыми: часто этого достаточно,
        # и закрывать чужие дескрипторы не приходится.
        forget_fonts(root)
        stopped.extend(release_open_files(root, budget=budget))
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

    known = {holder.pid for holder in found}
    for pid, image in items:
        if pid in known:
            continue
        for module in modules_of(pid):
            if is_inside(module, root):
                found.append(Holder(pid, image, "module", module))
                known.add(pid)
                break

    # Самый частый и самый непонятный случай: ни exe, ни DLL из папки нет,
    # а внутри открыт обычный файл (шрифт, лог, сохранение). Без разбора
    # дескрипторов пользователю говорили «виновника определить не удалось».
    for item in open_files_in(root):
        found.append(Holder(item.pid, item.image or f"pid {item.pid}",
                            "file", item.path, item.handle))
    return found


def describe_holders(items: Iterable[Holder]) -> List[str]:
    """Человеческие имена держателей папки — то, что увидит пользователь.

    Пользователю нужно не «pid 17208», а ответ на вопрос «что закрыть».
    Поэтому у чужой DLL называется сама DLL, а у открытого файла — его имя
    и номер процесса: по ним держателя видно в диспетчере задач.
    """
    described = set()
    for item in items:
        if item.kind == "module":
            described.add(
                f"{item.name} (держит {image_name(item.detail)})")
        elif item.kind == "file":
            described.add(
                f"{item.name} (pid {item.pid}, открыт файл "
                f"{image_name(item.detail)})")
        else:
            described.add(item.name)
    return sorted(described)


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


def folder_is_free(root: str, errors: Optional[List[str]] = None,
                   deep: bool = True, budget: float = 8.0) -> bool:
    """Честная проверка «папку можно удалить»: переименование + файлы.

    Одного пробного переименования МАЛО, и именно на этом программа раньше
    врала пользователю. Файл, открытый с флагом ``FILE_SHARE_DELETE``
    (так открывают шрифты, файлы, отображённые в память, журналы
    антивируса), не мешает переименовать каталог — проба проходит, а
    удаление всё равно обрывается на «файл открыт в другой программе».

    Поэтому проверка двойная:

    1. пробное переименование — ловит классическую занятость каталога;
    2. попытка открыть каждый файл внутри на монопольный доступ — ловит
       ровно те открытые файлы, из-за которых папка не удаляется.

    ``deep=False`` оставляет только первую, быструю пробу. В ``errors``,
    если он передан, попадает текст ошибки или список занятых файлов — по
    нему видно, действительно ли файл занят или, например, родительская
    папка доступна только на чтение.
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
    except OSError as exc:
        # Текст ошибки важен вызывающему: «папка занята» (sharing violation)
        # и «нет прав на запись в родительский каталог» выглядят одинаково,
        # но означают разное, и пользователю нельзя говорить второе первым.
        if errors is not None:
            errors.append(f"{exc.__class__.__name__}: {exc}")
        return False
    # Имя обязано вернуться на место при любом исходе: пользователь не должен
    # обнаружить свою папку переименованной из-за диагностики.
    restored = False
    for attempt in range(10):
        try:
            os.rename(probe, root)
            restored = True
            break
        except OSError:  # pragma: no cover - крайне маловероятно
            time.sleep(0.2 * (attempt + 1))
    if not restored:
        return False
    if not deep:
        return True

    locked = busy_files(root, budget=budget)
    if locked:
        if errors is not None:
            errors.append("Открытые файлы: " + ", ".join(locked[:8]))
        return False
    return True
