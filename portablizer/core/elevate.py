"""Явный запрос прав администратора через UAC.

Повышение не выполняется автоматически при старте приложения. Установщики,
системные runtime-пакеты и запись в HKLM могут менять Windows, поэтому
Portablizer работает с обычными правами, пока пользователь сам не запустит
его «от имени администратора» либо явно не передаст CLI-флаг ``--elevate``.
Этот модуль оставлен как единый механизм такого явного перезапуска.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import List, Optional, Sequence

IS_WINDOWS = sys.platform.startswith("win")

#: Аргумент-предохранитель: повышенная копия его получает и больше не
#: пытается повышаться, даже если проверка прав по какой-то причине соврёт.
NO_ELEVATE_FLAG = "--no-elevate"

#: Тот же предохранитель для окружения — переживает любую передачу аргументов.
NO_ELEVATE_ENV = "PORTABLIZER_NO_ELEVATE"


def is_elevated() -> bool:
    """True, если процесс уже работает с правами администратора."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def elevation_disabled(argv: Optional[Sequence[str]] = None,
                       env: Optional[dict] = None) -> bool:
    """Просили ли нас не повышаться (флаг, переменная среды, уже повышены)."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    environment = os.environ if env is None else env
    if any(str(a).casefold() in (NO_ELEVATE_FLAG, "/noelevate")
           for a in arguments):
        return True
    return str(environment.get(NO_ELEVATE_ENV, "")).strip() not in ("", "0")


def relaunch_arguments(argv: Optional[Sequence[str]] = None,
                       frozen: Optional[bool] = None,
                       executable: str = "",
                       script: str = "") -> "tuple[str, List[str]]":
    """``(программа, аргументы)`` для повторного запуска самих себя.

    Вынесено отдельной чистой функцией: командную строку повышения удобно
    проверять тестами на любой ОС, не вызывая UAC.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    is_frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    program = executable or sys.executable
    if is_frozen:
        return program, [*arguments, NO_ELEVATE_FLAG]
    entry = script or os.path.abspath(sys.argv[0])
    return program, [entry, *arguments, NO_ELEVATE_FLAG]


def _shell_execute_runas(program: str, arguments: Sequence[str],
                         directory: str = "") -> int:
    """Запускает программу через UAC. Возвращает код ShellExecuteW.

    Значения больше 32 означают успех; 1223 (``ERROR_CANCELLED``) —
    пользователь нажал «Нет» в окне UAC.
    """
    import ctypes  # pragma: no cover - вызывается только на Windows
    import subprocess

    shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    result = shell32.ShellExecuteW(
        None, "runas", program,
        subprocess.list2cmdline([str(a) for a in arguments]),
        directory or os.getcwd(), 1)
    return int(result or 0)


def ensure_elevated(argv: Optional[Sequence[str]] = None) -> bool:
    """Перезапускает Portablizer с правами администратора.

    Возвращает True, если повышенная копия запущена и текущий процесс должен
    молча завершиться. False — работаем дальше как есть (уже повышены, не
    Windows, повышение запрещено флагом или пользователь отказался).
    """
    if not IS_WINDOWS or is_elevated() or elevation_disabled(argv):
        return False
    program, arguments = relaunch_arguments(argv)
    try:
        code = _shell_execute_runas(program, arguments)
    except Exception:  # noqa: BLE001 - нет UAC: работаем без повышения
        return False
    return code > 32


# --- сборка под ДРУГИМ пользователем ------------------------------------------
#
# Это самая опасная форма «запуска от имени администратора». Если в окне UAC
# ввести учётные данные другого аккаунта, процесс получает ЕГО профиль: HKCU
# указывает на чужую ветку реестра, а %USERPROFILE% — на чужую папку. Снимок
# «до/после» тогда описывает настройки администратора (включая ветки оболочки
# меню «Пуск»), а лончер применяет их в профиле обычного пользователя — отсюда
# и «сбитое» меню «Пуск».
#
# Поэтому такие сборки не должны захватывать HKCU вообще. Отличить «тот же
# пользователь, но с правами» от «другой пользователь» можно по владельцу
# процесса explorer.exe: оболочка всегда работает от имени интерактивного
# пользователя.

_TOKEN_QUERY = 0x0008


def _process_sid(pid: int) -> "Optional[str]":
    """Строковый SID владельца процесса ``pid`` (``None`` — не определить)."""
    if not IS_WINDOWS or not pid:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(_TOKEN_QUERY, False, int(pid))
        if not handle:
            return None
        try:
            token = wintypes.HANDLE()
            if not advapi32.OpenProcessToken(ctypes.c_void_p(handle),
                                            _TOKEN_QUERY,
                                            ctypes.byref(token)):
                return None
            try:
                size = wintypes.DWORD(0)
                advapi32.GetTokenInformation(token, 1, None, 0,
                                             ctypes.byref(size))
                if not size.value:
                    return None
                buffer = ctypes.create_string_buffer(size.value)
                if not advapi32.GetTokenInformation(token, 1, buffer,
                                                    size.value,
                                                    ctypes.byref(size)):
                    return None
                # TOKEN_USER: первым полем идёт указатель на SID.
                sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
                text = wintypes.LPWSTR()
                if not advapi32.ConvertSidToStringSidW(
                        ctypes.c_void_p(sid), ctypes.byref(text)):
                    return None
                try:
                    return str(text.value or "")
                finally:
                    kernel32.LocalFree(text)
            finally:
                kernel32.CloseHandle(token)
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
    except Exception:  # noqa: BLE001 - диагностика не должна падать
        return None


def _shell_owner_pid() -> int:
    """PID процесса explorer.exe интерактивного пользователя (0 — нет)."""
    if not IS_WINDOWS:
        return 0
    try:
        completed = subprocess.run(
            ["tasklist", "/fi", "imagename eq explorer.exe", "/fo", "csv",
             "/nh"],
            capture_output=True, text=True, timeout=20, check=False,
            creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError):
        return 0
    for line in (completed.stdout or "").splitlines():
        parts = [item.strip().strip('"') for item in line.split('","')]
        if len(parts) < 2:
            continue
        try:
            return int(parts[1])
        except ValueError:
            continue
    return 0


def current_user_sid() -> "Optional[str]":
    """SID пользователя, от имени которого работает текущий процесс."""
    return _process_sid(os.getpid())


def same_user_as_shell() -> bool:
    """Работает ли процесс в профиле интерактивного пользователя.

    ``True``, если определить не удалось: запрещать сборку «на всякий случай»
    нельзя, а вот молча захватить чужой HKCU — можно предотвратить.
    """
    if not IS_WINDOWS:
        return True
    shell_pid = _shell_owner_pid()
    if not shell_pid:
        return True
    shell = _process_sid(shell_pid)
    own = current_user_sid()
    if not shell or not own:
        return True
    return shell.casefold() == own.casefold()


def switched_user_warning() -> str:
    """Готовый текст предупреждения для журнала сборки (или пустая строка)."""
    if not IS_WINDOWS or not is_elevated() or same_user_as_shell():
        return ""
    return (
        "Portablizer запущен с правами администратора в профиле ДРУГОГО "
        "пользователя (в окне UAC введены чужие учётные данные). В этом "
        "режиме HKEY_CURRENT_USER принадлежит администратору, поэтому "
        "настройки пользователя не захватываются: иначе лончер применил бы "
        "чужой снимок и испортил оболочку — в том числе меню «Пуск». "
        "Сборка продолжится, но portable.reg останется пустым. Если нужны "
        "настройки приложения, запустите Portablizer обычным пользователем "
        "(при необходимости — «от имени администратора» со СВОИМ паролем)."
    )
