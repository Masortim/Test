"""Автоматическое получение прав администратора при старте Portablizer.

Почему это часть «сборки без сучка и задоринки»
-----------------------------------------------
Практически всё, что делает Portablizer, требует повышения:

* установщики с ``requireAdministrator`` в манифесте без прав просто не
  стартуют и возвращают -1;
* снимок и импорт ветки HKLM недоступны обычному пользователю;
* тихая установка распространяемых пакетов (vcredist, DXSETUP) — тоже;
* уборка следов установки с этого ПК (запись в «Установленные программы»,
  ярлыки в общем меню «Пуск») затрагивает машинные ветки.

Раньше программа лишь писала в журнал «запустите от имени администратора»,
а сборка разваливалась на середине: пользователь должен был догадаться сам,
закрыть окно, найти exe, вызвать контекстное меню и начать заново. Теперь
Portablizer при запуске один раз просит повышение сам: один щелчок «Да» в
штатном окне UAC вместо ручного перезапуска и повторного заполнения полей.

Отказ пользователя ничего не ломает: программа продолжает работу с
обычными правами и честно предупреждает, что часть шагов будет недоступна.
"""
from __future__ import annotations

import os
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
