"""Меню «Пуск» и профиль пользователя: что ломается и как это починить.

Симптом из жалобы
-----------------
После запуска Portablizer «от имени администратора» перестало открываться
меню «Пуск» (Windows 11): плитки пропали, поиск не отвечает, меню закрывается
сразу. Одновременно в ``C:\\Users\\<user>\\`` появились десятки временных
каталогов.

Причина не в «кэше» как таковом, а в том, что сборка под чужими правами
касается чужого профиля:

* запуск «от имени администратора» с вводом учётных данных ДРУГОГО
  пользователя переключает ``HKCU`` на его ветку. Снимок «до/после» тогда
  описывает настройки администратора, а лончер применяет их в профиле
  пользователя — это и есть «сбитый» интерфейс: раскладка «Пуск», закрепления
  и часть настроек оболочки берутся из чужого снимка;
* сам установщик, запущенный с повышенными правами, может писать в
  ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer`` — ветку,
  которой живёт меню «Пуск» (``StartPage2``, ``StartPins``, кэш Win11).
  Устаревший снимок этой ветки, применённый позже, откатывает её к состоянию
  другого ПК/другого пользователя, и меню «Пуск» перестаёт строиться;
* прерванный запуск оставляет «Документы» (Known Folder) направленными внутрь
  удалённой портативной папки. Проводник и меню «Пуск» в этом случае
  показывают пустые/недоступные элементы.

Что делает Portablizer
----------------------
1. **Не допускает порчи**: ``registry.py`` держит ветки оболочки вне снимка,
   а сборка под чужим пользователем вообще отказывается захватывать ``HKCU``
   (см. ``elevate.same_user_as_shell``).
2. **Чинит последствия** — этот модуль: находит «Документы», указывающие в
   несуществующую папку, возвращает их на место и (по явному запросу)
   сбрасывает кэш ``StartMenuExperienceHost``, после чего перезапускает его.
   Windows сама перестраивает меню по своей базе — закрепления пользователя
   при этом не удаляются, удаляется только испорченный кэш.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
from typing import Iterable, List, Optional, Sequence

IS_WINDOWS = sys.platform.startswith("win")

#: Ключи профиля, в которых лежит путь «Документов». Оба пишутся Windows и
#: оба читаются приложениями (новый и legacy-вариант).
USER_SHELL = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
LEGACY_SHELL = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
DOCUMENTS_GUID = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"

#: Признак «Документы уехали в портатив»: Known Folder направлен внутрь
#: ``PortableData\User\Documents``.
PORTABLE_REDIRECT_MARKERS = (
    "\\portabledata\\user\\documents",
    "/portabledata/user/documents",
)

#: Каталог кэша меню «Пуск» Windows 11/10. Пакет один и тот же, меняется лишь
#: хэш издателя, поэтому ищем по маске.
START_MENU_PACKAGE_GLOB = "Microsoft.Windows.StartMenuExperienceHost_*"

#: Что именно внутри пакета считается кэшем, который безопасно удалить.
#: ``LocalState`` не трогаем: там пользовательские закрепления.
START_MENU_CACHE_DIRS = ("TempState",)

#: Процесс оболочки, который держит кэш. После его завершения Windows
#: запускает новый экземпляр сама.
START_MENU_PROCESS = "StartMenuExperienceHost.exe"

#: Процессы оболочки, которые перезапускаются автоматически и потому могут
#: быть завершены без последствий для сеанса. explorer.exe сюда НЕ входит.
RESTARTABLE_SHELL_PROCESSES = (
    START_MENU_PROCESS,
    "ShellExperienceHost.exe",
    "SearchHost.exe",
    "SearchApp.exe",
)


def _winreg():
    """``winreg`` или ``None``: модуль импортируется и на Linux (для тестов)."""
    if not IS_WINDOWS:
        return None
    try:
        import winreg  # type: ignore

        return winreg
    except ImportError:  # pragma: no cover - Windows без winreg не бывает
        return None


# --- определение поломки ------------------------------------------------------

def redirect_marker(path: str) -> bool:
    """Похоже ли значение Known Folder на перенаправление в портатив."""
    text = str(path or "").replace("/", "\\").casefold().rstrip("\\")
    return any(marker.replace("/", "\\") in text
               for marker in PORTABLE_REDIRECT_MARKERS)


def read_documents_folder() -> str:
    """Текущее значение Known Folder «Документы» (пустая строка вне Windows)."""
    reg = _winreg()
    if reg is None:
        return ""
    for subkey, name in ((USER_SHELL, "Personal"),
                         (USER_SHELL, DOCUMENTS_GUID),
                         (LEGACY_SHELL, "Personal"),
                         (LEGACY_SHELL, DOCUMENTS_GUID)):
        try:
            with reg.OpenKey(reg.HKEY_CURRENT_USER, subkey, 0,
                             reg.KEY_QUERY_VALUE) as handle:
                value, _typ = reg.QueryValueEx(handle, name)
        except OSError:
            continue
        if isinstance(value, str) and value.strip():
            return os.path.expandvars(value.strip())
    return ""


def documents_folder_broken(path: str = "") -> bool:
    """True, если «Документы» указывают в несуществующую (портативную) папку.

    Проверка консервативная: подозрительным считается только значение с
    признаком перенаправления в ``PortableData``, которого больше нет на
    диске. Обычный, просто отсутствующий каталог (сетевой диск отключён) —
    это не наша поломка, и трогать его нельзя.
    """
    value = path if path else read_documents_folder()
    if not value or not redirect_marker(value):
        return False
    return not os.path.isdir(value)


def start_menu_cache_dirs(local_appdata: Optional[str] = None
                          ) -> List[str]:
    """Все ``TempState`` пакета StartMenuExperienceHost на этом ПК."""
    local = local_appdata or os.environ.get("LOCALAPPDATA", "")
    if not local:
        return []
    pattern = os.path.join(local, "Packages", START_MENU_PACKAGE_GLOB)
    found: List[str] = []
    for package in glob.glob(pattern):
        for name in START_MENU_CACHE_DIRS:
            candidate = os.path.join(package, name)
            if os.path.isdir(candidate):
                found.append(candidate)
    return found


def diagnose(local_appdata: Optional[str] = None) -> List[str]:
    """Что именно испорчено — списком фраз для журнала и окна."""
    problems: List[str] = []
    documents = read_documents_folder()
    if documents_folder_broken(documents):
        problems.append(
            "Папка «Документы» направлена внутрь удалённой портативной "
            f"папки: {documents}")
    if IS_WINDOWS and not start_menu_cache_dirs(local_appdata):
        problems.append(
            "Кэш меню «Пуск» (StartMenuExperienceHost\\TempState) не найден — "
            "он мог быть удалён или испорчен.")
    return problems


# --- восстановление -----------------------------------------------------------

def _set_documents_folder(value: str) -> bool:
    """Возвращает «Документы» на ``value`` во всех четырёх местах."""
    reg = _winreg()
    if reg is None:
        return False
    ok = False
    for subkey, name, typ in (
        (USER_SHELL, "Personal", reg.REG_EXPAND_SZ),
        (USER_SHELL, DOCUMENTS_GUID, reg.REG_EXPAND_SZ),
        (LEGACY_SHELL, "Personal", reg.REG_SZ),
        (LEGACY_SHELL, DOCUMENTS_GUID, reg.REG_SZ),
    ):
        try:
            with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, subkey, 0,
                                 reg.KEY_SET_VALUE) as handle:
                reg.SetValueEx(handle, name, 0, typ, value)
            ok = True
        except OSError:
            continue
    return ok


def default_documents_folder() -> str:
    """Куда вернуть «Документы», если портатив исчез."""
    profile = os.environ.get("USERPROFILE", "")
    if profile:
        return os.path.join(profile, "Documents")
    return ""


def restore_documents_folder(log=None, target: str = "") -> str:
    """Возвращает Known Folder «Документы» из портатива в профиль пользователя.

    Возвращает описание сделанного (пустая строка — менять было нечего).
    """
    current = read_documents_folder()
    if not documents_folder_broken(current):
        return ""
    destination = target or default_documents_folder()
    if not destination:
        return ""
    if not _set_documents_folder(destination):
        return ""
    message = (f"Папка «Документы» возвращена в профиль пользователя: "
               f"{destination} (было: {current})")
    if log is not None:
        try:
            log.ok(message)
        except Exception:  # noqa: BLE001
            pass
    return message


def clear_start_menu_cache(local_appdata: Optional[str] = None,
                           log=None) -> int:
    """Удаляет испорченный кэш меню «Пуск». Возвращает число файлов.

    Удаляется только содержимое ``TempState``: Windows перестраивает его при
    следующем запуске оболочки, а закрепления пользователя лежат в
    ``LocalState`` и остаются нетронутыми.
    """
    removed = 0
    for folder in start_menu_cache_dirs(local_appdata):
        for entry in _iter_children(folder):
            try:
                if os.path.isdir(entry) and not os.path.islink(entry):
                    import shutil

                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    os.remove(entry)
            except OSError:
                continue
            removed += 1
    if removed and log is not None:
        try:
            log.info(f"Кэш меню «Пуск» сброшен: удалено файлов {removed}.")
        except Exception:  # noqa: BLE001
            pass
    return removed


def _iter_children(folder: str) -> Iterable[str]:
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return []
    return [os.path.join(folder, name) for name in names]


def restart_shell_processes(processes: Sequence[str] = (),
                            log=None) -> List[str]:
    """Перезапускает процессы оболочки, которые Windows поднимает сама.

    ``explorer.exe`` здесь нет намеренно: его завершение закрывает все окна
    пользователя. ``StartMenuExperienceHost`` и ``SearchHost`` поднимаются
    оболочкой автоматически, поэтому их перезапуск безопасен и именно он
    заставляет Windows перестроить меню.
    """
    if not IS_WINDOWS:
        return []
    restarted: List[str] = []
    for name in (processes or RESTARTABLE_SHELL_PROCESSES):
        try:
            completed = subprocess.run(
                ["taskkill", "/f", "/im", name],
                capture_output=True, timeout=30, check=False,
                creationflags=0x08000000)
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode == 0:
            restarted.append(name)
    if restarted and log is not None:
        try:
            log.info("Перезапущены процессы оболочки: " + ", ".join(restarted))
        except Exception:  # noqa: BLE001
            pass
    return restarted


def notify_shell_change() -> None:
    """Сообщает оболочке, что настройки папок изменились (иначе кэш старый)."""
    if not IS_WINDOWS:
        return
    try:
        import ctypes

        SHCNE_ASSOCCHANGED = 0x08000000
        SHCNF_IDLIST = 0x0000
        ctypes.windll.shell32.SHChangeNotify(  # type: ignore[attr-defined]
            SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
        WM_SETTINGCHANGE = 0x001A
        HWND_BROADCAST = 0xFFFF
        ctypes.windll.user32.SendMessageTimeoutW(  # type: ignore[attr-defined]
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "ShellState", 0x0002, 3000,
            None)
    except Exception:  # noqa: BLE001 - уведомление не является целью
        pass


def repair_start_menu(log=None, reset_cache: bool = True,
                      restart_shell: bool = True,
                      local_appdata: Optional[str] = None) -> List[str]:
    """Полное лечение: «Документы», кэш меню «Пуск», перезапуск оболочки.

    Возвращает список того, что было сделано. Ничего не делает вне Windows и
    никогда не завершает ``explorer.exe``.
    """
    done: List[str] = []
    if not IS_WINDOWS:
        return done
    restored = restore_documents_folder(log)
    if restored:
        done.append(restored)
    if reset_cache:
        removed = clear_start_menu_cache(local_appdata, log)
        if removed:
            done.append(f"Сброшен кэш меню «Пуск» (файлов: {removed}).")
    notify_shell_change()
    if restart_shell and done:
        restarted = restart_shell_processes(log=log)
        if restarted:
            done.append("Перезапущены: " + ", ".join(restarted) + ".")
    return done
