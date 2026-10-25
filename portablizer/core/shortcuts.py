"""Ярлыки рабочего стола и меню «Пуск»: не оставлять свои после сборки.

Жалоба
------
После портирования на рабочем столе оставался ярлык программы. Он был создан
установщиком и содержал **абсолютный** путь, а не ссылку на портатив. После
переноса папки на другой диск ярлык указывал на прежнее место (или вообще в
никуда), а обновление, запущенное с него, ставило новую версию по старому
адресу.

Договор модуля
--------------
1. **Не создавать ярлыки.** В команды тихой установки добавлены штатные ключи
   отказа: ``/NOICONS`` у Inno Setup и ``--no-desktop-shortcut`` у сборок
   electron-builder (NSIS). Ключ понимает не каждый движок, поэтому одной
   подсказки мало: кнопку «ярлык на рабочем столе» в самодельных скриптах
   NSIS/Wise/InstallShield так не отключить.
2. **Не удалять чужие ярлыки.** Единственный ярлык, который можно безопасно
   опознать, — тот, **которого не было до запуска** установщика и который
   указывает **внутрь портативной папки** (в том числе в её прежнее место,
   если папку уже перенесли). Только такие файлы удаляются. Ярлык, созданный
   пользователем раньше, остаётся при любом содержимом: отличить «наш» от
   «его» по имени или цели невозможно.
3. **Никакого COM и PowerShell на каждый файл.** Разрешение ярлыка через
   ``WScript.Shell`` — это отдельный процесс на каждый ``.lnk``; в урезанных
   сборках Windows компонент может отсутствовать. Цель ищется прямо в байтах
   файла: и ``.lnk``, и ``.url`` хранят её текстом. Необязательный
   ``resolver`` нужен только для тестов и нестандартных случаев.

Модуль намеренно не зависит от PySide6 и работает на любой ОС: на не-Windows
список папок пуст, и все функции возвращают пустой результат.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Callable, Iterable, List, Optional, Sequence, Set

IS_WINDOWS = sys.platform.startswith("win")

#: CSIDL папок «Рабочий стол» и «Пуск» (пользовательская и общая).
DESKTOP_CSIDLS = (0x10, 0x19)          # CSIDL_DESKTOP, CSIDL_COMMON_DESKTOP
START_MENU_CSIDLS = (0x0B, 0x16)       # CSIDL_STARTMENU, CSIDL_COMMON_STARTMENU

#: Расширения ярлыков. ``.pif`` — наследие старых установщиков, ``.url`` —
#: интернет-ссылка (её тоже создают некоторые установщики).
LINK_SUFFIXES = (".lnk", ".url", ".pif")

#: Больше мегабайта ярлык не весит; защита от чтения мусора по ошибке.
MAX_LINK_BYTES = 1024 * 1024

#: Тип «разрешателя»: путь ярлыка -> цель (пустая строка/``None``, если цель
#: определить не удалось).
Resolver = Callable[[str], Optional[str]]


def _winreg_module():
    """``winreg`` или ``None`` (модуль импортируется и вне Windows)."""
    if not IS_WINDOWS:
        return None
    try:
        import winreg  # type: ignore

        return winreg
    except ImportError:  # pragma: no cover - Windows без winreg не бывает
        return None


def _shell_folder(csidl: int) -> Optional[str]:
    """Путь Known Folder по CSIDL с учётом перенаправления (OneDrive и т. п.)."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(520)
        result = ctypes.windll.shell32.SHGetFolderPathW(  # type: ignore[attr-defined]
            None, csidl, None, 0, buffer)
        if result:
            return None
        return buffer.value or None
    except Exception:  # noqa: BLE001 - вне Windows и в урезанной среде
        return None


def _registry_shell_folders() -> List[str]:
    """Запасной путь: ``User Shell Folders`` из HKCU (если CSIDL не сработал)."""
    reg = _winreg_module()
    if reg is None:
        return []
    found: List[str] = []
    key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    for name in ("Desktop", "Start Menu", "Common Desktop", "Common Start Menu"):
        try:
            with reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0,
                             reg.KEY_QUERY_VALUE) as handle:
                value, _typ = reg.QueryValueEx(handle, name)
        except OSError:
            continue
        if isinstance(value, str) and value.strip():
            found.append(os.path.expandvars(value.strip()))
    return found


def shortcut_folders(include_start_menu: bool = True) -> List[str]:
    """Существующие папки, куда установщики кладут ярлыки.

    «Рабочий стол» идёт первым: именно его жалоба касается в первую очередь.
    """
    candidates: List[str] = []
    for csidl in DESKTOP_CSIDLS:
        found = _shell_folder(csidl)
        if found:
            candidates.append(found)
    if include_start_menu:
        for csidl in START_MENU_CSIDLS:
            found = _shell_folder(csidl)
            if found:
                candidates.append(found)
    candidates.extend(_registry_shell_folders())
    for variable in ("USERPROFILE", "PUBLIC"):
        base = os.environ.get(variable, "")
        if not base:
            continue
        candidates.append(os.path.join(base, "Desktop"))
        if include_start_menu:
            candidates.append(os.path.join(
                base, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu"))
    unique: List[str] = []
    seen: Set[str] = set()
    for folder in candidates:
        key = os.path.normcase(os.path.normpath(folder))
        if key in seen or not os.path.isdir(folder):
            continue
        seen.add(key)
        unique.append(os.path.normpath(folder))
    return unique


def _normalized(path: str) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _link_files(folder: str) -> Iterable[str]:
    """Все файлы-ярлыки в папке (рекурсивно: в «Пуске» есть подпапки)."""
    try:
        for current, _dirs, files in os.walk(folder):
            for name in files:
                if name.casefold().endswith(LINK_SUFFIXES):
                    yield os.path.join(current, name)
    except OSError:
        return


def snapshot(folders: Optional[Sequence[str]] = None) -> Set[str]:
    """Что уже лежало в папках ярлыков до запуска установщика."""
    result: Set[str] = set()
    for folder in folders if folders is not None else shortcut_folders():
        for path in _link_files(folder):
            result.add(_normalized(path))
    return result


def _root_forms(root: str) -> List[str]:
    """Начертания корня, которые встречаются внутри ярлыка."""
    base = str(root or "").strip().strip('"').rstrip("\\/")
    if not base:
        return []
    forms = {
        base,
        base.replace("\\", "/"),
        base.replace("/", "\\"),
        base.replace("\\", "\\\\"),
    }
    return sorted((form for form in forms if form), key=len, reverse=True)


def _within(path: str, root: str) -> bool:
    """Лежит ли путь внутри корня (без учёта регистра и вида слэшей)."""
    if not path or not root:
        return False
    inner = _normalized(path)
    outer = _normalized(root).rstrip("\\/")
    return bool(outer) and (inner == outer or inner.startswith(outer + os.sep))


def _decoded_views(data: bytes) -> List[str]:
    """Текстовые представления ярлыка: UTF-16LE (``.lnk``) и UTF-8 (``.url``)."""
    views: List[str] = []
    for encoding in ("utf-16-le", "utf-8"):
        try:
            views.append(data.decode(encoding, errors="ignore"))
        except (UnicodeError, LookupError):  # pragma: no cover - защита
            continue
    return views


def link_points_into(path: str, roots: Sequence[str],
                     resolver: Optional[Resolver] = None) -> bool:
    """Указывает ли ярлык внутрь одного из корней.

    ``roots`` — текущий корень портатива и (при переносе) его прежние места:
    ярлык, созданный до переноса, содержит как раз прежний путь.
    """
    forms = [form for root in roots for form in _root_forms(str(root))]
    if not forms:
        return False
    try:
        if os.path.getsize(path) > MAX_LINK_BYTES:
            return False
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return False
    for view in _decoded_views(data):
        for form in forms:
            # Границы пути: ``D:\\Apps\\Foo`` не должен совпасть с
            # ``D:\\Apps\\FooBar\\...`` — соседняя папка не наша.
            pattern = re.compile(r"(?<![0-9A-Za-z_.])" + re.escape(form)
                                 + r"(?![0-9A-Za-z_.])", re.IGNORECASE)
            if pattern.search(view):
                return True
    if resolver is not None:
        try:
            target = resolver(path)
        except Exception:  # noqa: BLE001 - разрешатель не должен срывать уборку
            target = None
        if target:
            return any(_within(str(target), str(root)) for root in roots)
    return False


def created_links(before: Set[str],
                  folders: Optional[Sequence[str]] = None) -> List[str]:
    """Ярлыки, появившиеся после снимка ``before``."""
    appeared: List[str] = []
    for folder in folders if folders is not None else shortcut_folders():
        for path in _link_files(folder):
            if _normalized(path) not in before:
                appeared.append(path)
    return appeared


def remove_own_shortcuts(root: str,
                         extra_roots: Sequence[str] = (),
                         folders: Optional[Sequence[str]] = None,
                         before: Optional[Set[str]] = None,
                         resolver: Optional[Resolver] = None) -> List[str]:
    """Удаляет ярлыки, созданные этим запуском и ведущие внутрь портатива.

    ``before`` — снимок :func:`snapshot` до установки. Без него функция ничего
    не делает: без снимка нельзя доказать, что ярлык создали мы, а не
    пользователь.
    """
    if before is None:
        return []
    roots = [str(root)] + [str(extra) for extra in extra_roots if str(extra)]
    removed: List[str] = []
    for path in created_links(before, folders):
        if not link_points_into(path, roots, resolver):
            continue
        try:
            os.remove(path)
        except OSError:
            continue
        removed.append(path)
    return removed


class ShortcutGuard:
    """Снимок папок ярлыков до установки и уборка только своих.

    Использование::

        guard = ShortcutGuard(portable_dir, extra_roots=previous_roots)
        guard.snapshot()
        ...                 # установщик, обновление, перезапуск программы
        removed = guard.cleanup()   # безопасно вызывать многократно
    """

    def __init__(self, root: str, extra_roots: Sequence[str] = (),
                 folders: Optional[Sequence[str]] = None,
                 resolver: Optional[Resolver] = None,
                 include_start_menu: bool = True) -> None:
        self.root = str(root)
        self.extra_roots = [str(item) for item in extra_roots if str(item)]
        self._folders = (list(folders) if folders is not None
                         else shortcut_folders(include_start_menu))
        self.resolver = resolver
        self.before: Optional[Set[str]] = None
        self.removed: List[str] = []

    def snapshot(self) -> int:
        """Запоминает текущее содержимое папок; возвращает число ярлыков."""
        self.before = snapshot(self._folders)
        self.removed = []
        return len(self.before)

    def cleanup(self) -> List[str]:
        """Убирает созданные этим запуском ярлыки и возвращает их пути."""
        if self.before is None:
            return []
        found = remove_own_shortcuts(
            self.root, extra_roots=self.extra_roots, folders=self._folders,
            before=self.before, resolver=self.resolver)
        known = {_normalized(item) for item in self.removed}
        fresh = [item for item in found if _normalized(item) not in known]
        self.removed.extend(fresh)
        return fresh
