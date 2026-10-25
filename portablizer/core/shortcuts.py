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


#: Блок LinkInfo начинается сразу после заголовка Shell Link (0x4C).
_LNK_LINK_INFO_OFFSET = 0x4C
#: Смещение Ansi-строки с локальным путём внутри LinkInfo (VS FixedLength).
_LNK_LINK_INFO_PATH = 0x10
#: Минимальный размер заголовка LinkInfo.
_LNK_LINK_INFO_HEADER = 0x1C


def lnk_target(path: str) -> str:
    """Локальный путь из ``.lnk`` или пустая строка, если его нет.

    Читается только нужное: заголовок Shell Link, блок LinkInfo (он идёт
    сразу за заголовком, с 0x4C) и Ansi-строка с локальным путём внутри
    него. COM (``WScript.Shell``) и дочерние процессы не используются:
    уборка ярлыков должна работать на любом ПК и не тратить секунды на
    каждый файл. Ярлык может ссылаться только на том или на сетевой путь —
    тогда здесь будет пустая строка, а путь всё равно найдётся по тексту
    файла (UTF-16LE) в :func:`link_points_into`.
    """
    try:
        if os.path.getsize(path) > MAX_LINK_BYTES:
            return ""
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return ""
    if len(data) < _LNK_LINK_INFO_OFFSET + 4 or not data.startswith(b"L\x00\x00\x00"):
        return ""
    flags = int.from_bytes(data[0x14:0x18], "little")
    if not flags & 0x2:  # HasLinkInfo
        return ""
    block = data[_LNK_LINK_INFO_OFFSET:]
    size = int.from_bytes(block[0:4], "little")
    header_size = int.from_bytes(block[4:8], "little")
    if size < _LNK_LINK_INFO_HEADER or header_size < _LNK_LINK_INFO_HEADER:
        return ""
    if header_size + 4 > len(block):
        return ""
    path_offset = int.from_bytes(
        block[_LNK_LINK_INFO_PATH:_LNK_LINK_INFO_PATH + 4], "little")
    if not header_size <= path_offset < min(size, len(block)):
        return ""
    raw = block[path_offset:min(size, len(block))]
    end = raw.find(b"\x00")
    if end <= 0:
        return ""
    codec = "mbcs" if sys.platform == "win32" else "latin-1"
    try:
        text = raw[:end].decode(codec, errors="replace")
    except LookupError:  # pragma: no cover - не-Windows без mbcs
        text = raw[:end].decode("latin-1", errors="replace")
    return text.strip()


def link_target(path: str, resolver: Optional[Resolver] = None) -> str:
    """Цель ярлыка: сначала из самого файла, затем (если надо) ``resolver``."""
    target = lnk_target(path) if path.casefold().endswith(".lnk") else ""
    if target:
        return target
    lowered = path.casefold()
    if lowered.endswith(".url"):
        try:
            with open(path, "r", encoding="utf-8-sig", errors="ignore") as handle:
                text = handle.read(MAX_LINK_BYTES)
        except OSError:
            return ""
        match = re.search(r"^\s*URL\s*=\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        if not match:
            return ""
        url = match.group(1).strip()
        if url.casefold().startswith("file:///"):
            return url[8:].replace("/", "\\")
        return url
    if resolver is not None:
        try:
            return str(resolver(path) or "")
        except Exception:  # noqa: BLE001 - разрешатель не срывает уборку
            return ""
    return ""


def target_is_missing(target: str) -> bool:
    """Цель заведомо никуда не ведёт (файла и каталога нет).

    Проверяются только пути файловой системы: ``http(s)`` и другие схемы к
    делу не относятся, а UNC-путь недоступного сейчас сервера — тоже не
    доказательство поломки, поэтому он пропускается.
    """
    text = str(target or "").strip().strip('"')
    if not text:
        return False
    if text.casefold().startswith(("http://", "https://", "mailto:",
                                  "shell:", "ms-", "{")):
        return False
    if text.startswith("\\\\") and not text.startswith("\\\\?\\"):
        return False
    expanded = os.path.expandvars(os.path.expanduser(text))
    if "%" in expanded:
        # Переменная не раскрылась — проверить путь нельзя.
        return False
    try:
        return not os.path.exists(expanded)
    except (OSError, ValueError):
        return False


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


def swept_folders(root: str,
                  folders: Optional[Sequence[str]] = None
                  ) -> List[str]:
    """Папки ярлыков, которые имеет смысл обходить при запуске портатива.

    Помимо Рабочего стола и меню «Пуск» площадки бывают у самого портатива:
    ``PortableData\\User\\Desktop`` — это перенаправленный профиль программы.
    Ярлык, созданный программой при первом запуске, лежит там, и убирать его
    нужно так же, как на настоящем рабочем столе.
    """
    found = list(folders) if folders is not None else shortcut_folders()
    data_name = "PortableData"
    extra = [
        os.path.join(root, data_name, "User", "Desktop"),
        os.path.join(root, data_name, "Public", "Desktop"),
    ]
    unique: List[str] = []
    seen: Set[str] = set()
    for folder in list(found) + extra:
        key = _normalized(folder)
        if key in seen or not os.path.isdir(folder):
            continue
        seen.add(key)
        unique.append(folder)
    return unique


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


def app_name_candidates(*values: str) -> List[str]:
    """Имена, под которыми установщик мог подписать ярлык этой программы.

    ``Ollama_Portable`` -> ``ollama`` (без ``_portable``), ``Ollama.lnk`` ->
    ``ollama``, ``ollama app.exe`` -> ``ollama app``.
    """
    names: List[str] = []
    for value in values:
        text = os.path.basename(str(value or "").strip().strip('"'))
        for suffix in (".exe", ".msi", ".lnk", ".url", ".pif"):
            if text.casefold().endswith(suffix):
                text = text[: -len(suffix)]
        text = text.casefold()
        if text.endswith("_portable"):
            text = text[: -len("_portable")]
        if text.endswith(" portable"):
            text = text[: -len(" portable")]
        collapsed = " ".join(text.replace("_", " ").split())
        if collapsed and collapsed not in names:
            names.append(collapsed)
    return names


def _name_matches(link_path: str, names: Sequence[str]) -> bool:
    """Похоже ли имя ярлыка на имя программы.

    Сравниваются только «дочищенные» формы (регистр, ``_``/пробелы, слова
    ``Portable``): совпадение целиком или имя программы + уточнение
    (``Ollama (2)``, ``Ollama Portable``). Это лишь дополнительное условие —
    удаляется такой ярлык только тогда, когда его цель уже не существует.
    """
    if not names:
        return False
    stem = os.path.splitext(os.path.basename(link_path))[0]
    normalized = " ".join(stem.replace("_", " ").casefold().split())
    for name in names:
        candidate = " ".join(str(name).replace("_", " ").casefold().split())
        if not candidate:
            continue
        if normalized == candidate:
            return True
        if normalized.startswith(candidate + " ") or normalized.startswith(
                candidate + "("):
            return True
    return False


def remove_stale_shortcuts(app_names: Sequence[str],
                           roots: Sequence[str] = (),
                           folders: Optional[Sequence[str]] = None,
                           resolver: Optional[Resolver] = None) -> List[str]:
    """Убирает ярлыки этой программы, оставшиеся на рабочем столе.

    Жалоба: после сборки на рабочем столе оставался **пустой** ярлык. Пустой
    он потому, что цель уже не существует (установщик записал путь в
    промежуточный каталог, которого больше нет), но сам файл ``.lnk`` —
    обычный файл, он не исчезает вместе с целью.

    Удаляется ярлык, если выполнено одно из условий:

    * он указывает **внутрь портатива** (в текущий корень или в любое из его
      прежних мест) — такой ярлык заведомо ведёт на переносимую копию и после
      переезда папки бесполезен;
    * его имя совпадает с именем программы **и** цель уже не существует —
      то есть это заведомо нерабочий остаток.

    В отличие от :func:`remove_own_shortcuts` снимок не нужен: условия сами
    по себе доказывают, что ярлык принадлежит этой программе. Ярлыки на
    существующие сторонние программы (``Telegram``, ``Steam``) не трогаются
    ни при каких условиях.
    """
    targets = list(folders) if folders is not None else shortcut_folders()
    removed: List[str] = []
    for folder in targets:
        for path in _link_files(folder):
            if link_points_into(path, [str(item) for item in roots], resolver):
                try:
                    os.remove(path)
                except OSError:
                    continue
                removed.append(path)
                continue
            if not _name_matches(path, app_names):
                continue
            if not target_is_missing(link_target(path, resolver)):
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
                 include_start_menu: bool = True,
                 app_names: Sequence[str] = ()) -> None:
        self.root = str(root)
        self.extra_roots = [str(item) for item in extra_roots if str(item)]
        self._folders = (list(folders) if folders is not None
                         else shortcut_folders(include_start_menu))
        self.resolver = resolver
        self.app_names = [str(item) for item in app_names if str(item).strip()]
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
        return self._remember(found)

    def sweep(self) -> List[str]:
        """Убирает оставшиеся нерабочие ярлыки этой программы.

        Нужен там, где снимок «до» невозможен (второй, третий запуск
        программы, чужой апдейтер, недописанный установщик): ярлык удаляется,
        если он ведёт внутрь портатива или если его имя совпадает с именем
        программы, а цель уже не существует — ровно «пустой ярлык» из
        жалобы.
        """
        found = remove_stale_shortcuts(
            self.app_names, roots=[self.root, *self.extra_roots],
            folders=self._folders, resolver=self.resolver)
        return self._remember(found)

    def _remember(self, items: Sequence[str]) -> List[str]:
        known = {_normalized(item) for item in self.removed}
        fresh = [item for item in items if _normalized(item) not in known]
        self.removed.extend(fresh)
        return fresh
