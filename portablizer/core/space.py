"""Свободное место на дисках: сколько нужно установщику и куда положить TEMP.

Зачем это нужно сборщику
------------------------
Установщики больших игр — и особенно офлайн-установщики GOG — распаковывают
данные **сначала во временную папку** и только потом переносят их в целевую.
Значит, в момент установки на дисках должны одновременно уместиться три
вещи:

  * сам дистрибутив (``setup_*.exe`` плюс его части ``setup_*.bin``);
  * распакованная копия в ``TEMP``;
  * результат в ``App``.

Portablizer перенаправляет ``TEMP`` внутрь портативной папки — это правильно
для чистоты компьютера (после сборки на нём не остаётся следов установки), но
у диска портатива появляется второй потребитель места. Если портатив собирают
на флешке или на небольшом разделе, установщику физически не хватает места, и
он не «отказывается работать», а **падает**: распаковка обрывается на середине,
а исключение прилетает в обработчик прогресса и превращается в код
``0xC000041D`` (необработанное исключение в пользовательском callback).

Здесь считаются три величины:

  * :func:`media_bytes` — сколько занимает дистрибутив целиком (exe плюс части
    ``.bin``/``.cab``): это честная оценка того, сколько данных установщику
    придётся развернуть;
  * :func:`free_space` — сколько места свободно на нужном диске;
  * :func:`pick_temp_root` — на какой диск перенести ``TEMP`` установщика, если
    на диске портатива для него нет места. Перенос всегда временный: папка
    удаляется после сборки (см. ``Portablizer._cleanup_install_temp``), а в
    журнал попадают и причина, и числа.
"""
from __future__ import annotations

import os
import re
import shutil
import string
import sys
import tempfile
from typing import Callable, List, Optional, Sequence

IS_WINDOWS = sys.platform.startswith("win")

#: Расширения файлов-частей одного дистрибутива. GOG режет офлайн-установщик
#: на части ``setup_<game>-1.bin`` (лимит FAT32 — 4 ГБ на файл), классические
#: многотомные архивы используют ``.001``, ``.part1`` и т. п.
PART_EXTENSIONS = (
    ".bin", ".cab", ".msi", ".msp", ".dat", ".pak", ".pkg",
    ".001", ".002", ".003", ".004", ".005", ".r00", ".z01",
    ".part1", ".part2", ".part3",
)

#: Минимальная общая часть имени, при которой файл считается частью ТОГО ЖЕ
#: дистрибутива. Установщик GOG называется
#: ``setup_hatred_2.1.0.9_(2069488821).exe``, а его части —
#: ``setup_hatred-1.bin``: общего префикса ``setup_hatred`` (11 символов)
#: достаточно, а чужой установщик в той же папке (``setup_hitman_…``, общий
#: префикс ``setuph``) не приклеится.
_PART_NAME_PREFIX = 8

#: Сколько частей вообще смотрим: больше не бывает, а обход большой сетевой
#: папки не должен стоить секунд.
MAX_PART_FILES = 128


def _name_key(path: str) -> str:
    """Имя файла без расширения, приведённое к «только буквы и цифры».

    Разделители у частей и у самого установщика разные (``_``, ``-``, ``.``),
    поэтому сравнивать имена напрямую нельзя: ``setup_hatred_2.1.0.9_(…)`` и
    ``setup_hatred-1`` совпадают только после нормализации.
    """
    stem = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r"[^0-9a-z]+", "", stem.casefold())


def _common_prefix_length(left: str, right: str) -> int:
    limit = min(len(left), len(right))
    index = 0
    while index < limit and left[index] == right[index]:
        index += 1
    return index


def part_files(installer_path: str, limit: int = MAX_PART_FILES) -> List[str]:
    """Части дистрибутива, лежащие рядом с установщиком.

    Возвращает только те файлы, которые принадлежат ЭТОМУ установщику:
    известное расширение-часть И общее с его именем начало. Рядом могут
    лежать установщики других игр — их вес к нашему отношения не имеет.
    """
    directory = os.path.dirname(os.path.abspath(installer_path))
    key = _name_key(installer_path)
    if not key:
        return []
    own_name = os.path.basename(installer_path).casefold()
    found: List[str] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(found) >= limit:
                    break
                try:
                    if not entry.is_file():
                        continue
                except OSError:
                    continue
                lowered = entry.name.casefold()
                if lowered == own_name:
                    continue
                if not lowered.endswith(PART_EXTENSIONS):
                    continue
                if _common_prefix_length(_name_key(entry.name),
                                         key) < _PART_NAME_PREFIX:
                    continue
                found.append(entry.path)
    except OSError:
        return []
    return sorted(found)


def media_bytes(installer_path: str) -> int:
    """Полный вес дистрибутива: установщик плюс все его части.

    Ошибки размера не считаются фатальными: неизвестный размер — это ``0``,
    то есть «оценить нельзя», и тогда никаких выводов о нехватке места не
    делается (лучше промолчать, чем напугать ложным предупреждением).
    """
    total = 0
    for path in [installer_path] + part_files(installer_path):
        try:
            total += os.path.getsize(path)
        except OSError:
            continue
    return total


def free_space(path: str) -> int:
    """Свободное место на диске, где лежит ``path`` (``-1`` — не определить)."""
    probe = path
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe.rstrip("\\/"))
        if parent == probe:
            break
        probe = parent
    if not probe:
        return -1
    try:
        return int(shutil.disk_usage(probe).free)
    except OSError:
        return -1


def volume_of(path: str) -> str:
    """Имя тома для пути: ``e:`` или ``\\\\server\\share`` (иначе — пусто)."""
    absolute = os.path.abspath(path)
    drive, _tail = os.path.splitdrive(absolute)
    if drive:
        return drive.casefold()
    # Unix-подобные системы (в том числе тесты): том — первый компонент пути.
    parts = [p for p in absolute.split(os.sep) if p]
    return (os.sep + parts[0]).casefold() if parts else ""


def windows_drives() -> List[str]:
    """Корни всех существующих дисков Windows (``C:\\``, ``D:\\``, …)."""
    if not IS_WINDOWS:
        return []
    drives: List[str] = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        try:
            if os.path.isdir(root):
                drives.append(root)
        except OSError:
            continue
    return drives


def pick_temp_root(primary_dir: str, need_bytes: int,
                   free: Callable[[str], int] = free_space,
                   roots: Optional[Sequence[str]] = None,
                   volume: Callable[[str], str] = volume_of,
                   ) -> Optional[str]:
    """Куда перенести ``TEMP`` установщика, если на диске портатива тесно.

    Возвращает каталог-кандидат (сам по себе ещё не временная папка —
    вызывающий создаёт внутри него свою) или ``None``, если менять нечего:
    другой диск не даёт больше места либо его вовсе нет.

    Сначала выбирается кандидат, которому хватает требуемого объёма; если
    такого нет, берётся просто самый свободный — с ним шансов больше, чем на
    переполненном диске портатива.

    ``free`` и ``volume`` подменяются в тестах: проверять выбор диска на
    машине, где он один, иначе нечем.
    """
    if need_bytes <= 0:
        return None
    primary_volume = volume(primary_dir)
    primary_free = free(primary_dir)
    if primary_free >= need_bytes:
        return None

    candidates = list(roots) if roots is not None else default_roots()
    best_fitting: Optional[tuple] = None   # (свободно, путь)
    best_any: Optional[tuple] = None
    for root in candidates:
        if not root or not os.path.isdir(root):
            continue
        if volume(root) == primary_volume:
            continue
        available = free(root)
        if available < 0:
            continue
        if best_any is None or available > best_any[0]:
            best_any = (available, root)
        if available >= need_bytes and (best_fitting is None
                                        or available > best_fitting[0]):
            best_fitting = (available, root)

    chosen = best_fitting or best_any
    if chosen is None or chosen[0] <= max(primary_free, 0):
        return None
    return chosen[1]


def default_roots() -> List[str]:
    """Кандидаты по умолчанию: штатный TEMP пользователя и диски Windows."""
    roots: List[str] = []
    for value in (os.environ.get("TEMP"), os.environ.get("TMP"),
                  tempfile.gettempdir()):
        if value:
            roots.append(value)
    roots.extend(windows_drives())
    unique: List[str] = []
    seen = set()
    for root in roots:
        key = os.path.normcase(os.path.abspath(root))
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique
