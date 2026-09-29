"""Собственный распаковщик кабинетов (CAB) — без внешних программ.

Зачем он нужен
--------------
Все распространяемые пакеты Microsoft — это кабинеты, просто в разной
обёртке:

* ``vcredist_x86.exe`` VC++ 2005/2008/2010 — обёртка IExpress (wextract):
  PE-заголовок, а следом, «довеском», обычный кабинет ``MSCF`` с
  ``vc_red.msi`` и ``vc_red.cab`` внутри;
* ``vcredist_x86.exe`` VC++ 2012/2013 и ``vc_redist.x64.exe`` VC++ 2015-2022 —
  бандл WiX Burn: к PE приклеены контейнеры, и это тоже кабинеты;
* ``directx_Jun2010_redist.exe`` — снова IExpress с сотней кабинетов внутри;
* сами ``.cab`` рядом с установщиком игры.

До этого модуля Portablizer вскрывал их чужими руками: запускал сам пакет с
ключом распаковки (``/T:``, ``/x:``, ``/layout``) или звал ``expand``. Это
ненадёжно по причинам, которые от нас не зависят:

* пакет разбирает путь **сам**, внутри одного аргумента: пробел обрывает
  путь, кириллица (а у русского пользователя каталог профиля — кириллица)
  разбирается как мусор, длинный путь упирается в MAX_PATH;
* запуск чужого exe может быть запрещён политикой, SmartScreen или
  антивирусом, а ``expand``/``msiexec`` — отсутствовать в PATH;
* тихий ключ у каждого поколения свой, и «не тот» ключ иногда открывает
  модальное окно, которое ждёт мышку.

Отсюда и брались сообщения «пакет скачан, но распаковать его автоматически
не удалось». Здесь кабинет читается напрямую: ищем сигнатуру ``MSCF``,
разбираем заголовки CFHEADER/CFFOLDER/CFFILE/CFDATA и распаковываем данные
штатным ``zlib`` (MSZIP — это тот же deflate с историей между блоками).
Никаких запусков, никаких путей в командной строке, работает и на Windows,
и в тестах на любой ОС.

Чего модуль не умеет: LZX и Quantum (в пакетах Microsoft они встречаются
редко — в основном в старых кабинетах DirectX). Такие папки кабинета просто
пропускаются, и вызывающий код возвращается к ``expand``.

Формат CAB описан в MS-CAB; здесь реализована минимально необходимая часть.
"""
from __future__ import annotations

import io
import mmap
import os
import re
import struct
import zlib
from typing import Iterator, List, Optional, Sequence

#: Сигнатура кабинета.
SIGNATURE = b"MSCF"

#: Флаги CFHEADER.
_FLAG_PREV = 0x0001
_FLAG_NEXT = 0x0002
_FLAG_RESERVE = 0x0004

#: Типы сжатия папки кабинета.
COMPRESSION_NONE = 0
COMPRESSION_MSZIP = 1
COMPRESSION_QUANTUM = 2
COMPRESSION_LZX = 3

#: Разумные ограничения: пакет не должен уметь «взорвать» сборку.
MAX_CABINETS = 4000
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024
#: Вложенность «кабинет внутри кабинета внутри msi».
MAX_DEPTH = 4


class CabinetError(Exception):
    """Кабинет повреждён или это вовсе не кабинет."""


class _Folder:
    __slots__ = ("offset", "blocks", "compression", "cache")

    def __init__(self, offset: int, blocks: int, compression: int) -> None:
        self.offset = offset
        self.blocks = blocks
        self.compression = compression
        self.cache: Optional[bytes] = None


class _File:
    __slots__ = ("name", "size", "folder", "offset")

    def __init__(self, name: str, size: int, folder: int, offset: int) -> None:
        self.name = name
        self.size = size
        self.folder = folder
        self.offset = offset


def _safe_name(name: str) -> str:
    """Имя файла из кабинета, пригодное для файловой системы.

    Внутри кабинета имена бывают с путями (``x86\\vcruntime140.dll``) и,
    в теории, с ``..`` — распаковка не должна писать мимо целевой папки.
    """
    name = name.replace("\\", "/")
    parts = []
    for part in name.split("/"):
        part = part.strip()
        if not part or part in (".", ".."):
            continue
        part = re.sub(r'[<>:"|?*\x00-\x1f]', "_", part)
        parts.append(part)
    return os.path.join(*parts) if parts else ""


class Cabinet:
    """Разобранный кабинет: список файлов и доступ к их содержимому."""

    def __init__(self, data, base: int = 0) -> None:
        self._data = data
        self._base = base
        self.folders: List[_Folder] = []
        self.files: List[_File] = []
        self.size = 0
        self._parse()

    # -- разбор заголовков ---------------------------------------------------
    def _read(self, offset: int, length: int) -> bytes:
        chunk = self._data[offset:offset + length]
        if len(chunk) != length:
            raise CabinetError("кабинет обрывается")
        return bytes(chunk)

    def _parse(self) -> None:
        base = self._base
        header = self._read(base, 36)
        if header[:4] != SIGNATURE:
            raise CabinetError("нет сигнатуры MSCF")
        (cb_cabinet, coff_files, minor, major, folders, files,
         flags) = struct.unpack_from("<I4xI4xBBHHH", header, 8)
        if (major, minor) != (1, 3):
            raise CabinetError(f"незнакомая версия кабинета {major}.{minor}")
        if not 0 < folders <= 65535 or files > 65535:
            raise CabinetError("подозрительные счётчики в заголовке")
        self.size = cb_cabinet

        position = base + 36
        folder_reserve = 0
        data_reserve = 0
        if flags & _FLAG_RESERVE:
            header_reserve, folder_reserve, data_reserve = struct.unpack(
                "<HBB", self._read(position, 4))
            position += 4 + header_reserve
        for flag in (_FLAG_PREV, _FLAG_NEXT):
            if flags & flag:
                for _ in range(2):
                    position = self._skip_string(position)

        for _ in range(folders):
            chunk = self._read(position, 8)
            offset, blocks, compression = struct.unpack("<IHH", chunk)
            self.folders.append(_Folder(base + offset, blocks, compression))
            position += 8 + folder_reserve

        position = base + coff_files
        for _ in range(files):
            chunk = self._read(position, 16)
            size, offset, folder, _date, _time, attributes = struct.unpack(
                "<IIHHHH", chunk)
            position += 16
            end = position
            while self._data[end:end + 1] not in (b"\x00", b""):
                end += 1
            raw = self._read(position, end - position)
            position = end + 1
            encoding = "utf-8" if attributes & 0x80 else "cp1252"
            try:
                name = raw.decode(encoding, "replace")
            except LookupError:
                name = raw.decode("latin-1", "replace")
            if size > MAX_FILE_SIZE or folder >= len(self.folders):
                continue
            self.files.append(_File(name, size, folder, offset))
        self._data_reserve = data_reserve

    def _skip_string(self, position: int) -> int:
        while self._data[position:position + 1] not in (b"\x00", b""):
            position += 1
        return position + 1

    # -- данные --------------------------------------------------------------
    def folder_data(self, index: int) -> bytes:
        """Распакованное содержимое одной папки кабинета."""
        folder = self.folders[index]
        if folder.cache is not None:
            return folder.cache
        compression = folder.compression & 0x000F
        if compression not in (COMPRESSION_NONE, COMPRESSION_MSZIP):
            raise CabinetError(
                "папка кабинета сжата способом, который умеет только Windows "
                f"(код {compression})")
        position = folder.offset
        out = io.BytesIO()
        history = b""
        total = 0
        for _ in range(folder.blocks):
            head = self._read(position, 8)
            _checksum, compressed, uncompressed = struct.unpack("<IHH", head)
            position += 8 + getattr(self, "_data_reserve", 0)
            block = self._read(position, compressed)
            position += compressed
            if compression == COMPRESSION_NONE:
                plain = block
            else:
                if block[:2] != b"CK":
                    raise CabinetError("повреждённый блок MSZIP")
                # MSZIP — это raw deflate, где словарём служат последние
                # 32 КБ предыдущего блока той же папки.
                decompressor = zlib.decompressobj(-15, zdict=history) \
                    if history else zlib.decompressobj(-15)
                plain = decompressor.decompress(block[2:], uncompressed)
                plain += decompressor.flush()
            out.write(plain)
            history = (history + plain)[-32768:]
            total += len(plain)
            if total > MAX_TOTAL_SIZE:
                raise CabinetError("папка кабинета неправдоподобно велика")
        folder.cache = out.getvalue()
        return folder.cache

    def read(self, entry: _File) -> bytes:
        data = self.folder_data(entry.folder)
        return data[entry.offset:entry.offset + entry.size]

    def names(self) -> List[str]:
        return [entry.name for entry in self.files]

    def extract(self, destination: str,
                wanted: Sequence[str] = ()) -> List[str]:
        """Распаковывает кабинет; ``wanted`` — если нужны не все файлы."""
        os.makedirs(destination, exist_ok=True)
        lowered = {name.lower() for name in wanted}
        written: List[str] = []
        for entry in self.files:
            if lowered and entry.name.lower() not in lowered:
                continue
            relative = _safe_name(entry.name)
            if not relative:
                continue
            target = os.path.join(destination, relative)
            try:
                payload = self.read(entry)
            except (CabinetError, zlib.error, struct.error):
                continue
            try:
                os.makedirs(os.path.dirname(target) or destination,
                            exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(payload)
            except OSError:
                continue
            written.append(target)
        return written


# =============================================================================
#  Поиск кабинетов внутри произвольного файла
# =============================================================================

def _open_mapped(path: str):
    """Отображает файл в память (для больших пакетов это важно)."""
    handle = open(path, "rb")
    try:
        mapped = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
    except (ValueError, OSError):
        data = handle.read()
        handle.close()
        return None, data
    return handle, mapped


def iter_cabinets(data, limit: int = MAX_CABINETS) -> Iterator[int]:
    """Смещения всех правдоподобных кабинетов внутри данных.

    Самораспаковывающийся exe — это PE, к которому «довеском» приклеен
    кабинет; у бандлов Burn таких довесков несколько. Сигнатуру ищем по
    всему файлу и проверяем заголовок, чтобы не принять за кабинет
    случайные четыре байта.
    """
    position = 0
    found = 0
    total = len(data)
    while found < limit:
        index = data.find(SIGNATURE, position)
        if index < 0:
            return
        position = index + 4
        try:
            (cb_cabinet, coff_files, minor, major, folders) = struct.unpack_from(
                "<I4xI4xBBH", data, index + 8)
        except struct.error:
            return
        if (major, minor) != (1, 3):
            continue
        if not 0 < folders <= 65535:
            continue
        if not 36 <= coff_files < cb_cabinet <= total - index:
            continue
        found += 1
        yield index
        # Следующий кабинет ищем уже после этого.
        position = index + max(cb_cabinet, 4)


def extract_file(path: str, destination: str, *, wanted: str = "",
                 depth: int = 0) -> List[str]:
    """Достаёт всё, что лежит в кабинетах внутри файла ``path``.

    Работает и с ``.cab``, и с самораспаковывающимся ``.exe``, и с ``.msi``
    (внутри MSI кабинет часто лежит отдельным потоком). Вложенные кабинеты
    (``vc_red.cab`` внутри ``vcredist_x86.exe``) раскрываются рекурсивно.
    Возвращает список созданных файлов.
    """
    if depth > MAX_DEPTH or not os.path.isfile(path):
        return []
    try:
        if os.path.getsize(path) < 64:
            return []
    except OSError:
        return []
    handle, data = _open_mapped(path)
    written: List[str] = []
    try:
        for offset in iter_cabinets(data):
            try:
                cabinet = Cabinet(data, offset)
                written += cabinet.extract(destination)
            except (CabinetError, struct.error, zlib.error, MemoryError):
                continue
    finally:
        try:
            if hasattr(data, "close"):
                data.close()
        except (BufferError, ValueError):
            pass
        if handle is not None:
            handle.close()

    # Внутри кабинета лежат .msi и вложенные .cab — раскрываем и их.
    nested: List[str] = []
    for item in list(written):
        lower = item.lower()
        if lower.endswith((".cab", ".msi", ".msp")) and os.path.isfile(item):
            nested += extract_file(item, os.path.dirname(item),
                                   wanted=wanted, depth=depth + 1)
    return written + nested


def extract_cabinet_file(path: str, destination: str) -> List[str]:
    """Распаковывает обычный ``.cab`` (то же, что ``expand -F:* … …``)."""
    return extract_file(path, destination)


def looks_like_cabinet(path: str) -> bool:
    """Файл начинается с ``MSCF``?"""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == SIGNATURE
    except OSError:
        return False


def contains_cabinet(path: str) -> bool:
    """В файле есть хотя бы один правдоподобный кабинет?"""
    handle, data = _open_mapped(path)
    try:
        for _offset in iter_cabinets(data, limit=1):
            return True
        return False
    finally:
        try:
            if hasattr(data, "close"):
                data.close()
        except (BufferError, ValueError):
            pass
        if handle is not None:
            handle.close()
