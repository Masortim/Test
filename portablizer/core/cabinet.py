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
штатным ``zlib`` (MSZIP — это deflate с историей между блоками) или собственным
декодером LZX (используется во многих vc_red.cab и кабинетах DirectX).
Никаких запусков, никаких путей в командной строке, работает и на Windows,
и в тестах на любой ОС.

Формат CAB описан в MS-CAB; здесь реализована необходимая часть включая MSZIP и LZX.
"""
from __future__ import annotations

import io
import mmap
import os
import re
import struct
import zlib
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Union

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


# =============================================================================
#  LZX Decompressor for MS-CAB
# =============================================================================

_LZX_MIN_MATCH = 2
_LZX_MAX_MATCH = 257
_LZX_NUM_CHARS = 256
_LZX_BLOCKTYPE_VERBATIM = 1
_LZX_BLOCKTYPE_ALIGNED = 2
_LZX_BLOCKTYPE_UNCOMPRESSED = 3
_LZX_PRETREE_NUM_ELEMENTS = 20
_LZX_ALIGNED_NUM_ELEMENTS = 8
_LZX_NUM_SECONDARY_LENGTHS = 249
_LZX_NUM_PRIMARY_LENGTHS = 7
_LZX_FRAME_SIZE = 32768

_POSITION_SLOTS = (30, 32, 34, 36, 38, 42, 50)
_EXTRA_BITS: List[int] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16
] + [17] * 300

_POSITION_BASE: List[int] = [0] * 300
for _i in range(1, 300):
    _eb = _EXTRA_BITS[_i - 1]
    _POSITION_BASE[_i] = _POSITION_BASE[_i - 1] + (1 << _eb)


class _LzxBitReader:
    __slots__ = ("data", "pos", "bit_buf", "bits_left")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.bit_buf = 0
        self.bits_left = 0

    def ensure_bits(self, n: int) -> None:
        while self.bits_left < n:
            if self.pos + 1 < len(self.data):
                b0 = self.data[self.pos]
                b1 = self.data[self.pos + 1]
                self.pos += 2
                word = b0 | (b1 << 8)
                self.bit_buf = (self.bit_buf << 16) | word
                self.bits_left += 16
            elif self.pos < len(self.data):
                b0 = self.data[self.pos]
                self.pos += 1
                self.bit_buf = (self.bit_buf << 16) | b0
                self.bits_left += 16
            else:
                self.bit_buf = (self.bit_buf << 16)
                self.bits_left += 16

    def peek_bits(self, n: int) -> int:
        self.ensure_bits(n)
        return (self.bit_buf >> (self.bits_left - n)) & ((1 << n) - 1)

    def remove_bits(self, n: int) -> None:
        self.bits_left -= n
        self.bit_buf &= (1 << self.bits_left) - 1

    def read_bits(self, n: int) -> int:
        if n <= 0:
            return 0
        self.ensure_bits(n)
        val = (self.bit_buf >> (self.bits_left - n)) & ((1 << n) - 1)
        self.bits_left -= n
        self.bit_buf &= (1 << self.bits_left) - 1
        return val

    def align_word(self) -> None:
        rem = self.bits_left % 16
        if rem != 0:
            self.remove_bits(rem)

    def read_bytes(self, count: int) -> bytes:
        if self.bits_left > 0:
            self.bit_buf = 0
            self.bits_left = 0
        res = self.data[self.pos:self.pos + count]
        self.pos += len(res)
        return res


class _FastHuffman:
    __slots__ = ("table_bits", "empty", "table")

    def __init__(self, lengths: Sequence[int], table_bits: int = 10) -> None:
        self.table_bits = table_bits
        max_len = max(lengths) if lengths else 0
        self.empty = (max_len == 0)
        self.table: List[Optional[Union[Tuple[int, int], dict]]] = [None] * (1 << table_bits)
        if self.empty:
            return

        bl_count = [0] * (max_len + 1)
        for length in lengths:
            if length > 0:
                bl_count[length] += 1

        next_code = [0] * (max_len + 1)
        code = 0
        for bits in range(1, max_len + 1):
            code = (code + bl_count[bits - 1]) << 1
            next_code[bits] = code

        for sym, length in enumerate(lengths):
            if length == 0:
                continue
            c = next_code[length]
            next_code[length] += 1
            if length <= table_bits:
                shift = table_bits - length
                start = c << shift
                for i in range(1 << shift):
                    self.table[start + i] = (sym, length)
            else:
                prefix = c >> (length - table_bits)
                if self.table[prefix] is None:
                    self.table[prefix] = {}
                node = self.table[prefix]
                rem_bits = length - table_bits
                for b_idx in range(rem_bits - 1, -1, -1):
                    bit = (c >> b_idx) & 1
                    if b_idx == 0:
                        node[bit] = (sym, length)
                    else:
                        if bit not in node:
                            node[bit] = {}
                        node = node[bit]

    def read_sym(self, reader: _LzxBitReader) -> int:
        if self.empty:
            raise CabinetError("пустое дерево Хаффмана в блоке LZX")
        peek = reader.peek_bits(self.table_bits)
        entry = self.table[peek]
        if entry is None:
            raise CabinetError("некорректный код Хаффмана в блоке LZX")
        if isinstance(entry, tuple):
            sym, length = entry
            reader.remove_bits(length)
            return sym
        reader.remove_bits(self.table_bits)
        node = entry
        while isinstance(node, dict):
            b = reader.read_bits(1)
            if b not in node:
                raise CabinetError("некорректный длинный код Хаффмана в блоке LZX")
            node = node[b]
        sym, _length = node
        return sym


def _lzx_read_lens(reader: _LzxBitReader, lens: List[int],
                   first: int, last: int) -> None:
    pretree_lens = [reader.read_bits(4) for _ in range(20)]
    pretree = _FastHuffman(pretree_lens, table_bits=6)
    x = first
    while x < last:
        z = pretree.read_sym(reader)
        if z == 17:
            y = reader.read_bits(4) + 4
            while y > 0 and x < last:
                lens[x] = 0
                x += 1
                y -= 1
        elif z == 18:
            y = reader.read_bits(5) + 20
            while y > 0 and x < last:
                lens[x] = 0
                x += 1
                y -= 1
        elif z == 19:
            y = reader.read_bits(1) + 4
            z = pretree.read_sym(reader)
            val = (lens[x] - z) % 17
            while y > 0 and x < last:
                lens[x] = val
                x += 1
                y -= 1
        else:
            val = (lens[x] - z) % 17
            lens[x] = val
            x += 1


def decompress_lzx(data: bytes, uncompressed_size: int,
                   window_bits: int = 21) -> bytes:
    """Распаковывает поток данных формата LZX для Microsoft Cabinet."""
    if uncompressed_size <= 0:
        return b""
    if window_bits < 15 or window_bits > 21:
        window_bits = 21
    window_size = 1 << window_bits
    window = bytearray(window_size)
    window_posn = 0
    frame_posn = 0
    frame = 0

    num_pos_slots = _POSITION_SLOTS[window_bits - 15]
    num_offsets = num_pos_slots * 8
    main_tree_symbols = _LZX_NUM_CHARS + num_offsets

    main_lens = [0] * main_tree_symbols
    length_lens = [0] * _LZX_NUM_SECONDARY_LENGTHS
    aligned_lens = [0] * _LZX_ALIGNED_NUM_ELEMENTS

    main_tree: Optional[_FastHuffman] = None
    length_tree: Optional[_FastHuffman] = None
    aligned_tree: Optional[_FastHuffman] = None

    r0, r1, r2 = 1, 1, 1

    reader = _LzxBitReader(data)
    header_read = False
    intel_filesize = 0
    intel_started = False

    block_remaining = 0
    block_type = 0
    block_length = 0

    out = bytearray()
    offset = 0

    while offset < uncompressed_size:
        if not header_read:
            hdr = reader.read_bits(1)
            if hdr != 0:
                hi = reader.read_bits(16)
                lo = reader.read_bits(16)
                intel_filesize = (hi << 16) | lo
            header_read = True

        frame_size = _LZX_FRAME_SIZE
        if uncompressed_size - offset < frame_size:
            frame_size = uncompressed_size - offset

        bytes_todo = frame_size
        while bytes_todo > 0:
            if block_remaining == 0:
                if block_type == _LZX_BLOCKTYPE_UNCOMPRESSED and (block_length & 1):
                    reader.read_bytes(1)

                block_type = reader.read_bits(3)
                hi = reader.read_bits(16)
                lo = reader.read_bits(8)
                block_remaining = block_length = (hi << 8) | lo

                if block_type == _LZX_BLOCKTYPE_ALIGNED:
                    aligned_lens = [reader.read_bits(3) for _ in range(8)]
                    aligned_tree = _FastHuffman(aligned_lens, table_bits=6)
                    _lzx_read_lens(reader, main_lens, 0, 256)
                    _lzx_read_lens(reader, main_lens, 256, main_tree_symbols)
                    main_tree = _FastHuffman(main_lens, table_bits=10)
                    if main_lens[0xE8] != 0:
                        intel_started = True
                    _lzx_read_lens(reader, length_lens, 0, _LZX_NUM_SECONDARY_LENGTHS)
                    length_tree = _FastHuffman(length_lens, table_bits=8)
                elif block_type == _LZX_BLOCKTYPE_VERBATIM:
                    _lzx_read_lens(reader, main_lens, 0, 256)
                    _lzx_read_lens(reader, main_lens, 256, main_tree_symbols)
                    main_tree = _FastHuffman(main_lens, table_bits=10)
                    if main_lens[0xE8] != 0:
                        intel_started = True
                    _lzx_read_lens(reader, length_lens, 0, _LZX_NUM_SECONDARY_LENGTHS)
                    length_tree = _FastHuffman(length_lens, table_bits=8)
                elif block_type == _LZX_BLOCKTYPE_UNCOMPRESSED:
                    intel_started = True
                    reader.align_word()
                    buf = reader.read_bytes(12)
                    if len(buf) < 12:
                        raise CabinetError("обрыв несжатого блока LZX")
                    r0, r1, r2 = struct.unpack("<III", buf)
                else:
                    raise CabinetError(f"незнакомый тип блока LZX: {block_type}")

            this_run = min(block_remaining, bytes_todo)
            bytes_todo -= this_run
            block_remaining -= this_run

            if block_type in (_LZX_BLOCKTYPE_VERBATIM, _LZX_BLOCKTYPE_ALIGNED):
                if main_tree is None:
                    raise CabinetError("дерево Хаффмана не инициализировано")
                while this_run > 0:
                    main_elem = main_tree.read_sym(reader)
                    if main_elem < _LZX_NUM_CHARS:
                        window[window_posn] = main_elem
                        window_posn += 1
                        this_run -= 1
                    else:
                        main_elem -= _LZX_NUM_CHARS
                        match_length = main_elem & _LZX_NUM_PRIMARY_LENGTHS
                        if match_length == _LZX_NUM_PRIMARY_LENGTHS:
                            if length_tree is None:
                                raise CabinetError("дерево длин не инициализировано")
                            match_length += length_tree.read_sym(reader)
                        match_length += _LZX_MIN_MATCH

                        match_offset = main_elem >> 3
                        if match_offset == 0:
                            match_offset = r0
                        elif match_offset == 1:
                            match_offset = r1
                            r1 = r0
                            r0 = match_offset
                        elif match_offset == 2:
                            match_offset = r2
                            r2 = r0
                            r0 = match_offset
                        else:
                            extra = 17 if match_offset >= 36 else _EXTRA_BITS[match_offset]
                            match_offset = _POSITION_BASE[match_offset] - 2
                            if extra >= 3 and block_type == _LZX_BLOCKTYPE_ALIGNED:
                                if extra > 3:
                                    v_bits = reader.read_bits(extra - 3)
                                    match_offset += (v_bits << 3)
                                if aligned_tree is None:
                                    raise CabinetError("дерево выравнивания не инициализировано")
                                a_bits = aligned_tree.read_sym(reader)
                                match_offset += a_bits
                            elif extra > 0:
                                v_bits = reader.read_bits(extra)
                                match_offset += v_bits

                            r2 = r1
                            r1 = r0
                            r0 = match_offset

                        for _ in range(match_length):
                            src = (window_posn - match_offset) % window_size
                            window[window_posn] = window[src]
                            window_posn += 1

                        this_run -= match_length

                if this_run < 0:
                    block_remaining -= (-this_run)

            elif block_type == _LZX_BLOCKTYPE_UNCOMPRESSED:
                chunk = reader.read_bytes(this_run)
                if len(chunk) < this_run:
                    raise CabinetError("обрыв несжатых данных LZX")
                window[window_posn:window_posn + len(chunk)] = chunk
                window_posn += len(chunk)
                this_run = 0

        reader.align_word()

        frame_bytes = window[frame_posn:frame_posn + frame_size]
        if intel_started and intel_filesize > 0 and frame < 32768 and frame_size > 10:
            frame_arr = bytearray(frame_bytes)
            curpos = offset
            p = 0
            limit = frame_size - 10
            while p < limit:
                if frame_arr[p] == 0xE8:
                    abs_off = struct.unpack_from("<i", frame_arr, p + 1)[0]
                    if -curpos <= abs_off < intel_filesize:
                        rel_off = abs_off - curpos if abs_off >= 0 else abs_off + intel_filesize
                        struct.pack_into("<i", frame_arr, p + 1, rel_off)
                    p += 4
                    curpos += 4
                p += 1
                curpos += 1
            frame_bytes = bytes(frame_arr)

        out.extend(frame_bytes)
        offset += frame_size
        frame_posn = (frame_posn + frame_size) % window_size
        window_posn = window_posn % window_size
        frame += 1

    return bytes(out[:uncompressed_size])


# =============================================================================
#  Cabinet Container Structures
# =============================================================================

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
        if compression not in (COMPRESSION_NONE, COMPRESSION_MSZIP, COMPRESSION_LZX):
            raise CabinetError(
                "папка кабинета сжата способом, который умеет только Windows "
                f"(код {compression})")
        position = folder.offset

        if compression == COMPRESSION_LZX:
            wnd_bits = (folder.compression >> 8) & 0x1F
            if not 15 <= wnd_bits <= 21:
                wnd_bits = 21
            compressed_data = bytearray()
            total_uncompressed = 0
            for _ in range(folder.blocks):
                head = self._read(position, 8)
                _checksum, compressed, uncompressed = struct.unpack("<IHH", head)
                position += 8 + getattr(self, "_data_reserve", 0)
                block = self._read(position, compressed)
                position += compressed
                compressed_data.extend(block)
                total_uncompressed += uncompressed
                if total_uncompressed > MAX_TOTAL_SIZE:
                    raise CabinetError("папка кабинета неправдоподобно велика")
            try:
                folder.cache = decompress_lzx(bytes(compressed_data), total_uncompressed, wnd_bits)
            except Exception as exc:
                raise CabinetError(f"ошибка распаковки LZX: {exc}") from exc
            return folder.cache

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
