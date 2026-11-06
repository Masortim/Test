"""Свой распаковщик контейнеров Inno Setup 6.x — без 7-Zip и без запуска установщика.

Зачем это нужно сборщику
------------------------
Inno Setup (PyCharm, и вообще любой современный установщик JetBrains и не
только) — это PE-файл, к которому приклеена таблица смещений, а за ней —
сериализованный заголовок и поток сжатых «чанков». Сторонний 7-Zip читает
такой контейнер напрямую, но когда 7-Zip на компьютере нет, раньше Portablizer
честно говорил «достать содержимое нечем» и на этом всё: установщик при этом
ещё и падал с кодом 1 («не удалось инициализировать установщик»), так что
портатив не создавался вовсе.

Здесь тот же контейнер разбирается стандартной библиотекой Python:

* :func:`locate_offsets` — находит таблицу смещений: либо по указателю на
  константном смещении 0x30 (Inno < 5.1.5), либо в PE-ресурсе с ID 11111
  (Inno 5.1.5+, то есть все 6.x);
* :func:`parse_header` — читает заголовок формата данных 6.x и доходит до
  списков файлов и «data entries» (ссылок файлов на chanки);
* :func:`decompress_chunk` — разжимает chanк: LZMA1 (с 5-байтовым заголовком
  свойств, как у Inno), zlib, bzip2 или просто stored;
* :func:`decode_call_instructions` — обратное преобразование
  ``TransformCallInstructions``: компилятор Inno при сжатии исполняемых файлов
  «превращает» относительные адреса CALL/JMP (E8/E9) в псевдоабсолютные, и без
  обратного преобразования извлечённый .exe был бы битым;
* :func:`extract_installer` — всё вместе: достаёт файлы из корня ``{app}`` в
  рабочую папку, не запуская код установщика вовсе.

Шифрование chanков (``ChunkEncrypted``, включается паролем в [Setup]) здесь не
поддерживается — о нём говорится честной ошибкой. Формат проверен против
innoextract и исходников Inno Setup 6.x (jrsoftware/issrc, ветка is6);
поддерживается формат данных 6.x (строка ``Inno Setup Setup Data (6.x.y)``).
"""
from __future__ import annotations

import bz2
import lzma
import os
import re
import shutil
import struct
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

__all__ = [
    "InnoError",
    "looks_like_inno",
    "extract_installer",
]


class InnoError(Exception):
    """Читаемая причина, почему контейнер Inno Setup не удалось разобрать."""


#: Смещение в PE-файле, по которому Inno Setup до 5.1.5 хранил указатель на
#: таблицу смещений (сейчас — в PE-ресурсе, см. ниже).
LOADER_PTR_OFFSET = 0x30
LOADER_PTR_MAGIC = 0x6F6E6E49  # "Inno" little-endian

#: Inno Setup 5.1.5+ кладёт таблицу смещений в PE-ресурс типа RT_RCDATA (10)
#: с именем (ID) 11111.
RESOURCE_TYPE_RCDATA = 10
RESOURCE_NAME_INSTALLER = 11111

#: Магик chanка сжатых данных внутри потока slices.
CHUNK_MAGIC = b"zlb\x1a"

#: Методы сжатия из заголовка (TSetupCompressMethod, 6.x).
COMPRESS_STORED = 0
COMPRESS_ZLIB = 1
COMPRESS_BZIP2 = 2
COMPRESS_LZMA = 3
COMPRESS_LZMA2 = 4

#: Биты флагов file entry (порядок битов — как в innoextract/Shared.Struct).
FO_DONT_COPY = 19

#: Биты флагов data entry (file location).
DE_CALL_INSTRUCTION_OPTIMIZED = 4
DE_CHUNK_ENCRYPTED = 6
DE_CHUNK_COMPRESSED = 7

#: Размер буфера, которым Inno обрабатывает TransformCallInstructions — ровно
#: такой же нужен здесь, иначе адреса «поплывут».
_TRANSFORM_BLOCK = 65535

_SETUP_ID_RE = re.compile(rb"Inno Setup Setup Data \((\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\)")


@dataclass
class _FileEntry:
    dest_name: str
    location: int
    options: int
    file_type: int


@dataclass
class _DataEntry:
    first_slice: int
    sort_offset: int
    file_offset: int
    file_size: int
    chunk_size: int
    options: int


@dataclass
class _Header:
    version: Tuple[int, int, int, int]
    compression: int
    files: List[_FileEntry] = field(default_factory=list)
    data_entries: List[_DataEntry] = field(default_factory=list)


class _Reader:
    """Маленький little-endian-читатель поверх открытого файла."""

    def __init__(self, fh):
        self.fh = fh

    def seek(self, offset: int) -> None:
        self.fh.seek(offset)

    def read(self, size: int) -> bytes:
        data = self.fh.read(size)
        if len(data) != size:
            raise InnoError("файл установщика обрезан: не хватило байтов")
        return data

    def _unpack(self, fmt: str):
        return struct.unpack("<" + fmt, self.read(struct.calcsize("<" + fmt)))[0]

    def u8(self) -> int:
        return self._unpack("B")

    def u16(self) -> int:
        return self._unpack("H")

    def u32(self) -> int:
        return self._unpack("I")

    def u64(self) -> int:
        return self._unpack("Q")

    def i16(self) -> int:
        return self._unpack("h")

    def i32(self) -> int:
        return self._unpack("i")

    def i64(self) -> int:
        return self._unpack("q")

    def boolean(self) -> bool:
        return self.u8() != 0

    def enum(self) -> int:
        return self.u8()

    def raw_string(self) -> bytes:
        """Строка с префиксом длины: u32 байт + сами байты."""
        length = self.u32()
        if length > 256 * 1024 * 1024:
            raise InnoError("нереальная длина строки в заголовке Inno")
        return self.read(length) if length else b""

    def ustring(self) -> str:
        """Unicode-строка (формат 6.x): UTF-16LE."""
        return self.raw_string().decode("utf-16-le", "replace")

    def ansi_string(self) -> str:
        return self.raw_string().decode("cp1252", "replace")

    def flags(self, count: int) -> int:
        """Набор флагов: по 8 штук в байте, 3 байта всегда дополняются до 4."""
        nbytes = (count + 7) // 8
        if nbytes == 3:
            nbytes = 4
        return int.from_bytes(self.read(nbytes), "little")

    def winver(self) -> None:
        """TSetupVersionData: win(2+1+1) + nt(2+1+1) + service pack(1+1)."""
        self.read(10)

    def condition_data(self) -> None:
        """components/tasks/languages/check/after/before — 6 строк, нам не нужны."""
        for _ in range(6):
            self.ustring()


# ---------------------------------------------------------------------------
# Локация данных внутри PE
# ---------------------------------------------------------------------------

def locate_offsets(fh) -> Tuple[int, int]:
    """Возвращает ``(header_offset, data_offset)`` — смещения заголовка и данных.

    Сначала пробуется указатель на константном смещении 0x30 (Inno < 5.1.5),
    затем PE-ресурс 10/11111 (Inno 5.1.5+ — все 6.x).
    """
    fh.seek(0, os.SEEK_END)
    file_size = fh.tell()
    if file_size < 0x40:
        raise InnoError("файл слишком мал, чтобы быть установщиком Inno")

    def read_offset_table(pos: int) -> Tuple[int, int]:
        fh.seek(pos)
        magic = fh.read(12)
        if len(magic) != 12:
            raise InnoError("таблица смещений Inno обрезана")
        fh.seek(pos + 12)
        revision = struct.unpack("<I", fh.read(4))[0]      # >= 5.1.5, всегда 1
        _checksum = struct.unpack("<I", fh.read(4))[0]
        _exe_offset = struct.unpack("<I", fh.read(4))[0]
        _exe_size = struct.unpack("<I", fh.read(4))[0]
        _exe_crc = struct.unpack("<I", fh.read(4))[0]
        header_offset = struct.unpack("<I", fh.read(4))[0]
        data_offset = struct.unpack("<I", fh.read(4))[0]
        if not header_offset or header_offset >= file_size:
            raise InnoError("в таблице смещений Inno неверный header_offset")
        if not data_offset or data_offset >= file_size:
            raise InnoError("в таблице смещений Inno неверный data_offset")
        return header_offset, data_offset

    # Вариант 1: указатель по адресу 0x30 (старые версии, «Inno» + offset + ~offset).
    fh.seek(LOADER_PTR_OFFSET)
    head = fh.read(12)
    if len(head) == 12:
        magic, table_off, not_table = struct.unpack("<III", head)
        if magic == LOADER_PTR_MAGIC and table_off == (~not_table) & 0xFFFFFFFF \
                and 0 < table_off < file_size:
            return read_offset_table(table_off)

    # Вариант 2: PE-ресурс RT_RCDATA/11111 (Inno 5.1.5+).
    try:
        res_off = _pe_resource_data_offset(fh)
    except InnoError:
        raise InnoError("таблицу смещений Inno не нашли ни по указателю, ни в ресурсах PE")
    return read_offset_table(res_off)


def _pe_resource_data_offset(fh) -> int:
    """Смещение данных PE-ресурса (RT_RCDATA, ID 11111, первый язык)."""
    fh.seek(0x3C)
    e_lfanew = struct.unpack("<I", fh.read(4))[0]
    fh.seek(e_lfanew)
    if fh.read(4) != b"PE\x00\x00":
        raise InnoError("это не PE-файл")
    fh.seek(e_lfanew + 4)
    fh.seek(2, os.SEEK_CUR)
    nsections = struct.unpack("<H", fh.read(2))[0]
    fh.seek(12, os.SEEK_CUR)
    opt_size = struct.unpack("<H", fh.read(2))[0]
    fh.seek(2, os.SEEK_CUR)
    opt_start = fh.tell()
    magic = struct.unpack("<H", fh.read(2))[0]
    dd_base = opt_start + (112 if magic == 0x20B else 96)
    fh.seek(dd_base + 2 * 8)
    res_rva = struct.unpack("<I", fh.read(4))[0]
    if not res_rva:
        raise InnoError("в PE нет ресурсной директории")
    sections = []
    fh.seek(opt_start + opt_size)
    for _ in range(nsections):
        fh.seek(8, os.SEEK_CUR)
        vsize, vaddr = struct.unpack("<II", fh.read(8))
        fh.read(4)
        raw_addr = struct.unpack("<I", fh.read(4))[0]
        fh.seek(16, os.SEEK_CUR)
        sections.append((vaddr, vsize, raw_addr))

    def to_file_offset(rva: int) -> int:
        for vaddr, vsize, raw_addr in sections:
            if vaddr <= rva < vaddr + max(vsize, 1):
                return rva - vaddr + raw_addr
        return 0

    res_off = to_file_offset(res_rva)
    if not res_off:
        raise InnoError("ресурсная директория PE не отображается на файл")

    def find_entry(offset: int, entry_id: Optional[int]) -> int:
        fh.seek(offset)
        fh.seek(12, os.SEEK_CUR)
        n_named, n_id = struct.unpack("<HH", fh.read(4))
        fh.seek(n_named * 8, os.SEEK_CUR)
        if entry_id is None:
            _id, off = struct.unpack("<II", fh.read(8))
            return off
        for _ in range(n_id):
            eid, off = struct.unpack("<II", fh.read(8))
            if eid == entry_id:
                return off
        return 0

    def descend(rel: int) -> int:
        if not rel & 0x80000000:
            raise InnoError("ожидалась таблица ресурсов, а попался лист")
        return (rel & 0x7FFFFFFF) + res_off

    type_rel = find_entry(res_off, RESOURCE_TYPE_RCDATA)
    name_rel = find_entry(descend(type_rel), RESOURCE_NAME_INSTALLER) \
        if type_rel else 0
    leaf_rel = find_entry(descend(name_rel), None) if name_rel else 0
    if not leaf_rel or leaf_rel & 0x80000000:
        raise InnoError("ресурс установщика Inno повреждён")
    fh.seek((leaf_rel & 0x7FFFFFFF) + res_off)
    data_rva, _size = struct.unpack("<II", fh.read(8))
    data_off = to_file_offset(data_rva)
    if not data_off:
        raise InnoError("данные ресурса Inno не отображаются на файл")
    return data_off


# ---------------------------------------------------------------------------
# Разбор заголовка (формат данных 6.x)
# ---------------------------------------------------------------------------

def _parse_version(reader: _Reader) -> Tuple[int, int, int, int]:
    blob = reader.read(64)
    match = _SETUP_ID_RE.search(blob)
    if not match:
        raise InnoError("не узнана сигнатура данных Inno Setup (не 6.x?)")
    nums = [int(g) for g in match.groups(default="0")]
    version = tuple((nums + [0, 0, 0, 0])[:4])
    if version[0] != 6:
        raise InnoError(
            f"формат данных Inno Setup {version[0]}.{version[1]}этот модуль "
            "читает только 6.x — попробуйте с установленным 7-Zip")
    return version  # type: ignore[return-value]


def parse_header(fh, header_offset: int) -> _Header:
    """Читает заголовок и возвращает файлы + data entries (формат 6.x)."""
    reader = _Reader(fh)
    reader.seek(header_offset)
    version = _parse_version(reader)
    major, minor, build, _rev = version
    v630 = version >= (6, 3, 0, 0)
    v640 = version >= (6, 4, 0, 0)
    v6401 = version >= (6, 4, 0, 1)
    v610 = version >= (6, 1, 0, 0)

    header = _Header(version=version, compression=COMPRESS_STORED)

    # --- строковые поля заголовка (порядок фиксирован форматом 6.x) ---
    for _ in range(29):
        reader.ustring()
    if v630:
        reader.ustring()   # architectures_allowed_expr
        reader.ustring()   # architectures_installed_in_64bit_mode_expr
    reader.ansi_string()   # license_text
    reader.ansi_string()   # info_before
    reader.ansi_string()   # info_after
    reader.raw_string()    # compiled_code

    language_count = reader.u32()
    message_count = reader.u32()
    permission_count = reader.u32()
    type_count = reader.u32()
    component_count = reader.u32()
    task_count = reader.u32()
    directory_count = reader.u32()
    file_count = reader.u32()
    data_count = reader.u32()
    icon_count = reader.u32()
    ini_count = reader.u32()
    registry_count = reader.u32()
    delete_count = reader.u32()
    uninstall_delete_count = reader.u32()
    run_count = reader.u32()
    uninstall_run_count = reader.u32()

    if max(language_count, file_count, data_count, registry_count) > 1_000_000:
        raise InnoError("счётчики записей в заголовке Inno нереальные — файл повреждён?")

    reader.winver()
    if not v6401:
        reader.u32()       # back_color
        reader.u32()       # back_color2
    reader.enum()          # wizard_style
    reader.u32()           # wizard_resize_percent_x
    reader.u32()           # wizard_resize_percent_y
    reader.enum()          # image_alpha_format
    reader.read(4 if v640 else 20)   # password hash (нам не нужен)
    reader.read(44 if v640 else 8)   # password salt (нам не нужна)
    reader.i64()           # extra_disk_space_required
    reader.u32()           # slices_per_disk
    reader.enum()          # uninstall_log_mode
    reader.enum()          # dir_exists_warning
    reader.enum()          # privileges_required
    reader.flags(2)        # privileges_required_override_allowed
    reader.enum()          # show_language_dialog
    reader.enum()          # language_detection
    header.compression = reader.enum()
    if not v630:
        reader.flags(5)    # architectures_allowed / install_in_64bit
        reader.flags(5)
    reader.enum()          # disable_dir_page
    reader.enum()          # disable_program_group_page
    reader.u64()           # uninstall_display_size
    reader.flags(44 if v630 else 43)   # options

    # --- записи: сначала все «метаданные», затем files и data entries ---
    for _ in range(language_count):
        reader.ustring()   # name
        reader.ustring()   # language_name
        reader.ustring()   # dialog_font
        reader.ustring()   # title_font
        reader.ustring()   # welcome_font
        reader.ustring()   # copyright_font
        reader.raw_string()  # data
        reader.raw_string()  # license_text
        reader.raw_string()  # info_before
        reader.raw_string()  # info_after
        reader.u32()       # language_id
        reader.u32()       # dialog_font_size
        reader.u32()       # title_font_size
        reader.u32()       # welcome_font_size
        reader.u32()       # copyright_font_size
        reader.boolean()   # right_to_left
    for _ in range(message_count):
        reader.ustring()
        reader.raw_string()
        reader.i32()
    for _ in range(permission_count):
        reader.raw_string()
    for _ in range(type_count):
        for _ in range(4):
            reader.ustring()
        reader.winver()
        reader.flags(1)
        reader.enum()
        reader.u64()
    for _ in range(component_count):
        for _ in range(5):
            reader.ustring()
        reader.u64()       # extra_disk_space
        reader.i32()       # level
        reader.boolean()   # used
        reader.winver()
        reader.flags(5)
        reader.u64()       # size
    for _ in range(task_count):
        for _ in range(6):
            reader.ustring()
        reader.i32()       # level
        reader.boolean()   # used
        reader.winver()
        reader.flags(5)
    for _ in range(directory_count):
        reader.ustring()
        reader.condition_data()
        reader.u32()       # attributes
        reader.winver()
        reader.i16()       # permission
        reader.flags(5)

    # --- file entries: имена и ссылки на data entries ---
    for _ in range(file_count):
        reader.ustring()   # source
        dest_name = reader.ustring()
        reader.ustring()   # install_font_name
        reader.ustring()   # strong_assembly_name
        reader.condition_data()
        reader.winver()
        location = reader.u32()
        reader.u32()       # attributes
        reader.u64()       # external_size
        reader.i16()       # permission
        options = reader.flags(32)
        file_type = reader.enum()
        header.files.append(_FileEntry(dest_name, location, options, file_type))

    for _ in range(icon_count):
        for _ in range(6):
            reader.ustring()
        reader.condition_data()
        reader.ustring()   # app_user_model_id
        if v610:
            reader.read(16)  # toast activator CLSID
        reader.winver()
        reader.i32()       # icon_index
        reader.i32()       # show_command
        reader.enum()      # close_on_exit
        reader.u16()       # hotkey
        reader.flags(6 if v610 else 5)
    for _ in range(ini_count):
        for _ in range(4):
            reader.ustring()
        reader.condition_data()
        reader.winver()
        reader.flags(5)
    for _ in range(registry_count):
        reader.ustring()   # key
        reader.ustring()   # name
        reader.raw_string()  # value
        reader.condition_data()
        reader.winver()
        reader.u32()       # hive
        reader.i16()       # permission
        reader.enum()      # type
        reader.flags(12)
    for _ in range(delete_count + uninstall_delete_count):
        reader.ustring()
        reader.condition_data()
        reader.winver()
        reader.enum()
    for _ in range(run_count + uninstall_run_count):
        for _ in range(7):
            reader.ustring()
        reader.condition_data()
        reader.winver()
        reader.i32()       # show_command
        reader.enum()      # wait
        reader.flags(12 if v630 else (11 if v610 else 10))

    # --- data entries (file location): ссылки файлов на chanки ---
    for _ in range(data_count):
        first_slice = reader.u32()
        _last_slice = reader.u32()
        sort_offset = reader.u32()
        file_offset = reader.u64()
        file_size = reader.u64()
        chunk_size = reader.u64()
        reader.read(32 if v640 else 20)   # SHA256/SHA1 файлового хеша
        reader.i64()       # filetime
        reader.u32()       # file_version_ms
        reader.u32()       # file_version_ls
        options = reader.flags(9)
        if v630:
            reader.enum()  # sign
        header.data_entries.append(_DataEntry(
            first_slice, sort_offset, file_offset, file_size, chunk_size, options))

    return header


# ---------------------------------------------------------------------------
# Распаковка chanков
# ---------------------------------------------------------------------------

def _lzma1_decompress(payload: bytes) -> bytes:
    """LZMA1-chanк Inno: 5 байт свойств (props + dict_size) + raw-поток."""
    if len(payload) < 5:
        raise InnoError("слишком короткий LZMA-chanк")
    props = payload[0]
    if props > 9 * 5 * 5:
        raise InnoError("неверные свойства LZMA в chanке Inno")
    pb = props // 45
    lp = (props % 45) // 9
    lc = props % 9
    dict_size = struct.unpack("<I", payload[1:5])[0]
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size,
                "lc": lc, "lp": lp, "pb": pb}]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    try:
        return dec.decompress(payload[5:])
    except lzma.LZMAError as exc:
        raise InnoError(f"LZMA-chanк Inno повреждён: {exc}") from exc


def _lzma2_decompress(payload: bytes) -> bytes:
    """LZMA2-chanк (формат 7.x): 1 байт свойства словаря + raw-поток."""
    if not payload:
        raise InnoError("пустой LZMA2-chanк")
    prop = payload[0]
    if prop > 40:
        raise InnoError("неверные свойства LZMA2 в chanке Inno")
    dict_size = 0xFFFFFFFF if prop == 40 else \
        (2 | (prop & 1)) << (prop // 2 + 11)
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    try:
        return dec.decompress(payload[1:])
    except lzma.LZMAError as exc:
        raise InnoError(f"LZMA2-chanк Inno повреждён: {exc}") from exc


def decompress_chunk(payload: bytes, method: int) -> bytes:
    """Разжимает тело chanка (после 4-байтового магика) по методу из заголовка."""
    if method == COMPRESS_STORED:
        return payload
    if method == COMPRESS_ZLIB:
        try:
            return zlib.decompress(payload)
        except zlib.error as exc:
            raise InnoError(f"zlib-chanк Inno повреждён: {exc}") from exc
    if method == COMPRESS_BZIP2:
        try:
            return bz2.decompress(payload)
        except OSError as exc:
            raise InnoError(f"bzip2-chanк Inno повреждён: {exc}") from exc
    if method == COMPRESS_LZMA:
        return _lzma1_decompress(payload)
    if method == COMPRESS_LZMA2:
        return _lzma2_decompress(payload)
    raise InnoError(f"неизвестный метод сжатия Inno: {method}")


def decode_call_instructions(data: bytearray, addr_offset: int = 0) -> None:
    """Обратное преобразование TransformCallInstructions (Encode=False).

    Inno при сжатии x86/x64-исполняемого файла меняет младшие 3 байта адреса у
    każдоЙ команды CALL/JMP (E8/E9) с относительного на псевдоабсолютный —
    installer делает обратное при распаковке. Обработка идёт блоками по 65535
    байт с нарастающим ``addr_offset`` — ровно как в Setup и в компиляторе.
    """
    size = len(data)
    if size < 5:
        return
    i = 0
    limit = size - 4
    while i < limit:
        op = data[i]
        if op == 0xE8 or op == 0xE9:
            hi = data[i + 4]
            if hi == 0x00 or hi == 0xFF:
                addr = (addr_offset + i + 5) & 0xFFFFFF
                rel = data[i + 1] | (data[i + 2] << 8) | (data[i + 3] << 16)
                rel = (rel - addr) & 0xFFFFFFFF
                if rel & 0x800000:
                    data[i + 4] = (~hi) & 0xFF
                data[i + 1] = rel & 0xFF
                data[i + 2] = (rel >> 8) & 0xFF
                data[i + 3] = (rel >> 16) & 0xFF
                i += 5
                continue
        i += 1


def _decode_call_instructions_stream(src, dst, total: int) -> None:
    """То же преобразование, но потоково: читает блоками по 65535 из src."""
    addr_offset = 0
    remaining = total
    while remaining > 0:
        block_size = min(_TRANSFORM_BLOCK, remaining)
        block = bytearray(src.read(block_size))
        if len(block) != block_size:
            raise InnoError("chanк Inno обрезан при чтении")
        decode_call_instructions(block, addr_offset)
        dst.write(block)
        addr_offset = (addr_offset + block_size) & 0xFFFFFFFF
        remaining -= block_size


# ---------------------------------------------------------------------------
# Публичный интерфейс
# ---------------------------------------------------------------------------

def looks_like_inno(path: str) -> bool:
    """Быстрый признак установщика Inno Setup.

    Сначала сигнатурные строки внутри файла и указатель по смещению 0x30,
    затем — честная проба: есть ли в PE ресурс 10/11111 с таблицей смещений.
    """
    try:
        size = os.path.getsize(path)
        if size < 0x40:
            return False
        with open(path, "rb") as fh:
            head = fh.read(0x40)
            if len(head) == 0x40:
                magic = struct.unpack("<I", head[LOADER_PTR_OFFSET:LOADER_PTR_OFFSET + 4])[0]
                if magic == LOADER_PTR_MAGIC:
                    return True
            fh.seek(0)
            blob = fh.read(1024 * 1024)
            if (b"This installation was built with Inno Setup" in blob
                    or b"InnoSetupLdrWindow" in blob
                    or b"JR.Inno.Setup" in blob):
                return True
            try:
                locate_offsets(fh)
                return True
            except InnoError:
                return False
    except OSError:
        return False


def _dest_to_relpath(dest_name: str) -> Optional[str]:
    """``{app}\\bin\\x.exe`` -> ``{app}/bin/x.exe``; чужие корни ({tmp}, {sys}…) — None.

    В портатив едет только {app}: {sys}/{win} — это подмена системных файлов
    чужого ПК, а не портативность.
    """
    parts = [p for p in dest_name.replace("/", "\\").split("\\") if p]
    if not parts:
        return None
    root = parts[0].casefold()
    if root != "{app}":
        return None
    rest = parts[1:]
    if any(p in ("..", ".") or ":" in p for p in rest):
        return None
    return "/".join(parts)


def extract_installer(installer_path: str, work_dir: str,
                      log: Optional[Callable[[str], None]] = None,
                      should_cancel: Optional[Callable[[], bool]] = None,
                      ) -> Tuple[bool, str]:
    """Достаёт файлы программы из установщика Inno Setup БЕЗ его запуска.

    Файлы корня ``{app}`` кладутся в ``work_dir/{app}/...`` — дальше работает
    обычная раскладка :func:`portablizer.core.unpacker.promote_payload`.
    Возвращает ``(успех, сообщение)``.
    """
    def info(text: str) -> None:
        if log:
            log(text)

    if not os.path.isfile(installer_path):
        return False, "файл установщика недоступен"
    os.makedirs(work_dir, exist_ok=True)
    chunk_dir = os.path.join(work_dir, ".inno_chunks")
    os.makedirs(chunk_dir, exist_ok=True)
    try:
        with open(installer_path, "rb") as fh:
            header_offset, data_offset = locate_offsets(fh)
            header = parse_header(fh, header_offset)
            info(f"Inno Setup: формат данных {header.version[0]}.{header.version[1]}."
                 f"{header.version[2]}, сжатие {header.compression}, "
                 f"файлов: {len(header.files)}")

            chunk_cache: Dict[Tuple[int, int], str] = {}

            def chunk_file(entry: _DataEntry) -> str:
                key = (entry.first_slice, entry.sort_offset)
                cached = chunk_cache.get(key)
                if cached:
                    return cached
                fh.seek(data_offset + entry.sort_offset)
                magic = fh.read(4)
                if magic != CHUNK_MAGIC:
                    raise InnoError("у chanка Inno нет магики 'zlb' — контейнер повреждён")
                payload = fh.read(entry.chunk_size)
                if len(payload) != entry.chunk_size:
                    raise InnoError("chanк Inno обрезан")
                if entry.options & (1 << DE_CHUNK_ENCRYPTED):
                    raise InnoError(
                        "chanк зашифрован паролем ([Setup] Password) — без пароля "
                        "свой распаковщик его не откроет; поставьте 7-Zip или "
                        "innoextract с ключом пароля")
                if entry.options & (1 << DE_CHUNK_COMPRESSED):
                    blob = decompress_chunk(payload, header.compression)
                else:
                    blob = payload
                path = os.path.join(chunk_dir, f"chunk_{entry.sort_offset}.bin")
                with open(path, "wb") as out:
                    out.write(blob)
                chunk_cache[key] = path
                return path

            written = 0
            skipped_other_roots = 0
            for index, file_entry in enumerate(header.files):
                if should_cancel and should_cancel():
                    return False, "распаковка отменена"
                if file_entry.options & (1 << FO_DONT_COPY):
                    continue
                if file_entry.location >= len(header.data_entries):
                    continue  # внешний/скачиваемый файл — в контейнере его нет
                rel = _dest_to_relpath(file_entry.dest_name)
                if rel is None:
                    skipped_other_roots += 1
                    continue
                entry = header.data_entries[file_entry.location]
                dest = os.path.join(work_dir, *rel.split("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                src_path = chunk_file(entry)
                with open(src_path, "rb") as src, open(dest, "wb") as dst:
                    src.seek(entry.file_offset)
                    if entry.options & (1 << DE_CALL_INSTRUCTION_OPTIMIZED):
                        _decode_call_instructions_stream(src, dst, entry.file_size)
                    else:
                        remaining = entry.file_size
                        while remaining > 0:
                            block = src.read(min(8 * 1024 * 1024, remaining))
                            if not block:
                                raise InnoError("chanк Inno обрезан при чтении файла")
                            dst.write(block)
                            remaining -= len(block)
                written += 1
                if written % 50 == 0:
                    info(f"Inno Setup: извлечено файлов: {written}")

        if written == 0:
            return False, ("внутри установщика Inno не нашлось файлов корня {app}"
                           + (f" (пропущено чужих корней: {skipped_other_roots})"
                              if skipped_other_roots else ""))
        note = (f" (чужие корни вроде {{tmp}}/{{sys}} пропущены: "
                f"{skipped_other_roots})") if skipped_other_roots else ""
        return True, f"своим распаковщиком Inno извлечено файлов: {written}" + note
    except InnoError as exc:
        return False, f"свой распаковщик Inno не смог разобрать контейнер: {exc}"
    except (OSError, struct.error) as exc:
        return False, f"ошибка чтения установщика Inno: {exc}"
    finally:
        shutil.rmtree(chunk_dir, ignore_errors=True)
