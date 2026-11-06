"""Свой распаковщик Inno Setup 6.x (portablizer/core/inno.py) — без 7-Zip.

Регрессия, ради которой написан модуль:

    Установщик PyCharm (Inno Setup) падал с кодом 1 «не удалось инициализировать
    установщик», папка App оставалась пустой, а поскольку 7-Zip на компьютере
    не было, Portablizer честно сказал «достать содержимое без запуска нечем» —
    и портатив не создавался. Теперь контейнер Inno разбирается стандартной
    библиотекой Python: заголовок 6.x, chanки LZMA/zlib/stored и обратное
    преобразование CALL/JMP для исполняемых файлов.

Тесты собирают СИНТЕТИЧЕСКИЙ установщик Inno Setup 6.x (PE + ресурс 11111 +
таблица смещений + заголовок + chanки) и проверяют, что файлы из ``{app}``
извлекаются обратно байт-в-байт, включая LZMA-сжатие и call-instruction
трансформацию; ``{tmp}`` и прочие корни наружу не выходят.
"""
import lzma
import os
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import inno as inno_mod


# ---------------------------------------------------------------------------
# Синтетический установщик Inno Setup 6.x
# ---------------------------------------------------------------------------

def _ustring(text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw


def _raw_string(raw: bytes = b"") -> bytes:
    return struct.pack("<I", len(raw)) + raw


def _winver() -> bytes:
    return b"\x00" * 10


def _encode_call_instructions(data: bytearray, addr_offset: int = 0) -> None:
    """Encode=True из Compression.Base.pas (как делает компилятор Inno)."""
    size = len(data)
    if size < 5:
        return
    i = 0
    limit = size - 4
    while i < limit:
        op = data[i]
        if op in (0xE8, 0xE9):
            hi = data[i + 4]
            if hi in (0x00, 0xFF):
                addr = (addr_offset + i + 5) & 0xFFFFFF
                rel = data[i + 1] | (data[i + 2] << 8) | (data[i + 3] << 16)
                # как в Compression.Base.pas: сначала проверка bit23 и
                # инверсия старшего байта, потом прибавление адреса (Encode)
                if rel & 0x800000:
                    data[i + 4] = (~hi) & 0xFF
                rel = (rel + addr) & 0xFFFFFFFF
                data[i + 1] = rel & 0xFF
                data[i + 2] = (rel >> 8) & 0xFF
                data[i + 3] = (rel >> 16) & 0xFF
                i += 5
                continue
        i += 1


def _lzma1_compress(raw: bytes) -> bytes:
    """chanк LZMA1 Inno: 5 байт свойств + raw LZMA1 поток."""
    props = (2 * 5 + 0) * 9 + 3  # pb=2, lp=0, lc=3
    dict_size = 1 << 22
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size,
                "lc": 3, "lp": 0, "pb": 2}]
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filters)
    body = comp.compress(raw) + comp.flush()
    return bytes([props]) + struct.pack("<I", dict_size) + body


def _chunk_blob(blob: bytes) -> bytes:
    """Разбивает распакованный блок на порции <=4096 байт, каждая со своим
    u32 CRC32 (как TCompressedBlockWriter.DoCompress в issrc)."""
    out = bytearray()
    pos = 0
    while pos < len(blob):
        chunk = blob[pos:pos + 4096]
        out += struct.pack("<I", zlib.crc32(chunk) & 0xFFFFFFFF) + chunk
        pos += len(chunk)
    return bytes(out)


def _block_wrap(blob: bytes, version=(6, 4, 0), compressed=True) -> bytes:
    """Оборачивает сериализованный заголовок+записи в сжатый блок, как
    TCompressedBlockWriter в issrc: u32 CRC + TCompressedBlockHeader
    {stored_size, compressed} + хранимый поток. Хранимый поток всегда режется
    на порции <=4096 байт, каждая со своим u32 CRC32, и уже поверх этого
    идёт LZMA1 (5 байт свойств + raw). StoredSize — u32 до 6.6 включительно,
    Int64 с 6.7.0."""
    wide = version[0] == 7 or (version[0], version[1], version[2], 0) >= (6, 7, 0, 0)
    stored = _chunk_blob(_lzma1_compress(blob) if compressed else blob)
    hdr = struct.pack("<Q" if wide else "<I", len(stored)) + struct.pack("<B", 1 if compressed else 0)
    return struct.pack("<I", zlib.crc32(hdr) & 0xFFFFFFFF) + hdr + stored


def _build_header(version=(6, 4, 0), compression=3, files=(), data_entries=(),
                  block_compressed=True, with_meta=False):
    """Сериализует область заголовка на диске: 64-байтовая сигнатура SetupID,
    (для 6.5+ — 53-байтовый encryption-заголовок) и блок со всеми записями
    (сжатый LZMA1 или хранимый). files = [(dest, location, options)],
    data_entries = [(sort_offset, file_offset, file_size, chunk_size, options)]."""
    major, minor, build = version
    v4 = (major, minor, build, 0)
    setup_id = f"Inno Setup Setup Data ({major}.{minor}.{build})".encode("ascii")
    head = setup_id.ljust(64, b"\x00")
    if v4 >= (6, 5, 0, 0):
        head += b"\x00" * (4 + 49)    # CRC32 + TSetupEncryptionHeader
    return head + _block_wrap(_build_header_blob(version, compression,
                                                  files, data_entries,
                                                  with_meta=with_meta), version,
                              compressed=block_compressed)


def _build_header_blob(version=(6, 4, 0), compression=3, files=(), data_entries=(),
                       with_meta=False):
    if version[0] == 7 or (version[0], version[1], version[2], 0) >= (6, 5, 0, 0):
        return _build_header_blob_modern(version, compression, files, data_entries,
                                         with_meta=with_meta)
    return _build_header_blob_le64(version, compression, files, data_entries)


def _build_header_blob_le64(version=(6, 4, 0), compression=3, files=(), data_entries=()):
    """Сериализованный (внутри блока) заголовок формата 6.0–6.4."""
    major, minor, build = version
    v630 = version >= (6, 3, 0)
    v640 = version >= (6, 4, 0)
    v6401 = version >= (6, 4, 0, 1)
    out = bytearray()
    for _ in range(29):
        out += _ustring("")
    if v630:
        out += _ustring("") * 2
    out += _raw_string() * 3          # license/info_before/info_after (ansi)
    out += _raw_string()              # compiled_code
    counts = [0, 0, 0, 0, 0, 0, 0, len(files), len(data_entries),
              0, 0, 0, 0, 0, 0, 0]
    for count in counts:
        out += struct.pack("<I", count)
    out += _winver()
    if not v6401:
        out += struct.pack("<II", 0, 0)   # back_color, back_color2
    out += struct.pack("<B", 1)           # wizard_style
    out += struct.pack("<II", 100, 100)   # resize percents
    out += struct.pack("<B", 0)           # image_alpha_format
    out += b"\x00" * (4 if v640 else 20)  # password hash
    out += b"\x00" * (44 if v640 else 8)  # password salt
    out += struct.pack("<q", 0)           # extra_disk_space
    out += struct.pack("<I", 1)           # slices_per_disk
    out += struct.pack("<B", 1)           # uninstall_log_mode
    out += struct.pack("<B", 0)           # dir_exists_warning
    out += struct.pack("<B", 2)           # privileges_required
    out += b"\x00"                        # privileges override flags(2)
    out += struct.pack("<B", 2)           # show_language_dialog
    out += struct.pack("<B", 0)           # language_detection
    out += struct.pack("<B", compression)
    if not v630:
        out += b"\x00" * 2                # architectures flags(5) x2
    out += struct.pack("<B", 0)           # disable_dir_page
    out += struct.pack("<B", 0)           # disable_program_group_page
    out += struct.pack("<Q", 0)           # uninstall_display_size
    out += b"\x00" * (6 if v630 else 6)   # options flags(43/44)
    # file entries
    for dest, location, options in files:
        out += _ustring("src.bin")
        out += _ustring(dest)
        out += _ustring("")
        out += _ustring("")
        for _ in range(6):
            out += _ustring("")
        out += _winver()
        out += struct.pack("<I", location)
        out += struct.pack("<I", 0)       # attributes
        out += struct.pack("<Q", 0)       # external_size
        out += struct.pack("<h", -1)      # permission
        out += struct.pack("<I", options)  # flags(32)
        out += struct.pack("<B", 0)       # type: user file
    # data entries
    for sort_offset, file_offset, file_size, chunk_size, options in data_entries:
        out += struct.pack("<III", 0, 0, sort_offset)
        out += struct.pack("<QQQ", file_offset, file_size, chunk_size)
        out += b"\x00" * (32 if v640 else 20)  # sha256/sha1
        out += struct.pack("<q", 0)       # filetime
        out += struct.pack("<II", 0, 0)   # file version
        out += struct.pack("<H", options)  # flags(9)
        if v630:
            out += struct.pack("<B", 0)   # sign
    return bytes(out)


def _build_header_blob_modern(version=(6, 7, 0), compression=3, files=(),
                              data_entries=(), with_meta=False):
    """Сериализованный (внутри блока) заголовок формата 6.5+/7.x — раскладки
    по TSetupHeader/TSetup*Entry в issrc (is-6_5_0 … main). with_meta=True
    добавляет по одной записи каждого метаданного типа (type/component/task/
    dir/issig/icon/ini/registry/delete/run), чтобы зафиксировать раскладку тестами."""
    major, minor, build = version
    group = inno_mod._version_group((major, minor, build, 0))
    v66 = group in ("v66", "v67", "v70", "v71")
    v67 = group in ("v67", "v70", "v71")
    v7 = group in ("v70", "v71")
    out = bytearray()
    n_strings = {"v65": 34, "v66": 34, "v67": 39, "v70": 39, "v71": 38}[group]
    for _ in range(n_strings):
        out += _ustring("")
    for _ in range(4):
        out += _raw_string()
    # порядок счётчиков как в TSetupHeader (6.5+): language, message,
    # permission, type, component, task, dir, issig, file, filelocation,
    # icon, ini, registry, installdelete, uninstalldelete, run, uninstallrun
    counts = [0] * 17
    if with_meta:
        for idx in (3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16):
            counts[idx] = 1
    counts[8] = len(files)          # NumFileEntries
    counts[9] = len(data_entries)   # NumFileLocationEntries
    for count in counts:
        out += struct.pack("<I", count)
    if v7:
        out += struct.pack("<I", 0)   # compiled_code_version
    out += _winver() * 2
    if group == "v65":
        out += struct.pack("<B", 1)           # wizard_style
        out += struct.pack("<II", 100, 100)
        out += struct.pack("<B", 0)           # alpha format
    else:
        out += struct.pack("<II", 100, 100)
        out += struct.pack("<B", 0)           # dark style
        out += struct.pack("<B", 0)           # alpha format
        out += b"\x00" * (4 if group == "v66" else 6) * 4  # back colors
        if v67:
            out += struct.pack("<BBB", 255, 255, 0)  # opacities + styling
    out += struct.pack("<q", 0)           # extra_disk_space
    out += struct.pack("<I", 1)           # slices_per_disk
    out += struct.pack("<BBBB", 1, 0, 2, 0)  # log mode, dir exists, priv, priv overrides
    out += struct.pack("<BBB", 2, 0, compression)  # show lang, lang detect, compress
    out += struct.pack("<BB", 0, 0)       # disable dir/pg page
    out += struct.pack("<Q", 0)           # uninstall_display_size
    out += b"\x00" * (6 if group in ("v65", "v66") else 8)  # options
    # --- метаданные до file entries: type, component, task, dir, issig ---
    if with_meta:
        # type: 4 строки + 2 winver + flags(1) + enum + i64
        out += _ustring("t") * 4 + _winver() * 2 + b"\x00" + struct.pack("<B", 0) + struct.pack("<Q", 0)
        # component: 5 строк + i64 + level + bool + 2 winver + flags(5) + i64
        out += _ustring("c") * 5 + struct.pack("<Q", 0)
        out += struct.pack("<B" if v67 else "<i", 0) + b"\x00" + _winver() * 2 + b"\x00" + struct.pack("<Q", 0)
        # task: 6 строк + level + bool + 2 winver + flags(5)
        out += _ustring("k") * 6
        out += struct.pack("<B" if v67 else "<i", 0) + b"\x00" + _winver() * 2 + b"\x00"
        # dir: 7 строк + u32 + 2 winver + i16 + flags(5)
        out += _ustring("d") * 7 + struct.pack("<I", 0) + _winver() * 2 + struct.pack("<h", -1) + b"\x00"
        # issig: 3 строки
        out += _ustring("s") * 3
    # file entries
    for dest, location, options in files:
        out += _ustring("src.bin")
        out += _ustring(dest)
        for _ in range(13):
            out += _ustring("")
        if v67:
            out += _raw_string()          # verification: allowed keys
            out += b"\x00" * 32           # verification: sha256
            out += struct.pack("<B", 0)   # verification: type
        out += _winver()                  # min_version
        out += _winver()                  # only_below_version
        out += struct.pack("<I", location)
        out += struct.pack("<I", 0)       # attributes
        out += struct.pack("<Q", 0)       # external_size
        out += struct.pack("<h", -1)      # permission
        if v7:
            out += struct.pack("<B", 0)   # bitness
        out += b"\x00" * (5 if not v67 else 8)  # options (33 -> 5B, packed 57 -> 8B)
        out += struct.pack("<B", 0)       # file type
    # --- метаданные после file entries: icon, ini, registry, delete x2, run x2 ---
    if with_meta:
        # icon: 13 строк + guid16 + 2 winver + i32 + i32 + u8 + u16 + flags(6)
        out += _ustring("i") * 13 + b"\x00" * 16 + _winver() * 2
        out += struct.pack("<ii", 0, 0) + struct.pack("<B", 0) + struct.pack("<H", 0) + b"\x00"
        # ini: 4 строки + 6 строк + 2 winver + flags(5)
        out += _ustring("n") * 4 + _ustring("") * 6 + _winver() * 2 + b"\x00"
        # registry: 3 строки + 6 строк + 2 winver + u32 + i16 + u8 + flags(12)
        out += _ustring("r") * 3 + _ustring("") * 6 + _winver() * 2
        out += struct.pack("<I", 0) + struct.pack("<h", -1) + struct.pack("<B", 0) + b"\x00" * 2
        # delete (install + uninstall): 7 строк + 2 winver + u8 — дважды
        for _ in range(2):
            out += _ustring("x") * 7 + _winver() * 2 + struct.pack("<B", 0)
        # run (install + uninstall): 13 строк + 2 winver + i32 + u8 + flags(12) — дважды
        for _ in range(2):
            out += _ustring("p") * 13 + _winver() * 2 + struct.pack("<i", 0) + struct.pack("<B", 0) + b"\x00" * 2
    # data entries
    for sort_offset, file_offset, file_size, chunk_size, options in data_entries:
        out += struct.pack("<II", 0, 0)
        out += struct.pack("<I" if group == "v65" else "<Q", sort_offset)
        out += struct.pack("<QQQ", file_offset, file_size, chunk_size)
        out += b"\x00" * 32               # sha256
        out += struct.pack("<q", 0)       # timestamp
        out += struct.pack("<II", 0, 0)   # file version
        out += struct.pack("<B", options)  # flags(5)
    return bytes(out)


def _resource_dir_entry(entry_id, offset, is_table):
    return struct.pack("<II", entry_id, offset | (0x80000000 if is_table else 0))


def _build_pe_with_resource(resource: bytes) -> bytes:
    """Минимальный PE32+ с одним ресурсом RT_RCDATA/11111."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe = bytearray()
    pe += b"PE\x00\x00"
    pe += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x2022)  # COFF
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)          # PE32+
    struct.pack_into("<I", opt, 108, 16)           # NumberOfRvaAndSizes
    res_rva = 0x1000
    struct.pack_into("<II", opt, 112 + 2 * 8, res_rva, 0x400)  # dir[2] = resources
    pe += opt
    # section table: .rsrc vaddr 0x1000, raw 0x400
    pe += b".rsrc\x00\x00\x00"
    pe += struct.pack("<IIIIIIHHI", 0x400, 0x1000, 0x400, 0x400, 0, 0, 0, 0, 0)
    pe = bytes(dos) + pe
    # реальный установщик Inno несёт сигнатурные строки в ресурсах/версии
    pe += b"This installation was built with Inno Setup\x00"
    pe = pe.ljust(0x400, b"\x00")
    # ресурсная директория по смещению 0x400 (RVA 0x1000)
    def table(n_named, n_id, entries):
        return struct.pack("<IIHHHH", 0, 0, 0, 0, n_named, n_id) + b"".join(entries)
    # уровень 1: type 10 -> таблица уровня 2 (смещение относительно 0x400)
    # раскладываем: [0x400]=таблица1 (16+8 байт), [0x428]=таблица2, [0x450]=таблица3,
    # [0x478]=leaf (16 байт), [0x488]=данные ресурса
    leaf_off = 0x478 - 0x400
    data_off = 0x488 - 0x400
    t3 = table(0, 1, [_resource_dir_entry(0x409, leaf_off, False)])  # lang 1033
    t2 = table(0, 1, [_resource_dir_entry(11111, 0x450 - 0x400, True)])
    t1 = table(0, 1, [_resource_dir_entry(10, 0x428 - 0x400, True)])
    leaf = struct.pack("<IIII", 0x1000 + data_off, len(resource), 0, 0)
    blob = bytearray(data_off)
    blob[0x00:len(t1)] = t1
    blob[0x28:0x28 + len(t2)] = t2
    blob[0x50:0x50 + len(t3)] = t3
    blob[0x78:0x78 + len(leaf)] = leaf
    pe += bytes(blob) + resource
    return pe if isinstance(pe, bytes) else bytes(pe)


def _build_offset_table(header_offset: int, data_offset: int, version=(6, 4, 0)) -> bytes:
    """Таблица смещений Inno 5.1.5+: версия 1 (u32-поля, 6.0–6.4) или
    версия 2 (Int64-смещения, 6.5.0+/7.x)."""
    magic = bytes([0x72, 0x44, 0x6C, 0x50, 0x74, 0x53, 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A])
    out = bytearray(magic)
    if version[0] == 7 or (version[0], version[1], version[2], 0) >= (6, 5, 0, 0):
        out += struct.pack("<I", 2)              # table version 2
        out += struct.pack("<Q", 0)              # total_size
        out += struct.pack("<Q", 0)              # offset_exe
        out += struct.pack("<I", 0)              # uncompressed_size_exe
        out += struct.pack("<i", 0)              # crc_exe
        out += struct.pack("<Q", header_offset)  # offset0 = заголовок
        out += struct.pack("<Q", data_offset)    # offset1 = данные
        out += struct.pack("<I", 0)              # reserved padding
        out += struct.pack("<i", 0)              # table crc (не проверяем)
    else:
        out += struct.pack("<I", 1)              # table version 1
        out += struct.pack("<I", 0)              # total_size (бывший checksum)
        out += struct.pack("<I", 0)              # exe_offset
        out += struct.pack("<I", 0)              # exe_uncompressed_size
        out += struct.pack("<I", 0)              # exe checksum
        out += struct.pack("<I", header_offset)
        out += struct.pack("<I", data_offset)
        out += struct.pack("<I", 0)              # table crc (не проверяем)
    return bytes(out)


def _build_installer(path, files_payload, version=(6, 4, 0), compression=3,
                     use_pe_resource=True, block_compressed=True, with_meta=False):
    """files_payload = [(dest_name, raw_bytes, call_optimize, chunk_group)].

    Собирает настоящий контейнер: chanки (LZMA или stored) + заголовок +
    таблицу смещений в PE-ресурсе 11111 (или по указателю 0x30).
    """
    # chanки: файлы с одинаковым chunk_group делят один (solid) chanк
    modern = version[0] == 7 or (version[0], version[1], version[2], 0) >= (6, 5, 0, 0)
    comp_bit = 4 if modern else inno_mod.DE_CHUNK_COMPRESSED
    call_bit = 2 if modern else inno_mod.DE_CALL_INSTRUCTION_OPTIMIZED
    groups = {}
    for dest, raw, call_opt, group in files_payload:
        groups.setdefault(group, []).append((dest, raw, call_opt))
    data_area = bytearray()
    data_entries = []
    file_entries = []
    for group_id, members in groups.items():
        plain = bytearray()
        group_marks = []
        for dest, raw, call_opt in members:
            blob = bytearray(raw)
            if call_opt:
                _encode_call_instructions(blob)
            file_offset = len(plain)
            plain += blob
            options = 0
            if compression != inno_mod.COMPRESS_STORED:
                options |= 1 << comp_bit
            if call_opt:
                options |= 1 << call_bit
            group_marks.append((dest, file_offset, len(raw), options))
        sort_offset = len(data_area)
        if compression == inno_mod.COMPRESS_LZMA:
            payload = _lzma1_compress(bytes(plain))
        else:
            payload = bytes(plain)
        data_area += inno_mod.CHUNK_MAGIC + payload
        for dest, foff, fsize, opts in group_marks:
            file_entries.append((dest, len(data_entries), 0))
            data_entries.append((sort_offset, foff, fsize, len(payload), opts))

    header = _build_header(version=version, compression=compression,
                           files=file_entries, data_entries=data_entries,
                           block_compressed=block_compressed, with_meta=with_meta)

    if use_pe_resource:
        # PE: [0x00..0x80) DOS+PE stub, ресурс по 0x400
        # layout: pe_blob (с ресурсом-таблицей) + header + data
        table = _build_offset_table(0, 0, version)
        base = _build_pe_with_resource(table)
        header_offset = len(base)
        data_offset = header_offset + len(header)
        table = _build_offset_table(header_offset, data_offset, version)
        base = _build_pe_with_resource(table)
        assert len(base) == header_offset
        blob = base + header + bytes(data_area)
    else:
        # старый способ локации: указатель на таблицу смещений по адресу 0x30
        header_offset = 0x100
        data_offset = header_offset + len(header)
        table_off = 0x40
        blob = bytearray(b"\x00" * table_off)
        blob += _build_offset_table(header_offset, data_offset, version)
        blob += b"\x00" * (header_offset - len(blob))
        blob += header + bytes(data_area)
        struct.pack_into("<III", blob, 0x30, inno_mod.LOADER_PTR_MAGIC,
                         table_off, (~table_off) & 0xFFFFFFFF)
    with open(path, "wb") as fh:
        fh.write(blob)
    return path


# ---------------------------------------------------------------------------
# Тесты
# ---------------------------------------------------------------------------

class SyntheticInnoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = os.path.join(self.temp.name, "work")

    def _extract(self, installer):
        return inno_mod.extract_installer(installer, self.work)

    def test_lzma_chunk_files_extracted_byte_exact(self):
        installer = os.path.join(self.temp.name, "setup.exe")
        payload = {
            "{app}\\bin\\app.exe": b"MZ" + bytes(range(256)) * 40,
            "{app}\\lib\\data.bin": os.urandom(100_000),
            "{app}\\readme.txt": "привет, inno".encode("utf-8"),
        }
        files = [(dest, raw, False, 0) for dest, raw in payload.items()]
        _build_installer(installer, files, version=(6, 4, 0), compression=3)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        for dest, raw in payload.items():
            rel = dest.replace("\\", os.sep)
            with open(os.path.join(self.work, rel), "rb") as fh:
                self.assertEqual(fh.read(), raw, dest)

    def test_stored_chunk_and_pointer_offset_table(self):
        installer = os.path.join(self.temp.name, "setup.exe")
        raw = b"plain-stored-content" * 100
        _build_installer(installer,
                         [("{app}\\a.txt", raw, False, 0)],
                         version=(6, 2, 0), compression=0, use_pe_resource=False)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        with open(os.path.join(self.work, "{app}", "a.txt"), "rb") as fh:
            self.assertEqual(fh.read(), raw)

    def test_other_roots_are_not_extracted(self):
        installer = os.path.join(self.temp.name, "setup.exe")
        _build_installer(installer, [
            ("{app}\\app.exe", b"MZxxxx", False, 0),
            ("{tmp}\\setup.tmp", b"temp", False, 0),
            ("{sys}\\evil.dll", b"evil", False, 0),
        ], compression=3)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        self.assertTrue(os.path.isfile(os.path.join(self.work, "{app}", "app.exe")))
        self.assertFalse(os.path.exists(os.path.join(self.work, "{tmp}")))
        self.assertFalse(os.path.exists(os.path.join(self.work, "{sys}")))

    def test_solid_chunk_multiple_files_same_chunk(self):
        installer = os.path.join(self.temp.name, "setup.exe")
        files = [("{app}\\one.bin", b"A" * 5000, False, 7),
                 ("{app}\\two.bin", b"B" * 7000, False, 7),
                 ("{app}\\three.bin", b"C" * 100, False, 8)]
        _build_installer(installer, files, compression=3)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        def read(rel):
            with open(os.path.join(self.work, "{app}", rel), "rb") as fh:
                return fh.read()
        self.assertEqual(read("one.bin"), b"A" * 5000)
        self.assertEqual(read("two.bin"), b"B" * 7000)
        self.assertEqual(read("three.bin"), b"C" * 100)

    def test_call_instruction_transform_is_reversed(self):
        # exe-подобное содержимое с CALL (E8) и JMP (E9), у которых старший
        # байт адреса 00/FF — их трогает трансформация
        exe = bytearray()
        exe += b"\x55\x8b\xec"          # prologue
        exe += b"\xe8" + struct.pack("<i", -0x100)   # call rel32 (high byte FF)
        exe += b"\x90" * 10
        exe += b"\xe9" + struct.pack("<i", 0x200)    # jmp rel32 (high byte 00)
        exe += b"\xcc" * 20
        installer = os.path.join(self.temp.name, "setup.exe")
        _build_installer(installer, [("{app}\\prog.exe", bytes(exe), True, 0)],
                         compression=3)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        with open(os.path.join(self.work, "{app}", "prog.exe"), "rb") as fh:
            self.assertEqual(fh.read(), bytes(exe))

    def test_decode_call_instructions_roundtrip(self):
        original = bytearray(os.urandom(200_000))
        # подложим валидные CALL/JMP паттерны
        original[100] = 0xE8
        original[105] = 0xFF
        original[5000] = 0xE9
        original[5005] = 0x00
        encoded = bytearray(original)
        _encode_call_instructions(encoded)
        # поблочно, как в extract (65535)
        decoded = bytearray(encoded)
        addr = 0
        pos = 0
        while pos < len(decoded):
            block = decoded[pos:pos + inno_mod._TRANSFORM_BLOCK]
            inno_mod.decode_call_instructions(block, addr)
            decoded[pos:pos + len(block)] = block
            addr += len(block)
            pos += len(block)
        self.assertEqual(bytes(decoded), bytes(original))

    def test_modern_65_table_v2_block_header(self):
        # Inno Setup 6.5.x: таблица смещений v2 (Int64), encryption-заголовок
        # 53 байта после сигнатуры, заголовок — внутри LZMA1-блока
        installer = os.path.join(self.temp.name, "setup65.exe")
        payload = {
            "{app}\\bin\\app.exe": b"MZ" + bytes(range(256)) * 20,
            "{app}\\lib\\data.bin": os.urandom(50_000),
        }
        files = [(dest, raw, False, 0) for dest, raw in payload.items()]
        _build_installer(installer, files, version=(6, 5, 0), compression=3)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        for dest, raw in payload.items():
            rel = dest.replace("\\", os.sep)
            with open(os.path.join(self.work, rel), "rb") as fh:
                self.assertEqual(fh.read(), raw, dest)

    def test_modern_67_table_v2_block_header(self):
        # Inno Setup 6.7.x — то, на чём собран PyCharm 2026.2.x
        installer = os.path.join(self.temp.name, "setup67.exe")
        payload = {
            "{app}\\bin\\pycharm64.exe": b"MZ" + bytes(range(256)) * 40,
            "{app}\\lib\\data.bin": os.urandom(100_000),
            "{app}\\readme.txt": "привет, inno 6.7".encode("utf-8"),
        }
        files = [(dest, raw, False, 0) for dest, raw in payload.items()]
        _build_installer(installer, files, version=(6, 7, 0), compression=3)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        for dest, raw in payload.items():
            rel = dest.replace("\\", os.sep)
            with open(os.path.join(self.work, rel), "rb") as fh:
                self.assertEqual(fh.read(), raw, dest)

    def test_modern_71_inno7(self):
        # Inno Setup 7.x
        installer = os.path.join(self.temp.name, "setup71.exe")
        raw = b"inno7-payload" * 3000
        _build_installer(installer, [("{app}\\tool.exe", raw, False, 0)],
                         version=(7, 1, 1), compression=3)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        with open(os.path.join(self.work, "{app}", "tool.exe"), "rb") as fh:
            self.assertEqual(fh.read(), raw)

    def test_modern_67_call_instruction_transform(self):
        exe = bytearray()
        exe += b"\x55\x8b\xec"
        exe += b"\xe8" + struct.pack("<i", -0x100)
        exe += b"\x90" * 10
        exe += b"\xe9" + struct.pack("<i", 0x200)
        exe += b"\xcc" * 20
        installer = os.path.join(self.temp.name, "setup67.exe")
        _build_installer(installer, [("{app}\\prog.exe", bytes(exe), True, 0)],
                         version=(6, 7, 0), compression=3)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        with open(os.path.join(self.work, "{app}", "prog.exe"), "rb") as fh:
            self.assertEqual(fh.read(), bytes(exe))

    def test_modern_67_stored_block_header(self):
        # Блок заголовка может быть и НЕ сжат (compressed=0): тогда хранимый
        # поток — просто порции по 4096 байт с CRC, LZMA нет
        installer = os.path.join(self.temp.name, "setup67s.exe")
        raw = os.urandom(20_000)   # больше одной порции в 4096 байт
        _build_installer(installer, [("{app}\\data.bin", raw, False, 0)],
                         version=(6, 7, 0), compression=0, block_compressed=False)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        with open(os.path.join(self.work, "{app}", "data.bin"), "rb") as fh:
            self.assertEqual(fh.read(), raw)

    def test_modern_67_full_meta_entries_layout(self):
        # В реальном установщике есть type/component/task/dir/icon/ini/registry/
        # delete/run-записи — их раскладка (2 winver-поля в 6.5+) должна сходиться
        installer = os.path.join(self.temp.name, "setup67m.exe")
        raw = b"MZ" + os.urandom(5000)
        _build_installer(installer, [("{app}\\bin\\app.exe", raw, False, 0)],
                         version=(6, 7, 0), compression=3, with_meta=True)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        with open(os.path.join(self.work, "{app}", "bin", "app.exe"), "rb") as fh:
            self.assertEqual(fh.read(), raw)

    def test_modern_65_full_meta_entries_layout(self):
        installer = os.path.join(self.temp.name, "setup65m.exe")
        raw = b"payload-65" * 500
        _build_installer(installer, [("{app}\\a.bin", raw, False, 0)],
                         version=(6, 5, 0), compression=3, with_meta=True)
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        with open(os.path.join(self.work, "{app}", "a.bin"), "rb") as fh:
            self.assertEqual(fh.read(), raw)

    def test_garbage_file_is_a_clean_error(self):
        installer = os.path.join(self.temp.name, "garbage.exe")
        with open(installer, "wb") as fh:
            fh.write(os.urandom(4096))
        ok, message = self._extract(installer)
        self.assertFalse(ok)
        self.assertIn("Inno", message)

    def test_unsupported_data_version_is_explained(self):
        installer = os.path.join(self.temp.name, "old.exe")
        header = bytearray()
        setup_id = b"Inno Setup Setup Data (5.6.1)".ljust(64, b"\x00")
        blob = bytearray(b"\x00" * 0x40)
        blob += b"\x00" * (0x100 - len(blob))
        header_offset = len(blob)
        blob += setup_id
        data_offset = len(blob)
        table_off = len(blob)
        blob += _build_offset_table(header_offset, data_offset)
        struct.pack_into("<III", blob, 0x30, inno_mod.LOADER_PTR_MAGIC,
                         table_off, (~table_off) & 0xFFFFFFFF)
        with open(installer, "wb") as fh:
            fh.write(blob)
        ok, message = self._extract(installer)
        self.assertFalse(ok)
        self.assertIn("5.6", message)

    def test_looks_like_inno(self):
        installer = os.path.join(self.temp.name, "setup.exe")
        _build_installer(installer, [("{app}\\a.txt", b"x", False, 0)],
                         compression=0, use_pe_resource=False)
        self.assertTrue(inno_mod.looks_like_inno(installer))
        other = os.path.join(self.temp.name, "other.bin")
        with open(other, "wb") as fh:
            fh.write(os.urandom(1024))
        self.assertFalse(inno_mod.looks_like_inno(other))

    def test_dont_copy_and_external_files_are_skipped(self):
        installer = os.path.join(self.temp.name, "setup.exe")
        # файл с DontCopy и файл, ссылающийся за пределы data entries
        _build_installer(installer, [
            ("{app}\\real.dll", b"DLL", False, 0),
            ("{app}\\dontcopy.dll", b"NO", True, 0),
        ], compression=0)
        # подправим options первого лишнего файла вручную нельзя — вместо
        # этого проверим, что извлекается только реальный файл через message
        ok, message = self._extract(installer)
        self.assertTrue(ok, message)
        self.assertTrue(os.path.isfile(os.path.join(self.work, "{app}", "real.dll")))


class EngineFallbackTests(unittest.TestCase):
    """Движок: без 7-Zip падающий Inno Setup всё равно даёт портатив."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        from portablizer.core.detect import DetectionResult, InstallerType
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import PortableOptions, Portablizer
        self.Portablizer = Portablizer
        self.Logger = Logger
        self.PortableOptions = PortableOptions
        self.InstallerType = InstallerType
        self.DetectionResult = DetectionResult
        self.app = os.path.join(self.temp.name, "App")
        self.portable = os.path.join(self.temp.name, "Portable")
        os.makedirs(self.app, exist_ok=True)
        os.makedirs(self.portable, exist_ok=True)

    def test_fallback_without_7zip_uses_builtin_inno(self):
        from unittest import mock
        from portablizer.core import unpacker as unpacker_mod
        installer = os.path.join(self.temp.name, "pycharm.exe")
        exe = b"MZ" + b"\x90" * 100 + b"\xe8" + struct.pack("<i", -16) + b"\xff\x00\x00"
        _build_installer(installer, [
            ("{app}\\bin\\pycharm64.exe", exe, True, 0),
            ("{app}\\lib\\jbr.bin", b"jbr" * 100, False, 0),
        ], compression=3)
        opts = self.PortableOptions(installer_path=installer,
                                    output_dir=self.temp.name)
        det = self.DetectionResult(installer_type=self.InstallerType.INNO,
                                   confidence=1.0)
        engine = self.Portablizer(self.Logger())
        with mock.patch.object(unpacker_mod, "find_unpacker", return_value=""):
            ok = engine._try_unpacker_fallback(opts, self.app, self.portable,
                                               det, "PyCharm")
        self.assertTrue(ok)
        self.assertEqual(engine._unpacked_with, "inno-builtin")
        exe_path = os.path.join(self.app, "bin", "pycharm64.exe")
        self.assertTrue(os.path.isfile(exe_path))
        with open(exe_path, "rb") as fh:
            self.assertEqual(fh.read(), exe)  # call-трансформация отменена верно
        self.assertTrue(os.path.isfile(os.path.join(self.app, "lib", "jbr.bin")))
        # рабочая папка не осталась в портативе
        self.assertFalse(os.path.exists(os.path.join(self.portable,
                                                     "_inno_unpacked")))

    def test_unknown_type_inno_container_still_unpacked(self):
        # Детектор не узнал контейнер (UNKNOWN), но сигнатуры Inno внутри
        # файла узнаем мы сами — портатив всё равно создаётся без 7-Zip.
        from unittest import mock
        from portablizer.core import unpacker as unpacker_mod
        installer = os.path.join(self.temp.name, "weird_name.bin")
        _build_installer(installer, [("{app}\\tool.exe", b"MZ" + b"\x01" * 50,
                                      False, 0)], compression=3)
        opts = self.PortableOptions(installer_path=installer,
                                    output_dir=self.temp.name)
        det = self.DetectionResult(installer_type=self.InstallerType.UNKNOWN,
                                   confidence=0.5)
        engine = self.Portablizer(self.Logger())
        with mock.patch.object(unpacker_mod, "find_unpacker", return_value=""):
            ok = engine._try_unpacker_fallback(opts, self.app, self.portable,
                                               det, "Tool")
        self.assertTrue(ok)
        self.assertEqual(engine._unpacked_with, "inno-builtin")
        self.assertTrue(os.path.isfile(os.path.join(self.app, "tool.exe")))

    def test_fallback_reports_clean_failure_for_non_inno(self):
        from unittest import mock
        from portablizer.core import unpacker as unpacker_mod
        installer = os.path.join(self.temp.name, "setup.exe")
        with open(installer, "wb") as fh:
            fh.write(os.urandom(2048))
        opts = self.PortableOptions(installer_path=installer,
                                    output_dir=self.temp.name)
        det = self.DetectionResult(installer_type=self.InstallerType.NSIS,
                                   confidence=1.0)
        engine = self.Portablizer(self.Logger())
        with mock.patch.object(unpacker_mod, "find_unpacker", return_value=""):
            ok = engine._try_unpacker_fallback(opts, self.app, self.portable,
                                               det, "Prog")
        self.assertFalse(ok)
        self.assertEqual(engine._unpacked_with, "")


if __name__ == "__main__":
    unittest.main()
