"""Сборка настоящих кабинетов (CAB) для тестов.

Тестам нужен не «файл, похожий на пакет», а честный ``MSCF`` со сжатыми
данными: только так проверяется, что собственный распаковщик Portablizer
действительно читает формат, а не удачно совпавшие байты. Формат — MS-CAB,
сжатие MSZIP (deflate с общей историей внутри папки кабинета).
"""
from __future__ import annotations

import struct
import zlib
from typing import Dict, Sequence

_BLOCK = 32 * 1024


def _mszip_blocks(payload: bytes) -> bytes:
    """Данные папки кабинета, нарезанные на блоки CFDATA (MSZIP)."""
    out = bytearray()
    history = b""
    for start in range(0, max(len(payload), 1), _BLOCK):
        chunk = payload[start:start + _BLOCK]
        if not chunk and start:
            break
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        if history:
            compressor = zlib.compressobj(9, zlib.DEFLATED, -15,
                                          zdict=history)
        block = b"CK" + compressor.compress(chunk) + compressor.flush()
        out += struct.pack("<IHH", 0, len(block), len(chunk)) + block
        history = (history + chunk)[-32768:]
    return bytes(out)


def _store_blocks(payload: bytes) -> bytes:
    out = bytearray()
    for start in range(0, max(len(payload), 1), _BLOCK):
        chunk = payload[start:start + _BLOCK]
        if not chunk and start:
            break
        out += struct.pack("<IHH", 0, len(chunk), len(chunk)) + chunk
    return bytes(out)


def _lzx_blocks(payload: bytes, window_bits: int = 21) -> bytes:
    """Данные папки кабинета, нарезанные на блоки CFDATA (LZX uncompressed blocks)."""
    out = bytearray()
    pos = 0
    first_block = True
    while pos < len(payload) or (pos == 0 and len(payload) == 0):
        chunk = payload[pos:pos + _BLOCK]
        pos += len(chunk)
        bs = bytearray()
        if first_block:
            # 1 bit (intel hdr=0) + 3 bits (type=3) + 24 bits (len)
            top_12 = (len(chunk) >> 12) & 0xFFF
            low_12 = len(chunk) & 0xFFF
            word1 = (0 << 15) | (3 << 12) | top_12
            word2 = (low_12 << 4)
            bs.append(word1 & 0xFF)
            bs.append((word1 >> 8) & 0xFF)
            bs.append(word2 & 0xFF)
            bs.append((word2 >> 8) & 0xFF)
            first_block = False
        else:
            # 3 bits (type=3) + 24 bits (len)
            top_13 = (len(chunk) >> 11) & 0x1FFF
            low_11 = len(chunk) & 0x7FF
            word1 = (3 << 13) | top_13
            word2 = (low_11 << 5)
            bs.append(word1 & 0xFF)
            bs.append((word1 >> 8) & 0xFF)
            bs.append(word2 & 0xFF)
            bs.append((word2 >> 8) & 0xFF)
        bs.extend(struct.pack("<III", 1, 1, 1))
        bs.extend(chunk)
        if len(chunk) & 1:
            bs.append(0)

        out.extend(struct.pack("<IHH", 0, len(bs), len(chunk)))
        out.extend(bs)
        if pos >= len(payload):
            break
    return bytes(out)


def make_cabinet(files: Dict[str, bytes], compress: bool = True,
                 compression_type: int = 1, window_bits: int = 21) -> bytes:
    """Готовый кабинет с одной папкой и перечисленными файлами."""
    payload = bytearray()
    entries = []
    for name, data in files.items():
        entries.append((name, len(payload), len(data)))
        payload += data

    if compression_type == 3:  # LZX
        blocks = _lzx_blocks(bytes(payload), window_bits=window_bits)
        folder_comp = 3 | (window_bits << 8)
    elif compress:
        blocks = _mszip_blocks(bytes(payload))
        folder_comp = 1
    else:
        blocks = _store_blocks(bytes(payload))
        folder_comp = 0

    block_count = 0
    position = 0
    while position < len(blocks):
        _csum, compressed, _plain = struct.unpack_from("<IHH", blocks, position)
        position += 8 + compressed
        block_count += 1

    file_table = bytearray()
    for name, offset, size in entries:
        file_table += struct.pack("<IIHHHH", size, offset, 0, 0x2A2A, 0x2A2A,
                                  0x20)
        file_table += name.encode("cp1252") + b"\x00"

    header_size = 36
    folder_size = 8
    coff_files = header_size + folder_size
    data_offset = coff_files + len(file_table)
    total = data_offset + len(blocks)

    header = struct.pack(
        "<4sIIIIIBBHHHHH", b"MSCF", 0, total, 0, coff_files, 0, 3, 1,
        1, len(entries), 0, 0, 0)
    folder = struct.pack("<IHH", data_offset, block_count, folder_comp)
    return bytes(header + folder + bytes(file_table) + blocks)


def make_lzx_cabinet(files: Dict[str, bytes], window_bits: int = 21) -> bytes:
    """Кабинет со сжатием LZX."""
    return make_cabinet(files, compression_type=3, window_bits=window_bits)


def make_self_extracting_exe(files: Dict[str, bytes],
                             stub: bytes = b"") -> bytes:
    """IExpress-подобный пакет: PE-заголовок, а следом «довеском» кабинет."""
    stub = stub or (b"MZ" + b"\x90" * 62 + b"This program cannot be run in "
                                           b"DOS mode.\r\n" + b"\x00" * 128)
    return stub + make_cabinet(files)


def make_burn_bundle(containers: Sequence[Dict[str, bytes]]) -> bytes:
    """Бандл WiX Burn: PE и несколько приклеенных контейнеров-кабинетов."""
    out = bytearray(b"MZ" + b"\x90" * 62 + b".wixburn" + b"\x00" * 256)
    for files in containers:
        out += make_cabinet(files)
    return bytes(out)
