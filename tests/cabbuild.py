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


def make_cabinet(files: Dict[str, bytes], compress: bool = True) -> bytes:
    """Готовый кабинет с одной папкой и перечисленными файлами."""
    payload = bytearray()
    entries = []
    for name, data in files.items():
        entries.append((name, len(payload), len(data)))
        payload += data

    blocks = _mszip_blocks(bytes(payload)) if compress \
        else _store_blocks(bytes(payload))
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
    folder = struct.pack("<IHH", data_offset, block_count,
                         1 if compress else 0)
    return bytes(header + folder + bytes(file_table) + blocks)


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
