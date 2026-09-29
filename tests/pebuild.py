"""Сборщик минимальных, но настоящих PE-файлов для тестов.

Проверять разбор таблицы импорта на «MZ + мусор» бессмысленно, а класть в
репозиторий настоящие exe нельзя. Здесь собирается корректный PE32/PE32+ с
таблицей импорта, отложенным импортом и ресурсом RT_MANIFEST — ровно то, что
читает :mod:`portablizer.core.redist`.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, Optional, Sequence

MACHINE_X86 = 0x014C
MACHINE_X64 = 0x8664

_SECTION_RVA = 0x1000
_RESOURCE_RVA = 0x8000
_ALIGN = 0x200


def _align(value: int, alignment: int = _ALIGN) -> int:
    return (value + alignment - 1) // alignment * alignment


def _resource_blob(manifest: str, base_rva: int) -> bytes:
    """Три уровня каталога ресурсов + данные одного RT_MANIFEST."""
    payload = manifest.encode("utf-8")
    header = 16 + 8                       # каталог + одна запись
    level1 = 0
    level2 = level1 + header
    level3 = level2 + header
    data_entry = level3 + header
    data_offset = data_entry + 16

    def directory(entry_name: int, offset: int, is_dir: bool) -> bytes:
        return (struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
                + struct.pack("<II", entry_name,
                              offset | (0x80000000 if is_dir else 0)))

    blob = bytearray()
    blob += directory(24, level2, True)          # тип 24 = RT_MANIFEST
    blob += directory(1, level3, True)           # имя ресурса
    blob += directory(1033, data_entry, False)   # язык
    blob += struct.pack("<IIII", base_rva + data_offset, len(payload), 0, 0)
    blob += payload
    return bytes(blob)


def write_pe(path: str | Path, imports: Sequence[str] = (),
             delay_imports: Sequence[str] = (),
             machine: int = MACHINE_X86, dotnet: bool = False,
             manifest: str = "", extra: bytes = b"") -> str:
    """Пишет валидный PE с заданными зависимостями и возвращает путь."""
    pe32plus = machine == MACHINE_X64
    optional_size = 240
    sections = 2 if manifest else 1
    headers = 0x40 + 4 + 20 + optional_size + 40 * sections
    raw_pointer = _align(headers)

    import_count = len(imports)
    delay_count = len(delay_imports)
    import_size = 20 * (import_count + 1)
    delay_size = 32 * (delay_count + 1)
    names_offset = import_size + delay_size

    body = bytearray(names_offset)
    name_rvas = {}
    for name in list(imports) + list(delay_imports):
        if name in name_rvas:
            continue
        name_rvas[name] = _SECTION_RVA + len(body)
        body += name.encode("ascii") + b"\0"

    for index, name in enumerate(imports):
        struct.pack_into("<IIIII", body, index * 20,
                         0, 0, 0, name_rvas[name], 0)
    for index, name in enumerate(delay_imports):
        struct.pack_into("<IIIIIIII", body, import_size + index * 32,
                         1, name_rvas[name], 0, 0, 0, 0, 0, 0)

    body += extra
    section_raw = _align(len(body))
    body += b"\0" * (section_raw - len(body))

    resource_raw = 0
    resource_body = b""
    if manifest:
        resource_body = _resource_blob(manifest, _RESOURCE_RVA)
        resource_raw = _align(len(resource_body))
        resource_body += b"\0" * (resource_raw - len(resource_body))

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH", machine, sections, 0, 0, 0,
                       optional_size, 0x0102)

    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x20B if pe32plus else 0x10B)
    if pe32plus:
        struct.pack_into("<Q", optional, 24, 0x140000000)
        directory_offset, count_offset = 112, 108
    else:
        struct.pack_into("<I", optional, 28, 0x400000)
        directory_offset, count_offset = 96, 92
    struct.pack_into("<I", optional, count_offset, 16)
    if imports:
        struct.pack_into("<II", optional, directory_offset + 1 * 8,
                         _SECTION_RVA, import_size)
    if manifest:
        struct.pack_into("<II", optional, directory_offset + 2 * 8,
                         _RESOURCE_RVA, len(resource_body))
    if delay_imports:
        struct.pack_into("<II", optional, directory_offset + 13 * 8,
                         _SECTION_RVA + import_size, delay_size)
    if dotnet:
        struct.pack_into("<II", optional, directory_offset + 14 * 8,
                         _SECTION_RVA, 0x48)

    table = bytearray()
    table += struct.pack("<8sIIIIIIHHI", b".rdata", len(body), _SECTION_RVA,
                         section_raw, raw_pointer, 0, 0, 0, 0, 0x40000040)
    if manifest:
        table += struct.pack("<8sIIIIIIHHI", b".rsrc", len(resource_body),
                             _RESOURCE_RVA, resource_raw,
                             raw_pointer + section_raw, 0, 0, 0, 0, 0x40000040)

    blob = bytearray()
    blob += dos + b"PE\0\0" + coff + bytes(optional) + bytes(table)
    blob += b"\0" * (raw_pointer - len(blob))
    blob += bytes(body)
    blob += resource_body

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(bytes(blob))
    return str(destination)


def write_runtime_dll(path: str | Path, machine: int = MACHINE_X86,
                      imports: Optional[Iterable[str]] = None) -> str:
    """Подделка системной библиотеки (msvcr110.dll и т. п.) нужной разрядности."""
    return write_pe(path, imports=tuple(imports or ("kernel32.dll",)),
                    machine=machine)
