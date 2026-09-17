"""Снимок и сравнение реестра Windows для захвата изменений установщика.

Стратегия: перед установкой делаем снимок интересующих веток реестра, после
установки — ещё один, вычисляем разницу и сохраняем её в файл `.reg`, который
лончер портативного приложения импортирует во временный/изолированный куст (или
предупреждает пользователя). Так программы, полагающиеся на записи реестра,
получают их «на лету», не загрязняя систему навсегда.

Модуль использует WinAPI через стандартный модуль ``winreg`` и работает только
на Windows. На других ОС функции безопасно вырождаются в заглушки, чтобы код
можно было импортировать и тестировать где угодно.
"""
from __future__ import annotations

import ast
import os
import re
import sys
from typing import Dict, List, Tuple

IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    import winreg  # type: ignore

# Ветки, которые чаще всего затрагивают установщики пользовательских программ.
# Мы намеренно НЕ трогаем критичные системные ветки целиком, а берём типовые
# поддеревья приложений.
_ROOTS: List[Tuple[str, "int"]] = []
if IS_WINDOWS:
    _ROOTS = [
        (r"HKCU\Software", winreg.HKEY_CURRENT_USER, r"Software"),  # type: ignore
        (r"HKLM\Software", winreg.HKEY_LOCAL_MACHINE, r"Software"),  # type: ignore
    ]


def _walk(hive: int, subkey: str, prefix: str, out: Dict[str, Dict[str, str]],
          max_depth: int = 6, depth: int = 0) -> None:
    """Рекурсивно обходит ветку реестра и заполняет out[path] = {value: data}."""
    if depth > max_depth:
        return
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)  # type: ignore
    except OSError:
        return
    full = f"{prefix}\\{subkey}" if subkey else prefix
    values: Dict[str, str] = {}
    try:
        i = 0
        while True:
            try:
                name, data, _t = winreg.EnumValue(key, i)  # type: ignore
                values[name] = repr(data)
                i += 1
            except OSError:
                break
        out[full] = values
        # Перечисляем подключи
        j = 0
        subkeys = []
        while True:
            try:
                subkeys.append(winreg.EnumKey(key, j))  # type: ignore
                j += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(key)  # type: ignore
    for sk in subkeys:
        _walk(hive, f"{subkey}\\{sk}" if subkey else sk, prefix, out,
              max_depth, depth + 1)


def snapshot() -> Dict[str, Dict[str, str]]:
    """Делает снимок наблюдаемых веток. На не-Windows возвращает пусто."""
    if not IS_WINDOWS:
        return {}
    snap: Dict[str, Dict[str, str]] = {}
    for prefix, hive, base in _ROOTS:
        _walk(hive, base, prefix.split("\\", 1)[0], snap)
    return snap


def changed_install_locations(before: Dict[str, Dict[str, str]],
                              after: Dict[str, Dict[str, str]]) -> List[str]:
    """Извлекает InstallLocation/DisplayIcon из новых записей установщика.

    Снимок хранит значения как ``repr``. Функция намеренно не зависит от
    ``winreg``, поэтому её можно тестировать и на других платформах.
    """
    locations: List[str] = []
    seen = set()
    for key, values in after.items():
        if key in before and values == before[key]:
            continue
        # Эти значения наиболее надёжны в ветках Uninstall, но некоторые
        # установщики сохраняют InstallLocation в собственном ключе Software.
        for value_name in ("InstallLocation", "DisplayIcon"):
            raw = values.get(value_name)
            if raw is None:
                # Имена значений реестра регистронезависимы.
                raw = next(
                    (v for n, v in values.items() if n.casefold() == value_name.casefold()),
                    None,
                )
            if raw is None:
                continue
            try:
                value = ast.literal_eval(raw)
            except (ValueError, SyntaxError):
                value = raw
            if not isinstance(value, str) or not value.strip():
                continue
            value = os.path.expandvars(value.strip())
            if value_name == "DisplayIcon":
                # Типичный формат: "C:\\Program Files\\App\\app.exe",0
                value = re.sub(r",\s*-?\d+\s*$", "", value).strip().strip('"')
            normalized = os.path.normcase(os.path.normpath(value))
            if normalized not in seen:
                seen.add(normalized)
                locations.append(value)
    return locations


def diff_to_reg(before: Dict[str, Dict[str, str]],
                after: Dict[str, Dict[str, str]]) -> str:
    """Формирует содержимое .reg-файла из разницы двух снимков.

    Возвращает готовый текст в формате Windows Registry Editor 5.00.
    Значения экспортируются повторным чтением из реестра, чтобы сохранить типы.
    """
    lines = ["Windows Registry Editor Version 5.00", ""]
    if not IS_WINDOWS:
        return "\n".join(lines)

    new_keys = [k for k in after if k not in before]
    changed_keys = [
        k for k in after
        if k in before and after[k] != before[k]
    ]

    export_keys = sorted(set(new_keys) | set(changed_keys))
    for key_path in export_keys:
        block = _export_key_block(key_path)
        if block:
            lines.append(block)
    return "\n".join(lines)


def _export_key_block(key_path: str) -> str:
    """Экспортирует значения одного ключа в текстовый блок .reg."""
    hive_map = {
        "HKCU": winreg.HKEY_CURRENT_USER,  # type: ignore
        "HKLM": winreg.HKEY_LOCAL_MACHINE,  # type: ignore
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,  # type: ignore
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,  # type: ignore
    }
    parts = key_path.split("\\", 1)
    if len(parts) != 2 or parts[0] not in hive_map:
        return ""
    hive = hive_map[parts[0]]
    subkey = parts[1]
    full_hive_name = "HKEY_CURRENT_USER" if "HKCU" in parts[0] or parts[0] == "HKEY_CURRENT_USER" else "HKEY_LOCAL_MACHINE"
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)  # type: ignore
    except OSError:
        return ""
    out = [f"[{full_hive_name}\\{subkey}]"]
    try:
        i = 0
        while True:
            try:
                name, data, typ = winreg.EnumValue(key, i)  # type: ignore
            except OSError:
                break
            out.append(_format_value(name, data, typ))
            i += 1
    finally:
        winreg.CloseKey(key)  # type: ignore
    out.append("")
    return "\n".join(out)


def _format_value(name: str, data, typ: int) -> str:
    """Форматирует одно значение реестра в синтаксис .reg."""
    quoted_name = "@" if name == "" else f'"{name}"'
    if typ == winreg.REG_SZ:  # type: ignore
        esc = str(data).replace("\\", "\\\\").replace('"', '\\"')
        return f'{quoted_name}="{esc}"'
    if typ == winreg.REG_EXPAND_SZ:  # type: ignore
        raw = str(data).encode("utf-16-le") + b"\x00\x00"
        hexed = ",".join(f"{b:02x}" for b in raw)
        return f"{quoted_name}=hex(2):{hexed}"
    if typ == winreg.REG_DWORD:  # type: ignore
        return f"{quoted_name}=dword:{int(data) & 0xffffffff:08x}"
    if typ == winreg.REG_QWORD:  # type: ignore
        raw = int(data).to_bytes(8, "little", signed=False)
        hexed = ",".join(f"{b:02x}" for b in raw)
        return f"{quoted_name}=hex(b):{hexed}"
    if typ == winreg.REG_MULTI_SZ:  # type: ignore
        joined = "\x00".join(data) + "\x00\x00"
        raw = joined.encode("utf-16-le")
        hexed = ",".join(f"{b:02x}" for b in raw)
        return f"{quoted_name}=hex(7):{hexed}"
    if typ == winreg.REG_BINARY:  # type: ignore
        hexed = ",".join(f"{b:02x}" for b in bytes(data))
        return f"{quoted_name}=hex:{hexed}"
    # Прочие типы — как бинарные.
    try:
        hexed = ",".join(f"{b:02x}" for b in bytes(data))
        return f"{quoted_name}=hex({typ}):{hexed}"
    except Exception:  # noqa: BLE001
        return f'{quoted_name}=""'
