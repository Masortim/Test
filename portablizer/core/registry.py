"""Снимок, сравнение и классификация изменений реестра Windows.

Задача модуля — понять, что именно установщик записал в реестр, и разделить
эти записи на три принципиально разные группы:

``app``
    Собственные настройки программы (``HKCU\\Software\\Vendor\\App`` и т.п.).
    Их можно и нужно переносить вместе с портативом.

``integration``
    Интеграция с оболочкой Windows: ``Software\\Classes`` (ассоциации файлов,
    COM), ``App Paths``, ``RegisteredApplications``. Программе они обычно не
    нужны для запуска, а чужому компьютеру приносят мусор, поэтому по
    умолчанию не применяются (есть флаг ``--integration``).

``trace``
    Следы установки: ветка ``Uninstall`` (именно она формирует список
    «Установленные программы»), автозапуск ``Run``, служба Windows Installer,
    службы, ``SharedDLLs``. Эти записи **никогда** не попадают в портатив —
    иначе портативная программа при первом же запуске «устанавливалась» бы на
    чужой компьютер. Они используются только для того, чтобы вычистить следы
    с машины, где создавался портатив.

Дополнительно модуль умеет:

* хранить в снимке тип значения, поэтому ``.reg`` формируется из самого снимка
  (не требуется повторное чтение реестра) и модуль полностью тестируется на
  любой ОС;
* заменять абсолютный путь портативной папки на маркер ``@@PORTABLE_ROOT@@``,
  чтобы захваченный реестр не был привязан к диску и каталогу конкретного ПК;
* формировать «откат» (``.reg`` с удалением созданных ключей), чтобы запуск
  портатива не оставлял следов на чужой машине.
"""
from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    import winreg  # type: ignore

# Константы типов значений продублированы намеренно: модуль должен
# импортироваться и тестироваться на Linux/macOS, где winreg отсутствует.
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11

# (тип значения, repr данных) — repr позволяет хранить str/bytes/int/list
# единообразно и сравнивать снимки обычным ==.
ValueEntry = Tuple[int, str]
KeyValues = Dict[str, ValueEntry]
Snapshot = Dict[str, KeyValues]

#: Маркер, который подставляется вместо абсолютного пути портативной папки.
ROOT_TOKEN = "@@PORTABLE_ROOT@@"

CATEGORY_APP = "app"
CATEGORY_INTEGRATION = "integration"
CATEGORY_TRACE = "trace"

_HIVE_FULL = {
    "HKCU": "HKEY_CURRENT_USER",
    "HKLM": "HKEY_LOCAL_MACHINE",
}

# Наблюдаемые ветки. Критичные системные кусты целиком не трогаем.
_ROOTS: List[Tuple[str, str]] = [("HKCU", "Software"), ("HKLM", "Software")]


# --- классификация ключей -----------------------------------------------------

# Ветки, которые Windows и сторонние службы переписывают постоянно. Они не
# имеют отношения к установке, поэтому не попадают ни в снимок, ни в очистку.
_VOLATILE_PREFIXES: Tuple[str, ...] = (
    r"software\microsoft\windows\currentversion\explorer",
    r"software\microsoft\windows\currentversion\search",
    r"software\microsoft\windows\currentversion\cloudstore",
    r"software\microsoft\windows\currentversion\notifications",
    r"software\microsoft\windows\currentversion\appmodel",
    r"software\microsoft\windows\currentversion\pushnotifications",
    r"software\microsoft\windows\currentversion\bitsagent",
    r"software\microsoft\windows\currentversion\wininet",
    r"software\microsoft\windows\currentversion\internet settings",
    r"software\microsoft\windows\currentversion\group policy",
    r"software\microsoft\windows nt\currentversion\appcompatflags",
    r"software\microsoft\windows nt\currentversion\fontsubstitutes",
    r"software\microsoft\windows security health",
    r"software\microsoft\windows defender",
    r"software\microsoft\tracing",
    r"software\microsoft\cryptography",
    r"software\microsoft\rac",
    r"software\microsoft\sqmclient",
    r"software\microsoft\input",
    r"software\microsoft\ime",
    r"software\microsoft\spellchecking",
    r"software\microsoft\eventlog",
    r"software\classes\local settings",
    r"software\classes\activatableclasses",
    r"software\google\update",
    r"software\microsoft\edgeupdate",
)

# Интеграция с оболочкой: перенос возможен, но по умолчанию выключен.
_INTEGRATION_PREFIXES: Tuple[str, ...] = (
    r"software\classes",
    r"software\wow6432node\classes",
    r"software\microsoft\windows\currentversion\app paths",
    r"software\wow6432node\microsoft\windows\currentversion\app paths",
    r"software\registeredapplications",
    r"software\clients",
    r"software\microsoft\windows\currentversion\explorer\fileexts",
    r"software\microsoft\windows\shell",
    r"software\microsoft\windows\currentversion\shell extensions",
)

# Следы установки. В портатив не попадают никогда.
_TRACE_PREFIXES: Tuple[str, ...] = (
    r"software\microsoft\windows\currentversion\uninstall",
    r"software\wow6432node\microsoft\windows\currentversion\uninstall",
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\microsoft\windows\currentversion\runonceex",
    r"software\microsoft\windows\currentversion\runservices",
    r"software\wow6432node\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\installer",
    r"software\wow6432node\microsoft\windows\currentversion\installer",
    r"software\microsoft\installer",
    r"software\classes\installer",
    r"software\microsoft\windows\currentversion\sharedlls",
    r"software\microsoft\windows\currentversion\side by side",
    r"software\microsoft\windows\currentversion\policies",
    r"software\microsoft\windows\currentversion\shellcompatibility",
    r"software\microsoft\windows\currentversion\uninstall",
    r"software\policies",
    r"software\microsoft\windows\currentversion\authentication",
    r"software\microsoft\windows\currentversion\telephony",
    r"software\microsoft\windows nt\currentversion\image file execution options",
    r"software\microsoft\windows nt\currentversion\svchost",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"software\microsoft\active setup",
    r"software\microsoft\.netframework",
    r"software\wow6432node\microsoft\.netframework",
)

#: Ветка, формирующая список «Установленные программы» (Add/Remove Programs).
#: Записью считается только ПОДКЛЮЧ внутри Uninstall, а не сама ветка.
_UNINSTALL_MARKER = "\\microsoft\\windows\\currentversion\\uninstall\\"


def _strip_hive(key_path: str) -> str:
    """``HKCU\\Software\\X`` -> ``software\\x`` (для сопоставления префиксов)."""
    parts = key_path.split("\\", 1)
    tail = parts[1] if len(parts) == 2 else ""
    return tail.casefold()


def _matches(path: str, prefixes: Sequence[str]) -> bool:
    for prefix in prefixes:
        if path == prefix or path.startswith(prefix + "\\"):
            return True
    return False


def is_volatile(key_path: str) -> bool:
    """Ветка, которую постоянно меняет сама Windows (в расчёт не берём)."""
    return _matches(_strip_hive(key_path), _VOLATILE_PREFIXES)


def categorize(key_path: str) -> str:
    """Относит ключ к ``app`` / ``integration`` / ``trace``."""
    path = _strip_hive(key_path)
    # Порядок важен: «App Paths» лежит внутри ...\CurrentVersion, но это
    # интеграция, а не просто системный шум.
    if _matches(path, _INTEGRATION_PREFIXES):
        return CATEGORY_INTEGRATION
    if _matches(path, _TRACE_PREFIXES):
        return CATEGORY_TRACE
    return CATEGORY_APP


def is_uninstall_entry(key_path: str) -> bool:
    """Ключ — это запись в списке «Установленные программы».

    ``...\\Uninstall\\MyApp`` — запись, сама ``...\\Uninstall`` — нет.
    """
    lowered = "\\" + _strip_hive(key_path)
    index = lowered.find(_UNINSTALL_MARKER)
    if index < 0:
        return False
    # После маркера должно остаться непустое имя подключа.
    return bool(lowered[index + len(_UNINSTALL_MARKER):].strip("\\"))


# --- снимок -------------------------------------------------------------------

def _walk(hive: int, subkey: str, prefix: str, out: Snapshot,
          max_depth: int = 7, depth: int = 0) -> None:
    """Рекурсивно обходит ветку и заполняет out[path] = {value: (type, repr)}."""
    if depth > max_depth:
        return
    full = f"{prefix}\\{subkey}" if subkey else prefix
    if depth and is_volatile(full):
        # Пропускаем всё поддерево: оно шумит и не относится к установке.
        return
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)  # type: ignore
    except OSError:
        return
    values: KeyValues = {}
    subkeys: List[str] = []
    try:
        i = 0
        while True:
            try:
                name, data, typ = winreg.EnumValue(key, i)  # type: ignore
            except OSError:
                break
            try:
                values[name] = (int(typ), repr(data))
            except Exception:  # noqa: BLE001 - экзотические типы пропускаем
                pass
            i += 1
        out[full] = values
        j = 0
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


def snapshot() -> Snapshot:
    """Делает снимок наблюдаемых веток. На не-Windows возвращает пусто."""
    if not IS_WINDOWS:
        return {}
    snap: Snapshot = {}
    hives = {
        "HKCU": winreg.HKEY_CURRENT_USER,  # type: ignore
        "HKLM": winreg.HKEY_LOCAL_MACHINE,  # type: ignore
    }
    for prefix, base in _ROOTS:
        _walk(hives[prefix], base, prefix, snap)
    return snap


# --- разница ------------------------------------------------------------------

@dataclass
class RegistryDiff:
    """Что именно изменилось между двумя снимками."""

    new_keys: List[str] = field(default_factory=list)
    changed_keys: List[str] = field(default_factory=list)
    #: ключ -> имена значений, которых раньше не было
    added_values: Dict[str, List[str]] = field(default_factory=dict)
    #: ключ -> {имя значения: прежнее (тип, repr)} — для отката на этом ПК
    previous_values: Dict[str, KeyValues] = field(default_factory=dict)

    @property
    def touched_keys(self) -> List[str]:
        return sorted(set(self.new_keys) | set(self.changed_keys))

    def keys_of(self, *categories: str) -> List[str]:
        wanted = set(categories)
        return [k for k in self.touched_keys if categorize(k) in wanted]

    def is_empty(self) -> bool:
        return not self.new_keys and not self.changed_keys


def compute_diff(before: Mapping[str, Mapping[str, object]],
                 after: Mapping[str, Mapping[str, object]]) -> RegistryDiff:
    """Сравнивает снимки, отбрасывая заведомо «шумные» ветки."""
    diff = RegistryDiff()
    for key, values in after.items():
        if is_volatile(key):
            continue
        old = before.get(key)
        if old is None:
            diff.new_keys.append(key)
            continue
        if dict(values) == dict(old):
            continue
        diff.changed_keys.append(key)
        added = [name for name in values if name not in old]
        if added:
            diff.added_values[key] = sorted(added)
        previous = {
            name: _as_entry(entry)
            for name, entry in old.items()
            if name not in values or values[name] != entry
        }
        if previous:
            diff.previous_values[key] = previous
    diff.new_keys.sort()
    diff.changed_keys.sort()
    return diff


def _as_entry(entry: object) -> ValueEntry:
    """Приводит запись снимка к (тип, repr). Понимает и старый формат."""
    if isinstance(entry, tuple) and len(entry) == 2:
        return int(entry[0]), str(entry[1])
    # Старый формат снимка хранил только repr строки.
    return REG_SZ, str(entry)


def _entry_value(entry: object):
    """Восстанавливает питоновское значение из записи снимка."""
    _typ, raw = _as_entry(entry)
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return raw


# --- формирование .reg --------------------------------------------------------

def _hive_name(key_path: str) -> str:
    return _HIVE_FULL.get(key_path.split("\\", 1)[0], "")


def _escape_sz(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _hex_bytes(raw: bytes) -> str:
    return ",".join(f"{b:02x}" for b in raw)


def _apply_tokens(text: str, tokens: Sequence[Tuple[str, str]]) -> str:
    """Заменяет абсолютные пути на маркеры (без учёта регистра)."""
    for needle, replacement in tokens:
        if not needle:
            continue
        text = re.sub(re.escape(needle), replacement.replace("\\", "\\\\"),
                      text, flags=re.IGNORECASE)
    return text


def format_value(name: str, typ: int, data,
                 tokens: Sequence[Tuple[str, str]] = ()) -> str:
    """Форматирует одно значение реестра в синтаксис .reg."""
    quoted_name = "@" if name == "" else f'"{_escape_sz(name)}"'
    if typ == REG_SZ:
        return f'{quoted_name}="{_escape_sz(_apply_tokens(str(data), tokens))}"'
    if typ == REG_EXPAND_SZ:
        text = _apply_tokens(str(data), tokens)
        raw = text.encode("utf-16-le") + b"\x00\x00"
        return f"{quoted_name}=hex(2):{_hex_bytes(raw)}"
    if typ == REG_DWORD:
        return f"{quoted_name}=dword:{int(data) & 0xffffffff:08x}"
    if typ == REG_QWORD:
        raw = (int(data) & 0xffffffffffffffff).to_bytes(8, "little")
        return f"{quoted_name}=hex(b):{_hex_bytes(raw)}"
    if typ == REG_MULTI_SZ:
        items = [_apply_tokens(str(x), tokens) for x in (data or [])]
        joined = "\x00".join(items) + "\x00\x00"
        return f"{quoted_name}=hex(7):{_hex_bytes(joined.encode('utf-16-le'))}"
    if typ == REG_BINARY:
        try:
            return f"{quoted_name}=hex:{_hex_bytes(bytes(data))}"
        except Exception:  # noqa: BLE001
            return f'{quoted_name}=""'
    try:
        return f"{quoted_name}=hex({typ:x}):{_hex_bytes(bytes(data))}"
    except Exception:  # noqa: BLE001
        return f'{quoted_name}=""'


_REG_HEADER = "Windows Registry Editor Version 5.00"


def _render(lines: Sequence[str]) -> str:
    body = "\n".join([_REG_HEADER, ""] + list(lines))
    return body.rstrip("\n") + "\n"


def render_keys(after: Mapping[str, Mapping[str, object]],
                keys: Iterable[str],
                tokens: Sequence[Tuple[str, str]] = ()) -> str:
    """Собирает .reg с текущим содержимым перечисленных ключей."""
    lines: List[str] = []
    for key in sorted(keys):
        hive = _hive_name(key)
        if not hive:
            continue
        subkey = key.split("\\", 1)[1]
        lines.append(f"[{hive}\\{subkey}]")
        for name, entry in sorted(after.get(key, {}).items()):
            typ, _raw = _as_entry(entry)
            lines.append(format_value(name, typ, _entry_value(entry), tokens))
        lines.append("")
    return _render(lines)


def render_launcher_undo(diff: RegistryDiff, keys: Iterable[str]) -> str:
    """Откат для чужого ПК: удаляет только то, что создал портатив.

    Прежние значения с машины сборки сюда намеренно не попадают — они
    относятся к другому компьютеру, и восстанавливать их где-то ещё нельзя.
    """
    wanted = set(keys)
    lines: List[str] = []
    for key in sorted(k for k in diff.new_keys if k in wanted):
        hive = _hive_name(key)
        if hive:
            lines.append(f"[-{hive}\\{key.split(chr(92), 1)[1]}]")
            lines.append("")
    for key in sorted(k for k in diff.changed_keys if k in wanted):
        added = diff.added_values.get(key)
        hive = _hive_name(key)
        if not added or not hive:
            continue
        lines.append(f"[{hive}\\{key.split(chr(92), 1)[1]}]")
        for name in added:
            quoted = "@" if name == "" else f'"{_escape_sz(name)}"'
            lines.append(f"{quoted}=-")
        lines.append("")
    return _render(lines)


def render_host_cleanup(diff: RegistryDiff, keys: Iterable[str]) -> str:
    """Полный откат для компьютера, на котором создавался портатив.

    Удаляет созданные ключи и возвращает прежние значения изменённым.
    """
    wanted = set(keys)
    lines: List[str] = []
    # Сначала восстановление значений, затем удаление ключей: так удаление
    # родителя не отменяет только что восстановленные данные потомка.
    for key in sorted(k for k in diff.changed_keys if k in wanted):
        hive = _hive_name(key)
        if not hive:
            continue
        previous = diff.previous_values.get(key, {})
        added = diff.added_values.get(key, [])
        if not previous and not added:
            continue
        lines.append(f"[{hive}\\{key.split(chr(92), 1)[1]}]")
        for name in added:
            quoted = "@" if name == "" else f'"{_escape_sz(name)}"'
            lines.append(f"{quoted}=-")
        for name, entry in sorted(previous.items()):
            typ, _raw = _as_entry(entry)
            lines.append(format_value(name, typ, _entry_value(entry)))
        lines.append("")
    for key in sorted(k for k in diff.new_keys if k in wanted):
        hive = _hive_name(key)
        if hive:
            lines.append(f"[-{hive}\\{key.split(chr(92), 1)[1]}]")
            lines.append("")
    return _render(lines)


def has_entries(reg_text: str) -> bool:
    """True, если в .reg есть хотя бы один блок ключа."""
    return any(line.startswith("[") for line in reg_text.splitlines())


def write_reg_file(path: str, text: str) -> None:
    """Пишет .reg в UTF-16 LE с BOM и CRLF — как ожидает ``reg import``."""
    with open(path, "w", encoding="utf-16", newline="\r\n") as fh:
        fh.write(text)


# --- вспомогательное для поиска установленной программы ------------------------

def changed_install_locations(before: Mapping[str, Mapping[str, object]],
                              after: Mapping[str, Mapping[str, object]]) -> List[str]:
    """Извлекает InstallLocation/DisplayIcon из новых записей установщика."""
    locations: List[str] = []
    seen: Set[str] = set()
    for key, values in after.items():
        if key in before and dict(values) == dict(before[key]):
            continue
        for value_name in ("InstallLocation", "DisplayIcon"):
            entry = values.get(value_name)
            if entry is None:
                entry = next(
                    (v for n, v in values.items()
                     if n.casefold() == value_name.casefold()),
                    None,
                )
            if entry is None:
                continue
            value = _entry_value(entry)
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


def installed_program_entries(diff: RegistryDiff,
                              after: Mapping[str, Mapping[str, object]]
                              ) -> List[Tuple[str, str]]:
    """Находит записи, добавленные в список «Установленные программы».

    Возвращает пары (ключ реестра, отображаемое имя).
    """
    entries: List[Tuple[str, str]] = []
    for key in diff.touched_keys:
        if not is_uninstall_entry(key):
            continue
        values = after.get(key, {})
        display = ""
        for name, entry in values.items():
            if name.casefold() == "displayname":
                value = _entry_value(entry)
                if isinstance(value, str):
                    display = value
                break
        entries.append((key, display or key.rsplit("\\", 1)[-1]))
    return entries
