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


def virtualize_machine_snapshot(snapshot: Mapping[str, Mapping[str, object]],
                                machine_keys: Iterable[str]
                                ) -> Tuple[Dict[str, KeyValues], List[str]]:
    """Создаёт виртуализированные HKCU-ветки для HKLM-ключей.

    Для 32-битных приложений (и для запуска без прав администратора) ключи
    HKLM\\Software\\... отображаются в:
      1. HKCU\\Software\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\...
         (официальная UAC-виртуализация реестра Windows)
      2. HKCU\\Software\\... (пользовательский fallback для приложений, ищущих
         настройки в HKCU)
    """
    virtual_snapshot: Dict[str, KeyValues] = {
        k: dict(v) for k, v in snapshot.items()  # type: ignore[misc]
    }
    virtual_keys: List[str] = []

    for key in machine_keys:
        if not key.upper().startswith("HKLM\\SOFTWARE"):
            continue
        tail = key[len("HKLM\\Software"):].strip("\\")
        if not tail:
            continue

        values = dict(snapshot.get(key, {}))
        if not values:
            continue

        # 1. VirtualStore
        vs_key = f"HKCU\\Software\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\{tail}"
        virtual_snapshot[vs_key] = values  # type: ignore[assignment]
        if vs_key not in virtual_keys:
            virtual_keys.append(vs_key)

        # 2. Прямой HKCU fallback
        hkcu_key = f"HKCU\\Software\\{tail}"
        virtual_snapshot[hkcu_key] = values  # type: ignore[assignment]
        if hkcu_key not in virtual_keys:
            virtual_keys.append(hkcu_key)

        # 3. Варианты с WOW6432Node и без него
        if tail.lower().startswith("wow6432node\\"):
            tail_no_wow = tail[len("wow6432node\\"):].strip("\\")
            if tail_no_wow:
                vs_no_wow = f"HKCU\\Software\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\{tail_no_wow}"
                hkcu_no_wow = f"HKCU\\Software\\{tail_no_wow}"
                virtual_snapshot[vs_no_wow] = values  # type: ignore[assignment]
                virtual_snapshot[hkcu_no_wow] = values  # type: ignore[assignment]
                if vs_no_wow not in virtual_keys:
                    virtual_keys.append(vs_no_wow)
                if hkcu_no_wow not in virtual_keys:
                    virtual_keys.append(hkcu_no_wow)
        else:
            vs_wow = f"HKCU\\Software\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\WOW6432Node\\{tail}"
            hkcu_wow = f"HKCU\\Software\\WOW6432Node\\{tail}"
            virtual_snapshot[vs_wow] = values  # type: ignore[assignment]
            virtual_snapshot[hkcu_wow] = values  # type: ignore[assignment]
            if vs_wow not in virtual_keys:
                virtual_keys.append(vs_wow)
            if hkcu_wow not in virtual_keys:
                virtual_keys.append(hkcu_wow)

    return virtual_snapshot, virtual_keys


def retarget_install_paths(snapshot: Mapping[str, Mapping[str, object]],
                           keys: Iterable[str], app_dir: str) -> Snapshot:
    """Перенаправляет захваченные пути установки в портативную ``App``.

    Некоторые установщики (в частности старые игры) не принимают переданную
    папку и сначала устанавливаются в ``Program Files``. Затем Portablizer
    переносит их файлы в ``App``, но значения вроде ``InstallFolder`` в
    захваченном реестре раньше продолжали указывать на уже удалённый исходный
    каталог. Основной exe часто обходится без этих значений, а комплектный
    Launcher/Configurator считает установку недействительной и молча
    закрывается.

    Меняются только общеупотребительные значения каталога установки в явно
    выбранных ключах приложения. Остальные строковые значения того же ключа
    (например ``LAUNCHCOMMAND``) получают замену старого корня на новый. Для
    GOG-подобной схемы значение ``EXE`` считается каталогом только когда рядом
    присутствует ``EXEFILE`` — это не даёт переписать произвольный путь к exe.
    """
    result: Snapshot = {
        key: {name: _as_entry(entry) for name, entry in values.items()}
        for key, values in snapshot.items()
    }
    destination = os.path.normpath(app_dir)
    install_names = {
        "installdir", "installdirectory", "installfolder", "installlocation",
    }

    for key in keys:
        values = result.get(key)
        if not values:
            continue
        names = {name.casefold(): name for name in values}
        path_names = [names[name] for name in install_names if name in names]
        if "exe" in names and "exefile" in names:
            path_names.append(names["exe"])
        if not path_names:
            continue

        old_roots: List[str] = []
        for name in path_names:
            typ, _raw = values[name]
            if typ not in (REG_SZ, REG_EXPAND_SZ):
                continue
            old = _entry_value(values[name])
            if not isinstance(old, str) or not old.strip():
                continue
            old_roots.append(old.rstrip("\\/"))
            trailing = "\\" if old.endswith(("\\", "/")) else ""
            values[name] = (typ, repr(destination + trailing))

        # Более длинный корень заменяется первым: C:\\Game\\bin не должен
        # частично совпасть с C:\\Game раньше времени.
        old_roots.sort(key=len, reverse=True)
        for name, entry in list(values.items()):
            typ, _raw = entry
            if typ not in (REG_SZ, REG_EXPAND_SZ):
                continue
            value = _entry_value(entry)
            if not isinstance(value, str):
                continue
            rewritten = value
            for old in old_roots:
                if old:
                    rewritten = re.sub(
                        re.escape(old),
                        lambda _match: destination,
                        rewritten,
                        flags=re.IGNORECASE,
                    )
            if rewritten != value:
                values[name] = (typ, repr(rewritten))
    return result


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


def render_host_cleanup_cmd(reg_file_name: str = "cleanup_host.reg") -> str:
    """Самоповышающийся .cmd для надёжного применения ``cleanup_host.reg``.

    Двойной клик по самому ``.reg`` запускает regedit **без** прав
    администратора, поэтому ветки ``HKLM`` (запись «Установленные программы»,
    службы и т.п.) записать не удаётся, и Windows показывает пугающее «Не все
    данные были успешно записаны в реестр». Этот скрипт:

    * сам запрашивает права администратора через UAC;
    * импортирует ``.reg`` уже с нужными правами (``reg import`` возвращает код,
      а не показывает модальное окно regedit);
    * молча пропускает ключи, которых уже нет, и сообщает об итоге понятным
      текстом.

    Файл строго ASCII — по той же причине, что и ``Launch.bat`` (см. модуль
    ``core/launcher``): cmd.exe читает .bat по байтовым смещениям.
    """
    # ``if errorlevel N`` (не ``%ERRORLEVEL%``) читается во время исполнения,
    # поэтому корректно работает и внутри блоков; переходы по меткам избавляют
    # от классической ловушки cmd с ранним раскрытием %ERRORLEVEL% в скобках.
    name = reg_file_name.replace('"', "")
    return (
        "@echo off\r\n"
        "setlocal EnableExtensions\r\n"
        "rem Removes the registry traces the installer left on THIS computer.\r\n"
        "rem It self-elevates so HKLM entries (the Add/Remove Programs record,\r\n"
        "rem services, etc.) can be removed without the scary regedit warning.\r\n"
        "\r\n"
        "net session >nul 2>&1\r\n"
        "if not errorlevel 1 goto do_cleanup\r\n"
        "echo Requesting administrator rights...\r\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"Start-Process -FilePath '%~f0' -Verb RunAs\" >nul 2>&1\r\n"
        "if errorlevel 1 (\r\n"
        "  echo.\r\n"
        "  echo Could not obtain administrator rights automatically.\r\n"
        "  echo Right-click this file and choose \"Run as administrator\".\r\n"
        "  pause\r\n"
        ")\r\n"
        "exit /b 0\r\n"
        "\r\n"
        ":do_cleanup\r\n"
        "cd /d \"%~dp0\"\r\n"
        f'if not exist "{name}" (\r\n'
        f'  echo Nothing to clean up: {name} was not found next to this file.\r\n'
        "  timeout /t 4 >nul 2>&1\r\n"
        "  exit /b 0\r\n"
        ")\r\n"
        "\r\n"
        f'reg import "{name}" >nul 2>&1\r\n'
        "echo.\r\n"
        "echo Cleanup finished. The install traces were removed from this PC.\r\n"
        "echo Entries that were already gone are simply skipped - that is fine.\r\n"
        "timeout /t 5 >nul 2>&1\r\n"
        "exit /b 0\r\n"
    )


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


# --- разбор .reg, зеркалирование WOW6432Node и языковая настройка -------------

#: Имена значений реестра, которые в играх и программах отвечают за язык
#: интерфейса, текста, субтитров или локали.
_LANGUAGE_VALUE_NAMES = frozenset({
    "language",
    "installlanguage",
    "textlanguage",
    "subtitlelanguage",
    "subtitleslanguage",
    "uilanguage",
    "interfacelanguage",
    "voicelanguage",
    "audiolanguage",
    "spokenlanguage",
    "locale",
    "lang",
    "langid",
    "languageid",
    "culture",
})

#: Имена папок в репаках (например, _Lang_SW у dixen18), где лежат .reg-переключатели.
_LANGUAGE_DIR_HINTS = (
    "lang", "locale", "language", "rus", "eng", "язык",
)

#: Конфигурационные файлы эмуляторов и загрузчиков, в которых задаётся язык игры.
_LANGUAGE_INI_FILENAMES = frozenset({
    "steam_emu.ini",
    "steam_api.ini",
    "steam_api64.ini",
    "ali213.ini",
    "codex.ini",
    "flt.ini",
    "tenoke.ini",
    "rld.ini",
    "rld!.ini",
    "skidrow.ini",
    "3dmgame.ini",
    "uplay.ini",
    "uplay_r1.ini",
    "uplay_r1_loader.ini",
    "orbit.ini",
    "ubiorbitapi_r2.ini",
    "ubiorbitapi_r2_loader.ini",
    "cpy.ini",
    "hlm.ini",
    "hoodlum.ini",
    "goggame.ini",
    "force_language.txt",
})


def read_reg_file_text(path: str) -> str:
    """Читает .reg-файл в любой распространённой кодировке (UTF-16, UTF-8, CP1251)."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw:
        return ""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if b"\x00" in raw[:64]:
        return raw.decode("utf-16-le", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("cp1251")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace")


def normalize_snapshot_key(raw_key: str) -> Optional[str]:
    """Приводит заголовок секции .reg к виду ключа в ``Snapshot``."""
    cleaned = (raw_key or "").strip().strip("[]").strip().rstrip("\\")
    if not cleaned or cleaned.startswith("-"):
        return None
    parts = [p for p in cleaned.split("\\") if p]
    if len(parts) < 2:
        return None
    root_up = parts[0].upper()
    if root_up in ("HKEY_LOCAL_MACHINE", "HKLM"):
        parts[0] = "HKLM"
    elif root_up in ("HKEY_CURRENT_USER", "HKCU"):
        parts[0] = "HKCU"
    else:
        return None
    if parts[1].upper() == "SOFTWARE":
        parts[1] = "Software"
    if len(parts) >= 3 and parts[2].upper() == "WOW6432NODE":
        parts[2] = "WOW6432Node"
    if (len(parts) >= 6
            and parts[1] == "Software"
            and parts[2].upper() == "CLASSES"
            and parts[3].upper() == "VIRTUALSTORE"
            and parts[4].upper() == "MACHINE"
            and parts[5].upper() == "SOFTWARE"):
        parts[2] = "Classes"
        parts[3] = "VirtualStore"
        parts[4] = "MACHINE"
        parts[5] = "SOFTWARE"
        if len(parts) >= 7 and parts[6].upper() == "WOW6432NODE":
            parts[6] = "WOW6432Node"
    return "\\".join(parts)


def _unescape_reg_string(text: str) -> str:
    """Раскрывает экранирование строкового литерала из .reg-файла."""
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt in ('"', "\\"):
                out.append(nxt)
                i += 2
                continue
            if nxt == "r":
                out.append("\r")
                i += 2
                continue
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _split_reg_name_and_value(line: str) -> Optional[Tuple[str, str]]:
    """Делит строку ``"Name"=...`` или ``@=...`` на имя параметра и правую часть."""
    stripped = line.strip()
    if not stripped or stripped.startswith(";"):
        return None
    if stripped.startswith("@"):
        rest = stripped[1:].lstrip()
        if not rest.startswith("="):
            return None
        return "", rest[1:].strip()
    if not stripped.startswith('"'):
        return None
    i = 1
    n = len(stripped)
    name_chars: List[str] = []
    while i < n:
        ch = stripped[i]
        if ch == "\\" and i + 1 < n:
            name_chars.append(stripped[i + 1])
            i += 2
            continue
        if ch == '"':
            i += 1
            break
        name_chars.append(ch)
        i += 1
    else:
        return None
    rest = stripped[i:].lstrip()
    if not rest.startswith("="):
        return None
    return "".join(name_chars), rest[1:].strip()


def _encode_value(typ: int, data: object) -> ValueEntry:
    """Кодирует значение реестра в пару ``(тип, repr(значение))`` для ``Snapshot``."""
    return (int(typ), repr(data))


def _parse_reg_rhs(rhs: str, regedit4: bool = False) -> Optional[ValueEntry]:
    """Преобразует правую часть строки .reg в ``ValueEntry`` снимка."""
    if not rhs or rhs == "-":
        return None
    if rhs.startswith('"') and rhs.endswith('"') and len(rhs) >= 2:
        return _encode_value(REG_SZ, _unescape_reg_string(rhs[1:-1]))
    low = rhs.lower()
    if low.startswith("dword:"):
        hex_part = rhs[6:].strip()
        try:
            return _encode_value(REG_DWORD, int(hex_part, 16))
        except ValueError:
            return None
    if low.startswith("hex"):
        colon = rhs.find(":")
        if colon < 0:
            return None
        prefix = low[:colon].strip()
        hex_bytes = [
            int(b, 16)
            for b in re.findall(r"[0-9a-fA-F]{2}", rhs[colon + 1:])
        ]
        raw_bytes = bytes(hex_bytes)
        if prefix == "hex":
            return _encode_value(REG_BINARY, raw_bytes)
        if prefix == "hex(b)":
            padded = (raw_bytes + b"\x00" * 8)[:8]
            return _encode_value(REG_QWORD, int.from_bytes(padded, "little"))
        if prefix == "hex(2)":
            enc = "cp1251" if regedit4 else "utf-16-le"
            decoded = raw_bytes.decode(enc, errors="replace").rstrip("\x00")
            return _encode_value(REG_EXPAND_SZ, decoded)
        if prefix == "hex(7)":
            enc = "cp1251" if regedit4 else "utf-16-le"
            decoded = raw_bytes.decode(enc, errors="replace")
            while decoded.endswith("\x00"):
                decoded = decoded[:-1]
            parts = decoded.split("\x00") if decoded else []
            return _encode_value(REG_MULTI_SZ, parts)
        return _encode_value(REG_BINARY, raw_bytes)
    return None


def parse_reg_text(text: str) -> Snapshot:
    """Разбирает текст .reg-файла в структуру ``Snapshot``."""
    result: Snapshot = {}
    if not text:
        return result

    regedit4 = "REGEDIT4" in text[:128].upper()
    logical_lines: List[str] = []
    carry = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if carry:
            if line.endswith("\\"):
                carry += line[:-1].strip()
            else:
                carry += line
                logical_lines.append(carry)
                carry = ""
            continue
        if line.endswith("\\") and not line.startswith(";"):
            carry = line[:-1].strip()
        else:
            logical_lines.append(line)
    if carry:
        logical_lines.append(carry)

    current_key: Optional[str] = None
    key_lookup: Dict[str, str] = {}
    for line in logical_lines:
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            norm_key = normalize_snapshot_key(line)
            if norm_key is None:
                current_key = None
                continue
            existing = key_lookup.get(norm_key.casefold())
            if existing is None:
                existing = norm_key
                key_lookup[norm_key.casefold()] = existing
                result[existing] = {}
            current_key = existing
            continue
        if current_key is None:
            continue
        parsed = _split_reg_name_and_value(line)
        if parsed is None:
            continue
        val_name, rhs = parsed
        if rhs == "-":
            for k_name in list(result[current_key]):
                if k_name.casefold() == val_name.casefold():
                    del result[current_key][k_name]
            continue
        entry = _parse_reg_rhs(rhs, regedit4=regedit4)
        if entry is None:
            continue
        existing_val_name = next(
            (n for n in result[current_key] if n.casefold() == val_name.casefold()),
            val_name,
        )
        result[current_key][existing_val_name] = entry
    return result


def parse_reg_file(path: str) -> Snapshot:
    """Читает и разбирает .reg-файл с диска."""
    try:
        text = read_reg_file_text(path)
    except OSError:
        return {}
    return parse_reg_text(text)


def _find_matching_key(snapshot: Mapping[str, object], key: str) -> Optional[str]:
    """Ищет ключ в ``snapshot`` без учёта регистра."""
    if key in snapshot:
        return key
    target = key.casefold()
    for existing in snapshot:
        if existing.casefold() == target:
            return existing
    return None


def _machine_sibling_key(key: str) -> Optional[str]:
    """Возвращает парный 32/64-битный ключ HKLM\\Software\\(WOW6432Node\\)..."""
    norm = normalize_snapshot_key(key) or key
    if not norm.upper().startswith("HKLM\\SOFTWARE\\"):
        return None
    tail = norm.split("\\", 2)[2] if norm.count("\\") >= 2 else ""
    if not tail:
        return None
    if tail.lower().startswith("wow6432node\\"):
        rest = tail[len("wow6432node\\"):].strip("\\")
        return f"HKLM\\Software\\{rest}" if rest else None
    if tail.lower() == "wow6432node":
        return None
    return f"HKLM\\Software\\WOW6432Node\\{tail}"


def mirror_machine_views(snapshot: Mapping[str, Mapping[str, object]],
                         keys: Iterable[str]) -> Tuple[Snapshot, List[str]]:
    """Синхронизирует ветки ``HKLM\\Software\\...`` и ``HKLM\\Software\\WOW6432Node\\...``.

    Репаки и игры (например, Assassin's Creed Brotherhood) на 64-битной Windows
    хранят настройки в ``WOW6432Node``, а в ``_Lang_SW`` держат отдельные .reg
    для ``x86`` и ``x64``. Зеркалирование обеих веток гарантирует, что и 32-битный,
    и 64-битный процесс увидят одинаковый ``Language`` и ``InstallDir``.
    """
    result: Snapshot = {
        k: {n: _as_entry(v) for n, v in vals.items()}
        for k, vals in snapshot.items()
    }
    out_keys: List[str] = list(keys)
    seen_cf = {k.casefold() for k in out_keys}

    for key in list(keys):
        if is_volatile(key) or categorize(key) != CATEGORY_APP:
            continue
        sibling = _machine_sibling_key(key)
        if not sibling or is_volatile(sibling) or categorize(sibling) != CATEGORY_APP:
            continue
        src_key = _find_matching_key(result, key)
        if src_key is None or not result.get(src_key):
            continue
        dst_key = _find_matching_key(result, sibling) or sibling
        merged: KeyValues = dict(result.get(dst_key, {}))
        existing_names = {n.casefold(): n for n in merged}
        for name, entry in result[src_key].items():
            target_name = existing_names.get(name.casefold(), name)
            merged[target_name] = _as_entry(entry)
            existing_names[name.casefold()] = target_name
        result[dst_key] = merged
        if dst_key.casefold() not in seen_cf:
            out_keys.append(dst_key)
            seen_cf.add(dst_key.casefold())

    return result, out_keys


def _detect_reg_snapshot_language(snap: Snapshot, rel_path: str) -> Optional[str]:
    """Определяет код языка («ru», «en», ...), за который отвечает .reg-файл."""
    from .languages import identify_language_token

    # 1. По значениям внутри самого .reg-файла (самый надёжный признак:
    #    например, "Language"="Russian" -> "ru").
    content_codes: List[str] = []
    total_values = sum(len(v) for v in snap.values())
    for key, values in snap.items():
        key_leaf = key.rsplit("\\", 1)[-1].casefold()
        for name, entry in values.items():
            name_cf = name.casefold()
            is_lang_field = (
                name_cf in _LANGUAGE_VALUE_NAMES
                or (name_cf == "" and key_leaf in _LANGUAGE_VALUE_NAMES)
                or total_values <= 8
            )
            if not is_lang_field:
                continue
            typ, _raw = _as_entry(entry)
            val = _entry_value(entry)
            code: Optional[str] = None
            if typ in (REG_SZ, REG_EXPAND_SZ) and isinstance(val, str):
                code = identify_language_token(val)
            elif typ == REG_DWORD and isinstance(val, int):
                code = identify_language_token(str(val))
            if code and code not in content_codes:
                content_codes.append(code)
    if len(content_codes) == 1:
        return content_codes[0]

    # 2. По токенам относительного пути и имени файла (например,
    #    _Lang_SW\x64\Rus.reg или _Lang_SW\Russian\x64.reg).
    norm_rel = rel_path.replace("/", "\\")
    stem_path = os.path.splitext(norm_rel)[0]
    tokens = [
        tok for tok in re.split(r"[^0-9A-Za-zА-Яа-яЁёІіЇїЄєҐґ\-]+", stem_path)
        if tok
    ]
    # Дополнительно проверяем части составных токенов с дефисом и без него
    expanded_tokens: List[str] = []
    for tok in tokens:
        expanded_tokens.append(tok)
        if "-" in tok:
            expanded_tokens.extend(p for p in tok.split("-") if p)

    path_codes: List[str] = []
    # Сначала проверяем имя самого файла, затем родительские папки от нижней к верхней
    parts = [p for p in stem_path.split("\\") if p]
    for part in reversed(parts):
        part_codes: List[str] = []
        subtokens = [t for t in re.split(r"[^0-9A-Za-zА-Яа-яЁёІіЇїЄєҐґ]+", part) if t]
        for cand in [part, *subtokens]:
            code = identify_language_token(cand)
            if code and code not in part_codes:
                part_codes.append(code)
        if len(part_codes) == 1:
            return part_codes[0]
        for code in part_codes:
            if code not in path_codes:
                path_codes.append(code)

    if len(path_codes) == 1:
        return path_codes[0]
    if content_codes:
        return content_codes[0]
    return None


def find_language_reg_files(app_dir: str, lang_code: str) -> List[str]:
    """Находит в ``App`` языковые .reg-файлы (например, ``_Lang_SW\\x64\\Rus.reg``),
    соответствующие выбранному языку ``lang_code``.
    """
    from .languages import find_registry_profile

    profile = find_registry_profile(lang_code)
    if profile is None or not app_dir or not os.path.isdir(app_dir):
        return []

    target_code = profile.code.casefold()
    matched: List[str] = []
    skip_dirs = {"portabledata", "redist", "_redist_cache", "updates"}

    for root, dirs, files in os.walk(app_dir):
        dirs[:] = sorted(
            d for d in dirs if d.casefold() not in skip_dirs
        )
        for fname in sorted(files):
            if not fname.lower().endswith(".reg"):
                continue
            if fname.lower() in (
                "portable.reg", "portable_machine.reg", "cleanup_host.reg",
            ):
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, app_dir)
            snap = parse_reg_file(full_path)
            if not snap:
                continue
            # Пропускаем файлы, где нет ни одного ключа категории app
            if not any(
                not is_volatile(k) and categorize(k) == CATEGORY_APP
                for k in snap
            ):
                continue
            detected = _detect_reg_snapshot_language(snap, rel_path)
            if detected and detected.casefold() == target_code:
                matched.append(full_path)

    return matched


def _rewrite_snapshot_language_values(
    snapshot: Snapshot,
    keys: Iterable[str],
    lang_code: str,
) -> List[str]:
    """Переписывает значения языка в указанных ключах ``snapshot`` на ``lang_code``."""
    from .languages import convert_language_dword, convert_language_string

    updated_keys: List[str] = []
    for key in list(keys):
        actual_key = _find_matching_key(snapshot, key)
        if actual_key is None:
            continue
        values = snapshot.get(actual_key)
        if not values:
            continue
        key_leaf = actual_key.rsplit("\\", 1)[-1].casefold()
        changed = False
        for name, entry in list(values.items()):
            name_cf = name.casefold()
            if name_cf not in _LANGUAGE_VALUE_NAMES and not (
                name_cf == "" and key_leaf in _LANGUAGE_VALUE_NAMES
            ):
                continue
            typ, _raw = _as_entry(entry)
            val = _entry_value(entry)
            if typ in (REG_SZ, REG_EXPAND_SZ) and isinstance(val, str):
                new_val = convert_language_string(val, lang_code)
                if new_val is not None and new_val != val:
                    values[name] = _encode_value(typ, new_val)
                    changed = True
            elif typ == REG_DWORD and isinstance(val, int):
                new_int = convert_language_dword(val, lang_code)
                if new_int is not None and new_int != val:
                    values[name] = _encode_value(REG_DWORD, new_int)
                    changed = True
        if changed and actual_key not in updated_keys:
            updated_keys.append(actual_key)
    return updated_keys


def apply_language_to_snapshot(
    before: Snapshot,
    after: Snapshot,
    app_dir: str,
    lang_code: str,
) -> Tuple[List[str], List[str]]:
    """Применяет выбранный язык ``lang_code`` к снимку реестра после установки.

    1. Ищет в ``app_dir`` комплектные .reg-файлы переключения языка
       (например, ``_Lang_SW\\x64\\Rus.reg`` и ``_Lang_SW\\x86\\Rus.reg``
       в репаках dixen18) и сливает их ключи/значения в ``after``.
    2. В захваченных ключах приложения переводит языковые значения
       (``Language``, ``InstallLanguage``, ``TextLanguage``, ``Locale`` и т.д.)
       в формат выбранного языка («English» -> «Russian», «eng» -> «rus»,
       1033 -> 1049).
    3. Зеркалирует ``HKLM\\Software\\...`` и ``HKLM\\Software\\WOW6432Node\\...``
       и убирает затронутые ключи игры из ``before``, чтобы ``compute_diff``
       гарантированно включил их в ``portable.reg`` и ``portable_machine.reg``.

    Возвращает ``(применённые_reg_файлы_отн_App, изменённые_ключи)``.
    """
    from .languages import find_registry_profile

    profile = find_registry_profile(lang_code)
    if profile is None:
        return [], []

    applied_files: List[str] = []
    touched_keys: List[str] = []

    reg_files = find_language_reg_files(app_dir, lang_code)
    for reg_path in reg_files:
        parsed = parse_reg_file(reg_path)
        if not parsed:
            continue
        rel = os.path.relpath(reg_path, app_dir) if app_dir else reg_path
        applied_files.append(rel)
        for key, vals in parsed.items():
            if is_volatile(key) or categorize(key) != CATEGORY_APP:
                continue
            target_key = _find_matching_key(after, key) or key
            dest_vals = after.setdefault(target_key, {})
            existing_names = {n.casefold(): n for n in dest_vals}
            for v_name, v_entry in vals.items():
                # Не затираем реальный InstallDir из снимка чужим путём из .reg
                if (v_name.casefold() in ("installdir", "installdirectory",
                                          "installfolder", "installlocation")
                        and v_name.casefold() in existing_names):
                    continue
                actual_name = existing_names.get(v_name.casefold(), v_name)
                dest_vals[actual_name] = _as_entry(v_entry)
                existing_names[v_name.casefold()] = actual_name
            if target_key not in touched_keys:
                touched_keys.append(target_key)

    diff = compute_diff(before, after)
    app_keys = list(diff.keys_of(CATEGORY_APP))
    for k in touched_keys:
        if k not in app_keys:
            app_keys.append(k)

    rewritten = _rewrite_snapshot_language_values(after, app_keys, lang_code)
    for k in rewritten:
        if k not in touched_keys:
            touched_keys.append(k)
        if k not in app_keys:
            app_keys.append(k)

    # Зеркалируем 32-битное (WOW6432Node) и 64-битное представления HKLM
    mirrored_after, mirrored_keys = mirror_machine_views(after, app_keys)
    after.clear()
    after.update(mirrored_after)
    for k in mirrored_keys:
        if k not in app_keys:
            app_keys.append(k)

    # Любой ключ, явно заданный языковым .reg-файлом или переписанный по языку,
    # должен попасть в portable.reg / portable_machine.reg даже если на ПК
    # сборки такой же ключ уже существовал до запуска Portablizer.
    force_keys = set(touched_keys)
    for k in list(force_keys):
        sib = _machine_sibling_key(k)
        if sib:
            force_keys.add(sib)
    for k in force_keys:
        if k in mirrored_keys and k not in touched_keys:
            touched_keys.append(k)
        before_key = _find_matching_key(before, k)
        if before_key is not None:
            del before[before_key]

    return applied_files, touched_keys


def apply_language_to_ini_files(app_dir: str, lang_code: str) -> List[str]:
    """Обновляет параметр языка в INI-файлах эмуляторов/загрузчиков внутри ``App``."""
    from .languages import convert_language_string, find_registry_profile

    profile = find_registry_profile(lang_code)
    if profile is None or not app_dir or not os.path.isdir(app_dir):
        return []

    updated_files: List[str] = []
    skip_dirs = {"portabledata", "redist", "_redist_cache", "updates"}
    ini_key_re = re.compile(
        r"^(\s*(?:Language|InstallLanguage|TextLanguage|SubtitleLanguage|"
        r"SubtitlesLanguage|UILanguage|InterfaceLanguage|Locale|Lang)\s*=\s*)"
        r"([^\r\n;#]*?)(\s*(?:[;#].*)?)$",
        re.IGNORECASE,
    )

    for root, dirs, files in os.walk(app_dir):
        dirs[:] = sorted(d for d in dirs if d.casefold() not in skip_dirs)
        for fname in sorted(files):
            if fname.casefold() not in _LANGUAGE_INI_FILENAMES:
                continue
            full_path = os.path.join(root, fname)
            try:
                with open(full_path, "rb") as fh:
                    raw = fh.read(512 * 1024)
            except OSError:
                continue
            if b"\x00" in raw[:64]:
                enc = "utf-16"
            elif raw.startswith(b"\xef\xbb\xbf"):
                enc = "utf-8-sig"
            else:
                enc = "utf-8"
            try:
                text = raw.decode(enc)
            except UnicodeDecodeError:
                enc = "cp1251"
                text = raw.decode(enc, errors="replace")

            if fname.casefold() == "force_language.txt":
                stripped = text.strip()
                new_val = convert_language_string(stripped, lang_code) or profile.english_name.lower()
                if new_val != stripped:
                    try:
                        with open(full_path, "w", encoding=enc, newline="\r\n") as fh:
                            fh.write(new_val + "\n")
                        updated_files.append(os.path.relpath(full_path, app_dir))
                    except OSError:
                        pass
                continue

            changed = False
            new_lines: List[str] = []
            for line in text.splitlines(keepends=True):
                ending = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
                body = line[:-len(ending)] if ending else line
                m = ini_key_re.match(body)
                if m:
                    prefix, val_part, suffix = m.groups()
                    quote = ""
                    clean_val = val_part.strip()
                    if (len(clean_val) >= 2
                            and clean_val[0] == clean_val[-1]
                            and clean_val[0] in ('"', "'")):
                        quote = clean_val[0]
                        clean_val = clean_val[1:-1]
                    converted = convert_language_string(clean_val, lang_code)
                    if converted is not None and converted != clean_val:
                        body = f"{prefix}{quote}{converted}{quote}{suffix}"
                        changed = True
                new_lines.append(body + ending)

            if changed:
                try:
                    with open(full_path, "wb") as fh:
                        fh.write("".join(new_lines).encode(enc))
                    updated_files.append(os.path.relpath(full_path, app_dir))
                except OSError:
                    pass

    return updated_files


def apply_language_to_portable_folder(
    portable_dir: str,
    lang_code: str,
    reg_file_name: str = "portable.reg",
    machine_reg_file_name: str = "portable_machine.reg",
    data_dir_name: str = "PortableData",
) -> Tuple[List[str], List[str], List[str]]:
    """Применяет язык ``lang_code`` к уже собранной папке портатива.

    Обновляет ``portable.reg``, ``portable_machine.reg``, сохранённую сессию
    ``PortableData\\Registry\\*.reg`` (включая ветки ``VirtualStore`` и
    ``WOW6432Node``) и INI-файлы в ``App``.
    Возвращает ``(применённые_reg_файлы, все_ключи_реестра, обновлённые_ini)``.
    """
    from .languages import find_registry_profile

    profile = find_registry_profile(lang_code)
    if profile is None or not portable_dir or not os.path.isdir(portable_dir):
        return [], [], []

    app_dir = os.path.join(portable_dir, "App")
    user_reg_path = os.path.join(portable_dir, reg_file_name)
    machine_reg_path = os.path.join(portable_dir, machine_reg_file_name)
    session_dir = os.path.join(portable_dir, data_dir_name, "Registry")

    combined: Snapshot = {}
    if os.path.isfile(user_reg_path):
        for k, v in parse_reg_file(user_reg_path).items():
            combined.setdefault(k, {}).update(v)
    if os.path.isfile(machine_reg_path):
        for k, v in parse_reg_file(machine_reg_path).items():
            combined.setdefault(k, {}).update(v)

    session_files: List[str] = []
    if os.path.isdir(session_dir):
        for fname in sorted(os.listdir(session_dir)):
            if fname.lower().endswith(".reg"):
                s_path = os.path.join(session_dir, fname)
                session_files.append(s_path)
                for k, v in parse_reg_file(s_path).items():
                    combined.setdefault(k, {}).update(v)

    before_empty: Snapshot = {}
    applied_regs, touched = apply_language_to_snapshot(
        before_empty, combined, app_dir, lang_code,
    )
    updated_inis = apply_language_to_ini_files(app_dir, lang_code)

    if not combined:
        return applied_regs, [], updated_inis

    # Перестраиваем виртуализацию HKLM -> HKCU / VirtualStore с обновлёнными
    # языковыми значениями
    machine_keys = [k for k in combined if k.startswith("HKLM")]
    if machine_keys:
        combined, virtual_keys = virtualize_machine_snapshot(combined, machine_keys)
    else:
        virtual_keys = []

    # Дополнительно переписываем любые существующие ключи HKCU / VirtualStore
    _rewrite_snapshot_language_values(combined, list(combined.keys()), lang_code)

    user_keys = sorted(k for k in combined if k.startswith("HKCU"))
    machine_keys = sorted(k for k in combined if k.startswith("HKLM"))

    tokens = [(portable_dir, ROOT_TOKEN)]
    alt = portable_dir.replace("\\", "/")
    if alt != portable_dir:
        tokens.append((alt, ROOT_TOKEN))

    if user_keys:
        user_text = render_keys(combined, user_keys, tokens)
        if has_entries(user_text):
            write_reg_file(user_reg_path, user_text)

    if machine_keys:
        machine_text = render_keys(combined, machine_keys, tokens)
        if has_entries(machine_text):
            write_reg_file(machine_reg_path, machine_text)

    # Обновляем сохранённые файлы сессии PortableData\Registry\k*.reg, чтобы
    # они не перетёрли обновлённый portable.reg при следующем запуске
    for s_path in session_files:
        s_snap = parse_reg_file(s_path)
        if not s_snap:
            continue
        for k in list(s_snap.keys()):
            match_k = _find_matching_key(combined, k)
            if match_k is not None:
                existing_names = {n.casefold(): n for n in s_snap[k]}
                for v_name, v_entry in combined[match_k].items():
                    t_name = existing_names.get(v_name.casefold(), v_name)
                    s_snap[k][t_name] = v_entry
        _rewrite_snapshot_language_values(s_snap, list(s_snap.keys()), lang_code)
        s_text = render_keys(s_snap, list(s_snap.keys()), tokens)
        if has_entries(s_text):
            write_reg_file(s_path, s_text)

    all_keys = sorted(set(user_keys + machine_keys + virtual_keys))
    return applied_regs, all_keys, updated_inis

