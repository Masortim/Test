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
import ntpath
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    import winreg  # type: ignore

from . import relpaths

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
# Кэш меню «Пуск» Win11 (StartPins / Start2 / StartCache) — типичный источник
# жалобы: при запуске от администратора Portablizer захватывал эти ключи в
# portable.reg, а лончер затем применял снимок из-под повышенных прав — в
# итоге кэш сбрасывался и закреплённые плитки пропадали (жалоба №2).
_VOLATILE_PREFIXES: Tuple[str, ...] = (
    r"software\microsoft\windows\currentversion\explorer\startcache",
    r"software\microsoft\windows\currentversion\explorer\startcache2",
    r"software\microsoft\windows\currentversion\explorer\startpage",
    r"software\microsoft\windows\currentversion\explorer\startpage2",
    r"software\microsoft\windows\currentversion\explorer\startpins",
    r"software\microsoft\windows\currentversion\explorer\start2",
    r"software\microsoft\windows\currentversion\explorer\advanced\start",
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

# Ключи, которые нельзя ни переносить в портатив, ни откатывать по снимку.
# Это не «настройки приложения»: здесь живут лицензирование Windows/Office,
# компоненты Windows и регистрации Microsoft Edge/WebView2. Их восстановление
# по старому снимку способно деактивировать продукты или нарушить обновление.
_PROTECTED_PREFIXES: Tuple[str, ...] = (
    r"software\microsoft\windows nt\currentversion\softwareprotectionplatform",
    r"software\microsoft\windows nt\currentversion\sl",
    r"software\microsoft\windows nt\currentversion\licensemanager",
    r"software\microsoft\windows\currentversion\activation",
    r"software\microsoft\windows\currentversion\licensing",
    r"software\microsoft\windows\currentversion\appx",
    r"software\microsoft\windows\currentversion\windowsupdate",
    r"software\microsoft\office",
    r"software\microsoft\officesoftwareprotectionplatform",
    r"software\microsoft\edge",
    r"software\microsoft\edgewebview",
    r"software\microsoft\edgeupdate",
    # Регистрация браузера по умолчанию. Портатив не устанавливает браузер:
    # перенос этих веток создавал на чужом ПК дубликат — вторую запись в
    # «Программах по умолчанию», второй пункт «Браузер» и перехват ссылок.
    # Страницы входа открываются в уже установленном браузере, поэтому
    # хранить здесь нечего.
    r"software\clients\startmenuinternet",
    r"software\registeredapplications",
    r"software\microsoft\windows\shell\associations\urlassociations",
    r"software\microsoft\windows\currentversion\applicationassociations",
)

# Отдельные записи «Программы и компоненты» могут иметь случайный GUID вместо
# понятного пути ключа. Отсекаем их по DisplayName, чтобы не удалить запись
# WebView2/Office при попытке очистить следы устанавливаемого приложения.
_PROTECTED_UNINSTALL_MARKERS: Tuple[str, ...] = (
    "microsoft office",
    "microsoft 365",
    "office software protection",
    "microsoft edge",
    "edge webview2",
    "windows 10",
    "windows 11",
    "microsoft windows",
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


def _path_variants(key_path: str) -> List[str]:
    """Путь реестра без hive и эквивалент без WOW6432Node."""
    path = _strip_hive(key_path)
    variants = [path]
    wow = "software\\wow6432node\\"
    if path.startswith(wow):
        variants.append("software\\" + path[len(wow):])
    return variants


def is_volatile(key_path: str) -> bool:
    """Ветка, которую постоянно меняет сама Windows (в расчёт не берём)."""
    return any(_matches(path, _VOLATILE_PREFIXES)
               for path in _path_variants(key_path))


def is_protected(key_path: str,
                 values: Optional[Mapping[str, object]] = None) -> bool:
    """Ветка/продукт с системным состоянием, которое Portablizer не трогает.

    Помимо явных веток Windows/Office/Edge учитывает записи с произвольным
    GUID в ``Uninstall``: там название продукта известно только из
    ``DisplayName``. Параметр ``values`` имеет формат снимка реестра.
    """
    if any(_matches(path, _PROTECTED_PREFIXES)
           for path in _path_variants(key_path)):
        return True
    if not values or not is_uninstall_entry(key_path):
        return False
    for name, entry in values.items():
        if str(name).casefold() != "displayname":
            continue
        try:
            display_name = str(_entry_value(entry)).strip().casefold()
        except Exception:  # noqa: BLE001 - повреждённая запись не должна ломать сбор
            continue
        if any(marker in display_name
               for marker in _PROTECTED_UNINSTALL_MARKERS):
            return True
    return False


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


# --- URL-протоколы приложений --------------------------------------------------
#
# Протоколы (figma://, discord://, spotify:// и т.п.) — это браузерные
# «глубокие ссылки»: браузер передаёт их в программу через реестр, а не через
# аргументы запуска. Figma после входа в аккаунт показывает «Открыть Figma»,
# и Windows открывает то, что записано в Software\Classes\<scheme> — если
# протокол не перенесён в портатив, это установленная программа, а не
# портативная копия. Поэтому протоколы переносятся ВСЕГДА (как настройки
# программы), а не вместе с --shell-integration: это не ассоциация файлов,
# а часть работы приложения.

#: Grammar RFC 3986 для схемы URL (регистр не важен: figma и FIGMA — один
#: протокол). Ассоциации файлов начинаются с «.», а COM-классы содержат
#: точки и заглавные буквы — их отсечёт проверка значений ниже.
_PROTOCOL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*$", re.IGNORECASE)

#: Значение, которое ставит установщик в ключ схемы при регистрации
#: протокола (``HKCU\Software\Classes\<scheme>``).
_PROTOCOL_MARKER_VALUE = "url protocol"

#: Схемы, которые принадлежат не программе, а браузеру и оболочке Windows.
#: Регистрация ``http``/``https`` — это заявка «я браузер по умолчанию»; если
#: перенести её в портатив, лончер на чужом ПК переназначит открытие ссылок
#: своей копии, то есть создаст второй браузер в реестре. Ровно этого и не
#: должно происходить: страница входа открывается в УЖЕ установленном
#: браузере пользователя (см. BrowserLoginBridge в лончере).
_WEB_SCHEMES = frozenset({
    "http", "https", "ftp", "ftps", "file", "mailto", "tel", "callto", "sms",
    "news", "nntp", "feed", "webcal", "irc", "ircs", "magnet", "mms",
    "microsoft-edge", "ms-edge", "msedge", "ms-settings", "search-ms",
})

#: Подключ с командой открытия протокола.
_PROTOCOL_COMMAND_SUBKEY = r"\shell\open\command"


def _protocol_tail(key_path: str) -> Optional[str]:
    """``HKCU\Software\Classes\figma`` -> ``figma`` (иначе ``None``).

    Только сам ключ схемы: ``...\figma\shell\open\command`` содержит
    обратный слэш и не проходит проверку.
    """
    path = _strip_hive(key_path)
    for prefix in (r"software\classes", r"software\wow6432node\classes"):
        if path.startswith(prefix + "\\"):
            tail = path[len(prefix) + 1:]
            if tail and "\\" not in tail and "/" not in tail:
                if _PROTOCOL_SCHEME_RE.match(tail):
                    return tail
    return None


def is_protocol_key(key_path: str,
                    values: Optional[Mapping[str, object]] = None,
                    after: Optional[Mapping[str, Mapping[str, object]]] = None
                    ) -> bool:
    """Ключ регистрирует кастомный URL-протокол приложения.

    Протокол живёт в ``HKCU/HKLM\Software\Classes\<scheme>`` и созывает
    ``shell\open\command``. Самый сильный признак — значение
    ``URL Protocol``; без него срабатывает наличие дочернего
    ``shell\open\command`` (такие регистрации встречаются у Electron-
    приложений, например Figma).
    """
    tail = _protocol_tail(key_path)
    if not tail:
        return False
    if tail.casefold() in _WEB_SCHEMES:
        # Схема браузера/оболочки: это не протокол приложения.
        return False
    if values is not None and _PROTOCOL_MARKER_VALUE in {
            str(name).casefold() for name in values}:
        return True
    if after is not None:
        child = key_path + _PROTOCOL_COMMAND_SUBKEY
        if after.get(child):
            return True
    return False


def protocol_keys_of(diff: "RegistryDiff",
                     after: Optional[Mapping[str, Mapping[str, object]]] = None
                     ) -> List[str]:
    """Ключи URL-протоколов в diff — переносим их в портатив всегда.

    Без них браузер («Открыть Figma» после входа) открывает установленную
    программу, а не портатив. Протокол — часть работы приложения, а не
    мусор оболочки, поэтому его не связывают с ``--shell-integration``.
    Возвращаются не только ключи схемы, но и измененные потомки
    (``shell\\open\\command``, ``DefaultIcon``): именно в них живёт
    команда открытия.
    """
    roots: List[str] = []
    for key in diff.touched_keys:
        if is_volatile(key):
            continue
        values = after.get(key) if after is not None else None
        if is_protocol_key(key, values, after):
            roots.append(key)
    out = sorted(set(roots))
    for root in roots:
        prefix = root.casefold() + "\\"
        for key in diff.touched_keys:
            if key.casefold().startswith(prefix) and key not in out:
                out.append(key)
    return sorted(set(out))


#: Первая кавычка в команде открытия протокола (``"...exe" --open "%1"``).
_COMMAND_QUOTED_RE = re.compile(r'"([^"]+)"')

#: Начало пути с буквы диска: ``C:\...`` или ``C:/...``.
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]", re.IGNORECASE)


def _protocol_command_exe(command: str) -> Optional[str]:
    """Путь к exe в команде открытия протокола.

    Команда выглядит как ``"C:\\Users\\me\\Figma\\Figma.exe" --open "%1"`` —
    путь в кавычках, а за ним аргументы. Ищем первый кавычный фрагмент,
    заканчивающийся на ``.exe`` (аргументы в кавычках — `"%1"` — не пройдут
    эту проверку). Без кавычек допустимо только когда первый токен явно
    заканчивается на ``.exe`` (иначе у «C:\\Program Files\\...» разорвался бы
    путь на слове).
    """
    if not command:
        return None
    candidates = _COMMAND_QUOTED_RE.findall(command)
    for candidate in candidates:
        if candidate.lower().endswith(".exe") and (
                _DRIVE_PATH_RE.match(candidate)
                or "/" in candidate or "\\" in candidate):
            return candidate
    # Без кавычек — только первый токен: «C:\Program Files\...\Figma.exe»
    # разбивается на «C:\Program» + «Files\...\Figma.exe», и второй токен
    # — не exe, а обломок пути. Путь без пробелов (C:\Users\me\Figma\...)
    # целиком лежит в первом токене.
    parts = command.split()
    if parts and parts[0].lower().endswith(".exe"):
        candidate = parts[0].strip('"')
        if (_DRIVE_PATH_RE.match(candidate)
                or "/" in candidate or "\\" in candidate):
            return candidate
    return None


def _quoted_paths_in(value: str) -> List[str]:
    """Все пути с буквы диска внутри кавычных фрагментов значения.

    Иконка протокола имеет вид ``"C:\\...\\Figma.exe,0"``: путь берём до
    запятой. Без кавычек пути не читаем — там path с пробелами
    (``C:\\Program Files\\...``) токенизируется обрывами.
    """
    out: List[str] = []
    for frag in _COMMAND_QUOTED_RE.findall(value):
        path = frag.split(",")[0].strip()
        if _DRIVE_PATH_RE.match(path):
            out.append(path)
    return out


def retarget_protocol_paths(snapshot: Mapping[str, Mapping[str, object]],
                            protocol_keys: Iterable[str],
                            app_dir: str) -> Snapshot:
    """Переписывает пути URL-протоколов в портативную ``App``.

    Команда открытия из установщика указывает на установленный каталог
    этого ПК (``"C:\\Users\\...\\Figma\\app-126\\Figma.exe" --open "%1"``).
    Без замены браузер вернёт именно его. Меняем корень пути: имя exe
    сохраняется (портатив лежит в ``App`` с тем же именем), аргументы не
    трогаются. Корни собираются из всех значений дерева протокола —
    ``shell\\open\\command`` и ``DefaultIcon`` могут указывать разные
    каталоги (version-дир vs родительский).
    """
    result: Snapshot = {
        key: {name: _as_entry(entry) for name, entry in values.items()}
        for key, values in snapshot.items()
    }
    destination = os.path.normpath(app_dir)
    for key in protocol_keys:
        command_key = key + _PROTOCOL_COMMAND_SUBKEY
        values = result.get(command_key)
        if not values:
            continue
        entry = values.get("")
        if entry is None:
            continue
        typ, _raw = _as_entry(entry)
        if typ not in (REG_SZ, REG_EXPAND_SZ):
            continue
        command = _entry_value(entry)
        if not isinstance(command, str):
            continue
        exe = _protocol_command_exe(command)
        if not exe:
            continue
        roots = set()
        old_root = ntpath.dirname(exe.rstrip("\\/"))
        if old_root:
            roots.add(old_root)
        # Остальные значения дерева (DefaultIcon и т.п.) — по кавычным
        # путям.
        for k, vals in result.items():
            if k != key and not k.casefold().startswith(key.casefold() + "\\"):
                continue
            for entry2 in vals.values():
                value = _entry_value(entry2)
                if not isinstance(value, str):
                    continue
                for path in _quoted_paths_in(value):
                    root = ntpath.dirname(path.rstrip("\\/"))
                    if root:
                        roots.add(root)
        # Сначала длинные корни: короткий «...\\Figma» не должен
        # разрезать «...\\Figma\\app-126.10.11\\...» посередине.
        old_roots = sorted(roots, key=len, reverse=True)
        if not old_roots:
            continue
        # Путь портативной папки может содержать пробелы: в команде
        # открытия его нужно закавычить, иначе разобьётся на слове.
        target_exe = (destination + "\\" + ntpath.basename(exe)
                      if " " in destination else None)
        prefix = key.casefold() + "\\"
        for k, vals in result.items():
            if k != key and not k.casefold().startswith(prefix):
                continue
            for name, entry2 in list(vals.items()):
                typ2, _raw2 = _as_entry(entry2)
                if typ2 not in (REG_SZ, REG_EXPAND_SZ):
                    continue
                value = _entry_value(entry2)
                if not isinstance(value, str):
                    continue
                rewritten = value
                for old in old_roots:
                    rewritten = re.sub(
                        re.escape(old),
                        lambda _match: destination,
                        rewritten,
                        flags=re.IGNORECASE,
                    )
                if rewritten != value:
                    if (k == command_key and target_exe
                            and target_exe in rewritten
                            and f'"{target_exe}"' not in rewritten):
                        rewritten = rewritten.replace(
                            target_exe, f'"{target_exe}"', 1)
                    vals[name] = (typ2, repr(rewritten))
    return result

# --- снимок -------------------------------------------------------------------

def _walk(hive: int, subkey: str, prefix: str, out: Snapshot,
          max_depth: int = 7, depth: int = 0) -> None:
    """Рекурсивно обходит ветку и заполняет out[path] = {value: (type, repr)}."""
    if depth > max_depth:
        return
    full = f"{prefix}\\{subkey}" if subkey else prefix
    if depth and (is_volatile(full) or is_protected(full)):
        # Не снимаем системное состояние, лицензии, Shell/Taskbar и компоненты
        # Microsoft: устаревший снимок не должен иметь возможность их стереть.
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
        j = 0
        while True:
            try:
                subkeys.append(winreg.EnumKey(key, j))  # type: ignore
                j += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(key)  # type: ignore
    if is_protected(full, values):
        # Некоторые Microsoft-компоненты используют GUID-подключи в Uninstall;
        # проверяем DisplayName после чтения ключа и не обходим его потомков.
        return
    out[full] = values
    for sk in subkeys:
        _walk(hive, f"{subkey}\\{sk}" if subkey else sk, prefix, out,
              max_depth, depth + 1)


def snapshot(include_user: bool = True) -> Snapshot:
    """Делает снимок наблюдаемых веток. На не-Windows возвращает пусто.

    ``include_user=False`` исключает ``HKCU``. Это нужно при сборке под
    ДРУГИМ пользователем (в окне UAC введены чужие учётные данные): профиль
    тогда принадлежит администратору, и захват его настроек означал бы, что
    лончер применит в профиле пользователя чужой снимок оболочки. Именно так
    раньше «сбивалось» меню «Пуск» Windows 11. HKLM при этом снимается: он
    общий для всех пользователей.
    """
    if not IS_WINDOWS:
        return {}
    snap: Snapshot = {}
    hives = {
        "HKCU": winreg.HKEY_CURRENT_USER,  # type: ignore
        "HKLM": winreg.HKEY_LOCAL_MACHINE,  # type: ignore
    }
    for prefix, base in _ROOTS:
        if prefix == "HKCU" and not include_user:
            continue
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
        old = before.get(key)
        if (is_volatile(key) or is_protected(key, values)
                or is_protected(key, old)):
            continue
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
    """Заменяет абсолютные пути на маркеры корня (см. core/relpaths.py).

    Замена идёт с границами пути и во всех начертаниях (``\\``, ``/``,
    удвоенные обратные слэши внутри значений ``.reg``). Без границ путь
    ``D:\\Apps\\XD`` находился внутри ``D:\\Apps\\XData\\save.ini`` и портил
    чужой путь — файл настроек после переноса указывал в никуда.
    """
    result = text
    for needle, replacement in tokens:
        if not needle:
            continue
        result = relpaths.tokenize_text(result, needle, replacement)
    return result


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


def _normalize_app_token(text: str) -> str:
    return "".join(ch for ch in str(text or "").casefold() if ch.isalnum())


def retarget_install_paths(snapshot: Mapping[str, Mapping[str, object]],
                           keys: Iterable[str], app_dir: str,
                           extra_roots: Sequence[str] = (),
                           portable_dir: str = "",
                           app_names: Sequence[str] = ()) -> Snapshot:
    """Перенаправляет захваченные пути установки в портативную ``App`` и корень портатива.

    Некоторые установщики (в частности старые игры) не принимают переданную
    папку и сначала устанавливаются в ``Program Files``. Затем Portablizer
    переносит их файлы в ``App``, но значения вроде ``InstallFolder`` в
    захваченном реестре раньше продолжали указывать на уже удалённый исходный
    каталог. Основной exe часто обходится без этих значений, а комплектный
    Launcher/Configurator считает установку недействительной и молча
    закрывается.

    Меняются только общеупотребительные значения каталога установки в явно
    выбранных ключах приложения, переданные ``extra_roots`` (каталоги, из
    которых приложение было перенесено в ``App``), а также рабочие папки
    приложения в корне диска вида ``C:\\multitran`` -> ``<PortableDir>\\multitran``.
    """
    result: Snapshot = {
        key: {name: _as_entry(entry) for name, entry in values.items()}
        for key, values in snapshot.items()
    }
    destination = os.path.normpath(app_dir).replace("/", "\\")
    portable_root = (
        os.path.normpath(portable_dir)
        if portable_dir
        else os.path.dirname(destination)
    ).replace("/", "\\")
    install_names = {
        "installdir", "installdirectory", "installfolder", "installlocation",
    }
    explicit_old_roots = sorted(
        {str(r).strip().rstrip("\\/") for r in (extra_roots or ())
         if str(r).strip().rstrip("\\/")},
        key=len,
        reverse=True,
    )
    app_tokens = {
        _normalize_app_token(name)
        for name in (app_names or ())
        if len(_normalize_app_token(name)) >= 4
    }
    drive_folder_re = re.compile(
        r"(?<![A-Za-z0-9_\\/.:-])([A-Za-z]:[\\/])([^\\/:*?\"<>|\r\n;]+)"
        r"([\\/][^\"<>|?*\r\n;]*)?",
    )

    for key in keys:
        values = result.get(key)
        if not values:
            continue
        names = {name.casefold(): name for name in values}
        path_names = [names[name] for name in install_names if name in names]
        if "exe" in names and "exefile" in names:
            path_names.append(names["exe"])

        old_roots: List[str] = list(explicit_old_roots)
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
            if app_tokens and portable_root:
                def _replace_drive_app_folder(match: "re.Match[str]") -> str:
                    folder = match.group(2)
                    tail = match.group(3) or ""
                    full_matched = match.group(0)
                    # Не трогаем пути, которые уже ведут внутрь portable_root.
                    if os.path.normcase(full_matched).startswith(
                            os.path.normcase(portable_root)):
                        return full_matched
                    folder_token = _normalize_app_token(folder)
                    if folder_token not in app_tokens:
                        return full_matched
                    rel_tail = tail.lstrip("\\/")
                    # Если хвост указывает на файл, лежащий в App (например,
                    # network.exe или словарь .erd), направляем в App.
                    # Иначе (рабочая папка данных вида c:\multitran,
                    # c:\multitran\<PC>\history.txt) — в <PortableDir>\<folder>.
                    if rel_tail and os.path.exists(
                            os.path.join(destination, *re.split(r"[\\/]+", rel_tail))):
                        return destination + ("\\" + rel_tail.replace("/", "\\"))
                    if name.casefold() in install_names:
                        return destination + (tail.replace("/", "\\") if tail else "")
                    target_folder = os.path.join(portable_root, folder).replace("/", "\\")
                    return target_folder + (tail.replace("/", "\\") if tail else "")

                rewritten = drive_folder_re.sub(
                    _replace_drive_app_folder, rewritten)
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


def render_host_cleanup(diff: RegistryDiff,
                        after: Mapping[str, Mapping[str, object]],
                        *, app_name: str, portable_dir: str) -> str:
    """Создаёт откат только для точно опознанной записи приложения.

    Записи из общего diff больше не восстанавливаются: откат изменённых ключей
    небезопасен для лицензий, ассоциаций и системных настроек. Удаляется лишь
    новая запись Uninstall, для которой совпали имя приложения и путь.
    """
    entries = safe_uninstall_entries(
        diff, after, app_name=app_name, portable_dir=portable_dir)
    lines: List[str] = []
    for key, _display in entries:
        hive = _hive_name(key)
        if hive:
            lines.append(f"[-{hive}\\{key.split(chr(92), 1)[1]}]")
            lines.append("")
    return _render(lines)


_HIVE_BY_NAME = {
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKLM": "HKEY_LOCAL_MACHINE",
}


def delete_uninstall_keys(keys: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Удаляет записи Uninstall напрямую через winreg.

    Возвращает ``(удалённые, оставшиеся)``. Импорт ``cleanup_host.reg`` может
    не сработать (другое представление WOW64, политика импорта, антивирус), а
    прямой ``RegDeleteKey`` в нужном представлении работает всегда, когда есть
    права. Ключи принимаются в виде ``HKEY_CURRENT_USER\\Software\\...\\Uninstall\\Имя``.
    """
    if not IS_WINDOWS:
        return [], []
    try:
        import winreg  # type: ignore
    except ImportError:  # pragma: no cover - Windows без winreg не бывает
        return [], []
    removed: List[str] = []
    remaining: List[str] = []
    for key in keys:
        hive_name = _hive_name(key)
        if not hive_name or not is_uninstall_entry(key):
            continue
        hive = getattr(winreg, hive_name)
        # «HKEY_CURRENT_USER\Software\...\Uninstall\Имя» -> путь родителя и имя.
        _hive_text, _sep, subkey = key.partition("\\")
        parent_path, _sep, name = subkey.rpartition("\\")
        if not parent_path or not name:
            remaining.append(key)
            continue
        access = (winreg.KEY_WRITE | winreg.KEY_READ
                  | getattr(winreg, "DELETE", 0))
        deleted = False
        for view in (0, getattr(winreg, "KEY_WOW64_64KEY", 0),
                     getattr(winreg, "KEY_WOW64_32KEY", 0)):
            try:
                with winreg.OpenKey(hive, parent_path, 0, access | view) as parent:
                    winreg.DeleteKey(parent, name)
            except FileNotFoundError:
                continue
            except OSError:
                continue
            deleted = True
            break
        if deleted:
            removed.append(key)
        else:
            remaining.append(key)
    return removed, remaining


def existing_uninstall_keys(keys: Iterable[str]) -> List[str]:
    """Какие из записей Uninstall ещё существуют на этом ПК.

    Нужно после удаления, чтобы не отчитываться об успехе, которого нет:
    запись могла остаться из-за прав или потому, что установщик успел
    создать её в другом представлении (WOW64).
    """
    if not IS_WINDOWS:
        return []
    try:
        import winreg  # type: ignore
    except ImportError:  # pragma: no cover - Windows без winreg не бывает
        return []
    alive: List[str] = []
    for key in keys:
        if not is_uninstall_entry(key):
            continue
        hive_name = _hive_name(key)
        if not hive_name:
            continue
        hive = getattr(winreg, hive_name)
        path = key.split("\\", 1)[1]
        for view in (0, getattr(winreg, "KEY_WOW64_64KEY", 0),
                     getattr(winreg, "KEY_WOW64_32KEY", 0)):
            try:
                with winreg.OpenKey(hive, path, 0,
                                    winreg.KEY_READ | view):
                    alive.append(key)
                    break
            except OSError:
                continue
    return alive


def has_entries(reg_text: str) -> bool:
    """True, если в .reg есть хотя бы один блок ключа."""
    return any(line.startswith("[") for line in reg_text.splitlines())


def render_host_cleanup_cmd(reg_file_name: str = "cleanup_host.reg") -> str:
    """Опциональный UAC-хелпер для точечной записи из ``cleanup_host.reg``.

    Импорт запускается только если пользователь сам открыл этот скрипт.
    Создаваемый Portablizer файл содержит лишь одну подтверждённую запись
    приложения в Uninstall; системные настройки и прежние значения не
    восстанавливаются. Файл строго ASCII, как и остальные cmd-скрипты.
    """
    # ``if errorlevel N`` (не ``%ERRORLEVEL%``) читается во время исполнения,
    # поэтому корректно работает и внутри блоков; переходы по меткам избавляют
    # от классической ловушки cmd с ранним раскрытием %ERRORLEVEL% в скобках.
    name = reg_file_name.replace('"', "")
    return (
        "@echo off\r\n"
        "setlocal EnableExtensions\r\n"
        "rem Removes only the confirmed app uninstall entry from THIS computer.\r\n"
        "rem No activation, associations, services or other registry settings are touched.\r\n"
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
        "echo The confirmed app entry was removed from this PC.\r\n"
        "echo Entries that were already gone are simply skipped - that is fine.\r\n"
        "timeout /t 5 >nul 2>&1\r\n"
        "exit /b 0\r\n"
    )


def write_reg_file(path: str, text: str) -> None:
    """Пишет .reg в UTF-16 LE с BOM и CRLF — как ожидает ``reg import``."""
    with open(path, "w", encoding="utf-16", newline="\r\n") as fh:
        fh.write(text)


# --- вспомогательное для поиска установленной программы ------------------------

_EXPLICIT_LOCATION_VALUE_NAMES = (
    "InstallLocation", "DisplayIcon", "InstallDir", "InstallDirectory",
    "InstallFolder", "InstallPath", "AppPath", "RootDir", "TargetDir",
    "HomeDir", "ExePath", "Path", "Directory",
)

_LOCAL_PATH_VALUE_RE = re.compile(
    r"^[A-Za-z]:[\\/][^\"<>|?*\r\n;]{2,240}$"
)


def _clean_registry_location(value: str, strip_icon_index: bool = False) -> str:
    text = os.path.expandvars(str(value or "").strip())
    if strip_icon_index:
        text = re.sub(r",\s*-?\d+\s*$", "", text).strip()
    text = text.strip().strip('"')
    # Если строка выглядит как командная строка ("C:\\App\\app.exe" /arg),
    # оставляем только путь к exe.
    exe_match = re.match(
        r"^([A-Za-z]:[\\/][^\"<>|?*\r\n]+?\.(?:exe|dll|erd|dat|db|mt))\b",
        text,
        re.IGNORECASE,
    )
    if exe_match:
        return exe_match.group(1).strip()
    return text


_SHARED_SOFTWARE_VENDORS = frozenset({
    "microsoft", "classes", "policies", "registeredapplications",
    "clients", "wow6432node", "khronos", "odbc", "mozilla", "google",
})


def matching_existing_app_keys(
    after: Mapping[str, Mapping[str, object]],
    app_names: Sequence[str] = (),
    source_roots: Sequence[str] = (),
) -> List[str]:
    """Находит ветки приложения в ``after``, даже если они уже были в ``before``.

    Если предыдущий запуск установщика (или прошлая попытка сборки) уже создал
    ключи в реестре хоста, повторный запуск ``setup.exe`` записывает те же
    значения поверх, и обычный ``compute_diff(before, after)`` видит нулевую
    разницу. Эта функция находит ключи ``CATEGORY_APP``, принадлежащие
    приложению по имени ветки или по путям к папке дистрибутива/приложения.
    """
    app_tokens = {
        _normalize_app_token(name)
        for name in (app_names or ())
        if len(_normalize_app_token(name)) >= 4
    }
    norm_roots = [
        str(r).strip().rstrip("\\/").replace("/", "\\").casefold()
        for r in (source_roots or ())
        if len(str(r).strip().rstrip("\\/")) >= 4
    ]
    if not app_tokens and not norm_roots:
        return []

    matched_prefixes: Set[str] = set()
    direct_keys: Set[str] = set()

    for key, values in after.items():
        if is_volatile(key) or is_protected(key, values):
            continue
        if categorize(key) != CATEGORY_APP:
            continue
        parts = [p for p in key.replace("/", "\\").split("\\") if p]
        # Ищем сегмент сразу после Software / WOW6432Node.
        vendor_idx = -1
        for idx, part in enumerate(parts):
            low = part.casefold()
            if low in ("software", "wow6432node"):
                vendor_idx = idx + 1
        if 0 < vendor_idx < len(parts):
            for seg in parts[vendor_idx:]:
                if _normalize_app_token(seg) in app_tokens:
                    direct_keys.add(key)
                    vendor_low = parts[vendor_idx].casefold()
                    if vendor_low not in _SHARED_SOFTWARE_VENDORS:
                        matched_prefixes.add(
                            "\\".join(parts[: vendor_idx + 1]).casefold()
                        )
                    break

        if key in direct_keys:
            continue

        for entry in values.values():
            val = _entry_value(entry)
            if not isinstance(val, str) or not val.strip():
                continue
            val_low = val.replace("/", "\\").casefold()
            hit = any(root in val_low for root in norm_roots)
            if not hit and app_tokens:
                m = re.match(
                    r"^[a-z]:\\([^\\/:*?\"<>|\r\n;]+)(?:\\|$)",
                    val_low.strip().strip('"'),
                )
                if m and _normalize_app_token(m.group(1)) in app_tokens:
                    hit = True
            if hit:
                direct_keys.add(key)
                if 0 < vendor_idx < len(parts):
                    vendor_low = parts[vendor_idx].casefold()
                    if vendor_low not in _SHARED_SOFTWARE_VENDORS:
                        matched_prefixes.add(
                            "\\".join(parts[: vendor_idx + 1]).casefold()
                        )
                break

    if matched_prefixes:
        for key, values in after.items():
            if is_volatile(key) or is_protected(key, values):
                continue
            if categorize(key) != CATEGORY_APP:
                continue
            key_low = key.replace("/", "\\").casefold()
            if any(
                key_low == pref or key_low.startswith(pref + "\\")
                for pref in matched_prefixes
            ):
                direct_keys.add(key)

    return sorted(direct_keys)


def changed_install_locations(before: Mapping[str, Mapping[str, object]],
                              after: Mapping[str, Mapping[str, object]],
                              app_names: Sequence[str] = (),
                              source_roots: Sequence[str] = ()) -> List[str]:
    """Извлекает пути установки из новых/изменённых записей реестра установщика."""
    locations: List[str] = []
    seen: Set[str] = set()
    forced_app_keys = set(
        matching_existing_app_keys(
            after, app_names=app_names, source_roots=source_roots)
    )

    def add_location(candidate: str) -> None:
        if not candidate:
            return
        low = candidate.replace("/", "\\").casefold()
        if any(sys_part in low for sys_part in (
                "\\windows\\", "\\system32", "\\syswow64", "\\temp\\")):
            return
        normalized = os.path.normcase(os.path.normpath(candidate))
        if normalized not in seen:
            seen.add(normalized)
            locations.append(candidate)

    for key, values in after.items():
        if is_volatile(key) or is_protected(key, values):
            continue
        is_forced = key in forced_app_keys
        if not is_forced and key in before and (
            is_protected(key, before[key])
            or dict(values) == dict(before[key])
        ):
            continue
        before_values = {} if is_forced else before.get(key, {})
        for value_name in _EXPLICIT_LOCATION_VALUE_NAMES:
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
            cleaned = _clean_registry_location(
                value, strip_icon_index=(value_name.casefold() == "displayicon"))
            if value_name.casefold() in ("path", "directory") and ";" in cleaned:
                continue
            add_location(cleaned)

        # Самописные установщики (например, Multitran setup.exe) пишут пути
        # к программе и словарям в собственные ключи HKCU/HKLM\Software\<App>
        # под произвольными именами параметров.
        if categorize(key) == CATEGORY_APP:
            for name, entry in values.items():
                if name in before_values and before_values[name] == entry:
                    continue
                value = _entry_value(entry)
                if not isinstance(value, str) or not value.strip():
                    continue
                cleaned = _clean_registry_location(value, strip_icon_index=True)
                if _LOCAL_PATH_VALUE_RE.match(cleaned):
                    add_location(cleaned)
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
        if is_protected(key, values):
            continue
        display = ""
        for name, entry in values.items():
            if name.casefold() == "displayname":
                value = _entry_value(entry)
                if isinstance(value, str):
                    display = value
                break
        entries.append((key, display or key.rsplit("\\", 1)[-1]))
    return entries


def _normalised_product_name(value: str) -> str:
    """Сопоставляет имена без пробелов/версии пунктуации, но без fuzzy-match."""
    return "".join(ch for ch in str(value).casefold() if ch.isalnum())


def _registry_path_is_inside(value: str, root: str) -> bool:
    """Windows-путь из реестра расположен внутри указанной папки портатива."""
    candidate = str(value).strip().strip('"')
    # DisplayIcon часто хранится как ``"C:\\App\\app.exe",0``.
    candidate = re.sub(r",\s*-?\d+\s*$", "", candidate).strip().strip('"')
    if not candidate or not root:
        return False
    candidate = os.path.expandvars(candidate).replace("/", "\\")
    root = os.path.expandvars(str(root)).replace("/", "\\")
    candidate = ntpath.normcase(ntpath.normpath(candidate)).rstrip("\\")
    root = ntpath.normcase(ntpath.normpath(root)).rstrip("\\")
    return candidate == root or candidate.startswith(root + "\\")


#: Значения записи Uninstall, в которых установщики хранят путь установки.
_UNINSTALL_PATH_VALUE_NAMES = frozenset({
    "installdir", "installdirectory", "installfolder", "installlocation",
    "installpath", "displayicon", "uninstallstring", "quietuninstallstring",
    "installsource", "inno setup: app path", "apppath", "path", "modifypath",
})


def _record_paths(values: "Mapping[str, object]") -> List[str]:
    """Пути из всех «путевых» значений записи Uninstall (строки, не repr)."""
    paths: List[str] = []
    for value_name, entry in values.items():
        if str(value_name).casefold() not in _UNINSTALL_PATH_VALUE_NAMES:
            continue
        value = _entry_value(entry)
        if isinstance(value, str) and value.strip():
            paths.append(value)
    return paths


def _path_looks_alive(path: str) -> bool:
    """Существует ли файл/папка, на которые ссылается значение записи.

    Нужно, чтобы отличить настоящую установку той же программы от следа
    установки, сделанной внутри портатива: в первом случае файлы на месте.
    """
    candidate = str(path or "").strip().strip('"')
    candidate = re.sub(r",\s*-?\d+\s*$", "", candidate).strip().strip('"')
    if not candidate:
        return False
    expanded = os.path.expandvars(candidate)
    for item in (candidate, expanded):
        try:
            if os.path.exists(item):
                return True
        except (OSError, ValueError):
            continue
    return False


def _names_look_like_same_product(left: str, right: str) -> bool:
    """Имена продуктов совпадают с точностью до версии и разделителей."""
    first = _normalised_product_name(left)
    second = _normalised_product_name(right)
    if not first or not second:
        return False
    return first == second or first.startswith(second) or second.startswith(first)


def safe_uninstall_entries(
        diff: RegistryDiff,
        after: Mapping[str, Mapping[str, object]],
        *, app_name: str, portable_dir: str,
) -> List[Tuple[str, str]]:
    """Возвращает только новые uninstall-записи точно этого портатива.

    Это единственная автоматическая правка реестра хоста, которую может
    выполнить Portablizer. Удаление разрешено, только если запись новая,
    DisplayName совпадает с именем выбранного приложения, а InstallLocation
    или DisplayIcon указывает внутрь созданной папки. Никакие изменённые
    настройки, ассоциации, ключи лицензирования и сторонние prereq-записи не
    откатываются.
    """
    expected = _normalised_product_name(app_name)
    if not expected or not portable_dir:
        return []
    safe: List[Tuple[str, str]] = []
    for key in diff.new_keys:
        if not is_uninstall_entry(key):
            continue
        values = after.get(key, {})
        if is_protected(key, values):
            continue
        display_name = ""
        for value_name, entry in values.items():
            if str(value_name).casefold() != "displayname":
                continue
            value = _entry_value(entry)
            if isinstance(value, str):
                display_name = value.strip()
            break
        key_name = key.rsplit("\\", 1)[-1]
        # Имя — обязательное условие: чужую программу не трогаем никогда.
        if not (_names_look_like_same_product(display_name, app_name)
                or _names_look_like_same_product(key_name, app_name)):
            continue
        # Не только InstallLocation: Inno Setup (Cursor, VS Code и прочие
        # установщики на его основе) пишет каталог в «Inno Setup: App Path», а
        # путь к файлу — в DisplayIcon и UninstallString. Без них запись
        # «Cursor» оставалась в списке установленных, хотя указывала внутрь
        # портатива.
        paths = _record_paths(values)
        inside = any(_registry_path_is_inside(path, portable_dir)
                     for path in paths)
        if not inside:
            # Ключ появился именно за эту установку (сравнение снимков реестра
            # до и после), поэтому он наш, даже если установщик записал в него
            # путь настоящего профиля (``%LOCALAPPDATA%\\Programs\\cursor`` —
            # так делает Cursor, устанавливаясь в App портатива). Настоящую
            # установку той же программы оставляем: её файлы существуют.
            alive_outside = any(
                _path_looks_alive(path)
                and not _registry_path_is_inside(path, portable_dir)
                for path in paths
            )
            if alive_outside:
                continue
        safe.append((key, display_name or key_name))
    return safe


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
    "lang-code",
    "lang_code",
    "langcode",
    "languagecode",
    "defaultlanguage",
    "gamelanguage",
    "selectedlanguage",
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
    "galaxy.ini",
    "comm.ini",
    "force_language.txt",
})

#: JSON GOG Galaxy: ``goggame-1446200766.info``. Поле ``language`` — то, что
#: читает игра без клиента Galaxy; без правки остаётся English.
_GOG_INFO_NAME_RE = re.compile(r"^goggame-.*\.(info|json)$", re.IGNORECASE)
_GOG_JSON_LANGUAGE_RE = re.compile(
    r'("language"\s*:\s*")([^"]*)(")',
    re.IGNORECASE,
)

_GOG_GAMES_MARKERS = (
    r"software\gog.com\games",
    r"software\wow6432node\gog.com\games",
)


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


def _is_gog_games_key(key_path: str) -> bool:
    """``HKLM\\Software\\[WOW6432Node\\]GOG.com\\Games\\{id}`` (не корень Games)."""
    path = _strip_hive(key_path)
    for marker in _GOG_GAMES_MARKERS:
        if path.startswith(marker + "\\"):
            rest = path[len(marker) + 1:].strip("\\")
            return bool(rest)
    return False


def _gog_game_ids_from_app(app_dir: str) -> List[str]:
    """Идентификаторы GOG-игр из имён ``goggame-{id}.info`` в ``App``."""
    if not app_dir or not os.path.isdir(app_dir):
        return []
    ids: List[str] = []
    seen = set()
    skip_dirs = {"portabledata", "redist", "_redist_cache", "updates"}
    for root, dirs, files in os.walk(app_dir):
        dirs[:] = [d for d in dirs if d.casefold() not in skip_dirs]
        for fname in files:
            if not _is_gog_info_file(fname):
                continue
            match = re.match(r"goggame-(\d+)\.", fname, re.IGNORECASE)
            if not match:
                continue
            game_id = match.group(1)
            if game_id not in seen:
                seen.add(game_id)
                ids.append(game_id)
    return ids


def _set_gog_language_values(
    values: KeyValues, lang_code: str,
) -> bool:
    """Пишет ``language`` / ``lang-code`` в значения ключа GOG.com\\Games."""
    from .languages import convert_language_string, find_registry_profile

    profile = find_registry_profile(lang_code)
    if profile is None:
        return False
    changed = False
    existing = {n.casefold(): n for n in values}

    def _put(want_names: Sequence[str], new_val: str) -> None:
        nonlocal changed
        for candidate in want_names:
            actual = existing.get(candidate.casefold())
            if actual is None:
                continue
            typ, _raw = _as_entry(values[actual])
            if typ not in (REG_SZ, REG_EXPAND_SZ):
                continue
            old = _entry_value(values[actual])
            if not isinstance(old, str):
                continue
            converted = convert_language_string(old, lang_code)
            if converted is None:
                converted = new_val
            if converted != old:
                values[actual] = _encode_value(typ, converted)
                changed = True
            return
        # Значения не было — GOG Galaxy как раз его и создаёт.
        name = want_names[0]
        values[name] = _encode_value(REG_SZ, new_val)
        existing[name.casefold()] = name
        changed = True

    _put(("language", "Language"), profile.english_name)
    _put(("lang-code", "lang_code", "Lang-Code"), profile.locale_hyphen)
    return changed


def _ensure_gog_registry_language(
    snapshot: Snapshot, app_dir: str, lang_code: str,
) -> List[str]:
    """Прописывает язык в ``GOG.com\\Games\\{id}`` и создаёт ключ, если его нет.

    Без Galaxy офлайн-установщик GOG оставляет ``language=English`` (или не
    пишет его вовсе) — Sleeping Dogs и другие игры тогда стартуют по-английски
    даже при выбранном русском в Portablizer.
    """
    from .languages import find_registry_profile

    profile = find_registry_profile(lang_code)
    if profile is None:
        return []

    touched: List[str] = []
    found_ids: Set[str] = set()
    for key in list(snapshot.keys()):
        if not _is_gog_games_key(key):
            continue
        leaf = key.rsplit("\\", 1)[-1]
        found_ids.add(leaf)
        values = snapshot.setdefault(key, {})
        if _set_gog_language_values(values, lang_code):
            touched.append(key)

    for game_id in _gog_game_ids_from_app(app_dir):
        if any(game_id.casefold() == existing.casefold()
               for existing in found_ids):
            continue
        key = rf"HKLM\Software\WOW6432Node\GOG.com\Games\{game_id}"
        values = snapshot.setdefault(key, {})
        values.setdefault("gameID", _encode_value(REG_SZ, game_id))
        _set_gog_language_values(values, lang_code)
        touched.append(key)
    return touched


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

    gog_keys = _ensure_gog_registry_language(after, app_dir, lang_code)
    for k in gog_keys:
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


def _is_gog_info_file(fname: str) -> bool:
    return bool(_GOG_INFO_NAME_RE.match(fname or ""))


def _is_language_settings_file(fname: str) -> bool:
    low = (fname or "").casefold()
    return low in _LANGUAGE_INI_FILENAMES or _is_gog_info_file(fname)


def _rewrite_gog_info_language(text: str, lang_code: str) -> Optional[str]:
    """Меняет поле ``language`` в JSON ``goggame-*.info``, сохраняя формат."""
    from .languages import convert_language_string, find_registry_profile

    profile = find_registry_profile(lang_code)
    if profile is None:
        return None

    def _repl(match: re.Match) -> str:
        old = match.group(2)
        converted = convert_language_string(old, lang_code)
        if converted is None:
            # GOG после обновлений требует имя с заглавной: «Russian».
            converted = profile.english_name
        if converted == old:
            return match.group(0)
        return f"{match.group(1)}{converted}{match.group(3)}"

    new_text, count = _GOG_JSON_LANGUAGE_RE.subn(_repl, text, count=1)
    if count:
        return new_text if new_text != text else None

    # Поля нет — вставляем сразу после открывающей скобки, как делает Galaxy.
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return None
    brace = text.find("{")
    insert = f'\n  "language": "{profile.english_name}",'
    return text[:brace + 1] + insert + text[brace + 1:]


def apply_language_to_ini_files(app_dir: str, lang_code: str) -> List[str]:
    """Обновляет параметр языка в INI/JSON эмуляторов, загрузчиков и GOG."""
    from .languages import convert_language_string, find_registry_profile

    profile = find_registry_profile(lang_code)
    if profile is None or not app_dir or not os.path.isdir(app_dir):
        return []

    updated_files: List[str] = []
    skip_dirs = {"portabledata", "redist", "_redist_cache", "updates"}
    ini_key_re = re.compile(
        r"^(\s*(?:Language|InstallLanguage|TextLanguage|SubtitleLanguage|"
        r"SubtitlesLanguage|UILanguage|InterfaceLanguage|Locale|Lang|"
        r"Lang-Code|Lang_Code|LangCode)\s*=\s*)"
        r"([^\r\n;#]*?)(\s*(?:[;#].*)?)$",
        re.IGNORECASE,
    )

    for root, dirs, files in os.walk(app_dir):
        dirs[:] = sorted(d for d in dirs if d.casefold() not in skip_dirs)
        for fname in sorted(files):
            if not _is_language_settings_file(fname):
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

            if _is_gog_info_file(fname):
                rewritten = _rewrite_gog_info_language(text, lang_code)
                if rewritten is not None and rewritten != text:
                    try:
                        with open(full_path, "w", encoding=enc, newline="\n") as fh:
                            fh.write(rewritten)
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

