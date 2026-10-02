"""Сквозные портативные сохранения: один набор сейвов для всех запусков.

Проблема, ради которой появился модуль
--------------------------------------
Портатив можно запустить по-разному, и до этой версии каждый способ видел
**свои** сохранения:

* ``App\\FalloutNV.exe`` или ``App\\launcher.exe`` двойным кликом — программа
  получает НАСТОЯЩИЙ профиль Windows и пишет сейвы в
  ``%USERPROFILE%\\Documents\\My Games\\FalloutNV\\Saves``;
* ``App\\LaunchPortable.exe``, ``Launch.bat``, ``Launch_Launcher.exe`` —
  лончер перенаправляет профиль внутрь портатива, и те же сейвы уходят в
  ``PortableData\\User\\Documents\\My Games\\FalloutNV\\Saves``.

Получались два независимых хранилища: сохранения, сделанные одним способом,
не видны другому. Это не ошибка перенаправления — это его прямое следствие:
изолированный профиль на то и изолированный.

Что делает этот модуль
----------------------
Он сводит оба хранилища в одно, **внутри портатива**, двумя разными
средствами — в зависимости от того, что умеет сама программа.

``inplace`` — «игра сама пишет в свою папку»
    Движок Gamebryo (Oblivion, Fallout 3, Fallout: New Vegas) умеет хранить
    INI-файлы и сохранения не в ``My Games``, а рядом с exe: за это отвечает
    ``bUseMyGamesDirectory=0`` в ``<Игра>_default.ini`` плюс
    ``SLocalSavePath=Saves\\``. Portablizer выставляет эти ключи в папке
    ``App``, и дальше **любой** способ запуска — хоть прямой ``FalloutNV.exe``,
    хоть ``LaunchPortable.exe``, хоть комплектный лаунчер — читает и пишет
    один и тот же ``App\\Saves``. Профиль Windows вообще перестаёт
    участвовать, поэтому сейвы остаются внутри портатива и переносятся
    вместе с папкой.

``mirror`` — «сводим две папки по времени изменения»
    Для программ, которым некуда сказать «пиши рядом с собой», лончер перед
    стартом забирает в портатив всё, что новее, из профиля этого ПК, а после
    выхода возвращает обновлённые файлы обратно. Канонической копией всегда
    остаётся та, что внутри портатива: она переносится на другой компьютер,
    а на чужой машине ничего лишнего не появляется (папка в чужом профиле
    создаётся, только если там действительно есть что отдать).

Ни один режим не удаляет файлы: при расхождении побеждает более свежая
версия файла, а всё остальное просто дополняется. Потерять сейв
синхронизацией невозможно.

Модуль используется и при сборке портатива, и при обслуживании уже готовой
папки (``maintenance.refresh``), а его схема настроек уезжает в
``launcher_config.json`` — по ней работает ``LaunchPortable.exe``.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .logutil import Logger

#: Папка портатива с пользовательскими данными (как в лончере).
DEFAULT_DATA_DIR = "PortableData"

#: Каталоги профиля, в которых игры держат сохранения. Относительно профиля
#: пользователя; ``Documents`` на реальном ПК может быть перенесён (OneDrive),
#: поэтому лончер определяет его через Known Folders, а не склейкой строк.
WATCHED_ROOTS: Tuple[str, ...] = ("Documents/My Games", "Saved Games")

#: Файлы, которые синхронизировать бессмысленно.
JUNK_FILES = frozenset({"desktop.ini", "thumbs.db", ".ds_store"})

#: Предохранитель от катастрофы: если «папка сохранений» вдруг оказалась
#: игровым каталогом на 100 ГБ, синхронизация должна остановиться, а не
#: копировать его часами.
MAX_SYNC_FILES = 20000
MAX_SYNC_BYTES = 20 * 1024 ** 3

#: Допуск по времени: FAT32 хранит время с точностью до двух секунд, и без
#: допуска один и тот же файл вечно считался бы «более новым».
MTIME_TOLERANCE = 2.0


# --- профили известных движков ------------------------------------------------

@dataclass(frozen=True)
class GameProfile:
    """Движок/игра, умеющая хранить сейвы рядом с собой."""

    id: str
    title: str
    #: Имена exe, по которым игра опознаётся однозначно.
    executables: Tuple[str, ...]
    #: Файл-шаблон настроек в папке игры (``Fallout_default.ini``).
    default_ini: str
    #: Пользовательские INI, которые игра держит рядом с шаблоном.
    user_inis: Tuple[str, ...]
    #: Имена папок в ``Documents\\My Games``, которыми игра пользуется.
    my_games: Tuple[str, ...]
    #: Подпапка сохранений внутри каталога данных.
    saves_dir: str = "Saves"
    #: Ключи, которые нужно выставить, чтобы данные остались в папке игры.
    ini_settings: Tuple[Tuple[str, str, str], ...] = (
        ("General", "bUseMyGamesDirectory", "0"),
        ("General", "SLocalSavePath", "Saves\\"),
    )


GAME_PROFILES: Tuple[GameProfile, ...] = (
    GameProfile(
        id="gamebryo-falloutnv",
        title="Fallout: New Vegas",
        executables=("falloutnv.exe", "falloutnvlauncher.exe",
                     "nvse_loader.exe", "fnv4gb.exe"),
        default_ini="Fallout_default.ini",
        user_inis=("Fallout.ini", "FalloutPrefs.ini", "FalloutCustom.ini"),
        my_games=("FalloutNV",),
    ),
    GameProfile(
        id="gamebryo-fallout3",
        title="Fallout 3",
        executables=("fallout3.exe", "fallout3launcher.exe",
                     "fose_loader.exe", "fallout3ng.exe"),
        default_ini="Fallout_default.ini",
        user_inis=("Fallout.ini", "FalloutPrefs.ini", "FalloutCustom.ini"),
        my_games=("Fallout3",),
    ),
    GameProfile(
        id="gamebryo-oblivion",
        title="The Elder Scrolls IV: Oblivion",
        executables=("oblivion.exe", "oblivionlauncher.exe",
                     "obse_loader.exe"),
        default_ini="Oblivion_default.ini",
        user_inis=("Oblivion.ini",),
        my_games=("Oblivion",),
    ),
)

#: Движок Gamebryo опознаётся и без списка игр: шаблон ``*_default.ini`` с
#: ключом SLocalSavePath бывает только у него.
GENERIC_GAMEBRYO_ID = "gamebryo"


@dataclass
class DetectedGame:
    """Найденная в портативе игра и её каталог."""

    profile: GameProfile
    #: Абсолютный путь к папке, где лежит ``<Игра>_default.ini``.
    game_dir: str
    default_ini: str


# --- описание сквозных сохранений ---------------------------------------------

@dataclass
class SaveEntry:
    """Канонический каталог данных и его двойники вне портатива.

    ``store``     — где данные лежат на самом деле (относительно корня
                    портатива): ``App`` для режима ``inplace`` либо папка
                    внутри ``PortableData`` для ``mirror``.
    ``host``      — такой же каталог в НАСТОЯЩЕМ профиле этого ПК
                    (относительно профиля пользователя).
    ``portable``  — он же в перенаправленном профиле портатива.
    ``patterns``  — что именно участвует в обмене (пусто = всё).
    ``direction`` — ``both``: двусторонняя синхронизация; ``in``: только
                    забираем в портатив (данные и так пишутся в ``store``).
    """

    name: str
    store: str
    host: str = ""
    portable: str = ""
    patterns: List[str] = field(default_factory=list)
    direction: str = "both"

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "store": _posix(self.store),
            "host": _posix(self.host),
            "portable": _posix(self.portable),
            "patterns": list(self.patterns),
            "direction": self.direction,
        }

    @staticmethod
    def from_dict(data: Dict[str, object]) -> "SaveEntry":
        patterns = data.get("patterns")
        return SaveEntry(
            name=str(data.get("name", "")),
            store=_posix(str(data.get("store", ""))),
            host=_posix(str(data.get("host", ""))),
            portable=_posix(str(data.get("portable", ""))),
            patterns=[str(p) for p in patterns] if isinstance(patterns, list)
            else [],
            direction=("in" if str(data.get("direction", "both")) == "in"
                       else "both"),
        )


@dataclass
class SaveSetup:
    """Полное описание сквозных сохранений портатива."""

    enabled: bool = False
    #: ``inplace`` | ``mirror`` | ``off``
    mode: str = "off"
    profile: str = ""
    title: str = ""
    #: Куда сходятся данные (относительно корня портатива).
    store: str = ""
    entries: List[SaveEntry] = field(default_factory=list)
    #: Имена, по которым лончер узнаёт папки этой программы в профиле.
    tokens: List[str] = field(default_factory=list)
    #: Корни профиля, которые лончер осматривает в поисках новых папок.
    roots: List[str] = field(default_factory=lambda: list(WATCHED_ROOTS))
    discovery: bool = True
    #: Человеческие пояснения (идут в журнал и README портатива).
    notes: List[str] = field(default_factory=list)
    #: Файлы, изменённые ради режима ``inplace``.
    patched: List[str] = field(default_factory=list)
    #: Сколько файлов перенесено в общее хранилище при сборке.
    migrated: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "profile": self.profile,
            "title": self.title,
            "store": _posix(self.store),
            "entries": [e.to_dict() for e in self.entries],
            "discovery": {
                "enabled": self.discovery,
                "tokens": list(self.tokens),
                "roots": [_posix(r) for r in self.roots],
            },
        }

    @staticmethod
    def from_dict(data: Dict[str, object]) -> "SaveSetup":
        if not isinstance(data, dict):
            return SaveSetup()
        raw_entries = data.get("entries")
        entries = [SaveEntry.from_dict(item) for item in raw_entries
                   if isinstance(item, dict)] \
            if isinstance(raw_entries, list) else []
        discovery = data.get("discovery")
        discovery = discovery if isinstance(discovery, dict) else {}
        tokens = discovery.get("tokens")
        roots = discovery.get("roots")
        return SaveSetup(
            enabled=bool(data.get("enabled", False)),
            mode=str(data.get("mode", "off")),
            profile=str(data.get("profile", "")),
            title=str(data.get("title", "")),
            store=_posix(str(data.get("store", ""))),
            entries=entries,
            tokens=[str(t) for t in tokens] if isinstance(tokens, list) else [],
            roots=[str(r) for r in roots] if isinstance(roots, list)
            else list(WATCHED_ROOTS),
            discovery=bool(discovery.get("enabled", True)),
        )


# --- вспомогательное ----------------------------------------------------------

def _posix(path: str) -> str:
    return str(path).replace("\\", "/").strip("/")


def normalize_name(value: str) -> str:
    """«Fallout New Vegas» и «FalloutNV» должны сравниваться одинаково."""
    return re.sub(r"[^a-z0-9]+", "", str(value).lower())


#: Имена, которые не опознают ничего: по ним можно утащить в портатив чужую
#: папку сохранений (``Documents\\My Games\\Launcher`` соседней игры).
GENERIC_TOKENS = frozenset({
    "launcher", "game", "games", "mygames", "setup", "install", "installer",
    "config", "configurator", "configuration", "settings", "options",
    "start", "play", "autorun", "data", "main", "client", "server",
    "application", "program", "software", "tool", "tools", "editor",
    "update", "updater", "patch", "patcher", "loader", "steam", "portable",
    "default", "user", "users", "profile", "profiles", "common", "shared",
    "test", "demo", "temp", "cache", "save", "saves", "savegames",
})


def name_tokens(app_name: str, executables: Sequence[str] = (),
                extra: Sequence[str] = ()) -> List[str]:
    """Имена, по которым папка в профиле опознаётся как «наша».

    Берём имя приложения, имена его exe (без расширения и без суффиксов
    ``launcher``/``setup``) и всё, что передали дополнительно. Слишком
    короткие огрызки и ничего не значащие слова отбрасываются: по токену
    ``nv`` или ``launcher`` можно утащить в портатив чужую папку.
    """
    raw: List[str] = [app_name]
    for item in executables:
        stem = os.path.splitext(os.path.basename(str(item)))[0]
        raw.append(stem)
        for suffix in ("launcher", "_loader", "loader", "config",
                       "configurator", "settings", "setup", "4gb"):
            if stem.lower().endswith(suffix) and len(stem) > len(suffix) + 2:
                raw.append(stem[: -len(suffix)])
    raw.extend(extra)

    tokens: List[str] = []
    for item in raw:
        token = normalize_name(item)
        if len(token) >= 4 and token not in GENERIC_TOKENS \
                and token not in tokens:
            tokens.append(token)
    return tokens


def matches_tokens(folder_name: str, tokens: Sequence[str]) -> bool:
    """Папка профиля принадлежит этой программе?

    Сравнение нечёткое, но не безрассудное: совпадение засчитывается, когда
    одно имя целиком содержится в другом (``FalloutNV`` ⊂ ``falloutnvgoty``),
    и только для токенов длиной от четырёх символов.
    """
    name = normalize_name(folder_name)
    if not name:
        return False
    for token in tokens:
        if len(token) < 4:
            continue
        if name == token or token in name or name in token:
            return True
    return False


def compile_patterns(patterns: Sequence[str]) -> List[re.Pattern]:
    """Превращает ``Saves``/``*.ini`` в регулярки по относительному пути.

    ``*`` и ``?`` не перепрыгивают через разделитель каталогов, ``**``
    означает «любая глубина». Шаблон без подстановок считается поддеревом:
    ``Saves`` накрывает ``Saves/Quicksave.fos``.
    """
    compiled: List[re.Pattern] = []
    for pattern in patterns:
        text = _posix(pattern)
        if not text:
            continue
        if not any(ch in text for ch in "*?["):
            compiled.append(re.compile(
                r"(?i)^" + re.escape(text) + r"(/.*)?$"))
            continue
        out = ["(?i)^"]
        index = 0
        while index < len(text):
            char = text[index]
            if char == "*":
                if text.startswith("**", index):
                    out.append(".*")
                    index += 2
                    continue
                out.append("[^/]*")
            elif char == "?":
                out.append("[^/]")
            else:
                out.append(re.escape(char))
            index += 1
        out.append("$")
        compiled.append(re.compile("".join(out)))
    return compiled


def path_allowed(rel_path: str, compiled: Sequence[re.Pattern]) -> bool:
    if not compiled:
        return True
    text = _posix(rel_path)
    return any(rule.match(text) for rule in compiled)


def _clear_readonly(path: str) -> bool:
    """Fallout.ini часто помечен «только для чтения» — снимаем флаг.

    Возвращает True, если флаг действительно был снят: вызывающий код
    сообщает об этом пользователю, потому что «только для чтения» в
    настроечном файле — причина бесконечного цикла лаунчеров Bethesda
    (закрылся — открылся — закрылся…).
    """
    try:
        mode = os.stat(path).st_mode
        if not mode & stat.S_IWRITE:
            os.chmod(path, mode | stat.S_IWRITE)
            return True
    except OSError:
        pass
    return False


def create_missing_user_inis(store_dir: str, profile: GameProfile) -> List[str]:
    """Создаёт рядом с exe пользовательские INI, которых там ещё нет.

    У игр движка Gamebryo (Fallout 3/New Vegas, Oblivion) шаблон
    ``<Игра>_default.ini`` — только источник значений по умолчанию: движок
    создаёт из него пользовательские ``<Игра>.ini`` и ``<Игра>Prefs.ini`` и
    дальше читает уже их. Пока этих файлов нет рядом с exe, сквозного
    конфигурационного файла не существует: игра кладёт свой INI в профиль
    (в портативе — в перенаправленные ``PortableData\\User\\Documents\\My
    Games\\...``), и настройки перестают быть общими для всех способов
    запуска. Пользователь видит пустую папку ``App`` и начинает копировать
    INI руками — а копия приносит флаг «только для чтения», и лаунчер игры
    уходит в бесконечный цикл.

    Поэтому отсутствующие пользовательские INI создаются из шаблона сразу
    при сборке — ровно то, что игра сделала бы при первом запуске, но рядом
    с exe и с уже включённым хранением данных внутри портатива.

    Возвращает имена созданных файлов (без пути).
    """
    created: List[str] = []
    default_path = os.path.join(store_dir, profile.default_ini)
    if not os.path.isfile(default_path):
        return created
    for name in profile.user_inis:
        candidate = os.path.join(store_dir, name)
        if os.path.isfile(candidate):
            continue
        try:
            # copyfile, а не copy2: копирование атрибутов принесло бы флаг
            # «только для чтения» с шаблона, который установщики игр любят
            # помечать только для чтения.
            shutil.copyfile(default_path, candidate)
        except OSError:
            continue
        _clear_readonly(candidate)
        created.append(name)
    return created


def make_inis_writable(store_dir: str, max_depth: int = 2) -> List[str]:
    """Снимает «только для чтения» со всех INI в папке игры.

    Установщики нередко оставляют настроечные файлы «только для чтения»
    (``Fallout_default.ini`` приходит таким от Bethesda). Для файлов, которые
    правит сам Portablizer, флаг снимается точечно, но INI, лежащие глубже
    или не тронутые сборкой, оставались недоступны для записи — а лаунчер
    игры переписывает свои настройки при каждом нажатии «Играть».

    Возвращает имена файлов, с которых флаг был снят.
    """
    repaired: List[str] = []
    if not os.path.isdir(store_dir):
        return repaired
    for root, dirs, files in os.walk(store_dir, followlinks=False):
        dirs[:] = [name for name in dirs
                   if not name.startswith((".git", "$"))]
        relative = os.path.relpath(root, store_dir)
        depth = 0 if relative == "." else relative.count(os.sep) + 1
        if depth >= max_depth:
            dirs[:] = []
        for name in files:
            if not name.casefold().endswith(".ini"):
                continue
            if _clear_readonly(os.path.join(root, name)):
                repaired.append(_posix(os.path.relpath(os.path.join(root,
                                                                    name),
                                                        store_dir)))
    return repaired


def read_ini(path: str) -> Tuple[str, str]:
    """Читает INI, возвращая (текст, имя кодировки).

    Кодировка определяется по факту, а не угадывается: BOM — только если он
    действительно есть (дописать его в ``Fallout_default.ini`` нельзя, игра
    перестанет читать первую секцию), иначе UTF-8, а в крайнем случае
    ``latin-1``. Последний выбран не из-за языка, а потому что без потерь
    отображает любой байт: файл можно изменить построчно и записать обратно
    байт в байт.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig"), "utf-8-sig"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "latin-1"


def patch_ini_text(text: str,
                   settings: Sequence[Tuple[str, str, str]]) -> Tuple[str, bool]:
    """Выставляет ключи в INI, сохраняя всё остальное как было.

    Правка построчная намеренно: в INI игр Bethesda встречаются повторы
    ключей, пустые значения и комментарии, которые ``configparser``
    перетасовал бы и переписал файл целиком.
    """
    newline = "\r\n" if "\r\n" in text else "\n"
    had_final_newline = text.endswith(("\n", "\r"))
    lines = text.splitlines()
    changed = False

    for section, key, value in settings:
        section_l = section.lower()
        key_l = key.lower()
        current = ""
        section_start = -1
        section_end = -1
        value_index = -1

        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                if current == section_l and section_end < 0:
                    section_end = index
                current = stripped[1:-1].strip().lower()
                if current == section_l and section_start < 0:
                    section_start = index
                continue
            if current != section_l or value_index >= 0:
                continue
            if "=" not in stripped or stripped.startswith((";", "#")):
                continue
            if stripped.split("=", 1)[0].strip().lower() == key_l:
                value_index = index

        if value_index >= 0:
            replacement = f"{key}={value}"
            if lines[value_index].strip() != replacement:
                lines[value_index] = replacement
                changed = True
            continue

        if section_start < 0:
            if lines and lines[-1].strip():
                lines.append("")
            lines.append(f"[{section}]")
            lines.append(f"{key}={value}")
            changed = True
            continue

        insert_at = section_end if section_end >= 0 else len(lines)
        while insert_at - 1 > section_start and not lines[insert_at - 1].strip():
            insert_at -= 1
        lines.insert(insert_at, f"{key}={value}")
        changed = True

    if not changed:
        return text, False
    patched = newline.join(lines) + (newline if had_final_newline or lines
                                     else "")
    return patched, True


def patch_ini_file(path: str,
                   settings: Sequence[Tuple[str, str, str]]) -> bool:
    """Правит INI на диске. Возвращает True, если файл действительно изменён."""
    try:
        text, encoding = read_ini(path)
    except OSError:
        return False
    patched, changed = patch_ini_text(text, settings)
    # Настроечные INI должны оставаться доступными пользователю даже тогда,
    # когда их содержимое уже совпадает с шаблоном. Раньше флаг снимался лишь
    # при фактической правке bUseMyGamesDirectory, а исходные Fallout.ini и
    # FalloutPrefs.ini могли остаться read-only.
    _clear_readonly(path)
    if not changed:
        return False
    try:
        with open(path, "wb") as handle:
            handle.write(patched.encode(encoding))
    except (OSError, UnicodeEncodeError):
        return False
    return True


# --- слияние каталогов --------------------------------------------------------

def merge_tree(source: str, destination: str,
               patterns: Sequence[str] = (),
               copied: Optional[List[str]] = None) -> int:
    """Копирует из ``source`` в ``destination`` то, чего там нет или что старее.

    Ничего не удаляет и ничего не перезаписывает более старой версией —
    поэтому слияние безопасно вызывать в любую сторону и сколько угодно раз.
    Возвращает количество скопированных файлов.
    """
    if not source or not destination:
        return 0
    source = os.path.abspath(source)
    destination = os.path.abspath(destination)
    if not os.path.isdir(source) or _is_inside(source, destination) \
            or _is_inside(destination, source):
        return 0

    compiled = compile_patterns(patterns)
    count = 0
    total_bytes = 0
    for root, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith((".git", "$"))]
        for name in files:
            if name.lower() in JUNK_FILES:
                continue
            src_file = os.path.join(root, name)
            rel = os.path.relpath(src_file, source)
            if not path_allowed(rel, compiled):
                continue
            dst_file = os.path.join(destination, rel)
            try:
                src_stat = os.stat(src_file)
            except OSError:
                continue
            if src_stat.st_size > MAX_SYNC_BYTES:
                continue
            try:
                dst_stat = os.stat(dst_file)
                if dst_stat.st_mtime + MTIME_TOLERANCE >= src_stat.st_mtime:
                    continue
            except OSError:
                pass
            try:
                os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                _clear_readonly(dst_file)
                shutil.copy2(src_file, dst_file)
                # copy2 сохраняет и атрибут «только для чтения» источника.
                # Снимаем его ПОСЛЕ копирования, иначе пользовательские INI
                # снова становятся недоступны для ручного редактирования.
                _clear_readonly(dst_file)
            except OSError:
                continue
            count += 1
            total_bytes += src_stat.st_size
            if copied is not None:
                copied.append(_posix(rel))
            if count >= MAX_SYNC_FILES or total_bytes >= MAX_SYNC_BYTES:
                return count
    return count


def _is_inside(path: str, parent: str) -> bool:
    try:
        return os.path.commonpath(
            (os.path.abspath(path), os.path.abspath(parent))
        ) == os.path.abspath(parent)
    except ValueError:          # разные диски
        return False


# --- определение игры ---------------------------------------------------------

def detect_game(app_dir: str, max_depth: int = 3) -> Optional[DetectedGame]:
    """Ищет в ``App`` игру, умеющую держать сейвы рядом с собой."""
    if not app_dir or not os.path.isdir(app_dir):
        return None

    app_dir = os.path.abspath(app_dir)
    layout: Dict[str, Dict[str, List[str]]] = {}
    for root, dirs, files in os.walk(app_dir, followlinks=False):
        depth = os.path.relpath(root, app_dir).count(os.sep)
        if os.path.relpath(root, app_dir) == ".":
            depth = 0
        if depth >= max_depth:
            dirs[:] = []
        exes = [f.lower() for f in files if f.lower().endswith(".exe")]
        inis = [f for f in files if f.lower().endswith("_default.ini")]
        if exes or inis:
            layout[root] = {"exe": exes, "ini": inis}

    # 1. Точное совпадение по известной игре: шаблон настроек и её exe.
    for profile in GAME_PROFILES:
        for directory, content in layout.items():
            ini = next((f for f in content["ini"]
                        if f.lower() == profile.default_ini.lower()), None)
            if not ini:
                continue
            if any(exe in content["exe"] for exe in profile.executables):
                return DetectedGame(profile, directory,
                                    os.path.join(directory, ini))

    # 2. Тот же шаблон, но exe переименован (репаки часто зовут его
    #    launcher.exe/game.exe). Шаблона достаточно: он принадлежит движку.
    for profile in GAME_PROFILES:
        for directory, content in layout.items():
            ini = next((f for f in content["ini"]
                        if f.lower() == profile.default_ini.lower()), None)
            if ini:
                return DetectedGame(profile, directory,
                                    os.path.join(directory, ini))

    # 3. Любой другой Gamebryo: шаблон с SLocalSavePath внутри.
    for directory, content in layout.items():
        for ini in content["ini"]:
            path = os.path.join(directory, ini)
            try:
                text, _ = read_ini(path)
            except OSError:
                continue
            if "slocalsavepath" not in text.lower():
                continue
            stem = ini[: -len("_default.ini")]
            profile = GameProfile(
                id=GENERIC_GAMEBRYO_ID,
                title=f"{stem} (движок Gamebryo)",
                executables=(),
                default_ini=ini,
                user_inis=(f"{stem}.ini", f"{stem}Prefs.ini"),
                my_games=(stem,),
            )
            return DetectedGame(profile, directory, path)
    return None


# --- планирование -------------------------------------------------------------

def host_profile_dir() -> str:
    """Настоящий профиль пользователя этого ПК (без перенаправлений).

    ``PORTABLE_HOST_PROFILE`` позволяет указать его явно: так делает
    запасной ``Launch.bat`` (он запоминает профиль до перенаправления) и
    так же ведут себя тесты, чтобы не трогать настоящий профиль машины.
    """
    override = os.environ.get("PORTABLE_HOST_PROFILE", "").strip()
    if override and os.path.isabs(override):
        return override
    return os.environ.get("USERPROFILE") or os.path.expanduser("~")


def host_documents_dir(profile_dir: str = "") -> str:
    """Документы этого ПК: через Known Folders, а не склейкой строк.

    Папка «Документы» бывает перенесена (OneDrive, второй диск), и тогда
    ``%USERPROFILE%\\Documents`` указывает в пустоту.
    """
    override = os.environ.get("PORTABLE_HOST_DOCUMENTS", "").strip()
    if override and os.path.isabs(override):
        return override
    profile_dir = profile_dir or host_profile_dir()
    fallback = os.path.join(profile_dir, "Documents")
    if os.environ.get("PORTABLE_HOST_PROFILE", "").strip():
        # Профиль задан явно — искать «Документы» в реестре этого ПК нельзя:
        # получится каталог другого (настоящего) профиля.
        return fallback
    try:
        import winreg                                  # noqa: WPS433
    except ImportError:
        return fallback
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer"
            r"\User Shell Folders", 0, winreg.KEY_QUERY_VALUE,
        ) as key:
            value, _type = winreg.QueryValueEx(key, "Personal")
        expanded = os.path.expandvars(str(value))
        if expanded and os.path.isabs(expanded):
            return expanded
    except OSError:
        pass
    return fallback


def _host_root(root: str, profile_dir: str, documents_dir: str) -> str:
    """Абсолютный путь корня профиля (``Documents/My Games`` и т.п.)."""
    parts = _posix(root).split("/")
    if parts and parts[0].lower() == "documents":
        return os.path.join(documents_dir, *parts[1:]) if len(parts) > 1 \
            else documents_dir
    return os.path.join(profile_dir, *parts)


def discover_profile_dirs(roots: Sequence[str], tokens: Sequence[str],
                          resolve) -> List[Tuple[str, str]]:
    """Находит в профиле папки программы: возвращает (корень, имя).

    ``resolve`` превращает относительный корень (``Documents/My Games``) в
    абсолютный путь: у реального профиля «Документы» могут быть перенесены,
    а у портативного — нет.
    """
    found: List[Tuple[str, str]] = []
    for root in roots:
        directory = resolve(_posix(root))
        if not directory or not os.path.isdir(directory):
            continue
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if not os.path.isdir(os.path.join(directory, name)):
                continue
            if matches_tokens(name, tokens):
                found.append((_posix(root), name))
    return found


def plan(portable_dir: str, app_name: str,
         executables: Sequence[str] = (),
         data_dir_name: str = DEFAULT_DATA_DIR,
         app_rel: str = "App",
         profile_dir: str = "",
         documents_dir: str = "") -> SaveSetup:
    """Строит описание сквозных сохранений для готовой папки портатива."""
    portable_dir = os.path.abspath(portable_dir)
    app_dir = os.path.join(portable_dir, *_posix(app_rel).split("/"))
    profile_dir = profile_dir or host_profile_dir()
    documents_dir = documents_dir or host_documents_dir(profile_dir)
    data_dir = _posix(data_dir_name) or DEFAULT_DATA_DIR
    portable_profile = os.path.join(portable_dir, data_dir, "User")

    detected = detect_game(app_dir)
    tokens = name_tokens(
        app_name, executables,
        extra=list(detected.profile.my_games) if detected else [],
    )

    # Имена папок данных: объявленные профилем игры плюс всё похожее, что уже
    # лежит в профиле этого ПК и в профиле портатива.
    candidates: List[Tuple[str, str]] = []
    if detected:
        for name in detected.profile.my_games:
            candidates.append(("Documents/My Games", name))
    candidates.extend(discover_profile_dirs(
        WATCHED_ROOTS, tokens,
        lambda root: _host_root(root, profile_dir, documents_dir)))
    candidates.extend(discover_profile_dirs(
        WATCHED_ROOTS, tokens,
        lambda root: os.path.join(portable_profile, *root.split("/"))))

    unique: List[Tuple[str, str]] = []
    seen = set()
    for root, name in candidates:
        key = (root.lower(), name.lower())
        if key not in seen:
            seen.add(key)
            unique.append((root, name))

    setup = SaveSetup(tokens=tokens, roots=list(WATCHED_ROOTS))

    if detected:
        store_rel = _posix(os.path.relpath(detected.game_dir, portable_dir))
        setup.enabled = True
        setup.mode = "inplace"
        setup.profile = detected.profile.id
        setup.title = detected.profile.title
        setup.store = store_rel
        # INI-файлы переносятся в store один раз при сборке/обновлении
        # портатива ниже. В runtime entries обслуживают только сейвы: если
        # синхронизировать *.ini перед каждым запуском, устаревшая копия из
        # Documents\My Games может перезаписать ручные правки пользователя.
        patterns = [detected.profile.saves_dir]
        for root, name in unique:
            setup.entries.append(SaveEntry(
                name=name,
                store=store_rel,
                host=f"{root}/{name}",
                portable=f"{data_dir}/User/{root}/{name}",
                patterns=list(patterns),
                # Данные пишет сама игра — прямо в store. Папки профиля
                # остаются источником старых сейвов, не приёмником.
                direction="in",
            ))
        if not setup.entries:
            for name in detected.profile.my_games:
                setup.entries.append(SaveEntry(
                    name=name, store=store_rel,
                    host=f"Documents/My Games/{name}",
                    portable=f"{data_dir}/User/Documents/My Games/{name}",
                    patterns=list(patterns), direction="in",
                ))
        setup.notes.append(
            f"{detected.profile.title}: сохранения и настройки переведены в "
            f"{store_rel.replace('/', os.sep)} — их видят и прямой запуск exe, "
            "и лончер, и комплектный launcher.")
        return setup

    if not unique:
        setup.enabled = False
        setup.mode = "off"
        setup.notes.append(
            "Отдельных папок сохранений у программы не обнаружено: её данные "
            "и так целиком лежат в PortableData.")
        return setup

    setup.enabled = True
    setup.mode = "mirror"
    setup.store = f"{data_dir}/User"
    for root, name in unique:
        setup.entries.append(SaveEntry(
            name=name,
            store=f"{data_dir}/User/{root}/{name}",
            host=f"{root}/{name}",
            portable="",
            patterns=[],
            direction="both",
        ))
    setup.notes.append(
        "Сохранения хранятся в портативе, а при каждом запуске сводятся с "
        "профилем этого ПК: прямой запуск exe и лончер видят одни и те же "
        "файлы.")
    return setup


# --- применение ---------------------------------------------------------------

def apply(portable_dir: str, setup: SaveSetup,
          log: Optional[Logger] = None,
          profile_dir: str = "", documents_dir: str = "") -> SaveSetup:
    """Делает сквозные сохранения фактом: правит INI и сводит старые сейвы.

    Возвращает тот же ``setup``, дополненный списком изменённых файлов и
    количеством перенесённых сохранений.
    """
    log = log or Logger()
    if not setup.enabled:
        return setup

    portable_dir = os.path.abspath(portable_dir)
    profile_dir = profile_dir or host_profile_dir()
    documents_dir = documents_dir or host_documents_dir(profile_dir)

    if setup.mode == "inplace":
        store_dir = os.path.join(portable_dir, *setup.store.split("/"))
        profile = next((p for p in GAME_PROFILES if p.id == setup.profile),
                       None)
        if profile is None:
            # Конфиг мог прийти от обобщённого Gamebryo-профиля: тогда данные
            # о нём живут не в таблице, а в самой папке игры.
            detected = detect_game(store_dir, max_depth=1) \
                or detect_game(os.path.join(portable_dir, "App"))
            if detected is None:
                return setup
            profile = detected.profile
            store_dir = detected.game_dir

        sources: List[str] = []
        for entry in setup.entries:
            sources.extend(_entry_sources(portable_dir, entry, profile_dir,
                                          documents_dir))

        # 1. Сначала забираем настройки, уже выбранные пользователем: иначе
        #    «переезд» в папку игры сбросил бы графику, язык и управление.
        for source in sources:
            setup.migrated += merge_tree(source, store_dir, patterns=["*.ini"])

        # 2. Включаем хранение данных рядом с exe — это и делает сохранения
        #    сквозными: профиль Windows перестаёт участвовать вообще.
        for name in (profile.default_ini, *profile.user_inis):
            candidate = os.path.join(store_dir, name)
            if os.path.isfile(candidate) \
                    and patch_ini_file(candidate, profile.ini_settings):
                setup.patched.append(
                    _posix(os.path.relpath(candidate, portable_dir)))

        # 3. Сквозной конфигурационный файл рядом с exe. Шаблон
        #    ``*_default.ini`` задаёт только значения по умолчанию: движок
        #    читает пользовательские ``<Игра>.ini``/``<Игра>Prefs.ini``. Пока
        #    их нет рядом с exe, «сквозного» конфига не существует — игра
        #    кладёт свой INI в профиль, а пользователь копирует файл руками и
        #    получает взамен бесконечный цикл лаунчера (см. docstring
        #    ``create_missing_user_inis``).
        created = create_missing_user_inis(store_dir, profile)
        for name in created:
            candidate = os.path.join(store_dir, name)
            # Страховка: даже если шаблон по какой-то причине не удалось
            # править, пользовательский INI получает нужные ключи напрямую.
            patch_ini_file(candidate, profile.ini_settings)
            setup.patched.append(
                _posix(os.path.relpath(candidate, portable_dir)))
        if setup.patched:
            log.ok(f"{profile.default_ini}: включено хранение сохранений и "
                   "настроек внутри портатива (bUseMyGamesDirectory=0, "
                   f"SLocalSavePath={profile.saves_dir}\\).")
        if created:
            log.ok("Рядом с exe создан сквозной конфигурационный файл: "
                   + ", ".join(created)
                   + ". Его видят прямой запуск, лончер и комплектный "
                     "лаунчер — копировать INI из PortableData вручную не "
                     "нужно.")

        # 4. Ни один настроечный INI в папке игры не должен остаться «только
        #    для чтения»: лаунчер переписывает свои настройки при каждом
        #    нажатии «Играть», а недоступный для записи файл заставляет его
        #    зацикливаться (закрылся — открылся — закрылся…).
        unlocked = make_inis_writable(store_dir)
        if unlocked:
            log.ok("Снят флаг «только для чтения» с настроечных файлов ("
                   + ", ".join(unlocked)
                   + "): иначе лаунчер игры не смог бы их переписать и "
                     "уходил бы в бесконечный цикл.")

        # 5. Копии INI в перенаправленном профиле (PortableData\User\...)
        #    тоже должны быть доступны для записи. Лаунчер Bethesda пишет
        #    свои настройки именно туда, и «только для чтения» в этом каталоге
        #    даёт ровно тот же бесконечный цикл. Настоящий профиль этого ПК не
        #    трогаем: файлы пользователя меняем только внутри портатива.
        for source in sources:
            if not _is_inside(source, portable_dir):
                continue
            unlocked = make_inis_writable(source)
            if unlocked:
                log.ok("Снят флаг «только для чтения» с копий настроек в "
                       + _posix(os.path.relpath(source, portable_dir))
                       + " (" + ", ".join(unlocked) + ").")

        # 6. Переносим сейвы, уже накопленные обоими способами запуска.
        saves_target = os.path.join(store_dir, profile.saves_dir)
        for source in sources:
            moved = merge_tree(os.path.join(source, profile.saves_dir),
                               saves_target)
            if moved:
                setup.migrated += moved
                log.ok(f"Перенесено сохранений в портатив: {moved} "
                       f"(из {source})")
        os.makedirs(saves_target, exist_ok=True)
        return setup

    if setup.mode == "mirror":
        for entry in setup.entries:
            store_dir = os.path.join(portable_dir, *entry.store.split("/"))
            for source in _entry_sources(portable_dir, entry, profile_dir,
                                         documents_dir):
                moved = merge_tree(source, store_dir, entry.patterns)
                if moved:
                    setup.migrated += moved
                    log.ok(f"Сохранения «{entry.name}» перенесены в портатив: "
                           f"{moved} файлов.")
            os.makedirs(store_dir, exist_ok=True)
            # Настроечные файлы в портативном хранилище не должны остаться
            # «только для чтения»: xcopy и сама программа не переписывают
            # такой файл, и настройки навсегда остались бы устаревшими.
            unlocked = make_inis_writable(store_dir)
            if unlocked:
                log.ok("Снят флаг «только для чтения» с настроек «"
                       + entry.name + "» (" + ", ".join(unlocked) + ").")
    return setup


def _entry_sources(portable_dir: str, entry: SaveEntry, profile_dir: str,
                   documents_dir: str) -> List[str]:
    """Откуда можно забрать уже существующие данные этой записи."""
    sources: List[str] = []
    if entry.host:
        sources.append(_host_root(entry.host, profile_dir, documents_dir))
    if entry.portable:
        sources.append(os.path.join(portable_dir, *entry.portable.split("/")))
    store = os.path.join(portable_dir, *entry.store.split("/"))
    return [s for s in sources
            if os.path.isdir(s) and os.path.abspath(s) != os.path.abspath(store)]


def describe(setup: SaveSetup) -> List[str]:
    """Короткое человеческое описание режима — для журнала и README."""
    if not setup.enabled or setup.mode == "off":
        return ["Сквозные сохранения: отдельного хранилища сейвов у программы "
                "нет, все данные и так внутри PortableData."]
    lines: List[str] = []
    if setup.mode == "inplace":
        store = setup.store.replace("/", os.sep)
        lines.append(
            f"Сквозные сохранения: {setup.title or 'программа'} хранит сейвы "
            f"и настройки в {store} — одинаково при запуске "
            f"{store}\\<exe>, LaunchPortable.exe и комплектного лаунчера.")
        lines.append(
            f"  • Настроечные INI редактируйте прямо в {store} — рядом с exe. "
            "Копия в PortableData\\User\\Documents\\My Games не является "
            "активной.")
        lines.append(
            "    Сквозной конфигурационный файл создаётся рядом с exe сам: "
            "копировать INI из PortableData вручную не нужно — копия приносит "
            "флаг «только для чтения», от которого лончер игры уходит в "
            "бесконечный цикл.")
        lines.append(
            "    INI не синхронизируются при каждом запуске, поэтому ручные "
            "изменения не заменяются старыми копиями.")
    else:
        lines.append(
            "Сквозные сохранения: папки сейвов сводятся между портативом и "
            "профилем этого ПК при каждом запуске (побеждает более свежий "
            "файл, ничего не удаляется).")
    for entry in setup.entries[:6]:
        lines.append(f"  • {entry.name}: {entry.store.replace('/', os.sep)}")
    if len(setup.entries) > 6:
        lines.append(f"  • … и ещё {len(setup.entries) - 6}")
    return lines
