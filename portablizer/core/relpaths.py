"""Относительные пути внутри портатива: маркеры, штамп корня, починка после переноса.

Зачем это нужно
---------------
Портатив переносят: ``D:\\Apps\\XD_Portable`` → ``F:\\XD_Portable``, с флешки на
внешний диск, из ``C:\\Users\\Имя\\Desktop`` в ``E:\\Backup\\Apps``. Любая
абсолютная строка, записанная внутрь портатива, после такого переноса указывает
в никуда: программа ищет свои файлы по старому адресу и падает либо молча
создаёт второй профиль настроек.

Договор, который держит этот модуль
-----------------------------------
1. **Наши файлы.** ``Launch.bat``, ``LaunchHidden.vbs``, ``launcher_config.json``,
   меню, скрипты NetStack и Redist содержат только пути ОТНОСИТЕЛЬНО корня
   портатива. Абсолютный корень вычисляется на месте запуска
   (``%~dp0`` / ``sys.executable``).
2. **Захваченный реестр.** ``portable.reg`` хранит корень маркером
   ``@@PORTABLE_ROOT@@``; лончер подставляет настоящий путь при импорте и
   снова упаковывает настройки маркером при выходе. Разбор маркера учитывает
   регистр, ``/`` вместо ``\\``, удвоенные обратные слэши внутри ``.reg`` и
   границы пути: ``D:\\Apps\\XD`` не должен превращаться в мусор внутри
   ``D:\\Apps\\XData\\...``.
3. **Чужие конфиги.** Программа (и её установщик) пишет собственные файлы с
   абсолютными путями — переписать их в относительные нельзя, формат не наш.
   Поэтому Portablizer запоминает корень в штампе
   ``PortableData\\portable-root.json``, а лончер при запуске сравнивает его с
   текущим положением папки. Если папку перенесли, все найденные абсолютные
   пути старого корня заменяются новым — до того, как программа прочитает
   свои настройки.

Что проверяется при сборке
--------------------------
:func:`audit` обходит портатив текстовыми файлами (``.ini``, ``.json``,
``.reg``, ``.xml``, ``.cfg``…), считает найденные абсолютные пути и делит их на
две группы:

* внутри портатива — их существование ожидаемо, починка при переносе берёт их
  на себя;
* вне портатива (``C:\\Program Files\\...``, чужой профиль) — переноситься они
  не могут и обычно означают, что программа часть данных ищет в системе.

Результат пишется в ``portability-report.txt`` в корне портатива: это ответ на
вопрос «почему после переноса что-то отвалилось» без гаданий.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

#: Маркер корня портатива внутри захваченных файлов.
ROOT_TOKEN = "@@PORTABLE_ROOT@@"

#: Переменная cmd, которой тот же корень раскрывается в сгенерированных .bat.
PORTABLE_ROOT_VAR = "%PORTABLE_ROOT%"

#: Файл штампа: последний известный корень портатива.
STAMP_REL = "PortableData/portable-root.json"
STAMP_NAME = "portable-root.json"

#: Тот же корень одной ASCII-строкой: его читает ``Launch.bat`` (cmd сравнивает
#: байты, поэтому не-ASCII путь в этот файл не пишется — им занимается EXE).
STAMP_TEXT_REL = "PortableData/portable-root.txt"
STAMP_TEXT_NAME = "portable-root.txt"

#: Отчёт о путях в корне портатива.
REPORT_NAME = "portability-report.txt"

#: Расширения, в которых имеет смысл искать и править текстовые пути.
TEXT_SUFFIXES: Tuple[str, ...] = (
    ".ini", ".cfg", ".conf", ".config", ".json", ".xml", ".yaml", ".yml",
    ".txt", ".reg", ".bat", ".cmd", ".vbs", ".ps1", ".url", ".properties",
    ".settings", ".prefs", ".toml", ".local", ".dat",
)

#: Каталоги, которые при переносе обходятся в последнюю очередь: там лежат
#: сами программы и их служебные файлы, а не настройки.
APP_DIR_NAME = "App"

#: Каталоги, которые не обходятся никогда: временные файлы и кэши браузеров
#: меняются каждую секунду и к переносу отношения не имеют.
SKIP_DIRS: Tuple[str, ...] = (
    "temp", "tmp", "cache", "caches", "cache2", "gpucache", "shadercache",
    "codecache", "crashpad", "crashdumps", "logs",
)

#: Предел размера файла: конфиг на десятки мегабайт — это не конфиг.
MAX_TEXT_BYTES = 2 * 1024 * 1024

#: Предел числа просмотренных файлов за один проход.
MAX_FILES = 6000

#: Абсолютный путь Windows: буква диска, двоеточие и разделитель.
_WIN_ABS = re.compile(r"(?<![0-9A-Za-z_])[A-Za-z]:[\\/][^\s\"'<>|,;]*")

#: UNC-путь вида ``\\server\share\...``.
_UNC_ABS = re.compile(r"\\\\[0-9A-Za-z_.$-]+\\[^\\\s\"'<>|,;]+[^\s\"'<>|,;]*")

#: POSIX-путь ``/opt/app/...``. На Windows таких путей почти не бывает, но
#: модуль обязан одинаково работать и в тестах на Linux, и в сборке.
_POSIX_ABS = re.compile(r"(?<![0-9A-Za-z_:/.])(?:/[^\s\"'<>|,;]+)")

IS_WINDOWS = os.name == "nt"

_BOMS: Tuple[Tuple[bytes, str], ...] = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)


# --- корень и его текстовые формы ---------------------------------------------

def normalize_root(root: str) -> str:
    """Корень без завершающего разделителя (``D:\\Apps\\XD\\`` -> ``D:\\Apps\\XD``)."""
    text = str(root or "").strip().strip('"')
    if len(text) > 1:
        text = text.rstrip("\\/")
    # Голый диск ``D:`` оставляем как есть: ``D:`` и ``D:\\`` — разные пути.
    if len(text) == 2 and text[1] == ":":
        return text.upper()
    return text


def root_forms(root: str, doubled: bool = False) -> List[str]:
    """Все текстовые начертания корня, которые встречаются в файлах.

    ``D:\\Apps\\XD`` живёт в трёх видах: с обратными слэшами (INI, BAT, REG),
    с прямыми (JSON, URL, XML) и с удвоенными обратными (внутри значения
    ``.reg`` и JSON-строки ``"D:\\\\Apps\\\\XD"``). Длинные формы идут первыми:
    иначе короткая успела бы испортить длинную.
    """
    base = normalize_root(root)
    if not base:
        return []
    forms: List[str] = []
    variants = [base, base.replace("\\", "/"), base.replace("/", "\\")]
    if doubled:
        variants += [base.replace("\\", "\\\\"),
                     base.replace("\\", "\\\\").replace("/", "\\\\")]
    elif "\\" in base:
        # Удвоенная форма нужна и в обычном проходе: значение .reg пишется
        # как ``"D:\\\\Apps\\\\XD\\\\app.exe"``, и без этой формы маркер в файл
        # не попал бы вовсе (сравнение идёт по уже экранированному тексту).
        variants.append(base.replace("\\", "\\\\"))
    for item in variants:
        if item and item not in forms:
            forms.append(item)
    forms.sort(key=len, reverse=True)
    return forms


def _needle_pattern(needle: str) -> "re.Pattern[str]":
    """Регулярное выражение для одного начертания корня с границами пути.

    Без границ ``D:\\Apps\\XD`` находится внутри ``D:\\Apps\\XData\\save.ini`` и
    превращает чужой путь в ``@@PORTABLE_ROOT@@Data\\save.ini``. Именно так
    ломались настройки у соседних папок с общим префиксом имени.
    """
    return re.compile(r"(?<![0-9A-Za-z_.])" + re.escape(needle)
                      + r"(?![0-9A-Za-z_.])", re.IGNORECASE)


def tokenize_text(text: str, root: str, token: str = ROOT_TOKEN) -> str:
    """Заменяет абсолютный корень маркером (все начертания, без учёта регистра)."""
    if not text or not root:
        return text
    result = text
    for needle in root_forms(root):
        result = _needle_pattern(needle).sub(token, result)
    return result


def expand_text(text: str, root: str, token: str = ROOT_TOKEN,
                escaped: bool = False) -> str:
    """Раскрывает маркер настоящим корнем.

    ``escaped=True`` — для текста, где обратные слэши уже удвоены (значения
    ``.reg``): маркер заменяется на ``D:\\\\Apps\\\\XD``, иначе импорт получит
    путь с «одинарными» слэшами и ``reg.exe`` прочитает их как escape-последо-
    вательности.
    """
    if not text or not token:
        return text
    base = normalize_root(root)
    if not base:
        return text
    replacement = base.replace("\\", "\\\\") if escaped else base
    return re.sub(re.escape(token), lambda _m: replacement, text,
                  flags=re.IGNORECASE)


def contains_token(text: str, token: str = ROOT_TOKEN) -> bool:
    """Есть ли в тексте маркер корня."""
    return bool(text) and re.search(re.escape(token), text, re.IGNORECASE) is not None


# --- обычные пути --------------------------------------------------------------

def is_absolute(path: str) -> bool:
    """Похоже ли значение на абсолютный путь Windows (включая UNC)."""
    text = str(path or "").strip().strip('"')
    if not text:
        return False
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return True
    return text.startswith("\\\\") and len(text) > 2


def is_within(path: str, root: str) -> bool:
    """Лежит ли путь внутри корня (сравнение без учёта регистра и вида слэшей)."""
    if not path or not root:
        return False

    def norm(value: str) -> str:
        return os.path.normpath(str(value).replace("/", "\\")).rstrip("\\").casefold()

    inner, outer = norm(path), norm(root)
    if not outer:
        return False
    return inner == outer or inner.startswith(outer + "\\")


def relativize(path: str, root: str) -> str:
    """Путь относительно корня (``App\\XD.exe``) или исходный, если он снаружи."""
    if not is_within(path, root):
        return path

    def norm(value: str) -> str:
        return str(value).replace("/", "\\")

    inner, outer = norm(path), norm(root).rstrip("\\")
    if inner.casefold() == outer.casefold():
        return "."
    return inner[len(outer) + 1:]


def join_rel(*parts: str) -> str:
    """Склеивает относительные части пути в виде ``a/b/c`` (как в конфиге)."""
    cleaned = [str(p).replace("\\", "/").strip("/") for p in parts if str(p)]
    return "/".join(cleaned)


def absolute_paths(text: str, limit: int = 200) -> List[str]:
    """Все абсолютные пути, найденные в тексте, в порядке появления."""
    found: List[str] = []
    seen = set()
    if not text:
        return found
    for match in _WIN_ABS.finditer(text):
        value = match.group(0).rstrip("\\/").rstrip(".")
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        found.append(value)
        if len(found) >= limit:
            return found
    for match in _UNC_ABS.finditer(text):
        value = match.group(0).rstrip("\\/").rstrip(".")
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        found.append(value)
        if len(found) >= limit:
            break
    return found

def find_all_absolute(text: str, limit: int = 200) -> List[str]:
    """Абсолютные пути с учётом платформы (для проверки на Linux и Windows)."""
    found = absolute_paths(text, limit=limit)
    if IS_WINDOWS or not text:
        return found
    seen = {item.casefold() for item in found}
    for match in _POSIX_ABS.finditer(text):
        value = match.group(0).rstrip("/").rstrip(".")
        if len(value) <= 1:
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        found.append(value)
        if len(found) >= limit:
            break
    return found


# --- чтение и запись текста с сохранением кодировки ----------------------------

def _sniff(data: bytes) -> Tuple[str, str]:
    """(текст, кодировка). Бросает ``UnicodeDecodeError``, если это не текст.

    Двоичный файл с «текстовым» расширением — обычное дело (кэши, миниатюры,
    сжатые ``.dat``). Молча превратить его в мусор нельзя: лучше пропустить.
    """
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            return data.decode(encoding), encoding
    return data.decode("utf-8"), "utf-8"


def read_text(path: str) -> Optional[Tuple[str, str]]:
    """Текст и его кодировка или ``None``, если файл не читается как текст."""
    try:
        if os.path.getsize(path) > MAX_TEXT_BYTES:
            return None
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    try:
        return _sniff(data)
    except (UnicodeDecodeError, UnicodeError):
        return None


def write_text(path: str, text: str, encoding: str = "utf-8") -> bool:
    """Записывает текст в прежней кодировке (с BOM, если он был)."""
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(text.encode(encoding))
        return True
    except (OSError, UnicodeError):
        return False


def iter_text_files(root: str, *, include_app: bool = True,
                    max_files: int = MAX_FILES,
                    suffixes: Sequence[str] = TEXT_SUFFIXES
                    ) -> "Iterable[Tuple[str, str]]":
    """Обходит портатив и отдаёт ``(абсолютный путь, относительный путь)``.

    ``PortableData`` идёт первым: именно там живут настройки, которые ломаются
    при переносе. ``App`` — в конце и с потолком по глубине: там несколько
    десятков тысяч файлов программы, и обходить их все ради конфига накладно.
    """
    root = normalize_root(root)
    if not root or not os.path.isdir(root):
        return
    yielded = 0
    for current, dirs, files in os.walk(root):
        depth = os.path.relpath(current, root).count(os.sep)
        if os.path.relpath(current, root) == ".":
            depth = 0
        keep: List[str] = []
        for name in sorted(dirs):
            lower = name.casefold()
            if lower in SKIP_DIRS:
                continue
            if lower in ("netstack", "redist", "updates"):
                # Наши собственные каталоги: их файлы портативны по построению,
                # но прочитать их дешевле, чем объяснять, почему их нет в отчёте.
                keep.append(name)
                continue
            if lower == APP_DIR_NAME.casefold():
                if not include_app or depth >= 2:
                    continue
                keep.append(name)
                continue
            keep.append(name)
        dirs[:] = keep
        for name in sorted(files):
            if not any(name.casefold().endswith(suffix) for suffix in suffixes):
                continue
            full = os.path.join(current, name)
            if os.path.islink(full):
                continue
            yield full, os.path.relpath(full, root)
            yielded += 1
            if yielded >= max_files:
                return


# --- проверка при сборке -------------------------------------------------------

@dataclass
class PathHit:
    """Один файл, в котором нашлись абсолютные пути."""

    rel: str
    total: int = 0
    inside: List[str] = field(default_factory=list)
    outside: List[str] = field(default_factory=list)
    tokens: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "file": self.rel.replace("\\", "/"),
            "paths": self.total,
            "inside": len(self.inside),
            "outside": len(self.outside),
        }


@dataclass
class Audit:
    """Итог проверки: сколько прочитано, что нашлось и в каком файле."""

    root: str = ""
    scanned: int = 0
    skipped: int = 0
    truncated: bool = False
    hits: List[PathHit] = field(default_factory=list)
    token_files: int = 0

    @property
    def inside_count(self) -> int:
        return sum(len(hit.inside) for hit in self.hits)

    @property
    def outside_count(self) -> int:
        return sum(len(hit.outside) for hit in self.hits)

    @property
    def is_clean(self) -> bool:
        """Ни одного абсолютного пути внутри портатива."""
        return self.inside_count == 0

    def summary(self) -> str:
        if self.scanned == 0:
            return "текстовых файлов не найдено"
        if not self.hits:
            return (f"проверено {self.scanned} файлов: абсолютных путей нет — "
                    "папку можно переносить между дисками")
        return (f"проверено {self.scanned} файлов, абсолютные пути в "
                f"{len(self.hits)}: внутри портатива — {self.inside_count}, "
                f"вне его — {self.outside_count}")

    def to_dict(self) -> Dict[str, object]:
        return {
            "root": self.root,
            "scanned": self.scanned,
            "skipped": self.skipped,
            "truncated": self.truncated,
            "inside": self.inside_count,
            "outside": self.outside_count,
            "token_files": self.token_files,
            "files": [hit.to_dict() for hit in self.hits[:50]],
        }


def audit(portable_dir: str, *, include_app: bool = True,
          max_files: int = MAX_FILES) -> Audit:
    """Читает текстовые файлы портатива и делит найденные пути на «свои»/«чужие»."""
    root = normalize_root(portable_dir)
    result = Audit(root=root)
    if not root or not os.path.isdir(root):
        return result
    for full, rel in iter_text_files(root, include_app=include_app,
                                     max_files=max_files):
        loaded = read_text(full)
        if loaded is None:
            result.skipped += 1
            continue
        text, _encoding = loaded
        result.scanned += 1
        if contains_token(text):
            result.token_files += 1
        paths = find_all_absolute(text)
        if not paths:
            continue
        hit = PathHit(rel=rel)
        for path in paths:
            if is_within(path, root):
                hit.inside.append(path)
            else:
                hit.outside.append(path)
        hit.total = len(paths)
        if hit.total:
            result.hits.append(hit)
    if result.scanned >= max_files:
        result.truncated = True
    result.hits.sort(key=lambda item: (-item.total, item.rel.casefold()))
    return result


# --- штамп корня ---------------------------------------------------------------

def stamp_path(portable_dir: str) -> str:
    """Путь штампа ``PortableData/portable-root.json`` внутри портатива."""
    return os.path.join(normalize_root(portable_dir),
                        STAMP_REL.replace("/", os.sep))


def stamp_text_path(portable_dir: str) -> str:
    """Путь ASCII-копии корня для ``Launch.bat``."""
    return os.path.join(normalize_root(portable_dir),
                        STAMP_TEXT_REL.replace("/", os.sep))


def write_stamp_text(portable_dir: str, root: str = "") -> Optional[str]:
    """Пишет корень одной строкой с завершающим разделителем (только ASCII).

    ``Launch.bat`` не умеет ни разбирать JSON, ни сравнивать не-ASCII пути
    побайтово, поэтому для него корень хранится отдельным файлом. Отсутствие
    файла для BAT безопасно: EXE-лончер правит пути и без него.
    """
    root = normalize_root(root or portable_dir)
    if not root or not root.isascii():
        return None
    path = stamp_text_path(root)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii", newline="\n") as handle:
            handle.write(root + "\\\n")
    except (OSError, UnicodeError):
        return None
    return path


def read_stamp(portable_dir: str) -> Optional[Dict[str, object]]:
    """Содержимое штампа или ``None``, если его нет/он испорчен."""
    try:
        with open(stamp_path(portable_dir), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_stamp(portable_dir: str, root: str = "", version: str = "",
                previous: str = "") -> Optional[str]:
    """Запоминает текущий корень портатива (для починки после переноса)."""
    root = normalize_root(root or portable_dir)
    if not root:
        return None
    path = stamp_path(root)
    created = time.strftime("%Y-%m-%d %H:%M:%S")
    payload: Dict[str, object] = {
        "schema": 1,
        "root": root,
        "updated": created,
    }
    if version:
        payload["version"] = version
    if previous and normalize_root(previous).casefold() != root.casefold():
        payload["previous"] = normalize_root(previous)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    except OSError:
        return None
    write_stamp_text(root)
    return path


def stored_root(portable_dir: str) -> str:
    """Корень из штампа (пустая строка, если штампа нет)."""
    data = read_stamp(portable_dir) or {}
    return normalize_root(str(data.get("root", "")))


def root_changed(portable_dir: str) -> Optional[Tuple[str, str]]:
    """``(бывший, текущий)`` корень, если папку перенесли с прошлого запуска."""
    current = normalize_root(portable_dir)
    remembered = stored_root(current)
    if not remembered or not current:
        return None
    if remembered.casefold() == current.casefold():
        return None
    return remembered, current


def repair_text(text: str, old_root: str, new_root: str) -> str:
    """Меняет старый корень на новый во всех начертаниях (для чужих конфигов)."""
    if not text or not old_root or not new_root:
        return text
    old_root = normalize_root(old_root)
    new_root = normalize_root(new_root)
    if old_root.casefold() == new_root.casefold():
        return text
    result = text
    for needle in root_forms(old_root):
        doubled = "\\\\" in needle
        replacement = new_root.replace("\\", "\\\\") if doubled else new_root
        result = _needle_pattern(needle).sub(lambda _m, r=replacement: r, result)
    return result


def repair_file(path: str, old_root: str, new_root: str) -> int:
    """Правит один файл. Возвращает число замен (0 — файл не тронут)."""
    loaded = read_text(path)
    if loaded is None:
        return 0
    text, encoding = loaded
    fixed = repair_text(text, old_root, new_root)
    if fixed == text:
        return 0
    # Сколько раз старый корень реально встретился — это и есть число правок.
    hits = 0
    for needle in root_forms(old_root):
        hits += len(_needle_pattern(needle).findall(text))
    if not write_text(path, fixed, encoding):
        return 0
    return max(hits, 1)


# --- отчёт ---------------------------------------------------------------------

def render_report(audit_result: Audit, *, version: str = "",
                  stamp: Optional[Dict[str, object]] = None,
                  launcher_exe: str = "") -> str:
    """Текст ``portability-report.txt``: что проверено и что будет при переносе."""
    root = audit_result.root
    lines: List[str] = []
    lines.append("Отчёт о переносимости портатива")
    lines.append("=" * 60)
    if version:
        lines.append(f"Portablizer: {version}")
    lines.append(f"Корень портатива: {root or '(не определён)'}")
    remembered = str((stamp or {}).get("root", "") or "")
    if remembered:
        lines.append(f"Запомненный корень: {remembered}")
    lines.append("")
    lines.append("Что делает Portablizer")
    lines.append("-" * 60)
    lines.append("  • свои файлы (лончер, конфиг, скрипты) хранят пути только")
    lines.append("    относительно корня портатива — их перенос не ломает;")
    lines.append("  • захваченный реестр хранит корень маркером "
                 f"{ROOT_TOKEN};")
    lines.append("    лончер подставляет настоящий путь при импорте и снова")
    lines.append("    упаковывает настройки маркером при выходе;")
    lines.append("  • настройки самой программы переписать в относительные")
    lines.append("    нельзя (их формат не наш), поэтому корень запоминается в")
    lines.append(f"    {STAMP_REL.replace('/', chr(92))}: при переносе лончер")
    lines.append("    заменяет старый путь новым до запуска программы.")
    lines.append("")
    lines.append("Проверка файлов")
    lines.append("-" * 60)
    lines.append(f"  прочитано текстовых файлов: {audit_result.scanned}")
    if audit_result.skipped:
        lines.append(f"  пропущено (не текст / слишком велик): "
                     f"{audit_result.skipped}")
    if audit_result.truncated:
        lines.append("  обход остановлен по потолку числа файлов")
    lines.append(f"  файлов с маркером корня: {audit_result.token_files}")
    lines.append(f"  абсолютных путей внутри портатива: "
                 f"{audit_result.inside_count}")
    lines.append(f"  абсолютных путей вне портатива: {audit_result.outside_count}")
    lines.append("")
    lines.append("Итог")
    lines.append("-" * 60)
    if audit_result.scanned == 0:
        lines.append("  Проверять было нечего: текстовых файлов не нашлось.")
    elif audit_result.inside_count == 0:
        lines.append("  Абсолютных путей внутри портатива нет: папку можно")
        lines.append("  переносить на другой диск или в другой каталог.")
    else:
        lines.append("  Абсолютные пути внутри портатива есть — при переносе")
        lines.append("  лончер заменит старый корень новым. Запускать программу")
        default_launcher = "App" + chr(92) + "LaunchPortable.exe"
        lines.append("  нужно через " + (launcher_exe or default_launcher))
        lines.append("  или Launch.bat: прямой запуск exe из App обходит починку.")
    if audit_result.outside_count:
        lines.append("  Пути вне портатива перенести нельзя: это либо ссылки на")
        lines.append("  системные файлы (нормально), либо следы сборки на этом ПК.")
    if audit_result.hits:
        lines.append("")
        lines.append("Файлы с абсолютными путями")
        lines.append("-" * 60)
        for hit in audit_result.hits[:40]:
            lines.append(f"  • {hit.rel}: всего {hit.total} "
                         f"(внутри {len(hit.inside)}, вне {len(hit.outside)})")
        if len(audit_result.hits) > 40:
            lines.append(f"  … и ещё {len(audit_result.hits) - 40} файлов")
        lines.append("")
        lines.append("Подробности по путям вне портатива")
        lines.append("-" * 60)
        shown = 0
        for hit in audit_result.hits:
            for path in hit.outside:
                if shown >= 25:
                    break
                lines.append(f"  {hit.rel}: {path}")
                shown += 1
            if shown >= 25:
                break
        if shown == 0:
            lines.append("  (нет)")
    lines.append("")
    return "\n".join(lines)


def write_report(portable_dir: str, audit_result: Audit, *, version: str = "",
                 stamp: Optional[Dict[str, object]] = None,
                 launcher_exe: str = "") -> Optional[str]:
    """Пишет ``portability-report.txt`` в корень портатива."""
    root = normalize_root(portable_dir)
    if not root:
        return None
    path = os.path.join(root, REPORT_NAME)
    text = render_report(audit_result, version=version, stamp=stamp,
                         launcher_exe=launcher_exe)
    if not write_text(path, text, "utf-8"):
        return None
    return path


def launcher_section(portable_dir: str = "", *, enabled: bool = True,
                     include_app: bool = True) -> Dict[str, object]:
    """Секция ``relative_paths`` для ``launcher_config.json``.

    Лончер читает её целиком и по ней решает, что и где править при переносе.
    Все значения относительны корня: абсолютного пути в конфиге нет.
    """
    return {
        "enabled": bool(enabled),
        "stamp": STAMP_REL,
        "report": REPORT_NAME,
        "root_token": ROOT_TOKEN,
        "include_app": bool(include_app),
        "max_files": MAX_FILES,
        "max_bytes": MAX_TEXT_BYTES,
        "skip_dirs": list(SKIP_DIRS),
        "suffixes": list(TEXT_SUFFIXES),
    }
