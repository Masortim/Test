"""Adobe Creative Cloud (HyperDrive): портатив без UWP-шага и «код ошибки 191».

Зачем это нужно
---------------
Установщики Adobe для Windows — это не один движок, а связка: оболочка
(``Set-up.exe`` / ``Setup.exe``), движок HyperDrive (``HDSetup``/``HDPIM``) и
набор пакетов в каталоге ``payloads``. Движок ставит пакеты программы
(``*.msi``), а последним шагом выполняет ``AddUWPAppxCommand``: регистрирует
UWP-пакет (у Adobe XD это ``SparklerApp.appx`` = ``Adobe.CC.XD``) сразу для
всех пользователей через DISM.

Именно этот шаг и падает с «В настоящее время невозможно установить XD. (Код
ошибки: 191)». Код 191 — не про командную строку и не про ключи тишины: шагу
нужны работающая служба ``AppXSvc``, разрешение на установку неопубликованных
приложений, системный том и повышение прав. Отдельная беда в том, что UWP-шаг
несовместим с самой идеей портатива: Windows регистрирует пакет на конкретном
компьютере и для всех его пользователей, а не «в папке».

Что делает этот модуль
----------------------
* :func:`find_payloads` — находит пакеты программы внутри установщика (или
  рядом с ним — у корпоративного пакета Adobe Admin Console это каталог
  ``payloads``) и отделяет их от UWP-пакетов.
* :func:`materialize` — раскладывает пакеты в ``App``: MSI ставятся
  административной установкой, ZIP-пакеты распаковываются, а Appx/MSIX
  **сознательно пропускаются**. Сама программа Adobe — обычное Win32-
  приложение и без UWP-пакета запускается.
* :func:`find_payloads_in_roots` — второй источник пакетов: установщик,
  упавший на UWP-шаге, уже успел распаковать payload во временный каталог
  (``C:\\adobeTemp\\ETRxxxx.tmp\\1\\``). Оттуда пакеты забираются, даже если
  контейнер установщика сторонним распаковщиком не читается.
* :func:`parse_failure` и :func:`failure_hints` — точная расшифровка кода
  ошибки и OS-кода Appx из журнала установщика и честные советы: что именно
  осталось за бортом портатива.
"""
from __future__ import annotations

import os
import re
import shutil
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

#: Имя плана «распаковать пакет без установки» в лестнице попыток.
PAYLOAD_ADOBE = "adobe"

#: Файл с объяснением, что осталось за бортом портатива (лежит в папке
#: портатива рядом с ``installer-output.log``).
ADOBE_NOTE_NAME = "adobe-uwp.txt"

#: Каталоги, в которых Adobe держит пакеты внутри установщика. У
#: корпоративного пакета Adobe Admin Console это ``Build\\payloads``.
PAYLOAD_DIR_NAMES = ("payloads", "payload")

#: Расширения UWP-пакетов: их установка — тот самый шаг с кодом 191.
UWP_SUFFIXES = (".appx", ".appxbundle", ".msix", ".msixbundle")

MSI_SUFFIX = ".msi"
ZIP_SUFFIX = ".zip"

#: Потолки обхода: payload'ов у больших пакетов много, но не бесконечно.
SCAN_FILE_LIMIT = 20000
SCAN_DEPTH_LIMIT = 8

#: Маркеры движка HyperDrive внутри установщика. Нужны для журнала и для
#: распознавания типа (см. ``detect.py``).
HD_MARKERS: Tuple[str, ...] = (
    "hdsetup", "hdpim", "adduwpappxcommand", "adobetemp",
    "adobe desktop common", "uwpassets", "sparklerapp",
)

#: Коды возврата установщика Adobe, которые встречаются чаще всего.
#: Расшифровка — по документации Adobe и по журналам установки.
ADOBE_CODES: Dict[int, str] = {
    190: "компьютер не отвечает требованиям программы (версия Windows, "
         "обновления, архитектура)",
    191: "не удалось установить UWP-пакет (Appx): шаг AddUWPAppxCommand — "
         "служба AppX, разрешение на неопубликованные приложения, системный "
         "том или права администратора",
    183: "установщику помешал каталог: файл или папку не удалось создать "
         "или перезаписать (часто — профиль пользователя или антивирус)",
    188: "установленная версия Creative Cloud несовместима с этим "
         "установщиком",
    192: "на компьютере уже установлена более новая версия программы",
    193: "установщик 64-битной программы запущен на 32-битной системе",
    506: "Windows запрещает установку неопубликованных приложений "
         "(политика sideloading / нет лицензии разработчика)",
    507: "служба развёртывания приложений (AppX) не отвечает или "
         "отключена",
}

#: OS-коды, которыми Windows отвечает на установку Appx. Они печатаются в
#: журнале Adobe рядом с кодом 191 и объясняют причину точнее самого 191.
APPX_OS_ERRORS: Dict[int, str] = {
    0x80070005: "отказано в доступе (пакет не читается или каталог защищён)",
    0x80070422: "служба отключена — обычно это AppXSvc "
                "(«Служба развёртывания AppX»)",
    0x80070490: "пакет не найден или его нельзя подготовить на этом томе "
                "(Windows требует системный том)",
    0x80073CFF: "Windows запрещает установку неопубликованных приложений: "
                "нужна политика sideloading (или лицензия разработчика)",
    0x80073CF3: "не найдена или не та версия framework-зависимости "
                "(VCLibs / .NET Native)",
    0x80073CF6: "пакет не удалось зарегистрировать для всех пользователей",
    0x80073CF9: "пакет с таким именем уже установлен в другой версии",
    0x80073D06: "на компьютере уже установлена более новая версия пакета",
    0x80073D0D: "том, на который ставится пакет, недоступен или отключён",
    0x80073D0A: "пакет заблокирован антивирусом или политикой устройства",
}

#: Продукты Adobe, у которых UWP-пакет — только оболочка/интеграция, а сама
#: программа ставится обычными MSI. Нужно для человеческих подсказок.
_UWP_ONLY_PRODUCTS = {
    "sparklerapp": "Adobe XD",
    "adobe.cc.xd": "Adobe XD",
    "uwpassets": "оболочка UWP (SparklerApp)",
    "adobenotificationclient": "Adobe Creative Cloud (уведомления)",
    "adobenativeclient": "Adobe Creative Cloud (клиент)",
    "adobeccx": "Adobe Creative Cloud",
}


# --- пакеты внутри установщика ----------------------------------------------

@dataclass(frozen=True)
class Payload:
    """Один файл пакета внутри установщика или рядом с ним."""

    path: str
    kind: str                 # "msi" | "zip" | "uwp" | "other"
    product: str = ""         # каталог пакета (AdobeXD20.0-mul и т. п.)

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def is_app_payload(self) -> bool:
        """Пакет содержит файлы программы (а не оболочку UWP)."""
        return self.kind in ("msi", "zip")


@dataclass
class AdobeLayout:
    """Что нашлось внутри установщика: пакеты программы и UWP-оболочки."""

    root: str = ""
    payloads: List[Payload] = field(default_factory=list)
    #: Каталоги ``payloads``, в которых лежат пакеты.
    payload_dirs: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    scanned: int = 0

    @property
    def msis(self) -> List[Payload]:
        return [p for p in self.payloads if p.kind == "msi"]

    @property
    def archives(self) -> List[Payload]:
        return [p for p in self.payloads if p.kind == "zip"]

    @property
    def uwp_packages(self) -> List[Payload]:
        return [p for p in self.payloads if p.kind == "uwp"]

    @property
    def app_payloads(self) -> List[Payload]:
        return [p for p in self.payloads if p.is_app_payload]

    @property
    def is_empty(self) -> bool:
        return not self.payloads

    @property
    def has_app_payload(self) -> bool:
        return bool(self.app_payloads)

    def extend(self, other: "AdobeLayout") -> None:
        """Добавляет пакеты другого результата, пропуская повторы."""
        known = {os.path.normcase(os.path.abspath(p.path)) for p in self.payloads}
        for payload in other.payloads:
            key = os.path.normcase(os.path.abspath(payload.path))
            if key in known:
                continue
            known.add(key)
            self.payloads.append(payload)
        for directory in other.payload_dirs:
            if directory not in self.payload_dirs:
                self.payload_dirs.append(directory)
        for note in other.notes:
            if note not in self.notes:
                self.notes.append(note)
        self.scanned += other.scanned

    def summary(self) -> str:
        """Короткая строка для журнала: что именно нашлось."""
        if self.is_empty:
            return "пакетов не найдено"
        parts = []
        if self.msis:
            parts.append(f"MSI: {len(self.msis)}")
        if self.archives:
            parts.append(f"ZIP: {len(self.archives)}")
        if self.uwp_packages:
            parts.append(f"UWP (пропуск): {len(self.uwp_packages)}")
        return ", ".join(parts) or "пакетов не найдено"

    def uwp_names(self) -> List[str]:
        return [p.name for p in self.uwp_packages]


def _classify(name: str) -> str:
    folded = name.casefold()
    if folded.endswith(MSI_SUFFIX):
        return "msi"
    if folded.endswith(ZIP_SUFFIX):
        return "zip"
    if folded.endswith(UWP_SUFFIXES):
        return "uwp"
    return "other"


def _payload_roots(root: str, max_depth: int) -> List[str]:
    """Каталоги-«пакеты» (``payloads``/``payload``) внутри дерева."""
    found: List[str] = []
    base_depth = os.path.normpath(root).count(os.sep)
    for current, dirs, _files in os.walk(root):
        depth = os.path.normpath(current).count(os.sep) - base_depth
        if depth >= max_depth:
            dirs[:] = []
            continue
        if os.path.basename(current).casefold() in PAYLOAD_DIR_NAMES:
            found.append(current)
            dirs[:] = []
    return found


def _product_name(path: str, payload_root: str = "") -> str:
    """Имя пакета для журнала: ближайший осмысленный каталог."""
    if payload_root:
        try:
            relative = os.path.relpath(path, payload_root)
        except ValueError:
            relative = path
        parts = [part for part in relative.split(os.sep) if part not in (".", "..")]
        if len(parts) > 1:
            return parts[0]
    return os.path.basename(os.path.dirname(path))


def find_payloads(root: str, *, payload_dirs_only: bool = False,
                  installer_path: str = "",
                  limit: int = SCAN_FILE_LIMIT,
                  max_depth: int = SCAN_DEPTH_LIMIT) -> AdobeLayout:
    """Собирает список пакетов внутри каталога ``root``.

    ``payload_dirs_only`` — смотреть только каталоги ``payloads``/``payload``.
    Так проверяется папка рядом с установщиком: брать оттуда произвольные
    ``*.msi`` нельзя, это могут быть чужие пакеты.

    ``installer_path`` исключается из результата: сам установщик — не пакет
    программы, даже если у него расширение ``.exe``/``.msi``.
    """
    layout = AdobeLayout(root=root)
    if not root or not os.path.isdir(root):
        if root:
            layout.notes.append(f"каталог недоступен: {root}")
        return layout

    own = (os.path.normcase(os.path.abspath(installer_path))
           if installer_path else "")
    payload_roots = _payload_roots(root, max_depth)
    layout.payload_dirs = list(payload_roots)
    if payload_roots:
        layout.notes.append(
            "найдены каталоги пакетов: "
            + ", ".join(os.path.basename(p) for p in payload_roots[:4]))
    bases: Sequence[str]
    if payload_roots:
        bases = payload_roots
    elif payload_dirs_only:
        layout.notes.append("каталогов payloads рядом с установщиком нет")
        return layout
    else:
        bases = (root,)

    seen: set = set()
    for base in bases:
        base_depth = os.path.normpath(base).count(os.sep)
        for current, _dirs, files in os.walk(base):
            depth = os.path.normpath(current).count(os.sep) - base_depth
            if depth >= max_depth:
                continue
            for name in files:
                if layout.scanned >= limit:
                    layout.notes.append(
                        f"просмотр остановлен на {limit} файлах — пакетов "
                        "больше, чем ожидалось")
                    break
                layout.scanned += 1
                path = os.path.join(current, name)
                if own and os.path.normcase(os.path.abspath(path)) == own:
                    continue
                kind = _classify(name)
                if kind == "other":
                    continue
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                seen.add(key)
                payload_root = next(
                    (p for p in payload_roots
                     if os.path.normcase(path).startswith(
                         os.path.normcase(p) + os.sep)),
                    payload_roots[0] if payload_roots else "")
                layout.payloads.append(Payload(
                    path=path, kind=kind,
                    product=_product_name(path, payload_root)))
            if layout.scanned >= limit:
                break
    layout.payloads.sort(key=lambda p: (p.kind != "msi", p.kind != "zip",
                                        p.path.casefold()))
    return layout


def default_temp_roots(env: Optional[dict] = None) -> List[str]:
    """Куда Adobe раскладывает payload, пока ставит программу.

    Основное место — ``%SystemDrive%\\adobeTemp``: движок специально выбирает
    короткий путь без пробелов. Тот же каталог может оказаться внутри TEMP,
    если TEMP перенаправлен (Portablizer как раз это и делает: TEMP
    установщика живёт в ``PortableData\\Temp``).
    """
    environment = os.environ if env is None else env
    candidates: List[str] = []
    drive = environment.get("SystemDrive") or "C:"
    candidates.append(os.path.join(drive + os.sep, "adobeTemp"))
    for variable in ("TEMP", "TMP", "LOCALAPPDATA", "PROGRAMDATA"):
        value = environment.get(variable, "")
        if value:
            candidates.append(os.path.join(value, "adobeTemp"))
    unique: List[str] = []
    seen = set()
    for path in candidates:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _adobe_runs(root: str) -> List[str]:
    """Каталоги одного запуска установщика внутри ``adobeTemp``.

    Adobe создаёт ``ETRxxxx.tmp`` и внутри него — пронумерованные подпапки
    (``1``, ``2``) с распакованными пакетами.
    """
    runs: List[str] = []
    try:
        with os.scandir(root) as scanned:
            entries = sorted(scanned, key=lambda e: e.name.casefold())
    except OSError:
        return runs
    for entry in entries:
        try:
            if not entry.is_dir():
                continue
        except OSError:
            continue
        if _looks_like_run(entry.name):
            runs.append(entry.path)
            continue
        try:
            with os.scandir(entry.path) as nested:
                for child in nested:
                    if child.is_dir() and _looks_like_run(child.name):
                        runs.append(child.path)
        except OSError:
            continue
    return runs


def _looks_like_run(name: str) -> bool:
    folded = name.casefold()
    return folded.startswith("etr") or folded in ("payloads", "payload")


def find_payloads_in_roots(roots: Iterable[str],
                           *, limit: int = SCAN_FILE_LIMIT) -> AdobeLayout:
    """Ищет пакеты во всех кандидатах (TEMP установщика, ``adobeTemp``…).

    Возвращает объединённый результат; в ``notes`` видно, откуда что взялось.
    """
    merged = AdobeLayout()
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        candidates = _adobe_runs(root) or [root]
        for candidate in candidates:
            layout = find_payloads(candidate, limit=limit)
            if layout.is_empty:
                continue
            layout.notes.insert(0, f"источник пакетов: {candidate}")
            merged.extend(layout)
    return merged


# --- раскладка пакетов в App -------------------------------------------------

@dataclass
class ApplyResult:
    """Что удалось положить в ``App`` и что сознательно пропущено."""

    msi_ok: List[str] = field(default_factory=list)
    msi_failed: List[Tuple[str, str]] = field(default_factory=list)
    archives_ok: List[str] = field(default_factory=list)
    archives_failed: List[Tuple[str, str]] = field(default_factory=list)
    #: UWP-пакеты, которые НЕ устанавливались (это и есть обход кода 191).
    skipped_uwp: List[str] = field(default_factory=list)
    files_extracted: int = 0
    notes: List[str] = field(default_factory=list)

    @property
    def has_result(self) -> bool:
        return bool(self.msi_ok or self.archives_ok or self.files_extracted)

    def summary(self) -> str:
        parts = []
        if self.msi_ok:
            parts.append(f"MSI распаковано: {len(self.msi_ok)}")
        if self.archives_ok:
            parts.append(f"ZIP распаковано: {len(self.archives_ok)}")
        if self.files_extracted:
            parts.append(f"файлов из архивов: {self.files_extracted}")
        if self.skipped_uwp:
            parts.append(f"UWP пропущено: {len(self.skipped_uwp)}")
        if self.msi_failed:
            parts.append(f"MSI с ошибкой: {len(self.msi_failed)}")
        if self.archives_failed:
            parts.append(f"ZIP с ошибкой: {len(self.archives_failed)}")
        return ", ".join(parts) or "ничего не сделано"


def _safe_member(destination: str, name: str) -> Optional[str]:
    """Путь распаковки или ``None``, если запись выходит за пределы папки."""
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return None
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        return None
    target = os.path.join(destination, *parts) if parts else destination
    destination_abs = os.path.abspath(destination)
    target_abs = os.path.abspath(target)
    if os.path.commonpath([destination_abs, target_abs]) != destination_abs:
        return None
    return target


def extract_zip(archive: str, destination: str) -> Tuple[bool, str]:
    """Распаковывает ZIP-пакет в ``App`` (без внешних утилит).

    Adobe складывает часть пакетов обычными ZIP-архивами, поэтому здесь не
    нужен ни 7-Zip, ни Windows: распаковка идёт стандартной библиотекой.
    Записи вне целевой папки (``..``, абсолютные пути) пропускаются.
    """
    written = 0
    try:
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                target = _safe_member(destination, item.filename)
                if target is None:
                    continue
                if item.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                parent = os.path.dirname(target)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with bundle.open(item) as source, open(target, "wb") as sink:
                    shutil.copyfileobj(source, sink, 1024 * 1024)
                written += 1
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        return False, f"{os.path.basename(archive)}: {exc}"
    return True, f"файлов: {written}"


def materialize(layout: AdobeLayout, app_dir: str,
                install_msi: Callable[[str], Optional[int]],
                extract: Callable[[str, str], Tuple[bool, str]] = extract_zip,
                ) -> ApplyResult:
    """Раскладывает найденные пакеты в ``App``.

    ``install_msi`` — установка MSI в ``App`` (в сборке это административная
    установка ``msiexec /a``; в тестах — что угодно, лишь бы вернуть код).
    UWP-пакеты не устанавливаются и не распаковываются: именно их установка
    и есть шаг, падающий с кодом 191.
    """
    result = ApplyResult()
    try:
        os.makedirs(app_dir, exist_ok=True)
    except OSError as exc:
        result.notes.append(f"не удалось создать App: {exc}")
        return result

    for payload in layout.msis:
        try:
            rc = install_msi(payload.path)
        except Exception as exc:  # noqa: BLE001 - один пакет не срывает сборку
            result.msi_failed.append((payload.name, str(exc)))
            continue
        if rc in (0, 3010):
            result.msi_ok.append(payload.name)
        else:
            result.msi_failed.append((payload.name, f"код {rc}"))

    for payload in layout.archives:
        ok, text = extract(payload.path, app_dir)
        if not ok:
            result.archives_failed.append((payload.name, text))
            continue
        result.archives_ok.append(payload.name)
        match = re.search(r"(\d+)", text)
        if match:
            result.files_extracted += int(match.group(1))

    for payload in layout.uwp_packages:
        result.skipped_uwp.append(payload.name)

    if layout.uwp_packages:
        result.notes.append(
            "UWP-пакеты пропущены намеренно: их установка — шаг "
            "AddUWPAppxCommand, который падает с кодом 191 и регистрирует "
            "приложение на этом компьютере для всех пользователей")
    return result


# --- диагностика кода 191 ----------------------------------------------------

@dataclass
class AdobeFailure:
    """Разобранная запись журнала Adobe о неудаче."""

    code: Optional[int] = None
    command: str = ""
    package: str = ""
    os_code: Optional[int] = None
    package_path: str = ""
    raw: str = ""

    @property
    def is_uwp(self) -> bool:
        """Отказ случился именно на установке UWP-пакета."""
        folded = f"{self.command} {self.package} {self.package_path}".casefold()
        if "adduwpappxcommand" in folded:
            return True
        return any(hint in folded for hint in
                   ("sparklerapp", "uwpassets", ".appx", ".msix"))

    @property
    def code_hint(self) -> str:
        if self.code is None:
            return ""
        return ADOBE_CODES.get(self.code, "неизвестный код установщика Adobe")

    @property
    def os_hint(self) -> str:
        if self.os_code is None:
            return ""
        return APPX_OS_ERRORS.get(
            self.os_code, "неизвестный код Windows для установки пакета")

    @property
    def product(self) -> str:
        folded = f"{self.package} {self.package_path}".casefold()
        for marker, name in _UWP_ONLY_PRODUCTS.items():
            if marker in folded:
                return name
        return self.package or "UWP-пакет"

    def summary(self) -> str:
        parts: List[str] = []
        if self.code is not None:
            parts.append(f"код {self.code} — {self.code_hint}")
        if self.command:
            parts.append(f"шаг «{self.command}»")
        if self.package:
            parts.append(f"пакет {self.package}")
        if self.os_code is not None:
            parts.append(f"Windows: 0x{self.os_code:08X} — {self.os_hint}")
        return "; ".join(parts)


_CODE_RE = re.compile(
    r"Error \(Code = (?P<code>-?\d+)\) executing in command "
    r"'(?P<command>[^']*)'(?: for package:? ?'?(?P<package>[^',\n]+))?",
    re.IGNORECASE)
_OS_CODE_RE = re.compile(
    r"OS_Error_Code:\s*(?P<code>0x[0-9A-Fa-f]+|-?\d+)")
_APPX_PATH_RE = re.compile(
    r"(?P<path>[A-Za-z]:\\[^\r\n#]*?\.(?:appx|appxbundle|msix|msixbundle))",
    re.IGNORECASE)
_PACKAGE_RE = re.compile(r"((?:Adobe\.)?(?:CC\.[A-Za-z]+|SparklerApp|UWPAssets)"
                         r"(?:_[\w.-]+)?)", re.IGNORECASE)


def _to_int(value: str) -> Optional[int]:
    try:
        return int(value, 0) if value.casefold().startswith("0x") else int(value)
    except (TypeError, ValueError):
        return None


def parse_failure(text: str) -> Optional[AdobeFailure]:
    """Достаёт из текста журнала Adobe код, шаг и OS-код Appx.

    Журнал Adobe — это не только «код 191»: рядом печатается имя шага
    (``AddUWPAppxCommand``), имя пакета и OS-код Windows. Именно они
    объясняют, чего не хватило этому компьютеру, поэтому разбираем их
    отдельно, а не довольствуемся одним числом.
    """
    if not text:
        return None
    match = _CODE_RE.search(text)
    os_match = _OS_CODE_RE.search(text)
    path_match = _APPX_PATH_RE.search(text)
    if match is None and os_match is None and path_match is None:
        return None
    failure = AdobeFailure(raw=match.group(0) if match else "")
    if match is not None:
        failure.code = _to_int(match.group("code"))
        failure.command = (match.group("command") or "").strip()
        package = (match.group("package") or "").strip()
        if package:
            failure.package = package
    if os_match is not None:
        failure.os_code = _to_int(os_match.group("code").split("#")[0])
    if path_match is not None:
        failure.package_path = path_match.group("path").strip()
    if not failure.package:
        package_match = _PACKAGE_RE.search(
            " ".join(part for part in (failure.package_path, failure.command,
                                       text) if part))
        if package_match is not None:
            failure.package = package_match.group(1)
    return failure


def has_uwp_failure(text: str) -> bool:
    """True, если журнал говорит об отказе на UWP-шаге (код 191 и родня)."""
    failure = parse_failure(text)
    return bool(failure and failure.is_uwp)


# --- советы ------------------------------------------------------------------

def failure_hints(failure: Optional[AdobeFailure] = None,
                  *, applied: Optional[ApplyResult] = None,
                  payload_extracted: bool = False,
                  unpacker_missing: bool = False,
                  salvage_attempted: bool = False,
                  layout: Optional[AdobeLayout] = None) -> List[str]:
    """Что делать, если Adobe-установщик не дал файлов программы.

    Тексты намеренно конкретные: «код 191» — это не «не хватило прав», а
    конкретный шаг установки UWP-пакета, и советы должны говорить о нём.
    """
    hints: List[str] = []

    if failure is not None and failure.is_uwp:
        product = failure.product
        hints.append(
            "Код ошибки 191 — это не про командную строку и не про тихий "
            "режим: упал шаг AddUWPAppxCommand, то есть установка UWP-пакета "
            f"{product} ({failure.package or 'Appx'})."
            + (f" {failure.summary()}." if failure.summary() else "")
            + " Этому шагу нужны служба AppX (AppXSvc), разрешение на "
            "установку неопубликованных приложений, системный том и "
            "повышение прав: Adobe регистрирует пакет сразу для всех "
            "пользователей. Поэтому любые ключи тишины дают один и тот же "
            "код 191."
        )
    elif failure is not None and failure.code is not None:
        hints.append(
            f"Установщик Adobe вернул код {failure.code} — {failure.code_hint}."
            + (f" Дополнительно Windows сообщает: 0x{failure.os_code:08X} — "
               f"{failure.os_hint}." if failure.os_code is not None else ""))

    hints.append(
        "Портативу UWP-пакет не нужен и даже вреден: Windows регистрирует "
        "его на этом компьютере и для всех пользователей, а не «в папке». "
        "Portablizer ставит в App сами пакеты программы (MSI/ZIP из "
        "payloads), а Appx/MSIX пропускает. Сама программа Adobe — обычное "
        "Win32-приложение и без UWP-пакета запускается."
    )

    if applied is not None and applied.has_result:
        hints.append(
            f"Распаковка пакетов Adobe уже выполнена: {applied.summary()}. "
            "Если исполняемого файла в App всё же нет — посмотрите "
            "installer-output.log: там видно код каждого MSI."
        )
    if payload_extracted and (applied is None or not applied.has_result):
        hints.append(
            "Пакеты внутри установщика найти удалось, но ни один из них не "
            "дал файлов программы. Такое бывает, когда в сборке лежит только "
            "UWP-версия (Appx) без MSI: из неё портатив не собрать. Возьмите "
            "корпоративный пакет Adobe Admin Console (в нём есть "
            "Build\\payloads с MSI) или отдельный offline-установщик с MSI."
        )
    if layout is not None and layout.payload_dirs and not layout.msis:
        hints.append(
            "В каталоге payloads нет ни одного MSI — только архивы и "
            "UWP-пакеты. Если ZIP-пакеты тоже не дали файлов, эта сборка не "
            "содержит Win32-части программы."
        )
    if unpacker_missing:
        hints.append(
            "7-Zip на этом компьютере не найден: Portablizer не носит свой "
            "распаковщик и не скачивает его из сети. Без 7-Zip содержимое "
            "установщика Adobe достать нечем, и остаётся только запуск "
            "установщика — а он упирается в UWP-шаг (код 191). Установите "
            "7-Zip и повторите сборку."
        )
    if salvage_attempted and (applied is None or not applied.has_result):
        hints.append(
            "Распакованных пакетов не осталось и во временных каталогах "
            "Adobe (adobeTemp): установщик убрал их при откате. Запустите "
            "сборку ещё раз с установленным 7-Zip — тогда пакеты достаются "
            "из самого установщика, не запуская его."
        )

    hints.append(
        "Проверить причину на этом ПК можно так: служба «Служба "
        "развёртывания AppX» (AppXSvc) должна запускаться, а установка "
        "неопубликованных приложений — быть разрешена. Но даже после "
        "починки Windows UWP-часть останется привязанной к этому "
        "компьютеру: в портатив она не переносится."
    )
    hints.append(
        "Что не переедет в портатив вместе с Adobe XD: плитка в меню «Пуск» "
        "и другие UWP-точки входа, интеграция «Поделиться» и UWP-ассоциации "
        "файлов. Для запуска программы это не требуется. Сама программа "
        "по-прежнему требует входа в Creative Cloud и действующей подписки — "
        "это ограничение Adobe, а не сборки."
    )
    return hints


def language_locale(code: str) -> str:
    """Локаль Adobe (``ru_RU``) по коду языка Portablizer или пустая строка.

    У Adobe ``--INSTALLLANGUAGE`` принимает локаль вида ``en_US``/``fr_CA``, а
    не имя языка Inno (``russian``) и не LCID. Импорт внутри функции: модуль
    остаётся листовым, а ``languages`` уже зависит от ``detect``.
    """
    if not (code or "").strip():
        return ""
    from .languages import find_registry_profile

    profile = find_registry_profile(code)
    return profile.locale_underscore if profile is not None else ""


def note_text(app_name: str, applied: ApplyResult,
              failure: Optional[AdobeFailure] = None,
              source: str = "") -> str:
    """Текст файла ``adobe-uwp.txt`` — объяснение для человека."""
    lines = [
        f"{app_name or 'Adobe'}: сборка портатива без UWP-шага",
        "=" * 60,
        "",
        "Установщики Adobe ставят программу в два этапа: сначала обычные",
        "пакеты (MSI) в папку установки, затем UWP-пакет (Appx) — он",
        "регистрируется в Windows на этом компьютере и для всех",
        "пользователей (шаг AddUWPAppxCommand). Именно второй этап падает",
        "с «кодом ошибки 191» и отменяет установку целиком.",
        "",
        "Для портатива UWP-пакет не нужен, поэтому Portablizer поставил в",
        "App только пакеты самой программы, а UWP пропустил.",
        "",
        f"Итог: {applied.summary()}.",
    ]
    if source:
        lines.append(f"Источник пакетов: {source}")
    if applied.msi_ok:
        lines.append("Установленные пакеты MSI:")
        lines.extend(f"  • {name}" for name in applied.msi_ok)
    if applied.archives_ok:
        lines.append("Распакованные архивы:")
        lines.extend(f"  • {name}" for name in applied.archives_ok)
    if applied.skipped_uwp:
        lines.append("Пропущенные UWP-пакеты (это и есть обход кода 191):")
        lines.extend(f"  • {name}" for name in applied.skipped_uwp)
    if applied.msi_failed or applied.archives_failed:
        lines.append("Пакеты, которые не удалось разложить:")
        for name, reason in applied.msi_failed + applied.archives_failed:
            lines.append(f"  • {name} — {reason}")
    if failure is not None and failure.summary():
        lines.append("")
        lines.append("Что именно сказал установщик Adobe:")
        lines.append(f"  {failure.summary()}")
    lines.extend([
        "",
        "Чего в портативе не будет:",
        "  • плитки в меню «Пуск» и прочих UWP-точек входа;",
        "  • интеграции «Поделиться» и UWP-ассоциаций файлов.",
        "",
        "Запуск самой программы от этого не зависит, но вход в Creative",
        "Cloud и действующая подписка по-прежнему требуются: это условие",
        "Adobe, а не ограничение сборки.",
        "",
    ])
    return "\n".join(lines)
