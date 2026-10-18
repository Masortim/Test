"""Сетевые компоненты программ (VPN и подобных): драйверы адаптеров и службы.

Игры и обычные приложения после переноса в портатив не требуют от системы
ничего, кроме себя: их сохранения и настройки живут в ``PortableData``, реестр
подставляется на время запуска. У VPN-клиентов (Planeta VPN, OpenVPN и т. п.)
есть компоненты, которые **нельзя** виртуализовать:

* сетевой драйвер-мини-порт — TAP-Windows9/V6 (``tap0901``, издатель
  «TAP-Windows Provider V9» / OpenVPN Technologies — окно Windows Security на
  скриншоте пользователя показывает именно его установку), ovpn-dok или
  wintun;
* системную службу, через которую клиент поднимает адаптер и ставит маршруты.

Ядро Windows не «переносится в папку»: драйвер живёт в DriverStore, служба —
в реестре ``HKLM\\SYSTEM\\CurrentControlSet\\Services``. Поэтому надёжный
портатив поступает иначе: **забирает компоненты с собой и чинит систему на
месте**, а не притворяется, что имитировал.

Что делает модуль:

1. :func:`scan_net_driver_packages` — находит пакет драйвера внутри
   установленной программы (``.inf`` с ``Class=Net`` и опознаваемым
   издателем/hwid, рядом лежащие ``.sys``/``.cat``/``.dll``, утилиты
   ``tapinstall.exe``/``devcon.exe`` и запасные установщики пакетов).
2. :func:`collect_companion_services` — берёт службы, которые установщик
   зарегистрировал НА ЭТОМ ПК и чей бинарник лежит в папке портатива
   (``procutil.services_in``), и переписывает их ``ImagePath`` на маркер
   ``@@PORTABLE_ROOT@@``. После сборки Portablizer снимает эти службы с
   регистрации, чтобы компьютер-сборщик остался чистым.
3. :func:`provision_netstack` — складывает всё в ``NetStack/`` портатива:
   копии пакетов драйверов, ``netstack.json`` (манифест) и скрипты —
   ``Setup.cmd`` (проверить и досоздать недостающее; службы регистрирует и
   запускает ``NetStackServices.ps1``) и ``Teardown.cmd`` (снимает с
   регистрации ТОЛЬКО то, что создал портатив). Сами драйверы остаются в
   системе осознанно — это общий компонент, как пакеты Visual C++ из
   ``Redist``; вырывать его из DriverStore после каждого сеанса значит ломать
   чужие VPN.

Весь разбор, сортировка и генерация скриптов — чистые функции: они работают
на любой ОС и покрываются тестами; обращение к реестру Windows изолировано в
:func:`read_service_registry_records`.
"""
from __future__ import annotations

import json
import ntpath
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform.startswith("win")

#: Маркер папки портатива в путях из манифеста (тот же, что в .reg-файлах).
ROOT_TOKEN = "@@PORTABLE_ROOT@@"

#: Папка компонентов внутри портатива (рядом с App/ и PortableData/).
NETSTACK_DIR_NAME = "NetStack"
DRIVERS_SUBDIR = "Drivers"
BIN_SUBDIR = "bin"
PACKAGES_SUBDIR = "Packages"
#: Манифест, скрипты и состояние.
MANIFEST_NAME = "netstack.json"
SETUP_SCRIPT_NAME = "Setup.cmd"
TEARDOWN_SCRIPT_NAME = "Teardown.cmd"
SERVICES_SCRIPT_NAME = "NetStackServices.ps1"
#: Живучее состояние (какие службы создал ЭТОТ ПК) — не рядом со скриптами,
#: а в PortableData: папку портатива копируют на другой компьютер, а службы
#: — локальны для каждой машины.
STATE_DIR_NAME = "NetStack"
CREATED_SERVICES_FILE = "created-services.txt"

#: Маркеры изолированного сеанса (PortableData\\NetStack\\): какие пакеты
#: опубликовал ЭТОТ портатив и что не удалось снять с системы по итогам.
DRIVER_PACKAGES_FILE = "driver-packages.txt"
PENDING_DRIVER_FILE = "pending-driver.txt"
#: Временные снимки %SystemRoot%\\INF перед установкой и после (diff =
#: наши опубликованные пакеты). Локальны для машины-сборки по смыслу.
SNAPSHOT_PRE_FILE = "ns_pre.tmp"
SNAPSHOT_POST_FILE = "ns_post.tmp"
#: hwid устройств, которые портатив создаёт в этом сеансе: по нему
#: .ps1 сопоставляет вновь опубликованные пакеты с адаптерами.
SNAPSHOT_IDS_FILE = "ns_ids.txt"

# --- виды драйверов -------------------------------------------------------------

#: TAP-Windows (OpenVPN): классический NDIS-мини-порт ``tap0901``.
KIND_TAP_WINDOWS = "tap-windows"
#: OpenVPN Data Channel Offload (ovpn-dok) — современный драйвер 2.6+.
KIND_OVPN_DCO = "ovpn-dco"
#: Wintun — пользовательский туннель: адаптер создаёт само приложение,
#: установка в DriverStore не нужна.
KIND_WINTUN = "wintun"
#: Пустой вид: «не наш».
KIND_OTHER = ""

#: Порядок обработки: сначала то, без чего VPN не поднимется вовсе.
KIND_ORDER = (KIND_TAP_WINDOWS, KIND_OVPN_DCO, KIND_WINTUN)

#: Служебное имя драйвера по умолчанию для каждого вида (ключ Services\\...).
KIND_DEFAULT_SERVICE = {
    KIND_TAP_WINDOWS: "tap0901",
    KIND_OVPN_DCO: "ovpn-dco",
    KIND_WINTUN: "Wintun",
}

#: Имена файлов пакетов/утилит, выдающие VPN-стек с головой.
_TOOL_NAMES = ("tapinstall.exe", "devcon.exe", "devcon64.exe", "tapctl.exe")
_PACKAGE_RE = re.compile(
    r"(tap-windows[\w.\-]*\.(exe|msi)|tapinstall[\w.\-]*\.(exe|msi)|"
    r"wintun[\w.\-]*\.(exe|msi|cab)|ovpn-dok[\w.\-]*\.(exe|msi))$",
    re.IGNORECASE)

# --- разбор .inf -----------------------------------------------------------------

_INF_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*(?:;.*)?$")
_INF_ASSIGN_RE = re.compile(r"^\s*([^=;]+?)\s*=\s*(.*?)\s*(?:;.*)?$")

_HWID_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    (KIND_TAP_WINDOWS,
     re.compile(r"\btap0901\b|\btapadapter\w*\b", re.IGNORECASE)),
    (KIND_OVPN_DCO,
     re.compile(r"\bovpn-dco\b|\bovpn-dok\b|\bovpn_dco\b", re.IGNORECASE)),
    (KIND_WINTUN, re.compile(r"\bwintun\b", re.IGNORECASE)),
)
_NET_PROVIDER_RE = re.compile(
    r"openvpn|tap-windows|tarent|wintun|softether", re.IGNORECASE)
_TAP_SERVICE_RE = re.compile(r"\btap0901\b", re.IGNORECASE)

#: Секции, где лежат строки для раскрытия ``%TOKEN%`` в реальном .inf.
_STRINGS_SECTIONS = frozenset({
    "strings", "tapstrings", "device.desc", "devicedescs", "manufacturer",
    "model",
})

_MAX_INF_BYTES = 400_000
_MAX_PACKAGES = 8
_MAX_SIBLINGS = 80


@dataclass(frozen=True)
class InfMeta:
    """Что важно знать о сетевом ``.inf`` из портатива."""

    kind: str
    #: Издатель из ``Provider`` (после раскрытия %строк%).
    provider: str = ""
    #: Имя службы драйвера (``tap0901``); пусто — по умолчанию для вида.
    service: str = ""
    #: Hardware ID корневого устройства (``tap0901`` для ``root\\tap0901``).
    device_id: str = ""
    #: Class из [Version]; сетевые пакеты — ``Net``.
    class_name: str = ""
    catalog: str = ""

    @property
    def usable(self) -> bool:
        """True, если пакет относится к VPN-стеку и его есть чем ставить."""
        return self.kind in KIND_ORDER

    @property
    def needs_install(self) -> bool:
        """Wintun поднимает сама программа; остальным нужен DriverStore."""
        return self.kind in (KIND_TAP_WINDOWS, KIND_OVPN_DCO)


def parse_net_inf(text: str) -> InfMeta:
    """Минимальный разбор ``.inf``: [Version] + раскрытие %строк%.

    Полноценный парсер INF не нужен: важны пять полей и наличие характерных
    идентификаторов. Раскрываются ``%TOKEN%`` из секций ``[Strings]``-семейства
    — издатель в реальных пакетах записан именно так
    (``Provider=%TapProvider%``).
    """
    version: Dict[str, str] = {}
    strings: Dict[str, str] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        matched = _INF_SECTION_RE.match(line)
        if matched:
            section = matched.group(1).strip().lower()
            continue
        assign = _INF_ASSIGN_RE.match(line)
        if not assign:
            continue
        key = assign.group(1).strip()
        value = assign.group(2).strip()
        if section == "version":
            version[key.lower()] = value
        elif section in _STRINGS_SECTIONS:
            strings.setdefault(key, value.strip('"').strip())
    resolved = version.get("provider", "")
    for token, replacement in strings.items():
        if f"%{token}%" in resolved:
            resolved = resolved.replace(f"%{token}%", replacement)

    class_name = version.get("class", "").strip()
    kind = KIND_OTHER
    if not class_name or class_name.lower() in ("net", "netservice"):
        for candidate, pattern in _HWID_PATTERNS:
            if pattern.search(text):
                kind = candidate
                break
        if (kind == KIND_OTHER and resolved
                and _NET_PROVIDER_RE.search(resolved)):
            kind = KIND_TAP_WINDOWS

    service = KIND_DEFAULT_SERVICE.get(kind, "")
    device_id = ""
    if kind == KIND_TAP_WINDOWS:
        if _TAP_SERVICE_RE.search(text):
            service = "tap0901"
            device_id = "tap0901"
    elif kind == KIND_OVPN_DCO:
        device_id = "ovpn-dco"
    return InfMeta(kind=kind, provider=resolved, service=service,
                   device_id=device_id, class_name=class_name,
                   catalog=version.get("catalogfile", ""))


# --- сканирование установленной программы ---------------------------------------

@dataclass
class NetDriverPackage:
    """Один пакет сетевого драйвера, найденный в ``App/``."""

    kind: str
    provider: str = ""
    service: str = ""
    device_id: str = ""
    #: Путь к ``.inf`` внутри папки портатива (``App/driver/OemVista.inf``).
    inf_rel: str = ""
    #: Соседи инф-файла, которые нужно взять с собой (пути внутри App).
    files: List[str] = field(default_factory=list)
    #: tapinstall/devcon, если вендор положил утилиту рядом.
    tool_rel: str = ""
    #: Запас: полный установщик пакета (``tap-windows-9.*.exe`` и т. п.).
    installer_rel: str = ""

    @property
    def needs_install(self) -> bool:
        return self.kind in (KIND_TAP_WINDOWS, KIND_OVPN_DCO)

    @property
    def check_service(self) -> str:
        """Ключ ``Services\\...``, по которому проверяют «драйвер есть»."""
        return self.service or KIND_DEFAULT_SERVICE.get(self.kind, "")


def _rel(path: str, base: str) -> str:
    try:
        return os.path.relpath(path, base).replace(os.sep, "/")
    except ValueError:
        return path.replace("\\", "/")


def scan_net_driver_packages(app_dir: str, max_files: int = 20_000
                             ) -> List[NetDriverPackage]:
    """Ищет в установленной программе пакеты VPN-драйверов.

    Сканируются только ``.inf``; «своими» считаются пакеты с узнаваемым
    издателем (OpenVPN/TAP/wintun) и характерными идентификаторами — чужие
    сетевые драйверы (Wi-Fi и прочее) не трогаются. Рядом с пакетом
    подбираются утилиты (``tapinstall.exe``) и полные установщики пакетов:
    они служат запасным путём установки на чистом ПК.
    """
    if not app_dir or not os.path.isdir(app_dir):
        return []
    scanned = 0
    seen_inf: set = set()
    packages: List[NetDriverPackage] = []
    tools: List[str] = []
    installers: List[str] = []
    stop = False
    for current, dirs, files in os.walk(app_dir):
        if stop:
            break
        dirs.sort()
        for name in sorted(files):
            scanned += 1
            if scanned > max_files:
                stop = True
                break
            full = os.path.join(current, name)
            lowered = name.lower()
            if lowered in _TOOL_NAMES:
                tools.append(full)
                continue
            if _PACKAGE_RE.search(name):
                installers.append(full)
                continue
            if not lowered.endswith(".inf") or len(packages) >= _MAX_PACKAGES:
                continue
            if full in seen_inf:
                continue
            seen_inf.add(full)
            try:
                if os.path.getsize(full) > _MAX_INF_BYTES:
                    continue
                with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            meta = parse_net_inf(text)
            if not meta.usable:
                continue
            try:
                siblings = sorted(os.listdir(current))[:_MAX_SIBLINGS]
            except OSError:
                siblings = []
            files_rel = []
            for sibling in siblings:
                candidate = os.path.join(current, sibling)
                if os.path.isfile(candidate) and sibling != name:
                    files_rel.append(_rel(candidate, app_dir))
            packages.append(NetDriverPackage(
                kind=meta.kind, provider=meta.provider,
                service=meta.service, device_id=meta.device_id,
                inf_rel=_rel(full, app_dir), files=files_rel))

    for package in packages:
        for tool in tools:
            package.tool_rel = _rel(tool, app_dir)
            break
        if installers:
            package.installer_rel = _rel(installers[0], app_dir)
    order = {kind: index for index, kind in enumerate(KIND_ORDER)}
    packages.sort(key=lambda p: (order.get(p.kind, len(order)), p.service))
    deduped: List[NetDriverPackage] = []
    seen_key: set = set()
    for package in packages:
        key = (package.kind, package.check_service)
        if key in seen_key:
            continue
        seen_key.add(key)
        deduped.append(package)
    return deduped


# --- службы-компаньоны -------------------------------------------------------------

@dataclass
class ServiceRecord:
    """Служба Windows, которую портатив переносит «как свою»."""

    name: str
    display: str = ""
    #: Путь к бинарнику с маркером ``@@PORTABLE_ROOT@@``.
    image: str = ""
    #: Аргументы командной строки (``--service`` и т. п.).
    args: str = ""
    #: ``demand`` (ручной запуск) или ``auto`` — как было у установщика.
    start: str = "demand"

    def to_dict(self) -> Dict[str, str]:
        return {"name": self.name, "display": self.display,
                "image": self.image, "args": self.args, "start": self.start}

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "ServiceRecord":
        return cls(
            name=str(data.get("name", "")),
            display=str(data.get("display", "")),
            image=str(data.get("image", "")),
            args=str(data.get("args", "")),
            start=str(data.get("start", "demand")) or "demand",
        )


def retarget_service_image(image: str, app_dir: str,
                           root_token: str = ROOT_TOKEN
                           ) -> Optional[Tuple[str, str]]:
    """Переписывает ``ImagePath`` службы на папку портатива.

    Возвращает ``(портативный путь с маркером, аргументы)`` или
    :data:`None`, если бинарник лежит вне портатива: такие службы не
    переносятся — они принадлежат системе, а не программе.
    """
    raw = str(image or "").strip().replace("\\??\\", "")
    if not raw:
        return None
    if raw.startswith('"'):
        closing = raw.find('"', 1)
        if closing <= 1:
            return None
        path, args = raw[1:closing], raw[closing + 1:].strip()
    else:
        cut = raw.lower().find(".exe")
        if cut < 0:
            path, args = raw.split(" ")[0], ""
        else:
            path, args = raw[:cut + 4], raw[cut + 4:].strip()
    if not path or path.casefold().startswith("\\systemroot"):
        return None
    # Пути сравниваем по Windows-синтаксису намеренно (ntpath, а не os.path):
    # реальный реестр службы приходит в синтаксисе Windows даже в тестах на
    # Linux, а normpath приводит и «нативные» тестовые пути к единому виду.
    cand_n = ntpath.normpath(path)
    app_n = ntpath.normpath(app_dir)
    if not (ntpath.normcase(cand_n).startswith(ntpath.normcase(app_n) + "\\")
            or ntpath.normcase(cand_n) == ntpath.normcase(app_n)):
        return None
    relative = ntpath.relpath(cand_n, app_n)
    portable = f"{root_token}\\App\\{relative}"
    args = args.strip()
    if args and not re.match(r"^[A-Za-z0-9 ._:=/\\@%+-]+$", args):
        args = ""
    return portable, args


def build_service_records(app_dir: str,
                          raw_records: Sequence[Dict[str, object]],
                          root_token: str = ROOT_TOKEN
                          ) -> List[ServiceRecord]:
    """Превращает снимок реестра служб в манифест портатива.

    ``raw_records`` — словари ``{name, display_name, image_path, start, type}``
    (``start`` — DWORD из реестра: 2=auto, 3=demand). Службы ядра (type
    1/2/4/8) отсекаются: их ставит inf-пакет, а не ``sc create``.
    """
    records: List[ServiceRecord] = []
    for entry in raw_records:
        try:
            stype = int(entry.get("type", 16) or 16)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            stype = 16
        if stype in (1, 2, 4, 8):  # kernel / filesystem / paging / boot-start
            continue
        retargeted = retarget_service_image(str(entry.get("image_path", "")),
                                            app_dir, root_token)
        if retargeted is None:
            continue
        image, args = retargeted
        try:
            start_code = int(entry.get("start", 3) or 3)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            start_code = 3
        records.append(ServiceRecord(
            name=str(entry.get("name", "")).strip(),
            display=str(entry.get("display_name", "")).strip(),
            image=image, args=args,
            start="auto" if start_code in (0, 1, 2) else "demand"))
    return [record for record in records if record.name]


def read_service_registry_records(names: Sequence[str]) -> List[Dict[str, object]]:
    """Читает записи служб из ``HKLM\\SYSTEM\\CurrentControlSet\\Services``.

    Только Windows; на других ОС и при любой ошибке — пустой список.
    """
    if not IS_WINDOWS or not names:
        return []
    try:
        import winreg  # type: ignore

        result: List[Dict[str, object]] = []
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services") as services:
            for name in names:
                record: Dict[str, object] = {"name": name}
                try:
                    with winreg.OpenKey(services, name) as key:
                        for value, field_name in (
                                ("ImagePath", "image_path"),
                                ("DisplayName", "display_name"),
                                ("Start", "start"),
                                ("Type", "type"),
                        ):
                            try:
                                record[field_name] = winreg.QueryValueEx(
                                    key, value)[0]
                            except OSError:
                                continue
                except OSError:
                    continue
                result.append(record)
        return result
    except Exception:  # noqa: BLE001 — доступ к реестру не роняет сборку
        return []


def collect_companion_services(app_dir: str,
                               names: Sequence[str]) -> List[ServiceRecord]:
    """Службы, чей бинарник лежит в ``App/``, — то, что портатив «забирает».

    Возвращает записи с путями, переписанными на маркер портатива.
    """
    raw = read_service_registry_records(names)
    return build_service_records(app_dir, raw)


# --- отчёт и манифест ----------------------------------------------------------------

@dataclass
class NetStackReport:
    """Итог переноса сетевых компонентов; из него рождается секция ``netstack``."""

    drivers: List[Dict[str, str]] = field(default_factory=list)
    services: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    manifest_rel: str = f"{NETSTACK_DIR_NAME}/{MANIFEST_NAME}"
    setup_rel: str = f"{NETSTACK_DIR_NAME}/{SETUP_SCRIPT_NAME}"
    teardown_rel: str = f"{NETSTACK_DIR_NAME}/{TEARDOWN_SCRIPT_NAME}"
    #: Скрипты реально записаны (нет диска/прав — и у лончера работы нет).
    written: bool = False
    #: "session" — изолированный портативный режим: пакет драйвера публикуется
    #: только на время сеанса и снимается с системы по его завершении;
    #: "shared" — драйвер остаётся общим системным компонентом (Redist-style).
    isolation: str = "session"

    @property
    def needed(self) -> bool:
        return bool(self.drivers or self.services)

    def to_config(self) -> Dict[str, object]:
        return {
            "manifest": self.manifest_rel,
            "setup": self.setup_rel,
            "teardown": self.teardown_rel,
            # Какие ключи Services\ должны существовать на каждом ПК.
            "driver_services": [
                entry.get("service", "") for entry in self.drivers
                if entry.get("needs_install") == "1" and entry.get("service")
            ],
            "service_names": [entry.get("name", "")
                              for entry in self.services if entry.get("name")],
            # Портатив снимает «свои» службы по завершении сеанса: чистый
            # компьютер-носитель важнее пары секунд на переподключение.
            # В изолированном режиме teardown нужен и без служб — именно он
            # убирает драйвер и адаптер с машины.
            "stop_on_exit": bool(self.services) or (
                self.isolation == "session" and any(
                    d.get("needs_install") == "1" for d in self.drivers)),
            # Секция для лончера/ENTRY: по ней решают, вызывать ли Teardown
            # без маркера служб и чинить ли осевший после сбоя сеанс.
            "isolation": self.isolation,
        }


def _entry_for_package(package: NetDriverPackage) -> Dict[str, str]:
    return {
        "kind": package.kind,
        "provider": package.provider,
        "service": package.check_service,
        "device_id": package.device_id,
        "needs_install": "1" if package.needs_install else "",
        "inf": package.inf_rel,
        "tool": package.tool_rel,
        "installer": package.installer_rel,
    }


def provision_netstack(portable_dir: str, app_dir: str,
                       packages: Sequence[NetDriverPackage],
                       services: Sequence[ServiceRecord],
                       isolated: bool = True) -> Optional[NetStackReport]:
    """Собирает ``NetStack/``: копии пакетов, манифест, Setup/Teardown.

    Файлы **копируются** (не переносятся): программа ждёт свои драйверы внутри
    ``App/``, а портатив должен уметь чинить систему и после того, как его
    скопировали на другой компьютер.

    ``isolated=True`` — изолированный портативный режим: драйвер публикуется
    из папки портатива только на время сеанса, по завершении сеанса
    ``Teardown`` снимает устройства адаптера и сам пакет из DriverStore, так
    что хост возвращается в состояние «до запуска». ``isolated=False`` —
    прошлое поведение «общего компонента»: драйвер остаётся в системе.
    """
    report = NetStackReport()
    report.isolation = "session" if isolated else "shared"
    if not packages and not services:
        return None

    netstack_dir = os.path.join(portable_dir, NETSTACK_DIR_NAME)
    drivers_root = os.path.join(netstack_dir, DRIVERS_SUBDIR)
    copied_any = False
    for package in packages:
        entry = _entry_for_package(package)
        dest_dir = os.path.join(drivers_root, package.kind or "other")
        try:
            os.makedirs(dest_dir, exist_ok=True)
            source_inf = os.path.join(app_dir,
                                      package.inf_rel.replace("/", os.sep))
            if os.path.isfile(source_inf):
                shutil.copy2(
                    source_inf,
                    os.path.join(dest_dir, os.path.basename(source_inf)))
                entry["inf"] = (f"{NETSTACK_DIR_NAME}/{DRIVERS_SUBDIR}/"
                                f"{package.kind or 'other'}/"
                                f"{os.path.basename(source_inf)}")
                copied_any = True
            for rel in package.files[:_MAX_SIBLINGS]:
                src = os.path.join(app_dir, rel.replace("/", os.sep))
                if os.path.isfile(src):
                    shutil.copy2(src,
                                 os.path.join(dest_dir, os.path.basename(src)))
        except OSError as exc:
            report.notes.append(
                f"пакет {package.kind}: часть файлов не скопирована ({exc})")
        if package.tool_rel:
            tool_dest = os.path.join(netstack_dir, BIN_SUBDIR)
            try:
                os.makedirs(tool_dest, exist_ok=True)
                src = os.path.join(app_dir,
                                   package.tool_rel.replace("/", os.sep))
                if os.path.isfile(src):
                    shutil.copy2(src,
                                 os.path.join(tool_dest, os.path.basename(src)))
                    entry["tool"] = (f"{NETSTACK_DIR_NAME}/{BIN_SUBDIR}/"
                                     f"{os.path.basename(src)}")
            except OSError:
                entry["tool"] = ""
        if package.installer_rel:
            pkg_dest = os.path.join(netstack_dir, PACKAGES_SUBDIR)
            try:
                os.makedirs(pkg_dest, exist_ok=True)
                src = os.path.join(app_dir,
                                   package.installer_rel.replace("/", os.sep))
                if os.path.isfile(src):
                    shutil.copy2(src,
                                 os.path.join(pkg_dest, os.path.basename(src)))
                    entry["installer"] = (f"{NETSTACK_DIR_NAME}/"
                                          f"{PACKAGES_SUBDIR}/"
                                          f"{os.path.basename(src)}")
            except OSError:
                entry["installer"] = ""
        if not copied_any and entry.get("needs_install") == "1":
            report.notes.append(
                f"пакет {package.kind}: установщик не найден в App — "
                "на чистом ПК драйвер придётся ставить вручную")
        report.drivers.append(entry)

    report.services = [record.to_dict() for record in services]
    report.written = bool(copied_any or services)
    if not report.written:
        return None

    try:
        os.makedirs(netstack_dir, exist_ok=True)
        manifest = {
            "schema": 1,
            "isolation": report.isolation,
            "root_token": ROOT_TOKEN,
            "drivers": report.drivers,
            "services": report.services,
            "state_dir": f"PortableData/{STATE_DIR_NAME}",
            "created_services_file": CREATED_SERVICES_FILE,
        }
        with open(os.path.join(netstack_dir, MANIFEST_NAME), "w",
                  encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        # .ps1 — с BOM: PowerShell 5 читает UTF-8 без BOM как ANSI, и
        # русские сообщения в выводе превращаются в кракозябры.
        with open(os.path.join(netstack_dir, SERVICES_SCRIPT_NAME), "w",
                  encoding="utf-8-sig", newline="\r\n") as fh:
            fh.write(render_services_ps1())
        with open(os.path.join(netstack_dir, SETUP_SCRIPT_NAME), "w",
                  encoding="ascii", errors="replace", newline="") as fh:
            fh.write(render_setup_cmd(report))
        with open(os.path.join(netstack_dir, TEARDOWN_SCRIPT_NAME), "w",
                  encoding="ascii", errors="replace", newline="") as fh:
            fh.write(render_teardown_cmd(report))
    except OSError as exc:
        report.notes.append(f"NetStack: не удалось записать скрипты ({exc})")
        report.written = False
    return report


# --- генерация скриптов -----------------------------------------------------------
#
# .cmd-файлы строго ASCII и CRLF (как Launch.bat: cmd.exe читает .bat по
# байтовым смещениям), пути с кириллицей в них не встраиваются — только
# относительные внутри NetStack/. Абсолютные пути раскрываются на целевом ПК
# через %PORTABLE_ROOT% (cmd) и через манифест (PowerShell). Скрипты
# идемпотентны: второй запуск не переустанавливает то, что уже стоит, а
# --check позволяет лончеру решить, нужен ли UAC вообще, не показывая его зря.

def _ascii_token(text: str, limit: int = 120) -> str:
    """Только печатный ASCII без «опасных» символов cmd — для echo/меток."""
    cleaned = "".join(
        ch for ch in str(text)
        if 32 <= ord(ch) < 127 and ch not in '%&|<>^()"')
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]


def _netstack_path_expr(rel: str) -> str:
    """Путь ``NetStack/x/y.inf`` -> ``"%NETSTACK_ROOT%x\\y.inf"``.

    В .cmd встраиваются только относительные части внутри NetStack (они
    генерируются нами и ASCII-ны), абсолютный путь раскрывается на месте.
    """
    rel = str(rel or "").strip()
    if not rel:
        return '""'
    if rel.startswith(NETSTACK_DIR_NAME):
        rel = rel[len(NETSTACK_DIR_NAME):]
    rel = rel.strip("/").replace("/", "\\")
    return f'"%NETSTACK_ROOT%{rel}"' if rel else '"%NETSTACK_ROOT%"'


def render_setup_cmd(report: NetStackReport) -> str:
    """``NetStack\\Setup.cmd``: доустановить драйверы, затем службы через .ps1.

    Режимы:

    * ``--check`` — только проверка наличия (права не нужны, ничего не
      меняется); код ``0`` — всё на месте, ``2``/``3``/``4`` — чего-то не
      хватает или не поставилось;
    * по умолчанию (и ``--elevated``) — установить недостающие пакеты
      драйверов и зарегистрировать/запустить службы.
    """
    lines = [
        "@echo off",
        "setlocal EnableExtensions",
        "rem NetStack setup: bundled network drivers (TAP-Windows and friends)",
        "rem plus the companion services, generated by Portablizer.",
        "rem   --check    verify only (no admin rights needed, no changes)",
        "rem   (default)  install what is missing; services go through the .ps1",
        'set "NETSTACK_MODE=%~1"',
        'set "NETSTACK_ROOT=%~dp0"',
        'set "PORTABLE_ROOT=%NETSTACK_ROOT%.."',
        'for %%I in ("%PORTABLE_ROOT%") do set "PORTABLE_ROOT=%%~fI"',
        'set "NETSTACK_STATE=%PORTABLE_ROOT%\\PortableData\\'
        + STATE_DIR_NAME + '"',
        'if not exist "%NETSTACK_STATE%" mkdir "%NETSTACK_STATE%" >nul 2>&1',
        'set "NETSTACK_RC=0"',
        "",
        "rem --check needs no elevation at all. The ensure pass asks UAC once",
        "rem for the whole batch, so nobody has to click through the device",
        'rem "install the software for this device" dialog by hand.',
        'if /i "%NETSTACK_MODE%" == "--check" goto netstack_pass',
        ">nul 2>&1 net session || (",
        "  powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"Start-Process -Verb RunAs -Wait -WindowStyle Hidden "
        "-FilePath '%~f0' -ArgumentList '--elevated'\" >nul 2>&1",
        "  goto netstack_done",
        ")",
        "",
        ":netstack_pass",
        'set "PNPMODERN=0"',
        'if exist "%SystemRoot%\\System32\\pnputil.exe" (',
        '  pnputil /? 2>nul | findstr /i /c:"/add-driver" >nul 2>&1 '
        '&& set "PNPMODERN=1"',
        ")",
    ]

    isolated = report.isolation == "session"
    if isolated:
        # Isolation bookkeeping: remember which oem*.inf packages EXIST before
        # we publish anything, so the difference afterwards is exactly what
        # this portable owns.  A driver that was already installed by another
        # program is used but never claimed, hence never removed either.
        lines += [
            "",
            "rem isolation: snapshot the driver store before publishing, so",
            "rem Teardown can remove exactly the packages this portable added.",
            'if /i not "%NETSTACK_MODE%" == "--check" (',
            '  dir /b "%SystemRoot%\INF\oem*.inf" ',
            '> "%NETSTACK_STATE\\' + SNAPSHOT_PRE_FILE + '" 2>nul',
            '  del "%NETSTACK_STATE\\' + SNAPSHOT_IDS_FILE + '" >nul 2>&1',
            ')',
        ]

    for index, driver in enumerate(report.drivers, start=1):
        kind = _ascii_token(driver.get("kind", "net")) or "net"
        service = _ascii_token(driver.get("service", ""))
        device = _ascii_token(driver.get("device_id", ""))
        inf = _ascii_token(driver.get("inf", ""))
        tool = _ascii_token(driver.get("tool", ""))
        installer = _ascii_token(driver.get("installer", ""))
        needs_install = driver.get("needs_install", "") == "1"
        lines += [
            "",
            f"rem --- driver package {kind}" + (f" ({service})" if service else ""),
        ]
        if not service or not needs_install:
            # Wintun и «чужие» пакеты: ставит их само приложение из App\.
            lines += [
                f"echo   [info] {kind}: installed by the application itself, "
                "nothing to do here",
            ]
            continue
        inf_path = _netstack_path_expr(inf)
        lines += [
            f'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}" '
            ">nul 2>&1",
            "if not errorlevel 1 goto netstack_after_driver_" + str(index),
            f"echo   [setup] driver service {service} is missing on this PC",
            'if /i "%NETSTACK_MODE%" == "--check" (',
            '  set "NETSTACK_RC=2"',
            "  goto netstack_after_driver_" + str(index),
            ")",
            *([f'echo {device}>> "%NETSTACK_STATE\\'
               f'{SNAPSHOT_IDS_FILE}"']
              if (isolated and device) else []),
            "rem 1) put the package into the driver store and let PnP install it",
            'if "%PNPMODERN%" == "1" (',
            f"  if exist {inf_path} pnputil /add-driver {inf_path} /install "
            f">> \"%NETSTACK_STATE%\\setup.log\" 2>&1",
            f") else if exist {inf_path} pnputil -i -a {inf_path}",
            "rem 2) create the root-enumerated adapter (the addtap.bat step)",
        ]
        if device:
            lines += [
                'if "%PNPMODERN%" == "1" pnputil /add-device root\\'
                f'{device} >> "%NETSTACK_STATE%\\setup.log" 2>&1',
            ]
        if tool:
            tool_path = _netstack_path_expr(tool)
            hwid = device or service or "tap0901"
            lines += [
                f'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}" '
                ">nul 2>&1",
                f"if errorlevel 1 if exist {tool_path} "
                f"{tool_path} install {inf_path} {hwid} "
                ">> \"%NETSTACK_STATE%\\setup.log\" 2>&1",
            ]
        if installer:
            inst_path = _netstack_path_expr(installer)
            lines += [
                f'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}" '
                ">nul 2>&1",
                f"if errorlevel 1 if exist {inst_path} (",
                "  echo   [setup] running the bundled package installer",
                f'  start "" /wait {inst_path} /S /NCRC',
                ")",
            ]
        # Честная проверка результата: не верим на слово ни pnputil, ни
        # tapinstall — «поставлено» только если ключ службы появился.
        lines += [
            f'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}" '
            ">nul 2>&1",
            "if errorlevel 1 (",
            f"  echo   [warn] driver service {service} still missing after "
            "all attempts",
            '  set "NETSTACK_RC=3"',
            ")",
            f":netstack_after_driver_{index}",
        ]

    services_script = f'"%NETSTACK_ROOT%{SERVICES_SCRIPT_NAME}"'
    if isolated:
        # Дифф снимков INF делает .ps1: свои пути он выводит из
        # $PSScriptRoot, поэтому кириллица в имени папки портатива не
        # зависит от кодовой страницы cmd, а содержимое снимков — ASCII.
        lines += [
            "",
            "rem --- ownership: publish what is ours, keep what is not ---------",
            'if /i not "%NETSTACK_MODE%" == "--check" (',
            '  dir /b "%SystemRoot%\\INF\\oem*.inf" '
            '> "%NETSTACK_STATE\\' + SNAPSHOT_POST_FILE + '" 2>nul',
            "  powershell -NoProfile -ExecutionPolicy Bypass -File "
            f"{services_script} -Mode ownership",
            ")",
        ]

    lines += [
        "",
        "rem --- companion services (registered from the portable folder) ------",
        'set "PS_MODE=ensure"',
        'if /i "%NETSTACK_MODE%" == "--check" set "PS_MODE=check"',
        f"powershell -NoProfile -ExecutionPolicy Bypass -File "
        f"{services_script} -Mode %PS_MODE%",
        "if errorlevel 4 set \"NETSTACK_RC=4\"",
        "rem Re-verify honestly: services that still do not exist keep the",
        "rem exit code at 4, the launcher asks UAC only when it really helps.",
        'if /i not "%NETSTACK_MODE%" == "--check" (',
        f"  powershell -NoProfile -ExecutionPolicy Bypass -File "
        f"{services_script} -Mode check >nul 2>&1",
        "  if errorlevel 4 set \"NETSTACK_RC=4\"",
        ")",
        "",
        'if /i not "%NETSTACK_MODE%" == "--check" echo   NetStack ready.',
        ":netstack_done",
        "endlocal & exit /b %NETSTACK_RC%",
        "",
    ]
    return "\r\n".join(lines)


def render_teardown_cmd(report: NetStackReport) -> str:
    """``NetStack\\Teardown.cmd``: снять с регистрации службы и — в
    изолированном режиме — устройства адаптеров и сами пакеты драйверов.

    * ``isolation == "session"`` (портативный изолированный режим по умолчанию):
      всё, что портатив опубликовал на этом ПК, с этого ПК и уходит:
      корневые устройства ``root\\<devid>`` снимаются, пакеты удаляются из
      DriverStore (``pnputil /delete-driver <oem> /uninstall /force``), службы
      снимаются с регистрации. Если драйвер ещё кем-то используется, удаление
      откладывается: маркер ``pending-driver.txt`` остаётся, и следующий
      выход из сеанса попробует снова. Чужие драйверы (уже установленные
      другими программами) портатив не трогает — они ему не принадлежат.
    * ``isolation == "shared"``: прошлое поведение — службы снимаются, пакет
      остаётся общим системным компонентом (как распространяемые Visual C++);
      флаг ``--remove-device`` дополнительно гасит корневые устройства.
    """
    isolated = report.isolation == "session"
    lines = [
        "@echo off",
        "setlocal EnableExtensions",
        "rem NetStack teardown: stops and unregisters ONLY the services this",
        "rem portable created on this PC (PortableData\\NetStack\\"
        + CREATED_SERVICES_FILE + ").",
    ]
    if isolated:
        lines += [
            "rem Isolated session mode: adapter devices and the driver packages",
            "rem THIS portable published go away too, so the host keeps nothing.",
            "rem Pass --keep-driver to leave the driver installed (next session",
            "rem starts without UAC); services are still unregistered.",
        ]
    else:
        lines += [
            "rem Driver packages are shared system components and are kept.",
            "rem Pass --remove-device to also delete the root-enumerated adapters.",
        ]
    lines += [
        'set "NETSTACK_ROOT=%~dp0"',
        'set "PORTABLE_ROOT=%NETSTACK_ROOT%.."',
        'for %%I in ("%PORTABLE_ROOT%") do set "PORTABLE_ROOT=%%~fI"',
        'set "NETSTACK_STATE=%PORTABLE_ROOT%\\PortableData\\'
        + STATE_DIR_NAME + '"',
        "rem The flag is scanned in every argument, not just %~1: after the",
        "rem UAC re-run the first slot is taken by --elevated.",
        'set "TEARDOWN_MODE="',
        ('for %%A in (%*) do if /i "%%~A" == "--keep-driver" '
         'set "TEARDOWN_MODE=--keep-driver"' if isolated else
         'for %%A in (%*) do if /i "%%~A" == "--remove-device" '
         'set "TEARDOWN_MODE=--remove-device"'),
        ">nul 2>&1 net session || (",
        "  powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"Start-Process -Verb RunAs -Wait -WindowStyle Hidden "
        "-FilePath '%~f0' -ArgumentList '--elevated %TEARDOWN_MODE%'\" >nul 2>&1",
        "  exit /b 0",
        ")",
        "",
        "rem Companion services first: the .ps1 knows exactly what Setup",
        "rem created on THIS machine and removes nothing else.",
        'powershell -NoProfile -ExecutionPolicy Bypass -File '
        '"%NETSTACK_ROOT%' + SERVICES_SCRIPT_NAME + '" -Mode teardown',
        "",
    ]
    if isolated:
        lines += [
            "rem --- rollback of what THIS portable published (devices first, ",
            "rem then the packages; the .ps1 keeps only what is really ours) --",
            'if "%TEARDOWN_MODE%" == "--keep-driver" exit /b 0',
            'powershell -NoProfile -ExecutionPolicy Bypass -File '
            '"%NETSTACK_ROOT%' + SERVICES_SCRIPT_NAME + '" -Mode rollback',
            "exit /b 0",
            "",
        ]
    else:
        lines += [
            'if /i not "%TEARDOWN_MODE%" == "--remove-device" exit /b 0',
        ]
        for driver in report.drivers:
            device = _ascii_token(driver.get("device_id", ""))
            service = _ascii_token(driver.get("service", ""))
            if not service:
                continue
            lines += [
                "rem detach the adapter instance created for this package (best",
                "rem effort: a busy adapter simply refuses and stays)",
                f'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}" '
                ">nul 2>&1",
                "if not errorlevel 1 (",
            ]
            if device:
                lines += [
                    f'  pnputil /remove-device "root\\{device}" >nul 2>&1',
                ]
            else:
                lines += ["  rem no device id - nothing to detach"]
            lines += [")"]
        lines += ["exit /b 0", ""]
    return "\r\n".join(lines)


#: PowerShell-скрипт служб-компаньонов и изоляционного учёта драйверов.
#: Данные берутся из ``netstack.json`` (путь портатива раскрывается на
#: месте, поэтому кириллица в путях не ломается), решения о том, что
#: создавать и что снимать, — из состояния машины и маркеров сеанса.
_PS1_BODY = r'''
# NetStack companion services and isolation bookkeeping. Generated by Portablizer.
# Modes: ensure (default) | check | teardown | ownership | rollback.
# Paths come from $PSScriptRoot, so a portable folder with a Russian name works:
# the .cmd side stays ASCII, all Unicode lives in netstack.json.
param([string]$Mode = 'ensure')
$ErrorActionPreference = 'SilentlyContinue'
$here = $PSScriptRoot
$manifestPath = Join-Path $here 'netstack.json'
if (-not (Get-Command ConvertFrom-Json)) { exit 5 }
if (-not (Test-Path -LiteralPath $manifestPath)) { exit 0 }
$cfg = Get-Content -Raw -LiteralPath $manifestPath |
     ConvertFrom-Json
$root = (Resolve-Path (Join-Path $here '..')).Path
$token = '@@PORTABLE_ROOT@@'
$stateDir = Join-Path $root 'PortableData\NetStack'
if (-not (Test-Path -LiteralPath $stateDir)) {
     New-Item -ItemType Directory -Path $stateDir | Out-Null }
$createdPath = Join-Path $stateDir 'created-services.txt'
$packagesPath = Join-Path $stateDir 'driver-packages.txt'
# --- ownership: what THIS portable published into the driver store ----------
# Setup snapshots %SystemRoot%\INF\oem*.inf before and after the install and
# remembers every root device it tried to create (ns_ids.txt). Everything that
# appeared in between belongs to this portable; drivers that already existed
# are used but never claimed - and therefore never removed on another host.
if ($Mode -eq 'ownership') {
     $pre = Join-Path $stateDir 'ns_pre.tmp'
     $post = Join-Path $stateDir 'ns_post.tmp'
     $idsPath = Join-Path $stateDir 'ns_ids.txt'
     if ((Test-Path -LiteralPath $pre) -and (Test-Path -LiteralPath $post)) {
          $old = @(Get-Content -LiteralPath $pre |
                 ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
          $new = @(Get-Content -LiteralPath $post |
                 ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
          $added = @($new | Where-Object { $old -notcontains $_ })
          $ids = @()
          if (Test-Path -LiteralPath $idsPath) {
               $ids = @(Get-Content -LiteralPath $idsPath |
                      ForEach-Object { $_.Trim() } | Where-Object { $_ })
          }
          $have = @()
          if (Test-Path -LiteralPath $packagesPath) {
               $have = @(Get-Content -LiteralPath $packagesPath |
                      ForEach-Object { (($_ -split '\s+')[0]).ToLower() })
          }
          for ($i = 0; $i -lt $added.Count; $i++) {
               if ($have -contains $added[$i]) { continue }
               $dev = ''
               if ($i -lt $ids.Count) { $dev = ' ' + $ids[$i] }
               Add-Content -LiteralPath $packagesPath `
                    -Value ($added[$i] + $dev) -Encoding ASCII
          }
     }
     Remove-Item -LiteralPath $pre, $post, $idsPath -Force `
          -ErrorAction SilentlyContinue
     exit 0
}
# --- rollback: take the session's driver back off this host ------------------
# Devices first (root-enumerated adapters belong to the package we published),
# then the published packages themselves. If the driver is still busy, the
# marker line stays and the next session end retries; a pending-driver.txt
# note keeps the story honest in the log.
if ($Mode -eq 'rollback') {
     if (-not (Test-Path -LiteralPath $packagesPath)) { exit 0 }
     $modern = ((& pnputil '/?' 2>$null) | Out-String) -match '/add-driver'
     $tools = @{}
     foreach ($d in @($cfg.drivers)) {
          if ($d.tool -and $d.device_id) {
               $tools[$d.device_id.ToLower()] =
                    (Join-Path $root ($d.tool -replace '/', '\'))
          }
     }
     $kept = @()
     $failed = $false
     foreach ($line in @(Get-Content -LiteralPath $packagesPath)) {
          $parts = @($line -split '\s+' | Where-Object { $_ })
          if ($parts.Count -lt 1) { continue }
          $name = $parts[0]
          $devid = ''
          if ($parts.Count -gt 1) { $devid = $parts[1] }
          $infNow = Join-Path $env:SystemRoot ('INF\' + $name)
          if (-not (Test-Path -LiteralPath $infNow)) { continue }
          if ($devid) {
               $enum = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$devid"
               if (Test-Path $enum) {
                    foreach ($inst in @(Get-ChildItem $enum)) {
                         $id = "root\$devid\" + $inst.PSChildName
                         if ($modern) {
                              & pnputil /remove-device $id 2>&1 | Out-Null
                         }
                    }
                    if (-not $modern -and $tools.ContainsKey($devid.ToLower()) `
                         -and (Test-Path -LiteralPath $tools[$devid.ToLower()])) {
                         & $tools[$devid.ToLower()] remove $devid 2>&1 | Out-Null
                    }
               }
          }
          if ($modern) {
               & pnputil /delete-driver $name /uninstall /force 2>&1 | Out-Null
          } else {
               & pnputil -f -d $name 2>&1 | Out-Null
          }
          if ($LASTEXITCODE -ne 0) { $failed = $true; $kept += $line }
     }
     $pending = Join-Path $stateDir 'pending-driver.txt'
     if ($failed) {
          Set-Content -LiteralPath $packagesPath -Value $kept -Encoding ASCII
          Set-Content -LiteralPath $pending `
               -Value 'driver still in use: retried on next session end' `
               -Encoding ASCII
     } else {
          Remove-Item -LiteralPath $packagesPath -Force
          Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue
     }
     exit 0
}
$services = @($cfg.services)
if ($services.Count -eq 0) { exit 0 }
if ($Mode -eq 'check') {
     foreach ($s in $services) {
          if (-not (Get-Service -Name $s.name)) { exit 4 }
     }
     exit 0
}
if ($Mode -eq 'teardown') {
     if (-not (Test-Path -LiteralPath $createdPath)) { exit 0 }
     $names = @(Get-Content -LiteralPath $createdPath |
               ForEach-Object { $_.Trim() } | Where-Object { $_ })
     foreach ($n in $names) {
          Stop-Service -Name $n -Force
          sc.exe delete $n | Out-Null
     }
     Remove-Item -LiteralPath $createdPath -Force
     exit 0
}
# ensure: create only what is absent, remember only what we created.
$created = @()
if (Test-Path -LiteralPath $createdPath) {
     $created = @(Get-Content -LiteralPath $createdPath |
                  ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
foreach ($s in $services) {
     $svc = Get-Service -Name $s.name
     if ($null -ne $svc) {
          if ($svc.Status -ne 'Running') { Start-Service -Name $s.name }
          continue
     }
     $image = $s.image.Replace($token, $root)
     if ($s.args) { $image = $image + ' ' + $s.args }
     $type = if ($s.start -eq 'auto') { 'Automatic' } else { 'Manual' }
     try {
          New-Service -Name $s.name -BinaryPathName $image `
                -DisplayName $s.display -StartupType $type -ErrorAction Stop |
            Out-Null
          $created += $s.name
     } catch {
          # PS 5.1 на Win10 ругается на StartupType у уже существующих
          # служб; сюда приходим только когда New-Service реально отказал.
          sc.exe create $s.name binPath= "`"$image`"" start= demand DisplayName= "$($s.display)" obj= LocalSystem | Out-Null
          if ($LASTEXITCODE -eq 0) { $created += $s.name }
          continue
     }
     Start-Service -Name $s.name
}
$created = @($created | Select-Object -Unique)
if ($created.Count -gt 0) {
     Set-Content -LiteralPath $createdPath -Value $created -Encoding UTF8
}
exit 0
'''


def render_services_ps1() -> str:
    """``NetStack\\NetStackServices.ps1`` — ensure | check | teardown |
    ownership | rollback.

    Коды выхода: 0 — всё в порядке; 4 — чего-то не хватает (режим check);
    5 — PowerShell слишком стар (нет ConvertFrom-Json), трогать ничего не
    стали.
    """
    return _PS1_BODY
