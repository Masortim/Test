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
#: Адаптеры, которые создал именно этот портатив (hwid + Instance ID).
CREATED_DEVICES_FILE = "created-devices.txt"

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
#: Потолки для поиска по самому ПК сборщика: DriverStore бывает большим
#: (тысячи каталогов), но перебирать его целиком незачем — TAP-Windows лежит
#: в каталоге, имя которого начинается с ``tap0901.inf_``/``oemvista.inf_``.
_MAX_STORE_DIRS = 20_000
_MAX_SYSTEM_FILES = 120


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
    """Один пакет сетевого драйвера, найденный для портатива.

    Пакет ищется в двух местах: внутри ``App/`` (его принёс сам установщик) и
    на компьютере-сборщике (DriverStore, ``Program Files\\TAP-Windows``).
    Второй источник — не мелочь: установщик VPN-клиента часто ставит драйвер
    **не в свою папку**, а в систему (``%SystemRoot%\\System32\\DriverStore``),
    поэтому сканирование одного ``App`` не находило ничего, портатив уезжал
    без драйвера и на чужом ПК клиент показывал «не удалось обнаружить
    TAP-Windows Provider V9 Network adapter … Установить сейчас?» и тут же
    «Ошибка установки драйвера адаптера» (см. README, «VPN-клиенты и
    NetStack»).

    Пути хранятся в двух видах: ``inf_rel``/``files`` — относительно ``App``
    (так пакет выглядит в готовом портативе), ``inf_path``/``file_paths`` —
    абсолютные (пакет взят из системы и будет скопирован в ``NetStack``).
    """

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
    #: Абсолютный ``.inf`` для пакета, найденного вне ``App``.
    inf_path: str = ""
    #: Абсолютные файлы такого пакета (``.sys``/``.cat``/``.dll``).
    file_paths: List[str] = field(default_factory=list)
    #: Абсолютный путь к tapinstall.exe/devcon.exe.
    tool_path: str = ""
    #: Откуда пакет: ``app``, ``driverstore``, ``program-files``.
    origin: str = "app"

    @property
    def needs_install(self) -> bool:
        return self.kind in (KIND_TAP_WINDOWS, KIND_OVPN_DCO)

    @property
    def check_service(self) -> str:
        """Ключ ``Services\\...``, по которому проверяют «драйвер есть»."""
        return self.service or KIND_DEFAULT_SERVICE.get(self.kind, "")

    @property
    def source_inf(self) -> str:
        """Абсолютный путь к инф-файлу (в App или в системе)."""
        return self.inf_path or self.inf_rel



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


# --- пакеты, установленные на компьютере-сборщике -------------------------------
#
# Установщик VPN-клиента почти всегда ставит драйвер TAP-Windows в СИСТЕМУ, а
# не в свою папку: пакет попадает в DriverStore, файлы — в System32\drivers,
# утилита — в Program Files\TAP-Windows. Сканирование одного App в этом
# случае не находит ничего, и портатив уезжает без драйвера — ровно та
# ситуация, когда вендорский клиент на чужом ПК пишет «Приложению не удалось
# обнаружить TAP-Windows Provider V9 Network adapter … Установить сейчас?»,
# а затем «Ошибка установки драйвера адаптера» (установка идёт без прав
# администратора и без нужных файлов).
#
# Поэтому пакет забирается ещё и с машины сборки. Это чтение, а не установка:
# ничего в системе не меняется, чужие драйверы не удаляются, а на целевом ПК
# уже установленный драйвер вообще не трогается (см. Setup.cmd/Teardown.cmd).
# DriverStore хранит ПОЛНЫЙ и согласованный пакет (inf + sys + подписанный
# cat), поэтому копировать можно целиком, и подпись остаётся действительной.

#: Где Windows держит установленные пакеты сторонних драйверов.
DRIVERSTORE_SUBPATH = ("System32", "DriverStore", "FileRepository")
#: Штатные места TAP-Windows и OpenVPN: там же лежит tapinstall.exe — им
#: пакет превращается в корневое устройство адаптера.
TAP_WINDOWS_SUBDIRS = (
    ("TAP-Windows", "driver"),
    ("TAP-Windows",),
    ("OpenVPN", "driver"),
    ("OpenVPN",),
    ("OpenVPN", "bin"),
)
#: Утилиты, которые умеют создать корневое устройство из inf (devcon-клоны).
TOOL_NAMES_ORDER = ("tapinstall.exe", "devcon.exe", "devcon64.exe", "tapctl.exe")


def _unique(items: Sequence[str]) -> List[str]:
    seen: List[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def system_platform_arch(env: Optional[Dict[str, str]] = None) -> str:
    """``amd64``/``x86``/``arm64`` для выбора пакета из DriverStore.

    Разрядность важна не приложению, а ядру: на x64-ПК нужен amd64-пакет, на
    ARM64 — arm64. DriverStore может содержать несколько версий одного
    пакета, и первая попавшаяся может оказаться не той.
    """
    env = os.environ if env is None else env
    value = str(env.get("PROCESSOR_ARCHITECTURE", "") or "").lower()
    if value in ("arm64", "aarch64"):
        return "arm64"
    if value in ("amd64", "x86_64", "x64"):
        return "amd64"
    if value in ("x86", "i386", "i686"):
        return "x86"
    machine = os.environ.get("PROCESSOR_ARCHITEW6432", "").lower()
    if machine in ("amd64", "arm64"):
        return machine
    return ""


def driverstore_dir(env: Optional[Dict[str, str]] = None) -> str:
    """Каталог DriverStore\\FileRepository текущей Windows (или пусто)."""
    env = os.environ if env is None else env
    root = env.get("SystemRoot") or env.get("windir") or ""
    if not root:
        return ""
    return os.path.join(root, *DRIVERSTORE_SUBPATH)


def program_files_dirs(env: Optional[Dict[str, str]] = None) -> List[str]:
    """Все варианты ``Program Files`` (x64, x86, ARM64) без дублей."""
    env = os.environ if env is None else env
    return _unique([env.get("ProgramW6432", ""),
                    env.get("ProgramFiles", ""),
                    env.get("ProgramFiles(x86)", "")])


def _package_from_directory(inf_path: str, origin: str,
                            max_files: int = _MAX_SYSTEM_FILES
                            ) -> Optional[NetDriverPackage]:
    """Собирает описание пакета по инф-файлу и его соседям."""
    try:
        if os.path.getsize(inf_path) > _MAX_INF_BYTES:
            return None
        with open(inf_path, "r", encoding="utf-8", errors="ignore") as fh:
            meta = parse_net_inf(fh.read())
    except OSError:
        return None
    if not meta.usable:
        return None
    directory = os.path.dirname(inf_path)
    files: List[str] = []
    try:
        for name in sorted(os.listdir(directory))[:_MAX_SYSTEM_FILES]:
            full = os.path.join(directory, name)
            if (os.path.isfile(full)
                    and os.path.normcase(full) != os.path.normcase(inf_path)):
                files.append(full)
    except OSError:
        pass
    return NetDriverPackage(
        kind=meta.kind, provider=meta.provider, service=meta.service,
        device_id=meta.device_id, inf_path=inf_path, file_paths=files,
        origin=origin)


def _arch_of(path: str) -> str:
    """Разрядность пакета по имени каталога DriverStore."""
    lowered = os.path.basename(path).lower()
    for arch in ("arm64", "amd64", "x86"):
        if f"_{arch}_" in lowered or lowered.endswith("_" + arch):
            return arch
    return ""


def scan_driverstore_packages(store_dir: str = "", arch: str = "",
                              max_dirs: int = _MAX_STORE_DIRS
                              ) -> List[NetDriverPackage]:
    """Ищет пакеты VPN-драйверов в ``DriverStore\\FileRepository``.

    Перебираются только каталоги, в имени которых угадывается нужный пакет
    (``tap0901.inf_*``, ``oemvista.inf_*``, ``wintun.inf_*``, ``ovpn-dco*``):
    полный обход DriverStore на большой машине занял бы минуты. Если таких
    имён нет, каталоги всё равно просматриваются — но с потолком.
    """
    if not store_dir or not os.path.isdir(store_dir):
        return []
    try:
        entries = sorted((entry for entry in os.scandir(store_dir)
                          if entry.is_dir()), key=lambda e: e.name)
    except OSError:
        return []
    hints = ("tap", "wintun", "ovpn", "openvpn")
    preferred = [e for e in entries if any(h in e.name.lower() for h in hints)]
    others = [e for e in entries if e not in preferred]
    ordered = (preferred + others)[:max_dirs]
    packages: List[NetDriverPackage] = []
    for entry in ordered:
        try:
            names = sorted(os.listdir(entry.path))[:_MAX_SYSTEM_FILES]
        except OSError:
            continue
        for name in names:
            if not name.lower().endswith(".inf"):
                continue
            package = _package_from_directory(os.path.join(entry.path, name),
                                              "driverstore")
            if package is None:
                continue
            packages.append(package)
            break
        if len(packages) >= _MAX_PACKAGES:
            break
    return _rank_system_packages(packages, arch)


def scan_program_files_packages(program_files: Sequence[str] = (),
                                max_depth: int = 2
                                ) -> List[NetDriverPackage]:
    """Ищет пакет TAP-Windows в ``Program Files\\TAP-Windows`` и у OpenVPN."""
    packages: List[NetDriverPackage] = []
    for base in _unique(program_files):
        for parts in TAP_WINDOWS_SUBDIRS:
            directory = os.path.join(base, *parts)
            if not os.path.isdir(directory):
                continue
            found_in_dir = False
            for name in sorted(os.listdir(directory))[:_MAX_SYSTEM_FILES]:
                if not name.lower().endswith(".inf"):
                    continue
                package = _package_from_directory(
                    os.path.join(directory, name), "program-files")
                if package is not None:
                    packages.append(package)
                    found_in_dir = True
            if found_in_dir or max_depth <= 1:
                continue
            for name in sorted(os.listdir(directory))[:_MAX_SYSTEM_FILES]:
                child = os.path.join(directory, name)
                if not os.path.isdir(child):
                    continue
                for nested in sorted(os.listdir(child))[:_MAX_SYSTEM_FILES]:
                    if not nested.lower().endswith(".inf"):
                        continue
                    package = _package_from_directory(
                        os.path.join(child, nested), "program-files")
                    if package is not None:
                        packages.append(package)
            if len(packages) >= _MAX_PACKAGES:
                break
    deduped: List[NetDriverPackage] = []
    seen_inf: set = set()
    for package in packages:
        key = os.path.normcase(package.inf_path or "")
        if key in seen_inf:
            continue
        seen_inf.add(key)
        deduped.append(package)
    return deduped


def find_netstack_tools(program_files: Sequence[str] = (),
                        extra_dirs: Sequence[str] = ()) -> List[str]:
    """Пути к tapinstall/devcon, которые уже есть на этом ПК.

    Установщик TAP-Windows кладёт ``tapinstall.exe`` в
    ``Program Files\\TAP-Windows\\bin``; OpenVPN — в свою ``bin``. Утилита
    нужна, чтобы из пакета появилось именно УСТРОЙСТВО адаптера: одного
    ``pnputil /add-driver`` для корневого устройства недостаточно.
    """
    tools: List[str] = []
    dirs: List[str] = []
    for base in _unique(program_files):
        for parts in (("TAP-Windows", "bin"), ("TAP-Windows",),
                      ("OpenVPN", "bin"), ("OpenVPN",)):
            dirs.append(os.path.join(base, *parts))
    dirs.extend(_unique(list(extra_dirs)))
    for directory in dirs:
        if not os.path.isdir(directory):
            continue
        for tool in TOOL_NAMES_ORDER:
            candidate = os.path.join(directory, tool)
            if os.path.isfile(candidate) and candidate not in tools:
                tools.append(candidate)
        if tools:
            # Первый найденный набор — самый точный: TAP-Windows важнее
            # случайного devcon от Windows SDK.
            break
    return tools


def package_file_names(package: NetDriverPackage) -> List[str]:
    """Имена файлов пакета в нижнем регистре (для проверки полноты)."""
    names = [os.path.basename(package.inf_path or package.inf_rel)]
    names += [os.path.basename(path) for path in package.file_paths]
    names += [os.path.basename(path) for path in package.files]
    return [name.lower() for name in names if name]


def is_complete_driver_package(package: NetDriverPackage) -> bool:
    """Хватает ли пакету файлов, чтобы Windows его принял.

    ``pnputil /add-driver`` требует подписанный каталог (``.cat``) и сам
    драйвер (``.sys``) рядом с ``.inf``. Установщики иногда кладут в свою
    папку только ``.inf`` (или только ``.sys``) — такой пакет на чистом ПК
    бесполезен, и его надо заменить полным пакетом из DriverStore.
    """
    if not package.needs_install:
        return True
    names = package_file_names(package)
    return (any(name.endswith(".inf") for name in names)
            and any(name.endswith(".sys") for name in names)
            and any(name.endswith(".cat") for name in names))


def merge_driver_packages(app_packages: Sequence[NetDriverPackage],
                          system_packages: Sequence[NetDriverPackage]
                          ) -> List[NetDriverPackage]:
    """Склеивает пакеты из ``App`` и с компьютера-сборщика.

    Приоритет у пакета из ``App`` — он «родной» и точно той версии, что ждёт
    программа. Но если в нём нет ``.sys``/``.cat``, берётся полный пакет того
    же вида из DriverStore: иначе установка на чистом ПК молча провалится.
    """
    by_key = {(package.kind, package.check_service): package
              for package in system_packages}
    merged: List[NetDriverPackage] = []
    for package in app_packages:
        key = (package.kind, package.check_service)
        replacement = by_key.get(key)
        if replacement is not None and not is_complete_driver_package(package):
            merged.append(replacement)
        else:
            merged.append(package)
    seen = {(package.kind, package.check_service) for package in merged}
    for package in system_packages:
        key = (package.kind, package.check_service)
        if key in seen:
            continue
        seen.add(key)
        merged.append(package)
    return merged


def attach_netstack_tools(packages: Sequence[NetDriverPackage],
                          tools: Sequence[str]) -> List[NetDriverPackage]:
    """Даёт каждому пакету tapinstall/devcon, если он нужен и найден.

    Утилита превращает пакет в УСТРОЙСТВО адаптера — без неё портатив
    публикует драйвер, но VPN-клиент по-прежнему не видит адаптер. Если
    утилиты нет, устройство создаст встроенный установщик на SetupAPI
    (см. NetStackServices.ps1), поэтому это не ошибка.
    """
    if not tools:
        return list(packages)
    tool = next((path for path in tools if os.path.isfile(path)), "")
    if not tool:
        return list(packages)
    for package in packages:
        if package.needs_install and not package.tool_rel and not package.tool_path:
            package.tool_path = tool
    return list(packages)


_VPN_NAME_RE = re.compile(r"vpn|openvpn|wireguard|planet|tap-windows",
                          re.IGNORECASE)


def looks_like_vpn(*texts: object) -> bool:
    """Похоже ли собираемое приложение на VPN-клиент (нужен NetStack)."""
    return any(_VPN_NAME_RE.search(str(text or "")) for text in texts)


def _rank_system_packages(packages: Sequence[NetDriverPackage],
                          arch: str = "") -> List[NetDriverPackage]:
    """Убирает дубли по (вид, служба) и ставит пакет нужной разрядности вперёд."""
    ranked: List[Tuple[Tuple[int, int, str], NetDriverPackage]] = []
    for package in packages:
        package_arch = _arch_of(package.inf_path or package.source_inf)
        arch_penalty = 0 if (not arch or not package_arch
                             or package_arch == arch) else 1
        kind_order = (KIND_ORDER.index(package.kind)
                      if package.kind in KIND_ORDER else len(KIND_ORDER))
        ranked.append(((kind_order, arch_penalty, package.service), package))
    ranked.sort(key=lambda item: item[0])
    result: List[NetDriverPackage] = []
    seen: set = set()
    for _key, package in ranked:
        dedupe = (package.kind, package.check_service)
        if dedupe in seen:
            continue
        seen.add(dedupe)
        result.append(package)
    return result


def scan_system_driver_packages(store_dir: str = "",
                                program_files: Sequence[str] = (),
                                arch: str = "") -> List[NetDriverPackage]:
    """Пакеты VPN-драйверов, УЖЕ установленные на компьютере-сборщике.

    Порядок источников: DriverStore (полный подписанный пакет) → Program
    Files\\TAP-Windows (там же утилита установки). Возвращает абсолютные пути;
    :func:`provision_netstack` скопирует их в ``NetStack/Drivers``.
    """
    if store_dir == "":
        store_dir = driverstore_dir()
    if not program_files:
        program_files = program_files_dirs()
    packages = scan_driverstore_packages(store_dir, arch)
    if len(packages) < _MAX_PACKAGES:
        seen = {p.check_service for p in packages if p.check_service}
        for package in scan_program_files_packages(program_files):
            if package.check_service in seen:
                continue
            seen.add(package.check_service)
            packages.append(package)
    return _rank_system_packages(packages, arch)


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
            # Hardware ID сетевого адаптера: служба драйвера может быть уже
            # зарегистрирована, а самого устройства нет — именно это состояние
            # вендорский VPN-клиент и называет «не удалось обнаружить
            # TAP-Windows Provider V9 Network adapter». Лончер проверяет оба
            # признака по отдельности.
            "driver_devices": [
                entry.get("device_id", "") for entry in self.drivers
                if entry.get("needs_install") == "1" and entry.get("device_id")
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
        package_copied = False
        try:
            os.makedirs(dest_dir, exist_ok=True)
            # Пакет из App лежит относительным путём, пакет из DriverStore —
            # абсолютным. Копируется и то, и другое: в портативе всегда
            # должен оказаться ПОЛНЫЙ набор (inf + sys + подписанный cat),
            # иначе pnputil откажется ставить драйвер на чистом ПК.
            if package.inf_path:
                source_inf = package.inf_path
            else:
                source_inf = os.path.join(
                    app_dir, package.inf_rel.replace("/", os.sep))
            if os.path.isfile(source_inf):
                shutil.copy2(
                    source_inf,
                    os.path.join(dest_dir, os.path.basename(source_inf)))
                entry["inf"] = (f"{NETSTACK_DIR_NAME}/{DRIVERS_SUBDIR}/"
                                f"{package.kind or 'other'}/"
                                f"{os.path.basename(source_inf)}")
                copied_any = True
                package_copied = True
            if package.file_paths:
                sources = list(package.file_paths[:_MAX_SYSTEM_FILES])
            else:
                sources = [os.path.join(app_dir, rel.replace("/", os.sep))
                           for rel in package.files[:_MAX_SIBLINGS]]
            for src in sources:
                if os.path.isfile(src):
                    shutil.copy2(src,
                                 os.path.join(dest_dir, os.path.basename(src)))
        except OSError as exc:
            report.notes.append(
                f"пакет {package.kind}: часть файлов не скопирована ({exc})")
        if package.tool_path:
            tool_dest = os.path.join(netstack_dir, BIN_SUBDIR)
            try:
                os.makedirs(tool_dest, exist_ok=True)
                if os.path.isfile(package.tool_path):
                    shutil.copy2(
                        package.tool_path,
                        os.path.join(tool_dest,
                                     os.path.basename(package.tool_path)))
                    entry["tool"] = (f"{NETSTACK_DIR_NAME}/{BIN_SUBDIR}/"
                                     f"{os.path.basename(package.tool_path)}")
            except OSError:
                entry["tool"] = ""
        elif package.tool_rel:
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
        if (not package_copied and entry.get("needs_install") == "1"):
            report.notes.append(
                f"пакет {package.kind}: инф-файл не найден — "
                "на чистом ПК драйвер придётся ставить вручную")
        elif (package_copied and entry.get("needs_install") == "1"
                and package.origin != "app"):
            # Строка для журнала сборки: видно, ОТКУДА взят драйвер.
            report.notes.append(
                f"пакет {package.kind}: взят с этого ПК "
                f"({package.origin}) — установщик положил его вне App")
        if entry.get("needs_install") == "1" and not entry.get("tool"):
            report.notes.append(
                f"пакет {package.kind}: tapinstall.exe не нужен — устройство "
                "адаптера создаст встроенный установщик (SetupAPI)")
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
            "rem The package can already be in the driver store while the",
            "rem ADAPTER is missing: that is exactly the state the vendor app",
            "rem reports as 'TAP-Windows Provider V9 Network adapter not",
            "rem found'. Both signs are verified by the .ps1 below; here the",
            "rem package is only published when its service key is absent.",
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
            "rem 1) put the package into the driver store. /install also",
            "rem    updates drivers of devices that already match the INF.",
            'if "%PNPMODERN%" == "1" (',
            f"  if exist {inf_path} pnputil /add-driver {inf_path} /install "
            f">> \"%NETSTACK_STATE%\\setup.log\" 2>&1",
            f") else if exist {inf_path} pnputil -i -a {inf_path}",
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
        lines += [
            "rem 2) make the PnP manager see the staged package",
            'if "%PNPMODERN%" == "1" pnputil /scan-devices '
            ">> \"%NETSTACK_STATE%\\setup.log\" 2>&1",
            "rem The ADAPTER itself (root-enumerated device tap0901) is",
            "rem created by NetStackServices.ps1: tapinstall when the vendor",
            "rem shipped it, otherwise the built-in SetupAPI installer.",
            "rem Creating a device with pnputil is impossible - it has no",
            "rem /add-device command; that is why the previous version could",
            "rem publish the driver and still leave the PC without adapter.",
        ]
        # Честная проверка результата: не верим на слово ни pnputil, ни
        # установщику — «поставлено» только если ключ службы появился.
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
        "rem 4 = companion service missing, 3 = adapter device missing.",
        "rem 'if errorlevel N' also matches greater codes, so 4 is tested",
        "rem first and 3 - only when the .ps1 really returned 3.",
        "if errorlevel 4 (set \"NETSTACK_RC=4\") else if errorlevel 3 "
        "set \"NETSTACK_RC=3\"",
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
            "rem Only adapters THIS portable created are detached: the exact",
            "rem instance IDs live in PortableData\\NetStack\\",
            "rem created-devices.txt (found by hardware ID, not by guessing",
            "rem 'root\\tap0901' - the real instance is ROOT\\NET\\000X).",
            "rem Driver packages stay, because shared mode treats them like",
            "rem the Visual C++ runtimes: a common component of the PC.",
            'powershell -NoProfile -ExecutionPolicy Bypass -File '
            '"%NETSTACK_ROOT%' + SERVICES_SCRIPT_NAME + '" -Mode detach',
            "exit /b 0",
            "",
        ]
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
$devicesPath = Join-Path $stateDir 'created-devices.txt'
# --- adapters: a driver service is not an adapter ---------------------------
# A VPN client does not ask Windows "is service tap0901 registered?" - it
# enumerates NETWORK ADAPTERS. So publishing the package is only half the job:
# the adapter itself is a root-enumerated devnode, and pnputil cannot create
# one (it has no /add-device command, only add-driver/remove-device). The
# supported way without foreign tools is SetupAPI - the same sequence devcon
# uses. When the vendor shipped tapinstall.exe, that tool goes first: it is
# the exact program the VPN vendor's own installer runs.
function Find-HwidDevices([string]$hwid) {
     $found = @()
     if (-not $hwid) { return $found }
     $needle = $hwid.ToLower()
     $pnpWorks = $false
     try {
          foreach ($d in @(Get-PnpDevice -Class Net -ErrorAction Stop)) {
               $pnpWorks = $true
               foreach ($h in @($d.HardwareID)) {
                    if ($h -and $h.ToLower().Contains($needle)) {
                         $found += [pscustomobject]@{
                              InstanceId = [string]$d.InstanceId
                              RegistryPath = ''
                         }
                         break
                    }
               }
          }
     } catch { }
     if ($pnpWorks) { return $found }
     # Windows without the PnpDevice module (7/8): the same facts are in Enum.
     $enum = 'HKLM:\SYSTEM\CurrentControlSet\Enum'
     foreach ($bus in @(Get-ChildItem -LiteralPath $enum -ErrorAction SilentlyContinue)) {
          foreach ($dev in @(Get-ChildItem -LiteralPath $bus.PSPath -ErrorAction SilentlyContinue)) {
               $ids = @((Get-ItemProperty -LiteralPath $dev.PSPath `
                    -Name HardwareID -ErrorAction SilentlyContinue).HardwareID)
               foreach ($h in $ids) {
                    if ($h -and $h.ToLower().Contains($needle)) {
                         $found += [pscustomobject]@{
                              InstanceId = ($bus.PSChildName + '\' + $dev.PSChildName)
                              RegistryPath = $dev.PSPath
                         }
                         break
                    }
               }
          }
     }
     return $found
}
function Install-RootDevice([string]$infPath, [string]$hwid, [string]$toolPath) {
     if (@(Find-HwidDevices $hwid).Count -gt 0) { return $true }
     if ($toolPath -and (Test-Path -LiteralPath $toolPath)) {
          & $toolPath install $infPath $hwid 2>&1 | Out-Null
          Start-Sleep -Milliseconds 400
          if (@(Find-HwidDevices $hwid).Count -gt 0) { return $true }
     }
     if (-not ('PortablizerNetStack.RootDevice' -as [type])) {
          $source = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PortablizerNetStack {
  public static class RootDevice {
    const int MAX_CLASS_NAME_LEN = 32;
    const uint DICD_GENERATE_ID = 0x00000001;
    const uint SPDRP_HARDWAREID = 0x00000001;
    const uint DIF_REGISTERDEVICE = 0x00000019;
    const uint DIF_REMOVE = 0x00000005;
    const uint INSTALLFLAG_FORCE = 0x00000001;
    const uint INSTALLFLAG_NONINTERACTIVE = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA {
      public uint cbSize;
      public Guid ClassGuid;
      public uint DevInst;
      public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiGetINFClass(string infName, out Guid classGuid,
      StringBuilder className, uint classNameSize, out uint requiredSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid classGuid,
      IntPtr hwndParent);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiCreateDeviceInfo(IntPtr deviceInfoSet,
      string deviceName, ref Guid classGuid, string deviceDescription,
      IntPtr hwndParent, uint creationFlags, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiSetDeviceRegistryProperty(IntPtr deviceInfoSet,
      ref SP_DEVINFO_DATA deviceInfoData, uint property, byte[] propertyBuffer,
      uint propertyBufferSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiCallClassInstaller(uint installFunction,
      IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool UpdateDriverForPlugAndPlayDevices(IntPtr hwndParent,
      string hardwareId, string fullInfPath, uint installFlags,
      out bool rebootRequired);

    public static bool Install(string infPath, string hwid) {
      Guid classGuid;
      StringBuilder className = new StringBuilder(MAX_CLASS_NAME_LEN);
      uint required;
      if (!SetupDiGetINFClass(infPath, out classGuid, className,
          MAX_CLASS_NAME_LEN, out required)) return false;
      IntPtr set = SetupDiCreateDeviceInfoList(ref classGuid, IntPtr.Zero);
      if (set == IntPtr.Zero || set == new IntPtr(-1)) return false;
      SP_DEVINFO_DATA data = new SP_DEVINFO_DATA();
      data.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
      try {
        if (!SetupDiCreateDeviceInfo(set, className.ToString(), ref classGuid,
            null, IntPtr.Zero, DICD_GENERATE_ID, ref data)) return false;
        byte[] ids = Encoding.Unicode.GetBytes(hwid + "\0\0");
        if (!SetupDiSetDeviceRegistryProperty(set, ref data, SPDRP_HARDWAREID,
            ids, (uint)ids.Length)) return false;
        if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, ref data))
          return false;
        bool reboot;
        bool ok = UpdateDriverForPlugAndPlayDevices(IntPtr.Zero, hwid, infPath,
            INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, out reboot);
        if (!ok) SetupDiCallClassInstaller(DIF_REMOVE, set, ref data);
        return ok;
      } finally {
        SetupDiDestroyDeviceInfoList(set);
      }
    }
  }
}
'@
          Add-Type -TypeDefinition $source -ErrorAction SilentlyContinue
     }
     if ('PortablizerNetStack.RootDevice' -as [type]) {
          try {
               [PortablizerNetStack.RootDevice]::Install($infPath, $hwid) |
                    Out-Null
          } catch { }
     }
     Start-Sleep -Milliseconds 600
     return (@(Find-HwidDevices $hwid).Count -gt 0)
}
function Remember-Device([string]$hwid, [string]$instance) {
     if (-not $hwid) { return }
     $line = $hwid
     if ($instance) { $line = $hwid + ' ' + $instance }
     $have = @()
     if (Test-Path -LiteralPath $devicesPath) {
          $have = @(Get-Content -LiteralPath $devicesPath |
               ForEach-Object { $_.Trim() } | Where-Object { $_ })
     }
     foreach ($entry in $have) {
          if ((($entry -split '\s+')[0]) -eq $hwid) { return }
     }
     Add-Content -LiteralPath $devicesPath -Value $line -Encoding ASCII
}
function Remove-RememberedDevices {
     if (-not (Test-Path -LiteralPath $devicesPath)) { return }
     $modern = ((& pnputil '/?' 2>$null) | Out-String) -match '/add-driver'
     foreach ($line in @(Get-Content -LiteralPath $devicesPath)) {
          $parts = @($line -split '\s+' | Where-Object { $_ })
          if ($parts.Count -lt 1) { continue }
          $hwid = $parts[0]
          foreach ($dev in @(Find-HwidDevices $hwid)) {
               if ($modern -and $dev.InstanceId) {
                    & pnputil /remove-device $dev.InstanceId 2>&1 | Out-Null
               } elseif ($dev.RegistryPath) {
                    Remove-Item -LiteralPath $dev.RegistryPath -Recurse `
                         -Force -ErrorAction SilentlyContinue
               }
          }
     }
     Remove-Item -LiteralPath $devicesPath -Force -ErrorAction SilentlyContinue
}
function Ensure-NetAdapters {
     $failed = $false
     $scanned = $false
     foreach ($d in @($cfg.drivers)) {
          if (-not $d.needs_install) { continue }
          $hwid = [string]$d.device_id
          if (-not $hwid) { continue }
          if (@(Find-HwidDevices $hwid).Count -gt 0) { continue }
          if (-not $d.inf) { $failed = $true; continue }
          $inf = Join-Path $root ([string]$d.inf -replace '/', '\')
          $tool = ''
          if ($d.tool) {
               $tool = Join-Path $root ([string]$d.tool -replace '/', '\')
          }
          if (-not (Test-Path -LiteralPath $inf)) { $failed = $true; continue }
          $created = Install-RootDevice $inf $hwid $tool
          if (-not $scanned) {
               & pnputil /scan-devices 2>&1 | Out-Null
               $scanned = $true
          }
          $instances = @(Find-HwidDevices $hwid)
          if ($instances.Count -eq 0) { $failed = $true }
          if ($created) {
               $instance = ''
               if ($instances.Count -gt 0) {
                    $instance = [string]$instances[0].InstanceId
               }
               Remember-Device $hwid $instance
          }
     }
     return (-not $failed)
}
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
     # Only adapters THIS portable created are removed (created-devices.txt):
     # a TAP adapter installed by OpenVPN or another VPN belongs to its owner
     # and must survive the portable's exit.
     Remove-RememberedDevices
     if (-not (Test-Path -LiteralPath $packagesPath)) { exit 0 }
     $modern = ((& pnputil '/?' 2>$null) | Out-String) -match '/add-driver'
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
if ($Mode -eq 'check') {
     # The adapter is checked as well: a registered service without a device
     # is exactly the vendor app's "adapter not found" state.
     foreach ($d in @($cfg.drivers)) {
          if (-not $d.needs_install) { continue }
          $hwid = [string]$d.device_id
          if ($hwid -and (@(Find-HwidDevices $hwid).Count -eq 0)) { exit 3 }
     }
     foreach ($s in $services) {
          if (-not (Get-Service -Name $s.name)) { exit 4 }
     }
     exit 0
}
if ($Mode -eq 'detach') {
     # Shared mode (--remove-device): detach only our adapters, keep packages.
     Remove-RememberedDevices
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
# Adapters first: the VPN client cannot do anything without one, and its own
# driver installation needs the rights this elevated pass already has.
if (-not (Ensure-NetAdapters)) { exit 3 }
if ($services.Count -eq 0) { exit 0 }
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
