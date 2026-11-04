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
from dataclasses import dataclass, field, replace
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
#: Потолок рекурсивного сбора файлов выделенного каталога драйвера.
_MAX_PACKAGE_FILES = 400
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
    #: Полный Hardware ID для создания устройства (``root\\tap0901``).
    hardware_id: str = ""
    #: Файлы, обязательные для публикации пакета (каталог + SourceDisksFiles).
    required_files: List[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        """True, если пакет относится к VPN-стеку и его есть чем ставить."""
        return self.kind in KIND_ORDER

    @property
    def needs_install(self) -> bool:
        """Wintun поднимает сама программа; остальным нужен DriverStore."""
        return self.kind in (KIND_TAP_WINDOWS, KIND_OVPN_DCO)


def read_inf_text(path: str) -> str:
    """Читает .inf в типичных кодировках Windows (ANSI/UTF-8/UTF-16 BOM).

    OemVista.inf из старых пакетов TAP-Windows нередко лежит в UTF-16LE.
    Прежнее чтение как UTF-8 с errors="ignore" превращало его в мусор с
    нулевыми байтами, пакет не распознавался или терял CatalogFile/SourceDisksFiles.
    """
    with open(path, "rb") as fh:
        raw = fh.read(_MAX_INF_BYTES + 1)
    if len(raw) > _MAX_INF_BYTES:
        raise OSError("INF file is too large")
    for bom, encoding in ((b"\xff\xfe", "utf-16-le"),
                          (b"\xfe\xff", "utf-16-be"),
                          (b"\xef\xbb\xbf", "utf-8-sig")):
        if raw.startswith(bom):
            return raw[len(bom):].decode(encoding, errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1251", errors="replace")


def _inf_assignments(text: str) -> Dict[str, List[Tuple[str, str]]]:
    """Секции .inf -> список пар (ключ, значение) без комментариев."""
    sections: Dict[str, List[Tuple[str, str]]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        matched = _INF_SECTION_RE.match(line)
        if matched:
            section = matched.group(1).strip().lower()
            sections.setdefault(section, [])
            continue
        assign = _INF_ASSIGN_RE.match(line)
        if assign and section:
            sections[section].append((assign.group(1).strip(),
                                      assign.group(2).strip()))
    return sections


def _resolve_inf_strings(value: str, strings: Dict[str, str]) -> str:
    for _ in range(4):
        before = value
        for token, replacement in strings.items():
            value = re.sub(re.escape(f"%{token}%"), lambda _m: replacement,
                           value, flags=re.IGNORECASE)
        if value == before:
            break
    return value.strip().strip('"').strip()


#: Токены разрядности в_decorated_ секциях INF (``SourceDisksFiles.amd64``).
_INF_ARCH_TOKENS = ("amd64", "x86", "arm64", "ia64", "ntamd64", "ntx86",
                    "ntarm64", "nt")


def _inf_section_arch(section: str) -> str:
    """Разрядность decorated-секции INF ("" — секция общая для всех).

    ``sourcedisksfiles.amd64`` -> ``amd64``; ``catalogfile.ntamd64`` -> ``amd64``.
    Без этого фильтр требовал бы файлы чужих архитектур и валидный
    одноархитектурный пакет из DriverStore казался неполным.
    """
    if "." not in section:
        return ""
    decoration = section.split(".", 1)[1].strip().lower()
    for token in _INF_ARCH_TOKENS:
        if decoration == token or decoration.startswith(token + "."):
            return {"ntamd64": "amd64", "ntx86": "x86",
                    "ntarm64": "arm64", "nt": ""}.get(token, token)
    return ""


def _inf_section_applies(section: str, arch: str) -> bool:
    """Применима ли секция к выбранной разрядности (пустая — ко всем)."""
    section_arch = _inf_section_arch(section)
    if not section_arch or not arch:
        return True
    return section_arch == arch


def inf_required_files(text: str, arch: str = "") -> List[str]:
    """Файлы, без которых Windows не примет пакет: каталог и SourceDisksFiles.

    Это не полный парсер INF, а точная проверка тех полей, из-за которых
    ``pnputil /add-driver`` отвечает «Не удается найти указанный файл» при
    живом ``OemVista.inf``: отсутствует ``tap0901.sys`` или подписанный
    ``.cat``, либо они лежат не там, где обещает INF.
    """
    sections = _inf_assignments(text)
    strings: Dict[str, str] = {}
    for name, pairs in sections.items():
        if name == "strings" or name.startswith("strings."):
            for key, value in pairs:
                strings.setdefault(key, value.strip('"').strip())
    required: List[str] = []
    for key, value in sections.get("version", []):
        if key.lower().startswith("catalogfile"):
            if not _inf_section_applies(key.lower(), arch):
                continue
            resolved = _resolve_inf_strings(value, strings)
            if resolved:
                required.append(resolved.replace("\\", "/"))
    disk_subdirs: Dict[str, str] = {}
    for name, pairs in sections.items():
        if name == "sourcedisksnames" or name.startswith("sourcedisksnames."):
            if not _inf_section_applies(name, arch):
                continue
            for disk_id, value in pairs:
                parts = [p.strip().strip('"') for p in value.split(",")]
                # diskid = description[,tagfile][,unused][,subdir]
                subdir = parts[3] if len(parts) > 3 else ""
                disk_subdirs[disk_id] = _resolve_inf_strings(subdir, strings)
    for name, pairs in sections.items():
        if name == "sourcedisksfiles" or name.startswith("sourcedisksfiles."):
            if not _inf_section_applies(name, arch):
                continue
            for filename, value in pairs:
                parts = [p.strip().strip('"') for p in value.split(",")]
                disk_id = parts[0] if parts else ""
                subdir = parts[1] if len(parts) > 1 else ""
                base = disk_subdirs.get(disk_id, "")
                rel = "/".join(p for p in (base, subdir, filename) if p)
                required.append(rel.replace("\\", "/"))
    return _unique(required)


def parse_net_inf(text: str, arch: str = "") -> InfMeta:
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
    hardware_id = f"root\\{device_id}" if device_id else ""
    return InfMeta(kind=kind, provider=resolved, service=service,
                   device_id=device_id, class_name=class_name,
                   catalog=version.get("catalogfile", ""),
                   hardware_id=hardware_id,
                   required_files=inf_required_files(text, arch))


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
    #: Полный Hardware ID корневого устройства (``root\\tap0901``).
    hardware_id: str = ""
    #: Обязательные файлы пакета относительно каталога INF.
    required_files: List[str] = field(default_factory=list)

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


def _safe_rel(path: str, base: str) -> str:
    """Относительный путь внутри каталога пакета (без выхода наружу)."""
    rel = _rel(path, base)
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or parts[0] == ".." or os.path.isabs(rel):
        return ""
    return "/".join(parts)


def _collect_app_package_files(inf_path: str, app_dir: str,
                               meta: InfMeta) -> List[str]:
    """Соседи INF в App плюс обязательные файлы из подкаталогов.

    INF может обещать ``amd64/tap0901.sys``: плоское копирование соседей
    теряло такой файл, и pnputil на чистом ПК отвечал «не найден файл».
    """
    directory = os.path.dirname(inf_path)
    found: List[str] = []
    try:
        siblings = sorted(os.listdir(directory))[:_MAX_SIBLINGS]
    except OSError:
        siblings = []
    for sibling in siblings:
        candidate = os.path.join(directory, sibling)
        if os.path.isfile(candidate) and candidate != inf_path:
            rel = _safe_rel(candidate, app_dir)
            if rel:
                found.append(rel)
    # Обязательные файлы ищем и глубже одного уровня (amd64/, i386/, ...).
    for required in meta.required_files:
        direct = os.path.join(directory, required.replace("/", os.sep))
        if os.path.isfile(direct):
            rel = _safe_rel(direct, app_dir)
            if rel and rel not in found:
                found.append(rel)
            continue
        basename = os.path.basename(required).lower()
        for current, _dirs, files in os.walk(directory):
            for name in files:
                if name.lower() != basename:
                    continue
                candidate = os.path.join(current, name)
                rel = _safe_rel(candidate, app_dir)
                if rel and rel not in found:
                    found.append(rel)
    return found


def _collect_system_package_files(inf_path: str) -> List[str]:
    """Все файлы выделенного каталога драйвера, с сохранением подкаталогов."""
    directory = os.path.dirname(inf_path)
    found: List[str] = []
    for current, dirs, files in os.walk(directory):
        dirs.sort()
        for name in sorted(files):
            candidate = os.path.join(current, name)
            if candidate == inf_path or not os.path.isfile(candidate):
                continue
            found.append(candidate)
            if len(found) >= _MAX_PACKAGE_FILES:
                return found
    return found


def package_missing_files(package: NetDriverPackage,
                          base_dir: str = "") -> List[str]:
    """Чего не хватает пакету: точные имена из INF, а не «какой-нибудь .sys».

    ``base_dir`` — корень, относительно которого задан ``inf_rel`` пакета
    из App. Для системного пакета путь к INF абсолютный, base_dir не нужен.
    """
    if not package.needs_install:
        return []
    if package.inf_path:
        inf_path = package.inf_path
        directory = os.path.dirname(inf_path)
    else:
        inf_path = os.path.join(base_dir, package.inf_rel.replace("/", os.sep))
        directory = os.path.dirname(inf_path)
    missing: List[str] = []
    if not os.path.isfile(inf_path):
        missing.append(os.path.basename(inf_path) or package.inf_rel)
    required = list(package.required_files)
    if not required:
        # Старый манифест/пакет без разбора SourceDisksFiles: требуем хотя
        # бы служебный .sys и подписанный .cat рядом с INF.
        service = package.check_service or "driver"
        required = [f"{service}.sys"]
    available: List[str] = []
    for rel in required:
        candidate = os.path.join(directory, rel.replace("/", os.sep))
        if os.path.isfile(candidate):
            available.append(rel)
        else:
            missing.append(rel)
    names = [os.path.basename(p).lower() for p in available]
    if not any(n.endswith(".sys") for n in names):
        # CatalogFile мог быть единственным обязательным файлом в INF.
        service = package.check_service or "driver"
        if not any(os.path.isfile(os.path.join(directory, n))
                   for n in (f"{service}.sys",)):
            missing.append(f"{service}.sys")
    if not any(n.endswith(".cat") for n in names):
        catalog = ""
        try:
            meta = parse_net_inf(read_inf_text(inf_path),
                                 _arch_of(directory) or system_platform_arch())
            catalog = meta.catalog
        except OSError:
            pass
        missing.append(catalog or f"{package.check_service or 'driver'}.cat")
    return _unique(missing)


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
                text = read_inf_text(full)
            except OSError:
                continue
            meta = parse_net_inf(text, system_platform_arch())
            if not meta.usable:
                continue
            files_rel = _collect_app_package_files(full, app_dir, meta)
            packages.append(NetDriverPackage(
                kind=meta.kind, provider=meta.provider,
                service=meta.service, device_id=meta.device_id,
                inf_rel=_rel(full, app_dir), files=files_rel,
                hardware_id=meta.hardware_id,
                required_files=list(meta.required_files)))

    for package in packages:
        for tool in tools:
            package.tool_rel = _rel(tool, app_dir)
            break
        if installers:
            package.installer_rel = _rel(installers[0], app_dir)
    order = {kind: index for index, kind in enumerate(KIND_ORDER)}
    packages.sort(key=lambda p: (order.get(p.kind, len(order)),
                                 0 if is_complete_driver_package(p) else 1,
                                 p.service))
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
        text = read_inf_text(inf_path)
    except OSError:
        return None
    # DriverStore names the package dir ..._amd64_...; that is the arch this
    # package was actually built for, so validate exactly its own files.
    meta = parse_net_inf(text, _arch_of(os.path.dirname(inf_path))
                         or system_platform_arch())
    if not meta.usable:
        return None
    files = _collect_system_package_files(inf_path)
    return NetDriverPackage(
        kind=meta.kind, provider=meta.provider, service=meta.service,
        device_id=meta.device_id, inf_path=inf_path, file_paths=files,
        origin=origin, hardware_id=meta.hardware_id,
        required_files=list(meta.required_files))


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
    if not (any(name.endswith(".inf") for name in names)
            and any(name.endswith(".sys") for name in names)
            and any(name.endswith(".cat") for name in names)):
        return False
    # Если INF уже разобран, требуем именно его CatalogFile/SourceDisksFiles,
    # а не «любой соседний .cat»: чужой каталог не подпишет этот пакет.
    required = [os.path.basename(rel).lower()
                for rel in package.required_files if rel]
    return all(name in names for name in required)


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
            # Полный пакет из DriverStore важнее, но утилиту/установщик,
            # принесённые самой программой, не теряем.
            if not replacement.tool_rel and package.tool_rel:
                replacement = replace(replacement, tool_rel=package.tool_rel)
            if not replacement.installer_rel and package.installer_rel:
                replacement = replace(replacement,
                                      installer_rel=package.installer_rel)
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
        complete_penalty = 0 if is_complete_driver_package(package) else 1
        ranked.append(((kind_order, arch_penalty, complete_penalty,
                        package.service), package))
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

    @property
    def complete(self) -> bool:
        """Все обязательные драйверы можно поставить на чистом ПК."""
        return all(entry.get("complete", "1") != "0"
                   for entry in self.drivers
                   if entry.get("needs_install") == "1")

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
        "hardware_id": package.hardware_id or (
            f"root\\{package.device_id}" if package.device_id else ""),
        "needs_install": "1" if package.needs_install else "",
        "inf": package.inf_rel,
        "tool": package.tool_rel,
        "installer": package.installer_rel,
        "required_files": ";".join(package.required_files),
        "complete": "1",
        "missing_files": "",
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
        if package.inf_path:
            source_inf = package.inf_path
        else:
            source_inf = os.path.join(
                app_dir, package.inf_rel.replace("/", os.sep))
        source_dir = os.path.dirname(source_inf)
        missing = package_missing_files(
            package, "" if package.inf_path else app_dir)
        if missing:
            entry["complete"] = "0"
            entry["missing_files"] = ";".join(missing)
            report.notes.append(
                f"пакет {package.kind}: неполный набор драйвера — нет "
                + ", ".join(missing)
                + ". На чистом ПК pnputil ответит «Не удается найти указанный "
                  "файл»; возьмите полный пакет из DriverStore или "
                  "Program Files\\TAP-Windows и соберите портатив заново.")
        try:
            os.makedirs(dest_dir, exist_ok=True)
            # Копируем с сохранением подкаталогов относительно INF: amd64/ и
            # i386/ нельзя сплющивать в один каталог, иначе INF ссылается в
            # пустоту и подпись каталога не сходится.
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
                sources = list(package.file_paths[:_MAX_PACKAGE_FILES])
            else:
                sources = [os.path.join(app_dir, rel.replace("/", os.sep))
                           for rel in package.files[:_MAX_PACKAGE_FILES]]
            for src in sources:
                if not os.path.isfile(src):
                    continue
                rel = _safe_rel(src, source_dir)
                if not rel:
                    continue
                dest = os.path.join(dest_dir, rel.replace("/", os.sep))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(src, dest)
        except OSError as exc:
            entry["complete"] = "0"
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

def refresh_netstack_scripts(portable_dir: str) -> List[str]:
    """Пересоздать NetStack/*.cmd/.ps1 из уже лежащего netstack.json.

    Нужно для старых портативов: в них остались скрипты, которые верили
    ``pnputil /scan-devices`` и писали ``healthy: True`` без драйвера.
    Заодно манифест обогащается ``hardware_id``/``required_files`` и честно
    помечает неполный пакет. Файлы драйвера отсюда не появляются: если
    ``.sys``/``.cat`` не были скопированы при сборке, портатив надо
    пересобрать/починить на ПК с полным подписанным пакетом.
    """
    root = os.path.abspath(portable_dir)
    netstack_dir = os.path.join(root, NETSTACK_DIR_NAME)
    manifest_path = os.path.join(netstack_dir, MANIFEST_NAME)
    if not os.path.isfile(manifest_path):
        return []
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    if not isinstance(manifest, dict):
        return []
    report = NetStackReport()
    report.isolation = str(manifest.get("isolation", "session"))
    report.drivers = [dict(entry) for entry in manifest.get("drivers", [])
                      if isinstance(entry, dict)]
    report.services = [dict(entry) for entry in manifest.get("services", [])
                       if isinstance(entry, dict)]
    for entry in report.drivers:
        if entry.get("needs_install") != "1":
            continue
        rel = str(entry.get("inf", ""))
        inf_path = os.path.join(root, rel.replace("/", os.sep))
        try:
            text = read_inf_text(inf_path)
        except OSError:
            text = ""
        if text:
            meta = parse_net_inf(text, _arch_of(os.path.dirname(inf_path))
                                 or system_platform_arch())
            entry["hardware_id"] = meta.hardware_id
            entry["required_files"] = ";".join(meta.required_files)
        package = NetDriverPackage(
            kind=str(entry.get("kind", KIND_TAP_WINDOWS)),
            service=str(entry.get("service", "")),
            device_id=str(entry.get("device_id", "")),
            inf_path=inf_path,
            hardware_id=str(entry.get("hardware_id", "")),
            required_files=[part for part in
                            str(entry.get("required_files", "")).split(";")
                            if part],
        )
        missing = package_missing_files(package)
        entry["complete"] = "0" if missing else "1"
        entry["missing_files"] = ";".join(missing)
    manifest["drivers"] = report.drivers
    manifest["services"] = report.services
    updated: List[str] = []
    try:
        with open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        updated.append(f"{NETSTACK_DIR_NAME}/{MANIFEST_NAME}")
        with open(os.path.join(netstack_dir, SERVICES_SCRIPT_NAME), "w",
                  encoding="utf-8-sig", newline="\r\n") as fh:
            fh.write(render_services_ps1())
        updated.append(f"{NETSTACK_DIR_NAME}/{SERVICES_SCRIPT_NAME}")
        with open(os.path.join(netstack_dir, SETUP_SCRIPT_NAME), "w",
                  encoding="ascii", errors="replace", newline="") as fh:
            fh.write(render_setup_cmd(report))
        updated.append(f"{NETSTACK_DIR_NAME}/{SETUP_SCRIPT_NAME}")
        with open(os.path.join(netstack_dir, TEARDOWN_SCRIPT_NAME), "w",
                  encoding="ascii", errors="replace", newline="") as fh:
            fh.write(render_teardown_cmd(report))
        updated.append(f"{NETSTACK_DIR_NAME}/{TEARDOWN_SCRIPT_NAME}")
    except OSError:
        return updated
    return updated


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

    * ``--check`` — только проверка (права не нужны, ничего не меняется):
      есть ли пакет, устройство адаптера, служба, указывает ли её ``ImagePath``
      внутрь ЭТОЙ папки и запущена ли она. Код ``0`` — всё в порядке,
      ``2`` — нет пакета драйвера, ``3`` — нет адаптера, ``4`` — службы нет
      или она устарела/остановлена;
    * по умолчанию (и ``--elevated``) — установить недостающие пакеты
      драйверов и зарегистрировать/запустить службы.
    """
    services_script = f'"%NETSTACK_ROOT%{SERVICES_SCRIPT_NAME}"'
    lines = [
        "@echo off",
        "setlocal EnableExtensions EnableDelayedExpansion",
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
        "rem Preflight runs WITHOUT elevation: a bundle with a missing",
        "rem tap0901.sys/.cat must not ask for UAC or run pnputil at all.",
        'set "NETSTACK_SELF=%~f0"',
        "powershell -NoProfile -ExecutionPolicy Bypass -File "
        f"{services_script} -Mode preflight",
        'if "%ERRORLEVEL%" == "5" (set "NETSTACK_RC=5" & goto netstack_done)',
        'if "%ERRORLEVEL%" == "2" (set "NETSTACK_RC=2" & goto netstack_done)',
        'if errorlevel 1 (set "NETSTACK_RC=5" & goto netstack_done)',
        ">nul 2>&1 net session",
        "if not errorlevel 1 goto netstack_pass",
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"try { $p = Start-Process -Verb RunAs -Wait -WindowStyle Hidden "
        "-PassThru -FilePath $env:NETSTACK_SELF -ArgumentList '--elevated' "
        "-ErrorAction Stop; exit $p.ExitCode } catch { exit 1223 }\"",
        'set "NETSTACK_RC=%ERRORLEVEL%"',
        "goto netstack_done",
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
        "rem The .ps1 is the authority: 2 = driver package/service missing,",
        "rem 3 = adapter not ready, 4 = companion service stale/absent,",
        "rem 6 = companion service did not start. Batch-side pnputil warnings",
        "rem must not survive a successful PowerShell repair.",
        'set "NETSTACK_RC=%ERRORLEVEL%"',
        'if /i not "%NETSTACK_MODE%" == "--check" (',
        f"  powershell -NoProfile -ExecutionPolicy Bypass -File "
        f"{services_script} -Mode check >nul 2>&1",
        '  if "!ERRORLEVEL!" == "2" set "NETSTACK_RC=2"',
        '  if "!ERRORLEVEL!" == "3" if "!NETSTACK_RC!" == "0" set "NETSTACK_RC=3"',
        '  if "!ERRORLEVEL!" == "4" if "!NETSTACK_RC!" == "0" set "NETSTACK_RC=4"',
        ")",
        "",
        'if /i not "%NETSTACK_MODE%" == "--check" if "%NETSTACK_RC%" == "0" echo   NetStack ready.',
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
        'set "NETSTACK_SELF=%~f0"',
        ">nul 2>&1 net session",
        "if not errorlevel 1 goto netstack_teardown_pass",
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"try { $p = Start-Process -Verb RunAs -Wait -WindowStyle Hidden "
        "-PassThru -FilePath $env:NETSTACK_SELF -ArgumentList @('--elevated', "
        "$env:TEARDOWN_MODE) -ErrorAction Stop; exit $p.ExitCode } "
        "catch { exit 1223 }\"",
        "exit /b %ERRORLEVEL%",
        "",
        ":netstack_teardown_pass",
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
function Write-SetupLog([string]$message) {
     $line = ('[' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '] ' + $message)
     Write-Output $line
     try {
          Add-Content -LiteralPath (Join-Path $stateDir 'setup.log') `
               -Value $line -Encoding UTF8 -ErrorAction Stop
     } catch { }
}
function Test-HwidMatch([string]$value, [string]$hwid) {
     if (-not $value -or -not $hwid) { return $false }
     $v = $value.Trim().ToLower()
     $n = $hwid.Trim().ToLower()
     return ($v -eq $n -or $v -eq ('root\' + $n))
}
function Test-DriverService([string]$name) {
     if (-not $name) { return $false }
     return (Test-Path -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $name))
}
function Find-HwidDevices([string]$hwid) {
     $found = @()
     if (-not $hwid) { return $found }
     $pnpWorks = $false
     try {
          # Get-PnpDevice returns only a summary; HardwareID is a separate
          # device property. Reading $d.HardwareID always yielded $null and
          # made a perfectly installed TAP adapter look missing.
          foreach ($d in @(Get-PnpDevice -Class Net -PresentOnly -ErrorAction Stop)) {
               $pnpWorks = $true
               $ids = @()
               try {
                    $ids = @((Get-PnpDeviceProperty -InstanceId $d.InstanceId `
                         -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction Stop).Data)
               } catch {
                    $reg = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + [string]$d.InstanceId
                    $ids = @((Get-ItemProperty -LiteralPath $reg -Name HardwareID `
                         -ErrorAction SilentlyContinue).HardwareID)
               }
               foreach ($h in $ids) {
                    if (Test-HwidMatch $h $hwid) {
                         $problem = $null
                         try {
                              $problem = (Get-PnpDeviceProperty -InstanceId $d.InstanceId `
                                   -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction Stop).Data
                         } catch { }
                         $found += [pscustomobject]@{
                              InstanceId = [string]$d.InstanceId
                              RegistryPath = ''
                              Status = [string]$d.Status
                              ProblemCode = $problem
                         }
                         break
                    }
               }
          }
     } catch { }
     if ($pnpWorks) { return $found }
     # Windows without the PnpDevice module (7/8): the same facts are in Enum.
     # The layout is Enum\<bus>\<device>\<instance> (ROOT\NET\0000) and
     # HardwareID lives on the INSTANCE key. Walking only two levels found
     # nothing and produced a truncated instance id, which Teardown could
     # never remove.
     $enum = 'HKLM:\SYSTEM\CurrentControlSet\Enum'
     foreach ($bus in @(Get-ChildItem -LiteralPath $enum -ErrorAction SilentlyContinue)) {
          foreach ($dev in @(Get-ChildItem -LiteralPath $bus.PSPath -ErrorAction SilentlyContinue)) {
               foreach ($inst in @(Get-ChildItem -LiteralPath $dev.PSPath -ErrorAction SilentlyContinue)) {
                    $ids = @((Get-ItemProperty -LiteralPath $inst.PSPath `
                         -Name HardwareID -ErrorAction SilentlyContinue).HardwareID)
                    foreach ($h in $ids) {
                         if (Test-HwidMatch $h $hwid) {
                              # No PnpDevice API here. 'Driver' exists only
                              # once a driver is bound to the devnode, and
                              # ConfigFlags bit 0x1 is CONFIGFLAG_DISABLED.
                              # Without this the fallback always said Unknown
                              # and the adapter was never considered ready.
                              $props = Get-ItemProperty -LiteralPath $inst.PSPath `
                                   -ErrorAction SilentlyContinue
                              $state = 'Error'
                              $problem = 28   # CM_PROB_FAILED_INSTALL
                              if ($props.Driver) {
                                   if (([int]$props.ConfigFlags -band 1) -ne 0) {
                                        $state = 'Disabled'
                                        $problem = 22  # CM_PROB_DISABLED
                                   } else {
                                        $state = 'OK'
                                        $problem = 0
                                   }
                              }
                              $found += [pscustomobject]@{
                                   InstanceId = ($bus.PSChildName + '\' +
                                        $dev.PSChildName + '\' + $inst.PSChildName)
                                   RegistryPath = $inst.PSPath
                                   Status = $state
                                   ProblemCode = $problem
                              }
                              break
                         }
                    }
               }
          }
     }
     return $found
}
function Test-AdapterReady([string]$hwid) {
     foreach ($dev in @(Find-HwidDevices $hwid)) {
          if ([string]$dev.Status -eq 'OK') { return $true }
          if ($null -ne $dev.ProblemCode -and [int]$dev.ProblemCode -eq 0) { return $true }
     }
     return $false
}
function Get-DriverPackageMissing($d) {
     $missing = @()
     if (-not $d.inf) { return @('INF path is empty') }
     $inf = Join-Path $root ([string]$d.inf -replace '/', '\')
     if (-not (Test-Path -LiteralPath $inf)) { return @([string]$d.inf) }
     $dir = Split-Path -Parent $inf
     $required = @()
     if ($d.required_files) {
          $required = @([string]$d.required_files -split ';' | Where-Object { $_ })
     }
     if ($required.Count -eq 0) {
          $svc = [string]$d.service
          if ($svc) { $required += ($svc + '.sys') }
     }
     foreach ($rel in $required) {
          $path = Join-Path $dir ($rel -replace '/', '\')
          if (-not (Test-Path -LiteralPath $path)) { $missing += $rel }
     }
     if ($required.Count -gt 0 -and -not (@($required | Where-Object { $_ -like '*.cat' }).Count)) {
          $cat = Get-ChildItem -LiteralPath $dir -Filter '*.cat' -File -ErrorAction SilentlyContinue |
                 Select-Object -First 1
          if (-not $cat) { $missing += ([string]$d.service + '.cat') }
     }
     return $missing
}
function Install-RootDevice([string]$infPath, [string]$hwid, [string]$toolPath,
     [string]$hardwareId = '') {
     if (Test-AdapterReady $hwid) { return $true }
     if ($toolPath -and (Test-Path -LiteralPath $toolPath)) {
          Write-SetupLog ('tapinstall: ' + $toolPath + ' install ' + $infPath + ' ' + $hwid)
          & $toolPath install $infPath $hwid 2>&1 |
               ForEach-Object { Write-SetupLog ([string]$_) }
          Write-SetupLog ('tapinstall exit: ' + $LASTEXITCODE)
          Start-Sleep -Milliseconds 400
          if (Test-AdapterReady $hwid) { return $true }
     }
     $installHwid = $hwid
     if ($hardwareId) { $installHwid = $hardwareId }
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

    public static int LastError;
    public static bool RebootRequired;

    static bool Fail() {
      LastError = Marshal.GetLastWin32Error();
      return false;
    }

    public static bool Install(string infPath, string hwid) {
      LastError = 0;
      RebootRequired = false;
      Guid classGuid;
      StringBuilder className = new StringBuilder(MAX_CLASS_NAME_LEN);
      uint required;
      if (!SetupDiGetINFClass(infPath, out classGuid, className,
          MAX_CLASS_NAME_LEN, out required)) return Fail();
      IntPtr set = SetupDiCreateDeviceInfoList(ref classGuid, IntPtr.Zero);
      if (set == IntPtr.Zero || set == new IntPtr(-1)) return Fail();
      SP_DEVINFO_DATA data = new SP_DEVINFO_DATA();
      data.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
      try {
        if (!SetupDiCreateDeviceInfo(set, className.ToString(), ref classGuid,
            null, IntPtr.Zero, DICD_GENERATE_ID, ref data)) return Fail();
        byte[] ids = Encoding.Unicode.GetBytes(hwid + "\0\0");
        if (!SetupDiSetDeviceRegistryProperty(set, ref data, SPDRP_HARDWAREID,
            ids, (uint)ids.Length)) return Fail();
        if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, ref data))
          return Fail();
        bool reboot;
        bool ok = UpdateDriverForPlugAndPlayDevices(IntPtr.Zero, hwid, infPath,
            INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, out reboot);
        if (!ok) {
          LastError = Marshal.GetLastWin32Error();
          SetupDiCallClassInstaller(DIF_REMOVE, set, ref data);
          return false;
        }
        RebootRequired = reboot;
        return true;
      } finally {
        SetupDiDestroyDeviceInfoList(set);
      }
    }
  }
}
'@
          try {
               Add-Type -TypeDefinition $source -ErrorAction Stop
          } catch {
               Write-SetupLog ('SetupAPI compiler unavailable: ' + $_.Exception.Message)
          }
     }
     if ('PortablizerNetStack.RootDevice' -as [type]) {
          try {
               $ok = [PortablizerNetStack.RootDevice]::Install($infPath, $installHwid)
               $err = [PortablizerNetStack.RootDevice]::LastError
               Write-SetupLog ('SetupAPI install ' + $installHwid + ': ok=' + $ok +
                    ' win32=' + $err)
               if ($ok -and [PortablizerNetStack.RootDevice]::RebootRequired) {
                    Write-SetupLog 'SetupAPI: a reboot is required to finish the driver install'
               }
          } catch {
               Write-SetupLog ('SetupAPI install failed: ' + $_.Exception.Message)
          }
     }
     Start-Sleep -Milliseconds 600
     return (Test-AdapterReady $hwid)
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
          if ($parts.Count -lt 2) {
               Write-SetupLog ('skip device without exact instance id: ' + $line)
               continue
          }
          $instance = $parts[1]
          # Remove ONLY the instance this portable created. Matching by hwid
          # here would also delete a TAP adapter owned by another VPN.
          if ($modern) {
               & pnputil /remove-device $instance 2>&1 | Out-Null
          } else {
               $reg = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + $instance
               Remove-Item -LiteralPath $reg -Recurse -Force -ErrorAction SilentlyContinue
          }
     }
     Remove-Item -LiteralPath $devicesPath -Force -ErrorAction SilentlyContinue
}
# --- companion services: the registry must point into THIS copy ------------
# A service registered by the vendor installer (or by an earlier copy of this
# portable) stores an ABSOLUTE ImagePath. After the folder is copied to another
# PC or moved to another drive that path leads nowhere: the service "exists",
# never starts, and the VPN client reports "Не удалось подключиться ни по
# одному из протоколов" although everything looks installed. So the ImagePath
# is compared with the one this copy needs, and a stale registration is
# replaced - but a live installation outside the portable is never touched.
function Get-ServiceExePath([string]$image) {
     if (-not $image) { return '' }
     $text = [Environment]::ExpandEnvironmentVariables($image.Trim())
     $text = $text.Replace('\??\', '')
     if ($text.StartsWith('"')) {
          $end = $text.IndexOf('"', 1)
          if ($end -gt 1) { return $text.Substring(1, $end - 1) }
          return $text.Trim('"')
     }
     $cut = $text.ToLower().IndexOf('.exe')
     if ($cut -gt 0) { return $text.Substring(0, $cut + 4) }
     return ($text -split '\s+')[0]
}
function Get-ServiceImagePath([string]$name) {
     if (-not $name) { return '' }
     $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $name
     return [string]((Get-ItemProperty -LiteralPath $key -Name ImagePath `
               -ErrorAction SilentlyContinue).ImagePath)
}
function Test-SamePath([string]$left, [string]$right) {
     if (-not $left -or -not $right) { return $false }
     return [string]::Equals($left.TrimEnd('\'), $right.TrimEnd('\'),
          [StringComparison]::OrdinalIgnoreCase)
}
function Test-ForeignService([string]$image) {
     # A service whose binary exists OUTSIDE a portable folder belongs to a
     # real installation on this PC: leave it alone (and never claim it).
     # A portable copy always has "PortableData" next to the folder its binary
     # lives in, so even a copy in another folder is recognised as ours.
     $exe = Get-ServiceExePath $image
     if (-not $exe) { return $false }
     if (-not (Test-Path -LiteralPath $exe)) { return $false }
     $dir = Split-Path -Parent $exe
     if ($dir -and (Test-Path -LiteralPath (Join-Path $dir 'PortableData'))) {
          return $false
     }
     $parent = Split-Path -Parent $dir
     if ($parent -and
          (Test-Path -LiteralPath (Join-Path $parent 'PortableData'))) {
          return $false
     }
     return $true
}
# --- adapters: present is not the same as usable ---------------------------
# A device can be present and DISABLED (or fail to start): the client sees the
# adapter, so it no longer says "not found", but every protocol fails. The
# elevated pass therefore enables the device instead of only creating it.
function Enable-HwidDevices([string]$hwid) {
     $changed = $false
     foreach ($dev in @(Find-HwidDevices $hwid)) {
          if (-not $dev.InstanceId) { continue }
          $status = ''
          try {
               $status = [string](Get-PnpDevice -InstanceId $dev.InstanceId `
                    -ErrorAction Stop).Status
          } catch { }
          if ($status -eq 'OK') { continue }
          try {
               Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false `
                    -ErrorAction Stop
               $changed = $true
               continue
          } catch { }
          & pnputil /enable-device $dev.InstanceId 2>&1 | Out-Null
          if ($LASTEXITCODE -eq 0) { $changed = $true }
     }
     if ($changed) { Start-Sleep -Milliseconds 700 }
     return $changed
}
function Write-NetStackStatus([bool]$serviceHealthy) {
     $lines = @()
     $lines += ('root: ' + $root)
     $lines += ('time: ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
     $driverHealthy = $true
     foreach ($d in @($cfg.drivers)) {
          if (-not $d.needs_install) { continue }
          $hwid = [string]$d.device_id
          $svcName = [string]$d.service
          if ($svcName) {
               $svcState = 'missing'
               if (Test-DriverService $svcName) { $svcState = 'present' }
               else { $driverHealthy = $false }
               $lines += ('driver ' + $svcName + ': ' + $svcState)
          }
          if (-not $hwid) { continue }
          $devices = @(Find-HwidDevices $hwid)
          $state = 'missing'
          if ($devices.Count -gt 0) {
               $state = [string]$devices[0].Status
               if (-not $state) { $state = 'present' }
          }
          if (-not (Test-AdapterReady $hwid)) { $driverHealthy = $false }
          $lines += ('adapter ' + $hwid + ': ' + $state)
          $missing = @(Get-DriverPackageMissing $d)
          if ($missing.Count -gt 0) {
               $lines += ('package ' + $hwid + ': incomplete | ' + ($missing -join ', '))
          }
     }
     foreach ($s in @($cfg.services)) {
          $name = [string]$s.name
          if (-not $name) { continue }
          $state = 'absent'
          $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
          if ($null -ne $svc) { $state = [string]$svc.Status }
          $lines += ('service ' + $name + ': ' + $state + ' | ' +
               (Get-ServiceImagePath $name))
     }
     $healthy = ($serviceHealthy -and $driverHealthy)
     $lines = @(('healthy: ' + $healthy)) + $lines
     Set-Content -LiteralPath (Join-Path $stateDir 'status.txt') -Value $lines `
          -Encoding UTF8 -ErrorAction SilentlyContinue
     return $healthy
}
function Test-NetStackPackages {
     foreach ($d in @($cfg.drivers)) {
          if (-not $d.needs_install) { continue }
          $hwid = [string]$d.device_id
          $svcName = [string]$d.service
          if ($hwid -and (Test-AdapterReady $hwid) -and
               (-not $svcName -or (Test-DriverService $svcName))) {
               continue
          }
          $missing = @(Get-DriverPackageMissing $d)
          if ($missing.Count -gt 0) {
               Write-SetupLog ('driver package ' + $hwid + ' is incomplete: ' +
                    ($missing -join ', '))
               return $false
          }
     }
     return $true
}
function Ensure-NetAdapters {
     $failed = $false
     $scanned = $false
     foreach ($d in @($cfg.drivers)) {
          if (-not $d.needs_install) { continue }
          $hwid = [string]$d.device_id
          if (-not $hwid) { continue }
          if (Test-AdapterReady $hwid) {
               Enable-HwidDevices $hwid | Out-Null
               continue
          }
          $missing = @(Get-DriverPackageMissing $d)
          if ($missing.Count -gt 0) {
               Write-SetupLog ('driver package ' + $hwid + ' is incomplete: ' +
                    ($missing -join ', '))
               return 2
          }
          $inf = Join-Path $root ([string]$d.inf -replace '/', '\')
          $tool = ''
          if ($d.tool) {
               $tool = Join-Path $root ([string]$d.tool -replace '/', '\')
          }
          $hardwareId = [string]$d.hardware_id
          if (-not $hardwareId) { $hardwareId = 'root\' + $hwid }
          $created = Install-RootDevice $inf $hwid $tool $hardwareId
          if (-not $scanned) {
               & pnputil /scan-devices 2>&1 | Out-Null
               $scanned = $true
          }
          Enable-HwidDevices $hwid | Out-Null
          $instances = @(Find-HwidDevices $hwid)
          if (-not (Test-AdapterReady $hwid)) { $failed = $true }
          if ($created) {
               $instance = ''
               if ($instances.Count -gt 0) {
                    $instance = [string]$instances[0].InstanceId
               }
               Remember-Device $hwid $instance
          }
     }
     if ($failed) { return 3 }
     return 0
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
     Write-NetStackStatus $false | Out-Null
     exit 0
}
$services = @($cfg.services)
if ($Mode -eq 'preflight') {
     if (Test-NetStackPackages) { exit 0 }
     Write-NetStackStatus $false | Out-Null
     exit 2
}
if ($Mode -eq 'check') {
     # Both halves are mandatory: the driver service AND a ready network
     # adapter. A registered service without a device is exactly the vendor
     # app's "adapter not found" state; a ghost/disabled device is not ready.
     $checkCode = 0
     foreach ($d in @($cfg.drivers)) {
          if (-not $d.needs_install) { continue }
          $hwid = [string]$d.device_id
          $svcName = [string]$d.service
          if ($svcName -and -not (Test-DriverService $svcName)) { $checkCode = 2 }
          if ($hwid -and -not (Test-AdapterReady $hwid)) {
               if ($checkCode -eq 0) { $checkCode = 3 }
          }
     }
     # A service is only useful when it exists, points to THIS copy and is
     # running: a stopped or stale service is exactly the "no protocol works"
     # state for a VPN client, and starting it needs no new installation.
     foreach ($s in $services) {
          $name = [string]$s.name
          if (-not $name) { continue }
          $current = Get-ServiceImagePath $name
          if (-not $current) { $checkCode = 4; break }
          if (Test-ForeignService $current) { continue }
          $exe = ([string]$s.image).Replace($token, $root)
          if (-not (Test-SamePath (Get-ServiceExePath $current) $exe)) { $checkCode = 4; break }
          if (-not (Test-Path -LiteralPath $exe)) { $checkCode = 4; break }
          $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
          if ($null -eq $svc) { $checkCode = 4; break }
          if (@('Running', 'StartPending') -notcontains [string]$svc.Status) {
               $checkCode = 4; break
          }
     }
     Write-NetStackStatus ($checkCode -eq 0) | Out-Null
     exit $checkCode
}
if ($Mode -eq 'detach') {
     # Shared mode (--remove-device): detach only our adapters, keep packages.
     Remove-RememberedDevices
     Write-NetStackStatus $false | Out-Null
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
     Write-NetStackStatus $false | Out-Null
     exit 0
}
# ensure: create only what is absent, remember only what we created.
# Adapters first: the VPN client cannot do anything without one, and its own
# driver installation needs the rights this elevated pass already has.
$adapterCode = Ensure-NetAdapters
if ($adapterCode -ne 0) {
     Write-NetStackStatus $false | Out-Null
     exit $adapterCode
}
if ($services.Count -eq 0) {
     # Драйвер-адаптер сам по себе: состояние всё равно фиксируется, иначе
     # после сеанса нечем объяснить, что именно было на машине.
     if (Write-NetStackStatus $true) { exit 0 }
     exit 3
}
$created = @()
if (Test-Path -LiteralPath $createdPath) {
     $created = @(Get-Content -LiteralPath $createdPath |
                  ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
$serviceFailed = $false
foreach ($s in $services) {
     $name = [string]$s.name
     if (-not $name) { continue }
     $exe = ([string]$s.image).Replace($token, $root)
     $image = $exe
     if ($s.args) { $image = $image + ' ' + $s.args }
     $type = if ($s.start -eq 'auto') { 'Automatic' } else { 'Manual' }
     $startArg = if ($s.start -eq 'auto') { 'auto' } else { 'demand' }
     $current = Get-ServiceImagePath $name
     $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
     if ($null -ne $svc) {
          $ours = (Test-SamePath (Get-ServiceExePath $current) $exe) -and
               (Test-Path -LiteralPath $exe)
          if (-not $ours -and (Test-ForeignService $current)) {
               Write-Output ("netstack: service '" + $name +
                    "' belongs to another installation (" + $current +
                    ") - left untouched")
               continue
          }
          if (-not $ours) {
               # Stale registration: the path points into the previous folder
               # (the portable was copied or moved). Replace it, and remember
               # the service as ours so the session end removes it again.
               Write-Output ("netstack: service '" + $name + "' pointed to " +
                    $current + " - re-registering it for this folder")
               Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
               sc.exe delete $name | Out-Null
               Start-Sleep -Milliseconds 400
               if ($created -notcontains $name) { $created += $name }
               $svc = $null
               $current = ''
          }
     }
     if ($null -ne $svc) {
          if ($svc.Status -ne 'Running') {
               Start-Service -Name $name -ErrorAction SilentlyContinue
               Start-Sleep -Milliseconds 600
               $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
          }
          if (($null -eq $svc) -or ($svc.Status -ne 'Running')) {
               Write-Output ("netstack: service '" + $name +
                    "' did not start")
               $serviceFailed = $true
          }
          continue
     }
     try {
          New-Service -Name $name -BinaryPathName ('"' + $image + '"') `
                -DisplayName $s.display -StartupType $type -ErrorAction Stop |
            Out-Null
          $created += $name
     } catch {
          # PS 5.1 на Win10 ругается на StartupType у уже существующих
          # служб; сюда приходим только когда New-Service реально отказал.
          sc.exe create $name binPath= "`"$image`"" start= $startArg DisplayName= "$($s.display)" obj= LocalSystem | Out-Null
          if ($LASTEXITCODE -eq 0) {
               $created += $name
          } else {
               Write-Output ("netstack: service '" + $name +
                    "' could not be created (sc exit " + $LASTEXITCODE + ")")
               $serviceFailed = $true
               continue
          }
     }
     Start-Service -Name $name -ErrorAction SilentlyContinue
     Start-Sleep -Milliseconds 600
     $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
     if (($null -eq $svc) -or ($svc.Status -ne 'Running')) {
          Write-Output ("netstack: service '" + $name + "' did not start")
          $serviceFailed = $true
     }
}
$created = @($created | Select-Object -Unique)
if ($created.Count -gt 0) {
     Set-Content -LiteralPath $createdPath -Value $created -Encoding UTF8
}
$healthy = Write-NetStackStatus (-not $serviceFailed)
if ($serviceFailed) { exit 6 }
if (-not $healthy) { exit 3 }
exit 0
'''


def render_services_ps1() -> str:
    """``NetStack\\NetStackServices.ps1`` — ensure | check | teardown |
    ownership | rollback.

    Коды выхода: 0 — всё в порядке; 4 — службы нет, её ``ImagePath`` ведёт в
    прежнюю папку или она остановлена (режим check); 6 — службу не удалось
    ни зарегистрировать, ни запустить (режим ensure); 5 — PowerShell слишком
    стар (нет ConvertFrom-Json), трогать ничего не стали.
    """
    return _PS1_BODY
