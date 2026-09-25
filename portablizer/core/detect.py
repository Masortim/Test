"""Определение типа установщика по содержимому exe/msi.

Разные семейства установщиков принимают разные ключи «тихой» установки и
разные способы задать целевую папку. Мы стараемся распознать наиболее
распространённые движки:

  * Inno Setup            -> /VERYSILENT /SUPPRESSMSGBOXES /DIR="..."
  * NSIS                  -> /S /D=...            (у /D особый синтаксис)
  * InstallShield         -> зависит от ПОКОЛЕНИЯ (см. InstallShieldGeneration):
                             обёртка над MSI   -> /s /v"/qn INSTALLDIR=..."
                             InstallScript 5/6 -> /s /f1"setup.iss" /f2"setup.log"
  * WiX / MSI (msiexec)   -> /qn INSTALLDIR=... (через msiexec)
  * WiX Burn (bundle)     -> /quiet /install
  * InstallAware / Wise / install4j / BitRock / прочее -> эвристики
  * Собственный bootstrapper -> ключи вида ``--silent --installPath=...``

Определение построено на четырёх независимых источниках:

1. **Структура PE.** Настоящий WiX Burn-бандл всегда имеет секцию с именем
   ``.wixburn``. Одноимённая строка внутри файла ничего не доказывает: она
   попадает в любой exe, который просто упоминает Burn (например, содержит
   его внутри себя как вложенный пакет). Раньше Portablizer верил строке и
   отправлял в заведомо чужой установщик ключи ``/quiet /install`` — тот
   падал с кодом ``-1`` (``0xFFFFFFFF``), ничего не установив.
2. **Байтовые сигнатуры** движков (быстро и без запуска). Одна короткая
   подстрока вроде «nsis» — слабое доказательство: она встречается и в чужих
   установщиках. Поэтому слабым сигнатурам без сильных подтверждений
   («Nullsoft Install System» и т.п.) уверенность сознательно занижается, а
   лестница попыток дополняется универсальными командами.
3. **Ключи командной строки, которые установщик сам содержит внутри себя.**
   Современные bootstrapper'ы (в т.ч. .NET) разбирают аргументы вида
   ``--silent``, ``--installPath``, ``--accept-license-agreement`` и хранят
   эти строки в бинарнике. Найдя их, мы можем построить корректную тихую
   команду даже для установщика, которого не знаем «в лицо».
4. **Профиль производителя.** У некоторых вендоров (ZennoLab) свежие сборки
   хранят строки упакованными — источники 2–3 молчат. Но имена файлов у их
   продуктов стандартизованы (``ZennoPosterLite-RU-v7.9.2.0.exe``), а точный
   синтаксис тихой установки опубликован в официальной документации. Если
   движок не опознан уверенно, а имя файла совпадает с профилем, ключи
   берутся из документации производителя.
"""
from __future__ import annotations

import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class InstallShieldGeneration(str, Enum):
    """Поколение InstallShield.

    Оба поколения дают на диске файл ``setup.exe`` с одинаковыми сигнатурами,
    но синтаксис тихой установки у них НЕСОВМЕСТИМ:

    * ``INSTALLSCRIPT`` — классический InstallScript (InstallShield 5/6,
      1998–2002; ресурсная библиотека ``_isres.dll``, компилированный скрипт
      ``setup.ins``, медиа ``data1.hdr``/``data1.cab``). Ключа ``/v`` он не
      знает, целевую папку из командной строки не принимает вовсе, а ``/s``
      работает ТОЛЬКО по заранее записанному файлу ответов ``setup.iss``
      (``/r``). Без файла ответов setup.exe выходит за пару секунд с кодом 0,
      оставив в ``setup.log`` ``ResultCode=-3``/``-5`` — ровно так выглядела
      неудача с диском «American McGee's Alice».
    * ``MSI`` — современная обёртка над MSI (Basic MSI / InstallScript MSI,
      InstallShield 7+): ``setup.exe /s /v"/qn INSTALLDIR=\\"…\\""``.
    """

    UNKNOWN = "поколение не определено"
    INSTALLSCRIPT = "InstallScript 5/6 (файл ответов setup.iss)"
    MSI = "обёртка над MSI (Basic MSI / InstallScript MSI)"


class InstallerType(str, Enum):
    INNO = "Inno Setup"
    NSIS = "NSIS"
    INSTALLSHIELD = "InstallShield"
    MSI = "Windows Installer (MSI)"
    WIX_BURN = "WiX Burn Bundle"
    INSTALLAWARE = "InstallAware"
    WISE = "Wise Installer"
    INSTALL4J = "install4j"
    BITROCK = "BitRock InstallBuilder"
    ADVANCED_INSTALLER = "Advanced Installer"
    SQUIRREL = "Squirrel/ClickOnce"
    SELF_EXTRACT = "Self-extracting archive"
    CUSTOM_CLI = "Custom CLI bootstrapper"
    UNKNOWN = "Unknown / Generic"


# Байтовые сигнатуры, которые встречаются внутри установщиков соответствующих
# движков. Список эвристический, но покрывает подавляющее большинство случаев.
_SIGNATURES: Dict[InstallerType, List[bytes]] = {
    InstallerType.INNO: [
        b"Inno Setup", b"JR.Inno.Setup", b"This installation was built with Inno Setup",
        b"InnoSetupLdrWindow", b"idp.dll",
    ],
    InstallerType.NSIS: [
        b"Nullsoft Install System", b"NullsoftInst", b"nsis", b"NSIS Error",
    ],
    InstallerType.INSTALLSHIELD: [
        b"InstallShield", b"ISSetup", b"isxdl", b"_isres",
    ],
    InstallerType.WIX_BURN: [
        b"WixBurn", b".wixburn", b"wixstdba",
    ],
    InstallerType.INSTALLAWARE: [
        b"InstallAware",
    ],
    InstallerType.WISE: [
        b"Wise Installation", b"WiseMain",
    ],
    InstallerType.INSTALL4J: [
        b"install4j", b"i4jparams",
    ],
    InstallerType.BITROCK: [
        b"BitRock Installer", b"InstallBuilder", b"installbuilder.com",
    ],
    InstallerType.ADVANCED_INSTALLER: [
        b"Advanced Installer", b"Caphyon",
    ],
    InstallerType.SQUIRREL: [
        b"Squirrel.Windows", b"SquirrelSetup", b"squirrel.exe",
    ],
    InstallerType.SELF_EXTRACT: [
        b"7-Zip", b"SFXWizard", b"WinRAR SFX", b"WinZip Self-Extractor",
    ],
}

#: Слабые сигнатуры. Короткая подстрока вроде «nsis» встречается и в чужих
#: установщиках (упоминание движка, вложенные ресурсы, URL). Реальный случай:
#: установщик ZennoPosterLite, опознанный как NSIS только по такой подстроке,
#: получил чужие ключи ``/S /D=``, завершился кодом -1 и ничего не установил.
#: Одно-два слабых совпадения без сильных подтверждений («Nullsoft Install
#: System» и т.п.) — не доказательство движка, а лишь повод понизить оценку.
_WEAK_SIGNATURES: Set[Tuple["InstallerType", bytes]] = {
    (InstallerType.NSIS, b"nsis"),
}

#: Оценка, начиная с которой определение считается заслуживающим доверия и
#: лестница попыток строится только из команд «своего» сценария. Ниже неё
#: добавляются универсальные запасные варианты (см. silentargs.build_attempts).
TRUSTED_CONFIDENCE = 0.6

#: Потолок уверенности для типа, опознанного только по слабым подстрокам.
_WEAK_ONLY_CONFIDENCE = 0.45

#: Ключи командной строки, которые умеют разбирать современные установщики.
#: Ищем их прямо в бинарнике: если установщик содержит строку ``--installPath``,
#: он почти наверняка её и разбирает. Регистр сохранён канонический — именно в
#: таком виде ключ будет передан установщику.
_SWITCH_TOKENS: Tuple[str, ...] = (
    # Собственные bootstrapper'ы (в т.ч. .NET).
    "--silent", "--hidden", "--quiet", "--unattended", "--nogui",
    "--accept-license-agreement", "--accept-licenses", "--acceptlicense",
    "--installPath", "--install-dir", "--installdir", "--prefix",
    "--installType", "--norestart", "--no-restart", "--verysilent",
    # Классические движки.
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NOICONS", "/NORESTART", "/SILENT",
    "/CURRENTUSER", "/ALLUSERS", "/DIR=", "/LOG=", "/LOADINF", "/SAVEINF",
    "/quiet", "/passive", "/layout", "/qn", "/qb", "/exenoui", "/exelog",
    "/extract_all", "/extract", "/uninstall", "/repair", "/install",
    # Имена публичных свойств целевой папки.
    "INSTALLDIR", "TARGETDIR", "InstallFolder", "APPDIR", "INSTALLLOCATION",
)

#: Строки-маркеры, которые не решают, ЧТО за движок, но говорят, КАКОГО ОН
#: ПОКОЛЕНИЯ. Для InstallShield это принципиально: у InstallScript 5/6 и у
#: обёртки над MSI командные строки несовместимы.
_MARKER_TOKENS: Tuple[str, ...] = (
    # Классический InstallScript (InstallShield 5/6).
    "_isres", "_setup.dll", "setup.ins", "isprobe", "ikernel",
    "_inst32i", "isdel.exe",
    # Обёртка над Windows Installer.
    "issetup.dll", "isscript.msi", "msiexec", "windows installer",
    "installshield setup launcher",
)

#: Файлы медиа-раскладки рядом с setup.exe. На дисках и в распакованных
#: образах они — самое надёжное доказательство поколения InstallShield:
#: заглядывать внутрь упакованного exe для этого не нужно.
_IS_LEGACY_MEDIA: Dict[str, int] = {
    "data1.hdr": 2, "setup.ins": 2, "_inst32i.ex_": 2, "_isres.dll": 2,
    "data1.cab": 1, "data2.cab": 1, "layout.bin": 1, "_sys1.cab": 1,
    "_user1.cab": 1, "engine32.cab": 1, "ikernel.ex_": 1, "_setup.dll": 1,
    "setup.ini": 0,
}

_IS_MSI_MEDIA: Dict[str, int] = {
    "issetup.dll": 2, "isscript.msi": 2, "instmsia.exe": 1,
    "instmsiw.exe": 1, "isscript11.msi": 2, "isscript1150.msi": 2,
}

#: Строка из встроенного манифеста: установщик обязательно требует UAC.
_ADMIN_MARKERS: Tuple[bytes, ...] = (
    b"requireadministrator",
    b"requireAdministrator".lower(),
)

_URL_RE = re.compile(
    r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,180}"
)

#: URL считается «ссылкой на лицензию», если содержит один из этих кусков.
_LICENSE_HINTS = ("terms", "license", "licence", "eula", "agreement", "legal")

_RESOURCE_SECTION = ".wixburn"


# --- профили производителей ---------------------------------------------------

@dataclass(frozen=True)
class VendorProfile:
    """Документированная командная строка установщиков одного вендора.

    Свежие сборки часто прячут служебные строки (упакованный .NET), поэтому
    эвристике по найденным в бинарнике ключам опереться не на что. Зато
    имена файлов продуктов стандартизованы, а синтаксис тихой установки
    опубликован самим производителем.
    """

    name: str                          # производитель (для журнала)
    filename_re: re.Pattern            # стандартизованное имя файла продукта
    hosts: Tuple[str, ...]             # характерные URL-хосты внутри бинарника
    switches: Tuple[str, ...]          # ключи из официальной документации
    license_url: str                   # URL, который требует --accept-license
    fixed_args: Tuple[str, ...] = ()   # документированные фиксированные ключи


_VENDOR_PROFILES: Tuple[VendorProfile, ...] = (
    # ZennoLab (docs.zennolab.com: «Silent Installation of ZennoLab Products»):
    #   product.exe --silent --hidden \
    #       --accept-license-agreement="https://zennolab.com/terms-of-service/" \
    #       --installPath="C:\\Path" --installType="StandAlone"
    # Без ключа принятия лицензии установщик завершается с кодом -1.
    # Тип StandAlone выбран осознанно: Default при наличии на этом ПК другой
    # версии продукта ОБНОВИЛ бы её, изменив чужую установку, а компьютер-
    # сборщик обещано оставить без изменений.
    VendorProfile(
        name="ZennoLab",
        filename_re=re.compile(r"zenno|capmonster", re.IGNORECASE),
        hosts=("zennolab.com",),
        switches=("--silent", "--hidden", "--accept-license-agreement",
                  "--installPath", "--installType"),
        license_url="https://zennolab.com/terms-of-service/",
        fixed_args=("--installType=StandAlone",),
    ),
)


def _vendor_profile(path: str) -> Optional[VendorProfile]:
    """Профиль производителя по имени файла установщика.

    Имя — умышленно «дешёвое» доказательство, поэтому профиль применяется
    только когда движок не опознан уверенно (см. detect_installer): случайно
    переименованный в Zenno*.exe установщик Inno Setup не пострадает.
    """
    basename = os.path.basename(path)
    for profile in _VENDOR_PROFILES:
        if profile.filename_re.search(basename):
            return profile
    return None


# --- разбор PE ----------------------------------------------------------------

@dataclass
class PEInfo:
    """Минимальные сведения из заголовка PE (без сторонних библиотек)."""

    is_pe: bool = False
    sections: List[str] = field(default_factory=list)
    is_dotnet: bool = False
    is_64bit: bool = False

    def has_section(self, name: str) -> bool:
        target = name.casefold()
        return any(s.casefold() == target for s in self.sections)


def read_pe_info(path: str) -> PEInfo:
    """Читает список секций и признак .NET прямо из заголовков PE.

    Нужен, чтобы отличать «настоящий» WiX Burn-бандл (секция ``.wixburn``) от
    файла, который лишь упоминает Burn внутри себя.
    """
    info = PEInfo()
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return info
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            if not 0 < e_lfanew < 0x1000000:
                return info
            fh.seek(e_lfanew)
            if fh.read(4) != b"PE\0\0":
                return info
            coff = fh.read(20)
            if len(coff) < 20:
                return info
            num_sections = struct.unpack_from("<H", coff, 2)[0]
            size_optional = struct.unpack_from("<H", coff, 16)[0]
            optional = fh.read(size_optional) if size_optional else b""
            info.is_pe = True

            if len(optional) >= 2:
                magic = struct.unpack_from("<H", optional, 0)[0]
                info.is_64bit = magic == 0x20B
                # Каталог данных №14 — заголовок CLR (признак .NET-сборки).
                dir_offset = 112 if info.is_64bit else 96
                count_offset = dir_offset - 4
                if len(optional) >= count_offset + 4:
                    count = struct.unpack_from("<I", optional, count_offset)[0]
                    clr = dir_offset + 14 * 8
                    if count > 14 and len(optional) >= clr + 8:
                        rva, size = struct.unpack_from("<II", optional, clr)
                        info.is_dotnet = bool(rva and size)

            raw = fh.read(40 * min(num_sections, 96))
            for i in range(len(raw) // 40):
                name = raw[i * 40:i * 40 + 8].rstrip(b"\0")
                info.sections.append(name.decode("latin-1", "replace"))
    except OSError:
        return PEInfo()
    return info


# --- сканирование содержимого -------------------------------------------------

@dataclass
class ScanResult:
    """Что нашлось при однопроходном чтении файла."""

    signatures: Dict[InstallerType, List[bytes]] = field(default_factory=dict)
    switches: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    requires_admin: bool = False
    #: Найденные строки-маркеры поколения (см. ``_MARKER_TOKENS``).
    markers: Set[str] = field(default_factory=set)


def _needles(text: str) -> Tuple[bytes, bytes]:
    """ASCII- и UTF-16LE-представления строки в нижнем регистре."""
    lowered = text.casefold()
    return lowered.encode("latin-1", "replace"), lowered.encode("utf-16-le")


def scan_file(path: str, chunk_size: int = 4 * 1024 * 1024) -> ScanResult:
    """Ищет сигнатуры, ключи и URL во всём файле, не загружая его целиком.

    Раньше проверялись только первые и последние 6 МБ. У крупных установщиков
    маркер движка часто находится посередине, из-за чего они ошибочно получали
    универсальный ключ ``/S`` и ничего не записывали в ``App``.
    """
    result = ScanResult(signatures={itype: [] for itype in _SIGNATURES})

    signature_needles: Dict[InstallerType, List[Tuple[bytes, bytes]]] = {
        itype: [_needles(sig.decode("latin-1")) for sig in signatures]
        for itype, signatures in _SIGNATURES.items()
    }
    switch_needles = [(token, _needles(token)) for token in _SWITCH_TOKENS]
    marker_needles = [(token, _needles(token)) for token in _MARKER_TOKENS]
    found_switches: Set[str] = set()
    found_markers: Set[str] = set()
    urls: List[str] = []
    seen_urls: Set[str] = set()

    longest = max(
        [len(encoded) for pair in
         [p for variants in signature_needles.values() for p in variants]
         for encoded in pair]
        + [len(encoded) for _t, pair in switch_needles for encoded in pair]
        + [len(encoded) for _t, pair in marker_needles for encoded in pair]
        + [400]  # запас на URL, разрезанный границей чанка
    )

    carry = b""
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                window = carry + chunk
                data = window.lower()

                for itype, variants in signature_needles.items():
                    for index, (ascii_sig, wide_sig) in enumerate(variants):
                        original = _SIGNATURES[itype][index]
                        if original in result.signatures[itype]:
                            continue
                        if ascii_sig in data or wide_sig in data:
                            result.signatures[itype].append(original)

                for token, (ascii_sig, wide_sig) in switch_needles:
                    if token in found_switches:
                        continue
                    if ascii_sig in data or wide_sig in data:
                        found_switches.add(token)

                for token, (ascii_sig, wide_sig) in marker_needles:
                    if token in found_markers:
                        continue
                    if ascii_sig in data or wide_sig in data:
                        found_markers.add(token)

                if not result.requires_admin:
                    result.requires_admin = any(m in data for m in _ADMIN_MARKERS)

                for text in _decoded_views(window):
                    for match in _URL_RE.findall(text):
                        url = match.rstrip(".,);\"'").strip()
                        key = url.casefold()
                        if key in seen_urls or len(urls) >= 64:
                            continue
                        seen_urls.add(key)
                        urls.append(url)

                carry = window[-(longest - 1):] if longest > 1 else b""
    except OSError:
        return result

    result.switches = [t for t in _SWITCH_TOKENS if t in found_switches]
    result.markers = found_markers
    result.urls = urls
    return result


def _decoded_views(data: bytes) -> List[str]:
    """Текстовые «проекции» блока: ASCII и UTF-16LE с обоими выравниваниями."""
    views = [data.decode("latin-1", "replace")]
    if b"\x00" in data:
        views.append(data.decode("utf-16-le", "replace"))
        views.append(data[1:].decode("utf-16-le", "replace"))
    return views


# --- медиа-раскладка рядом с установщиком -------------------------------------

@dataclass
class MediaLayout:
    """Что лежит в одной папке с установщиком.

    Классические установщики на дисках (CD/DVD, распакованный ISO) — это не
    один exe, а раскладка: ``setup.exe`` + ``data1.cab``/``data1.hdr`` +
    ``setup.ins``. По ней поколение InstallShield определяется точнее, чем по
    строкам внутри самого exe, и заодно находится готовый файл ответов
    ``setup.iss``, если он есть на диске.
    """

    directory: str = ""
    files: List[str] = field(default_factory=list)
    #: Найденные файлы ответов InstallShield (*.iss).
    response_files: List[str] = field(default_factory=list)
    #: MSI-пакеты рядом с setup.exe (признак обёртки над Windows Installer).
    msi_files: List[str] = field(default_factory=list)
    legacy_hits: List[str] = field(default_factory=list)
    msi_hits: List[str] = field(default_factory=list)

    @property
    def legacy_score(self) -> int:
        return sum(_IS_LEGACY_MEDIA.get(name, 0) for name in self.legacy_hits)

    @property
    def msi_score(self) -> int:
        score = sum(_IS_MSI_MEDIA.get(name, 0) for name in self.msi_hits)
        return score + (2 if self.msi_files else 0)


def scan_media_layout(path: str, limit: int = 4000) -> MediaLayout:
    """Читает список файлов рядом с установщиком (без рекурсии)."""
    layout = MediaLayout(directory=os.path.dirname(os.path.abspath(path)))
    try:
        with os.scandir(layout.directory) as entries:
            for index, entry in enumerate(entries):
                if index >= limit:
                    break
                if not entry.is_file():
                    continue
                layout.files.append(entry.name)
    except OSError:
        return layout

    installer_name = os.path.basename(path).casefold()
    for name in layout.files:
        lowered = name.casefold()
        if lowered == installer_name:
            continue
        if lowered.endswith(".iss"):
            layout.response_files.append(os.path.join(layout.directory, name))
        elif lowered.endswith(".msi"):
            layout.msi_files.append(os.path.join(layout.directory, name))
        if lowered in _IS_MSI_MEDIA:
            layout.msi_hits.append(lowered)
        elif lowered in _IS_LEGACY_MEDIA:
            layout.legacy_hits.append(lowered)
    # setup.iss рядом с setup.exe — то, что ищет `/s` по умолчанию.
    layout.response_files.sort(
        key=lambda p: (os.path.basename(p).casefold() != "setup.iss",
                       os.path.basename(p).casefold()))
    return layout


def installshield_generation(
    scan: ScanResult, layout: MediaLayout,
) -> Tuple[InstallShieldGeneration, List[str]]:
    """Определяет поколение InstallShield и объясняет, почему именно так."""
    evidence: List[str] = []

    legacy_markers = {"_isres": 2, "setup.ins": 2, "_inst32i": 2,
                      "_setup.dll": 1, "ikernel": 1, "isprobe": 1,
                      "isdel.exe": 1}
    msi_markers = {"issetup.dll": 2, "isscript.msi": 2,
                   "installshield setup launcher": 1, "msiexec": 1,
                   "windows installer": 1}

    legacy = sum(weight for token, weight in legacy_markers.items()
                 if token in scan.markers)
    msi = sum(weight for token, weight in msi_markers.items()
              if token in scan.markers)
    hit_names = [t for t in legacy_markers if t in scan.markers]
    if hit_names:
        evidence.append("строки InstallScript внутри setup.exe: "
                        + ", ".join(hit_names))
    msi_names = [t for t in msi_markers if t in scan.markers]
    if msi_names:
        evidence.append("строки обёртки над MSI: " + ", ".join(msi_names))

    legacy += layout.legacy_score
    msi += layout.msi_score
    if layout.legacy_hits:
        evidence.append("медиа-раскладка рядом с установщиком: "
                        + ", ".join(sorted(set(layout.legacy_hits))))
    if layout.msi_files:
        evidence.append(
            "рядом лежит MSI-пакет: "
            + ", ".join(sorted(os.path.basename(m)
                               for m in layout.msi_files)[:3]))
    if layout.response_files:
        evidence.append(
            "найден готовый файл ответов: "
            + ", ".join(sorted(os.path.basename(r)
                               for r in layout.response_files)[:3]))

    if msi >= 2 and msi >= legacy:
        return InstallShieldGeneration.MSI, evidence
    if legacy >= 2:
        return InstallShieldGeneration.INSTALLSCRIPT, evidence
    return InstallShieldGeneration.UNKNOWN, evidence


# --- результат ----------------------------------------------------------------

@dataclass
class DetectionResult:
    installer_type: InstallerType
    confidence: float  # 0..1
    is_msi: bool = False
    evidence: List[str] = field(default_factory=list)
    #: Ключи командной строки, найденные внутри самого установщика.
    switch_hints: List[str] = field(default_factory=list)
    #: URL лицензионного соглашения (нужен установщикам с --accept-license-*).
    license_urls: List[str] = field(default_factory=list)
    #: Фиксированные аргументы из документации производителя (профиль вендора);
    #: строками в бинарнике их не найти, значения заданы самим вендором.
    vendor_args: List[str] = field(default_factory=list)
    #: Имя производителя из профиля вендора (для показа пользователю).
    vendor_name: str = ""
    #: В манифесте указан requireAdministrator — без UAC установка невозможна.
    requires_admin: bool = False
    is_dotnet: bool = False
    sections: List[str] = field(default_factory=list)
    #: К файлу приклеен ZIP — его можно распаковать, не запуская установщик.
    has_zip_payload: bool = False
    #: Поколение InstallShield: от него зависит весь синтаксис тишины.
    installshield_generation: InstallShieldGeneration = (
        InstallShieldGeneration.UNKNOWN)
    #: Файлы ответов (*.iss), найденные рядом с установщиком.
    response_files: List[str] = field(default_factory=list)
    #: Папка с установщиком (медиа-раскладка диска).
    media_dir: str = ""

    @property
    def human(self) -> str:
        prefix = f"{self.vendor_name}: " if self.vendor_name else ""
        suffix = ""
        if (self.installer_type == InstallerType.INSTALLSHIELD
                and self.installshield_generation
                != InstallShieldGeneration.UNKNOWN):
            suffix = f", {self.installshield_generation.value}"
        return (f"{prefix}{self.installer_type.value}{suffix} "
                f"(уверенность {int(self.confidence * 100)}%)")

    @property
    def is_legacy_installshield(self) -> bool:
        """InstallScript 5/6: ни ``/v``, ни целевой папки в командной строке."""
        return (self.installer_type == InstallerType.INSTALLSHIELD
                and self.installshield_generation
                == InstallShieldGeneration.INSTALLSCRIPT)

    @property
    def response_file(self) -> str:
        return self.response_files[0] if self.response_files else ""

    def has_switch(self, *tokens: str) -> bool:
        available = {s.casefold() for s in self.switch_hints}
        return any(t.casefold() in available for t in tokens)

    def switch(self, token: str) -> str:
        """Возвращает ключ в том виде, в каком он найден в установщике."""
        for hint in self.switch_hints:
            if hint.casefold() == token.casefold():
                return hint
        return token

    @property
    def license_url(self) -> str:
        for url in self.license_urls:
            lowered = url.casefold()
            if any(hint in lowered for hint in _LICENSE_HINTS):
                return url
        return ""


def _has_zip_payload(path: str) -> bool:
    """True, если к exe приклеен ZIP (частый приём у .NET-инсталляторов)."""
    try:
        return zipfile.is_zipfile(path)
    except (OSError, zipfile.BadZipFile):
        return False


def detect_installer(path: str) -> DetectionResult:
    """Определяет тип установщика по пути к файлу."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".msi":
        return DetectionResult(InstallerType.MSI, 1.0, is_msi=True,
                               evidence=["расширение .msi"])

    if not os.path.isfile(path):
        return DetectionResult(InstallerType.UNKNOWN, 0.0,
                               evidence=["файл не найден"])

    pe = read_pe_info(path)
    scan = scan_file(path)
    layout = scan_media_layout(path)

    scores: Dict[InstallerType, float] = {}
    evidence: Dict[InstallerType, List[str]] = {}

    for itype, matched in scan.signatures.items():
        hits = [sig.decode("latin-1", "replace") for sig in matched]
        if not hits:
            continue
        strong = [sig for sig in matched
                  if (itype, sig) not in _WEAK_SIGNATURES]
        if strong:
            scores[itype] = min(1.0, 0.55 + 0.15 * len(strong))
        else:
            # Только слабые подстроки: верим мало — иначе чужому установщику
            # уйдут ключи движка, которого в нём нет.
            scores[itype] = min(_WEAK_ONLY_CONFIDENCE,
                                0.35 + 0.05 * len(matched))
        evidence[itype] = [f"найдена сигнатура: {h}" for h in hits]
        if not strong:
            evidence[itype].append(
                "совпали лишь слабые подстроки — такой тип не подтверждён "
                "и будет дополнен универсальными запасными командами")

    # Настоящий Burn-бандл опознаётся только по секции PE. Строка «WixBurn»
    # внутри файла означает лишь упоминание движка: так выглядят, например,
    # инсталляторы, которые несут Burn-пакет внутри себя. Раньше именно эта
    # ошибка приводила к запуску «/quiet /install» и коду -1.
    burn_section = pe.has_section(_RESOURCE_SECTION)
    if burn_section:
        scores[InstallerType.WIX_BURN] = 0.97
        evidence[InstallerType.WIX_BURN] = [
            f"в PE есть секция {_RESOURCE_SECTION} — это настоящий Burn-бандл",
        ]
    elif InstallerType.WIX_BURN in scores:
        scores[InstallerType.WIX_BURN] = min(
            scores[InstallerType.WIX_BURN], 0.35)
        evidence[InstallerType.WIX_BURN].append(
            f"секции {_RESOURCE_SECTION} в PE нет — упоминание Burn "
            "недостаточно для вывода о типе"
        )

    # Установщик, который сам содержит свои ключи командной строки.
    cli_evidence: List[str] = []
    strong_cli = [t for t in ("--accept-license-agreement", "--accept-licenses",
                              "--installPath", "--install-dir", "--installType")
                  if t in scan.switches]
    silent_cli = [t for t in ("--silent", "--unattended", "--quiet", "--hidden")
                  if t in scan.switches]
    if strong_cli and silent_cli:
        score = 0.72 + 0.06 * min(3, len(strong_cli))
        if pe.is_dotnet:
            score += 0.05
        scores[InstallerType.CUSTOM_CLI] = min(0.95, score)
        cli_evidence = [
            "установщик содержит собственные ключи: "
            + ", ".join(strong_cli + silent_cli),
        ]
        if pe.is_dotnet:
            cli_evidence.append(".NET-сборка (собственный bootstrapper)")
        evidence[InstallerType.CUSTOM_CLI] = cli_evidence

    # Раскладка диска (``data1.hdr`` + ``setup.ins`` рядом с setup.exe) —
    # доказательство не хуже сигнатуры: у упакованных или очень старых
    # setup.exe строки внутри файла могут не найтись вовсе.
    rival = max((score for itype, score in scores.items()
                 if itype != InstallerType.INSTALLSHIELD), default=0.0)
    if (layout.legacy_score >= 3 or layout.msi_score >= 3) and rival < 0.85:
        proven = max(scores.get(InstallerType.INSTALLSHIELD, 0.0), 0.9)
        scores[InstallerType.INSTALLSHIELD] = proven
        evidence.setdefault(InstallerType.INSTALLSHIELD, []).append(
            "рядом с установщиком лежит медиа-раскладка InstallShield")

    if not scores:
        result = DetectionResult(
            InstallerType.UNKNOWN, 0.2,
            evidence=["ни одна известная сигнатура не найдена"])
    else:
        best = max(scores, key=lambda k: scores[k])
        result = DetectionResult(best, scores[best],
                                 evidence=list(evidence.get(best, [])))

    # Профиль производителя — только если движок не опознан уверенно, а его
    # строковые ключи в бинарнике не нашлись (тип CUSTOM_CLI выше — как раз
    # они и есть). Сильная сигнатура настоящего движка для нас важнее имени
    # файла: репак, названный Zenno*.exe, но собранный в Inno Setup,
    # обрабатывается как Inno Setup.
    profile: Optional[VendorProfile] = None
    if (result.installer_type != InstallerType.CUSTOM_CLI
            and result.confidence < TRUSTED_CONFIDENCE):
        profile = _vendor_profile(path)
    if profile is not None:
        vendor_evidence = [
            f"установщик {profile.name}: имя файла соответствует продукту "
            f"этого производителя; строки внутри сборки упакованы, поэтому "
            f"ключи взяты из официальной документации {profile.name}",
            "ключи из документации: " + ", ".join(profile.switches),
            f"обязательное принятие лицензии: {profile.license_url}",
        ]
        if any(host in url for url in scan.urls for host in profile.hosts):
            vendor_evidence.append(
                "внутри найден сайт производителя: "
                + ", ".join(profile.hosts))
        scan_evidence = result.evidence
        result = DetectionResult(
            InstallerType.CUSTOM_CLI, 0.8,
            evidence=vendor_evidence + scan_evidence,
            switch_hints=list(profile.switches),
            license_urls=[profile.license_url]
            + [u for u in scan.urls if u != profile.license_url],
            vendor_args=list(profile.fixed_args),
            vendor_name=profile.name)

    if profile is None:
        result.switch_hints = list(scan.switches)
        result.license_urls = list(scan.urls)
    result.requires_admin = scan.requires_admin
    result.is_dotnet = pe.is_dotnet
    result.sections = list(pe.sections)
    result.has_zip_payload = _has_zip_payload(path)
    result.media_dir = layout.directory
    result.response_files = list(layout.response_files)

    if result.installer_type == InstallerType.INSTALLSHIELD:
        generation, generation_evidence = installshield_generation(scan, layout)
        result.installshield_generation = generation
        result.evidence.extend(generation_evidence)
        if generation == InstallShieldGeneration.INSTALLSCRIPT:
            result.evidence.append(
                "InstallScript 5/6: ключ /v не поддерживается, целевая папка "
                "из командной строки не принимается, а /s работает только по "
                "записанному файлу ответов setup.iss"
            )
        elif generation == InstallShieldGeneration.UNKNOWN:
            result.evidence.append(
                "поколение InstallShield определить не удалось — будут "
                "испробованы команды обоих поколений"
            )

    if profile is None and result.switch_hints:
        result.evidence.append(
            "ключи внутри файла: " + ", ".join(result.switch_hints[:8])
            + (" …" if len(result.switch_hints) > 8 else "")
        )
    if profile is None and result.license_url:
        result.evidence.append(
            f"ссылка на лицензионное соглашение: {result.license_url}")
    if result.requires_admin:
        result.evidence.append(
            "в манифесте requireAdministrator — установщик обязательно "
            "запросит права администратора"
        )
    if result.has_zip_payload:
        result.evidence.append("внутри есть ZIP — возможна распаковка без установки")
    return result
