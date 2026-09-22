"""Определение типа установщика по содержимому exe/msi.

Разные семейства установщиков принимают разные ключи «тихой» установки и
разные способы задать целевую папку. Мы стараемся распознать наиболее
распространённые движки:

  * Inno Setup            -> /VERYSILENT /SUPPRESSMSGBOXES /DIR="..."
  * NSIS                  -> /S /D=...            (у /D особый синтаксис)
  * InstallShield         -> /s /v"/qn INSTALLDIR=..."  (часто через setup.exe)
  * WiX / MSI (msiexec)   -> /qn INSTALLDIR=... (через msiexec)
  * WiX Burn (bundle)     -> /quiet /install
  * InstallAware / Wise / install4j / BitRock / прочее -> эвристики
  * Собственный bootstrapper -> ключи вида ``--silent --installPath=...``

Определение построено на трёх независимых источниках:

1. **Структура PE.** Настоящий WiX Burn-бандл всегда имеет секцию с именем
   ``.wixburn``. Одноимённая строка внутри файла ничего не доказывает: она
   попадает в любой exe, который просто упоминает Burn (например, содержит
   его внутри себя как вложенный пакет). Раньше Portablizer верил строке и
   отправлял в заведомо чужой установщик ключи ``/quiet /install`` — тот
   падал с кодом ``-1`` (``0xFFFFFFFF``), ничего не установив.
2. **Байтовые сигнатуры** движков (быстро и без запуска).
3. **Ключи командной строки, которые установщик сам содержит внутри себя.**
   Современные bootstrapper'ы (в т.ч. .NET) разбирают аргументы вида
   ``--silent``, ``--installPath``, ``--accept-license-agreement`` и хранят
   эти строки в бинарнике. Найдя их, мы можем построить корректную тихую
   команду даже для установщика, которого не знаем «в лицо».
"""
from __future__ import annotations

import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Tuple


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
    found_switches: Set[str] = set()
    urls: List[str] = []
    seen_urls: Set[str] = set()

    longest = max(
        [len(encoded) for pair in
         [p for variants in signature_needles.values() for p in variants]
         for encoded in pair]
        + [len(encoded) for _t, pair in switch_needles for encoded in pair]
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
    result.urls = urls
    return result


def _decoded_views(data: bytes) -> List[str]:
    """Текстовые «проекции» блока: ASCII и UTF-16LE с обоими выравниваниями."""
    views = [data.decode("latin-1", "replace")]
    if b"\x00" in data:
        views.append(data.decode("utf-16-le", "replace"))
        views.append(data[1:].decode("utf-16-le", "replace"))
    return views


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
    #: В манифесте указан requireAdministrator — без UAC установка невозможна.
    requires_admin: bool = False
    is_dotnet: bool = False
    sections: List[str] = field(default_factory=list)
    #: К файлу приклеен ZIP — его можно распаковать, не запуская установщик.
    has_zip_payload: bool = False

    @property
    def human(self) -> str:
        return f"{self.installer_type.value} (уверенность {int(self.confidence * 100)}%)"

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

    scores: Dict[InstallerType, float] = {}
    evidence: Dict[InstallerType, List[str]] = {}

    for itype, matched in scan.signatures.items():
        hits = [sig.decode("latin-1", "replace") for sig in matched]
        if hits:
            scores[itype] = min(1.0, 0.55 + 0.15 * len(hits))
            evidence[itype] = [f"найдена сигнатура: {h}" for h in hits]

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

    if not scores:
        result = DetectionResult(
            InstallerType.UNKNOWN, 0.2,
            evidence=["ни одна известная сигнатура не найдена"])
    else:
        best = max(scores, key=lambda k: scores[k])
        result = DetectionResult(best, scores[best],
                                 evidence=list(evidence.get(best, [])))

    result.switch_hints = list(scan.switches)
    result.license_urls = list(scan.urls)
    result.requires_admin = scan.requires_admin
    result.is_dotnet = pe.is_dotnet
    result.sections = list(pe.sections)
    result.has_zip_payload = _has_zip_payload(path)

    if result.switch_hints:
        result.evidence.append(
            "ключи внутри файла: " + ", ".join(result.switch_hints[:8])
            + (" …" if len(result.switch_hints) > 8 else "")
        )
    if result.license_url:
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
