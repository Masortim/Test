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
4. **Профиль производителя.** У некоторых вендоров (ZennoLab, Planeta VPN)
   свежие сборки хранят строки упакованными — источники 2–3 молчат. Но имена
   файлов у их продуктов стандартизованы (``ZennoPosterLite-RU-v7.9.2.0.exe``),
   а точный синтаксис тихой установки опубликован в официальной документации
   либо известен по движку продукта: профиль может задать ``installer_hint``
   (например, NSIS для VPN-клиентов, у которых публикаций по тихой установке
   нет вовсе). Если движок не опознан уверенно, а имя файла совпадает с
   профилем, ключи берутся из документации производителя.
"""
from __future__ import annotations

import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from . import space as space_mod


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

#: Малый EXE может быть не установщиком программы, а сетевой «заглушкой».
#: Порог отделяет компактный downloader от полного дистрибутива в сотни МБ.
DOWNLOADER_STUB_MAX_BYTES = 128 * 1024 * 1024

#: Признаки того, что bootstrapper умеет скачивать содержимое из сети.
#: Требуем одновременно API загрузки и адрес раздачи: наличие одного URL
#: поддержки или WinHTTP само по себе не делает обычный установщик заглушкой.
_DOWNLOAD_API_TOKENS: Tuple[str, ...] = (
    "URLDownloadToFile", "WinHttpOpen", "WinHttpReadData",
    "InternetOpenUrl", "InternetReadFile", "BackgroundCopyManager",
)
_DOWNLOAD_URL_HINTS = (
    "download", "downloads", "cdn.", "dl.", "/installers/", "/packages/",
    "/production/", ".exe", ".msi", ".zip", ".7z", ".cab",
)


@dataclass(frozen=True)
class OnlineOnlyProduct:
    """Профиль продукта, чей маленький файл — лишь сетевой загрузчик."""

    name: str
    filename_re: re.Pattern
    switches: Tuple[str, ...]
    reason: str
    #: Относительный каталог в перенаправленном LOCALAPPDATA, куда клиент
    #: разворачивает содержимое. Пусто для профилей без известного пути.
    profile_root: str = ""
    #: Исполняемые файлы, которые являются подтверждёнными точками входа.
    #: Не подменять их произвольным EXE из многотысячного webdeploy payload.
    entrypoint_exe_names: Tuple[str, ...] = ()


_ONLINE_ONLY_PRODUCTS: Tuple[OnlineOnlyProduct, ...] = (
    OnlineOnlyProduct(
        name="Autodesk Fusion",
        filename_re=re.compile(
            r"^(?=.*fusion)(?=.*(?:360|setup|downloader)).*\.exe$",
            re.IGNORECASE),
        # Документирован только тихий режим. --globalinstall не добавляем:
        # он регистрирует клиент в Program Files текущего компьютера.
        switches=("--quiet",),
        reason=(
            "это потоковый клиентский загрузчик: клиент разворачивается в "
            "%LOCALAPPDATA%\\Autodesk\\webdeploy\\production, обновляется "
            "через Autodesk и требует входа в аккаунт"
        ),
        profile_root="Autodesk/webdeploy/production",
        entrypoint_exe_names=("FusionLauncher.exe",),
    ),
)

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
    #: Движок, который вендор использует на самом деле, когда строки внутри
    #: сборки упакованы и сигнатуру движка найти нельзя (Planeta VPN — NSIS).
    #: Без него неопознанный установщик уехал бы в CUSTOM_CLI со «своими»
    #: ключами, которых у вендора нет.
    installer_hint: Optional[InstallerType] = None


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
    # Planeta VPN (planetavpn.com): клиент собран на NSIS; безлюдная установка
    # — «/S /D=<папка>». Отдельный профиль нужен вот чем: у свежих сборок
    # строки упакованы, слабая подстрока «nsis» давала бы 55 % уверенности и
    # одну команду с правом на ошибку, а имя файла стандартизовано
    # (``planeta_installer*.exe`` / ``PlanetaVPN*.exe``). Публикаций по тихой
    # установке вендор не ведёт — поэтому лицензионный URL не требуется, а
    # движок задаётся явно (NSIS, не CUSTOM_CLI): лестница сразу строится по
    # движку продукта, включая особый синтаксис ключа /D=.
    VendorProfile(
        name="Planeta VPN",
        filename_re=re.compile(
            r"planeta[\s._-]*(vpn|installer|setup|client)|planetavpn",
            re.IGNORECASE),
        hosts=("planetavpn.com",),
        switches=("/S", "/D=", "/NCRC"),
        license_url="",
        installer_hint=InstallerType.NSIS,
    ),
)


# --- профили перепаковщиков ---------------------------------------------------
#
# Репак — это не движок и не вендор: это конкретная сборка, автор которой
# заменил мастер установки своим скриптом. У KpoJIuK такой скрипт собран на Inno
# Setup, но разбирает командную строку сам: привычные ключи Inno
# (``/VERYSILENT``, ``/DIR=``) он не понимает и открывает мастер с вопросами о
# языке и папке. Документированный синтаксис его сборок —
# ``/S /RU /D=ПУТЬ`` (ключ пути последним, без кавычек).
#
# Без такого профиля Portablizer выбирал команду по движку (Inno), установщик
# показывал окно выбора языка и путь по умолчанию, сборка стояла на месте, а
# каждый следующий сценарий лестницы открывал мастер заново — пользователь
# видел один и тот же вопрос несколько раз.

@dataclass(frozen=True)
class RepackProfile:
    """Документированная командная строка известного перепаковщика."""

    name: str                          # автор репака (для журнала)
    product: str                       # продукт, который он перепаковывает
    filename_re: re.Pattern            # как называется файл репака
    silent_switch: str = "/S"          # «тихий режим» этого скрипта
    path_switch: str = "/D="           # ключ папки — последним, без кавычек
    #: Код языка (``ru``) -> короткий ключ (``/RU``). Пустой кортеж — язык
    #: скрипт не принимает.
    language_switches: Tuple[Tuple[str, str], ...] = ()
    hosts: Tuple[str, ...] = ()
    #: Движок, на котором собран репак: важен для подсказок и для запасных
    #: сценариев (распаковка, отчёт о журнале).
    engine_hint: InstallerType = InstallerType.INNO


_REPACK_PROFILES: Tuple[RepackProfile, ...] = (
    # SketchUp Pro RePack by KpoJIuK (например, SketchUp Pro v26.1.189.exe).
    # Документированные параметры (публикуются вместе с раздачей):
    #   Тихая установка русской версии: /S /RU
    #   Тихая установка английской версии: /S /EN
    #   Выбор места установки: /D=ПУТЬ (указывать самым последним)
    # Официальный установщик Trimble называется иначе (SketchUpFull-… exe /
    # SketchUpPro-… exe), собирается WiX Burn и сюда не попадает.
    RepackProfile(
        name="KpoJIuK",
        product="SketchUp Pro",
        # Именно «SketchUp Pro <версия с точками>» (репак) или прямое
        # упоминание автора. Официальный файл Trimble называется
        # «SketchUpFull-2026-…exe» / «SketchUpPro-2026-0-…exe» (дефисы, не
        # точки) и, главное, собирается WiX Burn — такой профиль к нему не
        # применяется.
        filename_re=re.compile(
            r"^\s*sketchup[\s._-]*pro\b.*\bv?\d+(?:\.\d+){2,}"
            r"|repack[\s._-]*by[\s._-]*kpojiuk",
            re.IGNORECASE),
        language_switches=(("ru", "/RU"), ("en", "/EN")),
        hosts=("sketchup.com", "trimble.com"),
    ),
)


def _repack_profile(path: str) -> Optional[RepackProfile]:
    """Профиль перепаковщика по стандартизованному имени файла."""
    basename = os.path.basename(path)
    for profile in _REPACK_PROFILES:
        if profile.filename_re.search(basename):
            return profile
    return None


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

#: Маркеры офлайн-установщика GOG. Сами по себе тип движка не решают
#: (это почти всегда Inno Setup), но от них зависит имя языка в ``/LANG=``
#: и пост-обработка ``goggame-*.info``.
_GOG_MARKERS: Tuple[str, ...] = (
    "gog.com", "gog galaxy", "goggame-", "gog.com/games",
)

#: Пары «короткий код + английское имя» как их кладёт Inno Setup GOG:
#: ``ru\\0Russian``. По ним ``/LANG=`` берёт ``ru``, а не ``russian``.
_INNO_SHORT_LANG_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("en", "english"),
    ("ru", "russian"),
    ("uk", "ukrainian"),
    ("de", "german"),
    ("fr", "french"),
    ("it", "italian"),
    ("es", "spanish"),
    ("pl", "polish"),
    ("pt", "brazilianportuguese"),
    ("pt", "portuguese"),
    ("br", "brazilian"),
    ("zh", "chinesesimplified"),
    ("zh", "chinese"),
    ("ja", "japanese"),
    ("tr", "turkish"),
)

#: Полные имена секции [Languages] обычного (не GOG) Inno Setup.
_INNO_LONG_LANG_NAMES: Tuple[str, ...] = (
    "english", "russian", "ukrainian", "german", "french", "italian",
    "spanish", "polish", "brazilianportuguese", "chinesesimplified",
    "japanese", "turkish",
)


def _wide_bytes(ascii_data: bytes) -> bytes:
    """ASCII (включая нули) → UTF-16LE."""
    return b"".join(bytes((byte, 0)) for byte in ascii_data)


@dataclass
class ScanResult:
    """Что нашлось при однопроходном чтении файла."""

    signatures: Dict[InstallerType, List[bytes]] = field(default_factory=dict)
    switches: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    requires_admin: bool = False
    #: Найденные строки-маркеры поколения (см. ``_MARKER_TOKENS``).
    markers: Set[str] = field(default_factory=set)
    #: Маркеры GOG (gog.com, goggame- и т.п.).
    gog_hits: List[str] = field(default_factory=list)
    #: Имена языков Inno Setup, найденные внутри файла (``ru``, ``russian``).
    inno_language_names: List[str] = field(default_factory=list)
    #: Сигнатуры API загрузки — только один из двух признаков сетевой заглушки.
    download_apis: List[str] = field(default_factory=list)


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
    gog_needles = [(token, _needles(token)) for token in _GOG_MARKERS]
    download_api_needles = [
        (token, _needles(token)) for token in _DOWNLOAD_API_TOKENS]
    short_lang_needles: List[Tuple[str, bytes, bytes]] = []
    for code, english in _INNO_SHORT_LANG_PAIRS:
        ascii_pair = f"{code}\x00{english}".encode("ascii")
        short_lang_needles.append((code, ascii_pair, _wide_bytes(ascii_pair)))
    long_lang_needles: List[Tuple[str, bytes, bytes]] = []
    for name in _INNO_LONG_LANG_NAMES:
        ascii_name = name.encode("ascii") + b"\x00"
        long_lang_needles.append((name, ascii_name, _wide_bytes(ascii_name)))
    found_switches: Set[str] = set()
    found_markers: Set[str] = set()
    found_gog: Set[str] = set()
    found_download_apis: Set[str] = set()
    found_short_langs: Set[str] = set()
    found_long_langs: Set[str] = set()
    urls: List[str] = []
    seen_urls: Set[str] = set()

    longest = max(
        [len(encoded) for pair in
         [p for variants in signature_needles.values() for p in variants]
         for encoded in pair]
        + [len(encoded) for _t, pair in switch_needles for encoded in pair]
        + [len(encoded) for _t, pair in marker_needles for encoded in pair]
        + [len(encoded) for _t, pair in gog_needles for encoded in pair]
        + [len(encoded) for _t, pair in download_api_needles
           for encoded in pair]
        + [len(encoded) for _c, ascii_p, wide_p in short_lang_needles
           for encoded in (ascii_p, wide_p)]
        + [len(encoded) for _n, ascii_p, wide_p in long_lang_needles
           for encoded in (ascii_p, wide_p)]
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

                for token, (ascii_sig, wide_sig) in gog_needles:
                    if token in found_gog:
                        continue
                    if ascii_sig in data or wide_sig in data:
                        found_gog.add(token)

                for token, (ascii_sig, wide_sig) in download_api_needles:
                    if token in found_download_apis:
                        continue
                    if ascii_sig in data or wide_sig in data:
                        found_download_apis.add(token)

                for code, ascii_sig, wide_sig in short_lang_needles:
                    if code in found_short_langs:
                        continue
                    if ascii_sig in data or wide_sig in data:
                        found_short_langs.add(code)

                for name, ascii_sig, wide_sig in long_lang_needles:
                    if name in found_long_langs:
                        continue
                    if ascii_sig in data or wide_sig in data:
                        found_long_langs.add(name)

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
    result.gog_hits = [t for t in _GOG_MARKERS if t in found_gog]
    result.download_apis = [t for t in _DOWNLOAD_API_TOKENS
                            if t in found_download_apis]
    # Короткая пара ``ru\\0Russian`` надёжнее голого ``russian\\0``: второе
    # совпадает с отображаемым именем рядом с кодом ``ru``.
    inno_names: List[str] = []
    seen_inno: Set[str] = set()
    for name in list(found_short_langs) + list(found_long_langs):
        if name in seen_inno:
            continue
        seen_inno.add(name)
        inno_names.append(name)
    result.inno_language_names = inno_names
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
    #: Офлайн-установщик GOG (Inno Setup с gog.com / setup_*.exe + .bin).
    is_gog: bool = False
    #: Имена языков из секции [Languages] Inno Setup (``ru``, ``russian``).
    inno_language_names: List[str] = field(default_factory=list)
    #: Установщик оказался маленьким сетевым загрузчиком, а не самим продуктом.
    is_downloader_stub: bool = False
    #: Что подтвердило признаки загрузчика (API, URL, размер пакета).
    downloader_evidence: List[str] = field(default_factory=list)
    #: Вес установщика вместе с подходящими файлами-частями.
    media_size: int = 0
    #: Профиль онлайн-продукта с известной причиной, почему stub не портативен.
    online_product: Optional[OnlineOnlyProduct] = None
    #: Профиль известного перепака (KpoJIuK и т. п.). Установщик такого файла
    #: — обычно Inno Setup с СОБСТВЕННЫМ разбором командной строки: движковые
    #: ключи молча не работают, а сборка открывает мастер и ждёт мышку.
    repack_profile: Optional[RepackProfile] = None

    @property
    def human(self) -> str:
        if self.is_downloader_stub:
            name = (self.online_product.name if self.online_product
                    else "программы")
            prefix = f"сетевой загрузчик {name}: "
        else:
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


def _online_product_profile(path: str) -> Optional[OnlineOnlyProduct]:
    basename = os.path.basename(path)
    return next((profile for profile in _ONLINE_ONLY_PRODUCTS
                 if profile.filename_re.search(basename)), None)


def _is_download_url(url: str) -> bool:
    """Отличает URL раздачи файлов от обычной ссылки поддержки/лицензии."""
    lowered = url.casefold()
    return any(hint in lowered for hint in _DOWNLOAD_URL_HINTS)


def _downloader_evidence(scan: ScanResult, media_size: int) -> List[str]:
    evidence: List[str] = []
    if scan.download_apis:
        evidence.append("найдены API загрузки из сети: "
                        + ", ".join(scan.download_apis))
    urls = [url for url in scan.urls if _is_download_url(url)]
    if urls:
        evidence.append("найден URL раздачи файлов: " + ", ".join(urls[:3]))
    if media_size:
        evidence.append(f"вес дистрибутива — {media_size} байт")
    return evidence


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
        ]
        if profile.license_url:
            vendor_evidence.append(
                f"обязательное принятие лицензии: {profile.license_url}")
        if any(host in url for url in scan.urls for host in profile.hosts):
            vendor_evidence.append(
                "внутри найден сайт производителя: "
                + ", ".join(profile.hosts))
        scan_evidence = result.evidence
        # Профиль может называть движок (NSIS у Planeta) — тогда лестница
        # строится по движку; если движок не указан, остаёмся на собственном
        # CLI-профиле с документированными ключами (ZennoLab).
        hinted = profile.installer_hint or InstallerType.CUSTOM_CLI
        result = DetectionResult(
            hinted, 0.8,
            evidence=vendor_evidence + scan_evidence,
            switch_hints=list(profile.switches),
            license_urls=([profile.license_url] if profile.license_url else [])
            + [u for u in scan.urls if u != profile.license_url],
            vendor_args=list(profile.fixed_args),
            vendor_name=profile.name)

    # Профиль перепака. Применяется к сборкам Inno/универсальным, но НЕ к
    # настоящим бандлам Trimble (WiX Burn) и не к MSI: у официального
    # установщика SketchUp свои ключи, и чужая команда ему только навредит.
    repack: Optional[RepackProfile] = None
    if profile is None:
        candidate = _repack_profile(path)
        if candidate is not None and result.installer_type in (
                InstallerType.INNO, InstallerType.SELF_EXTRACT,
                InstallerType.NSIS, InstallerType.UNKNOWN,
                InstallerType.SQUIRREL):
            repack = candidate
            result.repack_profile = candidate
            if not result.vendor_name:
                result.vendor_name = candidate.name
            language_keys = ", ".join(
                key for _code, key in candidate.language_switches) or "—"
            result.evidence.append(
                f"перепак {candidate.name}: {candidate.product}; "
                f"документированная тихая установка — {candidate.silent_switch} "
                f"<язык> {candidate.path_switch}<папка>, ключ пути последним, "
                f"без кавычек; ключи языка — {language_keys}. Стандартные "
                "ключи Inno Setup (/VERYSILENT /DIR=) этот скрипт не "
                "разбирает: он открывает мастер с выбором языка и папки"
            )

    if profile is None:
        result.switch_hints = list(scan.switches)
        result.license_urls = list(scan.urls)
        if repack is not None:
            result.switch_hints = list(result.switch_hints) + [
                repack.silent_switch, repack.path_switch,
                *[key for _code, key in repack.language_switches],
            ]
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

    result.inno_language_names = list(scan.inno_language_names)
    result.is_gog = _looks_like_gog(path, scan, layout)
    if result.is_gog:
        why = []
        if scan.gog_hits:
            why.append("строки " + ", ".join(scan.gog_hits[:4]))
        if _gog_bin_siblings(layout, path):
            why.append("рядом лежат setup_*.bin")
        if _gog_filename(path):
            why.append("имя файла setup_*.exe")
        result.evidence.append(
            "GOG-установщик (" + "; ".join(why or ["эвристика"]) + "): "
            "язык игры после установки берётся из goggame-*.info и "
            "GOG.com\\Games, а /LANG= у Inno — двухбуквенный (ru, не russian)"
        )
        if result.vendor_name == "":
            result.vendor_name = "GOG"
    if result.inno_language_names:
        result.evidence.append(
            "языки Inno Setup внутри файла: "
            + ", ".join(result.inno_language_names[:12])
            + (" …" if len(result.inno_language_names) > 12 else "")
        )

    result.media_size = space_mod.media_bytes(path)
    result.downloader_evidence = _downloader_evidence(scan, result.media_size)
    online_profile = _online_product_profile(path)
    small_package = 0 < result.media_size <= DOWNLOADER_STUB_MAX_BYTES
    can_be_stub = (
        small_package and not result.has_zip_payload and not result.is_gog
        and not result.is_msi
    )
    if can_be_stub and online_profile is not None:
        # Стандартизованное имя + малый размер сильнее общей эвристики:
        # Fusion_360_Setup.exe — веб-загрузчик, а не полный client payload.
        result.is_downloader_stub = True
        result.online_product = online_profile
        result.downloader_evidence.extend((
            f"имя файла соответствует профилю {online_profile.name}",
            online_profile.reason,
        ))
        result.evidence.append(
            f"распознан сетевой загрузчик {online_profile.name}: "
            f"{online_profile.reason}; документированный ключ — "
            + ", ".join(online_profile.switches)
        )
    elif (can_be_stub
          and result.installer_type in (InstallerType.UNKNOWN,
                                        InstallerType.SELF_EXTRACT,
                                        InstallerType.SQUIRREL)
          and scan.download_apis
          and any(_is_download_url(url) for url in scan.urls)):
        # Не объявляем обычный Inno/MSI/Burn установщик заглушкой лишь потому,
        # что он содержит WinHTTP и ссылку поддержки. Нужны одновременно
        # сигнатура загрузки, адрес раздачи и небольшой пакет.
        result.is_downloader_stub = True
        result.downloader_evidence.append(
            "установщик содержит API загрузки и URL раздачи, но сам файл "
            "слишком мал, чтобы быть автономным дистрибутивом"
        )
        result.evidence.append(
            "похоже, это сетевой загрузчик: обнаружены API загрузки и "
            "URL раздачи, но внутри нет полного payload"
        )
    return result


def _gog_filename(path: str) -> bool:
    name = os.path.basename(path).casefold()
    return name.startswith("setup_") and name.endswith(".exe")


def _gog_bin_siblings(layout: MediaLayout, path: str) -> bool:
    stem = os.path.splitext(os.path.basename(path))[0].casefold()
    for name in layout.files:
        lowered = name.casefold()
        if not lowered.endswith(".bin"):
            continue
        if lowered.startswith(stem) or lowered.startswith("setup_"):
            return True
    return False


def _looks_like_gog(path: str, scan: ScanResult, layout: MediaLayout) -> bool:
    """GOG offline installer: строки gog.com и/или setup_*.exe + .bin."""
    if scan.gog_hits:
        return True
    return _gog_filename(path) and _gog_bin_siblings(layout, path)
