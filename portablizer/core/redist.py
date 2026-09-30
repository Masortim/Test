"""Распространяемые компоненты (Redistributables): всё, что программа ждёт от Windows.

Зачем этот модуль
-----------------
Портатив собирается на компьютере, где нужные системные библиотеки уже есть:
их поставил либо сам установщик (он почти всегда тянет ``vcredist``/``DXSETUP``
как предусловие), либо другая программа. На чужом ПК их может не быть, и
пользователь вместо программы получает окно Windows::

    Запуск программы невозможен, так как на компьютере отсутствует
    XINPUT1_3.dll. Попробуйте переустановить программу.

Ровно так выглядят жалобы про ``d3dx9_38.dll``, ``d3dx9_39.dll``,
``MSVCP110.dll``, ``MSVCR110.dll``, ``MSVCP100.dll``, ``MSVCR100.dll`` и
десятки их родственников. Это не файлы программы — это части
**распространяемых пакетов** (Visual C++ Redistributable, DirectX End-User
Runtime и т. п.), которые обычная установка кладёт в систему, а портатив —
обязан принести с собой.

Что делает модуль
-----------------
1. **Читает таблицу импорта PE** у всех ``.exe``/``.dll`` внутри ``App`` —
   и обычную, и отложенную (delay-load). Это точный список того, что
   загрузчик Windows будет искать при старте, а не догадки по именам файлов.
2. **Классифицирует каждую библиотеку**: она уже лежит рядом с программой,
   её гарантированно даёт сама Windows (``kernel32.dll``) или это часть
   известного распространяемого пакета (``msvcp110.dll`` → Visual C++ 2012).
3. **Приносит недостающее в портатив** по лестнице источников: файлы
   redist-пакетов, приложенные к установщику (``_CommonRedist``, ``redist``,
   ``DirectX``…), затем системные папки этого ПК (с проверкой разрядности),
   затем WinSxS (для VC++ 2005/2008 — с генерацией private-манифеста),
   затем — по желанию — официальная загрузка с сайта Microsoft.
4. **Разворачивает полный комплект «про запас»** (по умолчанию): не только
   то, что нашлось в таблицах импорта, а **весь каталог известных библиотек**
   — все версии Visual C++ 2005…2022, весь набор DirectX июня 2010, OpenAL,
   PhysX, VB6-runtime. Таблица импорта не видит библиотек, которые грузятся
   динамически по имени, собранному строкой (игры делают так с
   ``d3dx9_%d.dll``), подключаются плагинами и модами или появляются после
   докачки компонента установщиком, — полный комплект закрывает и их: окно
   «отсутствует XINPUT1_3.dll» не возникает в принципе. Ненайденное «про
   запас» ошибкой **не** считается и предстартовую проверку лончера не
   тревожит.
5. **Честно сообщает об остатке**: то, что принести не удалось, попадает в
   ``redistributables.txt`` и в предстартовую проверку лончера — вместо
   системного окна «отсутствует MSVCR110.dll» пользователь видит название
   пакета и ссылку на него.

Модуль сознательно не использует сторонние библиотеки (pefile и т. п.):
Portablizer собирается в один EXE, а разбор PE здесь нужен минимальный.
Все операции, требующие Windows (копирование из System32, ``expand``,
``msiexec``), изолированы в :class:`RuntimeProvisioner` и на других ОС просто
не выполняются — сканирование и отчёт работают везде, в том числе в тестах.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import cabinet

IS_WINDOWS = sys.platform.startswith("win")

#: Сколько файлов максимум разбираем в App (защита от гигантских раскладок).
MAX_SCANNED_FILES = 4000

#: Сколько импортёров показываем в отчёте по одной библиотеке.
MAX_IMPORTERS_SHOWN = 6

#: Имя отчёта в корне портатива.
REPORT_NAME = "redistributables.txt"

#: Папка, куда складываются скачанные установщики пакетов (offline-запас).
REDIST_DIR_NAME = "Redist"

#: Колбэк хода работ: ``(доля этапа 0..1, подпись операции, её процент)``.
#: Процент ``-1`` означает «величина неизвестна» — интерфейс показывает
#: «бегущую» полосу вместо замершей цифры.
ProgressCB = Callable[[float, str, int], None]


# =============================================================================
#  1. Знание о пакетах
# =============================================================================

@dataclass(frozen=True)
class RedistPackage:
    """Один распространяемый пакет и его библиотеки."""

    key: str
    title: str
    #: Регулярное выражение по имени DLL в нижнем регистре (полное совпадение).
    pattern: str
    #: Название для Launch.bat: в .bat допустим только ASCII.
    ascii_title: str = ""
    #: Прямые ссылки на официальные пакеты: "x86"/"x64"/"any".
    downloads: Dict[str, str] = field(default_factory=dict)
    #: Запасные ссылки на те же пакеты (другие раздачи Microsoft). Нужны,
    #: когда основная ссылка отвечает страницей-заглушкой или обрывается:
    #: скачанный «пакет» тогда не пакет, и распаковывать его бессмысленно.
    mirrors: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    #: Страница загрузки (её показываем человеку, ссылки живут дольше).
    page: str = ""
    #: Имя side-by-side сборки (VC++ 2005/2008 ставятся только через WinSxS).
    sxs: str = ""
    #: Можно ли положить файлы рядом с программой (app-local deployment).
    app_local: bool = True
    #: Разрядности, для которых пакет вообще существует. Нужно только полному
    #: комплекту «про запас»: у VC++ 2012 нет сборки под arm64, а у runtime
    #: Visual Basic 6 — под x64. Обнаруженные таблицей импорта требования
    #: обрабатываются и вне этого списка.
    archs: Tuple[str, ...] = ("x86", "x64")
    #: Примерный размер пакета в байтах. Нужен только для честного текста в
    #: логе («около 96 МБ»): большие загрузки без предупреждения выглядят
    #: как зависание.
    size_hint: int = 0
    note: str = ""

    def matches(self, dll: str) -> bool:
        return re.fullmatch(self.pattern, dll.lower()) is not None

    def plain_title(self) -> str:
        """Название без кириллицы — для Launch.bat и консоли cmd."""
        if self.ascii_title:
            return self.ascii_title
        return self.title if self.title.isascii() else self.key

    def url(self, arch: str) -> str:
        return (self.downloads.get(arch)
                or self.downloads.get("any")
                or self.page)

    def urls(self, arch: str) -> List[str]:
        """Все известные ссылки на пакет: основная, затем запасные."""
        out: List[str] = []
        for candidate in (self.downloads.get(arch),
                          self.downloads.get("any")):
            if candidate and candidate not in out:
                out.append(candidate)
        for candidate in tuple(self.mirrors.get(arch, ())) \
                + tuple(self.mirrors.get("any", ())):
            if candidate and candidate not in out:
                out.append(candidate)
        return out


_VC_LICENSE_NOTE = (
    "Файлы Visual C++ Runtime разрешено распространять вместе с программой "
    "(см. условия лицензии Visual Studio)."
)

#: Порядок важен: более специфичные записи идут раньше общих.
REDIST_PACKAGES: Tuple[RedistPackage, ...] = (
    RedistPackage(
        key="vc2005",
        title="Microsoft Visual C++ 2005 SP1 Redistributable (VC++ 8.0)",
        pattern=r"(?:msvc[rpm]80|mfcm?80u?|mfc80[a-z]{3}|atl80|vcomp80)\.dll",
        # Последняя официальная сборка 2005 SP1 (MFC Security Update,
        # 8.0.50727.6195): именно в ней лежат mfc80.dll/mfc80u.dll/atl80.dll.
        downloads={
            "x86": "https://download.microsoft.com/download/8/B/4/"
                   "8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE",
            "x64": "https://download.microsoft.com/download/8/B/4/"
                   "8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE",
        },
        mirrors={
            "x86": ("https://download.microsoft.com/download/6/B/B/"
                    "6BB661D6-A8AE-4819-B79F-236472F6070C/vcredist_x86.exe",
                    "https://download.windowsupdate.com/msdownload/update/"
                    "software/secu/2011/06/vcredist_x86_"
                    "b8fab0bb7f62a24ddfe77b19cd9a1451abd7b847.exe"),
            "x64": ("https://download.microsoft.com/download/6/B/B/"
                    "6BB661D6-A8AE-4819-B79F-236472F6070C/vcredist_x64.exe",
                    "https://download.windowsupdate.com/msdownload/update/"
                    "software/secu/2011/06/vcredist_x64_"
                    "ee916012783024dac67fc606457377932c826f05.exe"),
        },
        page="https://www.microsoft.com/download/details.aspx?id=26347",
        sxs="Microsoft.VC80",
        note=_VC_LICENSE_NOTE,
    ),
    RedistPackage(
        key="vc2008",
        title="Microsoft Visual C++ 2008 SP1 Redistributable (VC++ 9.0)",
        pattern=r"(?:msvc[rpm]90|mfcm?90u?|mfc90[a-z]{3}|atl90|vcomp90)\.dll",
        downloads={
            "x86": "https://download.microsoft.com/download/5/D/8/"
                   "5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe",
            "x64": "https://download.microsoft.com/download/5/D/8/"
                   "5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe",
        },
        mirrors={
            "x86": ("https://download.microsoft.com/download/d/d/9/"
                    "dd9a82d0-52ef-40db-8dab-795376989c03/vcredist_x86.exe",),
            "x64": ("https://download.microsoft.com/download/2/d/6/"
                    "2d61c766-107b-409d-8fba-c39e61ca08e8/vcredist_x64.exe",),
        },
        page="https://www.microsoft.com/download/details.aspx?id=26368",
        sxs="Microsoft.VC90",
        note=_VC_LICENSE_NOTE,
    ),
    RedistPackage(
        key="vc2010",
        title="Microsoft Visual C++ 2010 SP1 Redistributable (VC++ 10.0)",
        pattern=r"(?:msvc[rpm]100|mfcm?100u?|mfc100[a-z]{3}|atl100|vcomp100)\.dll",
        downloads={
            "x86": "https://download.microsoft.com/download/1/6/5/"
                   "165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe",
            "x64": "https://download.microsoft.com/download/1/6/5/"
                   "165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe",
        },
        mirrors={
            "x86": ("https://download.microsoft.com/download/C/6/D/"
                    "C6D0FD4E-9E53-4897-9B91-836EBA2AACD3/vcredist_x86.exe",),
            "x64": ("https://download.microsoft.com/download/A/8/0/"
                    "A80747C3-41BD-45DF-B505-E9710D2744E0/vcredist_x64.exe",),
        },
        page="https://www.microsoft.com/download/details.aspx?id=26999",
        note=_VC_LICENSE_NOTE,
    ),
    RedistPackage(
        key="vc2012",
        title="Microsoft Visual C++ 2012 Update 4 Redistributable (VC++ 11.0)",
        pattern=r"(?:msvc[rpm]110|mfcm?110u?|mfc110[a-z]{3}|atl110|vcomp110"
                r"|vccorlib110|concrt110)\.dll",
        downloads={
            "x86": "https://download.microsoft.com/download/1/6/B/"
                   "16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe",
            "x64": "https://download.microsoft.com/download/1/6/B/"
                   "16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe",
        },
        mirrors={
            "x86": ("https://download.microsoft.com/download/1/6/B/"
                    "16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU4/"
                    "vcredist_x86.exe",),
            "x64": ("https://download.microsoft.com/download/1/6/B/"
                    "16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU4/"
                    "vcredist_x64.exe",),
        },
        page="https://www.microsoft.com/download/details.aspx?id=30679",
        note=_VC_LICENSE_NOTE,
    ),
    RedistPackage(
        key="vc2013",
        title="Microsoft Visual C++ 2013 Redistributable (VC++ 12.0)",
        pattern=r"(?:msvc[rp]120|msvcm120|mfcm?120u?|mfc120[a-z]{3}|atl120"
                r"|vcomp120|vccorlib120|concrt120)\.dll",
        downloads={
            "x86": "https://aka.ms/highdpimfc2013x86enu",
            "x64": "https://aka.ms/highdpimfc2013x64enu",
        },
        mirrors={
            "x86": ("https://download.microsoft.com/download/2/E/6/"
                    "2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe",),
            "x64": ("https://download.microsoft.com/download/2/E/6/"
                    "2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe",),
        },
        page="https://www.microsoft.com/download/details.aspx?id=40784",
        note=_VC_LICENSE_NOTE,
    ),
    RedistPackage(
        key="vc14",
        title="Microsoft Visual C++ 2015-2022 Redistributable (VC++ 14.x)",
        pattern=r"(?:vcruntime140(?:_1|_2|_threads)?|msvcp140(?:_1|_2"
                r"|_atomic_wait|_codecvt_ids)?|concrt140|vccorlib140|vcamp140"
                r"|vcomp140|mfcm?140u?|mfc140[a-z]{3}|ucrtbase"
                r"|api-ms-win-crt-[a-z0-9-]+-l\d-\d-\d)\.dll",
        downloads={
            "x86": "https://aka.ms/vc14/vc_redist.x86.exe",
            "x64": "https://aka.ms/vc14/vc_redist.x64.exe",
            "arm64": "https://aka.ms/vc14/vc_redist.arm64.exe",
        },
        page="https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
        archs=("x86", "x64", "arm64"),
        note="Универсальная среда выполнения C (UCRT) входит в Windows 10 и "
             "новее; на Windows 7/8.1 её приносит этот же пакет. " + _VC_LICENSE_NOTE,
    ),
    RedistPackage(
        key="vc_legacy",
        title="Visual C++ 6.0/2002/2003 Runtime (msvcr70/71, msvcp60/70/71)",
        pattern=r"(?:msvc[rp]7[01]|msvcp60|msvcirt|msvcp50)\.dll",
        downloads={},
        page="",
        archs=("x86",),
        note="Отдельного установщика от Microsoft не существует: эти файлы "
             "распространяются только рядом с программой. Portablizer берёт "
             "их с этого ПК и кладёт в портатив.",
    ),
    RedistPackage(
        key="directx_jun2010",
        title="DirectX End-User Runtime (июнь 2010)",
        ascii_title="DirectX End-User Runtime (June 2010)",
        pattern=r"(?:d3dx9_(?:2[4-9]|3\d|4[0-3])|d3dx10_(?:3[3-9]|4[0-3])"
                r"|d3dx11_4[23]|d3dcsx_4[0-3]|d3dcompiler_(?:3[3-9]|4[0-3])"
                r"|xinput1_[123]|xaudio2_[0-7]"
                r"|xactengine2_(?:\d|10)|xactengine3_[0-7]"
                r"|x3daudio1_[0-7]|xapofx1_[0-5]|dxerr|d3dref9"
                r"|dsetup|dsetup32|dpnaddr|dpnhpast)\.dll",
        downloads={
            "any": "https://download.microsoft.com/download/8/4/A/"
                   "84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe",
        },
        page="https://www.microsoft.com/download/details.aspx?id=8109",
        size_hint=103_000_000,
        note="Сама DirectX в Windows уже есть; пакет добавляет старые "
             "side-by-side компоненты (D3DX9/10/11, XInput 1.3, XAudio 2.7, "
             "XACT), которые Windows не содержит.",
    ),
    RedistPackage(
        key="d3dcompiler_modern",
        title="D3DCompiler_46/47 (входит в Windows 8 и новее)",
        ascii_title="D3DCompiler 46/47 (part of Windows 8 and newer)",
        pattern=r"d3dcompiler_4[4-7]\.dll",
        downloads={},
        page="https://support.microsoft.com/help/4019990",
        note="На Windows 8 и новее файл системный. Для Windows 7 его "
             "приносит обновление KB4019990 или сама программа.",
    ),
    RedistPackage(
        key="openal",
        title="OpenAL (звук в старых играх)",
        ascii_title="OpenAL runtime",
        pattern=r"(?:openal32|wrap_oal|soft_oal)\.dll",
        downloads={},
        page="https://www.openal.org/downloads/",
        note="OpenAL прекрасно работает рядом с программой: файл кладётся в "
             "папку игры, установка oalinst.exe на чужой ПК не нужна.",
    ),
    RedistPackage(
        key="physx",
        title="NVIDIA PhysX System Software",
        pattern=r"(?:physxloader|physxcore|physxdevice|physxcooking"
                r"|physx3(?:common|cooking|core|extensions)?[a-z0-9_]*"
                r"|nxcooking|nxcharacter|cudart[0-9_]*)\.dll",
        downloads={},
        page="https://www.nvidia.com/object/physx-9.19.0218-driver.html",
        note="Библиотеки PhysX обычно лежат рядом с игрой и переносятся "
             "вместе с ней.",
    ),
    RedistPackage(
        key="vb6",
        title="Visual Basic 6 Runtime (msvbvm60.dll)",
        pattern=r"(?:msvbvm[56]0|vb6[a-z]*|comcat|mswinsck)\.dll",
        downloads={},
        # 64-битного runtime у VB5/VB6 не существует.
        archs=("x86",),
        page="https://learn.microsoft.com/previous-versions/visualstudio/"
             "visual-basic-6/vb6-support",
        note="Runtime Visual Basic 6 входит в состав Windows, но на "
             "урезанных сборках может отсутствовать.",
    ),
    RedistPackage(
        key="gfwl",
        title="Games for Windows – LIVE (xlive.dll)",
        ascii_title="Games for Windows - LIVE (xlive.dll)",
        pattern=r"(?:xlive|gfwlivesetup)\.dll",
        downloads={},
        archs=("x86",),
        page="",
        note="Сервис закрыт, официального пакета больше нет. Игры обычно "
             "поставляют xlive.dll рядом с exe.",
    ),
)

#: Сборка side-by-side по имени библиотеки (только VC++ 2005/2008).
_SXS_SUFFIXES: Tuple[Tuple[str, str], ...] = (
    ("mfcm", "MFC"), ("mfc", "MFC"), ("atl", "ATL"), ("vcomp", "OPENMP"),
    ("msvcm", "CRT"), ("msvcp", "CRT"), ("msvcr", "CRT"),
)

#: Открытый ключ подписи всех сборок Microsoft (у VC++ 2005/2008 один и тот
#: же). Манифест без корректного publicKeyToken недействителен: с ним Windows
#: отвечает той же ошибкой 14001, что и без манифеста вовсе.
_SXS_PUBLIC_KEY_TOKEN = "1fc8b3b9a1e18e3b"

#: Канонические версии сборок — последние публичные обновления каждой линейки
#: (MS11-025). Используются только как запасной вариант, когда точную версию
#: не удалось взять ни из манифеста программы, ни из имени папки WinSxS, откуда
#: был взят файл: private-манифест обязан объявить какую-то версию.
_SXS_DEFAULT_VERSIONS: Dict[str, str] = {
    "vc2005": "8.0.50727.6195",
    "vc2008": "9.0.30729.6161",
}


def _dll_range(prefix: str, start: int, end: int) -> Tuple[str, ...]:
    """``d3dx9_24.dll`` … ``d3dx9_43.dll`` одним кортежем."""
    return tuple(f"{prefix}_{index}.dll" for index in range(start, end + 1))


#: **Полный комплект** библиотек каждого пакета — режим «про запас».
#:
#: Ключ ``"*"`` — файлы, существующие для всех разрядностей пакета; отдельный
#: ключ разрядности добавляет файлы, которые бывают **только** у неё:
#: ``vcruntime140_1.dll`` не выпускалась для x86, у PhysX 3 имена с суффиксом
#: ``_x86``/``_x64``, а локализованные MFC (``mfc90esv.dll`` и родня) в
#: комплект не входят — их приносит только точный путь по таблице импорта.
#: В комплект не включены и установочные файлы самого пакета (``dsetup``:
#: их загружает инсталлятор DirectX, а не программа). Каждое имя обязано
#: опознаваться регулярным выражением своего же пакета — это проверяется
#: тестами.
FULL_KIT: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "vc2005": {"*": (
        "msvcr80.dll", "msvcp80.dll", "msvcm80.dll",
        "mfc80.dll", "mfc80u.dll", "mfcm80.dll", "mfcm80u.dll",
        "atl80.dll", "vcomp80.dll",
    )},
    "vc2008": {"*": (
        "msvcr90.dll", "msvcp90.dll", "msvcm90.dll",
        "mfc90.dll", "mfc90u.dll", "mfcm90.dll", "mfcm90u.dll",
        "atl90.dll", "vcomp90.dll",
    )},
    "vc2010": {"*": (
        "msvcr100.dll", "msvcp100.dll", "msvcm100.dll",
        "mfc100.dll", "mfc100u.dll", "mfcm100.dll", "mfcm100u.dll",
        "atl100.dll", "vcomp100.dll",
    )},
    "vc2012": {"*": (
        "msvcr110.dll", "msvcp110.dll", "msvcm110.dll",
        "vcomp110.dll", "vccorlib110.dll", "concrt110.dll",
        "atl110.dll", "mfc110.dll", "mfc110u.dll",
        "mfcm110.dll", "mfcm110u.dll",
    )},
    "vc2013": {"*": (
        "msvcr120.dll", "msvcp120.dll", "msvcm120.dll",
        "vcomp120.dll", "vccorlib120.dll", "concrt120.dll",
        "atl120.dll", "mfc120.dll", "mfc120u.dll",
        "mfcm120.dll", "mfcm120u.dll",
    )},
    "vc14": {
        "*": (
            "vcruntime140.dll", "msvcp140.dll", "msvcp140_1.dll",
            "msvcp140_2.dll", "msvcp140_atomic_wait.dll",
            "msvcp140_codecvt_ids.dll", "concrt140.dll", "vccorlib140.dll",
            "vcamp140.dll", "vcomp140.dll",
            "mfc140.dll", "mfc140u.dll", "mfcm140.dll", "mfcm140u.dll",
            "ucrtbase.dll",
        ),
        # Эти файлы появились в 64-битной части redist 2015–2022.
        "x64": ("vcruntime140_1.dll", "vcruntime140_2.dll",
                "vcruntime140_threads.dll"),
        "arm64": ("vcruntime140_1.dll", "vcruntime140_2.dll",
                  "vcruntime140_threads.dll"),
    },
    "vc_legacy": {"*": (
        "msvcp60.dll", "msvcr70.dll", "msvcp70.dll",
        "msvcr71.dll", "msvcp71.dll", "msvcirt.dll",
    )},
    "directx_jun2010": {"*": (
        *_dll_range("d3dx9", 24, 43),
        *_dll_range("d3dx10", 33, 43),
        "d3dx11_42.dll", "d3dx11_43.dll",
        *_dll_range("d3dcsx", 40, 43),
        *_dll_range("d3dcompiler", 33, 43),
        "xinput1_1.dll", "xinput1_2.dll", "xinput1_3.dll",
        *_dll_range("xaudio2", 0, 7),
        *_dll_range("xactengine2", 0, 10),
        *_dll_range("xactengine3", 0, 7),
        *_dll_range("x3daudio1", 0, 7),
        *_dll_range("xapofx1", 0, 5),
    )},
    "d3dcompiler_modern": {"*": ("d3dcompiler_46.dll", "d3dcompiler_47.dll")},
    "openal": {"*": ("openal32.dll", "wrap_oal.dll", "soft_oal.dll")},
    "physx": {
        # PhysX 2.x и Ageia были только 32-битными.
        "x86": ("physxloader.dll", "physxcore.dll", "physxcooking.dll",
                "physxdevice.dll", "nxcooking.dll", "nxcharacter.dll",
                "physx3common_x86.dll", "physx3cooking_x86.dll",
                "physx3core_x86.dll"),
        "x64": ("physx3common_x64.dll", "physx3cooking_x64.dll",
                "physx3core_x64.dll"),
    },
    "vb6": {"*": ("msvbvm50.dll", "msvbvm60.dll")},
    "gfwl": {"*": ("xlive.dll",)},
}

#: Библиотеки, которые всегда даёт сама Windows.
SYSTEM_DLLS = frozenset("""
advapi32.dll amsi.dll authz.dll avicap32.dll avifil32.dll bcrypt.dll
bcryptprimitives.dll bthprops.cpl cabinet.dll cfgmgr32.dll clbcatq.dll
combase.dll comctl32.dll comdlg32.dll credui.dll crypt32.dll cryptbase.dll
cryptsp.dll d2d1.dll d3d10.dll d3d10_1.dll d3d10core.dll d3d11.dll d3d12.dll
d3d8.dll d3d9.dll davclnt.dll dbghelp.dll dciman32.dll ddraw.dll devmgr.dll
dhcpcsvc.dll dinput.dll dinput8.dll dnsapi.dll dsound.dll dwmapi.dll
dwrite.dll dxgi.dll dxva2.dll esent.dll fltlib.dll gdi32.dll gdi32full.dll
gdiplus.dll glu32.dll hid.dll httpapi.dll iertutil.dll imagehlp.dll imm32.dll
iphlpapi.dll kernel32.dll kernelbase.dll ksuser.dll ktmw32.dll loadperf.dll
mf.dll mfplat.dll mfreadwrite.dll mpr.dll mscms.dll msctf.dll msacm32.dll
mscoree.dll msi.dll msimg32.dll msvcrt.dll msvfw32.dll msxml3.dll msxml6.dll
mswsock.dll ncrypt.dll netapi32.dll netutils.dll normaliz.dll ntdll.dll
ntdsapi.dll ntmarta.dll odbc32.dll ole32.dll oleacc.dll oleaut32.dll
oledlg.dll olepro32.dll opengl32.dll pdh.dll powrprof.dll printui.dll
profapi.dll propsys.dll psapi.dll quartz.dll rasapi32.dll resutils.dll
riched20.dll riched32.dll rpcrt4.dll rstrtmgr.dll samcli.dll schannel.dll
secur32.dll security.dll sechost.dll sensapi.dll setupapi.dll sfc.dll
sfc_os.dll shcore.dll shell32.dll shfolder.dll shlwapi.dll slc.dll
srvcli.dll sspicli.dll t2embed.dll tdh.dll traffic.dll ucrtbase_enclave.dll
urlmon.dll user32.dll userenv.dll usp10.dll uxtheme.dll version.dll
wer.dll wevtapi.dll winbio.dll windowscodecs.dll winhttp.dll wininet.dll
winmm.dll winspool.drv wintrust.dll winusb.dll wkscli.dll wldap32.dll
wintypes.dll ws2_32.dll wsock32.dll wtsapi32.dll xinput1_4.dll
xinput9_1_0.dll xaudio2_8.dll xaudio2_9.dll xmllite.dll xolehlp.dll
xpsprint.dll dbgcore.dll cryptdll.dll dsrole.dll logoncli.dll winscard.dll
""".split())

#: Семейства системных библиотек (API-sets и прочие «зонтики» Windows).
SYSTEM_PREFIXES: Tuple[str, ...] = (
    "api-ms-win-core-", "api-ms-win-security-", "api-ms-win-service-",
    "api-ms-win-eventing-", "api-ms-win-shcore-", "api-ms-win-power-",
    "api-ms-win-downlevel-", "api-ms-win-appmodel-", "api-ms-win-devices-",
    "api-ms-win-shell-", "api-ms-win-gdi-", "api-ms-win-ntuser-",
    "ext-ms-win-", "ext-ms-",
)

#: Наши собственные файлы — их импорты разбирать бессмысленно.
_SKIP_FILES = frozenset({"launchportable.exe", "portablelauncher.exe"})


def normalize_dll(name: str) -> str:
    """Имя библиотеки в каноничном виде: нижний регистр, без пути."""
    cleaned = str(name).strip().strip("\x00").replace("/", "\\")
    cleaned = cleaned.rsplit("\\", 1)[-1].lower()
    return cleaned


def find_package(dll: str) -> Optional[RedistPackage]:
    """Пакет, в который входит библиотека (или None)."""
    name = normalize_dll(dll)
    for package in REDIST_PACKAGES:
        if package.matches(name):
            return package
    return None


def is_system_dll(dll: str) -> bool:
    """True для библиотек, которые есть в любой поддерживаемой Windows."""
    name = normalize_dll(dll)
    if name in SYSTEM_DLLS:
        return True
    return any(name.startswith(prefix) for prefix in SYSTEM_PREFIXES)


def classify_dll(dll: str) -> str:
    """``"redist"`` / ``"system"`` / ``"unknown"`` для одного имени."""
    if find_package(dll) is not None:
        return "redist"
    if is_system_dll(dll):
        return "system"
    return "unknown"


def sxs_assembly_for(dll: str, package: RedistPackage) -> str:
    """Полное имя side-by-side сборки: ``Microsoft.VC90.CRT`` и т. п."""
    if not package.sxs:
        return ""
    name = normalize_dll(dll)
    for prefix, suffix in _SXS_SUFFIXES:
        if name.startswith(prefix):
            return f"{package.sxs}.{suffix}"
    return f"{package.sxs}.CRT"


def sxs_family_prefix(assembly: str, arch: str) -> str:
    """Префикс папок сборки в WinSxS для проверки наличия рантайма.

    Например, ``x86_microsoft.vc80.crt_`` — по одному ``if exist`` с такой
    маской лончер понимает, стоит ли на целевом ПК Visual C++ 2005 runtime,
    хотя самих файлов в System32 нет и никогда не было (обычная проверка
    «лежит ли msvcr80.dll в System32/SysWOW64» там бесполезна в принципе).
    """
    if not assembly:
        return ""
    prefix = "x86" if arch == "x86" else "amd64"
    return f"{prefix}_{assembly.lower()}_"


# =============================================================================
#  2. Разбор PE: таблица импорта и встроенный манифест
# =============================================================================

_MACHINES: Dict[int, str] = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "arm64",
    0x01C0: "arm",
    0x01C4: "arm",
    0x0200: "ia64",
}


@dataclass
class PEImports:
    """Что именно исполняемый файл просит у загрузчика Windows."""

    path: str = ""
    is_pe: bool = False
    machine: str = ""
    is_dotnet: bool = False
    imports: List[str] = field(default_factory=list)
    delay_imports: List[str] = field(default_factory=list)

    @property
    def all_imports(self) -> List[str]:
        seen: Dict[str, None] = {}
        for name in list(self.imports) + list(self.delay_imports):
            seen.setdefault(name, None)
        return list(seen)


class _PEReader:
    """Минимальный разбор заголовков PE поверх открытого файла."""

    def __init__(self, fh) -> None:
        self.fh = fh
        self.ok = False
        self.machine = ""
        self.is_dotnet = False
        self.image_base = 0
        self.sections: List[Tuple[int, int, int, int]] = []
        self.directories: List[Tuple[int, int]] = []
        self._parse()

    def _parse(self) -> None:
        fh = self.fh
        head = fh.read(0x40)
        if len(head) < 0x40 or head[:2] != b"MZ":
            return
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if not 0 < e_lfanew < 0x10000000:
            return
        fh.seek(e_lfanew)
        if fh.read(4) != b"PE\0\0":
            return
        coff = fh.read(20)
        if len(coff) < 20:
            return
        machine, num_sections = struct.unpack_from("<HH", coff, 0)
        size_optional = struct.unpack_from("<H", coff, 16)[0]
        optional = fh.read(size_optional) if size_optional else b""
        self.machine = _MACHINES.get(machine, "")
        if len(optional) < 96:
            return
        magic = struct.unpack_from("<H", optional, 0)[0]
        pe32plus = magic == 0x20B
        if pe32plus:
            self.image_base = struct.unpack_from("<Q", optional, 24)[0]
            dir_offset = 112
        else:
            self.image_base = struct.unpack_from("<I", optional, 28)[0]
            dir_offset = 96
        count_offset = dir_offset - 4
        if len(optional) < count_offset + 4:
            return
        count = min(struct.unpack_from("<I", optional, count_offset)[0], 16)
        for index in range(count):
            offset = dir_offset + index * 8
            if len(optional) < offset + 8:
                break
            self.directories.append(struct.unpack_from("<II", optional, offset))
        clr = self.directory(14)
        self.is_dotnet = bool(clr[0] and clr[1])

        raw = fh.read(40 * min(num_sections, 96))
        for index in range(len(raw) // 40):
            _name, vsize, vaddr, rawsize, rawptr = struct.unpack_from(
                "<8sIIII", raw, index * 40)
            self.sections.append((vaddr, max(vsize, rawsize), rawptr, rawsize))
        self.ok = True

    def directory(self, index: int) -> Tuple[int, int]:
        if index < len(self.directories):
            return self.directories[index]
        return (0, 0)

    def offset(self, rva: int) -> int:
        """Смещение в файле по виртуальному адресу (0 — адрес вне секций)."""
        if rva <= 0:
            return 0
        for vaddr, vsize, rawptr, rawsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                delta = rva - vaddr
                if delta >= rawsize and rawsize:
                    return 0
                return rawptr + delta
        return 0

    def read_at(self, rva: int, size: int) -> bytes:
        offset = self.offset(rva)
        if not offset:
            return b""
        self.fh.seek(offset)
        return self.fh.read(size)

    def read_name(self, rva: int, limit: int = 255) -> str:
        raw = self.read_at(rva, limit)
        if not raw:
            return ""
        raw = raw.split(b"\0", 1)[0]
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError:
            return raw.decode("latin-1", "ignore")


def read_pe_imports(path: str, max_names: int = 512) -> PEImports:
    """Список импортируемых библиотек (обычных и delay-load) из PE-файла.

    Отложенный импорт учитывается специально: ``XINPUT1_3.dll`` и
    ``xaudio2_7.dll`` игры часто грузят именно так, и отсутствие файла
    проявляется не при старте, а посреди игры.
    """
    info = PEImports(path=path)
    try:
        with open(path, "rb") as fh:
            pe = _PEReader(fh)
            if not pe.ok:
                return info
            info.is_pe = True
            info.machine = pe.machine
            info.is_dotnet = pe.is_dotnet

            seen: Dict[str, None] = {}

            # --- обычный импорт (каталог 1) ---------------------------------
            import_rva = pe.directory(1)[0]
            if import_rva:
                for index in range(4096):
                    entry = pe.read_at(import_rva + index * 20, 20)
                    if len(entry) < 20 or not any(entry):
                        break
                    name = normalize_dll(pe.read_name(
                        struct.unpack_from("<I", entry, 12)[0]))
                    if name and name.endswith((".dll", ".drv", ".ocx", ".exe")) \
                            and name not in seen:
                        seen[name] = None
                        info.imports.append(name)
                    if len(seen) >= max_names:
                        break

            # --- отложенный импорт (каталог 13) -----------------------------
            delay_rva = pe.directory(13)[0]
            if delay_rva:
                for index in range(4096):
                    entry = pe.read_at(delay_rva + index * 32, 32)
                    if len(entry) < 32 or not any(entry):
                        break
                    attributes, name_ref = struct.unpack_from("<II", entry, 0)
                    # У старых компиляторов (VC6/VC7) в дескрипторе лежат не
                    # RVA, а полные виртуальные адреса: бит 1 не выставлен.
                    if not attributes & 1 and pe.image_base \
                            and name_ref > pe.image_base:
                        name_ref -= pe.image_base
                    name = normalize_dll(pe.read_name(name_ref))
                    if name and name.endswith((".dll", ".drv", ".ocx", ".exe")) \
                            and name not in seen:
                        seen[name] = None
                        info.delay_imports.append(name)
                    if len(seen) >= max_names:
                        break
    except (OSError, struct.error, ValueError):
        return PEImports(path=path)
    return info


def read_pe_manifest(path: str) -> str:
    """Встроенный манифест приложения (ресурс RT_MANIFEST) как текст.

    Нужен для VC++ 2005/2008: манифест указывает **точную** версию
    side-by-side сборки, которую требует программа, и private-копия рядом с
    exe обязана объявить ту же версию — иначе загрузчик её не примет.
    """
    try:
        with open(path, "rb") as fh:
            pe = _PEReader(fh)
            if not pe.ok:
                return ""
            resource_rva = pe.directory(2)[0]
            if not resource_rva:
                return ""

            def entries(table_rva: int) -> List[Tuple[int, int, bool]]:
                header = pe.read_at(table_rva, 16)
                if len(header) < 16:
                    return []
                named, ids = struct.unpack_from("<HH", header, 12)
                total = min(named + ids, 256)
                out: List[Tuple[int, int, bool]] = []
                for index in range(total):
                    raw = pe.read_at(table_rva + 16 + index * 8, 8)
                    if len(raw) < 8:
                        break
                    name, offset = struct.unpack_from("<II", raw, 0)
                    is_dir = bool(offset & 0x80000000)
                    out.append((name, offset & 0x7FFFFFFF, is_dir))
                return out

            for name, offset, is_dir in entries(resource_rva):
                # Тип 24 = RT_MANIFEST.
                if name != 24 or not is_dir:
                    continue
                for _n2, offset2, is_dir2 in entries(resource_rva + offset):
                    if not is_dir2:
                        continue
                    for _n3, offset3, is_dir3 in entries(resource_rva + offset2):
                        if is_dir3:
                            continue
                        data = pe.read_at(resource_rva + offset3, 16)
                        if len(data) < 8:
                            continue
                        data_rva, size = struct.unpack_from("<II", data, 0)
                        size = min(size, 128 * 1024)
                        raw = pe.read_at(data_rva, size)
                        if raw:
                            return raw.decode("utf-8", "ignore")
    except (OSError, struct.error, ValueError):
        return ""
    return ""


def manifest_identity(manifest: str, assembly: str) -> Dict[str, str]:
    """Идентичность запрошенной сборки из манифеста программы."""
    if not manifest or not assembly:
        return {}
    pattern = re.compile(
        r"<assemblyIdentity\b[^>]*?name=\"" + re.escape(assembly) + r"\"[^>]*?/?>",
        re.IGNORECASE)
    match = pattern.search(manifest)
    if not match:
        return {}
    chunk = match.group(0)
    out: Dict[str, str] = {}
    for key in ("type", "version", "processorArchitecture", "publicKeyToken"):
        found = re.search(key + r"=\"([^\"]+)\"", chunk, re.IGNORECASE)
        if found:
            out[key] = found.group(1)
    return out


# =============================================================================
#  3. Сканирование папки App
# =============================================================================

@dataclass
class RuntimeRequirement:
    """Одна библиотека, которая нужна программе для запуска."""

    dll: str
    arch: str = ""
    package: Optional[RedistPackage] = None
    importers: List[str] = field(default_factory=list)
    delay_only: bool = True
    #: bundled — уже лежит в App; system — даёт Windows; provided — принесли
    #: сейчас; missing — нужен пакет на целевом ПК; unknown — не опознана.
    status: str = "missing"
    source: str = ""
    targets: List[str] = field(default_factory=list)
    #: True — библиотека принесена «про запас» полным комплектом, а не потому,
    #: что её требует таблица импорта. Такое требование не может быть
    #: «обязательным»: его неудача — не ошибка, а пустое место в запасе.
    proactive: bool = False

    @property
    def title(self) -> str:
        return self.package.title if self.package else "неизвестный компонент"

    @property
    def plain_title(self) -> str:
        """Название пакета для Launch.bat (ASCII)."""
        return self.package.plain_title() if self.package else "unknown component"

    @property
    def url(self) -> str:
        return self.package.url(self.arch) if self.package else ""


@dataclass
class RuntimeScan:
    """Результат разбора всех исполняемых файлов портатива."""

    app_dir: str = ""
    requirements: List[RuntimeRequirement] = field(default_factory=list)
    arch: str = ""
    #: Все разрядности, встретившиеся среди exe/dll (для полного комплекта).
    archs: List[str] = field(default_factory=list)
    dotnet: bool = False
    scanned: int = 0
    parsed: int = 0

    def by_status(self, *statuses: str) -> List[RuntimeRequirement]:
        return [r for r in self.requirements if r.status in statuses]

    @property
    def needed(self) -> List[RuntimeRequirement]:
        """Всё, чего не хватает рядом с программой и не даёт Windows."""
        return [r for r in self.requirements if r.status == "missing"]


def _pick_local_copy(candidates: Sequence[str],
                     requirement: RuntimeRequirement) -> str:
    """Копия библиотеки внутри App, пригодная для этой программы.

    Разрядность проверяется специально: в комплекте нередко лежат обе версии
    (``redist\\x64\\msvcp110.dll`` и ``redist\\x86\\msvcp110.dll``), и
    32-битной программе 64-битный файл только навредит.
    """
    if not candidates:
        return ""
    if requirement.package is None or not requirement.arch:
        return candidates[0]
    for candidate in candidates:
        info = read_pe_imports(candidate)
        if not info.is_pe or info.machine == requirement.arch:
            return candidate
    return ""


def _iter_binaries(app_dir: str, max_files: int) -> Iterable[str]:
    count = 0
    for root, _dirs, files in os.walk(app_dir):
        for name in sorted(files):
            if not name.lower().endswith((".exe", ".dll")):
                continue
            if name.lower() in _SKIP_FILES:
                continue
            yield os.path.join(root, name)
            count += 1
            if count >= max_files:
                return


def scan_app_runtime(app_dir: str, max_files: int = MAX_SCANNED_FILES
                     ) -> RuntimeScan:
    """Собирает требования программы к системным библиотекам."""
    scan = RuntimeScan(app_dir=app_dir)
    if not app_dir or not os.path.isdir(app_dir):
        return scan

    present: Dict[str, List[str]] = {}
    for root, _dirs, files in os.walk(app_dir):
        for name in files:
            present.setdefault(name.lower(), []).append(
                os.path.join(root, name))

    machines: Dict[str, int] = {}
    collected: Dict[Tuple[str, str], RuntimeRequirement] = {}

    for path in _iter_binaries(app_dir, max_files):
        scan.scanned += 1
        info = read_pe_imports(path)
        if not info.is_pe:
            continue
        scan.parsed += 1
        if info.is_dotnet:
            scan.dotnet = True
        arch = info.machine or ""
        if arch:
            machines[arch] = machines.get(arch, 0) + 1
        rel = os.path.relpath(path, app_dir).replace("\\", "/")
        for dll in info.all_imports:
            key = (dll, arch)
            requirement = collected.get(key)
            if requirement is None:
                requirement = RuntimeRequirement(
                    dll=dll, arch=arch, package=find_package(dll))
                collected[key] = requirement
            if len(requirement.importers) < MAX_IMPORTERS_SHOWN:
                requirement.importers.append(rel)
            if dll in info.imports:
                requirement.delay_only = False

    if machines:
        scan.arch = max(machines.items(), key=lambda item: item[1])[0]
        # Порядок: от главной разрядности к второстепенной — так полный
        # комплект разворачивается в том же порядке, в каком программа
        # грузит свои бинарники.
        scan.archs = [arch for arch, _count in
                      sorted(machines.items(), key=lambda item: -item[1])]

    for requirement in collected.values():
        local = _pick_local_copy(present.get(requirement.dll, []),
                                 requirement)
        if local:
            requirement.status = "bundled"
            requirement.source = os.path.relpath(local, app_dir).replace("\\", "/")
        elif requirement.package is not None:
            requirement.status = "missing"
        elif is_system_dll(requirement.dll):
            requirement.status = "system"
        else:
            requirement.status = "unknown"

    scan.requirements = sorted(
        collected.values(),
        key=lambda r: (r.status != "missing", r.dll, r.arch))
    return scan


def full_kit_requirements(archs: Sequence[str],
                          anchors: Sequence[str] = (),
                          ) -> List[RuntimeRequirement]:
    """**Полный комплект** всех известных библиотек — «про запас».

    Таблица импорта отвечает на вопрос «что программа требует точно», но не
    видит библиотек, которые грузятся динамически по имени, собранному
    строкой (игры собирают ``d3dx9_%d.dll``), подключаются плагинами и
    модами или оказываются нужны после того, как установщик докачал
    компонент. Полный комплект приносит всё, что вообще умеет приносить
    Portablizer, — в этом случае окно «отсутствует XINPUT1_3.dll» не
    возникает в принципе.

    ``anchors`` — app-относительные пути главных exe: рядом с ними комплект
    и раскладывается. Требования помечаются ``proactive=True``, поэтому
    неудача их доставки ошибкой не считается.
    """
    out: List[RuntimeRequirement] = []
    for package in REDIST_PACKAGES:
        members = FULL_KIT.get(package.key)
        if not members:
            continue
        for arch in archs:
            if arch not in package.archs:
                continue
            for dll in members.get("*", ()) + members.get(arch, ()):
                out.append(RuntimeRequirement(
                    dll=dll, arch=arch, package=package, proactive=True,
                    importers=[str(a).replace("\\", "/") for a in anchors]))
    return out


# =============================================================================
#  4. Доставка недостающих файлов в портатив
# =============================================================================

@dataclass
class ProvisionReport:
    """Что удалось принести в портатив, а что придётся ставить на целевом ПК."""

    app_name: str = ""
    arch: str = ""
    dotnet: bool = False
    provided: List[RuntimeRequirement] = field(default_factory=list)
    bundled: List[RuntimeRequirement] = field(default_factory=list)
    system: List[RuntimeRequirement] = field(default_factory=list)
    missing: List[RuntimeRequirement] = field(default_factory=list)
    unknown: List[RuntimeRequirement] = field(default_factory=list)
    #: Скачанные установщики пакетов, оставленные в Redist/.
    packages: List[str] = field(default_factory=list)
    #: Пакеты, установленные в систему этого ПК в тихом режиме по ходу сборки.
    installed: List["SilentInstall"] = field(default_factory=list)
    #: Установщики, положенные в ``Redist`` портатива: если библиотеки всё же
    #: не хватит на целевом ПК, лончер поставит их оттуда — тоже молча.
    installers: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    #: Полный комплект включён: часть требований взята из каталога всех
    #: известных пакетов, а не из таблиц импорта программы.
    full_kit: bool = False
    #: Принесено «про запас» полным комплектом (не обязательно программе).
    stock: List[RuntimeRequirement] = field(default_factory=list)
    #: Полный комплект: найти не удалось (программе, скорее всего, не нужно).
    stock_missing: List[RuntimeRequirement] = field(default_factory=list)
    #: Сколько библиотек программа принесла с собой (её собственные файлы).
    own_files: int = 0

    @property
    def touched(self) -> bool:
        return bool(self.provided or self.missing or self.bundled
                    or self.unknown or self.packages or self.stock
                    or self.stock_missing)


def system_dirs_for(arch: str) -> List[str]:
    """Системные папки Windows, где искать библиотеку нужной разрядности."""
    if not IS_WINDOWS:
        return []
    windir = (os.environ.get("SystemRoot") or os.environ.get("WINDIR")
              or r"C:\Windows")
    system32 = os.path.join(windir, "System32")
    syswow64 = os.path.join(windir, "SysWOW64")
    # Из 32-битного процесса System32 подменяется на SysWOW64, а настоящий
    # System32 доступен как Sysnative. Разрядность найденного файла всё равно
    # проверяется отдельно, поэтому здесь достаточно перечислить кандидатов.
    sysnative = os.path.join(windir, "Sysnative")
    if arch == "x86":
        order = [syswow64, system32]
    elif arch in ("x64", "arm64"):
        order = [sysnative, system32, syswow64]
    else:
        order = [system32, syswow64]
    return [path for path in order if os.path.isdir(path)]


def winsxs_dir() -> str:
    if not IS_WINDOWS:
        return ""
    windir = (os.environ.get("SystemRoot") or os.environ.get("WINDIR")
              or r"C:\Windows")
    path = os.path.join(windir, "WinSxS")
    return path if os.path.isdir(path) else ""


#: Предел индексации папок-источников: «Setup» диска может быть огромной.
MAX_INDEXED_SOURCE_FILES = 120000

#: Приметы версии пакета в имени файла/папки: у вендоров это всегда год.
_PACKAGE_YEARS: Dict[str, Tuple[str, ...]] = {
    "vc2005": ("2005", "vc80", "8.0"),
    "vc2008": ("2008", "vc90", "9.0"),
    "vc2010": ("2010", "vc100", "10.0"),
    "vc2012": ("2012", "vc110", "11.0"),
    "vc2013": ("2013", "vc120", "12.0"),
    "vc14": ("2015", "2017", "2019", "2022", "vc140", "14."),
}

#: Папки рядом с установщиком/программой, где вендоры складывают пакеты.
REDIST_SOURCE_NAMES = (
    "_commonredist", "commonredist", "redist", "redistributable",
    "redistributables", "prerequisites", "prereq", "support", "directx",
    "vcredist", "runtimes", "_redist", "install", "setup", "extras",
)


def installer_source_dirs(installer_path: str, app_dir: str = "",
                          depth: int = 3, max_dirs: int = 4000) -> List[str]:
    """Каталоги, в которых имеет смысл искать готовые redist-файлы.

    Repack-сборки и диски игр почти всегда несут ``_CommonRedist`` или
    ``redist`` рядом с установщиком: оттуда можно взять ровно те версии
    библиотек, на которые рассчитывала программа.
    """
    roots: List[str] = []
    base = os.path.dirname(os.path.abspath(installer_path)) if installer_path else ""
    for candidate in (base, app_dir):
        if candidate and os.path.isdir(candidate) and candidate not in roots:
            roots.append(candidate)

    found: List[str] = []
    visited = 0
    for root in roots:
        for current, dirs, _files in os.walk(root):
            visited += 1
            # Установщик может лежать в корне диска или в «Загрузках» с
            # тысячами папок: обход обязан быть ограниченным.
            if visited > max_dirs:
                return found
            relative = os.path.relpath(current, root)
            level = 0 if relative == "." else relative.count(os.sep) + 1
            if level >= depth:
                dirs[:] = []
                continue
            for name in list(dirs):
                if name.lower() in REDIST_SOURCE_NAMES:
                    path = os.path.join(current, name)
                    if path not in found:
                        found.append(path)
    return found


#: Меньше этого ни один настоящий redist-пакет не весит. Файл поменьше —
#: это страница с ошибкой, редирект или оборванная закачка.
MIN_PACKAGE_SIZE = 64 * 1024

#: Обычный браузерный User-Agent: раздачи Microsoft иногда отвечают
#: страницей-заглушкой клиенту, который представился «непонятно кем».
_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/124.0 Safari/537.36")


def package_file_problem(path: str) -> str:
    """Что не так со скачанным пакетом (пустая строка — всё в порядке).

    Скачанный «пакет», который на самом деле HTML-страница с ошибкой или
    обрывок файла, невозможно ни распаковать, ни установить. Такое надо
    ловить сразу и называть своим именем, а не сообщением «распаковать не
    удалось».
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return "файл не сохранился"
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError as exc:
        return f"файл не читается ({exc})"
    lower = path.lower()
    if lower.endswith((".msi", ".msp")):
        expected, what = b"\xd0\xcf\x11\xe0", "MSI"
    elif lower.endswith(".cab"):
        expected, what = b"MSCF", "CAB"
    else:
        expected, what = b"MZ", "программа Windows"
    if not head.startswith(expected):
        if head.lstrip()[:1] in (b"<", b"{"):
            return ("сервер вернул веб-страницу вместо файла "
                    "(ссылка устарела или закрыта)")
        return f"это не {what}: файл начинается не с {expected!r}"
    if size < MIN_PACKAGE_SIZE:
        return (f"файл слишком мал ({size} Б) — закачка оборвалась или "
                "сервер отдал заглушку")
    return ""


def format_size(size: float) -> str:
    """Человеческий размер файла: ``97.8 МБ`` вместо ``102537240``."""
    if size < 0:
        return "?"
    for unit, step in (("Б", 1), ("КБ", 1024), ("МБ", 1024 ** 2),
                       ("ГБ", 1024 ** 3)):
        if size < step * 1024 or unit == "ГБ":
            value = size / step
            return f"{value:.0f} {unit}" if unit == "Б" else f"{value:.1f} {unit}"
    return f"{size:.0f} Б"


def format_duration(seconds: float) -> str:
    """Оставшееся время в виде ``0:42`` / ``3:05``."""
    if seconds < 0 or seconds != seconds or seconds == float("inf"):
        return "?"
    seconds = int(seconds + 0.5)
    if seconds >= 3600:
        return f"{seconds // 3600}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"
    return f"{seconds // 60}:{seconds % 60:02d}"


def describe_download(done: int, total: int, elapsed: float) -> Tuple[int, str]:
    """Процент и человеческое описание хода загрузки.

    Возвращает ``(percent, text)``; ``percent`` равен ``-1``, если сервер не
    сообщил размер файла (тогда полоса в интерфейсе становится «бегущей»).
    """
    speed = done / elapsed if elapsed > 0.2 else 0.0
    parts: List[str] = []
    if total > 0:
        percent = min(100, int(done * 100 / total))
        parts.append(f"{format_size(done)} из {format_size(total)}")
    else:
        percent = -1
        parts.append(format_size(done))
    if speed > 0:
        parts.append(f"{format_size(speed)}/с")
        if total > done:
            parts.append(f"осталось ~{format_duration((total - done) / speed)}")
    return percent, ", ".join(parts)


def _accepts_keyword(func: Callable, name: str) -> bool:
    """Принимает ли функция такой именованный аргумент.

    Загрузчик подменяется в тестах и во внешних сценариях функцией из двух
    аргументов — ей нельзя передавать ``progress``/``cancel``.
    """
    import inspect

    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return False
    for parameter in signature.parameters.values():
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            return True
        if parameter.name == name and parameter.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY):
            return True
    return False


#: Как часто обновляем ход загрузки (секунды) — чаще незачем, реже «висит».
DOWNLOAD_TICK_SECONDS = 0.5


#: Сколько максимум ждём собственный (чисто питоновский) декодер кабинетов
#: на ОДНОЙ операции: он читает LZX/MSZIP побитно и на огромном пакете
#: (``directx_Jun2010_redist.exe`` — почти 100 МБ) может оказаться на порядок
#: медленнее штатного ``expand``/wextract. Раньше это выглядело как «сборка
#: висит на 85%»: скачивание доходило до 100%, а дальше единственный вызов
#: ``cabinet.extract_file`` без единой точки прогресса или отмены мог идти
#: сколько угодно. Теперь у него есть потолок: не уложился — переходим к
#: следующей ступени лестницы (штатный ``expand``/wextract), а не ждём.
CABINET_DECODE_TIMEOUT = 60

#: Как часто, пока decoder работает, обновляем «живой» индикатор прогресса.
CABINET_HEARTBEAT_SECONDS = 3.0


def _bounded_call(func: Callable[..., object], *args,
                  timeout: Optional[float] = None,
                  heartbeat: Optional[float] = None,
                  on_tick: Optional[Callable[[float], None]] = None,
                  default: object = None, **kwargs) -> object:
    """Выполняет ``func`` в отдельном потоке и не ждёт его дольше ``timeout``.

    Наш декодер кабинетов — чистый Python без единой точки, где его можно
    прервать посередине, поэтому единственный надёжный способ не дать ему
    подвесить сборку — вынести вызов в daemon-поток и ограничить ожидание
    снаружи. Поток остаётся daemon'ом: если он всё же не уложится, он тихо
    доработает в фоне (или будет снят вместе с процессом), а сборка в это
    время уже перейдёт к следующей, более быстрой ступени лестницы
    (``expand``/wextract). ``on_tick(elapsed)`` вызывается каждые
    ``heartbeat`` секунд ожидания — сюда подключается индикатор прогресса,
    чтобы «висит» и «просто небыстро» не выглядели одинаково.

    ``timeout``/``heartbeat`` при отсутствии берутся из модульных констант
    в момент ВЫЗОВА, а не при определении функции — иначе их нельзя было бы
    переопределить ни тестам, ни будущим настройкам.
    """
    if timeout is None:
        timeout = CABINET_DECODE_TIMEOUT
    if heartbeat is None:
        heartbeat = CABINET_HEARTBEAT_SECONDS
    box: List[object] = [default]

    def worker() -> None:
        try:
            box[0] = func(*args, **kwargs)
        except Exception:  # noqa: BLE001 — чужой файл не должен ронять сборку
            pass

    done = threading.Event()

    def run_and_signal() -> None:
        try:
            worker()
        finally:
            done.set()

    thread = threading.Thread(target=run_and_signal, daemon=True)
    thread.start()
    started = time.monotonic()
    while not done.wait(timeout=heartbeat):
        elapsed = time.monotonic() - started
        if on_tick is not None:
            try:
                on_tick(elapsed)
            except Exception:  # noqa: BLE001
                pass
        if elapsed >= timeout:
            break
    return box[0]


def _download_file(url: str, destination: str, timeout: int = 120,
                   progress: Optional[Callable[[int, int, float], None]] = None,
                   cancel: Optional[Callable[[], bool]] = None) -> bool:
    """Скачивает файл во временное имя и переименовывает его по готовности.

    Читает поток кусками и после каждого куска сообщает ``progress(done,
    total, elapsed)``: без этого большие пакеты (DirectX June 2010 — почти
    100 МБ) выглядели как зависание на одном и том же проценте. ``timeout``
    здесь — предел ожидания **одной порции данных**, а не всей загрузки:
    замолчавший сервер обрывает её ошибкой, а не держит сборку часами.
    Оборванная закачка (получено меньше, чем обещал ``Content-Length``)
    считается неудачей — иначе в ``Redist`` оседал бы огрызок пакета.
    """
    import time
    import urllib.request

    temporary = destination + ".part"
    try:
        request = urllib.request.Request(url, headers={
            "User-Agent": _USER_AGENT,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        })
        started = time.monotonic()
        done = 0
        total = -1
        with urllib.request.urlopen(request, timeout=timeout) as response, \
                open(temporary, "wb") as fh:
            length = response.headers.get("Content-Length")
            try:
                total = int(length) if length else -1
            except (TypeError, ValueError):
                total = -1
            if progress is not None:
                progress(0, total, 0.0)
            while True:
                if cancel is not None and cancel():
                    raise RuntimeError("загрузка отменена пользователем")
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if progress is not None:
                    progress(done, total, time.monotonic() - started)
        if total > 0 and done < total:
            raise IOError(
                f"получено {done} Б из {total} Б — соединение оборвалось")
        os.replace(temporary, destination)
        return True
    except Exception:  # noqa: BLE001 — сеть не должна ронять сборку
        try:
            if os.path.exists(temporary):
                os.remove(temporary)
        except OSError:
            pass
        return False


#: Код «истекло время ожидания» (WAIT_TIMEOUT): пакет так и не завершился —
#: почти наверняка он всё же показал окно и ждёт мышку.
TIMEOUT_EXIT_CODE = 0x102


def _kill_tree(process: "subprocess.Popen") -> None:
    """Снимает зависший пакет вместе со всеми его детьми.

    ``Popen.kill()`` снимает только саму обёртку, а модальное окно обычно
    показывает её ребёнок (``msiexec``, ``DXSETUP``, распакованный
    ``setup.exe``). Пережившее сборку окно ждало бы мышку вечно, поэтому
    дерево процессов снимается целиком штатным ``taskkill``.
    """
    try:
        if sys.platform.startswith("win"):
            subprocess.run(
                [system_tool("taskkill"), "/T", "/F", "/PID", str(process.pid)],
                timeout=30, creationflags=0x08000000,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=15)
    except (OSError, subprocess.SubprocessError):
        pass


#: Сколько ждём между опросами долгого процесса (секунды): достаточно
#: часто, чтобы heartbeat не выглядел «мёртвым», и достаточно редко, чтобы
#: не грузить систему пустыми системными вызовами.
_WAIT_POLL_SECONDS = 2.0

#: Сколько ждём штатный инструмент распаковки (expand/extrac32/7-Zip/
#: wextract): на большом пакете (DirectX — почти 100 МБ, плюс антивирус,
#: который сканирует каждый распакованный файл) 5 минут — реальный сценарий
#: (а не признак зависания), но уже не те 10 минут, что были при первой
#: версии этого потолка.
NATIVE_TOOL_TIMEOUT = 300

#: Верхний потолок на доставку ОДНОЙ библиотеки целиком: поиск в источниках
#: + распаковка + скачивание + тихая установка. Это последняя линия
#: обороны: даже если внутри лестницы источников найдётся ступень без
#: собственного таймаута (сейчас или в будущем), сборка всё равно не
#: останется на одном requirement дольше этого предела — библиотека
#: помечается недостающей, и доставка продолжается со следующей.
REQUIREMENT_TIMEOUT = 15 * 60


def _run_quiet(args: Sequence[str], timeout: int = 600,
               on_tick: Optional[Callable[[float, int], None]] = None) -> int:
    """Запускает внешний инструмент (expand/msiexec/DXSETUP) без окна.

    Возвращает код возврата; :data:`TIMEOUT_EXIT_CODE` означает, что пакет
    не уложился в отведённое время и был снят вместе со своими детьми.
    Ждём не одним блокирующим ``wait(timeout=...)``, а короткими порциями:
    так вызывающий может показать, что установка «жива» — ``on_tick(elapsed,
    timeout)`` вызывается при каждом опросе, — а не только итог через
    15 минут молчаливого ожидания DirectX/.NET/обновлений Windows.
    """
    if not IS_WINDOWS:
        return 1
    flags = 0x08000000  # CREATE_NO_WINDOW
    try:
        process = subprocess.Popen(
            list(args), creationflags=flags,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return 1
    started = time.monotonic()
    try:
        while True:
            elapsed = time.monotonic() - started
            remaining = timeout - elapsed
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(args), timeout)
            try:
                return process.wait(timeout=min(_WAIT_POLL_SECONDS, remaining))
            except subprocess.TimeoutExpired:
                if on_tick is not None:
                    try:
                        on_tick(time.monotonic() - started, timeout)
                    except Exception:  # noqa: BLE001
                        pass
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        return TIMEOUT_EXIT_CODE
    except (OSError, subprocess.SubprocessError):
        _kill_tree(process)
        return 1


# =============================================================================
#  4a. Распаковка пакетов: пути, пригодные для командной строки
# =============================================================================
#
# Самораспаковывающиеся пакеты Microsoft (wextract/IExpress у VC++ 2005–2010,
# WiX Burn у VC++ 2012+) получают путь распаковки **внутри одного аргумента**:
# ``/T:C:\путь``, ``/x:C:\путь``, ``/layout C:\путь``. Этот разбор делает сам
# пакет, и он ломается там, где обычный CreateProcess справился бы:
#
# * пробел в пути обрывает аргумент (``/T:C:\Мои игры\…`` → цель ``C:\Мои``);
# * кириллица в пути (а у русского пользователя каталог профиля — кириллица)
#   разбирается старыми wextract-обёртками как мусор;
# * очень длинный путь упирается в MAX_PATH.
#
# Отсюда и появлялось «пакет скачан, но распаковать его автоматически не
# удалось»: команда возвращала успех, а файлы уходили не туда (или никуда).
# Поэтому распаковка всегда идёт в путь без пробелов и не-ASCII: сначала
# пробуем короткое имя 8.3 (``GetShortPathNameW``), затем временную папку,
# затем ``%PUBLIC%`` — и лишь потом переносим результат туда, куда просили.


def system_tool(name: str) -> str:
    """Абсолютный путь к штатной программе Windows (``expand``, ``msiexec``).

    В PATH службы сборки или урезанного профиля ``System32`` может не быть
    вовсе, а 32-битный процесс на 64-битной Windows видит System32 через
    перенаправление — поэтому путь ищем сами. Проверка идёт по настоящей
    платформе, а не по подменяемому в тестах флагу.
    """
    if not sys.platform.startswith("win"):
        return name
    windir = os.environ.get("SystemRoot") or r"C:\Windows"
    for folder in ("Sysnative", "System32", "SysWOW64"):
        candidate = os.path.join(windir, folder, name + ".exe")
        if os.path.isfile(candidate):
            return candidate
    return shutil.which(name) or name


def short_path(path: str) -> str:
    """Короткое имя 8.3 для пути (на не-Windows — путь без изменений)."""
    if not IS_WINDOWS or not path:
        return path
    try:
        import ctypes
        from ctypes import wintypes

        get_short = ctypes.windll.kernel32.GetShortPathNameW  # type: ignore[attr-defined]
        get_short.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        get_short.restype = wintypes.DWORD
        size = get_short(path, None, 0)
        if not size:
            return path
        buffer = ctypes.create_unicode_buffer(size)
        if not get_short(path, buffer, size):
            return path
        return buffer.value or path
    except Exception:  # noqa: BLE001 — короткое имя не критично
        return path


def is_cmdline_safe(path: str) -> bool:
    """Путь переживёт передачу внутри аргумента вида ``/T:<путь>``?"""
    if not path:
        return False
    return path.isascii() and " " not in path and len(path) < 160


def _public_temp_root() -> str:
    """``%PUBLIC%\\Portablizer`` — ASCII-путь без пробелов и без прав админа."""
    public = os.environ.get("PUBLIC") or ""
    if not public:
        drive = os.environ.get("SystemDrive") or "C:"
        public = os.path.join(drive + os.sep, "Users", "Public")
    return os.path.join(public, "Portablizer")


def cmdline_safe_dir(destination: str) -> str:
    """Папка для распаковки, которую не испортят пробелы и кириллица.

    Возвращает либо сам ``destination`` (если он и так безопасен), либо
    временную папку, куда пакет можно распаковать, а потом перенести файлы.
    Пустая строка — безопасного места не нашлось, работаем как есть.
    """
    try:
        os.makedirs(destination, exist_ok=True)
    except OSError:
        return ""
    if is_cmdline_safe(destination):
        return destination
    shortened = short_path(destination)
    if is_cmdline_safe(shortened):
        return shortened
    import tempfile

    for base in (None, _public_temp_root()):
        try:
            if base:
                os.makedirs(base, exist_ok=True)
            staging = tempfile.mkdtemp(prefix="pblz", dir=base)
        except OSError:
            continue
        candidate = short_path(staging)
        if is_cmdline_safe(candidate):
            return candidate
        if is_cmdline_safe(staging):
            return staging
        shutil.rmtree(staging, ignore_errors=True)
    return ""


def _same_dir(first: str, second: str) -> bool:
    """Одна и та же папка? Короткое имя 8.3 и длинное — это одна папка."""
    if not first or not second:
        return False
    try:
        if os.path.isdir(first) and os.path.isdir(second):
            return os.path.samefile(first, second)
    except OSError:
        pass
    try:
        return os.path.normcase(os.path.abspath(first)) == \
            os.path.normcase(os.path.abspath(second))
    except OSError:
        return first == second


def merge_tree(source: str, destination: str) -> None:
    """Переносит распакованное из временной папки в целевую."""
    if not os.path.isdir(source) or _same_dir(source, destination):
        return
    os.makedirs(destination, exist_ok=True)
    for current, _dirs, files in os.walk(source):
        relative = os.path.relpath(current, source)
        target = destination if relative == "." else os.path.join(destination,
                                                                  relative)
        os.makedirs(target, exist_ok=True)
        for name in files:
            try:
                shutil.move(os.path.join(current, name),
                            os.path.join(target, name))
            except (OSError, shutil.Error):
                continue


def find_7zip() -> str:
    """7-Zip, если он установлен: он вскрывает и IExpress, и Burn."""
    if not IS_WINDOWS:
        return ""
    candidates = [shutil.which("7z") or "", shutil.which("7za") or ""]
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(variable)
        if base:
            candidates.append(os.path.join(base, "7-Zip", "7z.exe"))
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return ""


#: Ключи **распаковки** (не установки!) по движку самораспаковывающегося пакета.
#: ``{dest}`` подставляется уже безопасным путём.
EXTRACT_SWITCHES: Dict[str, Tuple[Tuple[str, ...], ...]] = {
    # wextract/IExpress: VC++ 2005/2008/2010, directx_*_redist.exe, dxwebsetup.
    "iexpress": (("/Q", "/C", "/T:{dest}"),
                 ("/C", "/T:{dest}"),
                 ("/q", "/x:{dest}"),
                 ("/x:{dest}",)),
    "vcredist_legacy": (("/Q", "/C", "/T:{dest}"),
                        ("/C", "/T:{dest}"),
                        ("/q", "/x:{dest}"),
                        ("/x:{dest}",),
                        ("/extract:{dest}", "/quiet")),
    "directx_bundle": (("/Q", "/C", "/T:{dest}"),
                       ("/C", "/T:{dest}")),
    # WiX Burn: VC++ 2012 и новее. /layout раскладывает msi и cab-контейнеры.
    "burn": (("/quiet", "/norestart", "/layout", "{dest}"),
             ("/layout", "{dest}", "/quiet", "/norestart"),
             ("/quiet", "/layout", "{dest}"),
             ("/q", "/x:{dest}")),
    "nsis": (("/S", "/D={dest}"),),
    "installshield": (("/s", "/extract_all:{dest}"),
                      ("/b{dest}", "/s", "/v/qn")),
    # Движок неизвестен — перебираем всё ходовое, каждый запуск под таймаутом.
    "": (("/Q", "/C", "/T:{dest}"),
         ("/q", "/x:{dest}"),
         ("/x:{dest}",),
         ("/quiet", "/layout", "{dest}"),
         ("/extract:{dest}", "/quiet"),
         ("-y", "-o{dest}")),
}


def extraction_commands(archive: str, destination: str,
                        kind: str = "") -> List[List[str]]:
    """Лестница команд распаковки пакета — от самой точной к самой общей.

    Последние ступени универсальны: и IExpress-обёртки, и кабинеты внутри
    них — обычные CAB-контейнеры, которые умеют вскрывать штатные ``expand``
    и ``extrac32``, а 7-Zip (если он есть на ПК) вскрывает вдобавок Burn.
    """
    archive = os.path.abspath(archive)
    lower = os.path.basename(archive).lower()
    kind = kind or installer_kind(archive)
    if lower.endswith(".cab") or kind == "cab":
        return [
            [system_tool("expand"), "-F:*", archive, destination],
            [system_tool("expand"), "-r", archive, destination],
            [system_tool("extrac32"), "/Y", "/E", "/L", destination, archive],
        ]
    if lower.endswith((".msi", ".msp")) or kind == "msi":
        return [[system_tool("msiexec"), "/a", archive, "/qn",
                 f"TARGETDIR={destination}"]]

    commands: List[List[str]] = []
    seen: set = set()

    def add(command: Sequence[str]) -> None:
        key = tuple(command)
        if key not in seen:
            seen.add(key)
            commands.append(list(command))

    for key in (kind, ""):
        for switches in EXTRACT_SWITCHES.get(key, ()):
            add([archive] + [item.format(dest=destination)
                             for item in switches])
    # Самораспаковывающийся exe — это CAB с PE-заголовком: штатные
    # распаковщики Windows берут его и без «правильного» ключа.
    add([system_tool("expand"), "-F:*", archive, destination])
    add([system_tool("expand"), "-r", archive, destination])
    add([system_tool("extrac32"), "/Y", "/E", "/L", destination, archive])
    sevenzip = find_7zip()
    if sevenzip:
        add([sevenzip, "x", "-y", f"-o{destination}", archive])
    return commands


# =============================================================================
#  4b. Тихая установка распространяемых пакетов
# =============================================================================
#
# Установщики игр и программ почти всегда тянут за собой предусловия:
# ``vcredist_x86.exe``, ``DXSETUP.exe``, ``oalinst.exe``, PhysX, .NET. Когда
# очередь установки доходит до них, каждый показывает своё окно и ждёт «OK» —
# именно это и происходит с первым «Ведьмаком». Портативная сборка обязана
# идти без участия человека, поэтому Portablizer запускает такие пакеты сам
# и только в тихом режиме.
#
# Два правила, из которых сделан этот раздел:
#
# 1. **Запускаем только то, что опознали.** Список ``REDIST_INSTALLERS`` —
#    белый список имён файлов. Произвольный exe из папки установщика никто
#    молча не запустит: это чужой код с правами администратора.
# 2. **Ключи тихого режима подбираются лестницей.** Единственно верного
#    ключа не существует: WiX Burn понимает ``/install /quiet /norestart``,
#    IExpress-обёртки VC++ 2005–2010 — ``/q``, DXSETUP — ``/silent``,
#    Inno Setup — ``/VERYSILENT``, NSIS — ``/S``. Движок определяется по
#    имени и по сигнатурам внутри файла, а если он неизвестен — варианты
#    перебираются от самого частого к самому редкому, и каждый запуск
#    ограничен таймаутом: зависшее окно не остановит сборку.

#: Сколько ждать один пакет: DirectX на HDD ставится неторопливо, но не
#: часами. Раньше здесь было 900 с (15 минут) — с учётом того, что до этой
#: ступени доходят единицы библиотек (обычно файл находится прямо в
#: кабинете, без реальной установки), а heartbeat теперь и так показывает,
#: что процесс жив, отдавать зависшему окну целых 15 минут ожидания смысла
#: не было: 5 минут с запасом хватает настоящей тихой установке DirectX/
#: .NET/обновления Windows, а видимость «висит» сокращается втрое.
SILENT_INSTALL_TIMEOUT = 300

#: Пакеты, которым столько времени и правда нужно: DirectX раскладывает
#: сотню кабинетов, .NET и обновления Windows тоже не торопятся.
_SLOW_KINDS = frozenset({"dxsetup", "directx_bundle", "dotnet", "msu"})

#: Всем остальным хватает пары минут. Предел здесь — не про скорость,
#: а про застрявшее окно: раньше «не тот» ключ держал сборку 5 минут.
SILENT_INSTALL_TIMEOUT_FAST = 120


def silent_timeout(kind: str) -> int:
    """Сколько ждать тихую установку пакета этого типа (секунды)."""
    return (SILENT_INSTALL_TIMEOUT if kind in _SLOW_KINDS
            else SILENT_INSTALL_TIMEOUT_FAST)

#: Успех: 0 — поставлено, 1638/5100/0x80070666 — уже стоит (в т. ч. более
#: новая версия), 3010/1641 — поставлено, но просит перезагрузку.
SILENT_OK_CODES = frozenset({0})
SILENT_ALREADY_CODES = frozenset({1638, 5100, 0x80070666, 0x8007064F})
SILENT_REBOOT_CODES = frozenset({3010, 1641, 0x80240020})


@dataclass(frozen=True)
class RedistInstallerRule:
    """Опознанный установщик пакета и его ключи тихого режима."""

    pattern: str
    kind: str
    title: str
    package_key: str = ""

    def matches(self, filename: str) -> bool:
        return re.fullmatch(self.pattern, filename.lower()) is not None


#: Белый список установщиков предусловий. Порядок важен: более конкретные
#: правила стоят раньше общих.
REDIST_INSTALLERS: Tuple[RedistInstallerRule, ...] = (
    RedistInstallerRule(r"vc_redist\.(?:x86|x64|arm64)\.exe", "burn",
                        "Visual C++ 2015-2022 Redistributable", "vc14"),
    RedistInstallerRule(r"vcredist(?:2012|2013|2015|2017|2019|2022)"
                        r"[_ ]?(?:x86|x64)?\.exe", "burn",
                        "Visual C++ Redistributable"),
    RedistInstallerRule(r"vcredist_(?:x86|x64|ia64)\.exe", "vcredist_legacy",
                        "Visual C++ Redistributable"),
    RedistInstallerRule(r"vcredist(?:2005|2008|2010)"
                        r"[_ ]?(?:x86|x64)?\.exe", "vcredist_legacy",
                        "Visual C++ Redistributable"),
    RedistInstallerRule(r"vcredist\.msi|vc_red\.msi", "msi",
                        "Visual C++ Redistributable"),
    RedistInstallerRule(r"dxsetup\.exe", "dxsetup",
                        "DirectX End-User Runtime", "directx_jun2010"),
    RedistInstallerRule(r"(?:directx.*|dx.*redist.*)\.exe", "directx_bundle",
                        "DirectX End-User Runtime (redist)", "directx_jun2010"),
    RedistInstallerRule(r"dxwebsetup\.exe", "iexpress",
                        "DirectX Web Setup", "directx_jun2010"),
    RedistInstallerRule(r"oalinst\.exe|openal.*\.exe", "nsis",
                        "OpenAL runtime", "openal"),
    RedistInstallerRule(r"(?:nvidia_)?physx.*\.msi", "msi",
                        "NVIDIA PhysX System Software", "physx"),
    RedistInstallerRule(r"(?:nvidia_)?physx.*\.exe", "installshield",
                        "NVIDIA PhysX System Software", "physx"),
    RedistInstallerRule(r"(?:dotnetfx.*|ndp\d.*|netfx.*|dotnet-runtime-.*)\.exe",
                        "dotnet", ".NET Framework / .NET Runtime"),
    RedistInstallerRule(r"xnafx\d*_redist\.msi|xna.*redist.*\.msi", "msi",
                        "Microsoft XNA Framework Redistributable"),
    RedistInstallerRule(r"xliveredist\.msi|gfwlivesetup\.exe", "msi_or_exe",
                        "Games for Windows - LIVE", "gfwl"),
    RedistInstallerRule(r"wmfdist\d*\.exe|windowsmedia.*\.exe", "iexpress",
                        "Windows Media Format Runtime"),
    RedistInstallerRule(r"msxml\d*\.msi", "msi", "MSXML Parser"),
    RedistInstallerRule(r"windows\d[^\\/]*\.msu|kb\d{6,}[^\\/]*\.msu", "msu",
                        "Обновление Windows (MSU)"),
)

#: Лестница ключей тихого режима по движку установщика.
SILENT_SWITCHES: Dict[str, Tuple[Tuple[str, ...], ...]] = {
    # WiX Burn: vc_redist.x64.exe и большинство современных бандлов.
    "burn": (("/install", "/quiet", "/norestart"),
             ("/quiet", "/norestart"),
             ("/layout", "{dest}", "/quiet", "/norestart"),
             ("/q", "/norestart")),
    # IExpress-обёртки VC++ 2005/2008/2010 понимают голый /q. В частности,
    # VC++ 2005 НЕ понимает /norestart и показывает модальное окно
    # «Command line option syntax error», даже если процесс запущен скрыто.
    # Не передаём ему современные ключи и не перебираем сомнительные
    # варианты: /q является общим безопасным ключом для всех трёх версий.
    "vcredist_legacy": (("/q",),),
    # DXSETUP понимает ровно один ключ; на любом другом он показывает окно
    # «Установка DirectX — Неверная операция командной строки» и ждёт мышку,
    # поэтому перебирать варианты для него запрещено (см. silent_commands).
    "dxsetup": (("/silent",),),
    "iexpress": (("/Q",), ("/q",), ("/quiet",)),
    "inno": (("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"),
             ("/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART")),
    "nsis": (("/S",), ("/s",)),
    "installshield": (("/s", "/v/qn"), ("-s",), ("/s", "/sms")),
    "dotnet": (("/q", "/norestart"), ("/quiet", "/norestart"),
               ("/passive", "/norestart")),
    # Движок неизвестен: перебираем все ходовые варианты. Каждый запуск
    # ограничен таймаутом, поэтому «не тот» ключ стоит только времени.
    "": (("/quiet", "/norestart"), ("/q", "/norestart"), ("/S",),
         ("/silent",), ("/s", "/v/qn"),
         ("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")),
}

#: Сигнатуры движков внутри exe — когда имя файла ничего не подсказало.
_ENGINE_SIGNATURES: Tuple[Tuple[bytes, str], ...] = (
    (b".wixburn", "burn"),
    (b"Inno Setup", "inno"),
    (b"Nullsoft Install System", "nsis"),
    (b"InstallShield", "installshield"),
    (b"wextract", "iexpress"),
)


def installer_rule(path: str) -> Optional[RedistInstallerRule]:
    """Правило белого списка для файла (или ``None``, если он не наш)."""
    name = os.path.basename(str(path)).lower()
    for rule in REDIST_INSTALLERS:
        if rule.matches(name):
            return rule
    return None


def is_redist_installer(path: str) -> bool:
    """Это установщик известного распространяемого пакета?"""
    return installer_rule(path) is not None


def sniff_engine(path: str, limit: int = 2 * 1024 * 1024) -> str:
    """Движок установщика по сигнатурам внутри файла (пустая строка — не понял)."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(limit)
            tail = b""
            if size > limit:
                fh.seek(max(0, size - 131072))
                tail = fh.read(131072)
    except OSError:
        return ""
    for signature, engine in _ENGINE_SIGNATURES:
        if signature in head or (tail and signature in tail):
            return engine
    return ""


def installer_kind(path: str) -> str:
    """Тип пакета: ``msi``/``msu``/``burn``/``dxsetup``/… — что запускать и с чем.

    Порядок опознания принципиален. Сигнатура внутри файла говорит лишь о
    том, каким **упаковщиком** сделан exe, а белый список — о том, что это
    за **пакет** и как с ним разговаривать. Это не одно и то же:

    * ``vcredist_x86.exe`` VC++ 2005 упакован wextract, и по сигнатуре он
      «iexpress». Лестница ключей iexpress перебирает ``/Q``, ``/q``,
      ``/quiet`` — и на ``/quiet`` пакет показывает модальное окно
      «Command line option syntax error. Type Command /? for Help», которое
      ждёт мышку. Пакет VC++ 2005 понимает ровно один ключ — ``/q``;
    * ``directx_Jun2010_redist.exe`` — тоже wextract, но это вообще не
      установщик, а архив: любой ключ он пробрасывает вложенному DXSETUP,
      и тот отвечает окном «Установка DirectX — Неверная операция
      командной строки».

    Поэтому правило белого списка сильнее сигнатуры. Исключение одно:
    секция ``.wixburn`` — признак однозначный (ни у чего другого её нет),
    и она важнее имени файла, потому что VC++ 2012/2013 зовутся
    ``vcredist_x86.exe``, как и старые пакеты, но внутри у них WiX Burn.
    """
    lower = os.path.basename(str(path)).lower()
    if lower.endswith((".msi", ".msp")):
        return "msi"
    if lower.endswith(".msu"):
        return "msu"
    engine = sniff_engine(path) if lower.endswith(".exe") else ""
    if engine == "burn":
        return "burn"
    rule = installer_rule(path)
    kind = rule.kind if rule else ""
    if kind == "msi_or_exe":
        kind = "msi" if lower.endswith(".msi") else ""
    return kind or engine


def silent_commands(path: str, kind: str = "",
                    log_file: str = "") -> List[List[str]]:
    """Лестница команд тихой установки — от самой точной к самой общей."""
    path = os.path.abspath(path)
    kind = kind or installer_kind(path)
    if kind == "msi":
        command = ["msiexec", "/i", path, "/qn", "/norestart"]
        if log_file:
            command += ["/L*v", log_file]
        return [command]
    if kind == "msu":
        return [["wusa", path, "/quiet", "/norestart"]]
    if kind == "cab":
        return []
    if kind == "directx_bundle":
        # ``directx_Jun2010_redist.exe`` — не установщик, а самораспаковыва-
        # ющийся архив: внутри лежат кабинеты и DXSETUP.exe. Любой ключ
        # тихого режима он передаёт внутрь, и DXSETUP отвечает окном
        # «Неверная операция командной строки». Ставится он двумя шагами —
        # см. install_directx_bundle().
        return []
    commands = [[path, *switches]
                for switches in SILENT_SWITCHES.get(kind, SILENT_SWITCHES[""])]
    if kind and kind not in ("dxsetup", "directx_bundle", "vcredist_legacy"):
        # Подстраховка: если «правильные» ключи не сработали, пробуем общие.
        # Для старого vcredist такая лестница небезопасна: VC++ 2005 выводит
        # модальное «Command line option syntax error» на /norestart и
        # современные варианты, поэтому для него разрешён только голый /q.
        for switches in SILENT_SWITCHES[""]:
            candidate = [path, *switches]
            if candidate not in commands:
                commands.append(candidate)
    return commands


def classify_exit_code(code: Optional[int]) -> str:
    """Что означает код возврата установщика пакета."""
    if code is None:
        return "failed"
    value = int(code) & 0xFFFFFFFF
    if value in SILENT_OK_CODES:
        return "installed"
    if value in SILENT_ALREADY_CODES:
        return "already"
    if value in SILENT_REBOOT_CODES:
        return "reboot"
    return "failed"


@dataclass
class SilentInstall:
    """Результат тихой установки одного пакета."""

    path: str
    title: str = ""
    package_key: str = ""
    arch: str = ""
    kind: str = ""
    #: ``installed`` / ``already`` / ``reboot`` / ``failed`` / ``skipped``.
    status: str = "pending"
    code: Optional[int] = None
    command: str = ""

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def ok(self) -> bool:
        return self.status in ("installed", "already", "reboot")

    def describe(self) -> str:
        words = {
            "installed": "установлен",
            "already": "уже был установлен",
            "reboot": "установлен (Windows просит перезагрузку)",
            "failed": "установить не удалось",
            "skipped": "пропущен",
        }
        return f"{self.title or self.name}: {words.get(self.status, self.status)}"


def install_directx_bundle(path: str, run: Callable[[Sequence[str]], int],
                           log=None) -> Tuple[Optional[int], str]:
    """Ставит DirectX из ``directx_*_redist.exe`` — распаковка, потом DXSETUP.

    Сам бандл ничего не устанавливает: это архив IExpress. Ключи тихого
    режима он пробрасывает вложенному ``DXSETUP.exe``, а тот на всё, кроме
    ``/silent``, отвечает модальным окном «Установка DirectX — Неверная
    операция командной строки». Поэтому бандл сначала распаковывается во
    временную папку, а затем запускается ``DXSETUP.exe /silent``.
    """
    import tempfile

    if not IS_WINDOWS or not os.path.isfile(path):
        return None, ""
    try:
        base = tempfile.mkdtemp(prefix="pblzdx")
    except OSError:
        return None, ""
    work = cmdline_safe_dir(base) or base
    try:
        # Сначала — собственный распаковщик: бандл DirectX это IExpress,
        # то есть обычный кабинет, приклеенный к PE. Запускать сам бандл
        # (и гадать с ключами) не нужно вовсе.
        # recurse=False: DXSETUP ждёт кабинеты кабинетами. Разворачивать
        # сотню архивов June 2010 (это минуты) перед установкой не нужно
        # и вредно — ставит их он сам. Вызов ограничен по времени: это
        # чистый Python без точки отмены, и на ~100 МБ бандла он может
        # оказаться заметно медленнее штатного wextract из ступени ниже.
        def _on_decode_tick(elapsed: float) -> None:
            if log is not None:
                log.debug(
                    f"Свой распаковщик DirectX: работает уже {int(elapsed)} с "
                    "— жду ещё немного, затем перейду на штатный wextract.")

        _bounded_call(cabinet.extract_file, path, work, recurse=False,
                     default=[], on_tick=_on_decode_tick)
        if not _find_file(work, "dxsetup.exe", allow_mangled=False):
            for command in extraction_commands(path, work, "directx_bundle"):
                code = run(command)
                if log is not None:
                    log.debug(f"Распаковка DirectX (код {code}): "
                              + subprocess.list2cmdline(command))
                if _has_files(work):
                    break
        setup = _find_file(work, "dxsetup.exe", allow_mangled=False)
        if not setup:
            if log is not None:
                log.debug("DXSETUP.exe в пакете DirectX не найден — "
                          "установка пропущена.")
            return None, ""
        command = [setup, "/silent"]
        code = run(command)
        if log is not None:
            log.debug(f"Тихая установка DirectX (код {code}): "
                      + subprocess.list2cmdline(command))
        return code, subprocess.list2cmdline(command)
    finally:
        shutil.rmtree(base, ignore_errors=True)
        if not _same_dir(work, base):
            shutil.rmtree(work, ignore_errors=True)


def install_legacy_vcredist(path: str, run: Callable[[Sequence[str]], int],
                            log=None) -> Tuple[Optional[int], str]:
    """Ставит VC++ 2005/2008/2010 **без запуска самой обёртки**.

    ``vcredist_x86.exe`` этих лет — обёртка IExpress (wextract) вокруг
    обычного ``vc_red.msi`` с ``vc_red.cab``. Разбирать командную строку
    она умеет плохо: лишний ключ (``/norestart``, ``/quiet``) даёт модальное
    «Command line option syntax error. Type Command /? for Help», а ключ
    ``/q:a /c:"…"`` у разных сборок работает по-разному.

    Поэтому обёртку не запускаем вовсе: кабинет читается своим
    распаковщиком, а ``vc_red.msi`` ставится штатным ``msiexec /qn`` — тем
    самым, который вызвала бы и сама обёртка. Окон нет ни одного, а код
    возврата msiexec говорит точно, что произошло. Если внутри msi не
    нашлось (нестандартная сборка), возвращаемся к безопасному ``/q``.
    """
    import tempfile

    if not IS_WINDOWS or not os.path.isfile(path):
        return None, ""
    fallback = [path, "/q"]
    try:
        base = tempfile.mkdtemp(prefix="pblzvc")
    except OSError:
        code = run(fallback)
        return code, subprocess.list2cmdline(fallback)
    work = cmdline_safe_dir(base) or base
    try:
        _bounded_call(
            cabinet.extract_file, path, work, wanted="vc_red.msi",
            default=[],
            on_tick=(lambda elapsed: log.debug(
                f"Свой распаковщик VC++: работает уже {int(elapsed)} с."))
            if log is not None else None)
        package = (_find_file(work, "vc_red.msi", allow_mangled=False)
                   or _find_file(work, "vcredist.msi", allow_mangled=False))
        if package:
            command = [system_tool("msiexec"), "/i", package, "/qn",
                       "/norestart"]
        else:
            # Обёртку вскрыть не удалось — остаётся единственный ключ,
            # который понимают все три поколения пакета.
            command = fallback
        code = run(command)
        if log is not None:
            log.debug(f"Тихая установка VC++ (код {code}): "
                      + subprocess.list2cmdline(command))
        if package and classify_exit_code(code) == "failed":
            code = run(fallback)
            if log is not None:
                log.debug(f"Запасной путь VC++ (код {code}): "
                          + subprocess.list2cmdline(fallback))
            return code, subprocess.list2cmdline(fallback)
        return code, subprocess.list2cmdline(command)
    finally:
        shutil.rmtree(base, ignore_errors=True)
        if not _same_dir(work, base):
            shutil.rmtree(work, ignore_errors=True)


def run_silent_install(path: str, *,
                       runner: Optional[Callable[[Sequence[str]], int]] = None,
                       title: str = "", package_key: str = "", arch: str = "",
                       log=None) -> SilentInstall:
    """Ставит один распространяемый пакет **молча**, перебирая ключи.

    Ни одно окно при этом не появляется: запуск идёт с ``CREATE_NO_WINDOW``,
    а ключи подобраны так, чтобы установщик не задавал вопросов. Если пакет
    всё же решил показать мастер, его прервёт таймаут — сборка продолжится.
    """
    rule = installer_rule(path)
    kind = installer_kind(path)
    timeout = silent_timeout(kind)
    display_name = title or (rule.title if rule else os.path.basename(path))

    def _default_run(args: Sequence[str]) -> int:
        """Тихая установка с heartbeat: без него DirectX/.NET на 15 минут
        превращались в тишину в журнале — неотличимую от настоящего
        зависания сборки."""
        last = [-1]

        def on_tick(elapsed: float, total: int) -> None:
            # Не чаще раза в 20 секунд — иначе журнал завален «жду».
            step = int(elapsed // 20)
            if step == last[0]:
                return
            last[0] = step
            if log is not None:
                log.info(
                    f"  {display_name}: установка идёт уже {int(elapsed)} с "
                    f"из {int(total)} — это нормально для крупных пакетов "
                    "(DirectX, .NET, обновления Windows), ждём.")

        return _run_quiet(args, timeout, on_tick=on_tick)

    run = runner or _default_run
    outcome = SilentInstall(
        path=os.path.abspath(path), kind=kind, arch=arch,
        title=title or (rule.title if rule else os.path.basename(path)),
        package_key=package_key or (rule.package_key if rule else ""))
    if not os.path.isfile(path):
        outcome.status = "skipped"
        return outcome
    if kind == "directx_bundle":
        code, command = install_directx_bundle(path, run, log)
        outcome.code = code
        outcome.command = command
        outcome.status = classify_exit_code(code) if command else "skipped"
        return outcome
    if kind == "vcredist_legacy" and IS_WINDOWS:
        # VC++ 2005-2010 ставим через вложенный vc_red.msi: сама обёртка
        # на «лишний» ключ отвечает модальным окном (см. функцию).
        code, command = install_legacy_vcredist(path, run, log)
        if command:
            outcome.code = code
            outcome.command = command
            outcome.status = classify_exit_code(code)
            return outcome
    commands = silent_commands(path, kind)
    if not commands:
        outcome.status = "skipped"
        return outcome
    for command in commands:
        if log is not None:
            log.debug("Тихая установка: " + subprocess.list2cmdline(command))
        code = run(command)
        outcome.code = code
        outcome.command = subprocess.list2cmdline(command)
        outcome.status = classify_exit_code(code)
        if outcome.ok:
            break
        if code == TIMEOUT_EXIT_CODE:
            # Пакет не завершился сам: почти наверняка он всё-таки показал
            # окно, и оно было снято по таймауту. Перебирать оставшиеся
            # ключи — значит показать это окно ещё несколько раз и отдать
            # им ещё столько же минут. Останавливаемся: ниже по лестнице
            # библиотеки возьмутся из системы или из папки Redist.
            if log is not None:
                log.debug(
                    f"{outcome.name}: пакет не ответил за отведённое время "
                    "и был снят — остальные ключи не пробую.")
            break
    return outcome


#: Скрипт тихой установки, который кладётся в Redist портатива.
SILENT_SCRIPT_NAME = "Install-Redist.cmd"


def render_silent_install_script(entries: Sequence[Dict[str, str]]) -> str:
    """``Install-Redist.cmd``: ставит всё из ``Redist`` молча, за один UAC.

    Скрипт сам просит повышение прав (один раз), после чего каждый пакет
    ставится с ключами тихого режима: никаких мастеров и кнопок «OK». Его
    запускает лончер, но пользователь может выполнить файл и вручную.
    """
    lines = [
        "@echo off",
        "rem Silent installation of the Microsoft/vendor runtime packages",
        "rem this portable app may need. Generated by Portablizer.",
        "setlocal",
        'set "REDIST_ROOT=%~dp0.."',
        "",
        "rem One UAC prompt for the whole batch - installing runtimes needs",
        "rem administrator rights, everything after that is silent.",
        ">nul 2>&1 net session || (",
        '  powershell -NoProfile -ExecutionPolicy Bypass -Command '
        '"Start-Process -Verb RunAs -Wait -WindowStyle Hidden '
        '-FilePath \'%~f0\' -ArgumentList \'--elevated\'" >nul 2>&1',
        "  exit /b 0",
        ")",
        "",
        'set "REDIST_RC=0"',
    ]
    for index, entry in enumerate(entries, start=1):
        relative = str(entry.get("file", "")).replace("/", "\\")
        if not relative:
            continue
        title = "".join(ch for ch in str(entry.get("title", relative))
                        if 32 <= ord(ch) < 127 and ch not in '%&|<>^()"')
        kind = str(entry.get("kind", ""))
        args = str(entry.get("args", ""))
        target = f'"%REDIST_ROOT%\\{relative}"'
        if kind == "msi":
            body = [f"msiexec /i {target} /qn /norestart"]
        elif kind == "msu":
            body = [f"wusa {target} /quiet /norestart"]
        elif kind == "directx_bundle":
            # Бандл DirectX ничего не ставит сам: распаковываем его и
            # запускаем DXSETUP.exe /silent - единственный ключ, который
            # он понимает (на прочих показывает окно с ошибкой).
            temp = f"%SystemRoot%\\Temp\\pblz_dx{index}"
            body = [
                f'set "DXTMP={temp}"',
                'if exist "%DXTMP%" rd /s /q "%DXTMP%"',
                'md "%DXTMP%" 2>nul',
                f'start "" /wait {target} /Q /C /T:%DXTMP%',
                'if exist "%DXTMP%\\DXSETUP.exe" start "" /wait '
                '"%DXTMP%\\DXSETUP.exe" /silent',
                'rd /s /q "%DXTMP%" 2>nul',
            ]
        elif kind == "dxsetup" or relative.lower().endswith("dxsetup.exe"):
            body = [f'start "" /wait {target} /silent']
        elif kind == "vcredist_legacy":
            # VC++ 2005 rejects `/q /norestart` with a visible modal syntax
            # error. Ignore stale metadata too, so a regenerated script fixes
            # portable configs made by older Portablizer versions.
            body = [f'start "" /wait {target} /q']
        else:
            body = [f'start "" /wait {target} {args}'.rstrip()]
        lines += [
            "",
            f"rem --- {relative}",
            f"if not exist {target} goto redist_skip_{index}",
            f"echo Installing {title} ...",
            *body,
            f"call :redist_check %ERRORLEVEL%",
            f"goto redist_next_{index}",
            f":redist_skip_{index}",
            f"echo   skipped: {relative} is not in this folder",
            f":redist_next_{index}",
        ]
    lines += [
        "",
        'if not "%REDIST_RC%" == "0" echo Some packages could not be '
        "installed silently (last code %REDIST_RC%).",
        "endlocal & exit /b %REDIST_RC%",
        "",
        "rem 0 = installed, 1638/5100 = already present, 3010/1641 = reboot",
        "rem later. Everything else is a real failure worth reporting.",
        ":redist_check",
        'if "%~1" == "0" goto :eof',
        'if "%~1" == "1638" goto :eof',
        'if "%~1" == "5100" goto :eof',
        'if "%~1" == "3010" goto :eof',
        'if "%~1" == "1641" goto :eof',
        'set "REDIST_RC=%~1"',
        "echo   [WARNING] exit code %~1",
        "goto :eof",
        "",
    ]
    return "\r\n".join(lines)


def write_silent_install_script(portable_dir: str,
                                entries: Sequence[Dict[str, str]]) -> str:
    """Сохраняет ``Redist/Install-Redist.cmd`` и возвращает путь к нему."""
    if not entries:
        return ""
    redist_dir = os.path.join(portable_dir, REDIST_DIR_NAME)
    path = os.path.join(redist_dir, SILENT_SCRIPT_NAME)
    try:
        os.makedirs(redist_dir, exist_ok=True)
        with open(path, "w", encoding="ascii", errors="replace",
                  newline="") as fh:
            fh.write(render_silent_install_script(entries))
    except OSError:
        return ""
    return path


def find_prerequisite_installers(directories: Sequence[str],
                                 max_files: int = 60000) -> List[str]:
    """Установщики предусловий, приложенные к дистрибутиву.

    Возвращаются только файлы из белого списка (``vcredist_x86.exe``,
    ``DXSETUP.exe``, ``oalinst.exe``…), причём каждое имя — один раз:
    ``_CommonRedist`` часто содержит один и тот же пакет в нескольких
    подпапках.
    """
    found: List[str] = []
    seen: set = set()
    scanned = 0
    for root in directories:
        if not root or not os.path.isdir(root):
            continue
        for current, _dirs, files in os.walk(root):
            for name in files:
                scanned += 1
                if scanned > max_files:
                    return found
                if not is_redist_installer(name):
                    continue
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                found.append(os.path.join(current, name))
    # DirectX и VC++ — раньше всего: от них зависят остальные пакеты.
    def order(path: str) -> Tuple[int, str]:
        lower = os.path.basename(path).lower()
        if lower.startswith(("vcredist", "vc_redist")):
            return (0, lower)
        if lower.startswith(("dxsetup", "directx")):
            return (1, lower)
        return (2, lower)

    return sorted(found, key=order)


def extract_embedded_prerequisites(installer_path: str, log=None,
                                   timeout: int = 240) -> Tuple[str, List[str]]:
    """Достаёт «_CommonRedist»-подобные папки ИЗ САМОГО установщика.

    ``installer_source_dirs`` находит предусловия, только если они лежат
    РЯДОМ с установщиком отдельными файлами (типично для repack-сборок).
    Однофайловые инсталляторы (один ``Setup.exe`` без соседних файлов)
    несут vcredist/DXSETUP/OpenAL ВНУТРИ своего payload — и достаются
    оттуда только тогда, когда установщик сам их распаковывает и
    запускает. Именно тогда и всплывает окно DXSETUP «Неверная операция
    командной строки»: свой ключ тихого режима установщик передаёт
    вложенному DXSETUP, а тот его не понимает.

    Чтобы окно не появилось вовсе, нужные пакеты достаются из архива
    ЗАРАНЕЕ — без запуска самого установщика (никаких побочных эффектов,
    никакого мастера на экране) — и ставятся тихо шагом раньше. Работает
    только там, где есть 7-Zip: он умеет выборочно распаковывать путь
    внутри NSIS/InstallShield/Burn-архива, не трогая остальные гигабайты
    payload'а. Нет 7-Zip — метод просто не применяется, поведение прежнее.
    """
    if not IS_WINDOWS or not os.path.isfile(installer_path):
        return "", []
    sevenzip = find_7zip()
    if not sevenzip:
        return "", []
    import tempfile

    try:
        base = tempfile.mkdtemp(prefix="pblzprereq")
    except OSError:
        return "", []
    dest = cmdline_safe_dir(base) or base
    patterns = [f"*{name}*" for name in REDIST_SOURCE_NAMES]
    command = [sevenzip, "x", "-y", "-r", f"-o{dest}", installer_path, *patterns]
    try:
        code = _run_quiet(command, timeout)
        if log is not None:
            log.debug(f"Поиск предусловий внутри установщика (код {code}): "
                      + subprocess.list2cmdline(command))
        found = find_prerequisite_installers([dest]) if _has_files(dest) else []
        if not found:
            shutil.rmtree(base, ignore_errors=True)
            if not _same_dir(dest, base):
                shutil.rmtree(dest, ignore_errors=True)
            return "", []
        if log is not None:
            log.debug(f"Внутри установщика найдено предусловий: {len(found)}.")
        return base, found
    except Exception as exc:  # noqa: BLE001 — необязательный шаг, не критично
        if log is not None:
            log.debug(f"Поиск предусловий внутри установщика не удался: {exc}")
        shutil.rmtree(base, ignore_errors=True)
        return "", []


def install_prerequisites(directories: Sequence[str], log, *,
                          runner: Optional[Callable[[Sequence[str]], int]] = None,
                          limit: int = 24,
                          installer_path: str = "") -> List[SilentInstall]:
    """Ставит **молча** все предусловия, приложенные к установщику.

    Вызывается ДО запуска основного установщика: когда пакеты уже на месте,
    его собственный шаг «установка компонентов» либо пропускается целиком,
    либо проходит без единого окна с кнопкой «OK».

    Если рядом с установщиком подходящих файлов не нашлось, а сам
    ``installer_path`` передан, предусловия дополнительно ищутся ВНУТРИ
    установщика (см. :func:`extract_embedded_prerequisites`) — это и
    закрывает случай однофайловых дистрибутивов, чей встроенный DXSETUP
    иначе показал бы «Неверная операция командной строки» уже во время
    настоящей установки.
    """
    installers = find_prerequisite_installers(directories)
    scratch = ""
    if not installers and installer_path:
        scratch, installers = extract_embedded_prerequisites(installer_path, log)
    installers = installers[:limit]
    results: List[SilentInstall] = []
    if not installers:
        return results
    log.info(f"Предусловия установщика: найдено пакетов — {len(installers)}. "
             "Ставлю их в тихом режиме, окна с «OK» не появятся.")
    try:
        for path in installers:
            outcome = run_silent_install(path, runner=runner, log=log)
            results.append(outcome)
            if outcome.status == "failed":
                log.warn(f"  • {outcome.describe()} (код {outcome.code})")
            elif outcome.status == "skipped":
                log.debug(f"  • {outcome.describe()}")
            else:
                log.ok(f"  • {outcome.describe()}")
    finally:
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)
    return results


class RuntimeProvisioner:
    """Приносит недостающие системные библиотеки в портативную папку.

    Лестница источников — от самого точного к самому общему:

    1. файлы и пакеты, приложенные к установщику (``_CommonRedist`` и т. п.);
    2. системные папки этого ПК (с обязательной проверкой разрядности);
    3. WinSxS — для VC++ 2005/2008, которые живут только там; рядом с
       программой создаётся private-манифест сборки;
    4. официальная загрузка с сайта Microsoft (только если разрешена).
    """

    def __init__(self, log, *, source_dirs: Sequence[str] = (),
                 system_dirs: Optional[Sequence[str]] = None,
                 sxs_dir: Optional[str] = None,
                 allow_download: bool = False,
                 allow_install: bool = False,
                 downloader: Optional[Callable[[str, str], bool]] = None,
                 runner: Optional[Callable[[Sequence[str]], int]] = None,
                 installer_runner: Optional[Callable[[Sequence[str]], int]] = None,
                 progress: Optional["ProgressCB"] = None,
                 cancel: Optional[Callable[[], bool]] = None,
                 ) -> None:
        self.log = log
        #: ``progress(fraction, text, detail)`` — доля этапа 0..1, подпись
        #: текущей операции и её собственный процент (``-1`` — неизвестен).
        self._progress = progress
        self._cancel = cancel
        self.source_dirs = [d for d in source_dirs if d and os.path.isdir(d)]
        self._system_dirs = list(system_dirs) if system_dirs is not None else None
        self._sxs_dir = sxs_dir if sxs_dir is not None else winsxs_dir()
        self.allow_download = allow_download
        #: Разрешено ли ставить пакет в систему этого ПК — молча, как
        #: последнюю ступень лестницы: поставленный пакет кладёт файлы в
        #: System32/WinSxS, откуда их уже можно взять в портатив.
        self.allow_install = allow_install
        self._download = downloader or _download_file
        self._run = runner or self._default_runner
        self._install_run = installer_runner
        self._index: Optional[Dict[str, List[str]]] = None
        self._extracted: Dict[str, str] = {}
        self._failed_packages: set = set()
        #: Что было установлено в систему по ходу сборки.
        self.installs: List[SilentInstall] = []
        #: Кэш «пакет+разрядность → путь к установщику» (в т. ч. неудачи).
        self._archives: Dict[str, str] = {}
        self._install_tried: set = set()
        #: Пакеты, для которых распаковка УЖЕ запускалась (см.
        #: ``_from_package_payload``): один пакет (скажем, DirectX June
        #: 2010) в полном комплекте отвечает за десятки отдельных DLL, и без
        #: этой отметки каждая из них при застрявшей/медленной распаковке
        #: заново запускала бы тот же самый обречённый вызов — 20-минутный
        #: REQUIREMENT_TIMEOUT, умноженный на десятки библиотек, и есть
        #: настоящая причина «висит намертво», а не сама распаковка.
        self._extraction_tried: set = set()
        #: То же самое, но для закачки пакета с сайта Microsoft: без этой
        #: отметки оборвавшаяся/зависшая загрузка ~100 МБ повторялась бы
        #: заново для каждой DLL того же пакета из полного комплекта.
        self._download_tried: set = set()
        #: Доля этапа, достигнутая на данный момент (0..1).
        self._stage_fraction = 0.0

    # -- ход работ ------------------------------------------------------------
    def _report(self, fraction: Optional[float] = None, text: str = "",
                detail: int = -1) -> None:
        """Сообщает наверх, что происходит прямо сейчас.

        Нужна именно частая отчётность: самая долгая ступень лестницы —
        загрузка стомегабайтного пакета с сайта Microsoft, и без неё
        интерфейс замирал на «82%» на минуты, выглядя зависшим.
        """
        if fraction is not None:
            self._stage_fraction = max(0.0, min(1.0, fraction))
        if self._progress is None:
            return
        try:
            self._progress(self._stage_fraction, text, detail)
        except Exception:  # noqa: BLE001 — интерфейс не должен ронять сборку
            pass

    def _cancelled(self) -> bool:
        if self._cancel is None:
            return False
        try:
            return bool(self._cancel())
        except Exception:  # noqa: BLE001
            return False

    def _default_runner(self, args: Sequence[str]) -> int:
        """Штатный ``expand``/``extrac32``/7-Zip/wextract — но с heartbeat.

        Это единственный запускатель внешних программ, общий для всей
        лестницы распаковки (``_extract_installer``, ``_expand_payloads``,
        ``_expand_one``). Раньше он был просто ``_run_quiet`` без единой
        точки прогресса: если наш собственный (Python) декодер кабинетов
        не укладывался в потолок и уступал место штатному инструменту (см.
        :data:`CABINET_DECODE_TIMEOUT`), а тот на большом пакете
        (``directx_Jun2010_redist.exe`` — почти 100 МБ, антивирус может
        сканировать каждый распакованный файл) работал не одну секунду —
        сборка снова выглядела «висящей на 85%», просто чуть позже. Теперь
        каждые 15 секунд ожидания в журнал уходит строка о том, что процесс
        ещё жив.
        """
        tool = os.path.basename(args[0]) if args else "инструмент"
        last = [-1]

        def on_tick(elapsed: float, total: int) -> None:
            step = int(elapsed // 15)
            if step == last[0]:
                return
            last[0] = step
            self._report(
                None,
                f"{tool}: работает уже {int(elapsed)} с из {int(total)} — "
                "это большой пакет, не зависание", -1)

        return _run_quiet(args, NATIVE_TOOL_TIMEOUT, on_tick=on_tick)

    def _fetch(self, url: str, destination: str, title: str) -> bool:
        """Скачивает пакет, показывая проценты в логе и в интерфейсе.

        Загрузчик подменяется в тестах функцией из двух аргументов, поэтому
        расширенные параметры передаются только тем, кто их принимает.
        """
        import time

        state = {"tick": 0.0, "percent": -2}

        def on_progress(done: int, total: int, elapsed: float) -> None:
            now = time.monotonic()
            percent, human = describe_download(done, total, elapsed)
            finished = total > 0 and done >= total
            if not finished and now - state["tick"] < DOWNLOAD_TICK_SECONDS:
                return
            state["tick"] = now
            self._report(None, f"Скачиваю {title}: {human}", percent)
            step = percent if percent >= 0 else -1
            if step >= 0 and step // 5 == state["percent"] // 5 and not finished:
                return
            state["percent"] = step
            prefix = f"{percent}%" if percent >= 0 else "идёт загрузка"
            self.log.info(f"  {title}: {prefix} ({human})")

        self._report(None, f"Скачиваю {title}…", 0)
        extra: Dict[str, object] = {}
        if _accepts_keyword(self._download, "progress"):
            extra["progress"] = on_progress
        if _accepts_keyword(self._download, "cancel"):
            extra["cancel"] = self._cancel
        return bool(self._download(url, destination, **extra))

    # -- индекс источников ----------------------------------------------------
    def _source_index(self) -> Dict[str, List[str]]:
        if self._index is not None:
            return self._index
        index: Dict[str, List[str]] = {}
        seen = 0
        for root in self.source_dirs:
            for current, _dirs, files in os.walk(root):
                for name in files:
                    index.setdefault(name.lower(), []).append(
                        os.path.join(current, name))
                    seen += 1
                # Папки вроде «Setup» у дисковых изданий содержат весь
                # дистрибутив: индексировать его целиком незачем.
                if seen >= MAX_INDEXED_SOURCE_FILES:
                    self._index = index
                    return index
        self._index = index
        return index

    def _add_to_index(self, directory: str) -> None:
        index = self._source_index()
        for current, _dirs, files in os.walk(directory):
            for name in files:
                index.setdefault(name.lower(), []).insert(
                    0, os.path.join(current, name))

    # -- поиск ----------------------------------------------------------------
    @staticmethod
    def _arch_matches(path: str, arch: str) -> bool:
        if not arch:
            return True
        info = read_pe_imports(path)
        if not info.is_pe or not info.machine:
            return False
        if arch == "x86":
            return info.machine == "x86"
        return info.machine == arch

    def _from_sources(self, requirement: RuntimeRequirement
                      ) -> Tuple[str, str]:
        for candidate in self._source_index().get(requirement.dll, []):
            if self._arch_matches(candidate, requirement.arch):
                return candidate, "комплект установщика"
        return "", ""

    def _from_system(self, requirement: RuntimeRequirement) -> Tuple[str, str]:
        directories = (self._system_dirs if self._system_dirs is not None
                       else system_dirs_for(requirement.arch))
        for directory in directories:
            candidate = os.path.join(directory, requirement.dll)
            if os.path.isfile(candidate) \
                    and self._arch_matches(candidate, requirement.arch):
                return candidate, "системная папка Windows"
        return "", ""

    def _sxs_candidates(self, assembly: str, arch: str) -> List[str]:
        """Папки WinSxS нужной сборки, начиная с самой свежей версии."""
        if not self._sxs_dir or not os.path.isdir(self._sxs_dir):
            return []
        prefix = ("x86_" if arch == "x86" else "amd64_") + assembly.lower() + "_"
        found: List[Tuple[Tuple[int, ...], str]] = []
        try:
            names = os.listdir(self._sxs_dir)
        except OSError:
            return []
        for name in names:
            if not name.lower().startswith(prefix):
                continue
            path = os.path.join(self._sxs_dir, name)
            if not os.path.isdir(path):
                continue
            version = _folder_version(name)
            found.append((version, path))
        found.sort(reverse=True)
        return [path for _version, path in found]

    def _from_sxs(self, requirement: RuntimeRequirement) -> Tuple[str, str]:
        package = requirement.package
        if package is None or not package.sxs:
            return "", ""
        assembly = sxs_assembly_for(requirement.dll, package)
        for directory in self._sxs_candidates(assembly, requirement.arch):
            candidate = os.path.join(directory, requirement.dll)
            if os.path.isfile(candidate):
                return candidate, "WinSxS"
        return "", ""

    # -- распаковка пакетов ---------------------------------------------------
    def _extract_installer(self, archive: str, destination: str,
                           wanted: str = "") -> bool:
        """Распаковывает пакет Microsoft, не устанавливая его в систему.

        Порядок ступеней:

        1. **собственный распаковщик кабинетов** (:mod:`.cabinet`) — он не
           запускает ни сам пакет, ни внешние программы, поэтому его не
           может сорвать ни пробел с кириллицей в пути, ни политика запуска
           exe, ни отсутствие ``expand`` в PATH. Пакеты VC++ 2005-2022 и
           DirectX — это PE с приклеенными кабинетами, и читаются они
           напрямую. Вызов ограничен по времени (:data:`CABINET_DECODE_TIMEOUT`):
           это чистый Python без точки отмены, и на огромном пакете
           (``directx_Jun2010_redist.exe`` — почти 100 МБ) он может оказаться
           на порядок медленнее ступени 3 — не уложился, переходим дальше, а
           не ждём молча;
        2. запуск самого пакета с ключом распаковки, подобранным по его
           движку (wextract, WiX Burn, MSI), в путь без пробелов и не-ASCII;
        3. штатные ``expand``/``extrac32``/7-Zip как последняя надежда.
        """
        if not os.path.isfile(archive):
            return False
        os.makedirs(destination, exist_ok=True)
        base_name = os.path.basename(archive)
        self._report(None, f"Распаковываю {base_name}…", -1)

        # Ступень 1: читаем кабинеты сами — но не бесконечно (см.
        # CABINET_DECODE_TIMEOUT и _bounded_call): без потолка загрузка,
        # доходившая до 100%, дальше могла идти сколько угодно молча — то
        # самое «сборка висит на 85%».
        def _on_decode_tick(elapsed: float) -> None:
            self._report(
                None,
                f"Распаковываю {base_name}… ({int(elapsed)} с — большой "
                "пакет, это не зависание)", -1)

        written = _bounded_call(
            cabinet.extract_file, archive, destination, wanted=wanted,
            default=[], on_tick=_on_decode_tick)
        if written:
            self.log.debug(
                f"{os.path.basename(archive)}: собственным распаковщиком "
                f"извлечено файлов — {len(written)}.")
        self._expand_payloads(destination, wanted)
        enough = (bool(_find_file(destination, wanted)) if wanted
                  else _has_files(destination))
        if enough:
            return True

        # Ступени 2-3 требуют Windows: там живут wextract, expand и msiexec.
        if not IS_WINDOWS:
            return bool(_find_file(destination, wanted)) if wanted else bool(_has_files(destination))
        staging = cmdline_safe_dir(destination) or destination
        source = archive
        if not is_cmdline_safe(source):
            shortened = short_path(source)
            if os.path.isfile(shortened):
                source = shortened
        try:
            for attempt in extraction_commands(source, staging):
                code = self._run(attempt)
                self.log.debug(
                    f"Распаковка пакета (код {code}): "
                    + subprocess.list2cmdline(attempt))
                self._expand_payloads(staging, wanted)
                if (bool(_find_file(staging, wanted)) if wanted else _has_files(staging)):
                    break
            if not _same_dir(staging, destination):
                merge_tree(staging, destination)
        finally:
            if not _same_dir(staging, destination):
                shutil.rmtree(staging, ignore_errors=True)
        self._expand_payloads(destination, wanted)
        return bool(_find_file(destination, wanted)) if wanted else bool(_has_files(destination))

    def _expand_payloads(self, directory: str, wanted: str = "") -> None:
        """Раскрывает вложенные ``.cab`` и ``.msi`` внутри распакованного пакета.

        В DirectX-редисте около сотни кабинетов, и разворачивать их все ради
        одной ``d3dx9_39.dll`` — минуты впустую. Имя нужной библиотеки входит
        в имя кабинета (``Jun2010_d3dx9_39_x86.cab``), поэтому сначала
        пробуем только подходящие, и лишь если не вышло — все подряд.
        """
        if wanted and _find_file(directory, wanted):
            return
        stem = os.path.splitext(wanted)[0].lower() if wanted else ""
        cabinets: List[str] = []
        installers: List[str] = []
        for current, _dirs, files in os.walk(directory):
            for name in files:
                lower = name.lower()
                path = os.path.join(current, name)
                if lower.endswith(".cab"):
                    cabinets.append(path)
                elif lower.endswith((".msi", ".msp")):
                    installers.append(path)
                elif "." not in lower and cabinet.looks_like_container(path):
                    # WiX Burn (VC++ 2012-2022) хранит payload'ы под
                    # служебными именами без расширения (``a0``, ``u1``).
                    # Раньше их пропускали по расширению — отсюда и бралось
                    # «пакет скачан, но распаковать его автоматически не
                    # удалось» для VC++ 2013.
                    if cabinet.looks_like_cabinet(path):
                        cabinets.append(path)
                    else:
                        installers.append(path)

        targeted = [path for path in cabinets
                    if stem and stem in os.path.basename(path).lower()]
        rest = [path for path in cabinets if path not in targeted]
        total = len(targeted) + len(rest) + len(installers)
        done = 0

        def tick(path: str) -> None:
            nonlocal done
            done += 1
            if total > 1:
                self._report(
                    None,
                    f"Распаковываю {os.path.basename(path)} "
                    f"({done} из {total})",
                    int(done * 100 / total))

        for path in targeted:
            self._expand_one(path, os.path.dirname(path))
            tick(path)
        if stem and targeted and _find_file(directory, wanted):
            return

        for path in rest:
            self._expand_one(path, os.path.dirname(path))
            tick(path)
            if stem and _find_file(directory, wanted):
                break
        for path in installers:
            tick(path)
            target = os.path.join(os.path.dirname(path), "_msi")
            os.makedirs(target, exist_ok=True)
            # Внутри MSI кабинет часто лежит отдельным потоком — свой
            # распаковщик достаёт его без msiexec и без прав администратора.
            if self._expand_one(path, target):
                if stem and _find_file(directory, wanted):
                    break
                continue
            if IS_WINDOWS and path.lower().endswith((".msi", ".msp")):
                self._run([system_tool("msiexec"), "/a", path, "/qn",
                           f"TARGETDIR={target}"])
            if stem and _find_file(directory, wanted):
                break

    def _expand_one(self, archive: str, destination: str) -> bool:
        """Раскрывает один кабинет.

        Порядок ступеней зависит от того, где мы работаем:

        * на Windows обычный ``.cab`` сначала отдаём штатному ``expand`` —
          это нативный распаковщик, и на LZX (а именно так сжаты кабинеты
          DirectX и vc_red.cab) он в десятки раз быстрее нашего
          декодера на Python. Именно из-за него «распаковка
          directx_Jun2010_redist.exe шла слишком долго»;
        * всё остальное (и случай, когда ``expand`` не справился) читает
          собственный распаковщик: ему не мешают ни пробелы с кириллицей в
          пути, ни отсутствие ``expand`` в PATH, ни политики запуска exe.

        Успех определяется по появившимся файлам, а не по коду возврата:
        распаковка идёт в папку, где файлы уже лежат, и сам по себе ноль
        от ``expand`` ещё ничего не значит.
        """
        os.makedirs(destination, exist_ok=True)
        before = _dir_entries(destination)

        def produced() -> bool:
            return bool(_dir_entries(destination) - before)

        native_first = IS_WINDOWS and archive.lower().endswith(".cab")
        if native_first:
            self._run([system_tool("expand"), "-F:*", archive, destination])
            if produced():
                return True
        written = _bounded_call(
            cabinet.extract_file, archive, destination, default=[],
            on_tick=lambda elapsed: self.log.debug(
                f"Кабинет {os.path.basename(archive)}: свой распаковщик "
                f"работает уже {int(elapsed)} с."))
        if written:
            return True
        if not IS_WINDOWS:
            return False
        if not native_first:
            self._run([system_tool("expand"), "-F:*", archive, destination])
            if produced():
                return True
        self._run([system_tool("expand"), "-r", archive, destination])
        if produced():
            return True
        self._run([system_tool("extrac32"), "/Y", "/E", "/L", destination,
                   archive])
        if produced():
            return True
        sevenzip = find_7zip()
        if sevenzip:
            self._run([sevenzip, "x", "-y", f"-o{destination}", archive])
            if produced():
                return True
        return False

    def _package_archives(self, package: RedistPackage, arch: str) -> List[str]:
        """Пакеты этой версии, уже лежащие рядом с установщиком.

        Порядок важен: сначала архивы, в пути которых стоит нужный год
        (``_CommonRedist\\vcredist\\2012\\vcredist_x86.exe``), затем все
        остальные. Чужая версия пакета бесполезна: ``msvcp110.dll`` есть
        только в VC++ 2012, и распаковывать ради него VC++ 2013 незачем.
        """
        index = self._source_index()
        wanted_years = _PACKAGE_YEARS.get(package.key, ())
        other_years = {year for years in _PACKAGE_YEARS.values()
                       for year in years} - set(wanted_years)

        candidates: List[str] = []
        for name, paths in index.items():
            if package.key == "directx_jun2010":
                suitable = (name.startswith(("directx_", "dxsetup"))
                            or (name.endswith(".cab")
                                and re.match(r"(?:jun|feb|apr|aug|dec|mar|oct|nov)"
                                             r"\d{4}_", name)))
            elif package.key.startswith("vc"):
                if not name.startswith(("vcredist", "vc_redist")):
                    continue
                if arch == "x86" and "x64" in name:
                    continue
                if arch in ("x64", "arm64") and "x86" in name:
                    continue
                suitable = True
            else:
                suitable = False
            if suitable:
                candidates.extend(paths)

        def rank(path: str) -> Tuple[int, str]:
            lowered = path.lower()
            if not wanted_years:
                # У DirectX версии-года нет: «Jun2010» в имени файла — не
                # признак чужого пакета, и отбрасывать его нельзя.
                return (1, lowered)
            if any(year in lowered for year in wanted_years):
                return (0, lowered)
            if any(year in lowered for year in other_years):
                return (2, lowered)
            return (1, lowered)

        ranked = sorted(candidates, key=rank)
        return [path for path in ranked if rank(path)[0] < 2]

    def _from_package_payload(self, requirement: RuntimeRequirement,
                              work_dir: str) -> Tuple[str, str]:
        """Достаёт библиотеку из приложенного пакета (cab/exe/msi).

        Собственный распаковщик кабинетов работает на любой ОС, поэтому
        ступень больше не требует Windows целиком: внешние программы
        подключаются только там, где они есть.
        """
        package = requirement.package
        if package is None:
            return "", ""
        key = f"{package.key}:{requirement.arch}"
        if key in self._failed_packages:
            return "", ""
        destination = self._extracted.get(key)
        if destination is None:
            destination = os.path.join(work_dir, package.key,
                                       requirement.arch or "any")
            if key in self._extraction_tried:
                # Другая библиотека ИЗ ТОГО ЖЕ пакета уже запускала эту
                # распаковку раньше (у DirectX June 2010 в полном комплекте
                # их под сотню). Если тот вызов не уложился в свой лимит
                # времени (REQUIREMENT_TIMEOUT) и был брошен как «висящий» —
                # он мог всё ещё доделывать своё дело в фоне, но начинать
                # ЕЩЁ ОДНУ такую же попытку ради каждой следующей DLL нельзя:
                # именно так одна медленная/зависшая распаковка превращалась
                # в N таймаутов подряд. Смотрим, что уже успело появиться, и
                # не более того — как обычный «ещё не готово».
                candidate = _find_file(destination, requirement.dll)
                if candidate and self._arch_matches(candidate, requirement.arch):
                    return candidate, "пакет из комплекта установщика"
                return "", ""
            self._extraction_tried.add(key)
            extracted = False
            for archive in self._package_archives(package, requirement.arch):
                lower = archive.lower()
                if lower.endswith(".cab"):
                    os.makedirs(destination, exist_ok=True)
                    self._expand_one(archive, destination)
                    extracted = extracted or _has_files(destination)
                elif lower.endswith((".exe", ".msi")):
                    extracted = self._extract_installer(
                        archive, destination, requirement.dll) or extracted
                if os.path.isfile(os.path.join(destination, requirement.dll)):
                    break
            if not extracted:
                self._failed_packages.add(key)
                return "", ""
            self._extracted[key] = destination
            self._add_to_index(destination)
        candidate = _find_file(destination, requirement.dll)
        if not candidate:
            # Пакет уже распакован ради другой библиотеки, а кабинеты под
            # эту ещё не развёрнуты (например, второй d3dx9_* из того же
            # directx_Jun2010_redist.exe) — доворачиваем только их.
            self._expand_payloads(destination, requirement.dll)
            candidate = _find_file(destination, requirement.dll)
        if candidate and self._arch_matches(candidate, requirement.arch):
            return candidate, "пакет из комплекта установщика"
        return "", ""

    def _from_download(self, requirement: RuntimeRequirement,
                       portable_dir: str, work_dir: str) -> Tuple[str, str]:
        package = requirement.package
        if package is None or not self.allow_download:
            return "", ""
        url = package.downloads.get(requirement.arch) or package.downloads.get("any")
        if not url:
            return "", ""
        key = f"download:{package.key}:{requirement.arch}"
        if key in self._failed_packages:
            return "", ""
        destination = self._extracted.get(key)
        if destination is None:
            if key in self._extraction_tried:
                # Ту же самую распаковку скачанного пакета уже запускала
                # другая DLL из того же семейства (в полном комплекте их у
                # DirectX June 2010 под сотню) — если тот вызов был брошен
                # как «висящий», а не завершился, повторять его для каждой
                # следующей DLL нельзя: как раз это и раздувало ожидание.
                return "", ""
            self._extraction_tried.add(key)
            # Один и тот же файл нужен и распаковке, и тихой установке, и
            # папке Redist портатива: качаем его ровно один раз за сборку.
            archive = self._download_archive(package, requirement.arch,
                                             portable_dir)
            if not archive:
                self.log.warn(
                    f"Не удалось скачать {package.title}. Файл можно "
                    f"взять вручную: {package.page or url}")
                self._failed_packages.add(key)
                return "", ""
            destination = os.path.join(work_dir, "download", package.key,
                                       requirement.arch or "any")
            if not self._extract_installer(archive, destination,
                                           requirement.dll):
                self._failed_packages.add(key)
                self._extracted[key] = ""
                if requirement.proactive:
                    # Это библиотека «про запас» из полного комплекта:
                    # программа её не просила, поэтому предупреждать не о
                    # чем — строчка уходит в подробный журнал.
                    self.log.debug(
                        f"{package.title}: пакет скачан, но распаковать его "
                        f"не удалось; {requirement.dll} нужна только «про "
                        "запас» — пропускаю.")
                elif self.allow_install and IS_WINDOWS:
                    # Ничего включать не нужно: следующая ступень лестницы
                    # поставит пакет молча и заберёт файлы из системы.
                    self.log.info(
                        f"{package.title}: распаковать пакет не удалось — "
                        "ставлю его в тихом режиме и забираю файлы из "
                        "системы (окон не будет).")
                else:
                    self.log.warn(
                        f"{package.title}: пакет скачан, но распаковать его "
                        "автоматически не удалось. Включите «Тихая установка "
                        "пакетов», чтобы Portablizer взял файлы после "
                        f"установки пакета. Сам пакет сохранён в папке "
                        f"{REDIST_DIR_NAME} портатива "
                        f"(там же {SILENT_SCRIPT_NAME}).")
                return "", ""
            self._extracted[key] = destination
            self._add_to_index(destination)
        if not destination:
            return "", ""
        candidate = _find_file(destination, requirement.dll)
        if not candidate:
            # Скачанный пакет распакован ради другой библиотеки: кабинеты
            # под эту (и .msi с ней) ещё не развёрнуты.
            self._expand_payloads(destination, requirement.dll)
            candidate = _find_file(destination, requirement.dll)
        if candidate and self._arch_matches(candidate, requirement.arch):
            return candidate, "официальный пакет Microsoft"
        return "", ""

    # -- тихая установка пакета в систему ------------------------------------
    def _download_archive(self, package: RedistPackage, arch: str,
                          portable_dir: str) -> str:
        """Официальный пакет с сайта Microsoft — ровно одна загрузка за сборку.

        Файл остаётся в ``Redist`` портатива: он нужен и распаковке, и
        тихой установке, и целевому ПК (там интернета может не быть).
        """
        if not self.allow_download:
            return ""
        urls = package.urls(arch)
        if not urls:
            return ""
        key = f"archive:{package.key}:{arch}"
        cached = self._archives.get(key)
        if cached is not None:
            return cached
        if key in self._download_tried:
            # Другая DLL того же пакета уже начинала эту закачку. Если тот
            # вызов не уложился в свой лимит времени и был брошен как
            # «висящий» — сеть могла всё ещё тянуть файл в фоне, но качать
            # тот же ~100 МБ пакет ЗАНОВО ради каждой следующей DLL из
            # полного комплекта нельзя: одна медленная/оборвавшаяся закачка
            # не должна превращаться в десятки таких же закачек подряд.
            return ""
        self._download_tried.add(key)
        redist_dir = os.path.join(portable_dir, REDIST_DIR_NAME)
        filename = urls[0].rsplit("/", 1)[-1] or f"{package.key}.exe"
        if not filename.lower().endswith((".exe", ".msi", ".cab", ".zip")):
            filename = f"{package.key}_{arch or 'any'}.exe"
        archive = os.path.join(redist_dir, filename)
        try:
            os.makedirs(redist_dir, exist_ok=True)
        except OSError:
            return ""
        if os.path.isfile(archive):
            problem = package_file_problem(archive)
            if not problem:
                self._archives[key] = archive
                return archive
            # В папке лежит мусор от прошлой сборки — он только мешает.
            self.log.debug(f"{os.path.basename(archive)}: {problem} — качаю "
                           "заново.")
            try:
                os.remove(archive)
            except OSError:
                self._archives[key] = ""
                return ""
        # Ссылки перебираются по очереди: раздачи Microsoft периодически
        # переезжают, и «скачано» ещё не значит «скачан пакет».
        for index, url in enumerate(urls):
            size_hint = (f", около {format_size(package.size_hint)}"
                         if package.size_hint else "")
            self.log.info(
                f"Скачиваю {package.title}{size_hint} ({url})… "
                "Ход загрузки виден в процентах ниже.")
            if not self._fetch(url, archive, package.title):
                self.log.debug(f"Загрузка не удалась: {url}")
                self._report(None, f"{package.title}: загрузка не удалась", -1)
                continue
            self._report(None, f"{package.title}: проверяю файл", 100)
            problem = package_file_problem(archive)
            if not problem:
                self._archives[key] = archive
                return archive
            self.log.warn(
                f"{package.title}: файл по ссылке не похож на пакет — "
                f"{problem}."
                + (" Пробую запасную ссылку." if index + 1 < len(urls) else ""))
            try:
                os.remove(archive)
            except OSError:
                break
        self.log.warn(
            f"{package.title}: скачать пакет не удалось ни по одной из "
            f"{len(urls)} ссылок. Его можно положить вручную в папку "
            f"{REDIST_DIR_NAME} портатива: {package.page or urls[0]}")
        # Второй раз за сборку в сеть за тем же файлом не ходим.
        self._archives[key] = ""
        return ""

    def _archive_for_package(self, package: RedistPackage, arch: str,
                             portable_dir: str) -> str:
        """Установщик пакета: из комплекта дистрибутива или скачанный."""
        for archive in self._package_archives(package, arch):
            if archive.lower().endswith((".exe", ".msi")) \
                    and is_redist_installer(archive):
                return archive
        return self._download_archive(package, arch, portable_dir)

    def _from_silent_install(self, requirement: RuntimeRequirement,
                             portable_dir: str) -> Tuple[str, str]:
        """Последняя ступень: ставим пакет в систему **молча** и берём файлы.

        До этой ступени доходят только библиотеки, которых нет ни в
        комплекте установщика, ни на этом ПК, ни в WinSxS, и вытащить их из
        пакета распаковкой не удалось. Установка идёт без единого окна: ни
        мастера, ни «OK». После неё файл лежит в System32/SysWOW64, откуда
        обычная ступень ``_from_system`` и заберёт его в портатив.
        """
        package = requirement.package
        if package is None or not self.allow_install or not IS_WINDOWS:
            return "", ""
        key = f"install:{package.key}:{requirement.arch}"
        if key in self._failed_packages:
            return "", ""
        if key not in self._install_tried:
            self._install_tried.add(key)
            archive = self._archive_for_package(package, requirement.arch,
                                                portable_dir)
            if not archive:
                self._failed_packages.add(key)
                return "", ""
            self.log.info(
                f"{package.title}: файлов нет нигде — ставлю пакет в тихом "
                "режиме (окон не будет).")
            outcome = run_silent_install(
                archive, runner=self._install_run, title=package.title,
                package_key=package.key, arch=requirement.arch, log=self.log)
            self.installs.append(outcome)
            if outcome.ok:
                self.log.ok(f"  • {outcome.describe()}")
            else:
                self.log.warn(
                    f"  • {outcome.describe()} (код {outcome.code}). "
                    f"Файл оставлен: {os.path.basename(archive)}")
                self._failed_packages.add(key)
                return "", ""
        elif key in self._failed_packages:
            return "", ""
        path, _source = self._from_system(requirement)
        if path:
            return path, "пакет установлен в тихом режиме"
        path, _source = self._from_sxs(requirement)
        if path:
            return path, "пакет установлен в тихом режиме (WinSxS)"
        return "", ""

    # -- размещение в портативе ----------------------------------------------
    @staticmethod
    def _target_dirs(requirement: RuntimeRequirement, app_dir: str) -> List[str]:
        """Папки, куда положить библиотеку: рядом с каждым импортёром."""
        directories: List[str] = []
        for rel in requirement.importers:
            directory = os.path.dirname(os.path.join(app_dir, rel.replace("/", os.sep)))
            directory = directory or app_dir
            if directory not in directories:
                directories.append(directory)
        return directories or [app_dir]

    def _deploy(self, requirement: RuntimeRequirement, source: str,
                app_dir: str) -> List[str]:
        copied: List[str] = []
        for directory in self._target_dirs(requirement, app_dir):
            destination = os.path.join(directory, requirement.dll)
            if os.path.isfile(destination):
                copied.append(os.path.relpath(destination, app_dir)
                              .replace("\\", "/"))
                continue
            try:
                os.makedirs(directory, exist_ok=True)
                shutil.copy2(source, destination)
            except OSError as exc:
                self.log.warn(
                    f"Не удалось положить {requirement.dll} рядом с программой: {exc}")
                continue
            copied.append(os.path.relpath(destination, app_dir).replace("\\", "/"))
        return copied

    def _write_sxs_manifest(self, requirement: RuntimeRequirement,
                            source: str, app_dir: str) -> None:
        """Создаёт private-манифест сборки для VC++ 2005/2008.

        Без него библиотека рядом с exe просто игнорируется: программа с
        манифестом ищет сборку в WinSxS и падает с «не удалось запустить
        приложение, поскольку его параллельная конфигурация неправильна»
        (ошибка 14001, ERROR_SXS_CANT_GEN_ACTCTX).

        Два правила, без которых манифест недействителен и приводит ровно к
        той же ошибке:

        * в ``<file name=.../>`` перечисляются только библиотеки ЭТОЙ сборки —
          ``Microsoft.VC80.CRT.manifest``, в котором записан mfc80.dll,
          Windows отвергает целиком (MFC/ATL/OpenMP — отдельные сборки с
          собственными манифестами);
        * ``publicKeyToken`` обязан быть корректным — у всех сборок Microsoft
          он один и известен, поэтому пустым его не оставляем никогда.
        """
        package = requirement.package
        if package is None or not package.sxs:
            return
        assembly = sxs_assembly_for(requirement.dll, package)
        folder_identity = _identity_from_folder(os.path.basename(
            os.path.dirname(source)))
        for directory in self._target_dirs(requirement, app_dir):
            identity = dict(folder_identity)
            for rel in requirement.importers:
                importer = os.path.join(app_dir, rel.replace("/", os.sep))
                if os.path.dirname(importer) != directory:
                    continue
                # Версия из встроенного манифеста программы важнее всего:
                # private-сборка связывается с программой по ПОЛНОМУ имени,
                # включая версию, и никакая publisher-политика WinSxS тогда
                # не применяется.
                wanted = manifest_identity(read_pe_manifest(importer), assembly)
                if wanted.get("version"):
                    identity.update(wanted)
                    break
            if not identity.get("publicKeyToken"):
                identity["publicKeyToken"] = _SXS_PUBLIC_KEY_TOKEN
            if not identity.get("version"):
                canonical = _SXS_DEFAULT_VERSIONS.get(package.key, "")
                if canonical:
                    self.log.warn(
                        f"{assembly}: версию не удалось взять ни из манифеста "
                        f"программы, ни из имени папки WinSxS — в private-"
                        f"манифест записана каноническая {canonical}. Если "
                        f"Windows сообщит об ошибке 14001 (side-by-side), "
                        f"установите пакет из папки {REDIST_DIR_NAME} — он "
                        "поставит настоящую сборку в систему."
                    )
                    identity["version"] = canonical
            if not identity.get("version"):
                self.log.warn(
                    f"Не удалось определить версию сборки {assembly} — "
                    "private-манифест не создан. Программа на чистом ПК "
                    "потребует установки официального пакета."
                )
                continue
            files = sorted(
                name for name in os.listdir(directory)
                if name.lower().endswith(".dll")
                and package.matches(name.lower())
                and sxs_assembly_for(name, package) == assembly
            )
            if not files:
                continue
            manifest_path = os.path.join(directory, f"{assembly}.manifest")
            body = "\n".join(f'    <file name="{name}"/>' for name in files)
            text = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" '
                'manifestVersion="1.0">\n'
                '    <noInheritable/>\n'
                f'    <assemblyIdentity type="{identity.get("type", "win32")}" '
                f'name="{assembly}" version="{identity["version"]}" '
                f'processorArchitecture='
                f'"{identity.get("processorArchitecture", requirement.arch or "x86")}" '
                f'publicKeyToken="{identity.get("publicKeyToken", _SXS_PUBLIC_KEY_TOKEN)}"/>\n'
                f'{body}\n'
                '</assembly>\n'
            )
            try:
                with open(manifest_path, "w", encoding="utf-8",
                          newline="\r\n") as fh:
                    fh.write(text)
            except OSError as exc:
                self.log.warn(f"Не удалось создать {assembly}.manifest: {exc}")

    # -- основной проход ------------------------------------------------------
    def _stock_requirements(self, scan: RuntimeScan,
                            anchors: Sequence[str],
                            ) -> List[RuntimeRequirement]:
        """Библиотеки полного комплекта, которых нет среди обнаруженных.

        Обнаруженное таблицей импорта всегда точнее: у него известны
        импортёры и разрядность, поэтому дубликаты из комплекта убираются.
        """
        archs = list(scan.archs) or ([scan.arch] if scan.arch else ["x86"])
        known = {(item.dll, item.arch) for item in scan.requirements}
        any_arch = {item.dll for item in scan.requirements if not item.arch}
        out: List[RuntimeRequirement] = []
        for requirement in full_kit_requirements(archs, anchors):
            key = (requirement.dll, requirement.arch)
            if key in known or requirement.dll in any_arch:
                continue
            known.add(key)
            out.append(requirement)
        return out

    def provision(self, scan: RuntimeScan, app_dir: str, portable_dir: str,
                  app_name: str = "", *, full_kit: bool = False,
                  anchors: Sequence[str] = (),
                  ) -> ProvisionReport:
        """Доставляет библиотеки в портатив.

        ``full_kit=True`` добавляет к обнаруженным требованиям полный комплект
        всех известных библиотек «про запас»: они ложатся рядом с главными exe
        (``anchors`` — их app-относительные пути), а неудача их доставки
        ошибкой не считается — программа их, скорее всего, вовсе не просит.
        """
        report = ProvisionReport(app_name=app_name, arch=scan.arch,
                                 dotnet=scan.dotnet, full_kit=full_kit)
        work_dir = os.path.join(portable_dir, "_redist_cache")

        requirements = list(scan.requirements)
        if full_kit:
            requirements += self._stock_requirements(scan, anchors)

        total = max(1, len(requirements))
        for index, requirement in enumerate(requirements):
            if self._cancelled():
                # Пользователь нажал «Отмена»: доносить остаток компонентов
                # незачем, дальше сборку всё равно прервут.
                self.log.warn("Сборка отменена — доставка компонентов "
                              "остановлена.")
                break
            # Этап длинный (скачивание и распаковка пакетов Microsoft идут
            # минутами), поэтому доля считается по числу разобранных
            # библиотек — полоса движется, а не замирает на одном проценте.
            self._report(index / total,
                         f"Компоненты: {requirement.dll} "
                         f"({index + 1} из {total})",
                         int(index * 100 / total))
            if requirement.proactive:
                # Рядом с целевыми exe библиотека уже лежит (принёс
                # установщик или предыдущая сборка) — запас не нужен.
                if any(os.path.isfile(os.path.join(
                        directory, requirement.dll))
                        for directory in self._target_dirs(requirement, app_dir)):
                    continue
            if requirement.status == "bundled":
                # Собственные dll программы в отчёте не нужны: они лежат
                # рядом с exe и переезжают вместе с папкой.
                if requirement.package is None:
                    report.own_files += 1
                else:
                    self._place_next_to_importers(requirement, app_dir)
                    report.bundled.append(requirement)
                continue
            if requirement.status == "system":
                report.system.append(requirement)
                continue
            if requirement.package is None:
                report.unknown.append(requirement)
                continue

            def _resolve(requirement=requirement) -> Tuple[str, str]:
                path, source = self._from_sources(requirement)
                if not path:
                    path, source = self._from_system(requirement)
                if not path:
                    path, source = self._from_sxs(requirement)
                if not path:
                    path, source = self._from_package_payload(requirement, work_dir)
                if not path:
                    path, source = self._from_download(requirement, portable_dir,
                                                       work_dir)
                if not path and not requirement.proactive:
                    # Запас «про запас» ради установки пакета в систему не
                    # ставим: молча менять чужой ПК можно только ради того,
                    # без чего программа действительно не запустится.
                    path, source = self._from_silent_install(requirement,
                                                             portable_dir)
                return path, source

            def _on_requirement_tick(elapsed: float,
                                     requirement=requirement) -> None:
                # Последний рубеж обороны от «висит на N%»: даже если поиск
                # застрял на неизвестной нам ступени, полоса и журнал
                # продолжают сообщать, что сборка жива, а не молчат.
                self._report(
                    index / total,
                    f"Компоненты: {requirement.dll} ({index + 1} из {total}) "
                    f"— идёт уже {int(elapsed)} с, это не зависание", -1)

            path, source = _bounded_call(
                _resolve, timeout=REQUIREMENT_TIMEOUT, default=("", ""),
                on_tick=_on_requirement_tick)
            if not path:
                requirement.status = "missing"
                (report.stock_missing if requirement.proactive
                 else report.missing).append(requirement)
                continue

            copied = self._deploy(requirement, path, app_dir)
            if not copied:
                requirement.status = "missing"
                (report.stock_missing if requirement.proactive
                 else report.missing).append(requirement)
                continue
            if requirement.package is not None and requirement.package.sxs:
                # VC++ 2005/2008 без private-манифеста рядом с exe просто
                # игнорируются — и неважно, откуда взялся файл: из WinSxS,
                # из System32 или из распакованного vcredist.
                self._write_sxs_manifest(requirement, path, app_dir)
            requirement.status = "provided"
            requirement.source = source
            requirement.targets = copied
            (report.stock if requirement.proactive
             else report.provided).append(requirement)

        self._report(0.95, "Компоненты: базовые библиотеки UCRT", 95)
        self._provide_ucrt_base(report, app_dir, portable_dir, work_dir)
        report.installed = list(self.installs)
        self._report(0.98, "Компоненты: пакеты в папку Redist", 98)
        self._stage_installers(report, portable_dir)

        redist_dir = os.path.join(portable_dir, REDIST_DIR_NAME)
        if os.path.isdir(redist_dir):
            report.packages = sorted(
                name for name in os.listdir(redist_dir)
                if os.path.isfile(os.path.join(redist_dir, name))
                and name != SILENT_SCRIPT_NAME
            )
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)

        self._report(1.0, "Компоненты: готово", 100)
        if scan.dotnet:
            report.notes.append(
                "Программа собрана для .NET Framework. Сам .NET перенести в "
                "портатив нельзя: в Windows 10/11 он уже есть, а на Windows 7 "
                "может потребоваться установка .NET Framework 4.8 — "
                "https://dotnet.microsoft.com/download/dotnet-framework")
        return report


    def _stage_installers(self, report: ProvisionReport,
                          portable_dir: str) -> None:
        """Кладёт в ``Redist`` портатива установщики пакетов-страховки.

        Две ситуации покрываются одним механизмом:

        * библиотеки принести не удалось (``report.missing``) — значит, на
          целевом ПК их может не быть;
        * библиотеки VC++ 2005/2008 принести удалось, но работают они рядом с
          программой только при исправном private-манифесте сборки — самом
          хрупком элементе портатива: его версия/идентичность обязаны
          совпадать с тем, что запрашивает программа, иначе Windows отвечает
          ошибкой 14001 («параллельная конфигурация неправильна»). Официальный
          установщик рядом — гарантированный путь починки: он ставит настоящую
          сборку в WinSxS целевого ПК.

        Установщик рядом с портативом позволяет лончеру поставить пакет
        **молча**, одним запросом UAC, вместо череды окон с «OK» — или
        обойтись вовсе без интернета, если пакет уже скачан.
        """
        repair: List[RuntimeRequirement] = list(report.missing)
        repair += [
            item for item in list(report.provided) + list(report.stock)
            if item.package is not None and item.package.sxs
        ]
        if not repair:
            return
        redist_dir = os.path.join(portable_dir, REDIST_DIR_NAME)
        staged: Dict[str, Dict[str, str]] = {}
        for requirement in repair:
            package = requirement.package
            if package is None:
                continue
            key = f"{package.key}:{requirement.arch}"
            if key in staged:
                staged[key]["dlls"] = ",".join(sorted(set(
                    staged[key]["dlls"].split(",") + [requirement.dll])))
                continue
            archive = self._archive_for_package(package, requirement.arch,
                                                portable_dir)
            if not archive:
                continue
            try:
                os.makedirs(redist_dir, exist_ok=True)
                if os.path.dirname(os.path.abspath(archive)) != \
                        os.path.abspath(redist_dir):
                    destination = os.path.join(
                        redist_dir, os.path.basename(archive))
                    if not os.path.isfile(destination):
                        shutil.copy2(archive, destination)
                    archive = destination
            except OSError as exc:
                self.log.warn(
                    f"Не удалось положить {os.path.basename(archive)} в "
                    f"{REDIST_DIR_NAME}: {exc}")
                continue
            kind = installer_kind(archive)
            first = (silent_commands(archive, kind) or [[archive]])[0]
            entry = {
                "file": f"{REDIST_DIR_NAME}/{os.path.basename(archive)}",
                "title": package.plain_title(),
                "arch": requirement.arch,
                "dlls": requirement.dll,
                "kind": kind,
                # Ключи тихого режима для exe; у msi/msu команду собирает
                # тот, кто запускает (msiexec/wusa).
                "args": " ".join(first[1:]) if kind not in ("msi", "msu") else "",
            }
            staged[key] = entry
        report.installers = list(staged.values())
        if report.installers:
            write_silent_install_script(portable_dir, report.installers)
            self.log.ok(
                f"В папку {REDIST_DIR_NAME} положены установщики "
                f"({len(report.installers)} шт.) и {SILENT_SCRIPT_NAME}: "
                "на целевом ПК недостающее ставится молча, без окон.")

    def _place_next_to_importers(self, requirement: RuntimeRequirement,
                                 app_dir: str) -> None:
        """Дублирует уже принесённую установщиком библиотеку к её импортёрам.

        Установщики нередко кладут ``msvcr100.dll`` в служебную подпапку
        (``App\\redist``), откуда загрузчик Windows её не увидит: он смотрит
        в каталог самого exe, системные папки и PATH. Копия рядом с
        программой стоит копейки и убирает целый класс отказов.
        """
        source = os.path.join(app_dir, requirement.source.replace("/", os.sep))
        if not requirement.source or not os.path.isfile(source):
            return
        copied = self._deploy(requirement, source, app_dir)
        if copied:
            requirement.targets = copied

    def _provide_ucrt_base(self, report: ProvisionReport, app_dir: str,
                           portable_dir: str, work_dir: str) -> None:
        """Докладывает ``ucrtbase.dll`` к принесённым заглушкам ``api-ms-win-crt``.

        Файлы ``api-ms-win-crt-*.dll`` — это только переадресация на
        ``ucrtbase.dll``. В Windows 10/11 он есть всегда, а на Windows 7/8.1
        без обновления UCRT — нет, и программа падает уже после того, как
        заглушки успешно загрузились.
        """
        stubs = [item for item in report.provided + report.stock
                 if item.dll.startswith("api-ms-win-crt-")]
        if not stubs:
            return
        if any(item.dll == "ucrtbase.dll"
               for item in report.provided + report.bundled + report.stock):
            return
        sample = stubs[0]
        companion = RuntimeRequirement(
            dll="ucrtbase.dll", arch=sample.arch, package=find_package("ucrtbase.dll"),
            importers=list(sample.importers), proactive=sample.proactive)
        path, source = self._from_sources(companion)
        if not path:
            path, source = self._from_system(companion)
        if not path:
            path, source = self._from_download(companion, portable_dir, work_dir)
        if not path:
            return
        copied = self._deploy(companion, path, app_dir)
        if copied:
            companion.status = "provided"
            companion.source = source
            companion.targets = copied
            (report.stock if companion.proactive
             else report.provided).append(companion)


def _dir_entries(directory: str) -> set:
    """Имена файлов в папке (без обхода вложенных) — для «что появилось».

    Распаковка часто идёт в папку, где файлы уже есть, поэтому «получилось
    ли» приходится определять по разнице, а не по наличию файлов вообще.
    """
    try:
        with os.scandir(directory) as entries:
            return {entry.name for entry in entries}
    except OSError:
        return set()


def _has_files(directory: str) -> bool:
    for _root, _dirs, files in os.walk(directory):
        if files:
            return True
    return False


def _looks_like_pe(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def _find_file(directory: str, name: str, allow_mangled: bool = True) -> str:
    """Ищет файл в дереве — в том числе под «складским» именем из MSI.

    Внутри ``vc_red.cab`` (VC++ 2005/2008/2010) библиотеки лежат не под
    своими именами, а под именами таблицы File установщика:
    ``FL_mfc80_dll_01_8.0.50727.762_x-ww_1b4fc1e7``. Развёрнутый кабинет
    поэтому выглядит «пустым» для поиска по ``mfc80.dll`` — отсюда и
    появлялось «не удалось найти файлы для: mfc80.dll» при полностью
    скачанном и распакованном пакете.
    """
    target = name.lower()
    stem, extension = os.path.splitext(target)
    extension = extension.lstrip(".")
    pattern = None
    if allow_mangled and stem and extension:
        pattern = re.compile(
            rf"(?:^|[^a-z0-9]){re.escape(stem)}[_.]{re.escape(extension)}"
            rf"(?:[^a-z0-9]|$)", re.IGNORECASE)
    fallback = ""
    for root, _dirs, files in os.walk(directory):
        for candidate in files:
            lowered = candidate.lower()
            path = os.path.join(root, candidate)
            if lowered == target:
                return path
            if allow_mangled and not fallback and _looks_like_pe(path):
                if pattern is not None and pattern.search(lowered):
                    fallback = path
                elif f"{stem}_{extension}" in lowered or f"{stem}.{extension}" in lowered:
                    fallback = path
    return fallback


def _folder_version(name: str) -> Tuple[int, ...]:
    """Версия из имени папки WinSxS (…_9.0.30729.9635_none_…)."""
    match = re.search(r"_(\d+(?:\.\d+){1,3})_", name)
    if not match:
        return (0,)
    return tuple(int(part) for part in match.group(1).split("."))


def _identity_from_folder(name: str) -> Dict[str, str]:
    """Идентичность сборки, восстановленная по имени папки WinSxS."""
    parts = name.split("_")
    if len(parts) < 4:
        return {}
    identity = {
        "type": "win32",
        "processorArchitecture": parts[0],
        "publicKeyToken": parts[2],
    }
    version = re.search(r"\d+(?:\.\d+){1,3}", parts[3])
    if version:
        identity["version"] = version.group(0)
    return identity


# =============================================================================
#  5. Отчёт и предстартовая проверка
# =============================================================================

def launcher_requirements(report: ProvisionReport, limit: int = 24
                          ) -> List[Dict[str, str]]:
    """Список для предстартовой проверки лончера.

    Сюда попадают:

    1. **Недостающее** — то, что принести в портатив не удалось.
    2. **Зонды работоспособности** доставленных сборок VC++ 2005/2008
       (``sxs``, ``manifest``, ``sxs_family``): библиотека рядом с программой
       помогает, только когда рядом же лежит её private-манифест, а иначе —
       когда сборка стоит в WinSxS целевого ПК. Ни одно из условий обычной
       проверкой «есть ли файл в System32» не выражается, поэтому зонд несёт
       с собой имя манифеста и префикс папки сборки. Если на целевом ПК не
       сработает ни одно условие, лончер молча ставит пакет из ``Redist`` —
       вместо ошибки 14001 при старте программы.
    """
    out: List[Dict[str, str]] = []
    by_assembly: Dict[Tuple[str, str], Dict[str, str]] = {}
    plain_seen = set()
    # Недостающее идёт первым: оно обязательное. Доставленные сборки VC++
    # 2005/2008 — следом, как зонды работоспособности: их библиотека в папке
    # программы работает только вместе со своим private-манифестом, и это
    # надо проверить на целевом ПК.
    for requirement in (list(report.missing)
                        + list(report.provided) + list(report.stock)):
        package = requirement.package
        if package is not None and package.sxs:
            # Одна сборка — один зонд: её файлы приезжают только вместе, и
            # проверка по ведущей библиотеке отвечает за всех.
            assembly = sxs_assembly_for(requirement.dll, package)
            key = (assembly, requirement.arch)
            entry = by_assembly.get(key)
            if entry is None:
                if len(out) >= limit:
                    continue
                entry = _requirement_entry(requirement)
                by_assembly[key] = entry
                out.append(entry)
            else:
                dlls = entry["dlls"].split(",")
                if requirement.dll not in dlls:
                    entry["dlls"] = ",".join(sorted(dlls + [requirement.dll]))
            continue
        # Остальное проверяется построчно по имени файла — как раньше.
        if requirement.status != "missing" or requirement.dll in plain_seen:
            continue
        if len(out) >= limit:
            break
        plain_seen.add(requirement.dll)
        out.append(_requirement_entry(requirement))
    return out


def _requirement_entry(requirement: RuntimeRequirement) -> Dict[str, str]:
    """Запись ``runtime_requirements`` для лончера (с SxS-реквизитами)."""
    entry: Dict[str, str] = {
        "dll": requirement.dll,
        "title": requirement.plain_title,
        "url": requirement.url,
        "arch": requirement.arch,
    }
    package = requirement.package
    if package is not None and package.sxs:
        assembly = sxs_assembly_for(requirement.dll, package)
        entry["sxs"] = assembly
        entry["manifest"] = f"{assembly}.manifest"
        entry["sxs_family"] = sxs_family_prefix(assembly, requirement.arch)
        entry["dlls"] = requirement.dll
    return entry


def launcher_installers(report: ProvisionReport, limit: int = 12
                        ) -> List[Dict[str, str]]:
    """Установщики из ``Redist``, которые лончер вправе запустить молча."""
    out: List[Dict[str, str]] = []
    for entry in report.installers[:limit]:
        if not entry.get("file"):
            continue
        out.append({
            "file": str(entry.get("file", "")),
            "title": str(entry.get("title", "")),
            "kind": str(entry.get("kind", "")),
            "args": str(entry.get("args", "")),
            "dlls": str(entry.get("dlls", "")),
            "arch": str(entry.get("arch", "")),
        })
    return out


def _format_group(title: str, items: Sequence[RuntimeRequirement],
                  show_source: bool = False,
                  show_importers: bool = True) -> List[str]:
    if not items:
        return []
    lines = [title, "-" * len(title)]
    by_package: Dict[str, List[RuntimeRequirement]] = {}
    for item in items:
        by_package.setdefault(item.title, []).append(item)
    for package_title, group in sorted(by_package.items()):
        lines.append(f"  {package_title}")
        for item in sorted(group, key=lambda r: (r.dll, r.arch)):
            arch = f" [{item.arch}]" if item.arch else ""
            suffix = f" — {item.source}" if show_source and item.source else ""
            lines.append(f"    • {item.dll}{arch}{suffix}")
            if item.importers and show_importers:
                importers = ", ".join(item.importers[:3])
                lines.append(f"        нужна файлам: {importers}")
        url = group[0].url
        if url:
            lines.append(f"      пакет: {url}")
    lines.append("")
    return lines


def render_report(report: ProvisionReport) -> str:
    """Человекочитаемый ``redistributables.txt`` для корня портатива."""
    header = f"{report.app_name or 'Портативная программа'} — системные компоненты"
    lines = [
        header,
        "=" * len(header),
        "",
        "Здесь перечислено всё, что программа просит у Windows: библиотеки "
        "Visual C++,",
        "компоненты DirectX и прочие распространяемые пакеты. Список получен "
        "из таблиц",
        "импорта самих exe/dll, а не угадан по именам файлов.",
        "",
    ]
    if report.arch:
        lines.append(f"Разрядность программы: {report.arch}")
        lines.append("")

    if report.full_kit and (report.stock or report.stock_missing):
        lines += [
            "Включён полный комплект: рядом с программой оказались все "
            "известные",
            "версии распространяемых библиотек, а не только найденные в "
            "таблицах",
            "импорта. Это страхует плагины, моды и библиотеки, которые "
            "грузятся",
            "динамически (LoadLibrary по имени, собранному строкой), — окно",
            "«отсутствует dll» в этом случае не возникает в принципе.",
            "",
        ]

    lines += _format_group(
        "Принесено в портатив (на целевом ПК ставить ничего не нужно)",
        report.provided, show_source=True)
    lines += _format_group(
        "Принесено про запас — полный комплект всех redistributables",
        report.stock, show_source=True, show_importers=False)
    lines += _format_group(
        "Входит в состав программы (принёс сам установщик)", report.bundled)
    lines += _format_group(
        "ТРЕБУЕТСЯ НА ЦЕЛЕВОМ ПК — файлы найти не удалось", report.missing)
    lines += _format_group(
        "Полный комплект: найти не удалось (программе, скорее всего, "
        "не нужно)",
        report.stock_missing, show_importers=False)
    lines += _format_group(
        "Не опознано (проверьте вручную, если программа не запускается)",
        report.unknown)

    if report.stock_missing:
        lines += [
            "  Это НЕ обязательные файлы: полный комплект пытается принести "
            "всё",
            "  подряд, а нашлись только те, что есть на компьютере сборки. "
            "Если",
            "  программа всё-таки попросит один из них, включите «Скачивать",
            "  недостающие пакеты» и пересоберите портатив.",
            "",
        ]

    if report.installed:
        lines.append("Установлено в систему при сборке (в тихом режиме)")
        lines.append("-" * 48)
        lines.append("  Этих файлов не было ни в комплекте установщика, ни на "
                     "компьютере сборки,")
        lines.append("  поэтому пакет был поставлен молча — без мастеров и "
                     "окон с «OK» — и файлы")
        lines.append("  забраны из системы уже после установки.")
        for item in report.installed:
            lines.append(f"  • {item.describe()}")
        lines.append("")

    if report.packages:
        lines.append(f"Установщики пакетов в папке {REDIST_DIR_NAME}")
        lines.append("-" * 40)
        lines.append("  Библиотеки из них принести не удалось, но сами пакеты "
                     "уже лежат рядом:")
        lines.append(f"  запустите {REDIST_DIR_NAME}\\{SILENT_SCRIPT_NAME} — "
                     "он поставит всё молча, за один")
        lines.append("  запрос прав администратора, и интернет не "
                     "понадобится. Лончер делает это")
        lines.append("  сам, когда видит, что библиотеки на этом ПК нет.")
        for name in report.packages:
            lines.append(f"  • {REDIST_DIR_NAME}\\{name}")
        lines.append("")

    if report.missing:
        lines += [
            "Что делать с недостающим",
            "------------------------",
            "  1. Проще всего собрать портатив на ПК, где эти пакеты уже "
            "установлены:",
            "     Portablizer возьмёт файлы оттуда автоматически.",
            "  2. Либо включите в параметрах «Скачивать недостающие пакеты» — "
            "нужные",
            "     файлы будут загружены с сайта Microsoft при сборке.",
            "  3. Либо установите пакет по ссылке выше на том компьютере, где "
            "программа",
            "     будет запускаться. Это единственный случай, когда портативу "
            "нужна установка.",
            "",
        ]
    if report.notes:
        lines.append("Примечания")
        lines.append("----------")
        for note in report.notes:
            lines.append(f"  • {note}")
        lines.append("")

    lines.append(
        f"Библиотеки самой Windows в список не включены ({len(report.system)} шт.), "
        f"как и собственные файлы программы ({report.own_files} шт.).")
    return "\n".join(lines) + "\n"
