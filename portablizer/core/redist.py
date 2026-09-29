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
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform.startswith("win")

#: Сколько файлов максимум разбираем в App (защита от гигантских раскладок).
MAX_SCANNED_FILES = 4000

#: Сколько импортёров показываем в отчёте по одной библиотеке.
MAX_IMPORTERS_SHOWN = 6

#: Имя отчёта в корне портатива.
REPORT_NAME = "redistributables.txt"

#: Папка, куда складываются скачанные установщики пакетов (offline-запас).
REDIST_DIR_NAME = "Redist"


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
        downloads={},
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


def _download_file(url: str, destination: str, timeout: int = 120) -> bool:
    """Скачивает файл во временное имя и переименовывает его по готовности."""
    import urllib.request

    temporary = destination + ".part"
    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "Portablizer"})
        with urllib.request.urlopen(request, timeout=timeout) as response, \
                open(temporary, "wb") as fh:
            shutil.copyfileobj(response, fh, 1024 * 256)
        os.replace(temporary, destination)
        return True
    except Exception:  # noqa: BLE001 — сеть не должна ронять сборку
        try:
            if os.path.exists(temporary):
                os.remove(temporary)
        except OSError:
            pass
        return False


def _run_quiet(args: Sequence[str], timeout: int = 600) -> int:
    """Запускает внешний инструмент (expand/msiexec) без окна консоли."""
    if not IS_WINDOWS:
        return 1
    flags = 0x08000000  # CREATE_NO_WINDOW
    try:
        completed = subprocess.run(
            list(args), timeout=timeout, creationflags=flags,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return completed.returncode
    except (OSError, subprocess.SubprocessError):
        return 1


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
                 downloader: Optional[Callable[[str, str], bool]] = None,
                 runner: Optional[Callable[[Sequence[str]], int]] = None
                 ) -> None:
        self.log = log
        self.source_dirs = [d for d in source_dirs if d and os.path.isdir(d)]
        self._system_dirs = list(system_dirs) if system_dirs is not None else None
        self._sxs_dir = sxs_dir if sxs_dir is not None else winsxs_dir()
        self.allow_download = allow_download
        self._download = downloader or _download_file
        self._run = runner or _run_quiet
        self._index: Optional[Dict[str, List[str]]] = None
        self._extracted: Dict[str, str] = {}
        self._failed_packages: set = set()

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
        """Распаковывает пакет Microsoft, не устанавливая его в систему."""
        if not IS_WINDOWS or not os.path.isfile(archive):
            return False
        os.makedirs(destination, exist_ok=True)
        attempts: List[List[str]] = [
            # IExpress: DirectX redist и старые самораспаковывающиеся пакеты.
            [archive, "/Q", "/C", f"/T:{destination}"],
            # vcredist 2005/2008/2010.
            [archive, "/q", f"/x:{destination}"],
            # WiX Burn: vcredist 2012 и новее.
            [archive, "/quiet", "/layout", destination],
        ]
        for attempt in attempts:
            self._run(attempt)
            if _has_files(destination):
                break
        if not _has_files(destination):
            return False
        self._expand_payloads(destination, wanted)
        return True

    def _expand_payloads(self, directory: str, wanted: str = "") -> None:
        """Раскрывает вложенные ``.cab`` и ``.msi`` внутри распакованного пакета.

        В DirectX-редисте около сотни кабинетов, и разворачивать их все ради
        одной ``d3dx9_39.dll`` — минуты впустую. Имя нужной библиотеки входит
        в имя кабинета (``Jun2010_d3dx9_39_x86.cab``), поэтому сначала
        пробуем только подходящие, и лишь если не вышло — все подряд.
        """
        stem = os.path.splitext(wanted)[0].lower() if wanted else ""
        cabinets: List[str] = []
        installers: List[str] = []
        for current, _dirs, files in os.walk(directory):
            for name in files:
                lower = name.lower()
                if lower.endswith(".cab"):
                    cabinets.append(os.path.join(current, name))
                elif lower.endswith(".msi"):
                    installers.append(os.path.join(current, name))

        targeted = [path for path in cabinets
                    if stem and stem in os.path.basename(path).lower()]
        for path in targeted:
            self._run(["expand", "-R", "-F:*", path, os.path.dirname(path)])
        if stem and targeted and _find_file(directory, wanted):
            return

        for path in cabinets:
            if path in targeted:
                continue
            self._run(["expand", "-R", "-F:*", path, os.path.dirname(path)])
            if stem and _find_file(directory, wanted):
                break
        for path in installers:
            target = os.path.join(os.path.dirname(path), "_msi")
            os.makedirs(target, exist_ok=True)
            self._run(["msiexec", "/a", path, "/qn", f"TARGETDIR={target}"])
            if stem and _find_file(directory, wanted):
                break

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
        """Достаёт библиотеку из приложенного пакета (cab/exe/msi)."""
        package = requirement.package
        if package is None or not IS_WINDOWS:
            return "", ""
        key = f"{package.key}:{requirement.arch}"
        if key in self._failed_packages:
            return "", ""
        destination = self._extracted.get(key)
        if destination is None:
            destination = os.path.join(work_dir, package.key,
                                       requirement.arch or "any")
            extracted = False
            for archive in self._package_archives(package, requirement.arch):
                lower = archive.lower()
                if lower.endswith(".cab"):
                    os.makedirs(destination, exist_ok=True)
                    self._run(["expand", "-R", f"-F:{requirement.dll}",
                               archive, destination])
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
            redist_dir = os.path.join(portable_dir, REDIST_DIR_NAME)
            os.makedirs(redist_dir, exist_ok=True)
            filename = url.rsplit("/", 1)[-1] or f"{package.key}.exe"
            if not filename.lower().endswith((".exe", ".msi", ".cab", ".zip")):
                filename = f"{package.key}_{requirement.arch or 'any'}.exe"
            archive = os.path.join(redist_dir, filename)
            if not os.path.isfile(archive):
                self.log.info(f"Скачиваю {package.title} ({url})…")
                if not self._download(url, archive):
                    self.log.warn(
                        f"Не удалось скачать {package.title}. Файл можно "
                        f"взять вручную: {package.page or url}")
                    self._failed_packages.add(key)
                    return "", ""
            destination = os.path.join(work_dir, "download", package.key,
                                       requirement.arch or "any")
            if not self._extract_installer(archive, destination,
                                           requirement.dll):
                self.log.warn(
                    f"{package.title}: пакет скачан, но распаковать его "
                    "автоматически не удалось. Он сохранён в папке "
                    f"{REDIST_DIR_NAME} портатива.")
                self._failed_packages.add(key)
                self._extracted[key] = ""
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
        приложение, поскольку его параллельная конфигурация неправильна».
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
                wanted = manifest_identity(read_pe_manifest(importer), assembly)
                if wanted.get("version"):
                    identity.update(wanted)
                    break
            if not identity.get("version"):
                continue
            files = sorted(
                name for name in os.listdir(directory)
                if name.lower().endswith(".dll") and package.matches(name.lower())
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
                f'publicKeyToken="{identity.get("publicKeyToken", "")}"/>\n'
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

        for requirement in requirements:
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
            if source == "WinSxS":
                self._write_sxs_manifest(requirement, path, app_dir)
            requirement.status = "provided"
            requirement.source = source
            requirement.targets = copied
            (report.stock if requirement.proactive
             else report.provided).append(requirement)

        self._provide_ucrt_base(report, app_dir, portable_dir, work_dir)

        redist_dir = os.path.join(portable_dir, REDIST_DIR_NAME)
        if os.path.isdir(redist_dir):
            report.packages = sorted(
                name for name in os.listdir(redist_dir)
                if os.path.isfile(os.path.join(redist_dir, name))
            )
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)

        if scan.dotnet:
            report.notes.append(
                "Программа собрана для .NET Framework. Сам .NET перенести в "
                "портатив нельзя: в Windows 10/11 он уже есть, а на Windows 7 "
                "может потребоваться установка .NET Framework 4.8 — "
                "https://dotnet.microsoft.com/download/dotnet-framework")
        return report


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


def _has_files(directory: str) -> bool:
    for _root, _dirs, files in os.walk(directory):
        if files:
            return True
    return False


def _find_file(directory: str, name: str) -> str:
    target = name.lower()
    for root, _dirs, files in os.walk(directory):
        for candidate in files:
            if candidate.lower() == target:
                return os.path.join(root, candidate)
    return ""


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
    """Список для предстартовой проверки лончера (только недостающее)."""
    out: List[Dict[str, str]] = []
    seen = set()
    for requirement in report.missing:
        if requirement.dll in seen:
            continue
        seen.add(requirement.dll)
        out.append({
            "dll": requirement.dll,
            "title": requirement.plain_title,
            "url": requirement.url,
            "arch": requirement.arch,
        })
        if len(out) >= limit:
            break
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

    if report.packages:
        lines.append(f"Установщики пакетов в папке {REDIST_DIR_NAME}")
        lines.append("-" * 40)
        lines.append("  Распаковать их автоматически не удалось, но они уже "
                     "скачаны: запустите")
        lines.append("  нужный файл на том ПК, где программа не стартует, — "
                     "интернет не понадобится.")
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
