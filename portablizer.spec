# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller-спека для сборки Portablizer.exe (Windows, один файл, без консоли).

Версия внутри exe (свойства файла, «О программе» в проводнике) берётся из
``portablizer.__version__`` — единственного источника правды: рассинхрон версий здесь
невозможен: файл ресурсов генерируется прямо при сборке.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.curdir))
from portablizer import __version__  # noqa: E402 - докстринг объясняет импорт

block_cipher = None


def _version_resource(path):
    """Сгенерировать Windows-ресурс версии из __version__.

    Русский язык (0x0419) и UTF-16-кодировка строк (04b0) — чтобы описание
    было читаемо в свойствах файла, а не кракозябрами.
    """
    parts = [int(x) for x in __version__.split(".")[:3]]
    parts += [0] * (3 - len(parts))
    nums = tuple(parts + [0])
    body = (
        "VSVersionInfo(\n"
        "  ffi=FixedFileInfo(filevers=" + repr(nums) + ", prodvers=" + repr(nums) + ",\n"
        "    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,\n"
        "    date=(0, 0)),\n"
        "  kids=[\n"
        "    StringFileInfo([StringTable('041904b0', [\n"
        "      StringStruct('CompanyName', ''),\n"
        "      StringStruct('FileDescription', "
        + repr("Portablizer — создание портативных версий программ") + "),\n"
        "      StringStruct('FileVersion', " + repr(__version__) + "),\n"
        "      StringStruct('InternalName', 'Portablizer'),\n"
        "      StringStruct('LegalCopyright', ''),\n"
        "      StringStruct('OriginalFilename', 'Portablizer.exe'),\n"
        "      StringStruct('ProductName', 'Portablizer'),\n"
        "      StringStruct('ProductVersion', " + repr(__version__) + ")])]),\n"
        "    VarFileInfo([VarStruct('Translation', [1049, 1200])])\n"
        "  ]\n"
        ")\n"
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


_build_dir = os.path.join(os.getcwd(), "build")
os.makedirs(_build_dir, exist_ok=True)
version_file = _version_resource(os.path.join(_build_dir, "version_info.txt"))

datas = [
    (os.path.join("portablizer", "resources", "app.ico"), os.path.join("resources")),
    (os.path.join("portablizer", "resources", "app_256.png"), os.path.join("resources")),
    # Готовый нативный лончер, который Portablizer копирует в App/ каждого
    # результата. Сначала собирается portable_launcher.spec (см. build.bat/CI).
    (os.path.join("portablizer", "resources", "portable_launcher.exe"),
     os.path.join("resources")),
]

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "PySide6.QtWebEngineCore", "PySide6.Qt3DCore",
              "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtMultimedia"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="Portablizer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    version=version_file,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join("portablizer", "resources", "app.ico"),
)
