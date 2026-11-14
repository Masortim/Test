# -*- mode: python ; coding: utf-8 -*-
"""Build the generic EXE copied into each portable application's App folder."""
import os

block_cipher = None

# 7-Zip едет вместе с лончером: обновление умеет достать новую версию из
# установщика, не запуская его (см. «обновление без установщика» в
# portable_launcher_entry.py). Это ~2,5 МБ, зато на ПК без 7-Zip и без сети
# обновление всё равно доходит до конца: NSIS может завершиться кодом 2 и не
# положить программу в папку, а распаковка её достаёт.
a = Analysis(
    ["portable_launcher_entry.py"],
    pathex=[],
    binaries=[],
    datas=[
        (os.path.join("portablizer", "resources", "7zip", "x64"),
         os.path.join("resources", "7zip", "x64")),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "email", "html", "xml", "pydoc"],
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
    name="PortableLauncher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
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
