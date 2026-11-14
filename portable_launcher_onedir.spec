# -*- mode: python ; coding: utf-8 -*-
"""Build the generic EXE copied into each portable application's App folder.

Второй вариант сборки того же лончера — **без распаковки на каждом запуске**.

``portable_launcher.spec`` собирает onefile: PyInstaller распаковывает себя во
``%TEMP%`` при КАЖДОМ старте. На машине с антивирусом каждая распаковка — это
десятки новых файлов, которые проверяются заново; окно программы появляется
через секунды после появления самого процесса ``LaunchPortable.exe``. Ровно на
это и жаловались: «фоновый процесс есть, а Cursor открывается очень-очень
медленно».

Здесь тот же код собирается папкой (onedir): ``LaunchPortable.exe`` плюс
``_internal`` рядом с ним. Запуск — обычная загрузка DLL, без распаковки.
``portablizer/core/portablizer.py`` копирует эту папку в портатив так, чтобы
``App\\LaunchPortable.exe`` остался на месте: его ищут ``Launch.bat``,
``LaunchHidden.vbs``, ``StopPortable.cmd`` и ярлыки.
"""
import os

block_cipher = None

# 7-Zip рядом с лончером (в ``_internal``): этим распаковщиком обновление
# достаёт новую версию из установщика, не запуская его.
a = Analysis(
    ["portable_launcher_entry.py"],
    pathex=[],
    binaries=[],
    datas=[
        (os.path.join("portablizer", "resources", "7zip", "x64"),
         os.path.join("resources", "7zip", "x64")),
    ],
    hiddenimports=[
        # Скачивание обновления идёт через urllib: в замороженной сборке
        # лишённый статических импортов email не попадал в неё, и загрузка
        # падала с «No module named 'email'» (реальная жалоба).
        "email",
        "email.parser",
        "email.message",
        "email.feedparser",
        "email.errors",
        "email.header",
        "email.utils",
        "email._policybase",
        "http",
        "http.client",
        "http.cookiejar",
        "urllib.request",
        "urllib.error",
        "urllib.parse",
        "ssl",
        "_ssl",
    ],
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
    [],
    exclude_binaries=True,
    name="PortableLauncher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join("portablizer", "resources", "app.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="PortableLauncher",
)
