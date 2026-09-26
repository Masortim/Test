"""Генерация лончера портативного приложения.

Лончер — это то, что пользователь запускает из портативной папки. Его задачи:

1. Определить собственное расположение независимо от буквы диска и текущего
   каталога (флешка на разных ПК получает разные буквы).
2. Перенаправить пользовательские каталоги (APPDATA, LOCALAPPDATA, TEMP,
   USERPROFILE, Documents и т.д.) внутрь портативной папки.
3. Дополнить PATH локальными зависимостями.
4. Аккуратно поработать с реестром: сохранить прежнее состояние чужого ПК,
   подставить настройки программы, а после выхода выгрузить их обратно в
   портатив и вернуть реестр в исходное состояние.
5. Запустить программу (или её лаунчер/конфигуратор), дождаться завершения
   и вернуть её код возврата.

Почему ``Launch.bat`` строго ASCII
----------------------------------
cmd.exe читает .bat не построчно, а блоками, запоминая **байтовое** смещение.
Если внутри файла сменить кодовую страницу (``chcp``) или положить
многобайтовый символ, смещение «съезжает»: интерпретатор начинает читать
команды с середины строки и аварийно завершает работу. Внешне это выглядит
как «окно мигнуло и закрылось», без единого сообщения.

Поэтому генератор:

* не вставляет ``chcp`` вообще;
* проверяет результат на чистый ASCII (``ensure_ascii_bat``) и падает с
  ошибкой, если что-то не-ASCII просочилось в шаблон;
* не-ASCII имена файлов подставляет не литералом, а маской ``?`` — cmd
  раскрывает её через файловую систему и получает корректное имя в Unicode.

Мы генерируем несколько вариантов запуска:
  * ``Launch.bat``  — основной, не требует ничего, работает на любой Windows;
  * ``LaunchHidden.vbs`` — тот же запуск, но без окна консоли;
  * ``Launch_Launcher.bat`` / ``Launch_Configurator.bat`` / ``Launch_<Tool>.bat``
    — запуск вспомогательных лаунчеров и конфигураторов в изолированной среде;
  * ``Launch_Menu.bat`` — интерактивное меню выбора программы;
  * ``launcher.py`` — та же логика на Python (для сборки launcher.exe).
"""
from __future__ import annotations

import json
import os
import string
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from .. import __version__

#: Маркер портативной папки внутри захваченного .reg (см. core/registry.py).
ROOT_TOKEN = "@@PORTABLE_ROOT@@"

#: Максимум ключей реестра, обслуживаемых лончером (защита от «простыни»).
MAX_REGISTRY_KEYS = 256


@dataclass
class TargetInfo:
    """Информация об исполняемом файле в составе портативного приложения."""
    name: str
    rel_path: str
    role: str = "main"        # "main", "launcher", "config", "tool", "auxiliary"
    description: str = ""
    bat_name: str = ""
    vbs_name: str = ""


@dataclass
class LauncherConfig:
    app_name: str
    # Относительный (внутри портативной папки) путь к главному exe программы.
    target_exe_rel: str
    # Аргументы, передаваемые целевой программе.
    target_args: List[str] = field(default_factory=list)
    # Имя папки для «песочницы» пользовательских данных внутри портатива.
    data_dir_name: str = "PortableData"
    # Применять ли захваченный реестр.
    apply_registry: bool = True
    reg_file_name: str = "portable.reg"
    # Отдельный файл для HKLM: без прав администратора он не импортируется,
    # и его ошибка не должна мешать импорту пользовательских настроек.
    machine_reg_file_name: str = "portable_machine.reg"
    # Ключи, которые лончер сохраняет обратно в портатив после выхода.
    registry_keys: List[str] = field(default_factory=list)
    # Ключи, созданные установщиком: их после выхода нужно удалить из системы.
    registry_created_keys: List[str] = field(default_factory=list)
    # Нужна ли подстановка пути портатива в .reg при запуске.
    registry_has_root_token: bool = False
    # Дополнительные переменные окружения (имя -> значение; поддерживает %VAR%).
    extra_env: Dict[str, str] = field(default_factory=dict)
    # Относительные папки, добавляемые в PATH.
    path_prepend: List[str] = field(default_factory=list)
    # Все обнаруженные цели (главный exe, лаунчер, конфигуратор, утилиты)
    targets: List[TargetInfo] = field(default_factory=list)
    launcher_target_rel: str = ""
    config_target_rel: str = ""


# --- утилиты экранирования ----------------------------------------------------

_ASCII_OK = set(string.printable) - {"\x0b", "\x0c"}


def is_ascii_safe(text: str) -> bool:
    """True, если строку можно без риска положить в .bat литералом."""
    return all(ch in _ASCII_OK for ch in text)


def ensure_ascii_bat(text: str) -> str:
    """Страховка: .bat обязан быть чистым ASCII (см. модуль docstring)."""
    bad = {ch for ch in text if ch not in _ASCII_OK}
    if bad:
        shown = ", ".join(f"U+{ord(ch):04X}" for ch in sorted(bad))
        raise ValueError(
            "Launch.bat должен содержать только ASCII, иначе cmd.exe теряет "
            f"смещение чтения и окно закрывается. Найдены символы: {shown}"
        )
    return text


def ascii_display(text: str, fallback: str = "the application") -> str:
    """Готовит человекочитаемую ASCII-подпись для echo/title."""
    cleaned = "".join(ch if ch in _ASCII_OK else " " for ch in text)
    cleaned = " ".join(cleaned.split())
    # Символы, ломающие echo, из подписи просто убираем.
    for ch in '&|<>^"%()':
        cleaned = cleaned.replace(ch, "")
    cleaned = cleaned.strip()
    return cleaned if len(cleaned) >= 2 else fallback


def _bat_set_value(value: str) -> str:
    """Значение для ``set "K=V"``.

    Внутри кавычек cmd не трактует ``& | < > ( )`` как операторы, поэтому
    экранировать их нельзя — иначе ``^`` попадёт прямо в значение и путь
    вида ``D:\\A&B`` превратится в ``D:\\A^&B``. Реально требуется только
    удвоение ``%``; кавычки в путях Windows запрещены и просто убираются.
    """
    return value.replace('"', "").replace("%", "%%")


def _bat_echo(text: str) -> str:
    """Текст для ``echo``: здесь операторы уже вне кавычек и их надо гасить."""
    out = text.replace("^", "^^")
    for ch in ("&", "|", "<", ">", "(", ")"):
        out = out.replace(ch, "^" + ch)
    out = out.replace("%", "%%")
    return out.replace("\r", " ").replace("\n", " ")


def _bat_quote_arg(arg: str) -> str:
    if arg and not any(c in arg for c in ' \t"'):
        return arg.replace("%", "%%")
    return '"' + arg.replace('"', '\\"').replace("%", "%%") + '"'


def _bat_args(args: Sequence[str]) -> str:
    return " ".join(_bat_quote_arg(a) for a in args)


def _win_rel(path: str) -> str:
    return path.replace("/", "\\").strip("\\")


def _wildcard_mask(name: str) -> str:
    """Заменяет не-ASCII символы маской ``?`` для поиска через файловую систему."""
    return "".join(ch if ch in _ASCII_OK else "?" for ch in name)


# --- блоки .BAT ---------------------------------------------------------------

def _path_lines(cfg: LauncherConfig) -> str:
    lines: List[str] = []
    for rel in cfg.path_prepend:
        rel = _win_rel(rel)
        if not is_ascii_safe(rel):
            # Не-ASCII каталог в PATH литералом писать нельзя; он и так будет
            # доступен как рабочая папка программы.
            continue
        lines.append(f'set "PATH=%PORTABLE_ROOT%\\{_bat_set_value(rel)};%PATH%"')
    if not lines:
        lines.append("rem (no local dependency folders were detected)")
    return "\n".join(lines)


def _env_lines(cfg: LauncherConfig) -> str:
    lines: List[str] = []
    for key, value in cfg.extra_env.items():
        if not key or any(ch in key for ch in "= \t\r\n%&|<>^()\"") \
                or not is_ascii_safe(key) or not is_ascii_safe(str(value)):
            continue
        lines.append(f'set "{key}={_bat_set_value(str(value))}"')
    if not lines:
        lines.append("rem (no custom environment variables)")
    return "\n".join(lines)


def _target_lines(cfg: LauncherConfig) -> str:
    rel = _win_rel(cfg.target_exe_rel)
    if is_ascii_safe(rel):
        base_lines = [f'set "PORTABLE_TARGET=%PORTABLE_ROOT%\\{_bat_set_value(rel)}"']
    else:
        # Не-ASCII путь: литерал сломал бы разбор .bat, поэтому имя ищется маской.
        mask = _bat_set_value(_wildcard_mask(rel))
        directory, _, filename = rel.rpartition("\\")
        file_mask = _bat_set_value(_wildcard_mask(filename))
        base_lines = [
            "rem The executable name is not ASCII: resolve it through the file",
            "rem system with a ? mask instead of writing it into this script.",
            'set "PORTABLE_TARGET="',
            f'for %%F in ("%PORTABLE_ROOT%\\{mask}") do '
            'if not defined PORTABLE_TARGET set "PORTABLE_TARGET=%%~fF"',
            "if not defined PORTABLE_TARGET for /f \"delims=\" %%F in "
            f"('dir /b /s /a-d \"%PORTABLE_ROOT%\\{_bat_set_value(_win_rel(directory))}\\{file_mask}\" 2^>nul') do "
            'if not defined PORTABLE_TARGET set "PORTABLE_TARGET=%%~fF"',
            'if not defined PORTABLE_TARGET set "PORTABLE_TARGET=%PORTABLE_ROOT%\\'
            + mask + '"',
        ]

    # Поддержка переопределения через --target / --launcher / --config
    custom_lines = [
        'if defined PORTABLE_CUSTOM_TARGET (',
        '  if exist "%PORTABLE_ROOT%\\%PORTABLE_CUSTOM_TARGET%" (',
        '    set "PORTABLE_TARGET=%PORTABLE_ROOT%\\%PORTABLE_CUSTOM_TARGET%"',
        '  ) else if exist "%PORTABLE_CUSTOM_TARGET%" (',
        '    set "PORTABLE_TARGET=%PORTABLE_CUSTOM_TARGET%"',
        '  ) else if exist "%PORTABLE_ROOT%\\App\\%PORTABLE_CUSTOM_TARGET%" (',
        '    set "PORTABLE_TARGET=%PORTABLE_ROOT%\\App\\%PORTABLE_CUSTOM_TARGET%"',
        '  )',
        ')',
    ]
    return "\n".join(base_lines + custom_lines)


def usable_registry_keys(keys: Sequence[str]) -> List[str]:
    """Оставляет ключи, которые можно безопасно записать в .bat литералом."""
    result: List[str] = []
    for key in keys:
        if not key or not is_ascii_safe(key):
            continue
        if any(ch in key for ch in '"%<>|&^'):
            continue
        if key not in result:
            result.append(key)
        if len(result) >= MAX_REGISTRY_KEYS:
            break
    return result


def consolidate_root_keys(keys: Sequence[str]) -> List[str]:
    """Возвращает минимальный набор корневых ключей для безопасного экспорта/импорта.

    Если в списке есть 'HKCU\\Software\\Vendor' и 'HKCU\\Software\\Vendor\\App',
    экспорт 'HKCU\\Software\\Vendor' уже рекурсивно покрывает все дочерние ветки.
    """
    cleaned = [k.rstrip("\\") for k in keys if k and is_ascii_safe(k)]
    cleaned = sorted(set(cleaned), key=lambda s: (s.count("\\"), s.lower()))
    roots: List[str] = []
    for k in cleaned:
        parts = k.split("\\")
        if len(parts) <= 2:
            roots.append(k)
            continue
        is_sub = False
        for root in roots:
            if k.lower() == root.lower() or k.lower().startswith(root.lower() + "\\"):
                is_sub = True
                break
        if not is_sub:
            roots.append(k)
    return usable_registry_keys(roots)


def _registry_load_block(cfg: LauncherConfig) -> str:
    if not cfg.apply_registry:
        return "rem (registry support is disabled for this portable app)\ngoto :eof"

    lines: List[str] = [
        'if not defined PORTABLE_REGISTRY goto :eof',
        'set "PORTABLE_SESSION_FOUND="',
        'for %%F in ("%PORTABLE_REG_SESSION%\\*.reg") do set "PORTABLE_SESSION_FOUND=1"',
    ]

    # Прежнее состояние чужого ПК сохраняем до любых изменений, чтобы после
    # выхода вернуть всё как было.
    keys = consolidate_root_keys(cfg.registry_keys)
    for index, key in enumerate(keys):
        backup = f'%PORTABLE_REG_BACKUP%\\k{index:02d}.reg'
        lines.append(
            f'if not exist "{backup}" reg export "{key}" "{backup}" /y >nul 2>&1'
        )

    # Настройки прошлого запуска имеют приоритет над исходным снимком.
    lines += [
        'if defined PORTABLE_SESSION_FOUND (',
        '  for %%F in ("%PORTABLE_REG_SESSION%\\*.reg") do '
        'call :portable_registry_import "%%~fF"',
        '  goto :eof',
        ')',
    ]

    initial = '%PORTABLE_ROOT%\\' + _bat_set_value(cfg.reg_file_name)
    machine = '%PORTABLE_ROOT%\\' + _bat_set_value(cfg.machine_reg_file_name)
    lines += [
        f'if exist "{initial}" call :portable_registry_import "{initial}"',
        'rem HKLM entries need administrator rights; keep them in a separate',
        'rem file so a failure here cannot abort the user-level import.',
        f'if exist "{machine}" call :portable_registry_import "{machine}"',
        'goto :eof',
    ]
    return "\n".join(lines)


def _registry_save_block(cfg: LauncherConfig) -> str:
    if not cfg.apply_registry:
        return "goto :eof"
    keys = consolidate_root_keys(cfg.registry_keys)
    if not keys:
        return "goto :eof"

    created = set(consolidate_root_keys(cfg.registry_created_keys))
    lines: List[str] = [
        'if not defined PORTABLE_REGISTRY goto :eof',
        'if not defined PORTABLE_RESTORE goto :eof',
        'rem Save what the program wrote back into the portable folder, then',
        'rem leave this computer exactly as it was found.',
    ]
    for index, key in enumerate(keys):
        session = f'%PORTABLE_REG_SESSION%\\k{index:02d}.reg'
        backup = f'%PORTABLE_REG_BACKUP%\\k{index:02d}.reg'
        lines.append(f'del /f /q "{session}" >nul 2>&1')
        lines.append(f'reg export "{key}" "{session}" /y >nul 2>&1')
        # Абсолютный путь этой папки заменяем маркером, иначе на следующем
        # компьютере (другая буква диска) настройки укажут в никуда.
        lines.append(f'if exist "{session}" call :portable_registry_pack "{session}"')
        if key in created:
            lines.append(f'reg delete "{key}" /f >nul 2>&1')
        lines.append(f'if exist "{backup}" reg import "{backup}" >nul 2>&1')
        lines.append(f'del /f /q "{backup}" >nul 2>&1')
    lines.append("goto :eof")
    return "\n".join(lines)


_BAT_TEMPLATE = r"""@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem ===========================================================================
rem  {title} - portable launcher generated by Portablizer {version}
rem
rem  This script is deliberately pure ASCII and never calls "chcp".
rem  cmd.exe re-reads a batch file by BYTE offset: a codepage switch or a
rem  multi-byte character shifts that offset, the interpreter starts reading
rem  commands from the middle of a line and the window closes instantly with
rem  no message at all. Keep every literal in this file ASCII-only.
rem
rem  Usage:
rem    Launch.bat [options] [-- program arguments]
rem      --target <path>   run a specific target executable inside the sandbox
rem      --launcher        run the program's preinstalled launcher (if present)
rem      --config          run the configuration/settings tool (if present)
rem      --menu            show interactive menu to choose which program to run
rem      --list            list all detected runnable executables
rem      --nopause         never wait for a key press
rem      --pause           always wait for a key press before closing
rem      --no-registry     do not touch the registry at all
rem      --keep-registry   keep imported settings in the registry after exit
rem      --reset           forget the saved session settings and start clean
rem      --help            show this help
rem ===========================================================================

set "PORTABLE_PAUSE=auto"
set "PORTABLE_REGISTRY=1"
set "PORTABLE_RESTORE=1"
set "PORTABLE_RESET="
set "PORTABLE_ARGS="
set "PORTABLE_RC=0"
set "PORTABLE_CUSTOM_TARGET="
set "PORTABLE_MENU="

:portable_parse
if "%~1" == "" goto portable_parsed
if /i "%~1" == "--help" goto portable_help
if /i "%~1" == "/?" goto portable_help
if /i "%~1" == "--list" goto portable_list
if /i "%~1" == "--nopause" (
  set "PORTABLE_PAUSE=never"
  shift
  goto portable_parse
)
if /i "%~1" == "--pause" (
  set "PORTABLE_PAUSE=always"
  shift
  goto portable_parse
)
if /i "%~1" == "--no-registry" (
  set "PORTABLE_REGISTRY="
  shift
  goto portable_parse
)
if /i "%~1" == "--keep-registry" (
  set "PORTABLE_RESTORE="
  shift
  goto portable_parse
)
if /i "%~1" == "--reset" (
  set "PORTABLE_RESET=1"
  shift
  goto portable_parse
)
if /i "%~1" == "--menu" (
  set "PORTABLE_MENU=1"
  shift
  goto portable_parse
)
{launcher_arg_block}
{config_arg_block}
if /i "%~1" == "--target" (
  set "PORTABLE_CUSTOM_TARGET=%~2"
  shift
  shift
  goto portable_parse
)
if "%~1" == "--" (
  shift
  goto portable_rest
)
set "PORTABLE_ARGS=%PORTABLE_ARGS% %1"
shift
goto portable_parse

:portable_rest
if "%~1" == "" goto portable_parsed
set "PORTABLE_ARGS=%PORTABLE_ARGS% %1"
shift
goto portable_rest

:portable_parsed
title {title} (portable)

rem --- Root of the portable folder (works from any drive letter) -------------
for %%I in ("%~dp0.") do set "PORTABLE_ROOT=%%~fI"
set "PORTABLE_DATA=%PORTABLE_ROOT%\{data_dir_name}"
set "PORTABLE_REG_SESSION=%PORTABLE_DATA%\Registry"
set "PORTABLE_REG_BACKUP=%PORTABLE_DATA%\RegistryHostBackup"
rem Placeholder standing in for this folder inside the captured settings.
set "PORTABLE_REG_MARKER={root_token}"

rem --- Redirect the user profile into the portable folder --------------------
set "APPDATA=%PORTABLE_DATA%\AppData\Roaming"
set "LOCALAPPDATA=%PORTABLE_DATA%\AppData\Local"
set "USERPROFILE=%PORTABLE_DATA%\User"
set "TEMP=%PORTABLE_DATA%\Temp"
set "TMP=%PORTABLE_DATA%\Temp"
set "PROGRAMDATA=%PORTABLE_DATA%\ProgramData"
set "PUBLIC=%PORTABLE_DATA%\Public"
set "USERNAME=Portable"
set "PORTABLE_APP=1"

rem HOMEDRIVE/HOMEPATH only make sense for a real drive letter, never for UNC.
if "%PORTABLE_ROOT:~1,1%" == ":" (
  set "HOMEDRIVE=%PORTABLE_ROOT:~0,2%"
  set "HOMEPATH=%PORTABLE_DATA:~2%\User"
)

rem Pre-create the whole profile tree. Some programs (game DRM/Steam emulators
rem in particular) create their data folder without making intermediate
rem directories first: if the parent is missing they abort with an obscure
rem message such as "Internal error 0x06: System error!". Creating the usual
rem folders up front keeps those programs happy.
for %%D in (
  "%PORTABLE_DATA%"
  "%APPDATA%"
  "%LOCALAPPDATA%"
  "%LOCALAPPDATA%\Temp"
  "%USERPROFILE%"
  "%TEMP%"
  "%PROGRAMDATA%"
  "%PUBLIC%"
  "%USERPROFILE%\Documents"
  "%USERPROFILE%\Documents\My Games"
  "%USERPROFILE%\Desktop"
  "%USERPROFILE%\Downloads"
  "%USERPROFILE%\Saved Games"
  "%USERPROFILE%\AppData\Roaming"
  "%USERPROFILE%\AppData\Local"
  "%USERPROFILE%\AppData\LocalLow"
  "%PUBLIC%\Documents"
  "%PUBLIC%\Desktop"
  "%PUBLIC%\Downloads"
  "%PORTABLE_REG_SESSION%"
  "%PORTABLE_REG_BACKUP%"
) do if not exist "%%~D" mkdir "%%~D" >nul 2>&1

if defined PORTABLE_RESET del /f /q "%PORTABLE_REG_SESSION%\*.reg" >nul 2>&1

rem --- Local dependencies first in PATH --------------------------------------
{path_lines}

rem --- Custom environment variables ------------------------------------------
{env_lines}

rem --- Locate the program -----------------------------------------------------
{target_lines}

if defined PORTABLE_MENU goto portable_show_menu
goto portable_target_ready

:portable_show_menu
{menu_block}

:portable_target_ready
if not exist "%PORTABLE_TARGET%" (
  echo [ERROR] Program not found:
  echo   "%PORTABLE_TARGET%"
  echo.
  echo The portable folder looks incomplete. Copy the WHOLE folder,
  echo not just this file, and keep the App subfolder next to it.
  if not "%PORTABLE_PAUSE%" == "never" pause
  endlocal
  exit /b 1
)

call :portable_registry_load

for %%I in ("%PORTABLE_TARGET%") do set "PORTABLE_TARGET_DIR=%%~dpI"
pushd "%PORTABLE_TARGET_DIR%" 2>nul
echo Starting {title} from the portable folder...
"%PORTABLE_TARGET%" {target_args}%PORTABLE_ARGS%
set "PORTABLE_RC=%ERRORLEVEL%"
popd

call :portable_registry_save

if not "%PORTABLE_RC%" == "0" (
  echo.
  echo [WARNING] The program exited with code %PORTABLE_RC%.
  echo If it did not start at all, run this file from an open cmd window
  echo to read the messages above.
)
if "%PORTABLE_PAUSE%" == "always" pause
if "%PORTABLE_PAUSE%" == "auto" if not "%PORTABLE_RC%" == "0" pause
endlocal & exit /b %PORTABLE_RC%

rem ===========================================================================
rem  Subroutines
rem ===========================================================================

:portable_help
echo {title} - portable launcher
echo.
echo   Launch.bat [options] [-- program arguments]
echo.
echo     --target ^<path^>   run a specific target executable inside the sandbox
echo     --launcher        run the program's preinstalled launcher (if present)
echo     --config          run the configuration/settings tool (if present)
echo     --menu            show interactive menu to choose which program to run
echo     --list            list all detected runnable executables
echo     --nopause         never wait for a key press
echo     --pause           always wait for a key press before closing
echo     --no-registry     do not touch the registry at all
echo     --keep-registry   keep imported settings in the registry after exit
echo     --reset           forget the saved session settings and start clean
echo     --help            show this help
echo.
echo All settings stay inside the {data_dir_name} folder next to this file.
endlocal & exit /b 0

:portable_list
echo ===========================================================================
echo  {title} (portable) - Detected Executables:
echo ===========================================================================
{list_items}
echo ===========================================================================
endlocal & exit /b 0

:portable_registry_load
{registry_load}

:portable_registry_save
{registry_save}

{registry_helpers}"""

_REGISTRY_HELPERS = r""":portable_registry_import
rem Imports %1 after replacing the location marker with this folder, so the
rem settings keep working after the folder moves to another drive or PC.
set "PORTABLE_REG_SRC=%~f1"
set "PORTABLE_REG_OUT=%TEMP%\portable_import_%RANDOM%.reg"
call :portable_registry_rewrite unpack
if exist "%PORTABLE_REG_OUT%" (
  reg import "%PORTABLE_REG_OUT%" >nul 2>&1
  del /f /q "%PORTABLE_REG_OUT%" >nul 2>&1
) else (
  reg import "%PORTABLE_REG_SRC%" >nul 2>&1
)
goto :eof

:portable_registry_pack
rem Replaces this folder with the location marker before the settings are
rem stored back into the portable folder.
set "PORTABLE_REG_SRC=%~f1"
set "PORTABLE_REG_OUT=%TEMP%\portable_pack_%RANDOM%.reg"
call :portable_registry_rewrite pack
if exist "%PORTABLE_REG_OUT%" (
  copy /y "%PORTABLE_REG_OUT%" "%PORTABLE_REG_SRC%" >nul 2>&1
  del /f /q "%PORTABLE_REG_OUT%" >nul 2>&1
)
goto :eof

:portable_registry_rewrite
rem %1 = pack   : absolute path  -> marker
rem %1 = unpack : marker         -> absolute path
set "PORTABLE_REG_MODE=%~1"
set "PORTABLE_REG_TOKEN=%PORTABLE_REG_MARKER%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $p=[IO.File]::ReadAllBytes($env:PORTABLE_REG_SRC); $e=if($p.Length -ge 2 -and $p[0] -eq 255 -and $p[1] -eq 254){[Text.Encoding]::Unicode}else{[Text.Encoding]::UTF8}; $t=$e.GetString($p).TrimStart([char]0xFEFF); $r=$env:PORTABLE_ROOT.Replace('\','\\'); if($env:PORTABLE_REG_MODE -eq 'pack'){ $t=$t.Replace($r,$env:PORTABLE_REG_TOKEN); $t=$t.Replace($env:PORTABLE_ROOT,$env:PORTABLE_REG_TOKEN) } else { $t=$t.Replace($env:PORTABLE_REG_TOKEN,$r) }; [IO.File]::WriteAllText($env:PORTABLE_REG_OUT,$t,[Text.Encoding]::Unicode) } catch { exit 1 }" >nul 2>&1
goto :eof
"""


def render_bat(cfg: LauncherConfig) -> str:
    title = ascii_display(cfg.app_name)
    data_dir = _bat_set_value(cfg.data_dir_name)
    if not is_ascii_safe(data_dir):
        data_dir = "PortableData"
    args = _bat_args(cfg.target_args)

    # Дополнительные аргументы --launcher и --config
    launcher_rel = _win_rel(cfg.launcher_target_rel) if cfg.launcher_target_rel else ""
    config_rel = _win_rel(cfg.config_target_rel) if cfg.config_target_rel else ""

    if launcher_rel and is_ascii_safe(launcher_rel):
        launcher_arg_block = (
            'if /i "%~1" == "--launcher" (\n'
            f'  set "PORTABLE_CUSTOM_TARGET={_bat_set_value(launcher_rel)}"\n'
            '  shift\n'
            '  goto portable_parse\n'
            ')'
        )
    else:
        launcher_arg_block = "rem (no standalone launcher detected)"

    if config_rel and is_ascii_safe(config_rel):
        config_arg_block = (
            'if /i "%~1" == "--config" (\n'
            f'  set "PORTABLE_CUSTOM_TARGET={_bat_set_value(config_rel)}"\n'
            '  shift\n'
            '  goto portable_parse\n'
            ')\n'
            'if /i "%~1" == "--settings" (\n'
            f'  set "PORTABLE_CUSTOM_TARGET={_bat_set_value(config_rel)}"\n'
            '  shift\n'
            '  goto portable_parse\n'
            ')'
        )
    else:
        config_arg_block = "rem (no standalone configuration tool detected)"

    # Интерактивное меню и список целей
    all_targets = list(cfg.targets)
    if not all_targets and cfg.target_exe_rel:
        all_targets = [TargetInfo(name=title, rel_path=cfg.target_exe_rel, role="main")]

    menu_lines: List[str] = [
        "echo ===========================================================================",
        f"echo  {_bat_echo(title)} (portable) - Launcher Menu",
        "echo ===========================================================================",
    ]
    list_lines: List[str] = []
    choice_branches: List[str] = []

    for index, target in enumerate(all_targets, start=1):
        target_name = ascii_display(target.name, fallback="target")
        raw_rel = _win_rel(target.rel_path)
        target_rel_safe = raw_rel if is_ascii_safe(raw_rel) else _wildcard_mask(raw_rel)
        role_tag = f"[{target.role.upper()}]" if target.role != "main" else "[MAIN]"
        menu_lines.append(f"echo   [{index}] {role_tag} {target_name} ({_bat_echo(target_rel_safe)})")
        list_lines.append(f"echo   * {role_tag} {target_name}: {_bat_echo(target_rel_safe)}")
        choice_branches += [
            f'if "%PORTABLE_CHOICE%" == "{index}" (',
            f'  set "PORTABLE_CUSTOM_TARGET={_bat_set_value(target_rel_safe)}"',
            '  goto portable_menu_apply',
            ')',
        ]

    menu_lines.append("echo   [0] Exit")
    menu_lines.append("echo ===========================================================================")
    menu_lines.append('set "PORTABLE_CHOICE=1"')
    menu_lines.append(f'set /p "PORTABLE_CHOICE=Select program [0-{len(all_targets)}]: "')
    menu_lines.append('if "%PORTABLE_CHOICE%" == "0" (\n  endlocal\n  exit /b 0\n)')
    menu_lines.extend(choice_branches)
    menu_lines.append("echo Invalid choice. Starting default program...")
    menu_lines.append(":portable_menu_apply")
    menu_lines.append("if defined PORTABLE_CUSTOM_TARGET (")
    menu_lines.append('  if exist "%PORTABLE_ROOT%\\%PORTABLE_CUSTOM_TARGET%" (')
    menu_lines.append('    set "PORTABLE_TARGET=%PORTABLE_ROOT%\\%PORTABLE_CUSTOM_TARGET%"')
    menu_lines.append('  ) else if exist "%PORTABLE_CUSTOM_TARGET%" (')
    menu_lines.append('    set "PORTABLE_TARGET=%PORTABLE_CUSTOM_TARGET%"')
    menu_lines.append('  ) else if exist "%PORTABLE_ROOT%\\App\\%PORTABLE_CUSTOM_TARGET%" (')
    menu_lines.append('    set "PORTABLE_TARGET=%PORTABLE_ROOT%\\App\\%PORTABLE_CUSTOM_TARGET%"')
    menu_lines.append("  )")
    menu_lines.append(")")
    menu_lines.append("goto portable_target_ready")

    safe_main_rel = _win_rel(cfg.target_exe_rel)
    if not is_ascii_safe(safe_main_rel):
        safe_main_rel = _wildcard_mask(safe_main_rel)

    menu_block = "\n".join(menu_lines) if len(all_targets) >= 2 else "goto portable_target_ready"
    list_items = "\n".join(list_lines) if list_lines else f"echo   * [MAIN] {title}: {_bat_echo(safe_main_rel)}"

    text = _BAT_TEMPLATE.format(
        title=_bat_echo(title),
        version=_bat_echo(__version__),
        data_dir_name=data_dir,
        path_lines=_path_lines(cfg),
        env_lines=_env_lines(cfg),
        target_lines=_target_lines(cfg),
        target_args=(args + " ") if args else "",
        registry_load=_registry_load_block(cfg),
        registry_save=_registry_save_block(cfg),
        registry_helpers=_REGISTRY_HELPERS if cfg.apply_registry else "",
        root_token=ROOT_TOKEN,
        launcher_arg_block=launcher_arg_block,
        config_arg_block=config_arg_block,
        menu_block=menu_block,
        list_items=list_items,
    )
    return ensure_ascii_bat(text)


# --- VBS-обёртка (запуск без окна консоли) ------------------------------------

_VBS_TEMPLATE = """' Starts Launch.bat without showing a console window.
' Pure ASCII on purpose, see Launch.bat for the reason.
Option Explicit
Dim shell, fso, root, args, i, line
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
args = ""
For i = 0 To WScript.Arguments.Count - 1
    args = args & " " & Chr(34) & WScript.Arguments(i) & Chr(34)
Next
line = Chr(34) & root & "\\Launch.bat" & Chr(34) & " --nopause" & args
shell.Run line, 0, False
"""


def render_vbs() -> str:
    return ensure_ascii_bat(_VBS_TEMPLATE)


# --- Вспомогательные лаунчеры и меню ------------------------------------------

def render_companion_bat(cfg: LauncherConfig, target: TargetInfo) -> str:
    """Создаёт Launch_<Name>.bat для запуска вспомогательного файла в портативе."""
    title = ascii_display(f"{cfg.app_name} - {target.name}")
    rel = _win_rel(target.rel_path)
    text = (
        "@echo off\r\n"
        "setlocal EnableExtensions\r\n"
        "rem ===========================================================================\r\n"
        f"rem  {title} - companion portable launcher\r\n"
        f"rem  Target: {rel}\r\n"
        "rem ===========================================================================\r\n"
        "for %%I in (\"%~dp0.\") do set \"PORTABLE_LAUNCHER_DIR=%%~fI\"\r\n"
        f"\"%PORTABLE_LAUNCHER_DIR%\\Launch.bat\" --target \"{_bat_set_value(rel)}\" %*\r\n"
    )
    return ensure_ascii_bat(text)


def render_companion_vbs(cfg: LauncherConfig, target: TargetInfo) -> str:
    """Создаёт Launch_<Name>.vbs для скрытого запуска вспомогательного файла."""
    rel = _win_rel(target.rel_path)
    text = (
        "' Starts companion target without showing a console window.\r\n"
        "Option Explicit\r\n"
        "Dim shell, fso, root, args, i, line\r\n"
        "Set shell = CreateObject(\"WScript.Shell\")\r\n"
        "Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n"
        "root = fso.GetParentFolderName(WScript.ScriptFullName)\r\n"
        "args = \"\"\r\n"
        "For i = 0 To WScript.Arguments.Count - 1\r\n"
        "    args = args & \" \" & Chr(34) & WScript.Arguments(i) & Chr(34)\r\n"
        "Next\r\n"
        f"line = Chr(34) & root & \"\\Launch.bat\" & Chr(34) & \" --nopause --target \" & Chr(34) & \"{rel}\" & Chr(34) & args\r\n"
        "shell.Run line, 0, False\r\n"
    )
    return ensure_ascii_bat(text)


def render_menu_bat(cfg: LauncherConfig) -> str:
    """Создаёт Launch_Menu.bat для интерактивного выбора программы."""
    title = ascii_display(f"{cfg.app_name} - Menu")
    text = (
        "@echo off\r\n"
        "setlocal EnableExtensions\r\n"
        "rem ===========================================================================\r\n"
        f"rem  {title} - portable interactive menu\r\n"
        "rem ===========================================================================\r\n"
        "for %%I in (\"%~dp0.\") do set \"PORTABLE_LAUNCHER_DIR=%%~fI\"\r\n"
        "\"%PORTABLE_LAUNCHER_DIR%\\Launch.bat\" --menu %*\r\n"
    )
    return ensure_ascii_bat(text)


# --- Python лончер (для сборки launcher.exe) ---------------------------------

_PY_LAUNCHER = r'''#!/usr/bin/env python3
"""Портативный лончер (сгенерировано Portablizer).

Собирается в launcher.exe (PyInstaller, --noconsole) или запускается как есть.
Логика повторяет Launch.bat: изоляция профиля, подстановка пути в захваченный
реестр, запуск программы и возврат реестра чужого ПК в исходное состояние.
"""
import json
import os
import subprocess
import sys

NO_WINDOW = 0x08000000 if sys.platform.startswith("win") else 0


def portable_root():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def reg(*args):
    if not sys.platform.startswith("win"):
        return 1
    try:
        return subprocess.run(["reg", *args], check=False,
                              creationflags=NO_WINDOW).returncode
    except OSError:
        return 1


def main():
    root = portable_root()
    with open(os.path.join(root, "launcher_config.json"), "r",
              encoding="utf-8") as fh:
        cfg = json.load(fh)

    data = os.path.join(root, cfg.get("data_dir_name", "PortableData"))
    appdata = os.path.join(data, "AppData", "Roaming")
    localappdata = os.path.join(data, "AppData", "Local")
    userprofile = os.path.join(data, "User")
    temp = os.path.join(data, "Temp")
    programdata = os.path.join(data, "ProgramData")
    session = os.path.join(data, "Registry")
    backup = os.path.join(data, "RegistryHostBackup")

    public = os.path.join(data, "Public")
    # Pre-create the whole profile tree. Some programs (game DRM / Steam
    # emulators especially) create their data folder without first making the
    # intermediate directories and abort with an obscure "Internal error 0x06:
    # System error!" when a parent is missing. Creating them up front avoids it.
    for path in (appdata, localappdata, os.path.join(localappdata, "Temp"),
                 userprofile, temp, programdata, public, session, backup,
                 os.path.join(userprofile, "Documents"),
                 os.path.join(userprofile, "Documents", "My Games"),
                 os.path.join(userprofile, "Desktop"),
                 os.path.join(userprofile, "Downloads"),
                 os.path.join(userprofile, "Saved Games"),
                 os.path.join(userprofile, "AppData", "LocalLow"),
                 os.path.join(public, "Documents"),
                 os.path.join(public, "Desktop"),
                 os.path.join(public, "Downloads")):
        os.makedirs(path, exist_ok=True)

    env = dict(os.environ)
    env.update({
        "APPDATA": appdata,
        "LOCALAPPDATA": localappdata,
        "USERPROFILE": userprofile,
        "TEMP": temp, "TMP": temp,
        "PROGRAMDATA": programdata,
        "PUBLIC": public,
        "USERNAME": "Portable",
        "PORTABLE_APP": "1",
    })
    if root[1:2] == ":":
        env["HOMEDRIVE"] = root[:2]
        env["HOMEPATH"] = userprofile[2:]

    for rel in cfg.get("path_prepend", []):
        env["PATH"] = (os.path.join(root, rel.replace("/", os.sep))
                       + os.pathsep + env.get("PATH", ""))
    for key, value in cfg.get("extra_env", {}).items():
        env[key] = os.path.expandvars(value)

    registry = cfg.get("registry", {})
    keys = registry.get("keys", [])
    created = set(registry.get("created_keys", []))
    windows = sys.platform.startswith("win")
    active = bool(registry.get("enabled")) and windows

    if active:
        for index, key in enumerate(keys):
            path = os.path.join(backup, "k%02d.reg" % index)
            if not os.path.exists(path):
                reg("export", key, path, "/y")
        saved = [f for f in os.listdir(session) if f.lower().endswith(".reg")]
        if saved:
            for name in sorted(saved):
                reg("import", os.path.join(session, name))
        else:
            initial = os.path.join(root, registry.get("file", "portable.reg"))
            if os.path.exists(initial):
                token = registry.get("root_token")
                if token:
                    runtime = os.path.join(session, "_imported.reg")
                    with open(initial, "r", encoding="utf-16") as fh:
                        text = fh.read()
                    text = text.replace(token, root.replace("\\", "\\\\"))
                    with open(runtime, "w", encoding="utf-16",
                              newline="\r\n") as fh:
                        fh.write(text)
                    initial = runtime
                reg("import", initial)
            machine = os.path.join(root, registry.get("machine_file", ""))
            if registry.get("machine_file") and os.path.exists(machine):
                reg("import", machine)

    # Разбор аргументов для выбора цели
    target_rel = cfg["target_exe_rel"]
    custom_target = None
    argv = list(sys.argv[1:])

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--launcher" and cfg.get("launcher_target_rel"):
            custom_target = cfg["launcher_target_rel"]
            argv.pop(i)
            continue
        if (arg == "--config" or arg == "--settings") and cfg.get("config_target_rel"):
            custom_target = cfg["config_target_rel"]
            argv.pop(i)
            continue
        if arg == "--target" and i + 1 < len(argv):
            custom_target = argv[i + 1]
            argv.pop(i)
            argv.pop(i)
            continue
        if arg == "--list":
            print(f"Detected targets in {cfg.get('app_name', 'App')}:")
            for t in cfg.get("targets", []):
                print(f"  [{t.get('role', 'target')}] {t.get('name')}: {t.get('rel_path')}")
            return 0
        if arg == "--menu":
            targets = cfg.get("targets", [])
            if targets:
                print("=======================================================")
                print(f" {cfg.get('app_name', 'App')} - Launcher Menu")
                print("=======================================================")
                for idx, t in enumerate(targets, 1):
                    print(f"  [{idx}] {t.get('name')}: {t.get('rel_path')}")
                print("  [0] Exit")
                print("=======================================================")
                try:
                    choice = input(f"Select option [0-{len(targets)}]: ").strip()
                    if choice == "0":
                        return 0
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(targets):
                        custom_target = targets[choice_num - 1]["rel_path"]
                except (ValueError, EOFError, KeyboardInterrupt):
                    pass
            argv.pop(i)
            continue
        i += 1

    if custom_target:
        target_rel = custom_target

    target = os.path.join(root, target_rel.replace("/", os.sep))
    if not os.path.exists(target):
        alt = os.path.join(root, "App", target_rel.replace("/", os.sep))
        if os.path.exists(alt):
            target = alt
        else:
            print("ERROR: program not found:", target)
            return 1

    code = subprocess.run([target] + cfg.get("target_args", []) + argv,
                          cwd=os.path.dirname(target), env=env).returncode

    if active and registry.get("restore_on_exit", True):
        for index, key in enumerate(keys):
            path = os.path.join(session, "k%02d.reg" % index)
            if os.path.exists(path):
                os.remove(path)
            reg("export", key, path, "/y")
            if key in created:
                reg("delete", key, "/f")
            saved_backup = os.path.join(backup, "k%02d.reg" % index)
            if os.path.exists(saved_backup):
                reg("import", saved_backup)
                os.remove(saved_backup)
    return code


if __name__ == "__main__":
    sys.exit(main())
'''


def render_py_launcher(cfg: LauncherConfig) -> str:
    return _PY_LAUNCHER


def render_config_json(cfg: LauncherConfig) -> str:
    targets_data = [
        {
            "name": t.name,
            "rel_path": t.rel_path,
            "role": t.role,
            "description": t.description,
            "bat_name": t.bat_name,
            "vbs_name": t.vbs_name,
        }
        for t in cfg.targets
    ]
    return json.dumps({
        "generated_by": f"Portablizer {__version__}",
        "app_name": cfg.app_name,
        "target_exe_rel": cfg.target_exe_rel,
        "launcher_target_rel": cfg.launcher_target_rel,
        "config_target_rel": cfg.config_target_rel,
        "targets": targets_data,
        "target_args": cfg.target_args,
        "data_dir_name": cfg.data_dir_name,
        "extra_env": cfg.extra_env,
        "path_prepend": cfg.path_prepend,
        "registry": {
            "enabled": cfg.apply_registry,
            "file": cfg.reg_file_name,
            "machine_file": cfg.machine_reg_file_name,
            "root_token": ROOT_TOKEN if cfg.registry_has_root_token else "",
            "restore_on_exit": True,
            "keys": consolidate_root_keys(cfg.registry_keys),
            "created_keys": consolidate_root_keys(cfg.registry_created_keys),
        },
    }, ensure_ascii=False, indent=2)
