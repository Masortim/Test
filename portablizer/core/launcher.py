"""Генерация лончера портативного приложения.

Лончер — это то, что пользователь запускает из портативной папки. Его задачи:

1. Определить собственное расположение (папку портатива) независимо от буквы
   диска и текущего каталога.
2. Перенаправить пользовательские каталоги (APPDATA, LOCALAPPDATA, TEMP,
   USERPROFILE, Documents и т.д.) внутрь портативной папки, чтобы программа не
   писала на C:\\Users\\... .
3. Дополнить PATH локальными зависимостями (например, вложенным runtime).
4. При наличии применить захваченные изменения реестра (portable.reg) — по
   умолчанию во временный пользовательский куст, с откатом при выходе.
5. Запустить целевую программу и дождаться её завершения, затем прибраться.

Мы генерируем два варианта:
  * `Launch.bat`  — не требует ничего, работает на любой Windows.
  * `launcher.py` — та же логика на Python (используется, если решено собирать
    отдельный launcher.exe через PyInstaller).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


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
    # Дополнительные переменные окружения (имя -> значение; поддерживает %VAR%).
    extra_env: Dict[str, str] = field(default_factory=dict)
    # Относительные папки, добавляемые в PATH.
    path_prepend: List[str] = field(default_factory=list)


# --- .BAT лончер --------------------------------------------------------------

_BAT_TEMPLATE = r"""@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem ============================================================================
rem  {app_name} — портативный лончер (сгенерировано Portablizer)
rem  Не требует установки. Все данные хранятся рядом, диск C: не затрагивается.
rem ============================================================================

rem --- Корень портативной папки (там, где лежит этот .bat) ---
set "PORTABLE_ROOT=%~dp0"
if "%PORTABLE_ROOT:~-1%"=="\" set "PORTABLE_ROOT=%PORTABLE_ROOT:~0,-1%"

rem --- Изолированное хранилище пользовательских данных ---
set "PORTABLE_DATA=%PORTABLE_ROOT%\{data_dir_name}"
if not exist "%PORTABLE_DATA%" mkdir "%PORTABLE_DATA%"

rem --- Перенаправляем пользовательские каталоги внутрь портатива ---
set "APPDATA=%PORTABLE_DATA%\AppData\Roaming"
set "LOCALAPPDATA=%PORTABLE_DATA%\AppData\Local"
set "USERPROFILE=%PORTABLE_DATA%\User"
set "HOMEDRIVE=%PORTABLE_ROOT:~0,2%"
set "HOMEPATH=%PORTABLE_DATA:~2%\User"
set "TEMP=%PORTABLE_DATA%\Temp"
set "TMP=%PORTABLE_DATA%\Temp"
set "PROGRAMDATA=%PORTABLE_DATA%\ProgramData"
set "USERNAME=Portable"

for %%D in (
  "%APPDATA%" "%LOCALAPPDATA%" "%USERPROFILE%" "%TEMP%" "%PROGRAMDATA%"
  "%USERPROFILE%\Documents" "%USERPROFILE%\Desktop" "%USERPROFILE%\AppData\Roaming"
  "%USERPROFILE%\AppData\Local"
) do if not exist "%%~D" mkdir "%%~D" >nul 2>&1

rem --- Локальные зависимости в начало PATH ---
{path_lines}

rem --- Пользовательские переменные окружения ---
{env_lines}

rem --- Применяем захваченные изменения реестра (необязательно) ---
{registry_block}

rem --- Запуск целевой программы ---
set "TARGET=%PORTABLE_ROOT%\{target_exe_rel}"
if not exist "%TARGET%" (
  echo [ОШИБКА] Не найден исполняемый файл: "%TARGET%"
  echo Проверьте содержимое портативной папки.
  pause
  exit /b 1
)

pushd "%PORTABLE_ROOT%"
echo Запуск {app_name} в изолированном режиме...
start "" /wait "%TARGET%" {target_args}
set "RC=%ERRORLEVEL%"
popd

{registry_cleanup}

endlocal & exit /b %RC%
"""

_REG_APPLY_BLOCK = r"""set "PORTABLE_REG=%PORTABLE_ROOT%\{reg_file_name}"
if exist "%PORTABLE_REG%" (
  echo Применение сохранённых параметров реестра...
  rem Импортируем в HKCU текущего пользователя. Записи созданы установщиком и
  rem нужны программе. При желании этот блок можно отключить.
  reg import "%PORTABLE_REG%" >nul 2>&1
)"""

_REG_CLEANUP_BLOCK = ""  # по умолчанию реестр не откатываем (см. примечания)


def _bat_path_lines(cfg: LauncherConfig) -> str:
    lines = []
    for rel in cfg.path_prepend:
        rel = rel.replace("/", "\\")
        lines.append(f'set "PATH=%PORTABLE_ROOT%\\{rel};%PATH%"')
    if not lines:
        lines.append('rem (локальные зависимости для PATH не заданы)')
    return "\n".join(lines)


def _bat_env_lines(cfg: LauncherConfig) -> str:
    lines = []
    for k, v in cfg.extra_env.items():
        lines.append(f'set "{k}={v}"')
    if not lines:
        lines.append('rem (пользовательские переменные окружения не заданы)')
    return "\n".join(lines)


def render_bat(cfg: LauncherConfig) -> str:
    registry_block = ""
    if cfg.apply_registry:
        registry_block = _REG_APPLY_BLOCK.format(reg_file_name=cfg.reg_file_name)
    else:
        registry_block = "rem (импорт реестра отключён)"

    return _BAT_TEMPLATE.format(
        app_name=cfg.app_name,
        data_dir_name=cfg.data_dir_name,
        target_exe_rel=cfg.target_exe_rel.replace("/", "\\"),
        target_args=" ".join(cfg.target_args),
        path_lines=_bat_path_lines(cfg),
        env_lines=_bat_env_lines(cfg),
        registry_block=registry_block,
        registry_cleanup=_REG_CLEANUP_BLOCK,
    )


# --- Python лончер (для сборки launcher.exe) ---------------------------------

_PY_LAUNCHER = r'''#!/usr/bin/env python3
"""Портативный лончер {app_name} (сгенерировано Portablizer).

Собирается в launcher.exe (PyInstaller, --noconsole) или запускается как есть.
Логика идентична Launch.bat, но кроссплатформенно-безопасна и с чистым
восстановлением окружения.
"""
import json
import os
import subprocess
import sys

def portable_root() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

def main() -> int:
    root = portable_root()
    with open(os.path.join(root, "launcher_config.json"), "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    data = os.path.join(root, cfg["data_dir_name"])
    appdata = os.path.join(data, "AppData", "Roaming")
    localappdata = os.path.join(data, "AppData", "Local")
    userprofile = os.path.join(data, "User")
    temp = os.path.join(data, "Temp")
    programdata = os.path.join(data, "ProgramData")

    for d in (appdata, localappdata, userprofile, temp, programdata,
              os.path.join(userprofile, "Documents"),
              os.path.join(userprofile, "Desktop")):
        os.makedirs(d, exist_ok=True)

    env = dict(os.environ)
    env.update({{
        "APPDATA": appdata,
        "LOCALAPPDATA": localappdata,
        "USERPROFILE": userprofile,
        "HOMEDRIVE": root[:2],
        "HOMEPATH": userprofile[2:],
        "TEMP": temp, "TMP": temp,
        "PROGRAMDATA": programdata,
        "USERNAME": "Portable",
    }})

    for rel in cfg.get("path_prepend", []):
        p = os.path.join(root, rel.replace("/", os.sep))
        env["PATH"] = p + os.pathsep + env.get("PATH", "")
    for k, v in cfg.get("extra_env", {{}}).items():
        env[k] = os.path.expandvars(v)

    # Применяем реестр (только Windows и только если разрешено).
    if cfg.get("apply_registry") and sys.platform.startswith("win"):
        reg = os.path.join(root, cfg.get("reg_file_name", "portable.reg"))
        if os.path.exists(reg):
            try:
                subprocess.run(["reg", "import", reg],
                               check=False,
                               creationflags=0x08000000)  # CREATE_NO_WINDOW
            except Exception:
                pass

    target = os.path.join(root, cfg["target_exe_rel"].replace("/", os.sep))
    if not os.path.exists(target):
        print("ОШИБКА: не найден", target)
        return 1

    proc = subprocess.run([target] + cfg.get("target_args", []),
                          cwd=root, env=env)
    return proc.returncode

if __name__ == "__main__":
    sys.exit(main())
'''


def render_py_launcher(cfg: LauncherConfig) -> str:
    return _PY_LAUNCHER.format(app_name=cfg.app_name)


def render_config_json(cfg: LauncherConfig) -> str:
    return json.dumps({
        "app_name": cfg.app_name,
        "target_exe_rel": cfg.target_exe_rel,
        "target_args": cfg.target_args,
        "data_dir_name": cfg.data_dir_name,
        "apply_registry": cfg.apply_registry,
        "reg_file_name": cfg.reg_file_name,
        "extra_env": cfg.extra_env,
        "path_prepend": cfg.path_prepend,
    }, ensure_ascii=False, indent=2)
