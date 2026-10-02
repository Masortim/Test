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
  * ``App/LaunchPortable.exe`` — основной запуск двойным кликом; готовый
    бинарник собирается отдельно и копируется оркестратором;
  * ``Launch.bat`` — запасной вариант, работает на любой Windows;
  * ``LaunchHidden.vbs`` — тот же запасной запуск, но без окна консоли;
  * ``Launch_Launcher.bat`` / ``Launch_Configurator.bat`` — два полезных
    коротких вызова официального лаунчера и окна настроек;
  * ``Launch_Menu.bat`` — единое меню всех целей, включая редкие утилиты;
  * ``launcher.py`` — та же логика на Python (для сборки launcher.exe).
"""
from __future__ import annotations

import json
import math
import os
import string
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from .. import __version__
from .redist import REDIST_DIR_NAME, SILENT_SCRIPT_NAME as REDIST_SCRIPT_NAME

#: Маркер портативной папки внутри захваченного .reg (см. core/registry.py).
ROOT_TOKEN = "@@PORTABLE_ROOT@@"

#: Максимум ключей реестра, обслуживаемых лончером (защита от «простыни»).
MAX_REGISTRY_KEYS = 256

#: Максимум строк в предстартовой проверке системных библиотек.
MAX_RUNTIME_CHECKS = 12


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
    # Временно перенаправлять Windows Known Folder «Документы». Одного
    # USERPROFILE недостаточно: .NET/WinAPI-конфигураторы читают путь через
    # SHGetKnownFolderPath и иначе пишут настройки в реальный профиль.
    redirect_known_folders: bool = False
    # Все обнаруженные цели (главный exe, лаунчер, конфигуратор, утилиты)
    targets: List[TargetInfo] = field(default_factory=list)
    launcher_target_rel: str = ""
    config_target_rel: str = ""
    # Имя отдельного EXE-лончера в корне портатива -> запускаемая цель.
    # Все эти файлы являются копиями одного PortableLauncher.exe, поэтому
    # выбор цели хранится в переносимом JSON, а не в абсолютном пути.
    launcher_aliases: Dict[str, str] = field(default_factory=dict)
    # Распространяемые компоненты (VC++, DirectX…), которые не удалось
    # принести в портатив. Лончер проверяет их перед стартом и объясняет,
    # чего не хватает, вместо системного окна «отсутствует MSVCR110.dll».
    # Каждая запись: {"dll", "title", "url", "arch"}.
    runtime_requirements: List[Dict[str, str]] = field(default_factory=list)
    # Установщики этих пакетов, положенные в папку Redist портатива. Если
    # библиотеки на целевом ПК действительно нет, лончер ставит пакет
    # МОЛЧА (один запрос UAC, никаких окон с «OK»), а не забрасывает
    # пользователя сообщениями. Каждая запись: {"file", "title", "kind",
    # "args", "dlls", "arch"}.
    runtime_installers: List[Dict[str, str]] = field(default_factory=list)
    # --- завершение сеанса ---------------------------------------------------
    # Сколько секунд лончер ждёт запуска настоящей программы, если сначала
    # стартовал официальный launcher/splash.
    shutdown_spawn_grace: float = 6.0
    # Сколько секунд процессу ИЗ ПОРТАТИВА без единого видимого окна
    # позволено удерживать сеанс. Ровно из-за этого пункта раньше нельзя было
    # удалить папку: программа закрыта, а её апдейтер/крэш-хендлер продолжал
    # работать в фоне, и лончер (лежащий в App) ждал его сутки.
    shutdown_idle_grace: float = 20.0
    # Пауза между вежливым WM_CLOSE и принудительным завершением.
    shutdown_close_grace: float = 5.0
    # Потолок одного сеанса, секунды.
    shutdown_max_wait: float = 86400.0
    # Добивать то, что не закрылось само. Выключать стоит только при отладке:
    # без этого папка снова может остаться заблокированной.
    shutdown_kill_leftovers: bool = True
    # Разбирать ли открытые файлы папки (таблица дескрипторов ядра). Это
    # единственный способ отпустить файл, который держит системная служба
    # (кэш шрифтов и `PortableData\Temp\is-XXXX.tmp` — типичный случай).
    shutdown_deep_check: bool = True
    # Сколько секунд отводится на обход дескрипторов: лучше неполный
    # разбор, чем лончер, который не выходит.
    shutdown_handle_budget: float = 8.0
    # Чистить ли PortableData\Temp между запусками: распакованное туда
    # установщиками и держит потом папку.
    shutdown_purge_temp: bool = True
    # --- сквозные сохранения -------------------------------------------------
    # Описание общего хранилища сейвов (см. core/saves.py). Прямой запуск
    # App\Game.exe получает настоящий профиль Windows, а лончер —
    # перенаправленный: без этой секции каждый способ запуска видел бы свои
    # собственные сохранения. Структура: {"enabled", "mode", "store",
    # "entries": [...], "discovery": {...}}.
    shared_saves: Dict[str, object] = field(default_factory=dict)
    # --- единый редактируемый INI Gamebryo -----------------------------------
    # Отдельная схема для Fallout.ini/FalloutPrefs.ini: официальный launcher
    # Bethesda иногда пишет их в Documents, даже когда игра читает App. Поле
    # описывает канонический файл и его портативные профильные копии.
    game_settings: Dict[str, object] = field(default_factory=dict)
    # --- защита от карусели официального launcher'а --------------------------
    # Если launcher не может записать INI, он закрывается и запускает себя
    # снова. EXE-лончер ловит это, лечит INI и запускает игру напрямую.
    loop_guard_enabled: bool = True
    loop_guard_max_restarts: int = 3
    loop_guard_window: float = 120.0
    loop_guard_relaunch_grace: float = 10.0
    loop_guard_poll_interval: float = 0.5


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


def _ascii_token(value: str) -> str:
    """Готовит имя файла/ссылку к подстановке в .bat литералом.

    Символы, которые cmd.exe считает операторами, просто удаляются: имя DLL
    и адрес пакета их не содержат, а случайный мусор не должен ломать разбор.
    """
    cleaned = "".join(ch for ch in str(value) if ch in _ASCII_OK)
    for ch in '"%&|<>^()\r\n\t':
        cleaned = cleaned.replace(ch, "")
    return cleaned.strip()


def _runtime_check_block(cfg: LauncherConfig) -> str:
    """Предстартовая проверка распространяемых компонентов.

    Список формируется при сборке: в него попадает то, что Portablizer НЕ
    смог принести в портатив, плюс зонды работоспособности доставленных
    сборок VC++ 2005/2008. Если на целевом ПК библиотеки нет, пользователь
    увидит название пакета и ссылку, а не системное окно «Запуск программы
    невозможен: отсутствует MSVCR110.dll» — а после тихой установки пакета
    проверка повторяется, так что «установлено» не объявляется, пока файлы
    реально не появились.
    """
    calls: List[str] = []
    has_sxs = False
    for item in cfg.runtime_requirements[:MAX_RUNTIME_CHECKS]:
        dll = _ascii_token(item.get("dll", ""))
        if not dll:
            continue
        title = ascii_display(item.get("title", ""),
                              fallback="Microsoft runtime package")
        url = _ascii_token(item.get("url", ""))
        manifest = _ascii_token(item.get("manifest", ""))
        family = _ascii_token(item.get("sxs_family", ""))
        if not (manifest and family):
            manifest = ""
            family = ""
        else:
            has_sxs = True
        calls.append(
            f'call :portable_need_dll "{dll}" "{title}" "{url}" '
            f'"{manifest}" "{family}"')
    if not calls:
        return ("rem (this program needs no extra Microsoft runtime "
                "components)\ngoto :eof")
    script = f"%PORTABLE_ROOT%\\{REDIST_DIR_NAME}\\{REDIST_SCRIPT_NAME}"
    lines = ['set "PORTABLE_RUNTIME_MISSING="']
    lines += calls
    lines += [
        "if not defined PORTABLE_RUNTIME_MISSING goto :eof",
        # Пакеты лежат рядом - ставим их молча: один запрос прав вместо
        # череды окон установщика с кнопкой OK.
        f'if not exist "{script}" goto portable_runtime_manual',
        "echo   Installing the missing packages silently from the "
        f"{REDIST_DIR_NAME} folder...",
        f'call "{script}"',
        # Молчаливой установке install-скрипт сообщить о результате не может
        # (его повторный запуск с UAC - отдельный процесс), поэтому итог
        # проверяем самым надёжным способом: ищем файлы ещё раз. Только
        # появившиеся реально библиотеки позволяют сказать «готово».
        'set "PORTABLE_RUNTIME_MISSING="',
    ]
    lines += calls
    lines += [
        "if defined PORTABLE_RUNTIME_MISSING goto portable_runtime_manual",
        "echo   The packages are in place now - starting the program.",
        "echo.",
        "goto :eof",
        ":portable_runtime_manual",
        "echo   Details and download links: redistributables.txt",
    ]
    if has_sxs:
        lines += [
            "echo   The missing parts are Visual C++ 2005/2008 side-by-side",
            "echo   assemblies. Windows error 14001 - side-by-side",
            "echo   configuration is incorrect - means exactly this problem:",
            "echo   install the package above, or run "
            f"{REDIST_DIR_NAME}\\{REDIST_SCRIPT_NAME} manually.",
        ]
    lines += [
        "echo   The program may still start: some components load on demand.",
        "echo.",
        "goto :eof",
    ]
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
    initial = '%PORTABLE_ROOT%\\' + _bat_set_value(cfg.reg_file_name)
    machine = '%PORTABLE_ROOT%\\' + _bat_set_value(cfg.machine_reg_file_name)
    lines += [
        'if defined PORTABLE_SESSION_FOUND (',
        '  rem Always seed required HKLM install data. A previous normal game',
        '  rem run may have saved only HKCU/VirtualStore files; skipping the',
        '  rem machine seed made a later Configurator still see no installation.',
        f'  if exist "{machine}" call :portable_registry_import "{machine}"',
        '  for %%F in ("%PORTABLE_REG_SESSION%\\*.reg") do '
        'call :portable_registry_import "%%~fF"',
        '  goto :eof',
        ')',
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


def _machine_elevation_block(cfg: LauncherConfig) -> str:
    """UAC только для целей, которым действительно нужен захваченный HKLM."""
    if not cfg.machine_reg_file_name:
        return "goto :eof"
    machine = _bat_set_value(cfg.machine_reg_file_name)
    # Old games read their own install path from HKLM and exit with code 1 when
    # it is missing (The Witcher and other GOG re-releases behave exactly like
    # that). VirtualStore only helps un-manifested programs, so when the
    # captured HKLM keys are really absent here, the machine file must be
    # imported for real - which needs administrator rights for this run.
    machine_keys = [
        key for key in consolidate_root_keys(cfg.registry_keys)
        if key.upper().startswith("HKLM\\") or key.upper().startswith("HKEY_LOCAL_MACHINE\\")
    ]
    probe: List[str] = []
    if machine_keys:
        probe.append(f'if exist "%PORTABLE_ROOT%\\{machine}" (')
        for key in machine_keys:
            probe.append(
                f'  reg query "{key}" >nul 2>&1 || '
                'set "PORTABLE_MACHINE_REGISTRY=1"'
            )
        probe.append(')')
    return "\n".join([
        *probe,
        'if not defined PORTABLE_MACHINE_REGISTRY goto :eof',
        'if defined PORTABLE_ELEVATED goto :eof',
        f'if not exist "%PORTABLE_ROOT%\\{machine}" goto :eof',
        'net session >nul 2>&1',
        'if not errorlevel 1 goto :eof',
        'set "PORTABLE_SELF=%~f0"',
        'set "PORTABLE_ELEVATION_TARGET=%PORTABLE_TARGET%"',
        'echo This portable program keeps its installation entries in the',
        'echo machine registry (HKLM); on this PC those entries are missing.',
        'echo Requesting administrator rights for this run only...',
        'powershell -NoProfile -ExecutionPolicy Bypass -Command "$q=[char]34; $a=\'/d /c call \'+$q+$env:PORTABLE_SELF+$q+\' --nopause --elevated --machine-registry --target \'+$q+$env:PORTABLE_ELEVATION_TARGET+$q; $p=Start-Process -FilePath $env:ComSpec -ArgumentList $a -Verb RunAs -WindowStyle Normal -Wait -PassThru; exit $p.ExitCode"',
        'set "PORTABLE_RELAUNCH_RC=%ERRORLEVEL%"',
        'set "PORTABLE_RELAUNCHED=1"',
        'if "%PORTABLE_RELAUNCH_RC%" == "0" goto :eof',
        'echo.',
        'if "%PORTABLE_RELAUNCH_RC%" == "1223" goto portable_relaunch_declined',
        'if "%PORTABLE_RELAUNCH_RC%" == "14001" goto portable_relaunch_sxs',
        'echo [ERROR] The elevated run finished with exit code '
        '%PORTABLE_RELAUNCH_RC%.',
        'echo Administrator rights WERE granted for that run, so this is not',
        'echo a permission problem: the program itself failed to start.',
        'echo Run this file from an already open cmd window to read the exact',
        'echo error message the program printed above, and see portablizer.log',
        'echo and PortableData for details.',
        'goto portable_relaunch_failed',
        ':portable_relaunch_declined',
        'echo [ERROR] Administrator rights were declined at the UAC prompt.',
        'echo They are needed only to import the captured installation entries',
        'echo into the machine registry (HKLM) for this single run. Without',
        'echo them this program cannot find its own install data and quits.',
        'echo Run again and allow the request - or use --no-registry.',
        'goto portable_relaunch_failed',
        ':portable_relaunch_sxs',
        'echo [ERROR] Windows refused to start the program (error 14001):',
        'echo the side-by-side configuration is incorrect. The Visual C++',
        'echo 2005/2008 runtime this program was built with is missing here.',
        f'echo Fix: run {REDIST_DIR_NAME}\\{REDIST_SCRIPT_NAME} from this folder - it puts',
        'echo the needed packages in silently. Without that package the',
        'echo program cannot start at all. Details: redistributables.txt.',
        ':portable_relaunch_failed',
        'if not "%PORTABLE_PAUSE%" == "never" pause',
        'goto :eof',
    ])


_DOCUMENTS_USER_KEY = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)
_DOCUMENTS_LEGACY_KEY = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
)
_DOCUMENTS_GUID = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"


def _documents_load_block(cfg: LauncherConfig) -> str:
    """Временно направляет WinAPI Known Folder Documents внутрь портатива."""
    if not cfg.redirect_known_folders:
        return "goto :eof"
    return "\n".join([
        'set "PORTABLE_DOC_USER_BACKUP=%PORTABLE_REG_BACKUP%\\shell-user.reg"',
        'set "PORTABLE_DOC_LEGACY_BACKUP=%PORTABLE_REG_BACKUP%\\shell-legacy.reg"',
        'rem Recover an interrupted previous run before taking a new backup.',
        'if exist "%PORTABLE_DOC_USER_BACKUP%" call :portable_documents_restore',
        'if not defined PORTABLE_REGISTRY goto :eof',
        f'reg export "{_DOCUMENTS_USER_KEY}" "%PORTABLE_DOC_USER_BACKUP%" /y >nul 2>&1',
        'if not exist "%PORTABLE_DOC_USER_BACKUP%" goto :eof',
        f'reg add "{_DOCUMENTS_USER_KEY}" /v "Personal" /t REG_EXPAND_SZ /d "%PORTABLE_DOCUMENTS%" /f >nul 2>&1',
        f'reg add "{_DOCUMENTS_USER_KEY}" /v "{_DOCUMENTS_GUID}" /t REG_EXPAND_SZ /d "%PORTABLE_DOCUMENTS%" /f >nul 2>&1',
        f'reg export "{_DOCUMENTS_LEGACY_KEY}" "%PORTABLE_DOC_LEGACY_BACKUP%" /y >nul 2>&1',
        'if exist "%PORTABLE_DOC_LEGACY_BACKUP%" (',
        f'  reg add "{_DOCUMENTS_LEGACY_KEY}" /v "Personal" /t REG_SZ /d "%PORTABLE_DOCUMENTS%" /f >nul 2>&1',
        f'  reg add "{_DOCUMENTS_LEGACY_KEY}" /v "{_DOCUMENTS_GUID}" /t REG_SZ /d "%PORTABLE_DOCUMENTS%" /f >nul 2>&1',
        ')',
        'goto :eof',
    ])


def _documents_restore_block(cfg: LauncherConfig) -> str:
    if not cfg.redirect_known_folders:
        return "goto :eof"
    return "\n".join([
        'if not defined PORTABLE_DOC_USER_BACKUP set "PORTABLE_DOC_USER_BACKUP=%PORTABLE_REG_BACKUP%\\shell-user.reg"',
        'if not defined PORTABLE_DOC_LEGACY_BACKUP set "PORTABLE_DOC_LEGACY_BACKUP=%PORTABLE_REG_BACKUP%\\shell-legacy.reg"',
        'if exist "%PORTABLE_DOC_USER_BACKUP%" (',
        f'  reg delete "{_DOCUMENTS_USER_KEY}" /v "Personal" /f >nul 2>&1',
        f'  reg delete "{_DOCUMENTS_USER_KEY}" /v "{_DOCUMENTS_GUID}" /f >nul 2>&1',
        '  reg import "%PORTABLE_DOC_USER_BACKUP%" >nul 2>&1',
        '  del /f /q "%PORTABLE_DOC_USER_BACKUP%" >nul 2>&1',
        ')',
        'if exist "%PORTABLE_DOC_LEGACY_BACKUP%" (',
        f'  reg delete "{_DOCUMENTS_LEGACY_KEY}" /v "Personal" /f >nul 2>&1',
        f'  reg delete "{_DOCUMENTS_LEGACY_KEY}" /v "{_DOCUMENTS_GUID}" /f >nul 2>&1',
        '  reg import "%PORTABLE_DOC_LEGACY_BACKUP%" >nul 2>&1',
        '  del /f /q "%PORTABLE_DOC_LEGACY_BACKUP%" >nul 2>&1',
        ')',
        'goto :eof',
    ])


#: Максимум записей сквозных сохранений, обслуживаемых BAT-лончером. Всё
#: остальное делает LaunchPortable.exe: он умеет и поиск новых папок, и
#: сравнение по времени файла, а не целого каталога.
MAX_SAVE_ENTRIES = 12


def _bat_save_paths(entry: Dict[str, object]) -> "tuple":
    """(хранилище, спутники) в терминах переменных BAT — или ничего."""
    store = str(entry.get("store", "")).replace("/", "\\").strip("\\")
    if not store or not is_ascii_safe(store):
        return "", []
    store_path = f"%PORTABLE_ROOT%\\{store}"
    satellites: List[str] = []

    host = str(entry.get("host", "")).replace("/", "\\").strip("\\")
    if host and is_ascii_safe(host):
        head, _, tail = host.partition("\\")
        if head.lower() == "documents":
            satellites.append(f"%PORTABLE_HOST_DOCUMENTS%\\{tail}"
                              if tail else "%PORTABLE_HOST_DOCUMENTS%")
        else:
            satellites.append(f"%PORTABLE_HOST_PROFILE%\\{host}")

    portable = str(entry.get("portable", "")).replace("/", "\\").strip("\\")
    if portable and is_ascii_safe(portable):
        satellites.append(f"%PORTABLE_ROOT%\\{portable}")
    return store_path, satellites


def _bat_copy_lines(source: str, destination: str,
                    patterns: Sequence[str]) -> List[str]:
    """xcopy /D копирует только то, что новее приёмника, — это и нужно."""
    lines: List[str] = []
    usable = [str(p).replace("/", "\\").strip("\\") for p in patterns
              if str(p) and is_ascii_safe(str(p))]
    if not usable:
        lines.append(
            f'if exist "{source}\\" xcopy "{source}" "{destination}\\" '
            "/D /E /I /Y /Q >nul 2>&1")
        return lines
    for pattern in usable:
        if any(ch in pattern for ch in "*?"):
            lines.append(
                f'if exist "{source}\\" xcopy "{source}\\{pattern}" '
                f'"{destination}\\" /D /Y /Q >nul 2>&1')
        else:
            lines.append(
                f'if exist "{source}\\{pattern}\\" xcopy '
                f'"{source}\\{pattern}" "{destination}\\{pattern}\\" '
                "/D /E /I /Y /Q >nul 2>&1")
    return lines


def _safe_game_settings(cfg: LauncherConfig) -> "tuple":
    """Возвращает безопасные для CMD пути единого Gamebryo INI.

    Конфиг портатива может редактироваться вручную, поэтому BAT не должен
    подставлять из него ``..``/абсолютный путь или metacharacters. EXE-лончер
    проводит такую же валидацию перед записью на диск.
    """
    raw = cfg.game_settings if isinstance(cfg.game_settings, dict) else {}
    if not raw.get("enabled"):
        return "", "", [], []

    def relative(value: object) -> str:
        item = str(value or "").replace("/", "\\").strip("\\")
        if (not item or not is_ascii_safe(item) or ":" in item
                or any(part in ("", ".", "..") for part in item.split("\\"))):
            return ""
        return item

    store = relative(raw.get("store", ""))
    default_ini = relative(raw.get("default_ini", ""))
    # Names may only be direct children of the game directory.
    if not store or not default_ini or "\\" in default_ini:
        return "", "", [], []
    names: List[str] = []
    user_inis = raw.get("user_inis")
    if isinstance(user_inis, list):
        for value in user_inis[:12]:
            name = relative(value)
            if name and "\\" not in name and name.lower().endswith(".ini") \
                    and name.lower() not in {n.lower() for n in names}:
                names.append(name)
    profiles: List[str] = []
    raw_profiles = raw.get("profile_dirs")
    if isinstance(raw_profiles, list):
        for value in raw_profiles[:12]:
            profile = relative(value)
            if profile and profile.lower() not in {p.lower() for p in profiles}:
                profiles.append(profile)
    return store, default_ini, names, profiles


def _settings_repair_block(cfg: LauncherConfig) -> str:
    """BAT fallback: create writable profile-compatible copies of Fallout.ini."""
    store, default_ini, names, profiles = _safe_game_settings(cfg)
    if not store or not default_ini or not names:
        return "goto :eof"
    base = f"%PORTABLE_ROOT%\\{store}"
    template = f"{base}\\{default_ini}"
    lines = [
        "rem Keep the canonical editable game INI next to the executable.",
        "rem Bethesda launchers occasionally insist on a Documents copy; it is",
        "rem prepared from App before start so it cannot reject a write or reset it.",
        f'attrib -r "{template}" >nul 2>&1',
    ]
    for index, name in enumerate(names):
        canonical = f"{base}\\{name}"
        # Keep the seed branch flat. Apart from being easier to diagnose in a
        # user-edited BAT, this also works in the deliberately small BAT
        # interpreter used by the regression suite.
        seed_done = f"portable_settings_seed_done_{index}"
        lines += [
            f'attrib -r "{canonical}" >nul 2>&1',
            f'if exist "{canonical}" goto :{seed_done}',
            f'if exist "{template}" copy /y "{template}" "{canonical}" >nul 2>&1',
            f':{seed_done}',
            f'attrib -r "{canonical}" >nul 2>&1',
        ]
        for profile in profiles:
            satellite = f"%PORTABLE_ROOT%\\{profile}\\{name}"
            directory = f"%PORTABLE_ROOT%\\{profile}"
            lines += [
                f'if not exist "{directory}\\" md "{directory}" >nul 2>&1',
                f'attrib -r "{satellite}" >nul 2>&1',
                # App is authoritative before the process starts. Do not use
                # /D here: FAT/ZIP timestamp granularity can make a manual
                # edit look equally old and leave the launcher with stale INI.
                f'if exist "{canonical}" copy /y "{canonical}" "{satellite}" '
                ">nul 2>&1",
                f'attrib -r "{satellite}" >nul 2>&1',
            ]
    lines.append("goto :eof")
    return "\n".join(lines)


def _settings_adopt_block(cfg: LauncherConfig) -> str:
    """BAT fallback: accept only a newer profile copy after official launcher."""
    store, _default_ini, names, profiles = _safe_game_settings(cfg)
    if not store or not names or not profiles:
        return "goto :eof"
    base = f"%PORTABLE_ROOT%\\{store}"
    lines = [
        "rem A settings dialog may have changed the portable Documents copy.",
        "rem xcopy /D adopts it only when it is newer than the App original.",
    ]
    for name in names:
        canonical_dir = base
        canonical = f"{canonical_dir}\\{name}"
        for profile in profiles:
            satellite = f"%PORTABLE_ROOT%\\{profile}\\{name}"
            lines += [
                f'attrib -r "{canonical}" >nul 2>&1',
                f'if exist "{satellite}" xcopy "{satellite}" "{canonical_dir}\\" '
                "/D /Y /Q >nul 2>&1",
                f'attrib -r "{canonical}" >nul 2>&1',
            ]
    lines.append("goto :eof")
    return "\n".join(lines)


def _saves_block(cfg: LauncherConfig, direction: str) -> str:
    """Сведение сохранений в запасном BAT-лончере.

    ``direction='in'``  — забрать в портатив то, что появилось мимо лончера
    (прямой запуск ``App\\Game.exe`` пишет в настоящий профиль Windows).
    ``direction='out'`` — вернуть обновлённое наружу для записей с
    двусторонним обменом, чтобы прямой запуск увидел новые сейвы.
    """
    data = cfg.shared_saves or {}
    if not data.get("enabled"):
        return "goto :eof"
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        return "goto :eof"

    lines: List[str] = []
    for entry in raw_entries[:MAX_SAVE_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        if direction == "out" and str(entry.get("direction", "both")) != "both":
            continue
        store, satellites = _bat_save_paths(entry)
        if not store or not satellites:
            continue
        patterns = entry.get("patterns")
        patterns = [str(p) for p in patterns] if isinstance(patterns, list) \
            else []
        # Gamebryo INI has a dedicated one-writer guard. Treating it as a
        # generic save here would let an old Documents copy overwrite a manual
        # edit of App\Fallout.ini before the guard can arbitrate it.
        if _safe_game_settings(cfg)[0]:
            patterns = [p for p in patterns if not p.lower().endswith(".ini")]
        for satellite in satellites:
            source, destination = ((satellite, store) if direction == "in"
                                   else (store, satellite))
            lines.extend(_bat_copy_lines(source, destination, patterns))
    if not lines:
        return "goto :eof"
    header = ("rem Take into the portable folder everything that was saved "
              "past this launcher." if direction == "in"
              else "rem Hand the updated files back so a direct start of the "
                   "EXE sees them too.")
    return "\n".join([header, *lines, "goto :eof"])


_BAT_TEMPLATE = r"""@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Prefer the windowed EXE launcher when it is available. Launch.bat remains
rem a full console fallback for recovery/debugging; force it with --bat-fallback.
set "PORTABLE_USE_EXE_LAUNCHER=1"
if /i "%~1" == "--bat-fallback" (
  set "PORTABLE_USE_EXE_LAUNCHER="
  shift
)
if /i "%~1" == "--help" set "PORTABLE_USE_EXE_LAUNCHER="
if /i "%~1" == "/?" set "PORTABLE_USE_EXE_LAUNCHER="
if /i "%~1" == "--list" set "PORTABLE_USE_EXE_LAUNCHER="
if /i "%~1" == "--menu" set "PORTABLE_USE_EXE_LAUNCHER="
if /i "%~1" == "--pause" set "PORTABLE_USE_EXE_LAUNCHER="
if /i "%~1" == "--nopause" set "PORTABLE_USE_EXE_LAUNCHER="
if /i "%~1" == "--no-registry" set "PORTABLE_USE_EXE_LAUNCHER="
if /i "%~1" == "--keep-registry" set "PORTABLE_USE_EXE_LAUNCHER="
if /i "%~1" == "--reset" set "PORTABLE_USE_EXE_LAUNCHER="
if "%~1" == "--" set "PORTABLE_USE_EXE_LAUNCHER="
if defined PORTABLE_USE_EXE_LAUNCHER if exist "%~dp0App\LaunchPortable.exe" (
  start "" "%~dp0App\LaunchPortable.exe" %*
  endlocal
  exit /b 0
)
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
rem      --bat-fallback    force this console BAT instead of LaunchPortable.exe
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
set "PORTABLE_MACHINE_REGISTRY="
set "PORTABLE_ELEVATED="

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
if /i "%~1" == "--bat-fallback" (
  shift
  goto portable_parse
)
if /i "%~1" == "--menu" (
  set "PORTABLE_MENU=1"
  shift
  goto portable_parse
)
rem Internal switches used by generated companion launchers.
if /i "%~1" == "--machine-registry" (
  set "PORTABLE_MACHINE_REGISTRY=1"
  shift
  goto portable_parse
)
if /i "%~1" == "--elevated" (
  set "PORTABLE_ELEVATED=1"
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

rem --- The REAL profile of this PC, remembered before the redirect ----------
rem Shared saves need it: a direct start of the program inside App writes into
rem the real Documents folder, the launcher writes inside the portable folder.
rem Both have to end up in the same place, so the real path is captured here,
rem while the variables below still point at this computer.
set "PORTABLE_HOST_PROFILE=%USERPROFILE%"
set "PORTABLE_HOST_DOCUMENTS=%USERPROFILE%\Documents"
rem On modern Windows the Documents folder is often moved into OneDrive. The
rem EXE launcher asks the Known Folder API and is always right; this console
rem fallback checks the two usual places instead.
if not exist "%PORTABLE_HOST_DOCUMENTS%\" if exist "%USERPROFILE%\OneDrive\Documents\" set "PORTABLE_HOST_DOCUMENTS=%USERPROFILE%\OneDrive\Documents"
if not exist "%PORTABLE_HOST_DOCUMENTS%\" if defined OneDrive if exist "%OneDrive%\Documents\" set "PORTABLE_HOST_DOCUMENTS=%OneDrive%\Documents"

rem --- Redirect the user profile into the portable folder --------------------
set "APPDATA=%PORTABLE_DATA%\AppData\Roaming"
set "LOCALAPPDATA=%PORTABLE_DATA%\AppData\Local"
set "USERPROFILE=%PORTABLE_DATA%\User"
set "TEMP=%PORTABLE_DATA%\Temp"
set "TMP=%PORTABLE_DATA%\Temp"
set "PROGRAMDATA=%PORTABLE_DATA%\ProgramData"
set "PUBLIC=%PORTABLE_DATA%\Public"
set "PORTABLE_DOCUMENTS=%PORTABLE_DATA%\User\Documents"
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

for %%I in ("%PORTABLE_TARGET%") do set "PORTABLE_TARGET_DIR=%%~dpI"

rem --- Captured HKLM data: elevation FIRST, before anything that needs it ---
rem Old games read their install folder from HKLM and quit silently when it is
rem missing, and VirtualStore does not help manifest-aware programs. When the
rem captured machine keys really are absent here, this run is relaunched once
rem through UAC - and the elevated copy then performs every privileged step
rem (silent runtime install included) with no second prompt.
call :portable_elevate_for_machine
if defined PORTABLE_RELAUNCHED (
  endlocal & exit /b %PORTABLE_RELAUNCH_RC%
)

rem --- Microsoft runtime components (VC++, DirectX, ...) ---------------------
rem Windows only reports "the program can't start because MSVCR110.dll is
rem missing" after the fact; an invalid side-by-side setup reports even later,
rem as error 14001 at start. The check below names the package instead and
rem silently repairs what it can.
call :portable_check_runtime

call :portable_settings_repair
call :portable_saves_import
call :portable_documents_load
call :portable_registry_load

pushd "%PORTABLE_TARGET_DIR%" 2>nul
echo Starting {title} from the portable folder...
"%PORTABLE_TARGET%" {target_args}%PORTABLE_ARGS%
set "PORTABLE_RC=%ERRORLEVEL%"
popd

rem Official launchers (game launcher windows, GOG splash screens) start the
rem real program and exit immediately. Restoring the registry at that moment
rem would pull the install keys out from under the program that is just
rem starting, so wait while anything from this folder is still running.
call :portable_wait_children

call :portable_registry_save
call :portable_documents_restore
call :portable_saves_export
call :portable_settings_adopt
call :portable_settings_repair

rem Error 14001 deserves its own explanation: it is never about registry or
rem rights, it is the missing Visual C++ runtime the program was built with.
if "%PORTABLE_RC%" == "14001" (
  echo.
  echo [ERROR 14001] Windows could not apply the program's side-by-side
  echo configuration. The Visual C++ 2005/2008 runtime the program was built
  echo with is not available to it, so it did not start at all.
  echo Fix once: run {redist_dir}\{redist_script} from this folder - it puts
  echo the needed packages in silently, with a single UAC prompt.
  echo Details and download links: redistributables.txt
)
if not "%PORTABLE_RC%" == "0" if not "%PORTABLE_RC%" == "14001" (
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
echo     --bat-fallback    force this console BAT instead of LaunchPortable.exe
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

:portable_check_runtime
{runtime_check}

:portable_need_dll
rem %1 = library, %2 = package that provides it, %3 = where to get it,
rem %4 = private assembly manifest (VC++ 2005/2008 only), %5 = WinSxS probe.
rem A library next to the program or in the Windows folders is fine; only a
rem really missing one is reported.
if not "%~5" == "" goto portable_need_sxs_dll
if exist "%PORTABLE_TARGET_DIR%%~1" goto :eof
if exist "%PORTABLE_ROOT%\App\%~1" goto :eof
if exist "%SystemRoot%\System32\%~1" goto :eof
if exist "%SystemRoot%\SysWOW64\%~1" goto :eof
goto portable_need_dll_missing
:portable_need_sxs_dll
rem VC++ 2005/2008 exist ONLY as side-by-side assemblies: their files never
rem live in System32, a bare DLL next to the program is ignored by Windows
rem unless a matching private manifest sits beside it, and a DLL without that
rem manifest produces error 14001, not a "file not found" box. So check the
rem manifest + library pair first, and the WinSxS folders by wildcard.
if exist "%PORTABLE_TARGET_DIR%%~4" if exist "%PORTABLE_TARGET_DIR%%~1" goto :eof
if exist "%PORTABLE_ROOT%\App\%~4" if exist "%PORTABLE_ROOT%\App\%~1" goto :eof
if exist "%SystemRoot%\WinSxS\%~5*" goto :eof
:portable_need_dll_missing
if not defined PORTABLE_RUNTIME_MISSING (
  echo.
  echo [WARNING] This PC is missing Microsoft runtime components:
)
set "PORTABLE_RUNTIME_MISSING=1"
echo   - %~1 : %~2
if not "%~3" == "" echo     %~3
goto :eof

:portable_elevate_for_machine
{machine_elevation}

:portable_wait_children
rem Waits while the program is really being used, then frees the folder.
rem
rem Two rules, and the second one is what makes the folder deletable again:
rem   * a process from this folder that owns a visible window means the user
rem     is still working - wait as long as it takes;
rem   * a process WITHOUT any window (updater, crash handler, silent helper)
rem     only gets PORTABLE_IDLE_GRACE seconds. Afterwards it is asked to close
rem     and then terminated. Otherwise it would keep running in the background
rem     after the program was closed, and Windows would refuse to delete the
rem     portable folder.
if not defined PORTABLE_IDLE_GRACE set "PORTABLE_IDLE_GRACE={idle_grace}"
if not defined PORTABLE_KILL_LEFTOVERS set "PORTABLE_KILL_LEFTOVERS={kill_leftovers}"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$r=$env:PORTABLE_ROOT.TrimEnd('\')+'\'; function GetPortableProcesses(){{ $a=@(); foreach($p in [Diagnostics.Process]::GetProcesses()){{ if($p.Id -ne $PID){{ $f=''; try{{ $f=$p.Path }}catch{{ $f='' }}; if($f -and $f.StartsWith($r,[StringComparison]::OrdinalIgnoreCase)){{ $a+=$p }} }} }}; return $a }}; $grace=8; $idle=[int]$env:PORTABLE_IDLE_GRACE; if($idle -le 0){{ $idle=20 }}; $t=0; $seen=$false; $q=0; while($t -lt 86400){{ $ps=@(GetPortableProcesses); if($ps.Count -gt 0){{ $seen=$true; $vis=0; foreach($p in $ps){{ if($p.MainWindowHandle.ToInt64() -ne 0){{ $vis++ }} }}; if($vis -gt 0){{ $q=0 }} else {{ $q++; if($q -ge $idle){{ break }} }} }} elseif($seen -or $t -ge $grace){{ break }}; Start-Sleep -Seconds 1; $t++ }}; if($env:PORTABLE_KILL_LEFTOVERS -eq '0'){{ exit 0 }}; $ps=@(GetPortableProcesses); if($ps.Count -gt 0){{ foreach($p in $ps){{ try{{ [void]$p.CloseMainWindow() }}catch{{}} }}; Start-Sleep -Seconds 3; foreach($p in @(GetPortableProcesses)){{ try{{ $p.Kill() }}catch{{}} }} }}" >nul 2>&1
rem The temp folder of the portable app must not outlive the session: the
rem files installers unpack there (fonts above all) are picked up by Windows
rem services and keep the whole folder locked long after the program is gone.
if exist "%PORTABLE_ROOT%\{data_dir}\Temp" rd /s /q "%PORTABLE_ROOT%\{data_dir}\Temp" >nul 2>&1
if not exist "%PORTABLE_ROOT%\{data_dir}\Temp" md "%PORTABLE_ROOT%\{data_dir}\Temp" >nul 2>&1
goto :eof

:portable_settings_repair
{settings_repair}

:portable_settings_adopt
{settings_adopt}

:portable_saves_import
{saves_import}

:portable_saves_export
{saves_export}

:portable_documents_load
{documents_load}

:portable_documents_restore
{documents_restore}

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
            '  set "PORTABLE_MACHINE_REGISTRY=1"\n'
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
            '  set "PORTABLE_MACHINE_REGISTRY=1"\n'
            '  shift\n'
            '  goto portable_parse\n'
            ')\n'
            'if /i "%~1" == "--settings" (\n'
            f'  set "PORTABLE_CUSTOM_TARGET={_bat_set_value(config_rel)}"\n'
            '  set "PORTABLE_MACHINE_REGISTRY=1"\n'
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
        ]
        if target.role != "main":
            choice_branches.append('  set "PORTABLE_MACHINE_REGISTRY=1"')
        choice_branches += [
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
        machine_elevation=_machine_elevation_block(cfg),
        saves_import=_saves_block(cfg, "in"),
        saves_export=_saves_block(cfg, "out"),
        settings_repair=_settings_repair_block(cfg),
        settings_adopt=_settings_adopt_block(cfg),
        documents_load=_documents_load_block(cfg),
        documents_restore=_documents_restore_block(cfg),
        runtime_check=_runtime_check_block(cfg),
        redist_dir=REDIST_DIR_NAME,
        redist_script=REDIST_SCRIPT_NAME,
        idle_grace=int(max(1, round(cfg.shutdown_idle_grace))),
        kill_leftovers="1" if cfg.shutdown_kill_leftovers else "0",
        data_dir=data_dir,
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
If fso.FileExists(root & "\\App\\LaunchPortable.exe") Then
    line = Chr(34) & root & "\\App\\LaunchPortable.exe" & Chr(34) & args
Else
    line = Chr(34) & root & "\\Launch.bat" & Chr(34) & " --nopause" & args
End If
shell.Run line, 0, False
"""


def render_vbs() -> str:
    return ensure_ascii_bat(_VBS_TEMPLATE)


def config_from_dict(data: Dict[str, object]) -> LauncherConfig:
    """Восстанавливает ``LauncherConfig`` из готового ``launcher_config.json``.

    Нужно для обслуживания уже собранного портатива: чтобы перевыпустить его
    лончер новой версией, надо знать, чем он был собран. Разбор намеренно
    терпимый — конфиг мог быть создан прежней версией Portablizer, в которой
    части полей ещё не существовало (например, секции ``shutdown``).
    """
    def text(key: str, default: str = "") -> str:
        value = data.get(key, default)
        return value if isinstance(value, str) else default

    def items(key: str) -> List[str]:
        value = data.get(key)
        return [str(v) for v in value] if isinstance(value, list) else []

    def mapping(key: str) -> Dict[str, str]:
        value = data.get(key)
        if not isinstance(value, dict):
            return {}
        return {str(k): str(v) for k, v in value.items()}

    registry = data.get("registry")
    registry = registry if isinstance(registry, dict) else {}
    shutdown = data.get("shutdown")
    shutdown = shutdown if isinstance(shutdown, dict) else {}
    loop_guard = data.get("loop_guard")
    loop_guard = loop_guard if isinstance(loop_guard, dict) else {}

    def finite_number(value: object, default: float) -> float:
        try:
            number_value = float(value)
        except (TypeError, ValueError):
            return default
        return number_value if math.isfinite(number_value) else default

    def number(key: str, default: float) -> float:
        return finite_number(shutdown.get(key, default), default)

    def loop_number(key: str, default: float) -> float:
        return finite_number(loop_guard.get(key, default), default)

    targets: List[TargetInfo] = []
    raw_targets = data.get("targets")
    if isinstance(raw_targets, list):
        for item in raw_targets:
            if not isinstance(item, dict):
                continue
            targets.append(TargetInfo(
                name=str(item.get("name", "")),
                rel_path=str(item.get("rel_path", "")),
                role=str(item.get("role", "main")),
                description=str(item.get("description", "")),
                bat_name=str(item.get("bat_name", "")),
                vbs_name=str(item.get("vbs_name", "")),
            ))

    def dict_list(key: str) -> List[Dict[str, str]]:
        value = data.get(key)
        if not isinstance(value, list):
            return []
        return [{str(k): str(v) for k, v in item.items()}
                for item in value if isinstance(item, dict)]

    return LauncherConfig(
        app_name=text("app_name", "Portable"),
        target_exe_rel=text("target_exe_rel"),
        target_args=items("target_args"),
        data_dir_name=text("data_dir_name", "PortableData"),
        apply_registry=bool(registry.get("enabled", False)),
        reg_file_name=str(registry.get("file", "portable.reg")),
        machine_reg_file_name=str(
            registry.get("machine_file", "portable_machine.reg")),
        registry_keys=[str(k) for k in registry.get("keys", [])
                       if isinstance(registry.get("keys", []), list)],
        registry_created_keys=[
            str(k) for k in registry.get("created_keys", [])
            if isinstance(registry.get("created_keys", []), list)],
        registry_has_root_token=bool(registry.get("root_token")),
        extra_env=mapping("extra_env"),
        path_prepend=items("path_prepend"),
        redirect_known_folders=bool(data.get("redirect_known_folders", False)),
        shared_saves=(data.get("shared_saves")
                      if isinstance(data.get("shared_saves"), dict) else {}),
        game_settings=(data.get("game_settings")
                       if isinstance(data.get("game_settings"), dict) else {}),
        loop_guard_enabled=loop_guard.get("enabled", True) is not False,
        loop_guard_max_restarts=max(1, int(loop_number("max_restarts", 3))),
        loop_guard_window=loop_number("window", 120.0),
        loop_guard_relaunch_grace=loop_number("relaunch_grace", 10.0),
        loop_guard_poll_interval=loop_number("poll_interval", 0.5),
        targets=targets,
        launcher_target_rel=text("launcher_target_rel"),
        config_target_rel=text("config_target_rel"),
        launcher_aliases=mapping("launcher_aliases"),
        runtime_requirements=dict_list("runtime_requirements"),
        runtime_installers=dict_list("runtime_installers"),
        shutdown_spawn_grace=number("spawn_grace", 6.0),
        shutdown_idle_grace=number("idle_grace", 20.0),
        shutdown_close_grace=number("close_grace", 5.0),
        shutdown_max_wait=number("max_wait", 86400.0),
        shutdown_kill_leftovers=bool(shutdown.get("kill_leftovers", True)),
        shutdown_deep_check=shutdown.get("deep_check", True) is not False,
        shutdown_handle_budget=number("handle_budget", 8.0),
        shutdown_purge_temp=shutdown.get("purge_temp", True) is not False,
    )


# --- StopPortable.cmd (освобождение папки) ------------------------------------

#: Имя аварийного «отпускателя» папки в корне портатива.
STOP_SCRIPT_NAME = "StopPortable.cmd"

_STOP_PS_FALLBACK = (
    "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
    "$r=$env:PORTABLE_ROOT.TrimEnd('\\')+'\\'; "
    "function Running(){{ $a=@(); foreach($p in [Diagnostics.Process]::GetProcesses()){{ "
    "if($p.Id -ne $PID){{ $f=''; try{{ $f=$p.Path }}catch{{ $f='' }}; "
    "if($f -and $f.StartsWith($r,[StringComparison]::OrdinalIgnoreCase)){{ $a+=$p }} }} }}; return $a }}; "
    "function Busy(){{ $b=@(); $sw=[Diagnostics.Stopwatch]::StartNew(); "
    "foreach($f in (Get-ChildItem -LiteralPath $r -Recurse -Force -ErrorAction SilentlyContinue | "
    "Where-Object {{ -not $_.PSIsContainer }})){{ "
    "if($sw.Elapsed.TotalSeconds -gt 20){{ break }}; "
    "try{{ $s=[IO.File]::Open($f.FullName,'Open','Read','None'); $s.Close() }}"
    "catch [IO.IOException]{{ $b+=$f.FullName; if($b.Count -ge 12){{ break }} }}catch{{}} }}; return $b }}; "
    "$ps=@(Running); foreach($p in $ps){{ Write-Host ('Closing ' + $p.ProcessName + ' (pid ' + $p.Id + ')'); "
    "try{{ [void]$p.CloseMainWindow() }}catch{{}} }}; "
    "if($ps.Count -gt 0){{ Start-Sleep -Seconds 3; foreach($p in @(Running)){{ try{{ $p.Kill() }}catch{{}} }}; Start-Sleep -Seconds 1 }}; "
    "$left=@(Running); if($left.Count -gt 0){{ foreach($p in $left){{ Write-Host ('Still running: ' + $p.ProcessName) }}; exit 1 }}; "
    "$tmp=Join-Path $r 'PortableData\Temp'; if(Test-Path -LiteralPath $tmp){{ "
    "Get-ChildItem -LiteralPath $tmp -Force -ErrorAction SilentlyContinue | "
    "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }}; "
    "$busy=@(Busy); if($busy.Count -gt 0){{ Start-Sleep -Seconds 1; $busy=@(Busy) }}; "
    "if($busy.Count -gt 0){{ Write-Host 'These files are still open and keep the folder locked:'; "
    "foreach($f in $busy){{ Write-Host ('  ' + $f) }}; exit 1 }}; "
    "Write-Host 'Nothing from this folder is running and no file inside is open.'; exit 0\""
)

_STOP_TEMPLATE = r"""@echo off
rem ============================================================================
rem  {title} - free this portable folder
rem
rem  Run this file when the program has been closed but Windows still refuses
rem  to delete or move the folder ("the file is open in another program").
rem
rem  What it does, in order:
rem    1. closes every process whose executable lives inside this folder -
rem       politely first, by force afterwards;
rem    2. forces every OPEN FILE inside the folder to be released, even when
rem       the holder is a Windows service (the font cache keeps fonts from
rem       PortableData\Temp open long after the installer is gone);
rem    3. wipes the leftovers in PortableData\Temp;
rem    4. PROVES the result by trying to open every file inside exclusively -
rem       and only then reports that the folder is free.
rem
rem  Step 2 needs administrator rights, so the script asks for them itself
rem  when the folder is still locked.  Nothing outside this folder is touched.
rem ============================================================================
setlocal
set "PORTABLE_ROOT=%~dp0"
if "%PORTABLE_ROOT:~-1%" == "\" set "PORTABLE_ROOT=%PORTABLE_ROOT:~0,-1%"
set "PORTABLE_SELF=%~f0"
set "STOP_ELEVATED="
set "STOP_PAUSE=1"
set "STOP_RC=0"
for %%A in (%*) do (
  if /i "%%~A" == "--elevated" set "STOP_ELEVATED=1"
  if /i "%%~A" == "--nopause" set "STOP_PAUSE="
)

if not exist "%PORTABLE_ROOT%\App\{exe_launcher}" goto fallback
rem The launcher knows how to free the folder AND how to prove it, and it
rem asks for administrator rights on its own when a handle has to be forced
rem closed.  Its verdict is final: no silent fallback to a weaker check.
"%PORTABLE_ROOT%\App\{exe_launcher}" --stop
if errorlevel 1 goto stillbusy
goto free

:fallback
{powershell}
if errorlevel 1 goto locked
goto free

:locked
if defined STOP_ELEVATED goto stillbusy
if not defined STOP_PAUSE goto stillbusy
echo.
echo Something still holds this folder. Most often it is a Windows service
echo (the font cache keeps a font from PortableData\Temp open), and only an
echo administrator can force such a handle closed. Asking for rights now...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=Start-Process -FilePath $env:PORTABLE_SELF -ArgumentList '--elevated' -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
if errorlevel 1 goto stillbusy
goto free

:stillbusy
echo.
echo The folder is STILL locked. The names above say who holds it:
echo   - a program with a window: close that window;
echo   - explorer.exe: close the folder window and the preview pane;
echo   - an antivirus: wait a few seconds and run this file again.
set "STOP_RC=1"
goto done

:free
echo.
echo The folder is free: it can be deleted, moved or copied now.
set "STOP_RC=0"
goto done

:done
if defined STOP_PAUSE pause
endlocal & exit /b %STOP_RC%
"""


def render_stop_cmd(cfg: LauncherConfig,
                    exe_launcher_name: str = "LaunchPortable.exe") -> str:
    """Аварийный скрипт «освободить папку» в корне портатива."""
    return ensure_ascii_bat(_STOP_TEMPLATE.format(
        title=_bat_echo(ascii_display(cfg.app_name)),
        exe_launcher=exe_launcher_name,
        powershell=_STOP_PS_FALLBACK.format(),
    ))


# --- Вспомогательные лаунчеры и меню ------------------------------------------

def render_companion_bat(cfg: LauncherConfig, target: TargetInfo) -> str:
    """Создаёт надёжный короткий вызов общего портативного лончера.

    ``call`` здесь обязателен: обычный запуск одного BAT из другого передаёт
    управление навсегда и скрывает код ошибки. Вспомогательным GUI также
    разрешается временно импортировать machine-настройки через UAC.
    """
    title = ascii_display(f"{cfg.app_name} - {target.name}")
    rel = _win_rel(target.rel_path)
    machine = " --machine-registry" if target.role != "main" else ""
    text = (
        "@echo off\r\n"
        "setlocal EnableExtensions\r\n"
        "rem ===========================================================================\r\n"
        f"rem  {title} - companion portable launcher\r\n"
        f"rem  Target: {rel}\r\n"
        "rem ===========================================================================\r\n"
        "for %%I in (\"%~dp0.\") do set \"PORTABLE_LAUNCHER_DIR=%%~fI\"\r\n"
        f"call \"%PORTABLE_LAUNCHER_DIR%\\Launch.bat\"{machine} --target \"{_bat_set_value(rel)}\" %*\r\n"
        "set \"PORTABLE_COMPANION_RC=%ERRORLEVEL%\"\r\n"
        "endlocal & exit /b %PORTABLE_COMPANION_RC%\r\n"
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
        machine = os.path.join(root, registry.get("machine_file", ""))
        if saved:
            # A non-elevated run may have no saved HKLM export. Seed it first.
            if registry.get("machine_file") and os.path.exists(machine):
                reg("import", machine)
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
        "launcher_aliases": cfg.launcher_aliases,
        "targets": targets_data,
        "target_args": cfg.target_args,
        "data_dir_name": cfg.data_dir_name,
        "extra_env": cfg.extra_env,
        "path_prepend": cfg.path_prepend,
        "redirect_known_folders": cfg.redirect_known_folders,
        # Сквозные сохранения: одно хранилище сейвов для прямого запуска
        # exe, лончера и комплектного launcher'а (см. core/saves.py).
        "shared_saves": cfg.shared_saves,
        # Один канонический, записываемый Fallout.ini рядом с игрой. Копии,
        # которые создаёт официальный launcher в PortableData, не могут
        # молча затереть ручные изменения в App.
        "game_settings": cfg.game_settings,
        "loop_guard": {
            "enabled": cfg.loop_guard_enabled,
            "max_restarts": cfg.loop_guard_max_restarts,
            "window": cfg.loop_guard_window,
            "relaunch_grace": cfg.loop_guard_relaunch_grace,
            "poll_interval": cfg.loop_guard_poll_interval,
        },
        # Чего не хватает на чужом ПК: лончер проверяет этот список перед
        # стартом и называет пакет вместо системной ошибки про DLL.
        "runtime_requirements": cfg.runtime_requirements,
        # Чем это лечится прямо на месте: тихая установка из папки Redist.
        "runtime_installers": cfg.runtime_installers,
        "runtime_install_script": (
            f"{REDIST_DIR_NAME}/{REDIST_SCRIPT_NAME}"
            if cfg.runtime_installers else ""),
        # Как завершать сеанс. Лончер обязан отпустить папку: ничего
        # запущенного из портатива не должно пережить его самого.
        "shutdown": {
            "spawn_grace": cfg.shutdown_spawn_grace,
            "idle_grace": cfg.shutdown_idle_grace,
            "close_grace": cfg.shutdown_close_grace,
            "max_wait": cfg.shutdown_max_wait,
            "kill_leftovers": cfg.shutdown_kill_leftovers,
            # Кто держит файлы папки — и как это прекратить.
            "deep_check": cfg.shutdown_deep_check,
            "handle_budget": cfg.shutdown_handle_budget,
            "purge_temp": cfg.shutdown_purge_temp,
        },
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
