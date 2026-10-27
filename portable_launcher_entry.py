"""Entrypoint for the standalone launcher copied into ``App``.

This file is built as a small windowed Windows executable by PyInstaller.  The
resulting binary is bundled into Portablizer and copied to every portable app as
``App/LaunchPortable.exe``.  It deliberately uses only the Python standard
library so the generated executable has no dependency on the machine where the
portable app is started.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

ROOT_TOKEN = "@@PORTABLE_ROOT@@"
IS_WINDOWS = sys.platform.startswith("win")
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0
ERROR_ICON = 0x00000010
WARNING_ICON = 0x00000030

#: Переменная окружения и ключ, которые выключают диалоги лончера.
#:
#: Окно с кнопкой «ОК» в неинтерактивном сеансе (CI, планировщик заданий,
#: удалённый рабочий стол без пользователя) некому закрыть: MessageBoxW ждёт
#: вечно, и запуск программы не начинается вовсе. Поэтому у всех диалогов
#: есть выключатель — им пользуются тесты и автоматические прогоны.
NO_UI_ENV = "PORTABLE_LAUNCHER_NO_UI"


def _ui_disabled() -> bool:
    """True, если диалоги показывать нельзя (``--no-ui`` или переменная)."""
    if any(str(arg).casefold() in ("--no-ui", "/no-ui")
           for arg in sys.argv[1:]):
        return True
    value = str(os.environ.get(NO_UI_ENV, "")).strip().casefold()
    return value in {"1", "true", "yes", "on", "да"}


def _runtime_directory() -> Path:
    """Return the directory containing this script/the frozen launcher."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def find_portable_root(start: Optional[Path] = None) -> Path:
    """Find the portable root when the launcher lives inside ``App``.

    Looking for both the config and the App directory avoids accidentally using
    an unrelated ``launcher_config.json`` shipped by the target application.
    Searching a few parents also lets a user move the launcher into an App
    subdirectory without baking an absolute path or drive letter into the EXE.
    """
    current = (start or _runtime_directory()).resolve()
    candidates = [current, *current.parents]
    for candidate in candidates[:8]:
        if (candidate / "launcher_config.json").is_file() and (candidate / "App").is_dir():
            return candidate
    raise FileNotFoundError(
        "Не найдена корневая папка портативного приложения. "
        "Файл LaunchPortable.exe должен находиться внутри папки App, а рядом "
        "с App должны лежать launcher_config.json и Launch.bat."
    )


def _show_error(message: str) -> None:
    """Show an error even though the launcher is built without a console."""
    if _ui_disabled():
        try:
            print(message, file=sys.stderr)
        except Exception:  # noqa: BLE001
            pass
        return
    if IS_WINDOWS:
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                None, message, "Portable Launcher", ERROR_ICON
            )
            return
        except Exception:
            pass
    try:
        print(message, file=sys.stderr)
    except Exception:
        pass


def _show_warning(message: str) -> None:
    """Show a non-fatal warning; the program is still started afterwards."""
    if _ui_disabled():
        try:
            print(message, file=sys.stderr)
        except Exception:  # noqa: BLE001
            pass
        return
    if IS_WINDOWS:
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                None, message, "Portable Launcher", WARNING_ICON
            )
            return
        except Exception:
            pass
    try:
        print(message, file=sys.stderr)
    except Exception:
        pass


def _env_value(env: Dict[str, str], name: str, default: str = "") -> str:
    """Environment value honouring the key in ANY letter case.

    A plain ``dict(os.environ)`` copy on Windows keeps keys uppercased
    (``SYSTEMROOT``), while callers and configs spell them ``SystemRoot``.
    A case-sensitive ``get`` then silently misses the variable and the
    ``WINDIR`` fallback leaks the *real* ``C:\\Windows`` through - which
    ignored the caller's SystemRoot exactly where it matters most: the
    WinSxS probe for VC++ 2005/2008 assemblies.
    """
    value = env.get(name)
    if value is None:
        wanted = name.upper()
        for key, candidate in env.items():
            if str(key).upper() == wanted:
                value = candidate
                break
    return value if value else default


def _library_search_dirs(root: Path, target: Path,
                         env: Dict[str, str]) -> list[Path]:
    """Folders Windows will really look into when resolving a DLL."""
    dirs: list[Path] = [target.parent, root / "App", root]
    for entry in str(_env_value(env, "PATH")).split(os.pathsep)[:48]:
        entry = entry.strip().strip('"')
        if entry:
            dirs.append(Path(entry))
    windir = _env_value(env, "SystemRoot") or _env_value(env, "WINDIR") \
        or r"C:\Windows"
    dirs.append(Path(windir) / "System32")
    dirs.append(Path(windir) / "SysWOW64")
    unique: list[Path] = []
    seen = set()
    for item in dirs:
        key = str(item).rstrip("\\/").lower()
        if key and key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _winsxs_has_family(windir: Path, family: str) -> bool:
    """True when WinSxS holds at least one folder of the assembly family.

    Visual C++ 2005/2008 runtimes exist ONLY as side-by-side assemblies in
    ``%SystemRoot%\\WinSxS`` - their DLLs are never copied into System32, so
    probing well-known directories for ``msvcr90.dll`` always says "missing"
    even on a fully working computer.  The folder names embed version and
    hash (``x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.9635_...``),
    therefore the probe matches by the architecture+assembly prefix.
    """
    family = (family or "").strip().lower()
    if len(family) < 4 or not family.endswith("_"):
        return False
    try:
        for entry in os.listdir(str(windir / "WinSxS")):
            if entry.lower().startswith(family):
                return True
    except OSError:
        return False
    return False


def _requirement_satisfied(root: Path, target: Optional[Path],
                           env: Dict[str, str],
                           search_dirs: Optional[list[Path]],
                           item: Dict[str, Any]) -> bool:
    """True when this one runtime requirement is met on THIS computer.

    A plain DLL requirement is satisfied wherever Windows resolves it.  A
    side-by-side requirement (Visual C++ 2005/2008) works differently: a
    bare ``msvcr90.dll`` next to the program is IGNORED unless the matching
    private ``Microsoft.VC90.CRT.manifest`` sits beside it - without one
    the program dies at start with error 14001 ("side-by-side configuration
    is incorrect").  Hence the pair is checked, and the system copy is
    looked up in WinSxS by the assembly family prefix, never in System32.
    """
    name = str(item.get("dll", "")).strip()
    if not name:
        return True
    # Universal CRT API Set contracts are not files.  On Windows 10/11 the
    # loader resolves them via the schema; the payload is ucrtbase.dll.
    # Checking the contract name in System32 always "fails" and the launcher
    # used to nag about Visual C++ 2015-2022 on a healthy PC.
    if name.lower().startswith("api-ms-win-crt-"):
        ucrt = dict(item)
        ucrt["dll"] = "ucrtbase.dll"
        ucrt["manifest"] = ""
        ucrt["sxs_family"] = ""
        return _requirement_satisfied(root, target, env, search_dirs, ucrt)
    manifest = str(item.get("manifest", "") or "").strip()
    family = str(item.get("sxs_family", "") or "").strip()
    if manifest and family:
        candidates: list[Path] = [root, root / "App"]
        if target is not None:
            candidates.insert(0, target.parent)
        for directory in candidates:
            try:
                if (directory / name).is_file() and \
                        (directory / manifest).is_file():
                    return True
            except OSError:
                continue
        windir = Path(_env_value(env, "SystemRoot")
                      or _env_value(env, "WINDIR") or r"C:\Windows")
        return _winsxs_has_family(windir, family)
    if search_dirs is None:
        system_root = _env_value(env, "SystemRoot") or r"C:\Windows"
        search_dirs = [root, root / "App",
                       Path(system_root) / "System32",
                       Path(system_root) / "SysWOW64"]
    for directory in search_dirs:
        try:
            if (directory / name).is_file():
                return True
        except OSError:
            continue
    return False


def missing_runtime_components(root: Path, cfg: Dict[str, Any], target: Path,
                               env: Dict[str, str]) -> list[Dict[str, str]]:
    """Redistributable libraries that are absent on THIS computer.

    Portablizer bundles everything it can find while building the portable
    folder.  Whatever is left over is listed in ``launcher_config.json``;
    checking it here turns the cryptic Windows box ("MSVCR110.dll is
    missing") into the name of the package and a link to it.  For Visual
    C++ 2005/2008 entries the check is honest about side-by-side rules:
    a DLL without its private manifest is not usable, and a system copy
    lives in WinSxS rather than System32.  This kills both false alarms on
    healthy PCs and false approval of a broken bundle (error 14001).
    """
    requirements = cfg.get("runtime_requirements") or []
    if not isinstance(requirements, list) or not requirements:
        return []
    search_dirs = _library_search_dirs(root, target, env)
    missing: list[Dict[str, str]] = []
    for item in requirements[:32]:
        if not isinstance(item, dict):
            continue
        if not str(item.get("dll", "")).strip():
            continue
        if not _requirement_satisfied(root, target, env, search_dirs, item):
            missing.append(item)
    return missing


def install_missing_runtime(root: Path, cfg: Dict[str, Any],
                            missing: Sequence[Dict[str, Any]]
                            ) -> list[Dict[str, Any]]:
    """Compatibility shim: never install system runtimes during launch.

    Older launchers silently ran bundled Microsoft redistributables and could
    elevate through UAC on first run. That changes the host outside the
    portable folder. Keep this helper for existing callers, but only report
    the missing packages; the user can explicitly run Redist/Install-Redist.cmd.
    """
    del cfg
    if missing:
        _run_log(root, "automatic runtime installation skipped; "
                        "manual user action is required")
    return list(missing)


def _runtime_warning_is_new(root: Path, cfg: Dict[str, Any],
                            missing: Sequence[Dict[str, Any]]) -> bool:
    """True when this exact warning has not been acknowledged yet.

    The message box must not become a nuisance: after the user has seen it
    once for this portable folder it is only repeated when the list itself
    changes - which is exactly what happens on a different computer.
    """
    stamp = (root / str(cfg.get("data_dir_name", "PortableData"))
             / "runtime-warning.txt")
    current = ",".join(sorted(str(item.get("dll", "")).lower()
                              for item in missing))
    try:
        if stamp.is_file() and stamp.read_text(
                encoding="utf-8", errors="replace").strip() == current:
            return False
    except OSError:
        return True
    try:
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(current, encoding="utf-8")
    except OSError:
        pass
    return True


def _warn_about_runtime(root: Path, missing: Sequence[Dict[str, Any]]) -> None:
    lines = [
        "На этом компьютере не хватает системных компонентов, которые нужны "
        "программе:",
        "",
    ]
    for item in missing:
        title = str(item.get("title") or "распространяемый пакет Microsoft")
        lines.append(f"  • {item.get('dll')} — {title}")
        url = str(item.get("url") or "")
        if url:
            lines.append(f"      {url}")
    lines += [
        "",
        "Автоматическая установка отключена, чтобы не менять Windows без "
        "вашего действия.",
        "Если вы доверяете пакетам и хотите установить их, запустите "
        "Redist\\Install-Redist.cmd",
        "вручную рядом с портативной папкой (если файл там есть); он может "
        "запросить UAC.",
        "Подробности и официальные ссылки — в redistributables.txt рядом с "
        "портативной папкой.",
        "Программа всё равно будет запущена: часть компонентов нужна не "
        "всегда.",
    ]
    text = "\n".join(lines)
    _run_log(root, "missing runtime components: "
             + ", ".join(str(item.get("dll")) for item in missing))
    _show_warning(text)


# --- netstack: сетевые компоненты (VPN-драйверы и службы-компаньоны) ----------
#
# Planeta VPN и все клиенты на OpenVPN не могут работать без системных
# компонентов, которые нельзя виртуализовать: сетевой мини-порт TAP-Windows
# (``tap0901``) и, у части вендоров, служба. Portablizer кладёт пакеты
# драйверов в папку ``NetStack/`` рядом с ``App/``; здесь лончер проверяет,
# есть ли нужное на ЭТОМ ПК, и если нет — один раз тихо запускает
# ``NetStack\\Setup.cmd`` (он сам просит UAC). По завершении сеанса
# ``Teardown.cmd`` снимает с регистрации только те службы, которые создал
# портатив (файл-маркер в PortableData\\NetStack).

#: Имя штампа «пользователь уже видел предупреждение про NetStack на этом
#: ПК» — повторяем только когда состав недостающего реально изменился.
_NETSTACK_STAMP = "netstack-warning.txt"


def _netstack_section(cfg: Dict[str, Any]) -> Dict[str, Any]:
    section = cfg.get("netstack")
    return section if isinstance(section, dict) else {}


def _service_key_present(name: str) -> bool:
    """Есть ли служба/драйвер на этом ПК (ключ Services\\<name>).

    Реестр читается без повышения: HKLM\\SYSTEM\\...\\Services открыт на
    чтение всем. На не-Windows считаем всё присутствующим — работы нет.
    """
    if not IS_WINDOWS or not name:
        return True
    try:
        import winreg  # type: ignore

        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\" + str(name)):
            return True
    except OSError:
        return False


def netstack_missing(root: Path, cfg: Dict[str, Any]
                     ) -> "list[str]":
    """Имена недостающих системных компонентов из секции ``netstack``."""
    section = _netstack_section(cfg)
    names: "list[str]" = []
    for key in ("driver_services", "service_names"):
        raw = section.get(key)
        if isinstance(raw, list):
            names.extend(str(n) for n in raw if str(n).strip())
    if not names:
        return []
    return [name for name in dict.fromkeys(names)
            if not _service_key_present(name)]


def _netstack_warning_is_new(root: Path, cfg: Dict[str, Any],
                             missing: Sequence[str]) -> bool:
    """Одно предупреждение на состав недостающего (как для runtime-пакетов)."""
    stamp = (root / str(cfg.get("data_dir_name", "PortableData"))
             / _NETSTACK_STAMP)
    current = ",".join(sorted(missing))
    try:
        if stamp.is_file() and stamp.read_text(
                encoding="utf-8", errors="replace").strip() == current:
            return False
    except OSError:
        return True
    try:
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(current, encoding="utf-8")
    except OSError:
        pass
    return True


def _run_netstack_script(root: Path, relative: str, argument: str = ""
                        ) -> "Optional[int]":
    """Run one NetStack script; elevate only when the session is not elevated.

    The scripts themselves re-launch through UAC when nobody granted rights
    yet, so a plain ``cmd /c`` is enough here: when the launcher already runs
    elevated (HKLM registry import path) the script sees admin and does no
    second prompt.
    """
    relative = str(relative or "").replace("/", os.sep)
    if not relative:
        return None
    path = root / relative
    if not path.is_file():
        path2 = root / "App" / relative
        if not path2.is_file():
            return None
        path = path2
    args = ["/c", str(path)] + ([argument] if argument else [])
    if _is_elevated():
        return _run_hidden(["cmd.exe", *args])
    return _run_hidden_elevated("cmd.exe", args)


def ensure_netstack(root: Path, cfg: Dict[str, Any]) -> "list[str]":
    """Check/repair drivers and services BEFORE the program starts.

    Returns human-readable notes for the run log.  Never raises: a laptop
    without administrator consent must still be able to start the portable
    (the VPN itself will complain about the missing adapter — with our note
    in the log the user knows exactly why).
    """
    if not IS_WINDOWS:
        return []
    section = _netstack_section(cfg)
    setup = str(section.get("setup") or "")
    if not setup:
        return []
    notes: "list[str]" = []
    missing = netstack_missing(root, cfg)
    script = root / setup.replace("/", os.sep)
    if not script.is_file():
        script = root / "App" / setup.replace("/", os.sep)
    if not script.is_file():
        return []
    # Дешёвая проверка без повышения: коды Setup.cmd --check честнее, чем
    # один реестр (он видит и корневое устройство), но и без неё решаем.
    if not missing:
        code = _run_hidden(["cmd.exe", "/c", str(script), "--check"])
        if code in (0, None):
            return []
        notes.append("Setup.cmd --check reported missing components")
    code = _run_netstack_script(root, setup)
    if code is None:
        notes.append("UAC prompt was declined or unavailable - the driver "
                     "and services were NOT installed")
    else:
        notes.append(f"NetStack setup exit code {code}")
    still = netstack_missing(root, cfg)
    if still:
        notes.append("still missing: " + ", ".join(still))
        if _netstack_warning_is_new(root, cfg, still):
            _show_warning(
                "Программе нужны системные сетевые компоненты, которых нет на "
                "этом компьютере:\n\n  " + "\n  ".join(still)
                + "\n\nПортатив пытается поставить их сам из папки NetStack "
                "(один запрос прав администратора). Если окно UAC было "
                "отклонено - запустите NetStack\\Setup.cmd вручную.")
    else:
        notes.append("all required components are present")
    return notes


def stop_netstack(root: Path, cfg: Dict[str, Any]) -> "list[str]":
    """Undo on this PC what the portable created for the session.

    Two per-machine markers decide everything
    (PortableData\\NetStack\\created-services.txt for services,
    driver-packages.txt for driver packages published in isolation mode):
    a service or a driver that already existed on the PC was never claimed,
    hence is never touched here.  Busy drivers stay pending and the next
    session end retries them.
    """
    if not IS_WINDOWS:
        return []
    section = _netstack_section(cfg)
    teardown = str(section.get("teardown") or "")
    if not teardown or not section.get("stop_on_exit", True):
        return []
    state = (root / str(cfg.get("data_dir_name", "PortableData"))
             / "NetStack")
    claimed = (state / "created-services.txt").is_file() or (
        state / "driver-packages.txt").is_file()
    if not claimed:
        return []
    code = _run_netstack_script(root, teardown)
    return [f"NetStack teardown exit code {code}"]


# --- меню «Пуск»: починка последствий ----------------------------------------
#
# Жалоба: после запуска Portablizer «от имени администратора» перестало
# работать меню «Пуск» Windows 11. Механизм описан в portablizer/core/
# startmenu.py: сборка под чужим пользователем и захват ветки Explorer
# (StartPage2/StartPins/кэш Win11) плюс прерванное перенаправление папки
# «Документы». Настройки оболочки больше не импортируются (см.
# _SHELL_PROTECTED_SUBKEYS), а здесь — лечение того, что уже случилось.

_USER_SHELL_KEY = (r"Software\Microsoft\Windows\CurrentVersion\Explorer"
                   r"\User Shell Folders")
_LEGACY_SHELL_KEY = (r"Software\Microsoft\Windows\CurrentVersion\Explorer"
                     r"\Shell Folders")
_DOCUMENTS_FOLDER_GUID = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"

#: Признак «Документы уехали в портатив и остались там».
_PORTABLE_DOCS_MARKER = os.path.join("portabledata", "user", "documents")


def _documents_known_folder() -> str:
    """Путь Known Folder «Документы» этого пользователя (пусто — нет)."""
    if not IS_WINDOWS:
        return ""
    try:
        import winreg  # type: ignore
    except ImportError:
        return ""
    for subkey, name in ((_USER_SHELL_KEY, "Personal"),
                         (_USER_SHELL_KEY, _DOCUMENTS_FOLDER_GUID),
                         (_LEGACY_SHELL_KEY, "Personal"),
                         (_LEGACY_SHELL_KEY, _DOCUMENTS_FOLDER_GUID)):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0,
                                winreg.KEY_QUERY_VALUE) as handle:
                value, _typ = winreg.QueryValueEx(handle, name)
        except OSError:
            continue
        if isinstance(value, str) and value.strip():
            return os.path.expandvars(value.strip())
    return ""


def _documents_need_repair() -> bool:
    """«Документы» указывают внутрь портатива, которого больше нет."""
    value = _documents_known_folder()
    if not value:
        return False
    if _PORTABLE_DOCS_MARKER not in value.replace("/", "\\").casefold():
        return False
    return not os.path.isdir(value)


def restore_documents_known_folder(root: Optional[Path] = None) -> str:
    """Возвращает «Документы» из удалённого портатива в профиль пользователя."""
    if not IS_WINDOWS or not _documents_need_repair():
        return ""
    profile = os.environ.get("USERPROFILE", "")
    destination = os.path.join(profile, "Documents") if profile else ""
    if not destination:
        return ""
    try:
        import winreg  # type: ignore
    except ImportError:
        return ""
    written = False
    for subkey, name, typ in (
            (_USER_SHELL_KEY, "Personal", winreg.REG_EXPAND_SZ),
            (_USER_SHELL_KEY, _DOCUMENTS_FOLDER_GUID, winreg.REG_EXPAND_SZ),
            (_LEGACY_SHELL_KEY, "Personal", winreg.REG_SZ),
            (_LEGACY_SHELL_KEY, _DOCUMENTS_FOLDER_GUID, winreg.REG_SZ)):
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, subkey, 0,
                                    winreg.KEY_SET_VALUE) as handle:
                winreg.SetValueEx(handle, name, 0, typ, destination)
            written = True
        except OSError:
            continue
    if not written:
        return ""
    message = ("папка «Документы» возвращена в профиль пользователя ("
               f"{destination}); раньше она указывала в удалённый портатив")
    _run_log(root, "start menu repair: " + message)
    return message


def reset_start_menu_cache() -> int:
    """Сбрасывает кэш меню «Пуск» (TempState пакета StartMenuExperienceHost)."""
    if not IS_WINDOWS:
        return 0
    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        return 0
    import glob as _glob

    removed = 0
    pattern = os.path.join(local, "Packages",
                           "Microsoft.Windows.StartMenuExperienceHost_*",
                           "TempState")
    for folder in _glob.glob(pattern):
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            path = os.path.join(folder, name)
            try:
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)
            except OSError:
                continue
            removed += 1
    return removed


def _notify_shell_change() -> None:
    if not IS_WINDOWS:
        return
    try:
        import ctypes

        ctypes.windll.shell32.SHChangeNotify(  # type: ignore[attr-defined]
            0x08000000, 0, None, None)
        ctypes.windll.user32.SendMessageTimeoutW(  # type: ignore[attr-defined]
            0xFFFF, 0x001A, 0, "ShellState", 0x0002, 3000, None)
    except Exception:  # noqa: BLE001
        pass


def repair_start_menu(root: Optional[Path] = None, reset_cache: bool = True,
                      restart_shell: bool = True) -> "list[str]":
    """Лечит меню «Пуск»: «Документы», кэш Win11, перезапуск оболочки.

    Ничего не удаляет из пользовательских закреплений: перестраивается только
    кэш, а ``explorer.exe`` никогда не завершается (Windows поднимает
    ``StartMenuExperienceHost``/``SearchHost`` сама).
    """
    done: "list[str]" = []
    if not IS_WINDOWS:
        return done
    restored = restore_documents_known_folder(root)
    if restored:
        done.append(restored)
    if reset_cache:
        removed = reset_start_menu_cache()
        if removed:
            message = f"кэш меню «Пуск» сброшен (файлов: {removed})"
            _run_log(root, "start menu repair: " + message)
            done.append(message)
    _notify_shell_change()
    if restart_shell and done:
        for name in ("StartMenuExperienceHost.exe", "SearchHost.exe"):
            try:
                completed = subprocess.run(
                    ["taskkill", "/f", "/im", name], capture_output=True,
                    timeout=30, check=False, creationflags=NO_WINDOW)
            except (OSError, subprocess.SubprocessError):
                continue
            if completed.returncode == 0:
                done.append(f"перезапущен {name}")
    return done


def sanitize_portable_registry_files(root: Path) -> "list[str]":
    """Убирает секции оболочки из ``portable*.reg`` прямо в папке портатива.

    Нужно для портативов, собранных прежней версией: их ``portable.reg`` мог
    содержать ветку ``Explorer\\StartPage2`` другого пользователя, и лончер
    послушно её импортировал. Импорт теперь фильтруется, но запасной
    ``Launch.bat`` вызывает ``reg import`` напрямую — поэтому файл лучше
    вычистить один раз на месте. Возвращает список очищенных файлов.
    """
    cleaned: "list[str]" = []
    stamps = _sanitize_stamps(root)
    for name in ("portable.reg", "portable_machine.reg"):
        path = root / name
        if not path.is_file():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        key = (int(stat.st_size), int(stat.st_mtime_ns))
        if stamps.get(name) == list(key):
            # Этот файл уже проверен и переписан: ни читать, ни писать.
            # На медленном внешнем диске portable.reg бывает в мегабайты, и
            # каждая лишняя перезапись отодвигала появление окна.
            continue
        try:
            text = _decode_reg(path.read_bytes())
        except OSError:
            continue
        sanitized, dropped = sanitize_reg_text(text)
        if not dropped:
            stamps[name] = list(key)
            continue
        try:
            if not sanitized:
                # В файле были только секции оболочки — он больше не нужен.
                path.unlink()
                cleaned.append(name + " (удалён: только секции оболочки)")
                continue
            path.write_text(sanitized, encoding="utf-16", newline="\r\n")
            cleaned.append(name + f" (убрано секций: {len(dropped)})")
            try:
                stat = path.stat()
                stamps[name] = [int(stat.st_size), int(stat.st_mtime_ns)]
            except OSError:
                pass
        except OSError:
            continue
    _write_sanitize_stamps(root, stamps)
    for line in cleaned:
        _run_log(root, "registry: shell sections removed from " + line)
    return cleaned


#: Отметка «этот .reg уже вычищен»: имя файла -> [размер, время изменения].
#: Нужна, чтобы не читать и не перезаписывать многомегабайтный portable.reg
#: при каждом запуске (на внешнем диске это секунды).
SANITIZE_STAMPS_NAME = "registry-sanitized.json"


def _sanitize_stamps_file(root: Path) -> Path:
    return root / "PortableData" / SANITIZE_STAMPS_NAME


def _sanitize_stamps(root: Path) -> "Dict[str, list]":
    try:
        data = json.loads(_sanitize_stamps_file(root).read_text(
            encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return {}
    return {str(name): list(value) for name, value in files.items()
            if isinstance(value, (list, tuple)) and len(value) == 2}


def _write_sanitize_stamps(root: Path, stamps: "Dict[str, list]") -> None:
    try:
        target = _sanitize_stamps_file(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"files": stamps}, ensure_ascii=False,
                                     indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def autoheal_profile(root: Optional[Path] = None) -> None:
    """Дешёвая самопроверка при каждом запуске: «Документы» на месте?

    Если прежний сеанс был прерван и Known Folder остался направленным внутрь
    уже удалённой портативной папки, это ломает не только меню «Пуск», но и
    сохранения всех программ. Проверка стоит один запрос к реестру.
    """
    try:
        restored = restore_documents_known_folder(root)
    except Exception as exc:  # noqa: BLE001 - самопроверка не срывает запуск
        _run_log(root, f"start menu check failed: {exc}")
        return
    if restored:
        _notify_shell_change()


def _write_error_log(root: Optional[Path], message: str) -> None:
    if root is None:
        return
    try:
        data = root / "PortableData"
        data.mkdir(parents=True, exist_ok=True)
        (data / "launcher-exe-error.log").write_text(
            message + "\n", encoding="utf-8"
        )
    except OSError:
        pass


def _run_log(root: Optional[Path], message: str) -> None:
    """Append one diagnostic line to PortableData/launcher-run.log.

    Old games (The Witcher, GOG editions in particular) simply exit with code 1
    when something they need is missing.  Without a trace of what was started,
    with which registry data and what the child process did afterwards, the
    user only sees "nothing happens".  The log makes that debuggable.
    """
    if root is None:
        return
    try:
        import time

        data = root / "PortableData"
        data.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with (data / "launcher-run.log").open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {message}\n")
    except OSError:
        pass


#: Шаги, которые лончер выполняет ДО старта программы. Замеры пишутся в
#: журнал и в ``PortableData\\launch-timing.json``: по ним видно, что именно
#: задерживает запуск, не гадая по жалобе «стартует очень медленно».
LAUNCH_TIMING_NAME = "launch-timing.json"


def _process_start_age_seconds() -> float:
    """Сколько секунд назад Windows создала наш процесс.

    ``LaunchPortable.exe`` собран как PyInstaller-onefile: перед первой
    строкой Python он распаковывает себя во временную папку, и эти секунды
    собственными замерами не видны. ``GetProcessTimes`` знает настоящее время
    создания процесса, поэтому в отчёте появляется строка «exe boot», и
    становится видно, тормозит ли лончер или сама программа.
    """
    if not IS_WINDOWS:
        return 0.0
    try:
        import ctypes
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD),
                        ("dwHighDateTime", wintypes.DWORD)]

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        times = (FILETIME(), FILETIME(), FILETIME(), FILETIME())
        if not kernel32.GetProcessTimes(
                kernel32.GetCurrentProcess(),
                *[ctypes.byref(item) for item in times]):
            return 0.0
        created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    except Exception:  # noqa: BLE001 - замер не срывает запуск
        return 0.0
    if not created:
        return 0.0
    # FILETIME считает 100-нс интервалы от 1601-01-01.
    created_epoch = created / 10_000_000 - 11644473600
    return max(0.0, min(time.time() - created_epoch, 300.0))


class _StageTimer:
    """Секундомер предстартовых шагов: ``tick()`` закрывает предыдущий шаг.

    Такой способ не требует оборачивать каждый блок в ``with``: достаточно
    одной строки перед шагом, а диффы остаются читаемыми.
    """

    def __init__(self, data: Path) -> None:
        self.data = data
        self.steps: "list[tuple[str, float]]" = []
        #: Шаги, которые не успели до старта и ушли в фон (см. _run_session).
        self.deferred: "list[str]" = []
        self._name = ""
        self._started = 0.0
        self._began = time.monotonic()

    def note_deferred(self, name: str) -> None:
        """Запоминает отложенный шаг: он попадает и в журнал, и в отчёт."""
        if name and name not in self.deferred:
            self.deferred.append(name)

    @property
    def spent(self) -> float:
        """Сколько секунд прошло с начала предстартовых шагов."""
        return time.monotonic() - self._began

    def exceeded(self, budget: float) -> bool:
        """Вышел ли лончер за отведённое время до старта программы."""
        return bool(budget) and budget > 0 and self.spent > float(budget)

    def add_startup(self, seconds: float) -> None:
        """Первая строка отчёта: время от создания процесса до этой строки.

        Отсчёт ``spent`` (= бюджет предстартовых шагов) тоже начинается от
        создания процесса: сменить оболочку лончера — это уже задержка,
        которую видит пользователь, и в потолок она входит.
        """
        if seconds >= 0.02:
            self.steps.append(("exe boot", seconds))
            self._began = min(self._began, time.monotonic() - seconds)

    def tick(self, name: str) -> None:
        now = time.perf_counter()
        if self._name:
            self.steps.append((self._name, now - self._started))
        self._name = name
        self._started = now

    @property
    def total(self) -> float:
        finished = sum(seconds for _name, seconds in self.steps)
        if self._name:
            finished += time.perf_counter() - self._started
        return finished

    def finish(self, root: Optional[Path]) -> float:
        """Пишет итог в журнал и в JSON; возвращает длительность, секунды."""
        self.tick("")
        total = sum(seconds for _name, seconds in self.steps)
        if not self.steps:
            return total
        slowest = sorted(self.steps, key=lambda item: item[1], reverse=True)[:4]
        summary = ", ".join(f"{name} {seconds:.2f}s"
                            for name, seconds in slowest if seconds >= 0.05)
        line = (f"pre-launch (from LaunchPortable.exe start): {total:.2f}s "
                "before the program starts")
        if summary:
            line += " (slowest: " + summary + ")"
        _run_log(root, line)
        try:
            self.data.mkdir(parents=True, exist_ok=True)
            (self.data / LAUNCH_TIMING_NAME).write_text(json.dumps({
                "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_seconds": round(total, 3),
                "steps": [[name, round(seconds, 3)]
                          for name, seconds in self.steps],
                "deferred": list(self.deferred),
            }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        return total


def launcher_packaging_reason(root: Optional[Path] = None) -> str:
    """Строка для ``--diagnose``: почему лончер стартует быстро или медленно.

    ``LaunchPortable.exe`` бывает собран двумя способами:

    * **папкой** (onedir): рядом лежит ``_internal``, запуск — обычная загрузка
      DLL, окно программы появляется сразу;
    * **одним файлом** (onefile): при КАЖДОМ запуске exe распаковывает себя во
      ``%TEMP%`` — десятки файлов, которые антивирус проверяет заново. Именно
      это и выглядит как «фоновый процесс появился, а окно через несколько
      секунд».
    """
    base = root if root is not None else find_portable_root()
    exe = base / "App" / "LaunchPortable.exe"
    payload = base / "App" / "_internal"
    if payload.is_dir() and any(payload.iterdir()):
        return ("упаковка:        папкой (_internal) — запуск без распаковки, "
                "быстрый")
    if exe.is_file():
        return ("упаковка:        ОДНИМ ФАЙЛОМ — при каждом запуске "
                "распаковывается во временную папку (медленно). Нажмите "
                "«Обновить лончер» в Portablizer или пересоберите портатив.")
    return "упаковка:        LaunchPortable.exe не найден"


class _BackgroundWork:
    """Уборка на стороне Windows, которая не должна задерживать программу.

    Список «Установленные программы» и чужие ярлыки программе для старта не
    нужны: она спокойно открывается параллельно с этими шагами. Раньше они
    выполнялись до запуска, и любой медленный шаг (антивирус проверяет десятки
    ярлыков, Windows показывает запрос UAC) отодвигал появление окна. Теперь
    работа идёт в отдельных потоках, а перед восстановлением реестра лончер её
    дожидается.
    """

    def __init__(self, root: Path, name: str) -> None:
        self.root = root
        self.name = name
        self._threads: "list[Any]" = []
        self._finished: "list[float]" = []
        self._waited = 0.0
        self._reported = False

    def submit(self, work, name: str = "", prefix: bool = True) -> None:
        """Запускает ``work()`` в фоне; возвращаемый список — строки журнала.

        ``prefix=False`` — строки журнала уже сами объясняют, откуда они
        (``registry: ...``, ``update: ...``): приставку не добавляем.
        """
        import threading

        label = name or self.name

        def _run() -> None:
            started = time.perf_counter()
            try:
                for line in work():
                    if line:
                        _run_log(self.root, f"{label}: {line}" if prefix
                                 else line)
            except Exception as exc:  # noqa: BLE001 - уборка не срывает запуск
                _run_log(self.root, f"{label}: failed ({exc})")
            finally:
                self._finished.append(time.perf_counter() - started)

        thread = threading.Thread(target=_run, name="portable-" + label,
                                  daemon=True)
        thread.start()
        self._threads.append(thread)

    def wait(self, timeout: float = 30.0) -> None:
        """Дожидается фоновой работы; второй вызов не ждёт то же время снова."""
        if not self._threads:
            return
        deadline = time.monotonic() + max(0.1, float(timeout) - self._waited)
        started = time.monotonic()
        for thread in self._threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        self._waited += time.monotonic() - started
        alive = [thread for thread in self._threads if thread.is_alive()]
        if self._reported:
            return
        self._reported = True
        if alive:
            _run_log(self.root, f"{self.name}: still busy after "
                               f"{self._waited:.0f}s, the rest is done when the "
                               "program exits")
            return
        total = sum(self._finished)
        if total >= 0.2:
            _run_log(self.root, f"{self.name}: {total:.2f}s of host cleanup, "
                               "done in parallel with the program start")


#: Сколько лончеру отведено на всё, что делается ДО старта программы, секунды.
#:
#: Жалоба: «фоновый LaunchPortable.exe появился, а окно программы — через
#: несколько секунд». Причин может быть много и они разные на разных ПК и
#: дисках (медленный внешний диск, антивирус, сотни ключей реестра), а сам
#: пользователь ждёт окно, а не отчёт. Поэтому у предстартовых шагов есть
#: потолок: всё, что не успело, доделывается в фоне, параллельно с уже
#: запущенной программой. Обязательные шаги (профиль, пути, реестр настроек)
#: под потолок не попадают — без них программа стартует неправильно.
#:
#: Настраивается в ``launcher_config.json``: ``"prelaunch_budget_seconds"``.
#: ``0`` — без потолка (прежнее поведение: всё до старта).
PRELAUNCH_BUDGET_SECONDS = 2.5


def prelaunch_budget(cfg: "Optional[Dict[str, Any]]" = None) -> float:
    """Потолок времени на предстартовые шаги из конфига (или умолчание)."""
    try:
        value = float((cfg or {}).get("prelaunch_budget_seconds",
                                      PRELAUNCH_BUDGET_SECONDS))
    except (TypeError, ValueError):
        return PRELAUNCH_BUDGET_SECONDS
    return max(0.0, value)


def _last_launch_timing(data: Path) -> "list[str]":
    """Строки для ``--diagnose``: где прошлый запуск провёл время."""
    try:
        payload = json.loads((data / LAUNCH_TIMING_NAME).read_text(
            encoding="utf-8"))
    except (OSError, ValueError):
        return ["(замеров нет: лончер ещё не запускал программу)"]
    total = payload.get("total_seconds")
    lines = [f"всего до старта: {total} s ({payload.get('at', '')})"]
    for name, seconds in payload.get("steps") or []:
        lines.append(f"  {seconds:>7} s  {name}")
    deferred = payload.get("deferred") or []
    if deferred:
        lines.append("в фоне уже после старта: " + ", ".join(
            str(name) for name in deferred))
    return lines


def _reg(args: Sequence[str]) -> int:
    """Run reg.exe without flashing a console window."""
    if not IS_WINDOWS:
        return 1
    try:
        return subprocess.run(
            ["reg.exe", *args],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        ).returncode
    except OSError:
        return 1


def _decode_reg(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if b"\x00" in raw[:64]:
        return raw.decode("utf-16-le", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("cp1251")
        except UnicodeDecodeError:
            return raw.decode("utf-16-le", "replace")


# --- защита оболочки при импорте реестра --------------------------------------
#
# Портатив приносит с собой настройки приложения. Некоторые из них выглядят
# как настройки приложения, а на деле принадлежат оболочке Windows: раскладка
# меню «Пуск», закреплённые плитки, кэш Win11, панель задач, «Документы».
#
# Применять их из чужого снимка нельзя. Именно так ломалось меню «Пуск»:
# сборка под администратором записывала в portable.reg ветку
# ``...\CurrentVersion\Explorer\StartPage2`` (или ``StartPins``/``StartCache``)
# другого пользователя, а лончер послушно её импортировал — и меню перестало
# строиться. Теперь такие секции вырезаются из файла ПЕРЕД импортом, даже
# если portable.reg был создан прежней версией Portablizer.
_SHELL_PROTECTED_SUBKEYS = (
    r"software\microsoft\windows\currentversion\explorer\startpage",
    r"software\microsoft\windows\currentversion\explorer\startpage2",
    r"software\microsoft\windows\currentversion\explorer\startpins",
    r"software\microsoft\windows\currentversion\explorer\startcache",
    r"software\microsoft\windows\currentversion\explorer\startcache2",
    r"software\microsoft\windows\currentversion\explorer\starttiles",
    r"software\microsoft\windows\currentversion\explorer\caches",
    r"software\microsoft\windows\currentversion\explorer\taskband",
    r"software\microsoft\windows\currentversion\explorer\user pinned",
    r"software\microsoft\windows\currentversion\explorer\shell folders",
    r"software\microsoft\windows\currentversion\explorer\user shell folders",
    r"software\microsoft\windows\currentversion\explorer\fileexts",
    r"software\microsoft\windows\currentversion\explorer\advanced",
    r"software\microsoft\windows\currentversion\explorer\sessioninfo",
    r"software\microsoft\windows\currentversion\shell",
    r"software\microsoft\windows\currentversion\cloudstore",
)


#: Следы установки. Портатив не устанавливается, поэтому эти ветки из
#: ``portable.reg`` нельзя импортировать ни в каком виде: именно запись в
#: ``Uninstall`` и рисует «Cursor» в списке «Установленные программы» на
#: компьютере, где программу никогда не ставили (старые сборки переносили
#: такие ключи в портатив, и лончер послушно их импортировал).
_REG_TRACE_SUBKEYS = (
    r"software\microsoft\windows\currentversion\uninstall",
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\microsoft\windows\currentversion\runservices",
    r"software\microsoft\windows\currentversion\runservicesonce",
    r"software\microsoft\windows\currentversion\installer",
    r"software\microsoft\windows\currentversion\shareddlls",
    r"software\microsoft\installer",
    r"software\classes\installer",
)

#: Всё, что вырезается из .reg перед импортом: оболочка и следы установки.
_REG_DROPPED_SUBKEYS = tuple(dict.fromkeys(
    _SHELL_PROTECTED_SUBKEYS + _REG_TRACE_SUBKEYS))


def _reg_section_is_dropped(header: str) -> bool:
    """Секция .reg непригодна для импорта: оболочка Windows или след установки."""
    parts = [p for p in str(header or "").strip().strip("[]").split("\\") if p]
    if len(parts) < 2:
        return False
    up = parts[0].upper()
    if up in ("HKEY_CURRENT_USER", "HKCU"):
        rest = parts[1:]
    elif up in ("HKEY_USERS",):
        # HKEY_USERS\<SID>\Software\... — та же ветка пользователя.
        rest = parts[2:] if len(parts) > 2 else []
    elif up in ("HKEY_LOCAL_MACHINE", "HKLM"):
        # Следы установки бывают и в машинной ветке (установка «для всех»).
        rest = parts[1:]
    else:
        return False
    path = "\\".join(rest).casefold()
    if path.startswith("software\\wow6432node\\"):
        path = "software\\" + path[len("software\\wow6432node\\"):]
    return any(path == prefix or path.startswith(prefix + "\\")
               for prefix in _REG_DROPPED_SUBKEYS)


def _reg_section_is_shell_owned(header: str) -> bool:
    """Секция .reg непригодна для импорта (старое имя, см. выше)."""
    return _reg_section_is_dropped(header)


def sanitize_reg_text(text: str) -> "tuple[str, list[str]]":
    """Вырезает из текста .reg секции оболочки. Возвращает (текст, вырезанное)."""
    kept: list[str] = []
    dropped: list[str] = []
    skip = False
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            skip = _reg_section_is_dropped(stripped)
            if skip:
                dropped.append(stripped.strip("[]"))
                continue
        if skip:
            continue
        kept.append(line)
    body = "\n".join(kept).strip()
    # Одного заголовка «Windows Registry Editor Version 5.00» недостаточно:
    # если все секции вырезаны, импортировать нечего.
    if not any(line.lstrip().startswith("[") for line in kept):
        return "", dropped
    if not body.casefold().startswith("windows registry editor"):
        body = "Windows Registry Editor Version 5.00\n\n" + body
    return body + "\n\n", dropped


def _root_marker_pattern(needle: str) -> "re.Pattern[str]":
    """Регулярное выражение для пути/маркера с границами имени.

    Простая замена подстроки портила соседние каталоги: путь
    ``D:\\Apps\\XD`` находился внутри ``D:\\Apps\\XData\\save.ini``, и файл
    настроек после переноса указывал в никуда. Границы решают это, а
    ``IGNORECASE`` — ещё и разницу в регистре буквы диска (``d:\\`` и ``D:\\``).
    """
    return re.compile(r"(?<![0-9A-Za-z_.])" + re.escape(needle)
                      + r"(?![0-9A-Za-z_.])", re.IGNORECASE)


def _replace_root_text(text: str, old: str, new: str) -> str:
    """Меняет все вхождения пути/маркера ``old`` на ``new`` с границами."""
    if not text or not old:
        return text
    return _root_marker_pattern(old).sub(lambda _match: new, text)


def _rewrite_reg(source: Path, destination: Path,
                 replacements: Iterable[tuple[str, str]],
                 sanitize: bool = False,
                 log_root: "Optional[Path]" = None) -> bool:
    """Rewrite a .reg file as UTF-16 while replacing portable path markers.

    ``sanitize=True`` применяется при ИМПОРТЕ: секции оболочки Windows
    (меню «Пуск», панель задач, «Документы») из файла вырезаются, поэтому
    даже старый ``portable.reg`` не может их испортить.
    """
    try:
        text = _decode_reg(source.read_bytes())
        for old, new in replacements:
            text = _replace_root_text(text, old, new)
        if sanitize:
            text, dropped = sanitize_reg_text(text)
            if not text:
                # Импортировать нечего: профиль пользователя не трогаем.
                return False
            if dropped:
                _run_log(log_root, "registry: shell sections skipped: "
                         + ", ".join(dropped[:5]))
        # TextIO translates every \n when newline="\r\n". Normalize first so
        # an exported CRLF file does not turn into CRCRLF after rewriting.
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-16", newline="\r\n")
        return True
    except (OSError, UnicodeError):
        return False


def _unpacked_reg(source: Path, runtime_dir: Path, root: Path,
                  index: int) -> Optional[Path]:
    """Create a temporary importable copy with the current drive/path.

    ``None`` означает «импортировать нечего»: после вырезания секций оболочки
    в файле не осталось ни одного ключа приложения. Возвращать в этом случае
    исходный файл нельзя — он-то как раз и содержит эти секции, и именно их
    импорт раньше ломал меню «Пуск».

    Если заменять нечего (в файле нет маркера корня) и вырезать нечего, файл
    импортируется как есть: на медленном внешнем диске перезапись
    многомегабайтного ``portable.reg`` во временную папку стоила секунд.
    """
    destination = runtime_dir / f"import-{index:03d}.reg"
    escaped_root = str(root).replace("\\", "\\\\")
    try:
        text = _decode_reg(source.read_bytes())
    except OSError:
        return None
    if ROOT_TOKEN.casefold() not in text.casefold():
        _sanitized, dropped = sanitize_reg_text(text)
        if not dropped:
            return source
    if _rewrite_reg(source, destination, ((ROOT_TOKEN, escaped_root),),
                    sanitize=True, log_root=root):
        return destination
    return None


def _pack_reg(path: Path, root: Path) -> None:
    """Replace this computer's absolute root with a portable marker in-place."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    root_text = str(root)
    escaped_root = root_text.replace("\\", "\\\\")
    slashed_root = root_text.replace("\\", "/")
    # Ни одного вхождения корня — переписывать нечего. Раньше файл всё равно
    # читался и записывался целиком (в том числе на каждом выходе).
    try:
        raw = path.read_bytes()
    except OSError:
        return
    lowered = raw.lower()
    if not any(form.encode("utf-16-le").lower() in lowered
               or form.encode("utf-8").lower() in lowered
               for form in (root_text, escaped_root, slashed_root) if form):
        return
    if _rewrite_reg(
        path,
        temporary,
        ((escaped_root, ROOT_TOKEN), (root_text, ROOT_TOKEN),
         (slashed_root, ROOT_TOKEN)),
    ):
        try:
            os.replace(temporary, path)
        except OSError:
            try:
                temporary.unlink()
            except OSError:
                pass


def _as_relative_path(root: Path, value: str) -> Path:
    """Путь цели из конфига: относительный к корню или уже абсолютный.

    Прежние версии Portablizer писали в конфиг абсолютный путь установки.
    После переноса папки он ведёт в никуда, но сам по себе остаётся путём:
    приклеивать его к корню нельзя, иначе лончер искал бы
    ``<root>\\D:\\Apps\\...``.
    """
    normalized = str(value).replace("\\", os.sep).replace("/", os.sep)
    path = Path(normalized)
    if path.is_absolute():
        return path
    return root / normalized


# --- относительные пути и перенос между дисками ------------------------------
#
# Портатив переносят: ``D:\Apps\XD_Portable`` -> ``F:\XD_Portable``, с флешки
# на внешний диск, из папки пользователя в ``E:\Backup``. Наши собственные
# файлы (``Launch.bat``, ``launcher_config.json``, скрипты) хранят только пути
# относительно корня, а захваченный реестр — маркер ``@@PORTABLE_ROOT@@``,
# поэтому их перенос не ломает ничего.
#
# Иначе с настройками самой программы: формат чужой, и переписать абсолютный
# путь «в относительный» нельзя — программа такого не поймёт. Поэтому корень
# запоминается в ``PortableData\portable-root.json``, а при каждом запуске
# лончер сравнивает его с текущим положением папки. Если папка переехала,
# старый путь заменяется новым во всех найденных текстовых файлах — до того,
# как программа прочитает свои настройки. Так перенос работает и для чужих
# конфигов, и без единого абсолютного пути в наших файлах.

#: Штамп с последним известным корнем портатива (JSON, UTF-8).
PATHS_STAMP_NAME = "portable-root.json"

#: Тот же корень одной ASCII-строкой: его читает ``Launch.bat`` (cmd умеет
#: сравнивать только байты, поэтому не-ASCII путь в этот файл не пишется).
PATHS_STAMP_TEXT_NAME = "portable-root.txt"

#: Расширения, в которых имеет смысл искать текстовые пути.
PATHS_TEXT_SUFFIXES = (
    ".ini", ".cfg", ".conf", ".config", ".json", ".xml", ".yaml", ".yml",
    ".txt", ".reg", ".bat", ".cmd", ".vbs", ".ps1", ".url", ".properties",
    ".settings", ".prefs", ".toml", ".local", ".dat",
)

#: Каталоги, которые меняются каждую секунду и к переносу отношения не имеют,
#: а также деревья пакетов, где настроек программы заведомо нет.
#:
#: ``node_modules`` — не мелочь: у Cursor/VS Code (``resources\\app\\node_modules``
#: и ещё одно такое дерево в каждой распакованной папке расширения) это десятки
#: тысяч ``package.json``. Пока каталог не пропускался, после переноса папки
#: лончер читал их все при КАЖДОМ запуске, и программа открывалась в разы
#: медленнее прямого запуска exe.
PATHS_SKIP_DIRS = (
    "temp", "tmp", "cache", "caches", "cache2", "gpucache", "shadercache",
    # Папка содержимого лончера (App\_internal): ни маркера, ни путей
    # программы там быть не может, а файлов в ней сотни.
    "_internal",
    "codecache", "crashpad", "crashdumps", "logs",
    "node_modules", ".git", ".hg", ".svn",
    "blob_storage", "indexeddb", "service worker",
    "cacheddata", "cachedprofilesdata", "workspacestorage",
)

#: Потолки одного прохода: починка не должна задерживать запуск программы.
PATHS_MAX_FILES = 6000

#: Потолок для глубокого обхода (обновление, ручная починка путей).
PATHS_DEEP_MAX_FILES = 20000

#: Сколько всего можно прочитать за один проход. Потолок на файл (2 МБ) сам по
#: себе не спасает: 6000 файлов по 2 МБ — это 12 ГБ чтения, то есть минуты на
#: обычном диске. 64 МБ — уже с запасом, а запуск остаётся предсказуемым.
PATHS_MAX_TOTAL_BYTES = 64 * 1024 * 1024

#: Сколько прежних мест портатива помнить в штампе (кроме текущего).
PATHS_STAMP_HISTORY = 5
PATHS_MAX_BYTES = 2 * 1024 * 1024

#: Отметка «проход по этому положению папки уже сделан».
#:
#: Штамп помнит прежние места портатива ВСЕГДА (на них смотрит установщик
#: обновления), поэтому без этой отметки починка путей обходила и читала файлы
#: при каждом запуске — вечно. Отметка хранится в том же штампе (``scan``) и
#: сверяется с текущим набором прежних корней.
PATHS_SCAN_VERSION = 2

_PATHS_BOMS = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)


def _paths_settings(cfg: "Optional[Dict[str, Any]]") -> Dict[str, Any]:
    """Секция ``relative_paths`` конфига с разумными значениями по умолчанию.

    Конфиг мог быть создан прежней версией Portablizer: тогда секции нет, и
    починка всё равно должна работать — она и есть причина, по которой папку
    можно перенести.
    """
    section = (cfg or {}).get("relative_paths")
    settings: Dict[str, Any] = {
        "enabled": True,
        "include_app": True,
        "max_files": PATHS_MAX_FILES,
        "max_bytes": PATHS_MAX_BYTES,
        "skip_dirs": list(PATHS_SKIP_DIRS),
        "suffixes": list(PATHS_TEXT_SUFFIXES),
    }
    if isinstance(section, dict):
        if "enabled" in section:
            settings["enabled"] = bool(section.get("enabled"))
        if "include_app" in section:
            settings["include_app"] = bool(section.get("include_app"))
        for key in ("max_files", "max_bytes"):
            try:
                value = int(section.get(key) or 0)
            except (TypeError, ValueError):
                value = 0
            if value > 0:
                settings[key] = value
        for key in ("skip_dirs", "suffixes"):
            raw = section.get(key)
            if isinstance(raw, (list, tuple)) and raw:
                settings[key] = [str(item) for item in raw]
    return settings


def _paths_stamp_file(root: Path) -> Path:
    return root / "PortableData" / PATHS_STAMP_NAME


def _paths_stamp_text_file(root: Path) -> Path:
    return root / "PortableData" / PATHS_STAMP_TEXT_NAME


def _read_paths_stamp(root: Path) -> Dict[str, Any]:
    try:
        data = json.loads(_paths_stamp_file(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _root_key(text: object) -> str:
    """Ключ сравнения путей корня: «E:\\A\\B», «E:/A/B», «e:\\a\\b\\» равны.

    Нужен потому, что один и тот же корень попадает в штамп, в конфиг сборки и
    в записи реестра разными написаниями (разделители, регистр, хвостовой
    слеш, кавычки, длинный префикс ``\\\\?\\``). Пока каждое место сравнивало
    по-своему, в ``--diagnose`` один и тот же корень печатался дважды.
    """
    value = str(text or "").strip().strip('"').strip()
    if value[:4] == "\\\\?\\":
        value = value[4:]
    value = value.replace("/", "\\").rstrip("\\")
    return os.path.normcase(os.path.normpath(value)).casefold()


def _unique_roots(values: "Sequence[object]") -> "list[str]":
    """Список корней без повторов (см. :func:`_root_key`), порядок сохранён."""
    unique: "list[str]" = []
    seen: "set[str]" = set()
    for item in values:
        text = str(item or "").strip().strip('"').rstrip("\\/")
        if not text:
            continue
        key = _root_key(text)
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(text)
    return unique


def _remembered_root_list(root: Path) -> "list[str]":
    """Все известные прежние и текущий корни в порядке «свежее -> старее»."""
    stamp = _read_paths_stamp(root)
    current = _root_key(root)
    values = [stamp.get("root", ""), stamp.get("previous", "")]
    history = stamp.get("history")
    if isinstance(history, (list, tuple)):
        values.extend(history)
    return [text for text in _unique_roots(values) if _root_key(text) != current]


def _scan_marker_covers(root: Path, remembered: "Sequence[str]") -> bool:
    """Просмотрены ли файлы для этого положения папки.

    Починка путей нужна только после переезда, но прежние места остаются в
    штампе навсегда (на них смотрит установщик обновления). Поэтому «уже
    смотрели» хранится отдельно и сверяется с набором прежних корней: новый
    переезд меняет набор — и проход выполняется снова.
    """
    scan = _read_paths_stamp(root).get("scan")
    if not isinstance(scan, dict):
        return False
    if int(scan.get("version") or 0) != PATHS_SCAN_VERSION:
        return False
    if str(scan.get("root", "")).casefold() != str(root).casefold():
        return False
    stored = [str(item) for item in scan.get("roots") or []]
    if len(stored) != len(remembered):
        return False
    return all(a.casefold() == b.casefold() for a, b in zip(stored, remembered))


def write_paths_stamp(root: Path, previous: str = "",
                      scan_marker: "Optional[Sequence[str]]" = None) -> None:
    """Запоминает текущий корень портатива (для следующего переноса).

    Сохраняется не только предыдущее место, но и вся короткая история
    переездов: папку переносят флешка -> внешний диск -> другой ПК, и путь,
    записанный в настройках программы два переезда назад, тоже должен
    находиться — иначе установщик обновления возьмёт каталог установки из
    этого старого пути (жалоба «обновление поставилось по прежнему адресу»).

    ``scan_marker`` — набор прежних корней, для которых файлы уже просмотрены
    (см. :func:`repair_paths`). Без этой отметки починка путей выполняла полный
    обход и чтение файлов при КАЖДОМ запуске: прежние места остаются в штампе
    навсегда.
    """
    import time

    current = str(root)
    history = _remembered_root_list(root)
    if previous:
        older = str(previous).strip().strip('"').rstrip("\\/")
        if older and older.casefold() != current.casefold() and older not in history:
            history.insert(0, older)
    payload: Dict[str, Any] = {"schema": 2, "root": current,
                               "updated": time.strftime("%Y-%m-%d %H:%M:%S")}
    if history:
        payload["previous"] = history[0]
        if len(history) > 1:
            payload["history"] = history[1:PATHS_STAMP_HISTORY]
    previous_scan = _read_paths_stamp(root).get("scan")
    scan: Optional[Dict[str, Any]] = None
    if scan_marker is not None:
        scan = {"version": PATHS_SCAN_VERSION, "root": current,
                "roots": [str(item) for item in scan_marker],
                "at": payload["updated"]}
    elif (isinstance(previous_scan, dict)
          and str(previous_scan.get("root", "")).casefold() == current.casefold()):
        # Отметка действует, пока папка лежит на месте.
        scan = dict(previous_scan)
    if scan:
        payload["scan"] = scan
    try:
        _paths_stamp_file(root).parent.mkdir(parents=True, exist_ok=True)
        _paths_stamp_file(root).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
    except OSError:
        pass
    # Тот же путь строкой для Launch.bat. Только ASCII: cmd сравнивает байты,
    # и не-ASCII значение всё равно не совпало бы с %PORTABLE_ROOT%.
    try:
        if current.isascii():
            _paths_stamp_text_file(root).write_text(current + "\\\n",
                                                    encoding="ascii")
    except (OSError, UnicodeError):
        pass


def _decode_text_bytes(data: bytes) -> "Optional[tuple[str, str]]":
    """Текст и кодировка файла или ``None``, если это не текст."""
    for bom, encoding in _PATHS_BOMS:
        if data.startswith(bom):
            try:
                return data.decode(encoding), encoding
            except (UnicodeDecodeError, UnicodeError):
                return None
    try:
        return data.decode("utf-8"), "utf-8"
    except (UnicodeDecodeError, UnicodeError):
        return None


def _iter_paths_files(root: Path, settings: Dict[str, Any],
                      deep: bool = False) -> "Iterable[Path]":
    """Текстовые файлы портатива, в которых может жить абсолютный путь.

    ``PortableData`` (там настройки программы) обходится всегда полностью.
    ``App`` при обычном запуске читается на два уровня вглубь: внутри бывают
    десятки тысяч файлов, и обходить их все на каждый старт слишком дорого.
    ``deep=True`` (обновление, ``--repair-paths``) снимает это ограничение:
    установщик обновления читает каталог установки из конфига программы,
    который может лежать глубже, и тогда новая версия встанет по старому
    адресу. Потолок числа файлов при этом выше, но всё равно есть.
    """
    suffixes = tuple(str(item).casefold()
                     for item in settings.get("suffixes") or PATHS_TEXT_SUFFIXES)
    # Встроенный список объединяется с настройками, а не заменяется ими:
    # конфиг старого портатива содержит собственный ``skip_dirs``, и без
    # объединения новые исключения (``node_modules``) к нему бы не пришли.
    skip = {str(item).casefold() for item in PATHS_SKIP_DIRS}
    skip.update(str(item).casefold()
                for item in settings.get("skip_dirs") or ())
    limit = int(settings.get("max_files") or PATHS_MAX_FILES)
    if deep:
        limit = max(limit, PATHS_DEEP_MAX_FILES)
    include_app = bool(settings.get("include_app", True))
    total_budget = int(settings.get("max_total_bytes") or 0) or PATHS_MAX_TOTAL_BYTES
    yielded = 0
    read_bytes = 0
    app_name = "app"
    for current, dirs, files in os.walk(root):
        relative = os.path.relpath(current, root)
        depth = 0 if relative == "." else relative.count(os.sep) + 1
        keep = []
        for name in sorted(dirs):
            lowered = name.casefold()
            if lowered in skip or lowered.startswith("$"):
                continue
            if lowered == app_name and not include_app:
                continue
            if lowered == app_name and not deep and depth >= 2:
                continue
            keep.append(name)
        dirs[:] = keep
        for name in sorted(files):
            if not any(name.casefold().endswith(suffix) for suffix in suffixes):
                continue
            path = Path(current) / name
            try:
                if path.is_symlink():
                    continue
                size = path.stat().st_size
            except OSError:
                continue
            if size > int(settings.get("max_bytes") or PATHS_MAX_BYTES):
                continue
            if read_bytes + size > total_budget:
                return
            read_bytes += size
            yield path
            yielded += 1
            if yielded >= limit:
                return


def repair_paths(root: Path, cfg: "Optional[Dict[str, Any]]" = None,
                 force: bool = False, deep: bool = False) -> "list[str]":
    """Переписывает абсолютные пути старого корня новым, если папку перенесли.

    Возвращает строки отчёта (их пишут в ``PortableData\\launcher-run.log``).
    Ничего не делает, если корень не менялся: обычный запуск не платит за
    перенос ни одной лишней миллисекундой, кроме двух чтений штампа.

    Проверяются ОБА запомненных пути: текущий из штампа и предыдущий. Папку
    переносят не один раз (флешка -> внешний диск -> другой ПК), и путь,
    записанный программой два переезда назад, иначе так и остался бы в её
    настройках — а установщик обновления взял бы каталог установки оттуда.
    """
    settings = _paths_settings(cfg)
    if not settings.get("enabled", True) and not force:
        return []
    current = str(root)
    stamp = _read_paths_stamp(root)
    remembered: "list[str]" = []
    for text in _remembered_root_list(root):
        if len(text) <= 2 and text[1:2] == ":":
            # Корень «D:» — не путь, а буква диска: восстанавливать нечего.
            continue
        if text not in remembered:
            remembered.append(text)
    if not remembered:
        if not stamp:
            write_paths_stamp(root, scan_marker=[])
        elif not _paths_stamp_text_file(root).is_file() and current.isascii():
            # Штамп мог быть записан старой версией без файла для Launch.bat.
            write_paths_stamp(root)
        return []

    if not force and _scan_marker_covers(root, remembered):
        # Файлы уже просмотрены для этого места папки и этого набора прежних
        # корней: ничего не читаем. Именно этот случай — обычный запуск
        # портатива, который когда-то переносили, и раньше он стоил полного
        # обхода дерева с чтением тысяч файлов на каждом старте.
        return []

    # Все начертания запомненных корней. Удвоенная форма (``C:\\\\Apps\\\\Foo``
    # в JSON и .reg) длиннее обычной, поэтому замены идут от длинной к
    # короткой: иначе короткая успела бы испортить длинную.
    pairs: "list[tuple[str, str]]" = []
    for item in remembered:
        if "\\" in item:
            pairs.append((item.replace("\\", "\\\\"),
                          current.replace("\\", "\\\\")))
        pairs.append((item, current))
        pairs.append((item.replace("\\", "/"), current.replace("\\", "/")))
    # Маркер — тоже «не тот» путь: пока он в настройках, ни программа, ни её
    # установщик не понимают, где лежит папка.
    token_pair = (ROOT_TOKEN, current)
    if token_pair not in pairs:
        pairs.append(token_pair)
    pairs.sort(key=lambda pair: len(pair[0]), reverse=True)

    files: "list[str]" = []
    total = 0
    # Штамп и отчёт о путях пишем мы сами: переписывать их «старый корень»
    # бессмысленно, а в отчёте об этом был бы ложный след.
    own = {_paths_stamp_file(root), _paths_stamp_text_file(root)}
    for path in _iter_paths_files(root, settings, deep=deep):
        if path in own:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        decoded = _decode_text_bytes(data)
        if decoded is None:
            continue
        text, encoding = decoded
        folded = text.casefold()
        if not any(form.casefold() in folded for form, _ in pairs):
            continue
        fixed = text
        replaced = 0
        for form, replacement in pairs:
            if not form or form.casefold() not in fixed.casefold():
                continue
            replaced += len(_root_marker_pattern(form).findall(fixed))
            fixed = _replace_root_text(fixed, form, replacement)
        if fixed == text:
            continue
        try:
            path.write_bytes(fixed.encode(encoding))
        except (OSError, UnicodeError):
            continue
        total += max(replaced, 1)
        try:
            files.append(str(path.relative_to(root)))
        except ValueError:
            files.append(str(path))
    # Отметка «смотрели» ставится и тогда, когда ничего не нашлось: иначе
    # следующий запуск снова обошёл бы всё дерево.
    write_paths_stamp(root, previous=remembered[0],
                      scan_marker=remembered)
    if not files:
        # Запомненный путь остался только в штампе и ни в одном файле
        # настроек не встретился: сообщать нечего.
        return []
    note = (f"paths: folder moved from {', '.join(remembered)} to {current}; "
            f"rewritten {total} absolute path(s) in {len(files)} file(s)")
    if files:
        note += ": " + ", ".join(files[:8]) + (" ..." if len(files) > 8 else "")
    return [note]


#: Файл-отметка: маркер уже развёрнут в файлах для этого положения папки.
TOKEN_SWEEP_NAME = "token-sweep.json"


def _token_sweep_file(root: Path, cfg: "Optional[Dict[str, Any]]" = None) -> Path:
    return _data_dir(root, cfg or {}) / TOKEN_SWEEP_NAME


def expand_root_token_in_files(root: Path,
                              cfg: "Optional[Dict[str, Any]]" = None,
                              deep: bool = False) -> "list[str]":
    """Разворачивает маркер ``@@PORTABLE_ROOT@@`` в текстовых файлах портатива.

    Утечка маркера в настройки самой программы (или в её блокнот установщика)
    даёт тот же эффект, что и маркер в реестре: обновление пытается писать в
    ``@@PORTABLE_ROOT@@\\App`` и падает. Проход ограничен теми же правилами,
    что и ``repair_paths``: расширения, размер, потолок числа файлов, пропуск
    кэшей.

    ``deep=True`` — для обновления и ``--repair-paths`` (внутри ``App`` на
    любую глубину). Возвращает список исправленных файлов.
    """
    settings = _paths_settings(cfg)
    fixed_files: "list[str]" = []
    # Свои файлы не трогаем. В ``launcher_config.json`` маркер лежит значением
    # ``registry.root_token`` — это НАСТОЯЩЕЕ содержимое, а не путь: подстановка
    # превратила бы его в ``E:\Backup\...`` с одиночными слэшами, и JSON
    # перестал бы читаться («Invalid \escape: line 120 column 22»). Именно так
    # ломались все запускалки, пока программа из ``App`` работала.
    own = {_paths_stamp_file(root), _paths_stamp_text_file(root),
           _token_sweep_file(root, cfg),
           _session_marker(root),
           _data_dir(root, cfg or {}) / ADOPTED_LOG_NAME,
           root / "launcher_config.json"}
    for path in _iter_paths_files(root, settings, deep=deep):
        if path in own:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        decoded = _decode_text_bytes(data)
        if decoded is None:
            continue
        text, encoding = decoded
        if ROOT_TOKEN.casefold() not in text.casefold():
            continue
        fixed = expand_root_token_text(text, root)
        if fixed == text:
            continue
        if path.suffix.casefold() == ".json":
            # JSON: слэши внутри значения должны быть удвоены, иначе файл
            # становится нечитаемым. Заменяем маркер сразу на экранированную
            # форму, а результат проверяем разбором.
            fixed = _expand_token_json(text, root)
            if fixed == text:
                continue
            if _json_is_valid(text) and not _json_is_valid(fixed):
                _run_log(root, "paths: skipped " + path.name
                               + ": the marker in it cannot be replaced "
                                 "without breaking the JSON")
                continue
        try:
            path.write_bytes(fixed.encode(encoding))
        except (OSError, UnicodeError):
            continue
        try:
            fixed_files.append(str(path.relative_to(root)))
        except ValueError:
            fixed_files.append(str(path))
    if fixed_files:
        _run_log(root, "paths: replaced the portable marker in "
                       f"{len(fixed_files)} file(s): "
                       + ", ".join(fixed_files[:8])
                       + (" ..." if len(fixed_files) > 8 else ""))
    return fixed_files


def sweep_root_token_once(root: Path,
                          cfg: "Optional[Dict[str, Any]]" = None) -> "list[str]":
    """Разовый проход по маркеру для текущего положения папки.

    Полный (глубокий) обход на каждом запуске был бы слишком дорог, а маркер
    появляется только вместе с переездом или старой сборкой. Поэтому проход
    выполняется один раз на каждое место папки и запоминается в
    ``PortableData\\token-sweep.json``. После переезда отметка не совпадёт с
    текущим корнем, и проход повторится.
    """
    marker = _token_sweep_file(root, cfg)
    current = str(root)
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        if str(data.get("root", "")).casefold() == current.casefold():
            return []
    except (OSError, ValueError):
        pass
    fixed = expand_root_token_in_files(root, cfg, deep=True)
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({
            "root": current,
            "replaced": len(fixed),
            "files": fixed[:50],
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
    return fixed


def import_reg_command(root: "Optional[Path]" = None,
                       source: "Optional[str]" = None) -> int:
    """``LaunchPortable.exe --import-reg <файл>``: импорт с подстановкой маркера.

    Нужен ``Launch.bat``: если PowerShell на этом ПК недоступен или запрещён
    политикой, батник не может заменить ``@@PORTABLE_ROOT@@`` сам. Импортировать
    файл «как есть» нельзя — маркер попал бы в реестр, и установщик обновления
    программы пытался бы писать в ``@@PORTABLE_ROOT@@\\App``. Поэтому импорт
    передаётся лончеру, который маркер разворачивает.
    """
    root = root or find_portable_root()
    if not source:
        return 2
    path = Path(str(source).strip().strip('"'))
    if not path.is_absolute():
        path = root / path
    if not path.is_file():
        _run_log(root, f"registry: --import-reg: file not found ({path})")
        return 1
    try:
        text = _decode_reg(path.read_bytes())
    except OSError as exc:
        _run_log(root, f"registry: --import-reg: cannot read {path} ({exc})")
        return 1
    if ROOT_TOKEN.casefold() in text.casefold():
        text = expand_root_token_text(text, root)
    if ROOT_TOKEN.casefold() in text.casefold():
        _run_log(root, "registry: --import-reg: the marker is still present, "
                       "the file is not imported")
        return 1
    runtime = _data_dir(root, {}) / "Runtime"
    try:
        runtime.mkdir(parents=True, exist_ok=True)
        target = runtime / "import-bat.reg"
        target.write_text(text, encoding="utf-16", newline="\r\n")
    except OSError as exc:
        _run_log(root, f"registry: --import-reg: cannot write ({exc})")
        return 1
    if import_registry_file(target, root):
        _run_log(root, f"registry: --import-reg {path.name}: ok")
        result = 0
    else:
        _run_log(root, f"registry: --import-reg {path.name}: FAILED")
        result = 1
    try:
        target.unlink()
    except OSError:
        pass
    return result


CONFIG_NAME = "launcher_config.json"


def launcher_config_path(root: Path) -> Path:
    return root / CONFIG_NAME


def read_launcher_config(root: Path) -> "Dict[str, Any]":
    """Читает ``launcher_config.json`` и чинит его, если JSON испорчен.

    Жалоба: все запускалки (``Launch.bat``, ``LaunchHidden.vbs``,
    ``LaunchPortable.exe``, ярлык установщика) показывали
    «Не удалось запустить портативную программу.
    Invalid \\escape: line 120 column 22 (char 3665)», а сама программа из
    ``App`` работала.

    Причина была наша: проход по маркеру ``@@PORTABLE_ROOT@@`` подставлял в
    этот файл путь с одиночными обратными слэшами (``"root_token":
    "E:\\Backup\\Apps"``). Для JSON это управляющие последовательности, файл
    перестаёт разбираться — и ни один лончер не может прочитать конфиг.

    Теперь проход этот файл не трогает, но испорченные копии уже существуют:
    при чтении такой JSON чинится (слэши удваиваются, всё остальное остаётся
    как было) и записывается обратно. Заодно значение
    ``registry.root_token`` возвращается к маркеру, если в него попал путь:
    это не путь, а само содержимое.
    """
    path = launcher_config_path(root)
    data = path.read_bytes()
    text = data.decode("utf-8-sig")
    encoding = "utf-8"
    try:
        cfg = json.loads(text)
    except ValueError as first_error:
        repaired = _repair_json_escapes(text)
        try:
            cfg = json.loads(repaired)
        except ValueError:
            _run_log(root, f"config: {CONFIG_NAME} cannot be read "
                           f"({first_error}); restoring from the shipped copy")
            cfg = _restore_config_from_baseline(root, first_error)
            if cfg is None:
                raise
        else:
            try:
                path.write_text(repaired, encoding=encoding,
                                newline="\n")
                _run_log(root, "config: repaired invalid escapes in "
                               + CONFIG_NAME
                               + " (a Windows path was written with single "
                                 "backslashes)")
            except OSError:
                pass
    if not isinstance(cfg, dict):
        raise ValueError(f"{CONFIG_NAME}: ожидался объект JSON")
    return _sanitize_config(cfg, root)


def _restore_config_from_baseline(root: Path,
                                  error: Exception) -> "Optional[Dict[str, Any]]":
    """Последняя попытка: собирает минимальный конфиг из того, что уцелело.

    Если файл испорчен так, что и удвоение слэшей не помогает, лончер всё
    равно должен запустить программу: имя, цель и каталог данных достаются
    из остатков файла или из соседних наших файлов. Полный конфиг при этом не
    выдумывается — восстанавливается только необходимое для запуска.
    """
    path = launcher_config_path(root)
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None

    def find(pattern: str) -> str:
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1) if match else ""

    target = find(r'"target_exe_rel"\s*:\s*"([^"]+)"')
    name = find(r'"app_name"\s*:\s*"([^"]*)"')
    data_dir = find(r'"data_dir_name"\s*:\s*"([^"]*)"') or "PortableData"
    if not target:
        return None
    cfg: Dict[str, Any] = {
        "app_name": name or root.name,
        "target_exe_rel": target,
        "data_dir_name": data_dir,
        "restored_from_broken_config": str(error)[:200],
    }
    _run_log(root, "config: minimal config restored from the broken file "
                   f"(target={target})")
    return cfg


def _sanitize_config(cfg: "Dict[str, Any]", root: Path) -> "Dict[str, Any]":
    """Возвращает ``registry.root_token`` к маркеру, если туда попал путь.

    Маркер — это значение настройки, а не путь: ``portable.reg`` содержит его
    вместо корня. Если подстановка заменила его абсолютным путём, импорт
    настроек пойдёт «как есть», и маркер перестанет работать после переезда.
    """
    registry = cfg.get("registry")
    if not isinstance(registry, dict):
        return cfg
    token = str(registry.get("root_token") or "")
    if token and ROOT_TOKEN.casefold() not in token.casefold():
        registry["root_token"] = ROOT_TOKEN
        _run_log(root, "config: registry.root_token restored to the portable "
                       "marker (an absolute path had been written there)")
        try:
            launcher_config_path(root).write_text(
                json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8")
        except OSError:
            pass
    return cfg


def repair_paths_command(root: "Optional[Path]" = None) -> int:
    """``LaunchPortable.exe --repair-paths``: починить пути вручную.

    Нужна после переноса, если программу запускали напрямую из ``App`` (мимо
    лончера) или если перенос сделали при выключенном автопоиске.
    """
    root = root or find_portable_root()
    try:
        cfg = read_launcher_config(root)
    except (OSError, ValueError):
        cfg = {}
    lines = repair_paths(root, cfg, force=True, deep=True)
    tokens = expand_root_token_in_files(root, cfg, deep=True)
    lines = list(lines)
    if tokens:
        lines.append("paths: replaced the portable marker @@PORTABLE_ROOT@@ "
                     f"in {len(tokens)} file(s)")
    for line in lines or ["paths: nothing to repair"]:
        _run_log(root, line)
    return 0


def _expand_environment(value: Any, env: Dict[str, str]) -> str:
    """Expand %NAME% using the portable environment, not the host profile."""
    text = str(value)

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return env.get(key, env.get(key.upper(), match.group(0)))

    return re.sub(r"%([^%]+)%", replace, text)


def _prepare_environment(root: Path, cfg: Dict[str, Any]) -> Dict[str, str]:
    data = root / cfg.get("data_dir_name", "PortableData")
    appdata = data / "AppData" / "Roaming"
    localappdata = data / "AppData" / "Local"
    userprofile = data / "User"
    temp = data / "Temp"
    programdata = data / "ProgramData"
    public = data / "Public"

    directories = (
        data,
        appdata,
        localappdata,
        localappdata / "Temp",
        userprofile,
        temp,
        programdata,
        public,
        data / "Registry",
        data / "RegistryHostBackup",
        userprofile / "Documents",
        userprofile / "Documents" / "My Games",
        userprofile / "Desktop",
        userprofile / "Downloads",
        userprofile / "Saved Games",
        userprofile / "AppData" / "Roaming",
        userprofile / "AppData" / "Local",
        userprofile / "AppData" / "LocalLow",
        public / "Documents",
        public / "Desktop",
        public / "Downloads",
    )
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env.update({
        "APPDATA": str(appdata),
        "LOCALAPPDATA": str(localappdata),
        "USERPROFILE": str(userprofile),
        "TEMP": str(temp),
        "TMP": str(temp),
        "PROGRAMDATA": str(programdata),
        "PUBLIC": str(public),
        "PORTABLE_APP": "1",
        "PORTABLE_ROOT": str(root),
        "PORTABLE_DOCUMENTS": str(userprofile / "Documents"),
    })
    root_text = str(root)
    if len(root_text) >= 2 and root_text[1] == ":":
        env["HOMEDRIVE"] = root_text[:2]
        env["HOMEPATH"] = str(userprofile)[2:]

    prefixes = [str(_as_relative_path(root, rel)) for rel in cfg.get("path_prepend", [])]
    if prefixes:
        env["PATH"] = os.pathsep.join(prefixes + [env.get("PATH", "")])
    for key, value in cfg.get("extra_env", {}).items():
        if key:
            env[str(key)] = _expand_environment(value, env)
    return env


def _electron_environment(env: Dict[str, str], target: Path) -> Dict[str, str]:
    """Relax Chromium's sandbox when the target is an Electron host."""
    if not needs_electron_sandbox_off(target):
        return env
    patched = dict(env)
    patched["ELECTRON_NO_SANDBOX"] = "1"
    patched["ELECTRON_DISABLE_SANDBOX"] = "1"
    return patched


# --- сквозные сохранения ------------------------------------------------------
#
# Прямой запуск ``App\\Game.exe`` получает НАСТОЯЩИЙ профиль Windows, а запуск
# через лончер — перенаправленный профиль внутри портатива.  Без этой секции
# получались два независимых хранилища сейвов: сделанное одним способом не
# видно другому.  Канонической копией всегда остаётся та, что внутри
# портатива; папки профиля с ней сводятся — по времени изменения, без единого
# удаления.

#: Мусор, который синхронизировать бессмысленно.
_SAVE_JUNK = frozenset({"desktop.ini", "thumbs.db", ".ds_store"})

#: FAT32 хранит время с точностью до 2 секунд: без допуска один и тот же файл
#: вечно считался бы «более новым», и копирование шло бы каждый запуск.
_SAVE_MTIME_TOLERANCE = 2.0

#: Предохранитель: «папка сохранений» не должна оказаться игровым каталогом
#: на 100 ГБ, который лончер будет копировать часами.
_SAVE_MAX_FILES = 20000
_SAVE_MAX_BYTES = 20 * 1024 ** 3

#: Корни профиля, в которых игры держат сохранения.
_SAVE_ROOTS = ("Documents/My Games", "Saved Games")


def _save_pattern_regex(pattern: str) -> "Optional[re.Pattern]":
    """``Saves`` -> поддерево, ``*.ini`` -> файлы верхнего уровня."""
    text = str(pattern).replace("\\", "/").strip("/")
    if not text:
        return None
    if not any(ch in text for ch in "*?["):
        return re.compile(r"(?i)^" + re.escape(text) + r"(/.*)?$")
    out = ["(?i)^"]
    index = 0
    while index < len(text):
        char = text[index]
        if char == "*":
            if text.startswith("**", index):
                out.append(".*")
                index += 2
                continue
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(char))
        index += 1
    out.append("$")
    return re.compile("".join(out))


def _save_patterns(patterns: Sequence[str]) -> list:
    return [rule for rule in (_save_pattern_regex(p) for p in patterns)
            if rule is not None]


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def merge_saves(source: Path, destination: Path,
                patterns: Sequence[str] = ()) -> "list[str]":
    """Копирует то, чего в приёмнике нет или что там старее.

    Ничего не удаляет и никогда не затирает более свежий файл, поэтому
    вызывать её можно в любую сторону и сколько угодно раз: при расхождении
    побеждает последняя по времени версия, остальное дополняется.
    """
    if not source or not destination:
        return []
    try:
        if not source.is_dir():
            return []
    except OSError:
        return []
    if _inside(source, destination) or _inside(destination, source):
        return []

    compiled = _save_patterns(patterns)
    copied: "list[str]" = []
    total = 0
    for root, dirs, files in os.walk(str(source), followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith("$")]
        for name in files:
            if name.lower() in _SAVE_JUNK:
                continue
            src_file = Path(root) / name
            rel = os.path.relpath(str(src_file), str(source)).replace("\\", "/")
            if compiled and not any(rule.match(rel) for rule in compiled):
                continue
            dst_file = destination / rel.replace("/", os.sep)
            try:
                src_stat = src_file.stat()
            except OSError:
                continue
            try:
                if dst_file.stat().st_mtime + _SAVE_MTIME_TOLERANCE \
                        >= src_stat.st_mtime:
                    continue
            except OSError:
                pass
            try:
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                if dst_file.exists():
                    try:
                        dst_file.chmod(dst_file.stat().st_mode | 0o200)
                    except OSError:
                        pass
                shutil.copy2(str(src_file), str(dst_file))
            except OSError:
                continue
            copied.append(rel)
            total += src_stat.st_size
            if len(copied) >= _SAVE_MAX_FILES or total >= _SAVE_MAX_BYTES:
                return copied
    return copied


def _normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).lower())


def _matches_tokens(name: str, tokens: Sequence[str]) -> bool:
    normalized = _normalized_name(name)
    if not normalized:
        return False
    for token in tokens:
        token = str(token)
        if len(token) < 4:
            continue
        if normalized == token or token in normalized or normalized in token:
            return True
    return False


class SharedSaveSession:
    """Сводит сохранения портатива и профиля этого ПК в одно хранилище.

    Запускается дважды: перед стартом программы (забрать всё, что появилось
    мимо лончера — например, после прямого запуска ``App\\Game.exe``) и после
    её закрытия (вернуть обновлённое наружу, если данные пишутся в профиль).

    Важно: настоящие пути профиля определяются В КОНСТРУКТОРЕ — до того, как
    ``ShellFolderSession`` подменит Known Folder «Документы». Иначе лончер
    синхронизировал бы портатив сам с собой.
    """

    def __init__(self, root: Path, cfg: Dict[str, Any]) -> None:
        self.root = root
        data = cfg.get("shared_saves")
        self.cfg: Dict[str, Any] = data if isinstance(data, dict) else {}
        self.mode = str(self.cfg.get("mode", "off"))
        self.enabled = bool(self.cfg.get("enabled")) and self.mode != "off"
        self.data_dir = root / str(cfg.get("data_dir_name", "PortableData"))
        self.state_file = self.data_dir / "SharedSaves" / "state.json"
        discovery = self.cfg.get("discovery")
        discovery = discovery if isinstance(discovery, dict) else {}
        self.discovery = bool(discovery.get("enabled", True))
        self.tokens = [str(t) for t in discovery.get("tokens", [])
                       if isinstance(discovery.get("tokens", []), list)]
        roots = discovery.get("roots")
        self.roots = [str(r) for r in roots] if isinstance(roots, list) \
            else list(_SAVE_ROOTS)
        self.portable_profile = self.data_dir / "User"
        self.host_profile, self.host_documents = self._resolve_host()
        self.two_way = self._load_state()
        self.entries = self._configured_entries()

    # -- настоящий профиль пользователя ------------------------------------
    def _resolve_host(self) -> "tuple[Optional[Path], Optional[Path]]":
        # PORTABLE_HOST_PROFILE/PORTABLE_HOST_DOCUMENTS задают профиль явно:
        # так поступает запасной Launch.bat (он запоминает настоящие пути до
        # перенаправления) и так же работают тесты.
        forced_profile = os.environ.get("PORTABLE_HOST_PROFILE", "").strip()
        forced_documents = os.environ.get("PORTABLE_HOST_DOCUMENTS",
                                          "").strip()
        raw = forced_profile or os.environ.get("USERPROFILE") \
            or os.path.expanduser("~")
        profile = Path(raw) if raw else None
        if profile is not None and (_inside(profile, self.root)
                                    or not profile.is_dir()):
            profile = None

        documents: Optional[Path] = None
        if forced_documents and os.path.isabs(forced_documents):
            documents = Path(forced_documents)
        elif forced_profile:
            documents = (profile / "Documents") if profile is not None else None
        elif IS_WINDOWS:
            try:
                import winreg

                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer"
                    r"\User Shell Folders", 0, winreg.KEY_QUERY_VALUE,
                ) as key:
                    value, _type = winreg.QueryValueEx(key, "Personal")
                expanded = os.path.expandvars(str(value))
                if expanded and os.path.isabs(expanded):
                    documents = Path(expanded)
            except (OSError, ValueError):
                documents = None
        # Прерванный прошлый сеанс мог оставить Known Folder направленным
        # внутрь портатива: такой путь «настоящим профилем» считать нельзя.
        if documents is not None and _inside(documents, self.root):
            documents = None
        if documents is None and profile is not None:
            documents = profile / "Documents"
        return profile, documents

    def _host_path(self, relative: str) -> Optional[Path]:
        parts = [p for p in str(relative).replace("\\", "/").split("/") if p]
        if not parts:
            return None
        if parts[0].lower() == "documents":
            if self.host_documents is None:
                return None
            return self.host_documents.joinpath(*parts[1:]) if len(parts) > 1 \
                else self.host_documents
        if self.host_profile is None:
            return None
        return self.host_profile.joinpath(*parts)

    # -- состояние ----------------------------------------------------------
    def _load_state(self) -> "set[str]":
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return {str(name) for name in data.get("two_way", [])}
        except (OSError, ValueError, AttributeError):
            return set()

    def _save_state(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(
                json.dumps({"two_way": sorted(self.two_way)},
                           ensure_ascii=False),
                encoding="utf-8")
        except OSError:
            pass

    # -- записи -------------------------------------------------------------
    def _configured_entries(self) -> "list[Dict[str, Any]]":
        entries: "list[Dict[str, Any]]" = []
        raw = self.cfg.get("entries")
        if isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue
                store = str(item.get("store", "")).replace("\\", "/").strip("/")
                if not store:
                    continue
                entries.append({
                    "name": str(item.get("name", store)),
                    "store": store,
                    "host": str(item.get("host", "")),
                    "portable": str(item.get("portable", "")),
                    "patterns": [str(p) for p in item.get("patterns", [])
                                 if isinstance(item.get("patterns", []), list)],
                    "direction": ("in" if str(item.get("direction", "both"))
                                  == "in" else "both"),
                })
        return entries

    def _discovered_entries(self) -> "list[Dict[str, Any]]":
        """Папки сохранений, появившиеся уже после сборки портатива."""
        if not self.discovery or not self.tokens:
            return []
        known = {str(e.get("host", "")).replace("\\", "/").lower()
                 for e in self.entries}
        data_dir = self.data_dir.name
        found: "list[Dict[str, Any]]" = []
        for root in self.roots:
            root_rel = str(root).replace("\\", "/").strip("/")
            bases = []
            host_base = self._host_path(root_rel)
            if host_base is not None:
                bases.append(host_base)
            bases.append(self.portable_profile.joinpath(*root_rel.split("/")))
            names: "set[str]" = set()
            for base in bases:
                try:
                    names.update(item.name for item in base.iterdir()
                                 if item.is_dir())
                except OSError:
                    continue
            for name in sorted(names):
                host_rel = f"{root_rel}/{name}"
                if host_rel.lower() in known \
                        or not _matches_tokens(name, self.tokens):
                    continue
                found.append({
                    "name": name,
                    "store": f"{data_dir}/User/{host_rel}",
                    "host": host_rel,
                    "portable": "",
                    "patterns": [],
                    "direction": "both",
                    "discovered": True,
                })
        return found

    def _all_entries(self) -> "list[Dict[str, Any]]":
        return [*self.entries, *self._discovered_entries()]

    def _satellites(self, entry: Dict[str, Any]) -> "list[Path]":
        store = self.root.joinpath(*entry["store"].split("/"))
        result: "list[Path]" = []
        if entry.get("host"):
            host = self._host_path(entry["host"])
            if host is not None:
                result.append(host)
        if entry.get("portable"):
            result.append(
                self.root.joinpath(*str(entry["portable"]).split("/")))
        return [p for p in result if p.resolve() != store.resolve()] \
            if result else []

    def _two_way(self, entry: Dict[str, Any]) -> bool:
        return entry["direction"] == "both" or entry["name"] in self.two_way

    # -- синхронизация ------------------------------------------------------
    def pull(self) -> "list[str]":
        """Забрать в портатив всё, что новее, из папок профиля."""
        if not self.enabled:
            return []
        report: "list[str]" = []
        for entry in self._all_entries():
            store = self.root.joinpath(*entry["store"].split("/"))
            for satellite in self._satellites(entry):
                copied = merge_saves(satellite, store, entry["patterns"])
                if copied:
                    report.append(
                        f"{entry['name']}: {len(copied)} file(s) taken into "
                        f"the portable store from {satellite}")
        return report

    def push(self) -> "list[str]":
        """Вернуть обновлённое наружу — для записей с двусторонним обменом."""
        if not self.enabled:
            return []
        report: "list[str]" = []
        for entry in self._all_entries():
            if not self._two_way(entry):
                continue
            store = self.root.joinpath(*entry["store"].split("/"))
            if not store.is_dir():
                continue
            for satellite in self._satellites(entry):
                # Чужой профиль не трогаем, пока отдавать нечего: пустая
                # папка в чужом Documents - это след, которого быть не должно.
                copied = merge_saves(store, satellite, entry["patterns"])
                if copied:
                    report.append(
                        f"{entry['name']}: {len(copied)} file(s) written back "
                        f"to {satellite}")
        return report

    def before(self) -> "list[str]":
        return self.pull()

    def after(self) -> "list[str]":
        """После выхода: забрать новое и, если нужно, отдать обратно.

        Если данные пришли из папки профиля ПОСЛЕ старта программы, значит
        программа пишет туда, а не в портатив (например, игра проигнорировала
        ``bUseMyGamesDirectory``). Такая запись переводится в двусторонний
        режим навсегда — иначе прямой запуск так и не увидел бы сейвы,
        сделанные через лончер.
        """
        if not self.enabled:
            return []
        report: "list[str]" = []
        changed = False
        for entry in self._all_entries():
            store = self.root.joinpath(*entry["store"].split("/"))
            for satellite in self._satellites(entry):
                copied = merge_saves(satellite, store, entry["patterns"])
                if not copied:
                    continue
                report.append(
                    f"{entry['name']}: {len(copied)} file(s) taken into the "
                    f"portable store from {satellite}")
                if not self._two_way(entry):
                    self.two_way.add(entry["name"])
                    changed = True
                    report.append(
                        f"{entry['name']}: the program keeps writing to "
                        f"{satellite}; both folders are kept in sync from now")
        if changed:
            self._save_state()
        report.extend(self.push())
        return report


_DRIVE_ROOT_SYSTEM_DIRS = frozenset({
    "windows", "program files", "program files (x86)", "programdata",
    "users", "documents and settings", "perflogs", "recovery", "intel",
    "amd", "nvidia", "msocache", "system volume information",
    "$recycle.bin", "boot", "efi", "temp", "tmp", "app", "portabledata",
    "redist", "_lang_sw",
})


def _pe_unsigned_checksum_offset(data: bytes) -> Optional[int]:
    """Return optional header CheckSum offset if PE is unsigned, else None."""
    if len(data) < 0x100 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return None
    if e_lfanew < 0x40 or e_lfanew + 0x58 > len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    optional = e_lfanew + 24
    try:
        magic = struct.unpack_from("<H", data, optional)[0]
    except struct.error:
        return None
    if magic == 0x10B:
        sec_dir = optional + 96 + 4 * 8
    elif magic == 0x20B:
        sec_dir = optional + 112 + 4 * 8
    else:
        return None
    if sec_dir + 8 > len(data):
        return None
    cert_rva, cert_size = struct.unpack_from("<II", data, sec_dir)
    if cert_rva != 0 or cert_size != 0:
        return None
    return optional + 64


class DriveRootDataSession:
    """Keep working folders like ``C:\\multitran`` inside the portable root.

    Programs such as Multitran default to ``C:\\<app_name>`` (storing
    ``<COMPUTERNAME>\\history.txt``, ``usertra.reu``, and
    ``Subject Profiles\\subject.act``, ``subject.sel``) when no portable
    working folder is configured or when a hardcoded ``c:\\<app_name>`` string
    lives inside an executable or DLL.

    This helper:
    1. Rewrites hardcoded ``<Drive>:\\<folder>`` literals to ``..\\<folder>``
       in unsigned ``App`` binaries and configuration files.
    2. Moves any ``<SystemDrive>:\\<folder>`` into ``<PortableRoot>\\<folder>``
       and removes ``<SystemDrive>:\\<folder>`` before launch and after exit.
    3. Synchronises ``<COMPUTERNAME>`` profile subfolders inside
       ``<PortableRoot>\\<folder>`` so moving the portable folder to another
       PC, drive, or partition keeps history and user profiles intact.
    """

    def __init__(self, root: Path, cfg: Dict[str, Any]) -> None:
        self.root = root
        self.cfg = cfg

    def _candidate_folders(self) -> List[str]:
        candidates: List[str] = []
        seen: set[str] = set()

        def _add(raw: str) -> None:
            token = raw.strip().strip("\\/\"'")
            if not token or len(token) < 3:
                return
            low = token.casefold()
            if low in seen or low in _DRIVE_ROOT_SYSTEM_DIRS:
                return
            if any(ch in token for ch in (":", "*", "?", "<", ">", "|", "\\", "/")):
                return
            seen.add(low)
            candidates.append(token)

        app_name = str(self.cfg.get("app_name", "")).strip()
        if app_name:
            _add(app_name)
            first_word = re.split(r"[\s_\-\.]+", app_name)[0]
            _add(first_word)

        reg_cfg = self.cfg.get("registry", {}) or {}
        for key in reg_cfg.get("keys", []) or []:
            parts = [p for p in str(key).replace("/", "\\").split("\\") if p]
            for idx, part in enumerate(parts):
                if part.casefold() == "software" and idx + 1 < len(parts):
                    seg = parts[idx + 1]
                    if seg.casefold() == "wow6432node" and idx + 2 < len(parts):
                        seg = parts[idx + 2]
                    _add(seg)
                    for sub in parts[idx + 1:]:
                        if sub.casefold() != "wow6432node":
                            _add(sub)

        for reg_name in (
            reg_cfg.get("file", "portable.reg"),
            reg_cfg.get("machine_file", "portable_machine.reg"),
        ):
            if not reg_name:
                continue
            reg_path = self.root / str(reg_name)
            if not reg_path.is_file():
                continue
            try:
                text = _decode_reg(reg_path.read_bytes())
            except OSError:
                continue
            for m in re.finditer(
                re.escape(ROOT_TOKEN) + r"(?:\\\\|\\)([^\\\"\\\r\n]+)",
                text,
                re.IGNORECASE,
            ):
                _add(m.group(1))
        return candidates

    def _neutralize_app_binaries_and_configs(self, folders: Sequence[str]) -> int:
        app_dir = self.root / "App"
        if not app_dir.is_dir() or not folders:
            return 0
        own_names = {
            "launchportable.exe",
            "portable_launcher.exe",
        }
        pe_exts = {".exe", ".dll"}
        text_exts = {".ini", ".cfg", ".conf", ".xml", ".json", ".txt", ".cmd", ".bat"}
        patched = 0
        for dirpath, _dirnames, filenames in os.walk(app_dir):
            for fname in filenames:
                if fname.casefold() in own_names:
                    continue
                fpath = Path(dirpath) / fname
                ext = fpath.suffix.lower()
                if ext not in pe_exts and ext not in text_exts:
                    continue
                try:
                    if fpath.stat().st_size > 64 * 1024 * 1024:
                        continue
                    raw = fpath.read_bytes()
                except OSError:
                    continue
                new_raw = raw
                if ext in pe_exts:
                    csum_off = _pe_unsigned_checksum_offset(raw)
                    if csum_off is None:
                        continue
                    for token in folders:
                        try:
                            tok_b = token.encode("ascii")
                        except UnicodeEncodeError:
                            continue
                        pat_a = re.compile(
                            b"(?<![A-Za-z0-9_])([A-Za-z]):(\\\\" + re.escape(tok_b) + b")(?=[\\\\\"'\\x00\\r\\n\\s])",
                            re.IGNORECASE,
                        )
                        new_raw = pat_a.sub(rb"..\2", new_raw)
                        tok_u = b"".join(bytes([b, 0]) for b in tok_b)
                        pat_u = re.compile(
                            b"([A-Za-z])\x00:\x00(\\\\\x00" + re.escape(tok_u) + b")(?=(?:\\\\\x00|\"\x00|'\x00|\x00\x00|\r\x00|\n\x00| \x00))",
                            re.IGNORECASE,
                        )
                        new_raw = pat_u.sub(b".\x00.\x00\\2", new_raw)
                    if new_raw != raw and len(new_raw) == len(raw):
                        buf = bytearray(new_raw)
                        struct.pack_into("<I", buf, csum_off, 0)
                        new_raw = bytes(buf)
                else:
                    for token in folders:
                        try:
                            tok_b = token.encode("ascii")
                        except UnicodeEncodeError:
                            continue
                        pat = re.compile(
                            b"(?<![A-Za-z0-9_])[A-Za-z]:([\\\\/]" + re.escape(tok_b) + b")(?=[\\\\/\"'\\r\\n\\s]|$)",
                            re.IGNORECASE,
                        )
                        new_raw = pat.sub(rb"..\1", new_raw)
                if new_raw != raw:
                    try:
                        fpath.write_bytes(new_raw)
                        patched += 1
                    except OSError:
                        pass
        return patched

    @staticmethod
    def _sync_computer_profiles(folder: Path) -> None:
        if not folder.is_dir():
            return
        comp_name = (
            os.environ.get("COMPUTERNAME")
            or os.environ.get("HOSTNAME")
            or ""
        ).strip()
        if not comp_name:
            return
        profile_dirs: List[Path] = []
        try:
            for child in folder.iterdir():
                if not child.is_dir():
                    continue
                has_markers = (
                    (child / "history.txt").exists()
                    or (child / "usertra.reu").exists()
                    or (child / "Subject Profiles").is_dir()
                )
                if has_markers or child.name.casefold() == comp_name.casefold():
                    profile_dirs.append(child)
        except OSError:
            return
        if not profile_dirs:
            return
        target_dir: Optional[Path] = None
        for d in profile_dirs:
            if d.name.casefold() == comp_name.casefold():
                target_dir = d
                break
        if target_dir is None:
            target_dir = folder / comp_name
            target_dir.mkdir(parents=True, exist_ok=True)
            profile_dirs.append(target_dir)

        def _latest_mtime(d: Path) -> float:
            latest = 0.0
            try:
                for root_d, _dirs, files in os.walk(d):
                    for f in files:
                        try:
                            mt = (Path(root_d) / f).stat().st_mtime
                            if mt > latest:
                                latest = mt
                        except OSError:
                            pass
            except OSError:
                pass
            return latest

        donor = max(profile_dirs, key=_latest_mtime)
        if _latest_mtime(donor) == 0.0:
            return
        for dest in profile_dirs:
            if dest == donor:
                continue
            try:
                for root_d, dirs, files in os.walk(donor):
                    rel = Path(root_d).relative_to(donor)
                    dest_root = dest / rel
                    dest_root.mkdir(parents=True, exist_ok=True)
                    for d in dirs:
                        (dest_root / d).mkdir(parents=True, exist_ok=True)
                    for f in files:
                        s_file = Path(root_d) / f
                        d_file = dest_root / f
                        try:
                            if (
                                not d_file.exists()
                                or s_file.stat().st_mtime > d_file.stat().st_mtime
                            ):
                                shutil.copy2(s_file, d_file)
                        except OSError:
                            pass
            except OSError:
                pass

    def _collect_drive_roots(self, folders: Sequence[str]) -> List[str]:
        report: List[str] = []
        if not folders:
            return report
        drive_roots: List[Path] = []
        sys_drive = os.environ.get("SystemDrive", "C:").strip()
        if sys_drive:
            if not sys_drive.endswith(("\\", "/")):
                sys_drive += os.sep
            drive_roots.append(Path(sys_drive))
        if self.root.drive:
            cur_drive = Path(self.root.drive + "\\")
            if all(str(cur_drive).casefold() != str(d).casefold() for d in drive_roots):
                drive_roots.append(cur_drive)

        try:
            portable_resolved = str(self.root.resolve()).casefold()
        except OSError:
            portable_resolved = str(self.root).casefold()

        for folder_token in folders:
            dest_dir: Optional[Path] = None
            try:
                for child in self.root.iterdir():
                    if child.is_dir() and child.name.casefold() == folder_token.casefold():
                        dest_dir = child
                        break
            except OSError:
                pass

            for drv in drive_roots:
                if not drv.is_dir():
                    continue
                matched_src: Optional[Path] = None
                try:
                    for child in drv.iterdir():
                        if child.is_dir() and child.name.casefold() == folder_token.casefold():
                            matched_src = child
                            break
                except OSError:
                    continue
                if matched_src is None:
                    continue
                try:
                    src_resolved = str(matched_src.resolve()).casefold()
                except OSError:
                    src_resolved = str(matched_src).casefold()
                if (
                    src_resolved == portable_resolved
                    or src_resolved.startswith(portable_resolved + "\\")
                    or src_resolved.startswith(portable_resolved + "/")
                ):
                    continue
                if dest_dir is None:
                    dest_dir = self.root / matched_src.name
                dest_dir.mkdir(parents=True, exist_ok=True)
                copied_files = 0
                for root_d, dirs, files in os.walk(matched_src):
                    rel = Path(root_d).relative_to(matched_src)
                    target_root = dest_dir / rel
                    target_root.mkdir(parents=True, exist_ok=True)
                    for d in dirs:
                        (target_root / d).mkdir(parents=True, exist_ok=True)
                    for f in files:
                        s_file = Path(root_d) / f
                        d_file = target_root / f
                        try:
                            if (
                                not d_file.exists()
                                or s_file.stat().st_mtime >= d_file.stat().st_mtime
                            ):
                                shutil.copy2(s_file, d_file)
                                copied_files += 1
                        except OSError:
                            pass
                shutil.rmtree(matched_src, ignore_errors=True)
                report.append(
                    f"relocated {matched_src} -> {dest_dir} ({copied_files} file(s))"
                )

            if dest_dir is not None and dest_dir.is_dir():
                self._sync_computer_profiles(dest_dir)
        return report

    def before(self) -> List[str]:
        folders = self._candidate_folders()
        if not folders:
            return []
        report: List[str] = []
        patched = self._neutralize_app_binaries_and_configs(folders)
        if patched:
            report.append(f"neutralized hardcoded drive paths in {patched} file(s)")
        report.extend(self._collect_drive_roots(folders))
        return report

    def after(self) -> List[str]:
        folders = self._candidate_folders()
        if not folders:
            return []
        return self._collect_drive_roots(folders)


class ShellFolderSession:
    """Temporarily point the Windows Documents known folder at PortableData.

    Changing ``USERPROFILE`` is not enough for applications using
    SHGetKnownFolderPath/Environment.GetFolderPath (The Witcher 2 configurator
    is one example).  The original values are persisted before the change, so
    a launcher interrupted by a reboot/crash repairs them on its next start.
    """

    USER_SHELL = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    LEGACY_SHELL = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    DOCUMENTS_GUID = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"

    def __init__(self, root: Path, cfg: Dict[str, Any]) -> None:
        data = root / cfg.get("data_dir_name", "PortableData")
        self.documents = data / "User" / "Documents"
        self.backup_file = data / "RegistryHostBackup" / "shell-folders.json"
        self.active = bool(cfg.get("redirect_known_folders")) and IS_WINDOWS
        self.started = False

    @classmethod
    def _locations(cls) -> tuple[tuple[str, str], ...]:
        return (
            (cls.USER_SHELL, "Personal"),
            (cls.USER_SHELL, cls.DOCUMENTS_GUID),
            (cls.LEGACY_SHELL, "Personal"),
            (cls.LEGACY_SHELL, cls.DOCUMENTS_GUID),
        )

    def restore(self) -> None:
        if not self.active or not self.backup_file.is_file():
            return
        try:
            import winreg

            state = json.loads(self.backup_file.read_text(encoding="utf-8"))
            for item in state.get("values", []):
                subkey = str(item["subkey"])
                name = str(item["name"])
                with winreg.CreateKeyEx(
                    winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE
                ) as key:
                    if item.get("exists"):
                        winreg.SetValueEx(
                            key, name, 0, int(item["type"]), item.get("value", "")
                        )
                    else:
                        try:
                            winreg.DeleteValue(key, name)
                        except FileNotFoundError:
                            pass
            self.backup_file.unlink()
            self.started = False
            _notify_shell_change()
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            # Keep the recovery file: a later start can retry instead of
            # forgetting how the host profile looked before redirection.
            return

    def load(self) -> None:
        if not self.active:
            return
        self.documents.mkdir(parents=True, exist_ok=True)
        # Recover a previous interrupted run first. Never stack backups.
        if self.backup_file.exists():
            self.restore()
            if self.backup_file.exists():
                return

        try:
            import winreg

            saved = []
            for subkey, name in self._locations():
                exists = False
                typ = winreg.REG_SZ
                value: Any = ""
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_QUERY_VALUE
                    ) as key:
                        value, typ = winreg.QueryValueEx(key, name)
                        exists = True
                except FileNotFoundError:
                    pass
                saved.append({
                    "subkey": subkey, "name": name, "exists": exists,
                    "type": int(typ), "value": value,
                })

            self.backup_file.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.backup_file.with_suffix(".tmp")
            temporary.write_text(
                json.dumps({"values": saved}, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(temporary, self.backup_file)

            for subkey, name in self._locations():
                value_type = (winreg.REG_EXPAND_SZ
                              if subkey == self.USER_SHELL else winreg.REG_SZ)
                with winreg.CreateKeyEx(
                    winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE
                ) as key:
                    winreg.SetValueEx(
                        key, name, 0, value_type, str(self.documents)
                    )
            self.started = True
            # Проводник и меню «Пуск» держат собственный кэш путей: без
            # уведомления они продолжают показывать старые «Документы»,
            # а иногда и отказываются строить меню. Уведомляем оболочку.
            _notify_shell_change()
        except (OSError, TypeError, ValueError):
            # If the backup exists, restore whatever was changed before
            # allowing the target to start.
            self.restore()


def _normalize_reg_section_header(raw_header: str) -> Optional[str]:
    cleaned = (raw_header or "").strip().strip("[]").strip().rstrip("\\")
    if not cleaned or cleaned.startswith("-"):
        return None
    parts = [p for p in cleaned.split("\\") if p]
    if len(parts) < 2:
        return None
    root_up = parts[0].upper()
    if root_up in ("HKEY_LOCAL_MACHINE", "HKLM"):
        parts[0] = "HKEY_LOCAL_MACHINE"
    elif root_up in ("HKEY_CURRENT_USER", "HKCU"):
        parts[0] = "HKEY_CURRENT_USER"
    else:
        return None
    if parts[1].upper() == "SOFTWARE":
        parts[1] = "Software"
    if len(parts) >= 3 and parts[2].upper() == "WOW6432NODE":
        parts[2] = "WOW6432Node"
    if (len(parts) >= 6
            and parts[1] == "Software"
            and parts[2].upper() == "CLASSES"
            and parts[3].upper() == "VIRTUALSTORE"
            and parts[4].upper() == "MACHINE"
            and parts[5].upper() == "SOFTWARE"):
        parts[2] = "Classes"
        parts[3] = "VirtualStore"
        parts[4] = "MACHINE"
        parts[5] = "SOFTWARE"
        if len(parts) >= 7 and parts[6].upper() == "WOW6432NODE":
            parts[6] = "WOW6432Node"
    return "\\".join(parts)


def _extract_software_tail(key: str) -> Optional[str]:
    norm = _normalize_reg_section_header(key)
    if not norm:
        return None
    parts = norm.split("\\")
    if len(parts) < 3 or parts[1] != "Software":
        return None
    if (len(parts) >= 7
            and parts[2] == "Classes"
            and parts[3] == "VirtualStore"
            and parts[4] == "MACHINE"
            and parts[5] == "SOFTWARE"):
        rest = parts[7:] if parts[6] == "WOW6432Node" else parts[6:]
    elif parts[2] == "WOW6432Node":
        rest = parts[3:]
    else:
        rest = parts[2:]
    if not rest:
        return None
    first_low = rest[0].casefold()
    if first_low == "classes":
        return None
    if first_low == "microsoft" and len(rest) >= 2 and rest[1].casefold() in (
        "windows", "windows nt",
    ):
        return None
    return "\\".join(rest)


def _machine_sibling_reg_key(key: str) -> Optional[str]:
    cleaned = str(key).strip().rstrip("\\")
    head, sep, rest = cleaned.partition("\\")
    if not sep or head.upper() not in ("HKLM", "HKEY_LOCAL_MACHINE"):
        return None
    s_head, s_sep, tail = rest.partition("\\")
    if not s_sep or s_head.upper() != "SOFTWARE" or not tail:
        return None
    if tail.lower().startswith("wow6432node\\"):
        sub = tail[len("wow6432node\\"):].strip("\\")
        return f"{head}\\{s_head}\\{sub}" if sub else None
    if tail.lower() == "wow6432node":
        return None
    return f"{head}\\{s_head}\\WOW6432Node\\{tail}"


def _split_reg_assignment(line: str) -> Optional[tuple[str, str]]:
    stripped = line.strip()
    if not stripped or stripped.startswith(";"):
        return None
    if stripped.startswith("@"):
        rest = stripped[1:].lstrip()
        if not rest.startswith("="):
            return None
        return "", rest[1:].strip()
    if not stripped.startswith('"'):
        return None
    i = 1
    n = len(stripped)
    chars: list[str] = []
    while i < n:
        ch = stripped[i]
        if ch == "\\" and i + 1 < n:
            chars.append(stripped[i + 1])
            i += 2
            continue
        if ch == '"':
            i += 1
            break
        chars.append(ch)
        i += 1
    else:
        return None
    rest = stripped[i:].lstrip()
    if not rest.startswith("="):
        return None
    return "".join(chars), rest[1:].strip()


def _parse_reg_sections(text: str) -> Dict[str, Dict[str, str]]:
    sections: Dict[str, Dict[str, str]] = {}
    if not text:
        return sections
    logical_lines: list[str] = []
    carry = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if carry:
            if line.endswith("\\"):
                carry += line[:-1].strip()
            else:
                carry += line
                logical_lines.append(carry)
                carry = ""
            continue
        if line.endswith("\\") and not line.startswith(";"):
            carry = line[:-1].strip()
        else:
            logical_lines.append(line)
    if carry:
        logical_lines.append(carry)

    current: Optional[str] = None
    sec_lookup: Dict[str, str] = {}
    for line in logical_lines:
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            header = _normalize_reg_section_header(line)
            if header is None:
                current = None
                continue
            existing = sec_lookup.get(header.casefold())
            if existing is None:
                existing = header
                sec_lookup[header.casefold()] = existing
                sections[existing] = {}
            current = existing
            continue
        if current is None:
            continue
        parsed = _split_reg_assignment(line)
        if parsed is None:
            continue
        name, rhs = parsed
        if rhs == "-":
            for k in list(sections[current]):
                if k.casefold() == name.casefold():
                    del sections[current][k]
            continue
        actual = next(
            (k for k in sections[current] if k.casefold() == name.casefold()),
            name,
        )
        sections[current][actual] = rhs
    return sections


def _render_reg_sections(sections: Dict[str, Dict[str, str]]) -> str:
    lines = ["Windows Registry Editor Version 5.00", ""]
    for header, values in sections.items():
        if not values:
            continue
        lines.append(f"[{header}]")
        for name, rhs in values.items():
            if name == "":
                quoted = "@"
            else:
                escaped_name = name.replace("\\", "\\\\").replace('"', '\\"')
                quoted = f'"{escaped_name}"'
            lines.append(f"{quoted}={rhs}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n\n"


def _format_reg_sz_rhs(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _read_host_key_reg_values(key: str) -> Dict[str, str]:
    """Read string/dword values from a host registry key into .reg RHS syntax."""
    if not IS_WINDOWS:
        return {}
    try:
        import winreg
    except ImportError:  # pragma: no cover - Windows only
        return {}
    cleaned = str(key).replace("/", "\\").strip("\\")
    head, _, subkey = cleaned.partition("\\")
    if not subkey:
        return {}
    roots = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    }
    root_handle = roots.get(head.upper())
    if root_handle is None:
        return {}
    out: Dict[str, str] = {}
    for access in (winreg.KEY_READ,
                   winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0),
                   winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)):
        try:
            with winreg.OpenKey(root_handle, subkey, 0, access) as handle:
                idx = 0
                while True:
                    try:
                        name, val, typ = winreg.EnumValue(handle, idx)
                    except OSError:
                        break
                    idx += 1
                    if typ == winreg.REG_SZ and isinstance(val, str):
                        out[name] = _format_reg_sz_rhs(val)
                    elif typ == winreg.REG_DWORD and isinstance(val, int):
                        out[name] = f"dword:{val & 0xFFFFFFFF:08x}"
                if out:
                    break
        except OSError:
            continue
    return out


_LAUNCHER_LANG_TOKENS: Dict[str, tuple[str, ...]] = {
    "ru": ("ru", "rus", "russian", "ru-ru", "ru_ru", "ruru", "1049", "0419", "0x0419", "00000419", "рус", "русский"),
    "en": ("en", "eng", "enu", "english", "en-us", "en_us", "enus", "1033", "0409", "0x0409", "00000409", "анг", "английский"),
    "uk": ("uk", "ukr", "ua", "ukrainian", "uk-ua", "uk_ua", "1058", "0422", "0x0422", "укр", "українська"),
    "de": ("de", "ger", "deu", "german", "deutsch", "de-de", "de_de", "1031", "0407", "0x0407"),
    "fr": ("fr", "fre", "fra", "french", "francais", "français", "fr-fr", "fr_fr", "1036", "040c", "0x040c"),
    "it": ("it", "ita", "italian", "italiano", "it-it", "it_it", "1040", "0410", "0x0410"),
    "es": ("es", "spa", "esp", "spanish", "espanol", "español", "es-es", "es_es", "3082", "1034", "0c0a", "040a"),
    "pl": ("pl", "pol", "polish", "polski", "pl-pl", "pl_pl", "1045", "0415", "0x0415"),
    "pt-br": ("pt-br", "pt_br", "ptbr", "pt", "ptb", "bra", "por", "brazilian", "portuguese", "1046", "0416"),
    "zh-cn": ("zh-cn", "zh_cn", "zhcn", "zh", "chs", "chi", "zho", "schinese", "chinese", "2052", "0804"),
    "ja": ("ja", "jp", "jpn", "jap", "japanese", "ja-jp", "ja_jp", "1041", "0411"),
    "tr": ("tr", "tur", "trk", "turkish", "tr-tr", "tr_tr", "1055", "041f"),
}


def _identify_launcher_lang(token: str) -> Optional[str]:
    low = (token or "").strip().strip("\"'").casefold()
    if not low:
        return None
    for code, toks in _LAUNCHER_LANG_TOKENS.items():
        if low in toks:
            return code
    return None


def _detect_app_reg_file_lang(
    sections: Dict[str, Dict[str, str]],
    rel_path: str,
) -> Optional[str]:
    for vals in sections.values():
        for name, rhs in vals.items():
            if name.casefold() in (
                "language", "installlanguage", "textlanguage",
                "subtitlelanguage", "uilanguage", "locale", "lang",
            ):
                code = _identify_launcher_lang(rhs)
                if code:
                    return code
    stem = os.path.splitext(rel_path.replace("/", "\\"))[0]
    for part in reversed([p for p in stem.split("\\") if p]):
        subtokens = [t for t in re.split(r"[^0-9A-Za-zА-Яа-яЁёІіЇїЄєҐґ]+", part) if t]
        found: list[str] = []
        for cand in [part, *subtokens]:
            code = _identify_launcher_lang(cand)
            if code and code not in found:
                found.append(code)
        if len(found) == 1:
            return found[0]
    return None


#: Каталоги внутри App, где .reg-файлов программы заведомо нет. Обход дерева
#: пакетов (``node_modules`` у Cursor/VS Code — десятки тысяч файлов) на каждом
#: запуске стоил секунд на медленном диске, а результата не давал.
APP_REG_SKIP_DIRS = frozenset({
    "portabledata", "redist", "_redist_cache", "updates",
    "node_modules", ".git", ".hg", ".svn", "cache", "caches", "logs", "temp",
    # Содержимое onedir-сборки самого лончера (``App\_internal``): .reg-файлов
    # там нет, а обход стоит времени.
    "_internal",
})

#: Результат обхода App в этом процессе: ``sync_external_changes`` вызывается
#: дважды за запуск, и второй раз обходить дерево незачем.
_APP_REG_CACHE: Dict[str, tuple] = {}

#: Список найденных ``.reg`` запоминается и на диске: у Cursor в App десятки
#: тысяч файлов, и полный обход дерева на каждом запуске — это секунды до
#: появления окна. Ключ кэша — время изменения самой папки App, поэтому после
#: обновления программы (установщик меняет содержимое App) обход повторится.
APP_REG_CACHE_NAME = "app-reg-files.json"


def _app_reg_cache_file(root: Path,
                        cfg: "Optional[Dict[str, Any]]" = None) -> Path:
    return _data_dir(root, cfg or {}) / APP_REG_CACHE_NAME


def _read_app_reg_cache(root: Path,
                        cfg: "Optional[Dict[str, Any]]",
                        stamp: int) -> "Optional[list[str]]":
    """Список ``.reg`` из прошлого запуска, если App с тех пор не менялась."""
    try:
        data = json.loads(_app_reg_cache_file(root, cfg).read_text(
            encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or int(data.get("app_mtime") or -1) != stamp:
        return None
    files = data.get("files")
    if not isinstance(files, list):
        return None
    return [str(item) for item in files]


def _write_app_reg_cache(root: Path,
                         cfg: "Optional[Dict[str, Any]]",
                         stamp: int, files: "list[str]") -> None:
    target = _app_reg_cache_file(root, cfg)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({
            "app_mtime": stamp,
            "files": files,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def _load_app_reg_file(
        app_dir: Path, rel: str
) -> "Optional[tuple[Path, Dict[str, Dict[str, str]], Optional[str]]]":
    """Читает и разбирает один ``.reg`` из App (``None`` — не подходит)."""
    fpath = app_dir / rel.replace("/", os.sep)
    try:
        text = _decode_reg(fpath.read_bytes())
    except OSError:
        return None
    sections = _parse_reg_sections(text)
    if not any(_extract_software_tail(sec) for sec in sections):
        return None
    lang = _detect_app_reg_file_lang(sections, rel)
    return (fpath, sections, lang)


def _discover_app_reg_files(
    root: Path, cfg: "Optional[Dict[str, Any]]" = None,
) -> list[tuple[Path, Dict[str, Dict[str, str]], Optional[str]]]:
    app_dir = root / "App"
    if not app_dir.is_dir():
        return []
    try:
        stamp = os.stat(app_dir).st_mtime_ns
    except OSError:
        stamp = 0
    cached = _APP_REG_CACHE.get(str(app_dir))
    if cached is not None and cached[0] == stamp:
        return list(cached[1])

    known = _read_app_reg_cache(root, cfg, stamp)
    if known is not None:
        out: "list[tuple[Path, Dict[str, Dict[str, str]], Optional[str]]]" = []
        for rel in known:
            item = _load_app_reg_file(app_dir, rel)
            if item is not None:
                out.append(item)
        _APP_REG_CACHE[str(app_dir)] = (stamp, out)
        return out

    out = []
    skip = APP_REG_SKIP_DIRS
    found_rel: "list[str]" = []
    for cur_root, dirs, files in os.walk(app_dir):
        dirs[:] = sorted(d for d in dirs if d.casefold() not in skip)
        for fname in sorted(files):
            if not fname.lower().endswith(".reg"):
                continue
            if fname.lower() in ("portable.reg", "portable_machine.reg", "cleanup_host.reg"):
                continue
            fpath = Path(cur_root) / fname
            rel = str(fpath.relative_to(app_dir))
            item = _load_app_reg_file(app_dir, rel)
            if item is None:
                continue
            found_rel.append(rel)
            out.append(item)
    _APP_REG_CACHE[str(app_dir)] = (stamp, out)
    _write_app_reg_cache(root, cfg, stamp, found_rel)
    return out


# --- быстрый экспорт реестра --------------------------------------------------
#
# `reg.exe export` — отдельный процесс на каждый ключ: 40-150 мс каждый. У
# программы вроде Cursor ключей десятки, и лончер запускал их все перед стартом
# (и ещё раз столько же при закрытии) — окно программы ждало секунды, хотя
# прямой запуск exe открывался сразу. Поэтому снимок ключей делается напрямую
# через winreg: значения читаются тем же вызовом, каким их пишет regedit, и
# складываются в один .reg-файл — импорт при восстановлении тоже один.

#: Типы значений winreg, которые умеет записывать .reg-файл.
REG_TYPE_SZ = 1
REG_TYPE_EXPAND_SZ = 2
REG_TYPE_BINARY = 3
REG_TYPE_DWORD = 4
REG_TYPE_LINK = 6
REG_TYPE_MULTI_SZ = 7
REG_TYPE_QWORD = 11

#: Потолок числа ключей в одном снимке: защита от гигантских поддеревьев
#: (`Software\\Classes` целиком). Дальше — обычный `reg export`.
REG_SNAPSHOT_MAX_KEYS = 20000

#: Имя файла снимка реестра в PortableData\\RegistryHostBackup.
REGISTRY_SNAPSHOT_NAME = "all-keys.reg"

#: Экспорт ключей, созданных установщиком: нужен для сведения настроек.
REGISTRY_CREATED_NAME = "created-keys.reg"

#: Потолок глубины обхода: ключи приложения не бывают глубже.
REG_SNAPSHOT_MAX_DEPTH = 32


def _escape_reg_string(text: str) -> str:
    """Строка для .reg: обратный слэш и кавычка экранируются."""
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def _reg_hex_value(prefix: str, kind: "Optional[int]", payload: bytes) -> str:
    """Значение в виде ``hex:``/``hex(2):`` с переносами, как у regedit."""
    label = "hex" if kind is None else f"hex({kind})"
    digits = ",".join(f"{byte:02x}" for byte in payload)
    chunks = [digits[i:i + 72] for i in range(0, len(digits), 72)] or [""]
    body = "\\\r\n  ".join(chunks)
    return f"{prefix}={label}:{body}"


def _reg_utf16_payload(text: str) -> bytes:
    """Строка ``REG_SZ`` в том виде, в каком её пишет regedit в ``hex(2)``."""
    return str(text).encode("utf-16-le") + b"\x00\x00"


def _reg_value_line(name: str, kind: int, value: Any) -> "Optional[str]":
    """Строка значения для .reg или ``None``, если тип не поддержан."""
    prefix = "@" if not name else '"' + _escape_reg_string(name) + '"'
    if kind == REG_TYPE_SZ and isinstance(value, str):
        return f'{prefix}="{_escape_reg_string(value)}"'
    if kind == REG_TYPE_EXPAND_SZ and isinstance(value, str):
        return _reg_hex_value(prefix, kind, _reg_utf16_payload(value))
    if kind == REG_TYPE_MULTI_SZ and isinstance(value, (list, tuple)):
        payload = b"".join(_reg_utf16_payload(str(item)) for item in value)
        return _reg_hex_value(prefix, kind, payload + b"\x00\x00")
    if kind == REG_TYPE_DWORD and isinstance(value, int):
        return f"{prefix}=dword:{int(value) & 0xFFFFFFFF:08x}"
    if kind == REG_TYPE_QWORD and isinstance(value, int):
        raw = int(value).to_bytes(8, "little", signed=int(value) < 0)
        return _reg_hex_value(prefix, 0x0b, raw)
    if isinstance(value, (bytes, bytearray)):
        # REG_BINARY у regedit пишется как ``hex:``, остальные типы — ``hex(N)``.
        label = None if kind == REG_TYPE_BINARY else kind
        return _reg_hex_value(prefix, label, bytes(value))
    if isinstance(value, str):
        return f'{prefix}="{_escape_reg_string(value)}"'
    return None


def _export_key_lines(reg, hive_full: str, path: str, budget: "list[int]",
                      depth: int = 0) -> "list[str]":
    """Секции .reg для ключа и всех его подключей (``reg export`` целиком)."""
    if budget[0] <= 0 or depth > REG_SNAPSHOT_MAX_DEPTH:
        return []
    hive = getattr(reg, hive_full, None)
    if hive is None:
        return []
    try:
        handle = reg.OpenKey(hive, path, 0, reg.KEY_READ)
    except OSError:
        return []
    budget[0] -= 1
    values: "list[str]" = []
    children: "list[str]" = []
    with handle:
        index = 0
        while True:
            try:
                name, value, kind = reg.EnumValue(handle, index)
            except OSError:
                break
            index += 1
            try:
                typed = int(kind)
            except (TypeError, ValueError):
                continue
            line = _reg_value_line(str(name), typed, value)
            if line:
                values.append(line)
        index = 0
        while True:
            try:
                children.append(reg.EnumKey(handle, index))
            except OSError:
                break
            index += 1
    lines: "list[str]" = []
    # Секция пишется даже без значений: пустой ключ тоже часть состояния, и
    # при восстановлении он должен появиться (regedit пишет так же).
    lines.append(f"[{hive_full}\\{path}]")
    lines.extend(values)
    lines.append("")
    for child in children:
        lines.extend(_export_key_lines(reg, hive_full, path + "\\" + child,
                                       budget, depth + 1))
    return lines


def export_registry_text(keys: "Sequence[str]",
                         root: "Optional[Path]" = None) -> str:
    """Снимок ключей в виде одного .reg-документа (пусто — снимать нечего)."""
    reg = _winreg()
    if reg is None:
        return ""
    budget = [REG_SNAPSHOT_MAX_KEYS]
    body: "list[str]" = []
    for key in keys:
        hive_short, _sep, path = str(key).partition("\\")
        hive_full = _HIVE_BY_NAME.get(hive_short.upper(), "")
        if not hive_full or not path:
            continue
        body.extend(_export_key_lines(reg, hive_full, path, budget))
        if budget[0] <= 0:
            _run_log(root, "registry: snapshot budget reached, the rest is "
                           "exported by reg.exe")
            return ""
    if not body:
        return ""
    header = ["Windows Registry Editor Version 5.00", ""]
    return "\r\n".join(header + body)


#: Типы значений .reg, которые можно записать напрямую через winreg.
_REG_PLAIN_STRING_TYPES = {1: "REG_SZ", 2: "REG_EXPAND_SZ"}


def _reg_rhs_value(rhs: str) -> "Optional[tuple[int, Any]]":
    """Значение .reg (правая часть ``"Имя"=...``) -> ``(тип, значение)``.

    Понимает ровно то, что пишут regedit и мы сами: строки, ``dword:`` и
    ``hex:``/``hex(N):`` (включая UTF-16 строки). ``None`` — тип неизвестен,
    такой файл лучше отдать ``reg.exe``.
    """
    text = rhs.strip()
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        body = text[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        return REG_TYPE_SZ, body
    lowered = text.casefold()
    if lowered.startswith("dword:"):
        try:
            return REG_TYPE_DWORD, int(text[6:].strip(), 16) & 0xFFFFFFFF
        except ValueError:
            return None
    if not lowered.startswith("hex"):
        return None
    kind: "Optional[int]" = REG_TYPE_BINARY
    rest = text[3:]
    if rest.startswith("(") and ")" in rest:
        spec, _sep, rest = rest[1:].partition(")")
        try:
            kind = int(spec.strip(), 0)
        except ValueError:
            return None
    if not rest.startswith(":"):
        return None
    digits = "".join(ch for ch in rest[1:] if ch not in " \r\n\t")
    if not digits:
        raw = b""
    else:
        try:
            raw = bytes(int(item, 16) for item in digits.split(",") if item)
        except ValueError:
            return None
    if kind in (REG_TYPE_BINARY, 0):
        return REG_TYPE_BINARY, raw
    if kind in _REG_PLAIN_STRING_TYPES:
        value = raw.decode("utf-16-le", "replace").rstrip("\x00")
        return kind, value
    if kind == REG_TYPE_MULTI_SZ:
        parts = raw.decode("utf-16-le", "replace").split("\x00")
        while parts and not parts[-1]:
            parts.pop()
        return REG_TYPE_MULTI_SZ, parts
    if kind == REG_TYPE_DWORD:
        if len(raw) >= 4:
            return REG_TYPE_DWORD, int.from_bytes(raw[:4], "little")
        return None
    if kind == REG_TYPE_QWORD:
        if len(raw) >= 8:
            return REG_TYPE_QWORD, int.from_bytes(raw[:8], "little")
        return None
    return kind, raw


def _reg_hive_handle(reg, header: str):
    """``(куст, путь)`` из заголовка секции; ``None`` — не наш куст."""
    parts = [part for part in str(header).split("\\") if part]
    if len(parts) < 2:
        return None
    hive_name = _HIVE_BY_NAME.get(parts[0].upper(), "")
    if not hive_name:
        return None
    hive = getattr(reg, hive_name, None)
    if hive is None:
        return None
    return hive, "\\".join(parts[1:])


def import_registry_text(text: str) -> bool:
    """Применяет .reg-документ напрямую через winreg (без процесса reg.exe).

    Возвращает ``True``, только если файл применён целиком. Если в нём есть
    удаления (``"имя"=-``, ``[-КЛЮЧ]``), тип значения, которого мы не знаем,
    или машинный куст без прав администратора — ``False``: вызывающий код
    импортирует файл прежним способом через ``reg.exe`` и получит ровно
    прежнее поведение.
    """
    reg = _winreg()
    if reg is None or not text:
        return False
    lowered = text.casefold()
    if "=-" in lowered or "[-hkey" in lowered:
        return False
    sections = _parse_reg_sections(text)
    if not sections:
        return False
    if "hkey_local_machine" in lowered and not _is_elevated():
        # Машинные ключи пишет только администратор; запасной путь reg.exe
        # сообщит об отказе так же, как раньше.
        return False
    try:
        for header, values in sections.items():
            located = _reg_hive_handle(reg, header)
            if located is None:
                continue
            hive, path = located
            with reg.CreateKeyEx(hive, path, 0, reg.KEY_WRITE) as handle:
                for name, rhs in values.items():
                    parsed = _reg_rhs_value(rhs)
                    if parsed is None:
                        return False
                    kind, value = parsed
                    reg.SetValueEx(handle, name, 0, kind, value)
    except OSError:
        return False
    return True


def import_registry_file(path: Path, root: "Optional[Path]" = None) -> bool:
    """Импорт .reg напрямую, если это возможно; иначе — обычный ``reg import``."""
    try:
        text = _decode_reg(path.read_bytes())
    except OSError:
        return False
    if not import_registry_text(text):
        return _reg(("import", str(path))) == 0
    _run_log(root, "registry import " + path.name + ": ok (direct)")
    return True


def write_reg_file(path: Path, text: str) -> bool:
    """Записывает .reg в UTF-16 с BOM и CRLF (так его понимает reg import)."""
    if not text:
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(text.encode("utf-16"))
        os.replace(temporary, path)
        return True
    except OSError:
        return False


def delete_key_tree(key: str) -> bool:
    """Удаляет ключ реестра вместе с подключами без запуска reg.exe."""
    reg = _winreg()
    if reg is None:
        return False
    hive_short, _sep, path = str(key).partition("\\")
    hive_full = _HIVE_BY_NAME.get(hive_short.upper(), "")
    hive = getattr(reg, hive_full, None) if hive_full else None
    if hive is None or not path:
        return False

    def _remove(sub: str) -> None:
        names: "list[str]" = []
        try:
            with reg.OpenKey(hive, sub, 0, reg.KEY_READ) as handle:
                index = 0
                while True:
                    try:
                        names.append(reg.EnumKey(handle, index))
                    except OSError:
                        break
                    index += 1
        except OSError:
            names = []
        for child in names:
            _remove(sub + "\\" + child)
        try:
            reg.DeleteKey(hive, sub)
        except OSError:
            pass

    _remove(path)
    # Проверяем результат: если ключ остался (нет прав, занят), вызывающий
    # код успеет убрать его через reg.exe.
    try:
        reg.CloseKey(reg.OpenKey(hive, path, 0, reg.KEY_READ))
    except OSError:
        return True
    return False


#: Результат последнего ``sync_external_changes`` по корню портатива:
#: ``{корень: (отпечаток_входов, записи)}``. Функция вызывается до трёх раз
#: за запуск, и повторный разбор тех же файлов — чистая трата времени.
_REGISTRY_SYNC_CACHE: Dict[str, tuple] = {}


class RegistrySession:
    """Apply portable settings, save changes, and restore the host afterwards."""

    def __init__(self, root: Path, cfg: Dict[str, Any]) -> None:
        self.root = root
        self.full_cfg = cfg
        self.cfg = cfg.get("registry", {})
        self.language = str(cfg.get("language") or "").strip()
        data = root / cfg.get("data_dir_name", "PortableData")
        self.session = data / "Registry"
        self.backup = data / "RegistryHostBackup"
        self.runtime = self.backup / "RuntimeImports"
        self.keys = list(self.cfg.get("keys", []))
        self.created = {str(key).casefold() for key in self.cfg.get("created_keys", [])}
        self.active = bool(self.cfg.get("enabled")) and IS_WINDOWS
        self.started = False
        #: Снимок машины уже снят (см. prepare) — повторно его не делаем.
        self.prepared = False
        #: Файлы настроек, которые надо импортировать (заполняет prepare).
        self.sources: list[Path] = []
        self.created_exports: list[Path] = []
        self._prepare_seconds = 0.0

    def _apply_tail_overrides_to_files(
        self,
        overrides: Dict[str, Tuple[str, Dict[str, Tuple[str, str]]]],
        base_values: Dict[str, Tuple[str, Dict[str, Tuple[str, str]]]],
    ) -> None:
        """Write overridden (tail, val_name -> rhs) into portable.reg,
        portable_machine.reg, and PortableData\\Registry\\*.reg across all
        HKLM, WOW6432Node, HKCU, and VirtualStore mirrors.
        """
        if not overrides:
            return
        initial_name = self.cfg.get("file", "portable.reg")
        machine_name = self.cfg.get("machine_file", "portable_machine.reg")
        initial_path = self.root / str(initial_name) if initial_name else None
        machine_path = self.root / str(machine_name) if machine_name else None

        def _update_section_map(
            sections: Dict[str, Dict[str, str]],
            target_headers: Sequence[str],
            tail_cf: str,
        ) -> bool:
            changed = False
            _tail_orig, ov_vals = overrides[tail_cf]
            base_vals = base_values.get(tail_cf, ("", {}))[1]
            for hdr in target_headers:
                actual_hdr = next(
                    (h for h in sections if h.casefold() == hdr.casefold()),
                    hdr,
                )
                sec_vals = sections.setdefault(actual_hdr, {})
                existing_names = {n.casefold(): n for n in sec_vals}
                for b_cf, (b_name, b_rhs) in base_vals.items():
                    if b_cf not in existing_names:
                        sec_vals[b_name] = b_rhs
                        existing_names[b_cf] = b_name
                        changed = True
                for v_cf, (v_name, v_rhs) in ov_vals.items():
                    target_name = existing_names.get(v_cf, v_name)
                    if sec_vals.get(target_name) != v_rhs:
                        sec_vals[target_name] = v_rhs
                        existing_names[v_cf] = target_name
                        changed = True
            return changed

        if initial_path and initial_path.is_file():
            try:
                u_sec = _parse_reg_sections(_decode_reg(initial_path.read_bytes()))
                u_changed = False
                for tail_cf, (tail_str, _ov) in overrides.items():
                    u_headers = (
                        f"HKEY_CURRENT_USER\\Software\\{tail_str}",
                        f"HKEY_CURRENT_USER\\Software\\WOW6432Node\\{tail_str}",
                        f"HKEY_CURRENT_USER\\Software\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\{tail_str}",
                        f"HKEY_CURRENT_USER\\Software\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\WOW6432Node\\{tail_str}",
                    )
                    if _update_section_map(u_sec, u_headers, tail_cf):
                        u_changed = True
                if u_changed and u_sec:
                    initial_path.write_text(
                        _render_reg_sections(u_sec),
                        encoding="utf-16",
                        newline="\r\n",
                    )
            except OSError:
                pass

        if machine_path and machine_path.is_file():
            try:
                m_sec = _parse_reg_sections(_decode_reg(machine_path.read_bytes()))
                m_changed = False
                for tail_cf, (tail_str, _ov) in overrides.items():
                    m_headers = (
                        f"HKEY_LOCAL_MACHINE\\Software\\{tail_str}",
                        f"HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\{tail_str}",
                    )
                    if _update_section_map(m_sec, m_headers, tail_cf):
                        m_changed = True
                if m_changed and m_sec:
                    machine_path.write_text(
                        _render_reg_sections(m_sec),
                        encoding="utf-16",
                        newline="\r\n",
                    )
            except OSError:
                pass

        if self.session.is_dir():
            for s_file in sorted(self.session.glob("*.reg")):
                try:
                    s_sec = _parse_reg_sections(_decode_reg(s_file.read_bytes()))
                    if not s_sec:
                        continue
                    s_changed = False
                    for hdr in list(s_sec.keys()):
                        tail = _extract_software_tail(hdr)
                        if not tail or tail.casefold() not in overrides:
                            continue
                        if _update_section_map(s_sec, (hdr,), tail.casefold()):
                            s_changed = True
                    if s_changed:
                        s_file.write_text(
                            _render_reg_sections(s_sec),
                            encoding="utf-16",
                            newline="\r\n",
                        )
                except OSError:
                    pass

    def _sync_fingerprint(
            self, extra_files: Sequence[Path] = ()
    ) -> "tuple":
        """Отпечаток входных файлов: (путь, размер, время изменения).

        Дешёвый способ понять, что с прошлого вызова ничего не изменилось:
        сам разбор .reg-файлов (и особенно ``_read_host_key_reg_values``)
        заметно дороже пары ``stat``.
        """
        initial_name = self.cfg.get("file", "portable.reg")
        machine_name = self.cfg.get("machine_file", "portable_machine.reg")
        paths: "list[Path]" = []
        for name in (initial_name, machine_name):
            if name:
                paths.append(self.root / str(name))
        if self.session.is_dir():
            try:
                paths.extend(sorted(self.session.glob("*.reg")))
            except OSError:
                pass
        paths.extend(Path(item) for item in extra_files)
        stamps: "list[tuple[str, int, int]]" = []
        for path in paths:
            try:
                stat = path.stat()
            except OSError:
                continue
            stamps.append((str(path), int(stat.st_size), int(stat.st_mtime_ns)))
        return tuple(stamps)

    def sync_external_changes(
        self,
        extra_files: Sequence[Path] = (),
    ) -> list[str]:
        """Absorb external .reg changes (such as _Lang_SW\\x64\\Rus.reg applied
        on the host PC while the game was closed) into portable.reg,
        portable_machine.reg, and PortableData\\Registry\\*.reg before import.

        Вызывается до трёх раз за запуск (перед стартом, из ``load`` и ещё раз
        с экспортом созданных ключей). Повторный разбор тех же файлов ничего
        не меняет, поэтому результат запоминается по отпечатку входов.
        """
        if not self.active:
            return []

        fingerprint = self._sync_fingerprint(extra_files)
        cached = _REGISTRY_SYNC_CACHE.get(str(self.root))
        if cached is not None and cached[0] == fingerprint:
            return list(cached[1])

        initial_name = self.cfg.get("file", "portable.reg")
        machine_name = self.cfg.get("machine_file", "portable_machine.reg")
        initial_path = self.root / str(initial_name) if initial_name else None
        machine_path = self.root / str(machine_name) if machine_name else None

        base_values: Dict[str, Tuple[str, Dict[str, Tuple[str, str]]]] = {}
        user_current: Dict[str, Dict[str, str]] = {}
        for p in (initial_path, machine_path):
            if p is None or not p.is_file():
                continue
            try:
                secs = _parse_reg_sections(_decode_reg(p.read_bytes()))
            except OSError:
                continue
            for hdr, vals in secs.items():
                tail = _extract_software_tail(hdr)
                if not tail:
                    continue
                t_cf = tail.casefold()
                _, b_map = base_values.setdefault(t_cf, (tail, {}))
                for v_name, v_rhs in vals.items():
                    b_map.setdefault(v_name.casefold(), (v_name, v_rhs))
                    if hdr.startswith("HKEY_CURRENT_USER\\"):
                        user_current.setdefault(t_cf, {})[v_name.casefold()] = v_rhs

        saved_files = sorted(self.session.glob("*.reg")) if self.session.is_dir() else []
        session_hklm: Dict[str, Tuple[str, Dict[str, Tuple[str, str]]]] = {}
        for s_file in saved_files:
            try:
                secs = _parse_reg_sections(_decode_reg(s_file.read_bytes()))
            except OSError:
                continue
            for hdr, vals in secs.items():
                tail = _extract_software_tail(hdr)
                if not tail:
                    continue
                t_cf = tail.casefold()
                if hdr.startswith("HKEY_CURRENT_USER\\"):
                    for v_name, v_rhs in vals.items():
                        user_current.setdefault(t_cf, {})[v_name.casefold()] = v_rhs
                elif hdr.startswith("HKEY_LOCAL_MACHINE\\"):
                    _, m_map = session_hklm.setdefault(t_cf, (tail, {}))
                    for v_name, v_rhs in vals.items():
                        m_map[v_name.casefold()] = (v_name, v_rhs)

        candidate_tails: Dict[str, str] = {}
        for k in list(self.cfg.get("created_keys", [])) + list(self.keys):
            tail = _extract_software_tail(str(k))
            if tail:
                candidate_tails.setdefault(tail.casefold(), tail)

        app_regs = _discover_app_reg_files(self.root, self.full_cfg)
        for _fpath, secs, _lang in app_regs:
            for hdr in secs:
                tail = _extract_software_tail(hdr)
                if tail:
                    candidate_tails.setdefault(tail.casefold(), tail)

        overrides: Dict[str, Tuple[str, Dict[str, Tuple[str, str]]]] = {}
        notes: list[str] = []

        def _record_override(tail: str, v_name: str, v_rhs: str, source_tag: str) -> None:
            if v_name.casefold() in (
                "installdir", "installdirectory", "installfolder", "installlocation",
            ):
                return
            t_cf = tail.casefold()
            v_cf = v_name.casefold()
            base_rhs = base_values.get(t_cf, ("", {}))[1].get(v_cf, ("", ""))[1]
            cur_u_rhs = user_current.get(t_cf, {}).get(v_cf, "")
            # Никогда не затираем портативный маркер @@PORTABLE_ROOT@@ сырыми
            # путями из реестра хоста (например, c:\multitran или путём
            # дистрибутива, оставшимся после работы setup.exe).
            if ROOT_TOKEN in base_rhs or ROOT_TOKEN in cur_u_rhs:
                return
            if source_tag in ("host-export", "host-registry") and re.match(
                r'^"?[A-Za-z]:[\\/]', v_rhs.strip()
            ):
                return
            if v_rhs == base_rhs and (not cur_u_rhs or v_rhs == cur_u_rhs):
                return
            _, ov_map = overrides.setdefault(t_cf, (tail, {}))
            if ov_map.get(v_cf) != (v_name, v_rhs):
                ov_map[v_cf] = (v_name, v_rhs)
                notes.append(f"{source_tag}: {tail} -> {v_name}={v_rhs}")

        # 1. Явно переданные .reg-файлы (например, экспортированный с хоста
        #    created_key перед импортом).
        for ef in extra_files:
            if not ef.is_file():
                continue
            try:
                secs = _parse_reg_sections(_decode_reg(ef.read_bytes()))
            except OSError:
                continue
            for hdr, vals in secs.items():
                tail = _extract_software_tail(hdr)
                if not tail:
                    continue
                for v_name, v_rhs in vals.items():
                    _record_override(tail, v_name, v_rhs, "host-export")

        # 2. Значения в реестре хоста (например, после двойного клика по
        #    _Lang_SW\x64\Rus.reg при закрытой игре).
        no_active_backup = not (self.backup.is_dir() and any(self.backup.glob("*.reg")))
        if no_active_backup and candidate_tails:
            for t_cf, tail in candidate_tails.items():
                for probe_key in (
                    f"HKLM\\Software\\WOW6432Node\\{tail}",
                    f"HKLM\\Software\\{tail}",
                    f"HKCU\\Software\\WOW6432Node\\{tail}",
                    f"HKCU\\Software\\{tail}",
                ):
                    host_vals = _read_host_key_reg_values(probe_key)
                    for v_name, v_rhs in host_vals.items():
                        _record_override(tail, v_name, v_rhs, "host-registry")

        # 3. Несоответствие между сохранённым HKLM (k04.reg) и HKCU/VirtualStore
        #    от прошлого запуска без прав администратора.
        for t_cf, (tail, m_map) in session_hklm.items():
            for v_cf, (v_name, v_rhs) in m_map.items():
                base_rhs = base_values.get(t_cf, ("", {}))[1].get(v_cf, ("", ""))[1]
                cur_u_rhs = user_current.get(t_cf, {}).get(v_cf, "")
                if cur_u_rhs and v_rhs != cur_u_rhs and v_rhs != base_rhs:
                    _record_override(tail, v_name, v_rhs, "session-hklm")

        # 4. Если выбран язык в launcher_config.json, а в App есть _Lang_SW .reg
        #    для этого языка и внешних переопределений с хоста не было.
        if self.language and not overrides and app_regs:
            target_lang = self.language.casefold()
            for fpath, secs, lang in app_regs:
                if not lang or lang.casefold() != target_lang:
                    continue
                for hdr, vals in secs.items():
                    tail = _extract_software_tail(hdr)
                    if not tail:
                        continue
                    for v_name, v_rhs in vals.items():
                        _record_override(tail, v_name, v_rhs, fpath.name)

        if overrides:
            self._apply_tail_overrides_to_files(overrides, base_values)
            for note in notes:
                _run_log(self.root, f"registry sync: {note}")
        # Отпечаток снимается ПОСЛЕ работы: файлы могли быть перезаписаны, и
        # следующий вызов должен попасть в кэш только с новым отпечатком.
        _REGISTRY_SYNC_CACHE[str(self.root)] = (
            self._sync_fingerprint(extra_files), list(notes))
        return notes

    def _split_keys(self) -> "tuple[list[str], list[str]]":
        """Ключи на две группы: исходные на этом ПК и созданные установщиком.

        Вторые не входят в базовый снимок: их не должно быть на машине после
        выхода из портатива, поэтому их не восстанавливают, а удаляют.
        """
        plain: "list[str]" = []
        created: "list[str]" = []
        for key in self.keys:
            text = str(key)
            (created if text.casefold() in self.created else plain).append(text)
        return plain, created

    def _snapshot_host(self) -> "tuple[list[Path], list[Path]]":
        """Снимок реестра машины одним .reg вместо процесса на каждый ключ.

        Прямой обход через winreg дешевле ``reg export``: у программы вроде
        Cursor ключей десятки, и каждый запуск ``reg.exe`` стоил 40-150 мс —
        окно открывалось заметно позже прямого запуска её exe.

        Возвращает ``(базовые файлы, экспорты созданных ключей)``. Вторые нужны
        не для восстановления, а как «состояние ключа на хосте» для сведения
        настроек (см. ``sync_external_changes``), поэтому пишутся отдельно.
        """
        plain, created = self._split_keys()
        baseline: "list[Path]" = []
        target = self.backup / REGISTRY_SNAPSHOT_NAME
        if target.is_file():
            # Снимок остался от прошлого запуска, который не дошёл до
            # восстановления: это по-прежнему исходное состояние машины.
            baseline.append(target)
        else:
            legacy = sorted(self.backup.glob("k[0-9][0-9].reg"))
            if legacy:
                # Базовый снимок прежней версии (файл на ключ) — используем его.
                baseline.extend(legacy)
            else:
                text = export_registry_text(plain, self.root)
                if text and write_reg_file(target, text):
                    baseline.append(target)
                else:
                    # Запасной путь прежней версии: файл на каждый ключ. Номера
                    # файлов считаются по полному списку ``keys`` — так их
                    # потом найдёт восстановление.
                    created_cf = {str(key).casefold() for key in created}
                    for index, key in enumerate(self.keys):
                        text_key = str(key)
                        if text_key.casefold() in created_cf:
                            continue
                        legacy_file = self.backup / f"k{index:02d}.reg"
                        if _reg(("export", text_key, str(legacy_file),
                                 "/y")) == 0 and legacy_file.is_file():
                            baseline.append(legacy_file)

        created_exports: "list[Path]" = []
        if created:
            text = export_registry_text(created, self.root)
            created_file = self.backup / REGISTRY_CREATED_NAME
            if text and write_reg_file(created_file, text):
                created_exports.append(created_file)
        return baseline, created_exports

    def prepare(self) -> None:
        """Всё, что должно произойти ДО импорта настроек: снимок машины.

        Снимок обязан быть снят, пока программа ещё ничего не записала: по
        нему машина возвращается в исходное состояние после выхода. Он
        делается напрямую через winreg (см. ``_snapshot_host``), поэтому
        дешёв; сам импорт настроек можно отложить (см. ``apply``).
        """
        if not self.active or self.prepared:
            return
        started = time.perf_counter()
        self.session.mkdir(parents=True, exist_ok=True)
        self.backup.mkdir(parents=True, exist_ok=True)
        self.runtime.mkdir(parents=True, exist_ok=True)

        self.sync_external_changes()

        _baseline, created_exports = self._snapshot_host()
        if created_exports:
            self.sync_external_changes(extra_files=created_exports)

        saved = sorted(self.session.glob("*.reg"))
        initial_name = self.cfg.get("file", "portable.reg")
        machine_name = self.cfg.get("machine_file", "portable_machine.reg")
        sources: list[Path] = []
        if saved:
            # A prior non-elevated game run can save HKCU/VirtualStore while
            # being unable to export HKLM. Seed the captured machine install
            # keys first; any later elevated session file overrides them.
            if machine_name:
                sources.append(self.root / str(machine_name))
            sources.extend(saved)
        else:
            if initial_name:
                sources.append(self.root / str(initial_name))
            if machine_name:
                sources.append(self.root / str(machine_name))
        self.sources = [item for item in sources if item.is_file()]
        self.created_exports = created_exports
        self.prepared = True
        self._prepare_seconds = time.perf_counter() - started

    def apply(self) -> None:
        """Импорт настроек программы из ``portable*.reg`` в реестр этого ПК."""
        if not self.active or self.started:
            return
        self.prepare()
        started = time.perf_counter()
        for index, source in enumerate(self.sources):
            imported = _unpacked_reg(source, self.runtime, self.root, index)
            if imported is None:
                _run_log(self.root, "registry import " + source.name
                         + ": skipped (only shell sections, nothing to "
                           "apply)")
                continue
            try:
                text = _decode_reg(imported.read_bytes())
            except OSError:
                text = ""
            if import_registry_text(text):
                _run_log(self.root, f"registry import {source.name}: ok "
                                    "(direct)")
            else:
                code = _reg(("import", str(imported)))
                _run_log(
                    self.root,
                    f"registry import {source.name}: "
                    f"{'ok' if code == 0 else f'FAILED (reg.exe rc={code})'}",
                )
        for ext_file in self.created_exports:
            if ext_file.is_file():
                try:
                    ext_file.unlink()
                except OSError:
                    pass
        self.started = True
        # Итог одного строкой: по нему видно, сколько стоил реестр до старта
        # программы (в launch-timing.json — отдельным этапом).
        _run_log(self.root, "registry: snapshot "
                 f"{getattr(self, '_prepare_seconds', 0.0):.2f}s, import "
                 f"{time.perf_counter() - started:.2f}s "
                 f"({len(self.sources)} файл(ов), ключей {len(self.keys)})")

    def load(self) -> None:
        self.prepare()
        self.apply()

    def save_and_restore(self) -> None:
        if not self.active or not self.started:
            return
        restore = bool(self.cfg.get("restore_on_exit", True))
        if not restore:
            return

        # Что программа изменила в этом сеансе — один снимок, а не файл на
        # каждый ключ (см. _snapshot_host). Корень портатива заменяется
        # маркером, чтобы настройки переехали вместе с папкой.
        session_text = export_registry_text(self.keys, self.root)
        if session_text:
            session_file = self.session / "session.reg"
            for stale in self.session.glob("k[0-9][0-9].reg"):
                try:
                    stale.unlink()
                except OSError:
                    pass
            if write_reg_file(session_file, session_text):
                _pack_reg(session_file, self.root)

        # Ключи, созданные установщиком: их нет в базовом снимке, поэтому
        # импорт их не уберёт — удаляем явно. Список берётся из ``created_keys``
        # и из помеченных ключей, а не только из ``keys``: созданный ключ может
        # быть подключом сохранённого и отдельно в списке ключей не значиться.
        removed: "set[str]" = set()
        for key in list(self.keys) + list(self.cfg.get("created_keys", [])):
            text = str(key)
            if text.casefold() in removed or text.casefold() not in self.created:
                continue
            removed.add(text.casefold())
            # winreg быстрее, reg.exe — запасной путь, если ключ занят или
            # доступ закрыт.
            if not delete_key_tree(text):
                _reg(("delete", text, "/f"))

        snapshot = self.backup / REGISTRY_SNAPSHOT_NAME
        if snapshot.is_file():
            if import_registry_file(snapshot, self.root):
                _run_log(self.root, "registry restore: ok")
            else:
                _run_log(self.root, "registry restore: FAILED")
            try:
                snapshot.unlink()
            except OSError:
                pass
        else:
            # Снимка одним файлом нет — значит, он не получился, и лежат
            # пофайловые снимки прежнего пути. Файл созданного ключа не
            # импортируется никогда: такой ключ должен исчезнуть с машины.
            for index, key in enumerate(self.keys):
                backup_file = self.backup / f"k{index:02d}.reg"
                if not backup_file.is_file():
                    continue
                if str(key).casefold() not in self.created:
                    import_registry_file(backup_file, self.root)
                try:
                    backup_file.unlink()
                except OSError:
                    pass

        for leftover in (self.backup / REGISTRY_CREATED_NAME,):
            try:
                leftover.unlink()
            except OSError:
                pass

        try:
            for item in self.runtime.glob("*.reg"):
                item.unlink()
            self.runtime.rmdir()
        except OSError:
            pass


# --- ключ входа в аккаунт -----------------------------------------------------
#
# Ollama (и подобные программы) входит в аккаунт не паролем, а ключом в профиле
# пользователя: ~/.ollama/id_ed25519. Сервер признаёт запросы по публичной
# части, привязанной к аккаунту на сайте. Если вход выполнен одним ключом, а
# портатив при следующем запуске берёт другой (или вообще пустой профиль),
# окно входа крутится бесконечно: ключ «не тот».
#
# Поэтому лончер, но только для программ, у которых в launcher_config.json
# есть блок ``identity``: (1) переносит ключ из профиля Windows в портатив,
# если в портативе ключа ещё нет (существующий ключ портатива не трогает);
# (2) пишет в журнал отпечаток ключа, чтобы было видно, совпадает ли он с
# тем, что привязан к аккаунту, и почему вход не проходит.

#: Файлы ключа по умолчанию (относительно профиля), если блок не задаёт свои.
DEFAULT_IDENTITY_FILES = (".ollama/id_ed25519", ".ollama/id_ed25519.pub")

_OPENSSH_MAGIC = b"openssh-key-v1\x00"
_OPENSSH_BEGIN = b"-----BEGIN OPENSSH PRIVATE KEY-----"


def _public_blob_from_pub(data: bytes) -> Optional[bytes]:
    """Публичный ключ из строки ``ssh-ed25519 AAAA… комментарий``."""
    parts = data.decode("ascii", "replace").split()
    if len(parts) < 2:
        return None
    try:
        return base64.b64decode(parts[1], validate=True)
    except ValueError:
        return None


def _public_blob_from_private(data: bytes) -> Optional[bytes]:
    """Публичная часть закрытого ключа OpenSSH без пароля.

    Формат: base64 внутри PEM-обёртки, затем ``openssh-key-v1``, три строки
    (шифр, KDF, параметры KDF), число ключей и публичный блок. Расшифровывать
    ничего не нужно, поэтому пароль не требуется и секрет не раскрывается.
    """
    stripped = data.strip()
    if not stripped.startswith(_OPENSSH_BEGIN):
        return None
    body = b"".join(
        line.strip() for line in stripped.splitlines()
        if line.strip() and not line.strip().startswith(b"-----"))
    try:
        raw = base64.b64decode(body, validate=True)
    except ValueError:
        return None
    if not raw.startswith(_OPENSSH_MAGIC):
        return None

    def read_string(position: int) -> "tuple[bytes, int]":
        if position + 4 > len(raw):
            raise ValueError("truncated")
        size = struct.unpack(">I", raw[position:position + 4])[0]
        position += 4
        if position + size > len(raw):
            raise ValueError("truncated")
        return raw[position:position + size], position + size

    position = len(_OPENSSH_MAGIC)
    try:
        for _ in range(3):  # шифр, KDF, параметры KDF
            _, position = read_string(position)
        position += 4  # число ключей (uint32)
        blob, _ = read_string(position)
        return blob
    except ValueError:
        return None


def _identity_blob(path: Path) -> Optional[bytes]:
    """Публичный блок ключа из файла ``.pub`` или закрытого ключа."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if path.name.endswith(".pub"):
        return _public_blob_from_pub(data)
    return _public_blob_from_private(data)


def _fingerprint(blob: bytes) -> str:
    """Отпечаток в том же виде, что печатает ``ssh-keygen -lf``."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _first_identity_blob(profile: Path, files: Sequence[str]) -> Optional[bytes]:
    for rel in files:
        path = _as_relative_path(profile, rel)
        if path.is_file():
            blob = _identity_blob(path)
            if blob is not None:
                return blob
    return None


def identity_settings(cfg: Dict[str, Any]) -> "Optional[tuple[list[str], bool]]":
    """Есть ли у программы ключ входа, и какие файлы его составляют.

    Возвращает ``(файлы, можно_ли_переносить_из_профиля_Windows)`` или
    ``None``, если блока ``identity`` в конфиге нет (тогда лончер ничего не
    трогает — для обычных программ так и должно быть).
    """
    block = cfg.get("identity")
    if not isinstance(block, dict):
        return None
    raw_files = block.get("files")
    files = [str(item) for item in raw_files
             if str(item).strip()] if isinstance(raw_files, list) else []
    if not files:
        files = list(DEFAULT_IDENTITY_FILES)
    return files, bool(block.get("import_from_host", True))


def identity_report(root: Path, cfg: Dict[str, Any], host_profile: str = "",
                    import_from_host: bool = False) -> "list[str]":
    """Сверяет ключ входа в портативе с профилем Windows.

    При ``import_from_host=True`` и отсутствии ключа в портативе копирует
    ключ из профиля Windows (не перезаписывая ничего). При ``False`` только
    читает — так работает проверка ``--check-identity``. Возвращает строки
    отчёта; пустой список означает, что у программы ключа входа нет.
    """
    settings = identity_settings(cfg)
    if settings is None:
        return []
    files, allow_import = settings
    data = root / str(cfg.get("data_dir_name", "PortableData"))
    portable = data / "User"
    host: Optional[Path] = Path(host_profile) if host_profile else None
    if host is not None:
        try:
            if os.path.normcase(str(host.resolve())) == os.path.normcase(
                    str(portable.resolve())):
                host = None  # профиль уже перенаправлен внутрь портатива
        except OSError:
            host = None

    lines: list[str] = []
    portable_has_key = any(_as_relative_path(portable, rel).is_file()
                           for rel in files)
    host_has_key = host is not None and any(
        _as_relative_path(host, rel).is_file() for rel in files)

    if not portable_has_key and host_has_key:
        if import_from_host and allow_import:
            copied = []
            for rel in files:
                source = _as_relative_path(host, rel)
                if source.is_file():
                    target = _as_relative_path(portable, rel)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
                    copied.append(rel)
            lines.append("ключ перенесён из профиля Windows в портатив: "
                         + ", ".join(copied))
            portable_has_key = True
        elif not allow_import:
            lines.append("в профиле Windows есть ключ, но перенос отключён "
                         "(identity.import_from_host = false)")
        else:
            lines.append("в профиле Windows есть ключ; проверка не переносит "
                         "его сама — запустите программу через лончер")

    portable_blob = _first_identity_blob(portable, files)
    if portable_blob is None:
        lines.append("ключа входа в портативе нет: при входе программа создаст "
                     "новый ключ, и его придётся привязать к аккаунту заново")
    else:
        lines.append("ключ портатива: " + _fingerprint(portable_blob))

    if host is not None and host_has_key:
        host_blob = _first_identity_blob(host, files)
        if host_blob is not None and portable_blob is not None:
            if host_blob == portable_blob:
                lines.append("профиль Windows: тот же ключ, что в портативе")
            else:
                lines.append(
                    "ВНИМАНИЕ: в профиле Windows другой ключ ("
                    + _fingerprint(host_blob) + "). Вход, выполненный с ним, "
                    "в портативе не сработает — привяжите ключ портатива к "
                    "аккаунту на сайте программы.")
    return lines


def check_identity(root: Optional[Path] = None) -> int:
    """``LaunchPortable.exe --check-identity``: показать состояние ключа."""
    root = root or find_portable_root()
    cfg: Dict[str, Any] = read_launcher_config(root)
    lines = identity_report(root, cfg, os.environ.get("USERPROFILE", ""),
                            import_from_host=False)
    if not lines:
        text = "Для этой программы проверка ключа входа не предусмотрена."
    else:
        text = "\n".join(lines)
    for line in lines:
        _run_log(root, "identity check: " + line)
    _show_warning(text)
    return 0


def _arguments_with_executable_alias(
    cfg: Dict[str, Any], arguments: Sequence[str], executable_name: Optional[str] = None
) -> list[str]:
    """Select the target assigned to this copy of the generic launcher.

    Portablizer copies the same signed/self-contained binary under names such
    as ``Launch_Launcher.exe`` and ``Launch_Configurator.exe``.  The relative
    target is kept in launcher_config.json, so moving the portable folder or
    changing its drive letter cannot invalidate the shortcut.  Explicit CLI
    selectors still take precedence, which keeps these copies scriptable.
    """
    result = [str(arg) for arg in arguments]
    selectors = {"--target", "--launcher", "--config", "--settings"}
    if any(arg.casefold() in selectors for arg in result):
        return result

    name = executable_name
    if name is None and getattr(sys, "frozen", False):
        name = Path(sys.executable).name
    if not name:
        return result

    aliases = cfg.get("launcher_aliases", {})
    if not isinstance(aliases, dict):
        return result
    target = next(
        (str(value) for key, value in aliases.items()
         if str(key).casefold() == str(name).casefold()),
        "",
    )
    if not target:
        return result
    return ["--machine-registry", "--target", target, *result]


def _select_target(cfg: Dict[str, Any], arguments: Sequence[str]
                   ) -> tuple[str, list[str], bool]:
    """Resolve launcher/configurator switches without passing them to the app."""
    target_rel = str(cfg["target_exe_rel"])
    selected_role = "main"
    forwarded: list[str] = []
    targets = list(cfg.get("targets", []))
    by_path = {
        str(item.get("rel_path", "")).replace("\\", "/").casefold(): item
        for item in targets
    }
    index = 0
    while index < len(arguments):
        arg = str(arguments[index])
        lowered = arg.casefold()
        if lowered == "--elevated":
            index += 1
            continue
        if lowered == "--machine-registry":
            selected_role = selected_role if selected_role != "main" else "auxiliary"
            index += 1
            continue
        if lowered == "--launcher" and cfg.get("launcher_target_rel"):
            target_rel = str(cfg["launcher_target_rel"])
            selected_role = "launcher"
            index += 1
            continue
        if lowered in ("--config", "--settings") and cfg.get("config_target_rel"):
            target_rel = str(cfg["config_target_rel"])
            selected_role = "config"
            index += 1
            continue
        if lowered == "--target" and index + 1 < len(arguments):
            target_rel = str(arguments[index + 1])
            item = by_path.get(target_rel.replace("\\", "/").casefold(), {})
            selected_role = str(item.get("role", "auxiliary"))
            index += 2
            continue
        forwarded.append(arg)
        index += 1
    return target_rel, forwarded, selected_role != "main"


#: Служебные exe, которые не могут быть «главной программой».
_TARGET_JUNK = ("unins", "uninstall", "update", "updater", "setup", "install",
                "crashpad", "crashhandler", "crashreport", "elevate", "helper",
                "report", "vc_redist", "dxsetup")


def _find_replacement_target(root: Path, wanted: str) -> "Optional[Path]":
    """Ищет настоящий exe, если записанная в конфиге цель исчезла.

    Так бывает после неудачного обновления (родной апдейтер Cursor уносит
    ``Cursor.exe`` в промежуточную папку ``_``), после ручного переименования
    или если конфиг остался от сборки на прежнем диске. Ищем только внутри
    ``App`` и только то, что похоже на программу: служебные
    unins/update/crashpad-файлы пропускаются.
    """
    app = root / "App"
    try:
        if not app.is_dir():
            return None
    except OSError:
        return None
    wanted_name = Path(str(wanted).replace("\\", "/")).name.casefold()
    same_name: "list[Path]" = []
    largest: "Optional[Path]" = None
    largest_size = 0
    scanned = 0
    for current, dirs, files in os.walk(app):
        try:
            depth = len(Path(current).relative_to(app).parts)
        except ValueError:
            depth = 0
        if depth >= 4:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs
                       if not d.startswith(("_", "."))
                       and d.casefold() not in {"resources", "locales",
                                                "node_modules"}]
        for name in files:
            if not name.casefold().endswith(".exe"):
                continue
            scanned += 1
            if scanned > 5000:
                break
            path = Path(current) / name
            folded = name.casefold()
            if folded == wanted_name:
                same_name.append(path)
                continue
            if any(token in folded for token in _TARGET_JUNK):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > largest_size:
                largest_size = size
                largest = path
        if scanned > 5000:
            break
    if same_name:
        return same_name[0]
    return largest


def _remember_target(root: Path, new_rel: str) -> bool:
    """Persists a repaired target so the next start does not search again."""
    path = launcher_config_path(root)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if str(data.get("target_exe_rel") or "") == new_rel:
        return False
    data["target_exe_rel"] = new_rel
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8", newline="\n")
        return True
    except OSError:
        return False


def _repair_missing_target(root: Path, cfg: Dict[str, Any], target_rel: str) -> str:
    """Returns a usable target path, repairing the config when it is stale."""
    target = _as_relative_path(root, target_rel)
    try:
        if target.is_file():
            return target_rel
    except OSError:
        pass
    replacement = _find_replacement_target(root, target_rel)
    if replacement is None:
        return target_rel
    try:
        new_rel = str(replacement.relative_to(root)).replace(os.sep, "/")
    except ValueError:
        new_rel = str(replacement)
    _run_log(root, f"target: {target_rel} is missing; found {new_rel} in App")
    if _remember_target(root, new_rel):
        _run_log(root, f"target: launcher_config.json now points to {new_rel}")
    cfg["target_exe_rel"] = new_rel
    return new_rel


def _machine_file_needs_admin(path: Path) -> bool:
    """True when the captured machine file really contains HKLM sections."""
    try:
        text = _decode_reg(path.read_bytes())
    except OSError:
        return False
    lowered = text.casefold()
    return "[hkey_local_machine" in lowered


def _hklm_key_missing(
    keys: Iterable[str],
    machine_path: Optional[Path] = None,
    root: Optional[Path] = None,
) -> bool:
    """True when at least one captured HKLM key or value is absent on this PC.

    Games such as The Witcher read their install path from HKLM and quit with
    exit code 1 when the value is not there.  When a user imports a partial
    .reg file (for example _Lang_SW\\x64\\Rus.reg in Assassin's Creed
    Brotherhood), the key itself exists in HKLM with only "Language"="Russian"
    while "InstallDir" from portable_machine.reg is still missing.  Checking
    the sections and values of portable_machine.reg ensures the launcher still
    asks for UAC and imports the complete machine snapshot.
    """
    if not IS_WINDOWS:
        return False

    hklm_names = ("HKLM", "HKEY_LOCAL_MACHINE")
    checked = False
    try:
        import winreg
    except ImportError:
        winreg = None  # type: ignore[assignment]

    if winreg is not None:
        roots = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        }
        for key in keys:
            head, _, tail = str(key).replace("/", "\\").partition("\\")
            handle = roots.get(head.upper())
            if handle is None or not tail:
                continue
            checked = True
            for access in (winreg.KEY_READ,
                           winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0),
                           winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)):
                try:
                    winreg.CloseKey(winreg.OpenKey(handle, tail, 0, access))
                    break
                except OSError:
                    continue
            else:
                return True

    if machine_path is not None and machine_path.is_file():
        try:
            sections = _parse_reg_sections(_decode_reg(machine_path.read_bytes()))
        except OSError:
            sections = {}
        escaped_root = str(root).replace("\\", "\\\\") if root is not None else ""
        for header, expected_vals in sections.items():
            head, _, tail = header.partition("\\")
            if head.upper() not in hklm_names or not tail:
                continue
            checked = True
            host_vals = _read_host_key_reg_values(f"HKLM\\{tail}")
            if not host_vals and expected_vals:
                return True
            host_cf = {k.casefold(): v for k, v in host_vals.items()}
            for v_name, v_rhs in expected_vals.items():
                actual_rhs = host_cf.get(v_name.casefold())
                if actual_rhs is None:
                    return True
                expected_rhs = (
                    v_rhs.replace(ROOT_TOKEN, escaped_root)
                    if (ROOT_TOKEN in v_rhs and escaped_root)
                    else v_rhs
                )
                if ROOT_TOKEN not in expected_rhs and actual_rhs.casefold() != expected_rhs.casefold():
                    return True

    return False if checked else False


def _own_executable_images() -> tuple:
    """Case-folded paths of this launcher EXE (empty when run from source).

    Both the plain and the resolved form are kept: the portable folder may
    be reached through a mapped or substituted drive, and Windows reports
    process images in only one of the two spellings.
    """
    if not getattr(sys, "frozen", False):
        return ()
    images = [str(sys.executable).casefold()]
    try:
        resolved = str(Path(sys.executable).resolve()).casefold()
    except OSError:
        resolved = ""
    if resolved and resolved not in images:
        images.append(resolved)
    return tuple(images)


def _counts_as_portable_process(image: str, prefix: str, own_image) -> bool:
    """True when this running image is the portable program, not us.

    A one-file EXE always runs as two processes: the PyInstaller bootloader
    and the Python child it spawns.  The bootloader lives in App as well, so
    counting it would mean waiting for ourselves - the session would never
    end, the registry would never be restored and the window would hang
    around until the 24 hour limit.  Our own image is therefore skipped.
    """
    image = image.casefold()
    if not image.startswith(prefix):
        return False
    own = (own_image,) if isinstance(own_image, str) else tuple(own_image)
    return image not in [item for item in own if item]


def _image_name(image: str) -> str:
    """File name of a process image, whatever separator Windows reported."""
    return str(image).replace("/", "\\").rsplit("\\", 1)[-1]


def _portable_process_list(root: Path) -> "list[tuple[int, str]]":
    """``(pid, image)`` of every running process started from the folder.

    This is the raw material for two jobs: deciding how long the sandbox has
    to stay alive, and making sure nothing is left holding the folder when the
    launcher goes away.  Our own image is skipped (see
    :func:`_counts_as_portable_process`).
    """
    if not IS_WINDOWS:
        return []
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPPROCESS = 0x00000002
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot in (0, -1, None):
            return []
        prefix = str(root).rstrip("\\").casefold() + "\\"
        own = os.getpid()
        own_image = _own_executable_images()
        found: list[tuple[int, str]] = []
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while more:
                pid = int(entry.th32ProcessID)
                if pid not in (0, 4, own):
                    handle = kernel32.OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                    if handle:
                        try:
                            size = wintypes.DWORD(32768)
                            buffer = ctypes.create_unicode_buffer(size.value)
                            if kernel32.QueryFullProcessImageNameW(
                                    handle, 0, buffer, ctypes.byref(size)):
                                if _counts_as_portable_process(
                                        buffer.value, prefix, own_image):
                                    found.append((pid, buffer.value))
                        finally:
                            kernel32.CloseHandle(handle)
                more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
        return found
    except Exception:
        return []


def _portable_processes(root: Path) -> int:
    """Count running processes whose executable lives inside the folder."""
    return len(_portable_process_list(root))


#: Files that mark a Chromium-based tree (Electron, NW.js or a native app
#: with embedded CEF).  Those runtimes spawn GPU/renderer processes with
#: CREATE_BREAKAWAY_FROM_JOB and often keep only a message-only HWND for the
#: tray icon, so the launcher must not put them into its kill-on-close job.
#:
#: NOTE: ``libcef.dll`` means "uses CEF", NOT "is Electron".  SketchUp,
#: Steam and many CAD tools embed CEF while parsing their own command line;
#: Chromium switches make them refuse to start with «Unknown options:
#: no-sandbox, disable-gpu-sandbox, disable-features».
_CHROMIUM_EMBED_MARKERS = frozenset({
    "chrome_elf.dll", "libcef.dll", "nw.dll",
})

#: Files that only a real Electron/NW.js tree contains.  ``chrome_elf.dll``
#: alone is NOT enough: CEF distributions (SketchUp, Steam) ship it too.
#: Electron is identified by ``resources\\app.asar`` next to it or by
#: ``nw.dll`` (NW.js); everything else is treated as a native CEF host.
_ELECTRON_MARKERS = frozenset({"nw.dll"})

#: Strings present in a real Electron/NW.js executable.  A renamed
#: ``electron.exe`` keeps them; ``SketchUp.exe`` next to ``libcef.dll``
#: does not, so it never gets the switches below.
_ELECTRON_EXE_MARKERS = (b"ELECTRON_RUN_AS_NODE", b"electron.asar")

#: How much of the target exe is scanned for the markers above.
_ELECTRON_SCAN_BYTES = 8 * 1024 * 1024

#: Chromium flags that let a portable Electron app (Ollama) actually open a
#: window.  The renderer sandbox assumes a normal install layout and a job
#: it owns; inside a portable folder "Open Ollama" then shows nothing and
#: the tray icon stops responding.
_ELECTRON_CLI_FLAGS = (
    "--no-sandbox",
    "--disable-gpu-sandbox",
    "--disable-features=RendererCodeIntegrity",
)

_LEFTOVER_IMAGE_TOKENS = (
    "crashpad", "crashhandler", "unitycrash", "updater", "unins",
)


def _exe_is_electron_style(path: Path) -> bool:
    """True when the executable itself carries Electron markers."""
    try:
        remaining = _ELECTRON_SCAN_BYTES
        with open(path, "rb") as handle:
            while remaining > 0:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                if any(marker in chunk for marker in _ELECTRON_EXE_MARKERS):
                    return True
                remaining -= len(chunk)
    except OSError:
        return False
    return False


def is_electron_tree(directory: Path) -> bool:
    """True when ``directory`` looks like an Electron/NW.js app folder.

    Deliberately ignores ``libcef.dll``: embedded CEF is not Electron and
    must not receive Chromium command-line switches (see above).
    """
    try:
        names = {item.name.casefold() for item in directory.iterdir()
                 if item.is_file()}
    except OSError:
        return False
    if names & _ELECTRON_MARKERS:
        return True
    try:
        # app.asar бывает только у Electron; chrome_elf.dll у CEF-программ
        # тоже есть, поэтому одного его недостаточно.
        if (directory / "resources" / "app.asar").is_file() and "chrome_elf.dll" in names:
            return True
        # Cursor, VS Code и VSCodium ship the application UNPACKED:
        # resources\app\package.json, no app.asar at all. Without this branch
        # the most common Electron app of all is not recognized as Electron.
        return (directory / "resources" / "app" / "package.json").is_file()
    except OSError:
        return False


def is_chromium_tree(directory: Path) -> bool:
    """True for Chromium-based trees, including native CEF hosts.

    Used only to keep such programs out of the launcher's kill-on-close
    job: their child GPU/renderer processes break away from jobs.
    """
    try:
        names = {item.name.casefold() for item in directory.iterdir()
                 if item.is_file()}
    except OSError:
        return False
    if names & _CHROMIUM_EMBED_MARKERS:
        return True
    try:
        if (directory / "resources" / "app.asar").is_file():
            return True
        if (directory / "resources" / "app" / "package.json").is_file():
            return True
    except OSError:
        return False
    return False


def should_use_job(target: Path) -> bool:
    """False for Chromium/Ollama: a kill-on-close job breaks their windows.

    Chromium creates its own job and GPU/renderer processes with
    ``CREATE_BREAKAWAY_FROM_JOB``.  Even with BREAKAWAY_OK, starting the
    main process *suspended* (so it can be assigned to our job) races the
    sandbox setup: the tray icon appears, "Open Ollama" never shows a
    window, then the UI stops responding.  Cleanup still finds those
    processes by image path.
    """
    name = target.name.casefold()
    if "ollama" in name and "setup" not in name:
        return False
    return not is_chromium_tree(target.parent)


def needs_electron_sandbox_off(target: Path) -> bool:
    """True when ``target`` is a real Electron/NW host.

    Ollama's ``ollama app.exe`` is a Go tray + WebView2 UI, not Electron.
    SketchUp (and Steam, and other CEF hosts) are native programs with an
    embedded browser: the switches arrive as unknown arguments, so the app
    answers «Unknown options: no-sandbox, …» and does not start.  Only an
    actual Electron/NW.js executable gets the flags.
    """
    name = target.name.casefold()
    if name in {"electron.exe", "nw.exe"}:
        return True
    # Cursor / VS Code / VSCodium: настоящий Electron, но без app.asar.
    # Проверяется до чтения exe: Cursor.exe — это сотни мегабайт, а
    # маркерный проход по 8 МБ на каждом запуске ни к чему.
    if _vscode_product(target.parent) is not None:
        return True
    if _exe_is_electron_style(target):
        return True
    # Дальше — только по надёжным признакам Electron (app.asar / nw.dll).
    # Крупный exe рядом с chrome_elf.dll больше не считается: ровно так
    # выглядит CEF-программа (SketchUp) и именно из-за этого она получала
    # «Unknown options: no-sandbox».
    if not is_electron_tree(target.parent):
        return False
    if name.endswith(" app.exe") or name == "electron.exe":
        return True
    try:
        return target.stat().st_size >= 8 * 1024 * 1024
    except OSError:
        return False


def with_electron_flags(command: Sequence[str], target: Path) -> list[str]:
    """Add Chromium sandbox-off switches for Electron; strip them otherwise.

    Stripping matters for old ``launcher_config.json`` files written by a
    previous Portablizer version: they already contain ``--no-sandbox`` for
    a program that is not Electron (e.g. SketchUp).  The rebuilt launcher
    must not keep passing them.
    """
    parts = [str(item) for item in command]
    if not parts:
        return parts
    if not needs_electron_sandbox_off(target):
        return [parts[0], *[item for item in parts[1:]
                            if item not in _ELECTRON_CLI_FLAGS]]
    extra = [flag for flag in _ELECTRON_CLI_FLAGS if flag not in parts]
    return [parts[0], *extra, *parts[1:]]


# --- Cursor / VS Code: профиль внутри портатива -------------------------------
#
# Cursor и VS Code — Electron, но приложение лежит распакованным
# (``resources\\app\\package.json``) и в ``product.json`` у Cursor стоит
# ``"target": "user"``: встроенный portable-режим VS Code (папка ``data``
# рядом с exe) в такой сборке не включается вообще. Поэтому профиль задаётся
# переменными, которые понимает сам редактор:
#
#   VSCODE_APPDATA        корень, внутри которого лежит ``Cursor``/``Code``;
#   VSCODE_EXTENSIONS     каталог расширений (``%USERPROFILE%\\.cursor\\extensions``);
#   VSCODE_LOGS           каталог журналов;
#   VSCODE_CLI_DATA_DIR   данные CLI (``~/.cursor/cli``), которые иначе
#                         создаются в настоящем профиле даже в portable-режиме.
#
# Значения считаются от текущего корня на каждом запуске, поэтому переезд
# папки на другой диск ничего не ломает.

_VSCODE_PRODUCT = ("resources", "app", "product.json")

_VSCODE_EXE_NAMES = frozenset({
    "code.exe", "code - insiders.exe", "cursor.exe", "codium.exe",
    "vscodium.exe", "windsurf.exe", "trae.exe", "kiro.exe",
})

_VSCODE_DATA_FOLDERS = {
    "code.exe": ".vscode",
    "code - insiders.exe": ".vscode-insiders",
    "codium.exe": ".vscodium",
    "vscodium.exe": ".vscodium",
    "cursor.exe": ".cursor",
}

#: Ключ ``argv.json``, которым Cursor/VS Code отключают Chromium-песочницу.
#: Нужен именно в файле: ``--no-sandbox`` действует на один запуск, а после
#: перезапуска «для обновления» или старта из трея флаг бы терялся, Windows
#: отказывала helper-процессам, и Cursor завершался, не показав окна.
VSCODE_SANDBOX_KEY = "disable-chromium-sandbox"


def _vscode_product(directory: Path) -> "Optional[Dict[str, str]]":
    """Описание Cursor/VS Code рядом с exe или ``None`` для прочих программ."""
    product: Dict[str, Any] = {}
    path = directory / "resources" / "app" / "product.json"
    try:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8-sig",
                                             errors="replace"))
            if isinstance(data, dict):
                product = data
    except (OSError, ValueError):
        product = {}
    name = ""
    try:
        names = [item.name.casefold() for item in directory.glob("*.exe")]
    except OSError:
        names = []
    for candidate in names:
        if candidate in _VSCODE_EXE_NAMES:
            name = candidate
            break
    if not product and not name:
        return None
    folder = str(product.get("dataFolderName") or "").strip()
    if not folder:
        folder = _VSCODE_DATA_FOLDERS.get(name, "")
    if not folder:
        stem = os.path.splitext(name)[0] or "vscode"
        folder = "." + stem
    profile = str(product.get("nameShort") or product.get("nameLong") or "").strip()
    if not profile:
        profile = os.path.splitext(name)[0].title() or "Code"
    return {
        "name": profile,
        "data_folder": folder,
        "target": str(product.get("target") or ""),
    }


def _vscode_environment(env: Dict[str, str], root: Path, cfg: Dict[str, Any],
                        target: Path) -> Dict[str, str]:
    """Pin Cursor/VS Code profile paths inside the portable folder."""
    info = _vscode_product(target.parent)
    if info is None:
        return env
    data = root / str(cfg.get("data_dir_name") or "PortableData")
    folder = str(info.get("data_folder") or ".vscode")
    defaults = {
        "VSCODE_APPDATA": str(data / "AppData" / "Roaming"),
        "VSCODE_EXTENSIONS": str(data / "User" / folder / "extensions"),
        "VSCODE_LOGS": str(data / "Logs"),
        "VSCODE_CLI_DATA_DIR": str(data / "User" / folder / "cli"),
    }
    configured = cfg.get("extra_env")
    configured = configured if isinstance(configured, dict) else {}
    patched = dict(env)
    for key, value in defaults.items():
        # Значение из launcher_config.json главнее: его задал человек.
        if key not in configured:
            patched[key] = value
    return patched


def _merge_json_file(path: Path, add: Dict[str, Any]) -> bool:
    """Дописывает ключи в JSON-файл, сохраняя всё остальное."""
    existing: Dict[str, Any] = {}
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            existing = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return False
    changed = False
    for key, value in add.items():
        if existing.get(key) != value:
            existing[key] = value
            changed = True
    if not changed:
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(existing, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8", newline="\n")
        return True
    except OSError:
        return False


def _apply_vscode_profile(root: Path, cfg: Dict[str, Any],
                          target: Path) -> "list[str]":
    """Restores the Cursor/VS Code profile files before every start.

    The portablizer writes them at build time, but they are ordinary files in
    ``PortableData``: the user may delete them, copy the folder without them,
    or update the app.  Re-creating the two small files costs two reads and
    keeps ``--diagnose`` honest about what the app will actually read.
    """
    info = _vscode_product(target.parent)
    if info is None:
        return []
    data = root / str(cfg.get("data_dir_name") or "PortableData")
    notes: "list[str]" = []
    argv = data / "User" / str(info["data_folder"]) / "argv.json"
    if _merge_json_file(argv, {VSCODE_SANDBOX_KEY: True}):
        notes.append("vscode: argv.json now disables the Chromium sandbox "
                     f"({argv.relative_to(root)})")
    settings = (data / "AppData" / "Roaming" / str(info["name"])
                / "User" / "settings.json")
    if not settings.exists():
        if _merge_json_file(settings, {"update.mode": "none"}):
            notes.append("vscode: native auto-update is off for this portable "
                         f"({settings.relative_to(root)}); updates go through "
                         "UpdatePortable.cmd")
    return notes


def needs_webview2_bridge(target: Path) -> bool:
    """True for a WebView2 host (Ollama tray GUI, Wails, WinUI wrappers).

    Opening a window talks to Edge WebView2.  The evergreen runtime lives
    under the *host* ``%LOCALAPPDATA%\\Microsoft\\EdgeWebView``.  After the
    portable launcher redirects LOCALAPPDATA, that lookup misses, the
    tray menu still draws (native), and every item that should open a
    window or the log folder hangs the icon.
    """
    try:
        parent = target.parent
        if (parent / "WebView2Loader.dll").is_file():
            return True
        if is_electron_tree(parent):
            return False
    except OSError:
        pass
    name = target.name.casefold()
    return "ollama" in name and name.endswith(" app.exe")


def discover_webview2_browser_folder(
        host_localappdata: Optional[Path] = None) -> Optional[Path]:
    """Newest installed Edge WebView2 ``Application\\<version>`` folder."""
    roots: List[Path] = []
    local = host_localappdata
    if local is None:
        raw = os.environ.get("LOCALAPPDATA") or ""
        local = Path(raw) if raw else None
    if local:
        roots.append(local / "Microsoft" / "EdgeWebView" / "Application")
    for key in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
        pf = os.environ.get(key) or ""
        if pf:
            roots.append(Path(pf) / "Microsoft" / "EdgeWebView" / "Application")
    best: Optional[Path] = None
    best_name = ""
    for root in roots:
        try:
            if not root.is_dir():
                continue
            for child in root.iterdir():
                if not child.is_dir():
                    continue
                if not (child / "msedgewebview2.exe").is_file():
                    continue
                name = child.name
                if name > best_name:
                    best_name = name
                    best = child
        except OSError:
            continue
    return best


def _junction_directory(link: Path, target: Path) -> bool:
    """Point ``link`` at ``target`` (directory junction / symlink)."""
    try:
        if link.exists() or link.is_symlink():
            return True
        if not target.is_dir():
            return False
        link.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    try:
        os.symlink(str(target), str(link), target_is_directory=True)
        return True
    except OSError:
        pass
    if not IS_WINDOWS:
        return False
    try:
        creation = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True, creationflags=creation, timeout=15,
            check=False)
        return completed.returncode == 0 and (link.exists() or link.is_symlink())
    except (OSError, subprocess.SubprocessError):
        return False


def apply_webview2_bridge(env: Dict[str, str], target: Path,
                          host_localappdata: Optional[Path] = None
                          ) -> Dict[str, str]:
    """Keep WebView2 able to find Edge after LOCALAPPDATA is redirected."""
    if not needs_webview2_bridge(target):
        return env
    patched = dict(env)
    local = Path(patched.get("LOCALAPPDATA") or "")
    if local.name:
        user_data = local.parent.parent / "WebView2"
    else:
        user_data = Path(patched.get("PORTABLE_ROOT") or ".") / "PortableData" / "WebView2"
    try:
        user_data.mkdir(parents=True, exist_ok=True)
        patched.setdefault("WEBVIEW2_USER_DATA_FOLDER", str(user_data))
    except OSError:
        pass
    host = host_localappdata
    if host is None:
        # os.environ still has the real profile; env already has the portable one.
        raw = os.environ.get("LOCALAPPDATA") or ""
        host = Path(raw) if raw else None
    browser = discover_webview2_browser_folder(host)
    if browser is not None:
        patched.setdefault("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", str(browser))
    portable_local = Path(patched.get("LOCALAPPDATA") or "")
    if host and portable_local.name:
        for relative in (
            Path("Microsoft") / "EdgeWebView",
            Path("Microsoft") / "EdgeUpdate",
        ):
            source = host / relative
            dest = portable_local / relative
            if source.is_dir():
                _junction_directory(dest, source)
    return patched


def _is_interactive_image(image: str) -> bool:
    """True for a tray/Electron app that must not be idle-killed."""
    name = Path(image).name.casefold()
    if any(token in name for token in _LEFTOVER_IMAGE_TOKENS):
        return False
    if "ollama" in name:
        return True
    try:
        return is_electron_tree(Path(image).parent)
    except OSError:
        return False


def _visible_window_pids() -> "set[int]":
    """PIDs that own a UI - a visible window, a hidden one, or HWND_MESSAGE.

    A program the user is actually looking at must never be killed.  The
    same is true of a tray application (Ollama, messengers, GPU overlays):
    it has no visible main window, ``MainWindowHandle`` is zero, and the
    notify-icon HWND is often a *message-only* window.  ``EnumWindows``
    does not see those; ``FindWindowEx(HWND_MESSAGE, …)`` does.

    A process with *no* window at all is a crash handler, an updater or a
    silent helper - those still get ``idle_grace``.
    """
    if not IS_WINDOWS:
        return set()
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        pids: set[int] = set()
        callback_type = ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def collect(hwnd, _lparam):  # pragma: no cover - needs a desktop
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                pids.add(int(pid.value))
            return True

        user32.EnumWindows(callback_type(collect), 0)

        # Message-only windows (HWND_MESSAGE == -3) are where many tray
        # icons listen.  EnumWindows never lists them.
        FindWindowExW = user32.FindWindowExW
        GetWindowThreadProcessId = user32.GetWindowThreadProcessId
        hwnd_message = wintypes.HWND(-3)
        hwnd = wintypes.HWND()
        while True:
            hwnd = FindWindowExW(hwnd_message, hwnd, None, None)
            if not hwnd:
                break
            pid = wintypes.DWORD()
            GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                pids.add(int(pid.value))
        return pids
    except Exception:
        return set()


def _post_close_to_windows(pids: "Iterable[int]") -> int:
    """Ask every window of these processes to close politely (WM_CLOSE)."""
    if not IS_WINDOWS:
        return 0
    wanted = {int(pid) for pid in pids}
    if not wanted:
        return 0
    try:
        import ctypes
        from ctypes import wintypes

        WM_CLOSE = 0x0010
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        sent = 0
        callback_type = ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def collect(hwnd, _lparam):  # pragma: no cover - needs a desktop
            nonlocal sent
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if int(pid.value) in wanted:
                user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
                sent += 1
            return True

        user32.EnumWindows(callback_type(collect), 0)
        return sent
    except Exception:
        return 0


def _terminate_pids(pids: "Iterable[int]") -> "list[int]":
    """Hard-kill the given processes; return the PIDs that really went away."""
    if not IS_WINDOWS:
        return []
    killed: list[int] = []
    try:
        import ctypes

        PROCESS_TERMINATE = 0x0001
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        for pid in {int(p) for p in pids}:
            handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if not handle:
                continue
            try:
                if kernel32.TerminateProcess(handle, 0):
                    killed.append(pid)
            finally:
                kernel32.CloseHandle(handle)
    except Exception:
        return killed
    return killed


#: Процессы Windows, которые нельзя закрывать: снятие любого из них портит
#: сеанс пользователя. Если такой процесс держит файл из портатива (обычно
#: подгруженная DLL - расширение оболочки, хук, антивирусный сканер), его
#: можно только НАЗВАТЬ в журнале.
PROTECTED_IMAGES = frozenset({
    "explorer.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "services.exe",
    "lsass.exe", "smss.exe", "svchost.exe", "dwm.exe", "taskhostw.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "sihost.exe", "fontdrvhost.exe", "runtimebroker.exe", "ctfmon.exe",
    "msmpeng.exe", "mssense.exe", "securityhealthservice.exe",
    "system", "registry", "memory compression", "idle",
})


def _modules_of(pid: int) -> "list[str]":
    """Пути DLL, загруженных процессом ``pid``."""
    if not IS_WINDOWS:
        return []
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPMODULE = 0x00000008
        TH32CS_SNAPMODULE32 = 0x00000010

        class MODULEENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", wintypes.HMODULE),
                ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        snap = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, int(pid))
        if snap in (0, -1, None):
            return []
        modules: list[str] = []
        try:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
            more = kernel32.Module32FirstW(snap, ctypes.byref(entry))
            while more and len(modules) < 4096:
                modules.append(entry.szExePath)
                more = kernel32.Module32NextW(snap, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snap)
        return modules
    except Exception:
        return []


def _all_processes() -> "list[tuple[int, str]]":
    """Все процессы системы: ``(pid, путь к exe)``."""
    if not IS_WINDOWS:
        return []
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPPROCESS = 0x00000002
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap in (0, -1, None):
            return []
        own = os.getpid()
        found: list[tuple[int, str]] = []
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            more = kernel32.Process32FirstW(snap, ctypes.byref(entry))
            while more:
                pid = int(entry.th32ProcessID)
                if pid not in (0, 4, own):
                    handle = kernel32.OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                    image = entry.szExeFile
                    if handle:
                        try:
                            size = wintypes.DWORD(32768)
                            buffer = ctypes.create_unicode_buffer(size.value)
                            if kernel32.QueryFullProcessImageNameW(
                                    handle, 0, buffer, ctypes.byref(size)):
                                image = buffer.value
                        finally:
                            kernel32.CloseHandle(handle)
                    found.append((pid, image))
                more = kernel32.Process32NextW(snap, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snap)
        return found
    except Exception:
        return []


def module_holders(root: Path, budget: float = 4.0
                   ) -> "list[tuple[int, str, str]]":
    """Чужие процессы, подгрузившие DLL из портативной папки.

    Случай, который не ловится сравнением путей самих процессов: программа
    закрыта, её процессов нет, но DLL из папки держит кто-то снаружи -
    проводник (расширение контекстного меню), антивирус, хук ввода. Папка
    при этом не удаляется, а пользователю не за что зацепиться.

    Возвращает ``(pid, образ процесса, удерживаемый файл)``.
    """
    if not IS_WINDOWS:
        return []
    import time

    prefix = str(root).rstrip("\\").casefold() + "\\"
    own_images = {image.casefold() for image in _own_executable_images()}
    result: list[tuple[int, str, str]] = []
    # Перебор модулей всех процессов системы стоит заметного времени, а
    # выполняется на выходе, когда пользователь уже закрыл программу.
    # Ограничиваем бюджет: лучше неполный отчёт, чем задержка закрытия.
    deadline = time.monotonic() + budget
    for pid, image in _all_processes():
        if time.monotonic() > deadline:
            break
        if image.casefold() in own_images or image.casefold().startswith(prefix):
            continue
        for module in _modules_of(pid):
            if module.casefold().startswith(prefix):
                result.append((pid, image, module))
                break
    return result


def describe_holders(holders: "Sequence[tuple[int, str, str]]") -> str:
    """Человеческое описание того, кто держит папку."""
    parts = []
    for _pid, image, module in holders:
        parts.append(f"{_image_name(image)} (держит {_image_name(module)})")
    return ", ".join(sorted(set(parts)))


# --- открытые файлы: последняя причина, по которой папка не удаляется --------
#
# Процессов из папки нет, чужих DLL из папки нет, а папка всё равно занята:
# внутри открыт обычный ФАЙЛ. Классика - шрифт из
# `PortableData\Temp\is-XXXX.tmp`, который подхватила служба кэша шрифтов:
# установщик давно закончил работу, а дескриптор остался в системном
# процессе. Ни завершить его, ни дождаться нельзя - дескриптор нужно
# закрыть. Ниже ровно это: таблица дескрипторов ядра, имя файла по
# дескриптору и принудительное закрытие чужого дескриптора.

#: Момент последней безрезультатной уборки дескрипторов (см.
#: :func:`release_leftover_handles`): повторять её сразу же незачем.
_LAST_CLEAN_SWEEP = -1e9

_SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_PROCESS_DUP_HANDLE = 0x0040
_DUPLICATE_SAME_ACCESS = 0x00000002
_DUPLICATE_CLOSE_SOURCE = 0x00000001
_FILE_TYPE_DISK = 0x0001
_ERROR_SHARING_VIOLATION = 32
_ERROR_LOCK_VIOLATION = 33


def _enable_debug_privilege() -> bool:
    """SeDebugPrivilege: без неё не видны дескрипторы системных служб."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD),
                        ("HighPart", ctypes.c_long)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
            return False
        try:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                                  ctypes.byref(luid)):
                return False
            privileges = TOKEN_PRIVILEGES()
            privileges.PrivilegeCount = 1
            privileges.Privileges[0].Luid = luid
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            if not advapi32.AdjustTokenPrivileges(
                    token, False, ctypes.byref(privileges), 0, None, None):
                return False
            return kernel32.GetLastError() == 0
        finally:
            kernel32.CloseHandle(token)
    except Exception:
        return False


def _handle_table() -> "list[tuple[int, int, int]]":
    """Вся таблица дескрипторов системы: ``(pid, дескриптор, тип)``."""
    if not IS_WINDOWS:
        return []
    try:
        import ctypes
        from ctypes import wintypes

        class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
            _fields_ = [
                ("Object", ctypes.c_void_p),
                ("UniqueProcessId", ctypes.c_size_t),
                ("HandleValue", ctypes.c_size_t),
                ("GrantedAccess", wintypes.ULONG),
                ("CreatorBackTraceIndex", wintypes.USHORT),
                ("ObjectTypeIndex", wintypes.USHORT),
                ("HandleAttributes", wintypes.ULONG),
                ("Reserved", wintypes.ULONG),
            ]

        class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
            _fields_ = [
                ("NumberOfHandles", ctypes.c_size_t),
                ("Reserved", ctypes.c_size_t),
                ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
            ]

        ntdll = ctypes.windll.ntdll  # type: ignore[attr-defined]
        size = 1 << 20
        for _attempt in range(12):
            buffer = ctypes.create_string_buffer(size)
            needed = wintypes.ULONG(0)
            status = ntdll.NtQuerySystemInformation(
                _SYSTEM_EXTENDED_HANDLE_INFORMATION, buffer, size,
                ctypes.byref(needed))
            if status == 0:
                break
            if status & 0xFFFFFFFF != _STATUS_INFO_LENGTH_MISMATCH:
                return []
            size = max(int(needed.value) + (1 << 20), size * 2)
        else:
            return []

        header = ctypes.cast(
            buffer, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION_EX)).contents
        count = int(header.NumberOfHandles)
        if count <= 0:
            return []
        offset = SYSTEM_HANDLE_INFORMATION_EX.Handles.offset
        entries = ctypes.cast(
            ctypes.byref(buffer, offset),
            ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * count)).contents
        return [(int(e.UniqueProcessId), int(e.HandleValue),
                 int(e.ObjectTypeIndex)) for e in entries]
    except Exception:
        return []


def _file_type_index(table: "Sequence[tuple[int, int, int]]") -> int:
    """Номер типа «File» в этой Windows: определяется по своему же файлу."""
    if not IS_WINDOWS or not table:
        return -1
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        own = os.getpid()
        fd, path = tempfile.mkstemp(prefix="portable-probe-")
        try:
            handle = kernel32.CreateFileW(path, 0x80000000, 7, None, 3,
                                          0x80, None) or 0
            if not handle or handle == ctypes.c_void_p(-1).value:
                return -1
            try:
                for pid, value, kind in table:
                    if pid == own and value == int(handle):
                        return kind
            finally:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
        finally:
            os.close(fd)
            try:
                os.unlink(path)
            except OSError:
                pass
    except Exception:
        return -1
    return -1


def _path_of_handle(duplicate) -> str:
    """Путь файла по дескриптору; каналы и сокеты пропускаются."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        if kernel32.GetFileType(duplicate) != _FILE_TYPE_DISK:
            return ""
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel32.GetFinalPathNameByHandleW(duplicate, buffer, 32767, 0)
        if not length or length > 32767:
            return ""
        path = buffer.value
        if path.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path[8:]
        if path.startswith("\\\\?\\"):
            return path[4:]
        return path
    except Exception:
        return ""


def open_files_in(root: Path, budget: float = 8.0,
                  roots: "Optional[Sequence[Path]]" = None
                  ) -> "list[tuple[int, int, str, str]]":
    """Открытые файлы внутри папки: ``(pid, дескриптор, путь, образ)``.

    Собственные процессы (этот лончер и его загрузчик PyInstaller)
    исключаются: их дескрипторы исчезнут сами, как только лончер выйдет.
    """
    if not IS_WINDOWS:
        return []
    import time

    _enable_debug_privilege()
    table = _handle_table()
    if not table:
        return []
    wanted_type = _file_type_index(table)
    prefix = str(root).rstrip("\\").casefold() + "\\"
    # Пути интересующих папок: дескрипторы чужих файлов отбрасываются сразу,
    # не доходя до разбора процессов.
    wanted = [str(item).rstrip("\\").casefold() + "\\"
              for item in (roots or ()) if str(item).strip()]
    own_images = {image.casefold() for image in _own_executable_images()}
    images = {pid: image for pid, image in _all_processes()}
    skip = {os.getpid()}
    skip.update(pid for pid, image in images.items()
                if image.casefold() in own_images)
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        # HANDLE шире int: без restype псевдодескриптор текущего процесса
        # приедет в DuplicateHandle обрезанным.
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.restype = ctypes.c_void_p
        current = ctypes.c_void_p(kernel32.GetCurrentProcess())
        deadline = time.monotonic() + budget
        found: list[tuple[int, int, str, str]] = []
        opened: dict = {}
        try:
            for pid, value, kind in table:
                if time.monotonic() > deadline:
                    break
                if pid in skip or pid in (0, 4) or not value:
                    continue
                if wanted_type >= 0 and kind != wanted_type:
                    continue
                process = opened.get(pid, -1)
                if process == -1:
                    process = kernel32.OpenProcess(
                        _PROCESS_DUP_HANDLE, False, pid) or 0
                    opened[pid] = process
                if not process:
                    continue
                duplicate = ctypes.c_void_p()
                if not kernel32.DuplicateHandle(
                        ctypes.c_void_p(process), ctypes.c_void_p(value),
                        current, ctypes.byref(duplicate), 0, False,
                        _DUPLICATE_SAME_ACCESS):
                    continue
                try:
                    path = _path_of_handle(duplicate)
                finally:
                    kernel32.CloseHandle(duplicate)
                if not path or not path.casefold().startswith(prefix):
                    continue
                if wanted and not any(path.casefold().startswith(item)
                                      for item in wanted):
                    continue
                found.append((pid, value, path, images.get(pid, "")))
        finally:
            for process in opened.values():
                if process:
                    kernel32.CloseHandle(ctypes.c_void_p(process))
        return found
    except Exception:
        return []


def _close_remote_handle(pid: int, handle: int) -> bool:
    """Закрывает чужой дескриптор, не трогая сам процесс (нужны права)."""
    if not IS_WINDOWS or not pid or not handle:
        return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.restype = ctypes.c_void_p
        process = kernel32.OpenProcess(_PROCESS_DUP_HANDLE, False, int(pid))
        if not process:
            return False
        try:
            duplicate = ctypes.c_void_p()
            return bool(kernel32.DuplicateHandle(
                ctypes.c_void_p(process), ctypes.c_void_p(int(handle)),
                ctypes.c_void_p(kernel32.GetCurrentProcess()),
                ctypes.byref(duplicate), 0, False,
                _DUPLICATE_CLOSE_SOURCE)) and bool(
                    kernel32.CloseHandle(duplicate))
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(process))
    except Exception:
        return False


def describe_open_files(items: "Sequence[tuple[int, int, str, str]]") -> str:
    """«svchost.exe (pid 17208): OpenSans-Regular.ttf» - понятный виновник."""
    parts = []
    for pid, _handle, path, image in items:
        name = _image_name(image) or f"pid {pid}"
        parts.append(f"{name} (pid {pid}): {_image_name(path)}")
    return ", ".join(sorted(set(parts)))


def busy_files(root: Path, budget: float = 4.0, limit: int = 12,
               roots: "Optional[Sequence[Path]]" = None) -> "list[str]":
    """Файлы папки, которые Windows прямо сейчас не отдаёт.

    Проверка делом и без всяких прав: файл открывается на монопольный
    доступ. Именно это условие стоит за «файл открыт в другой программе»,
    то есть за невозможностью удалить папку. Файлы самого лончера
    пропускаются - они освободятся, как только лончер выйдет.

    ``roots`` ограничивает обход: у Cursor в ``App`` десятки тысяч файлов, и
    открывать каждый ради поиска запертого файла во временной папке - это
    секунды ожидания на ровном месте.
    """
    if not IS_WINDOWS or not root or not os.path.isdir(str(root)):
        return []
    import time

    walk_roots = [str(item) for item in (roots or ()) if os.path.isdir(str(item))]
    if not walk_roots:
        walk_roots = [str(root)]

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        invalid = ctypes.c_void_p(-1).value
        # Без явного restype ctypes обрежет HANDLE до 32-битного int, и
        # «не удалось открыть» станет неотличимо от удачи.
        kernel32.CreateFileW.restype = ctypes.c_void_p
        mine = {image.casefold() for image in _own_executable_images()}

        def locked(path: str) -> bool:
            if path.casefold() in mine:
                return False
            handle = kernel32.CreateFileW(path, 0x80000000, 0, None, 3,
                                          0x80, None)
            error = kernel32.GetLastError()
            if handle in (None, 0, invalid):
                return error in (_ERROR_SHARING_VIOLATION,
                                 _ERROR_LOCK_VIOLATION)
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return False

        deadline = time.monotonic() + budget
        suspects: list[str] = []
        for walk_root in walk_roots:
            for current, _dirs, files in os.walk(walk_root):
                if time.monotonic() > deadline or len(suspects) >= limit:
                    break
                for name in files:
                    path = os.path.join(current, name)
                    if locked(path):
                        suspects.append(path)
                        if len(suspects) >= limit:
                            break
                    if time.monotonic() > deadline:
                        break
                if time.monotonic() > deadline or len(suspects) >= limit:
                    break
        if not suspects:
            return []
        time.sleep(0.4)
        return [path for path in suspects if locked(path)]
    except Exception:
        return []


def forget_fonts(root: Path, budget: float = 3.0,
                 roots: "Optional[Sequence[Path]]" = None) -> int:
    """Снимает регистрацию шрифтов, подключённых из папки портатива.

    Установщики (Inno Setup с его `is-XXXX.tmp`) подключают свои шрифты
    через ``AddFontResource``. Установщик давно закрыт, а файл держит
    служба кэша шрифтов - папка не удаляется, и процесса-виновника при
    этом нет. ``RemoveFontResource`` снимает регистрацию, и файл
    освобождается.
    """
    if not IS_WINDOWS or not os.path.isdir(str(root)):
        return 0
    import time

    try:
        import ctypes

        gdi32 = ctypes.windll.gdi32  # type: ignore[attr-defined]
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        HWND_BROADCAST = 0xFFFF
        WM_FONTCHANGE = 0x001D
        extensions = (".ttf", ".ttc", ".otf", ".fon", ".fnt")
        deadline = time.monotonic() + budget
        removed = 0
        walk_roots = [str(item) for item in (roots or ()) if os.path.isdir(str(item))]
        for walk_root in walk_roots or [str(root)]:
            for current, _dirs, files in os.walk(walk_root):
                if time.monotonic() > deadline:
                    break
                for name in files:
                    if not name.casefold().endswith(extensions):
                        continue
                    path = os.path.join(current, name)
                    for _repeat in range(8):
                        if not gdi32.RemoveFontResourceW(path):
                            break
                        removed += 1
                if time.monotonic() > deadline:
                    break
        if removed:
            user32.PostMessageW(HWND_BROADCAST, WM_FONTCHANGE, 0, 0)
        return removed
    except Exception:
        return 0


def _installed_software_image(image: str) -> bool:
    """Программа из системных папок или Program Files - не остаток портатива.

    Антивирус, индексатор, синхронизация облака держат файл портатива
    совершенно законно: они его читают. Завершать их нельзя - у них можно
    только отобрать дескриптор.
    """
    if not image:
        return True
    normalized = str(image).replace("/", "\\").casefold()
    roots = [os.environ.get(name, "") for name in
             ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)",
              "ProgramW6432", "windir")]
    roots.extend(["c:\\windows", "c:\\program files",
                  "c:\\program files (x86)"])
    for folder in roots:
        if folder and normalized.startswith(
                str(folder).replace("/", "\\").rstrip("\\").casefold() + "\\"):
            return True
    return False


def release_open_files(root: Path, budget: float = 8.0,
                       roots: "Optional[Sequence[Path]]" = None) -> "list[str]":
    """Отпускает файлы папки, открытые кем-то снаружи.

    * безымянный фоновый «помощник» (без окна, запущен не из системных
      папок) - завершается: это и есть остаток портатива, из-за которого
      папку не удалить;
    * системный процесс Windows или установленная программа (антивирус,
      индексатор) - не трогаем, но закрываем её дескриптор на наш файл
      (это умеет только администратор);
    * чужое окно (редактор, файловый менеджер) - не трогаем вообще: за ним
      может быть несохранённый документ, его только называем.
    """
    if not IS_WINDOWS:
        return []
    import time

    items = open_files_in(root, budget=budget, roots=roots)
    if not items:
        return []
    visible = _visible_window_pids()
    stopped: list[str] = []
    background = sorted({
        pid for pid, _handle, _path, image in items
        if _image_name(image).casefold() not in PROTECTED_IMAGES
        and pid not in visible and not _is_interactive_image(image)
        and not _installed_software_image(image)})
    if background:
        names = sorted({_image_name(image) or f"pid {pid}"
                        for pid, _h, _p, image in items
                        if pid in background})
        _post_close_to_windows(background)
        time.sleep(0.5)
        _terminate_pids(background)
        stopped.extend(f"{name} (держал файл портатива)" for name in names)
        time.sleep(0.3)

    for pid, handle, path, image in open_files_in(root, budget=budget):
        if _close_remote_handle(pid, handle):
            stopped.append(
                f"{_image_name(image) or ('pid ' + str(pid))}: "
                f"освобождён файл {_image_name(path)}")
    return stopped


def purge_portable_temp(root: Path, cfg: "Optional[Dict[str, Any]]" = None
                        ) -> int:
    """Чистит временные папки портатива - источник вечных блокировок.

    ``PortableData\\Temp`` накапливает распакованные установщиками каталоги
    вида ``is-XXXX.tmp`` со шрифтами и DLL. Пока они лежат на диске, их
    может подхватить (и держать) системная служба, а пользователь получает
    папку, которую нельзя ни удалить, ни перенести. Содержимое Temp по
    определению одноразовое, поэтому между запусками оно удаляется.
    """
    import shutil

    config = cfg or {}
    shutdown = config.get("shutdown")
    if isinstance(shutdown, dict) and shutdown.get("purge_temp") is False:
        return 0
    data_name = str(config.get("data_dir_name", "PortableData"))
    removed = 0
    for relative in ((data_name, "Temp"),
                     (data_name, "AppData", "Local", "Temp")):
        folder = root.joinpath(*relative)
        if not folder.is_dir():
            continue
        for entry in folder.iterdir():
            try:
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink()
                removed += 1
            except OSError:
                continue
    return removed


def shutdown_settings(cfg: Dict[str, Any]) -> Dict[str, float]:
    """Timings of the shutdown sequence, with sane clamps.

    Everything is configurable from ``launcher_config.json`` ("shutdown"
    section) but never unbounded: the whole point of the section is that the
    launcher must not outlive the program it started.
    """
    raw = cfg.get("shutdown") or {}
    if not isinstance(raw, dict):
        raw = {}

    def number(name: str, default: float, low: float, high: float) -> float:
        try:
            value = float(raw.get(name, default))
        except (TypeError, ValueError):
            return default
        return max(low, min(high, value))

    kill = raw.get("kill_leftovers", True)
    return {
        # How long to wait for an official launcher to spawn the real program.
        "spawn_grace": number("spawn_grace", 6.0, 0.0, 120.0),
        # How long a windowless process from the folder may keep the session
        # alive before it is treated as a leftover. Снижено с 20 до 5 секунд:
        # жалоба №4 — LaunchPortable.exe висел в Диспетчере задач после
        # закрытия игры, потому что ждал фоновые crash-handler'ы 20 секунд.
        # Настоящая программа с окном всё равно не попадёт под таймер
        # (перепроверяется через _visible_window_pids / _is_interactive_image).
        "idle_grace": number("idle_grace", 5.0, 1.0, 3600.0),
        # Politeness window after WM_CLOSE, before TerminateProcess.
        "close_grace": number("close_grace", 5.0, 0.0, 120.0),
        # Absolute ceiling for a single portable session.
        "max_wait": number("max_wait", 86400.0, 10.0, 604800.0),
        "kill_leftovers": 1.0 if kill or kill is None else 0.0,
        # Искать ли чужие процессы, подгрузившие DLL из папки, и разбирать
        # ли таблицу дескрипторов. Стоит времени на выходе, зато называет
        # виновника (и закрывает его), когда папка всё же занята.
        "deep_check": 0.0 if raw.get("deep_check") is False else 1.0,
        # Потолок обхода дескрипторов: лончер не вправе зависнуть на выходе.
        "handle_budget": number("handle_budget", 8.0, 0.0, 60.0),
        # Чистить ли PortableData\Temp между запусками.
        "purge_temp": 0.0 if raw.get("purge_temp") is False else 1.0,
    }


def _wait_for_portable_processes(root: Path, grace: float = 6.0,
                                 limit: float = 86400.0,
                                 settings: Optional[Dict[str, float]] = None,
                                 tick: "Optional[Any]" = None
                                 ) -> int:
    """Wait while the portable program is really being used.

    Official game launchers (The Witcher's ``Launcher.exe``, GOG splash
    screens, Configurator windows) start the real executable and exit
    immediately.  If the portable session restored the registry and removed the
    redirected environment at that moment, the game that had just been spawned
    lost its install keys and died silently.  So after the direct child exits we
    keep the sandbox alive while any process started from this folder lives.

    The wait is no longer unconditional, though.  Anything that still runs
    from the folder *without a single visible window* - crash handlers,
    updaters, "helper" services, telemetry daemons - used to keep this
    launcher alive for up to 24 hours, and the launcher EXE itself sits inside
    ``App``: the user closed the program but could not delete the folder.
    Such windowless stragglers now only get ``idle_grace`` seconds, after
    which the caller shuts them down.  A tray icon (hidden top-level
    window, no ``MainWindowHandle``) is *not* windowless: it is the
    program the user is still using.
    """
    if not IS_WINDOWS:
        return 0
    import time

    cfg = settings or {}
    spawn_grace = float(cfg.get("spawn_grace", grace))
    idle_grace = float(cfg.get("idle_grace", 20.0))
    deadline = time.monotonic() + float(cfg.get("max_wait", limit))
    waited = 0
    # Give the launcher a moment to spawn the real program.
    spawn_deadline = time.monotonic() + spawn_grace
    while time.monotonic() < spawn_deadline:
        if _portable_processes(root):
            break
        if tick is not None:
            tick()
        time.sleep(0.5)

    idle_since: Optional[float] = None
    while True:
        running = _portable_process_list(root)
        if not running:
            return waited
        now = time.monotonic()
        if now >= deadline:
            return waited
        visible = _visible_window_pids()
        if any(pid in visible or _is_interactive_image(image)
               for pid, image in running):
            idle_since = None
        elif idle_since is None:
            idle_since = now
        elif now - idle_since >= idle_grace:
            # Nothing on screen for a while: the user is done, whatever is
            # left is background noise the caller will clean up.
            return waited
        waited += 1
        if tick is not None:
            # Родной апдейтер надо ловить за доли секунды, до первого файла.
            tick()
            time.sleep(0.5)
            tick()
            time.sleep(0.5)
        else:
            time.sleep(1.0)


def release_portable_folder(root: Path,
                            settings: Optional[Dict[str, float]] = None
                            ) -> "list[str]":
    """Make sure nothing from the portable folder is running any more.

    Returns the names of the processes that had to be stopped, so the caller
    can write them into the run log.  Politeness first: every window gets a
    ``WM_CLOSE`` and ``close_grace`` seconds to save its state; only then the
    survivors are terminated.  Without this step the folder stays locked by
    the very files the user is trying to delete.
    """
    if not IS_WINDOWS:
        return []
    import time

    cfg = settings or {}
    close_grace = float(cfg.get("close_grace", 5.0))
    kill = bool(cfg.get("kill_leftovers", 1.0))
    running = _portable_process_list(root)
    stopped = [_image_name(image) for _, image in running]

    if running:
        _post_close_to_windows(pid for pid, _ in running)
        deadline = time.monotonic() + close_grace
        while time.monotonic() < deadline:
            running = _portable_process_list(root)
            if not running:
                break
            time.sleep(0.25)

    running = _portable_process_list(root)
    if running and kill:
        _terminate_pids(pid for pid, _ in running)
        # Windows tears a process down asynchronously; give the handles a
        # moment to close so the folder is really deletable afterwards.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and _portable_process_list(root):
            time.sleep(0.25)
    stopped.extend(release_leftover_handles(root, cfg))
    return stopped


def release_leftover_handles(root: Path,
                             settings: Optional[Dict[str, float]] = None,
                             roots: "Optional[Sequence[Path]]" = None
                             ) -> "list[str]":
    """Добивает то, что держит папку уже без своего процесса.

    После завершения процессов портатива папка всё ещё может быть занята:
    шрифт из ``PortableData\\Temp`` подхватила служба кэша шрифтов, лог
    читает антивирус, сохранение открыл индексатор. Своего процесса у
    такого держателя нет, ждать его бесполезно - дескриптор закрывается
    принудительно, а фоновый держатель завершается.

    Дорогой разбор включается только по делу: сначала дешёвая проверка
    «есть ли вообще хоть один занятый файл». Если папка чиста - лончер
    выходит сразу, как и раньше.
    """
    if not IS_WINDOWS:
        return []
    import time

    global _LAST_CLEAN_SWEEP
    cfg = settings or {}
    if not bool(cfg.get("deep_check", 1.0)):
        return []
    # За один выход лончера уборка вызывается дважды (штатно и в
    # предохранителе finally). Если прошлый проход только что признал
    # папку чистой, второй не нужен.
    if time.monotonic() - _LAST_CLEAN_SWEEP < 10.0:
        return []
    if not busy_files(root, budget=float(cfg.get("busy_budget", 4.0)),
                      roots=roots):
        _LAST_CLEAN_SWEEP = time.monotonic()
        return []

    stopped: list[str] = []
    if forget_fonts(root, roots=roots):
        stopped.append("сняты с регистрации шрифты портатива")
    stopped.extend(release_open_files(root, budget=float(
        cfg.get("handle_budget", 8.0)), roots=roots))
    if not busy_files(root, budget=float(cfg.get("busy_budget", 4.0)),
                      roots=roots):
        _LAST_CLEAN_SWEEP = time.monotonic()
    return stopped


def folder_looks_clean() -> bool:
    """Признал ли недавний проход папку свободной (без нового обхода)."""
    import time

    return time.monotonic() - _LAST_CLEAN_SWEEP < 10.0


def _report_folder_state(root: Path,
                         settings: Optional[Dict[str, float]] = None) -> None:
    """Записывает в журнал честный вердикт: свободна ли папка.

    Пользователь хочет удалить папку. Если это почему-то всё ещё нельзя,
    он должен прочитать в журнале ИМЯ виновника, а не гадать.
    """
    remaining = _portable_process_list(root)
    if remaining:
        _run_log(root, "WARNING: still running from the portable folder: "
                 + ", ".join(sorted({_image_name(i) for _, i in remaining})))
        return
    deep = True
    if settings is not None:
        deep = bool(settings.get("deep_check", 1.0))
    if not deep:
        _run_log(root, "portable folder released: no processes left")
        return

    # Процессов из папки нет - но «нет процессов» и «папку можно удалить»
    # это разные вещи. Вердикт выдаётся только после проверки делом:
    # остался ли внутри хоть один файл, который Windows не отдаёт.
    locked = [] if folder_looks_clean() else busy_files(root)
    if locked:
        items = [item for item in open_files_in(root)
                 if item[2] in locked] or open_files_in(root)
        description = describe_open_files(items) or ", ".join(
            _image_name(path) for path in locked[:6])
        _run_log(root, "WARNING: the folder is still locked by open files: "
                 + description
                 + ". Run StopPortable.cmd as administrator to force them "
                   "closed.")
        return
    holders = module_holders(root)
    if holders:
        _run_log(root, "WARNING: the folder is still held by other programs: "
                 + describe_holders(holders)
                 + ". Close them (a file manager preview or an antivirus "
                   "scan is the usual reason) and the folder can be deleted.")
        return
    _run_log(root, "portable folder released: no processes left")


class _JobObject:
    """Kill-on-close job: the safety net under the whole shutdown sequence.

    Every process the portable program spawns - and every process *those*
    spawn - is put into this job.  Whatever happens afterwards (the launcher
    crashes, the user kills it from the Task Manager, a helper ignores
    ``WM_CLOSE``), Windows destroys the job together with its last handle and
    the folder is free again.  Nothing from the portable folder can outlive
    the launcher any more.

    Pass ``enabled=False`` for Electron/Ollama: see :func:`should_use_job`.
    """

    def __init__(self, enabled: bool = True) -> None:
        self.handle = None
        if not enabled or not IS_WINDOWS:
            return
        try:
            import ctypes
            from ctypes import wintypes

            JobObjectExtendedLimitInformation = 9
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
            # Chromium/Electron (Ollama, OpenCode, …) spawn GPU/renderer
            # processes with CREATE_BREAKAWAY_FROM_JOB.  Without BREAKAWAY_OK
            # that CreateProcess fails: the tray icon is alive but "Open
            # Ollama" never shows a window and the UI then stops responding.
            # Children that do break away are still found by image path and
            # closed in release_portable_folder.
            JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [("ReadOperationCount", ctypes.c_ulonglong),
                            ("WriteOperationCount", ctypes.c_ulonglong),
                            ("OtherOperationCount", ctypes.c_ulonglong),
                            ("ReadTransferCount", ctypes.c_ulonglong),
                            ("WriteTransferCount", ctypes.c_ulonglong),
                            ("OtherTransferCount", ctypes.c_ulonglong)]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                            ("PerJobUserTimeLimit", ctypes.c_longlong),
                            ("LimitFlags", wintypes.DWORD),
                            ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t),
                            ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                            ("PriorityClass", wintypes.DWORD),
                            ("SchedulingClass", wintypes.DWORD)]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [("BasicLimitInformation",
                             JOBOBJECT_BASIC_LIMIT_INFORMATION),
                            ("IoInfo", IO_COUNTERS),
                            ("ProcessMemoryLimit", ctypes.c_size_t),
                            ("JobMemoryLimit", ctypes.c_size_t),
                            ("PeakProcessMemoryUsed", ctypes.c_size_t),
                            ("PeakJobMemoryUsed", ctypes.c_size_t)]

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = (
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_BREAKAWAY_OK)
            if not kernel32.SetInformationJobObject(
                    handle, JobObjectExtendedLimitInformation,
                    ctypes.byref(info), ctypes.sizeof(info)):
                kernel32.CloseHandle(handle)
                return
            self.handle = handle
        except Exception:
            self.handle = None

    def assign(self, process_handle: int) -> bool:
        if not self.handle or not process_handle:
            return False
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            return bool(kernel32.AssignProcessToJobObject(
                self.handle, int(process_handle)))
        except Exception:
            return False

    def close(self) -> None:
        if not self.handle:
            return
        try:
            import ctypes

            ctypes.windll.kernel32.CloseHandle(  # type: ignore[attr-defined]
                self.handle)
        except Exception:
            pass
        finally:
            self.handle = None


def _resume_process_threads(pid: int) -> int:
    """Resume every thread of a process created with ``CREATE_SUSPENDED``."""
    if not IS_WINDOWS:
        return 0
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPTHREAD = 0x00000004
        THREAD_SUSPEND_RESUME = 0x0002

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD),
                        ("cntUsage", wintypes.DWORD),
                        ("th32ThreadID", wintypes.DWORD),
                        ("th32OwnerProcessID", wintypes.DWORD),
                        ("tpBasePri", ctypes.c_long),
                        ("tpDeltaPri", ctypes.c_long),
                        ("dwFlags", wintypes.DWORD)]

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snapshot in (0, -1, None):
            return 0
        resumed = 0
        try:
            entry = THREADENTRY32()
            entry.dwSize = ctypes.sizeof(THREADENTRY32)
            more = kernel32.Thread32First(snapshot, ctypes.byref(entry))
            while more:
                if int(entry.th32OwnerProcessID) == int(pid):
                    thread = kernel32.OpenThread(
                        THREAD_SUSPEND_RESUME, False, entry.th32ThreadID)
                    if thread:
                        try:
                            if kernel32.ResumeThread(thread) != -1:
                                resumed += 1
                        finally:
                            kernel32.CloseHandle(thread)
                more = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
        return resumed
    except Exception:
        return 0


def _spawn_target(command: Sequence[str], cwd: str, env: Dict[str, str],
                  job: Optional["_JobObject"] = None) -> subprocess.Popen:
    """Start the program already captured by the kill-on-close job.

    The child is created suspended, put into the job and only then resumed:
    that way even the very first process it spawns is inside the job, and no
    descendant can escape the cleanup.  Every step degrades gracefully - if
    the job cannot be created (very old Windows, an outer job that forbids
    nesting), the program still starts, just without the safety net.
    """
    creationflags = 0
    suspended = False
    if IS_WINDOWS and job is not None and job.handle:
        CREATE_SUSPENDED = 0x00000004
        creationflags = CREATE_SUSPENDED
        suspended = True
    try:
        process = subprocess.Popen(  # noqa: S603
            list(command), cwd=cwd, env=env, creationflags=creationflags)
    except Exception:
        if not suspended:
            raise
        # Suspended start refused: fall back to an ordinary launch.
        return subprocess.Popen(list(command), cwd=cwd, env=env)  # noqa: S603
    if suspended and job is not None:
        job.assign(int(process._handle))  # type: ignore[attr-defined]
        if not _resume_process_threads(process.pid):
            # Резюмировать не удалось - программа так и осталась бы висеть
            # замороженной, а пользователь смотрел бы в пустой экран.
            # Убираем неудачную попытку и стартуем обычным способом.
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass
            return subprocess.Popen(  # noqa: S603
                list(command), cwd=cwd, env=env)
    elif job is not None:
        job.assign(int(getattr(process, "_handle", 0) or 0))
    return process


def _is_elevated() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


#: Сколько ждать повышенную копию лончера, мс. Раньше ожидание было
#: бесконечным (``WaitForSingleObject(..., INFINITE)``): если окно UAC никто не
#: закрывал или повышенная копия зависала на своём диалоге, лончер висел
#: навсегда — ровно это и выглядело как «завис запрос UAC».
ELEVATED_WAIT_MS = 300_000


def _run_elevated(arguments: Sequence[str],
                  timeout_ms: int = ELEVATED_WAIT_MS) -> Optional[int]:
    """Relaunch this frozen EXE through UAC, wait for its exit code — но не вечно.

    ``None`` означает «результата нет»: пользователь отказался от UAC, окно
    повышения не появилось или повышенная копия не уложилась в ``timeout_ms``.
    Вызывающий код в этом случае продолжает работу без импорта HKLM (есть
    запасной путь через VirtualStore), а не остаётся ждать навсегда.
    """
    if not IS_WINDOWS or not getattr(sys, "frozen", False):
        return None
    try:
        import ctypes
        from ctypes import wintypes

        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        SEE_MASK_NO_CONSOLE = 0x00008000

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong),
                ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE),
            ]

        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE
        info.lpVerb = "runas"
        info.lpFile = str(sys.executable)
        info.lpParameters = subprocess.list2cmdline(
            [*map(str, arguments), "--elevated"])
        info.lpDirectory = str(_runtime_directory())
        info.nShow = 1
        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
        if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
            return None
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        WAIT_TIMEOUT = 0x00000102
        waited = kernel32.WaitForSingleObject(info.hProcess, int(timeout_ms))
        if waited == WAIT_TIMEOUT:
            # Повышенная копия не ответила за отведённое время. Процесс НЕ
            # убиваем: он может добросовестно работать (например, ставить
            # драйвер), а вот ждать его дальше нельзя — иначе весь запуск
            # программы превращается в «висящий» UAC.
            kernel32.CloseHandle(info.hProcess)
            return None
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        kernel32.CloseHandle(info.hProcess)
        return int(code.value)
    except Exception:
        return None


#: Сколько помнить отказ от UAC, секунды. Раньше отказ нигде не запоминался,
#: и лончер спрашивал права заново при КАЖДОМ запуске — при неудачном
#: раскладе это выглядело как «завис запрос UAC».
ELEVATION_REFUSAL_MEMORY = 3600.0

#: Насколько «в прошлое» может уйти отметка об отказе UAC из-за перевода
#: часов на машине (служба времени может сдвинуть их на несколько секунд
#: назад уже после записи файла). Без этого допуска только что записанная
#: отметка считалась бы отсутствующей, и лончер снова спрашивал бы UAC.
ELEVATION_CLOCK_SLACK = 300.0


def _elevation_stamp(root: Path) -> Path:
    data = root / "PortableData" / "RegistryHostBackup"
    return data / "elevation-refused.json"


def mark_elevation_refused(root: Path, reason: str = "") -> None:
    """Запоминает отказ/неудачу UAC, чтобы не спрашивать повторно каждый запуск."""
    import time

    path = _elevation_stamp(root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "when": time.time(),
            "reason": str(reason)[:300],
        }, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def elevation_recently_refused(root: Path,
                              memory: float = ELEVATION_REFUSAL_MEMORY
                              ) -> bool:
    """Отказывались ли от UAC недавно (по умолчанию — в течение часа)."""
    import time

    try:
        data = json.loads(_elevation_stamp(root).read_text(encoding="utf-8"))
        when = float(data.get("when", 0.0))
    except (OSError, ValueError, TypeError):
        return False
    if float(memory) <= 0.0:
        return False
    # Часы могли уйти назад уже после записи отметки — её всё равно считаем
    # свежей, иначе лончер спрашивал бы UAC заново каждый запуск.
    age = time.time() - when
    return -ELEVATION_CLOCK_SLACK < age < float(memory)


def clear_elevation_refusal(root: Path) -> None:
    """Сбрасывает отметку об отказе (например, после удачного повышенного хода)."""
    try:
        _elevation_stamp(root).unlink()
    except OSError:
        pass


def temp_leftovers(root: Path, cfg: "Optional[Dict[str, Any]]" = None) -> int:
    """Сколько записей осталось во временных папках портатива."""
    data_name = str((cfg or {}).get("data_dir_name", "PortableData"))
    left = 0
    for relative in ((data_name, "Temp"),
                     (data_name, "AppData", "Local", "Temp")):
        folder = root.joinpath(*relative)
        if folder.is_dir():
            try:
                left += sum(1 for _entry in folder.iterdir())
            except OSError:
                continue
    return left


def sweep_stale_session(root: Path, cfg: "Dict[str, Any]") -> "list[str]":
    """Убирает остатки ПРЕДЫДУЩЕГО запуска, пока новый ещё не начался.

    Правило, которого ждёт пользователь: не запущен портатив - не должно
    быть и его фоновых процессов. Поэтому перед стартом (когда из папки
    заведомо ничего не работает) добиваются остатки прошлой сессии:
    временная папка с распакованными установщиком файлами и тот, кто не
    даёт их удалить. Если из папки что-то уже запущено - это второй
    экземпляр программы, и трогать его нельзя.

    Порядок выбран ради скорости запуска: сначала дешёвое удаление, и
    только если что-то не удалилось (значит, держат) - дорогой разбор
    дескрипторов.
    """
    if not IS_WINDOWS:
        return []
    sweep = StaleSessionSweep(root, cfg)
    sweep.prepare()
    done = sweep.run()
    return done


def _temp_dirs(root: Path,
               cfg: "Optional[Dict[str, Any]]" = None) -> "list[Path]":
    """Временные папки портатива (там и только там ждут своей очереди остатки)."""
    config = cfg or {}
    data_name = str(config.get("data_dir_name", "PortableData"))
    return [root.joinpath(*relative) for relative in (
        (data_name, "Temp"),
        (data_name, "AppData", "Local", "Temp"),
    )]


class StaleSessionSweep:
    """Остатки прошлого запуска: найти ДО старта, убрать ПОСЛЕ него.

    Уборка временных папок — самая дорогая часть запуска на Windows: файлов
    там бывают тысячи (Electron и установщики пишут в ``%TEMP%`` постоянно),
    и каждый приходится удалять отдельным вызовом, мимо антивируса. Программе
    эта уборка для появления окна не нужна, поэтому до старта выполняется
    только дешёвая часть — проверка «из папки ничего не работает» и список
    того, что надо удалить (один обход каталога). Само удаление идёт в фоне,
    одновременно с запуском программы.

    Если же что-то удалить не далось, разбор «кто держит файл» ограничивается
    временными папками: раньше он открывал на монопольный доступ КАЖДЫЙ файл
    всего портатива (у Cursor это десятки тысяч) и мог занять секунды.
    """

    def __init__(self, root: Path,
                 cfg: "Optional[Dict[str, Any]]" = None) -> None:
        self.root = root
        self.cfg = cfg or {}
        self.entries: "list[Path]" = []
        self.skip = False
        self.skip_reason = ""

    def _dirs(self) -> "list[Path]":
        return [folder for folder in _temp_dirs(self.root, self.cfg)
                if folder.is_dir()]

    def prepare(self) -> None:
        """Дешёвая часть: можно ли трогать папку и что именно удалять."""
        if not IS_WINDOWS:
            self.skip = True
            return
        try:
            if _portable_process_list(self.root):
                # Из портатива уже что-то работает - это второй экземпляр
                # программы, и его временные файлы трогать нельзя.
                self.skip = True
                self.skip_reason = "the program is already running"
                return
        except Exception:  # noqa: BLE001 - уборка не срывает запуск
            pass
        # Достаточно верхнего уровня: содержимое папки удалится вместе с ней.
        for folder in self._dirs():
            try:
                self.entries.extend(folder.iterdir())
            except OSError:
                continue

    def run(self) -> "list[str]":
        """Дорогая часть — в фоне, пока программа уже запускается."""
        if self.skip or not self.entries:
            if self.skip_reason:
                _run_log(self.root, "stale session cleanup skipped: "
                         + self.skip_reason)
            return []
        removed = 0
        for entry in self.entries:
            try:
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink()
                removed += 1
            except OSError:
                continue
        done: list[str] = []
        if removed:
            done.append(f"очищена временная папка портатива ({removed})")
        left = [entry for entry in self.entries if entry.exists()]
        if left:
            # Что-то держат: разбираемся, но только во временных папках.
            dirs = self._dirs()
            done.extend(release_leftover_handles(
                self.root, shutdown_settings(self.cfg), roots=dirs))
            again = 0
            for entry in left:
                try:
                    if entry.is_dir() and not entry.is_symlink():
                        shutil.rmtree(entry, ignore_errors=True)
                    else:
                        entry.unlink()
                    again += 1
                except OSError:
                    continue
            if again:
                done.append("временная папка освобождена принудительно")
        return done


# --- обновление программы внутри портатива ------------------------------------
#
# Жалоба, ради которой написан раздел: Ollama показала «доступна новая версия»,
# пользователь нажал «перезапустить для обновления» - и всё зависло, а после
# принудительного завершения программа вылетала при каждом запуске.
#
# Причина в самом механизме. «Родное» обновление скачивает установщик в
# %LOCALAPPDATA%\Ollama\updates_v2, переименовывает его в
# %LOCALAPPDATA%\Ollama\OllamaSetup.exe, запускает его ОТДЕЛЬНЫМ процессом
# (/CLOSEAPPLICATIONS /FORCECLOSEAPPLICATIONS /SILENT) и тут же завершается.
# В портативе это ломается трижды:
#   * установщик не знает про папку App: он ставит программу по умолчанию -
#     в профиль ЭТОГО ПК, а не в портатив;
#   * лончер видит живой процесс из своей папки и ждёт его (окно установщика
#     считается «видимым» - ждать можно сутки), а потом убивает его на
#     полпути: половина файлов новая, половина старая;
#   * файл-маркер ``upgraded`` и недоустановленный OllamaSetup.exe остаются
#     лежать, и программа при следующем старте снова лезет в «обновление».
#
# Поэтому лончер перехватывает запуск обновления и просит установщик писать
# в Updates\stage: затем проверяет payload и подменяет файлы в App, сохраняя
# прежнюю версию в Updates\backup. Это защищает файлы самого портатива, но
# НЕ изолирует сторонний установщик от Windows: тот всё ещё может менять
# реестр, службы, ярлыки и профиль. Такие изменения автоматически не удаляются;
# для недоверенного установщика используйте Sandbox/виртуальную машину.
# Журнал Updates\journal.json помогает восстановить только состояние файлов
# портатива после прерывания.

UPDATE_DIR_NAME = "Updates"
UPDATE_JOURNAL_NAME = "journal.json"
UPDATE_LOG_NAME = "launcher-update.log"
UPDATE_HOST_CHANGE_WARNING = (
    "Важно: сторонний установщик выполняется без полной изоляции от Windows; "
    "он может менять системный реестр, службы, ярлыки и профиль. Portablizer "
    "не откатывает такие изменения. Для недоверенного файла используйте "
    "Windows Sandbox или виртуальную машину.")

#: Коды возврата установщиков, означающие успех.
UPDATE_OK_CODES = (0, 3010, 1641)

#: Запас по времени при поиске «свежих» файлов установщика. У FAT/exFAT
#: (флешка, внешний диск) время изменения файла хранится с точностью до двух
#: секунд, а часы файловой системы могут отставать от системных: файл,
#: записанный сразу после начала обновления, выглядел бы «старым».
STALE_MTIME_GRACE = 5.0

#: Известные программы с собственным обновлением. Значения - умолчания блока
#: ``update`` в launcher_config.json; сам блок их перекрывает. Маркер ищется в
#: имени программы и путях её exe, как у ``identity``.
UPDATE_PROFILES = (
    ("ollama", {
        "engine": "inno",
        "source_url": "https://ollama.com/download/OllamaSetup.exe",
        # Куда родной апдейтер кладёт скачанное (относительно PortableData).
        "staged": [
            "AppData/Local/Ollama/updates_v2/*/*.exe",
            "AppData/Local/Ollama/updates/*/*.exe",
            "AppData/Local/Ollama/OllamaSetup.exe",
        ],
        # Файл, который программа запускает при «перезапуске для обновления».
        "handoff": ["AppData/Local/Ollama/OllamaSetup.exe"],
        # Метка «обновление начато»: после УСПЕШНОГО старта программа сама её
        # удаляет, поэтому оставшаяся метка - след прерванного обновления.
        "markers": ["AppData/Local/Ollama/upgraded"],
        "installer_names": ["ollamasetup*"],
    }),
    ("opencode", {
        "engine": "nsis",
        "source_url": ("https://github.com/anomalyco/opencode/releases/"
                       "latest/download/opencode-desktop-win-x64.exe"),
        # electron-updater кладёт скачанный установщик в
        # %LOCALAPPDATA%\<имя-приложения>-updater\pending и по кнопке
        # «Обновить» запускает его отдельным процессом. autoDownload у OpenCode
        # выключен: файл появляется только после согласия пользователя.
        "staged": [
            "AppData/Local/*opencode*/pending/*.exe",
            "AppData/Local/*OpenCode*/pending/*.exe",
            "User/AppData/Local/*opencode*/pending/*.exe",
            "User/AppData/Local/*OpenCode*/pending/*.exe",
        ],
        "handoff": [],
        "markers": [],
        # Имя запускаемого установщика (opencode-desktop-win-x64.exe) и рабочая
        # копия NSIS в Temp. Сама программа (OpenCode.exe) под шаблоны не
        # попадает.
        "installer_names": ["opencode-desktop-win-*.exe", "~nsu*.tmp"],
        # Кнопка «Обновить» = согласие на обновление: скачивание начинается
        # только после неё, поэтому готовый установщик в pending - это и есть
        # момент перехвата (у Ollama скачивание идёт в фоне без согласия, там
        # перехват начинается лишь по метке «перезапуск для обновления»).
        "download_is_consent": True,
    }),
)


def _update_profile(cfg: Dict[str, Any]) -> Dict[str, Any]:
    names = [cfg.get("app_name", ""), cfg.get("target_exe_rel", ""),
             cfg.get("launcher_target_rel", "")]
    targets = cfg.get("targets")
    if isinstance(targets, list):
        names.extend(str(item.get("rel_path", ""))
                     for item in targets if isinstance(item, dict))
    haystack = " ".join(str(n) for n in names).casefold()
    for marker, profile in UPDATE_PROFILES:
        if marker in haystack:
            return profile
    return {}


def update_settings(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Настройки обновления: блок ``update`` поверх профиля программы.

    Ручное обновление (``--update``) работает для любого портатива и без
    блока; перехват родного апдейтера включается только там, где известно,
    что и где он кладёт (профиль или явные ``staged``/``handoff``).
    """
    block = cfg.get("update")
    block = block if isinstance(block, dict) else {}
    merged: Dict[str, Any] = dict(_update_profile(cfg))
    merged.update(block)

    def texts(name: str) -> "list[str]":
        value = merged.get(name)
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]

    try:
        timeout = float(merged.get("timeout", 3600.0))
    except (TypeError, ValueError):
        timeout = 3600.0
    args = merged.get("installer_args")
    handoff = texts("handoff")
    markers = texts("markers")
    names = [item.casefold() for item in texts("installer_names")]
    # Готовый установщик, скачанный программой, - сигнал перехвата только там,
    # где само скачивание происходит лишь после согласия пользователя.
    download_is_consent = merged.get("download_is_consent", False) is True
    return {
        "enabled": merged.get("enabled", True) is not False,
        "engine": str(merged.get("engine", "")).strip().casefold(),
        "source_url": str(merged.get("source_url", "")).strip(),
        "staged": texts("staged"),
        "handoff": handoff,
        "markers": markers,
        "installer_names": names,
        "preserve": texts("preserve"),
        "keep_backup": merged.get("keep_backup", True) is not False,
        "installer_args": ([str(a) for a in args]
                           if isinstance(args, list) and args else None),
        "timeout": max(60.0, min(86400.0, timeout)),
        "download_is_consent": download_is_consent,
        # Следить за родным апдейтером можно, если известно, по каким следам
        # его узнать (или само скачивание - уже согласие пользователя).
        "watch": bool(handoff or markers or download_is_consent),
    }


def _data_dir(root: Path, cfg: Dict[str, Any]) -> Path:
    return root / str(cfg.get("data_dir_name", "PortableData"))


def _update_log(root: Optional[Path], message: str) -> None:
    """Пишет и в общий журнал, и в отдельный журнал обновлений."""
    _run_log(root, "update: " + message)
    if root is None:
        return
    try:
        import time

        data = root / "PortableData"
        data.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with (data / UPDATE_LOG_NAME).open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {message}\n")
    except OSError:
        pass


def _glob_in_data(root: Path, cfg: Dict[str, Any],
                  patterns: Iterable[str]) -> "list[Path]":
    """Файлы PortableData по шаблонам вида ``AppData/Local/X/*/*.exe``."""
    data = _data_dir(root, cfg)
    found: "list[Path]" = []
    for pattern in patterns:
        text = str(pattern).replace("\\", "/").strip("/")
        if not text or ".." in text.split("/") or ":" in text:
            continue
        try:
            for item in data.glob(text):
                if item.is_file() and item not in found:
                    found.append(item)
        except (OSError, ValueError):
            continue
    return found


def staged_installers(root: Path, cfg: Dict[str, Any]) -> "list[Path]":
    """Установщики, которые программа сама скачала для обновления.

    Самый свежий - первым.
    """
    settings = update_settings(cfg)
    items = _glob_in_data(root, cfg, settings["staged"])
    items.sort(key=lambda p: _mtime(p), reverse=True)
    return items


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def update_markers(root: Path, cfg: Dict[str, Any]) -> "list[Path]":
    return _glob_in_data(root, cfg, update_settings(cfg)["markers"])


def stop_stray_installers(root: Path, cfg: Dict[str, Any]) -> "list[str]":
    """Завершает «родной» установщик, запущенный из портатива.

    Он поставил бы программу мимо App и умер бы на полпути вместе с лончером.
    Совпадение по имени (``ollamasetup*``): у Inno Setup рабочая копия в
    Temp называется ``OllamaSetup.tmp``, и она тоже должна уйти.
    """
    import fnmatch

    names = update_settings(cfg)["installer_names"]
    if not names:
        return []
    victims = []
    for pid, image in _portable_process_list(root):
        name = _image_name(image).casefold()
        if any(fnmatch.fnmatch(name, pattern) for pattern in names):
            victims.append((pid, _image_name(image)))
    if victims:
        _terminate_pids(pid for pid, _ in victims)
    return [name for _, name in victims]


def _remove_file(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _remove_empty_parents(path: Path, stop: Path) -> None:
    parent = path.parent
    while parent != stop and stop in parent.parents:
        try:
            parent.rmdir()
        except OSError:
            return
        parent = parent.parent


def quarantine_staged_update(root: Path, cfg: Dict[str, Any]
                             ) -> "tuple[Optional[Path], bool]":
    """Забирает у программы её обновление: установщик - в ``Updates``.

    Возвращает ``(путь_к_установщику_или_None, всё_ли_убрано)``. После этого
    программе нечего «применять» при старте, а скачанный установщик не
    пропадает - его можно поставить правильно, внутрь портатива.
    """
    settings = update_settings(cfg)
    installers = staged_installers(root, cfg)
    data = _data_dir(root, cfg)
    kept: Optional[Path] = None
    clean = True
    if installers:
        folder = root / UPDATE_DIR_NAME
        try:
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / installers[0].name
            os.replace(installers[0], target)
            kept = target
        except OSError:
            clean = False
        for extra in installers[1:]:
            if not _remove_file(extra):
                clean = False
        for item in installers:
            _remove_empty_parents(item, data)
    for marker in _glob_in_data(root, cfg, settings["markers"]):
        if not _remove_file(marker):
            clean = False
    # Недоустановленная рабочая копия «на месте запуска» тоже убирается: иначе
    # программа решит, что обновление всё ещё идёт.
    for leftover in _glob_in_data(root, cfg, settings["handoff"]):
        if not _remove_file(leftover):
            clean = False
    return kept, clean


def _pending_file(root: Path) -> Path:
    return root / UPDATE_DIR_NAME / "pending.json"


def _remember_pending(root: Path, installer: Path, declined: bool = False,
                      interrupted: bool = False) -> None:
    """Запоминает установщик, ждущий установки.

    ``interrupted`` - его уже пытались применить (пользователь нажал
    «перезапустить для обновления»); ``declined`` - от предложения поставить
    его пользователь отказался, и спрашивать каждый запуск не нужно.
    """
    try:
        _pending_file(root).parent.mkdir(parents=True, exist_ok=True)
        _pending_file(root).write_text(
            json.dumps({"installer": installer.name, "declined": declined,
                        "interrupted": interrupted}, ensure_ascii=False),
            encoding="utf-8")
    except OSError:
        pass


def _forget_pending(root: Path) -> None:
    _remove_file(_pending_file(root))


def _pending_state(root: Path) -> "tuple[Optional[Path], bool, bool]":
    """``(установщик, отказ, прервано)`` из Updates\\pending.json."""
    try:
        data = json.loads(_pending_file(root).read_text(encoding="utf-8"))
        candidate = root / UPDATE_DIR_NAME / Path(str(data["installer"])).name
        if candidate.is_file():
            return (candidate, bool(data.get("declined")),
                    bool(data.get("interrupted")))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None, False, False


def pending_installer(root: Path) -> Optional[Path]:
    """Установщик, оставшийся от перехваченного (или прерванного) обновления."""
    return _pending_state(root)[0]


class UpdateWatch:
    """Следит за родным апдейтером, пока работает программа.

    ``poll()`` дешёвый: пока нет следов обновления - это пара ``stat``.
    Как только программа начала «перезапуск для обновления» (появился
    файл установщика или метка), запущенный ею установщик завершается ДО
    того, как успеет что-то записать, а скачанный файл переезжает в
    ``Updates``. Саму программу не трогаем: она завершается сама.
    """

    def __init__(self, root: Path, cfg: Dict[str, Any]) -> None:
        self.root = root
        self.cfg = cfg
        self.settings = update_settings(cfg)
        self.active = bool(self.settings["enabled"]
                           and self.settings["watch"])
        self.handoff = False
        self.installer: Optional[Path] = None
        self._logged = False

    def _triggered(self) -> bool:
        # Готовый установщик в кэше апдейтера - это сигнал только там, где
        # программа скачивает обновление лишь после согласия пользователя
        # (OpenCode/electron-updater). У Ollama скачанное в фоне не трогаем.
        if (self.settings["download_is_consent"]
                and staged_installers(self.root, self.cfg)):
            return True
        return bool(
            _glob_in_data(self.root, self.cfg, self.settings["handoff"])
            or _glob_in_data(self.root, self.cfg, self.settings["markers"]))

    def poll(self) -> bool:
        """``True``, если обновление перехвачено (или перехватывается)."""
        if not self.active:
            return False
        if not self._triggered():
            return self.handoff
        if not self.handoff:
            self.handoff = True
            _update_log(self.root, "the program started its own updater - "
                        "intercepting it, the update will be installed "
                        "into the portable folder instead")
        self._intercept()
        return True

    def _intercept(self) -> None:
        """Гасит родной установщик и забирает скачанное обновление себе.

        У electron-updater (OpenCode) между «установщик скачан» и «он
        запущен» проходят миллисекунды, поэтому после остановки установщика
        перехват повторяется короткими сериями: файл бывает занят процессом,
        и переименовать его надо до того, как установщик что-то запишет.
        """
        import time

        guard = HostTraceGuard()
        guard.snapshot()
        try:
            deadline = time.monotonic() + (
                5.0 if self.settings["download_is_consent"] else 0.0)
            while True:
                stopped = stop_stray_installers(self.root, self.cfg)
                if stopped and not self._logged:
                    self._logged = True
                    _update_log(self.root, "stopped the built-in installer: "
                                + ", ".join(sorted(set(stopped))))
                if stopped:
                    return  # дочерние процессы установщика могли ещё остаться
                kept, _clean = quarantine_staged_update(self.root, self.cfg)
                if kept is not None:
                    self.installer = kept
                    _remember_pending(self.root, kept, interrupted=True)
                    _update_log(self.root,
                                f"the downloaded update is kept: {kept.name}")
                    return
                if not self._triggered() or time.monotonic() >= deadline:
                    return
                time.sleep(0.1)
        finally:
            guard.restore()
            _update_log(
                self.root,
                "automatic host-trace cleanup is disabled; any Windows "
                "changes made by the third-party updater require manual review")

    def finish(self, timeout: float = 15.0) -> None:
        """Дожимает перехват после выхода программы."""
        if not self.active:
            return
        import time

        deadline = time.monotonic() + timeout
        while self._triggered() and time.monotonic() < deadline:
            self.poll()
            time.sleep(0.5)
        self.poll()

    def take(self) -> Optional[Path]:
        """Установщик, который надо поставить после этого сеанса."""
        if self.installer is not None and self.installer.is_file():
            return self.installer
        if self.handoff:
            return pending_installer(self.root)
        return None


def _wait_target(process: "subprocess.Popen", watch: "Optional[UpdateWatch]"
                 ) -> int:
    """``process.wait()``, но с проверкой родного апдейтера каждые полсекунды."""
    if watch is None or not watch.active:
        return process.wait()
    while True:
        try:
            return process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            try:
                watch.poll()
            except Exception as exc:  # noqa: BLE001 - слежка не срывает запуск
                _run_log(watch.root, f"update watch failed: {exc}")


# --- установщик: определение движка и команды тихой установки ------------------

def installer_engine(path: Path) -> str:
    """``inno`` / ``nsis`` / ``msi`` / ``unknown`` по самому файлу."""
    if path.suffix.lower() == ".msi":
        return "msi"
    try:
        with path.open("rb") as fh:
            blob = fh.read(8 * 1024 * 1024)
            try:
                fh.seek(-2 * 1024 * 1024, os.SEEK_END)
                blob += fh.read()
            except OSError:
                pass
    except OSError:
        return "unknown"
    if blob.startswith(b"\xd0\xcf\x11\xe0"):
        return "msi"
    if (b"Inno Setup" in blob or b"JR.Inno.Setup" in blob
            or b"Inno Setup Setup Data" in blob):
        return "inno"
    if b"Nullsoft Install System" in blob or b"NullsoftInst" in blob:
        return "nsis"
    return "unknown"


def _replace_root_forms(text: str, roots: "Sequence[str]", target: str,
                        portable_root: str = "") -> str:
    """Переписывает запомненные корни портатива на текущие пути.

    Установщик мог сохранить каталог установки в своих настройках и при
    обновлении брать его оттуда, игнорируя переданный ``/DIR``. Тогда новая
    версия встала бы в папку, которой на этом диске уже нет (жалоба:
    «перенёс портатив на другой диск, а обновление поставилось по прежнему
    пути»).

    Путь внутри прежнего ``App`` ведёт в новый ``target`` (временная папка
    установки), остальной прежний корень — в текущий корень портатива.
    Границы пути проверяются: ``D:\\Apps\\Foo`` не должен испортить
    ``D:\\Apps\\FooBar``.
    """
    result = str(text)
    base_root = str(portable_root or target)
    for root in roots:
        base = str(root or "").strip().strip('"').rstrip("\\/")
        if not base:
            continue
        forms = sorted({base, base.replace("\\", "/"), base.replace("/", "\\"),
                        base.replace("\\", "\\\\")}, key=len, reverse=True)
        # Сначала «корень\App» -> target: иначе короткая замена испортит его.
        for form in forms:
            for separator in ("\\\\", "\\", "/"):
                pattern = re.compile(
                    r"(?<![0-9A-Za-z_])" + re.escape(form + separator + "App")
                    + r"(?![0-9A-Za-z_.])", re.IGNORECASE)
                result = pattern.sub(lambda _m: target, result)
        for form in forms:
            pattern = re.compile(
                r"(?<![0-9A-Za-z_])" + re.escape(form)
                + r"(?![0-9A-Za-z_.])", re.IGNORECASE)
            result = pattern.sub(lambda _m: base_root, result)
    return result


def _force_target(engine: str, args: "list[str]", target: str) -> "list[str]":
    """Добавляет ключ каталога, если пользовательские ключи его не задают.

    Свои ключи (``update.installer_args``) перекрывают лестницу, но не должны
    лишать обновление привязки к текущему портативу. Иначе установщик выберет
    каталог из собственных настроек — обычно это прежнее место папки.
    """
    joined = " ".join(str(item) for item in args).casefold()
    result = list(args)
    if engine == "inno":
        if "/dir=" not in joined:
            result.append(f"/DIR={target}")
        # /NOICONS: установщик не должен создавать ярлыки в меню «Пуск».
        if "/noicons" not in joined:
            result.append("/NOICONS")
    elif engine == "msi":
        if "installdir=" not in joined and "targetdir=" not in joined:
            result.append(f"INSTALLDIR={target}")
    return result


def install_commands(installer: Path, target_dir: Path, engine: str,
                     settings: Optional[Dict[str, Any]] = None,
                     log_file: Optional[Path] = None,
                     stale_roots: "Sequence[str]" = (),
                     portable_root: "Optional[Path]" = None
                     ) -> "list[tuple[str, str]]":
    """Лестница команд тихой установки в ``target_dir``: ``(подпись, команда)``.

    Команда - готовая строка: у NSIS параметр ``/D=`` обязан идти последним и
    без кавычек, обычный список аргументов этого не умеет.

    ``stale_roots`` — прежние места этой же портативной папки. Они нужны,
    чтобы обновление не ушло в каталог, которого на текущем диске уже нет:
    установщик узнаёт путь из своих настроек, если не получил явный.
    """
    settings = settings or {}
    quote = subprocess.list2cmdline
    program = str(installer)
    target = str(target_dir)
    custom = settings.get("installer_args")
    if custom:
        args = [str(a).replace("{DIR}", target).replace(
            "{INSTALLER}", program) for a in custom]
        args = [_replace_root_forms(item, stale_roots, target,
                                    str(portable_root or target))
                for item in args]
        args = _force_target(engine, args, target)
        if engine == "nsis":
            # /D= обязан идти последним и без кавычек: если он был в своих
            # ключах, переносим его в хвост команды (иначе NSIS его не
            # разберёт и поставит программу в каталог по умолчанию).
            args = [item for item in args
                    if not str(item).casefold().startswith("/d=")]
            return [("свои ключи", quote([program, *args])
                     + f" /D={target}")]
        return [("свои ключи", quote([program, *args]))]

    def inno() -> "tuple[str, str]":
        args = [program, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                "/NOICONS", "/SP-", f"/DIR={target}"]
        if log_file:
            args.append(f"/LOG={log_file}")
        return "Inno Setup", quote(args)

    def nsis() -> "tuple[str, str]":
        # --no-desktop-shortcut понимают установщики electron-builder (OpenCode
        # и т.п.): обновление внутри портатива не должно оставлять ярлык на
        # рабочем столе чужого ПК. Классический NSIS ключ просто игнорирует —
        # появившийся ярлык уберёт ShortcutGuard в apply_update().
        # /D= обязан идти последним и без кавычек.
        return ("NSIS", quote([program, "/S", "--no-desktop-shortcut"])
                + f" /D={target}")

    if engine == "inno":
        return [inno()]
    if engine == "nsis":
        return [nsis()]
    if engine == "msi":
        return [
            ("MSI: административная распаковка",
             quote(["msiexec.exe", "/a", program, "/qn", "/norestart",
                    f"TARGETDIR={target}"])),
            ("MSI: установка в папку",
             quote(["msiexec.exe", "/i", program, "/qn", "/norestart",
                    f"INSTALLDIR={target}"])),
        ]
    return [inno(), nsis()]


def _clear_dir(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    if path.is_dir():  # антивирус мог держать файл: вторая попытка
        import time

        time.sleep(1.0)
        shutil.rmtree(path, ignore_errors=True)


def _app_relative_target(cfg: Dict[str, Any]) -> str:
    """Путь главного exe относительно App (то, что должно появиться в stage)."""
    rel = str(cfg.get("target_exe_rel", "")).replace("\\", "/").strip("/")
    if rel.casefold().startswith("app/"):
        rel = rel[4:]
    return rel


def locate_payload(stage: Path, cfg: Dict[str, Any]) -> Optional[Path]:
    """Корень установленной программы внутри ``stage`` или ``None``.

    Установщик мог положить файлы прямо в ``stage`` или создать там ещё одну
    папку (``stage\\Ollama``); «установлено» - это когда в нём нашёлся
    главный exe программы.
    """
    rel = _app_relative_target(cfg)
    if not rel or not stage.is_dir():
        return None
    direct = stage / rel.replace("/", os.sep)
    if direct.is_file():
        return stage
    parts = rel.split("/")
    wanted = parts[-1].casefold()
    for folder, dirs, files in os.walk(stage):
        depth = len(Path(folder).relative_to(stage).parts)
        if depth > 4:
            dirs[:] = []
            continue
        if any(name.casefold() == wanted for name in files):
            candidate = Path(folder)
            for _ in parts[:-1]:
                candidate = candidate.parent
            if candidate == stage or stage in candidate.parents:
                return candidate
    return None


# --- следы установки на этом ПК -------------------------------------------------

_UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_ENV_KEY = "Environment"

#: CSIDL папок «Рабочий стол» и «Пуск». Запрос через shell возвращает
#: НАСТОЯЩИЕ папки Windows - с учётом перенаправления (OneDrive-«Рабочий
#: стол», корпоративные политики), куда действительно пишут
#: установщики. Пути из переменных окружения оставлены запасным вариантом.
_CSIDL_START_MENU = 0x0B
_CSIDL_DESKTOP = 0x10
_CSIDL_COMMON_START_MENU = 0x16
_CSIDL_COMMON_DESKTOP = 0x19

#: Что считается ярлыком. ``.url`` тоже создают установщики, а ``.pif`` —
#: наследие старых движков.
LINK_SUFFIXES = (".lnk", ".url", ".pif")

#: Больше мегабайта ярлык не весит.
MAX_LINK_BYTES = 1024 * 1024


def _shell_folder(csidl: int) -> Optional[Path]:
    """Папка Windows по CSIDL (с перенаправлением) или ``None`` вне Windows."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(520)  # MAX_PATH + запас
        if ctypes.windll.shell32.SHGetFolderPathW(  # type: ignore[attr-defined]
                None, csidl, None, 0, buffer):
            return None
        return Path(buffer.value) if buffer.value else None
    except Exception:  # noqa: BLE001 - папка не найдена, есть запасной путь
        return None


def shortcut_folders() -> "list[Path]":
    """Папки, куда установщики кладут ярлыки («Рабочий стол» и меню «Пуск»)."""
    folders: "list[Path]" = []
    for csidl in (_CSIDL_DESKTOP, _CSIDL_START_MENU,
                  _CSIDL_COMMON_DESKTOP, _CSIDL_COMMON_START_MENU):
        found = _shell_folder(csidl)
        if found is not None:
            folders.append(found)
    appdata = os.environ.get("APPDATA", "")
    public = os.environ.get("PUBLIC", "")
    profile = os.environ.get("USERPROFILE", "")
    programdata = os.environ.get("PROGRAMDATA", "")
    if appdata:
        folders.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu")
    if profile:
        folders.append(Path(profile) / "Desktop")
    if programdata:
        folders.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu")
    if public:
        folders.append(Path(public) / "Desktop")
    unique: "list[Path]" = []
    seen: "set[str]" = set()
    for folder in folders:
        key = str(folder).casefold()
        if key not in seen:
            seen.add(key)
            unique.append(folder)
    return [f for f in unique if f.is_dir()]


def _user_programs_dir() -> Path:
    """Стандартная пользовательская папка Programs (куда ставит NSIS/Inno)."""
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        return Path(local) / "Programs"
    return Path(os.environ.get("USERPROFILE", ".")) / "AppData" / "Local" / "Programs"


def _app_exe_names(cfg: Dict[str, Any]) -> "set[str]":
    """Имена файлов exe этой программы (главный и её цели запуска)."""
    rels = [str(cfg.get("target_exe_rel", "")), str(cfg.get("launcher_target_rel", ""))]
    targets = cfg.get("targets")
    if isinstance(targets, list):
        rels.extend(str(item.get("rel_path", ""))
                    for item in targets if isinstance(item, dict))
    names = set()
    for rel in rels:
        name = Path(rel.replace("\\", "/").strip("/")).name.casefold()
        if name:
            names.add(name)
    return names


def _lnk_target(path: Path) -> Optional[str]:
    """Цель ярлыка ``.lnk`` или ``None``, если определить не удалось."""
    if not IS_WINDOWS:
        return None
    try:
        completed = subprocess.run(  # noqa: S603
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "$sh = New-Object -ComObject WScript.Shell; "
             "$sh.CreateShortcut($env:PORTABLE_LNK).TargetPath"],
            capture_output=True, text=True, timeout=60,
            creationflags=NO_WINDOW,
            env={**os.environ, "PORTABLE_LNK": str(path)})
        target = completed.stdout.strip()
        return target or None
    except Exception:  # noqa: BLE001 - ярлык останется, это не срывает обновление
        return None


def _shortcut_snapshot(folders: "Optional[Iterable[Path]]" = None) -> "set[str]":
    """Что уже лежало в папках ярлыков до запуска установщика."""
    snapshot: "set[str]" = set()
    for folder in (list(folders) if folders is not None else shortcut_folders()):
        folder = Path(folder)
        if not folder.is_dir():
            continue
        for current, _dirs, files in os.walk(folder):
            for name in files:
                if name.casefold().endswith(LINK_SUFFIXES):
                    snapshot.add(os.path.normcase(os.path.normpath(
                        os.path.join(current, name))))
    return snapshot


def _shortcut_files(folders: "Iterable[Path]") -> "list[Path]":
    """Все файлы-ярлыки в папках (в «Пуске» есть подпапки)."""
    found: "list[Path]" = []
    for folder in folders:
        folder = Path(folder)
        if not folder.is_dir():
            continue
        for current, _dirs, files in os.walk(folder):
            for name in files:
                if name.casefold().endswith(LINK_SUFFIXES):
                    found.append(Path(current) / name)
    return found


def _root_forms(root: str) -> "list[str]":
    """Начертания корня, которые встречаются внутри ярлыка."""
    base = str(root or "").strip().strip('"').rstrip("\\/")
    if not base:
        return []
    forms = {base, base.replace("\\", "/"), base.replace("/", "\\"),
             base.replace("\\", "\\\\")}
    return sorted((form for form in forms if form), key=len, reverse=True)


def _path_within(path: str, root: str) -> bool:
    """Лежит ли путь внутри корня (без учёта регистра и вида слэшей)."""
    if not path or not root:
        return False
    inner = os.path.normcase(os.path.normpath(str(path)))
    outer = os.path.normcase(os.path.normpath(str(root))).rstrip("\\/")
    if not outer:
        return False
    return inner == outer or inner.startswith(outer + os.sep)


def _link_points_into(path: Path, roots: "Iterable[str]",
                      resolver: "Optional[Any]" = None) -> bool:
    """Указывает ли ярлык внутрь портатива (текущего или прежнего места).

    Цель ищется прямо в байтах файла: ``.lnk`` хранит её в UTF-16LE, ``.url`` —
    обычным текстом. Запускать PowerShell на каждый ярлык нельзя: это секунды
    на файл и лишние окна. ``resolver`` — запасной вариант для нестандартных
    ярлыков и тестов.
    """
    forms = [form for root in roots for form in _root_forms(str(root))]
    if not forms:
        return False
    try:
        if path.stat().st_size > MAX_LINK_BYTES:
            return False
        data = path.read_bytes()
    except OSError:
        return False
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = data.decode(encoding, errors="ignore")
        except (UnicodeError, LookupError):  # pragma: no cover - защита
            continue
        for form in forms:
            # Границы пути: ``D:\\Apps\\Foo`` не должен совпасть с
            # ``D:\\Apps\\FooBar\\...`` — соседняя папка не наша.
            pattern = re.compile(r"(?<![0-9A-Za-z_.])" + re.escape(form)
                                 + r"(?![0-9A-Za-z_.])", re.IGNORECASE)
            if pattern.search(text):
                return True
    if resolver is not None:
        try:
            target = resolver(path)
        except Exception:  # noqa: BLE001 - разрешатель не срывает уборку
            target = None
        if target:
            return any(_path_within(str(target), str(root)) for root in roots)
    return False


#: Блок LinkInfo начинается сразу после заголовка Shell Link (0x4C).
_LNK_LINK_INFO_OFFSET = 0x4C
#: Смещение Ansi-строки с локальным путём внутри LinkInfo.
_LNK_LINK_INFO_PATH = 0x10
#: Минимальный размер заголовка LinkInfo.
_LNK_LINK_INFO_HEADER = 0x1C


def lnk_target(path: Path) -> str:
    """Локальный путь из ``.lnk`` или пустая строка, если его нет.

    Читается только нужное: заголовок Shell Link, блок LinkInfo (идёт сразу
    за заголовком, с 0x4C) и Ansi-строка с локальным путём. COM
    (``WScript.Shell``) и дочерние процессы не используются: уборка ярлыков
    должна работать на любом ПК и не тратить секунды на каждый файл.
    """
    try:
        if path.stat().st_size > MAX_LINK_BYTES:
            return ""
        data = path.read_bytes()
    except OSError:
        return ""
    if len(data) < _LNK_LINK_INFO_OFFSET + 4 or not data.startswith(b"L\x00\x00\x00"):
        return ""
    flags = int.from_bytes(data[0x14:0x18], "little")
    if not flags & 0x2:  # HasLinkInfo
        return ""
    block = data[_LNK_LINK_INFO_OFFSET:]
    size = int.from_bytes(block[0:4], "little")
    header_size = int.from_bytes(block[4:8], "little")
    if size < _LNK_LINK_INFO_HEADER or header_size < _LNK_LINK_INFO_HEADER:
        return ""
    if header_size + 4 > len(block):
        return ""
    path_offset = int.from_bytes(
        block[_LNK_LINK_INFO_PATH:_LNK_LINK_INFO_PATH + 4], "little")
    if not header_size <= path_offset < min(size, len(block)):
        return ""
    raw = block[path_offset:min(size, len(block))]
    end = raw.find(b"\x00")
    if end <= 0:
        return ""
    codec = "mbcs" if sys.platform == "win32" else "latin-1"
    try:
        text = raw[:end].decode(codec, errors="replace")
    except LookupError:  # pragma: no cover - не-Windows без mbcs
        text = raw[:end].decode("latin-1", errors="replace")
    return text.strip()


def link_target(path: Path, resolver: "Optional[Any]" = None) -> str:
    """Цель ярлыка: из самого файла, затем (если нужно) из ``resolver``."""
    lowered = str(path).casefold()
    if lowered.endswith(".lnk"):
        target = lnk_target(path)
        if target:
            return target
    elif lowered.endswith(".url"):
        try:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
        except OSError:
            text = ""
        match = re.search(r"^\s*URL\s*=\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        if match:
            url = match.group(1).strip()
            if url.casefold().startswith("file:///"):
                return url[8:].replace("/", "\\")
            return url
    if resolver is not None:
        try:
            return str(resolver(path) or "")
        except Exception:  # noqa: BLE001 - разрешатель не срывает уборку
            return ""
    return ""


def target_is_missing(target: str) -> bool:
    """Цель заведомо никуда не ведёт.

    ``http(s)``/``shell:`` и UNC-путь недоступного сервера не считаются
    поломкой: проверить их локально нельзя.
    """
    text = str(target or "").strip().strip('"')
    if not text:
        return False
    if text.casefold().startswith(("http://", "https://", "mailto:",
                                   "shell:", "ms-", "{")):
        return False
    if text.startswith("\\\\") and not text.startswith("\\\\?\\"):
        return False
    expanded = os.path.expandvars(os.path.expanduser(text))
    if "%" in expanded:
        # Переменная не раскрылась — проверить путь нельзя.
        return False
    try:
        return not os.path.exists(expanded)
    except (OSError, ValueError):
        return False


def app_name_candidates(*values: str) -> "list[str]":
    """Имена, под которыми установщик мог подписать ярлык этой программы."""
    names: "list[str]" = []
    for value in values:
        text = Path(str(value or "")).name
        for suffix in (".exe", ".msi", ".lnk", ".url", ".pif"):
            if text.casefold().endswith(suffix):
                text = text[: -len(suffix)]
        text = text.casefold()
        if text.endswith("_portable"):
            text = text[: -len("_portable")]
        if text.endswith(" portable"):
            text = text[: -len(" portable")]
        collapsed = " ".join(text.replace("_", " ").split())
        if collapsed and collapsed not in names:
            names.append(collapsed)
    return names


def _name_matches(path: Path, names: "Sequence[str]") -> bool:
    """Похоже ли имя ярлыка на имя программы (см. одноимённую функцию сборщика)."""
    if not names:
        return False
    stem = Path(str(path)).stem
    normalized = " ".join(stem.replace("_", " ").casefold().split())
    for name in names:
        candidate = " ".join(str(name).replace("_", " ").casefold().split())
        if not candidate:
            continue
        if normalized == candidate:
            return True
        if (normalized.startswith(candidate + " ")
                or normalized.startswith(candidate + "(")):
            return True
    return False


def remove_stale_shortcuts(app_names: "Sequence[str]",
                           roots: "Sequence[str]" = (),
                           folders: "Optional[Iterable[Path]]" = None,
                           resolver: "Optional[Any]" = None) -> "list[str]":
    """Убирает ярлыки этой программы, которые уже никуда не ведут.

    Жалоба: после сборки на рабочем столе оставался **пустой** ярлык: цель
    (временный каталог установщика) исчезла, а сам ``.lnk`` остался. Такой
    ярлык бесполезен при любом раскладе, поэтому удаляется, если:

    * он указывает внутрь портатива (текущего корня или прежнего места) —
      значит, ведёт на переносимую копию и после переезда папки не работает;
    * его имя совпадает с именем программы **и** цель не существует.
    """
    targets = list(folders) if folders is not None else shortcut_folders()
    removed: "list[str]" = []
    for path in _shortcut_files(targets):
        if _link_points_into(path, [str(item) for item in roots], resolver):
            try:
                path.unlink()
            except OSError:
                continue
            removed.append(str(path))
            continue
        if not _name_matches(path, app_names):
            continue
        if not target_is_missing(link_target(path, resolver)):
            continue
        try:
            path.unlink()
        except OSError:
            continue
        removed.append(str(path))
    return removed


def _app_shortcut_names(root: Path, cfg: Dict[str, Any]) -> "list[str]":
    """Имена, под которыми установщик мог назвать ярлык этой программы."""
    return app_name_candidates(
        str(cfg.get("app_name", "")),
        str(cfg.get("target_exe_rel", "")),
        str(cfg.get("launcher_target_rel", "")),
        root.name,
        str(cfg.get("portable_dir_name", "")),
    )


def _shortcut_folders_for(root: Path,
                          cfg: "Optional[Dict[str, Any]]" = None) -> "list[Path]":
    """Папки ярлыков: настоящие и «рабочий стол» внутри портатива.

    Внутренний рабочий стол (``PortableData\\User\\Desktop``) — это
    перенаправленный профиль программы: ярлык, который она создала при первом
    запуске, лежит там и точно так же подлежит уборке.
    """
    found = [Path(item) for item in shortcut_folders()]
    data = _data_dir(root, cfg or {})
    for extra in (data / "User" / "Desktop", data / "Public" / "Desktop"):
        if extra.is_dir() and extra not in found:
            found.append(extra)
    return found


def remove_host_app_shortcuts(root: Path, cfg: Dict[str, Any],
                              folders: "Optional[Iterable[Path]]" = None,
                              resolver: "Optional[Any]" = None,
                              programs_dir: Optional[Path] = None,
                              before: "Optional[set[str]]" = None,
                              extra_roots: "Sequence[str]" = ()) -> "list[str]":
    """Удаляет только ярлыки этой установки, ведущие внутрь портатива.

    Жалоба: после портирования на рабочем столе оставался ярлык, а после
    переноса папки на другой диск он вёл в прежнее место. Такой ярлык —
    статичный абсолютный путь, записанный установщиком; в портативе он не
    нужен никогда.

    Безопасность важнее полноты: удаляется файл, **которого не было до
    запуска** (``before`` — снимок :func:`_shortcut_snapshot`) **и** который
    указывает внутрь одного из ``roots``. Ярлык пользователя не трогается
    даже тогда, когда ведёт на ту же программу: доказать его происхождение
    нельзя. Без снимка функция не делает ничего.
    """
    del cfg, programs_dir
    if before is None:
        return []
    roots = [str(root)] + [str(item) for item in extra_roots if str(item)]
    targets = list(folders) if folders is not None else shortcut_folders()
    removed: "list[str]" = []
    for path in _shortcut_files(targets):
        key = os.path.normcase(os.path.normpath(str(path)))
        if key in before:
            continue
        if not _link_points_into(path, roots, resolver):
            continue
        try:
            path.unlink()
        except OSError:
            continue
        removed.append(str(path))
    return removed


class ShortcutGuard:
    """Снимок папок ярлыков до установки и уборка только своих ярлыков.

    ``extra_roots`` — прежние места портатива (штамп переноса): ярлык,
    созданный до переезда, содержит именно старый путь.
    """

    def __init__(self, root: Path, extra_roots: "Sequence[str]" = (),
                 folders: "Optional[Iterable[Path]]" = None,
                 resolver: "Optional[Any]" = None,
                 app_names: "Sequence[str]" = ()) -> None:
        self.root = Path(root)
        self.extra_roots = [str(item) for item in extra_roots if str(item)]
        self._folders = (list(folders) if folders is not None
                         else shortcut_folders())
        self.resolver = resolver
        self.app_names = [str(item) for item in app_names if str(item).strip()]
        self.before: "Optional[set[str]]" = None
        self.removed: "list[str]" = []

    def snapshot(self) -> int:
        """Запоминает текущее содержимое папок; возвращает число ярлыков."""
        self.before = _shortcut_snapshot(self._folders)
        self.removed = []
        return len(self.before)

    def cleanup(self) -> "list[str]":
        """Убирает созданные этим запуском ярлыки; можно звать многократно."""
        if self.before is None:
            return []
        found = remove_host_app_shortcuts(
            self.root, {}, folders=self._folders, resolver=self.resolver,
            before=self.before, extra_roots=self.extra_roots)
        return self._remember(found)

    def sweep(self) -> "list[str]":
        """Убирает «пустые» ярлыки этой программы (цель уже не существует).

        Нужен там, где снимок «до» невозможен: программа стартовала впервые и
        сама положила ярлык, чужой апдейтер недописал файл, установщик
        записал путь во временный каталог. Условия те же, что в
        :func:`remove_stale_shortcuts`, поэтому чужие ярлыки не страдают.
        """
        found = remove_stale_shortcuts(
            self.app_names, roots=[str(self.root), *self.extra_roots],
            folders=self._folders, resolver=self.resolver)
        return self._remember(found)

    def _remember(self, items: "Sequence[str]") -> "list[str]":
        known = {os.path.normcase(os.path.normpath(item))
                 for item in self.removed}
        fresh = [item for item in items
                 if os.path.normcase(os.path.normpath(item)) not in known]
        self.removed.extend(fresh)
        return fresh


class HostTraceGuard:
    """Совместимый no-op для старых путей обновления.

    Предыдущая версия снимала HKCU, а затем без разбора удаляла новые записи
    Uninstall/Run, переменные окружения, ярлыки и новые папки Programs. Такой
    откат мог затронуть изменения пользователя или системных компонентов,
    поэтому автоматическое восстановление отключено. Снимок/откат реестра не
    является песочницей: установщик обновления всё ещё может менять Windows.
    """

    def __init__(self) -> None:
        self.active = False
        self.removed: "list[str]" = []

    def snapshot(self) -> None:
        """Ничего не меняет и намеренно не снимает общий снимок системы."""
        return None

    def restore(self) -> "list[str]":
        """Не удаляет записи, ярлыки, окружение и каталоги пользователя."""
        return []


# --- записи установки на этом ПК: где установщик ищет прошлую версию ----------

_APP_PATHS_KEY = r"Software\Microsoft\Windows\CurrentVersion\App Paths"

#: Значения записи об установке, в которых установщик хранит каталог прошлой
#: версии. Именно оттуда он берёт путь, когда обновляет «уже установленную»
#: программу, — и ставит новую версию по прежнему адресу.
_INSTALL_PATH_VALUES = (
    "InstallLocation", "Inno Setup: App Path", "InstallSource",
    "UninstallString", "QuietUninstallString", "DisplayIcon",
)


def expand_root_token_text(text: str, root: Any,
                           token: str = ROOT_TOKEN) -> str:
    """Заменяет маркер ``@@PORTABLE_ROOT@@`` текущим корнем портатива.

    Маркер — наш собственный способ хранить путь в ``portable*.reg``. Он
    должен исчезать при подстановке, раньше любого импорта. Но если маркер
    всё-таки оказался в реестре или в настройках программы (портатив собран
    прежней версией, импорт делал ``Launch.bat`` без PowerShell, настройки
    скопировали с другого ПК), установщик обновления получает каталог
    ``@@PORTABLE_ROOT@@\\App`` — и падает с «Error opening file for writing»:
    такой папки нет. Поэтому маркер разворачивается ещё и при каждом запуске.

    Форма значения сохраняется: если после маркера идёт ``\\`` (удвоенные
    слэши внутри ``.reg``), корень тоже пишется с удвоенными; если ``/`` —
    с прямыми слэшами.
    """
    value = str(text or "")
    base = str(root or "").strip().strip('"').rstrip("\\/")
    if not value or not base or not token:
        return value

    def _replacement(match: "re.Match[str]") -> str:
        following = value[match.end():match.end() + 2]
        if following.startswith("\\\\"):
            return base.replace("\\", "\\\\")
        if following.startswith("/"):
            return base.replace("\\", "/")
        return base

    return re.sub(re.escape(token), _replacement, value, flags=re.IGNORECASE)


def _json_is_valid(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except ValueError:
        return False


def _expand_token_json(text: str, root: Any,
                       token: str = ROOT_TOKEN) -> str:
    """Заменяет маркер в JSON-тексте на экранированный путь.

    В JSON обратный слэш — управляющий символ: ``"E:\Backup"`` не читается
    (``Invalid \escape``). Поэтому путь подставляется в том виде, в каком его
    записал бы ``json.dumps``: ``"E:\\Backup"``. Если в файле маркер уже был
    записан с удвоенными слэшами, форма сохраняется.
    """
    value = str(text or "")
    base = str(root or "").strip().strip('"').rstrip("\\/")
    if not value or not base or not token:
        return value
    escaped = json.dumps(base, ensure_ascii=False)[1:-1]

    def _replacement(match: "re.Match[str]") -> str:
        following = value[match.end():match.end() + 2]
        if following.startswith("\\\\"):
            return escaped
        if following.startswith("\\"):
            return escaped
        if following.startswith("/"):
            return base.replace("\\", "/")
        return escaped

    result = re.sub(re.escape(token), _replacement, value, flags=re.IGNORECASE)
    if not _json_is_valid(result):
        # Файл был испорчен раньше (одиночные слэши): чиним и его.
        result = _repair_json_escapes(result)
    return result


def _repair_json_escapes(text: str) -> str:
    r"""Удваивает «одиночные» обратные слэши внутри строк JSON.

    Так выглядит ``launcher_config.json``, испорченный подстановкой пути без
    экранирования: ``"root_token": "E:\Backup\Apps"``. Настоящие
    escape-последовательности (``\\``, ``\"``, ``\n``, ``\uXXXX``) не
    трогаются, поэтому обычный JSON остаётся байт в байт.
    """
    result: "list[str]" = []
    in_string = False
    index = 0
    valid = set('"\\/bfnrtu')
    while index < len(text):
        symbol = text[index]
        if not in_string:
            result.append(symbol)
            if symbol == '"':
                in_string = True
            index += 1
            continue
        if symbol == "\\":
            following = text[index + 1:index + 2]
            if following in valid and following:
                result.append(symbol + following)
                index += 2
                continue
            result.append("\\\\")
            index += 1
            continue
        result.append(symbol)
        if symbol == '"':
            in_string = False
        index += 1
    return "".join(result)


def retarget_record_text(text: str, stale_roots: "Sequence[str]",
                         current_root: str) -> str:
    """Заменяет в значении записи прежние места портатива текущим корнем.

    Чистая функция (без реестра): её же проверяют тесты на любой ОС.
    """
    result = str(text or "")
    base = str(current_root or "").strip().rstrip("\\/")
    if not result or not base:
        return result
    for root in stale_roots:
        stale = str(root or "").strip().strip('"').rstrip("\\/")
        if not stale or stale.casefold() == base.casefold():
            continue
        for form in sorted({stale, stale.replace("\\", "/"),
                            stale.replace("/", "\\"),
                            stale.replace("\\", "\\\\")}, key=len, reverse=True):
            pattern = re.compile(r"(?<![0-9A-Za-z_])" + re.escape(form)
                                 + r"(?![0-9A-Za-z_.])", re.IGNORECASE)
            result = pattern.sub(lambda _m: base, result)
    return expand_root_token_text(result, base)


def _registry_views():
    """Корни реестра, в которых установщик мог оставить запись об установке."""
    reg = _winreg()
    if reg is None:
        return []
    return [
        (reg.HKEY_CURRENT_USER, _UNINSTALL_KEY, reg.KEY_READ | reg.KEY_SET_VALUE),
        (reg.HKEY_CURRENT_USER, _APP_PATHS_KEY, reg.KEY_READ | reg.KEY_SET_VALUE),
        (reg.HKEY_LOCAL_MACHINE, _UNINSTALL_KEY,
         reg.KEY_READ | reg.KEY_SET_VALUE | reg.KEY_WOW64_64KEY),
        (reg.HKEY_LOCAL_MACHINE, _APP_PATHS_KEY,
         reg.KEY_READ | reg.KEY_SET_VALUE | reg.KEY_WOW64_64KEY),
        (reg.HKEY_LOCAL_MACHINE, _UNINSTALL_KEY,
         reg.KEY_READ | reg.KEY_SET_VALUE | reg.KEY_WOW64_32KEY),
    ]


def _winreg():
    """``winreg`` или ``None`` (модуль импортируется и вне Windows)."""
    if not IS_WINDOWS:
        return None
    try:
        import winreg  # type: ignore

        return winreg
    except ImportError:  # pragma: no cover - Windows без winreg не бывает
        return None


def replace_app_prefix(value: str, current_root: Path,
                       app_names: "Sequence[str]" = ()) -> str:
    """Заменяет «...\\<папка>\\App\\...» на текущий ``<корень>\\App``.

    Второй уровень защиты: запись об установке может помнить путь, которого
    нет в штампе переноса (портатив собран прежней версией, штамп удалён,
    папку скопировали вместе с чужими настройками). Тогда ориентир — сам
    вид пути: префикс, ``App`` и остаток. Замена выполняется, только если
    префикс **уже не существует** или его последняя папка названа как эта
    программа (``Foo_Portable``) — соседнюю установку не переписываем.
    """
    text = str(value or "")
    base = str(current_root or "").rstrip("\\/")
    if not text or not base:
        return text
    match = re.match(r"^(.*?)[\\/]App[\\/](.+)$", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return text
    prefix, rest = match.group(1), match.group(2)
    if not prefix:
        return text
    try:
        if os.path.exists(prefix) and not _name_matches(prefix, app_names):
            return text
    except (OSError, ValueError):
        return text
    separator = "\\" if "\\" in text else "/"
    return base + separator + "App" + separator + rest.lstrip("\\/")


def retarget_host_install_records(stale_roots: "Sequence[str]",
                                  current_root: Path,
                                  app_names: "Sequence[str]" = ()
                                  ) -> "list[str]":
    """Переводит записи об установке на текущий корень портатива.

    Зачем. Когда программу обновляют, установщик ищет «прошлую установку» в
    реестре этого ПК (``InstallLocation``, ``Inno Setup: App Path``,
    ``UninstallString``, ``App Paths``). Запись там могла остаться от прежнего
    места портатива — например, с диска ``D:``, откуда папку уже перенесли на
    ``E:``. Тогда установщик честно обновляет то, что знает, и новая версия
    оказывается по старому адресу, а в текущей папке ничего не меняется.

    Меняются **только** значения, указывающие внутрь известных прежних мест
    этой же портативной папки (или — при совпадении имени программы — внутрь
    несуществующей папки ``...\\App``). Путь заменяется текущим корнем.
    Ничего не удаляется: запись остаётся рабочей, просто ведёт туда, где
    портатив лежит сейчас.

    Возвращает список изменённых значений (``<ключ> :: <имя>``) для журнала.
    """
    if not IS_WINDOWS:
        return []
    reg = _winreg()
    if reg is None:
        return []
    changed: "list[str]" = []
    for hive, path, access in _registry_views():
        try:
            with reg.OpenKey(hive, path, 0, access) as parent:
                names = []
                index = 0
                while True:
                    try:
                        names.append(reg.EnumKey(parent, index))
                    except OSError:
                        break
                    index += 1
        except OSError:
            continue
        for name in names:
            subkey = path + "\\" + name
            try:
                with reg.OpenKey(hive, subkey, 0, access) as key:
                    changed.extend(_retarget_key_values(
                        reg, key, subkey, stale_roots, current_root,
                        app_names, subkey_name=name))
            except OSError:
                continue
    return changed


def _retarget_key_values(reg, key, subkey: str, stale_roots: "Sequence[str]",
                         current_root: Path, app_names: "Sequence[str]" = (),
                         subkey_name: str = "") -> "list[str]":
    """Правит значения одного ключа; возвращает изменённые имена."""
    values: "list[tuple[str, str, int]]" = []
    index = 0
    while True:
        try:
            name, value, kind = reg.EnumValue(key, index)
        except OSError:
            break
        index += 1
        values.append((name, value, kind))

    display = ""
    for name, value, kind in values:
        if str(name).casefold() == "displayname" and isinstance(value, str):
            display = value
            break
    names = [str(item) for item in app_names if str(item).strip()]
    #: Запись принадлежит этой программе: по DisplayName или по имени ключа
    #: (``App Paths\\Foo.exe``).
    belongs = any(
        set(app_name_candidates(candidate)) & set(names)
        for candidate in (display, subkey_name)
        if candidate
    )

    changed: "list[str]" = []
    for name, value, kind in values:
        if kind not in (reg.REG_SZ, reg.REG_EXPAND_SZ) or not isinstance(value, str):
            continue
        # Маркер — всегда наш: он разворачивается в текущий корень независимо
        # от того, чья это запись (у чужой программы маркера быть не может).
        fixed = expand_root_token_text(value, str(current_root))
        if stale_roots:
            fixed = retarget_record_text(fixed, stale_roots, str(current_root))
        if fixed == value and belongs:
            # Имя программы совпало, а путь остался прежним: заменяем
            # «...\\папка\\App\\...» на текущий корень, если тот префикс
            # уже не существует.
            fixed = replace_app_prefix(fixed, current_root, names)
        if fixed == value:
            continue
        try:
            reg.SetValueEx(key, name, 0, kind, fixed)
        except OSError:
            continue
        changed.append(f"{subkey} :: {name or '(default)'}")
    return changed


# --- запись в «Установленные программы» ---------------------------------------
#
# Портатив не устанавливается, поэтому в Панели управления (Параметры ->
# Приложения) его быть не должно. Но установщик, который разворачивается внутрь
# App, пишет свою запись в Uninstall — и она остаётся на компьютере навсегда.
# После переноса папки на другой диск такая запись ещё и указывает в никуда или
# в прежнее место, а пользователь видит «Cursor установлен», хотя это портатив.
#
# Удаляется только доказанная запись: какое-то из её значений с путём
# (InstallLocation, DisplayIcon, UninstallString, Inno Setup: App Path…)
# ведёт внутрь ЭТОЙ папки — текущей или одного из прежних мест — либо содержит
# наш маркер @@PORTABLE_ROOT@@. Чужая установка той же программы (например,
# %LOCALAPPDATA%\\Programs\\cursor) не совпадает ни с одним корнем и остаётся
# нетронутой.

#: Значения записи, в которых установщики хранят путь установки.
UNINSTALL_PATH_VALUES = (
    "InstallLocation", "InstallDir", "InstallDirectory", "InstallFolder",
    "InstallPath", "DisplayIcon", "UninstallString", "QuietUninstallString",
    "InstallSource", "Inno Setup: App Path", "AppPath", "Path", "ModifyPath",
)

#: Ветка, формирующая список «Установленные программы».
UNINSTALL_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

#: Сколько записей просматривается за один запуск (защита от гигантских
#: каталогов вроде Microsoft Visual Studio).
UNINSTALL_MAX_ENTRIES = 400

#: Путь Windows (``D:\\...``) или POSIX (``/opt/...``): второй вариант нужен
#: тестам и на случай значения, записанного чужой программой.
_WINDOWS_PATH_RE = re.compile(
    r"[A-Za-z]:[\\/][^\"<>|?*\r\n;]*|/[^\"<>|?*\r\n;]*")


def _record_roots(root: Path, cfg: "Optional[Dict[str, Any]]" = None
                  ) -> "list[str]":
    """Корни, которые считаются «этим портативом»: текущий и прежние места."""
    roots: "list[str]" = [str(root)]
    try:
        roots.extend(remembered_roots(root, cfg))
    except Exception:  # noqa: BLE001 - штамп мог быть нечитаем
        pass
    unique = _unique_roots(roots)
    # Текущий корень — всегда первым и в своём написании.
    return [str(root)] + [text for text in unique
                          if _root_key(text) != _root_key(root)]


#: Папки, которые портативный лончер подменяет в окружении программы. Значение
#: записи могло быть записано как ``%LOCALAPPDATA%\\Programs\\cursor`` — при
#: раскрытии окружением ЭТОГО ПК такой путь ведёт в настоящий профиль
#: пользователя, хотя установщик работал внутри портатива.
_PORTABLE_ENV_FOLDERS = (
    ("APPDATA", ("AppData", "Roaming")),
    ("LOCALAPPDATA", ("AppData", "Local")),
    ("USERPROFILE", ("User",)),
    ("TEMP", ("Temp",)),
    ("TMP", ("Temp",)),
    ("PROGRAMDATA", ("ProgramData",)),
    ("PUBLIC", ("Public",)),
)


def _portable_env(root: Path,
                  cfg: "Optional[Dict[str, Any]]" = None) -> Dict[str, str]:
    """Значения подменённых переменных окружения (как в _prepare_environment)."""
    data_name = str((cfg or {}).get("data_dir_name") or "PortableData")
    data = Path(root) / data_name
    env = {name: str(data.joinpath(*parts))
           for name, parts in _PORTABLE_ENV_FOLDERS}
    env["PORTABLE_ROOT"] = str(root)
    return env


#: ``%LOCALAPPDATA%``-подобная переменная в значении реестра. Раскрывается
#: явно, а не через ``os.path.expandvars``: тот понимает ``%VAR%`` только на
#: Windows, а правила проверки должны вести себя одинаково везде.
_WINVAR_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_()#@$ .-]*)%")


def _expand_record_value(value: str,
                         extra_env: "Optional[Dict[str, str]]" = None) -> str:
    """Раскрывает ``%VAR%``: окружением ПК и (если задано) портативным профилем."""
    text = str(value or "")
    if not text:
        return text
    env = {str(name).upper(): str(item) for name, item in os.environ.items()}
    if extra_env:
        env.update({str(name).upper(): str(item)
                    for name, item in extra_env.items()})

    def _replace(match: "re.Match[str]") -> str:
        return env.get(match.group(1).upper(), match.group(0))

    text = _WINVAR_RE.sub(_replace, text)
    try:
        text = os.path.expandvars(text)
    except Exception:  # noqa: BLE001
        pass
    return text.replace(ROOT_TOKEN, env.get("PORTABLE_ROOT", ""))


def _fold_record_path(text: str) -> str:
    """Путь в сравнимом виде: те же разделители, без хвостового слэша."""
    clean = str(text or "").strip().strip('"').replace("/", "\\")
    clean = os.path.normpath(clean).rstrip("\\")
    # Пути Windows регистронезависимы, а сравнение выполняется и в тестах на
    # Linux, где normcase ничего не меняет.
    return clean.casefold()


def _path_fragments(value: str,
                   extra_env: "Optional[Dict[str, str]]" = None
                   ) -> "list[str]":
    """Все похожие на путь фрагменты значения записи.

    Значение записи — не всегда чистый путь: ``"D:\\Apps\\Cursor\\App\\Cursor.exe",0``,
    ``"D:\\...\\unins000.exe" /SILENT``, ``%LOCALAPPDATA%\\Programs\\cursor``.
    Переменные раскрываются дважды: окружением этого ПК и (если известно)
    портативным профилем. Второй вариант важен, когда установщик работал
    внутри портатива и записал путь в переменных, а не абсолютом.
    """
    text = str(value or "").strip()
    if not text:
        return []
    variants = [text]
    expanded = _expand_record_value(text, extra_env)
    if expanded != text:
        variants.append(expanded)
    host_only = _expand_record_value(text)
    if host_only not in variants:
        variants.append(host_only)
    fragments: "list[str]" = []
    for variant in variants:
        for candidate in _WINDOWS_PATH_RE.findall(variant):
            clean = re.sub(r",\s*-?\d+\s*$", "", candidate.strip().strip('"'))
            if clean:
                fragments.append(clean)
    return fragments


def path_points_into_portable(value: str, roots: "Sequence[str]",
                              extra_env: "Optional[Dict[str, str]]" = None) -> bool:
    """Есть ли в значении путь внутрь одного из корней портатива.

    Кавычки, номер значка (``,0``) и переменные окружения отбрасываются или
    раскрываются — см. :func:`_path_fragments`.
    """
    text = str(value or "").strip()
    if not text:
        return False
    if ROOT_TOKEN.casefold() in text.casefold():
        return True
    normalized_roots = [folded for folded
                        in (_fold_record_path(item) for item in roots)
                        if folded and len(folded) >= 2]
    for candidate in _path_fragments(text, extra_env):
        folded = _fold_record_path(candidate)
        if len(folded) < 3:
            continue
        for root in normalized_roots:
            if folded == root or folded.startswith(root + "\\"):
                return True
    return False


def _record_path_fragments(values: Dict[str, Any],
                           extra_env: "Optional[Dict[str, str]]" = None
                           ) -> "list[str]":
    """Пути из всех «путевых» значений записи Uninstall."""
    path_values = {item.casefold() for item in UNINSTALL_PATH_VALUES}
    fragments: "list[str]" = []
    for name, value in values.items():
        if str(name).casefold() not in path_values:
            continue
        if isinstance(value, str):
            fragments.extend(_path_fragments(value, extra_env))
    return fragments


def _record_points_into_portable(values: Dict[str, Any],
                                 roots: "Sequence[str]",
                                 extra_env: "Optional[Dict[str, str]]" = None
                                 ) -> bool:
    """Хотя бы одно путевое значение ведёт внутрь портатива."""
    path_values = {item.casefold() for item in UNINSTALL_PATH_VALUES}
    for name, value in values.items():
        if str(name).casefold() not in path_values:
            continue
        if isinstance(value, str) and path_points_into_portable(
                value, roots, extra_env):
            return True
    return False


def _variable_values(values: Dict[str, Any]) -> "list[str]":
    """Путевые значения записи, в которых есть ``%ПЕРЕМЕННАЯ%``."""
    path_values = {item.casefold() for item in UNINSTALL_PATH_VALUES}
    found: "list[str]" = []
    for name, value in values.items():
        if str(name).casefold() not in path_values:
            continue
        if isinstance(value, str) and "%" in value:
            found.append(value)
    return found


def _record_variables_resolve_into_portable(
        values: Dict[str, Any], roots: "Sequence[str]",
        extra_env: "Optional[Dict[str, str]]") -> bool:
    """Переменная записи раскрывается в путь внутрь портативного профиля."""
    if not extra_env:
        return False
    for value in _variable_values(values):
        for fragment in _path_fragments(
                _expand_record_value(value, extra_env)):
            if path_points_into_portable(fragment, roots):
                return True
    return False


def _path_exists_on_host(path: str) -> bool:
    """Существует ли путь на этом ПК (с поправкой на разделители в тестах)."""
    candidate = str(path or "").strip()
    if not candidate:
        return False
    variants = [candidate]
    if os.sep != "\\":
        variants.append(candidate.replace("\\", "/"))
    for item in variants:
        try:
            if os.path.exists(item):
                return True
        except (OSError, ValueError):
            continue
    return False


def _record_has_live_expanded_path(values: Dict[str, Any],
                                   roots: "Sequence[str]") -> bool:
    """Переменная записи ведёт в существующий путь вне портатива.

    Это защита от ложного удаления: ``%LOCALAPPDATA%\\Programs\\cursor``
    раскрывается и внутрь портатива, и в настоящий профиль пользователя.
    Если по «настоящему» адресу лежат файлы — программа действительно
    установлена, запись трогать нельзя.
    """
    for value in _variable_values(values):
        for fragment in _path_fragments(_expand_record_value(value)):
            if path_points_into_portable(fragment, roots):
                continue
            if _path_exists_on_host(fragment):
                return True
    return False


def _record_is_orphan(values: Dict[str, Any],
                      roots: "Sequence[str]",
                      extra_env: "Optional[Dict[str, str]]" = None) -> bool:
    """Запись ссылается только на пути, которых на этом ПК нет.

    Так выглядит след установки, сделанной внутри портатива: программа
    установилась в ``App``, а запись помнит каталог, которого на компьютере
    никогда не было (``%LOCALAPPDATA%\\Programs\\cursor`` — раскрытая
    переменная настоящего профиля). Настоящая установка той же программы
    оставляет существующие файлы, поэтому не попадает под правило.
    """
    fragments = _record_path_fragments(values, extra_env)
    if not fragments:
        return False
    for fragment in fragments:
        if path_points_into_portable(fragment, roots, extra_env):
            continue
        if _path_exists_on_host(fragment):
            return False
    return True


def _normalised_record_name(value: str) -> str:
    """Имя приложения без разделителей и регистра: «Cursor 0.44» -> «cursor044»."""
    return re.sub(r"[^0-9a-z]+", "", str(value or "").casefold())


def _record_belongs_to_app(values: Dict[str, Any], key_name: str,
                           app_name: str) -> bool:
    """Запись называет это приложение (DisplayName или имя ключа).

    Проверка нужна вместе с путём: портатив можно положить в широкую папку
    (``D:\Apps`` и даже в корень диска), и тогда «путь внутри портатива»
    совпал бы у чужих программ. Имя сужает правило до своей записи.
    """
    expected = _normalised_record_name(app_name)
    if not expected:
        return False
    for candidate in (values.get("DisplayName", ""), key_name):
        found = _normalised_record_name(candidate)
        if not found:
            continue
        if found == expected:
            return True
        # Короткое имя («App», «FX») сравнивается только целиком: иначе
        # «App» совпало бы с половиной записей списка приложений.
        if len(expected) < 4 or len(found) < 4:
            continue
        if expected in found or found in expected:
            return True
    return False


def _record_hidden_by_system(values: Dict[str, Any]) -> bool:
    """Запись-компонент другой программы (``SystemComponent=1``).

    Такие записи Панель управления не показывает, а их ключи принадлежат
    msi-установке другого продукта — трогать их нельзя.
    """
    for name in ("SystemComponent", "NoRemove", "ParentKeyName"):
        value = values.get(name)
        if isinstance(value, str) and value.strip() not in ("", "0"):
            return True
    return False


def _record_looks_like_this_portable(values: Dict[str, Any],
                                     roots: "Sequence[str]",
                                     app_name: str = "",
                                     key_name: str = "",
                                     extra_env: "Optional[Dict[str, str]]" = None,
                                     remove_orphans: bool = True) -> bool:
    """Запись Uninstall принадлежит этому портативу.

    Имя обязано совпадать с приложением — одного пути мало (папка портатива
    может быть широкой), одного имени тоже (у пользователя бывает настоящая
    установка той же программы). Дальше достаточно одного из трёх:

    * какое-то путевое значение ведёт внутрь портатива (текущего или прежнего
      места);
    * путь записан переменной (``%LOCALAPPDATA%``), которая внутри портатива
      означает его собственный профиль, — и по этому адресу в настоящем
      профиле файлов нет;
    * все пути записи на этом ПК отсутствуют: это след установки, сделанной
      внутри портатива, а не работающая программа.
    """
    if _record_hidden_by_system(values):
        return False
    if not _record_belongs_to_app(values, key_name, app_name):
        return False
    # Прямой путь внутрь портатива (в том числе в его прежнее место).
    if _record_points_into_portable(values, roots):
        return True
    # Путь записан переменной (%LOCALAPPDATA% и т. п.), которая внутри
    # портатива означает его профиль. Настоящую установку по тому же адресу
    # не трогаем — для неё переменная раскрывается в существующие файлы.
    if (_record_variables_resolve_into_portable(values, roots, extra_env)
            and not _record_has_live_expanded_path(values, roots)):
        return True
    # Запись ссылается только на несуществующие пути — след установки.
    if remove_orphans and _record_is_orphan(values, roots, extra_env):
        return True
    return False


def _uninstall_registry_views() -> "list[tuple[Any, int, int, str]]":
    """(hive, чтение, запись, подпись) для HKCU и обоих видов HKLM.

    Чтение и запись — разные флаги: перечислять записи можно и без прав
    администратора, а ``RegDeleteKey`` требует у родительского ключа
    ``KEY_WRITE``. Иначе отказ в доступе к машинной ветке выглядел бы как
    «записей нет», и след установки тихо оставался бы на месте.
    """
    reg = _winreg()
    if reg is None:
        return []
    read = getattr(reg, "KEY_READ", 0)
    # RegDeleteKey требует у родительского ключа право DELETE; KEY_WRITE без
    # него на некоторых системах даёт «отказано в доступе» даже своему ключу.
    write = getattr(reg, "KEY_WRITE", 0) | getattr(reg, "DELETE", 0)
    views: "list[tuple[Any, int, int, str]]" = [
        (reg.HKEY_CURRENT_USER, read, write, "HKCU"),
        (reg.HKEY_LOCAL_MACHINE,
         read | getattr(reg, "KEY_WOW64_64KEY", 0),
         write | getattr(reg, "KEY_WOW64_64KEY", 0), "HKLM"),
    ]
    if getattr(reg, "KEY_WOW64_32KEY", 0):
        views.append((reg.HKEY_LOCAL_MACHINE,
                      read | reg.KEY_WOW64_32KEY,
                      write | reg.KEY_WOW64_32KEY, "HKLM32"))
    return views


def _read_uninstall_entry(reg, hive, access: int, name: str
                          ) -> "Optional[Dict[str, Any]]":
    """Значения одной записи Uninstall (только строковые)."""
    path = UNINSTALL_KEY_PATH + "\\" + name
    try:
        with reg.OpenKey(hive, path, 0, access) as key:
            values: Dict[str, Any] = {}
            index = 0
            while True:
                try:
                    value_name, value, _kind = reg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                if isinstance(value, str):
                    values[value_name] = value
            return values
    except OSError:
        return None


#: Имя куста в конфиге сборки (``host_cleanup.records``) -> имя в winreg.
_HIVE_BY_NAME = {
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
}


def _host_cleanup_settings(cfg: "Optional[Dict[str, Any]]") -> Dict[str, Any]:
    settings = (cfg or {}).get("host_cleanup")
    return settings if isinstance(settings, dict) else {}


def configured_install_records(cfg: "Optional[Dict[str, Any]]"
                               ) -> "list[Dict[str, str]]":
    """Записи, которые сборщик точно видел созданными этим установщиком.

    ``host_cleanup.records`` в ``launcher_config.json`` — страховка на случай,
    когда значения записи уже переписаны (путь обновлён, переменные не
    раскрываются, DisplayName заменён апдейтером). Сборщик сравнивал снимки
    реестра до и после установки, поэтому такой ключ — доказанно наш.
    """
    records = _host_cleanup_settings(cfg).get("records")
    if not isinstance(records, list):
        return []
    parsed: "list[Dict[str, str]]" = []
    for item in records:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip().strip("\\")
        hive = _HIVE_BY_NAME.get(str(item.get("hive") or "HKCU").upper(), "")
        if not path or not hive:
            continue
        # Удалять можно только записи списка приложений: путь из конфига
        # обязан лежать внутри Uninstall, иначе он игнорируется.
        normalised = path.replace("/", "\\").casefold()
        if not normalised.startswith(UNINSTALL_KEY_PATH.casefold() + "\\"):
            continue
        name = path.rsplit("\\", 1)[-1]
        parsed.append({
            "hive": hive,
            "path": path,
            "name": name,
            "display": str(item.get("display") or ""),
        })
    return parsed


_CLOSING_BRACES_RE = re.compile(r"\}{2,}")


def uninstall_name_variants(name: str) -> "list[str]":
    """Имя записи списка приложений и его «исправленное» написание.

    Установщики на Inno Setup называют ключ ``{GUID}_is1``. В конфиг сборки
    такое имя попадало и с лишней закрывающей скобкой
    (``{GUID}}_is1``) — тогда лончер искал ключ, которого нет, и настоящая
    запись оставалась в списке установленных программ. Поэтому к имени
    пробуются варианты: как есть, без двойных скобок и с одной парой скобок.
    """
    text = str(name or "").strip()
    variants = [text] if text else []
    for candidate in ((_CLOSING_BRACES_RE.sub("}", text)),
                      (_CLOSING_BRACES_RE.sub("}", text)).replace("{", "")):
        candidate = candidate.strip()
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants


def _read_uninstall_entry_variant(reg, hive, access: int, name: str
                                  ) -> "Optional[tuple[str, Dict[str, Any]]]":
    """Значения записи по любому из написаний имени (см. выше).

    Возвращает настоящее имя ключа и его значения — чтобы удалять именно
    существующий ключ, а не его «исправленное» имя.
    """
    for candidate in uninstall_name_variants(name):
        values = _read_uninstall_entry(reg, hive, access, candidate)
        if values:
            return candidate, values
    return None


def _hive_handle(reg, name: str):
    return getattr(reg, name, None)


def _uninstall_view_labels(reg, hive_name: str) -> "list[tuple[int, str]]":
    """(флаг представления, подпись) для ключа из конфига: 64 и 32 бита."""
    views = [(0, "HKCU" if hive_name == "HKEY_CURRENT_USER" else "HKLM")]
    if hive_name == "HKEY_LOCAL_MACHINE":
        wow32 = getattr(reg, "KEY_WOW64_32KEY", 0)
        if wow32:
            views.append((wow32, "HKLM32"))
    return views


def portable_install_records(root: Path,
                             cfg: "Optional[Dict[str, Any]]" = None
                             ) -> "list[Dict[str, Any]]":
    """Записи «Установленные программы», которые создал этот портатив.

    Два источника: обход списка приложений (с проверкой имени и пути) и
    готовый список ключей из конфига сборки (``host_cleanup.records``) — он
    снимает зависимость от того, что установщик записал в значения.
    """
    reg = _winreg()
    if reg is None:
        return []
    settings = _host_cleanup_settings(cfg)
    remove_orphans = settings.get("remove_orphan_entries") is not False
    roots = _record_roots(root, cfg)
    extra_env = _portable_env(root, cfg)
    app_name = str((cfg or {}).get("app_name") or "")
    found: "list[Dict[str, Any]]" = []
    seen: "set[tuple[str, str]]" = set()

    def _add(hive, read_access: int, write_access: int, label: str,
             name: str, values: "Dict[str, Any]", explicit: bool) -> None:
        key = (label, name.casefold())
        if key in seen:
            return
        seen.add(key)
        found.append({
            "hive": label,
            "hive_handle": hive,
            "write_access": int(write_access),
            "name": name,
            "display": str(values.get("DisplayName") or name),
            "explicit": explicit,
        })

    for hive, read_access, write_access, label in _uninstall_registry_views():
        try:
            with reg.OpenKey(hive, UNINSTALL_KEY_PATH, 0, read_access) as parent:
                names = []
                index = 0
                while len(names) < UNINSTALL_MAX_ENTRIES:
                    try:
                        names.append(reg.EnumKey(parent, index))
                    except OSError:
                        break
                    index += 1
        except OSError:
            continue
        for name in names:
            values = _read_uninstall_entry(reg, hive, read_access, name)
            if not values:
                continue
            if not _record_looks_like_this_portable(
                    values, roots, app_name, name,
                    extra_env=extra_env, remove_orphans=remove_orphans):
                continue
            _add(hive, read_access, write_access, label, name, values, False)

    # Ключи из конфига сборки: их создал именно этот установщик (сравнение
    # снимков реестра). Даже если значения уже не выглядят «портативными»,
    # запись остаётся следом установки, а не работающей программой.
    for record in configured_install_records(cfg):
        hive_name = record["hive"]
        hive = _hive_handle(reg, hive_name)
        if hive is None:
            continue
        name = record["name"]
        for view, label in _uninstall_view_labels(reg, hive_name):
            read_access = getattr(reg, "KEY_READ", 0) | view
            write_access = (getattr(reg, "KEY_WRITE", 0)
                            | getattr(reg, "DELETE", 0) | view)
            found_entry = _read_uninstall_entry_variant(reg, hive, read_access,
                                                        name)
            if not found_entry:
                continue
            real_name, values = found_entry
            if not _record_hidden_by_system(values) and (
                    _record_belongs_to_app(values, real_name, app_name)
                    or _record_is_orphan(values, roots, extra_env)):
                _add(hive, read_access, write_access, label, real_name,
                     values, True)
            break
    return found


def remove_portable_install_records(root: Path,
                                    cfg: "Optional[Dict[str, Any]]" = None
                                    ) -> "tuple[list[str], bool]":
    """Удаляет записи этого портатива из «Установленные программы».

    Возвращает ``(строки для журнала, нужны ли права администратора)``.
    Права нужны, только если запись лежит в машинной ветке (установка «для
    всех пользователей»), а лончер запущен без повышения.
    """
    reg = _winreg()
    if reg is None:
        return [], False
    lines: "list[str]" = []
    needs_admin = False
    for record in portable_install_records(root, cfg):
        hive = record["hive_handle"]
        access = int(record["write_access"])
        name = str(record["name"])
        display = str(record["display"])
        try:
            with reg.OpenKey(hive, UNINSTALL_KEY_PATH, 0, access) as parent:
                reg.DeleteKey(parent, name)
        except OSError as exc:
            if record["hive"] == "HKCU":
                lines.append(f"не удалось удалить запись «{display}» ({exc})")
            else:
                needs_admin = True
                lines.append(
                    f"запись «{display}» лежит в машинной ветке {record['hive']}: "
                    "нужны права администратора")
            continue
        lines.append(f"удалена запись «{display}» из списка установленных "
                     f"приложений ({record['hive']})")
    return lines, needs_admin


def describe_install_records(root: Path,
                             cfg: "Optional[Dict[str, Any]]" = None
                             ) -> "list[str]":
    """Что лончер думает о записях этого приложения — для ``--diagnose``.

    Показывает и те записи, которые решено оставить: по строке видно, почему
    запись не считается следом портатива (например, программа установлена
    по-настоящему и её файлы существуют). Без этого «не удалилось» выглядит
    как ошибка, хотя правило сработало верно.
    """
    reg = _winreg()
    if reg is None:
        return ["реестр Windows недоступен: проверка списка приложений "
                "выполняется только на Windows"]
    settings = _host_cleanup_settings(cfg)
    if settings.get("hide_installed_entry") is False:
        return ["уборка записи из списка приложений отключена в конфиге "
                "(host_cleanup.hide_installed_entry = false)"]
    remove_orphans = settings.get("remove_orphan_entries") is not False
    roots = _record_roots(root, cfg)
    extra_env = _portable_env(root, cfg)
    app_name = str((cfg or {}).get("app_name") or "")
    lines: "list[str]" = [
        "приложение: " + (app_name or "(не задано)"),
        "корни этого портатива: " + "; ".join(roots),
    ]
    ours = {(record["hive"], record["name"].casefold())
            for record in portable_install_records(root, cfg)}
    printed: "set[str]" = set()
    seen = 0
    for hive, read_access, _write_access, label in _uninstall_registry_views():
        try:
            with reg.OpenKey(hive, UNINSTALL_KEY_PATH, 0, read_access) as parent:
                names = []
                index = 0
                while len(names) < UNINSTALL_MAX_ENTRIES:
                    try:
                        names.append(reg.EnumKey(parent, index))
                    except OSError:
                        break
                    index += 1
        except OSError:
            continue
        for name in names:
            values = _read_uninstall_entry(reg, hive, read_access, name)
            if not values:
                continue
            if not _record_belongs_to_app(values, name, app_name):
                continue
            seen += 1
            display = str(values.get("DisplayName") or name)
            mine = (label, name.casefold()) in ours
            reason = _record_reason(values, roots, extra_env, remove_orphans)
            verdict = "будет удалена" if mine else "оставлена"
            lines.append(f"{label}\\{name}: «{display}» — {verdict} ({reason})")
            printed.add(name.casefold())
    for record in configured_install_records(cfg):
        state, found = _configured_record_state(reg, record)
        if found and found[0].casefold() not in printed:
            real_name, values = found
            if not _record_hidden_by_system(values):
                seen += 1
                display = str(values.get("DisplayName") or real_name)
                lines.append(f"{record['hive']}\\{real_name}: «{display}» — "
                             "будет удалена (ключ создан этим установщиком "
                             "при сборке: сравнение снимков реестра)")
                printed.add(real_name.casefold())
                continue
        lines.append("запись из сборки: " + record["hive"] + "\\"
                     + record["path"] + state)
    if not seen:
        lines.append("записей с именем этого приложения в списке "
                     "установленных программ нет")
    return lines


def _configured_record_state(reg, record: Dict[str, str]
                             ) -> "tuple[str, Optional[tuple[str, Dict[str, Any]]]]":
    """Что с ключом из конфига сборки: уточнение для отчёта и сам ключ.

    Уточнение нужно потому, что «запись из сборки» раньше выглядела как
    найденная запись, хотя ключа могло уже не быть (его удалили раньше), а имя
    в конфиге — искажённым (``{GUID}}_is1``). Второй элемент — настоящее имя
    ключа и его значения, если ключ на этом ПК есть.
    """
    hive = _hive_handle(reg, str(record.get("hive") or ""))
    if hive is None:
        return "", None
    for view, _label in _uninstall_view_labels(reg, str(record.get("hive"))):
        access = getattr(reg, "KEY_READ", 0) | view
        found = _read_uninstall_entry_variant(reg, hive, access,
                                              str(record.get("name") or ""))
        if not found:
            continue
        real_name, values = found
        display = str(values.get("DisplayName") or "")
        if real_name.casefold() != str(record.get("name") or "").casefold():
            return (f" — в реестре она называется «{real_name}»"
                    + (f" ({display})" if display else "")
                    + ", лончер найдёт её и по этому имени"), found
        return (" — ключ есть на этом ПК"
                + (f" («{display}»)" if display else "")), found
    return " — ключа на этом ПК нет (запись уже удалена)", None


def _record_reason(values: Dict[str, Any], roots: "Sequence[str]",
                   extra_env: "Optional[Dict[str, str]]",
                   remove_orphans: bool) -> str:
    """Короткое объяснение решения по записи."""
    if _record_hidden_by_system(values):
        return "запись-компонент другой программы (SystemComponent)"
    if _record_points_into_portable(values, roots):
        return "путь ведёт внутрь портатива"
    if _record_variables_resolve_into_portable(values, roots, extra_env):
        if _record_has_live_expanded_path(values, roots):
            return "файлы установки есть в настоящем профиле: похоже на настоящую установку"
        return "переменная профиля раскрывается внутрь портатива"
    if _record_is_orphan(values, roots, extra_env):
        if remove_orphans:
            return "все пути записи на этом ПК отсутствуют"
        return "пути отсутствуют, но уборка таких записей выключена"
    return "файлы установки есть вне портатива (похоже на настоящую установку)"


def _machine_registry_pending(root: Path, cfg: "Dict[str, Any]") -> bool:
    """Ожидается ли отдельный UAC для импорта машинного реестра.

    Если да, права администратора попросит он — второй запрос за один запуск
    только раздражает, а отказ от первого запоминается на час и отменил бы
    вторую (нужную) операцию.
    """
    registry = (cfg or {}).get("registry") or {}
    name = str(registry.get("machine_file") or "")
    if not registry.get("enabled") or not name:
        return False
    try:
        return _as_relative_path(root, name).is_file()
    except Exception:  # noqa: BLE001 - путь не разобрался, значит ничего не ждём
        return False


def clean_installed_programs(root: Path,
                             cfg: "Optional[Dict[str, Any]]" = None,
                             allow_elevation: bool = False) -> "list[str]":
    """Убирает след установки портатива из списка приложений Windows.

    Вызывается перед запуском программы и ещё раз после выхода: родной
    апдейтер программы может поставить запись заново, пока она работает.
    Удаление идёт только по доказанному пути внутрь портатива — см. выше.
    """
    if not IS_WINDOWS:
        return []
    settings = (cfg or {}).get("host_cleanup") or {}
    if isinstance(settings, dict) and settings.get("hide_installed_entry") is False:
        return []
    lines, needs_admin = remove_portable_install_records(root, cfg)
    if (needs_admin and allow_elevation and not _is_elevated()
            and getattr(sys, "frozen", False)
            and not elevation_refused_recently(root)):
        code = _run_elevated(["--clean-installed-entry"])
        if code is None:
            mark_elevation_refused(root, "no result from the UAC prompt")
            lines.append("машинную запись удалить не удалось: UAC не подтверждён")
        elif code == 0:
            clear_elevation_refusal(root)
            lines.append("машинная запись удалена с правами администратора")
        else:
            mark_elevation_refused(root, f"elevated cleanup returned {code}")
            lines.append("машинную запись удалить не удалось (повышенный "
                         f"запуск вернул код {code})")
    return lines


def clean_installed_programs_command(root: "Optional[Path]" = None) -> int:
    """``--clean-installed-entry``: служебный режим для повышенной копии."""
    root = root or find_portable_root()
    try:
        cfg = read_launcher_config(root)
    except Exception:  # noqa: BLE001 - конфиг мог быть старым
        cfg = {}
    lines, needs_admin = remove_portable_install_records(root, cfg)
    for line in lines:
        _run_log(root, "installed programs: " + line)
    if needs_admin:
        return 1
    return 0


def forget_installed_entry(name: str, root: "Optional[Path]" = None,
                           cfg: "Optional[Dict[str, Any]]" = None
                           ) -> "list[str]":
    """Удаляет записи списка приложений по указанному имени — вручную.

    Нужно, когда запись осталась от сборки прежней версией: в её значениях
    может не быть ни одного пути (чистый MSI) или путь уже переписан, и
    автоматическое правило её не опознаёт. Действие явное: пользователь сам
    назвал программу, поэтому путь не проверяется, но проверяется имя —
    ``DisplayName`` или имя ключа обязаны содержать запрошенное название.
    """
    reg = _winreg()
    if reg is None:
        return ["реестр Windows недоступен: действие выполняется только "
                "на Windows"]
    needle = _normalised_record_name(name)
    if not needle:
        return ["не задано имя записи"]
    app_name = str((cfg or {}).get("app_name") or name)
    lines: "list[str]" = []
    for hive, read_access, write_access, label in _uninstall_registry_views():
        try:
            with reg.OpenKey(hive, UNINSTALL_KEY_PATH, 0,
                             write_access) as parent:
                names = []
                index = 0
                while len(names) < UNINSTALL_MAX_ENTRIES:
                    try:
                        names.append(reg.EnumKey(parent, index))
                    except OSError:
                        break
                    index += 1
        except OSError:
            continue
        for key_name in names:
            values = _read_uninstall_entry(reg, hive, read_access, key_name)
            if not values:
                continue
            display = str(values.get("DisplayName") or key_name)
            found = (_normalised_record_name(display)
                     or _normalised_record_name(key_name))
            if needle not in found:
                continue
            try:
                with reg.OpenKey(hive, UNINSTALL_KEY_PATH, 0,
                                 write_access) as parent:
                    reg.DeleteKey(parent, key_name)
            except OSError as exc:
                lines.append(f"не удалось удалить «{display}» ({label}): {exc}")
                continue
            lines.append(f"удалена запись «{display}» ({label}\\{key_name})")
    if not lines:
        lines.append(f"записей с именем «{name}» не найдено "
                     f"(проверялось приложение «{app_name}»)")
    return lines


def forget_installed_entry_command(name: str,
                                   root: "Optional[Path]" = None) -> int:
    """``--remove-installed-entry ИМЯ``: ручная уборка записи из списка."""
    root = root or find_portable_root()
    try:
        cfg = read_launcher_config(root)
    except Exception:  # noqa: BLE001 - конфиг мог не читаться
        cfg = {}
    lines = forget_installed_entry(name, root, cfg)
    for line in lines:
        _run_log(root, "installed programs: " + line)
    report = "\n".join(lines)
    print(report)
    _show_info(report, "Список установленных программ")
    return 0 if all(line.startswith("удалена") for line in lines) else 1


# --- маркер в реестре и в настройках программы --------------------------------
#
# Маркер ``@@PORTABLE_ROOT@@`` — наш: он живёт в ``portable*.reg`` и подменяется
# текущим корнем при импорте. Но путь к маркеру может утечь на ПК:
# * ``Launch.bat`` без PowerShell импортирует файл целиком (ветка «не удалось
#   переписать»);
# * портатив собран прежней версией, где подстановки не было;
# * настройки скопировали с другого портатива вместе с реестром.
# Тогда программа (и её установщик обновления) видит каталог установки
# ``@@PORTABLE_ROOT@@\\App`` — такой папки нет, и установка падает с
# «Error opening file for writing». Поэтому при каждом запуске маркер
# разворачивается в текущий корень: и в записях об установке, и во всех
# захваченных ключах программы (включая VirtualStore-зеркала).

#: Сколько уровней вглубь просматривается внутри захваченного ключа.
REGISTRY_HEAL_MAX_DEPTH = 3
#: Потолок числа значений за один проход: запуск не должен зависать.
REGISTRY_HEAL_MAX_VALUES = 4000

_HIVE_NAMES = {
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKEY_USERS": "HKEY_USERS",
}


def _captured_registry_views(cfg: "Optional[Dict[str, Any]]" = None
                             ) -> "list[tuple[Any, str, int]]":
    """Ключи этого портатива (``registry.keys``) в виде открываемых путей."""
    reg = _winreg()
    if reg is None:
        return []
    registry = (cfg or {}).get("registry") or {}
    keys: "list[str]" = []
    for name in ("keys", "created_keys"):
        value = registry.get(name)
        if isinstance(value, (list, tuple)):
            keys.extend(str(item) for item in value if str(item).strip())
    views: "list[tuple[Any, str, int]]" = []
    seen = set()
    for key in keys:
        head, _, tail = key.strip().partition("\\")
        hive_name = _HIVE_NAMES.get(head.strip().upper())
        if not hive_name or not tail:
            continue
        hive = getattr(reg, hive_name, None)
        if hive is None:
            continue
        for extra in (0, getattr(reg, "KEY_WOW64_64KEY", 0),
                      getattr(reg, "KEY_WOW64_32KEY", 0)):
            access = reg.KEY_READ | reg.KEY_SET_VALUE | extra
            marker = (hive_name, tail.casefold(), extra)
            if marker in seen:
                continue
            seen.add(marker)
            views.append((hive, tail, access))
    return views


def _heal_registry_tree(reg, hive, path: str, access: int,
                        stale_roots: "Sequence[str]", root: Path,
                        names: "Sequence[str]", budget: "list[int]",
                        depth: int = 0) -> "list[str]":
    """Разворачивает маркер и прежние корни в значениях ключа и его подключах."""
    changed: "list[str]" = []
    if budget[0] <= 0:
        return changed
    try:
        with reg.OpenKey(hive, path, 0, access) as key:
            subkeys: "list[str]" = []
            index = 0
            while True:
                try:
                    subkeys.append(reg.EnumKey(key, index))
                except OSError:
                    break
                index += 1
            values: "list[tuple[str, Any, int]]" = []
            index = 0
            while True:
                try:
                    values.append(reg.EnumValue(key, index))
                except OSError:
                    break
                index += 1
            for name, value, kind in values:
                budget[0] -= 1
                if budget[0] <= 0:
                    break
                if kind not in (reg.REG_SZ, reg.REG_EXPAND_SZ):
                    continue
                if not isinstance(value, str) or not value:
                    continue
                fixed = retarget_record_text(value, stale_roots, str(root))
                if fixed == value and names:
                    fixed = replace_app_prefix(fixed, root, names)
                if fixed == value:
                    continue
                try:
                    reg.SetValueEx(key, name, 0, kind, fixed)
                except OSError:
                    continue
                changed.append(f"{path} :: {name or '(default)'}")
    except OSError:
        return changed
    if depth >= REGISTRY_HEAL_MAX_DEPTH:
        return changed
    for name in subkeys:
        if budget[0] <= 0:
            break
        changed.extend(_heal_registry_tree(
            reg, hive, path + "\\" + name, access, stale_roots, root, names,
            budget, depth + 1))
    return changed


def heal_host_registry(root: Path,
                       cfg: "Optional[Dict[str, Any]]" = None,
                       stale_roots: "Optional[Sequence[str]]" = None
                       ) -> "list[str]":
    """Правит реестр этого ПК до запуска программы и до установки обновления.

    Три вещи, из-за которых обновление уходит не туда:

    1. **Маркер** ``@@PORTABLE_ROOT@@`` в любом значении — разворачивается в
       текущий корень (``...\\App\\.exe`` сохраняется).
    2. **Прежнее место портатива** (``D:\\Portable\\Foo`` после переезда на
       ``E:``) — заменяется текущим корнем.
    3. **Несуществующая папка перед ``App``** у записи этой программы —
       заменяется текущим корнем (``replace_app_prefix``).

    Возвращает список исправленных значений для журнала. Мутирует только
    ``REG_SZ``/``REG_EXPAND_SZ`` и только если путь действительно указывает в
    прежнее место или содержит маркер.
    """
    if not IS_WINDOWS:
        return []
    settings = cfg or {}
    stale = list(stale_roots if stale_roots is not None
                 else remembered_roots(root, cfg))
    # Быстрая отсечка: править нечего, если папку не переносили (нет прежних
    # мест) и в захваченном реестре не осталось маркера корня. Обход ключей
    # даже с бюджетом в 4000 значений — это тысячи вызовов winreg, и раньше
    # он выполнялся при каждом запуске.
    section = settings.get("registry")
    token_possible = bool(isinstance(section, dict)
                          and section.get("has_root_token"))
    if not stale and not token_possible:
        return []
    reg = _winreg()
    if reg is None:
        return []
    names = _app_shortcut_names(root, settings)
    changed: "list[str]" = []
    try:
        changed.extend(retarget_host_install_records(stale, root, names))
    except Exception:  # noqa: BLE001 - реестр не срывает запуск
        pass
    budget = [REGISTRY_HEAL_MAX_VALUES]
    for hive, path, access in _captured_registry_views(settings):
        if budget[0] <= 0:
            break
        try:
            changed.extend(_heal_registry_tree(
                reg, hive, path, access, stale, root, names, budget))
        except OSError:
            continue
    return changed


# --- окно «идёт обновление» --------------------------------------------------

class _BusyNotice:
    """Окно с названием этапа и процентами, пока идёт долгая работа.

    Лончер собран без консоли и без GUI-библиотек. Обычное окно сообщения,
    показанное в фоновом потоке, прекрасно справляется: заголовок
    обновляется на лету (``SetWindowTextW``), а в конце окно закрывается
    само (``WM_CLOSE``). Кнопка «OK» его просто скрывает - обновление
    продолжается.
    """

    def __init__(self, title: str, text: str) -> None:
        self.base = title
        self.text = text
        self.token = f"[{os.getpid()}]"
        self.current = f"{title} {self.token}"
        self.thread = None

    def start(self) -> None:
        if not IS_WINDOWS:
            return
        import threading

        def show() -> None:  # pragma: no cover - нужен рабочий стол
            try:
                import ctypes

                MB_OK, MB_ICONINFORMATION = 0x0, 0x40
                MB_TOPMOST, MB_SETFOREGROUND = 0x40000, 0x10000
                ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                    None, self.text, self.current,
                    MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND)
            except Exception:  # noqa: BLE001
                pass

        self.thread = threading.Thread(target=show, daemon=True)
        self.thread.start()

    @staticmethod
    def _user32():  # pragma: no cover - нужен Windows
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        user32.FindWindowW.restype = wintypes.HWND
        user32.SetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
        user32.PostMessageW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        return user32

    def update(self, stage: str) -> None:
        if not IS_WINDOWS or self.thread is None:
            return
        try:
            import ctypes

            user32 = self._user32()
            hwnd = user32.FindWindowW(None, self.current)
            new_title = f"{self.base} - {stage} {self.token}"
            if hwnd and user32.SetWindowTextW(hwnd, new_title):
                self.current = new_title
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        if not IS_WINDOWS or self.thread is None:
            return
        try:
            import ctypes

            user32 = self._user32()
            hwnd = user32.FindWindowW(None, self.current)
            if hwnd:
                user32.PostMessageW(hwnd, 0x0010, 0, 0)
            self.thread.join(timeout=3.0)
        except Exception:  # noqa: BLE001
            pass


def _ask_yes_no(message: str, title: str = "Portable Launcher") -> bool:
    """Вопрос «Да/Нет». Без рабочего стола ответ всегда «нет»: молча менять
    файлы программы лончер не вправе."""
    if not IS_WINDOWS or _ui_disabled():
        return False
    try:
        import ctypes

        MB_YESNO, MB_ICONQUESTION, MB_TOPMOST = 0x4, 0x20, 0x40000
        IDYES = 6
        return ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
            None, message, title, MB_YESNO | MB_ICONQUESTION | MB_TOPMOST
        ) == IDYES
    except Exception:  # noqa: BLE001
        return False


def _show_info(message: str, title: str = "Portable Launcher") -> None:
    if _ui_disabled():
        try:
            print(message, file=sys.stderr)
        except Exception:  # noqa: BLE001
            pass
        return
    if IS_WINDOWS:
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                None, message, title, 0x40 | 0x40000)
            return
        except Exception:  # noqa: BLE001
            pass
    try:
        print(message, file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass


# --- загрузка установщика -----------------------------------------------------

def _authenticode_status(path: Path) -> Optional[str]:
    """Статус подписи Windows (``Valid``, ``NotSigned``...) или ``None``."""
    if not IS_WINDOWS:
        return None
    try:
        completed = subprocess.run(  # noqa: S603
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-AuthenticodeSignature -LiteralPath $env:PORTABLE_CHECK)"
             ".Status"],
            capture_output=True, text=True, timeout=120,
            creationflags=NO_WINDOW,
            env={**os.environ, "PORTABLE_CHECK": str(path)})
        status = completed.stdout.strip()
        return status or None
    except Exception:  # noqa: BLE001
        return None


def download_installer(url: str, destination: Path,
                       progress: "Optional[Any]" = None,
                       opener: "Optional[Any]" = None) -> Path:
    """Скачивает установщик в ``destination`` (через ``.part``).

    ``progress(done_bytes, total_bytes)`` вызывается по ходу. Недокачанный
    файл никогда не остаётся под настоящим именем: оборванное соединение не
    должно превратиться в «установщик».
    """
    import urllib.request

    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    request = urllib.request.Request(
        url, headers={"User-Agent": "PortableLauncher/1.0"})
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=60) as response, \
                partial.open("wb") as out:
            total = int(response.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
        if total and done != total:
            raise OSError(f"скачано {done} байт из {total}")
        if done == 0:
            raise OSError("сервер вернул пустой файл")
        os.replace(partial, destination)
    except Exception:
        _remove_file(partial)
        raise
    return destination


def _download_name(url: str) -> str:
    from urllib.parse import urlparse, unquote

    name = Path(unquote(urlparse(url).path)).name
    return name if name.lower().endswith((".exe", ".msi")) else "Update.exe"


# --- само обновление ---------------------------------------------------------

class UpdateResult:
    def __init__(self) -> None:
        self.ok = False
        self.message = ""
        self.backup: Optional[Path] = None
        self.traces: "list[str]" = []

    def fail(self, message: str) -> "UpdateResult":
        self.ok = False
        self.message = message
        return self


def _pid_alive(pid: int) -> bool:
    """Жив ли процесс ``pid`` (другой экземпляр, делающий обновление)."""
    if pid <= 0:
        return False
    if IS_WINDOWS:
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                code = ctypes.c_ulong()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return False
                return code.value == 259  # STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        except Exception:  # noqa: BLE001
            return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _journal_path(root: Path) -> Path:
    return root / UPDATE_DIR_NAME / UPDATE_JOURNAL_NAME


def _read_journal(root: Path) -> "Dict[str, Any]":
    try:
        data = json.loads(_journal_path(root).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_journal(root: Path, data: "Dict[str, Any]") -> None:
    try:
        path = _journal_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=1),
                             encoding="utf-8")
        os.replace(temporary, path)
    except OSError:
        pass


def _move_with_retry(source: Path, destination: Path, attempts: int = 6) -> None:
    """Перенос с повторами: сканер антивируса держит свежие файлы секунды."""
    import time

    last: Optional[OSError] = None
    for attempt in range(attempts):
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(1.0)
    assert last is not None
    raise last


def _protected_names(cfg: Dict[str, Any]) -> "set[str]":
    names = {"launchportable.exe", "saves"}
    settings = update_settings(cfg)
    names.update(Path(p.replace("\\", "/")).name.casefold()
                 for p in settings["preserve"])
    for alias in (cfg.get("launcher_aliases") or {}):
        names.add(Path(str(alias)).name.casefold())
    return names


def _rollback_journal(root: Path, journal: "Dict[str, Any]") -> "list[str]":
    """Возвращает App к состоянию до подмены. Идемпотентно."""
    app_dir = root / "App"
    backup = root / UPDATE_DIR_NAME / "backup"
    problems: "list[str]" = []
    for name in list(journal.get("added", [])):
        path = app_dir / name
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        except OSError as exc:
            problems.append(f"{name}: {exc}")
    for name in list(journal.get("replaced", [])):
        saved = backup / name
        if not saved.exists():
            continue
        path = app_dir / name
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
            _move_with_retry(saved, path)
        except OSError as exc:
            problems.append(f"{name}: {exc}")
    return problems


def _default_installer_runner(command: str, env: "Dict[str, str]", cwd: str,
                              timeout: float) -> Optional[int]:
    """Запускает установщик и ждёт его завершения. ``None`` - таймаут."""
    process = subprocess.Popen(  # noqa: S603
        command, cwd=cwd, env=env, creationflags=NO_WINDOW,
        stdin=subprocess.DEVNULL)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        return None


def remembered_roots(root: Path,
                     cfg: "Optional[Dict[str, Any]]" = None) -> "list[str]":
    """Прежние места этой портативной папки.

    Лончер пишет штамп ``PortableData/portable-root.json``: там текущий корень
    и, если папку уже переносили, предыдущий. Это единственное надёжное
    указание на «тот самый прежний диск», куда установщик мог запомнить
    каталог установки. Порядок — от свежего к старому.
    """
    found: "list[str]" = _remembered_root_list(root)
    section = (cfg or {}).get("relative_paths")
    if isinstance(section, dict):
        extra = section.get("previous_roots")
        if isinstance(extra, (list, tuple)):
            found.extend(str(item) for item in extra if str(item).strip())
    current = _root_key(root)
    return [text for text in _unique_roots(found) if _root_key(text) != current]


def _same_portable(candidate: Path, cfg: Dict[str, Any]) -> bool:
    """Прежнее место принадлежит этой же программе (а не соседней папке)."""
    try:
        data = read_launcher_config(candidate)
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return (str(data.get("app_name", "")).strip().casefold()
            == str(cfg.get("app_name", "")).strip().casefold())


def adopt_stale_install(stale_root: Path, stage: Path, cfg: Dict[str, Any],
                        since: float) -> "list[str]":
    """Забирает в ``stage`` свежие файлы, поставленные в прежнее место.

    Установщик может проигнорировать переданный каталог и поставить новую
    версию туда, где портатив лежал раньше (он помнит этот путь в своих
    настройках). Тогда обновление формально «удалось», но текущая папка
    осталась прежней. Здесь только **копируются** файлы, изменённые после
    начала обновления, и только из папки, которая доказуемо является прежним
    местом этой же программы (совпадает ``app_name`` в конфиге). Ничего не
    удаляется: старая папка остаётся на усмотрение пользователя.
    """
    copied: "list[str]" = []
    app = stale_root / "App"
    if not app.is_dir() or not _same_portable(stale_root, cfg):
        return copied
    for current, dirs, files in os.walk(app):
        dirs[:] = [name for name in dirs
                   if name.casefold() not in ("saves", "portabledata", "updates")]
        for name in files:
            source = Path(current) / name
            try:
                if source.stat().st_mtime < since - STALE_MTIME_GRACE:
                    continue
            except OSError:
                continue
            relative = source.relative_to(app)
            destination = stage / relative
            if destination.exists():
                continue
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            except OSError:
                continue
            copied.append(str(relative).replace("\\", "/"))
    return copied


def _copy_tree_into(source: Path, stage: Path,
                    skip_names: "set[str]") -> "list[str]":
    """Копирует содержимое ``source`` в ``stage``, не перезаписывая файлы."""
    copied: "list[str]" = []
    for current, dirs, files in os.walk(source):
        dirs[:] = [name for name in dirs
                   if name.casefold() not in ("saves", "portabledata", "updates",
                                              "node_modules.cache")]
        for name in files:
            if name.casefold() in skip_names:
                continue
            src = Path(current) / name
            relative = src.relative_to(source)
            destination = stage / relative
            if destination.exists():
                continue
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, destination)
            except OSError:
                continue
            copied.append(str(relative).replace("\\", "/"))
    return copied


def adopt_from_redirected_profile(root: Path, cfg: Dict[str, Any], stage: Path,
                                  since: float) -> "list[str]":
    """Забирает в ``stage`` программу, поставленную мимо ``/DIR``.

    Установщик обновления запускается с перенаправленным профилем: его
    ``LOCALAPPDATA``, ``APPDATA``, ``USERPROFILE`` и ``PROGRAMDATA`` указывают
    внутрь ``PortableData``. Поэтому установщик, который вообще не понимает
    ключ каталога (или игнорирует его в режиме обновления), всё равно ставит
    новую версию **внутрь портатива** — но не в ``Updates\\stage``. Раньше
    это выглядело как «обновление не установилось»: файлы лежали в
    перенаправленном профиле, а ``App`` оставался прежним.

    Здесь такие свежие файлы находятся и переносятся в ``stage``: дальше
    работает обычная проверка и подмена ``App`` с откатом.
    """
    rel = _app_relative_target(cfg)
    if not rel:
        return []
    parts = rel.split("/")
    wanted = parts[-1].casefold()
    depth = len(parts) - 1
    data = _data_dir(root, cfg)
    bases = [data / "AppData" / "Local" / "Programs",
             data / "AppData" / "Local",
             data / "AppData" / "Roaming",
             data / "ProgramData",
             data / "User"]
    skip = {"temp", "cache", "caches", "gpucache", "codecache", "shadercache",
            "crashpad", "logs", "registry", "registryhostbackup"}
    skip_names = {"launchportable.exe", "saves"}
    for base in bases:
        if not base.is_dir():
            continue
        for current, dirs, files in os.walk(base):
            dirs[:] = [name for name in dirs if name.casefold() not in skip]
            matches = [name for name in files if name.casefold() == wanted]
            if not matches:
                continue
            exe = Path(current) / matches[0]
            try:
                if exe.stat().st_mtime < since - STALE_MTIME_GRACE:
                    continue
            except OSError:
                continue
            payload = exe.parent
            for _ in range(depth):
                payload = payload.parent
            copied = _copy_tree_into(payload, stage, skip_names)
            if copied:
                return copied
    return []


# --- обновление, поставленное в ПРЕЖНЕЕ место портатива -----------------------

#: Файл с временем начала сеанса: по нему видно, что появилось ЗА сеанс.
SESSION_MARKER_NAME = "session-start.json"

#: Журнал перенесённых файлов (для журнала лончера и разбора).
ADOPTED_LOG_NAME = "adopted-from-previous.log"


def _session_marker(root: Path) -> Path:
    return _data_dir(root, {}) / SESSION_MARKER_NAME


def _read_session_start(root: Path) -> float:
    """Время начала прошлого сеанса (0.0, если отметки нет)."""
    try:
        data = json.loads(_session_marker(root).read_text(encoding="utf-8"))
        return float(data.get("started", 0.0) or 0.0)
    except (OSError, ValueError, TypeError):
        return 0.0


def write_session_start(root: Path,
                        started: "Optional[float]" = None) -> float:
    """Отмечает начало сеанса; возвращает записанное время."""
    import time

    moment = time.time() if started is None else float(started)
    try:
        path = _session_marker(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "started": moment,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(moment)),
            "pid": os.getpid(),
            "root": str(root),
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
    return moment


def _same_size_different_content(left: Path, right: Path) -> bool:
    """Сравнивает файлы, когда размер и время совпали (грубая ФС)."""
    try:
        with left.open("rb") as one, right.open("rb") as two:
            while True:
                block = one.read(65536)
                if block != two.read(65536):
                    return True
                if not block:
                    return False
    except OSError:
        return False


def _same_app_location(cfg: "Optional[Dict[str, Any]]", candidate: Path) -> bool:
    """Прежнее место принадлежит этой же портативной программе.

    Рядом на диске может лежать другой портатив (соседняя папка, другая
    программа). Его ``App`` — не источник обновления: там свои файлы.
    Сверяем имя программы и файл запуска из ``launcher_config.json``.
    """
    try:
        other = read_launcher_config(candidate)
    except (OSError, ValueError):
        return True  # своей настройки нет — доверяем штампу переноса
    if not isinstance(other, dict) or not cfg:
        return True
    for key in ("target_exe_rel", "app_name"):
        mine = str((cfg or {}).get(key) or "").strip().casefold()
        theirs = str(other.get(key) or "").strip().casefold()
        if mine and theirs and mine != theirs:
            return False
    return True


def stale_app_dirs(root: Path,
                   cfg: "Optional[Dict[str, Any]]" = None) -> "list[Path]":
    """Каталоги ``App`` в прежних местах этой же портативной папки."""
    found: "list[Path]" = []
    for item in remembered_roots(root, cfg):
        candidate = Path(item)
        app = candidate / "App"
        if not app.is_dir():
            continue
        if app.resolve() == (root / "App").resolve():
            continue
        if not _same_app_location(cfg, candidate):
            continue
        found.append(app)
    return found


def adopt_updates_from_previous_locations(root: Path,
                                          cfg: "Optional[Dict[str, Any]]" = None,
                                          since: float = 0.0,
                                          backup: "Optional[Path]" = None
                                          ) -> "list[str]":
    """Забирает в ``App`` файлы, которые обновление положило в прежнее место.

    Жалоба: портатив собран в ``D:\\Portable\\Baalda_0.1.87_Portable``,
    папку перенесли в ``E:\\Backup\\Apps\\Portable``, а встроенное
    обновление программы поставило новую версию **по прежнему адресу**
    (``D:\\Portable\\Baalda_0.1.87_Portable\\App``). Предотвратить это
    удаётся не всегда: установщик может запускать сама программа, со своим
    файлом ответов и своим пониманием «прошлой установки». Поэтому лончер
    дополнительно **забирает** свежие файлы из прежнего места в текущее —
    обновление оказывается там, где портатив лежит сейчас.

    Копируются только файлы, изменённые после ``since`` (начало сеанса):
    то, что лежало в старой копии давно, не переносится. Заменяемые файлы
    сохраняются в ``Updates\\backup-previous`` — откат возможен вручную.
    Файлы прежнего места не удаляются: это решает пользователь.
    """
    app_dir = root / "App"
    if not app_dir.is_dir() or since <= 0:
        return []
    backup = backup or (root / UPDATE_DIR_NAME / "backup-previous")
    protected = {"launchportable.exe", "saves"}
    copied: "list[str]" = []
    for stale_app in stale_app_dirs(root, cfg):
        # Дешёвая отсечка: у папки, в которую ничего не писали с начала
        # сеанса, время изменения старше этого начала. Обход всего прежнего
        # App (у Cursor — сотни тысяч файлов, и каждый ещё и stat) выполнялся
        # при КАЖДОМ запуске и занимал секунды; теперь он нужен только тогда,
        # когда установщик действительно что-то туда положил.
        try:
            if stale_app.stat().st_mtime < since - STALE_MTIME_GRACE:
                continue
        except OSError:
            continue
        for current, dirs, files in os.walk(stale_app):
            dirs[:] = [name for name in dirs
                       if name.casefold() not in ("saves", "portabledata",
                                                  "updates")]
            for name in sorted(files):
                source = Path(current) / name
                try:
                    stat = source.stat()
                except OSError:
                    continue
                if stat.st_mtime < since - STALE_MTIME_GRACE:
                    continue
                relative = source.relative_to(stale_app)
                if relative.parts and relative.parts[0].casefold() in protected:
                    continue
                destination = app_dir / relative
                try:
                    if destination.exists():
                        target_stat = destination.stat()
                        if (target_stat.st_size == stat.st_size
                                and target_stat.st_mtime >= stat.st_mtime
                                and not _same_size_different_content(
                                    source, destination)):
                            continue
                        saved = backup / relative
                        if not saved.exists():
                            saved.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(destination, saved)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
                except OSError:
                    continue
                copied.append(str(relative).replace("\\", "/"))
    if copied:
        log = _data_dir(root, {}) / ADOPTED_LOG_NAME
        try:
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a", encoding="utf-8") as handle:
                handle.write(
                    f"[{__import__('time').strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"adopted {len(copied)} file(s) from the previous "
                    f"location into {app_dir}\n")
                for item in copied:
                    handle.write("  " + item + "\n")
        except OSError:
            pass
    return copied


def _report_removed_shortcuts(root: Path, removed: "Sequence[str]") -> None:
    """Пишет в журнал, какие ярлыки убраны и почему."""
    if not removed:
        return
    names = ", ".join(Path(item).name for item in removed[:8])
    more = "" if len(removed) <= 8 else f" (+{len(removed) - 8})"
    _update_log(root, f"removed {len(removed)} shortcut(s) created by the "
                      f"installer: {names}{more}")


def apply_update(root: Path, cfg: Dict[str, Any], installer: Path,
                 progress: "Optional[Any]" = None,
                 runner: "Optional[Any]" = None) -> UpdateResult:
    """Ставит новую версию программы внутрь портатива.

    Порядок продуман так, чтобы в любой момент можно было вернуться назад:
    установка идёт во временную папку, App не трогается, пока там не
    появилась рабочая программа, а подмена записывается в журнал.

    Переносимость: перед установкой пути прежнего корня внутри портатива
    переписываются на текущий (та же починка, что при запуске), установщику
    передаётся явный каталог и в собственных ключах, а если он всё равно
    поставил новую версию в прежнее место — свежие файлы переносятся в
    портатив оттуда (см. :func:`adopt_stale_install`).
    """
    import time

    result = UpdateResult()
    say = progress or (lambda text: None)
    settings = update_settings(cfg)
    app_dir = root / "App"
    updates = root / UPDATE_DIR_NAME
    stage = updates / "stage"
    backup = updates / "backup"
    run_installer = runner or _default_installer_runner

    if not installer.is_file():
        return result.fail(f"Установщик не найден: {installer}")
    if not app_dir.is_dir():
        return result.fail(f"В портативе нет папки App: {app_dir}")

    started = time.time()
    # Перенос между дисками: путь прежнего корня внутри портатива (настройки
    # программы, импортированный реестр) заменяется текущим ДО установщика —
    # иначе он возьмёт каталог оттуда и поставит новую версию по старому
    # адресу. Та же починка выполняется при обычном запуске, но обновление
    # может быть первым действием после копирования папки.
    stale_roots = remembered_roots(root, cfg)
    try:
        for line in repair_paths(root, cfg, force=True, deep=True):
            _update_log(root, line)
    except Exception as exc:  # noqa: BLE001 - починка не срывает обновление
        _update_log(root, f"paths: repair before update failed ({exc})")
    if stale_roots:
        _update_log(root, "previous location(s) of this portable: "
                    + ", ".join(stale_roots))

    shutdown = shutdown_settings(cfg)
    say("закрываю программу")
    _update_log(root, f"update started from {installer.name}")
    release_portable_folder(root, shutdown)
    if IS_WINDOWS and _portable_process_list(root):
        return result.fail(
            "Не удалось закрыть программу из портативной папки. Закройте её "
            "и повторите обновление.")

    # Записи об установке на этом ПК: установщик ищет «прошлую версию»
    # именно там. Если запись помнит прежний диск портатива, новая версия
    # встанет по старому адресу — переводим её на текущий корень.
    try:
        moved = heal_host_registry(root, cfg, stale_roots)
    except Exception as exc:  # noqa: BLE001 - реестр не должен срывать обновление
        moved = []
        _update_log(root, f"install records: retarget failed ({exc})")
    try:
        marker_files = expand_root_token_in_files(root, cfg, deep=True)
    except Exception as exc:  # noqa: BLE001 - проход не срывает обновление
        marker_files = []
        _update_log(root, f"paths: marker sweep failed ({exc})")
    if marker_files:
        _update_log(
            root, "paths: the portable marker is replaced in "
            f"{len(marker_files)} file(s)" + (": "
            + ", ".join(marker_files[:5])
            + (" ..." if len(marker_files) > 5 else "")))
    if moved:
        _update_log(
            root,
            f"install records of the previous location now point to {root}: "
            + ", ".join(moved[:5]) + (" ..." if len(moved) > 5 else ""))

    updates.mkdir(parents=True, exist_ok=True)
    _clear_dir(stage)
    stage.mkdir(parents=True, exist_ok=True)
    journal: "Dict[str, Any]" = {
        "state": "installing", "installer": installer.name,
        "pid": os.getpid(),
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        "replaced": [], "added": [],
    }
    _write_journal(root, journal)

    engine = settings["engine"] or installer_engine(installer)
    log_file = _data_dir(root, cfg) / "installer-update.log"
    commands = install_commands(installer, stage, engine, settings, log_file,
                                stale_roots=stale_roots, portable_root=root)
    _update_log(root, f"installer engine: {engine}; {len(commands)} command(s)")

    # Ярлыки: обновление не должно оставлять на рабочем столе статичный
    # ярлык, ведущий в прежнее место папки. Убираются только файлы,
    # появившиеся за время установки и указывающие внутрь портатива.
    shortcuts = ShortcutGuard(
        root, extra_roots=stale_roots,
        folders=_shortcut_folders_for(root, cfg),
        app_names=_app_shortcut_names(root, cfg))
    shortcuts.snapshot()

    guard = HostTraceGuard()
    guard.snapshot()
    env = _prepare_environment(root, cfg)
    payload: Optional[Path] = None
    failures: "list[str]" = []
    try:
        for label, command in commands:
            say(f"устанавливаю новую версию ({label})")
            _update_log(root, f"running: {command}")
            try:
                code = run_installer(command, env, str(updates),
                                     settings["timeout"])
            except OSError as exc:
                failures.append(f"{label}: не запустился ({exc})")
                _update_log(root, failures[-1])
                continue
            # Установщик мог запустить только что поставленную программу.
            release_portable_folder(root, shutdown)
            payload = locate_payload(stage, cfg)
            if payload is not None and code in UPDATE_OK_CODES:
                _update_log(root, f"{label}: installed, code {code}")
                break
            payload = None
            failures.append(f"{label}: код {code}")
            _update_log(root, f"{label}: no usable result (code {code})")
            _clear_dir(stage)
            stage.mkdir(parents=True, exist_ok=True)
    finally:
        # The legacy cleanup hook is intentionally a no-op: third-party
        # installer changes must not be removed based on broad snapshots.
        guard.restore()
        _report_removed_shortcuts(root, shortcuts.cleanup())
        result.traces = []
        _update_log(
            root,
            "automatic host-trace cleanup is disabled; review Windows "
            "changes made by the third-party installer manually")

    if payload is None:
        # Установщик мог поставить новую версию в прежнее место портатива:
        # собственные ключи, забытый явный каталог или настройки программы.
        # Свежие файлы забираются оттуда в stage — обновление всё равно
        # окажется в папке на текущем диске.
        for stale in stale_roots:
            copied = adopt_stale_install(Path(stale), stage, cfg, started)
            if not copied:
                continue
            _update_log(
                root,
                f"the installer wrote the new version to the previous "
                f"location {stale}; adopted {len(copied)} file(s) into the "
                "portable: " + ", ".join(copied[:8])
                + (" ..." if len(copied) > 8 else ""))
            payload = locate_payload(stage, cfg)
            if payload is not None:
                break

    if payload is None:
        # Установщик не понял ключ каталога и поставил программу в
        # перенаправленный профиль внутри PortableData. Забираем оттуда.
        try:
            copied = adopt_from_redirected_profile(root, cfg, stage, started)
        except Exception as exc:  # noqa: BLE001 - поиск не должен срывать обновление
            copied = []
            _update_log(root, f"profile search failed ({exc})")
        if copied:
            _update_log(
                root, "the installer ignored the target folder and wrote "
                f"{len(copied)} file(s) into the portable profile; adopted "
                "them into Updates/stage: " + ", ".join(copied[:8])
                + (" ..." if len(copied) > 8 else ""))
            payload = locate_payload(stage, cfg)

    if payload is None:
        journal["state"] = "failed"
        _write_journal(root, journal)
        _clear_dir(stage)
        return result.fail(
            "Установщик не положил программу в папку: "
            + ("; ".join(failures) or "нет результата") + ". Портатив не "
            "изменён. Подробности: PortableData\\" + UPDATE_LOG_NAME)

    say("заменяю файлы программы")
    journal["state"] = "swapping"
    _clear_dir(backup)
    backup.mkdir(parents=True, exist_ok=True)
    protected = _protected_names(cfg)
    try:
        for entry in sorted(payload.iterdir(), key=lambda p: p.name.casefold()):
            if entry.name.casefold() in protected:
                continue
            target = app_dir / entry.name
            if target.exists() or target.is_symlink():
                _move_with_retry(target, backup / entry.name)
                journal["replaced"].append(entry.name)
            else:
                journal["added"].append(entry.name)
            _write_journal(root, journal)
            _move_with_retry(entry, target)
    except OSError as exc:
        _update_log(root, f"swap failed: {exc}; rolling back")
        problems = _rollback_journal(root, journal)
        journal["state"] = "rolled-back" if not problems else "rollback-failed"
        _write_journal(root, journal)
        _clear_dir(stage)
        suffix = ("" if not problems else " Откат прошёл не полностью: "
                  + "; ".join(problems[:3]) + ".")
        return result.fail(
            f"Не удалось заменить файлы ({exc}). Прежняя версия возвращена."
            + suffix)

    journal["state"] = "done"
    _write_journal(root, journal)
    _clear_dir(stage)
    if settings["keep_backup"]:
        result.backup = backup
    else:
        _clear_dir(backup)
    # Всё, что осталось от «родного» обновления, больше не нужно: иначе
    # программа при старте решит, что обновление не закончено.
    quarantine_staged_update(root, cfg)
    for leftover in sorted((root / UPDATE_DIR_NAME).glob("*")):
        if (leftover.is_file() and leftover.suffix.lower() in (".exe", ".msi")
                and leftover.resolve() == installer.resolve()):
            _remove_file(leftover)
    _forget_pending(root)
    purge_portable_temp(root, cfg)
    # Установщик мог запустить только что поставленную программу, а она —
    # положить ярлык на рабочий стол. Проверяем ещё раз уже после подмены:
    # и то, что появилось за время установки, и «пустые» ярлыки этой
    # программы, чья цель уже не существует.
    _report_removed_shortcuts(root, shortcuts.cleanup())
    _report_removed_shortcuts(root, shortcuts.sweep())
    result.ok = True
    result.message = ("Программа обновлена внутри портатива."
                      + (" Прежняя версия сохранена в папке Updates\\backup "
                         "(команда --rollback вернёт её; папку можно удалить, "
                         "чтобы освободить место)." if result.backup else ""))
    _update_log(root, "update finished successfully")
    return result


def rollback_update(root: Path, cfg: Dict[str, Any]) -> UpdateResult:
    """Возвращает версию, сохранённую при последнем обновлении."""
    result = UpdateResult()
    journal = _read_journal(root)
    backup = root / UPDATE_DIR_NAME / "backup"
    if not journal or not (journal.get("replaced") or journal.get("added")):
        return result.fail("Нет сохранённой прежней версии: откатывать нечего.")
    if journal.get("state") == "rolled-back":
        return result.fail("Откат уже выполнен.")
    if journal.get("replaced") and not backup.is_dir():
        return result.fail("Папка Updates\\backup удалена: откатывать не из чего.")
    release_portable_folder(root, shutdown_settings(cfg))
    problems = _rollback_journal(root, journal)
    if problems:
        return result.fail("Откат прошёл не полностью: "
                           + "; ".join(problems[:3]))
    journal["state"] = "rolled-back"
    _write_journal(root, journal)
    _clear_dir(backup)
    result.ok = True
    result.message = "Прежняя версия программы возвращена."
    _update_log(root, "rolled back to the previous version")
    return result


def recover_interrupted_update(root: Path, cfg: Dict[str, Any]) -> Optional[str]:
    """Доводит до конца обновление, прерванное принудительным завершением.

    ``swapping`` - подмена файлов началась, но не закончилась: App
    наполовину новый, наполовину старый, и единственный верный ход - вернуть
    сохранённое. ``installing`` - до App дело не дошло, достаточно убрать
    недоустановленную временную папку.
    """
    journal = _read_journal(root)
    state = journal.get("state")
    if state in ("installing", "swapping"):
        # Обновление, которое ещё идёт в ДРУГОМ процессе (UpdatePortable.cmd
        # и параллельный запуск программы), откатывать нельзя.
        try:
            owner = int(journal.get("pid", 0))
        except (TypeError, ValueError):
            owner = 0
        if owner and owner != os.getpid() and _pid_alive(owner):
            return None
    if state == "installing":
        _clear_dir(root / UPDATE_DIR_NAME / "stage")
        journal["state"] = "failed"
        _write_journal(root, journal)
        _update_log(root, "an interrupted installation was cleaned up; "
                    "the portable folder was not changed")
        return ("Прошлое обновление было прервано до замены файлов. "
                "Портатив не изменён.")
    if state == "swapping":
        problems = _rollback_journal(root, journal)
        journal["state"] = "rollback-failed" if problems else "rolled-back"
        _write_journal(root, journal)
        _clear_dir(root / UPDATE_DIR_NAME / "stage")
        _update_log(root, "an interrupted file swap was rolled back"
                    + (": " + "; ".join(problems[:3]) if problems else ""))
        if problems:
            return ("Прошлое обновление было прервано, а вернуть прежнюю "
                    "версию полностью не удалось: " + "; ".join(problems[:3])
                    + ". Запустите UpdatePortable.cmd - программа будет "
                    "установлена заново.")
        return ("Прошлое обновление было прервано посреди замены файлов. "
                "Прежняя версия возвращена, программа запустится как раньше.")
    return None


def _find_installer(root: Path, cfg: Dict[str, Any]) -> Optional[Path]:
    """Готовый установщик: оставленный перехватом, в Updates или скачанный."""
    pending = pending_installer(root)
    if pending is not None:
        return pending
    folder = root / UPDATE_DIR_NAME
    found = []
    if folder.is_dir():
        found = [p for p in folder.iterdir()
                 if p.is_file() and p.suffix.lower() in (".exe", ".msi")]
    found.extend(staged_installers(root, cfg))
    found.sort(key=_mtime, reverse=True)
    return found[0] if found else None


def run_update(root: Path, cfg: Dict[str, Any], source: str = "",
               interactive: bool = True, confirm_download: bool = True,
               runner: "Optional[Any]" = None,
               downloader: "Optional[Any]" = None) -> UpdateResult:
    """Весь сценарий: найти или скачать установщик, показать ход, поставить.

    ``source`` - путь к установщику или ``http(s)``-адрес; пусто - взять
    готовый (оставленный перехватом, лежащий в ``Updates``) или скачать по
    ``source_url`` из настроек.
    """
    settings = update_settings(cfg)
    result = UpdateResult()
    downloaded: Optional[Path] = None
    installer: Optional[Path] = None
    url = ""
    if source.lower().startswith(("http://", "https://")):
        url = source
    elif source:
        installer = Path(source)
        if not installer.is_file():
            return result.fail(f"Файл установщика не найден: {source}")
    else:
        installer = _find_installer(root, cfg)
        if installer is None:
            url = settings["source_url"]
    if installer is None and not url:
        return result.fail(
            "Нет установщика новой версии. Положите его в папку Updates, "
            "перетащите на UpdatePortable.cmd или запустите "
            "App\\LaunchPortable.exe --update <файл или ссылка>.")
    if url and confirm_download and interactive and not _ask_yes_no(
            f"Скачать новую версию программы с адреса\n{url}\n"
            "и установить её внутрь портатива?\n\n"
            "Данные и настройки (PortableData) не затрагиваются, прежняя "
            "версия сохраняется для отката.\n\n"
            + UPDATE_HOST_CHANGE_WARNING):
        return result.fail("Обновление отменено.")

    notice = _BusyNotice(
        "Обновление портатива",
        "Идёт обновление программы внутри портативной папки.\n\n"
        "Не выключайте компьютер и не вынимайте флешку. Окно закроется "
        "само; ход работы пишется в PortableData\\" + UPDATE_LOG_NAME + ".")
    if interactive:
        notice.start()
    try:
        if url:
            target = root / UPDATE_DIR_NAME / _download_name(url)
            fetch = downloader or download_installer

            def report(done: int, total: int) -> None:
                if total:
                    notice.update(f"скачиваю {done * 100 // total}%")
                else:
                    notice.update(f"скачиваю {done // (1024 * 1024)} МБ")

            _update_log(root, f"downloading {url}")
            try:
                downloaded = fetch(url, target, report)
            except Exception as exc:  # noqa: BLE001 - сеть бывает любой
                _update_log(root, f"download failed: {exc}")
                return result.fail(f"Не удалось скачать установщик: {exc}")
            status = _authenticode_status(downloaded)
            if status in ("NotSigned", "HashMismatch"):
                _remove_file(downloaded)
                _update_log(root, f"signature check failed: {status}")
                return result.fail(
                    "Скачанный файл не прошёл проверку цифровой подписи "
                    f"({status}); он удалён и не будет запущен.")
            if status not in (None, "Valid"):
                _update_log(root, f"signature status: {status} (not blocking)")
            installer = downloaded
        assert installer is not None
        return apply_update(root, cfg, installer, progress=notice.update,
                            runner=runner)
    finally:
        notice.close()


def offer_recovery(root: Path, cfg: Dict[str, Any],
                   ask: "Optional[Any]" = None,
                   updater: "Optional[Any]" = None) -> Optional[str]:
    """Предстартовая проверка: не осталось ли следов прерванного обновления.

    Именно это состояние остаётся после «зависло - закрыл через диспетчер
    задач»: маркер ``upgraded`` и недоустановленный OllamaSetup.exe. Они
    сами по себе роняют программу при старте, а App мог остаться
    наполовину обновлённым. Следы убираются, а пользователю предлагается
    поставить программу заново - правильно, внутрь портатива.
    """
    settings = update_settings(cfg)
    if not settings["enabled"]:
        return None
    ask = ask or _ask_yes_no
    notes: "list[str]" = []
    # Дешёвые проверки файлов - первыми: у обычного запуска их результат
    # пуст, и список процессов (дорогой) строить не нужно.
    journal_state = _read_journal(root).get("state")
    markers = update_markers(root, cfg)
    leftovers = _glob_in_data(root, cfg, settings["handoff"])
    staged = staged_installers(root, cfg)
    pending, declined, pending_interrupted = _pending_state(root)
    if not (markers or leftovers or staged or pending
            or journal_state in ("installing", "swapping")):
        return None
    if _portable_process_list(root):
        return None  # второй экземпляр программы: ничего не трогаем
    interrupted = recover_interrupted_update(root, cfg)
    if interrupted:
        notes.append(interrupted)
        if IS_WINDOWS:
            _show_info(interrupted)
    if not (markers or leftovers or staged or pending):
        return "\n".join(notes) or None

    stop_stray_installers(root, cfg)
    kept, clean = quarantine_staged_update(root, cfg)
    installer = kept or pending
    # Прерванным обновление считается, если остались следы ЗАПУСКА установщика
    # (метка, рабочая копия) или перехват не довёл дело до конца. Просто
    # скачанная программой новая версия - обычная ситуация «обновление
    # готово», об отказе от неё спрашивать каждый запуск не нужно.
    interrupted_update = bool(
        markers or leftovers
        or (pending and pending_interrupted and not declined))
    _update_log(root, "found traces of the program's own update: "
                f"markers={len(markers)}, started installers={len(leftovers)}, "
                f"downloaded={len(staged)}; portable staging cleanup "
                + ("complete" if clean else "incomplete")
                + "; host registry, shortcuts and environment are not cleaned")
    if installer is not None and declined and not interrupted_update:
        return "\n".join(notes) or None
    if installer is None and not interrupted_update:
        return "\n".join(notes) or None

    if installer is not None and interrupted_update:
        question = (
            "Обновление программы было прервано, а в портативной папке "
            f"остался скачанный установщик ({installer.name}).\n\n"
            "Установить новую версию сейчас - правильно, внутрь портатива? "
            "Это займёт несколько минут. Данные и настройки не "
            "затрагиваются, прежняя версия сохранится для отката.\n\n"
            + UPDATE_HOST_CHANGE_WARNING)
    elif installer is not None:
        question = (
            "Программа скачала новую версию "
            f"({installer.name}).\n\nУстановить её сейчас внутрь портатива? "
            "Это займёт несколько минут. Данные и настройки не "
            "затрагиваются, прежняя версия сохранится для отката.\n\n"
            "Если отказаться, файл останется в папке Updates: поставить его "
            "можно в любой момент через UpdatePortable.cmd.\n\n"
            + UPDATE_HOST_CHANGE_WARNING)
    else:
        question = (
            "Прошлое обновление программы было прервано: часть файлов могла "
            "остаться недоустановленной, и из-за этого программа вылетает при "
            "запуске.\n\nСкачать актуальную версию и переустановить её "
            "внутрь портатива? Данные и настройки не затрагиваются.\n\n"
            + UPDATE_HOST_CHANGE_WARNING)
        if not settings["source_url"]:
            _show_info(question.split("\n\n")[0]
                       + "\n\nВременные файлы обновления внутри портатива "
                         "убраны. Изменения Windows, которые мог внести "
                         "установщик, автоматически не откатываются. Если "
                         "программа всё равно не запускается, поставьте её "
                         "заново через UpdatePortable.cmd.")
            return "\n".join(notes) or None
    was_interrupted = interrupted_update or pending_interrupted
    if installer is not None:
        _remember_pending(root, installer, declined=False,
                          interrupted=was_interrupted)
    if not ask(question):
        _update_log(root, "the user postponed the update")
        if installer is not None:
            _remember_pending(root, installer, declined=True,
                              interrupted=was_interrupted)
        return "\n".join(notes) or None
    run = updater or run_update
    outcome = run(root, cfg, str(installer) if installer else "",
                  interactive=True, confirm_download=False)
    if outcome.ok:
        notes.append(outcome.message)
    else:
        _show_error("Обновление не удалось.\n\n" + outcome.message)
    return "\n".join(notes) or None


def update_command(root: Path, argv: Sequence[str]) -> int:
    """``LaunchPortable.exe --update [файл|ссылка] [--yes]``.

    Коды: 0 - обновлено, 1 - не удалось, 3 - отказ пользователя.
    """
    cfg: Dict[str, Any] = read_launcher_config(root)
    arguments = [str(a) for a in argv]
    quiet = any(a.casefold() in ("--yes", "/yes", "--quiet") for a in arguments)
    rest = [a for a in arguments
            if a.casefold() not in ("--update", "/update", "--yes", "/yes",
                                    "--quiet", "--elevated")]
    source = rest[0] if rest else ""
    result = run_update(root, cfg, source, interactive=True,
                        confirm_download=not quiet)
    if result.ok:
        # С ключом --yes окно итога не нужно: результат уходит в код возврата
        # и журнал, а показывает его тот, кто нас вызвал (Portablizer).
        if not quiet:
            _show_info(result.message)
        return 0
    _update_log(root, "failed: " + result.message)
    if result.message == "Обновление отменено.":
        return 3
    if not quiet:
        _show_error("Обновление не удалось.\n\n" + result.message)
    return 1


def rollback_command(root: Path, argv: Sequence[str] = ()) -> int:
    """``LaunchPortable.exe --rollback [--yes]``: вернуть прежнюю версию."""
    cfg: Dict[str, Any] = read_launcher_config(root)
    quiet = any(str(a).casefold() in ("--yes", "/yes", "--quiet") for a in argv)
    result = rollback_update(root, cfg)
    if result.ok:
        if not quiet:
            _show_info(result.message)
        return 0
    _update_log(root, "rollback failed: " + result.message)
    if not quiet:
        _show_error(result.message)
    return 1


def run(argv: Optional[Sequence[str]] = None) -> int:
    """Запуск программы + обновление внутри портатива, если оно понадобилось."""
    root = find_portable_root()
    cfg: Dict[str, Any] = read_launcher_config(root)

    # Следы прерванного обновления (принудительно закрытая программа, зависший
    # «перезапуск для обновления») убираются ДО старта: именно они роняют
    # программу при каждом следующем запуске.
    already_elevated = any(
        str(arg).casefold() == "--elevated"
        for arg in (argv if argv is not None else sys.argv[1:]))
    if not already_elevated:
        try:
            note = offer_recovery(root, cfg)
            if note:
                _run_log(root, "update: " + note.replace("\n", " "))
        except Exception as exc:  # noqa: BLE001 - восстановление не срывает запуск
            _run_log(root, f"update: recovery check failed ({exc})")

    watch = UpdateWatch(root, cfg)
    code = _run_session(argv, root, cfg, watch)
    # «Перезапустить для обновления»: родной установщик перехвачен, новая
    # версия ставится в портатив, после чего программа запускается снова.
    for _attempt in range(2):
        installer = watch.take() if watch.active else None
        if installer is None:
            break
        _update_log(root, "the program asked to restart for an update")
        outcome = run_update(root, cfg, str(installer), interactive=True,
                             confirm_download=False)
        if not outcome.ok:
            _update_log(root, "failed: " + outcome.message)
            _show_error("Обновление не удалось.\n\n" + outcome.message
                        + "\n\nПрограмма останется прежней версии.")
            break
        watch = UpdateWatch(root, cfg)
        code = _run_session(argv, root, cfg, watch)
    return code


def _run_session(argv: Optional[Sequence[str]], root: Path,
                 cfg: Dict[str, Any], watch: "UpdateWatch") -> int:
    #: Время начала сеанса (0.0, пока программа не запущена): по нему
    #: определяется, что установщик положил в прежнее место портатива.
    session_start = 0.0
    timings = _StageTimer(
        root / str(cfg.get("data_dir_name") or "PortableData"))
    # Первая строка отчёта — распаковка onefile-сборки до первой строки
    # Python: без неё «медленный запуск» некуда отнести (см. _process_start_age_seconds).
    timings.add_startup(_process_start_age_seconds())
    #: Потолок времени на предстартовые шаги (см. prelaunch_budget). Всё, что
    #: не успело, доделывается в фоне, уже после появления окна программы:
    #: пользователь ждёт программу, а не отчёт. Обязательные шаги (профиль,
    #: пути, реестр настроек) под потолок не попадают.
    budget = prelaunch_budget(cfg)
    background = _BackgroundWork(root, "pre-launch work")

    #: Отложенные шаги: выполняются по очереди в ОДНОМ фоновом потоке.
    #: По очереди — потому что они правят одни и те же файлы программы
    #: (маркер корня и старые пути), и два потока на одном файле испортили бы
    #: его куда надёжнее, чем любая задержка старта.
    pending: "list[tuple[str, Any]]" = []

    def _defer(name: str, work) -> bool:
        """Откладывает необязательный шаг, если лончер вышел за потолок."""
        if not timings.exceeded(budget):
            return False
        timings.note_deferred(name)
        pending.append((name, work))
        _run_log(root, "pre-launch: budget "
                 f"{budget:.1f}s reached, «{name}» moves to the background so "
                 "the program can start")
        return True

    def _run_now(name: str, work) -> None:
        """Выполняет шаг на месте: строки результата — в журнал."""
        try:
            for line in work():
                if line:
                    _run_log(root, line)
        except Exception as exc:  # noqa: BLE001 - шаг не срывает запуск
            _run_log(root, f"{name}: failed ({exc})")

    def _run_step(name: str, work) -> None:
        """Выполняет шаг сейчас или откладывает его (см. _defer)."""
        if not _defer(name, work):
            _run_now(name, work)

    timings.tick("profile self-check")
    # Самопроверка профиля: прерванный прошлый сеанс мог оставить Known Folder
    # «Документы» направленным внутрь уже удалённой папки портатива. Это ломает
    # сохранения и меню «Пуск», а стоит проверка один запрос к реестру.
    # Самопроверка не должна мешать запуску: её ошибка — только строка в
    # журнале.
    try:
        autoheal_profile(root)
    except Exception as exc:  # noqa: BLE001 - проверка не срывает запуск
        _run_log(root, f"profile self-check failed ({exc})")

    timings.tick("paths")
    # Перенос между дисками: если папка переехала с прошлого запуска, пути
    # старого корня в настройках программы заменяются новыми ДО того, как она
    # их прочитает. Наши файлы и реестр этого не требуют — там либо
    # относительные пути, либо маркер корня.
    def _repair_paths() -> "list[str]":
        return list(repair_paths(root, cfg))

    _run_step("path repair", _repair_paths)

    timings.tick("install records")
    # Записи об установке на этом ПК (`InstallLocation`, `App Paths`,
    # `UninstallString` и т. п.) могли остаться от прежнего места портатива:
    # именно оттуда установщик берёт «прошлую установку» и ставит новую
    # версию по старому адресу. Перед запуском переводим их на текущий корень
    # — обновление, которое запустит сама программа, попадёт в эту папку.
    def _heal_records() -> "list[str]":
        return ["registry: previous location or portable marker now points "
                f"to {root}: {item}" for item in heal_host_registry(root, cfg)]

    _run_now("install records", _heal_records)

    timings.tick("installed list")
    # Портатив не устанавливается: записи в «Установленные программы» тут не
    # место. Обычно её пишет установщик, который распаковывается в App, и после
    # переноса папки на другой диск она ещё и указывает в никуда. Удаляется
    # только запись, у которой какое-то значение с путём ведёт внутрь этой
    # папки (текущей или прежнего места) — чужая установка не страдает.
    #
    # Работа идёт в фоне: программе она для старта не нужна, а возможный
    # запрос UAC раньше вставал поперёк запуска.
    try:
        allow_elevation = not _machine_registry_pending(root, cfg)
        background.submit(
            lambda: ["installed programs: " + line
                     for line in clean_installed_programs(
                         root, cfg, allow_elevation=allow_elevation)],
            name="installed programs")
    except Exception as exc:  # noqa: BLE001 - след установки не срывает запуск
        _run_log(root, f"installed programs: cleanup failed ({exc})")

    timings.tick("marker sweep")
    # Маркер мог остаться и в настройках самой программы (включая App на любой
    # глубине): тогда установщик обновления читает каталог
    # ``@@PORTABLE_ROOT@@\App`` и падает с «Error opening file for writing».
    # Проход выполняется один раз на каждое положение папки.
    def _sweep_marker() -> "list[str]":
        replaced = sweep_root_token_once(root, cfg)
        if not replaced:
            return []
        return ["paths: the portable marker is gone from "
                f"{len(replaced)} file(s)"]

    _run_step("marker sweep", _sweep_marker)

    timings.tick("update adoption")
    # Обновление, поставленное в прежнее место портатива (в том числе
    # предыдущим сеансом, который закрыли аварийно), забирается в App — до
    # того, как программа прочитает свои файлы.
    def _adopt_updates() -> "list[str]":
        previous_start = _read_session_start(root)
        if not previous_start:
            return []
        adopted = adopt_updates_from_previous_locations(
            root, cfg, since=previous_start)
        if not adopted:
            return []
        return [f"update: adopted {len(adopted)} file(s) that the installer "
                "put into the previous location of this portable: "
                + ", ".join(adopted[:8]) + (" ..." if len(adopted) > 8 else "")]

    _run_step("update adoption", _adopt_updates)

    if pending:
        def _run_deferred_steps() -> "list[str]":
            lines: "list[str]" = []
            while pending:
                name, work = pending.pop(0)
                try:
                    lines.extend(line for line in (work() or []) if line)
                except Exception as exc:  # noqa: BLE001
                    lines.append(f"{name}: failed ({exc})")
            return lines

        background.submit(_run_deferred_steps, name="pre-launch work",
                          prefix=False)

    timings.tick("shortcuts")
    # «Пустые» ярлыки этой программы на рабочем столе. Установщик мог
    # записать в ярлык путь временного каталога, которого уже нет, или путь
    # прежнего места папки — такой ярлык не работает ни при каких условиях и
    # только путает. Чужие и рабочие ярлыки не трогаются: см.
    # remove_stale_shortcuts().
    #
    # Обход рабочего стола и меню «Пуск» тоже идёт в фоне (см. выше):
    # ярлыки на старт программы не влияют.
    def _sweep_shortcuts() -> "list[str]":
        stale_guard = ShortcutGuard(
            root, extra_roots=remembered_roots(root, cfg),
            folders=_shortcut_folders_for(root, cfg),
            app_names=_app_shortcut_names(root, cfg))
        return ["removed a stale shortcut: " + path
                for path in stale_guard.sweep()]

    background.submit(_sweep_shortcuts, name="shortcuts")

    timings.tick("registry sanitize")
    # Портатив, собранный прежней версией, мог принести в portable.reg ветки
    # оболочки (меню «Пуск»). Чистим файл на месте — и EXE-, и BAT-лончер
    # тогда импортируют только настройки приложения.
    def _sanitize_reg() -> "list[str]":
        # функция пишет журнал сама («registry: shell sections removed ...»)
        sanitize_portable_registry_files(root)
        return []

    # Санитайзер остаётся предстартовым в любом случае: он переписывает
    # ``portable.reg``, который тут же импортируется. Читать файл в тот
    # момент, когда его переписывают, — верный способ импортировать половину.
    _run_now("registry sanitize", _sanitize_reg)

    timings.tick("stale session")
    # Остатки прошлого запуска убираются ДО старта: иначе они так и будут
    # держать папку, пока пользователь не перезагрузит компьютер. Уборка —
    # вспомогательный шаг: её сбой не должен мешать запуску программы.
    # До старта — только наметка: что удалять и не работает ли уже второй
    # экземпляр программы (трогать его временные файлы нельзя). Само удаление
    # идёт в фоне вместе с запуском: в PortableData\Temp бывают тысячи
    # файлов, и каждый — отдельный вызов, мимо антивируса.
    stale_sweep = None
    try:
        stale_sweep = StaleSessionSweep(root, cfg)
        stale_sweep.prepare()
    except Exception as exc:  # noqa: BLE001 - уборка не срывает запуск
        _run_log(root, f"stale session check failed ({exc})")
        stale_sweep = None
    if stale_sweep is not None:
        def _sweep_temporaries() -> "list[str]":
            return ["cleaned up after the previous session: " + line
                    for line in stale_sweep.run()]

        background.submit(_sweep_temporaries, name="stale session")

    # Сквозные сохранения. Сессия создаётся ДО любых перенаправлений: она
    # обязана запомнить настоящие «Документы» этого ПК, пока Known Folder
    # ещё указывает на них, а не внутрь портатива.
    shared_saves = SharedSaveSession(root, cfg)
    drive_root_data = DriveRootDataSession(root, cfg)

    timings.tick("target selection")
    raw_arguments = _arguments_with_executable_alias(
        cfg, list(argv if argv is not None else sys.argv[1:])
    )
    target_rel, forwarded, needs_machine = _select_target(cfg, raw_arguments)
    # Записанная цель могла исчезнуть: неудачное обновление (родной апдейтер
    # Cursor уносит exe в промежуточную папку), переименование, конфиг от
    # сборки на прежнем диске. Ищем программу в App и правим конфиг, вместо
    # того чтобы показать «файл не найден» и не запустить ничего.
    target_rel = _repair_missing_target(root, cfg, target_rel)
    already_elevated = any(
        str(arg).casefold() == "--elevated" for arg in raw_arguments)
    registry_cfg = cfg.get("registry", {})
    machine_name = str(registry_cfg.get("machine_file", ""))
    machine_path = root / machine_name if machine_name else None
    machine_available = bool(machine_path and machine_path.is_file())

    # Ключ входа (Ollama и т.п.) сверяется ДО UAC-перезапуска: родительский
    # процесс видит настоящий профиль пользователя, а повышенный экземпляр
    # может работать от другой учётной записи администратора и не должен
    # переносить чужой ключ.
    try:
        for line in identity_report(
                root, cfg, os.environ.get("USERPROFILE", ""),
                import_from_host=not already_elevated):
            _run_log(root, "identity: " + line)
    except Exception as exc:  # noqa: BLE001 - ключ не должен срывать запуск
        _run_log(root, f"identity: check failed ({exc})")

    if bool(registry_cfg.get("enabled")):
        try:
            RegistrySession(root, cfg).sync_external_changes()
        except Exception as exc:  # noqa: BLE001
            _run_log(root, f"registry sync check failed: {exc}")

    # Not only launchers and configurators need the captured HKLM data: old
    # games (The Witcher and other GOG re-releases) read their install path
    # from HKLM themselves and quit with exit code 1 when it is not there.
    # VirtualStore covers un-manifested programs only, so when the keys really
    # are missing on this computer the machine file has to be imported for
    # real - and that needs administrator rights, once, for this run.
    if not needs_machine and machine_available and bool(registry_cfg.get("enabled")) \
            and _machine_file_needs_admin(machine_path) \
            and _hklm_key_missing(registry_cfg.get("keys", []), machine_path, root=root):
        needs_machine = True
        _run_log(root, "captured HKLM keys are missing on this PC: "
                       "the machine registry file has to be imported")

    if needs_machine and machine_available and not already_elevated \
            and not _is_elevated():
        if elevation_recently_refused(root):
            # От UAC уже отказывались в последний час: спрашивать снова при
            # каждом запуске — это и есть «зависший запрос UAC». Идём по
            # запасному пути (VirtualStore) и честно пишем об этом в журнал.
            _run_log(root, "the UAC prompt was declined recently; not asking "
                           "again this hour, starting with the VirtualStore "
                           "fallback instead")
        else:
            elevated_code = _run_elevated(raw_arguments)
            if elevated_code is not None:
                # The elevated copy already reported its own result (including
                # the friendly error 14001 box when the runtime is missing), so
                # only record what happened.
                _run_log(root, f"elevated run finished with code "
                               f"{elevated_code}")
                if elevated_code == 1223:
                    mark_elevation_refused(root, "declined at the UAC prompt")
                    _run_log(root, "elevation declined at the UAC prompt; "
                                   "the captured HKLM entries stay unimported "
                                   "and the request will not repeat for an "
                                   "hour")
                else:
                    clear_elevation_refusal(root)
                return elevated_code
            # UAC refused, unavailable or the elevated run did not answer in
            # time: keep going with the VirtualStore fallback instead of
            # refusing to start the program at all.
            mark_elevation_refused(root, "no result from the UAC prompt")
            _run_log(root, "elevation was refused, unavailable or timed out; "
                           "continuing without the HKLM import")

    timings.tick("environment")
    env = _prepare_environment(root, cfg)
    target = _as_relative_path(root, target_rel)
    if not target.is_file():
        alternative = root / "App" / str(target_rel).replace("\\", os.sep)
        if not Path(str(target_rel)).is_absolute() and alternative.is_file():
            target = alternative
        else:
            raise FileNotFoundError(
                f"Исполняемый файл программы не найден:\n{target}\n\n"
                "Похоже, папка App неполная (или программу обновил её "
                "собственный апдейтер). Запустите Launch.bat --diagnose: "
                "отчёт покажет, что лежит в App.")

    # Предстартовая проверка распространяемых компонентов: лучше назвать
    # пакет, чем оставить пользователя наедине с окном Windows
    # «отсутствует MSVCR110.dll». Запуск системного установщика при старте
    # запрещён; лончер сообщает о недостающем пакете и оставляет решение
    # пользователю.
    timings.tick("runtime check")
    missing_runtime = missing_runtime_components(root, cfg, target, env)
    if missing_runtime:
        missing_runtime = install_missing_runtime(root, cfg, missing_runtime)
    if missing_runtime and _runtime_warning_is_new(root, cfg, missing_runtime):
        _warn_about_runtime(root, missing_runtime)

    # Сетевые компоненты (драйвер TAP-Windows, службы-компаньоны): проверка
    # без повышения, UAC — только когда чего-то реально не хватает. Ошибки
    # не должны срывать запуск: программа сама объяснит отсутствие адаптера,
    # а журнал лончера скажет, пытался ли портатив это починить.
    timings.tick("netstack")
    try:
        for line in ensure_netstack(root, cfg):
            _run_log(root, "netstack: " + line)
    except Exception as exc:  # noqa: BLE001 - netstack must not block start
        _run_log(root, f"netstack: ensure failed ({exc})")

    timings.tick("saves")
    # Сейвы, сделанные мимо лончера (прямой запуск App\Game.exe), забираются
    # в портатив ПЕРЕД стартом: иначе программа их просто не увидит.
    # Синхронизация — вспомогательный шаг: её ошибка не должна оставить
    # пользователя без запущенной программы.
    try:
        for line in shared_saves.before():
            _run_log(root, "shared saves: " + line)
    except Exception as exc:  # noqa: BLE001 - сейвы не срывают запуск
        _run_log(root, f"shared saves: pre-launch sync failed ({exc})")
    try:
        for line in drive_root_data.before():
            _run_log(root, "drive-root data: " + line)
    except Exception as exc:  # noqa: BLE001
        _run_log(root, f"drive-root data: pre-launch sync failed ({exc})")

    timings.tick("session start")
    # Время начала сеанса: по нему определяется, что установщик (в том числе
    # запущенный самой программой) положил в прежнее место портатива.
    session_start = write_session_start(root)

    shell_folders = ShellFolderSession(root, cfg)
    registry = RegistrySession(root, cfg)
    shutdown = shutdown_settings(cfg)
    # Kill-on-close job: nothing started from the portable folder may outlive
    # this launcher, otherwise the user cannot delete the folder afterwards.
    job = _JobObject(enabled=should_use_job(target))
    env = _electron_environment(env, target)
    env = apply_webview2_bridge(env, target)
    # Cursor/VS Code: профиль и данные расширений — внутри портатива, а
    # argv.json отключает Chromium-песочницу, которая из папки портатива не
    # запускается (Windows отказывает helper-процессам, и Cursor выходит, не
    # показав окна). Применяется на каждом запуске: файлы могли исчезнуть
    # при копировании папки.
    env = _vscode_environment(env, root, cfg, target)
    try:
        for line in _apply_vscode_profile(root, cfg, target):
            _run_log(root, "vscode: " + line.split(": ", 1)[-1])
    except Exception as exc:  # noqa: BLE001 - профиль не срывает запуск
        _run_log(root, f"vscode: profile setup failed ({exc})")
    timings.tick("profile setup")
    try:
        shell_folders.load()
    except Exception as exc:  # noqa: BLE001 - Known Folder не срывает запуск
        _run_log(root, f"documents redirection failed ({exc})")
    # Реестр: снимок машины снимается всегда до старта — по нему она
    # возвращается в исходное состояние, когда программа закроется. Импорт
    # настроек можно отложить.
    #
    # Редакторам (Cursor/VS Code) настройки из реестра для появления окна не
    # нужны вовсе: они держат всё в JSON-профиле внутри портатива. Зато у
    # Cursor сборщик захватывает до 256 ключей (ассоциации, записи установки),
    # и импорт такого набора — это тысячи записей в реестр, каждая из которых
    # на медленном диске и под антивирусом заметна. Поэтому у них импорт идёт
    # параллельно с запуском программы, а лончер дожидается его перед возвратом
    # реестра (см. background.wait на выходе).
    #
    # Для прочих программ импорт остаётся предстартовым: их настройки лежат
    # именно в реестре, и программа прочтёт их сразу при запуске.
    try:
        registry.prepare()
    except Exception as exc:  # noqa: BLE001 - реестр не срывает запуск
        _run_log(root, f"registry snapshot failed ({exc})")

    def _import_registry() -> "list[str]":
        registry.apply()
        return []

    editor = budget > 0 and _vscode_product(target.parent) is not None
    if editor and registry.active:
        timings.note_deferred("registry import")
        background.submit(_import_registry, name="registry import",
                          prefix=False)
        _run_log(root, "registry: settings are imported in the background "
                       "while the program starts (the editor keeps them in "
                       "its own profile inside the portable folder)")
    else:
        try:
            registry.apply()
        except Exception as exc:  # noqa: BLE001 - реестр не срывает запуск
            _run_log(root, f"registry import failed ({exc})")
    timings.tick("registry")
    if timings.deferred:
        _run_log(root, "pre-launch: deferred to background: "
                 + ", ".join(timings.deferred))
    timings.finish(root)
    try:
        try:
            command = with_electron_flags(
                [
                    str(target),
                    *[str(arg) for arg in cfg.get("target_args", [])],
                    *forwarded,
                ],
                target,
            )
            _run_log(root, "start: " + subprocess.list2cmdline(command)
                     + f" (cwd={target.parent}, elevated={_is_elevated()}, "
                     + f"job={'yes' if job.handle else 'no'})")
            started_at = time.monotonic()
            try:
                code = _wait_target(_spawn_target(
                    command, str(target.parent), env, job), watch)
            except OSError as exc:
                if getattr(exc, "winerror", None) != 14001:
                    raise
                # ERROR_SXS_CANT_GEN_ACTCTX: Windows could not resolve the
                # program's side-by-side assembly.  The Visual C++ 2005/2008
                # runtime the program was built with is missing on this PC -
                # everything else (registry, rights) is irrelevant; without
                # that package the program can never start here.
                _run_log(root, f"{target.name} failed with error 14001 "
                               "(side-by-side configuration is incorrect)")
                _show_error(
                    f"Windows отказалась запускать {target.name} "
                    "(ошибка 14001: параллельная конфигурация "
                    "неправильна).\n\n"
                    "Программа собрана с рантаймом Visual C++ 2005/2008, "
                    "а на этом компьютере его нет. Это не проблема прав "
                    "или реестра — без пакета программа не запустится "
                    "вообще.\n\n"
                    "Исправить можно вручную: если вы доверяете пакету и "
                    "согласны на системное изменение, запустите "
                    "Redist\\Install-Redist.cmd из портативной папки. Он "
                    "установит компоненты в тихом режиме и может запросить "
                    "UAC. Подробности и ссылки — в redistributables.txt.")
                return 14001
            duration = time.monotonic() - started_at
            _run_log(root, f"{target.name} exited with code {code} after "
                           f"{duration:.1f}s")
            # The official launcher usually starts the game and exits at once.
            # Restoring the registry right now would pull the install keys out
            # from under the game that is just starting, so wait for it.
            waited = _wait_for_portable_processes(
                root, settings=shutdown,
                tick=watch.poll if watch.active else None)
            # Родной апдейтер мог стартовать в последний момент: дожимаем.
            watch.finish()
            if waited:
                _run_log(root, f"waited {waited}s for programs started from "
                               f"the portable folder to finish")
            # «Программа не запускается» на деле часто означает «запустилась и
            # сразу вышла». Раньше это было видно только в журнале; для
            # Cursor/VS Code (они не имеют права закрываться сами) пишем и
            # показываем причину поиска: main.log внутри портативного профиля.
            elif duration < 5.0:
                _run_log(root, f"{target.name} closed within {duration:.1f}s "
                               "and left nothing running")
                info = _vscode_product(target.parent)
                if info is not None and code != 0:
                    _show_warning(
                        f"{info['name']} завершился сразу после запуска "
                        f"(код {code}), не показав окна.\n\n"
                        "Журнал самого редактора лежит внутри портатива:\n"
                        f"{root / str(cfg.get('data_dir_name') or 'PortableData')}"
                        f"\\AppData\\Roaming\\{info['name']}\\logs\n\n"
                        "Полный отчёт: Launch.bat --diagnose")
            # Companion services first: a registered service whose binary
            # lives in App/ keeps the whole folder locked no matter how the
            # processes are closed. Teardown removes ONLY what this portable
            # created here; then the usual leftover sweep runs.
            try:
                for line in stop_netstack(root, cfg):
                    _run_log(root, "netstack: " + line)
            except Exception as exc:  # noqa: BLE001
                _run_log(root, f"netstack: teardown failed ({exc})")
            # Whatever still runs from this folder is a leftover (updater,
            # crash handler, silent helper).  It is closed down HERE, while
            # the sandbox is still in place: a helper saving its settings on
            # exit writes them into the portable folder, not into the host
            # registry it would see a moment later.
            stopped = release_portable_folder(root, shutdown)
            if stopped:
                _run_log(root, "stopped leftover processes from the portable "
                               "folder: " + ", ".join(sorted(set(stopped))))
            return code
        finally:
            # Фоновая уборка — до возврата реестра: она трогает те же ключи.
            # Ждём не дольше десяти секунд: программа уже закрыта, а остаток
            # работы заведомо повторится ниже, на выходе.
            background.wait(timeout=10.0)
            try:
                registry.save_and_restore()
            except Exception as exc:  # noqa: BLE001 - уже закрываемся
                _run_log(root, f"registry restore failed ({exc})")
    finally:
        try:
            background.wait(timeout=10.0)
        except Exception as exc:  # noqa: BLE001 - уже закрываемся
            _run_log(root, f"background cleanup: {exc}")
        try:
            shell_folders.restore()
        except Exception as exc:  # noqa: BLE001 - уже закрываемся
            _run_log(root, f"documents restore failed ({exc})")
        # Safety net for every path that skipped the block above (an error,
        # a program that spawned something during shutdown): sweep again and
        # drop the job handle - Windows finishes off anything that ignored
        # us.  Only after this the folder can really be deleted.
        try:
            stop_netstack(root, cfg)
        except Exception:  # noqa: BLE001 - already unwinding
            pass
        release_portable_folder(root, shutdown)
        job.close()
        # Теперь, когда из портатива уже ничего не выполняется и все файлы
        # закрыты, сохранения сводятся обратно: сделанное в этом сеансе
        # должно быть видно и при следующем прямом запуске exe.
        try:
            for line in shared_saves.after():
                _run_log(root, "shared saves: " + line)
        except OSError as exc:
            _run_log(root, f"shared saves: synchronisation failed ({exc})")
        try:
            for line in drive_root_data.after():
                _run_log(root, "drive-root data: " + line)
        except Exception as exc:  # noqa: BLE001
            _run_log(root, f"drive-root data: post-exit sync failed ({exc})")
        # Временная папка портатива не должна пережить сеанс: именно
        # распакованные в неё файлы (шрифты установщика, DLL «помощников»)
        # потом подхватывает система и держит их месяцами.
        removed = purge_portable_temp(root, cfg)
        if removed:
            _run_log(root, f"cleared the portable temp folder ({removed})")
        # Обновление, поставленное в прежнее место портатива, переносится в
        # текущую папку: пользователь должен получить новую версию там, где
        # портатив лежит сейчас, а не на прежнем диске.
        try:
            adopted = adopt_updates_from_previous_locations(
                root, cfg, since=session_start)
            if adopted:
                _run_log(
                    root, f"update: the installer wrote {len(adopted)} file(s) "
                    "into the previous location of this portable; they are "
                    "copied into the current App: " + ", ".join(adopted[:8])
                    + (" ..." if len(adopted) > 8 else ""))
                _show_info(
                    "Обновление установилось не в эту папку, а по прежнему "
                    "адресу портатива.\n\n"
                    f"Свежие файлы ({len(adopted)}) уже скопированы в текущую "
                    "папку App, прежние версии — в Updates\\backup-previous.\n\n"
                    "Запустите программу ещё раз, чтобы работать с новой "
                    "версией. Старую папку на прежнем диске можно удалить: она "
                    "больше не нужна.")
        except Exception as exc:  # noqa: BLE001 - уже закрываемся
            _run_log(root, f"update: adoption at exit failed ({exc})")
        # Родной апдейтер программы мог за время работы поставить запись
        # «Установленные программы» заново — снимаем и её. Права не просим:
        # закрытие не должно зависеть от UAC.
        try:
            for line in clean_installed_programs(root, cfg):
                _run_log(root, "installed programs (after exit): " + line)
        except Exception as exc:  # noqa: BLE001 - уже закрываемся
            _run_log(root, f"installed programs: post-exit cleanup failed ({exc})")
        _report_folder_state(root, shutdown)


def stop(root: Optional[Path] = None) -> int:
    """``LaunchPortable.exe --stop``: free the folder, then report the result.

    A rescue hatch for the case the user notices too late: the program was
    closed, but something from the folder is still running and Windows
    refuses to delete it.  The same politeness rules apply - windows are
    asked to close first, survivors are terminated.
    """
    root = root or find_portable_root()
    cfg: Dict[str, Any] = {}
    settings = {"close_grace": 5.0, "kill_leftovers": 1.0}
    try:
        cfg = read_launcher_config(root)
        settings = shutdown_settings(cfg)
    except (OSError, ValueError):
        pass
    # Службы-компаньоны (VPN), созданные этим портативом, держат свои exe из
    # App даже после убийства процесса — SCM поднимет службу снова. Сначала
    # снимаем их с регистрации (только свои, по маркеру PortableData), потом
    # занимаемся процессами.
    try:
        stop_netstack(root, cfg)
    except Exception as exc:  # noqa: BLE001 - stop не должен падать
        _run_log(root, f"netstack: teardown failed ({exc})")
    stopped = release_portable_folder(root, settings)
    remaining = _portable_process_list(root)
    if remaining:
        names = ", ".join(sorted({_image_name(i) for _, i in remaining}))
        _run_log(root, f"--stop: could not release the folder: {names}")
        retry = _retry_stop_elevated(root, "процессы")
        if retry == 0:
            return 0
        if retry == 1:
            return 1  # повышенная копия уже показала свой вердикт
        _show_warning(
            "Часть процессов из портативной папки остановить не удалось:\n"
            f"{names}\n\n"
            "Обычно это значит, что они запущены от имени администратора. "
            "Запустите этот же файл от имени администратора.")
        return 1

    # Временная папка - главный рассадник вечных блокировок: установщики
    # оставляют в ней распакованные шрифты и DLL, которые потом держит
    # система. Если из папки ничего не запущено, Temp можно вычистить.
    purge_portable_temp(root, cfg)

    # Главная проверка: не «кто запущен», а «можно ли удалить папку».
    # Раньше скрипт отвечал «папка свободна», опираясь на список
    # процессов, — и ошибался ровно в том случае, ради которого его
    # запускают: процессов нет, а файл внутри открыт.
    locked = busy_files(root)
    if locked:
        items = open_files_in(root)
        description = describe_open_files(items) or ", ".join(
            _image_name(path) for path in locked[:6])
        _run_log(root, f"--stop: the folder is still locked: {description}")
        retry = _retry_stop_elevated(root, "открытые файлы")
        if retry == 0:
            return 0
        if retry == 1:
            return 1  # повышенная копия уже показала свой вердикт
        _show_warning(
            "Папка портатива всё ещё занята. Её файлы держат:\n"
            f"{description}\n\n"
            "Это не процессы портатива, а системные службы Windows "
            "(например, кэш шрифтов) или программа с открытым окном. "
            "Закрыть такой дескриптор может только администратор: "
            "запустите StopPortable.cmd от имени администратора.")
        return 1

    # Процессов из папки нет, занятых файлов нет — но её может держать
    # кто-то снаружи, подгрузивший оттуда DLL.
    holders = module_holders(root)
    if holders:
        description = describe_holders(holders)
        _run_log(root, f"--stop: the folder is held from outside: {description}")
        _show_warning(
            "Из портативной папки ничего не запущено, но её файлы держат "
            "другие программы:\n"
            f"{description}\n\n"
            "Обычно это проводник Windows (открыт предпросмотр или окно "
            "папки) либо антивирус. Закройте окна этой папки и повторите — "
            "после этого папка удалится.")
        return 1

    _run_log(root, "--stop: portable folder released"
             + (": " + ", ".join(sorted(set(stopped))) if stopped else
                " (nothing was running)"))
    return 0


def _retry_stop_elevated(root: Path, reason: str) -> int:
    """Повторяет ``--stop`` с правами администратора.

    Чужой дескриптор (служба кэша шрифтов!) обычным правам не подчиняется,
    а пользователю неоткуда это знать: он видит «папка свободна» и злится.
    Поэтому лончер сам один раз просит повышение — и только если и это не
    помогло, честно признаётся.

    ``0`` — повышенная копия освободила папку, ``1`` — не смогла и уже
    показала об этом своё окно, ``-1`` — повышения не было (отказ UAC,
    запуск из исходников, мы и так администратор).
    """
    if not IS_WINDOWS or _is_elevated():
        return -1
    if any(str(arg).casefold() == "--elevated" for arg in sys.argv[1:]):
        return -1
    _run_log(root, f"--stop: asking for administrator rights ({reason})")
    code = _run_elevated(["--stop"])
    if code is None:
        return -1
    if code == 0:
        _run_log(root, "--stop: the elevated copy released the folder")
        return 0
    _run_log(root, f"--stop: the elevated copy returned {code}")
    return 1


def repair_start_menu_command(root: Optional[Path] = None) -> int:
    """``LaunchPortable.exe --repair-start-menu``: починить меню «Пуск».

    Нужно ровно после того, как сборка под администратором оставила след:
    меню «Пуск» Windows 11 не открывается, плитки пропали. Команда возвращает
    «Документы» в профиль (если их увели в удалённый портатив), сбрасывает
    испорченный кэш ``StartMenuExperienceHost`` и перезапускает его — Windows
    перестраивает меню по своей базе, закрепления пользователя не удаляются.
    """
    if not IS_WINDOWS:
        _show_info("Починка меню «Пуск» доступна только на Windows.\n\n"
                   "Команда работает внутри готового портатива: "
                   "App\\LaunchPortable.exe --repair-start-menu")
        return 1
    try:
        done = repair_start_menu(root)
    except Exception as exc:  # noqa: BLE001 - починка не должна падать
        _run_log(root, f"start menu repair failed: {exc}")
        _show_error("Не удалось починить меню «Пуск».\n\n" + str(exc))
        return 1
    if not done:
        _show_info("Следов поломки не найдено: папка «Документы» на месте, "
                   "кэш меню «Пуск» выглядит целым.\n\nЕсли меню всё равно "
                   "не открывается, перезагрузите компьютер: Windows "
                   "пересоберёт кэш при старте.")
        return 0
    _show_info("Меню «Пуск» починено:\n\n  • " + "\n  • ".join(done)
               + "\n\nПерезапустите Проводник или войдите заново, если меню "
                 "не открылось сразу.")
    return 0


def sync_saves(root: Optional[Path] = None) -> int:
    """``LaunchPortable.exe --sync-saves``: свести сохранения вручную.

    Нужно ровно в одном случае: программу запускали напрямую из ``App``,
    мимо лончера, и теперь её сейвы хочется увидеть в портативе (или
    наоборот) не дожидаясь следующего запуска через лончер.
    """
    root = root or find_portable_root()
    cfg: Dict[str, Any] = read_launcher_config(root)
    session = SharedSaveSession(root, cfg)
    if not session.enabled:
        _run_log(root, "shared saves: disabled for this portable app")
        return 0
    report = [*session.pull(), *session.push()]
    for line in report:
        _run_log(root, "shared saves: " + line)
    if not report:
        _run_log(root, "shared saves: everything is already in sync")
    return 0


#: Сколько последних строк журнала попадает в отчёт диагностики.
DIAGNOSE_LOG_LINES = 80


def _tail_lines(path: Path, count: int) -> "list[str]":
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()[-count:]


def diagnose(root: Optional[Path] = None) -> int:
    """``LaunchPortable.exe --diagnose``: пишет отчёт о состоянии портатива.

    Нужен ровно для жалобы «через Launch.bat и App\\LaunchPortable.exe ничего
    не запускается, а сам exe программы работает»: обычный пользователь не
    может открыть журнал лончера, а отчёт собирает в один текстовый файл всё,
    что нужно для ответа — конфиг, цель, содержимое App, определение Electron/
    VS Code, пути профиля и хвост журнала.
    """
    root = root or find_portable_root()
    cfg: Dict[str, Any] = {}
    config_error = ""
    try:
        cfg = read_launcher_config(root)
    except Exception as exc:  # noqa: BLE001 - отчёт нужен именно при ошибке
        config_error = f"{type(exc).__name__}: {exc}"
    data = root / str(cfg.get("data_dir_name") or "PortableData")
    lines: "list[str]" = []
    add = lines.append

    add("Portablizer — диагностика портативного приложения")
    add("=" * 60)
    add(f"Дата:            {time.strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"Корень:          {root}")
    add(f"Конфиг:          {launcher_config_path(root)}")
    if cfg:
        add(f"Приложение:      {cfg.get('app_name', '')}")
        add(f"Сборка:          {cfg.get('generated_by', 'неизвестно')}")
    if config_error:
        add(f"ОШИБКА КОНФИГА:  {config_error}")
    add("")

    target_rel = str(cfg.get("target_exe_rel") or "")
    target = _as_relative_path(root, target_rel) if target_rel else None
    add("Цель запуска")
    add("-" * 60)
    add(f"target_exe_rel:  {target_rel or '(не задан)'}")
    if target is not None:
        add(f"полный путь:     {target}")
        add(f"существует:      {'да' if target.is_file() else 'НЕТ'}")
    add(f"target_args:     {cfg.get('target_args', [])}")
    add("")

    add("Сам лончер")
    add("-" * 60)
    add(launcher_packaging_reason(root))
    add("")

    add("Pipeline (как лончер будет запускать программу)")
    add("-" * 60)
    if target is not None and target.is_file():
        info = _vscode_product(target.parent)
        add(f"Electron:        {'да' if is_electron_tree(target.parent) else 'нет'}")
        add(f"песочница off:   "
            f"{'да' if needs_electron_sandbox_off(target) else 'нет'}")
        add(f"kill-on-close:   {'да' if should_use_job(target) else 'нет'}")
        add(f"VS Code-семейство: "
            f"{info['name'] + ' (target=' + (info['target'] or 'не задан') + ')' if info else 'нет'}")
        if info is not None:
            defaults = {
                "VSCODE_APPDATA": str(data / "AppData" / "Roaming"),
                "VSCODE_EXTENSIONS": str(data / "User"
                                         / info["data_folder"] / "extensions"),
                "VSCODE_LOGS": str(data / "Logs"),
                "VSCODE_CLI_DATA_DIR": str(data / "User"
                                            / info["data_folder"] / "cli"),
            }
            configured = cfg.get("extra_env")
            configured = configured if isinstance(configured, dict) else {}
            for key, value in defaults.items():
                add(f"{key}: "
                    f"{configured.get(key, value)}"
                    f"{'  (из конфига)' if key in configured else ''}")
            argv = data / "User" / info["data_folder"] / "argv.json"
            add(f"argv.json:       {argv} "
                f"({'есть' if argv.is_file() else 'НЕТ'})")
    else:
        add("Цель не найдена — программа запуститься не может.")
    add("")

    add("App")
    add("-" * 60)
    app = root / "App"
    if app.is_dir():
        entries = []
        try:
            for item in os.scandir(app):
                if item.is_file():
                    try:
                        entries.append((item.stat().st_size, item.name))
                    except OSError:
                        entries.append((0, item.name))
        except OSError as exc:
            add(f"не удалось прочитать App: {exc}")
        entries.sort(reverse=True)
        add(f"файлов в корне App: {len(entries)}")
        for size, name in entries[:20]:
            add(f"  {size:>12}  {name}")
        add(f"resources\\app:    "
            f"{'есть' if (app / 'resources' / 'app').is_dir() else 'нет'}")
        add(f"app.asar:         "
            f"{'есть' if (app / 'resources' / 'app.asar').is_file() else 'нет'}")
        add(f"data (portable):  {'есть' if (app / 'data').is_dir() else 'нет'} "
            "(VS Code игнорирует её при target=user)")
    else:
        add("Папки App НЕТ — портатив неполный.")
    add("")

    add("Список «Установленные программы»")
    add("-" * 60)
    try:
        for line in describe_install_records(root, cfg):
            add(line)
    except Exception as exc:  # noqa: BLE001 - отчёт не должен падать
        add(f"проверить не удалось: {exc}")
    add("  Ручная уборка: Launch.bat --remove-installed-entry \"Cursor\"")
    add("")

    add("Предстартовые шаги (прошлый запуск)")
    add("-" * 60)
    budget = prelaunch_budget(cfg)
    add("потолок до старта: "
        + (f"{budget:g} s — что не успело, доделывается в фоне"
           if budget > 0 else "нет (prelaunch_budget_seconds = 0)"))
    lines.extend(_last_launch_timing(data))
    add("")

    add("Настройки переноса")
    add("-" * 60)
    add(f"data_dir_name:   {cfg.get('data_dir_name', 'PortableData')}")
    relative = cfg.get("relative_paths")
    add(f"relative_paths:  {'есть' if relative else 'нет секции'}")
    stamp = data / PATHS_STAMP_NAME
    add(f"portable-root:   {stamp} "
        f"({'есть' if stamp.is_file() else 'нет'})")
    registry = cfg.get("registry")
    if isinstance(registry, dict) and registry.get("enabled"):
        add(f"реестр:          ключей {len(registry.get('keys') or [])}")
    else:
        add("реестр:          не применяется")
    add(f"обновления:      {'секция есть' if cfg.get('update') else 'нет секции'}")
    add("")

    add("Журнал лончера (последние строки)")
    add("-" * 60)
    log_lines = _tail_lines(data / "launcher-run.log", DIAGNOSE_LOG_LINES)
    lines.extend(log_lines or ["(журнала нет: лончер ещё ни разу не доходил "
                               "до запуска программы)"])
    add("")
    error = data / "launcher-exe-error.log"
    if error.is_file():
        add("Ошибка запуска (launcher-exe-error.log)")
        add("-" * 60)
        lines.extend(_tail_lines(error, 40))
        add("")

    report = data / "diagnostics.txt"
    try:
        data.mkdir(parents=True, exist_ok=True)
        report.write_text("\n".join(lines) + "\n", encoding="utf-8",
                          newline="\n")
    except OSError as exc:
        _show_error(f"Не удалось записать отчёт диагностики: {exc}")
        return 1
    _run_log(root, f"diagnostics written to {report}")
    try:
        print(f"Diagnostics report: {report}")
    except Exception:  # noqa: BLE001
        pass
    if _ui_disabled():
        # Автоматический прогон: файл уже на диске, открывать его некому.
        return 0
    try:
        if IS_WINDOWS:
            os.startfile(str(report))  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - отчёт важнее просмотрщика
        pass
    _show_info("Отчёт диагностики записан:\n\n" + str(report)
               + "\n\nЕго можно приложить к сообщению о проблеме.")
    return 0


def main() -> int:
    root: Optional[Path] = None
    arguments = [str(arg).casefold() for arg in sys.argv[1:]]
    # Починка меню «Пуск» — единственная команда, которой папка портатива не
    # нужна: меню ломается как раз тогда, когда портатива под рукой может не
    # быть. Она работает и из любой папки, куда скопировали этот EXE.
    if any(arg in ("--repair-start-menu", "/repair-start-menu")
           for arg in arguments):
        try:
            root = find_portable_root()
        except Exception:  # noqa: BLE001 - вне портатива это нормально
            root = None
        return repair_start_menu_command(root)
    try:
        root = find_portable_root()
        if any(str(arg).casefold() in ("--stop", "/stop")
               for arg in sys.argv[1:]):
            return stop(root)
        if any(str(arg).casefold() in ("--update", "/update")
               for arg in sys.argv[1:]):
            return update_command(root, sys.argv[1:])
        if any(str(arg).casefold() in ("--rollback", "/rollback")
               for arg in sys.argv[1:]):
            return rollback_command(root, sys.argv[1:])
        if any(str(arg).casefold() in ("--repair-paths", "/repair-paths")
               for arg in sys.argv[1:]):
            return repair_paths_command(root)
        if any(str(arg).casefold() in ("--clean-installed-entry",
                                       "/clean-installed-entry")
               for arg in sys.argv[1:]):
            return clean_installed_programs_command(root)
        if any(str(arg).casefold() in ("--remove-installed-entry",
                                       "/remove-installed-entry")
               for arg in sys.argv[1:]):
            value = ""
            args = list(sys.argv[1:])
            for index, item in enumerate(args):
                if str(item).casefold() in ("--remove-installed-entry",
                                            "/remove-installed-entry"):
                    value = args[index + 1] if index + 1 < len(args) else ""
                    break
            return forget_installed_entry_command(value, root)
        if any(str(arg).casefold() in ("--import-reg", "/import-reg")
               for arg in sys.argv[1:]):
            value = ""
            args = list(sys.argv[1:])
            for index, item in enumerate(args):
                if str(item).casefold() in ("--import-reg", "/import-reg"):
                    value = args[index + 1] if index + 1 < len(args) else ""
                    break
            return import_reg_command(root, value)
        if any(str(arg).casefold() in ("--sync-saves", "/sync-saves")
               for arg in sys.argv[1:]):
            return sync_saves(root)
        if any(str(arg).casefold() in ("--check-identity", "/check-identity")
               for arg in sys.argv[1:]):
            return check_identity(root)
        if any(str(arg).casefold() in ("--diagnose", "/diagnose",
                                       "--diagnostics", "/diagnostics")
               for arg in sys.argv[1:]):
            return diagnose(root)
        return run()
    except Exception as exc:
        details = f"Не удалось запустить портативную программу.\n\n{exc}"
        _write_error_log(root, details + "\n\n" + traceback.format_exc())
        # Хвост журнала в самом окне: иначе пользователь видит только
        # «что-то не так» и не знает, где искать. Отчёт --diagnose собирает
        # то же самое в файл.
        data_name = "PortableData"
        if root is not None:
            try:
                data_name = str(read_launcher_config(root).get("data_dir_name")
                                or "PortableData")
            except Exception:  # noqa: BLE001 - конфиг мог и не читаться
                pass
        tail = (_tail_lines(root / data_name / "launcher-run.log", 12)
                if root is not None else [])
        if tail:
            details += "\n\nПоследние строки журнала:\n" + "\n".join(tail)
        details += ("\n\nПодробный отчёт: Launch.bat --diagnose "
                    "(PortableData\\diagnostics.txt).")
        _show_error(details)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
