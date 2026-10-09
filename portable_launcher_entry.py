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
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

ROOT_TOKEN = "@@PORTABLE_ROOT@@"
IS_WINDOWS = sys.platform.startswith("win")
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0
ERROR_ICON = 0x00000010
WARNING_ICON = 0x00000030


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


#: Exit codes meaning "the package is in place": installed, already there
#: (1638/5100/0x80070666) or installed but asking for a reboot (3010/1641).
RUNTIME_OK_CODES = frozenset({0, 1638, 5100, 3010, 1641, 0x80070666})


def _directx_scratch_dir() -> Path:
    """A writable folder for unpacking the DirectX bundle into."""
    candidates = [Path(os.environ.get("SystemRoot") or r"C:\Windows") / "Temp",
                  Path(tempfile.gettempdir())]
    for base in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
            probe = base / "pblz_dx.tmp"
            probe.write_bytes(b"")
            probe.unlink()
            return base / "pblz_dx"
        except OSError:
            continue
    return candidates[-1] / "pblz_dx"


def _directx_commands(path: Path) -> list[list[str]]:
    """Unpack directx_*_redist.exe, then run DXSETUP.exe /silent.

    The bundle is an IExpress archive, not an installer: any silent switch
    reaches DXSETUP, and DXSETUP knows exactly one ("/silent") - anything
    else pops up "Invalid command line operation" and waits for a click.
    Both steps go into one hidden cmd line so the exit code of DXSETUP is
    the exit code of the whole package.
    """
    scratch = _directx_scratch_dir()
    line = (
        f'rd /s /q "{scratch}" 2>nul & md "{scratch}" 2>nul & '
        f'"{path}" /Q /C /T:{scratch} & '
        f'if not exist "{scratch}\\DXSETUP.exe" (rd /s /q "{scratch}" 2>nul '
        f'& exit /b 1) & '
        f'"{scratch}\\DXSETUP.exe" /silent & set DXRC=!ERRORLEVEL! & '
        f'rd /s /q "{scratch}" 2>nul & exit /b !DXRC!'
    )
    return [["cmd.exe", "/v:on", "/c", line]]


def _runtime_install_commands(root: Path,
                              entry: Dict[str, Any]) -> list[list[str]]:
    """Command line that installs one package without showing anything."""
    relative = str(entry.get("file", "")).replace("/", os.sep)
    if not relative:
        return []
    path = root / relative
    if not path.is_file():
        return []
    kind = str(entry.get("kind", "")).lower()
    lower_name = path.name.lower()
    if kind == "msi" or path.suffix.lower() in (".msi", ".msp"):
        return [["msiexec", "/i", str(path), "/qn", "/norestart"]]
    if kind == "msu" or path.suffix.lower() == ".msu":
        return [["wusa", str(path), "/quiet", "/norestart"]]
    if kind == "dxsetup" or lower_name == "dxsetup.exe":
        # DXSETUP understands only /silent; any other switch pops up
        # "Invalid command line operation".
        return [[str(path), "/silent"]]
    if (kind == "directx_bundle" or lower_name.startswith("directx_")
            or lower_name.startswith("directx") or lower_name.startswith("dx_")
            or lower_name.startswith("dxredist")):
        # directx_*_redist.exe only unpacks itself; every silent switch is
        # handed over to DXSETUP, which answers with a modal "Invalid
        # command line operation" box.  Unpack first, then DXSETUP /silent.
        return _directx_commands(path)
    if kind == "vcredist_legacy":
        # VC++ 2005 accepts /q, but rejects the commonly used /norestart with
        # a visible "Command line option syntax error" dialog.  Do not trust
        # stale args saved by an older Portablizer and do not try modern
        # fallbacks against this legacy IExpress wrapper.
        return [[str(path), "/q"]]
    args = str(entry.get("args", "")).split()
    commands = [[str(path), *args]] if args else []
    for fallback in (["/quiet", "/norestart"], ["/q", "/norestart"],
                     ["/S"], ["/silent"]):
        candidate = [str(path), *fallback]
        if candidate not in commands:
            commands.append(candidate)
    return commands


def _run_hidden(command: Sequence[str], timeout: int = 900) -> Optional[int]:
    """Run an installer with no console and no window at all."""
    try:
        completed = subprocess.run(
            [str(part) for part in command], timeout=timeout,
            creationflags=NO_WINDOW, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return int(completed.returncode)
    except (OSError, subprocess.SubprocessError):
        return None


def _run_hidden_elevated(program: str,
                         arguments: Sequence[str]) -> Optional[int]:
    """Run a program through UAC with no window, and wait for it.

    One prompt for the whole batch of runtime packages: after the user has
    confirmed it, nothing else appears on screen.
    """
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        SEE_MASK_NO_CONSOLE = 0x00008000
        SW_HIDE = 0

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
        info.lpFile = str(program)
        info.lpParameters = subprocess.list2cmdline(
            [str(part) for part in arguments])
        info.nShow = SW_HIDE
        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
        if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
            return None
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        kernel32.CloseHandle(info.hProcess)
        return int(code.value)
    except Exception:  # noqa: BLE001 - UAC refusal must not break the launch
        return None


def install_missing_runtime(root: Path, cfg: Dict[str, Any],
                            missing: Sequence[Dict[str, Any]]
                            ) -> list[Dict[str, str]]:
    """Install the packages this PC lacks - silently, without any dialog.

    Portablizer ships the installers it could not unpack in the ``Redist``
    folder.  Instead of throwing one message box after another at the user
    ("MSVCR110.dll is missing - press OK"), the launcher runs them with the
    silent switches recorded at build time.  Everything that really got
    installed disappears from the warning; only genuine failures are
    reported, once.
    """
    entries = cfg.get("runtime_installers") or []
    if not IS_WINDOWS or not isinstance(entries, list) or not entries:
        return list(missing)

    # Installing a runtime needs administrator rights.  The generated
    # Redist\Install-Redist.cmd puts every package behind a SINGLE UAC
    # prompt and stays hidden, which is far better than one dialog per
    # package - or per missing DLL.
    script = str(cfg.get("runtime_install_script") or "")
    if script:
        path = root / script.replace("/", os.sep)
        if path.is_file():
            command = ["cmd.exe", "/c", str(path)]
            code = (_run_hidden(command) if _is_elevated()
                    else _run_hidden_elevated("cmd.exe",
                                              ["/c", str(path)]))
            _run_log(root, f"silent runtime install script -> {code}")
            still = [item for item in missing
                     if not _requirement_satisfied(root, None, dict(os.environ),
                                                   None, item)]
            if not still:
                return still

    wanted = {str(item.get("dll", "")).lower() for item in missing}
    installed: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        covered = {name.strip().lower()
                   for name in str(entry.get("dlls", "")).split(",")
                   if name.strip()}
        if covered and not (covered & wanted):
            continue
        for command in _runtime_install_commands(root, entry):
            code = _run_hidden(command)
            _run_log(root, f"silent runtime install: "
                           f"{subprocess.list2cmdline(command)} -> {code}")
            if code is not None and (code & 0xFFFFFFFF) in RUNTIME_OK_CODES:
                installed.append(str(entry.get("title") or entry.get("file")))
                break
    if installed:
        _run_log(root, "installed silently: " + ", ".join(installed))
    # Re-check every requirement properly: for a VC++ 2005/2008 assembly the
    # proof of installation is a WinSxS family folder, not a System32 file.
    env = dict(os.environ)
    return [item for item in missing
            if not _requirement_satisfied(root, None, env, None, item)]


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
        "Поставить их молча, без единого окна, можно файлом "
        "Redist\\Install-Redist.cmd",
        "рядом с портативной папкой (если он там есть).",
        "Подробности и ссылки — в файле redistributables.txt рядом с "
        "портативной папкой.",
        "Программа всё равно будет запущена: часть компонентов нужна не "
        "всегда.",
    ]
    text = "\n".join(lines)
    _run_log(root, "missing runtime components: "
             + ", ".join(str(item.get("dll")) for item in missing))
    _show_warning(text)


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
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-16-le", "replace")


def _rewrite_reg(source: Path, destination: Path, replacements: Iterable[tuple[str, str]]) -> bool:
    """Rewrite a .reg file as UTF-16 while replacing portable path markers."""
    try:
        text = _decode_reg(source.read_bytes())
        for old, new in replacements:
            if old:
                text = text.replace(old, new)
        # TextIO translates every \n when newline="\r\n". Normalize first so
        # an exported CRLF file does not turn into CRCRLF after rewriting.
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-16", newline="\r\n")
        return True
    except (OSError, UnicodeError):
        return False


def _unpacked_reg(source: Path, runtime_dir: Path, root: Path, index: int) -> Path:
    """Create a temporary importable copy with the current drive/path."""
    destination = runtime_dir / f"import-{index:03d}.reg"
    escaped_root = str(root).replace("\\", "\\\\")
    if _rewrite_reg(source, destination, ((ROOT_TOKEN, escaped_root),)):
        return destination
    return source


def _pack_reg(path: Path, root: Path) -> None:
    """Replace this computer's absolute root with a portable marker in-place."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    root_text = str(root)
    escaped_root = root_text.replace("\\", "\\\\")
    if _rewrite_reg(
        path,
        temporary,
        ((escaped_root, ROOT_TOKEN), (root_text, ROOT_TOKEN)),
    ):
        try:
            os.replace(temporary, path)
        except OSError:
            try:
                temporary.unlink()
            except OSError:
                pass


def _as_relative_path(root: Path, value: str) -> Path:
    normalized = str(value).replace("\\", os.sep).replace("/", os.sep)
    return root / normalized


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
        "USERNAME": "Portable",
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
        except (OSError, TypeError, ValueError):
            # If the backup exists, restore whatever was changed before
            # allowing the target to start.
            self.restore()


class RegistrySession:
    """Apply portable settings, save changes, and restore the host afterwards."""

    def __init__(self, root: Path, cfg: Dict[str, Any]) -> None:
        self.root = root
        self.cfg = cfg.get("registry", {})
        data = root / cfg.get("data_dir_name", "PortableData")
        self.session = data / "Registry"
        self.backup = data / "RegistryHostBackup"
        self.runtime = self.backup / "RuntimeImports"
        self.keys = list(self.cfg.get("keys", []))
        self.created = {str(key).casefold() for key in self.cfg.get("created_keys", [])}
        self.active = bool(self.cfg.get("enabled")) and IS_WINDOWS
        self.started = False

    def load(self) -> None:
        if not self.active:
            return
        self.session.mkdir(parents=True, exist_ok=True)
        self.backup.mkdir(parents=True, exist_ok=True)
        self.runtime.mkdir(parents=True, exist_ok=True)

        for index, key in enumerate(self.keys):
            backup_file = self.backup / f"k{index:02d}.reg"
            if not backup_file.exists():
                _reg(("export", str(key), str(backup_file), "/y"))

        saved = sorted(self.session.glob("*.reg"))
        initial_name = self.cfg.get("file", "portable.reg")
        machine_name = self.cfg.get("machine_file", "portable_machine.reg")
        sources = []
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
        for index, source in enumerate(sources):
            if source.is_file():
                imported = _unpacked_reg(source, self.runtime, self.root, index)
                code = _reg(("import", str(imported)))
                _run_log(
                    self.root,
                    f"registry import {source.name}: "
                    f"{'ok' if code == 0 else f'FAILED (reg.exe rc={code})'}",
                )
        self.started = True

    def save_and_restore(self) -> None:
        if not self.active or not self.started:
            return
        restore = bool(self.cfg.get("restore_on_exit", True))
        if not restore:
            return

        for index, key in enumerate(self.keys):
            session_file = self.session / f"k{index:02d}.reg"
            try:
                session_file.unlink()
            except FileNotFoundError:
                pass
            if _reg(("export", str(key), str(session_file), "/y")) == 0 and session_file.exists():
                _pack_reg(session_file, self.root)

            if str(key).casefold() in self.created:
                _reg(("delete", str(key), "/f"))
            backup_file = self.backup / f"k{index:02d}.reg"
            if backup_file.exists():
                _reg(("import", str(backup_file)))
                try:
                    backup_file.unlink()
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
    with (root / "launcher_config.json").open("r", encoding="utf-8-sig") as fh:
        cfg: Dict[str, Any] = json.load(fh)
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


def _machine_file_needs_admin(path: Path) -> bool:
    """True when the captured machine file really contains HKLM sections."""
    try:
        text = _decode_reg(path.read_bytes())
    except OSError:
        return False
    lowered = text.casefold()
    return "[hkey_local_machine" in lowered


def _hklm_key_missing(keys: Iterable[str]) -> bool:
    """True when at least one captured HKLM key is absent on this computer.

    Games such as The Witcher read their install path from HKLM and quit with
    exit code 1 when the value is not there.  The captured machine file can
    only be imported with administrator rights, so the launcher has to know
    whether the data is already in place before deciding to ask for UAC.
    """
    if not IS_WINDOWS:
        return False
    try:
        import winreg
    except ImportError:  # pragma: no cover - Windows only
        return False

    roots = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    }
    checked = False
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


def _visible_window_pids() -> "set[int]":
    """PIDs that own at least one visible top-level window.

    A program the user is actually looking at must never be killed, no matter
    how long it runs.  A process without any window, on the other hand, is
    either a crash handler, an updater or a leftover service - exactly the
    kind of thing that keeps the portable folder undeletable.
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
            if user32.IsWindowVisible(hwnd):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    pids.add(int(pid.value))
            return True

        user32.EnumWindows(callback_type(collect), 0)
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


def open_files_in(root: Path, budget: float = 8.0
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
                if path and path.casefold().startswith(prefix):
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


def busy_files(root: Path, budget: float = 4.0, limit: int = 12
               ) -> "list[str]":
    """Файлы папки, которые Windows прямо сейчас не отдаёт.

    Проверка делом и без всяких прав: файл открывается на монопольный
    доступ. Именно это условие стоит за «файл открыт в другой программе»,
    то есть за невозможностью удалить папку. Файлы самого лончера
    пропускаются - они освободятся, как только лончер выйдет.
    """
    if not IS_WINDOWS or not root or not os.path.isdir(str(root)):
        return []
    import time

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
        for current, _dirs, files in os.walk(str(root)):
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
        if not suspects:
            return []
        time.sleep(0.4)
        return [path for path in suspects if locked(path)]
    except Exception:
        return []


def forget_fonts(root: Path, budget: float = 3.0) -> int:
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
        for current, _dirs, files in os.walk(str(root)):
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


def release_open_files(root: Path, budget: float = 8.0) -> "list[str]":
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

    items = open_files_in(root, budget=budget)
    if not items:
        return []
    visible = _visible_window_pids()
    stopped: list[str] = []
    background = sorted({
        pid for pid, _handle, _path, image in items
        if _image_name(image).casefold() not in PROTECTED_IMAGES
        and pid not in visible and not _installed_software_image(image)})
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
        # alive before it is treated as a leftover.
        "idle_grace": number("idle_grace", 20.0, 1.0, 3600.0),
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
                                 settings: Optional[Dict[str, float]] = None
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
    which the caller shuts them down.
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
        if any(pid in visible for pid, _ in running):
            idle_since = None
        elif idle_since is None:
            idle_since = now
        elif now - idle_since >= idle_grace:
            # Nothing on screen for a while: the user is done, whatever is
            # left is background noise the caller will clean up.
            return waited
        waited += 1
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
                             settings: Optional[Dict[str, float]] = None
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
    if not busy_files(root, budget=float(cfg.get("busy_budget", 4.0))):
        _LAST_CLEAN_SWEEP = time.monotonic()
        return []

    stopped: list[str] = []
    if forget_fonts(root):
        stopped.append("сняты с регистрации шрифты портатива")
    stopped.extend(release_open_files(root, budget=float(
        cfg.get("handle_budget", 8.0))))
    if not busy_files(root, budget=float(cfg.get("busy_budget", 4.0))):
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
    """

    def __init__(self) -> None:
        self.handle = None
        if not IS_WINDOWS:
            return
        try:
            import ctypes
            from ctypes import wintypes

            JobObjectExtendedLimitInformation = 9
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

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
            info.BasicLimitInformation.LimitFlags = \
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
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


def _run_elevated(arguments: Sequence[str]) -> Optional[int]:
    """Relaunch this frozen EXE through UAC and wait for its exit code."""
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
        kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        kernel32.CloseHandle(info.hProcess)
        return int(code.value)
    except Exception:
        return None


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
    if _portable_process_list(root):
        return []
    done: list[str] = []
    removed = purge_portable_temp(root, cfg)
    if removed:
        done.append(f"очищена временная папка портатива ({removed})")
    if temp_leftovers(root, cfg):
        done.extend(release_leftover_handles(root, shutdown_settings(cfg)))
        if purge_portable_temp(root, cfg):
            done.append("временная папка освобождена принудительно")
    return done


def run(argv: Optional[Sequence[str]] = None) -> int:
    root = find_portable_root()
    with (root / "launcher_config.json").open("r", encoding="utf-8-sig") as fh:
        cfg: Dict[str, Any] = json.load(fh)

    # Остатки прошлого запуска убираются ДО старта: иначе они так и будут
    # держать папку, пока пользователь не перезагрузит компьютер.
    stale = sweep_stale_session(root, cfg)
    if stale:
        _run_log(root, "cleaned up after the previous session: "
                 + ", ".join(sorted(set(stale))))

    # Сквозные сохранения. Сессия создаётся ДО любых перенаправлений: она
    # обязана запомнить настоящие «Документы» этого ПК, пока Known Folder
    # ещё указывает на них, а не внутрь портатива.
    shared_saves = SharedSaveSession(root, cfg)

    raw_arguments = _arguments_with_executable_alias(
        cfg, list(argv if argv is not None else sys.argv[1:])
    )
    target_rel, forwarded, needs_machine = _select_target(cfg, raw_arguments)
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

    # Not only launchers and configurators need the captured HKLM data: old
    # games (The Witcher and other GOG re-releases) read their install path
    # from HKLM themselves and quit with exit code 1 when it is not there.
    # VirtualStore covers un-manifested programs only, so when the keys really
    # are missing on this computer the machine file has to be imported for
    # real - and that needs administrator rights, once, for this run.
    if not needs_machine and machine_available and bool(registry_cfg.get("enabled")) \
            and _machine_file_needs_admin(machine_path) \
            and _hklm_key_missing(registry_cfg.get("keys", [])):
        needs_machine = True
        _run_log(root, "captured HKLM keys are missing on this PC: "
                       "the machine registry file has to be imported")

    if needs_machine and machine_available and not already_elevated \
            and not _is_elevated():
        elevated_code = _run_elevated(raw_arguments)
        if elevated_code is not None:
            # The elevated copy already reported its own result (including
            # the friendly error 14001 box when the runtime is missing), so
            # only record what happened.
            _run_log(root, f"elevated run finished with code "
                           f"{elevated_code}")
            if elevated_code == 1223:
                _run_log(root, "elevation declined at the UAC prompt; "
                               "the captured HKLM entries stay unimported")
            return elevated_code
        # UAC refused or unavailable: keep going with the VirtualStore
        # fallback instead of refusing to start the program at all.
        _run_log(root, "elevation was refused or unavailable; "
                       "continuing without the HKLM import")

    env = _prepare_environment(root, cfg)
    target = _as_relative_path(root, target_rel)
    if not target.is_file():
        alternative = root / "App" / str(target_rel).replace("\\", os.sep)
        if alternative.is_file():
            target = alternative
        else:
            raise FileNotFoundError(
                f"Исполняемый файл программы не найден:\n{target}")

    # Предстартовая проверка распространяемых компонентов: лучше назвать
    # пакет, чем оставить пользователя наедине с окном Windows
    # «отсутствует MSVCR110.dll».
    # Предстартовая проверка распространяемых компонентов. Если нужного
    # пакета на этом ПК нет, сначала пробуем поставить его МОЛЧА из папки
    # Redist — пользователь не должен закрывать окна с «OK» ни во время
    # сборки, ни при запуске. Сообщение остаётся только на тот случай,
    # когда тихая установка невозможна (нет установщика, отказ UAC).
    missing_runtime = missing_runtime_components(root, cfg, target, env)
    if missing_runtime:
        missing_runtime = install_missing_runtime(root, cfg, missing_runtime)
    if missing_runtime and _runtime_warning_is_new(root, cfg, missing_runtime):
        _warn_about_runtime(root, missing_runtime)

    # Сейвы, сделанные мимо лончера (прямой запуск App\Game.exe), забираются
    # в портатив ПЕРЕД стартом: иначе программа их просто не увидит.
    for line in shared_saves.before():
        _run_log(root, "shared saves: " + line)

    shell_folders = ShellFolderSession(root, cfg)
    registry = RegistrySession(root, cfg)
    shutdown = shutdown_settings(cfg)
    # Kill-on-close job: nothing started from the portable folder may outlive
    # this launcher, otherwise the user cannot delete the folder afterwards.
    job = _JobObject()
    shell_folders.load()
    try:
        registry.load()
        try:
            command = [
                str(target),
                *[str(arg) for arg in cfg.get("target_args", [])],
                *forwarded,
            ]
            _run_log(root, "start: " + subprocess.list2cmdline(command)
                     + f" (cwd={target.parent}, elevated={_is_elevated()}, "
                     + f"job={'yes' if job.handle else 'no'})")
            try:
                code = _spawn_target(
                    command, str(target.parent), env, job).wait()
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
                    "Чинится один раз: запустите Redist\\Install-Redist.cmd "
                    "из портативной папки — он поставит нужные пакеты молча, "
                    "с одним UAC-запросом. Подробности и ссылки — в файле "
                    "redistributables.txt.")
                return 14001
            _run_log(root, f"{target.name} exited with code {code}")
            # The official launcher usually starts the game and exits at once.
            # Restoring the registry right now would pull the install keys out
            # from under the game that is just starting, so wait for it.
            waited = _wait_for_portable_processes(root, settings=shutdown)
            if waited:
                _run_log(root, f"waited {waited}s for programs started from "
                               f"the portable folder to finish")
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
            registry.save_and_restore()
    finally:
        shell_folders.restore()
        # Safety net for every path that skipped the block above (an error,
        # a program that spawned something during shutdown): sweep again and
        # drop the job handle - Windows finishes off anything that ignored
        # us.  Only after this the folder can really be deleted.
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
        # Временная папка портатива не должна пережить сеанс: именно
        # распакованные в неё файлы (шрифты установщика, DLL «помощников»)
        # потом подхватывает система и держит их месяцами.
        removed = purge_portable_temp(root, cfg)
        if removed:
            _run_log(root, f"cleared the portable temp folder ({removed})")
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
        with (root / "launcher_config.json").open("r", encoding="utf-8-sig") as fh:
            cfg = json.load(fh)
        settings = shutdown_settings(cfg)
    except (OSError, ValueError):
        pass
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


def sync_saves(root: Optional[Path] = None) -> int:
    """``LaunchPortable.exe --sync-saves``: свести сохранения вручную.

    Нужно ровно в одном случае: программу запускали напрямую из ``App``,
    мимо лончера, и теперь её сейвы хочется увидеть в портативе (или
    наоборот) не дожидаясь следующего запуска через лончер.
    """
    root = root or find_portable_root()
    with (root / "launcher_config.json").open("r", encoding="utf-8-sig") as fh:
        cfg: Dict[str, Any] = json.load(fh)
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


def main() -> int:
    root: Optional[Path] = None
    try:
        root = find_portable_root()
        if any(str(arg).casefold() in ("--stop", "/stop")
               for arg in sys.argv[1:]):
            return stop(root)
        if any(str(arg).casefold() in ("--sync-saves", "/sync-saves")
               for arg in sys.argv[1:]):
            return sync_saves(root)
        if any(str(arg).casefold() in ("--check-identity", "/check-identity")
               for arg in sys.argv[1:]):
            return check_identity(root)
        return run()
    except Exception as exc:
        details = f"Не удалось запустить портативную программу.\n\n{exc}"
        _write_error_log(root, details + "\n\n" + traceback.format_exc())
        _show_error(details)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
