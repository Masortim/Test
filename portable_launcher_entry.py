"""Entrypoint for the standalone launcher copied into ``App``.

This file is built as a small windowed Windows executable by PyInstaller.  The
resulting binary is bundled into Portablizer and copied to every portable app as
``App/LaunchPortable.exe``.  It deliberately uses only the Python standard
library so the generated executable has no dependency on the machine where the
portable app is started.
"""
from __future__ import annotations

import json
import os
import re
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


def _library_search_dirs(root: Path, target: Path,
                         env: Dict[str, str]) -> list[Path]:
    """Folders Windows will really look into when resolving a DLL."""
    dirs: list[Path] = [target.parent, root / "App", root]
    for entry in str(env.get("PATH", "")).split(os.pathsep)[:48]:
        entry = entry.strip().strip('"')
        if entry:
            dirs.append(Path(entry))
    windir = env.get("SystemRoot") or env.get("WINDIR") or r"C:\Windows"
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


def missing_runtime_components(root: Path, cfg: Dict[str, Any], target: Path,
                               env: Dict[str, str]) -> list[Dict[str, str]]:
    """Redistributable libraries that are absent on THIS computer.

    Portablizer bundles everything it can find while building the portable
    folder.  Whatever is left over is listed in ``launcher_config.json``;
    checking it here turns the cryptic Windows box ("MSVCR110.dll is
    missing") into the name of the package and a link to it.
    """
    requirements = cfg.get("runtime_requirements") or []
    if not isinstance(requirements, list) or not requirements:
        return []
    search_dirs = _library_search_dirs(root, target, env)
    missing: list[Dict[str, str]] = []
    for item in requirements[:32]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("dll", "")).strip()
        if not name:
            continue
        found = False
        for directory in search_dirs:
            try:
                if (directory / name).is_file():
                    found = True
                    break
            except OSError:
                continue
        if not found:
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
                     if not _library_present(root, str(item.get("dll", "")))]
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
    return [item for item in missing
            if not _library_present(root, str(item.get("dll", "")))]


def _library_present(root: Path, name: str) -> bool:
    """True when Windows can resolve the library right now."""
    if not name:
        return True
    windir = os.environ.get("SystemRoot") or r"C:\Windows"
    for directory in (root / "App", Path(windir) / "System32",
                      Path(windir) / "SysWOW64"):
        try:
            if (directory / name).is_file():
                return True
        except OSError:
            continue
    return False


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


def _portable_processes(root: Path) -> int:
    """Count running processes whose executable lives inside the portable folder."""
    if not IS_WINDOWS:
        return 0
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
            return 0
        prefix = str(root).rstrip("\\").casefold() + "\\"
        own = os.getpid()
        own_image = _own_executable_images()
        found = 0
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
                                    found += 1
                        finally:
                            kernel32.CloseHandle(handle)
                more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
        return found
    except Exception:
        return 0


def _wait_for_portable_processes(root: Path, grace: float = 6.0,
                                 limit: float = 86400.0) -> int:
    """Wait until nothing inside the portable folder is running any more.

    Official game launchers (The Witcher's ``Launcher.exe``, GOG splash
    screens, Configurator windows) start the real executable and exit
    immediately.  If the portable session restored the registry and removed the
    redirected environment at that moment, the game that had just been spawned
    lost its install keys and died silently.  So after the direct child exits we
    keep the sandbox alive while any process started from this folder lives.
    """
    if not IS_WINDOWS:
        return 0
    import time

    deadline = time.monotonic() + limit
    waited = 0
    # Give the launcher a moment to spawn the real program.
    spawn_deadline = time.monotonic() + grace
    while time.monotonic() < spawn_deadline:
        if _portable_processes(root):
            break
        time.sleep(0.5)
    while _portable_processes(root) and time.monotonic() < deadline:
        waited += 1
        time.sleep(1.0)
    return waited


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


def run(argv: Optional[Sequence[str]] = None) -> int:
    root = find_portable_root()
    with (root / "launcher_config.json").open("r", encoding="utf-8-sig") as fh:
        cfg: Dict[str, Any] = json.load(fh)

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

    shell_folders = ShellFolderSession(root, cfg)
    registry = RegistrySession(root, cfg)
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
                     + f" (cwd={target.parent}, elevated={_is_elevated()})")
            code = subprocess.run(
                command,
                cwd=str(target.parent),
                env=env,
                check=False,
            ).returncode
            _run_log(root, f"{target.name} exited with code {code}")
            # The official launcher usually starts the game and exits at once.
            # Restoring the registry right now would pull the install keys out
            # from under the game that is just starting, so wait for it.
            waited = _wait_for_portable_processes(root)
            if waited:
                _run_log(root, f"waited {waited}s for programs started from "
                               f"the portable folder to finish")
            return code
        finally:
            registry.save_and_restore()
    finally:
        shell_folders.restore()


def main() -> int:
    root: Optional[Path] = None
    try:
        root = find_portable_root()
        return run()
    except Exception as exc:
        details = f"Не удалось запустить портативную программу.\n\n{exc}"
        _write_error_log(root, details + "\n\n" + traceback.format_exc())
        _show_error(details)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
