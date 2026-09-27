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
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

ROOT_TOKEN = "@@PORTABLE_ROOT@@"
IS_WINDOWS = sys.platform.startswith("win")
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0
ERROR_ICON = 0x00000010


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
                _reg(("import", str(imported)))
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

    raw_arguments = list(argv if argv is not None else sys.argv[1:])
    target_rel, forwarded, needs_machine = _select_target(cfg, raw_arguments)
    already_elevated = any(
        str(arg).casefold() == "--elevated" for arg in raw_arguments)
    machine_name = str(cfg.get("registry", {}).get("machine_file", ""))
    machine_available = bool(machine_name and (root / machine_name).is_file())
    if needs_machine and machine_available and not already_elevated \
            and not _is_elevated():
        elevated_code = _run_elevated(raw_arguments)
        if elevated_code is None:
            raise PermissionError(
                "Для запуска конфигуратора нужны захваченные параметры HKLM. "
                "Разрешите запрос контроля учётных записей (UAC)."
            )
        return elevated_code

    env = _prepare_environment(root, cfg)
    target = _as_relative_path(root, target_rel)
    if not target.is_file():
        alternative = root / "App" / str(target_rel).replace("\\", os.sep)
        if alternative.is_file():
            target = alternative
        else:
            raise FileNotFoundError(
                f"Исполняемый файл программы не найден:\n{target}")

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
            return subprocess.run(
                command,
                cwd=str(target.parent),
                env=env,
                check=False,
            ).returncode
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
