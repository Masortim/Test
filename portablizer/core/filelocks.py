"""Bounded, non-destructive Windows DELETE-sharing diagnostics.

A single daemon worker performs the walk and all probes. A stuck filesystem
call cannot hang the UI, and large installations do not create one thread per
file. The result is advisory: no probe can promise that later deletion succeeds.
"""
from __future__ import annotations

import ctypes
import ntpath
import os
import threading
from typing import Callable, List, Optional, Sequence, Tuple


# Extended syntax also works without the system's LongPathsEnabled setting.
def extended_path(path: str) -> str:
    path = str(path).replace('/', '\\')
    if path.startswith(('\\\\?\\', '\\\\.\\')):
        return path
    path = ntpath.abspath(path)
    if path.startswith('\\\\'):
        return '\\\\?\\UNC\\' + path[2:]
    if len(path) >= 3 and path[1:3] == ':\\':
        return '\\\\?\\' + path
    return path


def display_path(path: str) -> str:
    if path.upper().startswith('\\\\?\\UNC\\'):
        return '\\\\' + path[8:]
    if path.startswith('\\\\?\\'):
        return path[4:]
    return path


def _native_path(path: str) -> str:
    return extended_path(path) if os.name == 'nt' else path


# --- Token privileges (Windows) -------------------------------------------
# WinINet creates ...\Windows\INetCache\Content.IE5 (and its Low\ twin) with a
# deny-ACE that blocks listing for the owner and administrators alike — the
# "Access Denied" folder. Backup mode is the supported way to walk such
# trees: SE_BACKUP_NAME bypasses ACL checks for traversal and listing, and
# SE_RESTORE_NAME for write-type opens (our DELETE probe). The privileges are
# enabled only inside the scan worker and restored when it exits. A regular
# user does not hold them at all; in that case the scan behaves exactly as
# before and an access error stays an explicitly reported, incomplete check —
# never a success.
SE_BACKUP_NAME = 'SeBackupPrivilege'
SE_RESTORE_NAME = 'SeRestorePrivilege'
_SE_PRIVILEGE_ENABLED = 0x00000002
_ERROR_NOT_ALL_ASSIGNED = 1300
_TOKEN_ADJUST_PRIVILEGES = 0x0020
_TOKEN_QUERY = 0x0008


class _LUID(ctypes.Structure):
    _fields_ = [('LowPart', ctypes.c_ulong), ('HighPart', ctypes.c_long)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Luid', _LUID), ('Attributes', ctypes.c_ulong)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [('PrivilegeCount', ctypes.c_ulong),
                ('Privileges', _LUID_AND_ATTRIBUTES * 1)]


def _set_privilege(name: str, enable: bool) -> bool:
    """Best-effort AdjustTokenPrivileges.

    Returns True only when the privilege ended in the requested state; False
    when the process does not hold it (e.g. unelevated or standard user) or
    anything failed. Never raises: a diagnostic must not crash on this.
    """
    if os.name != 'nt':
        return False
    try:
        kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
        advapi = ctypes.windll.advapi32  # type: ignore[attr-defined]
        token = ctypes.c_void_p()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(),
                                       _TOKEN_ADJUST_PRIVILEGES | _TOKEN_QUERY,
                                       ctypes.byref(token)):
            return False
        try:
            luid = _LUID()
            if not advapi.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                return False
            privileges = _TOKEN_PRIVILEGES()
            privileges.PrivilegeCount = 1
            privileges.Privileges[0].Luid = luid
            privileges.Privileges[0].Attributes = _SE_PRIVILEGE_ENABLED if enable else 0
            if not advapi.AdjustTokenPrivileges(token, False,
                                                ctypes.byref(privileges),
                                                0, None, None):
                return False
            return kernel.GetLastError() != _ERROR_NOT_ALL_ASSIGNED
        finally:
            try:
                kernel.CloseHandle(token)
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        return False


def acquire_scan_privileges() -> List[str]:
    """Enable backup/restore privileges; returns the names actually enabled."""
    enabled: List[str] = []
    for name in (SE_BACKUP_NAME, SE_RESTORE_NAME):
        if _set_privilege(name, True):
            enabled.append(name)
    return enabled


def release_scan_privileges(enabled: Sequence[str]) -> None:
    for name in enabled:
        _set_privilege(name, False)


def scan(roots: Sequence[str], budget: float, limit: int = 20,
         recheck: float = 0.4,
         skip: Optional[Callable[[str], bool]] = None) -> Tuple[List[str], List[str]]:
    """Return confirmed locks and diagnostic issues, never modify files.

    All unknown results (including a stalled scan) are reported. The worker
    closes a successfully opened handle even if the caller timed out already.
    """
    guard = threading.Lock()
    cancel = threading.Event()
    state = {'current': '', 'locked': [], 'issues': [], 'extra': 0}

    def current(path: str) -> None:
        with guard:
            state['current'] = display_path(path)

    def issue(text: str) -> None:
        with guard:
            if len(state['issues']) < 8:
                state['issues'].append(text)
            else:
                state['extra'] += 1

    def worker() -> None:
        try:
            privileges = acquire_scan_privileges()
        except Exception:  # noqa: BLE001 - a diagnostic must not crash on this
            privileges = []
        try:
            kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel.CreateFileW.restype = ctypes.c_void_p
            invalid = ctypes.c_void_p(-1).value
            hint_added = False

            def probe(path: str) -> Optional[bool]:
                current(path)
                try:
                    handle = kernel.CreateFileW(_native_path(path), 0x00010000, 7,
                                                None, 3, 0x80, None)
                    error = kernel.GetLastError() if handle in (None, 0, invalid) else 0
                    if not error and handle not in (None, 0, invalid):
                        kernel.CloseHandle(ctypes.c_void_p(handle))
                        return False
                    if error in (32, 33):
                        return True
                    if error in (2, 3):
                        # A disappearing cache file is normal; don't silently
                        # discard a path error when the file still exists.
                        try:
                            os.stat(_native_path(path))
                        except FileNotFoundError:
                            return False
                        except OSError:
                            pass
                    advice = ''
                    if error == 5:
                        advice = '; доступ запрещён, проверьте разрешения'
                        try:
                            kernel.GetFileAttributesW.restype = ctypes.c_uint32
                            attributes = kernel.GetFileAttributesW(_native_path(path))
                            if attributes != 0xFFFFFFFF and attributes & 1:
                                advice += ('; установлен атрибут «только чтение» '
                                           '(проверка его не меняла)')
                        except Exception:
                            pass
                    issue(f'{display_path(path)}: WinError {error}{advice}')
                except Exception as exc:  # noqa: BLE001 - a diagnostic must not crash
                    issue(f'{display_path(path)}: {type(exc).__name__}: {exc}')
                return None

            def walk_error(exc: OSError) -> None:
                nonlocal hint_added
                path = display_path(str(getattr(exc, 'filename', '') or 'каталог'))
                code = getattr(exc, 'winerror', None) or getattr(exc, 'errno', None)
                issue(f'{path}: ошибка обхода ({"WinError " + str(code) if code else str(exc)})')
                # Windows creates some cache directories (WinINet Content.IE5)
                # with a deny-ACE that hides them from everyone. Backup
                # privileges can see through it, but a regular user does not
                # hold them — then the honest message needs one hint, once.
                if not privileges and code == 5 and not hint_added:
                    hint_added = True
                    issue('Подсказка: каталог недоступен даже владельцу; '
                          'запуск Portablizer от имени администратора позволит '
                          'его проверить (чужие процессы закрываться не будут).')

            suspects: List[str] = []
            hit_limit = False
            for root in roots:
                current(root)
                for directory, dirs, files in os.walk(_native_path(root), onerror=walk_error):
                    dirs.sort(key=lambda item: (item.casefold() != 'portabledata', item.casefold()))
                    for name in files:
                        if cancel.is_set():
                            return
                        path = os.path.join(directory, name)
                        shown = display_path(path)
                        if skip and skip(shown):
                            continue
                        if probe(path) is True:
                            suspects.append(path)
                            if len(suspects) >= max(1, limit):
                                hit_limit = True
                                break
                    if hit_limit or cancel.is_set():
                        break
                if hit_limit or cancel.is_set():
                    break
            if hit_limit:
                issue(f'Проверка остановлена после {len(suspects)} занятых файлов; остальные не проверены.')
            if suspects and cancel.wait(max(0.0, recheck)):
                return
            for path in suspects:
                if cancel.is_set():
                    return
                if probe(path) is True:
                    with guard:
                        state['locked'].append(display_path(path))
        except Exception as exc:  # noqa: BLE001
            issue(f'Ошибка проверки: {type(exc).__name__}: {exc}')
        finally:
            try:
                release_scan_privileges(privileges)
            except Exception:  # noqa: BLE001
                pass

    thread = threading.Thread(target=worker, name='portable-file-check', daemon=True)
    try:
        thread.start()
    except RuntimeError as exc:
        return [], [f'Не удалось запустить проверку файлов: {exc}']
    thread.join(max(0.0, budget))
    if thread.is_alive():
        cancel.set()
        with guard:
            path = state['current']
        issue('Проверка не завершилась за отведённое время'
              + (f'; последний путь: {path}' if path else '') + '.')
    with guard:
        locked = list(state['locked'])
        issues = list(state['issues'])
        extra = state['extra']
    if extra:
        issues.append(f'Других ошибок проверки: {extra}.')
    return locked, issues
