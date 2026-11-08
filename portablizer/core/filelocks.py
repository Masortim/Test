"""Bounded, non-destructive Windows DELETE-sharing diagnostics.

A single daemon worker performs the walk and all probes. A stuck filesystem
call cannot hang the UI, and large installations do not create one thread per
file. The result is advisory: no probe can promise that later deletion succeeds.
"""
from __future__ import annotations

from collections import deque
import ctypes
import ntpath
import os
import re
import shutil
import stat
import sys
import threading
import time
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


# --- Reparse points & WinINet deny-list cache folders ----------------------
_FILE_ATTRIBUTE_DIRECTORY = 0x0010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_LIST_DIRECTORY = 0x0001
_FILE_TRAVERSE = 0x0020
_FILE_READ_ATTRIBUTES = 0x0080
_SYNCHRONIZE = 0x00100000
_GENERIC_ALL = 0x10000000
_GENERIC_READ = 0x80000000
_DENY_LIST_MASK = (
    _FILE_LIST_DIRECTORY
    | _FILE_TRAVERSE
    | _FILE_READ_ATTRIBUTES
    | _GENERIC_READ
    | _GENERIC_ALL
)

_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PROTECTED = 0x1000
_ACCESS_DENIED_ACE_TYPE = 1
_FileIdBothDirectoryInfo = 10
_ERROR_NO_MORE_FILES = 18

_WININET_CACHE_MARKERS = (
    '\\microsoft\\windows\\inetcache\\',
    '\\microsoft\\windows\\temporary internet files\\',
    '\\microsoft\\windows\\history\\',
    '\\local settings\\temporary internet files\\',
    '\\local settings\\history\\',
)
_WININET_LEAF_NAMES = frozenset({'content.ie5', 'history.ie5'})


class _ACL(ctypes.Structure):
    _fields_ = [
        ('AclRevision', ctypes.c_ubyte),
        ('Sbz1', ctypes.c_ubyte),
        ('AclSize', ctypes.c_ushort),
        ('AceCount', ctypes.c_ushort),
        ('Sbz2', ctypes.c_ushort),
    ]


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [
        ('AceType', ctypes.c_ubyte),
        ('AceFlags', ctypes.c_ubyte),
        ('AceSize', ctypes.c_ushort),
    ]


class _ACCESS_ACE(ctypes.Structure):
    _fields_ = [
        ('Header', _ACE_HEADER),
        ('Mask', ctypes.c_uint32),
        ('SidStart', ctypes.c_uint32),
    ]


class _FILE_ID_BOTH_DIR_INFO(ctypes.Structure):
    _fields_ = [
        ('NextEntryOffset', ctypes.c_uint32),
        ('FileIndex', ctypes.c_uint32),
        ('CreationTime', ctypes.c_int64),
        ('LastAccessTime', ctypes.c_int64),
        ('LastWriteTime', ctypes.c_int64),
        ('ChangeTime', ctypes.c_int64),
        ('EndOfFile', ctypes.c_int64),
        ('AllocationSize', ctypes.c_int64),
        ('FileAttributes', ctypes.c_uint32),
        ('FileNameLength', ctypes.c_uint32),
        ('EaSize', ctypes.c_uint32),
        ('ShortNameLength', ctypes.c_byte),
        ('ShortName', ctypes.c_wchar * 12),
        ('FileId', ctypes.c_int64),
        ('FileName', ctypes.c_wchar * 1),
    ]


def is_reparse_point(path: str) -> bool:
    """True when path is a symlink or NTFS junction/reparse point.

    Python 3.11's ``os.walk(..., followlinks=False)`` skips symlinks on Windows
    but still descends into NTFS directory junctions (``IO_REPARSE_TAG_MOUNT_POINT``),
    such as ``Temporary Internet Files``, ``Application Data``, or host
    ``EdgeWebView`` links inside ``PortableData``. Deleting or moving a portable
    folder removes only the link node itself, never the target's contents.
    """
    if not path:
        return False
    native = _native_path(path)
    try:
        if os.path.islink(native):
            return True
    except OSError:
        pass
    try:
        st = os.lstat(native)
        if stat.S_ISLNK(st.st_mode):
            return True
        attrs = int(getattr(st, 'st_file_attributes', 0) or 0)
        if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    except OSError:
        if os.name == 'nt':
            try:
                k32 = ctypes.WinDLL('kernel32', use_last_error=True)
                k32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
                k32.GetFileAttributesW.restype = ctypes.c_uint32
                attrs = int(k32.GetFileAttributesW(native))
                if attrs != 0xFFFFFFFF and (attrs & _FILE_ATTRIBUTE_REPARSE_POINT):
                    return True
            except Exception:  # noqa: BLE001
                pass
    return False


def _is_wininet_cache_dir(path: str) -> bool:
    norm = display_path(str(path)).replace('/', '\\').rstrip('\\').casefold()
    if not norm:
        return False
    leaf = norm.rsplit('\\', 1)[-1]
    check = norm + '\\'
    if any(marker in check for marker in _WININET_CACHE_MARKERS):
        return True
    return leaf in _WININET_LEAF_NAMES and '\\microsoft\\windows\\' in check


def _can_listdir(native_path: str) -> bool:
    try:
        os.listdir(native_path)
        return True
    except OSError:
        return False


def _strip_list_deny_aces(path: str) -> bool:
    """Remove WinINet's explicit deny-listing ACE from an owned cache directory.

    Windows ``wininet.dll`` creates ``INetCache\\Content.IE5`` (and ``Low\\Content.IE5``,
    ``History\\History.IE5``) inside redirected portable ``USERPROFILE`` /
    ``LOCALAPPDATA`` trees with ``Everyone:(DENY)(S,RD)``. That blocks standard
    (unelevated) lock scans, Explorer USB copies, and folder deletion even when
    nothing holds the folder open. Because the user who ran the portable build
    owns ``PortableData``, ``WRITE_DAC`` succeeds without administrator rights
    and without deleting any files. Never follows reparse points.
    """
    if os.name != 'nt' or not path or is_reparse_point(path):
        return False
    native = _native_path(path)
    try:
        st = os.lstat(native)
        if not stat.S_ISDIR(st.st_mode):
            return False
        if int(getattr(st, 'st_file_attributes', 0) or 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
            return False
    except OSError:
        return False

    try:
        os.listdir(native)
        return False
    except PermissionError as exc:
        if getattr(exc, 'winerror', None) not in (5, None):
            return False
    except OSError:
        return False

    try:
        advapi = ctypes.WinDLL('advapi32')
        k32 = ctypes.WinDLL('kernel32')
        advapi.GetNamedSecurityInfoW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.GetNamedSecurityInfoW.restype = ctypes.c_uint32
        advapi.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ushort),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        advapi.GetSecurityDescriptorControl.restype = ctypes.c_int
        advapi.GetAce.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.GetAce.restype = ctypes.c_int
        advapi.DeleteAce.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        advapi.DeleteAce.restype = ctypes.c_int
        advapi.SetNamedSecurityInfoW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        advapi.SetNamedSecurityInfoW.restype = ctypes.c_uint32
        k32.LocalFree.argtypes = [ctypes.c_void_p]
        k32.LocalFree.restype = ctypes.c_void_p

        p_dacl = ctypes.c_void_p()
        p_sd = ctypes.c_void_p()
        target = native
        rc = advapi.GetNamedSecurityInfoW(
            target, _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION,
            None, None, ctypes.byref(p_dacl), None, ctypes.byref(p_sd),
        )
        if rc != 0 and len(display_path(path)) < 260:
            target = display_path(path)
            rc = advapi.GetNamedSecurityInfoW(
                target, _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION,
                None, None, ctypes.byref(p_dacl), None, ctypes.byref(p_sd),
            )
        if rc != 0:
            if p_sd.value:
                k32.LocalFree(p_sd)
            return False
        try:
            removed = False
            if p_dacl.value:
                acl = _ACL.from_address(p_dacl.value)
                for idx in range(int(acl.AceCount) - 1, -1, -1):
                    ace_ptr = ctypes.c_void_p()
                    if not advapi.GetAce(p_dacl, idx, ctypes.byref(ace_ptr)) or not ace_ptr.value:
                        continue
                    ace = _ACCESS_ACE.from_address(ace_ptr.value)
                    if (ace.Header.AceType == _ACCESS_DENIED_ACE_TYPE
                            and (int(ace.Mask) & _DENY_LIST_MASK)):
                        if advapi.DeleteAce(p_dacl, idx):
                            removed = True

            control = ctypes.c_ushort(0)
            revision = ctypes.c_uint32(0)
            advapi.GetSecurityDescriptorControl(
                p_sd, ctypes.byref(control), ctypes.byref(revision),
            )
            if removed and p_dacl.value:
                sec_info = _DACL_SECURITY_INFORMATION | (
                    _PROTECTED_DACL_SECURITY_INFORMATION
                    if (control.value & _SE_DACL_PROTECTED)
                    else _UNPROTECTED_DACL_SECURITY_INFORMATION
                )
                advapi.SetNamedSecurityInfoW(
                    target, _SE_FILE_OBJECT, sec_info,
                    None, None, p_dacl, None,
                )
                if _can_listdir(native):
                    return True

            # Fallback when DACL lacked an explicit ALLOW for the owner and
            # blocked inheritance from parent INetCache.
            if p_dacl.value:
                advapi.SetNamedSecurityInfoW(
                    target, _SE_FILE_OBJECT,
                    _DACL_SECURITY_INFORMATION | _UNPROTECTED_DACL_SECURITY_INFORMATION,
                    None, None, p_dacl, None,
                )
                if _can_listdir(native):
                    return True
        finally:
            if p_sd.value:
                k32.LocalFree(p_sd)
    except Exception:  # noqa: BLE001
        return False
    return False


def unhide_wininet_cache(root: str, budget: float = 2.0) -> List[str]:
    """Clear WinINet deny-listing ACEs on cache folders inside ``root``.

    Only inspects redirected ``Microsoft\\Windows`` / ``Local Settings`` cache
    locations inside ``root`` (skipping ``App`` and all reparse points), never
    deletes files, and never touches paths outside ``root``.
    """
    if os.name != 'nt' or not root or is_reparse_point(root):
        return []
    native_root = _native_path(root)
    if not os.path.isdir(native_root):
        return []

    bases = [display_path(root)]
    try:
        for entry in os.scandir(native_root):
            if entry.name.casefold() == 'app':
                continue
            child = os.path.join(display_path(root), entry.name)
            if is_reparse_point(child):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    bases.append(child)
            except OSError:
                continue
    except OSError:
        pass

    rel_candidates = (
        ('Microsoft', 'Windows'),
        ('AppData', 'Local', 'Microsoft', 'Windows'),
        ('AppData', 'LocalLow', 'Microsoft', 'Windows'),
        ('AppData', 'Roaming', 'Microsoft', 'Windows'),
        ('Local Settings', 'Temporary Internet Files'),
        ('Local Settings', 'History'),
        ('User', 'AppData', 'Local', 'Microsoft', 'Windows'),
        ('User', 'AppData', 'LocalLow', 'Microsoft', 'Windows'),
        ('User', 'AppData', 'Roaming', 'Microsoft', 'Windows'),
        ('User', 'Local Settings', 'Temporary Internet Files'),
        ('User', 'Local Settings', 'History'),
    )
    queue: deque[str] = deque()
    seen = set()

    def enqueue(candidate: str) -> None:
        key = os.path.normcase(display_path(candidate).rstrip('\\/'))
        if key in seen or is_reparse_point(candidate):
            return
        try:
            st = os.lstat(_native_path(candidate))
            if not stat.S_ISDIR(st.st_mode):
                return
            if int(getattr(st, 'st_file_attributes', 0) or 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
                return
        except OSError:
            return
        seen.add(key)
        queue.append(display_path(candidate))

    if _is_wininet_cache_dir(root) or '\\microsoft\\windows' in display_path(root).replace('/', '\\').casefold():
        enqueue(root)
    for base in bases:
        for rel in rel_candidates:
            enqueue(os.path.join(base, *rel))

    unhidden: List[str] = []
    deadline = time.monotonic() + max(0.1, budget)
    while queue and time.monotonic() <= deadline:
        cur = queue.popleft()
        if _is_wininet_cache_dir(cur) and _strip_list_deny_aces(cur):
            unhidden.append(display_path(cur))
        try:
            entries = list(os.scandir(_native_path(cur)))
        except OSError:
            continue
        for entry in entries:
            child = os.path.join(cur, entry.name)
            if is_reparse_point(child):
                continue
            try:
                st = os.lstat(_native_path(child))
                if not stat.S_ISDIR(st.st_mode):
                    continue
                if int(getattr(st, 'st_file_attributes', 0) or 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
            except OSError:
                continue
            enqueue(child)
    return unhidden


# --- Token privileges (Windows) -------------------------------------------
# Backup mode is the supported way to walk ACL-restricted trees when elevated:
# SE_BACKUP_NAME bypasses ACL checks for traversal/listing ONLY when combined
# with FILE_FLAG_BACKUP_SEMANTICS, and SE_RESTORE_NAME for write-type opens
# (our DELETE probe with FILE_FLAG_BACKUP_SEMANTICS). The privileges are
# enabled only inside the scan worker and restored when it exits.
SE_BACKUP_NAME = 'SeBackupPrivilege'
SE_RESTORE_NAME = 'SeRestorePrivilege'
SE_TAKE_OWNERSHIP_NAME = 'SeTakeOwnershipPrivilege'
_SE_PRIVILEGE_ENABLED = 0x00000002
_ERROR_NOT_ALL_ASSIGNED = 1300
_TOKEN_ADJUST_PRIVILEGES = 0x0020
_TOKEN_QUERY = 0x0008
_OWNER_SECURITY_INFORMATION = 0x00000001
_ACCESS_ALLOWED_ACE_TYPE = 0
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_INHERIT_BOTH = _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE
_FILE_ALL_ACCESS = 0x001F01FF
_FILE_ATTRIBUTE_READONLY = 0x0001
_FILE_ATTRIBUTE_HIDDEN = 0x0002
_FILE_ATTRIBUTE_SYSTEM = 0x0004
_FILE_ATTRIBUTE_NORMAL = 0x0080
_CLEARABLE_ATTRS = (
    _FILE_ATTRIBUTE_READONLY | _FILE_ATTRIBUTE_HIDDEN | _FILE_ATTRIBUTE_SYSTEM
)
_SID_RE = re.compile(r'^S-1-\d+(?:-\d+){1,15}$')


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


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Sid', ctypes.c_void_p), ('Attributes', ctypes.c_uint32)]


class _TRUSTEE_W(ctypes.Structure):
    _fields_ = [
        ('pMultipleTrustee', ctypes.c_void_p),
        ('MultipleTrusteeOperation', ctypes.c_uint),
        ('TrusteeForm', ctypes.c_uint),
        ('TrusteeType', ctypes.c_uint),
        ('ptstrName', ctypes.c_void_p),
    ]


class _EXPLICIT_ACCESS_W(ctypes.Structure):
    _fields_ = [
        ('grfAccessPermissions', ctypes.c_uint32),
        ('grfAccessMode', ctypes.c_uint),
        ('grfInheritance', ctypes.c_uint32),
        ('Trustee', _TRUSTEE_W),
    ]


def _is_subpath_or_same(candidate: str, root: str) -> bool:
    if not candidate or not root:
        return False
    c = os.path.normcase(os.path.abspath(display_path(candidate))).rstrip('\\/')
    r = os.path.normcase(os.path.abspath(display_path(root))).rstrip('\\/')
    return bool(c and r) and (c == r or c.startswith(r + os.sep))


def clear_readonly(path: str) -> None:
    """Clear read-only/hidden/system flags on a non-reparse file or directory.

    Windows ``RemoveDirectoryW`` and ``DeleteFileW`` fail with ``WinError 5``
    (Access is denied) whenever ``FILE_ATTRIBUTE_READONLY`` is set — including
    on empty directories marked ``+R`` for custom ``desktop.ini`` folder icons
    (common in Inno Setup repacks such as ``App\\PyCharm2025.2``). Never touches
    reparse points so junction targets outside the portable folder stay safe.
    """
    if not path or is_reparse_point(path):
        return
    native = _native_path(path)
    if os.name == 'nt':
        try:
            k32 = ctypes.WinDLL('kernel32', use_last_error=True)
            k32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
            k32.GetFileAttributesW.restype = ctypes.c_uint32
            k32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
            k32.SetFileAttributesW.restype = ctypes.c_int
            attrs = int(k32.GetFileAttributesW(native))
            if (attrs != 0xFFFFFFFF
                    and not (attrs & _FILE_ATTRIBUTE_REPARSE_POINT)
                    and (attrs & _CLEARABLE_ATTRS)):
                new_attrs = (attrs & ~_CLEARABLE_ATTRS) or _FILE_ATTRIBUTE_NORMAL
                k32.SetFileAttributesW(native, new_attrs)
        except Exception:  # noqa: BLE001
            pass
    try:
        st = os.lstat(native)
        if not stat.S_ISLNK(st.st_mode):
            need = 0o700 if stat.S_ISDIR(st.st_mode) else 0o600
            if (st.st_mode & need) != need:
                os.chmod(native, st.st_mode | need)
    except OSError:
        pass


def current_user_sid_string() -> str:
    """Return the current process ``TokenUser`` SID string (``S-1-5-...``).

    Even under UAC split-token elevation (where ``TokenOwner`` becomes
    ``BUILTIN\\Administrators``), ``TokenUser`` remains the interactive user's
    SID, allowing elevated builds to grant inheritable access back to the
    unelevated user.
    """
    if os.name != 'nt':
        return ''
    try:
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        k32.GetCurrentProcess.argtypes = []
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.restype = ctypes.c_int
        k32.LocalFree.argtypes = [ctypes.c_void_p]
        k32.LocalFree.restype = ctypes.c_void_p
        advapi.OpenProcessToken.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.OpenProcessToken.restype = ctypes.c_int
        advapi.GetTokenInformation.argtypes = [
            ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
        ]
        advapi.GetTokenInformation.restype = ctypes.c_int
        advapi.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.ConvertSidToStringSidW.restype = ctypes.c_int

        token = ctypes.c_void_p()
        if not advapi.OpenProcessToken(
            ctypes.c_void_p(k32.GetCurrentProcess()), _TOKEN_QUERY, ctypes.byref(token),
        ):
            return ''
        try:
            needed = ctypes.c_uint32(0)
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            if not needed.value or needed.value > 4096:
                return ''
            buf = ctypes.create_string_buffer(int(needed.value))
            if not advapi.GetTokenInformation(
                token, 1, buf, needed.value, ctypes.byref(needed),
            ):
                return ''
            info = _SID_AND_ATTRIBUTES.from_buffer(buf)
            if not info.Sid:
                return ''
            str_ptr = ctypes.c_void_p()
            if not advapi.ConvertSidToStringSidW(
                ctypes.c_void_p(info.Sid), ctypes.byref(str_ptr),
            ) or not str_ptr.value:
                return ''
            try:
                sid = ctypes.wstring_at(str_ptr.value)
                return sid if _SID_RE.match(sid) else ''
            finally:
                k32.LocalFree(str_ptr)
        finally:
            k32.CloseHandle(token)
    except Exception:  # noqa: BLE001
        return ''


def ensure_user_dir_access(path: str) -> bool:
    """Ensure ``TokenUser`` has inheritable ``(OI)(CI)`` full access on ``path``.

    On secondary NTFS volumes (``D:\\``, ``E:\\``), Windows's default root DACL
    grants ``FullControl`` only to ``CREATOR OWNER`` and ``Administrators``,
    giving ``BUILTIN\\Users`` only ``Read & Execute`` without ``DELETE``. When an
    elevated installer creates ``App\\...``, ``CREATOR OWNER`` resolves to
    ``Administrators`` and a later unelevated run cannot clean or delete its own
    portable folder unless ``portable_dir`` carries an inheritable allow ACE for
    ``TokenUser``. Idempotent: skips ``SetNamedSecurityInfoW`` when already set.
    """
    if os.name != 'nt' or not path or is_reparse_point(path):
        return False
    sid_str = current_user_sid_string()
    if not sid_str:
        return False
    native = _native_path(path)
    try:
        st = os.lstat(native)
        if not stat.S_ISDIR(st.st_mode):
            return False
        if int(getattr(st, 'st_file_attributes', 0) or 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
            return False
    except OSError:
        return False

    try:
        advapi = ctypes.WinDLL('advapi32')
        k32 = ctypes.WinDLL('kernel32')
        k32.LocalFree.argtypes = [ctypes.c_void_p]
        k32.LocalFree.restype = ctypes.c_void_p
        advapi.ConvertStringSidToSidW.argtypes = [
            ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.ConvertStringSidToSidW.restype = ctypes.c_int
        advapi.GetNamedSecurityInfoW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.GetNamedSecurityInfoW.restype = ctypes.c_uint32
        advapi.GetAce.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.GetAce.restype = ctypes.c_int
        advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        advapi.EqualSid.restype = ctypes.c_int
        advapi.SetEntriesInAclW.argtypes = [
            ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.SetEntriesInAclW.restype = ctypes.c_uint32
        advapi.SetNamedSecurityInfoW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        advapi.SetNamedSecurityInfoW.restype = ctypes.c_uint32

        user_sid = ctypes.c_void_p()
        if not advapi.ConvertStringSidToSidW(sid_str, ctypes.byref(user_sid)) or not user_sid.value:
            return False
        try:
            p_dacl = ctypes.c_void_p()
            p_sd = ctypes.c_void_p()
            target = native
            rc = advapi.GetNamedSecurityInfoW(
                target, _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION,
                None, None, ctypes.byref(p_dacl), None, ctypes.byref(p_sd),
            )
            if rc != 0 and len(display_path(path)) < 260:
                target = display_path(path)
                rc = advapi.GetNamedSecurityInfoW(
                    target, _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION,
                    None, None, ctypes.byref(p_dacl), None, ctypes.byref(p_sd),
                )
            if rc != 0:
                if p_sd.value:
                    k32.LocalFree(p_sd)
                return False
            try:
                if p_dacl.value:
                    acl = _ACL.from_address(p_dacl.value)
                    for idx in range(int(acl.AceCount)):
                        ace_ptr = ctypes.c_void_p()
                        if not advapi.GetAce(p_dacl, idx, ctypes.byref(ace_ptr)) or not ace_ptr.value:
                            continue
                        ace = _ACCESS_ACE.from_address(ace_ptr.value)
                        if (ace.Header.AceType == _ACCESS_ALLOWED_ACE_TYPE
                                and (ace.Header.AceFlags & _INHERIT_BOTH) == _INHERIT_BOTH
                                and (int(ace.Mask) & _FILE_ALL_ACCESS) == _FILE_ALL_ACCESS):
                            ace_sid = ctypes.c_void_p(ace_ptr.value + 8)
                            if advapi.EqualSid(ace_sid, user_sid):
                                return True

                ea = _EXPLICIT_ACCESS_W()
                ea.grfAccessPermissions = _GENERIC_ALL
                ea.grfAccessMode = 1  # GRANT_ACCESS
                ea.grfInheritance = _INHERIT_BOTH
                ea.Trustee.pMultipleTrustee = None
                ea.Trustee.MultipleTrusteeOperation = 0
                ea.Trustee.TrusteeForm = 0  # TRUSTEE_IS_SID
                ea.Trustee.TrusteeType = 1  # TRUSTEE_IS_USER
                ea.Trustee.ptstrName = user_sid.value

                new_dacl = ctypes.c_void_p()
                if advapi.SetEntriesInAclW(
                    1, ctypes.byref(ea), p_dacl, ctypes.byref(new_dacl),
                ) != 0 or not new_dacl.value:
                    return False
                try:
                    return advapi.SetNamedSecurityInfoW(
                        target, _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION,
                        None, None, new_dacl, None,
                    ) == 0
                finally:
                    k32.LocalFree(new_dacl)
            finally:
                if p_sd.value:
                    k32.LocalFree(p_sd)
        finally:
            k32.LocalFree(user_sid)
    except Exception:  # noqa: BLE001
        return False


def unlock_path_for_delete(path: str, stop_at: str = '') -> bool:
    """Clear restrictive attributes/DACL on an owned (or elevated) doomed path.

    Used ONLY inside destructive tree/file removal when ``os.unlink``,
    ``os.rmdir``, or ``os.scandir`` failed with ``PermissionError``. Never
    touches reparse points or paths outside ``stop_at``.
    """
    if not path or is_reparse_point(path):
        return False
    clear_readonly(path)
    parent = os.path.dirname(os.path.abspath(display_path(path)))
    if stop_at and _is_subpath_or_same(parent, stop_at):
        clear_readonly(parent)
    if os.name != 'nt':
        return True

    sid_str = current_user_sid_string()
    if not sid_str:
        return False
    sddl = f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid_str})'
    try:
        advapi = ctypes.WinDLL('advapi32')
        k32 = ctypes.WinDLL('kernel32')
        k32.LocalFree.argtypes = [ctypes.c_void_p]
        k32.LocalFree.restype = ctypes.c_void_p
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32),
        ]
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
        advapi.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int),
        ]
        advapi.GetSecurityDescriptorDacl.restype = ctypes.c_int
        advapi.ConvertStringSidToSidW.argtypes = [
            ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.ConvertStringSidToSidW.restype = ctypes.c_int
        advapi.SetNamedSecurityInfoW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        advapi.SetNamedSecurityInfoW.restype = ctypes.c_uint32

        sd_ptr = ctypes.c_void_p()
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(sd_ptr), None,
        ) or not sd_ptr.value:
            return False
        try:
            present = ctypes.c_int(0)
            defaulted = ctypes.c_int(0)
            dacl_ptr = ctypes.c_void_p()
            if not advapi.GetSecurityDescriptorDacl(
                sd_ptr, ctypes.byref(present), ctypes.byref(dacl_ptr), ctypes.byref(defaulted),
            ) or not dacl_ptr.value:
                return False

            target = _native_path(path)
            sec_flags = _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION
            rc = advapi.SetNamedSecurityInfoW(
                target, _SE_FILE_OBJECT, sec_flags, None, None, dacl_ptr, None,
            )
            if rc != 0 and len(display_path(path)) < 260:
                rc = advapi.SetNamedSecurityInfoW(
                    display_path(path), _SE_FILE_OBJECT, sec_flags,
                    None, None, dacl_ptr, None,
                )
            if rc != 0:
                privs = [
                    p for p in (SE_TAKE_OWNERSHIP_NAME, SE_RESTORE_NAME, SE_BACKUP_NAME)
                    if _set_privilege(p, True)
                ]
                try:
                    if privs:
                        user_sid = ctypes.c_void_p()
                        if advapi.ConvertStringSidToSidW(sid_str, ctypes.byref(user_sid)) and user_sid.value:
                            try:
                                advapi.SetNamedSecurityInfoW(
                                    target, _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION,
                                    user_sid, None, None, None,
                                )
                            finally:
                                k32.LocalFree(user_sid)
                        rc = advapi.SetNamedSecurityInfoW(
                            target, _SE_FILE_OBJECT, sec_flags, None, None, dacl_ptr, None,
                        )
                finally:
                    release_scan_privileges(privs)
            clear_readonly(path)
            if stop_at and _is_subpath_or_same(parent, stop_at):
                ensure_user_dir_access(parent)
            return rc == 0
        finally:
            k32.LocalFree(sd_ptr)
    except Exception:  # noqa: BLE001
        return False


def make_rmtree_onerror(stop_at: str = '', swallow: bool = False) -> Callable:
    """Create an ``shutil.rmtree(..., onerror=...)`` handler for Windows trees.

    Clears ``READONLY | HIDDEN | SYSTEM`` flags on files and directories (such as
    ``App\\PyCharm2025.2`` marked ``+R`` for ``desktop.ini`` folder icons),
    unlocks owned restrictive DACLs, unlinks nested NTFS junctions/symlinks
    without traversing into their targets, and handles ``MAX_PATH`` paths.
    """
    def _handler(func: Callable, target: str, exc_info: tuple) -> None:
        exc = exc_info[1]
        if isinstance(exc, FileNotFoundError):
            return
        try:
            if is_reparse_point(target):
                native_link = _native_path(target)
                try:
                    os.rmdir(native_link)
                except OSError:
                    os.unlink(native_link)
                return

            clear_readonly(target)
            if stop_at:
                parent = os.path.dirname(os.path.abspath(display_path(target)))
                if _is_subpath_or_same(parent, stop_at):
                    clear_readonly(parent)

            native = _native_path(target)
            if func in (os.scandir, os.listdir):
                try:
                    entries = list(os.scandir(native))
                except OSError:
                    unlock_path_for_delete(target, stop_at=stop_at)
                    entries = list(os.scandir(native))
                for entry in entries:
                    child = os.path.join(display_path(target), entry.name)
                    if is_reparse_point(child):
                        try:
                            os.rmdir(_native_path(child))
                        except OSError:
                            os.unlink(_native_path(child))
                    elif entry.is_dir(follow_symlinks=False):
                        shutil.rmtree(child, onerror=_handler)
                    else:
                        try:
                            os.unlink(_native_path(child))
                        except OSError:
                            _handler(os.unlink, child, sys.exc_info())
                return

            try:
                func(native)
                return
            except FileNotFoundError:
                return
            except OSError:
                unlock_path_for_delete(target, stop_at=stop_at)
                time.sleep(0.05)
                if func is os.rmdir and os.path.isdir(native) and not is_reparse_point(target):
                    for entry in list(os.scandir(native)):
                        child = os.path.join(display_path(target), entry.name)
                        if is_reparse_point(child):
                            try:
                                os.rmdir(_native_path(child))
                            except OSError:
                                os.unlink(_native_path(child))
                        elif entry.is_dir(follow_symlinks=False):
                            shutil.rmtree(child, onerror=_handler)
                        else:
                            clear_readonly(child)
                            unlock_path_for_delete(child, stop_at=stop_at)
                            os.unlink(_native_path(child))
                try:
                    func(native)
                    return
                except FileNotFoundError:
                    return
        except OSError:
            if swallow:
                return
            raise exc
    return _handler


def rmtree_robust(path: str) -> None:
    """Remove directory tree ``path`` safely without traversing reparse points."""
    if not path:
        return
    if is_reparse_point(path) or os.path.islink(path):
        native_link = _native_path(path)
        try:
            os.rmdir(native_link)
        except OSError:
            os.unlink(native_link)
        return
    unhide_wininet_cache(path)
    walk_root = _native_path(path) if (os.name == 'nt' and len(os.path.abspath(path)) >= 240) else path
    for current, dirs, _files in os.walk(walk_root, topdown=True, followlinks=False):
        for name in list(dirs):
            child = os.path.join(current, name)
            if not is_reparse_point(child):
                continue
            clear_readonly(current)
            try:
                os.rmdir(_native_path(child))
            except OSError:
                try:
                    os.unlink(_native_path(child))
                except OSError:
                    pass
            dirs.remove(name)
    clear_readonly(path)
    shutil.rmtree(walk_root, onerror=make_rmtree_onerror(stop_at=path, swallow=False))


def _backup_list_dir(native_dir_path: str) -> Optional[Tuple[List[str], List[str]]]:
    """List a directory via FILE_FLAG_BACKUP_SEMANTICS when FindFirstFileW is denied."""
    if os.name != 'nt' or not native_dir_path:
        return None
    try:
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        k32.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.GetFileInformationByHandleEx.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
        ]
        k32.GetFileInformationByHandleEx.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.restype = ctypes.c_int

        invalid = ctypes.c_void_p(-1).value
        handle = k32.CreateFileW(
            native_dir_path,
            _FILE_LIST_DIRECTORY | _SYNCHRONIZE,
            7,
            None,
            3,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle in (None, 0, invalid):
            return None
        subdirs: List[str] = []
        files: List[str] = []
        buf = ctypes.create_string_buffer(65536)
        name_offset = _FILE_ID_BOTH_DIR_INFO.FileName.offset
        try:
            while True:
                if not k32.GetFileInformationByHandleEx(
                    handle, _FileIdBothDirectoryInfo, buf, len(buf),
                ):
                    if ctypes.get_last_error() == _ERROR_NO_MORE_FILES:
                        break
                    return None
                offset = 0
                base = ctypes.addressof(buf)
                while True:
                    entry = _FILE_ID_BOTH_DIR_INFO.from_address(base + offset)
                    nchars = int(entry.FileNameLength) // ctypes.sizeof(ctypes.c_wchar)
                    if nchars > 0:
                        name = ctypes.wstring_at(base + offset + name_offset, nchars)
                        if name not in ('.', '..'):
                            attrs = int(entry.FileAttributes)
                            if attrs & _FILE_ATTRIBUTE_DIRECTORY:
                                if not (attrs & _FILE_ATTRIBUTE_REPARSE_POINT):
                                    subdirs.append(name)
                            else:
                                files.append(name)
                    if not entry.NextEntryOffset:
                        break
                    offset += int(entry.NextEntryOffset)
        finally:
            k32.CloseHandle(ctypes.c_void_p(handle))
        return subdirs, files
    except Exception:  # noqa: BLE001
        return None


def scan(roots: Sequence[str], budget: float, limit: int = 20,
         recheck: float = 0.4,
         skip: Optional[Callable[[str], bool]] = None) -> Tuple[List[str], List[str]]:
    """Return confirmed locks and diagnostic issues, never modify user files.

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
            open_flags = 0x80 | (_FILE_FLAG_BACKUP_SEMANTICS if privileges else 0)
            hint_added = False
            suspects: List[str] = []
            hit_limit = False
            unhidden_tried = set()

            def probe(path: str) -> Optional[bool]:
                current(path)
                try:
                    handle = kernel.CreateFileW(_native_path(path), 0x00010000, 7,
                                                None, 3, open_flags, None)
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

            def check_file(path: str) -> bool:
                """Return True if scan should stop (cancelled or hit limit)."""
                nonlocal hit_limit
                if cancel.is_set():
                    return True
                shown = display_path(path)
                if skip and skip(shown):
                    return False
                if probe(path) is True:
                    suspects.append(path)
                    if len(suspects) >= max(1, limit):
                        hit_limit = True
                        return True
                return False

            def backup_walk_tree(start_dir: str) -> bool:
                """Enumerate an ACL-hidden subtree using FILE_FLAG_BACKUP_SEMANTICS."""
                first = _backup_list_dir(_native_path(start_dir))
                if first is None:
                    return False
                pending: deque[Tuple[str, Optional[Tuple[List[str], List[str]]]]] = deque(
                    [(start_dir, first)]
                )
                while pending and not hit_limit and not cancel.is_set():
                    cur_dir, listed = pending.popleft()
                    current(cur_dir)
                    if listed is None:
                        listed = _backup_list_dir(_native_path(cur_dir))
                        if listed is None:
                            issue(f'{display_path(cur_dir)}: ошибка обхода (WinError 5)')
                            continue
                    subdirs, dir_files = listed
                    subdirs.sort(key=str.casefold)
                    for fname in dir_files:
                        if check_file(os.path.join(cur_dir, fname)):
                            return True
                    for dname in subdirs:
                        pending.append((os.path.join(cur_dir, dname), None))
                return True

            def report_walk_error(raw_path: str, code: object, exc: OSError) -> None:
                nonlocal hint_added
                path = display_path(raw_path or 'каталог')
                issue(f'{path}: ошибка обхода ({"WinError " + str(code) if code else str(exc)})')
                if not privileges and code == 5 and not hint_added:
                    hint_added = True
                    issue('Подсказка: каталог недоступен даже владельцу; '
                          'запуск Portablizer от имени администратора позволит '
                          'его проверить (чужие процессы закрываться не будут).')

            def walk_error(exc: OSError) -> None:
                raw_name = getattr(exc, 'filename', None)
                raw_text = str(raw_name) if raw_name else ''
                code = getattr(exc, 'winerror', None) or getattr(exc, 'errno', None)
                if os.name == 'nt' and code == 5 and raw_text:
                    if is_reparse_point(raw_text):
                        return
                    norm_key = os.path.normcase(display_path(raw_text))
                    if (norm_key not in unhidden_tried
                            and _is_wininet_cache_dir(raw_text)):
                        unhidden_tried.add(norm_key)
                        if _strip_list_deny_aces(raw_text):
                            walk_tree(raw_text)
                            return
                    if SE_BACKUP_NAME in privileges and backup_walk_tree(raw_text):
                        return
                report_walk_error(raw_text, code, exc)

            def walk_tree(start_root: str) -> None:
                current(start_root)
                if is_reparse_point(start_root):
                    return
                for directory, dirs, files in os.walk(_native_path(start_root),
                                                      onerror=walk_error):
                    dirs[:] = [
                        d for d in dirs
                        if not is_reparse_point(os.path.join(directory, d))
                    ]
                    dirs.sort(key=lambda item: (item.casefold() != 'portabledata',
                                                item.casefold()))
                    for name in files:
                        if check_file(os.path.join(directory, name)):
                            break
                    if hit_limit or cancel.is_set():
                        break

            for root in roots:
                walk_tree(root)
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
