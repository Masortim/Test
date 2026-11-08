"""Read-only Windows Restart Manager lookup for exact locked file paths.

No RmShutdown/RmRestart or handle closure: an owner can be an unrelated
browser, editor, service or antivirus with unsaved data. Results are advisory.
"""
from __future__ import annotations

import os
import sys
from typing import List, NamedTuple, Sequence


class FileOwner(NamedTuple):
    pid: int
    app_name: str
    service_name: str
    path: str


def file_owners(paths: Sequence[str], max_files: int = 6) -> List[FileOwner]:
    if not sys.platform.startswith('win'):
        return []
    try:
        import ctypes
        from ctypes import wintypes

        class UniqueProcess(ctypes.Structure):
            _fields_ = [('pid', wintypes.DWORD), ('start', wintypes.FILETIME)]

        class ProcessInfo(ctypes.Structure):
            _fields_ = [('process', UniqueProcess),
                        ('app_name', wintypes.WCHAR * 256),
                        ('service_name', wintypes.WCHAR * 64),
                        ('app_type', ctypes.c_int),
                        ('app_status', wintypes.ULONG),
                        ('session_id', wintypes.DWORD),
                        ('restartable', wintypes.BOOL)]

        rm = ctypes.WinDLL('Rstrtmgr', use_last_error=True)
        rm.RmStartSession.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
                                      wintypes.LPWSTR]
        rm.RmStartSession.restype = wintypes.DWORD
        rm.RmRegisterResources.argtypes = [wintypes.DWORD, wintypes.UINT,
                                           ctypes.POINTER(wintypes.LPCWSTR),
                                           wintypes.UINT, ctypes.POINTER(UniqueProcess),
                                           wintypes.UINT, ctypes.POINTER(wintypes.LPCWSTR)]
        rm.RmRegisterResources.restype = wintypes.DWORD
        rm.RmGetList.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.UINT),
                                ctypes.POINTER(wintypes.UINT), ctypes.POINTER(ProcessInfo),
                                ctypes.POINTER(wintypes.DWORD)]
        rm.RmGetList.restype = wintypes.DWORD
        rm.RmEndSession.argtypes = [wintypes.DWORD]
        rm.RmEndSession.restype = wintypes.DWORD
        owners = []
        seen = set()
        for path in list(dict.fromkeys(paths))[:max_files]:
            session = wintypes.DWORD()
            key = ctypes.create_unicode_buffer(33)
            if rm.RmStartSession(ctypes.byref(session), 0, key) != 0:
                continue
            try:
                files = (wintypes.LPCWSTR * 1)(str(path))
                if rm.RmRegisterResources(session, 1, files, 0, None, 0, None) != 0:
                    continue
                needed, count, reasons = wintypes.UINT(), wintypes.UINT(), wintypes.DWORD()
                code = rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), None,
                                    ctypes.byref(reasons))
                if code != 234 or not needed.value or needed.value > 256:
                    continue
                for _ in range(2):
                    count.value = needed.value
                    array = (ProcessInfo * count.value)()
                    code = rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count),
                                        array, ctypes.byref(reasons))
                    if code != 234:
                        break
                    if needed.value > 256:
                        break
                if code != 0:
                    continue
                for info in array[:count.value]:
                    pid = int(info.process.pid)
                    marker = (pid, os.path.normcase(path))
                    if pid and pid != os.getpid() and marker not in seen:
                        owners.append(FileOwner(pid, info.app_name, info.service_name, str(path)))
                        seen.add(marker)
            finally:
                rm.RmEndSession(session)
        return owners
    except (AttributeError, OSError, ValueError, TypeError):
        return []
