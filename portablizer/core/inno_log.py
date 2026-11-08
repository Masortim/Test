"""Best-effort diagnosis of Inno Setup's diagnostic log.

Inno does not promise a stable machine-readable log format. Only recognize
explicit message-box records; never guess a cause from an exit code alone.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

_MAX_BYTES = 1024 * 1024
_TIMESTAMP = re.compile(r'^\s*\[\d{2}:\d{2}:\d{2}(?:\.\d+)?\]')
_SUPPRESSED = re.compile(r'defaulting to\s+abort\s+for suppressed message box\s*\(', re.I)
_DIALOG = re.compile(r'message box\s*\(\s*abort\s*/\s*retry', re.I)
_CHOSE_ABORT = re.compile(r'user chose\s+abort\b', re.I)


@dataclass(frozen=True)
class InnoDialog:
    text: str
    suppressed: bool


def _read_tail(path: str) -> str:
    """Read a bounded, best-effort decoded tail of an installer log."""
    try:
        with open(path, 'rb') as fh:
            bom = fh.read(4)
            size = os.fstat(fh.fileno()).st_size
            start = max(0, size - _MAX_BYTES)
            if bom.startswith((b'\xff\xfe', b'\xfe\xff')):
                start -= start % 2
            fh.seek(start)
            data = fh.read(_MAX_BYTES + 2)
    except OSError:
        return ""
    if bom.startswith(b'\xff\xfe'):
        text = data.decode('utf-16-le', 'replace').lstrip('\ufeff')
    elif bom.startswith(b'\xfe\xff'):
        text = data.decode('utf-16-be', 'replace').lstrip('\ufeff')
    else:
        try:
            text = data.decode('utf-8-sig')
        except UnicodeDecodeError:
            # Older ANSI logs use the Windows system code page.
            try:
                text = data.decode('mbcs', 'replace')
            except LookupError:
                text = data.decode('cp1251', 'replace')
    return text


_LONG_PATH = re.compile(
    r"(?:\b(?:error(?:\s+code)?|winerror|ошибка|код(?:\s+ошибки)?)\s*[:=]?\s*206\b"
    r"|the filename or extension is too long"
    r"|имя файла или его расширение имеет слишком большую длину)", re.I)


def has_long_path_error(path: str) -> bool:
    # Code 3 (path not found) alone is not evidence of a long path.
    return bool(_LONG_PATH.search(_read_tail(path)))



def has_ignored_error(path: str) -> bool:
    """Detect an explicit Ignore response to an Abort/Retry/Ignore dialog.

    Normal version-based skips are not errors. The log format is not stable,
    so an absent match does not prove that every file was installed.
    """
    lines = _read_tail(path).splitlines()
    for index, line in enumerate(lines):
        if not _DIALOG.search(line):
            continue
        for item in lines[index + 1:index + 32]:
            if _TIMESTAMP.match(item):
                if re.search(r'user chose\s+ignore\b', item, re.I):
                    return True
                break
    return False

def read_dialog(path: str) -> Optional[InnoDialog]:
    """Return a bounded excerpt of the latest explicit Abort dialog, if any.

    Only inspect the end of the log. A missing/truncated/unrecognized log is
    not evidence for any particular reason. Installer text remains untrusted.
    """
    lines = _read_tail(path).splitlines()
    for index in range(len(lines) - 1, -1, -1):
        line = lines[index]
        suppressed = bool(_SUPPRESSED.search(line))
        if not suppressed and not _DIALOG.search(line):
            continue
        message = []
        chosen = False
        for item in lines[index + 1:index + 32]:
            if _TIMESTAMP.match(item):
                chosen = bool(_CHOSE_ABORT.search(item))
                break
            value = item.strip()
            if value:
                message.append(value)
        if not suppressed and not chosen:
            continue
        excerpt = ' '.join(message)
        # Avoid copying control characters or unlimited installer output into UI.
        excerpt = ''.join(c for c in excerpt if c.isprintable())[:1000]
        return InnoDialog(excerpt, suppressed)
    return None
