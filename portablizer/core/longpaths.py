"""Choose a readable, shorter and isolated directory for sensitive installers.

Shortening cannot guarantee that an arbitrary payload fits MAX_PATH. No SUBST,
registry changes, junctions or deletion/reuse of existing folders are used.
"""
from __future__ import annotations

import os
import re
import secrets

MAX_PREFERRED_APP_UNITS = 48
MIN_SAVING_UNITS = 12
MAX_LABEL_UNITS = 12


def path_units(path: str) -> int:
    return len(path.encode('utf-16-le', 'surrogatepass')) // 2


def short_label(name: str) -> str:
    """A small recognisable product label, with no Windows path characters."""
    text = str(name or '').strip()
    # Versions and common packaging suffixes aren't useful in a very short
    # name. Keep leading numbers (e.g. 7-Zip) and Unicode product names.
    text = re.split(r'(?i)(?:[_\s-]+(?:setup|installer|install|portable|x64|x86|win64|win32)(?:\b|_)|(?<=[^\d])[_\s-]*\d[\d.]*)', text, maxsplit=1)[0]
    text = re.sub(r'[^\w-]+', '_', text, flags=re.UNICODE).strip('_.-')
    chars = []
    for char in text:
        if path_units(''.join(chars) + char) > MAX_LABEL_UNITS:
            break
        chars.append(char)
    label = ''.join(chars).rstrip('_.-')
    return label or 'App'


def should_use_short_root(output_dir: str, name: str) -> bool:
    output = os.path.abspath(output_dir)
    normal = os.path.join(output, name + '_Portable', 'App')
    short = os.path.join(output, short_label(name) + '-1234', 'App')
    return (path_units(normal) > MAX_PREFERRED_APP_UNITS
            and path_units(normal) - path_units(short) >= MIN_SAVING_UNITS)


def reserve_short_root(output_dir: str, name: str) -> str:
    """Atomically reserve a fresh, human-readable directory inside output_dir.

    A collision (including a symlink) is never reused; mkdir is exclusive. If
    randomness fails repeatedly we fail safely rather than touching another
    build. User data from older portables is never overwritten or relocated.
    """
    os.makedirs(output_dir, exist_ok=True)
    label = short_label(name)
    for _ in range(128):
        candidate = os.path.join(output_dir, label + '-' + secrets.token_hex(2))
        try:
            os.mkdir(candidate)
            return candidate
        except FileExistsError:
            continue
    raise FileExistsError('Cannot reserve an unused short portable folder')
