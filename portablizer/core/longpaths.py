"""Choose a shorter, isolated result directory for path-sensitive installers.

Shortening saves a bounded number of characters; it cannot guarantee that an
arbitrary payload fits MAX_PATH or that the resulting app supports relocation.
We never use SUBST, registry changes, junctions or delete an existing folder.
"""
from __future__ import annotations

import os
import tempfile
from typing import Optional

# Inno installers can contain very deep trees. This is a heuristic, not a
# statement that shorter paths are safe. Windows counts UTF-16 code units.
MAX_PREFERRED_APP_UNITS = 48
MIN_SAVING_UNITS = 12


def path_units(path: str) -> int:
    return len(path.encode('utf-16-le', 'surrogatepass')) // 2


def should_use_short_root(output_dir: str, name: str) -> bool:
    output = os.path.abspath(output_dir)
    normal = os.path.join(output, name + '_Portable', 'App')
    # tempfile.mkdtemp uses eight random characters after the P- prefix.
    short = os.path.join(output, 'P-12345678', 'App')
    return (path_units(normal) > MAX_PREFERRED_APP_UNITS
            and path_units(normal) - path_units(short) >= MIN_SAVING_UNITS)


def reserve_short_root(output_dir: str) -> str:
    """Atomically reserve a fresh directory within the selected output folder."""
    os.makedirs(output_dir, exist_ok=True)
    return tempfile.mkdtemp(prefix='P-', dir=output_dir)
