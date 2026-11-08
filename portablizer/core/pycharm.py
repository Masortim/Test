"""Conservative identification of a nested PyCharm Windows entry point."""
from __future__ import annotations

import json
import os
from typing import Optional


def find_pycharm_executable(app_dir: str, app_name: str) -> Optional[str]:
    """Find one unambiguous PyCharm bin/pycharm64.exe, not bundled helpers.

    A PyCharm title and PyCharm-named product directory, or official product
    metadata, are required. Multiple versions are left to normal selection.
    This identifies a plausible entry point, not a complete installation.
    """
    if not os.path.isdir(app_dir):
        return None
    found = []
    base = os.path.abspath(app_dir)
    for root, dirs, files in os.walk(base, followlinks=False):
        depth = os.path.relpath(root, base).count(os.sep) + (root != base)
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        if depth >= 3:
            dirs[:] = []
        if os.path.basename(root).casefold() != 'bin':
            continue
        product = os.path.dirname(root)
        title_match = ('pycharm' in (app_name or '').casefold()
                       and os.path.basename(product).casefold().startswith('pycharm'))
        metadata_match = False
        metadata = os.path.join(product, 'product-info.json')
        try:
            if os.path.getsize(metadata) <= 1024 * 1024:
                with open(metadata, encoding='utf-8-sig') as fh:
                    info = json.load(fh)
                metadata_match = (isinstance(info, dict)
                                  and str(info.get('name', '')).casefold().startswith('pycharm')
                                  and str(info.get('productCode', '')).upper() in ('PC', 'PY'))
        except (OSError, ValueError, TypeError):
            pass
        if not (title_match or metadata_match):
            continue
        for filename in files:
            candidate = os.path.join(root, filename)
            if filename.casefold() == 'pycharm64.exe' and not os.path.islink(candidate):
                found.append(candidate)
    return found[0] if len(found) == 1 else None
