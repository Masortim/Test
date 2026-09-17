"""Определение типа установщика по содержимому exe/msi.

Разные семейства установщиков принимают разные ключи «тихой» установки и
разные способы задать целевую папку. Мы стараемся распознать наиболее
распространённые движки:

  * Inno Setup            -> /VERYSILENT /SUPPRESSMSGBOXES /DIR="..."
  * NSIS                  -> /S /D=...            (у /D особый синтаксис)
  * InstallShield         -> /s /v"/qn INSTALLDIR=..."  (часто через setup.exe)
  * WiX / MSI (msiexec)   -> /qn INSTALLDIR=... (через msiexec)
  * WiX Burn (bundle)     -> /quiet /install
  * InstallAware / Wise / прочее -> эвристики

Определение построено на поиске сигнатур в бинарнике — быстро и без запуска.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class InstallerType(str, Enum):
    INNO = "Inno Setup"
    NSIS = "NSIS"
    INSTALLSHIELD = "InstallShield"
    MSI = "Windows Installer (MSI)"
    WIX_BURN = "WiX Burn Bundle"
    INSTALLAWARE = "InstallAware"
    WISE = "Wise Installer"
    SELF_EXTRACT = "Self-extracting archive"
    UNKNOWN = "Unknown / Generic"


# Байтовые сигнатуры, которые встречаются внутри установщиков соответствующих
# движков. Список эвристический, но покрывает подавляющее большинство случаев.
_SIGNATURES: Dict[InstallerType, List[bytes]] = {
    InstallerType.INNO: [
        b"Inno Setup", b"JR.Inno.Setup", b"This installation was built with Inno Setup",
        b"InnoSetupLdrWindow", b"idp.dll",
    ],
    InstallerType.NSIS: [
        b"Nullsoft Install System", b"NullsoftInst", b"nsis", b"NSIS Error",
    ],
    InstallerType.INSTALLSHIELD: [
        b"InstallShield", b"ISSetup", b"isxdl", b"_isres",
    ],
    InstallerType.WIX_BURN: [
        b"WixBurn", b".wixburn", b"wixstdba",
    ],
    InstallerType.INSTALLAWARE: [
        b"InstallAware",
    ],
    InstallerType.WISE: [
        b"Wise Installation", b"WiseMain",
    ],
    InstallerType.SELF_EXTRACT: [
        b"7-Zip", b"SFXWizard", b"WinRAR SFX", b"WinZip Self-Extractor",
    ],
}


@dataclass
class DetectionResult:
    installer_type: InstallerType
    confidence: float  # 0..1
    is_msi: bool = False
    evidence: List[str] = field(default_factory=list)

    @property
    def human(self) -> str:
        return f"{self.installer_type.value} (уверенность {int(self.confidence * 100)}%)"


def _scan_signatures(path: str, chunk_size: int = 4 * 1024 * 1024) -> Dict[InstallerType, List[bytes]]:
    """Ищет сигнатуры во всём файле, не загружая установщик целиком.

    Раньше проверялись только первые и последние 6 МБ. У крупных установщиков
    маркер движка часто находится посередине, из-за чего они ошибочно получали
    универсальный ключ ``/S`` и ничего не записывали в ``App``.
    """
    needles: Dict[InstallerType, List[tuple[bytes, bytes]]] = {
        itype: [
            (sig.lower(), sig.decode("latin-1").lower().encode("utf-16-le"))
            for sig in signatures
        ]
        for itype, signatures in _SIGNATURES.items()
    }
    found: Dict[InstallerType, List[bytes]] = {itype: [] for itype in _SIGNATURES}
    longest = max(
        len(encoded)
        for variants in needles.values()
        for pair in variants
        for encoded in pair
    )
    carry = b""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            data = (carry + chunk).lower()
            for itype, variants in needles.items():
                for index, (ascii_sig, wide_sig) in enumerate(variants):
                    original = _SIGNATURES[itype][index]
                    if original in found[itype]:
                        continue
                    if ascii_sig in data or wide_sig in data:
                        found[itype].append(original)
            carry = data[-(longest - 1):] if longest > 1 else b""
    return found


def detect_installer(path: str) -> DetectionResult:
    """Определяет тип установщика по пути к файлу."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".msi":
        return DetectionResult(InstallerType.MSI, 1.0, is_msi=True,
                               evidence=["расширение .msi"])

    try:
        signature_hits = _scan_signatures(path)
    except OSError as exc:  # noqa: PERF203
        return DetectionResult(InstallerType.UNKNOWN, 0.0, evidence=[f"ошибка чтения: {exc}"])

    scores: Dict[InstallerType, float] = {}
    evidence: Dict[InstallerType, List[str]] = {}

    for itype, matched in signature_hits.items():
        hits = [sig.decode("latin-1", "replace") for sig in matched]
        if hits:
            scores[itype] = min(1.0, 0.55 + 0.15 * len(hits))
            evidence[itype] = [f"найдена сигнатура: {h}" for h in hits]

    if not scores:
        return DetectionResult(InstallerType.UNKNOWN, 0.2,
                               evidence=["ни одна известная сигнатура не найдена"])

    # Выбираем движок с наибольшим счётом.
    best = max(scores, key=lambda k: scores[k])
    return DetectionResult(best, scores[best], evidence=evidence[best])
