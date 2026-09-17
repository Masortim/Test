"""Построение аргументов «тихой» установки в указанную папку.

Каждый движок имеет свой синтаксис. Здесь мы формируем список аргументов
командной строки для запуска установщика в silent-режиме с явным указанием
директории установки внутри портативной папки.

Особые случаи:
  * NSIS: параметр /D=<путь> ДОЛЖЕН быть последним, без кавычек, даже если
    в пути есть пробелы. Поэтому его добавляют отдельно (см. build()).
  * MSI: запускается через msiexec.exe, TARGETDIR/INSTALLDIR передаются как
    свойства.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .detect import InstallerType


@dataclass
class SilentPlan:
    """Готовый план запуска тихой установки."""
    program: str                       # что запускать (сам exe или msiexec)
    args: List[str] = field(default_factory=list)
    # Для NSIS: /D= передаётся сырой строкой в конце (без кавычек).
    raw_tail: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def display(self) -> str:
        parts = [self.program] + list(self.args)
        line = " ".join(_q(p) for p in parts)
        if self.raw_tail:
            line += " " + self.raw_tail
        return line


def _q(s: str) -> str:
    return f'"{s}"' if (" " in s and not s.startswith('"')) else s


# Дополнительные (пользовательские) ключи всегда можно добавить сверху.
def build_silent_plan(
    installer_type: InstallerType,
    installer_path: str,
    target_dir: str,
    is_msi: bool = False,
    log_file: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> SilentPlan:
    extra_args = extra_args or []
    notes: List[str] = []

    if is_msi or installer_type == InstallerType.MSI:
        args = [
            "/i", installer_path,
            "/qn",                       # полностью тихо, без UI
            "/norestart",
            f"TARGETDIR={target_dir}",
            f"INSTALLDIR={target_dir}",
            f"APPLICATIONFOLDER={target_dir}",
        ]
        if log_file:
            args += ["/L*v", log_file]
        args += extra_args
        notes.append("MSI запускается через msiexec с TARGETDIR/INSTALLDIR.")
        return SilentPlan(program="msiexec.exe", args=args, notes=notes)

    if installer_type == InstallerType.INNO:
        args = [
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/NOICONS",
            f'/DIR={target_dir}',
        ]
        if log_file:
            args.append(f'/LOG={log_file}')
        args += extra_args
        notes.append("Inno Setup: /VERYSILENT /DIR=<папка>.")
        return SilentPlan(program=installer_path, args=args, notes=notes)

    if installer_type == InstallerType.NSIS:
        # У NSIS /D должен быть ПОСЛЕДНИМ и БЕЗ кавычек.
        args = ["/S"] + extra_args
        notes.append("NSIS: /S для тишины, /D=<путь> добавлен последним без кавычек.")
        return SilentPlan(program=installer_path, args=args,
                          raw_tail=f"/D={target_dir}", notes=notes)

    if installer_type == InstallerType.INSTALLSHIELD:
        # Классический InstallShield: /s /v"/qn INSTALLDIR=\"...\""
        inner = f'/qn INSTALLDIR="{target_dir}" /norestart'
        args = ["/s", f'/v{inner}'] + extra_args
        notes.append("InstallShield: /s /v\"/qn INSTALLDIR=...\".")
        return SilentPlan(program=installer_path, args=args, notes=notes)

    if installer_type == InstallerType.WIX_BURN:
        args = ["/quiet", "/norestart", "/install",
                f"InstallFolder={target_dir}"] + extra_args
        notes.append("WiX Burn: /quiet /install (папку принимает не всегда).")
        return SilentPlan(program=installer_path, args=args, notes=notes)

    if installer_type == InstallerType.INSTALLAWARE:
        args = ["/s", f'/D={target_dir}'] + extra_args
        notes.append("InstallAware: /s.")
        return SilentPlan(program=installer_path, args=args, notes=notes)

    if installer_type == InstallerType.WISE:
        args = ["/s"] + extra_args
        notes.append("Wise: /s (папка часто не поддерживается, полагаемся на изоляцию).")
        return SilentPlan(program=installer_path, args=args, notes=notes)

    # UNKNOWN / self-extract: пробуем самые распространённые ключи по очереди.
    args = ["/S", "/silent", "/quiet"][:1] + extra_args
    notes.append(
        "Тип не распознан. Использованы универсальные ключи; "
        "рекомендуется задать ключи вручную в поле «Доп. аргументы»."
    )
    return SilentPlan(program=installer_path, args=args, notes=notes)


def candidate_silent_switches(installer_type: InstallerType) -> List[str]:
    """Возвращает список ключей-кандидатов для перебора, если основной не сработал."""
    common = ["/S", "/silent", "/VERYSILENT", "/quiet", "/qn", "-s", "-silent"]
    return common
