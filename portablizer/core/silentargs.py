"""Построение аргументов «тихой» установки в указанную папку.

Каждый движок имеет свой синтаксис. Здесь мы формируем список аргументов
командной строки для запуска установщика в silent-режиме с явным указанием
директории установки внутри портативной папки.

Особые случаи:
  * NSIS: параметр /D=<путь> ДОЛЖЕН быть последним, без кавычек, даже если
    в пути есть пробелы. Поэтому его добавляют отдельно (см. build()).
  * MSI: административно распаковывается через msiexec.exe /a с TARGETDIR,
    чтобы не регистрировать пакет в системе.
"""
from __future__ import annotations

import ntpath
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
    override_install_folder: bool = True,
) -> SilentPlan:
    extra_args = extra_args or []
    notes: List[str] = []

    # QFileDialog нередко возвращает путь с прямыми слешами (`E:/Type`), а
    # os.path.join на Windows добавляет к нему обратные. Windows API это обычно
    # принимает, но NSIS разбирает сырой хвост /D самостоятельно и у некоторых
    # сборок смешанный путь остаётся без эффекта. Передаём только канонический
    # Windows-синтаксис: `E:\\Type\\Type_Portable\\App`.
    installer_path = ntpath.normpath(installer_path)
    target_dir = ntpath.normpath(target_dir)
    if log_file:
        log_file = ntpath.normpath(log_file)

    if is_msi or installer_type == InstallerType.MSI:
        # Административная установка распаковывает MSI в целевой каталог, не
        # регистрируя пакет в системе. Обычный /i часто игнорирует INSTALLDIR и
        # оставляет App пустой, одновременно изменяя Windows.
        args = [
            "/a", installer_path,
            "/qn",                       # полностью тихо, без UI
            "/norestart",
            f"TARGETDIR={target_dir}",
        ]
        if log_file:
            args += ["/L*v", log_file]
        args += extra_args
        notes.append("MSI распаковывается через административную установку /a в TARGETDIR.")
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
        # Переменную InstallFolder принимают только бандлы, объявившие её
        # публичной (bal:Overridable). Если бандл её не знает, вся командная
        # строка считается недопустимой и установка мгновенно проваливается
        # (типичен код -1 / 0xFFFFFFFF). Поэтому при неудаче Portablizer
        # повторяет запуск уже без неё (Portablizer._burn_fallback), а затем
        # распаковывает бандл через /layout (build_burn_layout_plan).
        args = ["/quiet", "/norestart", "/install"]
        if override_install_folder:
            args.append(f"InstallFolder={target_dir}")
        if log_file:
            args += ["/log", log_file]
        args += extra_args
        notes.append(
            "WiX Burn: /quiet /install + /log. Папку бандл принимает только "
            "при публичной переменной InstallFolder; при неудаче Portablizer "
            "повторит запуск без неё и распакует бандл через /layout."
        )
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


def build_burn_layout_plan(
    installer_path: str,
    layout_dir: str,
    log_file: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> SilentPlan:
    """План распаковки WiX Burn-бандла без установки (``/layout``).

    ``/layout <папка>`` просит движок Burn собрать все пакеты бандла в
    указанную папку, не выполняя установку: не нужны ни права администратора,
    ни изменение системы. Извлечённые MSI затем распаковываются
    административной установкой (``msiexec /a``) прямо в папку App портатива.
    """
    installer_path = ntpath.normpath(installer_path)
    layout_dir = ntpath.normpath(layout_dir)
    if log_file:
        log_file = ntpath.normpath(log_file)
    args = ["/layout", layout_dir, "/quiet", "/norestart"]
    if log_file:
        args += ["/log", log_file]
    args += list(extra_args or [])
    return SilentPlan(
        program=installer_path,
        args=args,
        notes=[
            "WiX Burn /layout: содержимое бандла собирается в папку без "
            "установки в систему и без прав администратора.",
        ],
    )


def candidate_silent_switches(installer_type: InstallerType) -> List[str]:
    """Возвращает список ключей-кандидатов для перебора, если основной не сработал."""
    common = ["/S", "/silent", "/VERYSILENT", "/quiet", "/qn", "-s", "-silent"]
    return common
