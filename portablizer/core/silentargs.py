"""Построение аргументов «тихой» установки в указанную папку.

Каждый движок имеет свой синтаксис. Здесь мы формируем список аргументов
командной строки для запуска установщика в silent-режиме с явным указанием
директории установки внутри портативной папки.

Особые случаи:
  * NSIS: параметр /D=<путь> ДОЛЖЕН быть последним, без кавычек, даже если
    в пути есть пробелы. Поэтому его добавляют отдельно (см. build()).
  * MSI: административно распаковывается через msiexec.exe /a с TARGETDIR,
    чтобы не регистрировать пакет в системе.
  * Собственные bootstrapper'ы (``--silent --installPath=...``): ключи
    берутся из самого установщика (см. ``detect.scan_file``), а не угадываются.

Главная идея модуля — **лестница попыток** (``build_attempts``). Один
«правильный» набор ключей существует далеко не всегда: установщик может не
знать переданную переменную, отказаться от чужой целевой папки или вовсе
требовать другой синтаксис. Вместо одной команды мы строим упорядоченный
список вариантов — от самого точного к самому общему — и оркестратор
останавливается на первом, который реально положил файлы в ``App``.
"""
from __future__ import annotations

import ntpath
import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from .detect import (
    TRUSTED_CONFIDENCE, DetectionResult, InstallerType,
)

#: Больше попыток запускать бессмысленно: каждая стоит времени пользователя.
MAX_ATTEMPTS = 6


@dataclass
class SilentPlan:
    """Готовый план запуска тихой установки."""
    program: str                       # что запускать (сам exe или msiexec)
    args: List[str] = field(default_factory=list)
    # Для NSIS: /D= передаётся сырой строкой в конце (без кавычек).
    raw_tail: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    #: Человекочитаемое название попытки — попадает в журнал.
    label: str = ""
    #: Куда план реально пишет файлы (обычно App, для /layout — папка бандла).
    output_dir: str = ""
    #: План только распаковывает пакет и не меняет систему.
    extracts_only: bool = False
    #: Плану заведомо нужны права администратора.
    needs_admin: bool = False

    def display(self) -> str:
        parts = [self.program] + list(self.args)
        line = " ".join(_q(p) for p in parts)
        if self.raw_tail:
            line += " " + self.raw_tail
        return line


def _q(s: str) -> str:
    return f'"{s}"' if (" " in s and not s.startswith('"')) else s


def _native(path: str) -> str:
    """Путь в синтаксисе ТЕКУЩЕЙ ОС.

    ``output_dir`` читает уже сам Portablizer через ``os.path``, а не
    установщик. На Windows это тот же путь, что и в аргументах; на Linux
    (тесты, демо-режим) ntpath-нормализация превратила бы ``/tmp/x`` в
    ``\\tmp\\x`` и папка «исчезла» бы.
    """
    return os.path.normpath(path) if path else path


def _norm(path: str) -> str:
    """Канонический Windows-путь без завершающего слеша.

    Завершающий ``\\`` ломает разбор ``CommandLineToArgvW``: он экранирует
    закрывающую кавычку, и установщик получает склеенный аргумент.
    """
    if not path:
        return path
    normalized = ntpath.normpath(path)
    if len(normalized) > 3 and normalized.endswith("\\"):
        normalized = normalized.rstrip("\\")
    return normalized


# Дополнительные (пользовательские) ключи всегда можно добавить сверху.
def build_silent_plan(
    installer_type: InstallerType,
    installer_path: str,
    target_dir: str,
    is_msi: bool = False,
    log_file: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    override_install_folder: bool = True,
    detection: Optional[DetectionResult] = None,
) -> SilentPlan:
    extra_args = extra_args or []
    notes: List[str] = []

    # QFileDialog нередко возвращает путь с прямыми слешами (`E:/Type`), а
    # os.path.join на Windows добавляет к нему обратные. Windows API это обычно
    # принимает, но NSIS разбирает сырой хвост /D самостоятельно и у некоторых
    # сборок смешанный путь остаётся без эффекта. Передаём только канонический
    # Windows-синтаксис: `E:\\Type\\Type_Portable\\App`.
    native_target = _native(target_dir)
    installer_path = _norm(installer_path)
    target_dir = _norm(target_dir)
    if log_file:
        log_file = _norm(log_file)

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
        return SilentPlan(program="msiexec.exe", args=args, notes=notes,
                          label="MSI: административная распаковка",
                          output_dir=native_target, extracts_only=True)

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
        return SilentPlan(program=installer_path, args=args, notes=notes,
                          label="Inno Setup: /VERYSILENT /DIR",
                          output_dir=native_target)

    if installer_type == InstallerType.NSIS:
        # У NSIS /D должен быть ПОСЛЕДНИМ и БЕЗ кавычек.
        args = ["/S"] + extra_args
        notes.append("NSIS: /S для тишины, /D=<путь> добавлен последним без кавычек.")
        return SilentPlan(program=installer_path, args=args,
                          raw_tail=f"/D={target_dir}", notes=notes,
                          label="NSIS: /S /D", output_dir=native_target)

    if installer_type == InstallerType.INSTALLSHIELD:
        # Классический InstallShield: /s /v"/qn INSTALLDIR=\"...\""
        inner = f'/qn INSTALLDIR="{target_dir}" /norestart'
        args = ["/s", f'/v{inner}'] + extra_args
        notes.append("InstallShield: /s /v\"/qn INSTALLDIR=...\".")
        return SilentPlan(program=installer_path, args=args, notes=notes,
                          label="InstallShield: /s /v\"/qn INSTALLDIR\"",
                          output_dir=native_target)

    if installer_type == InstallerType.WIX_BURN:
        # Переменную InstallFolder принимают только бандлы, объявившие её
        # публичной (bal:Overridable). Если бандл её не знает, вся командная
        # строка считается недопустимой и установка мгновенно проваливается
        # (типичен код -1 / 0xFFFFFFFF). Поэтому лестница попыток сначала
        # пробует с переменной, затем без неё, затем распаковку /layout.
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
        label = ("WiX Burn: /quiet /install + InstallFolder"
                 if override_install_folder else "WiX Burn: /quiet /install")
        return SilentPlan(program=installer_path, args=args, notes=notes,
                          label=label, output_dir=native_target, needs_admin=True)

    if installer_type == InstallerType.INSTALLAWARE:
        args = ["/s", f'/D={target_dir}'] + extra_args
        notes.append("InstallAware: /s.")
        return SilentPlan(program=installer_path, args=args, notes=notes,
                          label="InstallAware: /s /D", output_dir=native_target)

    if installer_type == InstallerType.WISE:
        args = ["/s"] + extra_args
        notes.append("Wise: /s (папка часто не поддерживается, полагаемся на изоляцию).")
        return SilentPlan(program=installer_path, args=args, notes=notes,
                          label="Wise: /s", output_dir=native_target)

    if installer_type == InstallerType.INSTALL4J:
        args = ["-q", "-overwrite", "-dir", target_dir] + extra_args
        notes.append("install4j: -q -dir <папка>.")
        return SilentPlan(program=installer_path, args=args, notes=notes,
                          label="install4j: -q -dir", output_dir=native_target)

    if installer_type == InstallerType.BITROCK:
        args = ["--mode", "unattended", "--unattendedmodeui", "none",
                "--prefix", target_dir] + extra_args
        notes.append("BitRock: --mode unattended --prefix <папка>.")
        return SilentPlan(program=installer_path, args=args, notes=notes,
                          label="BitRock: --mode unattended",
                          output_dir=native_target)

    if installer_type == InstallerType.ADVANCED_INSTALLER:
        args = ["/exenoui", "/qn", f"APPDIR={target_dir}"] + extra_args
        if log_file:
            args += ["/exelog", log_file]
        notes.append("Advanced Installer: /exenoui /qn APPDIR=<папка>.")
        return SilentPlan(program=installer_path, args=args, notes=notes,
                          label="Advanced Installer: /exenoui /qn",
                          output_dir=native_target)

    if installer_type == InstallerType.CUSTOM_CLI:
        return build_custom_cli_plan(installer_path, target_dir,
                                     detection=detection,
                                     extra_args=extra_args)

    # UNKNOWN / self-extract: пробуем самые распространённые ключи по очереди.
    args = ["/S"] + extra_args
    notes.append(
        "Тип не распознан. Использованы универсальные ключи; "
        "рекомендуется задать ключи вручную в поле «Доп. аргументы»."
    )
    return SilentPlan(program=installer_path, args=args, notes=notes,
                      label="Универсальный ключ /S", output_dir=native_target)


def build_custom_cli_plan(
    installer_path: str,
    target_dir: str,
    detection: Optional[DetectionResult] = None,
    extra_args: Optional[Sequence[str]] = None,
    with_install_path: bool = True,
    hidden: bool = True,
) -> SilentPlan:
    """План для установщика с собственными ключами (``--silent`` и т.п.).

    Ключи не угадываются, а берутся из самого бинарника: ``detect.scan_file``
    находит строки вида ``--silent``/``--installPath``, которые установщик
    разбирает. Так поддерживаются современные bootstrapper'ы, не относящиеся
    ни к одному классическому движку (типичный пример — установщики ZennoLab,
    требующие ``--silent --accept-license-agreement="…"``).
    """
    native_target = _native(target_dir)
    installer_path = _norm(installer_path)
    target_dir = _norm(target_dir)
    args: List[str] = []
    notes: List[str] = []

    silent = "--silent"
    if detection is not None:
        for candidate in ("--silent", "--unattended", "--quiet"):
            if detection.has_switch(candidate):
                silent = detection.switch(candidate)
                break
    args.append(silent)

    if hidden and detection is not None and detection.has_switch("--hidden"):
        args.append(detection.switch("--hidden"))

    if detection is not None:
        for candidate in ("--accept-license-agreement", "--accept-licenses",
                          "--acceptlicense"):
            if detection.has_switch(candidate):
                url = detection.license_url
                key = detection.switch(candidate)
                args.append(f"{key}={url}" if url else key)
                notes.append(
                    "Установщик требует явного принятия лицензии — ключ "
                    f"{key} добавлен автоматически."
                )
                break

    if with_install_path and detection is not None:
        for candidate in ("--installPath", "--install-dir", "--installdir",
                          "--prefix"):
            if detection.has_switch(candidate):
                args.append(f"{detection.switch(candidate)}={target_dir}")
                break

    if detection is not None and detection.has_switch("--norestart"):
        args.append(detection.switch("--norestart"))

    # Документированные производителем фиксированные ключи (профиль вендора):
    # например, у ZennoLab --installType=StandAlone гарантирует чистую
    # установку в нашу папку даже при наличии другой версии на этом ПК —
    # иначе Default обновил бы чужую установку, а компьютер-сборщик должен
    # остаться без изменений.
    if detection is not None:
        present = {a.split("=", 1)[0].casefold() for a in args}
        for fixed in detection.vendor_args:
            key = fixed.split("=", 1)[0].casefold()
            if key not in present:
                args.append(fixed)
                present.add(key)

    args += list(extra_args or [])
    if detection is not None and detection.vendor_args:
        notes.append(
            "Ключи заданы по официальной документации производителя "
            "(строки внутри сборки упакованы и не использовались)."
        )
    else:
        notes.append(
            "Ключи взяты из строк самого установщика, а не подобраны наугад."
        )
    label = "Собственные ключи установщика: " + " ".join(
        a.split("=", 1)[0] for a in args[:4])
    return SilentPlan(program=installer_path, args=args, notes=notes,
                      label=label, output_dir=native_target)


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
    native_layout = _native(layout_dir)
    installer_path = _norm(installer_path)
    layout_dir = _norm(layout_dir)
    if log_file:
        log_file = _norm(log_file)
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
        label="WiX Burn: распаковка /layout",
        output_dir=native_layout,
        extracts_only=True,
    )


#: Универсальные наборы ключей для нераспознанных установщиков.
#: Порядок важен: сначала самые «тихие» и безопасные.
_GENERIC_LADDER: Sequence[Sequence[str]] = (
    ("/S",),
    ("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"),
    ("/silent", "/norestart"),
    ("/quiet", "/norestart"),
    ("-s",),
    ("--silent",),
)


def build_attempts(
    detection: DetectionResult,
    installer_path: str,
    target_dir: str,
    log_dir: str = "",
    extra_args: Optional[Sequence[str]] = None,
    layout_dir: str = "",
) -> List[SilentPlan]:
    """Строит упорядоченную лестницу попыток тихой установки.

    Оркестратор выполняет их по очереди и останавливается, как только в
    ``App`` появились файлы программы. Это принципиально надёжнее одной
    «правильной» команды: у одного и того же движка встречаются сборки с
    разным набором поддерживаемых ключей.
    """
    extra = list(extra_args or [])
    native_target = _native(target_dir)
    installer_path = _norm(installer_path)
    target_dir = _norm(target_dir)

    def log_path(name: str) -> Optional[str]:
        return ntpath.join(_norm(log_dir), name) if log_dir else None

    attempts: List[SilentPlan] = []
    itype = detection.installer_type

    if detection.is_msi or itype == InstallerType.MSI:
        attempts.append(build_silent_plan(
            InstallerType.MSI, installer_path, target_dir, is_msi=True,
            log_file=log_path("install.log"), extra_args=extra))
        return attempts

    if itype == InstallerType.CUSTOM_CLI:
        attempts.append(build_custom_cli_plan(
            installer_path, target_dir, detection=detection, extra_args=extra))
        # Некоторые bootstrapper'ы принимают путь только при «своём» типе
        # установки, зато без него отрабатывают штатно — файлы потом находит
        # поиск по перенаправленному профилю.
        without_path = build_custom_cli_plan(
            installer_path, target_dir, detection=detection,
            extra_args=extra, with_install_path=False)
        without_path.label = "Собственные ключи без пути установки"
        attempts.append(without_path)
        if detection.has_switch("--hidden"):
            visible = build_custom_cli_plan(
                installer_path, target_dir, detection=detection,
                extra_args=extra, hidden=False)
            visible.label = "Собственные ключи без --hidden"
            attempts.append(visible)
    elif itype == InstallerType.WIX_BURN:
        attempts.append(build_silent_plan(
            InstallerType.WIX_BURN, installer_path, target_dir,
            log_file=log_path("install.log"), extra_args=extra))
        attempts.append(build_silent_plan(
            InstallerType.WIX_BURN, installer_path, target_dir,
            override_install_folder=False,
            log_file=log_path("install-retry.log"), extra_args=extra))
    elif itype != InstallerType.UNKNOWN:
        attempts.append(build_silent_plan(
            itype, installer_path, target_dir,
            log_file=log_path("install.log"), extra_args=extra,
            detection=detection))

    # Установщик может содержать собственные ключи, даже если опознан движок
    # (bootstrapper часто оборачивает классический установщик).
    if (itype != InstallerType.CUSTOM_CLI
            and detection.has_switch("--silent", "--unattended")
            and detection.has_switch("--installPath", "--install-dir",
                                     "--accept-license-agreement")):
        attempts.append(build_custom_cli_plan(
            installer_path, target_dir, detection=detection, extra_args=extra))

    # Распаковка бандла: не требует прав администратора и не меняет систему.
    if itype == InstallerType.WIX_BURN and layout_dir:
        attempts.append(build_burn_layout_plan(
            installer_path, layout_dir, log_file=log_path("install-layout.log"),
            extra_args=extra))

    # Тип, опознанный ненадёжно (например, по одиночной слабой подстроке
    # «nsis»), не должен заканчиваться единственной типо-специфичной
    # командой: если она не подошла, в ход идут универсальные наборы ключей.
    weakly_detected = (
        not (detection.is_msi or itype == InstallerType.MSI)
        and itype != InstallerType.CUSTOM_CLI
        and detection.confidence < TRUSTED_CONFIDENCE
    )
    generic_types = (InstallerType.UNKNOWN, InstallerType.SELF_EXTRACT,
                     InstallerType.SQUIRREL)
    if weakly_detected or itype in generic_types:
        note = ("Универсальный набор ключей для нераспознанного установщика."
                if itype in generic_types and not weakly_detected
                else "Универсальный набор ключей: определение типа "
                     "ненадёжно, пробуем типовые ключи по очереди.")
        for switches in _GENERIC_LADDER:
            plan = SilentPlan(
                program=installer_path, args=list(switches) + extra,
                notes=[note],
                label="Универсальные ключи: " + " ".join(switches),
                output_dir=native_target,
            )
            attempts.append(plan)

    if not attempts:
        attempts.append(build_silent_plan(
            itype, installer_path, target_dir,
            log_file=log_path("install.log"), extra_args=extra,
            detection=detection))

    # Убираем дубликаты команд, сохраняя порядок.
    unique: List[SilentPlan] = []
    seen = set()
    for plan in attempts:
        key = (plan.program, tuple(plan.args), plan.raw_tail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(plan)
    return unique[:MAX_ATTEMPTS]


def candidate_silent_switches(installer_type: InstallerType) -> List[str]:
    """Возвращает список ключей-кандидатов для перебора, если основной не сработал."""
    common = ["/S", "/silent", "/VERYSILENT", "/quiet", "/qn", "-s", "-silent"]
    return common
