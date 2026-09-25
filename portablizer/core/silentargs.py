"""Построение аргументов «тихой» установки в указанную папку.

Каждый движок имеет свой синтаксис. Здесь мы формируем список аргументов
командной строки для запуска установщика в silent-режиме с явным указанием
директории установки внутри портативной папки.

Особые случаи:
  * NSIS: параметр /D=<путь> ДОЛЖЕН быть последним, без кавычек, даже если
    в пути есть пробелы. Поэтому его добавляют отдельно (см. build()).
  * InstallShield: команда зависит от ПОКОЛЕНИЯ. Обёртке над MSI нужен
    ``/s /v"/qn INSTALLDIR=\"…\""`` (кавычки внутри /v экранируются),
    классическому InstallScript 5/6 — ``/s /f1"setup.iss" /f2"setup.log"``,
    и целевую папку он принимает только через файл ответов.
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
    TRUSTED_CONFIDENCE, DetectionResult, InstallerType, InstallShieldGeneration,
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
    #: Установщик показывает окно и ждёт действий пользователя (режим записи
    #: ответов у InstallScript). Такой план нельзя запускать с CREATE_NO_WINDOW
    #: и нельзя ограничивать обычным таймаутом тихой установки.
    interactive: bool = False
    #: Движок сам пишет сюда итог (InstallShield: setup.log с ResultCode).
    result_log: str = ""
    #: Движок физически не умеет принимать целевую папку в командной строке:
    #: файлы окажутся в его каталоге по умолчанию, и их придётся переносить.
    ignores_target_dir: bool = False
    #: Что сказать пользователю перед запуском (для интерактивных планов).
    instructions: List[str] = field(default_factory=list)
    #: Файл ответов, который план читает (или записывает в режиме /r).
    response_file: str = ""

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
        generation = (detection.installshield_generation if detection
                      else InstallShieldGeneration.UNKNOWN)
        if generation == InstallShieldGeneration.INSTALLSCRIPT:
            return build_installscript_plan(
                installer_path, target_dir,
                response_file=(detection.response_file if detection else ""),
                log_file=log_file, extra_args=extra_args)
        return build_installshield_msi_plan(
            installer_path, target_dir, extra_args=extra_args)

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


def _is_switch(switch: str, value: str) -> str:
    """Ключ InstallShield с путём: ``/f1"C:\\dir\\setup.iss"``.

    У setup.exe между ключом и значением НЕ должно быть пробела, а путь
    заключается в кавычки внутри самого аргумента. Собрать это через
    ``subprocess.list2cmdline`` нельзя: он закавычит аргумент целиком
    (``"/f1C:\\dir with space\\setup.iss"``) — такую форму движок не разбирает.
    Поэтому подобные ключи уходят «сырым хвостом» командной строки.
    """
    return f'{switch}"{value}"' if value else switch


def build_installscript_plan(
    installer_path: str,
    target_dir: str,
    response_file: str = "",
    log_file: Optional[str] = None,
    extra_args: Optional[Sequence[str]] = None,
    record: bool = False,
) -> SilentPlan:
    """Команда для классического InstallShield InstallScript (5/6).

    Отличия от современной обёртки над MSI — принципиальные:

    * ключа ``/v`` не существует: всё, что передано после него, движок просто
      не понимает (именно это и произошло с диском American McGee's Alice —
      setup.exe вышел за две секунды с кодом 0, ничего не установив);
    * целевую папку из командной строки InstallScript не принимает: путь
      хранится в файле ответов, поэтому программу приходится забирать из
      каталога по умолчанию (этим занимается перенос из ``_recover_installed_app``);
    * ``/s`` работает только по записанному файлу ответов ``setup.iss``
      (``/r``); без него setup.log получает ``ResultCode=-3`` или ``-5``;
    * ``/f1``/``/f2`` задают файл ответов и журнал. Для установщика на
      компакт-диске это обязательно: по умолчанию движок пишет журнал рядом с
      setup.exe, то есть на носитель только для чтения.
    """
    # Пути в аргументах — в синтаксисе Windows (их читает установщик), а
    # native_* — в синтаксисе текущей ОС: эти файлы Portablizer открывает сам.
    native_target = _native(target_dir)
    native_response = _native(response_file) if response_file else ""
    native_log = _native(log_file) if log_file else ""
    installer_path = _norm(installer_path)
    response_file = _norm(response_file) if response_file else ""
    log_file = _norm(log_file) if log_file else ""

    args = ["/r" if record else "/s"] + list(extra_args or [])
    tail: List[str] = []
    if response_file:
        tail.append(_is_switch("/f1", response_file))
    if log_file:
        tail.append(_is_switch("/f2", log_file))
    # /SMS заставляет setup.exe дождаться конца установки, а не возвращать
    # управление сразу (движок работает в отдельном процессе ikernel.exe).
    tail.append("/SMS")

    if record:
        notes = [
            "InstallShield InstallScript: режим записи ответов /r — мастер "
            "покажет окна, а Portablizer сохранит ваши ответы в setup.iss и "
            "заберёт установленную программу в портатив.",
        ]
        label = "InstallShield InstallScript: мастер с записью ответов /r"
    else:
        notes = [
            "InstallShield InstallScript: /s работает только по файлу "
            "ответов setup.iss, поэтому он передан ключом /f1, а журнал — "
            "ключом /f2 (носитель установщика может быть только для чтения).",
        ]
        label = ("InstallScript: /s /f1\"setup.iss\"" if response_file
                 else "InstallScript: /s без файла ответов")

    return SilentPlan(
        program=installer_path,
        args=args,
        raw_tail=" ".join(tail),
        notes=notes,
        label=label,
        output_dir=native_target,
        interactive=record,
        result_log=native_log,
        response_file=native_response,
        ignores_target_dir=True,
        instructions=[
            "Откроется окно мастера установки. Пройдите его и в качестве "
            f"папки назначения укажите: {native_target}",
            "Если мастер не даёт выбрать папку, оставьте его вариант — "
            "Portablizer сам перенесёт установленную программу в портатив.",
        ] if record else [],
    )


def build_installshield_msi_plan(
    installer_path: str,
    target_dir: str,
    response_file: str = "",
    extra_args: Optional[Sequence[str]] = None,
    with_target_dir: bool = True,
) -> SilentPlan:
    """Команда для InstallShield-обёртки над MSI (Basic / InstallScript MSI).

    Документированная форма — ``setup.exe /s /v"/qn INSTALLDIR=\\"путь\\""``:
    ключ ``/v`` стоит ВНЕ кавычек, а внутренние кавычки экранируются. Если
    собрать это списком аргументов, ``list2cmdline`` закавычит токен целиком
    (``"/v/qn INSTALLDIR=…"``) — такую строку setup.exe разбирает неверно.
    """
    native_target = _native(target_dir)
    installer_path = _norm(installer_path)
    target_dir = _norm(target_dir)
    response_file = _norm(response_file) if response_file else ""

    args = ["/s"] + list(extra_args or [])
    tail: List[str] = []
    if response_file:
        # InstallScript MSI умеет и файл ответов, и /v одновременно.
        tail.append(_is_switch("/f1", response_file))
    if with_target_dir:
        inner = f'/qn INSTALLDIR=\\"{target_dir}\\" /norestart'
        label = "InstallShield (MSI): /s /v\"/qn INSTALLDIR=…\""
    else:
        inner = "/qn /norestart"
        label = "InstallShield (MSI): /s /v\"/qn\" без целевой папки"
    tail.append(f'/v"{inner}"')

    return SilentPlan(
        program=installer_path,
        args=args,
        raw_tail=" ".join(tail),
        notes=[
            "InstallShield с обёрткой над MSI: ключи после /v передаются "
            "msiexec; кавычки внутри /v экранируются, иначе setup.exe "
            "разбирает строку неправильно.",
        ],
        label=label,
        output_dir=native_target,
        ignores_target_dir=not with_target_dir,
    )


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


def build_installshield_attempts(
    detection: DetectionResult,
    installer_path: str,
    target_dir: str,
    response_file: str = "",
    record_file: str = "",
    log_file: str = "",
    extract_dir: str = "",
    extra_args: Optional[Sequence[str]] = None,
    allow_assisted: bool = False,
) -> List[SilentPlan]:
    """Лестница попыток для InstallShield — отдельно по поколениям.

    Раньше здесь была одна-единственная команда обёртки над MSI
    (``/s /v"/qn INSTALLDIR=…"``). Для InstallScript 5/6 она бессмысленна:
    ключ ``/v`` такому движку неизвестен, и setup.exe завершается за пару
    секунд с кодом 0, не установив ничего. Теперь набор команд выбирается по
    поколению, а при неуверенном определении пробуются оба.
    """
    extra = list(extra_args or [])
    generation = detection.installshield_generation
    attempts: List[SilentPlan] = []

    def installscript(record: bool = False) -> SilentPlan:
        # В режиме записи файл ответов ещё не существует, но путь обязателен:
        # без /f1 движок создаёт setup.iss в папке Windows, то есть мусорит на
        # компьютере-сборщике и теряет файл, ради которого всё затевалось.
        answers = (record_file or response_file) if record else response_file
        return build_installscript_plan(
            installer_path, target_dir, response_file=answers,
            log_file=log_file, extra_args=extra, record=record)

    def msi_wrapper(with_target_dir: bool = True) -> SilentPlan:
        return build_installshield_msi_plan(
            installer_path, target_dir, response_file=response_file,
            extra_args=extra, with_target_dir=with_target_dir)

    if generation == InstallShieldGeneration.INSTALLSCRIPT:
        attempts.append(installscript())
    elif generation == InstallShieldGeneration.MSI:
        attempts.append(msi_wrapper())
        attempts.append(msi_wrapper(with_target_dir=False))
    else:
        # Поколение неизвестно: обёртка над MSI безопаснее (лишние ключи
        # InstallScript просто игнорирует), поэтому она идёт первой.
        attempts.append(msi_wrapper())
        attempts.append(installscript())
        attempts.append(msi_wrapper(with_target_dir=False))

    # Распаковка без установки: современные setup.exe умеют выложить свои
    # MSI-пакеты в папку, откуда их распакует msiexec /a — система при этом
    # не меняется и права администратора не нужны.
    if extract_dir and generation != InstallShieldGeneration.INSTALLSCRIPT \
            and detection.has_switch("/extract_all"):
        attempts.append(SilentPlan(
            program=_norm(installer_path),
            args=["/s"],
            raw_tail=_is_switch("/extract_all:", _norm(extract_dir)),
            notes=["InstallShield: /extract_all выкладывает MSI-пакеты в "
                   "папку, не устанавливая программу в систему."],
            label="InstallShield: распаковка /extract_all",
            output_dir=_native(extract_dir),
            extracts_only=True,
        ))

    # Записать ответы может только человек: мастер задаёт вопросы, на которые
    # нет правильного ответа «по умолчанию». Поэтому режим /r — последний и
    # только с явного разрешения пользователя.
    if allow_assisted and generation != InstallShieldGeneration.MSI:
        attempts.append(installscript(record=True))

    return attempts


def build_attempts(
    detection: DetectionResult,
    installer_path: str,
    target_dir: str,
    log_dir: str = "",
    extra_args: Optional[Sequence[str]] = None,
    layout_dir: str = "",
    response_file: str = "",
    allow_assisted: bool = False,
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

    def artifact(name: str) -> str:
        """Путь к файлу, который открывает сам Portablizer.

        В отличие от log_path он остаётся в синтаксисе текущей ОС: план
        приводит его к виду Windows только для командной строки установщика.
        """
        return os.path.join(log_dir, name) if log_dir else ""

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
    elif itype == InstallerType.INSTALLSHIELD:
        attempts.extend(build_installshield_attempts(
            detection, installer_path, target_dir,
            response_file=response_file,
            record_file=artifact("setup.iss"),
            log_file=artifact("setup-installshield.log"),
            extract_dir=layout_dir, extra_args=extra,
            allow_assisted=allow_assisted))
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

    # План с окном мастера требует человека у клавиатуры, поэтому он всегда
    # последний и не должен вытесняться автоматическими вариантами при
    # обрезке лестницы.
    silent = [p for p in unique if not p.interactive]
    interactive = [p for p in unique if p.interactive]
    if interactive:
        return silent[:max(1, MAX_ATTEMPTS - len(interactive))] + interactive
    return silent[:MAX_ATTEMPTS]


def candidate_silent_switches(installer_type: InstallerType) -> List[str]:
    """Возвращает список ключей-кандидатов для перебора, если основной не сработал."""
    common = ["/S", "/silent", "/VERYSILENT", "/quiet", "/qn", "-s", "-silent"]
    return common
