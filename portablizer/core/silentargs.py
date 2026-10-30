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
from dataclasses import dataclass, field, replace
from typing import List, Optional, Sequence

from . import adobe as adobe_mod
from .detect import (
    TRUSTED_CONFIDENCE, DetectionResult, InstallerType, InstallShieldGeneration,
    RepackProfile,
)
from .languages import (
    find_language, os_ui_language_code, plan_language,
)

#: Больше попыток запускать бессмысленно: каждая стоит времени пользователя.
MAX_ATTEMPTS = 6

#: Сетевые загрузчики не должны получать все шесть случайных ключей: два
#: коротких успеха с пустым App обычно означают «это только downloader».
STUB_MAX_ATTEMPTS = 3
ONLINE_PRODUCT_MAX_ATTEMPTS = 2


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
    #: Журналы, которые установщик ведёт ПО ХОДУ работы. Их рост — самое
    #: честное доказательство, что долгая установка жива (см.
    #: ``portablizer.core.portablizer._InstallWatchdog``): по журналу видно,
    #: что движок продолжает распаковывать файлы, а не ждёт мышку.
    progress_logs: List[str] = field(default_factory=list)
    #: Движок физически не умеет принимать целевую папку в командной строке:
    #: файлы окажутся в его каталоге по умолчанию, и их придётся переносить.
    ignores_target_dir: bool = False
    #: План НЕ трогает страницу выбора каталога: не вбивает в неё App и
    #: не кликает «Далее» с нашей папкой. Нужно для обёрток (Multitran),
    #: у которых внутренний мастер со страницей выбора папки отклоняет
    #: переданный через командную строку путь («folder is not accessible»)
    #: и при этом сам не пропускает страницу тишиной. Тогда мастер должен
    #: пройти с каталогом по умолчанию, а уже потом файлы перенесут в App
    #: через recover() — иначе установщик зависает на этой странице и
    #: обрывает сборку.
    prefers_installer_default_dir: bool = False
    #: Что сказать пользователю перед запуском (для интерактивных планов).
    instructions: List[str] = field(default_factory=list)
    #: Файл ответов, который план читает (или записывает в режиме /r).
    response_file: str = ""
    #: План не запускает установщик, а раскладывает его пакеты своими силами.
    #: ``adobe`` — Adobe HyperDrive: пакеты берутся из контейнера и из
    #: ``payloads``, UWP-шаг пропускается (см. core/adobe.py). Для таких
    #: планов оркестратор вызывает не ``_run_install``, а свой обработчик.
    payload_kind: str = ""

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
                          output_dir=native_target, extracts_only=True,
                          progress_logs=[log_file] if log_file else [])

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
                          output_dir=native_target,
                          progress_logs=[log_file] if log_file else [])

    if installer_type == InstallerType.NSIS:
        # У NSIS /D должен быть ПОСЛЕДНИМ и БЕЗ кавычек.
        # --no-desktop-shortcut понимают установщики electron-builder (OpenCode
        # и т.п.): сборка портатива не должна оставлять ярлык на рабочем столе
        # этого ПК. Классический NSIS ключ просто игнорирует.
        args = ["/S", "--no-desktop-shortcut"] + extra_args
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
                          label=label, output_dir=native_target, needs_admin=True,
                          progress_logs=[log_file] if log_file else [])

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
                          output_dir=native_target,
                          progress_logs=[log_file] if log_file else [])

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
        progress_logs=[native_log] if native_log else [],
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
        progress_logs=[log_file] if log_file else [],
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


def _effective_type(detection: DetectionResult) -> InstallerType:
    """Тип, по которому строится команда: MSI-пакет важнее всего."""
    if detection.is_msi:
        return InstallerType.MSI
    return detection.installer_type


# --- известные перепаки -------------------------------------------------------
#
# Скрипт перепака разбирает командную строку сам. Документированный синтаксис
# у каждого автора свой, и «универсальная» команда движка для него — набор
# неизвестных аргументов: установщик показывает мастер (язык, папка) и ждёт
# мышку. Поэтому лестница строится от опубликованной команды, а не от типа
# движка.

def _repack_language_order(profile: RepackProfile,
                           language: str) -> List[Tuple[str, str]]:
    """Порядок ключей языка: выбранный человеком → язык Windows → остальные.

    Репак KpoJIuK без ``/RU`` или ``/EN`` открывает окно выбора языка, поэтому
    «язык по умолчанию» здесь не пустой ключ, а язык интерфейса Windows.
    """
    switches = list(profile.language_switches or ())
    if not switches:
        return []
    preferred = find_language(language) if (language or "").strip() else None
    wanted = preferred.code.split("-")[0].lower() if preferred else ""
    if not wanted:
        wanted = os_ui_language_code()
    ordered: List[Tuple[str, str]] = []
    for code, switch in switches:
        if code.casefold() == wanted.casefold():
            ordered.append((code, switch))
    for item in switches:
        if item not in ordered:
            ordered.append(item)
    return ordered


def build_repack_attempts(
    profile: RepackProfile,
    installer_path: str,
    target_dir: str,
    log_dir: str = "",
    extra_args: Optional[Sequence[str]] = None,
    language: str = "",
) -> List[SilentPlan]:
    """Лестница команд для документированного перепака.

    Порядок намеренно повторяет документацию автора:

    1. ``/S <язык> /D=<App>`` — «тихая установка нужного языка в нашу папку»;
    2. ``/S <язык>`` — без пути: скрипт поставит в Program Files, и recovery
       перенесёт файлы в App (``ignores_target_dir``);
    3. стандартная команда Inno Setup — на случай, если перед нами всё-таки
       обычный Inno Setup, а имя файла совпало случайно.

    Ключ пути передаётся «сырым» хвостом без кавычек: так его разбирает
    скрипт репака (как NSIS ``/D=``).
    """
    native_target = _native(target_dir)
    installer_path = _norm(installer_path)
    target_dir = _norm(target_dir)
    user_extra = list(extra_args or [])
    silence = profile.silent_switch or "/S"
    path_switch = profile.path_switch or ""
    attempts: List[SilentPlan] = []

    language_pairs = _repack_language_order(profile, language)
    chosen = find_language(language) if (language or "").strip() else None
    chosen_short = chosen.code.split("-")[0].casefold() if chosen else ""
    if chosen and language_pairs and language_pairs[0][0].casefold() == chosen_short:
        language_note = (f"Язык установки: {chosen.title} — ключом "
                         f"{language_pairs[0][1]}.")
    elif language_pairs:
        language_note = (
            "Язык не выбран: репак без короткого ключа (/RU, /EN) открывает "
            "окно выбора языка, поэтому передаётся язык интерфейса Windows "
            f"({language_pairs[0][1]}). Выбрать язык вручную можно в поле "
            "«Язык установки».")
    else:
        language_note = ""

    def add(lang_switch: str, with_path: bool, note: str) -> None:
        args = [silence]
        if lang_switch:
            args.append(lang_switch)
        args.extend(user_extra)
        raw_tail = (f"{path_switch}{target_dir}"
                    if with_path and path_switch else None)
        label = f"{profile.name}: {silence}"
        if lang_switch:
            label += f" {lang_switch}"
        label += f" {path_switch}<App>" if raw_tail else " без пути"
        attempts.append(SilentPlan(
            program=installer_path,
            args=args,
            raw_tail=raw_tail,
            notes=[note] + ([language_note] if language_note else []),
            label=label,
            output_dir=native_target,
            ignores_target_dir=not with_path,
        ))

    documented_note = (
        f"{profile.name} ({profile.product}): документированная команда — "
        f"{silence} <язык> {path_switch}<папка>, ключ пути последним и без "
        "кавычек, как у NSIS."
    )

    # 1. Документированная команда: язык + папка (сначала предпочтительный
    #    язык, затем второй из тех, что знает скрипт).
    for _code, switch in language_pairs:
        add(switch, True, documented_note)
    # 2. То же без ключа языка — если человек выбрал «как в установщике», а
    #    у репака есть язык по умолчанию и мастер он не показывает.
    add("", True, documented_note)
    # 3. Без пути: скрипт поставит в Program Files, recovery заберёт файлы
    #    в App и удалит оригинал. Это лучше, чем ещё один мастер с вопросом.
    no_path_note = (
        "Путь в командной строке не передан: скрипт поставит программу в "
        "папку по умолчанию, Portablizer перенесёт её в App и удалит "
        "оригинал из Program Files.")
    for _code, switch in language_pairs:
        add(switch, False, no_path_note)
    add("", False, no_path_note)

    # 4. Запасной путь: если это всё-таки обычный Inno Setup с необычным
    #    именем файла, сработают его штатные ключи.
    inno_language = find_language(language) if (language or "").strip() else None
    inno_args = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    if inno_language is not None:
        inno_args.append(f"/LANG={inno_language.inno_name}")
    attempts.append(SilentPlan(
        program=installer_path,
        args=inno_args + user_extra,
        raw_tail=f"/DIR={target_dir}",
        notes=["Стандартная команда Inno Setup — если имя файла совпало с "
               "репаком случайно и перед нами обычный установщик Inno."],
        label=f"{profile.name}: запасной вариант Inno Setup /VERYSILENT /DIR=",
        output_dir=native_target,
        ignores_target_dir=True,
    ))
    return attempts


# -- Adobe Creative Cloud / XD -------------------------------------------------
#
# Установщик Adobe ставит программу в два этапа: пакеты MSI (файлы программы)
# и UWP-пакет (Appx) — последний регистрируется в Windows для всех
# пользователей и падает с «кодом ошибки 191» на большинстве машин (служба
# AppXSvc, sideloading, системный том, права). Для портатива UWP-шаг не
# нужен вовсе, поэтому первый и главный сценарий — вообще не запускать
# установщик: достать пакеты из контейнера/каталога payloads и поставить их в
# App (см. core/adobe.py). Тихие команды Adobe остаются запасными: если
# пакетов достать не удалось, установщик хотя бы попробует отработать сам, а
# сборка заберёт распакованное им из adobeTemp.

#: Документированные наборы ключей Adobe. Современный пакет (``Build\\setup.exe``,
#: в т. ч. собранный из Adobe Admin Console) принимает ``--silent`` с
#: ``--ADOBEINSTALLDIR=``; старые оболочки — ``/sAll /rs``. ``/S`` оставлен для
#: сборок HyperDrive, у которых нет длинных ключей.
_ADOBE_LADDER: Sequence[Tuple[str, ...]] = (
    ("--silent",),
    ("/sAll", "/rs"),
    ("/S",),
)


def build_adobe_payload_plan(installer_path: str, layout_dir: str) -> SilentPlan:
    """План «раскладка пакетов Adobe без запуска установщика».

    Установщик при этом не выполняется вообще: пакеты достаются из его
    контейнера (7-Zip) или из каталога ``payloads`` рядом с ним, а UWP-пакет
    пропускается — то есть шаг, падающий с кодом 191, просто не выполняется.
    """
    return SilentPlan(
        program=installer_path,
        notes=[
            "Установщик Adobe не запускается: пакеты программы достаются из "
            "его контейнера (7-Zip) или из каталога payloads, а UWP-пакет "
            "пропускается.",
            "Именно UWP-шаг (AddUWPAppxCommand) падает с «кодом ошибки 191» и "
            "отменяет установку целиком. Портативу он не нужен: Windows "
            "регистрирует такой пакет на конкретном компьютере для всех "
            "пользователей, а не «в папке».",
        ],
        label="Adobe: раскладка пакетов без установки (UWP пропускается)",
        output_dir=_native(layout_dir),
        extracts_only=True,
        payload_kind=adobe_mod.PAYLOAD_ADOBE,
    )


def build_adobe_attempts(
    detection: DetectionResult,
    installer_path: str,
    target_dir: str,
    layout_dir: str = "",
    extra_args: Optional[Sequence[str]] = None,
    language: str = "",
) -> List[SilentPlan]:
    """Лестница для установщика Adobe HyperDrive.

    Порядок принципиален:

    1. **раскладка пакетов без установки** — единственный сценарий, который
       не упирается в UWP-шаг;
    2. документированный ``--silent --ADOBEINSTALLDIR=<App>`` (пакет
       Admin Console умеет ставить программу в указанную папку);
    3. ``--silent`` без пути — если конкретная сборка не знает
       ``--ADOBEINSTALLDIR``, файлы найдутся в перенаправленном профиле;
    4. ``/sAll /rs`` и ``/S`` — старые оболочки HyperDrive.

    После каждого запуска сборка забирает распакованные пакеты из
    ``adobeTemp``: установщик успевает разложить их ДО падения на UWP-шаге.
    """
    user_extra = list(extra_args or [])
    native_target = _native(target_dir)
    installer_path = _norm(installer_path)
    target_dir = _norm(target_dir)

    attempts: List[SilentPlan] = []
    if layout_dir:
        attempts.append(build_adobe_payload_plan(installer_path, layout_dir))

    lang_args: List[str] = []
    locale = adobe_mod.language_locale(language)
    if locale:
        # Adobe принимает локаль в виде en_US/fr_CA, а не имя языка Inno.
        lang_args = [f"--INSTALLLANGUAGE={locale}"]

    def silent_plan(args: Sequence[str], label: str, notes: Sequence[str],
                    ignores: bool = False) -> SilentPlan:
        return SilentPlan(
            program=installer_path,
            args=list(args) + lang_args + user_extra,
            notes=list(notes),
            label=label,
            output_dir=native_target,
            ignores_target_dir=ignores,
        )

    attempts.append(silent_plan(
        ["--silent", f"--ADOBEINSTALLDIR={target_dir}"],
        "Adobe: --silent --ADOBEINSTALLDIR",
        ["Документированная тихая установка пакета Adobe: "
         "setup.exe --silent --ADOBEINSTALLDIR=<папка>.",
         "Если сборка всё равно упадёт с кодом 191 — это UWP-шаг, а не "
         "командная строка; файлы программы при этом уже могут лежать в "
         "adobeTemp, и сборка заберёт их оттуда."]))
    attempts.append(silent_plan(
        ["--silent"],
        "Adobe: --silent",
        ["Не все сборки HyperDrive знают --ADOBEINSTALLDIR: тихий режим без "
         "ключа папки, программа окажется в профиле или Program Files, а "
         "сборка перенесёт её в App."],
        ignores=True))
    attempts.append(silent_plan(
        ["/sAll", "/rs"], "Adobe: /sAll /rs",
        ["Старая оболочка HyperDrive: /sAll — полная тишина, /rs — без "
         "перезагрузки."], ignores=True))
    attempts.append(silent_plan(
        ["/S"], "Adobe: /S",
        ["Минимальный ключ тишины, который понимают сборки HyperDrive без "
         "длинных ключей."], ignores=True))
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
    language: str = "",
    adobe_layout_dir: str = "",
) -> List[SilentPlan]:
    """Строит упорядоченную лестницу попыток тихой установки.

    Оркестратор выполняет их по очереди и останавливается, как только в
    ``App`` появились файлы программы. Это принципиально надёжнее одной
    «правильной» команды: у одного и того же движка встречаются сборки с
    разным набором поддерживаемых ключей.

    ``language`` — код языка из ``languages.LANGUAGES`` (пусто — язык по
    умолчанию установщика). Ключ выбора языка добавляется ко ВСЕМ попыткам
    движка, кроме универсального набора: тот не знает, какой движок на самом
    деле, и чужой ключ ``/LANG=`` ему бы только мешал.
    """
    user_extra = list(extra_args or [])
    lang_plan = plan_language(
        _effective_type(detection), language, user_extra,
        is_gog=bool(getattr(detection, "is_gog", False)),
        inno_language_names=list(
            getattr(detection, "inno_language_names", ()) or ()),
    )
    extra = user_extra + lang_plan.args
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

    if getattr(detection, "is_downloader_stub", False) is True:
        product = getattr(detection, "online_product", None)
        if product is not None:
            documented = list(getattr(product, "switches", ()) or ())
            if not documented:
                documented = ["--quiet"]
            product_name = getattr(product, "name", "онлайн-продукт")
            reason = getattr(product, "reason", "")
            attempts = [SilentPlan(
                program=installer_path,
                args=documented + user_extra,
                notes=[
                    f"{product_name}: используем только документированный "
                    "пользовательский режим без --globalinstall. " + reason,
                ],
                label=f"{product_name}: " + " ".join(documented),
                output_dir=native_target,
            )]
            # Если тихая команда лишь скачивает bootstrapper и ничего не
            # кладёт в App, один видимый запуск может показать обязательный
            # вход/ошибку сети. Не подменяем его ещё четырьмя случайными ключами.
            attempts.append(SilentPlan(
                program=installer_path,
                args=user_extra,
                notes=[
                    f"{product_name}: диагностический запуск с интерфейсом; "
                    "сам по себе вход в аккаунт не делает приложение портативным.",
                ],
                label=f"{product_name}: запуск с интерфейсом",
                output_dir=native_target,
                interactive=True,
                instructions=[
                    "Если загрузчик попросит войти в аккаунт, завершите "
                    "вход только если доверяете установщику. Клиент может "
                    "остаться привязанным к этому компьютеру и не стать портативным.",
                ],
            ))
            return attempts[:ONLINE_PRODUCT_MAX_ATTEMPTS]

        # Общий downloader: три аккуратных варианта, но без чужих аргументов
        # от Inno/NSIS и без запуска распаковщика как будто это payload.
        for switches in (("/S",), ("/quiet",), ("--silent",)):
            attempts.append(SilentPlan(
                program=installer_path,
                args=list(switches) + user_extra,
                notes=[
                    "Небольшой сетевой загрузчик: пробуем ограниченный "
                    "набор ключей, затем проверяем, появились ли реальные файлы.",
                ],
                label="Загрузчик: " + " ".join(switches),
                output_dir=native_target,
            ))
        return attempts[:STUB_MAX_ATTEMPTS]

    # Известный перепак: документированная команда автора сборки важнее
    # любых догадок по движку. Скрипт репака открывает мастер на «чужие»
    # ключи Inno, поэтому здесь нельзя примешивать /LANG= и /DIR=.
    repack = getattr(detection, "repack_profile", None)
    if isinstance(repack, RepackProfile):
        return build_repack_attempts(
            repack, installer_path, target_dir,
            log_dir=log_dir, extra_args=user_extra, language=language,
        )[:MAX_ATTEMPTS + 2]

    # Adobe HyperDrive: UWP-шаг (код 191) портативу не нужен, поэтому первым
    # сценарием идёт раскладка пакетов без запуска установщика. Обычная
    # тихая установка Adobe всё равно упирается в этот шаг.
    if itype == InstallerType.ADOBE_HD:
        payload_dir = adobe_layout_dir or layout_dir
        return build_adobe_attempts(
            detection, installer_path, target_dir,
            layout_dir=payload_dir, extra_args=user_extra,
            language=language,
        )

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
    elif itype not in (InstallerType.UNKNOWN, InstallerType.SELF_EXTRACT):
        # SELF_EXTRACT сюда не попадает: для него единственной лестницей
        # служит универсальный набор ключей ниже — с ключом языка и
        # /D=<App> в конце, а «просто /S» без пути только наделает
        # побочного эффекта в Program Files.
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
        if allow_assisted:
            # Последний шанс только по явному согласию пользователя: некоторые
            # bundle'ы возвращают 0 в quiet mode, но требуют подтверждения в
            # штатном мастере. Видимое окно позволяет выбрать Install, а не
            # принять пустой Package Cache за установленное приложение.
            args = ["/install", f"InstallFolder={native_target}"]
            if log_file := log_path("install-interactive.log"):
                args += ["/log", log_file]
            attempts.append(SilentPlan(
                program=installer_path, args=args,
                notes=["Последний сценарий WiX Burn показывает штатный "
                       "мастер. Проверьте, что выбрано Install/Установить "
                       "(не Repair/Восстановить и не Remove/Удалить)."],
                label="WiX Burn: штатное окно мастера (opt-in)",
                output_dir=native_target, needs_admin=True, interactive=True,
                instructions=[
                    "В окне установщика выберите Install/Установить, не "
                    "Repair/Восстановить и не Remove/Удалить.",
                    "Если появится выбор папки, укажите папку App портатива.",
                    "Дождитесь завершения мастера.",
                ],
            ))

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
    winrar_sfx = (
        itype == InstallerType.SELF_EXTRACT
        and any("winrar sfx" in e.casefold()
                for e in (getattr(detection, "evidence", None) or ()))
    )
    if winrar_sfx:
        # WinRAR SFX понимает -s и -d<папка> БЕЗ знака «=». Передача /D=<App>
        # или /DIR=<App> заставляет обёртку воспринять «= <App>» как имя
        # каталога и показать окно «"= <App>" folder is not accessible».
        attempts.extend([
            SilentPlan(
                program=installer_path,
                args=["-s"] + user_extra,
                raw_tail=f"-d{native_target}",
                notes=[
                    "WinRAR SFX: документированные ключи тихой распаковки "
                    "-s и -d<папка> (без знака «=», иначе «=» попадает в имя "
                    "папки и вызывает ошибку «folder is not accessible»).",
                ],
                label="WinRAR SFX: -s -d<App>",
                output_dir=native_target,
                ignores_target_dir=True,
            ),
            SilentPlan(
                program=installer_path,
                args=["/S"] + list(lang_plan.args) + user_extra,
                raw_tail=f"-d{native_target}",
                notes=[
                    "WinRAR SFX: вариант /S с ключом папки -d<папка> без знака «=».",
                ],
                label="WinRAR SFX: /S -d<App>",
                output_dir=native_target,
                ignores_target_dir=True,
            ),
            SilentPlan(
                program=installer_path,
                args=["-s"] + user_extra,
                notes=[
                    "WinRAR SFX: тихая распаковка без ключа папки в командной строке.",
                ],
                label="WinRAR SFX: -s без пути",
                output_dir=native_target,
                ignores_target_dir=True,
            ),
        ])
    if weakly_detected or itype in generic_types:
        note = ("Универсальный набор ключей для нераспознанного установщика."
                if itype in generic_types and not weakly_detected
                else "Универсальный набор ключей: определение типа "
                     "ненадёжно, пробуем типовые ключи по очереди.")
        for switches in _GENERIC_LADDER:
            args = list(switches) + user_extra
            raw_tail: Optional[str] = None
            ignores = False
            if itype == InstallerType.SELF_EXTRACT:
                # Сворачиваемый архив: ключ языка доходит до внутреннего
                # установщика коротким ключом (/RU, /EN — см. languages),
                # а путь установки — /D=<App> последним без кавычек, как
                # у NSIS (кроме чистого WinRAR SFX, где «=» ломает путь).
                args = list(switches) + list(lang_plan.args) + user_extra
                raw_tail = None if winrar_sfx else f"/D={target_dir}"
                ignores = True
            plan = SilentPlan(
                program=installer_path, args=args,
                notes=[note] + ([
                    "Сворачиваемый архив: путь установки /D=<App> передан "
                    "последним без кавычек, как документировано перепаковщиком."
                ] if (itype == InstallerType.SELF_EXTRACT and not winrar_sfx) else []),
                label="Универсальные ключи: " + " ".join(switches),
                output_dir=native_target, raw_tail=raw_tail,
                ignores_target_dir=ignores,
            )
            attempts.append(plan)

    # Inno Setup inside SFX: некоторые SFX-архивы содержат внутренний
    # Inno Setup installer, который не понимает короткие ключи перепаковщика
    # (/S, /RU, /D=) и показывает диалоги выбора языка и пути установки.
    # Для него нужна собственная синтаксис: /VERYSILENT /SUPPRESSMSGBOXES
    # /NORESTART /LANG=<язык> /DIR=<App>. Пробуем после универсальной
    # лестницы, чтобы не разбивать уже работающие SFX с NSIS внутри.
    if itype == InstallerType.SELF_EXTRACT and not winrar_sfx:
        _inno_switches = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
        _inno_language = find_language(language) if (language or "").strip() else None
        # Порядок: сначала с языком и path, потом без языка (если /LANG не
        # поддерживается), но всегда с /DIR.
        if _inno_language is not None:
            plan = SilentPlan(
                program=installer_path,
                args=_inno_switches + [f"/LANG={_inno_language.inno_name}"],
                raw_tail=f"/DIR={target_dir}",
                notes=[
                    "Внутренний Inno Setup: /VERYSILENT /SUPPRESSMSGBOXES "
                    "/NORESTART /LANG= /DIR= передаётся как есть."
                ],
                label="Inno Setup внутри SFX: /VERYSILENT /LANG= /DIR=",
                output_dir=native_target,
                ignores_target_dir=True,
            )
            attempts.append(plan)
        # Без языка — если внутренний установщик не поддерживает /LANG
        plan = SilentPlan(
            program=installer_path,
            args=_inno_switches,
            raw_tail=f"/DIR={target_dir}",
            notes=[
                "Внутренний Inno Setup: /VERYSILENT /SUPPRESSMSGBOXES "
                "/NORESTART /DIR= (без /LANG — установщик сам выберет язык)."
            ],
            label="Inno Setup внутри SFX: /VERYSILENT /DIR=",
            output_dir=native_target,
            ignores_target_dir=True,
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
    # SELF_EXTRACT: универсальная лестница (6) + Inno Setup (2-3) —
    # тратим на попытки чуть больше, чтобы Inno Setup не улетучивалась.
    max_attempts = MAX_ATTEMPTS + 2 if itype == InstallerType.SELF_EXTRACT else MAX_ATTEMPTS
    if interactive:
        return silent[:max(1, max_attempts - len(interactive))] + interactive
    return silent[:max_attempts]


def candidate_silent_switches(installer_type: InstallerType) -> List[str]:
    """Возвращает список ключей-кандидатов для перебора, если основной не сработал."""
    common = ["/S", "/silent", "/VERYSILENT", "/quiet", "/qn", "-s", "-silent"]
    return common


# -- восстановление после падения установщика ---------------------------------
#
# лестница попыток рассчитана на «установщик не понял ключи». Падение — другая
# ситуация: движок стартовал и рухнул внутри себя (типичный код 0xC000041D —
# необработанное исключение в callback’е). Здесь два шага, которые имеет смысл
# сделать именно в этом случае.

#: Чем заменить «самый тихий» ключ, чтобы у установщика появилось окно.
#: У Inno Setup ``/VERYSILENT`` вообще не создаёт окно прогресса, а
#: ``/SILENT`` создаёт: это другой путь в коде установщика, и падение на нём
#: часто не повторяется — именно поэтому такой запуск стоит попробовать
#: отдельно, а не полагаться на «а вдруг другой ключ тишины».
_PROGRESS_WINDOW_SWITCHES = {"/VERYSILENT": "/SILENT"}


def repeat_attempt(plan: SilentPlan, note: str) -> SilentPlan:
    """Та же команда ещё раз, но с пометкой в названии сценария.

    Повтор делается после падения, случившегося сразу после старта: такие
    сбои часто разовые (антивирус проверял файл, памяти не хватило в момент
    распаковки). Отличить повтор от исходной попытки в журнале нужно — иначе
    непонятно, почему одна и та же строка встречается дважды.
    """
    return replace(plan, label=f"{plan.label} — {note}")


def build_progress_window_attempt(plan: SilentPlan,
                                  ) -> Optional[SilentPlan]:
    """Копия попытки с окном прогресса вместо полной тишины.

    Возвращает ``None``, если менять в команде нечего: у NSIS ``/S`` и у
    собственных ключей bootstrapper'а «тише» уже некуда, а окно мастера
    требует человека у клавиатуры (такие сценарии помечены ``interactive``).
    """
    if plan.interactive:
        return None
    replaced = False
    args: List[str] = []
    for arg in plan.args:
        swap = _PROGRESS_WINDOW_SWITCHES.get(arg.upper())
        if swap is None:
            args.append(arg)
        else:
            args.append(swap)
            replaced = True
    if not replaced:
        return None
    notes = list(plan.notes) + [
        "Повтор после падения: вместо /VERYSILENT — /SILENT. В самом тихом "
        "режиме окно прогресса не создаётся вообще, и исключение могло "
        "прилететь именно в его отрисовку.",
    ]
    return replace(plan, args=args, notes=notes,
                   label=f"{plan.label} → окно прогресса (/SILENT)")
