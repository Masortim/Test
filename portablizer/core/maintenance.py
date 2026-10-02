"""Обслуживание уже созданного портатива: освободить папку и обновить лончер.

Зачем отдельный модуль
----------------------
Исправления в лончере помогают только тем портативам, которые собраны
ПОСЛЕ них: внутри каждой готовой папки лежит своя копия
``App\\LaunchPortable.exe`` и свой ``Launch.bat``. Портатив, собранный
прежней версией, продолжает вести себя по-старому — ждать фоновые процессы
сутками и не убирать за собой, — даже если сам Portablizer уже обновлён.

Поэтому здесь две операции, которые применимы к любой существующей папке:

``release``
    «Я хочу удалить эту папку прямо сейчас». Останавливает службы, чьи
    бинарники лежат внутри, вежливо закрывает и затем завершает процессы из
    папки, проверяет результат пробным переименованием и, если папка всё
    ещё занята, называет виновника по имени — включая чужие программы,
    подгрузившие оттуда DLL.

``refresh``
    «Пусть этот портатив ведёт себя правильно». Перевыпускает лончеры
    (``LaunchPortable.exe``, ``Launch.bat``, ``LaunchHidden.vbs``,
    ``StopPortable.cmd``), дописывает в конфиг секции ``shutdown`` и
    ``shared_saves`` и настраивает сквозные сохранения прямо на месте —
    сохраняя все настройки портатива: цели, реестр, переменные среды,
    требования к распространяемым компонентам. Именно так лечится портатив,
    у которого прямой запуск ``App\\Game.exe`` и ``LaunchPortable.exe``
    видели разные сейвы: пересобирать его не нужно.

Обе операции ничего не устанавливают и не трогают ничего за пределами
указанной папки.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

from . import launcher as launcher_mod
from . import procutil
from . import saves as saves_mod
from .logutil import Logger

CONFIG_NAME = "launcher_config.json"


@dataclass
class MaintenanceReport:
    """Итог обслуживания — то, что показывается пользователю."""

    folder: str = ""
    success: bool = False
    #: Что было остановлено (процессы, службы).
    stopped: List[str] = field(default_factory=list)
    #: Кто держит папку, если освободить её не удалось.
    holders: List[str] = field(default_factory=list)
    #: Какие файлы портатива перевыпущены.
    updated: List[str] = field(default_factory=list)
    #: Режим сквозных сохранений, настроенный на месте.
    saves_mode: str = ""
    #: Сколько сейвов сведено в общее хранилище.
    saves_migrated: int = 0
    #: Человеческие сообщения (они же уходят в журнал).
    messages: List[str] = field(default_factory=list)


def looks_like_portable(folder: str) -> bool:
    """Похожа ли папка на портатив, собранный Portablizer."""
    return bool(folder) and os.path.isfile(os.path.join(folder, CONFIG_NAME)) \
        and os.path.isdir(os.path.join(folder, "App"))


def release(folder: str, log: Optional[Logger] = None) -> MaintenanceReport:
    """Освобождает папку: службы, процессы, проверка, поиск виновника."""
    log = log or Logger()
    report = MaintenanceReport(folder=folder)
    if not folder or not os.path.isdir(folder):
        message = f"Папка не найдена: {folder}"
        log.error(message)
        report.messages.append(message)
        return report

    log.info(f"Освобождаю папку: {folder}")
    if not looks_like_portable(folder):
        log.warn(
            "В папке нет launcher_config.json и App — это не похоже на "
            "портатив, собранный Portablizer. Останавливаю только то, что "
            "запущено из неё, и ничего не меняю.")

    report.stopped = procutil.release_folder(folder)
    for name in report.stopped:
        log.ok(f"Остановлено: {name}")

    errors: List[str] = []
    if procutil.folder_is_free(folder, errors):
        report.success = True
        message = ("Папка свободна: её можно удалить, перенести или "
                   "скопировать прямо сейчас.")
        log.ok(message)
        report.messages.append(message)
        return report

    for line in errors:
        log.debug(f"Папка не отпускается: {line}")

    # Вторая попытка: первый проход мог завершить процесс, который как раз
    # в этот момент открывал новые файлы (апдейтер, перезапускающий себя).
    again = procutil.release_folder(folder, stop_services=False)
    if again:
        report.stopped.extend(again)
        for name in again:
            log.ok(f"Остановлено: {name}")
        errors = []
        if procutil.folder_is_free(folder, errors):
            report.success = True
            message = ("Папка свободна: её можно удалить, перенести или "
                       "скопировать прямо сейчас.")
            log.ok(message)
            report.messages.append(message)
            return report
        for line in errors:
            log.debug(f"Папка не отпускается: {line}")

    holders = procutil.holders(folder)
    report.holders = procutil.describe_holders(holders)
    if report.holders:
        message = "Папку держат: " + ", ".join(report.holders)
        log.warn(message + ".")
        report.messages.append(message)
        if any(item.protected for item in holders):
            hint = ("Среди них системные процессы Windows — завершать их "
                    "нельзя. Закройте окна этой папки в проводнике, снимите "
                    "предпросмотр файла и повторите.")
            log.warn(hint)
            report.messages.append(hint)
        if any(item.kind == "file" and item.protected for item in holders):
            hint = ("Системный процесс держит открытым файл из папки "
                    "(так бывает со шрифтами из PortableData\\Temp). Его "
                    "дескриптор закрывается принудительно, но на это нужны "
                    "права администратора — запустите Portablizer от имени "
                    "администратора.")
            log.warn(hint)
            report.messages.append(hint)
        if any(not item.protected for item in holders):
            hint = ("Процессы, запущенные от имени администратора, обычной "
                    "программе не подчиняются: запустите Portablizer от "
                    "имени администратора и повторите.")
            log.info(hint)
            report.messages.append(hint)
    else:
        locked = procutil.busy_files(folder)
        if locked:
            report.holders = [os.path.basename(path) for path in locked]
            message = ("Папку держат открытые файлы: "
                       + ", ".join(report.holders[:6])
                       + ". Кто именно их открыл, без прав администратора "
                         "не видно — запустите Portablizer от имени "
                         "администратора, и держатель будет закрыт "
                         "принудительно.")
        else:
            message = ("Папка занята, но виновника определить не удалось. "
                       "Чаще всего это открытое окно проводника, "
                       "предпросмотр файла или проверка антивирусом — "
                       "через несколько секунд папка освободится сама.")
        log.warn(message)
        report.messages.append(message)
    return report


def refresh(folder: str, log: Optional[Logger] = None,
            copy_exe=None, shared_saves: bool = True) -> MaintenanceReport:
    """Перевыпускает лончеры существующего портатива текущей версией.

    ``copy_exe`` — функция ``(portable_dir, destination_rel) -> str``,
    копирующая встроенный ``LaunchPortable.exe`` (передаётся оркестратором,
    чтобы не тянуть сюда весь Portablizer).

    ``shared_saves`` — настроить ли заодно сквозные сохранения: свести
    сейвы прямого запуска и лончера в одно хранилище внутри портатива.
    """
    log = log or Logger()
    report = MaintenanceReport(folder=folder)
    config_path = os.path.join(folder, CONFIG_NAME)
    if not looks_like_portable(folder):
        message = (f"В папке нет {CONFIG_NAME} или App — обновлять нечего. "
                   "Укажите корень портатива (папку, где лежит Launch.bat).")
        log.error(message)
        report.messages.append(message)
        return report

    try:
        with open(config_path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        message = f"Не удалось прочитать {CONFIG_NAME}: {exc}"
        log.error(message)
        report.messages.append(message)
        return report

    # Старый лончер может быть ещё запущен — его файл нельзя перезаписать,
    # пока он работает.
    stopped = procutil.release_folder(folder)
    report.stopped = stopped
    for name in stopped:
        log.ok(f"Остановлено перед обновлением: {name}")

    cfg = launcher_mod.config_from_dict(data)
    log.info(f"Обновляю лончеры портатива «{cfg.app_name}»")

    # Сквозные сохранения настраиваются ЗДЕСЬ, а не только при сборке: иначе
    # уже готовый портатив так и остался бы с двумя разными хранилищами
    # сейвов — одним для прямого запуска App\Game.exe, другим для лончера.
    if shared_saves:
        try:
            setup = saves_mod.plan(
                folder, cfg.app_name,
                [t.rel_path for t in cfg.targets] or [cfg.target_exe_rel],
                data_dir_name=cfg.data_dir_name)
            saves_mod.apply(folder, setup, log)
            cfg.shared_saves = setup.to_dict()
            # Инструкция по настройкам игры (какие INI держать рядом с exe и
            # что в них подтверждать) едет в конфиг вместе с сохранениями:
            # по ней обновлённый лончер обслуживает Fallout.ini в runtime.
            cfg.game_settings = setup.game_settings
            report.saves_mode = setup.mode
            report.saves_migrated = setup.migrated
            for line in saves_mod.describe(setup):
                log.ok(line) if setup.enabled else log.info(line)
                report.messages.append(line)
            if setup.patched:
                report.updated.extend(setup.patched)
            if setup.migrated:
                message = ("Сохранения сведены в общее хранилище портатива: "
                           f"{setup.migrated} файлов. Их видят все способы "
                           "запуска.")
                log.ok(message)
                report.messages.append(message)
        except OSError as exc:
            message = f"Сквозные сохранения настроить не удалось: {exc}"
            log.warn(message)
            report.messages.append(message)

    files = {
        "Launch.bat": (launcher_mod.render_bat(cfg), "ascii"),
        "LaunchHidden.vbs": (launcher_mod.render_vbs(), "ascii"),
        launcher_mod.STOP_SCRIPT_NAME: (
            launcher_mod.render_stop_cmd(cfg), "ascii"),
    }
    for name, (text, encoding) in files.items():
        try:
            with open(os.path.join(folder, name), "w", encoding=encoding,
                      newline="\r\n") as handle:
                handle.write(text)
            report.updated.append(name)
        except OSError as exc:
            message = f"Не удалось записать {name}: {exc}"
            log.warn(message)
            report.messages.append(message)

    # Конфиг переписывается последним: в нём появляется секция shutdown,
    # по которой новый лончер понимает, когда отпускать папку.
    try:
        with open(config_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(launcher_mod.render_config_json(cfg))
        report.updated.append(CONFIG_NAME)
    except OSError as exc:
        message = f"Не удалось обновить {CONFIG_NAME}: {exc}"
        log.warn(message)
        report.messages.append(message)

    if copy_exe is not None:
        main_rel = os.path.join("App", "LaunchPortable.exe")
        if copy_exe(folder, main_rel):
            report.updated.append(main_rel)
        for alias in cfg.launcher_aliases:
            if copy_exe(folder, alias):
                report.updated.append(alias)

    report.success = bool(report.updated)
    if report.success:
        message = ("Портатив обновлён: теперь он сам закрывает фоновые "
                   "процессы при выходе, освобождает свою папку и держит "
                   "единые сохранения для всех способов запуска. "
                   "Обновлено файлов: " + str(len(report.updated)))
        log.ok(message)
        report.messages.append(message)
    return report
