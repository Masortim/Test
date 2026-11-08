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
    «Я хочу удалить эту папку прямо сейчас». Вежливо закрывает и затем
    завершает процессы из папки, проверяет результат пробным переименованием
    и, если папка всё ещё занята, называет виновника — включая службы и
    чужие программы, подгрузившие оттуда DLL. Системные службы не удаляются.

``refresh``
    «Пусть этот портатив ведёт себя правильно». Перевыпускает лончеры
    (``LaunchPortable.exe``, ``Launch.bat``, ``LaunchHidden.vbs``,
    ``StopPortable.cmd``), дописывает в конфиг секции ``shutdown`` и
    ``shared_saves`` и настраивает сквозные сохранения прямо на месте —
    сохраняя все настройки портатива: цели, реестр, переменные среды,
    требования к распространяемым компонентам. Именно так лечится портатив,
    у которого прямой запуск ``App\\Game.exe`` и ``LaunchPortable.exe``
    видели разные сейвы: пересобирать его не нужно.

``update``
    «Вышла новая версия программы». Запускает ``App\\LaunchPortable.exe
    --update``: тот ставит новую версию во временную папку, проверяет и
    только потом подменяет файлы в ``App`` (прежняя версия остаётся в
    ``Updates\\backup``). Данные в ``PortableData`` не затрагиваются.

``release`` и ``refresh`` ничего не устанавливают и не трогают ничего за
пределами указанной папки.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from .. import __version__
from . import launcher as launcher_mod
from . import elevate as elevate_mod
from . import pycharm as pycharm_mod
from . import procutil
from . import registry as reg_mod
from . import relpaths
from . import saves as saves_mod
from .languages import find_language
from .logutil import Logger

CONFIG_NAME = "launcher_config.json"


@dataclass
class MaintenanceReport:
    """Итог обслуживания — то, что показывается пользователю."""

    folder: str = ""
    success: bool = False
    #: Какие процессы из папки были остановлены (службы не удаляются).
    stopped: List[str] = field(default_factory=list)
    #: Службы, которые указывают внутрь папки и поэтому требуют ручной проверки.
    registered_services: List[str] = field(default_factory=list)
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


def read_config(path: str) -> dict:
    """Читает ``launcher_config.json``, починив сломанные escape-последовательности.

    Конфиг мог быть испорчен прежней версией (в него подставлялся путь с
    одиночными обратными слэшами). Обновление такого портатива не должно
    отказывать: файл чинится на месте, и обновление продолжается.
    """
    with open(path, "r", encoding="utf-8-sig") as handle:
        text = handle.read()
    try:
        return json.loads(text)
    except ValueError:
        repaired = launcher_mod.repair_json_escapes(text)
        data = json.loads(repaired)
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(repaired)
        except OSError:
            pass
        return data


def looks_like_portable(folder: str) -> bool:
    """Похожа ли папка на портатив, собранный Portablizer."""
    return bool(folder) and os.path.isfile(os.path.join(folder, CONFIG_NAME)) \
        and os.path.isdir(os.path.join(folder, "App"))


def release(folder: str, log: Optional[Logger] = None) -> MaintenanceReport:
    """Освобождает папку без снятия регистрации системных служб."""
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

    try:
        report.registered_services = procutil.services_in(folder)
    except Exception as exc:  # noqa: BLE001 - диагностика не блокирует обслуживание
        log.debug(f"Не удалось проверить службы папки: {exc}")
    if report.registered_services:
        message = (
            "Обнаружены службы, указывающие внутрь папки: "
            + ", ".join(report.registered_services)
            + ". Они не останавливались и не удалялись; удаление папки может "
              "не пройти, пока служба активна.")
        log.warn(message)
        report.messages.append(message)

    report.stopped = procutil.release_folder(folder, stop_services=False)
    for name in report.stopped:
        log.ok(f"Остановлено: {name}")

    errors: List[str] = []
    if procutil.folder_is_free(folder, errors):
        report.success = True
        message = ("При проверке блокировок не обнаружено. Попробуйте удалить "
                   "или перенести папку; Windows может обнаружить другие препятствия.")
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
            message = ("При проверке блокировок не обнаружено. Попробуйте удалить "
                       "или перенести папку; Windows может обнаружить другие препятствия.")
            log.ok(message)
            report.messages.append(message)
            return report
        for line in errors:
            log.debug(f"Папка не отпускается: {line}")

    scan_status: List[str] = []
    locked = procutil.busy_files(folder, scan_status=scan_status)
    holders = procutil.holders(folder, locked_files=locked)
    report.holders = procutil.describe_holders(holders)
    if not report.holders and not locked and not scan_status:
        recheck_errors: List[str] = []
        if procutil.folder_is_free(folder, recheck_errors):
            report.success = True
            message = ("При проверке блокировок не обнаружено. Попробуйте удалить "
                       "или перенести папку; Windows может обнаружить другие препятствия.")
            log.ok(message)
            report.messages.append(message)
            return report
        if recheck_errors:
            errors = recheck_errors
    if report.holders:
        message = "Папку держат: " + ", ".join(report.holders)
        log.warn(message + ".")
        report.messages.append(message)
        hint = ("Закройте указанные приложения штатно и повторите проверку. "
                "Чужие процессы и системные службы автоматически не завершаются, "
                "их дескрипторы принудительно не закрываются: это может "
                "повредить данные. При необходимости проверьте PID в "
                "Диспетчере задач или Мониторе ресурсов.")
        log.warn(hint)
        report.messages.append(hint)
    elif locked:
        report.holders = [os.path.basename(path) for path in locked]
        message = ("Windows сообщает о блокировке файлов: "
                   + ", ".join(report.holders[:6])
                   + ". Не удалось надёжно определить владельца; "
                     "он не был принудительно закрыт. Закройте программу "
                     "или найдите PID в Мониторе ресурсов и повторите.")
        log.warn(message)
        report.messages.append(message)
        if elevate_mod.is_elevated():
            hint = ("Portablizer уже запущен с повышенными правами; повторный "
                    "запуск администратором не гарантирует обнаружение владельца.")
        else:
            hint = ("Повышенные права могут помочь диагностике, но не "
                    "гарантируют обнаружение владельца и не разрешают "
                    "принудительно закрывать чужие процессы.")
        log.info(hint)
        report.messages.append(hint)
    else:
        message = ("Не удалось подтвердить, что папка свободна. "
                   + (" ".join(errors[:2]) if errors else
                      "Причина может быть в правах, занятом каталоге или "
                      "неполной проверке; повторите после закрытия приложений."))
        log.warn(message)
        report.messages.append(message)
    # A lock and an inaccessible path can coexist. Never hide the latter
    # behind a holder message, and retain the first check's concrete cause.
    if report.holders:
        details = [line for line in errors + scan_status
                   if not line.startswith("Открытые файлы:")]
        if details:
            detail = "Проверка также была неполной: " + " ".join(dict.fromkeys(details))
            log.warn(detail)
            report.messages.append(detail)
    return report


def _prefer_delta_gui_target(folder: str, cfg) -> bool:
    """Переключить старый portable Delta с CLI на desktop application.

    В paired-сборке ``Delta.exe`` — терминальный клиент, а
    ``delta-app.exe`` — окно, которое обрабатывает sign-in и Review Terms.
    Старые конфиги могли выбрать CLI по размеру/имени.  Меняем только
    существующую стандартную цель; явные дополнительные target'ы остаются
    доступными через меню.
    """
    current = str(getattr(cfg, "target_exe_rel", "") or "").replace("\\", "/")
    if current.rsplit("/", 1)[-1].casefold() != "delta.exe":
        return False
    candidate = (current.rsplit("/", 1)[0] + "/delta-app.exe"
                 if "/" in current else "delta-app.exe")
    candidate_path = os.path.join(folder, *candidate.split("/"))
    if not os.path.isfile(candidate_path):
        return False
    cfg.target_exe_rel = candidate
    for item in getattr(cfg, "targets", []):
        rel = str(item.rel_path).replace("\\", "/")
        if rel.casefold() == current.casefold() and item.role == "main":
            item.role = "auxiliary"
        elif rel.casefold() == candidate.casefold():
            item.role = "main"
    return True


def _prefer_pycharm_target(folder: str, cfg) -> bool:
    """Repair an App-based target only when one PyCharm IDE is unambiguous."""
    current = str(cfg.target_exe_rel or "").replace("\\", "/")
    if not current.casefold().startswith("app/") or ".." in current.split("/"):
        return False
    executable = pycharm_mod.find_pycharm_executable(os.path.join(folder, "App"), cfg.app_name)
    if not executable:
        return False
    candidate = os.path.relpath(executable, folder).replace("\\", "/")
    if current.casefold() != candidate.casefold():
        cfg.target_exe_rel = candidate
        found = False
        for item in cfg.targets:
            rel = item.rel_path.replace("\\", "/").casefold()
            if item.role == "main":
                item.role = "auxiliary"
            if rel == candidate.casefold():
                item.role = "main"
                found = True
        if not found:
            cfg.targets.insert(0, launcher_mod.TargetInfo(
                name="pycharm64", rel_path=candidate, role="main", bat_name="Launch.bat"))
    cfg.launcher_target_rel = candidate
    return True


def _generated_main_alias_bat(folder: str) -> bool:
    """Never overwrite an unrelated user-authored BAT during refresh."""
    path = os.path.join(folder, "Launch_Launcher.bat")
    if not os.path.exists(path):
        return True
    try:
        with open(path, "r", encoding="ascii") as fh:
            header = fh.read(1024)
        return ("companion portable launcher" in header or
                "Portablizer main launcher alias" in header)
    except (OSError, UnicodeError):
        return False


def refresh(folder: str, log: Optional[Logger] = None,
            copy_exe=None, shared_saves: bool = True,
            language: str = "") -> MaintenanceReport:
    """Перевыпускает лончеры существующего портатива текущей версией.

    ``copy_exe`` — функция ``(portable_dir, destination_rel) -> str``,
    копирующая встроенный ``LaunchPortable.exe`` (передаётся оркестратором,
    чтобы не тянуть сюда весь Portablizer).

    ``shared_saves`` — настроить ли заодно сквозные сохранения: свести
    сейвы прямого запуска и лончера в одно хранилище внутри портатива.

    ``language`` — код выбранного языка (например, ``"ru"``): применяет
    комплектные языковые .reg-переключатели из ``App`` (``_Lang_SW`` и т.п.)
    и переводит языковые значения в ``portable.reg``, ``portable_machine.reg``
    и ``PortableData\\Registry``.
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
    if _prefer_delta_gui_target(folder, cfg):
        message = ("Delta: основной запуск переключён с CLI Delta.exe на "
                   "delta-app.exe — desktop-версию с рабочим browser sign-in.")
        log.info(message)
        report.messages.append(message)
    pycharm = _prefer_pycharm_target(folder, cfg)
    if pycharm:
        message = "PyCharm: основной запуск направлен на существующий bin/pycharm64.exe."
        log.info(message)
        report.messages.append(message)
        alias_exe = os.path.join(folder, "Launch_Launcher.exe")
        if ("Launch_Launcher.exe" in cfg.launcher_aliases
                or not os.path.lexists(alias_exe)):
            cfg.launcher_aliases["Launch_Launcher.exe"] = cfg.target_exe_rel
        else:
            report.messages.append("Существующий чужой Launch_Launcher.exe не изменён.")
    log.info(f"Обновляю лончеры портатива «{cfg.app_name}»")

    # Портатив, собранный до 1.15.0, не имеет ни секции относительных путей,
    # ни штампа корня — значит после переноса на другой диск его настройки не
    # починятся. Обслуживание дописывает и то, и другое.
    if not cfg.relative_paths:
        cfg.relative_paths = relpaths.launcher_section(folder)
    try:
        relpaths.write_stamp(folder, folder, __version__)
    except OSError as exc:  # noqa: BLE001 - штамп не должен срывать обслуживание
        log.warn(f"Не удалось запомнить корень портатива: {exc}")

    effective_lang = (language or cfg.language or "").strip()
    if effective_lang:
        cfg.language = effective_lang
        applied_regs, all_reg_keys, updated_inis = (
            reg_mod.apply_language_to_portable_folder(
                folder,
                effective_lang,
                reg_file_name=cfg.reg_file_name,
                machine_reg_file_name=cfg.machine_reg_file_name,
                data_dir_name=cfg.data_dir_name,
            )
        )
        lang_obj = find_language(effective_lang)
        lang_title = lang_obj.title if lang_obj else effective_lang
        if all_reg_keys:
            cfg.apply_registry = True
            cfg.registry_keys = launcher_mod.consolidate_root_keys(
                list(cfg.registry_keys) + all_reg_keys
            )
            cfg.registry_created_keys = launcher_mod.consolidate_root_keys(
                list(cfg.registry_created_keys) + all_reg_keys
            )
            for r_name in (cfg.reg_file_name, cfg.machine_reg_file_name):
                r_path = os.path.join(folder, r_name)
                if os.path.isfile(r_path):
                    if launcher_mod.ROOT_TOKEN in reg_mod.read_reg_file_text(r_path):
                        cfg.registry_has_root_token = True
                    if r_name not in report.updated:
                        report.updated.append(r_name)
        if applied_regs:
            msg = (f"Применён языковой файл реестра ({lang_title}): "
                   f"{', '.join(applied_regs)}.")
            log.ok(msg)
            report.messages.append(msg)
        elif all_reg_keys:
            msg = f"Язык «{lang_title}» обновлён в реестре портатива."
            log.ok(msg)
            report.messages.append(msg)
        if updated_inis:
            msg = (f"Язык «{lang_title}» прописан в настройках: "
                   f"{', '.join(updated_inis)}.")
            log.ok(msg)
            report.messages.append(msg)
            report.updated.extend(updated_inis)

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

    # Cursor/VS Code: у портатива, собранного прежней версией, профиль не
    # привязан к папке (VSCODE_* переменных нет), а Chromium-песочница не
    # отключена. Обслуживание дописывает и то, и другое — пересобирать
    # приложение ради этого не нужно.
    # target_exe_rel уже включает "App" (это путь от корня портатива).
    app_main = os.path.join(folder, cfg.target_exe_rel.replace("/", os.sep)
                            .replace("\\", os.sep))
    vscode = launcher_mod.vscode_product(app_main)
    if vscode:
        for key, value in launcher_mod.vscode_portable_env(
                vscode, cfg.data_dir_name).items():
            cfg.extra_env.setdefault(key, value)
        try:
            for note in launcher_mod.prepare_vscode_profile(
                    folder, cfg.target_exe_rel, cfg.data_dir_name):
                log.ok(note)
                report.messages.append(note)
        except OSError as exc:
            log.warn(f"Профиль {vscode['name']} подготовить не удалось: {exc}")

    files = {
        "Launch.bat": (launcher_mod.render_bat(cfg), "ascii"),
        "LaunchHidden.vbs": (launcher_mod.render_vbs(), "ascii"),
        launcher_mod.STOP_SCRIPT_NAME: (
            launcher_mod.render_stop_cmd(cfg), "ascii"),
        launcher_mod.UPDATE_SCRIPT_NAME: (
            launcher_mod.render_update_cmd(cfg), "ascii"),
    }
    if pycharm and _generated_main_alias_bat(folder):
        files["Launch_Launcher.bat"] = (launcher_mod.render_main_alias_bat(), "ascii")
    elif pycharm:
        report.messages.append("Существующий чужой Launch_Launcher.bat не изменён.")
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

    # NetStack: старые портативы несли Setup.cmd/NetStackServices.ps1, которые
    # верили pnputil и писали healthy=True без драйвера. Пересоздаём их из
    # манифеста вместе с лончером, чтобы «Обновить лончер» чинило и tap0901.
    try:
        from . import netstack as netstack_mod
        netstack_updated = netstack_mod.refresh_netstack_scripts(folder)
        report.updated.extend(netstack_updated)
        if netstack_updated:
            report.messages.append("NetStack: скрипты установки/проверки "
                                   "драйверов обновлены.")
    except Exception as exc:  # noqa: BLE001 — NetStack не должен ронять refresh
        report.messages.append(f"NetStack: не удалось обновить скрипты ({exc}).")

    report.success = bool(report.updated)
    if report.success:
        message = ("Портатив обновлён: теперь он сам закрывает фоновые "
                   "процессы при выходе, освобождает свою папку и держит "
                   "единые сохранения для всех способов запуска. "
                   "Обновлено файлов: " + str(len(report.updated)))
        log.ok(message)
        report.messages.append(message)
    return report


#: Значение ``installer``, требующее свежий официальный драйвер OpenVPN.
OFFICIAL_SOURCE = "@official"


def repair_netstack(folder: str, installer: str = "",
                    log: Optional[Logger] = None) -> MaintenanceReport:
    """Починить драйверы VPN у готового портатива — то же, что кнопка в окне.

    Порядок источников недостающих ``.sys``/``.cat``:

    1. указанный установщик (только читается, НЕ запускается);
    2. этот компьютер — DriverStore/``Program Files\\TAP-Windows``, если
       VPN-клиент здесь уже установлен и работает;
    3. официальный архив OpenVPN — когда комплект ПОЛНЫЙ, но Windows
       блокирует драйвер как уязвимый (TAP младше 9.27, CVE-2024-1305).
       Тогда ни установщик, ни система не помогут: там лежит тот же
       старый файл, и его отвергает сама Windows.

    Затем манифест и скрипты ``NetStack/`` пересоздаются текущей версией.
    Отчёт честно говорит, укомплектован пакет или нет: «обновлено» не
    означает «драйвер есть».
    """
    from . import netstack as netstack_mod

    log = log or Logger()
    report = MaintenanceReport(folder=folder)
    root = os.path.abspath(str(folder or ""))
    if not os.path.isdir(root):
        report.messages.append(f"Папка не найдена: {root}")
        log.error(report.messages[-1])
        return report
    before = netstack_mod.inspect_netstack(root)
    if not before.present:
        report.messages.append(
            "В этом портативе нет NetStack: программа не использует "
            "сетевые драйверы VPN либо собрана без них. Чинить нечего.")
        log.warn(report.messages[-1])
        return report
    if not before.has_installable:
        report.messages.append(
            "NetStack есть, но ставить драйверы портатив не должен "
            "(адаптер создаёт само приложение) — починка не нужна.")
        log.info(report.messages[-1])
        return report
    forced_official = str(installer or "") == OFFICIAL_SOURCE
    if forced_official:
        installer = ""
    if forced_official:
        # Комплект может быть полным и всё равно нерабочим: Windows
        # отказывается ставить tap0901.sys младше 9.27. Именно это видит
        # и вендорский клиент как «Ошибка установки драйвера адаптера».
        for line in before.outdated:
            log.warn(f"драйвер устарел и блокируется Windows — {line}")
        log.info("Беру актуальный подписанный TAP-Windows у проекта "
                 "OpenVPN (нужна сеть; установка только по вашему запуску)…")
        # В сеть идём ТОЛЬКО по явному выбору человека: обычная починка
        # обязана работать без интернета и ничего не скачивать молча.
        try:
            replaced = netstack_mod.refill_netstack_from_official(
                root, log=log, only_outdated=not forced_official)
            report.updated.extend(replaced)
            for rel in replaced:
                log.ok(f"заменён {rel}")
            if replaced:
                before = netstack_mod.inspect_netstack(root)
        except (OSError, ValueError, RuntimeError) as exc:
            log.warn(f"официальный драйвер получить не удалось: {exc}")
            report.messages.append(
                "Свежий драйвер скачать не удалось (нужен доступ в интернет): "
                f"{exc}")
    if before.complete:
        log.info("Пакет драйвера уже укомплектован: "
                 + ", ".join(before.ready))
    else:
        for line in before.missing:
            log.warn(f"не хватает файлов — {line}")
        added: List[str] = []
        if installer:
            if not os.path.isfile(installer):
                report.messages.append(f"Установщик не найден: {installer}")
                log.error(report.messages[-1])
                return report
            log.info("Ищу полный пакет драйвера внутри установщика "
                     "(установщик не запускается)…")
            try:
                added = netstack_mod.refill_netstack_from_installer(
                    root, installer)
            except (OSError, ValueError) as exc:
                log.warn(f"из установщика драйверы не извлечены: {exc}")
            for rel in added:
                log.ok(f"добавлен {rel}")
        if not added:
            log.info("Пробую взять пакет с этого компьютера "
                     "(DriverStore, Program Files\\TAP-Windows)…")
            try:
                added = netstack_mod.refill_netstack_from_system(root)
            except (OSError, ValueError) as exc:
                log.warn(f"с этого ПК пакет взять не удалось: {exc}")
            for rel in added:
                log.ok(f"добавлен {rel}")
        report.updated.extend(added)
    try:
        report.updated.extend(netstack_mod.refresh_netstack_scripts(root))
    except (OSError, ValueError) as exc:
        report.messages.append(f"NetStack: скрипты не обновлены ({exc}).")
        log.error(report.messages[-1])
        return report
    after = netstack_mod.inspect_netstack(root)
    # Комплектный, но заблокированный Windows драйвер успехом не считается:
    # именно в этом состоянии установка падает и у самого VPN-клиента.
    report.success = after.complete and not after.outdated
    if after.complete and after.outdated:
        message = (
            "Файлы драйвера на месте, но сама Windows откажется его "
            "ставить: " + "; ".join(after.outdated) + ".\n\n"
            "В этих версиях tap0901.sys есть уязвимость CVE-2024-1305, "
            "поэтому современные Windows блокируют драйвер — отсюда "
            "«Ошибка установки драйвера адаптера» и у самого VPN-клиента. "
            "Нужен TAP-Windows 9.27.0 или новее. Нажмите «Починить драйверы "
            "VPN» → «Скачать свежий драйвер» (нужен интернет), затем "
            "запустите портатив и подтвердите запрос прав администратора.")
        log.warn(message)
    elif after.complete:
        message = (
            "Драйверы VPN укомплектованы: " + ", ".join(after.ready) + ". "
            "Скрипты NetStack обновлены. Запустите портатив на нужном "
            "компьютере и подтвердите запрос прав администратора — адаптер "
            "будет создан автоматически.")
        log.ok(message)
    else:
        message = (
            "Полный пакет драйвера получить не удалось. Не хватает: "
            + "; ".join(after.missing) + ".\n\n"
            "Укажите установщик той программы, из которой собран портатив "
            "(кнопка «Починить драйверы VPN» → «Выбрать установщик…»), либо "
            "выполните починку на компьютере, где этот VPN-клиент уже "
            "установлен и работает: тогда пакет будет взят из системы. "
            "Без полного подписанного пакета адаптер на чужом ПК не "
            "поднимется.")
        log.warn(message)
    report.messages.append(message)
    return report


def repair_start_menu(log: Optional[Logger] = None) -> MaintenanceReport:
    """Лечит меню «Пуск» после сборки под администратором.

    Что именно ломалось и почему — в ``core/startmenu.py``. Здесь только
    операция для окна: возвращает «Документы» на место, если их увели внутрь
    удалённой портативной папки, сбрасывает испорченный кэш
    ``StartMenuExperienceHost`` и перезапускает его (Windows перестраивает
    меню сама; закрепления пользователя не удаляются).

    ``explorer.exe`` не завершается никогда: это закрыло бы все окна.
    """
    from . import startmenu

    log = log or Logger()
    report = MaintenanceReport(folder="")
    if not startmenu.IS_WINDOWS:
        message = "Починка меню «Пуск» доступна только на Windows."
        log.warn(message)
        report.messages.append(message)
        return report

    found = startmenu.diagnose()
    if not found:
        message = ("Следов поломки не найдено: «Документы» указывают на "
                   "существующую папку, кэш меню «Пуск» на месте.")
        log.info(message)
        report.messages.append(message)
        report.success = True
        return report
    for line in found:
        log.warn(line)

    try:
        done = startmenu.repair_start_menu(log)
    except Exception as exc:  # noqa: BLE001 - починка не должна падать
        message = f"Починить меню «Пуск» не удалось: {exc}"
        log.error(message)
        report.messages.append(message)
        return report

    report.messages.extend(done)
    report.success = bool(done)
    if done:
        message = ("Меню «Пуск» починено. Если оно не открылось сразу, "
                   "перезапустите Проводник или войдите заново.")
        log.ok(message)
        report.messages.append(message)
    else:
        message = ("Исправить автоматически нечего либо не хватило прав. "
                   "Перезагрузите компьютер: Windows пересоберёт кэш меню при "
                   "старте.")
        log.warn(message)
        report.messages.append(message)
    return report


#: Имя журнала обновления (лежит в папке данных портатива).
UPDATE_LOG_NAME = "launcher-update.log"


def _tail(path: str, lines: int = 6) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return [line.rstrip() for line in handle.readlines()[-lines:]
                    if line.strip()]
    except OSError:
        return []


def update_app(folder: str, installer: str = "", log: Optional[Logger] = None,
               runner=None) -> MaintenanceReport:
    """Обновляет программу внутри портатива через его собственный лончер.

    ``installer`` - файл установщика или ``http(s)``-адрес; пусто - лончер
    возьмёт скачанное программой или загрузит актуальную версию по адресу
    из ``launcher_config.json``. ``runner(command) -> int`` подменяется в
    тестах.
    """
    log = log or Logger()
    report = MaintenanceReport(folder=folder)
    exe = os.path.join(folder, "App", "LaunchPortable.exe")
    if not looks_like_portable(folder) or not os.path.isfile(exe):
        message = (
            "В папке нет App\\LaunchPortable.exe. Сначала нажмите «Обновить "
            "лончер»: он перевыпустит лончер, умеющий обновлять программу.")
        log.error(message)
        report.messages.append(message)
        return report

    command = [exe, "--update", "--yes"]
    if installer:
        command.insert(2, installer)
    log.info("Обновляю программу внутри портатива: " + " ".join(command[1:]))
    data_name = "PortableData"
    try:
        with open(os.path.join(folder, CONFIG_NAME), "r",
                  encoding="utf-8-sig") as handle:
            data_name = str(json.load(handle).get("data_dir_name", data_name))
    except (OSError, ValueError):
        pass
    update_log = os.path.join(folder, data_name, UPDATE_LOG_NAME)
    try:
        code = (runner or (lambda cmd: subprocess.call(cmd, cwd=folder)))(
            command)
    except OSError as exc:
        message = f"Не удалось запустить лончер: {exc}"
        log.error(message)
        report.messages.append(message)
        return report

    for line in _tail(update_log):
        log.debug(line)
    if code == 0:
        report.success = True
        report.updated.append("App")
        message = ("Программа обновлена внутри портатива. Прежняя версия "
                   "сохранена в Updates\\backup (откат: UpdatePortable.cmd "
                   "--rollback). Данные в PortableData не тронуты.")
        log.ok(message)
    elif code == 3:
        message = "Обновление отменено."
        log.warn(message)
    else:
        message = (f"Обновление не удалось (код {code}). Портатив остался "
                   f"прежним. Подробности: {update_log}")
        log.error(message)
    report.messages.append(message)
    return report
