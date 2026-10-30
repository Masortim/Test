"""Командная строка Portablizer: сборка портатива без интерфейса.

``Portablizer.exe`` без аргументов — это обычный GUI; с аргументами — этот
модуль. Режим нужен не только «для автоматизации»: он проверяем тестами на
любой ОС (ядро и так ничего не знает о Qt — см. ``core/logutil.py``), а в
exe покрывает то, до чего окно интерфейса не докликивается: пакетную сборку,
``--dry-run`` с предпросмотром плана и журналом.

Две детали, которые и делают CLI в оконном exe полезным:

* у бинарника, собранного с ``console=False``, стандартных потоков как бы не
  существует: запуск из cmd прицепляет родительскую консоль
  (:func:`attach_console`), а если цеплять нечего — весь вывод всё равно
  уходит в ``portablizer-cli.log`` рядом с папкой результата;
* повышение прав — только при явном ``--elevate``. По умолчанию CLI
  работает без UAC; ``--no-elevate`` оставлен как совместимый флаг.

Выход: 0 — успех; 1 — сборка не удалась (подсказки движка печатаются);
2 — ошибка в командной строке.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Sequence

from . import __app_name__, __version__


def attach_console() -> bool:
    """Вернуть True, если окну суждено печатать в консоль.

    Вызывается ДО первого ``print``: у оконного exe ``sys.stdout`` либо
    ``None``, либо пишет в никуда. Порядок такой: прицепить консоль
    родителя (cmd/PowerShell), иначе — создать новую. У уже консольного
    запуска (``python app.py`` и тесты) ничего не делаем.
    """
    if not sys.platform.startswith("win"):
        return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        if not kernel32:
            return False
        # STD_OUTPUT_HANDLE уже занят — мы и так в консоли.
        if kernel32.GetStdHandle(-11) not in (0, None, -1):
            return False
        ATTACH_PARENT_PROCESS = 0x03
        if not kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
            if not kernel32.AllocConsole():
                return False
        # После AttachConsole «родной» sys.stdout указывает в несуществующую
        # трубу; переоткрываем консольное устройство сами, с UTF-8 — иначе
        # первая же кириллица упрётся в кодовую страницу OEM.
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        return True
    except Exception:  # noqa: BLE001 — консоль это украшение, не опора
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=__app_name__,
        description="Создание портативных версий программ из установщиков.")
    parser.add_argument("--version", action="version",
                        version=f"{__app_name__} {__version__}")
    sub = parser.add_subparsers(dest="command")

    b = sub.add_parser("build", help="собрать портатив из установщика")
    b.add_argument("installer", help="путь к setup/exe/msi установщику")
    b.add_argument("--out", default="",
                   help="папка результата (по умолчанию — текущая)")
    b.add_argument("--name", default="",
                   help="имя приложения; по умолчанию — из имени файла")
    b.add_argument("--lang", default="",
                   help="язык многоязычного установщика (ru, en, …)")
    b.add_argument("--extra-args", nargs="*", default=[],
                   metavar="ARG", help="аргументы, дописанные тихой установке")
    b.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                   help="переменная окружения для лончера (можно повторять)")
    b.add_argument("--idle-timeout", type=int, default=0, metavar="SEC",
                   help="предел тишины установщика (иначе — пока пишет)")
    b.add_argument("--hard-timeout", type=int, default=0, metavar="SEC",
                   help="абсолютный потолок одной попытки установки")

    toggles = b.add_argument_group("режимы, как в окне интерфейса")
    toggles.add_argument("--single-file", action="store_true",
                         help="использовать только выбранный файл: временно "
                              "копировать его в пустую папку, не брать файлы "
                              "рядом")
    toggles.add_argument("--no-registry", action="store_true",
                         help="не захватывать изменения реестра")
    toggles.add_argument("--no-userdirs", action="store_true",
                         help="не изолировать AppData/Temp в PortableData")
    toggles.add_argument("--cleanup-app-entry", action="store_true",
                         help="совместимый флаг: запись приложения из списка "
                              "установленных удаляется и так (по умолчанию)")
    toggles.add_argument("--no-cleanup", action="store_true",
                         help="оставить в списке установленных запись, которую "
                              "создал установщик внутри портатива")
    toggles.add_argument("--shell-integration", action="store_true",
                         help="перенести и ассоциации файлов/COM (по умолчанию "
                              "нет: чужому ПК они не нужны)")
    toggles.add_argument("--no-exe-launcher", action="store_true",
                         help="не класть готовый LaunchPortable.exe в App")
    toggles.add_argument("--no-runtimes", action="store_true",
                         help="не приносить Visual C++/DirectX в портатив")
    toggles.add_argument("--lean-runtimes", action="store_true",
                         help="только реально требуемые библиотеки, без "
                              "полного комплекта «про запас»")
    toggles.add_argument("--download-runtimes", action="store_true",
                         help="разрешить докачку недостающих пакетов с сайта "
                              "Microsoft (по умолчанию сеть не трогает)")
    toggles.add_argument("--silent-redist", action="store_true",
                         help="установить опознанные runtime-пакеты на этом ПК "
                              "(системное изменение; по умолчанию выключено)")
    toggles.add_argument("--no-silent-redist", action="store_true",
                         help="совместимый флаг: не устанавливать runtime-пакеты "
                              "на этом ПК")
    toggles.add_argument("--no-shared-saves", action="store_true",
                         help="выключить сквозные портативные сохранения")
    toggles.add_argument("--no-relative-paths", action="store_true",
                         help="не запоминать корень портатива: после переноса "
                              "папки на другой диск настройки программы могут "
                              "указывать в старое место (по умолчанию пути "
                              "остаются переносимыми)")
    toggles.add_argument("--no-netstack", action="store_true",
                         help="не переносить системные сетевые компоненты "
                              "(драйверы TAP-Windows, службы VPN) в "
                              "NetStack")
    toggles.add_argument("--shared-netstack", action="store_true",
                         help="NetStack в режиме общего компонента: драйвер "
                              "остаётся в системе (по умолчанию — изоляция "
                              "на время сеанса)")
    toggles.add_argument("--assisted", action="store_true",
                         help="разрешить окно мастера (старые InstallShield)")
    toggles.add_argument("--assisted-timeout", type=int, default=0,
                         metavar="SEC",
                         help="сколько ждать человека в мастере")
    b.add_argument("--elevate", action="store_true",
                   help="явно запросить UAC перед сборкой (по умолчанию "
                        "работать без повышения прав)")
    b.add_argument("--no-elevate", action="store_true",
                   help="совместимый флаг: не просить UAC")
    b.add_argument("--dry-run", action="store_true",
                   help="показать разбор задачи и план и выйти, ничего не "
                        "устанавливая")
    b.add_argument("--log-file", default="",
                   help="куда писать журнал (по умолчанию <out>/portablizer-cli.log)")

    # Починка профиля: нужна после сборки под администратором, когда меню
    # «Пуск» Windows 11 перестало открываться. Папка портатива не нужна.
    sub.add_parser(
        "repair-start-menu",
        help="починить меню «Пуск» и вернуть папку «Документы» в профиль "
             "пользователя после сборки под администратором")
    return parser


def _parse_env(pairs: Sequence[str]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for raw in pairs:
        key, sep, value = str(raw).partition("=")
        if not sep or not key.strip():
            raise ValueError(f"--env ждёт KEY=VALUE, получено: {raw!r}")
        env[key.strip()] = value
    return env


def options_from_args(ns: argparse.Namespace) -> "object":
    """Аргументы → PortableOptions. Отдельная функция — ради тестов."""
    from .core.portablizer import PortableOptions

    installer = os.path.abspath(str(ns.installer or ""))
    if not os.path.isfile(installer):
        raise FileNotFoundError(f"Установщик не найден: {installer}")
    out = os.path.abspath(ns.out or os.getcwd())
    os.makedirs(out, exist_ok=True)
    bundle = not ns.no_runtimes
    opts = PortableOptions(
        installer_path=installer,
        output_dir=out,
        single_file=bool(ns.single_file),
        app_name=(ns.name or "").strip(),
        redirect_userdirs=not ns.no_userdirs,
        capture_registry=not ns.no_registry,
        build_exe_launcher=not ns.no_exe_launcher,
        cleanup_host=not ns.no_cleanup,
        include_shell_integration=bool(ns.shell_integration),
        allow_assisted_install=bool(ns.assisted),
        bundle_runtimes=bundle,
        full_runtimes=bundle and not ns.lean_runtimes,
        download_runtimes=bundle and bool(ns.download_runtimes),
        silent_runtime_install=(bundle and bool(ns.silent_redist)
                               and not ns.no_silent_redist),
        shared_saves=not ns.no_shared_saves,
        relative_paths=not ns.no_relative_paths,
        netstack_components=not ns.no_netstack,
        netstack_isolated=not ns.shared_netstack,
        extra_install_args=[str(a) for a in (ns.extra_args or [])],
        install_language=(ns.lang or "").strip(),
        extra_env=_parse_env(ns.env or []),
    )
    if ns.idle_timeout:
        opts.install_timeout = int(ns.idle_timeout)
    if ns.hard_timeout:
        opts.install_deadline = int(ns.hard_timeout)
    if ns.assisted_timeout:
        opts.assisted_timeout = int(ns.assisted_timeout)
    return opts


def _plan_preview(opts, engine) -> Dict[str, object]:
    """To, что покажет --dry-run: конфигурация + вычисленный путь результата."""
    name = engine._safe_name(opts)
    portable_dir = os.path.normpath(
        os.path.join(opts.output_dir, f"{name}_Portable"))
    from dataclasses import asdict
    plan = asdict(opts)
    plan["portable_dir"] = portable_dir
    plan["python"] = sys.version.split()[0]
    plan["frozen"] = bool(getattr(sys, "frozen", False))
    plan["windows"] = os.name == "nt"
    return plan


def cmd_build(ns: argparse.Namespace) -> int:
    from .core.logutil import Logger
    from .core.portablizer import Portablizer

    try:
        opts = options_from_args(ns)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 2

    engine = Portablizer(Logger())
    if ns.dry_run:
        print(json.dumps(_plan_preview(opts, engine), ensure_ascii=False,
                         indent=2, sort_keys=True))
        return 0

    if ns.elevate and not ns.no_elevate:
        from .core import elevate
        if elevate.ensure_elevated():
            # Повышенная копия печатает свою версию этой команды; здесь
            # остаётся только не мешать: выход 0 — результат у пользователя.
            return 0

    log_file = ns.log_file or os.path.join(opts.output_dir,
                                           "portablizer-cli.log")
    log = Logger(logfile=log_file)
    last_line = [""]

    def sink(level: str, message: str) -> None:
        line = message if message != last_line[0] else ""
        if line:
            last_line[0] = message
            print(f"{level:<5} {line}")

    log.add_sink(sink)
    shown = [-1]

    def progress(percent: int, stage: str) -> None:
        if percent != shown[0]:
            shown[0] = percent
            print(f"[{percent:3d}%] {stage}")

    engine = Portablizer(log, progress=progress)
    result = engine.run(opts)
    print()
    if result.success:
        if result.hints:
            print(f"Файлы собраны (переносимость не подтверждена): {result.portable_dir}")
        else:
            print(f"Портатив готов: {result.portable_dir}")
        if result.main_exe_rel:
            print(f"Запуск:        {os.path.join(result.portable_dir, result.main_exe_rel)}")
        for hint in result.hints or []:
            print(f"Внимание:      {hint}")
        if not result.folder_is_free and result.folder_holders:
            print(f"Внимание: папку держат {', '.join(result.folder_holders)}")
        if result.netstack_drivers or result.netstack_services:
            net = []
            if result.netstack_drivers:
                net.append("драйверы: " + ", ".join(result.netstack_drivers))
            if result.netstack_services:
                net.append("службы: " + ", ".join(result.netstack_services))
            print("NetStack:      " + "; ".join(net)
                  + (" (изоляция)" if opts.netstack_isolated else " (общий)"))
        return 0
    print(f"Сборка не удалась. Журнал: {log_file}")
    for hint in result.hints or []:
        print(f"  • {hint}")
    return 1


def cmd_repair_start_menu(ns: argparse.Namespace) -> int:
    """``repair-start-menu``: лечение последствий сборки под администратором."""
    from .core.logutil import Logger
    from .core.maintenance import repair_start_menu

    log = Logger()
    log.add_sink(lambda level, message: print(f"{level:<5} {message}"))

    report = repair_start_menu(log)
    print()
    for message in report.messages:
        print(f"• {message}")
    return 0 if report.success else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    attach_console()
    parser = build_parser()
    ns = parser.parse_args(args)
    if ns.command == "build":
        return cmd_build(ns)
    if ns.command == "repair-start-menu":
        return cmd_repair_start_menu(ns)
    parser.print_help()
    return 2
