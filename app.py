#!/usr/bin/env python3
"""Portablizer — единая точка входа для запуска и для сборки PyInstaller.

Запуск из исходников:
    python app.py                 — интерфейс, как раньше
    python app.py build A.exe --out B   — то же самое без окна (см. portablizer/cli.py)

Сборка Windows-exe (на Windows):
    build.bat        (или см. .github/workflows/build-windows.yml для CI)

exe собран с ``console=False`` (чтобы двойной клик не мигал чёрным окном),
поэтому для CLI-аргументов он сам прицепляет родительскую консоль, а журнал
дублирует в файл: подробности — в докстринге ``portablizer.cli``.
"""
import os
import sys
import time
import traceback

#: Куда пишется отчёт о падении при старте. Папка своя, а не рядом с exe:
#: Portablizer часто лежит в Program Files или на флешке только для чтения.
CRASH_LOG_ENV = "PORTABLIZER_CRASH_LOG"


def crash_log_path() -> str:
    """Путь журнала падений: переопределяется переменной окружения."""
    override = os.environ.get(CRASH_LOG_ENV)
    if override:
        return override
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or "."
    return os.path.join(base, "Portablizer", "portablizer-crash.log")


def write_crash_log(text: str, path: str = "") -> str:
    """Сохраняет отчёт о падении; возвращает путь (или "" при неудаче).

    Без этого сбой при старте в собранном exe (``console=False``) не виден
    вообще: окно не появляется, консоли нет, и пользователь видит только
    «программа не запускается». Так было с ``inspect.getsource`` в 1.20.0 —
    PyInstaller-сборка не содержит исходников, и импорт падал с
    ``OSError: could not get source code``.
    """
    target = path or crash_log_path()
    try:
        folder = os.path.dirname(target)
        if folder:
            os.makedirs(folder, exist_ok=True)
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} "
                         f"(pid {os.getpid()}) =====\n{text}\n")
        return target
    except OSError:
        return ""


def _show_error(text: str) -> None:
    """Показывает ошибку пользователю: окно Windows, иначе стандартный вывод."""
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
            None, text, "Portablizer — ошибка запуска", 0x10)
        return
    except Exception:  # noqa: BLE001 - вне Windows или без user32
        pass
    try:
        print(text, file=sys.stderr)
    except Exception:  # noqa: BLE001 - консоли может не быть вовсе
        pass


def report_crash(exc: BaseException) -> int:
    """Пишет журнал и сообщает пользователю, что случилось и куда смотреть."""
    details = "".join(traceback.format_exception(type(exc), exc,
                                                 exc.__traceback__))
    path = write_crash_log(details)
    hint = f"\n\nПодробности записаны в файл:\n{path}" if path else ""
    _show_error("Portablizer не смог запуститься.\n\n"
                f"{type(exc).__name__}: {exc}{hint}")
    try:
        print(details, file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass
    return 1


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        from portablizer.cli import main as cli_main
        return cli_main(args)
    from portablizer.gui.main_window import run
    return run()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as error:  # noqa: BLE001 - показываем, а не молчим
        sys.exit(report_crash(error))
