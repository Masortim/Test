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
import sys


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        from portablizer.cli import main as cli_main
        return cli_main(args)
    from portablizer.gui.main_window import run
    return run()


if __name__ == "__main__":
    sys.exit(main())
