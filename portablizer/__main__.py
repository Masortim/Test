"""Точка входа: `python -m portablizer`.

Без аргументов — графический интерфейс; с аргументами — командная строка
(:mod:`portablizer.cli`). Тот же выбор живёт в ``app.py`` и, соответственно,
в собранном Portablizer.exe.
"""
import sys


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        from .cli import main as cli_main
        return cli_main(args)
    from .gui.main_window import run
    return run()


if __name__ == "__main__":
    sys.exit(main())
