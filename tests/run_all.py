"""Прогон всего набора тестов по модулям — с потолком времени на каждый.

Зачем не одним ``unittest discover``
------------------------------------
* Вывод длинного прогона буферизуется, и при зависании в журнале сборки не
  видно, на каком тесте прогон встал: до последней строки дело не доходит.
  Здесь каждый модуль идёт отдельным процессом и с ``-v``, поэтому имена
  тестов попадают в журнал по мере выполнения.
* Зависший модуль не должен занимать всё задание: у каждого свой потолок, по
  его истечении :mod:`faulthandler` печатает стеки ВСЕХ потоков — сразу
  видно, что именно ждёт (дочерний процесс, поток, мьютекс), после чего
  модуль закрывается.
* Остальные модули выполняются дальше, так что один прогон даёт полную
  картину: какие модули прошли, какой сломался и какой замолчал.

Запуск::

    python tests/run_all.py [потолок_на_модуль_в_секундах]
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import List

#: Потолок на модуль. Самый долгий модуль набора укладывается в минуту, так
#: что четыре минуты — это уже не «долго», а зависание.
MODULE_LIMIT = 240.0

#: Сколько ждать после сброса стеков, прежде чем закрыть процесс силой.
KILL_GRACE = 60.0

#: Тело дочернего процесса: сброс стеков по таймеру + обычный прогон модуля.
#: ``-v`` обязателен: после зависания видно, какой тест был последним.
#: Загрузка идёт через ``discover`` с шаблоном имени файла: модуль, который
#: пропускается целиком (``raise unittest.SkipTest`` при импорте), при этом
#: отмечается как пропущенный, а не роняет прогон трассировкой.
_WRAPPER = (
    "import faulthandler, sys, unittest;"
    "faulthandler.dump_traceback_later(float(sys.argv[1]), exit=True);"
    "unittest.main(module=None, argv=['unittest', 'discover', '-s', 'tests',"
    " '-p', sys.argv[2] + '.py', '-v'], exit=True)"
)


def _enable_utf8() -> None:
    """Русские строки в журнале сборки: на Windows стандартный вывод не UTF-8.

    Без этого первый же ``print`` с кириллицей роняет прогон на
    ``UnicodeEncodeError`` — именно это случилось с первой версией этого
    файла на Windows-раннере.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue


def _modules(root: str) -> List[str]:
    """Имена файлов набора в устойчивом порядке (``test_*.py``)."""
    tests_dir = os.path.join(root, "tests")
    names: List[str] = []
    for entry in sorted(os.listdir(tests_dir)):
        if entry.startswith("test_") and entry.endswith(".py"):
            names.append(entry[:-3])
    return names


def run_module(root: str, name: str, limit: float) -> int:
    """Прогоняет один модуль и возвращает его код возврата."""
    env = dict(os.environ)
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONFAULTHANDLER"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    # Дочерний процесс печатает имена тестов (в них есть кириллица) и стеки:
    # кодировку задаём явно, иначе на Windows это UnicodeEncodeError.
    env["PYTHONIOENCODING"] = "utf-8"
    cmd = [sys.executable, "-u", "-c", _WRAPPER, str(limit), name]
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, cwd=root, env=env,
                              timeout=limit + KILL_GRACE)
    except subprocess.TimeoutExpired:
        print(f"!! {name}: процесс не закрылся даже после сброса стеков "
              f"({limit + KILL_GRACE:.0f} с) — закрываю.", flush=True)
        return 1
    spent = time.monotonic() - started
    if proc.returncode == 0:
        print(f"-- {name}: прошёл за {spent:.1f} с", flush=True)
    else:
        print(f"!! {name}: код {proc.returncode} за {spent:.1f} с", flush=True)
    return proc.returncode


def main(argv: List[str]) -> int:
    _enable_utf8()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        limit = float(argv[1]) if len(argv) > 1 else MODULE_LIMIT
    except ValueError:
        print(f"Потолок времени задан не числом: {argv[1]!r}", flush=True)
        return 2
    modules = _modules(root)
    print(f"Набор тестов: {len(modules)} модулей, потолок на модуль — "
          f"{limit:.0f} с.", flush=True)
    failed: List[str] = []
    for name in modules:
        print(f"===== {name} =====", flush=True)
        if run_module(root, name, limit):
            failed.append(name)
    print("", flush=True)
    if failed:
        print("Модули с ошибками: " + ", ".join(failed), flush=True)
        return 1
    print("Все модули прошли.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
