"""Распаковка установщика БЕЗ запуска — последний шанс после падения.

Зачем это нужно сборщику
------------------------
Inno Setup, NSIS и большинство «самораспаковывающихся» установщиков — это
упакованные контейнеры. Их содержимое можно достать сторонним
распаковщиком, **не выполняя код установщика**. Когда Portablizer упирается в
падение (``0xC000041D`` и родственные коды) или в установщик, который ни на
один ключ тишины не отвечает, запуск уже не помогает — а распаковка
помогает: системе это ничего не делает, прав администратора не требует,
реестр не трогает.

Что здесь есть
--------------
* :func:`find_unpacker` — поиск уже установленного распаковщика (7-Zip). Свой
  бинарник Portablizer с собой не носит и в сеть за ним не ходит: сборка не
  должна молча скачивать исполняемые файлы. Не нашлось — об этом честно
  говорится в подсказках, и остаются обычные способы.
* :func:`unpacker_argv` — команда распаковки в папку.
* :func:`promote_payload` — раскладка распакованного по папке ``App``: Inno
  держит файлы программы под ``{app}``, а рядом лежат ``{tmp}``, ``{sys}``,
  ``{userappdata}`` и прочие места, которые в портатив переносить нельзя.
* :func:`unpack_installer` — всё вместе, с подменяемым запуском процесса: в
  тестах распаковщик не нужен, достаточно функции-двойника.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Callable, List, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform.startswith("win")

#: Имена исполняемых файлов распаковщика: полный 7-Zip, автономный ``7za`` и
#: уменьшенный ``7zr`` (последний Inno Setup не понимает, но архивы и NSIS —
#: вполне).
UNPACKER_NAMES = ("7z.exe", "7za.exe", "7zr.exe")

#: Переменные окружения, в которых ищем каталог установки 7-Zip.
UNPACKER_ENV_VARS = ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)")

#: Куда кладёт файлы сам 7-Zip внутри установки Windows.
UNPACKER_SUBDIRS = ("7-Zip", "7-Zip-Zstandard")

#: Имя «корня», куда Inno Setup складывает файлы программы. Именно его
#: содержимое становится содержимым ``App``; остальные корни в фигурных
#: скобках — либо временные данные установщика (``{tmp}``), либо системные
#: каталоги (``{sys}``, ``{win}``, ``{userappdata}``), которые в портатив не
#: переносятся.
APP_ROOT_NAMES = ("{app}",)

RunResult = Tuple[int, str]
Runner = Callable[[Sequence[str], Optional[float]], RunResult]


def find_unpacker(env: Optional[dict] = None,
                  which: Callable[[str], Optional[str]] = shutil.which,
                  isfile: Callable[[str], bool] = os.path.isfile) -> str:
    """Путь к установленному распаковщику или пустая строка.

    Сначала смотрим стандартные каталоги 7-Zip (там бинарник лежит рядом с
    библиотеками, которые ему нужны), затем — ``PATH``: 7-Zip часто ставят
    «портативно», распаковав в произвольную папку и добавив её в PATH.
    """
    environment = os.environ if env is None else env
    candidates: List[str] = []
    for variable in UNPACKER_ENV_VARS:
        root = environment.get(variable, "")
        if not root:
            continue
        for subdir in UNPACKER_SUBDIRS:
            for name in UNPACKER_NAMES:
                candidates.append(os.path.join(root, subdir, name))
    for name in UNPACKER_NAMES:
        found = which(name)
        if found:
            candidates.append(found)
    for path in candidates:
        try:
            if isfile(path):
                return path
        except OSError:
            continue
    return ""


def unpacker_argv(unpacker: str, installer: str, work_dir: str) -> List[str]:
    """Команда распаковки: ``7z x -y -o<папка> -- <установщик>``.

    ``-bso0 -bsp0`` убирает служебный вывод 7-Zip (он всё равно попадает в
    журнал), ``--`` закрывает разбор ключей: имя установщика может начинаться
    с дефиса.
    """
    return [unpacker, "x", "-y", "-bso0", "-bsp0", f"-o{work_dir}", "--",
            installer]


def _default_runner(cmd: Sequence[str],
                    timeout: Optional[float]) -> RunResult:
    kwargs: dict = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        # stdin закрыт: 7-Zip умеет спрашивать пароль, а ждать ввода в
        # автоматической сборке нельзя — лучше честная ошибка распаковки.
        proc = subprocess.run(list(cmd), stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=timeout,
                              **kwargs)
    except subprocess.TimeoutExpired:
        return -1, "распаковка не завершилась за отведённое время"
    except OSError as exc:
        return -1, str(exc)
    text = (proc.stdout or b"").decode("utf-8", "replace")
    return int(proc.returncode or 0), text


def _copy_into(source_dir: str, destination: str) -> int:
    """Сливает содержимое каталога с ``App``; возвращает число файлов."""
    copied = 0
    for current, _dirs, files in os.walk(source_dir):
        relative = os.path.relpath(current, source_dir)
        target_dir = destination if relative == "." else os.path.join(
            destination, relative)
        os.makedirs(target_dir, exist_ok=True)
        for name in files:
            source = os.path.join(current, name)
            target = os.path.join(target_dir, name)
            try:
                if os.path.exists(target):
                    os.chmod(target, 0o666)
            except OSError:
                pass
            shutil.copy2(source, target)
            copied += 1
    return copied


def promote_payload(work_dir: str, destination: str,
                    installer_path: str = "") -> int:
    """Переносит распакованное содержимое в ``App``.

    Inno Setup раскладывает файлы по «корням» в фигурных скобках: ``{app}`` —
    файлы программы, ``{tmp}`` — его временные данные, ``{sys}``/``{win}`` —
    системные каталоги. В портатив едет только ``{app}`` и то, что лежит в
    архиве без обёртки (так выглядят NSIS-сборки и простые SFX). Прочие
    корни пропускаются: ``{sys}`` в портативе — это подмена системных файлов
    чужого ПК, а не портативность.

    Возвращает число перенесённых файлов.
    """
    if not os.path.isdir(work_dir) or not os.path.isdir(destination):
        return 0
    own_name = os.path.basename(installer_path).casefold() if installer_path \
        else ""
    copied = 0
    with os.scandir(work_dir) as scanned:
        entries = sorted(scanned, key=lambda e: e.name.casefold())
    for entry in entries:
        name = entry.name
        folded = name.casefold()
        try:
            is_dir = entry.is_dir()
        except OSError:
            continue
        if folded.startswith("{"):
            # Inno Setup: {app} — файлы программы, остальное (например,
            # {tmp} и {sys}) в портатив не переносится.
            if folded in APP_ROOT_NAMES and is_dir:
                copied += _copy_into(entry.path, destination)
            continue
        if is_dir:
            # NSIS и простые SFX раскладывают содержимое обычными папками:
            # им место в App, иначе программа приедет без своих данных.
            copied += _copy_into(entry.path, os.path.join(destination, name))
            continue
        if folded == own_name:
            continue
        try:
            shutil.copy2(entry.path, os.path.join(destination, name))
        except OSError:
            continue
        copied += 1
    return copied


def unpack_installer(unpacker: str, installer: str, destination: str,
                     work_dir: str, runner: Optional[Runner] = None,
                     timeout: Optional[float] = None,
                     installer_path: str = "") -> Tuple[bool, str]:
    """Распаковывает установщик в ``destination``. Возвращает ``(успех, текст)``.

    Текст во втором элементе — причина неудачи словами (её видно в журнале и
    в итоговых подсказках), а не стек вызовов.
    """
    if not unpacker:
        return False, "распаковщик не найден"
    if not os.path.isfile(installer):
        return False, "файл установщика недоступен"
    try:
        os.makedirs(work_dir, exist_ok=True)
    except OSError as exc:
        return False, f"не удалось создать рабочую папку: {exc}"

    run = runner or _default_runner
    cmd = unpacker_argv(unpacker, installer, work_dir)
    try:
        code, output = run(cmd, timeout)
    except Exception as exc:  # noqa: BLE001 - распаковка не должна ронять сборку
        return False, f"распаковщик не запустился: {exc}"
    tail = " ".join((output or "").split())[-300:]
    # Код 1 у 7-Zip означает предупреждение (часть файлов не распакована), а
    # не отказ: то, что достали, всё равно нужно проверить.
    if code not in (0, 1):
        return False, (f"{os.path.basename(unpacker)} завершился с кодом {code}"
                       + (f": {tail}" if tail else ""))

    copied = promote_payload(work_dir, destination,
                             installer_path=installer_path or installer)
    if copied == 0:
        return False, ("внутри установщика не нашлось файлов программы "
                       "(это может быть упаковка, которую 7-Zip не читает)")
    return True, f"перенесено файлов: {copied}"
