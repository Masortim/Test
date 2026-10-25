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
* :func:`find_extractors` — поиск распаковщиков, которые уже есть на машине.
  Свой бинарник Portablizer с собой не носит и в сеть за ним не ходит: сборка
  не должна молча скачивать исполняемые файлы. Годится не только 7-Zip:
  подойдёт WinRAR (``UnRAR.exe``/``Rar.exe``), а на Windows 10 и новее —
  **встроенный ``tar.exe``**: это bsdtar из libarchive, он читает ZIP, 7z и
  RAR/RAR5. Именно поэтому отсутствие 7-Zip больше не тупик.
* :func:`find_unpacker` — тот же поиск, но только для 7-Zip (совместимость).
* :func:`unpacker_argv` / :func:`extractor_argv` — команда распаковки в папку.
* :func:`carve_archive` — вырезает архив (RAR/RAR5/7z) из самораспаковывающегося
  EXE: сторонние распаковщики читают сам архив, а не PE-обёртку перед ним.
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
from dataclasses import dataclass
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


#: Стили командной строки. Синтаксис у распаковщиков разный, поэтому одна
#: «универсальная» команда здесь не работает.
STYLE_7ZIP = "7zip"
STYLE_RAR = "rar"
STYLE_TAR = "tar"

#: WinRAR и его консольные части. ``WinRAR.exe`` — оконная программа, она
#: возвращает управление до конца распаковки, поэтому её не берём.
RAR_NAMES = ("UnRAR.exe", "Rar.exe", "unrar", "rar")

#: Каталоги, куда WinRAR ставится по умолчанию.
RAR_SUBDIRS = ("WinRAR", "WinRAR-x64")

#: Встроенный в Windows архиватор: с Windows 10 (1803) это bsdtar из
#: libarchive — читает ZIP, 7z и RAR/RAR5. Ничего доустанавливать не нужно, а
#: значит отсутствие 7-Zip больше не мешает достать содержимое установщика.
TAR_NAMES = ("tar.exe", "tar")


@dataclass(frozen=True)
class Extractor:
    """Найденный распаковщик: стиль командной строки и путь к бинарнику."""

    style: str
    path: str

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    def __str__(self) -> str:  # для журнала
        return self.name


def _first_existing(candidates: Sequence[str],
                    isfile: Callable[[str], bool]) -> str:
    for path in candidates:
        try:
            if isfile(path):
                return path
        except OSError:
            continue
    return ""


def find_extractors(env: Optional[dict] = None,
                    which: Callable[[str], Optional[str]] = shutil.which,
                    isfile: Callable[[str], bool] = os.path.isfile
                    ) -> List[Extractor]:
    """Все распаковщики, которыми можно прочитать контейнер установщика.

    Порядок — по удобству и точности: сначала 7-Zip (он лучше всех разбирает
    самораспаковывающиеся EXE и понимает больше форматов), затем WinRAR
    (консольные ``UnRAR``/``Rar``), в конце — встроенный в Windows ``tar.exe``
    (bsdtar). Отсутствие любого из них — не ошибка: важен хотя бы один.
    """
    environment = os.environ if env is None else env
    found: List[Extractor] = []

    seven_zip: List[str] = []
    for variable in UNPACKER_ENV_VARS:
        root = environment.get(variable, "")
        if not root:
            continue
        for subdir in UNPACKER_SUBDIRS:
            for name in UNPACKER_NAMES:
                seven_zip.append(os.path.join(root, subdir, name))
    for name in UNPACKER_NAMES:
        located = which(name)
        if located:
            seven_zip.append(located)
    seven = _first_existing(seven_zip, isfile)
    if seven:
        found.append(Extractor(STYLE_7ZIP, seven))

    rar: List[str] = []
    for variable in UNPACKER_ENV_VARS:
        root = environment.get(variable, "")
        if not root:
            continue
        for subdir in RAR_SUBDIRS:
            for name in RAR_NAMES:
                rar.append(os.path.join(root, subdir, name))
    for name in RAR_NAMES:
        located = which(name)
        if located:
            rar.append(located)
    unrar = _first_existing(rar, isfile)
    if unrar:
        found.append(Extractor(STYLE_RAR, unrar))

    tar: List[str] = []
    system_root = environment.get("SystemRoot") or environment.get("windir")
    if system_root:
        tar.append(os.path.join(system_root, "System32", "tar.exe"))
    located_tar = which("tar")
    if located_tar:
        tar.append(located_tar)
    tar_exe = _first_existing(tar, isfile)
    if tar_exe and all(item.path != tar_exe for item in found):
        found.append(Extractor(STYLE_TAR, tar_exe))
    return found


def find_unpacker(env: Optional[dict] = None,
                  which: Callable[[str], Optional[str]] = shutil.which,
                  isfile: Callable[[str], bool] = os.path.isfile) -> str:
    """Путь к установленному 7-Zip или пустая строка.

    Оставлено для тех мест, где нужен именно 7-Zip (у него самый точный разбор
    самораспаковывающихся EXE). Общий поиск — :func:`find_extractors`.
    """
    extractors = find_extractors(env=env, which=which, isfile=isfile)
    return next((item.path for item in extractors if item.style == STYLE_7ZIP),
                "")


def extractor_argv(extractor: Extractor, archive: str,
                   work_dir: str) -> List[str]:
    """Команда распаковки ``archive`` в ``work_dir`` для этого распаковщика."""
    if extractor.style == STYLE_7ZIP:
        return unpacker_argv(extractor.path, archive, work_dir)
    if extractor.style == STYLE_RAR:
        # -o+ перезаписывает без вопросов, -idq убирает служебный вывод,
        # завершающий разделитель обязателен: иначе UnRAR им не считает.
        return [extractor.path, "x", "-y", "-o+", "-idq", archive,
                work_dir + os.sep]
    if extractor.style == STYLE_TAR:
        # bsdtar сам определяет формат (ZIP, 7z, RAR/RAR5, CAB).
        return [extractor.path, "-x", "-f", archive, "-C", work_dir]
    raise ValueError(f"неизвестный распаковщик: {extractor.style}")


#: Подписи архивов, вокруг которых может быть приклеена PE-обёртка SFX.
#: RAR5 идёт раньше RAR4: у него более длинная подпись, иначе RAR4 «съел» бы
#: первые байты RAR5.
_ARCHIVE_SIGNATURES: Tuple[Tuple[bytes, str], ...] = (
    (b"Rar!\x1a\x07\x01\x00", "rar5"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
)

#: Размер порции при поиске подписи: файлы установщиков большие, поэтому
#: читаем кусками, а не целиком в память.
_CARVE_CHUNK = 1024 * 1024


def archive_kind(path: str) -> str:
    """Тип архива по первым байтам файла (``rar``/``rar5``/``7z``/``zip``)."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return ""
    for signature, kind in _ARCHIVE_SIGNATURES:
        if head.startswith(signature):
            return kind
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    return ""


def carve_archive(installer: str, destination_dir: str,
                  limit: Optional[int] = None) -> Tuple[str, str]:
    """Вырезает архив, приклеенный к EXE, и возвращает ``(путь, тип)``.

    Самораспаковывающийся архив — это PE-загрузчик, к которому просто
    дописан архив. 7-Zip находит его сам, а libarchive и UnRAR читают **файл
    архива**, а не EXE: поэтому обёртку нужно отрезать. Копия пишется рядом с
    папкой распаковки — исходный установщик при этом не меняется.

    Если архив лежит в файле с самого начала (обычный ``.rar``/``.7z``),
    возвращается он сам, а копия не делается. Пустая строка в первом
    элементе — подписи не нашлось (например, это ZIP: ``zipfile`` читает EXE
    с приклеенным ZIP сам, вырезать ничего не нужно).
    """
    kind = archive_kind(installer)
    if kind in ("rar", "rar5", "7z"):
        return installer, kind
    if kind == "zip" or not os.path.isfile(installer):
        return "", ""
    try:
        size = os.path.getsize(installer)
    except OSError:
        return "", ""
    if limit is not None and size > limit:
        return "", ""
    signature_end = max(len(sig) for sig, _ in _ARCHIVE_SIGNATURES)
    offset = -1
    found_kind = ""
    try:
        with open(installer, "rb") as handle:
            position = 0
            tail = b""
            while True:
                chunk = handle.read(_CARVE_CHUNK)
                if not chunk:
                    break
                window = tail + chunk
                for signature, candidate in _ARCHIVE_SIGNATURES:
                    index = window.find(signature)
                    if index >= 0:
                        offset = position - len(tail) + index
                        found_kind = candidate
                        break
                if offset >= 0:
                    break
                position += len(chunk)
                tail = window[-signature_end:]
    except OSError:
        return "", ""
    if offset < 0:
        return "", ""

    suffix = ".rar" if found_kind.startswith("rar") else ".7z"
    target = os.path.join(destination_dir,
                          os.path.basename(installer) + suffix)
    try:
        os.makedirs(destination_dir, exist_ok=True)
        with open(installer, "rb") as source, open(target, "wb") as sink:
            source.seek(offset)
            shutil.copyfileobj(source, sink, _CARVE_CHUNK * 8)
    except OSError:
        return "", ""
    return target, found_kind


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
