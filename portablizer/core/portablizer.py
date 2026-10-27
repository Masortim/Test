"""Оркестратор процесса создания портативного приложения.

Порядок работы:
  1. detect          — определить движок установщика (и поколение, если это
                       InstallShield: у InstallScript 5/6 и обёртки над MSI
                       несовместимые командные строки).
  1b. response       — подготовить файл ответов setup.iss, если он нужен:
                       скопировать с диска в портатив и подменить в нём путь
                       установки на папку App.
  2. plan            — построить ЛЕСТНИЦУ команд тихой установки (несколько
                       вариантов от самого точного к самому общему).
  3. snapshot(before)— снять состояние реестра (Windows).
  4. install         — выполнять попытки по очереди, пока не появится
                       запускаемый клиент в App или известном профиле.
                       Долгая установка при этом не прерывается: предел
                       ожидания относится к паузе в
                       работе установщика, а не ко времени установки (см.
                       _InstallWatchdog).
  5. snapshot(after) — снять состояние реестра и сохранить diff в portable.reg.
  6. detect_main_exe — найти главный exe установленной программы.
  7. gather_deps     — эвристически собрать/скопировать зависимости (VC++ и т.п.).
  8. launcher        — сгенерировать Launch.bat / launcher_config.json и
                       скопировать готовый App/LaunchPortable.exe.

Почему именно лестница попыток
------------------------------
Один «правильный» набор ключей существует далеко не всегда. Установщик может
не знать переданную переменную целевой папки, требовать явного принятия
лицензии или вовсе использовать собственный синтаксис. Раньше Portablizer
делал одну попытку (плюс два жёстко зашитых сценария для WiX Burn) и сдавался,
сообщая лишь код возврата. Теперь варианты перебираются по порядку, а после
каждого проверяется фактический результат — файлы в ``App``.

Класс спроектирован так, чтобы работать в отдельном потоке GUI: он принимает
``Logger`` и функцию ``progress(percent, stage)`` и не трогает Qt напрямую.
Отмена реализована через флаг ``cancel_event``.
"""
from __future__ import annotations

import configparser
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .. import __version__
from . import adobe as adobe_mod
from . import crashinfo as crash_mod
from . import elevate as elevate_mod
from . import launcher as launcher_mod
from . import netstack as netstack_mod
from . import procutil
from . import redist as redist_mod
from . import registry as reg_mod
from . import relpaths as relpaths_mod
from . import saves as saves_mod
from . import shortcuts as shortcuts_mod
from . import space as space_mod
from . import unpacker as unpacker_mod
from .detect import (
    DetectionResult, InstallerType, RepackProfile, detect_installer, read_pe_info,
)
from .logutil import Logger
from .languages import find_language, plan_language
from .silentargs import (
    SilentPlan, build_attempts, build_progress_window_attempt,
    build_silent_plan, repeat_attempt,
)

ProgressCB = Callable[[int, str], None]
#: Ход текущей операции: ``(процент или -1, подпись)``. ``-1`` означает, что
#: величину заранее узнать нельзя (сервер не сообщил размер файла и т. п.) —
#: интерфейс показывает «бегущую» полосу вместо замершего числа.
DetailCB = Callable[[int, str], None]
#: Вопрос к человеку, когда установка замолчала: ждать ещё или прекращать.
#: Возвращает :data:`STALL_WAIT`, :data:`STALL_STOP` или :data:`STALL_CANCEL`.
StallCB = Callable[["InstallStall"], str]

#: Вердикты на доклад о затишье в установке.
STALL_WAIT = "wait"        # «установщик всё ещё может работать — ждём ещё»
STALL_STOP = "stop"        # «хватит ждать»: снять установщик и идти дальше
STALL_CANCEL = "cancel"    # «отменить всю сборку»

IS_WINDOWS = sys.platform.startswith("win")

#: Сколько терпеть установку БЕЗ ПРИЗНАКОВ РАБОТЫ (секунды).
#:
#: Это не предел времени установки: пока установщик пишет файлы, читает диск,
#: тратит процессор или дописывает свой журнал, ждать можно сколько угодно.
#: Предел относится к ПАУЗЕ. Раньше здесь был общий потолок на попытку в
#: 30 минут: BioShock Infinite (десятки гигабайт, сотни тысяч файлов) ставится
#: дольше, и сборка обрывалась с «Превышено время ожидания установки», хотя
#: установщик в этот момент исправно работал.
INSTALL_IDLE_LIMIT = 900

#: Абсолютный потолок на одну попытку (секунды). Ноль — без потолка.
#: Нужен только как страховка от бесконечно долгой работы: обычные установки до
#: него не доживают, а зависшая распознаётся по паузе (см. выше) гораздо раньше.
INSTALL_HARD_LIMIT = 6 * 3600

#: Как часто опрашивать признаки работы (секунды). Дешёвые счётчики процессов
#: опрашиваются с этой частотой, обход целевой папки — реже (см. ниже).
INSTALL_PROBE_SECONDS = 5.0

#: Как часто пересчитывать размер и число файлов в целевой папке: обход сотен
#: тысяч файлов заметно дороже опроса счётчиков, а для вывода «работа идёт или
#: нет» такая точность не нужна.
INSTALL_DIR_SCAN_SECONDS = 20.0

#: Меньше этого предел ожидания не ставится, даже если его задали крошечным:
#: вопрос «ждать ещё?» не должен всплывать каждые несколько секунд. Тесты и
#: внешние сценарии переопределяют это значение, а не обходят его.
INSTALL_IDLE_FLOOR = 30.0

#: Сколько ждать мастер установщика, который показывает страницы и ждёт
#: нажатий. Обычный предел паузы (15 минут) рассчитан на распаковку: там
#: молчание процесса ещё может означать «пишет большие файлы». Мастер же
#: стоит ровно потому, что ему не нажали «Далее», и держать сборку четверть
#: часа — это и есть «зависло на 38 %». Поэтому, как только на экране
#: распознана страница выбора языка/папки и признаков работы нет, попытка
#: заканчивается через минуту-полторы, а не через INSTALL_IDLE_LIMIT.
INSTALL_GUI_PROMPT_LIMIT = 90.0

#: Сколько ждать установщик, который не сделал НИЧЕГО с самого запуска
#: (секунды). Обычный предел паузы (15 минут) рассчитан на честную работу:
#: там установщик уже распаковал гигабайты и просто задумался. Здесь другое —
#: ни прочитанного байта, ни созданного файла, ни процессорного времени.
#: Тяжёлый дистрибутив так себя не ведёт: он читает свой архив, и это видно в
#: счётчиках ввода-вывода. Значит, процесс стоит на внешнем препятствии
#: (запрос UAC, модальное окно обёртки-SFX, антивирус, неподходящий ключ), и
#: ждать четверть часа бессмысленно: сборка простоит час и не сдвинется.
#: Поэтому «мёртвый старт» распознаётся за пять минут, попытка снимается без
#: вопроса человеку, а сборка честно переходит к следующему сценарию — в
#: частности, к распаковке контейнера без запуска его кода.
INSTALL_DEAD_START_LIMIT = 300.0

#: Сколько сценариев подряд могут закончиться «мёртвым стартом», прежде чем
#: перебор ключей станет бессмысленным. Две попытки подряд, в которых
#: установщик не прочитал ни байта, означают, что ключи до него не доходят:
#: дальше сборка идёт к распаковке содержимого без запуска, а не сжигает по
#: пять минут на каждый из оставшихся вариантов.
DEAD_START_ATTEMPTS_LIMIT = 2

#: Короткие быстрые «успехи» без payload обычно означают, что команда
#: проигнорирована либо перед нами web-downloader. Двух подряд достаточно,
#: чтобы не запускать остальные случайные ключи (и не менять систему лишний раз).
HOLLOW_ATTEMPTS_LIMIT = 2
HOLLOW_ATTEMPT_MAX_SECONDS = 15.0

# Имя готового EXE-лончера внутри App/. Сам бинарник собирается из
# portable_launcher_entry.py, встраивается в Portablizer.exe как ресурс и не
# требует Python на компьютере, где запускают готовый портатив.
#
# Имя ``LaunchPortable.exe`` остаётся: его ищут Launch.bat, LaunchHidden.vbs,
# StopPortable.cmd и UpdatePortable.cmd. Но в Диспетчере задач оно ничего не
# говорило о запущенной программе, поэтому рядом создаётся та же самая копия
# с именем ``Launch <Имя программы>.exe`` (см. ``_task_manager_name``).
APP_EXE_LAUNCHER_NAME = "LaunchPortable.exe"


def bundled_exe_launcher_path() -> str:
    """Путь к шаблону LaunchPortable.exe в исходниках или PyInstaller EXE."""
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return os.path.join(frozen_root, "resources", "portable_launcher.exe")
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(package_root, "resources", "portable_launcher.exe")


# -- коды возврата установщиков ---------------------------------------------
#: Типовые коды возврата и их расшифровка (для журнала и итоговой ошибки).
_EXIT_CODE_HINTS: Dict[int, str] = {
    2: "файл не найден",
    5: "отказано в доступе (нужны права администратора)",
    # WAIT_TIMEOUT: наша собственная метка «установщик перестал подавать
    # признаки работы и был снят», а не код, который вернул сам движок.
    0x102: "установщик молчал дольше отведённого времени и был снят вместе "
           "с дочерними процессами — смотрите предел ожидания установки",
    1223: "пользователь отменил операцию (например, отклонил UAC-запрос)",
    740: "запрашиваются права администратора — запустите Portablizer от "
         "имени администратора",
    1603: "фатальная ошибка установки",
    1618: "другая установка уже выполняется",
    1625: "установка запрещена системной политикой",
    1638: "уже установлена другая версия пакета",
    14001: "параллельная конфигурация неправильна (side-by-side): программа "
           "собрана с Visual C++ 2005/2008, а этого рантайма на ПК нет — "
           "запустите Redist\\Install-Redist.cmd из портативной папки",
    # Коды установщиков Adobe HyperDrive. 191 — это не «непонятая
    # командная строка»: упал шаг установки UWP-пакета (Appx). Разбор и
    # обход — в core/adobe.py.
    **adobe_mod.ADOBE_CODES,
}

_NEGATIVE_EXIT_HINT = (
    "процесс установщика аварийно завершился: как правило, не хватило прав "
    "администратора или тихий режим не поддерживается"
)

# -- аварийное завершение процесса --------------------------------------------
#
# Отрицательный код возврата — это не всегда «мало прав». Коды вида 0xC0000…
# (NTSTATUS) означают, что процесс УПАЛ: он стартовал, начал работу и был
# оборван исключением. Пользователю нужен именно такой диагноз: он ведёт к
# месту в TEMP, целостности дистрибутива и стороннему коду в процессе, а не к
# повышению прав, которое в этом случае ничего не меняет.
# Расшифровка кодов и факты о падении — в core/crashinfo.py.

#: Столько живёт папка TEMP установщика ВНЕ портатива, если его пришлось
#: перенести на другой диск: папка удаляется сразу после сборки, но если
#: сборку снимут аварийно (питание, диспетчер задач), на диске останется
#: каталог с известным именем — его видно и можно удалить руками.
EXTERNAL_TEMP_PREFIX = "Portablizer-"

#: Сколько места нужно установщику в TEMP относительно веса дистрибутива.
#: Офлайн-установщики GOG распаковывают данные целиком во временную папку и
#: только потом переносят их в целевую, то есть на диске одновременно живут
#: дистрибутив, распакованная копия и результат.
TEMP_NEED_FACTOR = 2.0

#: Масштаб плавного прогресса установщика (секунды). Установщик не сообщает
#: своих процентов, а большая игра ставится минутами. Прежняя линейная шкала
#: «доля = время / 60 с» насыщалась на первой минуте, и полоса замирала на
#: верхней границе этапа (58 %) до конца установки. Кривая ``1 - exp(-t/T)``
#: растёт всё время работы и никогда не достигает конца отрезка, поэтому
#: полоса видимо движется, а следующий этап наступает только по факту.
INSTALL_PROGRESS_SCALE = 600.0


def creep_fraction(elapsed: float, scale: float = INSTALL_PROGRESS_SCALE) -> float:
    """Доля 0..1 для плавной полосы по времени работы (никогда не 1.0)."""
    value = 1.0 - math.exp(-max(0.0, float(elapsed)) / max(1.0, float(scale)))
    # В float при очень долгой работе exp() даёт 1.0 — ограничиваем, чтобы
    # int(span * доля) никогда не дотягивал до конца отрезка.
    return min(value, 0.999)

#: Потолок на распаковку установщика без запуска (секунды). Даже если потолок
#: установки снят (``install_deadline = 0``), распаковка не может идти вечно:
#: 7-Zip на зашифрованном контейнере способен ждать ввод, а сборка — нет.
UNPACK_HARD_LIMIT = 1800.0

#: Падение через считанные секунды после старта и до записи файлов — обычно
#: разовая помеха (антивирус проверял бинарник, не хватило памяти в момент
#: распаковки). Такую попытку повторяют один раз, но только если она была
#: короткой: повторять падение, случившееся после часа работы, бессмысленно.
CRASH_RETRY_MAX_SECONDS = 240.0

#: Установщики, содержимое которых умеет доставать сторонний распаковщик
#: (Inno Setup, NSIS и самораспаковывающиеся архивы). У MSI, InstallShield и
#: остальных движков своя упаковка — для них распаковка без запуска не
#: предлагается.
UNPACKABLE_TYPES = (
    InstallerType.INNO, InstallerType.NSIS, InstallerType.SELF_EXTRACT,
    InstallerType.UNKNOWN,
)

#: Код -1 от bootstrapper'а почти всегда означает «не разобрал командную
#: строку»: неизвестный ключ, отсутствие обязательного (например, принятия
#: лицензии) или запрет на запуск без UAC.
_BAD_COMMAND_LINE_CODES = frozenset({0xFFFFFFFF, 0x80070057, 1639, 87})


def is_elevated() -> bool:
    """True, если Portablizer запущен с правами администратора.

    Знать это нужно заранее: установщик с ``requireAdministrator`` в манифесте
    без повышения прав просто не стартует, и пользователю надо сказать об этом
    прямо, а не показывать код ``-1``.
    """
    if not IS_WINDOWS:
        return False
    try:
        import ctypes  # локальный импорт: модуль должен грузиться и на Linux

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def _format_exit_code(rc: Optional[int]) -> str:
    """Код возврата установщика в человекочитаемом виде.

    Windows-процесс может вернуть код как беззнаковое 32-битное число:
    «4294967295» в журнале — это на самом деле ``-1`` (``0xFFFFFFFF``).
    """
    if rc is None:
        return "неизвестен"
    if rc > 0x7FFFFFFF:
        return f"{rc} ({rc - (1 << 32)}, 0x{rc:08X})"
    return str(rc)


def _exit_code_hint(rc: Optional[int],
                    installer_type: Optional[InstallerType] = None) -> str:
    """Расшифровка кода возврата для журнала и итогового сообщения.

    Сначала проверяются коды аварийного завершения процесса: у них своя
    расшифровка (NTSTATUS), и подменять её общей фразой про права
    администратора нельзя — она уводит в сторону от настоящей причины.
    Затем — коды самого движка: у Inno Setup они свои и с Win32 не совпадают.
    """
    if rc is None:
        return ""
    crash = crash_mod.crash_code(rc)
    if crash is not None:
        return crash.hint
    if rc > 0x7FFFFFFF:
        return _NEGATIVE_EXIT_HINT
    if installer_type == InstallerType.INNO:
        return {
            1: "не удалось инициализировать установщик",
            2: "установка отменена до начала или пользователь отказался от продолжения",
            3: "фатальная ошибка подготовки к следующему этапу установки",
            4: "фатальная ошибка во время установки",
            5: "установка отменена до начала установки файлов",
            6: "установка отменена во время установки файлов",
            7: "подготовка к установке завершилась неудачно; причина — в install.log",
            8: "для завершения подготовки требуется перезагрузка компьютера",
        }.get(rc, _EXIT_CODE_HINTS.get(rc, ""))
    return _EXIT_CODE_HINTS.get(rc, "")


# -- InstallShield InstallScript ---------------------------------------------
#: Расшифровка [ResponseResult]/ResultCode из setup.log классического
#: InstallShield. Без неё «код 0 и пустая папка» выглядит необъяснимо, хотя
#: движок честно записал причину отказа в свой журнал.
_INSTALLSHIELD_RESULT_HINTS: Dict[int, str] = {
    0: "установка прошла успешно",
    -1: "общая ошибка установки",
    -2: "режим установки не поддерживается",
    -3: "в файле ответов setup.iss нет нужных данных (или файла ответов нет)",
    -4: "не хватило памяти",
    -5: "файл ответов не найден",
    -6: "не удалось записать файл ответов",
    -7: "не удалось записать журнал (носитель только для чтения?)",
    -8: "неверный путь к файлу ответов setup.iss",
    -9: "недопустимый тип списка в файле ответов",
    -10: "недопустимый тип данных в файле ответов",
    -11: "неизвестная ошибка установщика",
    -12: "диалоги в файле ответов не совпадают с диалогами этого установщика",
    -51: "не удалось создать указанную папку",
    -52: "нет доступа к указанному файлу или папке",
    -53: "в файле ответов выбран недопустимый вариант",
}

#: Ключи файла ответов, в которых лежит путь установки. ``szFolder`` намеренно
#: не трогаем: это имя группы в меню «Пуск», а не каталог.
_ISS_TARGET_KEYS = ("szdir", "sztargetdir", "szdestpath", "szinstalldir")


def read_installshield_result(log_path: str) -> Optional[int]:
    """Читает ResultCode из setup.log, созданного InstallShield."""
    if not log_path:
        return None
    try:
        with open(log_path, "rb") as fh:
            raw = fh.read(64 * 1024)
    except OSError:
        return None
    text = _decode_installer_text(raw)
    match = re.search(r"^\s*ResultCode\s*=\s*(-?\d+)", text,
                      re.IGNORECASE | re.MULTILINE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _decode_installer_text(raw: bytes) -> str:
    """Декодирует ini-подобный файл установщика (ANSI/UTF-8/UTF-16)."""
    if raw.startswith(b"\xff\xfe") or (len(raw) > 1 and raw[1:2] == b"\x00"):
        return raw.decode("utf-16-le", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1251", "replace")


def _encode_installer_text(text: str, sample: bytes) -> bytes:
    """Кодирует текст обратно в том же виде, в каком файл был прочитан."""
    if sample.startswith(b"\xff\xfe") or (len(sample) > 1
                                          and sample[1:2] == b"\x00"):
        prefix = b"\xff\xfe" if sample.startswith(b"\xff\xfe") else b""
        body = text[1:] if text.startswith("\ufeff") else text
        return prefix + body.encode("utf-16-le", "replace")
    try:
        return text.encode("cp1251")
    except UnicodeEncodeError:
        return text.encode("utf-8")


def _text_tail(path: str, limit: int = 2000) -> str:
    """Последние байты текстового журнала — для сообщения об ошибке."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > limit:
                fh.seek(size - limit)
            return fh.read(limit).decode("utf-8", "replace").strip()
    except OSError:
        return ""


def retarget_response_file(text: str, target_dir: str) -> Tuple[str, int]:
    """Подменяет путь установки в файле ответов InstallShield.

    Файл ответов — это ini: секция диалога и строки вида
    ``szDir=C:\\Program Files\\Игра``. Командной строкой InstallScript папку
    не принимает, зато уважает путь из файла ответов — так портатив получает
    свои файлы сразу в ``App``, без переноса из Program Files.
    """
    lines = text.splitlines(keepends=True)
    replaced = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith((";", "[")):
            continue
        key, sep, _value = stripped.partition("=")
        if not sep or key.strip().casefold() not in _ISS_TARGET_KEYS:
            continue
        ending = ""
        while line.endswith(("\r", "\n")):
            ending = line[-1] + ending
            line = line[:-1]
        lines[index] = f"{key.strip()}={target_dir}{ending}"
        replaced += 1
    return "".join(lines), replaced


def _burn_layout_payloads(layout_dir: str) -> "Tuple[List[str], List[str]]":
    """Находит в распакованном (/layout) бандле MSI-пакеты и прочие payload'ы.

    Возвращает ``(msis, others)``. MSI сортируются по убыванию размера: главный
    пакет приложения почти всегда крупнейший, мелкие пакеты (redist и пр.)
    распаковываются следом и дополняют портатив зависимостями. Прочие пакеты
    (exe/msu/msp) молча выполнять нельзя — они только перечисляются в отчёте.
    """
    msis: List[str] = []
    others: List[str] = []
    if not os.path.isdir(layout_dir):
        return msis, others
    for current, _dirs, files in os.walk(layout_dir):
        for filename in files:
            path = os.path.join(current, filename)
            if filename.lower().endswith(".msi"):
                msis.append(path)
            elif filename.lower().endswith((".exe", ".msu", ".msp")):
                others.append(path)

    def _size(path: str) -> int:
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    msis.sort(key=_size, reverse=True)
    return msis, others


#: Временные каталоги, которые предыдущие версии оставляли в профиле
#: пользователя (C:\Users\<user>). Они появляются, когда Portablizer
#: аварийно завершается до уборки внешнего TEMP или когда PyInstaller
#: не успевает удалить _MEI*. Очищаются при каждом запуске.
_STALE_TEMP_PATTERNS = (
    EXTERNAL_TEMP_PREFIX, "Portablizer_", "_MEI", "pblz",
)

#: Каталоги-однодневки redist/распаковки: имя начинается с этих префиксов.
_STALE_TEMP_SOON = ("pblz",)

#: Сколько секунд каталог должен «полежать», прежде чем его можно удалять.
#: Свежий каталог может принадлежать идущей установке или другому экземпляру
#: Portablizer, поэтому трогаем только заведомо брошенные.
STALE_TEMP_MIN_AGE = 3600.0


def _stale_temp_roots() -> List[str]:
    """Где искать мусор предыдущих запусков: TEMP и профиль пользователя.

    Именно в ``C:\\Users\\<user>`` пользователь и увидел десятки каталогов:
    старые версии создавали там ``Portablizer-<имя>-Temp`` (внешний TEMP) и
    ``_MEI*`` (распаковка PyInstaller), а убирали только то, что успели
    создать в текущем запуске. Аварийное завершение оставляло их навсегда.
    """
    import tempfile

    roots: List[str] = []
    for value in (os.environ.get("TEMP"), os.environ.get("TMP"),
                  tempfile.gettempdir(), os.environ.get("USERPROFILE")):
        if not value:
            continue
        try:
            folder = os.path.abspath(value)
        except OSError:
            continue
        if os.path.isdir(folder) and folder not in roots:
            roots.append(folder)
    return roots


def _mine_temp_directory(path: str) -> bool:
    """True, если этот каталог принадлежит ТЕКУЩЕМУ процессу.

    Однофайловый PyInstaller-EXE распаковывает себя в ``_MEIxxxx`` при каждом
    запуске. Удалить свой же каталог — значит убить себя посреди работы,
    поэтому он исключается всегда, независимо от времени создания.
    """
    own = str(getattr(sys, "_MEIPASS", "") or "")
    if own and os.path.normcase(os.path.abspath(own)) == os.path.normcase(path):
        return True
    own_exe = os.path.normcase(os.path.abspath(sys.executable or ""))
    try:
        marker = os.path.join(path, "Portablizer.exe")
        if own_exe and os.path.normcase(os.path.abspath(marker)) == own_exe:
            return True
    except OSError:
        pass
    return False


def _cleanup_stale_temp_dirs(log: Optional["Logger"] = None,
                             roots: Optional[Sequence[str]] = None,
                             min_age: float = STALE_TEMP_MIN_AGE,
                             now: Optional[float] = None) -> List[str]:
    """Удаляет брошенные временные каталоги Portablizer из прошлых запусков.

    Возвращает список удалённых путей (он же идёт в журнал сборки). Ничего не
    бросает: уборка мусора не имеет права сорвать сборку портатива.
    """
    current = time.time() if now is None else float(now)
    removed: List[str] = []
    for root in (list(roots) if roots is not None else _stale_temp_roots()):
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            continue
        for name in entries:
            if not any(name.casefold().startswith(prefix.casefold())
                       for prefix in _STALE_TEMP_PATTERNS):
                continue
            path = os.path.join(root, name)
            try:
                if not os.path.isdir(path) or os.path.islink(path):
                    continue
                if _mine_temp_directory(path):
                    continue
                stat = os.stat(path)
            except OSError:
                continue
            limit = min_age
            for prefix in _STALE_TEMP_SOON:
                if name.casefold().startswith(prefix):
                    # Распаковка redist идёт минутами, а не часом.
                    limit = min(limit, 600.0)
            if current - stat.st_mtime < limit:
                continue
            try:
                shutil.rmtree(path, ignore_errors=True)
            except OSError:
                continue
            if os.path.exists(path):
                continue
            removed.append(path)
            if log is not None:
                try:
                    log.debug(f"Удалён брошенный временный каталог: {path}")
                except Exception:  # noqa: BLE001 - лог не должен мешать уборке
                    pass
    return removed


@dataclass
class PortableOptions:
    installer_path: str
    output_dir: str                    # куда положить портативную папку
    app_name: str = ""                 # имя приложения (для папки/лончера)
    redirect_userdirs: bool = True     # изолировать AppData/Temp/...
    capture_registry: bool = True      # захватывать изменения реестра
    # Копировать готовый LaunchPortable.exe в App/. Он запускает программу с
    # теми же переносимыми AppData/реестром, что и Launch.bat, но обычным
    # двойным кликом по EXE и без установленного Python.
    build_exe_launcher: bool = True
    # Удалить запись «Установленные программы», созданную этим же установщиком
    # внутри портатива: портатив не устанавливается, и в списке приложений его
    # быть не должно. Критерий строгий — DisplayName совпадает с приложением, а
    # одно из значений с путём (InstallLocation, DisplayIcon, UninstallString…)
    # ведёт внутрь созданной папки. Чужие записи и общий откат реестра,
    # ярлыков и служб не трогаются.
    cleanup_host: bool = True
    # Переносить ассоциации файлов/COM. По умолчанию выключено: чужому ПК это
    # не нужно, а портативность от этого только страдает.
    include_shell_integration: bool = False
    extra_install_args: List[str] = field(default_factory=list)
    # Язык многоязычного установщика (код из core/languages.py, например
    # «ru»). Пусто — язык по умолчанию, как выбрал бы установщик сам. От языка
    # зависит, какие текстовые файлы, субтитры и шрифты попадут в портатив.
    install_language: str = ""
    extra_env: Dict[str, str] = field(default_factory=dict)
    # Предел ожидания установки. Считается НЕ от запуска, а от последнего
    # признака работы (запись в целевую папку, ввод-вывод и процессорное время
    # дерева процессов установщика, рост журнала установщика). Поэтому долгая
    # установка большой игры не прерывается: 40 ГБ, которые пишутся два часа,
    # — это «идёт работа», а не «зависло». Прерывается только молчание.
    install_timeout: int = INSTALL_IDLE_LIMIT          # сек без работы
    # Абсолютный потолок на одну попытку, сек. 0 — без потолка. Страховка от
    # бесконечной работы (например, установщик зациклился и пишет по кругу).
    install_deadline: int = INSTALL_HARD_LIMIT
    # Разрешить сценарий с видимым окном мастера. Нужен старым InstallShield
    # InstallScript: тихий режим у них работает только по файлу ответов
    # setup.iss, а записать его может лишь человек, прошедший мастер.
    allow_assisted_install: bool = False
    assisted_timeout: int = 3600       # сек: человек за клавиатурой не спешит
    # Приносить в портатив распространяемые компоненты (Visual C++, DirectX и
    # т. п.), чтобы на чужом ПК не возникало «отсутствует MSVCP110.dll».
    bundle_runtimes: bool = True
    # Полный комплект «про запас»: не только то, что нашлось в таблицах
    # импорта, а все известные библиотеки всех версий (VC++ 2005–2022, весь
    # DirectX июня 2010, OpenAL, PhysX…). Закрывает динамические загрузки,
    # плагины и моды: ошибки «отсутствует XINPUT1_3.dll / d3dx9_38.dll» не
    # возникают изначально. Портатив становится заметно больше.
    full_runtimes: bool = True
    # Докачивать недостающие пакеты с сайта Microsoft. По умолчанию выключено:
    # сборка не должна молча ходить в сеть.
    download_runtimes: bool = False
    # Устанавливать распространяемые пакеты (vcredist, DXSETUP, OpenAL,
    # PhysX…) в тихом режиме НА ХОСТЕ. Это изменяет Windows и требует UAC,
    # поэтому выключено по умолчанию; в портатив библиотеки по возможности
    # копируются из установщика/системы, а пакеты ставятся только по согласию.
    silent_runtime_install: bool = False
    # Переносить системные сетевые компоненты (драйверы TAP-Windows/wintun,
    # службы-компаньоны) в папку NetStack портатива. Нужна VPN-клиентам
    # (Planeta VPN и всем, что собрано вокруг OpenVPN): ядро Windows нельзя
    # виртуализовать, поэтому портатив берёт пакеты драйверов с собой и на
    # каждом ПК досоздаёт недостающее сам — один тихий UAC вместо окон
    # «Установить программное обеспечение для данного устройства?».
    netstack_components: bool = True
    #: Изолированный режим NetStack: драйвер публикуется на время сеанса
    #: и снимается с системы при выходе (хост не получает постоянного
    #: следа). Снятие — по умолчанию: «портативный изолированный» важнее
    #: пары секунд на переподключение; shared оставлен как осознанный
    #: выбор для «своего» ПК, где UAC на каждый запуск — лишний шум.
    netstack_isolated: bool = True
    # Сквозные портативные сохранения: одно хранилище сейвов для ВСЕХ
    # способов запуска. Без этого прямой запуск App\Game.exe пишет в
    # настоящий профиль Windows, а LaunchPortable.exe — в PortableData, и
    # сохранения одного способа не видны другому (см. core/saves.py).
    shared_saves: bool = True
    # Держать пути внутри портатива относительными (см. core/relpaths.py):
    # корень запоминается в PortableData\portable-root.json, реестр хранит
    # маркер @@PORTABLE_ROOT@@, а лончер при переносе папки на другой диск
    # сам меняет старый абсолютный путь новым. Выключать стоит только для
    # отладки: без этого перенос ломает настройки программы.
    relative_paths: bool = True


@dataclass
class RegistryCapture:
    """Результат захвата реестра: что переносим и что чистим."""

    diff: "reg_mod.RegistryDiff"
    keys: List[str] = field(default_factory=list)
    created_keys: List[str] = field(default_factory=list)
    reg_file: str = ""
    machine_reg_file: str = ""
    has_root_token: bool = False
    uninstall_entries: List[str] = field(default_factory=list)
    cleanup_file: str = ""
    #: Самоповышающийся .cmd, применяющий cleanup_host.reg с правами админа.
    cleanup_cmd_file: str = ""
    cleanup_keys: List[str] = field(default_factory=list)
    cleanup_entries: List[str] = field(default_factory=list)


@dataclass
class PortableResult:
    success: bool
    portable_dir: str = ""
    main_exe_rel: str = ""
    detection: Optional[DetectionResult] = None
    plan: Optional[SilentPlan] = None
    reg_file: str = ""
    messages: List[str] = field(default_factory=list)
    #: Ключи реестра, которые обслуживает лончер.
    registry_keys: List[str] = field(default_factory=list)
    #: Новые записи установщика, которые увидели в «Установленных программах».
    installed_entries_detected: List[str] = field(default_factory=list)
    #: Записи, убранные из списка «Установленные программы» этого ПК.
    removed_from_installed_list: List[str] = field(default_factory=list)
    #: Осталось ли что-то вычистить вручную (не хватило прав).
    cleanup_pending: bool = False
    #: Сетевые компоненты, перенесённые в NetStack (драйверы и службы).
    netstack_drivers: List[str] = field(default_factory=list)
    netstack_services: List[str] = field(default_factory=list)
    #: Сколько вариантов команды установки было запланировано.
    attempts_planned: int = 0
    #: Сколько вариантов реально выполнено.
    attempts_made: int = 0
    #: Название сработавшего сценария установки.
    successful_attempt: str = ""
    #: История лестницы: (название сценария, код возврата). Кода только
    #: последней попытки для диагностики мало — нужен итог каждой.
    attempt_outcomes: List[Tuple[str, Optional[int]]] = field(
        default_factory=list)
    #: Подсказки пользователю, если установка не удалась.
    hints: List[str] = field(default_factory=list)
    #: Все обнаруженные цели (главный exe, лаунчер, конфигуратор, утилиты)
    targets: List[launcher_mod.TargetInfo] = field(default_factory=list)
    #: Созданные варианты запуска (только launcher/configurator и общее меню).
    companion_launchers: List[str] = field(default_factory=list)
    #: Готовый EXE для запуска портатива двойным кликом из папки App.
    portable_launcher_exe_rel: str = ""
    launcher_exe_rel: str = ""
    config_exe_rel: str = ""
    #: Системные библиотеки (VC++/DirectX…), принесённые в портатив.
    runtime_provided: List[str] = field(default_factory=list)
    #: То, чего принести не удалось: нужен пакет на целевом ПК.
    runtime_missing: List[str] = field(default_factory=list)
    #: Библиотеки, принесённые «про запас» полным комплектом (все версии
    #: VC++ и DirectX) — программа их прямо не требует, но плагины и
    #: динамические загрузки могут попросить.
    runtime_stock: List[str] = field(default_factory=list)
    #: Пакеты, которые придётся установить (человеческие названия + ссылки).
    runtime_packages: List[str] = field(default_factory=list)
    #: Отчёт по распространяемым компонентам внутри портатива.
    runtime_report_rel: str = ""
    #: Пакеты, установленные в тихом режиме на этом ПК по ходу сборки
    #: (предусловия дистрибутива и недостающие runtime).
    runtime_installed: List[str] = field(default_factory=list)
    #: Проверено ли фактически, что папку результата можно удалить/перенести.
    folder_is_free: bool = True
    #: Кто держит папку, если это всё же не так (для показа пользователю).
    folder_holders: List[str] = field(default_factory=list)
    #: Где установщик брал временное место (``PortableData\\Temp`` или
    #: перенесённая папка на другом диске — такую папку сборка удаляет).
    installer_temp_dir: str = ""
    #: Отчёт о падении установщика (``installer-crash.log``), если процесс
    #: завершился аварийно.
    crash_report_rel: str = ""
    #: Распаковщик, которым достали содержимое установщика БЕЗ его запуска
    #: (пусто — не потребовался).
    unpacked_with: str = ""
    #: Объяснение, почему в портативе нет UWP-части Adobe
    #: (``adobe-uwp.txt``), если установщик этой части и требовал.
    adobe_note_rel: str = ""
    #: Пошаговый отчёт сборки Adobe (``adobe-report.txt``): что читали, что
    #: нашли и что в итоге лежит в App. По нему разбирают неудачу без догадок.
    adobe_report_rel: str = ""
    #: Отчёт о переносимости (``portability-report.txt``): какие абсолютные
    #: пути остались внутри портатива и что лончер сделает при переносе.
    portability_report_rel: str = ""
    #: Найденные службы, указывающие внутрь портатива. Они только сообщаются;
    #: Portablizer не останавливает и не удаляет системные службы автоматически.
    registered_services: List[str] = field(default_factory=list)
    #: Устаревшее поле: службы больше не снимаются с регистрации сборщиком.
    removed_services: List[str] = field(default_factory=list)
    #: Режим сквозных сохранений: ``inplace`` | ``mirror`` | ``off``.
    saves_mode: str = "off"
    #: Где лежит общее хранилище сейвов (относительно папки портатива).
    saves_store_rel: str = ""
    #: Сколько сохранений перенесено в это хранилище при сборке.
    saves_migrated: int = 0
    #: Человеческое описание режима (идёт в журнал, README и окно итога).
    saves_notes: List[str] = field(default_factory=list)


# -- «установка долго идёт» и «установка зависла» — это разные вещи -----------
#
# Раньше у тихой установки был один общий потолок на попытку (30 минут), и
# большая игра его не переживала: BioShock Infinite — десятки гигабайт и сотни
# тысяч файлов, установка идёт дольше, и сборка обрывалась сообщением
# «Превышено время ожидания установки», хотя установщик в этот момент
# добросовестно распаковывал файлы. Отличить одно от другого можно только по
# признакам работы, поэтому ниже ведутся три независимых наблюдения:
#   1) ввод-вывод и процессорное время дерева процессов установщика
#      (``procutil.process_activity``) — работает даже внутри одного большого
#      файла, который дописывается часами;
#   2) размер и число файлов в целевой папке (и в перенаправленном профиле:
#      движки вроде InstallScript ставят не туда, куда просили);
#   3) журналы, которые пишет сам установщик (Inno ``/LOG``, Burn ``/log``,
#      msiexec ``/L*v``, InstallShield ``/f2``).
# Пока растёт хоть что-то — установка живёт, и ждать можно сколько угодно.
# Замолчало всё сразу — вот это и есть зависание: его видно за минуты, а не
# через полчаса ожидания «на всякий случай».


@dataclass
class InstallStall:
    """Доклад о затишье: по нему человек решает, ждать ли ещё.

    Идёт в интерфейс (окно с вопросом), в журнал и в итоговые подсказки.
    Показывать одни секунды бесполезно — рядом должны стоять размеры уже
    распакованного, иначе «завис» и «медленно пишет» выглядят одинаково.
    """

    attempt: str = ""
    elapsed: float = 0.0        # сколько идёт попытка, секунд
    idle: float = 0.0           # сколько нет признаков работы, секунд
    idle_limit: float = 0.0     # сколько их терпят по настройкам
    deadline: float = 0.0       # абсолютный потолок (0 — без потолка)
    written: int = 0            # сколько байт уже лежит в целевой папке
    files: int = 0              # сколько файлов появилось
    processes: int = 0          # сколько процессов в дереве установщика
    logs: List[str] = field(default_factory=list)
    io_bytes: int = 0
    cpu_seconds: float = 0.0

    def message(self) -> str:
        """Готовая фраза для журнала и окна с вопросом."""
        parts = [f"Установка идёт {redist_mod.human_duration(self.elapsed)}"]
        if self.files or self.written:
            parts.append(
                f"уже распаковано {redist_mod.format_size(self.written)} "
                f"в {self.files} файлах")
        parts.append(
            f"но последние {redist_mod.human_duration(self.idle)} нет "
            "признаков работы "
            f"(предел {redist_mod.human_duration(self.idle_limit)})")
        return ", ".join(parts) + "."


def _stall_verdict(answer: object) -> str:
    """Приводит ответ колбэка к одному из :data:`STALL_WAIT`/``STOP``/``CANCEL``.

    Разные вызывающие коды отвечают по-разному (строка, флаг, ничего), поэтому
    незнакомый ответ считается решением «больше не ждать»: молчание не должно
    превращаться в бесконечное ожидание.
    """
    if answer is True:
        return STALL_WAIT
    if answer is False or answer is None:
        return STALL_STOP
    text = str(answer).strip().casefold()
    if text.startswith(("wait", "more", "ждать", "подожд", "ещё", "еще",
                        "продолж")):
        return STALL_WAIT
    if text.startswith(("cancel", "abort", "отмен", "прерв")):
        return STALL_CANCEL
    return STALL_STOP


def _tree_usage(root: str, budget: float = 3.0) -> Tuple[int, int]:
    """``(файлов, байт)`` внутри ``root`` за отведённое время.

    Обход намеренно ограничен по времени: целевая папка установщика большой
    игры — сотни тысяч файлов, и полный пересчёт на каждом опросе стоил бы
    дороже самой установки. Частичный результат для наблюдения за ходом работ
    ничем не хуже полного: важно, что число меняется, а не его абсолютное
    значение. Ошибки доступа не прерывают обход (установщик может держать
    файлы открытыми), а просто пропускают недоступное.
    """
    files = 0
    total = 0
    if not root:
        return files, total
    limit = time.monotonic() + max(0.1, budget)
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            files += 1
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
        if time.monotonic() > limit:
            break
    return files, total


class _InstallWatchdog:
    """Отличает долгую установку от зависшей по признакам работы.

    Опрашивает дерево процессов установщика (ввод-вывод, процессор), целевую
    папку и журналы установщика. ``poll()`` возвращает ``True``, когда с
    прошлого опроса появились изменения — то есть установщик работает.
    """

    def __init__(self, pid: int, roots: Sequence[str] = (),
                 logs: Sequence[str] = (),
                 probe_seconds: Optional[float] = None,
                 dir_seconds: Optional[float] = None,
                 scan_budget: float = 3.0) -> None:
        # Частоты опроса берутся из модульных констант в момент ВЫЗОВА, а не
        # при определении класса: их переопределяют тесты и внешние сценарии.
        self.pid = int(pid)
        self.roots = [str(path) for path in roots if path]
        self.logs = [str(path) for path in dict.fromkeys(logs) if path]
        self.probe_seconds = max(0.01, float(
            INSTALL_PROBE_SECONDS if probe_seconds is None else probe_seconds))
        self.dir_seconds = max(self.probe_seconds, float(
            INSTALL_DIR_SCAN_SECONDS if dir_seconds is None else dir_seconds))
        self.scan_budget = max(0.1, float(scan_budget))
        self._next_probe = 0.0
        self._next_dir_scan = 0.0
        self._fingerprint: Tuple = ()
        #: Признаки реальной работы (без логов и процессора) — последнее
        #: изменение и сам fingerprint, чтобы знать, что опрос уже состоялся.
        self._strong_fingerprint: Tuple = ()
        self._strong_changed = False
        self.samples = 0
        self.io_bytes = 0
        self.cpu_seconds = 0.0
        self.processes = 0
        self.files = 0
        self.bytes = 0
        self.log_bytes = 0
        #: Счётчики на первом опросе: по ним видно, делал ли установщик хоть
        #: что-нибудь за всю попытку. Именно это отличает «медленно
        #: распаковывает» от «стоит и ждёт нажатия/подтверждения».
        self.start_io = 0
        self.start_cpu = 0.0
        self.start_known = False

    # -- наблюдения -----------------------------------------------------------
    def _log_bytes(self) -> int:
        total = 0
        for path in self.logs:
            try:
                total += os.path.getsize(path)
            except OSError:
                continue
        return total

    def _sample_now(self, now: float) -> None:
        """Снимает все наблюдения, которые пора снять."""
        activity = procutil.process_activity(self.pid)
        if activity is not None:
            self.io_bytes = int(activity.io_bytes)
            self.cpu_seconds = float(activity.cpu_seconds)
            self.processes = len(activity.pids)
        if now >= self._next_dir_scan:
            # Целевую папку считаем реже процессов, но обязательно вместе с
            # журналами: журнал растёт построчно, папка — целыми файлами.
            self._next_dir_scan = now + self.dir_seconds
            files = 0
            total = 0
            for root in self.roots:
                found_files, found_bytes = _tree_usage(root, self.scan_budget)
                files += found_files
                total += found_bytes
            self.files, self.bytes = files, total
        self.log_bytes = self._log_bytes()

    def _fingerprint_now(self) -> Tuple:
        return (self.processes, self.io_bytes, int(self.cpu_seconds * 10),
                self.files, self.bytes, self.log_bytes)

    def _strong_now(self) -> Tuple:
        """Признаки реальной работы: процессы, диск, целевая папка.

        Лог и счётчик процессора сюда не входят: у встроенного установщика
        верстака SFX (особенно у верстальщиков, которые ставят «разогнанную»
        версию) процессор мелькает и лог растёт, когда внутренний
        установщик уже завис — и наоборот. Для таймаута затишья честным
        признаком «работает» являются только процессы, диск и файлы, а
        слабые признаки идут на вывод в журнал, но не удерживают якорь
        непрерывной работы (см. ``strong_changed``).
        """
        return (self.processes, self.io_bytes, self.files, self.bytes)

    def poll(self, now: Optional[float] = None) -> bool:
        """``True``, если установщик подал признаки работы с прошлого опроса.

        Первый опрос всегда считается работой: установщик только что
        запустился, и ждать от него счётчиков раньше времени нечего.
        Любое изменение счётчиков (включая слабые — лог, процессор)
        считается прогрессом, чтобы таймер затишья не тикали при
        правильном, но тихим установщике.
        """
        now = time.monotonic() if now is None else float(now)
        if self.samples and now < self._next_probe:
            return False
        self._next_probe = now + self.probe_seconds
        self._sample_now(now)
        if not self.start_known:
            # Точка отсчёта: с ней сравнивается ВСЁ дальнейшее поведение
            # установщика. Первый опрос всегда считается работой (процесс
            # только запустился), но если после него счётчики так и не
            # сдвинулись — установщик не сделал вообще ничего.
            self.start_known = True
            self.start_io = self.io_bytes
            self.start_cpu = self.cpu_seconds
        current = self._fingerprint_now()
        changed = self.samples == 0 or current != self._fingerprint
        self._fingerprint = current
        strong = self._strong_now()
        self._strong_changed = (self.samples == 0
                                or strong != self._strong_fingerprint)
        self._strong_fingerprint = strong
        self.samples += 1
        return changed

    def strong_changed(self) -> bool:
        """Изменились ли признаки реальной работы на последнем опросе.

        Вернёт ``True`` на первом опросе (установка только что началась)
        и при любом изменении процессов, счётчиков ввода-вывода, файлов или
        объёма в целевой папке. Изменения журнала и счётчика процессора
        сами по себе это значение не обновляют — иначе установщик, который
        завис внутри верстака, но сохраняет процессор и лог в движении,
        никогда не спросит, что с ним сделать.
        """
        return self._strong_changed

    def never_started(self, cpu_slack: float = 1.0,
                      io_slack: int = 4 * 1024 * 1024) -> bool:
        """Установщик запущен, но за всю попытку не сделал НИЧЕГО.

        Отличие от :meth:`strong_changed`: там речь о паузе ПОСЛЕ работы, а
        здесь — о попытке, в которой работы не было ни секунды. Такое
        поведение нельзя объяснить размером дистрибутива: 3,7-гигабайтный
        установщик читает свой архив с диска, и это видно в счётчиках
        ввода-вывода дерева процессов. Если же ни ввод-вывод, ни процессор,
        ни целевая папка не сдвинулись даже на мегабайт, процесс стоит на
        чём-то внешнем:

        * Windows показывает запрос UAC (он принадлежит ``consent.exe``, а не
          дереву установщика, поэтому наши счётчики его не видят);
        * обёртка-SFX показала модальное окно «неверная операция командной
          строки» и ждёт нажатия «ОК»;
        * антивирус держит файл и не отдаёт его установщику;
        * ключ установки не подошёл, и обёртка молча ждёт.

        ``cpu_slack``/``io_slack`` — допуск на «дрожание» счётчиков: оболочка
        успевает прочитать собственный заголовок, и это не работа установки.
        """
        if not self.start_known:
            # Ни одного опроса ещё не было: судить не о чем.
            return False
        return (self.files == 0 and self.bytes == 0
                and self.io_bytes <= self.start_io + max(0, int(io_slack))
                and self.cpu_seconds <= self.start_cpu + max(0.0, float(cpu_slack)))

    # -- отчёт ---------------------------------------------------------------
    def summary(self) -> str:
        """Что видно про работу установщика (для журнала и подробной строки)."""
        parts: List[str] = []
        if self.bytes or self.files:
            parts.append(f"распаковано {redist_mod.format_size(self.bytes)} "
                         f"в {self.files} файлах")
        if self.io_bytes:
            parts.append(f"диск: {redist_mod.format_size(self.io_bytes)}")
        if self.cpu_seconds:
            parts.append(f"процессор: "
                         f"{redist_mod.format_duration(self.cpu_seconds)}")
        if self.log_bytes:
            parts.append("журнал установщика растёт")
        if not parts:
            parts.append("процессы установщика живы")
        return ", ".join(parts)

    def report(self, attempt: str, elapsed: float, idle: float,
               idle_limit: float, deadline: float) -> InstallStall:
        """Доклад о затишье для интерфейса, журнала и подсказок."""
        return InstallStall(
            attempt=attempt, elapsed=elapsed, idle=idle,
            idle_limit=idle_limit, deadline=deadline,
            written=self.bytes, files=self.files, processes=self.processes,
            logs=list(self.logs), io_bytes=self.io_bytes,
            cpu_seconds=self.cpu_seconds)


class Portablizer:
    def __init__(self, logger: Logger,
                 progress: Optional[ProgressCB] = None,
                 cancel_event: Optional[threading.Event] = None,
                 detail: Optional[DetailCB] = None,
                 on_stall: Optional[StallCB] = None) -> None:
        self.log = logger
        #: Колбэк общего хода сборки, как его передал вызывающий код.
        self._progress_cb: ProgressCB = progress or (lambda p, s: None)
        #: Подробный ход текущей операции (загрузка пакета, распаковка).
        self.detail = detail or (lambda p, s: None)
        self.cancel = cancel_event or threading.Event()
        #: Время начала run() — по нему отбираются журналы установщика.
        self._run_started: Optional[float] = None
        #: Сколько вариантов команды установки реально выполнено.
        self._attempts_made = 0
        #: Сколько раз за сборку был закрыт диалог Windows Security
        #: «Установить ПО для данного устройства?» (установка драйвера TAP).
        #: Нужен для честных подсказок, когда установка всё же не удалась.
        self._device_prompt_hits = 0
        #: История лестницы попыток: (название сценария, код возврата).
        self._attempt_history: List[Tuple[str, Optional[int]]] = []
        #: Последний ResultCode из setup.log классического InstallShield.
        self._installshield_result: Optional[int] = None
        #: Вопрос «установка замолчала — ждать ещё?» (см. ``StallCB``).
        self.on_stall: Optional[StallCB] = on_stall
        #: Попытка была снята по пределу ожидания (для итоговой диагностики).
        self._install_stalled = False
        #: Доклад о последнем затишье: по нему строятся подсказки.
        self._install_stall: Optional[InstallStall] = None
        #: Установщик открывал собственный мастер (язык/папка) и ждал
        #: нажатий — из этого строится отдельная подсказка в отчёте.
        self._install_gui_seen = False
        #: Попытка снята потому, что установщик не сделал НИЧЕГО с самого
        #: запуска (ни ввода-вывода, ни файлов). Это не то же самое, что
        #: затишье после работы: здесь сборка не ждёт 15 минут, а сразу
        #: переходит к следующему сценарию (см. INSTALL_DEAD_START_LIMIT).
        self._install_dead_start = False
        #: Сколько попыток подряд закончились «мёртвым стартом» (см.
        #: DEAD_START_ATTEMPTS_LIMIT).
        self._dead_start_attempts = 0
        #: Заголовки окон установщика, которые Portablizer не закрывает сам
        #: (незнакомый диалог). Нужны для честного диагноза: «стоит окно с
        #: таким-то текстом» вместо «нет признаков работы».
        self._install_dialog_titles: List[str] = []
        #: Папка TEMP, из которой работает установщик. По умолчанию —
        #: ``PortableData\Temp``; может быть перенесена на другой диск, если на
        #: диске портатива для распаковки не хватает места (см.
        #: ``_prepare_install_temp``).
        self._install_temp_dir = ""
        #: Временные папки ВНЕ портатива, созданные для установщика: после
        #: сборки их надо убрать, иначе на компьютере останется мусор.
        self._external_temp_dirs: List[str] = []
        #: Что сказать про свободное место (заполняется, только если места
        #: действительно не хватало).
        self._temp_space_note = ""
        #: Падения установщика: (название сценария, код возврата).
        self._crash_history: List[Tuple[str, int]] = []
        #: Записи журнала событий Windows о последнем падении.
        self._crash_events: List[crash_mod.CrashEvent] = []
        #: Повтор той же команды после падения уже выполнялся.
        self._crash_retried = False
        #: Сценарий «с окном прогресса» после падения уже добавлялся.
        self._progress_retry_done = False
        #: Сколько секунд шла последняя попытка установки.
        self._last_install_seconds = 0.0
        #: Имя упавшего процесса: по нему ищутся записи в журнале событий.
        self._installer_name = ""
        #: Чем закончилась распаковка без запуска (для подсказок).
        self._unpacker_result = ""
        #: Каким распаковщиком воспользовались (пусто — ни одним).
        self._unpacked_with = ""
        #: Диагноз последовательно пустых быстрых запусков установщика.
        self._hollow_note = ""
        #: Текущий результат распознавания, нужен и для диагностики лестницы.
        self._detection: Optional[DetectionResult] = None
        #: Установщик Adobe (HyperDrive): UWP-шаг (код 191) портативу не
        #: нужен, поэтому пакеты раскладываются в обход установщика. Флаги —
        #: ниже; разбор и тексты — в core/adobe.py.
        self._adobe_detected = False
        #: Что удалось разложить в App из пакетов Adobe (для подсказок).
        self._adobe_applied: Optional[adobe_mod.ApplyResult] = None
        #: Найденные пакеты Adobe (для подсказок про «только UWP без MSI»).
        self._adobe_layout: Optional[adobe_mod.AdobeLayout] = None
        #: Откуда взяли пакеты Adobe (каталог распаковки/TEMP установщика).
        self._adobe_source = ""
        #: Установщик уже оставил payload в TEMP — забирать его пробовали.
        self._adobe_salvage_attempted = False
        #: Разобранная причина отказа Adobe из журнала (код 191, OS-код Appx).
        self._adobe_failure: Optional[adobe_mod.AdobeFailure] = None
        #: Файл-объяснение про UWP-часть (``adobe-uwp.txt``), если он записан.
        self._adobe_note_rel = ""
        #: Настоящий установщик внутри контейнера (SFX-обёртка над setup.exe).
        self._adobe_nested_setup = ""
        #: Сбор пакетов «на лету», пока установщик работает (см. adobe.py).
        self._adobe_watcher: Optional[adobe_mod.PayloadWatcher] = None
        #: Пошаговый след сборки Adobe — основа файла adobe-report.txt.
        self._adobe_steps: List[str] = []
        #: Путь к отчёту, если он записан (показывается в итоговом окне).
        self._adobe_report_rel = ""
        #: Копия установщика на локальном диске: Adobe отказывается работать
        #: со съёмного и сетевого носителя (код 1000).
        self._adobe_media_copy = ""
        self._adobe_media_dir = ""
        #: Fusion может развернуться в перенаправленный LOCALAPPDATA, а не App.
        self._online_profile_main_exe = ""
        self._online_profile_checked = False
        self._online_profile_deferred = False
        self._online_profile_targets: List[launcher_mod.TargetInfo] = []
        self._online_profile_diagnostic = ""
        self._recovered_sources: List[str] = []

    # -- вспомогательное ------------------------------------------------------
    def progress(self, percent: int, stage: str) -> None:
        """Переход к новому этапу сборки: подробности прошлого больше не нужны."""
        self._emit_progress(percent, stage)
        self._detail(0, "")

    def _emit_progress(self, percent: int, stage: str) -> None:
        try:
            self._progress_cb(int(percent), stage)
        except Exception:  # noqa: BLE001
            pass

    def _detail(self, percent: int, text: str) -> None:
        """Показывает ход текущей операции, не роняя сборку на ошибке GUI."""
        try:
            self.detail(int(percent), text)
        except Exception:  # noqa: BLE001
            pass

    def _stage_progress(self, start: int, stop: int) -> Callable[[float, str, int], None]:
        """Колбэк для долгого этапа: доля этапа → общий процент + подробности.

        Именно из-за отсутствия такого колбэка сборка выглядела зависшей на
        «82%»: загрузка DirectX идёт минутами и раньше ничего о себе не
        сообщала.
        """
        span = max(1, stop - start)

        def report(fraction: float, text: str, detail: int = -1) -> None:
            value = start + int(span * max(0.0, min(1.0, fraction)))
            self._emit_progress(min(stop, value),
                                text or "Распространяемые компоненты")
            if text:
                self._detail(detail, text)

        return report

    def _check_cancel(self) -> None:
        if self.cancel.is_set():
            raise RuntimeError("Операция отменена пользователем.")

    def _safe_name(self, opts: PortableOptions) -> str:
        if opts.app_name.strip():
            base = opts.app_name.strip()
        else:
            base = os.path.splitext(os.path.basename(opts.installer_path))[0]
        keep = "-_. ()"
        cleaned = "".join(c for c in base if c.isalnum() or c in keep).strip()
        return cleaned or "PortableApp"

    def _release_portable_dir(self, portable_dir: str,
                              reason: str = "") -> List[str]:
        """Закрывает процессы из папки результата, не меняя регистрацию служб.

        Вызывается трижды за сборку: перед очисткой старого результата,
        сразу после установки (установщики любят закончить галочкой
        «Запустить программу сейчас») и перед выдачей готового портатива.
        Смысл один: пользователь должен получить папку, которую можно
        удалить, перенести и скопировать на флешку без «файл занят другим
        процессом».
        """
        if not portable_dir or not os.path.isdir(portable_dir):
            return []
        try:
            stopped = procutil.release_folder(portable_dir, stop_services=False)
        except Exception as exc:  # noqa: BLE001 - уборка не ломает сборку
            self.log.debug(f"Не удалось опросить процессы папки: {exc}")
            return []
        if stopped:
            tail = f" ({reason})" if reason else ""
            self.log.info(
                "Остановлены процессы, запущенные из папки портатива"
                f"{tail}: " + ", ".join(sorted(set(stopped))))
        return stopped

    def _release_after_install(
        self, det: DetectionResult, opts: PortableOptions, data_dir: str,
        portable_dir: str, app_name: str,
    ) -> None:
        """Не убивает незавершённый Autodesk Streamer после выхода bootstrapper.

        Fusion может завершить родительский downloader раньше дочернего
        процесса, который заменяет placeholder FusionLauncher.exe.ini. Сначала
        проверяем именно штатную точку входа. Если конфигурация ещё неполная,
        но в PortableData остались живые процессы, оставляем их завершить
        настройку; иначе release_folder мог бы сам создать этот placeholder-
        сбой, приняв финализатор за «Запустить программу сейчас».
        """
        product = getattr(det, "online_product", None)
        if (not getattr(det, "is_downloader_stub", False)
                or product is None
                or not getattr(product, "entrypoint_exe_names", ())):
            self._release_portable_dir(portable_dir, reason="после установки")
            return

        configured = self._discover_online_profile_payload(
            opts, data_dir, portable_dir, app_name)
        if not configured:
            try:
                running = procutil.processes_in(data_dir)
                process_scan_ok = True
            except Exception as exc:  # noqa: BLE001 - безопаснее не убивать finalizer
                self.log.debug(
                    f"Не удалось проверить процессы Autodesk Streamer: {exc}")
                running = []
                process_scan_ok = False
            if running or not process_scan_ok:
                self._online_profile_deferred = True
                names = sorted({os.path.basename(image) or str(pid)
                                for pid, image in running})
                detail = ", ".join(names) if names else "состояние неизвестно"
                self.log.warn(
                    "FusionLauncher.exe.ini пока не подтверждает готовую "
                    "установку; не останавливаю процессы PortableData, чтобы "
                    "не прервать финализацию Autodesk Streamer: "
                    + detail + "."
                )
                return
        self._release_portable_dir(portable_dir, reason="после установки")

    def _verify_folder_is_free(self, portable_dir: str,
                               result: "PortableResult") -> bool:
        """Проверяет делом: папку можно удалить, перенести, скопировать.

        Перебор процессов отвечает на вопрос «кто запущен», а пользователь
        спрашивает другое — «почему я не могу удалить папку». Windows не даёт
        переименовать каталог, внутри которого открыт хотя бы один файл, то
        есть ровно при том же условии, что и удаление. Поэтому пробное
        переименование — это честная проверка результата сборки, не
        зависящая от того, кто именно держит папку: процесс, служба или
        подгруженная кем-то DLL.

        Дорогой поиск виновника (обход модулей всех процессов системы)
        выполняется только если проба не прошла.
        """
        if not IS_WINDOWS:
            return True
        probe_errors: List[str] = []
        if procutil.folder_is_free(portable_dir, probe_errors):
            self.log.ok(
                "Папка портатива свободна: её можно удалить, перенести или "
                "скопировать на флешку прямо сейчас.")
            return True
        for line in probe_errors:
            self.log.debug(f"Папка не отпускается: {line}")

        # Папка занята — значит первый проход кого-то не добил. Пробуем ещё
        # раз, уже с разбором открытых файлов, и только потом жалуемся.
        again = procutil.release_folder(portable_dir, stop_services=False)
        if again:
            self.log.info("Повторно остановлено: " + ", ".join(sorted(set(again))))
            probe_errors = []
            if procutil.folder_is_free(portable_dir, probe_errors):
                self.log.ok(
                    "Папка портатива свободна: её можно удалить, перенести "
                    "или скопировать на флешку прямо сейчас.")
                return True
            for line in probe_errors:
                self.log.debug(f"Папка не отпускается: {line}")

        holders = procutil.holders(portable_dir)
        names = procutil.describe_holders(holders)
        result.folder_holders = names
        if names:
            self.log.warn(
                "Папку портатива всё ещё держат: " + ", ".join(names) + ".")
            if any(h.protected for h in holders):
                self.log.warn(
                    "Среди них есть системные процессы (служба кэша шрифтов, "
                    "индексатор, открытое окно проводника) — их дескрипторы "
                    "на файлы папки закрываются принудительно; если файл всё "
                    "ещё занят, нужны права администратора.")
        else:
            locked = procutil.busy_files(portable_dir)
            result.folder_holders = [os.path.basename(p) for p in locked]
            if locked:
                self.log.warn(
                    "Папку портатива держат открытые файлы: "
                    + ", ".join(result.folder_holders[:6])
                    + ". Запустите Portablizer от имени администратора — "
                      "тогда держателя видно по имени и его дескриптор "
                      "закрывается принудительно.")
            else:
                self.log.warn(
                    "Папка портатива занята, но виновника определить не "
                    "удалось: чаще всего это открытое окно проводника или "
                    "проверка антивирусом. Через несколько секунд папка "
                    "освободится сама.")
        self.log.info(
            f"Освободить папку вручную: {launcher_mod.STOP_SCRIPT_NAME} "
            "в её корне.")
        return False

    def _remove_path(self, path: str, attempts: int = 4) -> None:
        """Удаляет файл или дерево, переживая кратковременную блокировку.

        Антивирус, индексатор Windows и только что закрытая программа
        отпускают файл не мгновенно. Раньше такая секундная блокировка
        обрывала всю сборку сообщением «не удалось очистить старый файл»;
        теперь попытка повторяется с нарастающей паузой, а перед последней
        из папки выгоняются оставшиеся процессы.
        """
        last: Optional[OSError] = None
        for attempt in range(attempts):
            try:
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                elif os.path.exists(path) or os.path.islink(path):
                    os.remove(path)
                return
            except OSError as exc:
                last = exc
                if attempt == attempts - 2:
                    self._release_portable_dir(
                        os.path.dirname(path),
                        reason=f"файл занят: {os.path.basename(path)}")
                time.sleep(0.4 * (attempt + 1))
        if last is not None:
            raise last

    def _prepare_output(self, portable_dir: str, app_dir: str,
                        data_dir: str) -> None:
        """Готовит чистый App и удаляет лончер от незавершённого запуска.

        ``PortableData`` намеренно сохраняется: пользователь мог повторно
        собрать уже используемый портатив, и удалять его настройки нельзя.
        Программные файлы, напротив, должны соответствовать только текущему
        установщику — иначе старый exe маскирует неудачную установку.
        """
        os.makedirs(portable_dir, exist_ok=True)
        if IS_WINDOWS:
            try:
                existing_services = procutil.services_in(portable_dir)
            except Exception:  # noqa: BLE001 - ниже безопасное поведение по умолчанию
                existing_services = []
            if existing_services:
                raise RuntimeError(
                    "В указанной папке уже зарегистрированы службы Windows "
                    "(" + ", ".join(existing_services) + "). Portablizer "
                    "не будет останавливать их или удалять файлы под ними; "
                    "выберите другую папку либо проверьте службы вручную.")

        # Пересборка поверх работающего портатива — самая частая причина
        # «не удалось очистить старый файл результата»: прошлый запуск
        # оставил в папке живой процесс (апдейтер, лончер, сама программа),
        # и Windows не даёт удалить его файлы. Освобождаем папку сами,
        # вместо того чтобы просить пользователя искать процесс в диспетчере.
        self._release_portable_dir(portable_dir, reason="перед очисткой")

        if os.path.isdir(app_dir):
            self._remove_path(app_dir)
        elif os.path.exists(app_dir):
            self._remove_path(app_dir)
        os.makedirs(app_dir, exist_ok=True)
        os.makedirs(data_dir, exist_ok=True)

        # Сохранённая сессия реестра от предыдущей сборки (PortableData\Registry)
        # при запуске имеет приоритет над portable.reg и portable_machine.reg.
        # При пересборке портатива с нуля (например, с другим языком установки)
        # старый кэш реестра нужно сбросить, сохранив пользовательские сейвы.
        for reg_subdir in ("Registry", "RegistryHostBackup"):
            reg_cache = os.path.join(data_dir, reg_subdir)
            if os.path.exists(reg_cache):
                try:
                    self._remove_path(reg_cache)
                except OSError:
                    pass

        # Временная папка установщика от предыдущей сборки. Она же — «второй
        # потребитель» места на диске: неудачная установка большой игры
        # оставляет в ней десятки гигабайт, и следующая попытка начинается
        # уже с пустым диском. Содержимое TEMP по определению не нужно — его
        # удаление безопасно, и об освобождённом месте честно сообщается.
        stale_temp = os.path.join(data_dir, "Temp")
        if os.path.isdir(stale_temp):
            freed = _tree_usage(stale_temp)[0]
            try:
                self._remove_path(stale_temp)
            except OSError as exc:
                self.log.debug(f"  • старую временную папку очистить не удалось: {exc}")
            else:
                if freed:
                    self.log.info(
                        "Временная папка прошлой сборки очищена: освобождено "
                        f"{redist_mod.format_size(freed)}."
                    )
        os.makedirs(stale_temp, exist_ok=True)

        for filename in (
            "Launch.bat", "LaunchHidden.vbs", "launcher.py",
            "launcher_config.json", "README_PORTABLE.txt", "portable.reg",
            "portable_machine.reg", "cleanup_host.reg", "cleanup_host.cmd",
            "install.log",
            "install-retry.log", "install-layout.log", "installer-engine.log",
            "installer-output.log", "installer-crash.log",
            "unpacker-output.log", "portablizer.log", "_bundle_layout",
            "_unpacked", "setup-installshield.log", redist_mod.REPORT_NAME,
            "_redist_cache",
            launcher_mod.STOP_SCRIPT_NAME, launcher_mod.UPDATE_SCRIPT_NAME,
            "Updates",
        ):
            path = os.path.join(portable_dir, filename)
            try:
                self._remove_path(path)
            except OSError as exc:
                raise RuntimeError(
                    f"Не удалось очистить старый файл результата: {path}: {exc}"
                ) from exc

        # Набор обнаруженных exe меняется от сборки к сборке. Удаляем старые
        # сгенерированные Launch_<Target>.bat/.vbs/.exe, иначе после повторной
        # сборки в корне остаются лончеры уже отсутствующих компонентов.
        try:
            root_files = os.listdir(portable_dir)
        except OSError:
            root_files = []
        for filename in root_files:
            if not re.fullmatch(r"Launch_.+\.(?:bat|vbs|exe)", filename,
                                flags=re.IGNORECASE):
                continue
            path = os.path.join(portable_dir, filename)
            try:
                if os.path.isfile(path):
                    self._remove_path(path)
            except OSError as exc:
                raise RuntimeError(
                    f"Не удалось очистить старый лончер: {path}: {exc}"
                ) from exc

    def _save_run_log(self, portable_dir: str) -> None:
        """Сохраняет журнал ядра независимо от поддержки лога установщиком."""
        if not portable_dir:
            return
        try:
            with open(os.path.join(portable_dir, "portablizer.log"), "w",
                      encoding="utf-8-sig", newline="\r\n") as fh:
                fh.write(self.log.text)
                fh.write("\n")
        except OSError:
            pass

    def _warn_downloader_stub(self, det: DetectionResult) -> None:
        """До запуска объясняет, если выбран только сетевой загрузчик."""
        if getattr(det, "is_downloader_stub", False) is not True:
            return
        size = redist_mod.format_size(getattr(det, "media_size", 0))
        product = getattr(det, "online_product", None)
        if product is not None:
            switches = ", ".join(getattr(product, "switches", ()) or ())
            self.log.warn(
                f"Обнаружен сетевой загрузчик {product.name} ({size}), а не "
                f"полный дистрибутив. {product.reason}. Документированный "
                f"тихий ключ: {switches or '--quiet'}. Ключ --globalinstall "
                "не используется: он устанавливает клиент в Program Files "
                "этого компьютера. Даже при успешной загрузке вход в аккаунт "
                "и привязка к профилю могут помешать переносимости."
            )
            return
        evidence = "; ".join(getattr(det, "downloader_evidence", ()) or ())
        self.log.warn(
            f"Похоже, выбран сетевой загрузчик ({size}), а не полный "
            "дистрибутив. Если он завершится без файлов программы, не буду "
            "перебирать все ключи: нужен автономный пакет со всеми частями."
            + (f" Признаки: {evidence}." if evidence else "")
        )

    @staticmethod
    def _host_online_profile_note(parts: Sequence[str], portable_dir: str) -> str:
        """Указывает на профиль Windows, но никогда не переносит его файлы."""
        host_local = os.environ.get("LOCALAPPDATA", "")
        if not host_local:
            return ""
        host_root = os.path.abspath(os.path.join(host_local, *parts))
        portable_abs = os.path.abspath(portable_dir)
        try:
            if os.path.commonpath((portable_abs, host_root)) == portable_abs:
                return ""
        except ValueError:
            pass
        if os.path.isdir(host_root):
            return (
                f" В профиле Windows также существует {host_root}; "
                "этот внешний каталог намеренно не копируется."
            )
        return ""

    @staticmethod
    def _validate_fusion_launcher_ini(
        launcher_exe: str, profile_root: str, local_appdata: str,
    ) -> Tuple[str, str]:
        """Возвращает путь app-exe из настроенного FusionLauncher.ini.

        Само наличие FusionLauncher.exe недостаточно: Streamer сначала кладёт
        рядом placeholder ``FusionLauncher.exe.ini``, а в конце установки
        заменяет его конфигурацией с командой запуска Fusion. Placeholder и
        конфиг без существующего app-exe означают незавершённую установку.
        """
        ini_path = launcher_exe + ".ini"
        if not os.path.isfile(ini_path):
            return "", "FusionLauncher.exe.ini отсутствует"
        try:
            with open(ini_path, "rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
        except OSError as exc:
            return "", f"FusionLauncher.exe.ini не читается ({exc})"
        if len(raw) > 1024 * 1024:
            return "", "FusionLauncher.exe.ini превышает ожидаемый размер"
        if not raw:
            return "", "FusionLauncher.exe.ini пуст"

        try:
            if raw.startswith((bytes((0xff, 0xfe)), bytes((0xfe, 0xff)))):
                text = raw.decode("utf-16")
            elif len(raw) > 1 and raw[1:2] == bytes((0,)):
                text = raw.decode("utf-16-le")
            elif raw[:1] == bytes((0,)):
                text = raw.decode("utf-16-be")
            else:
                text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("cp1252", errors="replace")
        if "placeholder file which is intended to be updated by the streamer" \
                in text.casefold():
            return "", "FusionLauncher.exe.ini всё ещё является placeholder Streamer"

        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error:
            return "", "FusionLauncher.exe.ini не содержит корректную INI-конфигурацию"
        if not parser.has_section("Launcher"):
            return "", "в FusionLauncher.exe.ini отсутствует секция [Launcher]"
        settings = parser["Launcher"]
        command = settings.get("cmd", "").replace('""', '"').strip()
        if not command:
            return "", "в [Launcher] отсутствует команда cmd"
        if settings.get("stream", "production").casefold() != "production":
            return "", "FusionLauncher.ini указывает на неизвестный webdeploy stream"

        command = command.strip().strip(chr(34) + chr(39))
        command = re.sub(r"%LOCALAPPDATA%", lambda _match: local_appdata,
                         command, flags=re.IGNORECASE)
        executable_end = command.casefold().find(".exe")
        if executable_end < 0:
            return "", "команда cmd не содержит путь к исполняемому файлу"
        executable_end += len(".exe")
        executable_command = command[:executable_end]
        drive_start = -1
        for index in range(max(0, len(executable_command) - 2)):
            if (executable_command[index].isalpha()
                    and executable_command[index + 1] == ":"
                    and executable_command[index + 2] in (chr(92), "/")):
                drive_start = index
                break
        if drive_start >= 0:
            path_start = drive_start
        elif executable_command.startswith("/"):
            path_start = 0
        else:
            quote_start = executable_command.rfind(chr(34))
            if quote_start >= 0:
                path_start = quote_start + 1
            else:
                path_start = executable_command.rfind(" ") + 1
        target = executable_command[path_start:].strip().strip(chr(34) + chr(39))
        if not target:
            return "", "команда cmd не содержит путь к исполняемому файлу"
        if not os.path.isabs(target):
            target = os.path.join(os.path.dirname(launcher_exe), target)
        target = os.path.abspath(os.path.normpath(target))
        if os.path.basename(target).casefold() != "fusion360.exe":
            return "", (
                "команда FusionLauncher.ini должна указывать на "
                "Fusion360.exe, а не на вспомогательный EXE"
            )
        profile_abs = os.path.abspath(profile_root)
        try:
            common = os.path.commonpath((profile_abs, target))
            contained = os.path.normcase(common) == os.path.normcase(profile_abs)
        except ValueError:
            contained = False
        if not contained:
            return "", "команда FusionLauncher указывает за пределы PortableData/webdeploy"
        if not os.path.isfile(target):
            return "", f"app-exe из FusionLauncher.ini не найден: {os.path.relpath(target, profile_abs)}"
        try:
            if os.path.getsize(target) < 128 * 1024 or not read_pe_info(target).is_pe:
                return "", "app-exe из FusionLauncher.ini неполный или не является PE"
        except OSError as exc:
            return "", f"app-exe из FusionLauncher.ini не читается ({exc})"
        return target, ""

    def _discover_online_profile_payload(
        self, opts: PortableOptions, data_dir: str, portable_dir: str,
        app_name: str,
    ) -> bool:
        """Ищет продукт внутри перенаправленного LOCALAPPDATA без копирования.

        Fusion Client Downloader может штатно развернуть клиент в
        ``%LOCALAPPDATA%\\Autodesk\\webdeploy\\production`` и оставить
        ``App`` пустой. Если профиль изолирован внутри портатива, запускаем
        найденный exe именно оттуда: так сохраняются исходные относительные
        пути webdeploy, не дублируются гигабайты и остаётся тот же профиль
        LOCALAPPDATA для обновлений.
        """
        self._online_profile_checked = True
        product = getattr(self._detection, "online_product", None)
        profile_rel = getattr(product, "profile_root", "") if product else ""
        if not profile_rel:
            return False
        if not opts.redirect_userdirs:
            self._online_profile_diagnostic = (
                "Перенаправление пользовательских папок отключено; "
                "переносимый LOCALAPPDATA не проверялся."
            )
            return False

        parts = [part for part in re.split(r"[\\/]+", profile_rel) if part]
        if not parts or any(part in (".", "..") for part in parts):
            self._online_profile_diagnostic = (
                "Профиль онлайн-продукта имеет небезопасный относительный путь."
            )
            return False
        data_abs = os.path.abspath(data_dir)
        profile_root = os.path.abspath(os.path.join(
            data_abs, "AppData", "Local", *parts))
        try:
            if os.path.commonpath((data_abs, profile_root)) != data_abs:
                self._online_profile_diagnostic = (
                    "Путь webdeploy выходит за пределы PortableData; "
                    "внешний профиль не будет перенесён."
                )
                return False
        except ValueError:
            return False
        if not os.path.isdir(profile_root):
            self._online_profile_diagnostic = (
                "В перенаправленном профиле не найден каталог "
                f"{os.path.relpath(profile_root, portable_dir)}. "
                "Проверяйте, не развернул ли установщик Fusion в настоящий "
                "LOCALAPPDATA этого компьютера."
                + self._host_online_profile_note(parts, portable_dir)
            )
            return False

        portable_prefix = os.path.relpath(profile_root, portable_dir).replace(
            "\\", "/")
        entrypoint_names = tuple(
            name.casefold() for name in
            (getattr(product, "entrypoint_exe_names", ()) or ()))
        if entrypoint_names:
            launcher_candidates: List[Tuple[str, str]] = []
            invalid_configs: List[str] = []
            for root, _dirs, files in os.walk(profile_root):
                for filename in sorted(files, key=str.casefold):
                    if filename.casefold() not in entrypoint_names:
                        continue
                    launcher_path = os.path.join(root, filename)
                    try:
                        if (os.path.getsize(launcher_path) < 128 * 1024
                                or not read_pe_info(launcher_path).is_pe):
                            invalid_configs.append(
                                f"{os.path.relpath(launcher_path, profile_root)}: "
                                "launcher EXE неполный или не является PE")
                            continue
                    except OSError as exc:
                        invalid_configs.append(
                            f"{os.path.relpath(launcher_path, profile_root)}: {exc}")
                        continue
                    app_exe, why_invalid = self._validate_fusion_launcher_ini(
                        launcher_path, profile_root,
                        os.path.join(data_abs, "AppData", "Local"))
                    if app_exe:
                        launcher_candidates.append((launcher_path, app_exe))
                    elif why_invalid:
                        invalid_configs.append(
                            f"{os.path.relpath(launcher_path, profile_root)}: "
                            f"{why_invalid}")

            if launcher_candidates:
                launcher_path, app_exe = max(
                    launcher_candidates,
                    key=lambda item: os.path.getmtime(item[0] + ".ini"))
                selected_rel = os.path.relpath(
                    launcher_path, portable_dir).replace("\\", "/")
                selected = launcher_mod.TargetInfo(
                    name=os.path.basename(launcher_path),
                    rel_path=selected_rel,
                    role="main",
                    description=(
                        "Autodesk Fusion через настроенный FusionLauncher "
                        "из перенаправленного webdeploy-профиля"),
                    bat_name="Launch.bat",
                    vbs_name="LaunchHidden.vbs",
                )
                self._online_profile_main_exe = launcher_path
                self._online_profile_targets = [selected]
                self._online_profile_diagnostic = ""
                self.log.ok(
                    "Настроенный FusionLauncher найден: "
                    f"{selected.rel_path}; его INI указывает на существующий "
                    f"Fusion app-exe: "
                    f"{os.path.relpath(app_exe, profile_root)}."
                )
                return True

            if not invalid_configs:
                invalid_configs.append(
                    "FusionLauncher.exe в webdeploy-профиле не найден")
            details = "; ".join(invalid_configs[:3])
            self._online_profile_diagnostic = (
                "Fusion webdeploy найден, но установка не сконфигурирована "
                "для запуска: " + details + ". Не выбираю FusionDocTest.exe "
                "или другой вспомогательный EXE вместо настоящей точки входа. "
                "Проверьте завершение Autodesk Streamer и [Launcher]/cmd в "
                "FusionLauncher.exe.ini; cmd должен указывать на существующий "
                "Fusion app-exe внутри production."
                + self._host_online_profile_note(parts, portable_dir)
            )
            self.log.warn(self._online_profile_diagnostic)
            return False

        main_exe, targets = self._discover_app_executables(
            profile_root, getattr(product, "name", app_name),
            portable_prefix=portable_prefix)
        eligible: List[launcher_mod.TargetInfo] = []
        for target in targets:
            if target.role not in ("main", "launcher"):
                continue
            candidate = os.path.join(
                portable_dir, target.rel_path.replace("/", os.sep))
            try:
                if (os.path.getsize(candidate) >= 128 * 1024
                        and read_pe_info(candidate).is_pe):
                    eligible.append(target)
            except OSError:
                continue
        if main_exe and eligible:
            selected = eligible[0]
            self._online_profile_main_exe = os.path.join(
                portable_dir, selected.rel_path.replace("/", os.sep))
            self._online_profile_targets = [launcher_mod.TargetInfo(
                name=selected.name,
                rel_path=selected.rel_path,
                role="main",
                description="Autodesk Fusion из перенаправленного webdeploy-профиля",
                bat_name="Launch.bat",
                vbs_name="LaunchHidden.vbs",
            )]
            self._online_profile_diagnostic = ""
            self.log.ok(
                "Клиент Autodesk найден в перенаправленном LOCALAPPDATA: "
                f"{selected.rel_path}. Запускаю его с исходного webdeploy-пути, "
                "не копируя 5+ ГБ в App."
            )
            return True

        self._online_profile_diagnostic = (
            "Каталог перенаправленного webdeploy найден, но подходящий "
            "exe приложения не найден; путь "
            f"{os.path.relpath(profile_root, portable_dir)}."
            + self._host_online_profile_note(parts, portable_dir)
        )
        return False

    def _log_language_choice(self, det, opts: PortableOptions) -> None:
        """Пишет в журнал, какой язык установщика будет выбран и как."""
        if not opts.install_language.strip():
            self.log.info("Язык установщика: по умолчанию (как в самом "
                          "установщике).")
            return
        if getattr(det, "is_adobe_hd", False):
            # Adobe принимает локаль в виде ru_RU/en_US, а не имя языка Inno.
            locale = adobe_mod.language_locale(opts.install_language)
            if locale:
                self.log.ok(
                    f"Язык установки Adobe: {opts.install_language} "
                    f"(ключ --INSTALLLANGUAGE={locale}).")
            else:
                self.log.warn(
                    f"Язык «{opts.install_language}» не поддерживается "
                    "Portablizer — установщик Adobe выполнится с языком по "
                    "умолчанию.")
            return
        plan = plan_language(
            det.installer_type, opts.install_language,
            opts.extra_install_args,
            is_gog=bool(getattr(det, "is_gog", False)),
            inno_language_names=list(
                getattr(det, "inno_language_names", ()) or ()),
        )
        if plan.level == "warn":
            self.log.warn(plan.message)
        else:
            self.log.ok(plan.message)
        if getattr(det, "is_gog", False) and opts.install_language.strip():
            self.log.info(
                "GOG-установщик: язык мастера и язык игры — разные вещи. "
                "После установки выбранный язык будет прописан в "
                "goggame-*.info и в ветке GOG.com\\Games, иначе игра "
                "(Sleeping Dogs и другие) останется на английском."
            )

    # -- шаги -----------------------------------------------------------------
    def run(self, opts: PortableOptions) -> PortableResult:
        result = PortableResult(success=False)
        try:
            self.log.info(f"Portablizer {__version__}")
            self._run_started = time.time()
            self._attempts_made = 0
            self._device_prompt_hits = 0
            self._attempt_history = []
            self._installshield_result = None
            self._install_stalled = False
            self._install_stall = None
            self._install_gui_seen = False
            self._install_dead_start = False
            self._dead_start_attempts = 0
            self._install_dialog_titles = []
            # Всё, что относится к диагностике падений и временному месту
            # установщика, начинается заново: один и тот же объект может
            # собирать несколько портативов подряд.
            self._install_temp_dir = ""
            self._external_temp_dirs = []
            self._temp_space_note = ""
            self._crash_history = []
            self._crash_events = []
            self._crash_retried = False
            self._progress_retry_done = False
            self._last_install_seconds = 0.0
            self._unpacker_result = ""
            self._unpacked_with = ""
            self._hollow_note = ""
            self._detection = None
            self._adobe_detected = False
            self._adobe_applied = None
            self._adobe_layout = None
            self._adobe_source = ""
            self._adobe_salvage_attempted = False
            self._adobe_failure = None
            self._adobe_note_rel = ""
            self._adobe_nested_setup = ""
            self._adobe_steps = []
            self._adobe_report_rel = ""
            self._stop_adobe_watcher()
            self._drop_adobe_media_copy()
            self._adobe_media_copy = ""
            self._adobe_media_dir = ""
            self._online_profile_main_exe = ""
            self._online_profile_checked = False
            self._online_profile_deferred = False
            self._online_profile_targets = []
            self._online_profile_diagnostic = ""
            self._recovered_sources = []
            self._installer_name = opts.installer_path
            # Жалоба: в C:\Users\<user> накапливались Portablizer-*-Temp / _MEI*
            # от аварийных завершений предыдущих запусков. Убираем их сразу,
            # до любой новой работы с TEMP — иначе их будет всё больше.
            try:
                removed = _cleanup_stale_temp_dirs(self.log)
                if removed:
                    self.log.info(
                        "Убрано брошенных временных каталогов прошлых "
                        f"запусков: {len(removed)}.")
            except Exception:  # noqa: BLE001 - уборка не срывает сборку
                pass
            self.progress(2, "Проверка входных данных")
            if not os.path.isfile(opts.installer_path):
                raise FileNotFoundError(f"Установщик не найден: {opts.installer_path}")

            name = self._safe_name(opts)
            # normpath убирает «смешанные» пути вида E:/Portable\App (QFileDialog
            # нередко отдаёт прямые слеши): единый синтаксис важен и для журнала,
            # и для подстановки маркера в захваченный реестр.
            portable_dir = os.path.normpath(
                os.path.join(opts.output_dir, f"{name}_Portable"))
            app_dir = os.path.join(portable_dir, "App")
            data_dir = os.path.join(portable_dir, "PortableData")
            result.portable_dir = portable_dir
            self.log.info(f"Портативная папка: {portable_dir}")

            # 1. Определение типа установщика
            self._check_cancel()
            self.progress(8, "Определение типа установщика")
            det = detect_installer(opts.installer_path)
            result.detection = det
            self._detection = det
            # Adobe: даже если движок опознан иначе (оболочка пакета — обычный
            # самораспаковывающийся архив), имя файла и раскладка payloads
            # говорят, что это Adobe. Тогда имеет смысл забирать пакеты из
            # adobeTemp после отказа и объяснять код 191 по-человечески.
            self._adobe_detected = bool(det.is_adobe_hd or det.adobe_named)
            self.log.ok(f"Тип установщика: {det.human}")
            for e in det.evidence:
                self.log.debug(f"  • {e}")
            self._warn_downloader_stub(det)

            # Не очищаем старую сборку, пока не закончилось распознавание:
            # анализ повреждённого/неподдерживаемого установщика не должен
            # удалять уже имеющийся App и запускатели.
            self._prepare_output(portable_dir, app_dir, data_dir)

            if IS_WINDOWS:
                self.log.warn(
                    "Важно: сторонний установщик запускается без полной "
                    "виртуализации — Portablizer не является песочницей. "
                    "Перенаправление профиля не блокирует изменения реестра, "
                    "служб, драйверов, ассоциаций, активации Windows/Office "
                    "или Edge/WebView2. Portablizer не может надёжно отменить "
                    "неизвестные изменения установщика; для недоверенного "
                    "файла остановитесь и используйте Windows Sandbox или VM.")

            # 1b. Предупреждаем о нехватке прав ДО запуска: установщик с
            # requireAdministrator без повышения просто не стартует.
            if IS_WINDOWS and det.requires_admin and not is_elevated():
                self.log.warn(
                    "Установщик требует прав администратора "
                    "(requireAdministrator в манифесте), а Portablizer запущен "
                    "без повышения. Тихая установка, скорее всего, завершится "
                    "кодом -1. Закройте программу и запустите её «от имени "
                    "администратора»."
                )

            # 1c. Классический InstallShield: подготовка файла ответов.
            response_file = self._prepare_response_file(
                det, portable_dir, app_dir, opts)

            # 1d. Временное место установщика. Проверяется ДО первой команды
            # установки: большие (особенно GOG) распаковывают данные в TEMP, и
            # нехватка места проявляется не отказом, а падением установщика.
            self._check_cancel()
            self.progress(12, "Проверка места под распаковку")
            self._prepare_install_temp(opts, portable_dir, data_dir, det)

            # 2. Лестница планов тихой установки
            self.progress(15, "Построение команды тихой установки")
            self._log_language_choice(det, opts)
            attempts = build_attempts(
                det, opts.installer_path, app_dir,
                log_dir=portable_dir,
                extra_args=opts.extra_install_args,
                layout_dir=os.path.join(portable_dir, "_bundle_layout"),
                response_file=response_file,
                allow_assisted=opts.allow_assisted_install,
                language=opts.install_language,
                adobe_layout_dir=os.path.join(portable_dir, "_adobe_payloads"),
            )
            if det.is_adobe_hd:
                self.log.info(
                    "Adobe HyperDrive ставит программу в два этапа: пакеты "
                    "MSI и UWP-пакет (Appx). Второй шаг падает с «кодом "
                    "ошибки 191» и отменяет установку целиком. Для портатива "
                    "он не нужен: пакеты программы раскладываются в App, а "
                    "UWP пропускается."
                )
            result.plan = attempts[0] if attempts else None
            result.attempts_planned = len(attempts)
            self.log.info(f"Команда: {attempts[0].display()}")
            for n in attempts[0].notes:
                self.log.debug(f"  • {n}")
            if len(attempts) > 1:
                self.log.info(
                    f"Подготовлено запасных сценариев установки: "
                    f"{len(attempts) - 1}. Они запустятся автоматически, если "
                    "основной не даст файлов."
                )
                for extra_plan in attempts[1:]:
                    self.log.debug(f"  • запасной: {extra_plan.label}")
            if self._container_first_worth_trying(det):
                self.log.info(
                    "Этот файл — контейнер (самораспаковывающийся архив). "
                    "Сначала Portablizer достанет его содержимое, не выполняя "
                    "код обёртки, и поставит установщик изнутри его "
                    "собственными ключами; команды выше — запасной вариант, "
                    "если содержимое достать не удастся."
                )

            # 3. Снимок реестра ДО
            # Профиль чужого пользователя (UAC с вводом чужих учётных данных)
            # не снимаем: его настройки оболочки нельзя приносить в портатив,
            # иначе у пользователя «слетает» меню «Пуск» Windows 11.
            switched_user = elevate_mod.switched_user_warning()
            if switched_user:
                self.log.warn(switched_user)
            before = {}
            if opts.capture_registry and IS_WINDOWS:
                self.progress(22, "Снимок реестра (до установки)")
                self.log.info("Делаю снимок реестра до установки...")
                before = reg_mod.snapshot(include_user=not switched_user)
                self.log.debug(f"  зафиксировано веток: {len(before)}")
            elif opts.capture_registry and not IS_WINDOWS:
                self.log.warn("Захват реестра доступен только на Windows — пропускаю.")

            # Запоминаем содержимое типовых каталогов установки. Некоторые
            # установщики игнорируют /DIR и пишут в LocalAppData/Program Files;
            # после завершения попробуем безопасно перенести созданный каталог.
            install_locations_before = self._snapshot_install_locations(data_dir)
            # Ярлыки. Запоминаем, что уже лежало на рабочем столе и в меню
            # «Пуск» ДО установщика: после сборки убираются только файлы,
            # появившиеся за время установки и ведущие внутрь портатива.
            # Ярлык пользователя (даже указывающий на эту же программу)
            # остаётся нетронутым — его нельзя отличить от «нашего» иначе.
            # Причина уборки: ярлык установщика содержит статичный абсолютный
            # путь, поэтому после переноса папки на другой диск он ведёт в
            # старое место (жалоба: «ярлык остался и указывает не туда»).
            shortcut_guard = shortcuts_mod.ShortcutGuard(
                portable_dir,
                app_names=shortcuts_mod.app_name_candidates(
                    name, opts.installer_path, os.path.basename(portable_dir)))
            shortcut_guard.snapshot()

            # 3b. Тихая установка предусловий (vcredist, DirectX, OpenAL,
            # PhysX…) — только отдельное opt-in: она меняет систему.
            # Без него пакеты остаются на усмотрение основного установщика;
            # он может показать собственные окна.
            self._check_cancel()
            self.progress(26, "Распространяемые компоненты")
            # IFEO-перехват DXSETUP меняет системный реестр, пусть и
            # временно. Включаем его только вместе с явным opt-in на тихую
            # установку runtime; по умолчанию вложенный установщик остаётся
            # видимым и Portablizer не трогает IFEO.
            dx_guard = None
            if opts.bundle_runtimes and opts.silent_runtime_install:
                dx_guard = redist_mod.DxsetupSilentGuard(log=self.log)
                dx_guard.install()
            install_rc, used_plan = None, None
            try:
                self._install_prerequisites(opts, result)

                # 4. Тихая установка: идём по лестнице попыток, пока не
                # появится запускаемый клиент в App или известном профиле.
                # Снимок реестра «после» делается ниже — он накрывает все
                # попытки сразу.
                self._check_cancel()
                self.progress(30, "Тихая установка в изолированном режиме")

                def recover() -> bool:
                    """Забрать программу из каталога по умолчанию прямо в ходе
                    лестницы: движки, которые не принимают целевую папку
                    (InstallScript), иначе выглядели бы как неудача, и
                    Portablizer запускал бы следующий сценарий поверх уже
                    установленной программы."""
                    return self._recover_installed_app(
                        app_dir=app_dir, data_dir=data_dir, app_name=name,
                        installer_path=opts.installer_path,
                        before=install_locations_before,
                        shortcut_locations=shortcut_guard.created_targets(),
                    )

                # Самораспаковывающийся архив ставится не «ключами», а
                # содержимым: сначала достаём его без запуска обёртки, потом
                # ставим установщик изнутри (или переносим файлы в App).
                # Только если это не удалось — обычная лестница ключей.
                container = self._run_container_first(
                    opts, app_dir, data_dir, portable_dir, det, name,
                    recover=recover)
                if container is not None:
                    install_rc, used_plan = container
                    if used_plan is not None:
                        self._attempts_made += 1
                        self._attempt_history.append(
                            (used_plan.label, install_rc))
                else:
                    install_rc, used_plan = self._run_attempts(
                        attempts, opts, app_dir, data_dir, portable_dir, name,
                        recover=recover)
            finally:
                if dx_guard is not None:
                    dx_guard.remove()
            # Лестница закончилась на 58 %, а следующий этап ниже сам по себе
            # полосу не двигает (закрытие процессов, распаковка без запуска).
            # Честно подписываем переход, иначе выглядит как зависание.
            self._check_cancel()
            self.progress(59, "Проверка результата установки")
            result.attempts_made = self._attempts_made
            if used_plan is not None:
                result.plan = used_plan
                result.successful_attempt = used_plan.label

            # Установщик мог закончить галочкой «Запустить программу сейчас»
            # или оставить свой фоновый помощник. Закрываем их ДО снимка
            # реестра: так программа успевает записать свои настройки (они
            # уедут в портатив), а файлы App перестают быть занятыми.
            self._release_after_install(
                det, opts, data_dir, portable_dir, name)
            # Ярлыки, которые установщик успел положить на рабочий стол или в
            # меню «Пуск», убираются сразу после установки: до того, как
            # Portablizer начнёт проверять результат и создавать лончер.
            # sweep убирает и «пустые» ярлыки этой программы.
            for src_root in self._recovered_sources:
                if src_root and src_root not in shortcut_guard.extra_roots:
                    shortcut_guard.extra_roots.append(src_root)
            self._report_own_shortcuts(shortcut_guard, sweep=True)

            # 4b. Установщик не отдал файлы ни одной командой. Последний
            # honest-шанс: распаковать приклеенный к exe ZIP — так устроены
            # многие современные bootstrapper'ы, и это не требует ни прав
            # администратора, ни изменения системы.
            if (not self._find_main_exe(app_dir, name) and det.has_zip_payload
                    and not self._adobe_detected):
                # У Adobe приклеенный архив — это весь пакет (payloads, MSI,
                # Appx). Вываливать его содержимое в App нельзя: пакеты
                # ставятся отдельно, а не копируются как файлы.
                self._check_cancel()
                self.progress(62, "Распаковка вложенного архива установщика")
                self._extract_zip_payload(opts.installer_path, app_dir, name)

            # 4c. Последний честный шанс для падающего установщика: достать
            # его содержимое БЕЗ запуска (Inno Setup и NSIS — обычные
            # контейнеры, и установленный 7-Zip читает их напрямую). Код
            # установщика при этом не выполняется вовсе — он и не падает.
            if not self._find_main_exe(app_dir, name):
                self._try_unpacker_fallback(opts, app_dir, portable_dir, det,
                                            name)

            # 5. Снимок реестра ПОСЛЕ + поиск файлов + diff
            after: reg_mod.Snapshot = {}
            capture = None
            if opts.capture_registry and IS_WINDOWS:
                self._check_cancel()
                self.progress(65, "Снимок реестра (после установки)")
                self.log.info("Делаю снимок реестра после установки...")
                after = reg_mod.snapshot(include_user=not switched_user)

            app_names_for_reg = sorted(
                set(shortcuts_mod.app_name_candidates(name, opts.installer_path))
                | self._name_keys(name, opts.installer_path)
            )
            source_roots_for_reg = [
                os.path.dirname(os.path.abspath(opts.installer_path)),
                *self._recovered_sources,
            ]
            registry_locations = (
                reg_mod.changed_install_locations(
                    before, after,
                    app_names=app_names_for_reg,
                    source_roots=source_roots_for_reg,
                )
                if after else []
            )

            # Если установщик не послушался целевого пути, ищем его результат
            # в перенаправленном профиле и в новых каталогах Program Files.
            if not self._find_main_exe(app_dir, name):
                self.progress(72, "Поиск файлов, созданных установщиком")
                online_product = getattr(det, "online_product", None)
                if (getattr(det, "is_downloader_stub", False) is True
                        and online_product is not None):
                    profile_found = bool(self._online_profile_main_exe)
                    if (not profile_found
                            and (not self._online_profile_checked
                                 or self._online_profile_deferred)):
                        profile_found = self._discover_online_profile_payload(
                            opts, data_dir, portable_dir, name)
                        self._online_profile_deferred = False
                    if profile_found:
                        self.log.warn(
                            f"{online_product.name} найден в изолированном "
                            "LOCALAPPDATA внутри PortableData. Не копирую "
                            "webdeploy в App: сохранены исходная структура и "
                            "путь для обновлений; вход и лицензия Autodesk "
                            "всё ещё могут ограничить переносимость."
                        )
                    else:
                        self.log.warn(
                            f"Не копирую {online_product.name} из профиля "
                            "Windows в App: это сетевой webdeploy-клиент, а "
                            "не подтверждённый автономный установщик. "
                            "Проверен только изолированный PortableData; "
                            "системный профиль не переносится автоматически."
                        )
                else:
                    recovered = self._recover_installed_app(
                        app_dir=app_dir,
                        data_dir=data_dir,
                        app_name=name,
                        installer_path=opts.installer_path,
                        before=install_locations_before,
                        registry_locations=registry_locations,
                        shortcut_locations=shortcut_guard.created_targets(),
                    )
                    if recovered:
                        self.log.ok("Файлы программы перенесены в папку App.")
            elif registry_locations:
                self._supplement_recovered_from_registry(
                    app_dir=app_dir,
                    app_name=name,
                    installer_path=opts.installer_path,
                    registry_locations=registry_locations,
                )

            # 5b. Бросовые каталоги из Program Files: даже если recovery
            # забрал файлы в App, оригинал в Program Files может остаться
            # (не совпало имя, не удалился из-за прав). Удаляем только
            # каталоги, имя которых совпадает с приложением.
            if self._find_main_exe(app_dir, name):
                leftover = self._cleanup_leftover_install_dirs(
                    name, opts.installer_path, opts, data_dir,
                    before=install_locations_before, app_dir=app_dir)
                if leftover:
                    self.log.ok(
                        f"Удалено {len(leftover)} брошенных каталог(ов) "
                        "установки из Program Files/профилей.")
                self._relocate_drive_root_app_folders(
                    portable_dir=portable_dir,
                    app_dir=app_dir,
                    app_name=name,
                    installer_path=opts.installer_path,
                    registry_locations=registry_locations,
                )
                for src_root in self._recovered_sources:
                    if src_root and src_root not in shortcut_guard.extra_roots:
                        shortcut_guard.extra_roots.append(src_root)
                self._report_own_shortcuts(shortcut_guard, sweep=True)

            if opts.capture_registry and (IS_WINDOWS or opts.install_language.strip()):
                capture = self._capture_registry(
                    portable_dir, before, after, opts,
                )
                result.reg_file = capture.reg_file
                result.registry_keys = capture.keys
                result.installed_entries_detected = capture.uninstall_entries
            elif opts.install_language.strip():
                updated_inis = reg_mod.apply_language_to_ini_files(
                    app_dir, opts.install_language)
                if updated_inis:
                    lang_obj = find_language(opts.install_language)
                    lang_title = lang_obj.title if lang_obj else opts.install_language
                    self.log.ok(
                        f"Язык «{lang_title}» прописан в настройках: "
                        f"{', '.join(updated_inis)}."
                    )

            # 6. Поиск главного exe и обнаружение всех вспомогательных программ
            self._check_cancel()
            self.progress(75, "Поиск главного исполняемого файла и лаунчеров")
            online_product = getattr(det, "online_product", None)
            profile_only_product = bool(
                getattr(det, "is_downloader_stub", False)
                and online_product is not None
                and getattr(online_product, "entrypoint_exe_names", ()))
            if profile_only_product:
                # Не разрешать общий PE-скоринг выбрать FusionDocTest.exe
                # или bootstrapper из App, если webdeploy не сконфигурирован.
                main_exe, targets = "", []
            else:
                main_exe, targets = self._discover_app_executables(app_dir, name)
            runtime_app_dir = app_dir
            if not main_exe and self._online_profile_main_exe:
                if os.path.isfile(self._online_profile_main_exe):
                    main_exe = self._online_profile_main_exe
                    targets = list(self._online_profile_targets)
                    # Сканируем зависимости только рядом с выбранным launcher,
                    # а не тысячи вспомогательных EXE во всём webdeploy.
                    runtime_app_dir = os.path.dirname(main_exe)
                    self.log.warn(
                        "Исполняемый файл находится в перенаправленном "
                        "LOCALAPPDATA внутри PortableData; launcher будет "
                        "запускать его непосредственно оттуда."
                    )
            if not main_exe:
                result.hints = self._failure_hints(det, install_rc, opts,
                                                   portable_dir)
                result.attempt_outcomes = list(self._attempt_history)
                raise RuntimeError(
                    self._failure_message(det, install_rc, result))
            result.targets = targets
            result.main_exe_rel = os.path.relpath(main_exe, portable_dir)
            self.log.ok(f"Главный exe: {result.main_exe_rel}")

            for t in targets:
                if t.role == "launcher":
                    result.launcher_exe_rel = os.path.relpath(
                        os.path.join(portable_dir, t.rel_path), portable_dir)
                elif t.role == "config":
                    result.config_exe_rel = os.path.relpath(
                        os.path.join(portable_dir, t.rel_path), portable_dir)

            # 7. Распространяемые компоненты: VC++, DirectX и прочее, чего на
            # чужом ПК может не оказаться.
            self._check_cancel()
            self.progress(82, "Распространяемые компоненты (VC++, DirectX)")
            runtime_report = self._provision_runtimes(
                runtime_app_dir, portable_dir, opts, name, result,
                main_exe=main_exe, targets=targets)

            # 7b. Зависимости и переменные среды
            self.progress(87, "Учёт зависимостей и переменных среды")
            path_prepend = self._collect_dep_dirs(runtime_app_dir, portable_dir)

            # 7в. Сквозные сохранения: один набор сейвов для прямого запуска
            # exe, лончера и комплектного launcher'а.
            self._check_cancel()
            self.progress(90, "Сквозные портативные сохранения")
            save_setup = self._setup_shared_saves(
                portable_dir, runtime_app_dir, name, targets, opts, result)

            # 7г. Сетевые компоненты: драйверы (TAP-Windows и т. п.) и
            # службы-компаньоны, которые нельзя виртуализовать, уезжают в
            # NetStack/ и на целевом ПК досоздаются лончером. Делается ДО
            # записи лончера (секция netstack в конфиге).
            self._check_cancel()
            self.progress(91, "Сетевые компоненты (драйверы TAP, службы)")
            netstack_report = self._provision_netstack(
                portable_dir, runtime_app_dir, opts, result)

            # 8. Генерация лончера и вспомогательных скриптов
            self._check_cancel()
            self.progress(92, "Генерация портативного лончера и меню")
            companion_files = self._write_launcher(
                portable_dir, name, result.main_exe_rel,
                opts, path_prepend, capture, targets,
                runtime_report=runtime_report, save_setup=save_setup,
                netstack_report=netstack_report)
            result.companion_launchers = companion_files
            online_product = getattr(det, "online_product", None)
            if (getattr(det, "is_downloader_stub", False) is True
                    and online_product is not None):
                profile_location = (
                    result.main_exe_rel.replace("\\", "/")
                    if result.main_exe_rel.startswith("PortableData") else ""
                )
                location_note = (
                    "Клиент запускается прямо из перенаправленного "
                    f"LOCALAPPDATA ({profile_location}), без копирования "
                    "5+ ГБ в App. "
                    if profile_location else ""
                )
                update_note = (
                    "UpdatePortable.cmd намеренно отключён; штатное "
                    "обновление Autodesk не проверено. "
                    if profile_location else ""
                )
                portability_note = (
                    f"{online_product.name}: {location_note}{update_note}"
                    "автономная работа на другом ПК не подтверждена. "
                    f"{online_product.reason}. Для запуска может потребоваться "
                    "интернет, вход в Autodesk-аккаунт и действующая лицензия; "
                    "Autodesk может обновить клиент или потребовать "
                    "компоненты вне портатива. Проверьте на отдельном ПК — "
                    "этот результат не является гарантией автономного portable."
                )
                result.hints.append(portability_note)
                self.log.warn(portability_note)
                readme_path = os.path.join(
                    portable_dir, "README_PORTABLE.txt")
                try:
                    with open(readme_path, "r", encoding="utf-8") as readme:
                        readme_text = readme.read()
                    readme_text = readme_text.replace(
                        f"{name} — портативная версия",
                        f"{name} — переносимость не подтверждена", 1)
                    self._write_text(
                        readme_path,
                        readme_text.rstrip() +
                        "\n\nВАЖНОЕ ОГРАНИЧЕНИЕ ДЛЯ ОНЛАЙН-ПРОДУКТА\n"
                        + portability_note + "\n",
                    )
                except OSError as exc:
                    self.log.warn(
                        f"Не удалось записать ограничение в README: {exc}")
            exe_launcher = os.path.join(
                portable_dir, "App", APP_EXE_LAUNCHER_NAME)
            if os.path.isfile(exe_launcher):
                result.portable_launcher_exe_rel = os.path.relpath(
                    exe_launcher, portable_dir)

            # 8б. Относительные пути: корень портатива запоминается, текстовые
            # файлы проверяются, отчёт объясняет, что произойдёт при переносе
            # папки на другой диск.
            self._check_cancel()
            self.progress(94, "Относительные пути и перенос между дисками")
            result.portability_report_rel = self._make_paths_relative(
                portable_dir, name, opts, result)

            # 9. Только безопасная уборка, выбранная пользователем:
            # не откатываем произвольный реестр и не трогаем чужие ярлыки,
            # службы и закрепления. Свои ярлыки (созданные установщиком в
            # этой сборке) уже убраны; повторная проверка ловит те, что
            # появились при автоматическом запуске программы установщиком.
            self.progress(97, "Проверка изменений на этом ПК")
            self._report_own_shortcuts(shortcut_guard, sweep=True)
            self._report_portable_services(portable_dir, result)
            if capture is not None:
                self._cleanup_host(capture, opts, result)

            # 10. Папка результата должна быть свободна: её сразу копируют
            # на флешку, переносят и удаляют. Ничего запущенного из неё
            # оставаться не должно.
            self.progress(99, "Освобождение папки результата")
            self._release_portable_dir(portable_dir, reason="перед выдачей")
            result.folder_is_free = self._verify_folder_is_free(
                portable_dir, result)

            self.progress(100, "Готово")
            self.log.ok("Портативное приложение успешно создано!")
            result.success = True
            self._fill_temp_fields(result, portable_dir)
            self._save_run_log(result.portable_dir)
            return result

        except Exception as exc:  # noqa: BLE001
            self.log.error(str(exc))
            result.messages.append(str(exc))
            self._fill_temp_fields(result, result.portable_dir)
            self._save_run_log(result.portable_dir)
            return result
        finally:
            # Временные папки вне портатива (если установщику не хватило
            # места на диске портатива и его TEMP перенесли) убираются в
            # любом случае: на компьютере пользователя не должно оставаться
            # ни гигабайта мусора, ни после успеха, ни после ошибки.
            self._cleanup_install_temp()

    # -- классический InstallShield ------------------------------------------
    def _record_command(self, det: DetectionResult, opts: PortableOptions,
                        portable_dir: str) -> str:
        """Готовая команда записи файла ответов — её можно скопировать в cmd.

        Куда писать setup.iss, зависит от носителя: рядом с установщиком —
        удобнее всего (Portablizer найдёт файл при любой сборке), но диск
        может быть только для чтения; тогда предлагаем папку портатива, откуда
        файл подхватится при следующем запуске.
        """
        media = det.media_dir or os.path.dirname(opts.installer_path)
        if media and self._is_writable_dir(media):
            target = os.path.join(media, "setup.iss")
        elif portable_dir:
            target = os.path.join(portable_dir, "setup.iss")
        else:
            target = os.path.join(os.path.expanduser("~"), "setup.iss")
        return f'"{opts.installer_path}" /r /f1"{target}"'

    def _prepare_response_file(self, det: DetectionResult, portable_dir: str,
                               app_dir: str,
                               opts: PortableOptions) -> str:
        """Готовит файл ответов setup.iss для InstallShield InstallScript.

        Тихий режим у этого поколения работает ТОЛЬКО по записанному файлу
        ответов. Если файл лежит рядом с установщиком (так делают многие
        корпоративные раздачи и репаки), Portablizer копирует его в портатив —
        носитель может быть только для чтения — и подменяет в нём путь
        установки на папку ``App``. Тогда программа сразу попадает в портатив,
        а не в ``C:\\Program Files``.
        """
        if det.installer_type != InstallerType.INSTALLSHIELD:
            return ""

        if det.is_legacy_installshield:
            self.log.info(
                "InstallShield InstallScript 5/6: ключ /v этому поколению "
                "неизвестен, целевую папку из командной строки оно не "
                "принимает, а /s требует файл ответов setup.iss."
            )
        if det.media_dir and not self._is_writable_dir(det.media_dir):
            self.log.warn(
                f"Папка установщика доступна только для чтения: "
                f"{det.media_dir}. Старые InstallShield пишут рядом с "
                "setup.exe служебные файлы; журнал и файл ответов перенесены "
                "в папку портатива."
            )

        # Файл ответов, записанный прошлым запуском, ценнее найденного на
        # диске: он снят с ЭТОГО установщика на этой машине. Поэтому
        # _prepare_output его не удаляет, а мы проверяем его первым.
        recorded = os.path.join(portable_dir, "setup.iss")
        source = recorded if os.path.isfile(recorded) else det.response_file
        if not source:
            if det.is_legacy_installshield and not opts.allow_assisted_install:
                self.log.warn(
                    "Файл ответов setup.iss не найден, а без него тихий режим "
                    "этого поколения не работает. Запишите ответы один раз "
                    f"командой {self._record_command(det, opts, portable_dir)} "
                    "и повторите сборку — или включите галочку «Разрешить "
                    "окно мастера установки», и Portablizer сделает это сам."
                )
            return ""

        destination = os.path.join(portable_dir, "setup.iss")
        try:
            with open(source, "rb") as fh:
                raw = fh.read(4 * 1024 * 1024)
            text = _decode_installer_text(raw)
            patched, replaced = retarget_response_file(text, app_dir)
            with open(destination, "wb") as fh:
                fh.write(_encode_installer_text(patched, raw))
        except OSError as exc:
            self.log.warn(f"Не удалось подготовить файл ответов: {exc}")
            return ""

        if os.path.normcase(source) == os.path.normcase(recorded):
            self.log.ok(
                f"Использую файл ответов, записанный прошлым запуском: {source}")
        else:
            self.log.ok(f"Найден файл ответов установщика: {source}")
        if replaced:
            self.log.info(
                f"В копии файла ответов путь установки заменён на папку App "
                f"({replaced} знач.): {app_dir}"
            )
        else:
            self.log.info(
                "В файле ответов нет строки с путём установки — программа "
                "встанет в каталог по умолчанию, и Portablizer перенесёт её "
                "в портатив сам."
            )
        return destination

    @staticmethod
    def _is_writable_dir(path: str) -> bool:
        """Проверяет запись реальной пробой: у CD/ISO атрибуты обманчивы."""
        if not path or not os.path.isdir(path):
            return False
        probe = os.path.join(path, f".portablizer-write-test-{os.getpid()}")
        try:
            with open(probe, "wb"):
                pass
            os.remove(probe)
            return True
        except OSError:
            return False

    def _report_installshield_log(self, plan: SilentPlan) -> Optional[int]:
        """Расшифровывает setup.log InstallShield после попытки установки."""
        code = read_installshield_result(plan.result_log)
        if code is None:
            return None
        hint = _INSTALLSHIELD_RESULT_HINTS.get(code, "неизвестный код")
        message = f"InstallShield записал в setup.log ResultCode={code} — {hint}."
        if code == 0:
            self.log.ok(message)
        else:
            self.log.warn(message)
        self._installshield_result = code
        return code

    # -- диагностика неудачи --------------------------------------------------
    def _failure_hints(self, det: DetectionResult, rc: Optional[int],
                       opts: PortableOptions,
                       portable_dir: str = "") -> List[str]:
        """Формирует конкретные советы вместо общего «смотрите журнал».

        Пользователю бесполезно знать, что «код -1»; ему нужно знать, что
        именно сделать дальше. Подсказки упорядочены по вероятности решения.
        """
        hints: List[str] = []

        # Adobe: «код 191» — это шаг установки UWP-пакета, а не непонятая
        # командная строка. Общие советы про права и ключи тишины здесь
        # уводят в сторону, поэтому диагноз ставится первым.
        if det.is_adobe_hd or self._adobe_detected or self._adobe_failure:
            hints.extend(self._adobe_hints(det, rc, portable_dir))

        if getattr(det, "is_downloader_stub", False) is True:
            product = getattr(det, "online_product", None)
            if product is not None:
                switches = ", ".join(getattr(product, "switches", ()) or ())
                hints.append(
                    f"{product.name} использует сетевой загрузчик и "
                    f"разворачивает клиент не в App. Из этого файла нельзя "
                    f"подтвердить автономный portable. {product.reason}. "
                    f"Ключ {switches or '--quiet'} "
                    "лишь запускает загрузку: нужны доступ к серверам и вход "
                    "в Autodesk-аккаунт; клиент может оставаться привязанным "
                    "к этому ПК и обновляться вне портатива. Надёжный путь — "
                    "официальный полный/автономный дистрибутив или поддерживаемая "
                    "Autodesk процедура развёртывания; не добавляйте --globalinstall."
                )
            else:
                hints.append(
                    "Это небольшой сетевой загрузчик, а не автономный "
                    "дистрибутив: после успешного кода установщика не появилось "
                    "ни одного файла программы. Возьмите полный автономный "
                    "установщик и все части дистрибутива (.bin/.cab), а не "
                    "подбирайте дополнительные ключи тишины."
                )
            if self._online_profile_diagnostic:
                hints.append(self._online_profile_diagnostic)
            if self._hollow_note:
                hints.append(self._hollow_note)
            return hints

        if self._install_stalled:
            hints.extend(self._stall_hints())
        if self._install_dead_start:
            hints.extend(self._dead_start_hints())

        repack = getattr(det, "repack_profile", None)
        if isinstance(repack, RepackProfile):
            keys = ", ".join(
                f"{repack.silent_switch} {key}"
                for _code, key in repack.language_switches) or repack.silent_switch
            hints.append(
                f"Это перепак {repack.name} ({repack.product}). Его скрипт "
                "понимает только документированную команду: "
                f"{keys} и {repack.path_switch}<папка> — ключ пути последним, "
                "без кавычек. Ключи Inno Setup (/VERYSILENT, /DIR=) для него "
                "неизвестны: установщик открывает мастер с выбором языка и "
                "папки. Выберите язык в поле «Язык установки» (или оставьте "
                "«как в установщике» — тогда берётся язык Windows) и повторите "
                "сборку."
            )

        if getattr(self, "_install_gui_seen", False):
            hints.append(
                "Установщик показывал собственный мастер (язык/папка) вместо "
                "тихой установки — значит, переданные ключи ему не подошли. "
                "Portablizer сам отвечал на страницы и вводил папку App, но "
                "если мастер всё равно не продвинулся, посмотрите "
                "installer-output.log: там видно, какая команда и какой код "
                "возврата были у каждого сценария."
            )

        # Падение установщика: свой диагноз и свои шаги. Общие советы про
        # «непонятую командную строку» здесь были бы прямым обманом.
        crash_rc = rc if crash_mod.is_crash_code(rc) else self._last_crash_rc()
        if crash_rc is not None:
            hints.extend(crash_mod.crash_hints(
                crash_rc,
                installer_path=opts.installer_path,
                event=self._crash_events[0] if self._crash_events else None,
                is_gog=bool(getattr(det, "is_gog", False)),
                is_inno=det.installer_type == InstallerType.INNO,
                space_note=self._temp_space_note,
                relocated_to=(", ".join(self._external_temp_dirs)
                              if self._install_temp_dir
                              in self._external_temp_dirs else ""),
                retried=self._crash_retried,
                progress_retry=self._crash_retry_note(),
                suggest_unpacker=(self._unpacker_worth_trying(det)
                                  and not self._unpacked_with
                                  and not self._unpacker_result),
                unpacker_result=self._unpacker_result,
            ))

        needs_admin = det.requires_admin or (
            rc is not None and rc in _BAD_COMMAND_LINE_CODES)
        if IS_WINDOWS and needs_admin and not is_elevated():
            hints.append(
                "Запустите Portablizer от имени администратора — этому "
                "установщику нужны повышенные права (правый клик по "
                "Portablizer.exe → «Запуск от имени администратора»)."
            )

        if det.installer_type == InstallerType.INSTALLSHIELD:
            hints.extend(self._installshield_hints(det, opts, portable_dir))

        if det.installer_type == InstallerType.CUSTOM_CLI or det.has_switch(
                "--accept-license-agreement", "--accept-licenses"):
            url = det.license_url or "https://<сайт разработчика>/terms/"
            hints.append(
                "Установщик принимает собственные ключи. Проверьте в поле "
                "«Доп. аргументы установки» строку вида: "
                f'--silent --accept-license-agreement="{url}"'
            )

        if det.installer_type == InstallerType.UNKNOWN:
            hints.append(
                "Тип установщика распознать не удалось. Узнайте ключи тихой "
                "установки в документации разработчика (часто это /S, "
                "/VERYSILENT, /quiet или --silent) и укажите их в поле "
                "«Доп. аргументы установки»."
            )

        if rc is not None and rc in _BAD_COMMAND_LINE_CODES:
            hints.append(
                "Код -1 обычно означает, что установщик не понял командную "
                "строку: лишний или неизвестный ключ. Попробуйте очистить "
                "поле «Доп. аргументы установки» или указать только ключ "
                "тишины."
            )

        if opts.extra_install_args:
            hints.append(
                "Сейчас передаются ваши аргументы: "
                + " ".join(opts.extra_install_args)
                + ". Если установка не идёт, попробуйте без них."
            )

        if self._device_prompt_hits:
            hints.append(
                "Во время установки Windows спрашивал «Установить "
                "программное обеспечение для данного устройства?» (окно "
                "«Безопасность Windows», драйвер сетевого адаптера TAP) — "
                f"Portablizer подтвердил установку {self._device_prompt_hits} "
                "раз(а). Если сборка остановилась именно на драйвере: "
                "запустите Portablizer от имени администратора и повторите — "
                "для установки системных драйверов нужны повышенные права. "
                "После успешной сборки пакет драйвера переезжает в NetStack\\ "
                "и портатив досоздаёт его сам на любом ПК."
            )

        if det.installer_type == InstallerType.INNO and rc in (7, 8):
            hints.append(
                f"Inno Setup: {_exit_code_hint(rc, InstallerType.INNO)}. "
                "Откройте install.log в папке портатива и найдите сообщение "
                "перед завершением подготовки (PrepareToInstall). "
                "installer-output.log может содержать только команду и код "
                "возврата — точная причина обычно в install.log."
            )
            hints.append(
                "Код подготовки сам по себе не доказывает проблему с "
                "лицензией, ключом /DIR или тихим режимом. Проверьте по "
                "журналу требования установщика: перезагрузку, права, "
                "службы и драйверы. Для VPN системный драйвер или служба "
                "могут требоваться даже при хранении файлов в App; "
                "распаковка файлов не заменяет их установку."
            )
        else:
            hints.append(
                "Если установщик требует аккаунт или лицензию, проверьте "
                "его требования в документации разработчика. Сам код "
                "ошибки не доказывает, что портативная сборка невозможна."
            )
        return hints

    def _stall_hints(self) -> List[str]:
        """Подсказки, когда установка была снята по пределу ожидания.

        Пользователю важно понять две вещи: что установщик не «сломался», а
        замолчал, и что ожидание можно продлить — для больших игр это штатный
        сценарий, а не ошибка.
        """
        stall = self._install_stall
        hints: List[str] = []
        if stall is not None:
            hints.append(
                f"Установка остановлена по пределу ожидания: сценарий "
                f"«{stall.attempt}» шёл "
                f"{redist_mod.human_duration(stall.elapsed)}, из них "
                f"{redist_mod.human_duration(stall.idle)} — без признаков "
                "работы (записи в App, ввода-вывода установщика, роста его "
                "журнала)."
                + (f" Успело распаковаться: "
                   f"{redist_mod.format_size(stall.written)} "
                   f"в {stall.files} файлах." if stall.files else "")
            )
        hints.append(
            "Если установщик ещё работал (у больших игр вроде BioShock "
            "Infinite установка идёт часами), повторите сборку с более щедрым "
            "ожиданием: поле «Долгие установки» → «Ждать, пока идёт работа, "
            "без предела». Предел относится к паузе без работы, поэтому долгая "
            "установка сама по себе сборку больше не прерывает."
        )
        hints.append(
            "Если пауза в самом деле была зависанием, посмотрите "
            "installer-output.log и журнал установщика (install.log): чаще "
            "всего движок показал модальное окно (не тот ключ тишины, "
            "требование перезагрузки, нехватка места) и ждал нажатия кнопки."
        )
        return hints

    def _dead_start_hints(self) -> List[str]:
        """Подсказки, когда установщик не начал работу вовсе.

        Это не «долго идёт» и не «зависло на середине»: процесс не прочитал
        ни байта и не создал ни одного файла. Совет «подождите ещё» здесь
        прямо вреден — он и приводил к часам ожидания на пустом месте.
        """
        stall = self._install_stall
        hints: List[str] = []
        if stall is not None:
            hints.append(
                "Установщик был снят как «не начавший работу»: сценарий "
                f"«{stall.attempt}» шёл {redist_mod.human_duration(stall.elapsed)}, "
                "и за это время не появилось ни прочитанных байт, ни файлов "
                "в App, ни процессорного времени. Это не медленная "
                "распаковка — процесс стоял на внешнем препятствии."
            )
        for title in self._install_dialog_titles[:3]:
            hints.append(
                f"Установщик показывал окно «{title}». Обёртка "
                "самораспаковывающегося архива часто не понимает ключи "
                "тишины (/S, /VERYSILENT) и сообщает об этом окном, которое "
                "ждёт нажатия ОК."
            )
        hints.append(
            "Проверьте по порядку: 1) запрос UAC — подтвердите его; "
            "2) исключения антивируса — добавьте установщик и папку "
            "портатива; 3) запустите Portablizer от имени администратора. "
            "Если ни то, ни другое не помогло, самораспаковывающийся архив "
            "не понимает ключей вовсе: Portablizer сам достаёт его "
            "содержимое распаковщиком (7-Zip, WinRAR или встроенный tar.exe "
            "Windows) — установите любой из них и повторите сборку."
        )
        return hints

    def _installshield_hints(self, det: DetectionResult,
                             opts: PortableOptions,
                             portable_dir: str = "") -> List[str]:
        """Советы для InstallShield — с учётом поколения и setup.log."""
        hints: List[str] = []
        record_cmd = self._record_command(det, opts, portable_dir)

        code = self._installshield_result
        if code is not None and code != 0:
            hint = _INSTALLSHIELD_RESULT_HINTS.get(code, "неизвестный код")
            hints.append(
                f"Сам InstallShield записал в setup.log ResultCode={code} — "
                f"{hint}. Это точная причина отказа, а не догадка."
            )

        if det.is_legacy_installshield or code in (-3, -5, -12):
            if det.response_file:
                hints.append(
                    "Файл ответов найден, но установщику он не подошёл "
                    f"({det.response_file}). Файл ответов записывается для "
                    "конкретной версии установщика: перезапишите его на этом "
                    f"же ПК командой {record_cmd} и повторите сборку."
                )
            else:
                hints.append(
                    "Это InstallShield InstallScript 5/6 (диски и программы "
                    "1998–2002 годов). Тихая установка у него возможна только "
                    "по записанному файлу ответов: выполните один раз "
                    f"{record_cmd}, пройдите мастер — и повторите сборку, "
                    "Portablizer подхватит setup.iss автоматически."
                )
            if not opts.allow_assisted_install:
                hints.append(
                    "Либо включите галочку «Разрешить окно мастера "
                    "установки»: Portablizer сам запустит мастер в режиме "
                    "записи, сохранит setup.iss в папку портатива и перенесёт "
                    "установленную программу в App."
                )

        if det.media_dir and not self._is_writable_dir(det.media_dir):
            hints.append(
                "Установщик запускается с носителя только для чтения "
                f"({det.media_dir}). Скопируйте весь диск/папку установщика на "
                "жёсткий диск и соберите портатив из копии: старым "
                "InstallShield нужно место рядом с setup.exe."
            )
        return hints

    def _failure_message(self, det: DetectionResult, rc: Optional[int],
                         result: PortableResult) -> str:
        """Итоговое сообщение об ошибке — с расшифровкой кода и советами."""
        if rc is None or rc in (0, 3010):
            rc_hint = ""
        else:
            hint = _exit_code_hint(rc, det.installer_type)
            rc_hint = (
                f" (код установщика: {_format_exit_code(rc)}"
                + (f" — {hint}" if hint else "") + ")"
            )
        tried = result.attempts_made or result.attempts_planned
        attempts_text = (
            f" Испробовано вариантов команды: {tried}." if tried > 1 else ""
        )
        outcomes_text = ""
        if len(result.attempt_outcomes) > 1:
            lines = []
            for label, outcome in result.attempt_outcomes:
                if outcome is None:
                    verdict = "не запускалась"
                elif outcome in (0, 3010):
                    if (getattr(det, "is_downloader_stub", False)
                            and getattr(det, "online_product", None) is not None):
                        verdict = (
                            f"код {outcome}, но запускаемый exe не найден в "
                            "App или перенаправленном профиле"
                        )
                    else:
                        verdict = f"код {outcome}, но файлов в App не появилось"
                elif outcome == redist_mod.TIMEOUT_EXIT_CODE:
                    verdict = ("снят по пределу ожидания — установщик "
                               "перестал подавать признаки работы")
                else:
                    verdict = f"код {_format_exit_code(outcome)}"
                lines.append(f"\n  • «{label}» — {verdict}")
            outcomes_text = "\n\nИтог каждой команды:" + "".join(lines)
        advice = "".join(f"\n  • {h}" for h in result.hints)
        # Если установщик выводил текст (stdout/stderr), он сохранён рядом —
        # там часто написана точная причина отказа.
        output_note = ""
        if result.portable_dir:
            try:
                output_log = os.path.join(result.portable_dir,
                                          "installer-output.log")
                if os.path.getsize(output_log) > 0:
                    output_note = ("\nТекстовый вывод установщика "
                                   "(stdout/stderr) — в installer-output.log.")
            except OSError:
                pass
            try:
                crash_log = os.path.join(result.portable_dir,
                                         crash_mod.CRASH_LOG_NAME)
                if os.path.getsize(crash_log) > 0:
                    output_note += (
                        "\nГде именно упал установщик (модуль, код "
                        f"исключения, состояние TEMP) — в {crash_mod.CRASH_LOG_NAME}."
                    )
            except OSError:
                pass
        kept_text = ""
        if self._install_stalled and self._app_has_payload(
                os.path.join(result.portable_dir, "App")):
            # Неполная установка — не мусор: по ней видно, что именно движок
            # успел распаковать, и с ней же можно запустить проверку вручную.
            kept_text = ("\n\nРаспакованные файлы оставлены в папке App: по "
                         "ним видно, что установщик успел сделать.")
        return (
            "Установщик завершился, но в папке App не найден ни один "
            f"исполняемый файл{rc_hint}.{attempts_text} Портатив не создан."
            + kept_text
            + outcomes_text
            + (f"\n\nЧто можно сделать:{advice}" if advice else "")
            + "\n\nПодробности — в portablizer.log рядом с папкой портатива."
            + output_note
        )

    # -- реестр ---------------------------------------------------------------
    def _capture_registry(self, portable_dir: str,
                          before: "reg_mod.Snapshot",
                          after: "reg_mod.Snapshot",
                          opts: PortableOptions) -> RegistryCapture:
        """Разделяет изменения реестра на «переносим» и «чистим».

        В портатив попадают только настройки самой программы. Записи об
        установке (список «Установленные программы», автозапуск, служба
        Windows Installer) переносить нельзя: иначе портатив «устанавливал»
        бы себя на каждом чужом ПК — ровно то, чего от него не ждут.
        """
        raw_diff = reg_mod.compute_diff(before, after)
        portable_before: reg_mod.Snapshot = {
            k: dict(v) for k, v in before.items()
        }
        portable_after_in: reg_mod.Snapshot = {
            k: dict(v) for k, v in after.items()
        }

        app_dir = os.path.join(portable_dir, "App")
        if opts.install_language.strip():
            applied_regs, touched_keys = reg_mod.apply_language_to_snapshot(
                portable_before, portable_after_in, app_dir,
                opts.install_language,
            )
            updated_inis = reg_mod.apply_language_to_ini_files(
                app_dir, opts.install_language,
            )
            lang_obj = find_language(opts.install_language)
            lang_title = lang_obj.title if lang_obj else opts.install_language
            if applied_regs:
                self.log.ok(
                    f"Применён языковой файл реестра из папки программы "
                    f"({lang_title}): {', '.join(applied_regs)}."
                )
            elif touched_keys:
                self.log.ok(
                    f"Язык «{lang_title}» прописан в захваченных ключах реестра "
                    f"({len(touched_keys)} вет.)."
                )
            if updated_inis:
                self.log.ok(
                    f"Язык «{lang_title}» прописан в настройках: "
                    f"{', '.join(updated_inis)}."
                )

        diff = reg_mod.compute_diff(portable_before, portable_after_in)
        capture = RegistryCapture(diff=diff)

        wanted = [reg_mod.CATEGORY_APP]
        if opts.include_shell_integration:
            wanted.append(reg_mod.CATEGORY_INTEGRATION)
        portable_keys = diff.keys_of(*wanted)
        trace_keys = raw_diff.keys_of(reg_mod.CATEGORY_TRACE)
        skipped_integration = (
            [] if opts.include_shell_integration
            else raw_diff.keys_of(reg_mod.CATEGORY_INTEGRATION)
        )

        safe_app_name = opts.app_name.strip() or self._safe_name(opts)
        app_names = sorted(
            set(shortcuts_mod.app_name_candidates(
                safe_app_name, opts.installer_path))
            | self._name_keys(safe_app_name, opts.installer_path)
        )
        source_roots = [
            *(
                [os.path.dirname(os.path.abspath(opts.installer_path))]
                if opts.installer_path and os.path.dirname(opts.installer_path)
                else []
            ),
            *self._recovered_sources,
        ]
        reused_app_keys: List[str] = []
        if before and not any(
            reg_mod.categorize(k) == reg_mod.CATEGORY_APP
            for k in portable_keys
        ):
            for existing_key in reg_mod.matching_existing_app_keys(
                portable_after_in,
                app_names=app_names,
                source_roots=source_roots,
            ):
                if existing_key not in portable_keys:
                    portable_keys.append(existing_key)
                    reused_app_keys.append(existing_key)

        # URL-протоколы: браузерные глубокие ссылки («Открыть Figma» после
        # входа) должны открывать портативную программу, а не установленную.
        # Переносим их всегда, даже без --shell-integration: это не ассоциация
        # файлов, а часть работы приложения (см. core/registry.py).
        protocol_keys = reg_mod.protocol_keys_of(raw_diff, after)
        for protocol_key in protocol_keys:
            if protocol_key not in portable_keys:
                portable_keys.append(protocol_key)
        skipped_integration = [
            k for k in skipped_integration
            if k not in set(protocol_keys)
        ]

        # Путь портативной папки заменяем маркером: иначе настройки указывали
        # бы на каталог того ПК, где собирали портатив.
        tokens = [(portable_dir, launcher_mod.ROOT_TOKEN)]
        alt = portable_dir.replace("\\", "/")
        if alt != portable_dir:
            tokens.append((alt, launcher_mod.ROOT_TOKEN))

        # Если установщик сначала писал в Program Files, а затем его файлы были
        # перенесены в App, InstallFolder не должен остаться направленным в
        # старый/удалённый каталог. Именно из-за такого значения The Witcher 2
        # запускался напрямую, но Launcher.exe и Configurator.exe считали
        # установку недействительной и сразу закрывались.
        portable_after = reg_mod.retarget_install_paths(
            portable_after_in, portable_keys, app_dir,
            extra_roots=self._recovered_sources,
            portable_dir=portable_dir,
            app_names=app_names,
        )

        # Команды открытия протоколов указывают на установленный каталог
        # этого ПК: без замены «Открыть Figma» в браузере вернёт именно его.
        if protocol_keys:
            portable_after = reg_mod.retarget_protocol_paths(
                portable_after, protocol_keys, app_dir)

        user_keys = [k for k in portable_keys if k.startswith("HKCU")]
        machine_keys = [k for k in portable_keys if k.startswith("HKLM")]
        if machine_keys:
            portable_after, machine_keys = reg_mod.mirror_machine_views(
                portable_after, machine_keys)
            for mk in machine_keys:
                if mk not in portable_keys:
                    portable_keys.append(mk)

        # Виртуализация HKLM-ключей остаётся бесправным fallback. Для программ
        # с manifest (у них Windows отключает VirtualStore) вспомогательные
        # лончеры ниже запросят UAC и временно применят portable_machine.reg.
        virtual_keys: List[str] = []
        if machine_keys:
            after_virtualized, virtual_keys = reg_mod.virtualize_machine_snapshot(
                portable_after, machine_keys)
        else:
            after_virtualized = portable_after

        all_user_keys = sorted(set(user_keys + virtual_keys))

        reg_path = os.path.join(portable_dir, "portable.reg")
        user_text = reg_mod.render_keys(after_virtualized, all_user_keys, tokens)
        if reg_mod.has_entries(user_text):
            reg_mod.write_reg_file(reg_path, user_text)
            capture.reg_file = reg_path

        machine_text = ""
        if machine_keys:
            machine_path = os.path.join(portable_dir, "portable_machine.reg")
            machine_text = reg_mod.render_keys(
                portable_after, machine_keys, tokens)
            if reg_mod.has_entries(machine_text):
                reg_mod.write_reg_file(machine_path, machine_text)
                capture.machine_reg_file = machine_path

        # На сборочном ПК установщик уже записал в реестр хоста сырые пути
        # (например, c:\multitran и исходную папку дистрибутива). Сразу
        # применяем перенаправленные пути в реестр хоста, чтобы первый запуск
        # программы на этом же ПК не читал старый c:\multitran из HKCU/HKLM.
        if IS_WINDOWS and (all_user_keys or machine_keys):
            for snap_view, keys_view in (
                (after_virtualized, all_user_keys),
                (portable_after, machine_keys),
            ):
                if not keys_view:
                    continue
                expanded_text = reg_mod.render_keys(snap_view, keys_view, ())
                if not reg_mod.has_entries(expanded_text):
                    continue
                tmp_reg = ""
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="wb", suffix=".reg", delete=False
                    ) as fh:
                        tmp_reg = fh.name
                    reg_mod.write_reg_file(tmp_reg, expanded_text)
                    subprocess.run(
                        ["reg.exe", "import", tmp_reg],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        timeout=15,
                        check=False,
                    )
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    if tmp_reg:
                        try:
                            os.remove(tmp_reg)
                        except OSError:
                            pass

        capture.has_root_token = (
            launcher_mod.ROOT_TOKEN in user_text
            or launcher_mod.ROOT_TOKEN in machine_text
        )

        all_portable_keys = sorted(set(portable_keys + virtual_keys))
        capture.keys = launcher_mod.consolidate_root_keys(all_portable_keys)
        created_machine = [
            mk for mk in machine_keys
            if mk not in before or mk in set(reused_app_keys)
        ]
        capture.created_keys = launcher_mod.consolidate_root_keys(
            [k for k in diff.new_keys if k in set(portable_keys)]
            + reused_app_keys
            + created_machine
            + virtual_keys
        )

        # Безопасный режим не пытается «вернуть весь реестр как было»:
        # сравнение двух снимков не доказывает, что любое изменение вызвано
        # установщиком, и откат способен затронуть активацию/ассоциации,
        # сделанные параллельно. По явному согласию удаляем только НОВУЮ запись
        # самого приложения, подтверждённую DisplayName и путём в портатив.
        safe_entries = reg_mod.safe_uninstall_entries(
            raw_diff, after,
            app_name=(opts.app_name.strip() or self._safe_name(opts)),
            portable_dir=portable_dir,
        )
        capture.cleanup_keys = [key for key, _display in safe_entries]
        capture.cleanup_entries = [display for _key, display in safe_entries]
        capture.uninstall_entries = [
            name for _key, name
            in reg_mod.installed_program_entries(raw_diff, after)
        ]
        if opts.cleanup_host:
            cleanup_text = reg_mod.render_host_cleanup(
                raw_diff, after,
                app_name=(opts.app_name.strip() or self._safe_name(opts)),
                portable_dir=portable_dir,
            )
            if reg_mod.has_entries(cleanup_text):
                cleanup_path = os.path.join(portable_dir, "cleanup_host.reg")
                reg_mod.write_reg_file(cleanup_path, cleanup_text)
                capture.cleanup_file = cleanup_path
                # Скрипт сам повышается только если пользователь его запустит.
                cleanup_cmd_path = os.path.join(portable_dir, "cleanup_host.cmd")
                self._write_text(
                    cleanup_cmd_path,
                    reg_mod.render_host_cleanup_cmd("cleanup_host.reg"),
                    encoding="ascii", newline="",
                )
                capture.cleanup_cmd_file = cleanup_cmd_path

        if capture.reg_file or capture.machine_reg_file:
            self.log.ok(
                f"Настройки программы сохранены в портатив: "
                f"{len(capture.keys)} ключ(ей) реестра."
            )
        else:
            self.log.info("Программа не создала собственных настроек в реестре.")
        if trace_keys:
            self.log.info(
                f"Записи об установке в портатив НЕ переносятся "
                f"({len(trace_keys)} ключ(ей)): они нужны только этому ПК."
            )
        if skipped_integration:
            self.log.info(
                f"Ассоциации файлов и COM пропущены ({len(skipped_integration)} "
                "ключ(ей)) — портатив не меняет настройки чужой системы."
            )
        if protocol_keys:
            self.log.ok(
                f"URL-протоколы перенесены в портатив ({len(protocol_keys)} "
                "ключ(ей)): браузерные глубокие ссылки будут открывать "
                "портативную программу (например, «Открыть Figma» после "
                "входа в аккаунт)."
            )
        return capture

    def _cleanup_host(self, capture: RegistryCapture, opts: PortableOptions,
                      result: PortableResult) -> None:
        """Убирает только собственную запись приложения из списка программ.

        Никакой общий diff реестра не импортируется: устаревший снимок не
        должен сбрасывать активацию, ассоциации и настройки, изменённые другим
        процессом. Удаляется ровно то, что установщик создал за эту сборку.

        Два пути: импорт ``cleanup_host.reg`` (работает и без прав на Python —
        файл остаётся рядом как ручной хелпер) и прямое удаление ключей через
        ``winreg`` в нужном представлении WOW64. Второй точнее и не зависит от
        политики импорта .reg.
        """
        if not opts.cleanup_host or not IS_WINDOWS:
            return
        if not capture.cleanup_keys and not capture.cleanup_file:
            return

        rc = self._reg_import(capture.cleanup_file) if capture.cleanup_file else 1
        removed, _left = reg_mod.delete_uninstall_keys(capture.cleanup_keys)
        if removed:
            self.log.info(
                "Записи списка приложений удалены напрямую из реестра: "
                + ", ".join(removed))

        # Проверяем результат, а не верим коду возврата: запись могла остаться
        # в другом представлении реестра (WOW64) или её успел вернуть сам
        # установщик.
        remaining = reg_mod.existing_uninstall_keys(capture.cleanup_keys)
        if remaining:
            self.log.warn(
                "Запись приложения всё ещё есть в списке установленных "
                "программ: " + ", ".join(remaining)
                + ". Лончер уберёт её при первом запуске портатива "
                  "(он проверяет запись на каждом старте)."
            )
            result.cleanup_pending = True
            if rc != 0:
                target = capture.cleanup_cmd_file or capture.cleanup_file
                self.log.warn(
                    "Импорт cleanup_host.reg не сработал (код "
                    f"{rc}), возможно, нужны права администратора. Никакие "
                    "другие ключи реестра не менялись. При необходимости "
                    f"проверьте: {target}"
                )
            return

        result.removed_from_installed_list = list(capture.cleanup_entries)
        if capture.cleanup_entries:
            self.log.ok(
                "Удалена только новая запись приложения из списка "
                "«Установленные программы»: "
                + ", ".join(capture.cleanup_entries)
            )

    def _report_own_shortcuts(
        self, guard: "shortcuts_mod.ShortcutGuard", sweep: bool = False,
    ) -> List[str]:
        """Убирает ярлыки, созданные установщиком за время этой сборки.

        ``sweep=True`` дополнительно убирает «пустые» ярлыки этой программы:
        те, что ведут внутрь портатива или чья цель уже не существует
        (установщик записал путь временного каталога). Именно такой ярлык
        остался на рабочем столе в жалобе: файл ``.lnk`` живёт отдельно от
        своей цели и сам по себе не исчезает.
        

        Удаляются только файлы, которых не было до установки и которые
        указывают внутрь портативной папки. Ярлык пользователя не трогается
        даже тогда, когда ведёт на ту же программу: доказать его
        происхождение нельзя, а чужие ярлыки Portablizer не удаляет.

        Почему это вообще нужно: установщик пишет в ярлык **статичный**
        абсолютный путь. После переноса папки на другой диск такой ярлык
        указывает на прежнее место — и запускает старую копию, а её
        обновление ставит новую версию туда же, а не в текущий портатив.
        """
        try:
            removed = guard.cleanup()
            if sweep:
                removed.extend(guard.sweep())
        except OSError as exc:
            self.log.warn(f"Уборка ярлыков не удалась: {exc}")
            return []
        if removed:
            names = ", ".join(os.path.basename(path) for path in removed[:5])
            more = "" if len(removed) <= 5 else f" и ещё {len(removed) - 5}"
            self.log.ok(
                f"Убрано ярлыков, созданных установщиком: {len(removed)} "
                f"({names}{more}). Портатив запускается из "
                f"App\\{APP_EXE_LAUNCHER_NAME}; ярлык установщика содержал "
                "статичный путь и после переноса папки на другой диск вёл бы "
                "в прежнее место."
            )
        return removed

    def _report_portable_services(self, portable_dir: str,
                                  result: PortableResult) -> None:
        """Обнаруживает службы, но не останавливает и не снимает их.

        Служба может принадлежать антивирусу, лицензированию или другому
        установленному компоненту. Автоматическое ``sc delete`` по пути
        бинарника потенциально разрушительно, поэтому здесь только отчёт.
        """
        if not IS_WINDOWS or not portable_dir:
            return
        try:
            services = procutil.services_in(portable_dir)
        except Exception as exc:  # noqa: BLE001
            self.log.debug(f"Не удалось перечислить службы: {exc}")
            return
        if not services:
            return
        result.registered_services = list(services)
        self.log.warn(
            "Обнаружены зарегистрированные службы, указывающие внутрь "
            "портатива: " + ", ".join(services) + ". Portablizer их не "
            "останавливает и не удаляет. Такая сборка может быть не полностью "
            "переносимой; проверьте службы вручную, не удаляя незнакомые.")

    @staticmethod
    def _reg_import(path: str) -> int:
        """Импортирует .reg без появления окна консоли."""
        try:
            proc = subprocess.run(
                ["reg", "import", path],
                creationflags=0x08000000,  # CREATE_NO_WINDOW
                capture_output=True,
            )
            return proc.returncode
        except OSError:
            return 1

    # -- установка ------------------------------------------------------------
    def _run_install(self, plan: SilentPlan, opts: PortableOptions,
                     app_dir: str, data_dir: str,
                     progress_from: int = 30, progress_to: int = 60,
                     console_log: Optional[str] = None) -> Optional[int]:
        if not IS_WINDOWS:
            # Не выдаём заглушку за готовое приложение: следующий этап честно
            # завершит операцию ошибкой из-за отсутствия exe.
            self.log.warn(
                "Не Windows: реальный запуск установщика невозможен. "
                "Создание портатива поддерживается только на Windows."
            )
            return None

        cmd = [plan.program] + list(plan.args)
        # NSIS: /D=... должен быть последним и без кавычек — добавляем сырьём.
        # subprocess с list не даст «сырой» аргумент, поэтому для NSIS собираем
        # командную строку строкой.
        env = self._build_isolated_env(opts, data_dir)
        cmdline = subprocess.list2cmdline(cmd)
        if plan.raw_tail:
            cmdline += " " + plan.raw_tail

        # stdout/stderr установщика сохраняем в файл: CLI-установщики пишут
        # туда причину отказа (например, «license agreement not accepted»),
        # а GUI-движки просто молчат. Без этого код -1 остаётся загадкой.
        console_handle = None
        if console_log:
            try:
                console_handle = open(console_log, "ab")
                console_handle.write(
                    (f"===== {plan.label} =====\r\n{cmdline}\r\n")
                    .encode("utf-8", "replace"))
                console_handle.flush()
            except OSError:
                console_handle = None

        # Интерактивный план (запись ответов InstallScript) обязан показать
        # окно: пользователь должен пройти мастер, иначе записывать нечего.
        creationflags = 0 if plan.interactive else 0x08000000  # CREATE_NO_WINDOW
        # Предел ожидания относится к ПАУЗЕ в работе установщика, а не ко всему
        # времени установки (см. _InstallWatchdog). У мастера с человеком за
        # клавиатурой пауза своя: думать над окном можно долго.
        idle_limit = max(INSTALL_IDLE_FLOOR, float(
            max(opts.install_timeout, opts.assisted_timeout)
            if plan.interactive else opts.install_timeout))
        deadline = 0.0 if plan.interactive else max(
            0.0, float(opts.install_deadline))
        if plan.interactive:
            self.log.info("Запуск установщика с окном мастера (изолированно)...")
            for line in plan.instructions:
                self.log.info(f"  → {line}")
        else:
            self.log.info("Запуск установщика (тихо, изолированно)...")
        rc: Optional[int] = None
        started = time.monotonic()
        # Флаг «мёртвого старта» относится к текущей попытке: каждая новая
        # команда получает свой шанс, даже если предыдущая не началась.
        self._install_dead_start = False
        try:
            try:
                if plan.raw_tail:
                    self.log.debug(f"cmdline: {cmdline}")
                    popen_args = cmdline
                else:
                    popen_args = cmd
                proc = subprocess.Popen(
                    popen_args, env=env, creationflags=creationflags,
                    stdout=console_handle,
                    stderr=subprocess.STDOUT if console_handle else None)
            except FileNotFoundError as exc:
                raise RuntimeError(
                    f"Не удалось запустить установщик: {exc}") from exc
            except OSError as exc:
                if getattr(exc, "winerror", None) == 740:  # ERROR_ELEVATION_REQUIRED
                    raise RuntimeError(
                        "Установщику нужны права администратора. Запустите "
                        "Portablizer от имени администратора и повторите сборку."
                    ) from exc
                raise RuntimeError(
                    f"Не удалось запустить установщик: {exc}") from exc

            rc = self._wait_for_install(proc, plan, app_dir, data_dir,
                                        idle_limit=idle_limit,
                                        deadline=deadline,
                                        progress_from=progress_from,
                                        progress_to=progress_to,
                                        console_log=console_log)
        finally:
            self._last_install_seconds = time.monotonic() - started
            if console_handle is not None:
                try:
                    code = (str(rc) if rc is not None
                            else "нет (установщик не запустился или прерван)")
                    console_handle.write(
                        f"<<< код возврата: {code} >>>\r\n\r\n"
                        .encode("utf-8", "replace"))
                    console_handle.close()
                except OSError:
                    pass

        crash = crash_mod.crash_code(rc)
        if rc == redist_mod.TIMEOUT_EXIT_CODE:
            # Это наша метка, а не код движка: подробности уже сказаны выше
            # (см. _note_stall), здесь важно лишь подвести итог попытки.
            self.log.warn(
                "Установщик был снят по пределу ожидания (это не код движка, "
                "а решение Portablizer). Проверяю, что он успел установить."
            )
        elif crash is not None:
            # Падение — не «отказ понять командную строку»: процесс стартовал
            # и был оборван исключением. Отдельный диагноз (и отдельные шаги)
            # описан в core/crashinfo.py.
            self.log.warn(
                f"Установщик аварийно завершился через "
                f"{redist_mod.human_duration(self._last_install_seconds)} "
                f"работы: {_format_exit_code(rc)} — {crash.hint}."
            )
            self._note_crash(plan, rc, cmdline, console_log)
        elif rc not in (0, 3010):  # 3010 = успех, требуется перезагрузка
            hint = _exit_code_hint(rc)
            self.log.warn(
                f"Установщик вернул код {_format_exit_code(rc)}."
                + (f" Похоже, {hint}." if hint else "")
                + " Подробности — в журнале установки."
            )
        else:
            self.log.ok(f"Установка завершена (код {rc}).")

        # Проверим, что что-то реально установилось.
        try:
            entries = os.listdir(app_dir)
        except OSError:
            entries = []
        if not entries:
            if plan.ignores_target_dir:
                self.log.info(
                    "Этот движок не принимает целевую папку в командной "
                    "строке — ищу установленную программу в каталогах по "
                    "умолчанию, чтобы перенести её в App."
                )
            else:
                self.log.warn(
                    "Целевая папка пуста. Установщик мог проигнорировать ключ папки; "
                    "проверяю перенаправленный профиль и системные каталоги установки."
                )
        return rc

    # -- ожидание установщика: долго ≠ зависло --------------------------------
    def _install_watch_roots(self, plan: SilentPlan, app_dir: str,
                             data_dir: str) -> List[str]:
        """Где искать признаки работы установщика.

        Целевая папка — очевидное место, но не единственное: движки, не
        принимающие папку в командной строке (InstallScript), и установщики,
        игнорирующие её, пишут в перенаправленный профиль (``data_dir``), а
        распаковка бандла ``/layout`` — в свою временную папку.
        """
        roots = [app_dir, data_dir]
        if plan.output_dir:
            roots.append(plan.output_dir)
        return list(dict.fromkeys(path for path in roots if path))

    def _install_watch_logs(self, plan: SilentPlan, data_dir: str,
                            console_log: Optional[str]) -> List[str]:
        """Журналы установщика, по которым видно, что он продолжает работу.

        Помимо явных ключей (Inno ``/LOG``, Burn ``/log``, msiexec ``/L*v``,
        InstallShield ``/f2``) смотрим свежие ``*.log`` в перенаправленном
        TEMP: Burn и многие бутстрапперы пишут туда, даже когда ключ журнала
        не поддержан.
        """
        logs: List[str] = []
        for path in (console_log, plan.result_log, *plan.progress_logs):
            if path:
                logs.append(path)
        if data_dir:
            # TEMP может быть перенесён на другой диск (нехватка места на
            # диске портатива): журналы ищутся там, где установщик реально
            # работал, а не там, где папка была бы по умолчанию.
            temp = self._temp_dir_for(data_dir)
            try:
                for name in os.listdir(temp):
                    if name.lower().endswith(".log"):
                        logs.append(os.path.join(temp, name))
            except OSError:
                pass
        return list(dict.fromkeys(logs))

    def _wait_for_install(self, proc: "subprocess.Popen", plan: SilentPlan,
                          app_dir: str, data_dir: str,
                          idle_limit: float, deadline: float,
                          progress_from: int, progress_to: int,
                          console_log: Optional[str] = None) -> Optional[int]:
        """Ждёт установщик, пока он подаёт признаки работы.

        Возвращает код возврата процесса или :data:`TIMEOUT_EXIT_CODE`, если
        установщик замолчал и был снят (``redist_mod.TIMEOUT_EXIT_CODE``).
        Исключение — только отмена пользователем: обычный тайм-аут больше не
        обрывает сборку, потому что «долго» и «зависло» — разные вещи.
        """
        watchdog = _InstallWatchdog(
            proc.pid,
            roots=self._install_watch_roots(plan, app_dir, data_dir),
            logs=self._install_watch_logs(plan, data_dir, console_log))
        started = time.monotonic()
        last_work = started
        last_report = -1
        dismissed = 0
        last_dismiss_log = 0.0
        # Состояние страниц мастера: какой клик уже отправлен и когда. Без
        # него «Далее» уходило бы в ту же неизменившуюся страницу каждые
        # полсекунды, прокручивая мастер рывками.
        dialog_state: Dict[object, Tuple[str, float]] = {}
        interactive_since = 0.0
        tree_pids: List[int] = [proc.pid]
        tree_refresh = 0.0
        last_dialog_probe = 0.0
        while proc.poll() is None:
            now = time.monotonic()
            if self.cancel.is_set():
                self._stop_installer(proc)
                raise RuntimeError("Установка отменена пользователем.")
            # Запасной путь: IFEO уже переписывает командную строку
            # DXSETUP на /silent. Если перехват недоступен (нет прав),
            # закрываем оставшееся окно сами — не сбрасывая таймер паузы.
            try:
                tally: Dict[str, int] = {}
                if now - tree_refresh >= 5.0:
                    tree_pids = procutil.process_tree(proc.pid) or [proc.pid]
                    tree_refresh = now
                try:
                    # target_dir — чтобы на странице выбора папки ввести
                    # путь в App, а не согласиться с C:\\Program Files.
                    # pids — чтобы не трогать окна чужих программ.
                    # Планов, которые намеренно отдают выбор каталога
                    # установщику (prefers_installer_default_dir), App во
                    # вкладку выбора папки не вбиваем: внутренний мастер
                    # его отклоняет («folder is not accessible») и зависает.
                    dialog_target = "" if plan.prefers_installer_default_dir else app_dir
                    clicked = redist_mod._dismiss_installer_dialogs(
                        tally, target_dir=dialog_target, pids=tree_pids,
                        state=dialog_state)
                except TypeError:
                    # Совместимость с заменённой/старой реализацией:
                    # сначала только счётчик, затем вовсе без аргументов.
                    try:
                        clicked = redist_mod._dismiss_installer_dialogs(tally)
                    except TypeError:
                        clicked = redist_mod._dismiss_installer_dialogs()
                self._device_prompt_hits += int(tally.get("device", 0))
                if tally.get("interactive"):
                    if not interactive_since:
                        interactive_since = now
                        if not self._install_gui_seen:
                            self._install_gui_seen = True
                            self.log.warn(
                                "Установщик открыл собственный мастер "
                                "(страница выбора языка или папки) — "
                                "значит, тихие ключи не подошли. Portablizer "
                                "отвечает на страницы сам и вводит папку App; "
                                "если мастер не продвинется, попытка будет "
                                "остановлена без ожидания общего предела."
                            )
                else:
                    interactive_since = 0.0
            except Exception:  # noqa: BLE001 — WinAPI не вправе ронять сборку
                clicked = 0
                interactive_since = 0.0
            # Незнакомые окна установщика. Portablizer их не нажимает (у
            # кнопок может быть разрушительный смысл), но и молчать о них
            # нельзя: именно такое окно чаще всего и держит процесс, пока
            # сборка считает, что «нет признаков работы». Заголовки попадают
            # в журнал и в диагноз «мёртвого старта».
            if now - last_dialog_probe >= 20.0 and now - last_work >= 30.0:
                last_dialog_probe = now
                try:
                    titles = redist_mod.pending_dialog_titles(tree_pids)
                except Exception:  # noqa: BLE001 — WinAPI не вправе ронять сборку
                    titles = []
                for title in titles:
                    if title and title not in self._install_dialog_titles:
                        self._install_dialog_titles.append(title)
                        self.log.warn(
                            "Установщик показывает окно «" + title + "» и ждёт "
                            "нажатия. Portablizer не нажимает незнакомые "
                            "кнопки сам: подтвердите или закройте это окно, "
                            "либо дождитесь конца попытки — сборка продолжит "
                            "другими сценариями."
                        )
            if clicked:
                dismissed += clicked
                if now - last_dismiss_log >= 5.0:
                    last_dismiss_log = now
                    self.log.info(
                        "  Закрыл служебное окно установщика "
                        "(DirectX/VC++ «неверная операция командной "
                        "строки», согласие Windows на установку драйвера "
                        "устройства и подобные). Таких окон за эту попытку: "
                        f"{dismissed}."
                    )
            if watchdog.poll(now) and watchdog.strong_changed():
                # Якорь «установщик работает» тянем только по признакам
                # реальной работы (процессы, диск, файлы): лог и процессор
                # могут двигаться, когда внутри верстака SFX завис
                # внутренний установщик — а тогда затишье не получится
                # распознать и вопрос «с чем дела» не зададут.
                last_work = now
            elapsed = now - started
            idle = now - last_work
            # Плавный прогресс во время установки: progress_from -> progress_to.
            frac = creep_fraction(elapsed)
            span = max(1, progress_to - progress_from)
            title = ("Установка в окне мастера..." if plan.interactive
                     else "Тихая установка...")
            self._emit_progress(progress_from + int(span * frac), title)
            # Установщик о себе процентов не сообщает, поэтому подробная
            # строка показывает и время работы, и её видимый результат: так
            # «медленно пишет 40 ГБ» не выглядит как «зависло».
            self._detail(
                min(99, int(idle * 100 / max(1.0, idle_limit))),
                f"{title} идёт {redist_mod.format_duration(elapsed)}; "
                f"{watchdog.summary()}; пауза без признаков работы "
                f"{redist_mod.format_duration(idle)} из "
                f"{redist_mod.format_duration(idle_limit)}")
            # Абсолютный потолок проверяется первым: он не обсуждается и не
            # продлевается вопросом — это страховка от вечной работы.
            if deadline and elapsed > deadline:
                self._note_stall(watchdog, plan, elapsed, idle, idle_limit,
                                 deadline, reason="достигнут предел времени")
                self._stop_installer(proc)
                return redist_mod.TIMEOUT_EXIT_CODE
            # «Мёртвый старт»: установщик не прочитал и не записал ни байта,
            # не потратил ни секунды процессорного времени и не создал ни
            # одного файла за всю попытку. Тяжёлый дистрибутив так не
            # выглядит (он читает свой архив), значит процесс стоит на
            # внешнем препятствии — и тут нечего ждать четверть часа.
            # Попытка снимается сама, без вопроса человеку: ответ «ждать
            # ещё» на такой вопрос ничего не меняет, а сборка стоит.
            if (not plan.interactive and not self._install_dead_start
                    and elapsed >= INSTALL_DEAD_START_LIMIT
                    and watchdog.never_started()):
                self._install_dead_start = True
                self._install_stall = watchdog.report(
                    plan.label, elapsed, idle, idle_limit, deadline)
                self.log.warn(
                    "Установщик не начал работу за "
                    f"{redist_mod.human_duration(elapsed)}: ни прочитанных "
                    "байт, ни созданных файлов, ни процессорного времени. "
                    "Это не медленная распаковка — так ведёт себя обёртка, "
                    "которая ждёт подтверждения (запрос UAC или её "
                    "собственное окно) либо не поняла ключи вовсе. Снимаю "
                    "эту попытку без ожидания общего предела и перехожу к "
                    "следующему сценарию."
                )
                for line in self._dead_start_diagnosis():
                    self.log.warn("  • " + line)
                self._stop_installer(proc)
                return redist_mod.TIMEOUT_EXIT_CODE
            # Мастер с вопросами: не ждать INSTALL_IDLE_LIMIT. Установщик
            # стоит не потому, что распаковывает гигабайты, а потому, что
            # ему не нажали кнопку. Спрашиваем человека так же, как при
            # обычном затишье, но уже через INSTALL_GUI_PROMPT_LIMIT.
            if (not plan.interactive and interactive_since
                    and idle >= INSTALL_GUI_PROMPT_LIMIT):
                self.log.warn(
                    "Установщик показывает мастер и ждёт нажатий: страница "
                    f"выбора языка/папки не меняется {redist_mod.human_duration(idle)}. "
                    "Это не долгая распаковка — без ответа сборка стояла бы "
                    f"весь предел ({redist_mod.human_duration(idle_limit)})."
                )
                verdict = self._ask_about_stall(
                    watchdog.report(plan.label, elapsed, idle,
                                    INSTALL_GUI_PROMPT_LIMIT, deadline))
                if verdict == STALL_WAIT:
                    last_work = time.monotonic()
                    interactive_since = 0.0
                    continue
                if verdict == STALL_CANCEL:
                    self._stop_installer(proc)
                    raise RuntimeError("Операция отменена пользователем.")
                self._note_stall(watchdog, plan, elapsed, idle,
                                 INSTALL_GUI_PROMPT_LIMIT, deadline,
                                 reason="мастер установщика ждёт нажатий")
                self._stop_installer(proc)
                return redist_mod.TIMEOUT_EXIT_CODE
            if idle >= idle_limit:
                verdict = self._ask_about_stall(
                    watchdog.report(plan.label, elapsed, idle, idle_limit,
                                    deadline))
                if verdict == STALL_WAIT:
                    last_work = time.monotonic()
                    continue
                if verdict == STALL_CANCEL:
                    self._stop_installer(proc)
                    raise RuntimeError("Операция отменена пользователем.")
                self._note_stall(watchdog, plan, elapsed, idle, idle_limit,
                                 deadline, reason="установщик замолчал")
                self._stop_installer(proc)
                return redist_mod.TIMEOUT_EXIT_CODE
            # Строка отчёта в журнал — раз в минуту: часы установки не должны
            # превращать журнал в лестницу из одинаковых строк.
            minute = int(elapsed // 60)
            if minute != last_report:
                last_report = minute
                self.log.info(
                    f"  {title} идёт {redist_mod.format_duration(elapsed)}; "
                    f"{watchdog.summary()}")
            time.sleep(0.5)
        return proc.returncode

    def _ask_about_stall(self, stall: InstallStall) -> str:
        """Спрашивает человека, ждать ли ещё (если спросить есть кому).

        Без колбэка (CLI, тесты, сборка без интерфейса) решение принимается
        самим: затишье — это зависание, и ждать дальше нечего.
        """
        self.log.warn(stall.message())
        if self.on_stall is None:
            return STALL_STOP
        try:
            answer = self.on_stall(stall)
        except Exception as exc:  # noqa: BLE001 - интерфейс не вправе ронять сборку
            self.log.debug(f"  • вопрос о продолжении ожидания не удался: {exc}")
            return STALL_STOP
        verdict = _stall_verdict(answer)
        if verdict == STALL_WAIT:
            self.log.info(
                "По вашему решению жду ещё: следующий вопрос — ещё через "
                f"{redist_mod.human_duration(stall.idle_limit)} тишины.")
        return verdict

    def _note_stall(self, watchdog: _InstallWatchdog, plan: SilentPlan,
                    elapsed: float, idle: float, idle_limit: float,
                    deadline: float, reason: str) -> None:
        """Запоминает затишье: из него потом строятся итоговые подсказки."""
        stall = watchdog.report(plan.label, elapsed, idle, idle_limit, deadline)
        self._install_stalled = True
        self._install_stall = stall
        self.log.warn(
            f"{reason.capitalize()}: {stall.message()} Установщик снят вместе "
            "с дочерними процессами — сборка продолжается с тем, что уже "
            "лежит в папке App.")

    def _dead_start_diagnosis(self) -> List[str]:
        """Почему установщик мог не начать работу: по пунктам, без догадок.

        Диагноз строится только на фактах, которые видно снаружи: открытые
        окна самого установщика, запущенный ``consent.exe`` (запрос UAC) и
        права текущего процесса. Придумывать причину «на всякий случай»
        нельзя: неверный совет стоит пользователю часа.
        """
        lines: List[str] = []
        for title in self._install_dialog_titles[:3]:
            lines.append(
                f"Открыто окно установщика «{title}» — если оно ждёт "
                "нажатия, нажмите кнопку в нём: обёртка-SFX часто не "
                "понимает переданные ключи и показывает ошибку."
            )
        try:
            uac = procutil.uac_prompt_pending()
        except Exception:  # noqa: BLE001 - диагностика необязательна
            uac = False
        if uac:
            lines.append(
                "Windows показывает запрос контроля учётных записей (UAC). "
                "Подтвердите его — до этого установщик не получит управление "
                "вовсе."
            )
        if IS_WINDOWS and not is_elevated():
            lines.append(
                "Portablizer запущен без прав администратора: установщику "
                "может требоваться повышение, и он ждёт его молча."
            )
        lines.append(
            "Если окон нет и UAC не спрашивает, файл, скорее всего, "
            "проверяет антивирус: добавьте установщик и папку портатива в "
            "исключения и повторите сборку."
        )
        return lines

    @staticmethod
    def _stop_installer(proc: "subprocess.Popen") -> None:
        """Снимает установщик вместе со всеми его дочерними процессами.

        ``Popen.terminate()`` снимает только обёртку, а файлы пишет ребёнок
        (``setup.tmp``, ``msiexec``, ``ikernel.exe``). Переживший сборку
        процесс продолжал бы занимать папку результата и показывать модальное
        окно уже после того, как сборка признала попытку неудачной.
        """
        procutil.kill_tree(getattr(proc, "pid", 0), proc)

    # -- лестница попыток установки ------------------------------------------
    def _run_attempts(self, attempts: Sequence[SilentPlan],
                      opts: PortableOptions, app_dir: str, data_dir: str,
                      portable_dir: str, name: str,
                      recover: Optional[Callable[[], bool]] = None,
                      ) -> Tuple[Optional[int], Optional[SilentPlan]]:
        """Выполняет сценарии, пока не появится запускаемый клиент.

        Возвращает ``(код последней попытки, сработавший план)``. Успехом
        считается только фактический результат на диске: код возврата ``0``
        при отсутствии исполняемого файла в App и известном профиле успехом
        не является; некоторые установщики отдают ненулевой код, успев
        разложить файлы.
        """
        last_rc: Optional[int] = None
        span = max(1, 58 - 30)
        console_log = os.path.join(portable_dir, "installer-output.log")
        # Очередь, а не просто список: после падения установщика в неё
        # добавляются сценарии, которых в обычной лестнице нет (повтор той же
        # команды и запуск с окном прогресса). См. _queue_crash_recovery.
        queue: List[SilentPlan] = list(attempts)
        self._hollow_note = ""
        hollow_successes = 0
        # Счётчик «мёртвых стартов» ведётся по попыткам этой лестницы:
        # распаковка содержимого контейнера (если она была) свои счётчики
        # сюда не приносит.
        self._dead_start_attempts = 0
        payload_before = (
            space_mod.payload_signature(app_dir),
            space_mod.payload_signature(data_dir),
        )
        payload_seen = False
        index = 0
        while index < len(queue):
            plan = queue[index]
            total = len(queue)
            self._check_cancel()
            start = 30 + int(span * index / max(1, total))
            stop = 30 + int(span * (index + 1) / max(1, total))
            if index:
                self.log.info(
                    f"Сценарий {index + 1} из {total}: {plan.label}")
                self.log.debug(f"cmdline: {plan.display()}")
            if plan.needs_admin and IS_WINDOWS and not is_elevated():
                self.log.debug(
                    "  • сценарию нужны права администратора, которых нет — "
                    "выполняю, но успех маловероятен"
                )

            if self._adobe_detected and plan.payload_kind != adobe_mod.PAYLOAD_ADOBE:
                # Adobe не работает с установщиком на съёмном/сетевом диске
                # (код 1000), поэтому запускаем локальную копию.
                source = self._adobe_installer_source(opts)
                if source and os.path.normcase(source) != os.path.normcase(
                        plan.program):
                    plan.program = source

            if plan.payload_kind:
                # План не запускает установщик: он раскладывает его пакеты
                # своими силами (Adobe: UWP-шаг с кодом 191 тогда просто не
                # выполняется). Запускать установщик здесь нельзя — смысл
                # сценария именно в обратном.
                rc = self._run_payload_plan(
                    plan, opts, app_dir, data_dir, name,
                    portable_dir=portable_dir, console_log=console_log,
                    progress_from=start, progress_to=stop)
            else:
                # Adobe успевает распаковать пакеты во временный каталог и
                # убирает их при откате. Пока установщик работает, копии
                # снимаются на диск — из них потом собирается портатив.
                self._start_adobe_watcher(portable_dir, opts)
                rc = self._run_install(plan, opts, app_dir, data_dir,
                                       progress_from=start, progress_to=stop,
                                       console_log=console_log)
            last_rc = rc
            # Классический InstallShield пишет причину отказа в свой
            # setup.log — без неё «код 0 при пустой папке» необъясним.
            self._report_installshield_log(plan)
            self._attempts_made += 1
            self._attempt_history.append((plan.label, rc))
            if self._install_dead_start:
                self._dead_start_attempts += 1
            index += 1

            # Adobe: установщик успевает разложить пакеты во временный каталог
            # ДО того, как упадёт на UWP-шаге с кодом 191 (и откатит
            # установку). Забираем их оттуда в App — это второй источник
            # пакетов после контейнера самого установщика.
            if (self._adobe_detected
                    and plan.payload_kind != adobe_mod.PAYLOAD_ADOBE
                    and not self._find_main_exe(app_dir, name)):
                self._salvage_adobe_payloads(
                    opts, app_dir, data_dir, name, portable_dir=portable_dir,
                    console_log=console_log)

            if plan.interactive and plan.response_file \
                    and os.path.isfile(plan.response_file):
                self.log.ok(
                    f"Ваши ответы сохранены в файл {plan.response_file}. "
                    "Он лежит в папке портатива: следующая сборка этой же "
                    "программы пройдёт полностью автоматически, без окон."
                )

            # Распаковка бандла сама по себе файлов в App не даёт: из неё ещё
            # нужно вытащить MSI-пакеты. Для планов со свой раскладкой
            # (``payload_kind``) это уже сделано внутри них: их каталог — не
            # layout Burn-бандла, и разбирать его как бандл нельзя.
            if (plan.extracts_only and not plan.payload_kind
                    and plan.output_dir
                    and os.path.normcase(plan.output_dir) != os.path.normcase(app_dir)):
                if self._install_layout_packages(plan.output_dir, opts, app_dir,
                                                 data_dir, name,
                                                 console_log=console_log):
                    self.log.ok(f"Сработал сценарий: {plan.label}")
                    return rc, plan
                continue

            # Падение — отдельный случай, и разбирать его нужно ДО проверки
            # «а файлы-то появились»: установщик, упавший в отрисовке
            # прогресса (0xC000041D и похожие), почти всегда успевает
            # распаковать часть payload'а, включая сам главный exe, ДО
            # исключения. Если сначала посмотреть на App и увидеть там
            # файлы, падение останется незамеченным, лестница остановится,
            # а пользователь получит «Тихая установка прошла успешно» на
            # установке, которая на самом деле прервалась на середине.
            if crash_mod.is_crash_code(rc):
                if self._queue_crash_recovery(plan, rc, app_dir, queue, index):
                    continue
                # Восстановиться больше нечем (лестница падений исчерпана).
                # Если что-то в App всё же появилось — это лучшее, что есть,
                # но говорить нужно честно: установщик упал, а не «прошёл
                # успешно».
                if self._find_main_exe(app_dir, name):
                    self.log.warn(
                        "Установщик упал, но часть файлов программы уже "
                        "оказалась в App, а других шагов на восстановление "
                        "не осталось. Использую то, что успело записаться — "
                        "проверьте игру после сборки: установка может быть "
                        "неполной."
                    )
                    return rc, plan

            if self._find_main_exe(app_dir, name):
                if index > 1:
                    self.log.ok(f"Сработал запасной сценарий: {plan.label}")
                else:
                    self.log.ok("Тихая установка прошла успешно.")
                return rc, plan

            # Движок, не принимающий целевую папку (InstallScript 5/6 или
            # универсальная лестница без целевого пути), ставит программу в
            # свой каталог по умолчанию или регистрирует распакованную папку
            # на месте. Это успех, а не неудача: забираем файлы сразу, иначе
            # следующий сценарий начнёт ставить программу поверх уже
            # установленной или сработает защита от «пустых» запусков.
            can_recover_now = (
                plan.ignores_target_dir
                or (not plan.raw_tail
                    and not getattr(self._detection, "is_downloader_stub", False))
            )
            if can_recover_now and recover is not None \
                    and rc in (0, 3010):
                if recover():
                    self.log.ok(
                        "Программа установлена в каталог по умолчанию и "
                        f"перенесена в App. Сработал сценарий: {plan.label}"
                    )
                    return rc, plan

            # Стойка (TIMEOUT_EXIT_CODE): внутренний установщик верстака SFX
            # успел скопировать файлы в Program Files, но затем завис на
            # диалоге выбора языка/пути. Recovery забирает эти файлы в App
            # и удаляет оригинал из Program Files — без этого на C: остаётся
            # брошенный каталог и Launcher.bat не находит главный exe.
            if (plan.ignores_target_dir and recover is not None
                    and rc == redist_mod.TIMEOUT_EXIT_CODE
                    and not self._app_has_payload(app_dir)):
                if recover():
                    self.log.ok(
                        "Программа была установлена в каталог по умолчанию "
                        "(Program Files) перед зависанием установщика; "
                        "файлы перенесены в App, оригинал удалён. "
                        f"Сработал сценарий: {plan.label}"
                    )
                    return rc, plan

            # Autodesk Fusion штатно оставляет webdeploy-клиент в
            # %LOCALAPPDATA%, а не в App. Если загрузка завершилась и exe
            # уже находится в изолированном профиле, не запускаем второй
            # (часто интерактивный) сценарий установщика.
            if rc in (0, 3010) and self._discover_online_profile_payload(
                    opts, data_dir, portable_dir, name):
                self.log.ok(
                    "Загрузчик завершился; клиент найден в PortableData. "
                    f"Сценарий: {plan.label}"
                )
                return rc, plan

            # «Мёртвый старт» повторяется: ключи до установщика не доходят
            # вовсе. Дальше перебирать их бессмысленно — сборка идёт к
            # распаковке содержимого без запуска установщика.
            if (rc == redist_mod.TIMEOUT_EXIT_CODE and self._install_dead_start
                    and not self._app_has_payload(app_dir)
                    and self._dead_start_attempts >= DEAD_START_ATTEMPTS_LIMIT):
                self.log.warn(
                    "Две попытки подряд установщик не прочитал ни байта: "
                    "ключи тишины до него не доходят (так ведут себя "
                    "обёртки самораспаковывающихся архивов). Остальные "
                    "варианты ключей пропускаю — содержимое будет достано "
                    "распаковкой без запуска."
                )
                break

            # Установщик замолчал, но уже успел распаковать часть данных.
            # Запускать поверх них следующий сценарий бессмысленно и вредно:
            # это те же гигабайты заново, только ещё и с риском получить
            # «кашу» из двух неполных установок. Останавливаем лестницу и
            # честно объясняем, что произошло (подсказки — _failure_hints).
            if rc == redist_mod.TIMEOUT_EXIT_CODE and self._app_has_payload(app_dir):
                self.log.warn(
                    "Повторять установку другими ключами не буду: в папке App "
                    "уже лежат распакованные файлы, а поверх неполной установки "
                    "новая только займёт место и время. Что успело "
                    "установиться — оставлено на месте для проверки."
                )
                break

            # Мгновенный код 0 без payload — это не успех установки.
            # Загрузчики могут написать несколько КБ журнала в PortableData\\Temp;
            # сравниваем содержательные файлы и игнорируем TEMP/мелкие логи.
            payload_now = (
                space_mod.payload_signature(app_dir),
                space_mod.payload_signature(data_dir),
            )
            if payload_now != payload_before:
                payload_seen = True

            is_hollow_candidate = (
                rc in (0, 3010)
                and 0 < self._last_install_seconds <= HOLLOW_ATTEMPT_MAX_SECONDS
                and not payload_seen
                and not plan.interactive
                and not plan.extracts_only
                and not plan.result_log
                and not plan.ignores_target_dir
            )
            if is_hollow_candidate:
                hollow_successes += 1
            else:
                hollow_successes = 0

            has_extraction_fallback = any(
                pending.extracts_only for pending in queue[index:])
            if (hollow_successes >= HOLLOW_ATTEMPTS_LIMIT
                    and not has_extraction_fallback):
                product = getattr(self._detection, "online_product", None)
                if product is not None:
                    self._hollow_note = (
                        "Повторять установку другими ключами не буду: "
                        f"{product.name} — сетевой загрузчик, который может "
                        "лишь записать журнал/загрузить файлы в webdeploy, "
                        "но не положить приложение в App."
                    )
                else:
                    self._hollow_note = (
                        "Повторять установку другими ключами не буду: "
                        "несколько быстрых команд завершились кодом 0, но "
                        "не создали ни одного содержательного файла программы."
                    )
                self.log.warn(self._hollow_note)
                break

            if index < total:
                if getattr(self._detection, "online_product", None) is not None:
                    self.log.warn(
                        f"Сценарий «{plan.label}» не дал запускаемого exe в "
                        "App или перенаправленном профиле — перехожу к следующему."
                    )
                else:
                    self.log.warn(
                        f"Сценарий «{plan.label}» не дал файлов в App — перехожу "
                        "к следующему."
                    )

        self._collect_engine_log(opts, data_dir, portable_dir)
        if self._adobe_detected and portable_dir:
            # Отчёт пишется и здесь: так он появляется независимо от того,
            # дошла ли сборка до финальных полей результата.
            self._installer_path = opts.installer_path
            self._write_adobe_report(portable_dir, name,
                                     getattr(self, "_detection", None))
        return last_rc, None

    def _queue_crash_recovery(self, plan: SilentPlan, rc: Optional[int],
                              app_dir: str, queue: List[SilentPlan],
                              index: int) -> bool:
        """Добавляет в очередь шаги, которые делают только после падения.

        Их два, и оба основаны на природе таких сбоев:

        * **повтор той же команды** — если установщик упал через секунды
          после старта и ничего не записал, причиной могла быть разовая
          помеха (антивирус проверял файл, не хватило памяти в момент
          распаковки). Падение после часа работы повторять бессмысленно;
        * **запуск с окном прогресса** — в самом тихом режиме (``/VERYSILENT``)
          установщик вообще не создаёт окно, а в ``/SILENT`` создаёт. Это
          другой путь в его коде, и падение в отрисовке прогресса на нём не
          повторяется.

        Возвращает ``True``, если сценарий добавлен прямо перед текущей позицией:
        тогда вызывающий цикл переходит к нему, а не идёт дальше по лестнице.
        """
        if not crash_mod.is_crash_code(rc):
            return False

        if (crash_mod.is_retryable(rc) and not self._crash_retried
                and self._last_install_seconds <= CRASH_RETRY_MAX_SECONDS
                and not self._app_has_payload(app_dir)):
            self._crash_retried = True
            queue.insert(index, repeat_attempt(plan, "повтор после падения"))
            self.log.info(
                "Падение произошло сразу после старта и до записи файлов: "
                "такие сбои часто разовые. Повторяю ровно ту же команду ещё "
                "раз — без этого шага Portablizer сразу перешёл бы к другим "
                "ключам и не проверил, что дело не в разовой помехе."
            )
            return True

        if not self._progress_retry_done:
            self._progress_retry_done = True
            recovery = build_progress_window_attempt(plan)
            if recovery is not None and self._enqueue_plan(queue, index,
                                                           recovery):
                self.log.info(
                    "Пробую тот же запуск, но с окном прогресса (/SILENT "
                    "вместо /VERYSILENT): в самом тихом режиме окно не "
                    "создаётся вообще, и исключение могло прилететь именно в "
                    "его отрисовку."
                )
                return True
        return False

    @staticmethod
    def _enqueue_plan(queue: List[SilentPlan], index: int,
                      plan: SilentPlan) -> bool:
        """Вставляет сценарий в очередь, если такого в ней ещё нет."""
        key = (plan.program, tuple(plan.args), plan.raw_tail)
        for existing in queue:
            if (existing.program, tuple(existing.args),
                    existing.raw_tail) == key:
                return False
        queue.insert(index, plan)
        return True

    def _install_layout_packages(self, layout_dir: str, opts: PortableOptions,
                                 app_dir: str, data_dir: str,
                                 name: str,
                                 console_log: Optional[str] = None) -> bool:
        """Распаковывает MSI из подготовленного ``/layout`` прямо в ``App``."""
        msis, other_payloads = _burn_layout_payloads(layout_dir)
        if other_payloads:
            self.log.info(
                "Побочные пакеты бандла (exe/msu/msp) в портатив не "
                "переносятся: "
                + ", ".join(sorted(
                    os.path.basename(p) for p in other_payloads)[:5])
            )
        if not msis:
            self.log.warn(
                "В распакованном бандле нет ни одного MSI-пакета — "
                "распаковывать нечего."
            )
            return False

        for msi in msis:
            self._check_cancel()
            self.log.info(f"Распаковываю MSI-пакет в App: {os.path.basename(msi)}")
            msi_plan = build_silent_plan(InstallerType.MSI, msi, app_dir,
                                         is_msi=True)
            self._run_install(msi_plan, opts, app_dir, data_dir,
                              progress_from=58, progress_to=60,
                              console_log=console_log)

        if self._find_main_exe(app_dir, name):
            self.log.ok("Пакеты бандла распакованы в папку App.")
            shutil.rmtree(layout_dir, ignore_errors=True)
            self.log.info("Временная распаковка бандла удалена.")
            return True

        self.log.warn(
            "MSI-пакеты не дали исполняемых файлов. Распакованное "
            f"содержимое оставлено для диагностики: {layout_dir}"
        )
        return False

    # -- распаковка вложенного архива ----------------------------------------
    def _extract_zip_payload(self, installer_path: str, app_dir: str,
                             name: str) -> bool:
        """Достаёт программу из ZIP, приклеенного к установщику.

        Многие современные bootstrapper'ы — это обычный exe с ZIP на конце.
        Если ни одна команда установки не сработала, содержимое можно забрать
        напрямую: системе это ничего не делает и прав администратора не
        требует.
        """
        self.log.info(
            "Внутри установщика найден архив — пробую распаковать его "
            "напрямую, без установки в систему..."
        )
        try:
            with zipfile.ZipFile(installer_path) as archive:
                members = [m for m in archive.infolist() if not m.is_dir()]
                if not members:
                    return False
                for member in members:
                    # Защита от путей вида ../../ в архиве.
                    target = os.path.normpath(
                        os.path.join(app_dir, member.filename))
                    if not os.path.normcase(target).startswith(
                            os.path.normcase(os.path.abspath(app_dir))):
                        continue
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with archive.open(member) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            self.log.warn(f"Не удалось распаковать вложенный архив: {exc}")
            return False

        if self._find_main_exe(app_dir, name):
            self.log.ok("Программа извлечена из вложенного архива установщика.")
            return True
        self.log.warn(
            "Вложенный архив распакован, но исполняемых файлов программы в "
            "нём нет."
        )
        shutil.rmtree(app_dir, ignore_errors=True)
        os.makedirs(app_dir, exist_ok=True)
        return False

    def _collect_engine_log(self, opts: PortableOptions, data_dir: str,
                            portable_dir: str) -> None:
        """Сохраняет журнал движка установщика из перенаправлённого TEMP.

        Burn всегда пишет лог в ``%TEMP%`` — даже когда ключ ``/log`` не
        поддержан (например, в кастомном bootstrapper application). При
        перенаправлении профиля этот TEMP — наша песочница, поэтому свежий
        журнал можно безопасно скопировать в портатив для диагностики.
        """
        if not opts.redirect_userdirs:
            return
        if os.path.exists(os.path.join(portable_dir, "install.log")):
            return
        since = self._run_started or 0.0
        temp = self._temp_dir_for(data_dir)
        candidates: List[str] = []
        for current, _dirs, files in os.walk(temp):
            for filename in files:
                if not filename.lower().endswith(".log"):
                    continue
                path = os.path.join(current, filename)
                try:
                    if os.path.getmtime(path) >= since - 1:
                        candidates.append(path)
                except OSError:
                    continue
        if not candidates:
            return
        try:
            newest = max(candidates, key=os.path.getmtime)
            destination = os.path.join(portable_dir, "installer-engine.log")
            shutil.copy2(newest, destination)
            self.log.info(f"Журнал движка установщика сохранён: {destination}")
        except OSError:
            pass

    # -- временное место установщика ------------------------------------------
    def _temp_dir_for(self, data_dir: str) -> str:
        """Папка TEMP, которая сейчас отдана установщику."""
        return self._install_temp_dir or os.path.join(data_dir, "Temp")

    def _prepare_install_temp(self, opts: PortableOptions, portable_dir: str,
                              data_dir: str, det: DetectionResult) -> None:
        """Выбирает временное место установщика — с оглядкой на свободный диск.

        Установщики больших игр (особенно офлайн-установщики GOG)
        распаковывают данные СНАЧАЛА во временную папку и только потом
        переносят их в целевую. Значит, на диске должны одновременно
        уместиться дистрибутив, распакованная копия и результат. Portablizer
        перенаправляет TEMP внутрь портативной папки — это удерживает эти
        временные файлы, но не блокирует другие записи установщика в Windows.
        На флешке или небольшом разделе места может не хватить, и он **падает**
        (типичный код 0xC000041D —
        исключение в обработчике прогресса, когда распаковка оборвалась).

        Поэтому место проверяется заранее, а если его нет — TEMP установщика
        переносится на другой диск. Папка временная: она удаляется сразу
        после сборки (``_cleanup_install_temp``).
        """
        default_temp = os.path.join(data_dir, "Temp")
        self._install_temp_dir = default_temp
        need = int(space_mod.media_bytes(opts.installer_path)
                   * TEMP_NEED_FACTOR)
        available = space_mod.free_space(portable_dir)
        if need <= 0 or available < 0:
            self.log.debug(
                "  • размер дистрибутива или свободное место определить не "
                "удалось — TEMP остаётся в папке портатива."
            )
            return
        fmt = redist_mod.format_size
        if available >= need:
            self.log.info(
                "Место под распаковку: свободно "
                f"{fmt(available)}, установщику нужно около {fmt(need)} "
                "(TEMP — в папке портатива)."
            )
            return

        root = space_mod.pick_temp_root(portable_dir, need)
        target = self._make_external_temp(root, opts) if root else ""
        if not target:
            self._temp_space_note = (
                f"На диске «{space_mod.volume_of(portable_dir) or portable_dir}» "
                f"свободно {fmt(available)}, а установщику нужно около "
                f"{fmt(need)}: распаковка идёт через TEMP, и в момент "
                "установки на диске должны уместиться и дистрибутив, и "
                "распакованная копия. Места хватит, если освободить диск или "
                "собирать портатив на другом диске."
            )
            self.log.warn(self._temp_space_note)
            return

        self._install_temp_dir = target
        self.log.warn(
            f"На диске «{space_mod.volume_of(portable_dir) or portable_dir}» "
            f"свободно {fmt(available)}, а установщику нужно около "
            f"{fmt(need)}: он распаковывает данные в TEMP. Переношу "
            f"временную папку установщика на другой диск: {target}. "
            "Папка будет удалена сразу после сборки."
        )
        if getattr(det, "is_gog", False):
            self.log.info(
                "  • GOG-установщик распаковывает данные в TEMP целиком — "
                "именно поэтому места нужно вдвое больше веса дистрибутива."
            )

    def _make_external_temp(self, root: str, opts: PortableOptions) -> str:
        """Создаёт временную папку вне портатива и берёт её на уборку."""
        safe = "".join(c for c in self._safe_name(opts)
                       if c.isalnum() or c in "-_")[:40] or "installer"
        target = os.path.join(root, f"{EXTERNAL_TEMP_PREFIX}{safe}-Temp")
        try:
            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
            os.makedirs(target, exist_ok=True)
        except OSError as exc:
            self.log.debug(f"  • временную папку вне портатива создать не "
                           f"удалось: {exc}")
            return ""
        self._external_temp_dirs.append(target)
        return target

    def _cleanup_install_temp(self) -> None:
        """Убирает временные папки, созданные ВНЕ портатива.

        TEMP внутри портативной папки не трогаем: он принадлежит лончеру и
        нужен программе при запуске. А перенесённая папка — чужая территория,
        на компьютере пользователя её оставлять нельзя.
        """
        for path in list(self._external_temp_dirs):
            if not os.path.isdir(path):
                continue
            try:
                procutil.release_folder(path, stop_services=False)
            except Exception as exc:  # noqa: BLE001 - уборка не ломает сборку
                self.log.debug(f"  • не удалось опросить процессы временной "
                               f"папки: {exc}")
            try:
                shutil.rmtree(path)
            except OSError as exc:
                self.log.warn(
                    f"Временную папку установщика удалить не удалось: {path} "
                    f"({exc}). Её можно удалить вручную — в ней нет ничего "
                    "нужного."
                )
            else:
                self.log.info(f"Временная папка установщика удалена: {path}")
        self._external_temp_dirs = []

    # -- диагностика падения ---------------------------------------------------
    def _fill_temp_fields(self, result: "PortableResult",
                          portable_dir: str) -> None:
        """Переносит в результат сведения о временном месте и о падении.

        Итоговое окно показывает их пользователю: где установщик брал
        временное место и есть ли отчёт о падении, который стоит открыть.
        """
        # Наблюдение за пакетами заканчивается вместе со сборкой: поток не
        # должен продолжать читать чужие временные каталоги после неё.
        self._stop_adobe_watcher()
        if self._adobe_detected and portable_dir:
            self._write_adobe_report(portable_dir,
                                     os.path.basename(portable_dir),
                                     getattr(self, "_detection", None))
        if result.success:
            shutil.rmtree(os.path.join(portable_dir, "_adobe_grabbed"),
                          ignore_errors=True)
        result.installer_temp_dir = self._install_temp_dir
        result.unpacked_with = self._unpacked_with
        result.adobe_note_rel = self._adobe_note_rel
        result.adobe_report_rel = self._adobe_report_rel
        if not portable_dir:
            return
        report = os.path.join(portable_dir, crash_mod.CRASH_LOG_NAME)
        if os.path.isfile(report):
            result.crash_report_rel = os.path.relpath(report, portable_dir)

    def _note_crash(self, plan: SilentPlan, rc: Optional[int],
                    command: str, console_log: Optional[str]) -> None:
        """Собирает факты о падении установщика и пишет ``installer-crash.log``.

        Код возврата говорит только «процесс упал». Где именно и в каком
        модуле — знает журнал событий Windows, поэтому после падения он
        читается один раз: имя модуля отделяет падение самого установщика от
        вмешательства чужого кода (антивируса, оверлея, инжектора).
        """
        if not crash_mod.is_crash_code(rc):
            return
        self._crash_history.append((plan.label, int(rc)))  # type: ignore[arg-type]
        names = [name for name in (self._installer_name,
                                   os.path.basename(plan.program)) if name]
        try:
            events = crash_mod.read_crash_events(names, since=self._run_started)
        except Exception as exc:  # noqa: BLE001 - журнал не ломает сборку
            self.log.debug(f"  • журнал событий прочитать не удалось: {exc}")
            events = []
        if events:
            # Накапливаем (в подсказках пригодится любая запись этого запуска),
            # а в отчёт выше попадают только записи ТЕКУЩЕГО падения.
            self._crash_events = events
            first = events[0]
            where = crash_mod.module_verdict(first.module, first.module_path,
                                             self._installer_name)
            self.log.warn(
                "  • журнал событий: упал " + (first.module or "неизвестный "
                                               "модуль")
                + (f" ({first.module_path})" if first.module_path else "")
                + (f" — {where}." if where else ".")
            )
        else:
            self.log.debug("  • записей об этом падении в журнале событий нет.")

        if not console_log:
            return
        report = crash_mod.format_report(
            rc, plan.label, command, events,
            installer_path=self._installer_name,
            temp_line=self._temp_line(),
            # Версия — чтобы по одной жалобе сразу было видно, какая сборка
            # это написала: старые версии давали неверный диагноз.
            version=__version__,
        )
        path = os.path.join(os.path.dirname(console_log),
                            crash_mod.CRASH_LOG_NAME)
        try:
            with open(path, "a", encoding="utf-8-sig", newline="\r\n") as fh:
                fh.write(report)
                fh.write("\n")
        except OSError as exc:
            self.log.debug(f"  • отчёт о падении записать не удалось: {exc}")
        else:
            self.log.info(f"Отчёт о падении сохранён: {path}")

    def _temp_line(self) -> str:
        """Строка про временное место для отчёта о падении."""
        if not self._install_temp_dir:
            return ""
        available = space_mod.free_space(self._install_temp_dir)
        text = f"TEMP установщика: {self._install_temp_dir}"
        if available >= 0:
            text += f" (свободно {redist_mod.format_size(available)})"
        if self._install_temp_dir in self._external_temp_dirs:
            text += " [перенесён с диска портатива из-за нехватки места]"
        return text

    def _last_crash_rc(self) -> Optional[int]:
        if self._crash_history:
            return self._crash_history[-1][1]
        return None

    def _crash_retry_note(self) -> str:
        """Подсказка про уже сделанный повтор с окном прогресса."""
        if not self._progress_retry_done:
            return ""
        return ("Portablizer уже пробовал этот установщик с окном прогресса "
                "(/SILENT вместо /VERYSILENT) — падение повторилось, значит "
                "причина не в отрисовке тихого прогресса.")

    # -- самораспаковывающийся архив: сначала содержимое, потом установка ------
    #
    # Обёртка-SFX (WinRAR SFX, 7-Zip SFX, WinZip Self-Extractor, IExpress) —
    # это не установщик, а программа распаковки. Ключи тишины она не разбирает
    # и передаёт их своей программе установки как получится; при неизвестном
    # ключе она может показать модальное окно и ждать нажатия «ОК» — а сборка
    # в это время видит «процессы живы, работы нет» и ждёт по четверти часа на
    # каждый сценарий. Ровно так выглядела попытка портировать MultiTran
    # (3,7 ГБ, WinRAR SFX поверх Inno Setup): 47 минут, ноль файлов, ноль
    # процессорного времени.
    #
    # Поэтому для SFX порядок обратный: сначала достать содержимое, НЕ выполняя
    # код обёртки (7-Zip/WinRAR/tar.exe или сама обёртка с «-s -d<папка>»), а
    # затем — если внутри нашёлся настоящий установщик — запустить его
    # собственными ключами, а не ключами обёртки. Если настоящего установщика
    # нет, содержимое и есть программа: оно переносится в App как есть.

    def _container_first_worth_trying(self, det: Optional[DetectionResult]) -> bool:
        """Стоит ли доставать содержимое SFX до запуска его обёртки.

        Только самораспаковывающийся архив и только когда у него нет
        собственного разбора ключей: у известных перепаков (KpoJIuK и
        подобных) и у профилей производителей команда документирована
        автором, и распаковка «в общую кучу» только помешает.
        """
        if not IS_WINDOWS or det is None:
            return False
        if getattr(det, "is_downloader_stub", False) is True:
            return False
        if self._adobe_detected:
            # Adobe разбирается своим сценарием: его содержимое — пакеты, а не
            # папка программы (см. _run_payload_plan).
            return False
        if det.installer_type != InstallerType.SELF_EXTRACT:
            return False
        if det.repack_profile is not None or det.vendor_name:
            return False
        return True

    def _run_container_first(self, opts: PortableOptions, app_dir: str,
                             data_dir: str, portable_dir: str,
                             det: Optional[DetectionResult], name: str,
                             recover: Optional[Callable[[], bool]] = None,
                             progress_from: int = 30,
                             progress_to: int = 58,
                             ) -> Optional[Tuple[Optional[int], Optional[SilentPlan]]]:
        """Достаёт содержимое SFX и ставит программу, не доверяя обёртке.

        Возвращает ``(код, сработавший план)`` при успехе и ``None``, если
        сценарий не подошёл: тогда сборка идёт обычной лестницей ключей.
        """
        if not self._container_first_worth_trying(det):
            return None
        source = opts.installer_path
        if not os.path.isfile(source):
            return None
        self._check_cancel()
        work = os.path.join(portable_dir, "_sfx_content")
        shutil.rmtree(work, ignore_errors=True)
        try:
            os.makedirs(work, exist_ok=True)
        except OSError as exc:
            self.log.warn(f"Не удалось создать папку распаковки SFX: {exc}")
            return None
        console_log = os.path.join(portable_dir, "installer-output.log")
        self.progress(progress_from, "Распаковка самораспаковывающегося архива")
        self.log.info(
            "Это самораспаковывающийся архив: сначала достаю его содержимое, "
            "не выполняя код обёртки. Ключи тишины обёртка не разбирает — "
            "именно поэтому она может стоять без работы часами."
        )

        need = 0
        try:
            need = int(space_mod.media_bytes(source))
        except Exception:  # noqa: BLE001 - оценка размера необязательна
            need = 0
        available = space_mod.free_space(portable_dir)
        if need > 0 and 0 <= available < need:
            self.log.warn(
                "Для распаковки содержимого на диске портатива нужно около "
                f"{redist_mod.format_size(need)}, а свободно "
                f"{redist_mod.format_size(available)}. Распаковка может "
                "оборваться — освободите место или собирайте портатив на "
                "другом диске."
            )
        files, method = self._extract_container_to(
            source, work, opts, console_log,
            progress=(progress_from, max(progress_from, progress_to - 8)))
        if not files:
            self.log.warn(
                "Достать содержимое архива без запуска не удалось (ни 7-Zip, "
                "ни WinRAR, ни встроенный tar.exe, ни сама обёртка с «-s -d»). "
                "Возвращаюсь к обычной лестнице ключей тишины."
            )
            shutil.rmtree(work, ignore_errors=True)
            return None
        self.log.ok(
            f"Содержимое архива получено без запуска обёртки ({method}): "
            f"файлов {files}. Теперь ставлю программу изнутри."
        )

        nested = self._find_nested_setup(work)
        if nested:
            # Если вложенный setup.exe не принадлежит известному движку
            # (Inno/NSIS/InstallShield/Burn), а рядом в распакованном архиве
            # УЖЕ лежит готовый exe самой программы (как в WinRAR SFX со
            # словарями Multitran), переносим содержимое напрямую в App, не
            # запуская самописный setup.exe с чужими ключами /DIR= и /D=.
            if (self._nested_installer_kind(nested) == InstallerType.UNKNOWN
                    and self._container_payload_program_exe(work, name, nested) is not None
                    and self._promote_container_payload(work, app_dir, name, nested)):
                shutil.rmtree(work, ignore_errors=True)
                return 0, None
            result = self._install_from_container(
                nested, work, opts, app_dir, data_dir, portable_dir, name,
                recover=recover,
                progress_from=max(progress_from, progress_to - 8),
                progress_to=progress_to,
                console_log=console_log)
            if result is not None:
                shutil.rmtree(work, ignore_errors=True)
                return result
            # Настоящий установщик был, но программу не поставил: либо не
            # прошёл ни один ключ тишины, либо открыл свой мастер, не
            # принял переданный путь и завис/вылетел. Перед тем как
            # бросать распакованное содержимое, даём два отката:
            # 1) переносим в App само содержимое контейнера, если там
            #    уже лежит запускаемая программа (у Multitran — файлы
            #    словаря); 2) достаём payload вложенного контейнера
            #    (Inno Setup/NSIS) без запуска распаковщиком. Голый
            #    setup.exe в App не переносим — это не программа.
            if self._promote_container_payload(
                    work, app_dir, name, nested):
                shutil.rmtree(work, ignore_errors=True)
                return 0, None
            if self._promote_nested_installer_payload(
                    nested, app_dir, portable_dir, name):
                shutil.rmtree(work, ignore_errors=True)
                return 0, None
            self.log.warn(
                "Установщик изнутри архива не дал файлов программы. "
                "Распакованное удаляю, чтобы не занимать гигабайты, и "
                "возвращаюсь к обычной лестнице сценариев."
            )
            shutil.rmtree(work, ignore_errors=True)
            return None

        if not self._tree_has_executable(work):
            # Внутри только документы/данные: переносить их в App нельзя —
            # программой они не являются, а папку они бы засорили.
            self.log.warn(
                "Внутри архива нет ни одного запускаемого exe — это не "
                "программа, а данные. Переносить их в App не буду: "
                "возвращаюсь к обычной лестнице сценариев."
            )
            shutil.rmtree(work, ignore_errors=True)
            return None

        copied = unpacker_mod.promote_payload(
            work, app_dir, installer_path=source)
        if copied and self._find_main_exe(app_dir, name):
            self._unpacked_with = method
            self.log.ok(
                "Содержимое самораспаковывающегося архива перенесено в App "
                f"напрямую (файлов: {copied}) — код обёртки не выполнялся."
            )
            shutil.rmtree(work, ignore_errors=True)
            return 0, None
        if copied:
            self.log.warn(
                f"В App перенесено файлов: {copied}, но запускаемого exe "
                "программы среди них не нашлось — папка оставлена для "
                "проверки: " + work
            )
        else:
            shutil.rmtree(work, ignore_errors=True)
        return None

    def _extract_container_to(self, source: str, work: str,
                              opts: PortableOptions, console_log: str,
                              progress: "Tuple[int, int]" = (30, 50),
                              ) -> "Tuple[int, str]":
        """Распаковывает контейнер в ``work``. Возвращает ``(файлов, чем)``.

        Порядок тот же, что у сборки пакетов Adobe, и по той же причине:
        распаковщиков на машине может не быть ни одного, зато подойдёт любой
        (7-Zip, WinRAR, встроенный ``tar.exe``), а в самом крайнем случае
        распакуется сама обёртка документированным ``-s -d<папка>``.
        """
        extractors = unpacker_mod.find_extractors()
        if extractors:
            names = ", ".join(str(item) for item in extractors)
            self.log.info(f"Распаковщики на этом компьютере: {names}.")
        else:
            self.log.info(
                "Сторонних распаковщиков нет — попробую саму обёртку с "
                "«-s -d<папка>»."
            )
        for extractor in extractors:
            self._check_cancel()
            archive = source
            carved = ""
            if extractor.style in (unpacker_mod.STYLE_RAR,
                                   unpacker_mod.STYLE_TAR):
                # Эти инструменты читают сам архив, а не PE-обёртку.
                archive, _kind = unpacker_mod.carve_archive(source, work)
                if not archive:
                    continue
                carved = archive
            cmd = unpacker_mod.extractor_argv(extractor, archive, work)
            try:
                code, output = self._run_unpacker_command(
                    cmd, console_log, opts, progress=progress,
                    stage=f"Распаковка архива ({extractor.name})")
            finally:
                if carved and os.path.isfile(carved):
                    try:
                        os.remove(carved)
                    except OSError:
                        pass
            ok_codes = (0, 1) if extractor.style == unpacker_mod.STYLE_7ZIP \
                else (0,)
            files = self._count_files(work)
            if code in ok_codes and files:
                return files, extractor.name
            # Очищаем обрывки после неудачной попытки (например, tar.exe на
            # solid RAR успевает создать первый пустой файл и падает с кодом 1).
            self._reset_work_dir(work)
            tail = " ".join((output or "").split())[-200:]
            self.log.info(
                f"{extractor.name} не дал файлов (код {code})"
                + (f": {tail}" if tail else "") + " — пробую дальше."
            )
        # Последний способ: пусть распакуется сама обёртка. Её собственную
        # программу установки мы снимем — нужны только файлы.
        nested = ""
        try:
            nested = self._sfx_self_extract(source, work, opts, console_log,
                                            progress)
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001 - запасной путь необязателен
            self.log.warn(f"Распаковка самой обёрткой не удалась: {exc}")
        files = self._count_files(work)
        if files:
            return files, "сама обёртка (-s -d)"
        if nested:
            self.log.info(
                "Обёртка отдала только установщик без данных рядом: "
                f"{os.path.basename(nested)}."
            )
        return 0, ""

    @staticmethod
    def _reset_work_dir(work: str) -> None:
        """Очищает рабочую папку после неудачной попытки распаковщика."""
        if not work or not os.path.isdir(work):
            return
        try:
            entries = list(os.scandir(work))
        except OSError:
            return
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path, ignore_errors=True)
                else:
                    os.remove(entry.path)
            except OSError:
                pass

    @staticmethod
    def _tree_has_executable(root: str, limit: int = 2000) -> bool:
        """Есть ли в папке хоть один exe (быстрый обход с потолком)."""
        if not root or not os.path.isdir(root):
            return False
        seen = 0
        for _current, _dirs, names in os.walk(root):
            for name in names:
                seen += 1
                if name.casefold().endswith(".exe"):
                    return True
                if seen > limit:
                    return False
        return False

    @staticmethod
    def _count_files(root: str, limit: int = 5000) -> int:
        """Сколько файлов лежит в папке (быстрый обход с потолком)."""
        total = 0
        if not root or not os.path.isdir(root):
            return 0
        for _current, _dirs, names in os.walk(root):
            total += len(names)
            if total >= limit:
                return total
        return total

    def _nested_installer_kind(self, path: str) -> InstallerType:
        """Какой движок у установщика, найденного внутри архива.

        Читается начало и конец файла: у Inno Setup и NSIS сигнатуры лежат в
        загрузчике (начало), у InstallShield — тоже рядом с ним. Полный
        разбор файла здесь не нужен и стоил бы секунд на гигабайтах.
        """
        try:
            size = os.path.getsize(path)
            chunk = 4 * 1024 * 1024
            with open(path, "rb") as handle:
                head = handle.read(chunk)
                if size > chunk:
                    handle.seek(max(0, size - chunk))
                    tail = handle.read(chunk)
                else:
                    tail = b""
        except OSError:
            return InstallerType.UNKNOWN
        data = head + tail
        checks = (
            (b"Inno Setup", InstallerType.INNO),
            (b"JR.Inno.Setup", InstallerType.INNO),
            (b"Nullsoft Install System", InstallerType.NSIS),
            (b"NullsoftInst", InstallerType.NSIS),
            (b"InstallShield", InstallerType.INSTALLSHIELD),
            (b"WixBurn", InstallerType.WIX_BURN),
        )
        for needle, kind in checks:
            if needle in data:
                return kind
        return InstallerType.UNKNOWN

    def _plans_for_nested_setup(self, nested: str, app_dir: str,
                                opts: PortableOptions) -> List[SilentPlan]:
        """Тихие команды для установщика, найденного внутри SFX.

        Обёртке чужие ключи не подходят, а самому установщику — подходят его
        собственные: у Inno Setup это ``/VERYSILENT /DIR=``, у NSIS —
        ``/S /D=``. Порядок — от точного к общему.
        """
        kind = self._nested_installer_kind(nested)
        label_suffix = f" (внутри SFX: {os.path.basename(nested)})"
        plans: List[SilentPlan] = []
        if kind == InstallerType.INNO:
            args = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                    "/NOICONS"]
            language = (opts.install_language or "").strip()
            if language:
                found = find_language(language)
                if found is not None:
                    args.append(f"/LANG={found.inno_name}")
            plans.append(SilentPlan(
                program=nested, args=args,
                raw_tail=f'/DIR="{app_dir}"',
                notes=["Установщик внутри архива — Inno Setup: ему передаются "
                       "его собственные ключи, а не ключи обёртки."],
                label="Inno Setup внутри SFX: /VERYSILENT /DIR=" + label_suffix,
                output_dir=app_dir,
            ))
            plans.append(SilentPlan(
                program=nested, args=args,
                notes=["Тот же установщик без ключа папки: путь берётся из "
                       "настроек, а готовую программу сборка заберёт из "
                       "каталога по умолчанию."],
                label="Inno Setup внутри SFX без /DIR" + label_suffix,
                output_dir=app_dir, ignores_target_dir=True,
                prefers_installer_default_dir=True,
            ))
        elif kind == InstallerType.NSIS:
            plans.append(SilentPlan(
                program=nested, args=["/S"], raw_tail=f"/D={app_dir}",
                notes=["Установщик внутри архива — NSIS: /S и /D=<App> "
                       "последним без кавычек."],
                label="NSIS внутри SFX: /S /D=" + label_suffix,
                output_dir=app_dir,
            ))
        elif kind == InstallerType.INSTALLSHIELD:
            plans.append(SilentPlan(
                program=nested,
                args=["/s", "/v/qn", f"/vINSTALLDIR=\"{app_dir}\""],
                notes=["Установщик внутри архива — InstallShield: тихая "
                       "установка через /s и свойства MSI."],
                label="InstallShield внутри SFX: /s /v/qn" + label_suffix,
                output_dir=app_dir,
            ))
        if not plans:
            # Движок не опознан: пробуем два самых распространённых набора.
            plans.append(SilentPlan(
                program=nested,
                args=["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"],
                raw_tail=f'/DIR="{app_dir}"',
                notes=["Движок установщика внутри архива не опознан: сначала "
                       "ключи Inno Setup."],
                label="Установщик из архива: /VERYSILENT" + label_suffix,
                output_dir=app_dir,
            ))
            plans.append(SilentPlan(
                program=nested, args=["/S"], raw_tail=f"/D={app_dir}",
                notes=["Если это NSIS, работают /S и /D=<App>."],
                label="Установщик из архива: /S /D=" + label_suffix,
                output_dir=app_dir,
            ))
        return plans

    def _install_from_container(self, nested: str, work: str,
                                opts: PortableOptions, app_dir: str,
                                data_dir: str, portable_dir: str, name: str,
                                recover: Optional[Callable[[], bool]] = None,
                                progress_from: int = 40,
                                progress_to: int = 58,
                                console_log: Optional[str] = None,
                                ) -> Optional[Tuple[Optional[int], Optional[SilentPlan]]]:
        """Запускает установщик из архива его собственными ключами."""
        self.log.info(
            "Внутри архива лежит настоящий установщик: "
            f"{os.path.basename(nested)}. Запускаю его своими ключами тишины — "
            "обёртка их не понимает, а он понимает."
        )
        # Установщик из архива лежит в нашей рабочей папке и не является
        # файлом, который выбрал пользователь: подменять его путь в
        # логах/отчётах нельзя, поэтому план хранит собственный program.
        plans = self._plans_for_nested_setup(nested, app_dir, opts)
        for plan in plans:
            self._check_cancel()
            rc = self._run_install(
                plan, opts, app_dir, data_dir,
                progress_from=progress_from, progress_to=progress_to,
                console_log=console_log)
            if self._find_main_exe(app_dir, name):
                self.log.ok(f"Сработал сценарий: {plan.label}")
                return rc, plan
            if plan.ignores_target_dir and recover is not None:
                # Установщик мог поставить программу в каталог по
                # умолчанию и завершиться нестандартным кодом — особенно
                # когда он провёл весь мастер через диалоги и вернул 1.
                # recover() сам ничего не переносит, если не нашёл нового
                # каталога с именем программы, поэтому зовём без gate по
                # коду выхода: иначе готовая установка остаётся лежать
                # в Program Files, а App остаётся пустым.
                if recover():
                    self.log.ok(
                        "Программа установлена в каталог по умолчанию и "
                        f"перенесена в App. Сценарий: {plan.label}"
                    )
                    return rc, plan
        return None

    # -- распаковка без запуска ------------------------------------------------
    #: Запускаемые, которые не могут быть «главной программой» при переносе
    #: распакованного содержимого контейнера: это установщики и их
    #: служебные утилиты. Их в App переносить нельзя — получается пустой
    #: портатив, который запускает опять же установщик.
    _PAYLOAD_INSTALLER_NAMES = frozenset({
        "setup.exe", "install.exe", "installer.exe", "uninstall.exe",
        "unins000.exe", "unins001.exe", "setup.bin", "install.bin",
        "installshield.exe", "vc_redist.exe", "vcredist.exe",
    })

    @classmethod
    def _container_payload_program_exe(cls, work: str, name: str,
                                       nested: str) -> Optional[str]:
        """Запускаемая программа среди распакованного содержимого контейнера.

        Имя вложенного установщика (``setup.exe``) и прочие имена
        установщиков исключаются: перенесённый голый установщик — не
        программа.
        """
        best = None
        best_score = 0
        bad_prefixes = (
            "unins", "vcredist", "vc_redist", "dxsetup", "ndp", "dotnet",
            "directx", "physx", "oalinst", "ue4prereq", "crash", "unitycrash",
        )
        for root, _dirs, files in os.walk(work):
            for f in files:
                if not f.lower().endswith(".exe"):
                    continue
                path = os.path.join(root, f)
                if nested and os.path.abspath(path) == os.path.abspath(nested):
                    continue
                base = f.lower()
                if base in cls._PAYLOAD_INSTALLER_NAMES or base.startswith(bad_prefixes):
                    continue
                stem = os.path.splitext(f)[0]
                # Даём положительный базовый балл любому не-служебному exe
                # программы: имя архива («mt_2025-03-06.exe») или папки
                # («Multitran») может не совпадать с именем exe («mt.exe»,
                # «multitran.exe», «network.exe»).
                score = 20 + cls._app_name_score(stem, name)
                try:
                    score -= os.path.relpath(path, work).count(os.sep) * 2
                except ValueError:
                    pass
                if score > best_score:
                    best, best_score = path, score
        return best

    def _promote_container_payload(self, work: str, app_dir: str,
                                   name: str, nested: str) -> bool:
        """Переносим распакованное содержимое контейнера в App.

        Только если внутри уже лежит запускаемая программа: у обёрток
        вроде Multitran это файлы словаря, а не только setup.exe. Внутренний
        установщик в App не переносится (``installer_path=nested``).
        """
        if self._container_payload_program_exe(work, name, nested) is None:
            return False
        try:
            copied = unpacker_mod.promote_payload(
                work, app_dir, installer_path=nested)
        except Exception as exc:  # noqa: BLE001 - перенос не должен ронять сборку
            self.log.warn(f"Перенос содержимого контейнера в App не удалось: {exc}")
            return False
        main_exe = self._find_main_exe(app_dir, name)
        base = os.path.basename(main_exe or "").lower()
        if not main_exe or base in self._PAYLOAD_INSTALLER_NAMES or base.startswith("unins"):
            return False
        self._unpacked_with = "sfx-content"
        self.log.ok(
            "Файлы программы из содержимого контейнера перенесены в App "
            f"({copied} файлов)."
        )
        return True

    def _promote_nested_installer_payload(self, nested: str, app_dir: str,
                                          portable_dir: str, name: str) -> bool:
        """Достаём payload вложенного контейнера БЕЗ запуска установщика.

        Внутренний Inno Setup/NSIS — обычный контейнер; установленный
        распаковщик читает его напрямую, код установщика не выполняется,
        так что он не спрашивает App и не ломает сборку своим мастером.
        """
        kind = self._nested_installer_kind(nested)
        if kind not in (InstallerType.INNO, InstallerType.NSIS):
            return False
        unpacker = unpacker_mod.find_unpacker()
        if not unpacker:
            self.log.info(
                "Распаковщик (7-Zip) на этом компьютере не найден: достать "
                "содержимое вложенного установщика без запуска нечем."
            )
            return False
        work = os.path.join(portable_dir, "_nested_unpacked")
        shutil.rmtree(work, ignore_errors=True)
        self.log.info(
            "Достаю содержимое вложенного установщика без его запуска: "
            f"{os.path.basename(unpacker)} читает такие контейнеры напрямую."
        )
        try:
            ok, message = unpacker_mod.unpack_installer(
                unpacker, nested, app_dir, work, installer_path=nested)
        except Exception as exc:  # noqa: BLE001 - распаковка не должна ронять сборку
            self.log.warn(f"Распаковка вложенного установщика не удалось: {exc}")
            return False
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if not ok:
            self.log.warn(
                "Содержимое вложенного установщика без запуска не дало "
                f"файлов программы: {message}"
            )
            return False
        main_exe = self._find_main_exe(app_dir, name)
        base = os.path.basename(main_exe or "").lower()
        if not main_exe or base in self._PAYLOAD_INSTALLER_NAMES or base.startswith("unins"):
            return False
        self._unpacked_with = unpacker
        self.log.ok(
            "Содержимое вложенного установщика достали без запуска — "
            f"файлы программы в App ({message})."
        )
        return True

    def _unpacker_worth_trying(self, det: DetectionResult) -> bool:
        """Есть ли смысл доставать содержимое установщика распаковщиком."""
        return det.installer_type in UNPACKABLE_TYPES

    def _try_unpacker_fallback(self, opts: PortableOptions, app_dir: str,
                               portable_dir: str, det: DetectionResult,
                               name: str) -> bool:
        """Достаёт файлы программы из установщика БЕЗ его запуска.

        Когда установщик падает или не понимает ни одного ключа тишины,
        остаётся последний честный путь: Inno Setup и NSIS — это обычные
        контейнеры, и установленный на компьютере 7-Zip читает их, не
        выполняя код установщика. Системе это не делает ничего, прав
        администратора не требует, а программа оказывается в ``App``.

        Свой распаковщик Portablizer с собой не носит и не скачивает: сборка
        не должна молча тянуть из сети исполняемые файлы. Не нашлось — так и
        говорится в подсказках.
        """
        if getattr(det, "is_downloader_stub", False) is True:
            self.log.info(
                "Распаковщик не запускаю: файл распознан как сетевой "
                "загрузчик, а не как контейнер с файлами программы."
            )
            return False
        if self._adobe_detected:
            # У Adobe контейнер — это набор пакетов (payloads, MSI, Appx), а не
            # папка программы: копировать его в App бессмысленно. Пакеты
            # раскладывает отдельный сценарий (см. _run_payload_plan), он же
            # пропускает UWP-шаг с кодом 191.
            self.log.info(
                "Распаковку «в общую кучу» не делаю: это установщик Adobe, "
                "его содержимое — пакеты, а не папка программы."
            )
            return False
        if not self._unpacker_worth_trying(det):
            return False
        unpacker = unpacker_mod.find_unpacker()
        if not unpacker:
            self.log.info(
                "Распаковщик (7-Zip) на этом компьютере не найден: достать "
                "содержимое установщика без запуска нечем. В подсказках ниже "
                "сказано, что это меняет."
            )
            return False

        self._check_cancel()
        self.progress(63, "Распаковка установщика без запуска")
        self.log.info(
            "Пробую достать файлы программы из установщика без его запуска: "
            f"{os.path.basename(unpacker)} читает такие контейнеры напрямую."
        )
        work = os.path.join(portable_dir, "_unpacked")
        shutil.rmtree(work, ignore_errors=True)
        console_log = os.path.join(portable_dir, "unpacker-output.log")

        def runner(cmd, timeout):  # noqa: ANN001 - подпись задана unpacker'ом
            return self._run_unpacker_command(cmd, console_log, opts)

        try:
            ok, message = unpacker_mod.unpack_installer(
                unpacker, opts.installer_path, app_dir, work, runner=runner,
                installer_path=opts.installer_path)
        finally:
            shutil.rmtree(work, ignore_errors=True)

        if ok and self._find_main_exe(app_dir, name):
            self._unpacked_with = unpacker
            self.log.ok(
                "Установщик распакован без запуска — файлы программы в папке "
                f"App ({message})."
            )
            return True
        self._unpacker_result = (
            f"Распаковка без запуска ({os.path.basename(unpacker)}) не дала "
            f"файлов программы: {message}"
        )
        self.log.warn(self._unpacker_result)
        return False

    def _run_unpacker_command(self, cmd: Sequence[str], console_log: str,
                              opts: PortableOptions,
                              progress: "Tuple[int, int]" = (63, 65),
                              stage: str = "Распаковка установщика",
                              env: "Optional[Dict[str, str]]" = None,
                              deadline: Optional[float] = None,
                              stop_when: Optional[Callable[[], bool]] = None,
                              ) -> "Tuple[int, str]":
        """Запускает распаковщик с возможностью отмены и отчётом о ходе.

        Распаковка десятков гигабайт идёт минутами, поэтому у неё тот же
        контракт, что у установки: видимый прогресс, реакция на «Отменить» и
        жёсткий потолок по времени вместо молчаливого зависания.

        ``progress`` — отрезок общей полосы, на котором виден ход распаковки:
        у сценария Adobe он свой (лестница попыток идёт с 30 до 58 %), а не
        63–65 %, где живёт «последний шанс» после установки.

        ``env`` и ``deadline`` нужны самораспаковывающимся архивам: свой
        временный каталог (чтобы распакованное не уехало в чужой TEMP) и
        короткий потолок — SFX после распаковки запускает свою программу
        установки, которая может показать окно и ждать мышку.

        ``stop_when`` — «работа сделана, дальше она ждёт мышку»: если функция
        вернёт True, процесс снимается вместе с потомками, а распакованное
        остаётся на диске. Именно так забирается содержимое SFX, чья
        программа установки заблокирована Защитником Windows: ждать «ОК» в
        модальном окне бессмысленно.
        """
        handle = None
        try:
            handle = open(console_log, "wb")
            handle.write(("===== распаковка без запуска =====\r\n"
                          + " ".join(cmd) + "\r\n").encode("utf-8", "replace"))
            handle.flush()
        except OSError:
            handle = None
        creationflags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        try:
            proc = subprocess.Popen(
                list(cmd), stdin=subprocess.DEVNULL,
                stdout=handle or subprocess.DEVNULL,
                stderr=subprocess.STDOUT if handle else subprocess.DEVNULL,
                creationflags=creationflags, env=env)
        except OSError as exc:
            if handle is not None:
                handle.close()
            return -1, str(exc)

        deadline = (float(deadline) if deadline
                    else float(opts.install_deadline) or UNPACK_HARD_LIMIT)
        started = time.monotonic()
        timed_out = False
        last_io_bytes = 0
        last_cpu_seconds = 0.0
        last_proc_active = 0.0
        dialog_state: Dict[Tuple[int, str], Tuple[str, float]] = {}
        unpack_target_dir = ""
        for arg in cmd:
            if isinstance(arg, str) and arg.startswith("-d") and len(arg) > 2:
                unpack_target_dir = arg[2:]
                break
        while proc.poll() is None:
            if self.cancel.is_set():
                self._stop_installer(proc)
                if handle is not None:
                    handle.close()
                raise RuntimeError("Операция отменена пользователем.")
            now = time.monotonic()
            elapsed = now - started
            fraction = creep_fraction(elapsed, scale=120.0)
            # Несколько процентов вместо одного: плавная полоса должна
            # сдвигаться, иначе она замирала бы на всё время распаковки.
            low, high = progress
            self._emit_progress(low + int(max(0, high - low) * fraction), stage)
            self._detail(
                min(99, int(fraction * 100)),
                "Распаковка без запуска идёт "
                f"{redist_mod.format_duration(elapsed)}")
            if deadline and elapsed > deadline:
                timed_out = True
                self._stop_installer(proc)
                break
            if stop_when is not None:
                activity = procutil.process_activity(proc.pid)
                if (activity.io_bytes > last_io_bytes
                        or activity.cpu_seconds - last_cpu_seconds >= 0.05):
                    last_io_bytes = max(last_io_bytes, activity.io_bytes)
                    last_cpu_seconds = max(last_cpu_seconds, activity.cpu_seconds)
                    last_proc_active = now
                if unpack_target_dir and activity.pids:
                    try:
                        redist_mod._dismiss_installer_dialogs(
                            target_dir=unpack_target_dir,
                            pids=activity.pids,
                            state=dialog_state,
                        )
                    except Exception:  # noqa: BLE001 - WinAPI необязателен
                        pass
                # WinRAR SFX заранее резервирует полный размер крупного файла
                # через SetEndOfFile и затем десятки секунд пишет в него данные.
                # Пока процесс активно читает архив или пишет на диск, снимать
                # его по замершему os.path.getsize() нельзя.
                proc_busy = (last_proc_active > 0.0
                             and (now - last_proc_active) < 4.0)
                if not proc_busy and stop_when():
                    self.log.debug(
                        "  • распаковка закончена — снимаю процесс, не дожидаясь "
                        "его собственной установки.")
                    self._stop_installer(proc)
                    break
            time.sleep(0.5)
        rc = proc.returncode if not timed_out else -1
        if handle is not None:
            try:
                handle.write(f"<<< код: {rc} >>>\r\n".encode("utf-8", "replace"))
                handle.close()
            except OSError:
                pass
        if timed_out:
            return -1, "распаковка снята по пределу времени"
        return int(rc or 0), _text_tail(console_log)

    # -- Adobe: обход UWP-шага (код ошибки 191) -------------------------------
    #
    # Установщик Adobe ставит программу в два этапа: пакеты MSI и UWP-пакет
    # (Appx, шаг AddUWPAppxCommand). Второй этап регистрирует пакет в Windows
    # для ВСЕХ пользователей и падает с «кодом 191» везде, где нет рабочей
    # службы AppX, разрешения на неопубликованные приложения, системного тома
    # или прав администратора. При этом он отменяет установку целиком.
    #
    # Портативу этот шаг не нужен: сама программа — обычное Win32-приложение.
    # Поэтому пакеты берутся из контейнера установщика (любым архиватором) или из каталога
    # payloads рядом с ним, а если контейнер не читается — из adobeTemp, куда
    # установщик успевает их разложить ДО падения на UWP-шаге. Разбор и тексты
    # живут в core/adobe.py, здесь только решения оркестратора.

    def _run_payload_plan(self, plan: SilentPlan, opts: PortableOptions,
                          app_dir: str, data_dir: str, name: str,
                          portable_dir: str = "",
                          console_log: Optional[str] = None,
                          progress_from: int = 30,
                          progress_to: int = 58) -> Optional[int]:
        """Раскладывает пакеты установщика в App, не запуская его.

        Источников три, и проверяются они по порядку: сам контейнер
        установщика (7-Zip/WinRAR/tar.exe, а для ZIP-оболочки — стандартная
        библиотека),
        каталог ``payloads`` рядом с установщиком (пакет Adobe Admin Console)
        и — уже после запуска установщика, отдельным шагом —
        ``adobeTemp`` (см. :meth:`_salvage_adobe_payloads`). Возвращает код
        0, если в App появился исполняемый файл, иначе — понятную причину в
        журнале и код -1.
        """
        if not IS_WINDOWS:
            self.log.warn(
                "Не Windows: раскладка пакетов установщика невозможна.")
            return None

        work = plan.output_dir or os.path.join(portable_dir, "_adobe_payloads")
        shutil.rmtree(work, ignore_errors=True)
        try:
            os.makedirs(work, exist_ok=True)
        except OSError as exc:
            self.log.warn(f"Не удалось создать папку распаковки: {exc}")
            return -1

        layout = adobe_mod.AdobeLayout(root=work)
        layout = self._extract_adobe_container(
            opts, work, layout, console_log=console_log,
            portable_dir=portable_dir,
            progress=(progress_from, max(progress_from, progress_to - 2)))

        # Контейнер установщика может оказаться обычным ZIP (так устроены
        # некоторые оболочки Adobe). Тогда внешний распаковщик не обязателен:
        # стандартная библиотека распакует его сама — и код установщика снова
        # не выполняется.
        if layout.is_empty and getattr(self._detection, "has_zip_payload",
                                       False):
            self.log.info(
                "Контейнер установщика — обычный ZIP: распаковываю его без "
                "внешнего распаковщика и без запуска установщика.")
            ok, text = adobe_mod.extract_zip(
                self._adobe_installer_source(opts), work)
            if ok:
                layout = adobe_mod.find_payloads(
                    work, installer_path=opts.installer_path)
            else:
                self.log.warn(f"Распаковать ZIP установщика не удалось: {text}")

        # Второй источник: готовый каталог payloads рядом с установщиком
        # (распакованный пакет Admin Console, папка Build).
        media = getattr(self._detection, "media_dir", "") or os.path.dirname(
            opts.installer_path)
        if media:
            # Только ближайшие каталоги: ``payloads`` в пакете Admin Console
            # лежит прямо рядом с setup.exe или в ``Build``. Глубже искать
            # нельзя — в соседних папках могут оказаться чужие MSI (и наша же
            # распаковка внутри папки портатива).
            nearby = adobe_mod.find_payloads(
                media, payload_dirs_only=True, max_depth=2,
                installer_path=opts.installer_path)
            if nearby.has_app_payload:
                self.log.info(
                    "Пакеты Adobe найдены рядом с установщиком: "
                    + ", ".join(os.path.basename(p) for p in nearby.payload_dirs))
                layout.extend(nearby)

        if layout.is_empty:
            # Пакетов MSI/ZIP нет, но внутри мог оказаться настоящий
            # установщик программы (SFX-обёртка над setup.exe). Его запуск —
            # единственный оставшийся путь: обёртка ключей тишины не понимает,
            # а он понимает.
            if self._attempt_nested_adobe_setup(
                    opts, app_dir, data_dir, name, portable_dir=portable_dir,
                    console_log=console_log, progress_from=progress_from,
                    progress_to=progress_to):
                shutil.rmtree(work, ignore_errors=True)
                return 0
            self.log.warn(
                "Пакетов программы Adobe найти не удалось: ни внутри "
                "контейнера, ни в каталоге payloads рядом с установщиком.")
            self._adobe_source = ""
            self._adobe_applied = None
            self._keep_work_for_inspection(work)
            return -1

        self.log.info(f"Найдено в установщике Adobe: {layout.summary()}.")
        applied = self._install_adobe_payloads(
            layout, opts, app_dir, data_dir, name,
            portable_dir=portable_dir, console_log=console_log,
            progress_from=max(progress_from, progress_to - 3),
            progress_to=progress_to)
        self._adobe_source = layout.root
        if self._find_main_exe(app_dir, name):
            shutil.rmtree(work, ignore_errors=True)
            self.log.ok(
                "Пакеты Adobe разложены в App без запуска установщика — "
                "UWP-шаг с кодом 191 не выполнялся."
            )
            if portable_dir:
                self._installer_path = opts.installer_path
                self._write_adobe_report(portable_dir, name,
                                         getattr(self, "_detection", None))
            return 0

        if self._attempt_nested_adobe_setup(
                opts, app_dir, data_dir, name, portable_dir=portable_dir,
                console_log=console_log, progress_from=progress_to,
                progress_to=progress_to):
            shutil.rmtree(work, ignore_errors=True)
            return 0

        self.log.warn(
            "Пакеты Adobe разложены, но исполняемого файла программы в App "
            "нет: возможно, в этой сборке только UWP-часть (Appx) без MSI. "
            f"Распакованное оставлено для проверки: {work}"
        )
        return -1

    def _attempt_nested_adobe_setup(self, opts: PortableOptions, app_dir: str,
                                    data_dir: str, name: str,
                                    portable_dir: str = "",
                                    console_log: Optional[str] = None,
                                    progress_from: int = 55,
                                    progress_to: int = 58) -> bool:
        """Запускает установщик, найденный внутри контейнера, если он есть."""
        setup = self._adobe_nested_setup
        if not setup or not os.path.isfile(setup):
            return False
        # Установщик из контейнера — такой же Adobe: он раскладывает пакеты во
        # временный каталог и убирает их при откате. Значит, наблюдение нужно
        # и здесь, а не только в общей лестнице попыток.
        self._start_adobe_watcher(portable_dir, opts)
        rc = self._run_nested_adobe_setup(
            setup, opts, app_dir, data_dir, console_log=console_log,
            progress_from=progress_from, progress_to=progress_to)
        if self._find_main_exe(app_dir, name):
            self.log.ok(
                "Программа поставлена установщиком из контейнера — без "
                "UWP-шага (Appx не устанавливался).")
            return True
        self.log.warn(
            f"Установщик из контейнера не дал файлов программы (код {rc}).")
        self._salvage_adobe_payloads(
            opts, app_dir, data_dir, name, portable_dir=portable_dir,
            console_log=console_log)
        return bool(self._find_main_exe(app_dir, name))

    def _keep_work_for_inspection(self, work: str) -> None:
        """Оставляет распакованное для разбора — или убирает пустую папку.

        Если архиватор всё же что-то распаковал, выбрасывать это нельзя: по
        folder видно, что внутри сборки, и это же можно поставить вручную.
        Пустой каталог, наоборот, только мешает.
        """
        if not os.path.isdir(work):
            return
        try:
            has_files = any(files for _c, _d, files in os.walk(work))
        except OSError:
            has_files = False
        if has_files:
            self.log.info(
                "Распакованное содержимое оставлено для проверки: " + work)
        else:
            shutil.rmtree(work, ignore_errors=True)

    def _run_nested_adobe_setup(self, setup: str, opts: PortableOptions,
                                app_dir: str, data_dir: str,
                                console_log: Optional[str] = None,
                                progress_from: int = 55,
                                progress_to: int = 58,
                                ) -> Optional[int]:
        """Запускает установщик, найденный внутри контейнера.

        Обёртка-SFX не понимает ``--silent``, а её внутренний установщик —
        понимает: он и есть настоящий установщик Adobe. Ключи те же, что в
        лестнице, но папка установки указывает на App. Его собственный отказ
        на UWP-шаге нас не смущает: пакеты он успевает разложить в
        ``adobeTemp``, откуда их забирает сборка.
        """
        self.log.info(
            f"Запускаю установщик из контейнера: {os.path.basename(setup)} "
            "(обёртка-SFX ключей тишины не понимает, а он понимает).")
        # Свой план, а не шаблон движка: у вложенного установщика Adobe свой
        # разбор командной строки, и подставлять ему чужие ключи (/S, /quiet,
        # /VERYSILENT) нельзя — он на них отвечает мгновенным отказом.
        plan = SilentPlan(
            program=setup,
            args=["--silent", f"--ADOBEINSTALLDIR={app_dir}"],
            notes=["Установщик, найденный внутри контейнера: документированные "
                   "ключи Adobe --silent и --ADOBEINSTALLDIR."],
            label="Adobe: установщик из контейнера (--silent)",
            output_dir=app_dir,
        )
        try:
            return self._run_install(
                plan, opts, app_dir, data_dir,
                progress_from=progress_from, progress_to=progress_to,
                console_log=console_log)
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001 - необязательный шаг
            self.log.warn(f"Запустить установщик из контейнера не удалось: {exc}")
            return None

    def _adobe_installer_source(self, opts: PortableOptions) -> str:
        """Путь к установщику, с которым можно работать.

        Adobe отвечает кодом 1000, когда установщик лежит на сетевом диске
        (это подтверждено в сообществе Adobe), и часто отказывается работать
        со съёмного. Поэтому такой файл один раз копируется на локальный диск
        — и дальше и распаковка, и запуск идут с копии.
        """
        if self._adobe_media_copy:
            return self._adobe_media_copy
        source = opts.installer_path
        if not adobe_mod.portable_media_drive(source):
            return source
        try:
            folder = tempfile.mkdtemp(prefix="PortablizerMedia-")
            target = os.path.join(folder, os.path.basename(source))
            self.log.info(
                "Установщик Adobe лежит на съёмном или сетевом диске, а "
                "Adobe с таких носителей не работает (код 1000). Копирую его "
                "на локальный диск — это разово и не меняет исходный файл.")
            shutil.copy2(source, target)
        except OSError as exc:
            self.log.warn(
                f"Скопировать установщик на локальный диск не удалось: {exc}. "
                "Работаю с исходного места — Adobe на таком носителе обычно "
                "отвечает кодом 1000.")
            return source
        self._adobe_media_copy = target
        self._adobe_media_dir = folder
        self.log.ok(f"Копия установщика для Adobe: {target}")
        return target

    def _drop_adobe_media_copy(self) -> None:
        """Убирает локальную копию установщика (гигабайты в TEMP)."""
        if self._adobe_media_dir:
            shutil.rmtree(self._adobe_media_dir, ignore_errors=True)
        self._adobe_media_copy = ""
        self._adobe_media_dir = ""

    def _extract_adobe_container(self, opts: PortableOptions, work: str,
                                 layout: adobe_mod.AdobeLayout,
                                 console_log: Optional[str] = None,
                                 portable_dir: str = "",
                                 progress: "Tuple[int, int]" = (30, 56),
                                 ) -> adobe_mod.AdobeLayout:
        """Достаёт пакеты из контейнера установщика, не выполняя его код.

        Распаковщиков на машине может не быть вовсе — и это не тупик.
        Установщик Adobe обычно приходит самораспаковывающимся EXE поверх RAR
        или 7z, поэтому подойдёт любой архиватор, который уже есть:

        * 7-Zip (самый точный разбор SFX);
        * WinRAR — консольные ``UnRAR.exe``/``Rar.exe``;
        * **встроенный в Windows ``tar.exe``** (bsdtar из libarchive): с
          Windows 10 он читает ZIP, 7z и RAR/RAR5, и доустанавливать ничего
          не нужно. Именно этот путь работает, когда 7-Zip не установлен.

        libarchive и UnRAR читают сам архив, а не PE-обёртку, поэтому для них
        архив сначала вырезается из EXE (:func:`unpacker.carve_archive`).
        """
        extractors = unpacker_mod.find_extractors()
        if not extractors:
            self.log.warn(
                "Распаковщиков не найдено вовсе: ни 7-Zip, ни WinRAR, ни "
                "встроенного tar.exe. Пробую каталог payloads рядом с "
                "установщиком."
            )
            return layout

        source = self._adobe_installer_source(opts)
        if (unpacker_mod.archive_kind(source) == "zip"
                and getattr(self._detection, "has_zip_payload", False)):
            self.log.info(
                "Контейнер установщика — обычный ZIP: его распакует "
                "стандартная библиотека Python, внешний распаковщик не нужен.")
            return layout

        names = ", ".join(str(item) for item in extractors)
        self.log.info(
            "Достаю пакеты Adobe из установщика без его запуска: подойдёт "
            f"любой архиватор ({names}) — UWP-шаг (код 191) при этом не "
            "выполняется вовсе.")
        self._adobe_steps.append(f"найдены распаковщики: {names}")

        unpack_log = console_log or os.path.join(portable_dir,
                                                 "unpacker-output.log")
        for extractor in extractors:
            self._check_cancel()
            archive = source
            carved = ""
            if extractor.style in (unpacker_mod.STYLE_RAR,
                                   unpacker_mod.STYLE_TAR):
                # Эти инструменты не ищут архив внутри PE-обёртки: отрезаем
                # обёртку и отдаём им сам архив.
                archive, kind = unpacker_mod.carve_archive(source, work)
                if not archive:
                    self.log.info(
                        f"{extractor.name} не умеет читать PE-обёртку, а "
                        "приклеенного RAR/7z внутри не нашлось — пробую "
                        "следующий способ.")
                    self._adobe_steps.append(
                        f"{extractor.name}: в установщике нет приклеенного "
                        "RAR/7z (только PE-обёртка)")
                    continue
                carved = archive
                self.log.info(
                    f"{extractor.name} читает сам архив ({kind}), поэтому "
                    f"вырезаю его из установщика: {os.path.basename(archive)}."
                )
            cmd = unpacker_mod.extractor_argv(extractor, archive, work)
            try:
                code, output = self._run_unpacker_command(
                    cmd, unpack_log, opts, progress=progress,
                    stage=f"Распаковка пакета Adobe ({extractor.name})")
            except RuntimeError:
                shutil.rmtree(work, ignore_errors=True)
                raise
            finally:
                if carved and os.path.isfile(carved):
                    try:
                        os.remove(carved)
                    except OSError:
                        pass
            # У 7-Zip код 1 — это предупреждение («часть файлов не
            # распакована»), а у tar.exe и UnRAR — обычная ошибка. Раньше это
            # различие скрывало настоящую причину: архив не читался вовсе, а в
            # журнале не было ни слова, потому что код 1 считался успехом.
            ok_codes = (0, 1) if extractor.style == unpacker_mod.STYLE_7ZIP \
                else (0,)
            if code not in ok_codes:
                tail = " ".join((output or "").split())[-300:]
                self.log.warn(
                    f"{extractor.name} завершился с кодом {code}: контейнер "
                    "установщика прочитать не удалось."
                    + (f" Ответ архиватора: {tail}" if tail else ""))
                self._adobe_steps.append(
                    f"{extractor.name}: код {code}"
                    + (f", ответ: {tail}" if tail else ""))
            layout = adobe_mod.find_payloads(
                work, installer_path=opts.installer_path)
            self._adobe_steps.append(
                f"{extractor.name}: распаковано, пакетов программы "
                f"{'найдено' if layout.has_app_payload else 'не найдено'}"
                f" ({layout.summary()})")
            if layout.has_app_payload:
                return layout
            self._log_extracted_tree(work, extractor.name)
            if extractor is not extractors[-1]:
                self.log.info(
                    f"{extractor.name} не дал пакетов программы — пробую "
                    "следующий распаковщик.")

        # Последний способ, который не зависит от чужих библиотек: попросить
        # распаковаться сам установщик. WinRAR-SFX понимает -d<папка> и -s,
        # и файлы остаются в нашей папке даже если его собственная установка
        # тут же падает (у Adobe она и падает — код 191/1000).
        nested = self._sfx_self_extract(source, work, opts, unpack_log,
                                        progress)
        layout = adobe_mod.find_payloads(
            work, installer_path=opts.installer_path)
        if layout.has_app_payload:
            return layout
        self._log_extracted_tree(work, "SFX")

        if nested:
            # Внутри контейнера — обычный установщик программы. Запускает его
            # отдельный шаг (см. _run_payload_plan), а здесь только сообщаем.
            self._adobe_nested_setup = nested
            self.log.info(
                f"Внутри контейнера лежит установщик программы: "
                f"{os.path.basename(nested)} — поставлю его отдельным шагом.")

        if layout.is_empty:
            self.log.warn(
                "Внутри контейнера не нашлось пакетов Adobe "
                "(payloads/MSI/ZIP).")
        else:
            self.log.warn(
                "Внутри контейнера нашлись только UWP-пакеты: пакетов "
                "программы (MSI/ZIP) в этой сборке нет.")
        return layout

    def _log_extracted_tree(self, work: str, who: str) -> None:
        """Пишет в журнал, что именно оказалось в папке распаковки.

        Без этого «пакетов не нашлось» ничего не объясняет: непонятно, архив
        не прочитался вовсе или внутри лежит что-то другое. Список верхних
        уровней отвечает на этот вопрос сразу.
        """
        if not os.path.isdir(work):
            self.log.debug(f"  • {who}: папка распаковки не создана.")
            return
        files = 0
        total = 0
        tops: List[str] = []
        for current, dirs, names in os.walk(work):
            depth = os.path.relpath(current, work).count(os.sep)
            if os.path.relpath(current, work) == ".":
                tops.extend(sorted(dirs)[:8])
            if depth > 2:
                dirs[:] = []
                continue
            for name in names:
                files += 1
                try:
                    total += os.path.getsize(os.path.join(current, name))
                except OSError:
                    pass
        if not files:
            self.log.debug(f"  • {who}: в папке распаковки пусто.")
            return
        sizes = redist_mod.format_size(total)
        listing = ", ".join(tops[:8]) if tops else "без подкаталогов"
        self.log.info(
            f"  • {who}: распаковано файлов {files} ({sizes}); верхний "
            f"уровень: {listing}.")
        executables = []
        for current, _dirs, names in os.walk(work):
            for name in names:
                if name.casefold().endswith((".exe", ".msi", ".appx", ".msix",
                                             ".zip", ".cab")):
                    executables.append(os.path.join(current, name))
            if len(executables) > 400:
                break
        for path in executables[:8]:
            self.log.debug(f"  • файл: {os.path.relpath(path, work)}")
        if len(executables) > 8:
            self.log.debug(f"  • …и ещё {len(executables) - 8} файлов.")

    def _sfx_self_extract(self, source: str, work: str, opts: PortableOptions,
                          unpack_log: str,
                          progress: "Tuple[int, int]" = (30, 56)) -> str:
        """Просит распаковаться сам установщик (``-s -d<папка>``).

        Это запасной путь для самораспаковывающихся архивов, которые чужие
        библиотеки не читают (libarchive, например, не понимает часть
        RAR5-архивов). WinRAR-SFX документированно принимает ``-d<папка>`` и
        ``-s``.

        Две тонкости, из-за которых этот шаг раньше пропадал зря:

        * SFX после распаковки **запускает свою программу установки**
          (у пакета Adobe это ``Nsudo.exe`` — помощник повышения прав). Её
          может заблокировать Защитник Windows, и тогда показывается модальное
          окно «файл содержит вирус», а сборка ждёт мышку. Поэтому запуск
          ограничен по времени, а процесс снимается вместе с потомками.
        * Временный каталог SFX всё равно создаёт свой (``RarSFX0``). Ему
          подставляется TEMP внутри папки сборки, а после запуска содержимое
          ``RarSFX*``/``7zSFX*`` переносится в рабочую папку — даже если
          установка внутри SFX так и не началась.
        """
        if not IS_WINDOWS or not os.path.isfile(source):
            return ""
        self.log.info(
            "Архиваторы контейнер не прочитали. Прошу распаковаться сам "
            "установщик: WinRAR-SFX понимает «-s -d<папка>», а его программу "
            "установки мы сразу снимем — нам нужны только файлы.")
        source = os.path.normpath(source)
        work = os.path.normpath(work)
        sfx_temp = os.path.join(work, "_sfx_temp")
        try:
            os.makedirs(sfx_temp, exist_ok=True)
        except OSError:
            sfx_temp = ""
        env = dict(os.environ)
        if sfx_temp:
            # Свой TEMP: иначе SFX распакуется в общий временный каталог, и
            # найти его можно будет только перебором всей системы.
            env.update({"TEMP": sfx_temp, "TMP": sfx_temp})
        watch_roots = [sfx_temp, work] if sfx_temp else [work]
        try:
            code, output = self._run_unpacker_command(
                [source, "-s", f"-d{work}"], unpack_log, opts,
                progress=progress, stage="Распаковка самим установщиком",
                env=env, deadline=adobe_mod.SFX_UNPACK_LIMIT,
                stop_when=self._sfx_extraction_finished(watch_roots))
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001 - запасной путь не должен ронять сборку
            self.log.warn(f"Запустить установщик для распаковки не удалось: {exc}")
            return ""
        tail = " ".join((output or "").split())[-200:]
        self.log.debug(
            f"  • установщик-распаковщик завершился с кодом {code}"
            + (f": {tail}" if tail else ""))

        # Забираем то, что SFX успел разложить. Смотрим его собственный TEMP,
        # TEMP установщика и системные места: модуль может выбрать любое.
        roots: List[str] = []
        if sfx_temp:
            roots.append(sfx_temp)
        roots.append(work)
        if self._install_temp_dir:
            roots.append(self._install_temp_dir)
        roots.extend(adobe_mod.default_temp_roots())
        dirs = adobe_mod.find_sfx_dirs(roots)
        copied = adobe_mod.harvest_dirs(dirs, work) if dirs else 0
        shutil.rmtree(sfx_temp, ignore_errors=True)
        if copied:
            self.log.info(
                "Самораспаковка разложила файлы во временный каталог "
                f"({os.path.basename(dirs[0])}): забрал оттуда {copied} "
                "файл(ов) — программа установки внутри SFX нам не нужна.")
        elif not self._count_files(work):
            self.log.info(
                "Самораспаковка не оставила файлов: SFX либо не смог "
                "распаковаться, либо убрал за собой временный каталог.")
        return self._find_nested_setup(work)

    @staticmethod
    def _sfx_extraction_finished(roots: Sequence[str],
                                 calm: float = 8.0) -> Callable[[], bool]:
        """Ждёт, когда SFX перестанет писать файлы, и просит снять процесс.

        SFX распаковывается, а потом запускает свою программу установки — и
        висит, пока кто-нибудь не нажмёт «ОК» в её окне (а если программу
        заблокировал Защитник Windows — не нажмёт никто). Нам нужны только
        файлы, поэтому как только их общий размер перестал расти на
        ``calm`` секунд, распаковка считается законченной.
        """
        state: Dict[str, float] = {"size": -1.0, "since": 0.0, "seen": 0.0,
                                   "next": 0.0}

        def check() -> bool:
            now = time.monotonic()
            # Обход папки распаковки может стоить секунды (архив на десятки
            # тысяч файлов), а вызывается эта проверка дважды в секунду.
            # Поэтому после дорогого обхода следующий откладывается: иначе
            # наблюдение за распаковкой замедляло бы саму распаковку.
            if now < state["next"]:
                return False
            total = 0.0
            for root in roots:
                if not root or not os.path.isdir(root):
                    continue
                for current, _dirs, files in os.walk(root):
                    for item in files:
                        try:
                            total += os.path.getsize(
                                os.path.join(current, item))
                        except OSError:
                            continue
            spent = time.monotonic() - now
            if spent > 0.2:
                state["next"] = time.monotonic() + min(5.0, spent * 4)
            if total <= 0:
                return False
            if total != state["size"]:
                state["size"] = total
                state["since"] = time.monotonic()
                state["seen"] = state["since"]
                return False
            return (time.monotonic() - state["since"]) >= calm

        return check

    def _find_nested_setup(self, work: str) -> str:
        """Настоящий установщик внутри контейнера (SFX-обёртка над setup.exe)."""
        wanted = ("setup.exe", "set-up.exe", "install.exe", "installer.exe",
                  "xdsetup.exe", "adobesetup.exe")
        candidates: List[str] = []
        for current, _dirs, names in os.walk(work):
            for name in names:
                folded = name.casefold()
                if folded in wanted:
                    candidates.append(os.path.join(current, name))
                elif folded.endswith(".exe") and "setup" in folded:
                    candidates.append(os.path.join(current, name))
        if not candidates:
            return ""
        # Ставим самый «главный» на вид: setup/set-up важнее прочих.
        candidates.sort(key=lambda path: (
            os.path.basename(path).casefold() not in wanted, len(path)))
        return candidates[0]

    def _start_adobe_watcher(self, portable_dir: str,
                             opts: PortableOptions) -> None:
        """Начинает снимать пакеты, которые установщик раскладывает на лету."""
        if not self._adobe_detected or self._adobe_watcher is not None:
            return
        target = os.path.join(portable_dir, "_adobe_grabbed")
        roots: List[str] = []
        if self._install_temp_dir:
            roots.append(self._install_temp_dir)
        roots.extend(adobe_mod.default_temp_roots())
        watcher = adobe_mod.PayloadWatcher(roots, target)
        try:
            watcher.start()
        except Exception as exc:  # noqa: BLE001 - наблюдение необязательно
            self.log.debug(f"  • сбор пакетов на лету не запустился: {exc}")
            return
        self._adobe_watcher = watcher
        self.log.debug(
            "  • пока установщик работает, пакеты снимаются с диска: он "
            "убирает их при откате.")

    def _stop_adobe_watcher(self) -> None:
        watcher = self._adobe_watcher
        if watcher is None:
            return
        watcher.stop()
        self._adobe_watcher = None

    def _install_adobe_payloads(self, layout: adobe_mod.AdobeLayout,
                                opts: PortableOptions, app_dir: str,
                                data_dir: str, name: str,
                                portable_dir: str = "",
                                console_log: Optional[str] = None,
                                progress_from: int = 55,
                                progress_to: int = 58,
                                ) -> adobe_mod.ApplyResult:
        """Ставит пакеты Adobe в App и объясняет, что пропущено.

        MSI ставятся административной установкой (``msiexec /a``) — так же,
        как пакеты WiX Burn: файлы попадают в App, а система не меняется.
        ZIP распаковываются стандартной библиотекой, UWP-пакеты не трогаются.
        """
        def install_msi(msi_path: str) -> Optional[int]:
            self.log.info(
                f"Раскладываю пакет Adobe в App: {os.path.basename(msi_path)}")
            msi_plan = build_silent_plan(
                InstallerType.MSI, msi_path, app_dir, is_msi=True)
            return self._run_install(
                msi_plan, opts, app_dir, data_dir,
                progress_from=progress_from, progress_to=progress_to,
                console_log=console_log)

        # Вложенные архивы (7z/cab/rar) сначала раскрываются: внутри них и
        # лежат пакеты программы. Стандартная библиотека такие форматы не
        # читает — нужен любой из найденных архиваторов.
        layout = self._expand_adobe_packs(
            layout, opts, console_log=console_log, portable_dir=portable_dir)
        self._adobe_layout = layout
        applied = adobe_mod.materialize(layout, app_dir, install_msi)
        self._adobe_applied = applied
        self.log.info(f"Итог по пакетам Adobe: {applied.summary()}.")
        for name_failed, reason in applied.msi_failed:
            self.log.warn(f"Пакет {name_failed} не разложился: {reason}")
        for name_failed, reason in applied.archives_failed:
            self.log.warn(f"Архив {name_failed} не распаковался: {reason}")
        if applied.skipped_uwp:
            self.log.info(
                "UWP-пакеты пропущены (это и есть обход кода 191): "
                + ", ".join(applied.skipped_uwp)
                + ". Плитка в меню «Пуск» и другие UWP-точки входа в портатив "
                "не переносятся, для запуска программы они не нужны.")
        if portable_dir:
            self._write_adobe_note(portable_dir, name, applied)
        return applied

    def _expand_adobe_packs(self, layout: adobe_mod.AdobeLayout,
                            opts: PortableOptions,
                            console_log: Optional[str] = None,
                            portable_dir: str = "") -> adobe_mod.AdobeLayout:
        """Раскрывает вложенные архивы (7z/cab/rar) и добавляет их содержимое.

        В раскладке Adobe пакеты иногда лежат не «голыми» MSI, а сжатыми в
        архив: сам установщик распаковывает их по ходу. Раз он падает на
        UWP-шаге, распаковать их должны мы — иначе в App нечего ставить.
        """
        packs = layout.packs
        if not packs:
            return layout
        extractors = unpacker_mod.find_extractors()
        if not extractors:
            self.log.warn(
                "Внутри сборки есть архивы с пакетами, но распаковщика нет — "
                "раскрыть их нечем.")
            return layout
        extractor = extractors[0]
        target = os.path.join(layout.root or portable_dir, "_expanded")
        unpack_log = console_log or os.path.join(portable_dir,
                                                 "unpacker-output.log")
        for pack in packs:
            self._check_cancel()
            self.log.info(
                f"Раскрываю архив с пакетами Adobe: {pack.name} "
                f"({extractor.name}).")
            try:
                code, output = self._run_unpacker_command(
                    unpacker_mod.extractor_argv(extractor, pack.path, target),
                    unpack_log, opts, progress=(54, 56),
                    stage="Раскрытие архива Adobe")
            except RuntimeError:
                raise
            ok_codes = (0,) if extractor.style != unpacker_mod.STYLE_7ZIP \
                else (0, 1)
            if code not in ok_codes:
                tail = " ".join((output or "").split())[-200:]
                self.log.warn(
                    f"{extractor.name} не раскрыл {pack.name} (код {code})"
                    + (f": {tail}" if tail else ""))
                continue
            found = adobe_mod.find_payloads(target,
                                            installer_path=opts.installer_path)
            if found.is_empty:
                self.log.debug(f"  • в {pack.name} пакетов не нашлось.")
                continue
            self.log.info(f"  • в {pack.name}: {found.summary()}.")
            layout.extend(found)
        return layout

    def _salvage_adobe_payloads(self, opts: PortableOptions, app_dir: str,
                                data_dir: str, name: str,
                                portable_dir: str = "",
                                console_log: Optional[str] = None) -> bool:
        """Забирает пакеты, которые установщик Adobe уже распаковал в TEMP.

        Установщик раскладывает payload в ``adobeTemp\\ETRxxxx.tmp\\N`` и
        только потом падает на UWP-шаге. Даже если контейнер установщика
        сторонним распаковщиком не читается, эти пакеты никуда не делись:
        из них можно собрать портатив. TEMP установщика принадлежит сборке
        (``PortableData\Temp``), поэтому сначала смотрим туда, потом — в
        системный ``adobeTemp``.
        """
        self._adobe_salvage_attempted = True
        if self._adobe_applied is not None and self._adobe_applied.has_result:
            # Пакеты из этого же временного каталога уже разложены: повторять
            # установку тех же MSI на каждом следующем сценарии незачем.
            self.log.debug(
                "Пакеты Adobe уже разложены из временного каталога — "
                "повторять не буду.")
            return False

        # Снятые «на лету» пакеты — самый надёжный источник: при откате
        # установщик их уже удалил, а копии остались.
        if self._adobe_watcher is not None:
            self._adobe_watcher.stop()
            grabbed = self._adobe_watcher.layout()
            self._adobe_watcher = None
            if grabbed.has_app_payload:
                self.log.info(
                    "Пока установщик работал, пакеты удалось снять с диска: "
                    f"{grabbed.summary()}. Ставлю их в App.")
                self._install_adobe_payloads(
                    grabbed, opts, app_dir, data_dir, name,
                    portable_dir=portable_dir, console_log=console_log,
                    progress_from=56, progress_to=58)
                self._adobe_source = grabbed.root
                if self._find_main_exe(app_dir, name):
                    self.log.ok(
                        "Программа собрана из пакетов, снятых на лету, — без "
                        "UWP-шага.")
                    return True

        roots: List[str] = []
        if self._install_temp_dir:
            roots.append(self._install_temp_dir)
        if portable_dir:
            roots.append(os.path.join(portable_dir, "_adobe_payloads"))
        roots.extend(adobe_mod.default_temp_roots())

        # Внешняя оболочка Adobe — сама WinRAR-SFX: она распаковывает себя в
        # ``RarSFX0`` и запускает оттуда установку. Если та не пошла (а её
        # помощник повышения прав ещё и блокирует Защитник Windows —
        # «файл содержит вирус»), распакованное всё равно остаётся на диске.
        # Забираем его первым делом: это самый полный набор файлов.
        sfx_dirs = adobe_mod.find_sfx_dirs(roots)
        if sfx_dirs:
            harvest_dir = os.path.join(portable_dir or roots[0],
                                       "_adobe_grabbed", "sfx")
            copied = adobe_mod.harvest_dirs(sfx_dirs, harvest_dir)
            if copied:
                self.log.info(
                    "Самораспаковка установщика оставила файлы во временном "
                    f"каталоге ({os.path.basename(sfx_dirs[0])}): забрал "
                    f"оттуда {copied} файл(ов).")
                harvested = adobe_mod.find_payloads(
                    harvest_dir, installer_path=opts.installer_path)
                if harvested.has_app_payload:
                    self.log.info(
                        "Из них пакеты программы: " + harvested.summary() + ".")
                    applied = self._install_adobe_payloads(
                        harvested, opts, app_dir, data_dir, name,
                        portable_dir=portable_dir, console_log=console_log,
                        progress_from=56, progress_to=58)
                    self._adobe_source = harvest_dir
                    if self._find_main_exe(app_dir, name):
                        self.log.ok(
                            "Программа собрана из файлов, распакованных самим "
                            "установщиком, — без UWP-шага.")
                        return True
                roots.append(harvest_dir)

        layout = adobe_mod.find_payloads_in_roots(roots)
        if not layout.has_app_payload:
            self.log.debug(
                "Распакованных пакетов Adobe во временных каталогах нет: "
                "установщик убрал их при откате.")
            return False

        self.log.info(
            "Установщик Adobe успел распаковать пакеты до отказа на "
            f"UWP-шаге: {layout.summary()}. Забираю их в App — сам "
            "установщик для этого запускать не нужно."
        )
        for note in layout.notes[:4]:
            self.log.debug(f"  • {note}")
        applied = self._install_adobe_payloads(
            layout, opts, app_dir, data_dir, name,
            portable_dir=portable_dir, console_log=console_log,
            progress_from=56, progress_to=58)
        self._adobe_source = layout.root
        if self._find_main_exe(app_dir, name):
            self.log.ok(
                "Программа собрана из пакетов, распакованных установщиком "
                "Adobe, — без UWP-шага.")
            return True
        self.log.warn(
            "Пакеты из временного каталога Adobe не дали исполняемого файла "
            f"в App. Что удалось разложить: {applied.summary()}.")
        return False

    def _write_adobe_report(self, portable_dir: str, name: str,
                            det: Optional[DetectionResult] = None) -> None:
        """Пишет ``adobe-report.txt`` — что именно происходило со сборкой.

        Adobe — единственный установщик, где «не собралось» может означать
        десяток разных вещей: архиватор не прочитал контейнер, пакеты удалились
        при откате, MSI не принял папку. Без общего отчёта каждый такой случай
        приходится угадывать по длинному журналу, поэтому всё важное
        складывается в один файл рядом с портативом.
        """
        if not portable_dir:
            return
        lines: List[str] = [
            f"Отчёт сборки портатива: {name}",
            "=" * 60,
            f"Версия Portablizer: {__version__}",
        ]
        if det is not None:
            lines.append(f"Установщик: {det.installer_type.value} "
                         f"(уверенность {int(det.confidence * 100)}%)")
        if opts_path := getattr(self, "_installer_path", ""):
            lines.append(f"Файл: {opts_path}")
        lines.append("")

        lines.append("Что было сделано")
        lines.append("-" * 60)
        lines.extend(f"  • {step}" for step in self._adobe_steps) if self._adobe_steps \
            else lines.append("  (шаги не записаны)")

        watcher = self._adobe_watcher
        if watcher is not None:
            captured = list(watcher.captured)
            if captured:
                lines.append("")
                lines.append("Пакеты, снятые с диска во время установки")
                lines.append("-" * 60)
                lines.extend(f"  • {os.path.basename(path)}" for path in captured)

        layout = self._adobe_layout
        if layout is not None and not layout.is_empty:
            lines.append("")
            lines.append("Найденные пакеты")
            lines.append("-" * 60)
            for payload in layout.payloads:
                lines.append(f"  • {payload.kind}: {payload.path}")

        applied = self._adobe_applied
        if applied is not None:
            lines.append("")
            lines.append("Что получилось")
            lines.append("-" * 60)
            lines.append(f"  итог: {applied.summary()}")
            for name_ok in applied.msi_ok:
                lines.append(f"  • MSI разложен: {name_ok}")
            for name_bad, reason in applied.msi_failed:
                lines.append(f"  • MSI не разложился: {name_bad} — {reason}")
            for name_ok in applied.archives_ok:
                lines.append(f"  • архив распакован: {name_ok}")
            for name_bad, reason in applied.archives_failed:
                lines.append(f"  • архив не распакован: {name_bad} — {reason}")
            for name_uwp in applied.skipped_uwp:
                lines.append(f"  • UWP пропущен (это и есть обход кода 191): "
                             f"{name_uwp}")

        # Что в итоге лежит в App — главный ответ на вопрос «а собралось ли».
        app_dir = os.path.join(portable_dir, "App")
        lines.append("")
        lines.append("Содержимое App")
        lines.append("-" * 60)
        tops: List[str] = []
        exes: List[str] = []
        for current, _dirs, files in os.walk(app_dir):
            relative = os.path.relpath(current, app_dir)
            if relative == ".":
                tops.extend(sorted(_dirs)[:12])
            for item in files:
                if item.casefold().endswith(".exe"):
                    exes.append(os.path.relpath(os.path.join(current, item),
                                                app_dir))
        if tops:
            lines.append("  верхний уровень: " + ", ".join(tops))
        if exes:
            lines.append(f"  исполняемых файлов: {len(exes)}")
            lines.extend(f"  • {path}" for path in exes[:25])
        else:
            lines.append("  исполняемых файлов нет")

        path = os.path.join(portable_dir, adobe_mod.ADOBE_REPORT_NAME)
        try:
            self._write_text(path, "\n".join(lines) + "\n")
        except OSError as exc:
            self.log.debug(f"  • отчёт Adobe не записан: {exc}")
            return
        self._adobe_report_rel = os.path.relpath(path, portable_dir)
        self.log.info(f"Подробный отчёт о сборке Adobe: {path}")

    def _write_adobe_note(self, portable_dir: str, name: str,
                          applied: adobe_mod.ApplyResult) -> None:
        """Пишет рядом объяснение, чего в портативе нет и почему.

        Без этого файла пользователь, увидев в журнале «UWP пропущен»,
        решит, что сборка недоделана. Объяснение остаётся рядом с портативом
        и переезжает вместе с ним.
        """
        failure = self._adobe_failure
        if failure is None and portable_dir:
            failure = self._read_adobe_failure(portable_dir)
        path = os.path.join(portable_dir, adobe_mod.ADOBE_NOTE_NAME)
        try:
            self._write_text(
                path, adobe_mod.note_text(name, applied, failure=failure,
                                          source=self._adobe_source))
        except OSError as exc:
            self.log.warn(f"Не удалось записать {adobe_mod.ADOBE_NOTE_NAME}: "
                          f"{exc}")
            return
        self._adobe_note_rel = os.path.relpath(path, portable_dir)

    def _read_adobe_failure(self, portable_dir: str
                            ) -> Optional[adobe_mod.AdobeFailure]:
        """Разбирает причину отказа Adobe из журналов сборки.

        Сначала — собственный вывод установщика (``installer-output.log``),
        затем журнал внутри портатива (``install.log``). Точная причина
        (шаг, пакет, OS-код Appx) важнее кода возврата: именно она отличает
        «не хватило прав» от «служба AppX отключена».
        """
        candidates = [os.path.join(portable_dir, "installer-output.log"),
                      os.path.join(portable_dir, "install.log")]
        for path in candidates:
            try:
                with open(path, "rb") as handle:
                    text = handle.read(512 * 1024).decode("utf-8", "replace")
            except OSError:
                continue
            failure = adobe_mod.parse_failure(text)
            if failure is not None:
                return failure
        return None

    def _adobe_hints(self, det: DetectionResult, rc: Optional[int],
                     portable_dir: str = "") -> List[str]:
        """Подсказки для Adobe: код 191 — это UWP-шаг, а не ключи тишины."""
        failure = self._adobe_failure
        if failure is None and portable_dir:
            failure = self._read_adobe_failure(portable_dir)
            self._adobe_failure = failure
        if failure is None and rc in adobe_mod.ADOBE_CODES:
            failure = adobe_mod.AdobeFailure(code=int(rc))
        if failure is None and not det.is_adobe_hd:
            return []
        return adobe_mod.failure_hints(
            failure,
            applied=self._adobe_applied,
            payload_extracted=bool(self._adobe_source),
            unpacker_missing=not bool(unpacker_mod.find_extractors()),
            salvage_attempted=self._adobe_salvage_attempted,
            layout=self._adobe_layout,
        )

    def _build_isolated_env(self, opts: PortableOptions,
                            data_dir: str) -> Dict[str, str]:
        env = dict(os.environ)
        if opts.redirect_userdirs:
            appdata = os.path.join(data_dir, "AppData", "Roaming")
            local = os.path.join(data_dir, "AppData", "Local")
            temp = self._temp_dir_for(data_dir)
            user = os.path.join(data_dir, "User")
            programdata = os.path.join(data_dir, "ProgramData")
            for d in (appdata, local, temp, user, programdata):
                os.makedirs(d, exist_ok=True)
            env.update({
                "APPDATA": appdata,
                "LOCALAPPDATA": local,
                "TEMP": temp, "TMP": temp,
                "USERPROFILE": user,
                "PROGRAMDATA": programdata,
            })
        if IS_WINDOWS and is_elevated():
            # Portablizer уже повышен. Дочерний установщик наследует тот же
            # уровень целостности, поэтому второе окно согласия ему не нужно —
            # а именно оно и «зависает», когда появляется за окном программы
            # или на защищённом рабочем столе. RunAsInvoker запрещает
            # запрашивать повышение заново и ничего не отнимает: права уже есть.
            env["__COMPAT_LAYER"] = "RunAsInvoker"
        for k, v in opts.extra_env.items():
            env[k] = os.path.expandvars(v)
        if opts.redirect_userdirs:
            # Дерево профиля внутри портатива. Установщики (Autodesk Streamer,
            # .NET-бутстрапперы) спрашивают пути не только через переменные
            # APPDATA/LOCALAPPDATA, но и через Known Folder API: Shell
            # разрешает их как ``%USERPROFILE%\AppData\...``. Если такого
            # каталога нет, GetKnownFolderPath завершается ERROR_FILE_NOT_FOUND
            # — ровно это показывает окно Autodesk «[WinError -2147024894]
            # Не удается найти указанный файл». Поэтому создаём оба
            # эквивалентных дерева заранее, а не только корень USERPROFILE.
            profile = env.get("USERPROFILE", "")
            if profile:
                profile_tree = (
                    ("AppData", "Roaming"),
                    ("AppData", "Local"),
                    ("AppData", "LocalLow"),
                    ("Desktop",),
                    ("Documents",),
                    ("Downloads",),
                    ("Saved Games",),
                    ("Favorites",),
                    ("Links",),
                    ("Music",),
                    ("Pictures",),
                    ("Videos",),
                    ("Contacts",),
                    ("Searches",),
                )
                for parts in profile_tree:
                    folder = os.path.join(profile, *parts)
                    os.makedirs(folder, exist_ok=True)
                self.log.debug(
                    "Подготовлено дерево перенаправленного профиля: "
                    f"{profile}")
            # Autodesk Streamer выполняет CREATE_LAUNCH_ITEMS и запрашивает
            # FOLDERID_UserPinned (9E3995AB-1F9C-4F13-B827-48B24B6C7174).
            # В 1.14.16 каталог под APPDATA был создан, но GetKnownFolderPath
            # всё ещё завершился ERROR_FILE_NOT_FOUND. У нас APPDATA и
            # USERPROFILE намеренно имеют разные корни; Shell может разрешать
            # этот Known Folder через User Shell Folders как
            # ``%USERPROFILE%/AppData/Roaming``, а не через переменную APPDATA.
            # Создаём User Pinned в обоих эквивалентных portable-путях, чтобы
            # не менять реестр или каталоги профиля хоста.
            #
            # Autodesk документирует и второй уровень: Streamer закрепляет
            # ярлык Fusion на панели задач и без существующего
            # ``User Pinned\TaskBar`` падает с тем же
            # ``[WinError -2147024894]`` («The system cannot find the file
            # specified»). Поэтому создаём и TaskBar, а не только User Pinned.
            profile = env.get("USERPROFILE", "")
            roaming_roots = (
                env.get("APPDATA", ""),
                os.path.join(profile, "AppData", "Roaming") if profile else "",
            )
            for roaming in dict.fromkeys(root for root in roaming_roots if root):
                pinned_folder = os.path.join(
                    roaming, "Microsoft", "Internet Explorer", "Quick Launch",
                    "User Pinned",
                )
                os.makedirs(pinned_folder, exist_ok=True)
                os.makedirs(os.path.join(pinned_folder, "TaskBar"),
                            exist_ok=True)
                self.log.debug(
                    f"Подготовлен Known Folder UserPinned: {pinned_folder}")
        return env

    # -- поиск результата установки вне App ---------------------------------
    _SYSTEM_DRIVE_SKIP_DIRS = frozenset({
        "windows", "program files", "program files (x86)", "programdata",
        "users", "documents and settings", "$recycle.bin", "$winreagent",
        "system volume information", "recovery", "perflogs", "msocache",
        "config.msi", "intel", "amd", "nvidia", "boot", "efi", "temp", "tmp",
    })

    @staticmethod
    def _is_drive_root(path: str) -> bool:
        drive, tail = os.path.splitdrive(os.path.abspath(path))
        return bool(drive) and tail in ("\\", "/")

    def _install_search_roots(self, data_dir: str) -> List[Tuple[str, int, bool]]:
        """Возвращает (каталог, приоритет, принадлежит портативу).

        Первые каталоги находятся в перенаправленном профиле и безопасны для
        копирования. Затем идут обычные места установки Windows — они нужны для
        установщиков, которые не учитывают переданное окружение.
        """
        roots: List[Tuple[str, int, bool]] = [
            (os.path.join(data_dir, "AppData", "Local", "Programs"), 150, True),
            (os.path.join(data_dir, "AppData", "Local"), 120, True),
            (os.path.join(data_dir, "ProgramData"), 105, True),
            (os.path.join(data_dir, "AppData", "Roaming"), 90, True),
        ]
        if IS_WINDOWS:
            local = os.environ.get("LOCALAPPDATA", "")
            roaming = os.environ.get("APPDATA", "")
            program_data = os.environ.get("PROGRAMDATA", "")
            if local:
                roots.extend([
                    (os.path.join(local, "Programs"), 130, False),
                    (local, 80, False),
                ])
            for key in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
                value = os.environ.get(key, "")
                if value:
                    roots.append((value, 110, False))
            if program_data:
                roots.append((program_data, 65, False))
            if roaming:
                roots.append((roaming, 55, False))
            # Некоторые старые и словарные установщики (например, Multitran)
            # ставят программу прямо в корень диска (C:\Multitran, C:\mt).
            sys_drive = os.environ.get("SystemDrive", "C:").strip().rstrip("\\/")
            if sys_drive:
                roots.append((sys_drive + "\\", 70, False))
            data_drive, _ = os.path.splitdrive(os.path.abspath(data_dir))
            if data_drive:
                roots.append((data_drive + "\\", 70, False))

        # Переменные ProgramFiles часто указывают на один каталог.
        unique: List[Tuple[str, int, bool]] = []
        seen: Set[str] = set()
        for path, priority, owned in roots:
            if not path:
                continue
            normalized = os.path.normcase(os.path.abspath(path))
            if normalized in seen:
                continue
            seen.add(normalized)
            unique.append((os.path.abspath(path), priority, owned))
        return unique

    @staticmethod
    def _location_entries(root: str) -> List[Tuple[str, str, bool, bool]]:
        """Возвращает потомков места установки на глубине до двух уровней."""
        result: List[Tuple[str, str, bool, bool]] = []
        drive_root = Portablizer._is_drive_root(root)
        try:
            first_level = list(os.scandir(root))
        except OSError:
            return result
        for entry in first_level:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                continue
            if drive_root:
                low_name = entry.name.casefold()
                if (not is_dir
                        or low_name.startswith("$")
                        or low_name in Portablizer._SYSTEM_DRIVE_SKIP_DIRS):
                    continue
                result.append((entry.path, entry.name, is_dir, is_file))
                continue
            result.append((entry.path, entry.name, is_dir, is_file))
            if not is_dir:
                continue
            # Пример: Program Files\\Vendor уже существовал, а установщик
            # создал внутри новый каталог Vendor\\Type.
            try:
                second_level = list(os.scandir(entry.path))
            except OSError:
                continue
            for child in second_level:
                try:
                    child_is_dir = child.is_dir(follow_symlinks=False)
                    child_is_file = child.is_file(follow_symlinks=False)
                except OSError:
                    continue
                result.append((
                    child.path, child.name, child_is_dir, child_is_file,
                ))
        return result

    def _snapshot_install_locations(self, data_dir: str) -> Dict[str, Set[str]]:
        """Запоминает потомков типовых мест установки на глубине до двух."""
        snapshot: Dict[str, Set[str]] = {}
        for root, _priority, _owned in self._install_search_roots(data_dir):
            entries = {
                os.path.normcase(os.path.abspath(path))
                for path, _name, _is_dir, _is_file in self._location_entries(root)
            }
            snapshot[os.path.normcase(os.path.abspath(root))] = entries
        return snapshot

    @staticmethod
    def _find_executables(root: str, limit: int = 2000,
                          exclude_dirs: Sequence[str] = ()) -> List[str]:
        """Ищет exe без перехода по симлинкам/переходным каталогам."""
        found: List[str] = []
        if not os.path.isdir(root):
            return found
        excluded_norms = {
            os.path.normcase(os.path.abspath(d))
            for d in (exclude_dirs or ()) if d
        }
        for current, dirs, files in os.walk(root, followlinks=False):
            # Не уходим в возможные junction/symlink и в папку самого портатива.
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(os.path.join(current, d))
                and os.path.normcase(os.path.abspath(os.path.join(current, d)))
                not in excluded_norms
                and not d.casefold().endswith("_portable")
            ]
            for filename in files:
                if filename.lower().endswith(".exe"):
                    found.append(os.path.join(current, filename))
                    if len(found) >= limit:
                        return found
        return found

    #: Слова, которые не могут быть «именем продукта»: названия версий,
    #: редакций и обёрток («Pro», «Full Edition», «Setup»).
    _GENERIC_NAME_WORDS = frozenset({
        "the", "and", "for", "pro", "plus", "premium", "ultimate", "deluxe",
        "studio", "classic", "standard", "enterprise", "professional",
        "home", "student", "education", "full", "edition", "version",
        "setup", "install", "installer", "portable", "repack", "game",
        "download", "free", "win", "windows", "x64", "x86", "amd64",
    })

    #: Хвост «версия/редакция» после имени продукта: SketchUp 2026,
    #: SketchUp Pro. Такой каталог считается тем же продуктом.
    _EDITION_TAIL_RE = re.compile(
        r"^(?:(?:19|20)\d{2}|v\d+|pro|plus|premium|ultimate|deluxe|studio|"
        r"classic|standard|enterprise|professional|home|student|education|"
        r"full|x64|x86|win(?:32|64))+$",
        re.IGNORECASE,
    )

    @staticmethod
    def _name_keys(app_name: str, installer_path: str) -> Set[str]:
        """Формирует нормализованные имена для оценки найденных файлов.

        Кроме полного названия добавляется ключ-слово продукта. Это важно для
        репаков: имя файла — «SketchUp Pro v26.1.189», а каталог установки —
        просто «SketchUp». Без ключа «sketchup» такой каталог в Program Files
        не совпадал ни с одним ключом (полное имя содержит версию) и потому
        не удалялся после переноса в App.
        """
        inst_stem = os.path.splitext(os.path.basename(installer_path))[0]
        values = [app_name, inst_stem]
        if inst_stem.strip().casefold() in (
                "setup", "install", "installer", "autorun"):
            parent_name = os.path.basename(
                os.path.dirname(os.path.abspath(installer_path)))
            if parent_name:
                values.append(parent_name)
        version_re = re.compile(
            r"\b(?:v\.?\s*)?\d+(?:\.\d+){1,4}\b|\b(?:19|20)\d{2}\b",
            re.IGNORECASE)
        suffixes = re.compile(
            r"(?:[\s._-]*(?:setup|installer|install|portable|win(?:32|64)|"
            r"x(?:86|64)|amd64|online|offline|latest|[0-9]+(?:\.[0-9]+)*))+$",
            re.IGNORECASE,
        )
        keys: Set[str] = set()
        for value in values:
            cleaned = version_re.sub(" ", value or "")
            cleaned = suffixes.sub("", cleaned).strip()
            normalized = "".join(ch for ch in cleaned.casefold() if ch.isalnum())
            if len(normalized) >= 2:
                keys.add(normalized)
            # Первое содержательное слово названия — имя продукта.
            for word in re.split(r"[\s._+\-()\[\]]+", cleaned):
                token = "".join(ch for ch in word.casefold() if ch.isalnum())
                if len(token) >= 4 and token not in Portablizer._GENERIC_NAME_WORDS:
                    keys.add(token)
                    break
        return keys

    @staticmethod
    def _name_score(path: str, keys: Set[str]) -> int:
        stem = os.path.splitext(os.path.basename(path))[0]
        normalized = "".join(ch for ch in stem.casefold() if ch.isalnum())
        score = 0
        for key in keys:
            if normalized == key:
                score = max(score, 220)
            elif (normalized.startswith(key)
                  and Portablizer._EDITION_TAIL_RE.match(
                      normalized[len(key):] or "")):
                # «SketchUp 2026» / «SketchUp Pro» — тот же продукт.
                score = max(score, 210)
            elif key in normalized or normalized in key:
                score = max(score, 125)
        bad = (
            "unins", "uninstall", "setup", "install", "update", "updater",
            "helper", "crash", "report", "redist", "vcredist", "squirrel",
        )
        if any(word in normalized for word in bad):
            score -= 180
        return score

    def _remember_recovered_source(self, source: str) -> None:
        if not source:
            return
        abs_src = os.path.abspath(source)
        norm_src = os.path.normcase(abs_src)
        if all(os.path.normcase(item) != norm_src
               for item in self._recovered_sources):
            self._recovered_sources.append(abs_src)

    def _copy_recovered_tree(self, source: str, app_dir: str, data_dir: str,
                             installer_path: str,
                             overwrite: bool = True) -> None:
        """Копирует содержимое ``source`` в ``app_dir``, пропуская сам портатив и setup.exe."""
        portable_dir = os.path.dirname(os.path.abspath(app_dir))
        excluded_dir_norms = {
            os.path.normcase(os.path.abspath(p))
            for p in (portable_dir, app_dir, data_dir) if p
        }
        installer_abs_norm = (
            os.path.normcase(os.path.abspath(installer_path))
            if installer_path else ""
        )
        installer_dir_norm = (
            os.path.normcase(os.path.dirname(os.path.abspath(installer_path)))
            if installer_path else ""
        )
        source_abs = os.path.abspath(source)
        is_installer_dir = (
            bool(installer_dir_norm)
            and os.path.normcase(source_abs) == installer_dir_norm
        )
        skip_Root_files = {
            "setup.exe", "install.exe", "installer.exe", "autorun.exe",
            "portablizer.log", "installer-output.log", "unpacker-output.log",
        }

        def _ignore_in_tree(cur_dir: str, names: List[str]) -> Set[str]:
            ignored: Set[str] = set()
            for n in names:
                child_abs = os.path.abspath(os.path.join(cur_dir, n))
                child_norm = os.path.normcase(child_abs)
                if (child_norm in excluded_dir_norms
                        or n.casefold().endswith("_portable")
                        or (installer_abs_norm and child_norm == installer_abs_norm)):
                    ignored.add(n)
            return ignored

        if os.path.isdir(source_abs):
            for item in os.scandir(source_abs):
                item_abs = os.path.abspath(item.path)
                item_norm = os.path.normcase(item_abs)
                if (item_norm in excluded_dir_norms
                        or item.name.casefold().endswith("_portable")):
                    continue
                if installer_abs_norm and item_norm == installer_abs_norm:
                    continue
                if is_installer_dir and item.name.casefold() in skip_Root_files:
                    continue
                destination = os.path.join(app_dir, item.name)
                if item.is_dir(follow_symlinks=False):
                    shutil.copytree(
                        item.path, destination, dirs_exist_ok=True,
                        ignore=_ignore_in_tree)
                elif item.is_file(follow_symlinks=False):
                    if overwrite or not os.path.exists(destination):
                        shutil.copy2(item.path, destination)
        else:
            destination = os.path.join(app_dir, os.path.basename(source_abs))
            if overwrite or not os.path.exists(destination):
                shutil.copy2(source_abs, destination)

    def _supplement_recovered_from_registry(
        self,
        app_dir: str,
        app_name: str,
        installer_path: str,
        registry_locations: Iterable[str] = (),
    ) -> None:
        """Дополняет ``_recovered_sources`` и ``App`` путями из снимка реестра.

        Например, если ``setup.exe`` из распакованной папки ``Multitran 03.11.2023``
        скопировал оболочку в ``C:\\Multitran`` (которую ``recover()`` уже забрал
        в ``App`` на шаге 4), а словарные базы в реестре оставил привязанными
        к исходной папке ``E:\\...\\Multitran 03.11.2023``, докопируем базы в
        ``App`` и добавим исходную папку в ``_recovered_sources`` для перепривязки
        путей в ``portable.reg``.
        """
        if not installer_path:
            return
        keys = self._name_keys(app_name, installer_path)
        installer_dir = os.path.dirname(os.path.abspath(installer_path))
        installer_dir_norm = os.path.normcase(installer_dir)
        portable_dir = os.path.dirname(os.path.abspath(app_dir))
        portable_norm = os.path.normcase(portable_dir)
        data_dir = os.path.join(portable_dir, "PortableData")

        for location in registry_locations:
            loc_abs = os.path.abspath(location)
            src = os.path.dirname(loc_abs) if os.path.isfile(loc_abs) else loc_abs
            if not os.path.isdir(src):
                continue
            src_norm = os.path.normcase(src)
            if (src_norm == portable_norm
                    or src_norm.startswith(portable_norm + os.sep)):
                continue
            if (src_norm == installer_dir_norm
                    or src_norm.startswith(installer_dir_norm + os.sep)):
                self._remember_recovered_source(installer_dir)
                try:
                    self._copy_recovered_tree(
                        installer_dir, app_dir, data_dir, installer_path,
                        overwrite=False)
                except OSError:
                    pass
            elif self._name_score(os.path.basename(src), keys) >= 125:
                self._remember_recovered_source(src)

    def _recover_installed_app(
        self,
        app_dir: str,
        data_dir: str,
        app_name: str,
        installer_path: str,
        before: Dict[str, Set[str]],
        registry_locations: Iterable[str] = (),
        shortcut_locations: Iterable[str] = (),
    ) -> bool:
        """Копирует результат установщика, если тот проигнорировал папку App.

        Рассматриваются только новые каталоги, цели созданных ярлыков, записи
        реестра или уже распакованная папка дистрибутива рядом с ``setup.exe``.
        Это не даёт случайно скопировать произвольную уже установленную
        программу из Program Files.
        """
        keys = self._name_keys(app_name, installer_path)
        search_roots = self._install_search_roots(data_dir)
        protected_roots = {
            os.path.normcase(os.path.abspath(path))
            for path, _priority, _owned in search_roots
        }
        portable_dir = os.path.dirname(os.path.abspath(app_dir))
        app_dir_norm = os.path.normcase(os.path.abspath(app_dir))
        excluded_dirs = (portable_dir, app_dir, data_dir)
        excluded_dir_norms = {
            os.path.normcase(os.path.abspath(p))
            for p in excluded_dirs if p
        }
        installer_abs = os.path.abspath(installer_path) if installer_path else ""
        installer_abs_norm = (
            os.path.normcase(installer_abs) if installer_abs else ""
        )
        installer_dir = os.path.dirname(installer_abs) if installer_abs else ""
        installer_dir_norm = (
            os.path.normcase(installer_dir) if installer_dir else ""
        )
        # normalized source -> (score, representative exe, explanation, source)
        candidates: Dict[str, Tuple[int, str, str, str]] = {}

        def add_source(source: str, score: int, reason: str) -> None:
            source = os.path.abspath(source)
            source_norm = os.path.normcase(source)
            # Никогда не копируем Program Files/AppData/корень диска целиком
            # или саму папку собираемого портатива.
            if (source_norm in protected_roots
                    or self._is_drive_root(source)
                    or source_norm in excluded_dir_norms):
                return
            if not os.path.exists(source):
                return
            if os.path.isfile(source):
                exes = [source] if source.lower().endswith(".exe") else []
            else:
                exes = self._find_executables(
                    source, exclude_dirs=excluded_dirs)
            for exe in exes:
                exe_abs = os.path.abspath(exe)
                exe_norm = os.path.normcase(exe_abs)
                if installer_abs_norm and exe_norm == installer_abs_norm:
                    continue
                if (exe_norm == app_dir_norm
                        or exe_norm.startswith(app_dir_norm + os.sep)):
                    continue
                if (installer_dir_norm
                        and source_norm == installer_dir_norm
                        and os.path.basename(exe_abs).casefold() in (
                            "setup.exe", "install.exe", "installer.exe",
                            "autorun.exe", "unins000.exe", "uninstall.exe")):
                    continue
                exe_score = score + self._name_score(exe, keys)
                try:
                    exe_score += min(35, int(os.path.getsize(exe) / (1024 * 1024)))
                except OSError:
                    pass
                previous = candidates.get(source_norm)
                if previous is None or exe_score > previous[0]:
                    candidates[source_norm] = (exe_score, exe, reason, source)

        # Цели новых ярлыков, созданных установщиком на Рабочем столе / в Пуске.
        for location in shortcut_locations:
            location = os.path.abspath(location)
            source = os.path.dirname(location) if os.path.isfile(location) else location
            add_source(source, 250, "цель ярлыка, созданного установщиком")

        # InstallLocation/DisplayIcon и локальные пути из новых записей реестра.
        for location in registry_locations:
            location = os.path.abspath(location)
            source = os.path.dirname(location) if os.path.isfile(location) else location
            add_source(source, 240, "новая запись InstallLocation в реестре")

        for root, priority, owned in search_roots:
            root_key = os.path.normcase(os.path.abspath(root))
            old_entries = before.get(root_key, set())
            for path, entry_name, is_dir, is_file in self._location_entries(root):
                entry_path = os.path.abspath(path)
                is_new = os.path.normcase(entry_path) not in old_entries
                # Для уже существующего каталога совпадение должно быть
                # точным. Короткое имя приложения вроде "Type" раньше
                # совпадало с системным "TypeScript" и Portablizer мог забрать
                # чужую предустановленную программу, объявив неудачную сборку
                # успешной. Нечёткое совпадение допустимо только для реально
                # нового каталога, появившегося после запуска установщика.
                name_match = self._name_score(entry_name, keys) >= 200
                if not (is_new or name_match):
                    continue
                # Прямой exe безопасно копируем отдельно. Для каталога берём
                # всё его дерево (dll/resources должны остаться рядом).
                is_exe = is_file and entry_name.lower().endswith(".exe")
                if not is_dir and not is_exe:
                    continue
                reason = "перенаправленный профиль" if owned else "новый каталог установки"
                bonus = 55 if is_new else 0
                if owned:
                    bonus += 35
                add_source(entry_path, priority + bonus, reason)

        # Распакованный дистрибутив с безликим setup.exe/install.exe внутри
        # папки приложения (например, «Multitran 03.11.2023\setup.exe»): такой
        # setup.exe нередко лишь прописывает текущую папку и словари в реестр
        # и создаёт ярлык.
        installer_base_low = (
            os.path.basename(installer_abs).casefold() if installer_abs else ""
        )
        unpacked_installer_dir_match = (
            bool(installer_dir)
            and installer_base_low in (
                "setup.exe", "install.exe", "installer.exe", "autorun.exe")
            and os.path.isdir(installer_dir)
            and installer_dir_norm not in protected_roots
            and not self._is_drive_root(installer_dir)
            and self._name_score(os.path.basename(installer_dir), keys) >= 125
        )
        if unpacked_installer_dir_match:
            add_source(
                installer_dir, 140,
                "распакованная папка дистрибутива рядом с setup.exe")

        ranked = sorted(candidates.values(), key=lambda item: item[0], reverse=True)
        for score, _exe, reason, source in ranked:
            # Отрицательный результат — почти наверняка updater/uninstaller.
            if score <= 0:
                continue
            self.log.info(
                f"Найден возможный каталог программы ({reason}, оценка {score}): "
                f"{source}"
            )
            try:
                self._copy_recovered_tree(
                    source, app_dir, data_dir, installer_path, overwrite=True)
            except OSError as exc:
                self.log.warn(f"Не удалось скопировать найденные файлы: {exc}")
                # Не оставляем частичный каталог перед следующей попыткой.
                shutil.rmtree(app_dir, ignore_errors=True)
                os.makedirs(app_dir, exist_ok=True)
                continue
            if self._find_main_exe(app_dir, app_name):
                source_dir = (
                    source if os.path.isdir(source)
                    else os.path.dirname(os.path.abspath(source))
                )
                self._remember_recovered_source(source_dir)
                # Если setup.exe скопировал только exe-оболочку в каталог по
                # умолчанию (например, C:\Multitran), а базы/словари лежат в
                # распакованной папке дистрибутива рядом с setup.exe,
                # докопируем недостающие файлы из неё и перепривяжем её путь.
                if (unpacked_installer_dir_match
                        and os.path.normcase(source_dir) != installer_dir_norm):
                    try:
                        self._copy_recovered_tree(
                            installer_dir, app_dir, data_dir, installer_path,
                            overwrite=False)
                        self._remember_recovered_source(installer_dir)
                    except OSError:
                        pass
                # Удаляем оригинал из Program Files/корня диска — иначе на C:
                # остаётся брошенный каталог установки. Исходную папку
                # пользователя рядом с setup.exe _remove_recovered_source не
                # трогает.
                self._remove_recovered_source(
                    source, app_dir, data_dir, installer_path=installer_path)
                return True
            shutil.rmtree(app_dir, ignore_errors=True)
            os.makedirs(app_dir, exist_ok=True)
        return False

    def _cleanup_leftover_install_dirs(
            self, name: str, installer_path: str,
            opts: "PortableOptions", data_dir: str = "",
            before: "Optional[Dict[str, Set[str]]]" = None,
            app_dir: str = "") -> List[str]:
        """Удаляет брошенные каталоги установки из Program Files и профилей.

        Установщик (особенно мастер репака) может поставить программу в
        C:\\Program Files\\<имя>, даже если recovery уже забрал файлы в App:
        оригинал остаётся, если recovery не нашёл его (не совпало имя, не
        попал в search roots) или не удалил из-за ошибки прав. На системном
        диске при этом живёт вторая копия программы, и пользователь видит
        «программа всё равно установилась».

        Сканирует до двух уровней вглубь (Program Files, Program Files (x86),
        ProgramData, LOCALAPPDATA\\Programs) и удаляет только каталоги,
        которых ДО установки не было, чьё имя совпадает с приложением и
        внутри которых есть exe. Предустановленную программу с тем же именем
        не трогает: ``before`` — снимок, сделанный до запуска установщика.
        """
        if not IS_WINDOWS:
            return []
        keys = self._name_keys(name, installer_path)
        sys_drive = os.environ.get("SystemDrive", "C:").strip().rstrip("\\/")
        search_roots = [
            os.environ.get("PROGRAMFILES", ""),
            os.environ.get("PROGRAMFILES(X86)", ""),
            os.environ.get("PROGRAMW6432", ""),
            os.environ.get("PROGRAMDATA", ""),
            (sys_drive + "\\") if sys_drive else "",
        ]
        # User-owned roots: LOCALAPPDATA/Programs, LOCALAPPDATA
        user_roots = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs"),
            os.environ.get("LOCALAPPDATA", ""),
        ]
        data_abs = os.path.abspath(data_dir) if data_dir else ""
        result_dir = app_dir or getattr(opts, "app_dir", "")
        portable_abs = (
            os.path.dirname(os.path.abspath(result_dir)) if result_dir else ""
        )
        installer_abs = (
            os.path.abspath(installer_path) if installer_path else ""
        )
        removed: List[str] = []
        for root in search_roots + user_roots:
            if not root or not os.path.isdir(root):
                continue
            root_key = os.path.normcase(os.path.abspath(root))
            old_entries = (before or {}).get(root_key)
            if before is not None and old_entries is None:
                # Снимка именно этого корня нет (например, переменную
                # окружения поменяли между снимком и уборкой). Удалять без
                # снимка нельзя: под «похожее имя» может попасть чужая,
                # давно установленная программа.
                continue
            old_entries = old_entries or set()
            gone: Set[str] = set()
            try:
                entries = self._location_entries(root)
            except OSError:
                continue
            for entry_path, entry_name, is_dir, _is_file in entries:
                if not is_dir:
                    continue
                entry_abs = os.path.abspath(entry_path)
                entry_key = os.path.normcase(entry_abs)
                # Родитель уже удалён — его потомков обрабатывать нечего.
                if any(entry_key == item or entry_key.startswith(item + os.sep)
                       for item in gone):
                    continue
                if self._name_score(entry_name, keys) < 200:
                    continue
                # Каталог должен появиться именно в этой установке: иначе это
                # чужая, ранее установленная программа с похожим именем.
                if before is not None and entry_key in old_entries:
                    continue
                # Не трогаем каталоги внутри портативного профиля, саму папку
                # портатива и каталог, содержащий исходный установщик.
                protected_targets = [
                    p for p in (data_abs, result_dir, portable_abs, installer_abs)
                    if p
                ]
                if any(
                    os.path.normcase(os.path.abspath(t)) == entry_key
                    or os.path.normcase(os.path.abspath(t)).startswith(
                        entry_key + os.sep)
                    or entry_key.startswith(
                        os.path.normcase(os.path.abspath(t)) + os.sep)
                    for t in protected_targets
                ):
                    continue
                # Проверяем, что внутри есть exe — иначе это не каталог
                # установки приложения.
                if not self._find_executables(entry_abs, limit=5):
                    continue
                self.log.info(
                    f"Найден брошенный каталог установки: {entry_abs}")
                try:
                    shutil.rmtree(entry_abs, ignore_errors=False)
                    removed.append(entry_abs)
                    gone.add(entry_key)
                    self._remember_recovered_source(entry_abs)
                    self.log.ok(f"Удалено: {entry_abs}")
                except OSError as exc:
                    self.log.warn(
                        f"Не удалось удалить брошенный каталог "
                        f"{entry_abs}: {exc}. Проверьте права "
                        "администратора.")
                    # Повторять для вложенных каталогов бессмысленно.
                    gone.add(entry_key)
        return removed

    def _remove_recovered_source(self, source: str, app_dir: str,
                                 data_dir: str,
                                 installer_path: str = "") -> None:
        """Удаляет оригинал установки из Program Files после переноса в App.

        Только если синхронная копия прошла успешно и App не совпадает с
        первоначальным каталогом. Никогда не удаляет исходную папку, в которой
        лежит сам установщик пользователя, или предка портативной папки.
        """
        try:
            source_abs = os.path.abspath(source)
            source_norm = os.path.normcase(source_abs)
            portable_abs = os.path.dirname(os.path.abspath(app_dir))
            protected_targets = [
                os.path.abspath(p)
                for p in (app_dir, data_dir, portable_abs, installer_path)
                if p
            ]
            for target in protected_targets:
                target_norm = os.path.normcase(target)
                # Не трогаем саму защищённую цель, её потомков и её предков
                # (например, папку дистрибутива, в которой лежит setup.exe или
                # внутри которой создаётся <App>_Portable).
                if (source_norm == target_norm
                        or source_norm.startswith(target_norm + os.sep)
                        or target_norm.startswith(source_norm + os.sep)):
                    return
            if not os.path.isdir(source_abs):
                return
            # Проверяем, что каталог содержит exe с именем приложения —
            # иначе это может быть системный каталог, не относящийся к
            # recovered приложению.
            self.log.info(
                f"Удаляю оригинал установки из Program Files: {source_abs}")
            shutil.rmtree(source_abs, ignore_errors=False)
        except OSError as exc:
            self.log.warn(
                f"Не удалось удалить оригинал установки из Program Files "
                f"({source}): {exc}. Файл оставлен, но портатив уже содержит "
                "копию в App.")

    @staticmethod
    def _pe_is_unsigned_and_checksum_offset(data: bytes) -> Tuple[bool, int]:
        """Возвращает ``(True, checksum_offset)`` для неподписанного PE-файла."""
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False, -1
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if not 0 < e_lfanew < len(data) - 24:
            return False, -1
        if data[e_lfanew: e_lfanew + 4] != b"PE\0\0":
            return False, -1
        size_optional = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        opt_start = e_lfanew + 24
        if size_optional < 68 or opt_start + size_optional > len(data):
            return False, -1
        magic = struct.unpack_from("<H", data, opt_start)[0]
        if magic not in (0x10B, 0x20B):
            return False, -1
        dir_offset = 112 if magic == 0x20B else 96
        if size_optional >= dir_offset + 5 * 8:
            count = struct.unpack_from(
                "<I", data, opt_start + dir_offset - 4
            )[0]
            if count > 4:
                sec_rva, sec_size = struct.unpack_from(
                    "<II", data, opt_start + dir_offset + 4 * 8
                )
                if sec_rva != 0 or sec_size != 0:
                    return False, -1
        return True, opt_start + 64

    def _neutralize_hardcoded_drive_app_paths(
        self,
        portable_dir: str,
        app_dir: str,
        app_names: Sequence[str],
    ) -> Set[str]:
        """Заменяет зашитые в exe/dll/ini пути вида ``c:\\multitran`` на ``..\\multitran``.

        Некоторые старые программы (в частности оболочка Multitran ``network.exe``)
        хранят путь к рабочему каталогу пользовательских профилей, истории и
        пользовательских словарей прямо внутри бинарника как ``c:\\multitran``.
        Поскольку ``c:`` и ``..`` имеют одинаковую длину (2 байта в ASCII,
        4 байта в UTF-16LE), замена ``c:\\multitran`` -> ``..\\multitran``
        в неподписанном PE-файле не сдвигает ни одного смещения или таблицы
        секций, а при запуске из ``<PortableDir>\\App`` относительный путь
        ``..\\multitran`` на любом диске и в любом разделе указывает ровно в
        ``<PortableDir>\\multitran``.
        """
        matched_folders: Set[str] = set()
        if not os.path.isdir(app_dir):
            return matched_folders
        tokens = sorted(
            {
                reg_mod._normalize_app_token(name)
                for name in (app_names or ())
                if len(reg_mod._normalize_app_token(name)) >= 4
                and reg_mod._normalize_app_token(name).isascii()
            },
            key=len,
            reverse=True,
        )
        if not tokens:
            return matched_folders

        token_alt_str = "|".join(re.escape(t) for t in tokens)
        text_re = re.compile(
            r"(?<![A-Za-z0-9_\\/.:-])([A-Za-z]:)([\\/])("
            + token_alt_str
            + r")(?=[\\/\"'\r\n\t ;]|$)",
            re.IGNORECASE,
        )
        ascii_re = re.compile(
            rb"(?<![A-Za-z0-9_\\/.:-])([A-Za-z]:)([\\/])("
            + b"|".join(re.escape(t.encode("ascii")) for t in tokens)
            + rb")(?=[\\/\x00%\"'\r\n\t ;]|$)",
            re.IGNORECASE,
        )
        utf16_patterns = []
        for t in tokens:
            char_parts = [
                rb"[" + re.escape(ch.lower().encode("ascii"))
                + re.escape(ch.upper().encode("ascii")) + rb"]\x00"
                for ch in t
            ]
            utf16_patterns.append((
                t,
                re.compile(
                    rb"([A-Za-z]\x00:\x00)([\\/]\x00)("
                    + b"".join(char_parts)
                    + rb")(?=[\\/\x00%\"'\r\n\t ;]\x00)",
                ),
            ))

        portable_abs = os.path.abspath(portable_dir)
        portable_norm = os.path.normcase(portable_abs)
        skip_files = {
            "launchportable.exe", "unins000.exe", "uninstall.exe",
            "portablizer.log", "installer-output.log", "unpacker-output.log",
        }
        text_exts = {".ini", ".cfg", ".conf", ".xml", ".json", ".txt"}

        for current, _dirs, files in os.walk(app_dir, followlinks=False):
            rel_to_portable = os.path.relpath(
                portable_abs, os.path.abspath(current)
            ).replace("/", "\\")
            for fname in files:
                low_name = fname.casefold()
                if low_name in skip_files:
                    continue
                fpath = os.path.join(current, fname)
                ext = os.path.splitext(low_name)[1]
                try:
                    fsize = os.path.getsize(fpath)
                except OSError:
                    continue

                if ext in text_exts and 0 < fsize <= 4 * 1024 * 1024:
                    try:
                        raw = Path(fpath).read_bytes()
                    except OSError:
                        continue
                    for enc in ("utf-8", "utf-16", "cp1251"):
                        try:
                            txt = raw.decode(enc)
                        except UnicodeDecodeError:
                            continue

                        def _repl_text(m: "re.Match[str]") -> str:
                            full = m.group(0)
                            if os.path.normcase(full).startswith(portable_norm):
                                return full
                            matched_folders.add(m.group(3))
                            sep = m.group(2)
                            prefix = rel_to_portable.replace("\\", sep)
                            return f"{prefix}{sep}{m.group(3)}"

                        new_txt = text_re.sub(_repl_text, txt)
                        if new_txt != txt:
                            try:
                                Path(fpath).write_bytes(new_txt.encode(enc))
                            except OSError:
                                pass
                        break
                    continue

                if (ext in (".exe", ".dll")
                        and rel_to_portable == ".."
                        and 0 < fsize <= 128 * 1024 * 1024):
                    try:
                        raw = Path(fpath).read_bytes()
                    except OSError:
                        continue
                    unsigned, checksum_off = (
                        self._pe_is_unsigned_and_checksum_offset(raw)
                    )
                    if not unsigned:
                        continue
                    buf = bytearray(raw)
                    changed = False
                    for m in ascii_re.finditer(raw):
                        folder_str = m.group(3).decode("ascii", "ignore")
                        matched_folders.add(folder_str)
                        buf[m.start(1): m.end(1)] = b".."
                        changed = True
                    for token_name, u_re in utf16_patterns:
                        for m in u_re.finditer(raw):
                            matched_folders.add(token_name)
                            buf[m.start(1): m.end(1)] = b".\x00.\x00"
                            changed = True
                    if changed:
                        if checksum_off > 0:
                            struct.pack_into("<I", buf, checksum_off, 0)
                        try:
                            Path(fpath).write_bytes(bytes(buf))
                            self.log.info(
                                f"Перенаправлен зашитый путь к папке данных в "
                                f"{os.path.relpath(fpath, app_dir)} -> ..\\{next(iter(matched_folders))}"
                            )
                        except OSError:
                            pass
        return matched_folders

    @staticmethod
    def _sync_computer_profile_subfolders(folder_path: str) -> None:
        """Синхронизирует подпапки ``<COMPUTERNAME>`` внутри рабочей папки портатива.

        В частности, Multitran хранит пользовательские файлы в
        ``multitran\\<ИМЯ_КОМПЬЮТЕРА>\\history.txt``, ``usertra.reu`` и
        ``Subject Profiles\\subject.act``, ``subject.sel``. Чтобы при переносе
        папки портатива на другой компьютер эти файлы подхватывались под новым
        именем компьютера без потерь, синхронизируем свежие файлы между
        существующими профилями и текущим ``%COMPUTERNAME%``.
        """
        if not os.path.isdir(folder_path):
            return
        marker_names = {"history.txt", "usertra.reu", "subject profiles"}
        comp_dirs: List[str] = []
        try:
            entries = list(os.scandir(folder_path))
        except OSError:
            return
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                child_names = {c.name.casefold() for c in os.scandir(entry.path)}
            except OSError:
                continue
            if child_names & marker_names:
                comp_dirs.append(entry.path)

        current_comp = (
            os.environ.get("COMPUTERNAME")
            or os.environ.get("HOSTNAME")
            or ""
        ).strip()
        if not current_comp or not comp_dirs:
            return
        target_comp_dir = os.path.join(folder_path, current_comp)
        if all(
            os.path.normcase(d) != os.path.normcase(target_comp_dir)
            for d in comp_dirs
        ):
            os.makedirs(target_comp_dir, exist_ok=True)
            comp_dirs.append(target_comp_dir)

        if len(comp_dirs) < 2:
            return

        # Собираем самую свежую версию каждого относительного файла по всем
        # профилям компьютеров и раскладываем во все профили (включая текущий).
        newest: Dict[str, Tuple[float, str]] = {}
        for cdir in comp_dirs:
            for cur, _subdirs, files in os.walk(cdir, followlinks=False):
                for fname in files:
                    src_file = os.path.join(cur, fname)
                    rel = os.path.relpath(src_file, cdir)
                    rel_key = os.path.normcase(rel)
                    try:
                        mtime = os.path.getmtime(src_file)
                    except OSError:
                        continue
                    prev = newest.get(rel_key)
                    if prev is None or mtime > prev[0]:
                        newest[rel_key] = (mtime, src_file)

        for cdir in comp_dirs:
            for _rel_key, (src_mtime, src_file) in newest.items():
                rel = os.path.relpath(
                    src_file,
                    next(
                        d for d in comp_dirs
                        if os.path.normcase(src_file).startswith(
                            os.path.normcase(d) + os.sep
                        )
                    ),
                )
                dst_file = os.path.join(cdir, rel)
                if os.path.normcase(src_file) == os.path.normcase(dst_file):
                    continue
                try:
                    if os.path.isfile(dst_file):
                        if os.path.getmtime(dst_file) >= src_mtime - 0.001:
                            continue
                    os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                    shutil.copy2(src_file, dst_file)
                except OSError:
                    continue

    def _relocate_drive_root_app_folders(
        self,
        portable_dir: str,
        app_dir: str,
        app_name: str,
        installer_path: str,
        registry_locations: Iterable[str] = (),
    ) -> List[str]:
        """Переносит рабочую папку программы вида ``C:\\multitran`` внутрь портатива.

        Если программа или установщик использует каталог в корне диска
        (например, ``C:\\multitran\\<COMPUTERNAME>\\history.txt``,
        ``usertra.reu``, ``Subject Profiles\\subject.act``, ``subject.sel``),
        заменяет жёсткие ссылки в бинарниках ``App`` на ``..\\multitran``,
        переносит уже существующую папку ``C:\\multitran`` со всем содержимым
        в ``<PortableDir>\\multitran`` и удаляет оригинал с диска ``C:``.
        """
        keys = self._name_keys(app_name, installer_path)
        app_names = sorted(
            set(shortcuts_mod.app_name_candidates(app_name, installer_path))
            | keys
        )
        matched_folders = self._neutralize_hardcoded_drive_app_paths(
            portable_dir, app_dir, app_names
        )

        portable_abs = os.path.abspath(portable_dir)
        app_abs = os.path.abspath(app_dir)
        data_abs = os.path.join(portable_abs, "PortableData")
        installer_abs = (
            os.path.abspath(installer_path) if installer_path else ""
        )
        protected_targets = [
            p for p in (portable_abs, app_abs, data_abs, installer_abs) if p
        ]

        def _is_protected_path(candidate_abs: str) -> bool:
            cand_norm = os.path.normcase(candidate_abs)
            for target in protected_targets:
                target_norm = os.path.normcase(target)
                if (cand_norm == target_norm
                        or cand_norm.startswith(target_norm + os.sep)
                        or target_norm.startswith(cand_norm + os.sep)):
                    return True
            return False

        drive_roots: List[str] = []
        if IS_WINDOWS:
            sys_drive = os.environ.get("SystemDrive", "C:").strip().rstrip("\\/")
            if sys_drive:
                drive_roots.append(sys_drive + "\\")
        port_drive, _ = os.path.splitdrive(portable_abs)
        if port_drive:
            drive_roots.append(port_drive + "\\")

        candidate_dirs: List[str] = []
        for d_root in dict.fromkeys(drive_roots):
            if not os.path.isdir(d_root):
                continue
            try:
                for entry in os.scandir(d_root):
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    low = entry.name.casefold()
                    if (low.startswith("$")
                            or low in self._SYSTEM_DRIVE_SKIP_DIRS):
                        continue
                    if self._name_score(entry.name, keys) >= 200:
                        candidate_dirs.append(os.path.abspath(entry.path))
            except OSError:
                continue

        for loc in registry_locations:
            loc_str = str(loc or "").strip().strip('"')
            m = re.match(
                r"^([A-Za-z]:[\\/])([^\\/:*?\"<>|\r\n;]+)",
                loc_str,
            )
            if not m:
                continue
            top_folder = m.group(2)
            if top_folder.casefold() in self._SYSTEM_DRIVE_SKIP_DIRS:
                continue
            if self._name_score(top_folder, keys) >= 200:
                matched_folders.add(top_folder)
                top_abs = os.path.abspath(m.group(1) + top_folder)
                if os.path.isdir(top_abs):
                    candidate_dirs.append(top_abs)

        relocated: List[str] = []
        seen_cands: Set[str] = set()
        for src_dir in candidate_dirs:
            src_norm = os.path.normcase(src_dir)
            if src_norm in seen_cands or _is_protected_path(src_dir):
                continue
            seen_cands.add(src_norm)
            if not os.path.isdir(src_dir):
                continue
            folder_name = os.path.basename(src_dir)
            matched_folders.add(folder_name)
            dest_dir = os.path.join(portable_abs, folder_name)
            try:
                os.makedirs(dest_dir, exist_ok=True)
                shutil.copytree(src_dir, dest_dir, dirs_exist_ok=True)
                self._remember_recovered_source(src_dir)
                shutil.rmtree(src_dir, ignore_errors=False)
                relocated.append(dest_dir)
                self.log.ok(
                    f"Рабочая папка программы перенесена в портатив: "
                    f"{src_dir} -> {dest_dir}"
                )
            except OSError as exc:
                self.log.warn(
                    f"Не удалось полностью перенести или удалить {src_dir}: {exc}"
                )

        # Создаём рабочую папку внутри портатива (например, <PortableDir>\multitran),
        # если на неё ссылаются бинарники или реестр, и синхронизируем профили ПК.
        chosen_names: Dict[str, str] = {}
        for fname in matched_folders:
            clean = fname.strip().strip("\\/")
            if clean:
                chosen_names.setdefault(clean.casefold(), clean)
        for clean_low, folder_name in chosen_names.items():
            # Предпочитаем нижний регистр для уже известных рабочих папок вроде multitran
            existing = next(
                (
                    entry.name
                    for entry in (
                        os.scandir(portable_abs)
                        if os.path.isdir(portable_abs)
                        else ()
                    )
                    if entry.is_dir(follow_symlinks=False)
                    and entry.name.casefold() == clean_low
                ),
                folder_name.lower(),
            )
            target_folder = os.path.join(portable_abs, existing)
            try:
                os.makedirs(target_folder, exist_ok=True)
                self._sync_computer_profile_subfolders(target_folder)
                if target_folder not in relocated:
                    relocated.append(target_folder)
            except OSError:
                pass
        return relocated

    # -- поиск главного exe ---------------------------------------------------
    # -- поиск и классификация исполняемых файлов -----------------------------
    #: Filler words in GOG/Steam installer titles — they must not beat a
    #: real game exe when matching names.
    _GENERIC_APP_TOKENS = frozenset({
        "the", "and", "for", "game", "games", "setup", "installer",
        "enhanced", "edition", "directors", "director", "cut", "original",
        "complete", "gold", "deluxe", "digital", "definitive", "ultimate",
        "goty", "gog", "steam", "epic", "windows", "win32", "win64",
        "version", "pack", "bundle", "collection", "anniversary",
        "remaster", "remastered", "portable",
    })
    #: Bonus editors, SDKs, crash helpers — never the default Launch.bat.
    #: The Witcher EE ships ``djinni.exe`` / ``djini.exe`` next to
    #: ``witcher.exe``; it is a mod editor, not the game.
    _TOOL_NAME_HINTS = (
        "djinni", "djini", "djinn", "editor", "sdk", "worldbuilder",
        "mapeditor", "leveleditor", "dedicated", "server", "crash",
        "crashpad", "redist", "vcredist", "unins", "helper", "dump",
        "benchmark", "perf", "tester", "tool", "maker", "builder",
        "manager", "content", "mod", "patch", "werfault", "bugreport",
    )

    @staticmethod
    def _app_name_score(stem: str, app_name: str) -> int:
        """How well an exe stem matches the product title (no ``.exe``)."""
        stem_l = (stem or "").lower()
        name_l = (app_name or "").lower()
        if not stem_l or not name_l:
            return 0
        if stem_l in name_l or name_l in stem_l:
            return 100
        tokens = [
            token for token in re.findall(r"[a-z0-9]{4,}", name_l)
            if token not in Portablizer._GENERIC_APP_TOKENS
        ]
        score = 0
        for token in tokens:
            if token == stem_l or token in stem_l or stem_l in token:
                score += 80
        return min(100, score)

    def _discover_app_executables(
        self, app_dir: str, app_name: str, portable_prefix: str = "App",
    ) -> Tuple[Optional[str], List[launcher_mod.TargetInfo]]:
        """Сканирует каталог продукта и находит все запускаемые программы.

        ``portable_prefix`` — расположение ``app_dir`` относительно корня
        портатива (обычно ``App``; у Fusion webdeploy это PortableData/...)
        и используется при формировании root-relative путей лончера.
        Классифицирует файлы по ролям:
          - main: основной исполняемый файл (игра/приложение);
          - launcher: предустановленный официальный лаунчер;
          - config: утилита настройки графики, языка, звука;
          - tool: редакторы, менеджеры модов/DLC, серверы;
          - auxiliary: прочие вспомогательные бинарники.
        """
        candidates: List[str] = []
        for root, _dirs, files in os.walk(app_dir):
            for f in files:
                if f.lower().endswith(".exe"):
                    candidates.append(os.path.join(root, f))
        if not candidates:
            return None, []

        bad_prefixes = (
            "unins", "vcredist", "vc_redist", "dxsetup", "oalinst",
            "crashpad", "crashreport", "unitycrashhandler", "werfault",
            "bugreport", "epicwebhelper", "update", "helper", "feedback",
        )

        non_ignored: List[Tuple[int, str, str, str, str]] = []

        for p in candidates:
            base = os.path.basename(p).lower()
            stem = os.path.splitext(os.path.basename(p))[0]
            if base.startswith("unins") or base == "uninstall.exe":
                continue
            if any(b in base for b in bad_prefixes):
                continue

            rel_app = os.path.relpath(p, app_dir)
            depth = rel_app.count(os.sep)
            try:
                size = os.path.getsize(p)
            except OSError:
                size = 0

            role = "main"
            desc = stem
            if any(k in base for k in ("launcher", "autorun")) or base in ("play.exe", "start.exe", "launch.exe", "gamelauncher.exe"):
                role = "launcher"
                desc = "Лаунчер программы"
            elif any(k in base for k in ("config", "setting", "setup", "option", "language", "lang", "video", "graphics", "display", "resolution", "audio", "sound")):
                role = "config"
                desc = "Настройки графики и языка"
            elif any(k in stem.lower() for k in self._TOOL_NAME_HINTS) or any(
                    k in base for k in ("manager", "content", "mod", "editor", "edit", "tool", "bench", "maker", "builder", "patch", "server", "dedicated")):
                role = "tool"
                desc = f"Утилита ({stem})"

            # Оценка вероятности быть главным исполняемым файлом
            s = 0
            s += self._app_name_score(stem, app_name)
            if role == "main":
                s += 30
            elif role == "launcher":
                s += 10
            elif role == "tool":
                s -= 80
            elif role == "config":
                s -= 40
            # Electron tray hosts are often "Name app.exe" next to chrome_elf.dll
            # (Ollama). Prefer that over the CLI/server sibling of the same name.
            if base.endswith(" app.exe"):
                s += 40
            if os.path.isfile(os.path.join(os.path.dirname(p), "chrome_elf.dll")):
                s += 25
            # exe в корне App/ или в App/bin обычно важнее
            s -= depth * 5
            # Size is a weak hint: a 40 MB mod editor must not beat a 5 MB
            # game exe that actually matches the title.
            s += min(12, int(size / (1024 * 1024)))
            non_ignored.append((s, p, stem, role, desc))

        if not non_ignored:
            return None, []

        non_ignored.sort(key=lambda x: x[0], reverse=True)
        # Launch.bat must start the game or its launcher, never a bonus
        # editor (Witcher ``djinni.exe``) just because it is large.
        preferred = [item for item in non_ignored if item[3] == "main"]
        if not preferred:
            preferred = [item for item in non_ignored if item[3] == "launcher"]
        if not preferred:
            preferred = non_ignored
        main_exe = preferred[0][1]

        def _safe_slug(s: str) -> str:
            cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_")
            return cleaned if cleaned else "App"

        targets: List[launcher_mod.TargetInfo] = []
        used_bat_names: Set[str] = set()

        for _score, path, stem, role, desc in non_ignored:
            rel_path = os.path.join(
                portable_prefix, os.path.relpath(path, app_dir)).replace("\\", "/")
            is_main = (path == main_exe)
            actual_role = "main" if is_main else role

            if is_main:
                bat_name = "Launch.bat"
                vbs_name = "LaunchHidden.vbs"
            elif actual_role == "launcher":
                bat_name = "Launch_Launcher.bat"
                vbs_name = "Launch_Launcher.vbs"
            elif actual_role == "config":
                bat_base = "Launch_Configurator" if "config" in stem.lower() else ("Launch_Settings" if "setting" in stem.lower() else f"Launch_{_safe_slug(stem)}")
                bat_name = f"{bat_base}.bat"
                vbs_name = f"{bat_base}.vbs"
            else:
                bat_name = f"Launch_{_safe_slug(stem)}.bat"
                vbs_name = f"Launch_{_safe_slug(stem)}.vbs"

            # Гарантируем уникальность имён файлов лончеров
            counter = 2
            original_bat = bat_name
            while bat_name in used_bat_names:
                root_name, ext = os.path.splitext(original_bat)
                bat_name = f"{root_name}_{counter}{ext}"
                vbs_name = f"{root_name}_{counter}.vbs"
                counter += 1
            used_bat_names.add(bat_name)

            targets.append(launcher_mod.TargetInfo(
                name=stem,
                rel_path=rel_path,
                role=actual_role,
                description=desc,
                bat_name=bat_name,
                vbs_name=vbs_name,
            ))

        # Главный exe первым, затем лаунчеры, конфигураторы и утилиты
        targets.sort(key=lambda t: 0 if t.role == "main" else (1 if t.role == "launcher" else (2 if t.role == "config" else 3)))
        return main_exe, targets

    @staticmethod
    def _app_has_payload(app_dir: str) -> bool:
        """Есть ли в ``App`` содержательный файл (неполная установка).

        Нужно, чтобы отличить два разных исхода тайм-аута: «движок не понял
        ключи и не сделал ничего» (тогда перебор сценариев продолжается) и
        «установка шла, но не дошла до конца» (тогда повторять её поверх
        недописанных гигабайтов нельзя). Маленький лог, TEMP или частичный
        download не считаются payload.
        """
        return space_mod.has_payload(app_dir)

    def _find_main_exe(self, app_dir: str, name: str) -> Optional[str]:
        main_exe, _ = self._discover_app_executables(app_dir, name)
        return main_exe

    # -- зависимости ----------------------------------------------------------
    def _collect_dep_dirs(self, app_dir: str, portable_dir: str) -> List[str]:
        """Определяет папки с dll/runtime для добавления в PATH лончера.

        Мы не пытаемся «вытащить» системные VC++ Runtime (это отдельная большая
        задача), но: (1) добавляем в PATH корень App и все подпапки, где лежат
        dll; (2) фиксируем обнаруженные зависимости в отчёте.
        """
        dep_dirs: List[str] = []
        seen = set()
        for root, _dirs, files in os.walk(app_dir):
            if any(f.lower().endswith(".dll") for f in files):
                rel = os.path.relpath(root, portable_dir)
                if rel not in seen:
                    seen.add(rel)
                    dep_dirs.append(rel.replace("\\", "/"))
        if dep_dirs:
            self.log.info(f"Папки с зависимостями (dll) добавлены в PATH: {len(dep_dirs)} шт.")
        # Ограничим, чтобы PATH не разросся: корень App + до 10 подпапок.
        return dep_dirs[:12]

    # -- предусловия дистрибутива --------------------------------------------
    def _install_prerequisites(self, opts: PortableOptions,
                               result: PortableResult) -> None:
        """При opt-in ставит предусловия молча ДО основного установщика.

        Эти установщики меняют систему. Поэтому вызывающий код проверяет
        ``silent_runtime_install`` (выключено по умолчанию); без opt-in
        Portablizer оставляет решение основному установщику, который может
        показать собственные окна.

        Запускается только то, что опознано белым списком
        (``vcredist_x86.exe``, ``DXSETUP.exe``, ``oalinst.exe``, PhysX,
        .NET…): произвольный exe из папки дистрибутива никто молча не
        выполняет.
        """
        if not opts.bundle_runtimes or not opts.silent_runtime_install:
            return
        if not IS_WINDOWS:
            self.log.debug(
                "Тихая установка распространяемых пакетов доступна только "
                "на Windows — пропускаю.")
            return
        sources = redist_mod.installer_source_dirs(opts.installer_path)
        if not sources and not os.path.isfile(opts.installer_path or ""):
            return
        if not is_elevated():
            self.log.warn(
                "Portablizer запущен без прав администратора: тихая "
                "установка распространяемых пакетов может не пройти, и "
                "установщик программы снова покажет окна с «OK».")
        try:
            outcomes = redist_mod.install_prerequisites(
                sources, self.log, installer_path=opts.installer_path)
        except Exception as exc:  # noqa: BLE001 — предусловия не критичны
            self.log.warn(f"Не удалось поставить предусловия: {exc}")
            return
        for item in outcomes:
            if item.ok:
                result.runtime_installed.append(item.title or item.name)
        if outcomes:
            failed = [item for item in outcomes if item.status == "failed"]
            if failed:
                self.log.warn(
                    "Часть предусловий поставить молча не удалось: "
                    + ", ".join(item.name for item in failed[:6])
                    + ". Если установщик покажет их окна, закройте их "
                      "кнопкой «OK» — на портатив это не влияет.")
            else:
                self.log.ok(
                    "Все предусловия дистрибутива установлены в тихом "
                    "режиме — окон с «OK» по ходу установки не будет.")

    # -- распространяемые компоненты -----------------------------------------
    def _provision_runtimes(
        self, app_dir: str, portable_dir: str, opts: PortableOptions,
        name: str, result: PortableResult, main_exe: str = "",
        targets: Optional[List["launcher_mod.TargetInfo"]] = None,
    ) -> Optional["redist_mod.ProvisionReport"]:
        """Приносит в портатив VC++/DirectX и прочие системные библиотеки.

        Обычная установка кладёт их в систему, поэтому на компьютере-сборщике
        всё работает, а на чужом ПК Windows показывает «отсутствует
        MSVCP110.dll». Здесь список нужных библиотек берётся из таблиц импорта
        самих exe/dll программы, а файлы — из комплекта установщика, системных
        папок этого ПК, WinSxS или (по желанию) с сайта Microsoft.

        Поверх точного списка разворачивается **полный комплект «про запас»**
        (``full_runtimes``): все известные библиотеки всех версий рядом с
        каждым exe программы. Таблица импорта не видит библиотек, которые
        грузятся по имени, собранному строкой, или подключаются плагинами и
        модами, — полный комплект закрывает и их. Ненайденное «про запас»
        ошибкой не считается.
        """
        if not opts.bundle_runtimes:
            self.log.info(
                "Проверка распространяемых компонентов отключена в параметрах.")
            return None
        try:
            scan = redist_mod.scan_app_runtime(app_dir)
        except Exception as exc:  # noqa: BLE001 — диагностика не должна ронять сборку
            self.log.warn(f"Не удалось разобрать зависимости программы: {exc}")
            return None
        if not scan.parsed:
            self.log.debug(
                "Ни одного PE-файла в App разобрать не удалось — проверка "
                "распространяемых компонентов пропущена.")
            return None

        self.log.info(
            f"Разобрано исполняемых файлов: {scan.parsed}; внешних библиотек: "
            f"{len(scan.requirements)}; из них требует внимания: "
            f"{len(scan.needed)}.")

        # Куда раскладывать полный комплект: рядом с каждым exe программы.
        anchors: List[str] = []
        anchor_paths = [main_exe] + [
            os.path.join(portable_dir, t.rel_path) for t in (targets or [])]
        for path in anchor_paths:
            if not path:
                continue
            rel = os.path.relpath(path, app_dir)
            if rel.startswith(".."):
                continue
            rel = rel.replace("\\", "/")
            if rel not in anchors:
                anchors.append(rel)

        sources = redist_mod.installer_source_dirs(opts.installer_path, app_dir)
        if sources:
            self.log.debug(
                "Папки с готовыми redist-файлами рядом с установщиком: "
                + ", ".join(os.path.basename(s) for s in sources[:6]))
        provisioner = redist_mod.RuntimeProvisioner(
            self.log, source_dirs=sources,
            allow_download=opts.download_runtimes,
            allow_install=opts.silent_runtime_install,
            progress=self._stage_progress(82, 87),
            cancel=self.cancel.is_set)
        try:
            report = provisioner.provision(
                scan, app_dir, portable_dir, name,
                full_kit=opts.full_runtimes, anchors=anchors)
        except Exception as exc:  # noqa: BLE001
            self.log.warn(
                f"Не удалось перенести распространяемые компоненты: {exc}")
            return None

        for requirement in report.provided:
            self.log.ok(
                f"В портатив добавлена {requirement.dll} "
                f"[{requirement.arch or '?'}] — {requirement.title} "
                f"({requirement.source})")
        result.runtime_provided = [r.dll for r in report.provided]
        result.runtime_stock = [r.dll for r in report.stock]
        if report.stock:
            self.log.ok(
                f"Полный комплект «про запас»: рядом с exe дополнительно "
                f"разложено {len(report.stock)} библиотек — все версии "
                "VC++ и DirectX, какие удалось найти. Плагинам и "
                "динамическим загрузкам хватит всего.")
        if report.stock_missing:
            self.log.info(
                f"Полный комплект: ещё {len(report.stock_missing)} библиотек "
                "не нашлись на этом ПК. Программе они, скорее всего, не "
                "нужны; список — в " + redist_mod.REPORT_NAME + ".")

        packages: List[str] = []
        for requirement in report.missing:
            entry = f"{requirement.title} — {requirement.url}" \
                if requirement.url else requirement.title
            if entry not in packages:
                packages.append(entry)
        result.runtime_missing = [r.dll for r in report.missing]
        result.runtime_packages = packages
        for item in report.installed:
            if item.ok and (item.title or item.name) not in result.runtime_installed:
                result.runtime_installed.append(item.title or item.name)
        if report.installers:
            self.log.ok(
                "Недостающие пакеты сохранены в папке "
                f"{redist_mod.REDIST_DIR_NAME} вместе со скриптом "
                f"{redist_mod.SILENT_SCRIPT_NAME}. Лончер только предупредит; "
                "установка начнётся лишь после ручного запуска скрипта.")

        if report.missing:
            self.log.warn(
                "Не удалось найти файлы для: "
                + ", ".join(sorted({r.dll for r in report.missing}))
                + ". На целевом ПК может понадобиться установка пакета — "
                  "см. " + redist_mod.REPORT_NAME + " в папке портатива.")
            for entry in packages[:6]:
                self.log.warn(f"  • {entry}")
            if not opts.download_runtimes:
                self.log.info(
                    "Совет: включите «Скачивать недостающие пакеты», и "
                    "Portablizer возьмёт файлы прямо с сайта Microsoft.")
        elif report.provided or report.stock:
            self.log.ok(
                "Все системные компоненты, нужные программе, теперь лежат "
                "внутри портатива — установка на чужом ПК не потребуется.")

        if report.touched:
            try:
                self._write_text(
                    os.path.join(portable_dir, redist_mod.REPORT_NAME),
                    redist_mod.render_report(report), encoding="utf-8-sig")
                result.runtime_report_rel = redist_mod.REPORT_NAME
            except OSError as exc:
                self.log.warn(
                    f"Не удалось сохранить {redist_mod.REPORT_NAME}: {exc}")
        return report

    # -- относительные пути ---------------------------------------------------
    def _make_paths_relative(self, portable_dir: str, name: str,
                             opts: PortableOptions,
                             result: PortableResult) -> str:
        """Запоминает корень портатива и проверяет пути внутри него.

        Сами по себе файлы портатива переносимы: лончер и конфиг хранят пути
        относительно корня, реестр — маркер ``@@PORTABLE_ROOT@@``. Проблема в
        настройках самой программы: их формат не наш, и «относительного» пути
        там не бывает. Поэтому корень записывается в
        ``PortableData\\portable-root.json``: при запуске лончер сравнит его с
        текущим положением папки и, если она переехала на другой диск,
        заменит старый путь новым до старта программы.

        Заодно составляется ``portability-report.txt`` — список файлов, где
        абсолютные пути всё-таки есть, с делением на «внутри портатива» и
        «вне его». Это ответ на вопрос «почему после переноса что-то
        отвалилось» без догадок.
        """
        if not opts.relative_paths:
            self.log.info(
                "Относительные пути отключены: корень портатива не "
                "запоминается, и после переноса настройки программы могут "
                "указывать в старое место.")
            return ""

        previous = relpaths_mod.stored_root(portable_dir)
        relpaths_mod.write_stamp(portable_dir, portable_dir, __version__,
                                 previous=previous)
        audit = relpaths_mod.audit(portable_dir, include_app=True)
        stamp = relpaths_mod.read_stamp(portable_dir)
        report = relpaths_mod.write_report(
            portable_dir, audit, version=__version__, stamp=stamp,
            launcher_exe=os.path.join("App", APP_EXE_LAUNCHER_NAME))

        if audit.is_clean:
            self.log.ok(
                "Пути внутри портатива относительные — проверено "
                f"{audit.scanned} текстовых файлов. Папку можно переносить "
                "на другой диск или в другой каталог.")
        else:
            self.log.info(
                f"Абсолютные пути старого корня есть в {len(audit.hits)} "
                f"файлах настройки ({audit.inside_count} путей). При переносе "
                "лончер заменит их новым путём: запускайте программу через "
                f"App\\{APP_EXE_LAUNCHER_NAME} или Launch.bat.")
        if audit.outside_count:
            self.log.info(
                f"Пути вне портатива: {audit.outside_count}. Перенести их "
                "нельзя — подробности в " + relpaths_mod.REPORT_NAME + ".")
        if not report:
            self.log.warn(
                f"Не удалось записать {relpaths_mod.REPORT_NAME}.")
            return ""
        return os.path.relpath(report, portable_dir)

    # -- лончер ---------------------------------------------------------------
    def _copy_exe_launcher(
        self, portable_dir: str,
        destination_rel: str = os.path.join("App", APP_EXE_LAUNCHER_NAME),
    ) -> str:
        """Копирует самодостаточный EXE-лончер в указанное место портатива.

        Один бинарник используется и для главной программы, и для отдельных
        ``Launch_Launcher.exe``/``Launch_Configurator.exe``. При запуске копия
        находит своё имя в ``launcher_config.json`` и выбирает относительный
        путь цели, сохраняя изоляцию профиля и переносимость между дисками.
        """
        source = bundled_exe_launcher_path()
        if not os.path.isfile(source):
            self.log.warn(
                "В сборке Portablizer отсутствует встроенный "
                "portable_launcher.exe; LaunchPortable.exe в App не создан. "
                "Пересоберите проект через build.bat (он сначала выполняет "
                "portable_launcher.spec)."
            )
            return ""
        try:
            with open(source, "rb") as fh:
                if fh.read(2) != b"MZ":
                    raise RuntimeError("ресурс не является Windows EXE (нет заголовка MZ)")
            destination = os.path.abspath(os.path.join(portable_dir, destination_rel))
            portable_abs = os.path.abspath(portable_dir)
            if os.path.commonpath((portable_abs, destination)) != portable_abs:
                raise RuntimeError("путь EXE-лончера выходит за пределы портатива")
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            temporary = destination + ".tmp"
            shutil.copy2(source, temporary)
            os.replace(temporary, destination)
        except (OSError, RuntimeError, ValueError) as exc:
            self.log.warn(f"Не удалось создать {destination_rel}: {exc}")
            return ""
        rel = os.path.relpath(destination, portable_dir)
        self.log.ok(
            f"Создан переносимый EXE-лончер: {rel}. Его можно запускать "
            "двойным кликом без Python и без Launch.bat."
        )
        if os.path.normcase(os.path.normpath(destination_rel)) != os.path.normcase(
                os.path.normpath(os.path.join("App", APP_EXE_LAUNCHER_NAME))):
            # Копии под именами Launch_Launcher.exe / Launch_Configurator.exe
            # получают свой алиас в конфиге; дополнительная «именная» копия
            # нужна только рядом с основным лончером.
            return rel
        # Дополнительно: копия лончера с понятным именем для Диспетчера задач.
        # Жалоба: в Task Manager висел ``LaunchPortable.exe``, и было
        # непонятно, какую программу он запускает. Рядом кладётся та же самая
        # копия с именем «Launch <AppName>.exe»: имя процесса в Диспетчере
        # задач сразу говорит, что именно запущено. Цель у копии та же, что у
        # основного лончера (main-цель из конфига), поэтому никаких aliases не
        # требуется, а конфликт с настоящим exe программы исключён префиксом.
        named = self._copy_named_exe_launcher(portable_dir, os.path.normpath(
            os.path.join(portable_dir, destination_rel)))
        if named:
            self.log.ok(
                "Создан лончер с именем программы: " + named + " — именно он "
                "виден в Диспетчере задач как «Launch <программа>».")
        return rel

    @staticmethod
    def _task_manager_name(portable_dir: str) -> str:
        """Имя лончера, понятное в Диспетчере задач: «Launch <Программа>».

        ``LaunchPortable.exe`` само по себе не отвечает на вопрос «какую
        программу он запускает» — а именно этот вопрос и задал пользователь.
        """
        # Путь может быть в Windows-синтаксисе даже на не-Windows (тесты,
        # разбор чужого конфига), поэтому делим по обоим разделителям.
        text = os.path.normpath(str(portable_dir)).replace("\\", "/")
        base = text.rsplit("/", 1)[-1].strip()
        if base.casefold().endswith("_portable"):
            base = base[: -len("_portable")]
        cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', " ", base or "")
        cleaned = " ".join(cleaned.split()).strip(" .")
        # Оставляем место под префикс и расширение: MAX_PATH никто не отменял.
        return ("Launch " + cleaned)[:120] if cleaned else "Launch Portable"

    def _copy_named_exe_launcher(self, portable_dir: str,
                                 launcher_path: str) -> str:
        """Кладёт рядом копию лончера с именем программы (для Task Manager).

        Возвращает относительный путь копии или пустую строку. Копия — тот же
        самый самодостаточный лончер: он находит ``launcher_config.json`` по
        своему расположению и запускает ту же главную цель, что и
        ``LaunchPortable.exe``. Имя начинается с «Launch », поэтому оно не
        может совпасть с настоящим exe программы и ничего не перезапишет.
        """
        if not launcher_path or not os.path.isfile(launcher_path):
            return ""
        try:
            name = self._task_manager_name(portable_dir) + ".exe"
            destination = os.path.join(os.path.dirname(launcher_path), name)
            if os.path.normcase(destination) == os.path.normcase(launcher_path):
                return ""
            portable_abs = os.path.abspath(portable_dir)
            if os.path.commonpath((portable_abs, os.path.abspath(destination))) \
                    != portable_abs:
                return ""
            temporary = destination + ".tmp"
            shutil.copy2(launcher_path, temporary)
            os.replace(temporary, destination)
        except (OSError, ValueError):
            return ""
        return os.path.relpath(destination, portable_dir)

    # -- сквозные сохранения --------------------------------------------------
    def _setup_shared_saves(
        self, portable_dir: str, app_dir: str, name: str,
        targets: Optional[List[launcher_mod.TargetInfo]],
        opts: PortableOptions, result: PortableResult,
    ) -> "Optional[saves_mod.SaveSetup]":
        """Сводит сохранения всех способов запуска в одно хранилище.

        Прямой запуск ``App\\Game.exe`` получает настоящий профиль Windows, а
        лончер — перенаправленный внутрь портатива. Пока эти два хранилища
        существуют порознь, сохранения одного способа не видны другому. Здесь
        они сводятся: игре движка Gamebryo объясняется, что данные надо
        держать рядом с exe, а всем остальным назначается синхронизация,
        которую лончер выполняет при каждом запуске.
        """
        if not opts.shared_saves:
            result.saves_mode = "off"
            self.log.info("Сквозные сохранения отключены в настройках сборки.")
            return None
        try:
            executables = [t.rel_path for t in (targets or [])]
            setup = saves_mod.plan(portable_dir, name, executables)
            saves_mod.apply(portable_dir, setup, self.log)
        except OSError as exc:
            self.log.warn(f"Сквозные сохранения настроить не удалось: {exc}")
            return None

        result.saves_mode = setup.mode
        result.saves_store_rel = setup.store.replace("/", os.sep)
        result.saves_migrated = setup.migrated
        result.saves_notes = saves_mod.describe(setup)
        for line in result.saves_notes:
            self.log.ok(line) if setup.enabled else self.log.info(line)
        if setup.migrated:
            self.log.ok(
                f"В общее хранилище перенесено файлов сохранений и настроек: "
                f"{setup.migrated}. Их увидят все способы запуска.")
        return setup

    def _provision_netstack(self, portable_dir: str, app_dir: str,
                            opts: PortableOptions,
                            result: PortableResult
                            ) -> Optional["netstack_mod.NetStackReport"]:
        """Переносит системные сетевые компоненты программы в ``NetStack/``.

        Драйвер TAP-Windows и служба VPN-клиента живут вне папки: их нельзя
        ни «подставить», как реестр, ни откатить, как ярлыки. Надёжность
        портатива здесь измеряется тем, что он делает на ЧИСТОМ ПК: лончер
        проверяет наличие драйвера/службы и досоздаёт недостающее из копий,
        приложенных к портативу (один тихий UAC вместо окон «Безопасность
        Windows»).

        На ЦЕЛЕВОМ ПК по умолчанию работает изолированный режим: драйвер
        публикуется из NetStack только на время сеанса (один тихий UAC),
        по завершении сеанса портатив снимает и свои службы, и корневые
        устройства адаптера, и сам пакет из DriverStore — хост возвращается
        в состояние «до запуска». Пакеты, которые на этом ПК поставили НЕ
        портативом, он не трогает никогда (владение фиксируется диффом
        %SystemRoot%\\INF при публикации). Режим shared («драйвер как
        общий компонент, как Visual C++ из Redist») остаётся опцией.
        """
        if not opts.netstack_components or not app_dir:
            return None
        try:
            packages = netstack_mod.scan_net_driver_packages(app_dir)
            service_names: List[str] = []
            if IS_WINDOWS:
                try:
                    service_names = procutil.services_in(portable_dir)
                except Exception as exc:  # noqa: BLE001
                    self.log.debug(f"Не удалось перечислить службы: {exc}")
            records = netstack_mod.collect_companion_services(
                app_dir, service_names) if service_names else []
            report = netstack_mod.provision_netstack(
                portable_dir, app_dir, packages, records,
                isolated=opts.netstack_isolated)
        except Exception as exc:  # noqa: BLE001 — компоненты не роняют сборку
            self.log.warn(f"Сетевые компоненты не перенесены: {exc}")
            return None
        if report is None:
            self.log.debug(
                "Сетевых компонентов (TAP-Windows/wintun/ovpn-dco) в App не "
                "найдено — NetStack не создаётся.")
            return None
        for note in report.notes:
            self.log.debug(f"  • {note}")
        result.netstack_drivers = sorted({
            entry.get("service") or entry.get("kind", "")
            for entry in report.drivers})
        result.netstack_services = sorted({
            entry.get("name", "") for entry in report.services
            if entry.get("name")})
        parts = []
        if result.netstack_drivers:
            parts.append("драйверы: " + ", ".join(result.netstack_drivers))
        if result.netstack_services:
            parts.append("службы: " + ", ".join(result.netstack_services))
        if parts:
            self.log.ok("Сетевые компоненты перенесены в NetStack — "
                        + "; ".join(parts)
                        + ". Лончер проверит и досоздаст их на любом ПК.")
        return report

    def _write_launcher(self, portable_dir: str, name: str, main_exe_rel: str,
                        opts: PortableOptions, path_prepend: List[str],
                        capture: Optional[RegistryCapture] = None,
                        targets: Optional[List[launcher_mod.TargetInfo]] = None,
                        runtime_report: "Optional[redist_mod.ProvisionReport]" = None,
                        save_setup: "Optional[saves_mod.SaveSetup]" = None,
                        netstack_report: "Optional[netstack_mod.NetStackReport]" = None
                        ) -> List[str]:
        has_registry = bool(
            capture and (capture.reg_file or capture.machine_reg_file
                         or capture.keys)
        )
        all_targets = list(targets or [])
        launcher_target = next((t.rel_path for t in all_targets if t.role == "launcher"), "")
        config_target = next((t.rel_path for t in all_targets if t.role == "config"), "")

        extra_env = dict(opts.extra_env)
        target_args: List[str] = []
        main_abs = os.path.join(portable_dir, main_exe_rel.replace("/", os.sep))
        main_dir = os.path.dirname(main_abs)
        main_base = os.path.basename(main_abs).lower()
        # Только настоящий Electron/NW.js. Раньше здесь хватало
        # ``libcef.dll``, и SketchUp (встроенный CEF для браузерных панелей)
        # получал Chromium-ключи, на которые отвечает окном «Unknown options:
        # no-sandbox, disable-gpu-sandbox, disable-features» и не запускается.
        electron_host = launcher_mod.is_electron_app(main_abs)
        webview2_host = (
            not electron_host
            and (
                os.path.isfile(os.path.join(main_dir, "WebView2Loader.dll"))
                or (main_base.endswith(" app.exe") and "ollama" in main_base)
            )
        )
        if electron_host and not main_base.endswith("ollama.exe"):
            extra_env.setdefault("ELECTRON_NO_SANDBOX", "1")
            extra_env.setdefault("ELECTRON_DISABLE_SANDBOX", "1")
            target_args = list(launcher_mod.ELECTRON_CHROMIUM_FLAGS)
        # Cursor / VS Code / VSCodium: Electron с распакованным app-каталогом.
        # Его профиль задаётся не только APPDATA, а ещё и VSCODE_* переменными;
        # без них helper-процессы и перезапуск «для обновления» уходят в
        # настоящий профиль Windows, а на другом диске — в старый путь.
        vscode = launcher_mod.vscode_product(main_abs)
        if vscode:
            for key, value in launcher_mod.vscode_portable_env(
                    vscode, "PortableData").items():
                extra_env.setdefault(key, value)
        if webview2_host:
            extra_env.setdefault(
                "WEBVIEW2_USER_DATA_FOLDER",
                "%PORTABLE_ROOT%\\PortableData\\WebView2",
            )

        cfg = launcher_mod.LauncherConfig(
            app_name=name,
            target_exe_rel=main_exe_rel.replace("\\", "/"),
            target_args=target_args,
            data_dir_name="PortableData",
            apply_registry=has_registry,
            registry_keys=list(capture.keys) if capture else [],
            registry_created_keys=list(capture.created_keys) if capture else [],
            registry_has_root_token=bool(capture and capture.has_root_token),
            # Ключи списка приложений, которые создал этот установщик: лончер
            # снимает их даже если значения записи потом перепишет апдейтер.
            host_cleanup_records=(
                launcher_mod.installed_entry_records(capture.cleanup_keys,
                                                     capture.cleanup_entries)
                if capture is not None
                and getattr(opts, "cleanup_host", True) else []
            ),
            extra_env=extra_env,
            path_prepend=path_prepend,
            redirect_known_folders=True,
            targets=all_targets,
            launcher_target_rel=launcher_target,
            config_target_rel=config_target,
            runtime_requirements=(
                redist_mod.launcher_requirements(runtime_report)
                if runtime_report is not None else []
            ),
            runtime_installers=(
                redist_mod.launcher_installers(runtime_report)
                if runtime_report is not None else []
            ),
            shared_saves=(save_setup.to_dict()
                          if save_setup is not None else {}),
            netstack=(netstack_report.to_config()
                      if netstack_report is not None and netstack_report.written
                      else {}),
            language=opts.install_language.strip(),
            # Относительные пути: секция говорит лончеру, что при переносе
            # папки надо сверить запомненный корень с текущим. В ней нет ни
            # одного абсолютного пути — только имена файлов внутри портатива.
            relative_paths=relpaths_mod.launcher_section(
                portable_dir, enabled=opts.relative_paths),
        )
        # Launch.bat — CRLF, чистый ASCII и без BOM. cmd.exe читает .bat по
        # байтовым смещениям: BOM, LF-концы строк или многобайтовый символ
        # сбивают разбор, и окно закрывается без сообщения.
        bat = launcher_mod.render_bat(cfg)
        self._write_text(os.path.join(portable_dir, "Launch.bat"), bat,
                         encoding="ascii")
        # Запуск без окна консоли.
        self._write_text(os.path.join(portable_dir, "LaunchHidden.vbs"),
                         launcher_mod.render_vbs(), encoding="ascii")

        # Аварийный «отпускатель» папки. Штатно лончер закрывает за собой
        # всё сам, но пользователь мог запустить программу из App напрямую,
        # мимо лончера — тогда этот файл возвращает папку в состояние
        # «можно удалить» без диспетчера задач.
        self._write_text(
            os.path.join(portable_dir, launcher_mod.STOP_SCRIPT_NAME),
            launcher_mod.render_stop_cmd(cfg, APP_EXE_LAUNCHER_NAME),
            encoding="ascii")

        # Обновление программы внутри портатива: перетащить новый установщик
        # на этот файл (или запустить без аргументов - он скачает сам).
        self._write_text(
            os.path.join(portable_dir, launcher_mod.UPDATE_SCRIPT_NAME),
            launcher_mod.render_update_cmd(cfg, APP_EXE_LAUNCHER_NAME),
            encoding="ascii")

        created_launchers: List[str] = ["Launch.bat", "LaunchHidden.vbs",
                                        launcher_mod.STOP_SCRIPT_NAME,
                                        launcher_mod.UPDATE_SCRIPT_NAME]

        # Отдельные файлы нужны только для двух частых действий: официальный
        # launcher и окно настроек. Раньше BAT+VBS создавались для каждого
        # PerformanceTester/UserContentManager/helper, загромождая корень
        # десятком почти одинаковых файлов. Редкие утилиты остаются доступны
        # из единого Launch_Menu.bat.
        main_norm = main_exe_rel.replace("\\", "/").lower()
        companion_targets = [
            t for t in all_targets
            if t.rel_path.replace("\\", "/").lower() != main_norm
            and t.role in ("launcher", "config")
        ]
        for t in companion_targets:
            t_bat_path = os.path.join(portable_dir, t.bat_name)
            self._write_text(t_bat_path, launcher_mod.render_companion_bat(cfg, t),
                             encoding="ascii")
            created_launchers.append(t.bat_name)
            # Отдельный оконный EXE надёжнее цепочки BAT -> PowerShell -> UAC
            # и при этом использует в точности тот же портативный профиль.
            exe_name = os.path.splitext(t.bat_name)[0] + ".exe"
            cfg.launcher_aliases[exe_name] = t.rel_path

            if t.role == "launcher":
                self.log.ok(
                    f"Обнаружен лаунчер программы: {t.rel_path} "
                    f"(создан {t.bat_name})")
            else:
                self.log.ok(
                    f"Обнаружен конфигуратор/настройки: {t.rel_path} "
                    f"(создан {t.bat_name})")

        if len(all_targets) >= 2:
            menu_bat_path = os.path.join(portable_dir, "Launch_Menu.bat")
            self._write_text(menu_bat_path, launcher_mod.render_menu_bat(cfg),
                             encoding="ascii")
            created_launchers.append("Launch_Menu.bat")
            self.log.ok("Создано интерактивное меню выбора программ: Launch_Menu.bat")

        # Общий config читают и корневые скрипты, и готовый EXE в App/.
        self._write_text(os.path.join(portable_dir, "launcher_config.json"),
                         launcher_mod.render_config_json(cfg), newline="\n")
        # Cursor/VS Code: профиль и расширения живут в PortableData, а
        # disable-chromium-sandbox в argv.json не даёт Chromium-песочнице
        # отказаться от запуска внутри папки портатива. Файлы пишутся один раз
        # при сборке, но лончер проверяет и восстанавливает их на каждом
        # запуске (см. portable_launcher_entry._apply_vscode_profile).
        if vscode:
            self.log.ok(
                f"Обнаружено приложение VS Code-семейства ({vscode['name']}): "
                "профиль и расширения будут храниться в PortableData "
                "(VSCODE_APPDATA / VSCODE_EXTENSIONS)")
            for note in launcher_mod.prepare_vscode_profile(
                    portable_dir, main_exe_rel, "PortableData"):
                self.log.ok(note)
        if launcher_mod.identity_settings(cfg) is not None:
            self.log.info(
                "Программа входит в аккаунт ключом профиля (Ollama): ключ "
                "переносится в портатив при запуске через лончер, если его там "
                "ещё нет. Проверка: App\\LaunchPortable.exe --check-identity")
        if opts.build_exe_launcher:
            self._copy_exe_launcher(portable_dir)
            for exe_name in cfg.launcher_aliases:
                if self._copy_exe_launcher(portable_dir, exe_name):
                    created_launchers.append(exe_name)

        # Формируем описание дополнительных файлов в README
        companion_lines = []
        companion_files_desc = []
        for t in companion_targets:
            exe_name = os.path.splitext(t.bat_name)[0] + ".exe"
            preferred_name = (
                exe_name if os.path.isfile(os.path.join(portable_dir, exe_name))
                else t.bat_name
            )
            companion_lines.append(
                f"  • {preferred_name:<24} — запуск {t.description} ({t.rel_path})")
            if preferred_name != t.bat_name:
                companion_files_desc.append(
                    f"  {preferred_name:<21} — переносимый EXE-запуск {t.name}\n")
            companion_files_desc.append(
                f"  {t.bat_name:<21} — запасной запуск {t.name} ({t.rel_path})\n")

        if len(all_targets) >= 2:
            companion_lines.append("  • Launch_Menu.bat          — интерактивное меню выбора программы")
            companion_files_desc.append("  Launch_Menu.bat       — интерактивное меню выбора исполняемого файла\n")

        companion_section = ""
        if companion_lines:
            companion_section = "\nДополнительные варианты запуска:\n" + "\n".join(companion_lines) + "\n"
        companion_files_list = "".join(companion_files_desc)

        # README
        registry_note = (
            "  portable.reg          — настройки программы (переносятся с папкой)\n"
            if capture and capture.reg_file else ""
        )
        # Раздел о системных библиотеках нужен, только если они вообще
        # обсуждались: пустой заголовок в README только путает.
        runtime_note = ""
        runtime_section = ""
        if runtime_report is not None and runtime_report.touched:
            runtime_note = (
                f"  {redist_mod.REPORT_NAME:<21} — какие системные библиотеки "
                "нужны программе\n"
            )
            if runtime_report.provided:
                runtime_section = (
                    "\nСистемные библиотеки (Visual C++, DirectX и т.п.):\n"
                    "  • нужные файлы уже лежат внутри папки App — "
                    "устанавливать пакеты\n"
                    "    на чужом компьютере не нужно;\n"
                    f"  • полный список — в {redist_mod.REPORT_NAME}.\n"
                )
            if runtime_report.missing:
                missing_names = ", ".join(sorted({
                    item.dll for item in runtime_report.missing})[:8])
                runtime_section += (
                    "\nВНИМАНИЕ: часть системных библиотек найти не удалось: "
                    f"{missing_names}.\n"
                    "  Если программа не запустится, установите пакеты по "
                    f"ссылкам из {redist_mod.REPORT_NAME}\n"
                    "  (обычно это Microsoft Visual C++ Redistributable или "
                    "DirectX End-User Runtime).\n"
                )
                if runtime_report.installers:
                    runtime_section += (
                        "  Если вы доверяете пакетам и хотите установить их, "
                        "запустите вручную\n"
                        f"  {redist_mod.REDIST_DIR_NAME}\\"
                        f"{redist_mod.SILENT_SCRIPT_NAME}. Он работает тихо "
                        "и может запросить UAC;\n"
                        "  лончер никогда не запускает установку сам.\n"
                    )
        # Раздел о сетевых компонентах: без него пользователь портатива не
        # узнает, зачем рядом папка NetStack и почему лончер просит права.
        netstack_note = ""
        netstack_section = ""
        if netstack_report is not None and netstack_report.written:
            netstack_note = (
                "  NetStack\\            — системные сетевые компоненты "
                "(драйверы, службы)\n")
            items = []
            if netstack_report.drivers:
                items.append("драйверы: " + ", ".join(sorted({
                    d.get("service") or d.get("kind", "")
                    for d in netstack_report.drivers})))
            if netstack_report.services:
                items.append("службы: " + ", ".join(sorted(
                    s.get("name", "") for s in netstack_report.services)))
            netstack_section = (
                "\nСетевые компоненты (" + "; ".join(items) + "):\n"
                "  • часть программ (VPN-клиенты на OpenVPN: Planeta VPN и "
                "подобные) требует\n"
                "    системный сетевой драйвер (TAP-Windows) и/или службу; "
                "Windows не умеет\n"
                "    виртуализовать ядро, поэтому портатив несёт копии "
                "пакетов в NetStack\\\n"
                "    и при первом запуске на новом ПК досоздаёт недостающее "
                "сам — лончер\n"
                "    проверяет реестр/службы и показывает ОДИН запрос прав "
                "(NetStack\\Setup.cmd);\n"
                "  • если адаптер уже установлен другой программой — ничего "
                "не переустанавливается;\n"
                "  • изолированный режим: всё, что портатив создал на этом "
                "ПК (службы,\n"
                "    устройства адаптеров, сам пакет драйвера в "
                "DriverStore), снимается по "
                "завершении\n"
                "    сеанса — на хосте не остаётся следа; драйвер "
                "существовал ДО портатива — портатив "
                "его не трогает;\n"
                "  • UAC при этом просится на каждый первый запуск на ПК "
                "после чистки (взамен —\n"
                "    чистая машина). Не хотите снимать драйвер — запустите "
                "NetStack\\Teardown.cmd \n"
                "    вручную с флагом --keep-driver и удалите "
                "PortableData\\NetStack\\driver-packages.txt\n"
                "    перед следующим выходом;\n"
                "  • вручную: NetStack\\Setup.cmd (поставить/проверить), "
                "NetStack\\Teardown.cmd (снять всё).\n"
            )
        # Раздел о сохранениях: пользователю важно знать, где они лежат и
        # почему их теперь видно при любом способе запуска.
        saves_section = ""
        # Отступ перед разделом нужен, только когда выше уже что-то есть.
        saves_lead = "\n" if runtime_section else ""
        if save_setup is not None and save_setup.enabled:
            store = (save_setup.store.replace("/", "\\")
                     or "PortableData")
            if save_setup.mode == "inplace":
                saves_section = (
                    saves_lead
                    + "Сохранения (общие для всех способов запуска):\n"
                    f"  • лежат в {store}\\Saves внутри этой папки и "
                    "переносятся вместе с ней;\n"
                    f"  • {save_setup.title or 'программа'} переведена на "
                    "хранение сейвов и настроек рядом с exe\n"
                    "    (bUseMyGamesDirectory=0), поэтому один и тот же "
                    "набор видят и прямой\n"
                    "    запуск exe из App, и LaunchPortable.exe, и "
                    "комплектный лаунчер;\n"
                    "  • в «Документы» этого компьютера ничего не пишется.\n"
                )
            else:
                saves_section = (
                    saves_lead
                    + "Сохранения (общие для всех способов запуска):\n"
                    f"  • хранятся внутри портатива ({store}) и переносятся "
                    "вместе с папкой;\n"
                    "  • при каждом запуске лончер сводит их с профилем "
                    "этого ПК: сейв, сделанный\n"
                    "    прямым запуском exe, виден в портативе, и "
                    "наоборот. Побеждает более\n"
                    "    свежий файл, ничего не удаляется;\n"
                    "  • свести вручную: App\\LaunchPortable.exe "
                    "--sync-saves.\n"
                )
        separator = chr(92)
        main_rel_display = main_exe_rel.replace("/", separator)
        if main_rel_display.casefold().startswith("portabledata" + separator):
            profile_dir_display = main_rel_display.rsplit(separator, 1)[0]
            program_location_line = chr(10).join((
                f"  App{separator}                  — Fusion webdeploy-клиент находится ниже",
                f"  {profile_dir_display}{separator} — клиент; основной exe: "
                f"{main_rel_display.rsplit(separator, 1)[-1]}",
            ))
            update_portable_line = (
                "  UpdatePortable.cmd    — отключён для webdeploy; штатное "
                "обновление Autodesk не проверено"
            )
            update_section = chr(10).join((
                f"Обновление {name} (webdeploy-профиль):",
                "  • если клиент предлагает обновление, используйте только "
                "штатный механизм Autodesk;",
                "    ему могут потребоваться интернет, вход в аккаунт и "
                "действующая лицензия;",
                "    переносимость обновления не проверена;",
                "  • UpdatePortable.cmd намеренно отказывает: общий механизм "
                "Portablizer",
                "    устанавливает новые версии в App, а этот клиент "
                "запускается из",
                f"    {profile_dir_display};",
                "  • после обновления проверьте запуск и переносимость заново.",
                "",
            ))
        else:
            program_location_line = (
                f"  App{separator}                  — установленная программа "
                f"({main_exe_rel})"
            )
            update_portable_line = (
                "  UpdatePortable.cmd    — обновить программу ВНУТРИ портатива "
                "(см. ниже)"
            )
            update_section = _STANDARD_UPDATE_SECTION
        self._write_text(
            os.path.join(portable_dir, "README_PORTABLE.txt"),
            _README.format(
                app_name=name,
                main_exe_rel=main_exe_rel,
                program_location_line=program_location_line,
                update_portable_line=update_portable_line,
                update_section=update_section,
                netstack_note=netstack_note,
                netstack_section=netstack_section,
                saves_section=saves_section,
                companion_section=companion_section,
                companion_files_list=companion_files_list,
                registry_note=registry_note,
                runtime_note=runtime_note,
                runtime_section=runtime_section,
                exe_launcher_step=(
                    "  2. Запустите App\\LaunchPortable.exe — это готовый EXE, "
                    "который сохраняет изоляцию.\n"
                    "     Launch.bat и LaunchHidden.vbs в корне — запасные "
                    "варианты запуска.\n"
                    if os.path.isfile(os.path.join(
                        portable_dir, "App", APP_EXE_LAUNCHER_NAME))
                    else
                    "  2. Запустите Launch.bat (или LaunchHidden.vbs без "
                    "окна консоли).\n"
                ),
                exe_launcher_file=(
                    "  App\\LaunchPortable.exe — основной запуск из EXE с "
                    "портативным окружением (то же самое, что в Диспетчере "
                    "задач видно как «Launch " + name + "»)\n"
                    if os.path.isfile(os.path.join(
                        portable_dir, "App", APP_EXE_LAUNCHER_NAME))
                    else ""
                ),
            ),
        )
        self.log.ok("Лончер и сопроводительные файлы созданы.")
        return created_launchers

    @staticmethod
    def _write_text(path: str, text: str, encoding: str = "utf-8",
                    newline: str = "\r\n") -> None:
        with open(path, "w", encoding=encoding, newline=newline) as fh:
            fh.write(text)


_STANDARD_UPDATE_SECTION = """Обновление программы (новая версия вышла):
  • кнопка «перезапустить для обновления» внутри самой программы на портативе
    не нужна: лончер перехватывает её и сам ставит новую версию в App\\ —
    данные в PortableData не затрагиваются;
  • то же самое вручную: перетащите новый установщик на UpdatePortable.cmd
    (или запустите его без аргументов — он скачает актуальную версию сам);
  • новая версия сначала ставится во временную папку Updates\\stage и только
    после проверки подменяет файлы в App\\. Прежняя версия остаётся в
    Updates\\backup: «UpdatePortable.cmd --rollback» вернёт её, а саму папку
    можно удалить, чтобы освободить место на флешке;
  • если обновление прервали (зависло, закрыли через диспетчер задач),
    при следующем запуске лончер сам вернёт прежнюю версию или предложит
    доустановить новую. Ход работы — PortableData\\launcher-update.log;
  • обновление ставится в папку портатива НА ТОМ ДИСКЕ, ГДЕ ОНА ЛЕЖИТ
    СЕЙЧАС. Прежние пути внутри настроек программы переписываются на текущий
    корень перед установкой; если установщик всё равно поставит новую версию
    в место, где папка лежала раньше, свежие файлы оттуда копируются в App;
  • ярлыков на рабочем столе и в меню «Пуск» обновление не оставляет: они
    содержат статичный путь и после переноса папки вели бы в прежнее место.
    Ярлык, который пользователь создал сам, не удаляется.
"""


_README = """{app_name} — портативная версия
================================================================

Как пользоваться:
  1. Скопируйте ВСЮ эту папку на флешку, другой ПК или в любое место.
{exe_launcher_step}{companion_section}
На целевом компьютере ничего устанавливать не нужно: сам портатив не
создаёт запись в списке «Установленные программы». Установщик при создании
портатива может изменить исходный компьютер — Portablizer не является полной
песочницей Windows. Обычный запуск не требует прав администратора; старый
комплектный launcher/configurator может один раз показать UAC, чтобы временно
применить обязательный InstallFolder из HKLM.

Если есть Launch_Configurator.exe (или его запасной Launch_Configurator.bat),
сначала запустите его, выберите графику, язык и разрешение, сохраните настройки
и закройте окно. Затем запускайте игру
через App\\LaunchPortable.exe или Launch.bat. Оба запуска используют один
портативный каталог Documents, поэтому выбранные настройки применятся в игре.

Что внутри:
{program_location_line}
{exe_launcher_file}  PortableData\\         — все пользовательские данные (AppData, Temp, настройки)
  Launch.bat            — запуск через EXE-лончер; --bat-fallback для консоли
  LaunchHidden.vbs      — запуск без окна консоли
  StopPortable.cmd      — освободить папку, если что-то из неё осталось в фоне
{update_portable_line}
{companion_files_list}  launcher_config.json  — параметры лончера
{registry_note}{runtime_note}{netstack_note}  install.log           — подробный журнал установщика (если он поддерживается)
  portablizer.log       — журнал создания и диагностики портатива

Ключи запуска (Launch.bat):
  --target <путь>   запустить конкретный exe в изолированном окружении
  --launcher        запустить встроенный лаунчер программы
  --config          запустить конфигуратор/настройки программы
  --menu            интерактивное меню выбора исполняемого файла
  --list            список обнаруженных запускаемых файлов
  --nopause         не ждать нажатия клавиши
  --pause           всегда ждать нажатия клавиши перед закрытием
  --no-registry     вообще не трогать реестр
  --keep-registry   оставить настройки в реестре после выхода
  --reset           забыть сохранённые настройки и стартовать «с нуля»
  --bat-fallback    принудительно использовать консольный BAT-лончер
  --help            справка
  --repair-start-menu  починить меню «Пуск» Windows 11 (после сборки под
                    администратором): вернуть «Документы» в профиль и
                    сбросить испорченный кэш StartMenuExperienceHost
  -- <аргументы>    передать аргументы самой программе

{runtime_section}{netstack_section}{saves_section}
Как это работает:
  • стандартные каталоги профиля (AppData, Temp, Документы и др.) на время
    работы перенаправляются в PortableData — программа не пишет в C:\\Users;
  • сохранения при этом общие для ВСЕХ способов запуска: прямой запуск exe
    из App, LaunchPortable.exe и комплектный лаунчер читают и пишут один и
    тот же набор файлов внутри портатива;
  • Windows Known Folder Documents тоже временно направляется в PortableData,
    поэтому Configurator.exe и сама игра используют один файл настроек;
  • если программе нужны настройки реестра, лончер подставляет только
    отобранные для портатива ключи приложения и после выхода сохраняет их
    изменения в PortableData. Это не общий откат Windows: активация, Office,
    ассоциации, закрепления, Edge/WebView2 и другие системные ветки не входят
    в этот снимок;
  • путь портативной папки внутри настроек хранится маркером, поэтому смена
    буквы диска или компьютера ничего не ломает.

Полной виртуализации Windows лончер не выполняет: отдельные программы могут
обращаться к системным каталогам напрямую.

{update_section}
Если папка не удаляется («файл открыт в другой программе»):
  • обычно этого не бывает: после выхода лончер сам закрывает всё, что было
    запущено из папки, — и программу, и её фоновых помощников (апдейтер,
    отправку отчётов). Процессы объединяются в job-объект Windows, поэтому
    пережить лончер они не могут;
  • но если программу запускали напрямую из App, мимо лончера, помощник
    мог остаться. Запустите StopPortable.cmd в этой папке: он вежливо
    закроет такие процессы, а упрямых завершит принудительно, после чего
    папку можно удалять, переносить и копировать;
  • папку может держать не процесс, а открытый ФАЙЛ внутри неё: чаще всего
    это шрифт, который установщик распаковал в PortableData\\Temp и
    подключил к системе, — его держит служба Windows, а не программа.
    StopPortable.cmd отбирает такой файл принудительно: он закрывает чужой
    дескриптор, не трогая сам системный процесс, и чистит PortableData\\Temp;
  • на это нужны права администратора, поэтому скрипт запрашивает их сам.
    Согласитесь с запросом UAC — после этого папка освободится;
  • StopPortable.cmd сообщает «The folder is free» только тогда, когда это
    проверено делом: каждый файл внутри папки пробуют открыть монопольно.
    Если он сообщает об обратном — он назовёт, кто именно держит файлы.

Если окно консоли закрывается сразу:
  • штатный Launch.bat при наличии App\\LaunchPortable.exe сразу передаёт
    запуск оконному EXE-лончеру и закрывается; для диагностики запустите
    Launch.bat --bat-fallback из уже открытой консоли (cmd.exe) — вы увидите
    текст ошибки;
  • убедитесь, что папка App скопирована целиком вместе с Launch.bat;
  • подробности — в portablizer.log.

Если программа не стартует с ошибкой «Не удалось запустить приложение,
поскольку его параллельная конфигурация неправильна» (код 14001,
«side-by-side configuration is incorrect»):
  • это НЕ проблема прав администратора или реестра: программа собрана с
    рантаймом Visual C++ 2005/2008, а на этом компьютере его нет либо
    его копия в папке App повреждена (например, нет manifest-файла —
    Windows тогда игнорирует копию рядом с exe, как будто её нет вообще);
  • чинится один раз: запустите Redist\Install-Redist.cmd из этой папки —
    он поставит нужные пакеты Visual C++ молча, с одним UAC-запросом;
  • после установки Launch.bat сам проверит наличие сборок ещё раз и
    запустит программу;
  • подробности и ссылки на пакеты — в redistributables.txt рядом с
    портативной папкой.

Если программа выдаёт ошибку доступа к своим данным (например «Internal
error 0x06: System error!» у игр со Steam-эмулятором):
  • лончер заранее создаёт стандартные папки профиля (Документы, My Games,
    Public\\Documents и др.) внутри PortableData, чтобы такие программы не
    падали из-за отсутствующего каталога;
  • если ошибка осталась, программе может требоваться доступ к реальным
    системным каталогам — тогда запустите Launch.bat без изоляции профиля
    (см. portablizer.log) или обратитесь к разработчику Portablizer.

Безопасность компьютера-сборщика:
  • Portablizer не откатывает общий снимок реестра: активация Windows/Office,
    ассоциации, закреплённые значки панели задач, службы и Microsoft Edge
    WebView2 не очищаются и не восстанавливаются из устаревшего снимка;
  • если перед сборкой пользователь включил точечную очистку и в папке есть
    cleanup_host.cmd, он удалит только новую запись этого приложения из
    «Установленных программ», когда совпали имя и путь. Скрипт просит UAC
    только при ручном запуске; прочие ключи реестра не меняются;
  • ярлык, который установщик положил на рабочий стол или в меню «Пуск» и
    который ведёт внутрь этой папки, Portablizer убирает: он содержит
    статичный путь и после переноса папки на другой диск ведёт в прежнее
    место. Ярлыки, созданные раньше (и любые чужие), не удаляются; службы
    автоматически не снимаются. Runtime-пакеты на
    компьютер-сборщик устанавливаются только при отдельном opt-in; если он был
    включён, эти изменения остаются и не откатываются. При запуске портатива
    пакеты автоматически не устанавливаются. Сам установщик всё ещё может
    менять Windows — для незнакомых файлов используйте Sandbox или виртуальную машину.

Сгенерировано Portablizer.
"""
