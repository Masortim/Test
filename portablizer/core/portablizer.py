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
  4. install         — выполнять попытки по очереди, пока в App не появятся
                       файлы программы.
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

import os
import re
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .. import __version__
from . import launcher as launcher_mod
from . import procutil
from . import redist as redist_mod
from . import registry as reg_mod
from .detect import DetectionResult, InstallerType, detect_installer
from .logutil import Logger
from .silentargs import SilentPlan, build_attempts, build_silent_plan

ProgressCB = Callable[[int, str], None]
#: Ход текущей операции: ``(процент или -1, подпись)``. ``-1`` означает, что
#: величину заранее узнать нельзя (сервер не сообщил размер файла и т. п.) —
#: интерфейс показывает «бегущую» полосу вместо замершего числа.
DetailCB = Callable[[int, str], None]

IS_WINDOWS = sys.platform.startswith("win")

# Имя готового EXE-лончера внутри App/. Сам бинарник собирается из
# portable_launcher_entry.py, встраивается в Portablizer.exe как ресурс и не
# требует Python на компьютере, где запускают готовый портатив.
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
}

_NEGATIVE_EXIT_HINT = (
    "процесс установщика аварийно завершился: как правило, не хватило прав "
    "администратора или тихий режим не поддерживается"
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


def _exit_code_hint(rc: Optional[int]) -> str:
    if rc is None:
        return ""
    if rc > 0x7FFFFFFF:
        return _NEGATIVE_EXIT_HINT
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
    # Удалять следы установки (в т.ч. запись в «Установленные программы») с
    # компьютера, на котором создаётся портатив.
    cleanup_host: bool = True
    # Переносить ассоциации файлов/COM. По умолчанию выключено: чужому ПК это
    # не нужно, а портативность от этого только страдает.
    include_shell_integration: bool = False
    extra_install_args: List[str] = field(default_factory=list)
    extra_env: Dict[str, str] = field(default_factory=dict)
    install_timeout: int = 1800        # сек
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
    # Ставить распространяемые пакеты (vcredist, DXSETUP, OpenAL, PhysX…) в
    # ТИХОМ режиме. Установщики игр запускают их сами и показывают окно за
    # окном с кнопкой «OK» — так ведёт себя, например, первый «Ведьмак».
    # Portablizer ставит предусловия заранее и молча: мастер основной
    # установки их пропускает, а недостающие библиотеки после этого можно
    # забрать из системы в портатив. Ставится только то, что опознано как
    # известный распространяемый пакет.
    silent_runtime_install: bool = True


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
    #: Записи, убранные из списка «Установленные программы» этого ПК.
    removed_from_installed_list: List[str] = field(default_factory=list)
    #: Осталось ли что-то вычистить вручную (не хватило прав).
    cleanup_pending: bool = False
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
    #: Службы Windows, снятые с регистрации (их бинарник лежал в портативе).
    removed_services: List[str] = field(default_factory=list)


class Portablizer:
    def __init__(self, logger: Logger,
                 progress: Optional[ProgressCB] = None,
                 cancel_event: Optional[threading.Event] = None,
                 detail: Optional[DetailCB] = None) -> None:
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
        #: История лестницы попыток: (название сценария, код возврата).
        self._attempt_history: List[Tuple[str, Optional[int]]] = []
        #: Последний ResultCode из setup.log классического InstallShield.
        self._installshield_result: Optional[int] = None

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
        """Останавливает всё, что запущено из папки результата.

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
            stopped = procutil.release_folder(portable_dir)
        except Exception as exc:  # noqa: BLE001 - уборка не ломает сборку
            self.log.debug(f"Не удалось опросить процессы папки: {exc}")
            return []
        if stopped:
            tail = f" ({reason})" if reason else ""
            self.log.info(
                "Остановлены процессы, запущенные из папки портатива"
                f"{tail}: " + ", ".join(sorted(set(stopped))))
        return stopped

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
            self.log.debug(f"Проба переименования не прошла: {line}")

        holders = procutil.holders(portable_dir)
        names = sorted({
            (f"{h.name} (держит {procutil.image_name(h.detail)})"
             if h.kind == "module" else h.name)
            for h in holders
        })
        result.folder_holders = names
        if names:
            self.log.warn(
                "Папку портатива всё ещё держат: " + ", ".join(names) + ".")
            if any(h.protected for h in holders):
                self.log.warn(
                    "Среди них есть системные процессы (обычно это открытое "
                    "окно проводника или предпросмотр файла) — закройте окна "
                    "этой папки, и она освободится.")
        else:
            self.log.warn(
                "Папка портатива занята, но виновника определить не удалось: "
                "чаще всего это открытое окно проводника или проверка "
                "антивирусом. Через несколько секунд папка освободится сама.")
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

        for filename in (
            "Launch.bat", "LaunchHidden.vbs", "launcher.py",
            "launcher_config.json", "README_PORTABLE.txt", "portable.reg",
            "portable_machine.reg", "cleanup_host.reg", "cleanup_host.cmd",
            "install.log",
            "install-retry.log", "install-layout.log", "installer-engine.log",
            "installer-output.log", "portablizer.log", "_bundle_layout",
            "setup-installshield.log", redist_mod.REPORT_NAME, "_redist_cache",
            launcher_mod.STOP_SCRIPT_NAME,
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

    # -- шаги -----------------------------------------------------------------
    def run(self, opts: PortableOptions) -> PortableResult:
        result = PortableResult(success=False)
        try:
            self.log.info(f"Portablizer {__version__}")
            self._run_started = time.time()
            self._attempts_made = 0
            self._attempt_history = []
            self._installshield_result = None
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
            self._prepare_output(portable_dir, app_dir, data_dir)
            result.portable_dir = portable_dir
            self.log.info(f"Портативная папка: {portable_dir}")

            # 1. Определение типа установщика
            self._check_cancel()
            self.progress(8, "Определение типа установщика")
            det = detect_installer(opts.installer_path)
            result.detection = det
            self.log.ok(f"Тип установщика: {det.human}")
            for e in det.evidence:
                self.log.debug(f"  • {e}")

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

            # 2. Лестница планов тихой установки
            self.progress(15, "Построение команды тихой установки")
            attempts = build_attempts(
                det, opts.installer_path, app_dir,
                log_dir=portable_dir,
                extra_args=opts.extra_install_args,
                layout_dir=os.path.join(portable_dir, "_bundle_layout"),
                response_file=response_file,
                allow_assisted=opts.allow_assisted_install,
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

            # 3. Снимок реестра ДО
            before = {}
            if opts.capture_registry and IS_WINDOWS:
                self.progress(22, "Снимок реестра (до установки)")
                self.log.info("Делаю снимок реестра до установки...")
                before = reg_mod.snapshot()
                self.log.debug(f"  зафиксировано веток: {len(before)}")
            elif opts.capture_registry and not IS_WINDOWS:
                self.log.warn("Захват реестра доступен только на Windows — пропускаю.")

            # Запоминаем содержимое типовых каталогов установки. Некоторые
            # установщики игнорируют /DIR и пишут в LocalAppData/Program Files;
            # после завершения попробуем безопасно перенести созданный каталог.
            install_locations_before = self._snapshot_install_locations(data_dir)
            # Ярлыки в меню «Пуск» и на рабочем столе создаются через
            # shell-папки и не подчиняются переменным окружения, поэтому их
            # приходится отслеживать отдельно.
            shortcuts_before = self._snapshot_shortcuts()

            # 3b. Предусловия дистрибутива (vcredist, DirectX, OpenAL,
            # PhysX…). Их надо поставить ДО основного установщика: иначе он
            # сделает это сам — с окном и кнопкой «OK» на каждый пакет.
            self._check_cancel()
            self.progress(26, "Распространяемые компоненты (тихая установка)")
            self._install_prerequisites(opts, result)

            # 4. Тихая установка: идём по лестнице попыток, пока в App не
            # появятся файлы программы. Снимок реестра «после» делается ниже —
            # он накрывает все попытки сразу.
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
                )

            install_rc, used_plan = self._run_attempts(
                attempts, opts, app_dir, data_dir, portable_dir, name,
                recover=recover)
            result.attempts_made = self._attempts_made
            if used_plan is not None:
                result.plan = used_plan
                result.successful_attempt = used_plan.label

            # Установщик мог закончить галочкой «Запустить программу сейчас»
            # или оставить свой фоновый помощник. Закрываем их ДО снимка
            # реестра: так программа успевает записать свои настройки (они
            # уедут в портатив), а файлы App перестают быть занятыми.
            self._release_portable_dir(portable_dir, reason="после установки")

            # 4b. Установщик не отдал файлы ни одной командой. Последний
            # honest-шанс: распаковать приклеенный к exe ZIP — так устроены
            # многие современные bootstrapper'ы, и это не требует ни прав
            # администратора, ни изменения системы.
            if not self._find_main_exe(app_dir, name) and det.has_zip_payload:
                self._check_cancel()
                self.progress(62, "Распаковка вложенного архива установщика")
                self._extract_zip_payload(opts.installer_path, app_dir, name)

            # 5. Снимок реестра ПОСЛЕ + diff
            after: reg_mod.Snapshot = {}
            capture = None
            if opts.capture_registry and IS_WINDOWS:
                self._check_cancel()
                self.progress(65, "Снимок реестра (после установки)")
                self.log.info("Делаю снимок реестра после установки...")
                after = reg_mod.snapshot()
                capture = self._capture_registry(
                    portable_dir, before, after, opts,
                )
                result.reg_file = capture.reg_file
                result.registry_keys = capture.keys
                result.removed_from_installed_list = capture.uninstall_entries

            # Если установщик не послушался целевого пути, ищем его результат
            # в перенаправленном профиле и в новых каталогах Program Files.
            if not self._find_main_exe(app_dir, name):
                self.progress(72, "Поиск файлов, созданных установщиком")
                registry_locations = reg_mod.changed_install_locations(before, after)
                recovered = self._recover_installed_app(
                    app_dir=app_dir,
                    data_dir=data_dir,
                    app_name=name,
                    installer_path=opts.installer_path,
                    before=install_locations_before,
                    registry_locations=registry_locations,
                )
                if recovered:
                    self.log.ok("Файлы программы перенесены в папку App.")

            # 6. Поиск главного exe и обнаружение всех вспомогательных программ
            self._check_cancel()
            self.progress(75, "Поиск главного исполняемого файла и лаунчеров")
            main_exe, targets = self._discover_app_executables(app_dir, name)
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
                app_dir, portable_dir, opts, name, result,
                main_exe=main_exe, targets=targets)

            # 7b. Зависимости и переменные среды
            self.progress(87, "Учёт зависимостей и переменных среды")
            path_prepend = self._collect_dep_dirs(app_dir, portable_dir)

            # 8. Генерация лончера и вспомогательных скриптов
            self._check_cancel()
            self.progress(92, "Генерация портативного лончера и меню")
            companion_files = self._write_launcher(
                portable_dir, name, result.main_exe_rel,
                opts, path_prepend, capture, targets,
                runtime_report=runtime_report)
            result.companion_launchers = companion_files
            exe_launcher = os.path.join(
                portable_dir, "App", APP_EXE_LAUNCHER_NAME)
            if os.path.isfile(exe_launcher):
                result.portable_launcher_exe_rel = os.path.relpath(
                    exe_launcher, portable_dir)

            # 9. Уборка следов установки с ЭТОГО компьютера: программа не
            # должна остаться в списке «Установленные программы».
            self.progress(97, "Удаление следов установки с этого ПК")
            self._remove_portable_services(portable_dir, opts, result)
            if capture is not None:
                self._cleanup_host(capture, opts, result)
            if opts.cleanup_host:
                self._cleanup_shortcuts(shortcuts_before, result)

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
            self._save_run_log(result.portable_dir)
            return result

        except Exception as exc:  # noqa: BLE001
            self.log.error(str(exc))
            result.messages.append(str(exc))
            self._save_run_log(result.portable_dir)
            return result

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

        hints.append(
            "Некоторые установщики требуют входа в аккаунт или активной "
            "лицензии и в тихом режиме не работают в принципе — такую "
            "программу портативной сделать нельзя."
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
            hint = _exit_code_hint(rc)
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
                    verdict = f"код {outcome}, но файлов в App не появилось"
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
        return (
            "Установщик завершился, но в папке App не найден ни один "
            f"исполняемый файл{rc_hint}.{attempts_text} Портатив не создан."
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
        diff = reg_mod.compute_diff(before, after)
        capture = RegistryCapture(diff=diff)

        wanted = [reg_mod.CATEGORY_APP]
        if opts.include_shell_integration:
            wanted.append(reg_mod.CATEGORY_INTEGRATION)
        portable_keys = diff.keys_of(*wanted)
        trace_keys = diff.keys_of(reg_mod.CATEGORY_TRACE)
        skipped_integration = (
            [] if opts.include_shell_integration
            else diff.keys_of(reg_mod.CATEGORY_INTEGRATION)
        )

        # Путь портативной папки заменяем маркером: иначе настройки указывали
        # бы на каталог того ПК, где собирали портатив.
        tokens = [(portable_dir, launcher_mod.ROOT_TOKEN)]
        alt = portable_dir.replace("\\", "/")
        if alt != portable_dir:
            tokens.append((alt, launcher_mod.ROOT_TOKEN))

        user_keys = [k for k in portable_keys if k.startswith("HKCU")]
        machine_keys = [k for k in portable_keys if k.startswith("HKLM")]

        # Если установщик сначала писал в Program Files, а затем его файлы были
        # перенесены в App, InstallFolder не должен остаться направленным в
        # старый/удалённый каталог. Именно из-за такого значения The Witcher 2
        # запускался напрямую, но Launcher.exe и Configurator.exe считали
        # установку недействительной и сразу закрывались.
        portable_after = reg_mod.retarget_install_paths(
            after, portable_keys, os.path.join(portable_dir, "App"))

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

        capture.has_root_token = (
            launcher_mod.ROOT_TOKEN in user_text
            or launcher_mod.ROOT_TOKEN in machine_text
        )

        all_portable_keys = sorted(set(portable_keys + virtual_keys))
        capture.keys = launcher_mod.consolidate_root_keys(all_portable_keys)
        capture.created_keys = launcher_mod.consolidate_root_keys(
            [k for k in diff.new_keys if k in set(portable_keys)] + virtual_keys
        )

        # Всё, что установщик наследил на этом ПК: и следы, и перенесённые в
        # портатив настройки — на исходной машине они больше не нужны.
        capture.cleanup_keys = sorted(
            set(trace_keys) | set(portable_keys) | set(skipped_integration)
        )
        cleanup_text = reg_mod.render_host_cleanup(diff, capture.cleanup_keys)
        if reg_mod.has_entries(cleanup_text):
            cleanup_path = os.path.join(portable_dir, "cleanup_host.reg")
            reg_mod.write_reg_file(cleanup_path, cleanup_text)
            capture.cleanup_file = cleanup_path
            # Самоповышающийся .cmd: двойной клик по .reg импортирует его без
            # прав администратора и роняет ветки HKLM с ошибкой «не все данные
            # были записаны». Скрипт сам запрашивает права и делает это чисто.
            cleanup_cmd_path = os.path.join(portable_dir, "cleanup_host.cmd")
            self._write_text(
                cleanup_cmd_path,
                reg_mod.render_host_cleanup_cmd("cleanup_host.reg"),
                encoding="ascii", newline="",
            )
            capture.cleanup_cmd_file = cleanup_cmd_path

        capture.uninstall_entries = [
            name for _key, name
            in reg_mod.installed_program_entries(diff, after)
        ]

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
        return capture

    def _cleanup_host(self, capture: RegistryCapture, opts: PortableOptions,
                      result: PortableResult) -> None:
        """Возвращает реестр этого ПК в состояние «до установки»."""
        entries = capture.uninstall_entries
        if not opts.cleanup_host:
            if entries:
                result.cleanup_pending = True
                self.log.warn(
                    "Очистка отключена: программа осталась в списке "
                    f"«Установленные программы» ({', '.join(entries)}). "
                    "Запустите cleanup_host.cmd, чтобы убрать её (он сам "
                    "запросит права администратора)."
                )
            return
        if not capture.cleanup_file or not IS_WINDOWS:
            return

        rc = self._reg_import(capture.cleanup_file)
        # Часть следов (запись «Установленные программы», службы) лежит в HKLM
        # и без прав администратора не удаляется. Если Portablizer запущен без
        # повышения — сразу пробуем импорт через UAC, а не сдаёмся с ошибкой.
        if rc != 0 and not is_elevated():
            elevated = self._reg_import_elevated(capture.cleanup_file)
            if elevated is not None:
                rc = elevated
        if rc == 0:
            if entries:
                self.log.ok(
                    "Из списка «Установленные программы» удалено: "
                    + ", ".join(entries)
                )
            self.log.ok(
                "Следы установки удалены — этот компьютер остался чистым."
            )
            return

        result.cleanup_pending = True
        target = capture.cleanup_cmd_file or capture.cleanup_file
        self.log.warn(
            "Не удалось полностью удалить следы установки (обычно нужны права "
            "администратора). Запустите cleanup_host.cmd (он сам запросит права "
            f"администратора): {target}"
        )

    def _remove_portable_services(self, portable_dir: str,
                                  opts: PortableOptions,
                                  result: PortableResult) -> None:
        """Снимает службы Windows, чей бинарник оказался внутри портатива.

        Установщики игр и «тяжёлых» программ регистрируют службы: защита от
        копирования, обновлятор, вспомогательный драйвер. После сборки такая
        служба указывает уже в папку портатива и делает сразу две гадости:

        * держит файлы открытыми, поэтому папка не удаляется и не копируется
          (убивать её процесс бесполезно — диспетчер служб поднимет его
          снова);
        * остаётся следом установки на этом компьютере, хотя программа
          «не устанавливалась».

        Поэтому служба останавливается и снимается с регистрации. Для этого
        нужны права администратора — Portablizer запрашивает их при старте.
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
        if not opts.cleanup_host:
            result.cleanup_pending = True
            self.log.warn(
                "Очистка отключена: на этом ПК осталась зарегистрирована "
                "служба из папки портатива (" + ", ".join(services) + "). "
                "Пока она работает, папку нельзя ни удалить, ни перенести.")
            return
        if not is_elevated():
            result.cleanup_pending = True
            self.log.warn(
                "Служба из папки портатива (" + ", ".join(services) + ") "
                "требует прав администратора для снятия. Запустите "
                "Portablizer от имени администратора и повторите сборку.")
            return
        for name in services:
            procutil.stop_service(name, remove=True)
            self.log.ok(f"Служба {name} остановлена и снята с регистрации.")
        result.removed_services = list(services)

    # -- ярлыки ---------------------------------------------------------------
    @staticmethod
    def _shortcut_roots() -> List[str]:
        """Каталоги, куда установщики кладут ярлыки (меню «Пуск», рабочий стол)."""
        if not IS_WINDOWS:
            return []
        roots: List[str] = []
        for base, tail in (
            ("APPDATA", os.path.join("Microsoft", "Windows", "Start Menu", "Programs")),
            ("PROGRAMDATA", os.path.join("Microsoft", "Windows", "Start Menu", "Programs")),
            ("USERPROFILE", "Desktop"),
            ("PUBLIC", "Desktop"),
        ):
            value = os.environ.get(base, "")
            if value:
                roots.append(os.path.join(value, tail))
        return roots

    def _snapshot_shortcuts(self) -> Set[str]:
        """Запоминает существующие ярлыки, чтобы найти созданные установщиком."""
        found: Set[str] = set()
        for root in self._shortcut_roots():
            for current, _dirs, files in os.walk(root):
                for filename in files:
                    if filename.lower().endswith((".lnk", ".url")):
                        found.add(os.path.normcase(
                            os.path.join(current, filename)))
        return found

    def _cleanup_shortcuts(self, before: Set[str],
                           result: PortableResult) -> None:
        """Удаляет ярлыки, созданные установщиком на этом компьютере."""
        if not IS_WINDOWS:
            return
        removed: List[str] = []
        for root in self._shortcut_roots():
            for current, _dirs, files in os.walk(root):
                for filename in files:
                    if not filename.lower().endswith((".lnk", ".url")):
                        continue
                    path = os.path.join(current, filename)
                    if os.path.normcase(path) in before:
                        continue
                    try:
                        os.remove(path)
                        removed.append(filename)
                    except OSError:
                        result.cleanup_pending = True
        # Пустые папки меню «Пуск», оставшиеся после удаления ярлыков.
        for root in self._shortcut_roots():
            for current, dirs, _files in os.walk(root, topdown=False):
                for name in dirs:
                    path = os.path.join(current, name)
                    try:
                        if not os.listdir(path):
                            os.rmdir(path)
                    except OSError:
                        pass
        if removed:
            self.log.ok(
                f"Удалены созданные установщиком ярлыки ({len(removed)}): "
                + ", ".join(sorted(removed)[:5])
                + (" …" if len(removed) > 5 else "")
            )

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

    @staticmethod
    def _reg_import_elevated(path: str) -> Optional[int]:
        """Импортирует .reg с правами администратора через UAC (ShellExecute).

        Возвращает код возврата ``reg import`` или ``None``, если запустить
        повышенный процесс не удалось (пользователь отклонил UAC, нет Windows).
        Это позволяет автоматически убрать следы в HKLM без ручного запуска.
        """
        if not IS_WINDOWS:
            return None
        try:
            import ctypes  # локальный импорт: модуль грузится и на Linux
            from ctypes import wintypes

            shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
            SEE_MASK_NOCLOSEPROCESS = 0x00000040
            SEE_MASK_NO_CONSOLE = 0x00008000

            class SHELLEXECUTEINFOW(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.DWORD),
                    ("fMask", ctypes.c_ulong),
                    ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int),
                    ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD),
                    ("hIcon", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE),
                ]

            info = SHELLEXECUTEINFOW()
            info.cbSize = ctypes.sizeof(info)
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE
            info.lpVerb = "runas"  # запрос повышения прав через UAC
            info.lpFile = "reg.exe"
            info.lpParameters = subprocess.list2cmdline(["import", path])
            info.nShow = 0  # SW_HIDE

            if not shell32.ShellExecuteExW(ctypes.byref(info)):
                return None
            if not info.hProcess:
                return None

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
            code = wintypes.DWORD()
            kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
            kernel32.CloseHandle(info.hProcess)
            return int(code.value)
        except Exception:  # noqa: BLE001 - отказ UAC/любой сбой -> ручной путь
            return None

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
        timeout = (max(opts.install_timeout, opts.assisted_timeout)
                   if plan.interactive else opts.install_timeout)
        if plan.interactive:
            self.log.info("Запуск установщика с окном мастера (изолированно)...")
            for line in plan.instructions:
                self.log.info(f"  → {line}")
        else:
            self.log.info("Запуск установщика (тихо, изолированно)...")
        rc: Optional[int] = None
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

            start = time.time()
            while proc.poll() is None:
                if self.cancel.is_set():
                    proc.terminate()
                    raise RuntimeError("Установка отменена пользователем.")
                if time.time() - start > timeout:
                    proc.terminate()
                    raise RuntimeError("Превышено время ожидания установки.")
                # плавный прогресс во время установки: progress_from -> progress_to
                elapsed = time.time() - start
                frac = min(1.0, elapsed / 60.0)
                span = max(1, progress_to - progress_from)
                title = ("Установка в окне мастера..." if plan.interactive
                         else "Тихая установка...")
                self._emit_progress(progress_from + int(span * frac), title)
                # Установщик о себе процентов не сообщает, поэтому подробная
                # строка показывает прошедшее время и предел ожидания —
                # видно, что процесс жив, и сколько он ещё может идти.
                self._detail(
                    min(99, int(elapsed * 100 / max(1, timeout))),
                    f"{title} идёт "
                    f"{redist_mod.format_duration(elapsed)} "
                    f"(предел {redist_mod.format_duration(timeout)})")
                time.sleep(0.5)
            rc = proc.returncode
        finally:
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

        if rc not in (0, 3010):  # 3010 = успех, требуется перезагрузка
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

    # -- лестница попыток установки ------------------------------------------
    def _run_attempts(self, attempts: Sequence[SilentPlan],
                      opts: PortableOptions, app_dir: str, data_dir: str,
                      portable_dir: str, name: str,
                      recover: Optional[Callable[[], bool]] = None,
                      ) -> Tuple[Optional[int], Optional[SilentPlan]]:
        """Выполняет варианты установки, пока в ``App`` не появятся файлы.

        Возвращает ``(код последней попытки, сработавший план)``. Успехом
        считается только фактический результат на диске: код возврата ``0``
        при пустой папке успехом не является, и наоборот — некоторые
        установщики отдают ненулевой код, успев разложить файлы.
        """
        last_rc: Optional[int] = None
        total = len(attempts)
        span = max(1, 58 - 30)
        console_log = os.path.join(portable_dir, "installer-output.log")

        for index, plan in enumerate(attempts):
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

            rc = self._run_install(plan, opts, app_dir, data_dir,
                                   progress_from=start, progress_to=stop,
                                   console_log=console_log)
            last_rc = rc
            # Классический InstallShield пишет причину отказа в свой
            # setup.log — без неё «код 0 при пустой папке» необъясним.
            self._report_installshield_log(plan)
            self._attempts_made += 1
            self._attempt_history.append((plan.label, rc))

            if plan.interactive and plan.response_file \
                    and os.path.isfile(plan.response_file):
                self.log.ok(
                    f"Ваши ответы сохранены в файл {plan.response_file}. "
                    "Он лежит в папке портатива: следующая сборка этой же "
                    "программы пройдёт полностью автоматически, без окон."
                )

            # Распаковка бандла сама по себе файлов в App не даёт: из неё ещё
            # нужно вытащить MSI-пакеты.
            if plan.extracts_only and plan.output_dir \
                    and os.path.normcase(plan.output_dir) != os.path.normcase(app_dir):
                if self._install_layout_packages(plan.output_dir, opts, app_dir,
                                                 data_dir, name,
                                                 console_log=console_log):
                    self.log.ok(f"Сработал сценарий: {plan.label}")
                    return rc, plan
                continue

            if self._find_main_exe(app_dir, name):
                if index:
                    self.log.ok(f"Сработал запасной сценарий: {plan.label}")
                else:
                    self.log.ok("Тихая установка прошла успешно.")
                return rc, plan

            # Движок, не принимающий целевую папку (InstallScript 5/6),
            # ставит программу в свой каталог по умолчанию. Это успех, а не
            # неудача: забираем файлы сразу, иначе следующий сценарий начнёт
            # ставить программу поверх уже установленной.
            if plan.ignores_target_dir and recover is not None \
                    and rc in (0, 3010):
                if recover():
                    self.log.ok(
                        "Программа установлена в каталог по умолчанию и "
                        f"перенесена в App. Сработал сценарий: {plan.label}"
                    )
                    return rc, plan

            if index + 1 < total:
                self.log.warn(
                    f"Сценарий «{plan.label}» не дал файлов в App — перехожу "
                    "к следующему."
                )

        self._collect_engine_log(opts, data_dir, portable_dir)
        return last_rc, None

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
        temp = os.path.join(data_dir, "Temp")
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

    def _build_isolated_env(self, opts: PortableOptions,
                            data_dir: str) -> Dict[str, str]:
        env = dict(os.environ)
        if opts.redirect_userdirs:
            appdata = os.path.join(data_dir, "AppData", "Roaming")
            local = os.path.join(data_dir, "AppData", "Local")
            temp = os.path.join(data_dir, "Temp")
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
        for k, v in opts.extra_env.items():
            env[k] = os.path.expandvars(v)
        return env

    # -- поиск результата установки вне App ---------------------------------
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
    def _find_executables(root: str, limit: int = 2000) -> List[str]:
        """Ищет exe без перехода по симлинкам/переходным каталогам."""
        found: List[str] = []
        if not os.path.isdir(root):
            return found
        for current, dirs, files in os.walk(root, followlinks=False):
            # Не уходим в возможные junction/symlink за пределы дерева.
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(os.path.join(current, d))
            ]
            for filename in files:
                if filename.lower().endswith(".exe"):
                    found.append(os.path.join(current, filename))
                    if len(found) >= limit:
                        return found
        return found

    @staticmethod
    def _name_keys(app_name: str, installer_path: str) -> Set[str]:
        """Формирует нормализованные имена для оценки найденных файлов."""
        values = [app_name, os.path.splitext(os.path.basename(installer_path))[0]]
        keys: Set[str] = set()
        suffixes = re.compile(
            r"(?:[\s._-]*(?:setup|installer|install|portable|win(?:32|64)|"
            r"x(?:86|64)|amd64|online|offline|latest|[0-9]+(?:\.[0-9]+)*))+$",
            re.IGNORECASE,
        )
        for value in values:
            value = suffixes.sub("", value).strip()
            normalized = "".join(ch for ch in value.casefold() if ch.isalnum())
            if len(normalized) >= 2:
                keys.add(normalized)
        return keys

    @staticmethod
    def _name_score(path: str, keys: Set[str]) -> int:
        stem = os.path.splitext(os.path.basename(path))[0]
        normalized = "".join(ch for ch in stem.casefold() if ch.isalnum())
        score = 0
        for key in keys:
            if normalized == key:
                score = max(score, 220)
            elif key in normalized or normalized in key:
                score = max(score, 125)
        bad = (
            "unins", "uninstall", "setup", "install", "update", "updater",
            "helper", "crash", "report", "redist", "vcredist", "squirrel",
        )
        if any(word in normalized for word in bad):
            score -= 180
        return score

    def _recover_installed_app(
        self,
        app_dir: str,
        data_dir: str,
        app_name: str,
        installer_path: str,
        before: Dict[str, Set[str]],
        registry_locations: Iterable[str] = (),
    ) -> bool:
        """Копирует результат установщика, если тот проигнорировал папку App.

        Рассматриваются только новые каталоги или каталоги, имя которых похоже
        на имя приложения. Это не даёт случайно скопировать произвольную уже
        установленную программу из Program Files.
        """
        keys = self._name_keys(app_name, installer_path)
        search_roots = self._install_search_roots(data_dir)
        protected_roots = {
            os.path.normcase(os.path.abspath(path))
            for path, _priority, _owned in search_roots
        }
        # normalized source -> (score, representative exe, explanation, source)
        candidates: Dict[str, Tuple[int, str, str, str]] = {}

        def add_source(source: str, score: int, reason: str) -> None:
            source = os.path.abspath(source)
            # Никогда не копируем Program Files/AppData целиком, даже если
            # некорректная запись реестра указывает прямо на такой корень.
            if os.path.normcase(source) in protected_roots:
                return
            if not os.path.exists(source):
                return
            if os.path.isfile(source):
                exes = [source] if source.lower().endswith(".exe") else []
            else:
                exes = self._find_executables(source)
            for exe in exes:
                exe_score = score + self._name_score(exe, keys)
                try:
                    exe_score += min(35, int(os.path.getsize(exe) / (1024 * 1024)))
                except OSError:
                    pass
                normalized = os.path.normcase(source)
                previous = candidates.get(normalized)
                if previous is None or exe_score > previous[0]:
                    candidates[normalized] = (exe_score, exe, reason, source)

        # InstallLocation/DisplayIcon из новых записей реестра — самый точный
        # сигнал. Для DisplayIcon берём каталог исполняемого файла.
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
                if os.path.isdir(source):
                    for item in os.scandir(source):
                        destination = os.path.join(app_dir, item.name)
                        if item.is_dir(follow_symlinks=False):
                            shutil.copytree(item.path, destination, dirs_exist_ok=True)
                        elif item.is_file(follow_symlinks=False):
                            shutil.copy2(item.path, destination)
                else:
                    shutil.copy2(source, os.path.join(app_dir, os.path.basename(source)))
            except OSError as exc:
                self.log.warn(f"Не удалось скопировать найденные файлы: {exc}")
                # Не оставляем частичный каталог перед следующей попыткой.
                shutil.rmtree(app_dir, ignore_errors=True)
                os.makedirs(app_dir, exist_ok=True)
                continue
            if self._find_main_exe(app_dir, app_name):
                return True
            shutil.rmtree(app_dir, ignore_errors=True)
            os.makedirs(app_dir, exist_ok=True)
        return False

    # -- поиск главного exe ---------------------------------------------------
    # -- поиск и классификация исполняемых файлов -----------------------------
    def _discover_app_executables(self, app_dir: str, app_name: str
                                  ) -> Tuple[Optional[str], List[launcher_mod.TargetInfo]]:
        """Сканирует App/ и находит все запускаемые программы.

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

        name_l = app_name.lower()
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
            elif any(k in base for k in ("manager", "content", "mod", "editor", "edit", "tool", "bench", "maker", "builder", "patch", "server", "dedicated")):
                role = "tool"
                desc = f"Утилита ({stem})"

            # Оценка вероятности быть главным исполняемым файлом
            s = 0
            if name_l and (name_l in base or base in name_l):
                s += 100
            if role == "main":
                s += 30
            # exe в корне App/ или в App/bin обычно важнее
            s -= depth * 5
            s += min(30, int(size / (1024 * 1024)))
            non_ignored.append((s, p, stem, role, desc))

        if not non_ignored:
            return None, []

        non_ignored.sort(key=lambda x: x[0], reverse=True)
        best_score, best_path, _stem, _role, _ = non_ignored[0]
        main_exe = best_path if best_score >= 0 else non_ignored[0][1]

        def _safe_slug(s: str) -> str:
            cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_")
            return cleaned if cleaned else "App"

        targets: List[launcher_mod.TargetInfo] = []
        used_bat_names: Set[str] = set()

        for _score, path, stem, role, desc in non_ignored:
            rel_path = os.path.join("App", os.path.relpath(path, app_dir)).replace("\\", "/")
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
        """Ставит предусловия дистрибутива молча — ДО основного установщика.

        Так выглядит проблема без этого шага: установщик первого «Ведьмака»
        доходит до шага «установка компонентов», по очереди запускает
        ``vcredist``, ``DXSETUP`` и компанию — и каждый показывает своё окно,
        которое надо закрыть кнопкой «OK». Портативная сборка обязана идти
        без человека, поэтому пакеты ставятся заранее и в тихом режиме:
        мастер видит их уже установленными и молча проходит этот шаг.

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
                "Недостающие пакеты положены в папку "
                f"{redist_mod.REDIST_DIR_NAME} вместе со скриптом "
                f"{redist_mod.SILENT_SCRIPT_NAME}: на целевом ПК лончер "
                "поставит их молча, без окон с «OK».")

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
        return rel

    def _write_launcher(self, portable_dir: str, name: str, main_exe_rel: str,
                        opts: PortableOptions, path_prepend: List[str],
                        capture: Optional[RegistryCapture] = None,
                        targets: Optional[List[launcher_mod.TargetInfo]] = None,
                        runtime_report: "Optional[redist_mod.ProvisionReport]" = None
                        ) -> List[str]:
        has_registry = bool(
            capture and (capture.reg_file or capture.machine_reg_file
                         or capture.keys)
        )
        all_targets = list(targets or [])
        launcher_target = next((t.rel_path for t in all_targets if t.role == "launcher"), "")
        config_target = next((t.rel_path for t in all_targets if t.role == "config"), "")

        cfg = launcher_mod.LauncherConfig(
            app_name=name,
            target_exe_rel=main_exe_rel.replace("\\", "/"),
            data_dir_name="PortableData",
            apply_registry=has_registry,
            registry_keys=list(capture.keys) if capture else [],
            registry_created_keys=list(capture.created_keys) if capture else [],
            registry_has_root_token=bool(capture and capture.has_root_token),
            extra_env=opts.extra_env,
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

        created_launchers: List[str] = ["Launch.bat", "LaunchHidden.vbs",
                                        launcher_mod.STOP_SCRIPT_NAME]

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
                        "  Проще всего запустить "
                        f"{redist_mod.REDIST_DIR_NAME}\\"
                        f"{redist_mod.SILENT_SCRIPT_NAME}: он поставит всё "
                        "молча,\n"
                        "  за один запрос прав администратора. Лончер "
                        "делает это сам, когда\n"
                        "  видит, что библиотеки на этом компьютере нет.\n"
                    )
        self._write_text(
            os.path.join(portable_dir, "README_PORTABLE.txt"),
            _README.format(
                app_name=name,
                main_exe_rel=main_exe_rel,
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
                    "портативным окружением\n"
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


_README = """{app_name} — портативная версия
================================================================

Как пользоваться:
  1. Скопируйте ВСЮ эту папку на флешку, другой ПК или в любое место.
{exe_launcher_step}{companion_section}
Устанавливать ничего не нужно: программа не появляется в списке
«Установленные программы». Обычный запуск не требует прав администратора;
старый комплектный launcher/configurator может один раз показать UAC, чтобы
временно применить обязательный InstallFolder из HKLM.

Если есть Launch_Configurator.exe (или его запасной Launch_Configurator.bat),
сначала запустите его, выберите графику, язык и разрешение, сохраните настройки
и закройте окно. Затем запускайте игру
через App\\LaunchPortable.exe или Launch.bat. Оба запуска используют один
портативный каталог Documents, поэтому выбранные настройки применятся в игре.

Что внутри:
  App\\                  — установленная программа ({main_exe_rel})
{exe_launcher_file}  PortableData\\         — все пользовательские данные (AppData, Temp, настройки)
  Launch.bat            — запуск через EXE-лончер; --bat-fallback для консоли
  LaunchHidden.vbs      — запуск без окна консоли
  StopPortable.cmd      — освободить папку, если что-то из неё осталось в фоне
{companion_files_list}  launcher_config.json  — параметры лончера
{registry_note}{runtime_note}  install.log           — подробный журнал установщика (если он поддерживается)
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
  -- <аргументы>    передать аргументы самой программе

{runtime_section}
Как это работает:
  • стандартные каталоги профиля (AppData, Temp, Документы и др.) на время
    работы перенаправляются в PortableData — программа не пишет в C:\\Users;
  • Windows Known Folder Documents тоже временно направляется в PortableData,
    поэтому Configurator.exe и сама игра используют один файл настроек;
  • если программе нужны записи реестра, лончер перед стартом сохраняет
    прежнее состояние чужого ПК, подставляет настройки из портатива (включая
    UAC VirtualStore для бесправного доступа к machine-ключам), а после выхода
    выгружает изменения обратно в папку и возвращает реестр как было;
  • путь портативной папки внутри настроек хранится маркером, поэтому смена
    буквы диска или компьютера ничего не ломает.

Полной виртуализации Windows лончер не выполняет: отдельные программы могут
обращаться к системным каталогам напрямую.

Если папка не удаляется («файл открыт в другой программе»):
  • обычно этого не бывает: после выхода лончер сам закрывает всё, что было
    запущено из папки, — и программу, и её фоновых помощников (апдейтер,
    отправку отчётов). Процессы объединяются в job-объект Windows, поэтому
    пережить лончер они не могут;
  • но если программу запускали напрямую из App, мимо лончера, помощник
    мог остаться. Запустите StopPortable.cmd в этой папке: он вежливо
    закроет такие процессы, а упрямых завершит принудительно, после чего
    папку можно удалять, переносить и копировать;
  • если StopPortable.cmd сообщает, что процесс не остановлен, запустите его
    «от имени администратора» — процесс был запущен с повышенными правами.

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

Очистка следов на ЭТОМ компьютере (где собирался портатив):
  • cleanup_host.cmd убирает записи установки из реестра этого ПК (запись в
    списке «Установленные программы» и т.п.). Он сам запрашивает права
    администратора — двойного клика по cleanup_host.reg недостаточно, потому
    что ветки HKLM без прав администратора не удаляются и Windows пишет
    «Не все данные были успешно записаны в реестр»;
  • на другом ПК этот файл не нужен — портатив ничего туда не устанавливает.

Сгенерировано Portablizer.
"""
