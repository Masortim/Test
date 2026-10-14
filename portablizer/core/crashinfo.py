"""Аварийное завершение установщика: расшифровка кода и факты о падении.

Зачем отдельный модуль
----------------------
Установщик может завершиться не «кодом ошибки», а **кодом аварийного
завершения процесса** — значением NTSTATUS вида ``0xC0000…``. Такой код не
имеет отношения ни к командной строке, ни к правам администратора: процесс
успел запуститься и упал. Прежний Portablizer на любой отрицательный код
показывал одну и ту же фразу «как правило, не хватило прав администратора»,
и это уводило в сторону: пользователь шёл повышать права, а причина была в
другом — кончилось место в TEMP, повреждён дистрибутив, мешает антивирус.

Здесь три независимые вещи:

1. **Таблица NTSTATUS-кодов**, которые реально возвращают установщики, с
   расшифровкой и признаком «похоже на разовое падение» (тогда имеет смысл
   повторить ровно ту же команду ещё раз). Таблица — не единственный путь:
   **любой** код из полосы фатальных NTSTATUS (``0xC0000000–0xC000FFFF``)
   считается аварийным завершением, даже если его в таблице нет. Иначе
   «редкий» код снова получил бы общий совет про права администратора —
   то есть ровно тот неверный диагноз, из-за которого этот модуль появился.
2. **Журнал событий Windows** (Application, Event ID 1000). Windows сама
   записывает туда модуль, в котором упал процесс, и точный код исключения.
   Это факт, а не догадка: по модулю видно, падает ли сам установщик или
   сторонний код (антивирус, оверлей, инжектор), который в него влез.
3. **Подсказки под конкретную причину** — с числами (сколько нужно места и
   сколько есть, какие части дистрибутива лежат рядом), а не общий совет
   «смотрите журнал».

Модуль работает и вне Windows: без журнала событий остаются таблица и
подсказки, а чтение журнала просто возвращает пустой список.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform.startswith("win")

#: Имя файла с отчётом о падении внутри портативной папки.
CRASH_LOG_NAME = "installer-crash.log"

#: Полоса фатальных кодов NTSTATUS. Windows ставит такие коды, когда процесс
#: убит исключением (обращение к недоступной памяти, переполнение стека,
#: исключение в callback’е и т. п.). Всё, что сюда попало, — аварийное
#: завершение, а не «код ошибки движка»: командная строка и права
#: администратора тут не при чём.
#:
#: Границы важны: ``0xFFFFFFFF`` (классическое ``exit(-1)``) в полосу НЕ
#: входит — это код, который установщик вернул сам, и для него прежний совет
#: про права и тихий режим остаётся в силе.
NTSTATUS_FATAL_BAND = (0xC0000000, 0xC000FFFF)


@dataclass(frozen=True)
class CrashCode:
    """Расшифровка кода аварийного завершения процесса."""

    code: int
    name: str            # имя константы NTSTATUS
    summary: str         # одна фраза по-русски: что это значит
    kind: str            # семейство причин (см. ниже)
    #: Разовость: падение через секунды после старта часто объясняется
    #: помехой извне (антивирус, нехватка памяти, файл ещё занят) — такую
    #: попытку имеет смысл повторить ровно один раз.
    retryable: bool = False

    @property
    def hint(self) -> str:
        """Строка для журнала: имя константы и расшифровка."""
        return f"{self.name} — {self.summary}" if self.name else self.summary


def describe(item: CrashCode) -> str:
    """Код для показа человеку: ``0xC000041D STATUS_… — расшифровка``.

    У кодов вне таблицы имени нет — тогда показывается только номер и
    расшифровка: выдумывать имя константы хуже, чем признать, что её нет.
    """
    head = f"0x{item.code:08X}"
    if item.name:
        head += f" {item.name}"
    return f"{head} — {item.summary}"


# Семейства причин: ``callback`` — исключение в обратном вызове (оконная
# процедура, обработчик прогресса), ``access`` — обращение к недоступной
# памяти, ``io`` — ошибка чтения носителя, ``memory`` — не хватило памяти или
# места в файле подкачки, ``dll`` — не нашлась или не смогла загрузиться
# библиотека, ``stack`` — переполнение стека/сработала защита компилятора,
# ``internal`` — внутренняя ошибка (сторожевое срабатывание), ``other`` —
# остальное.

#: Коды, которые установщики возвращают чаще всего. Порядок — по вероятности
#: встречи в сборках Portablizer.
CRASH_CODES: Tuple[CrashCode, ...] = (
    CrashCode(0xC000041D, "STATUS_FATAL_USER_CALLBACK_EXCEPTION",
              "необработанное исключение внутри callback’а — обычно это "
              "оконная процедура установщика (отрисовка прогресса, таймер, "
              "перечислитель файлов)", "callback", retryable=True),
    CrashCode(0xC0000005, "STATUS_ACCESS_VIOLATION",
              "обращение к недоступной памяти", "access", retryable=True),
    CrashCode(0xC0000006, "STATUS_IN_PAGE_ERROR",
              "ошибка чтения файла или страницы памяти: носитель, "
              "дистрибутив или жёсткий диск «отвалились» на середине",
              "io"),
    CrashCode(0xC0000017, "STATUS_NO_MEMORY",
              "не хватило памяти или места в файле подкачки", "memory"),
    CrashCode(0xC0000018, "STATUS_CONFLICTING_ADDRESSES",
              "конфликт адресов при загрузке библиотек: в процесс "
              "установщика уже влез посторонний модуль", "other"),
    CrashCode(0xC000001D, "STATUS_ILLEGAL_INSTRUCTION",
              "процессор получил недопустимую инструкцию", "other"),
    CrashCode(0xC0000008, "STATUS_INVALID_HANDLE",
              "установщик обратился к объекту, которого уже нет (закрытый "
              "файл, удалённый во время установки каталог) — так ведут себя "
              "и программы, чьи файлы меняет антивирус", "internal"),
    CrashCode(0xC000000E, "STATUS_NO_SUCH_DEVICE",
              "носитель исчез во время работы: отключили флешку или внешний "
              "диск, на котором лежал дистрибутив или куда шла установка",
              "io"),
    CrashCode(0xC0000022, "STATUS_ACCESS_DENIED",
              "отказано в доступе к файлу или каталогу", "access"),
    CrashCode(0xC000008F, "STATUS_FLOAT_INEXACT_RESULT",
              "ошибка вычислений с плавающей точкой", "other"),
    CrashCode(0xC0000094, "STATUS_INTEGER_DIVIDE_BY_ZERO",
              "деление на ноль внутри установщика", "other"),
    CrashCode(0xC0000096, "STATUS_PRIVILEGED_INSTRUCTION",
              "попытка выполнить привилегированную инструкцию", "other"),
    CrashCode(0xC00000FD, "STATUS_STACK_OVERFLOW",
              "переполнение стека: обычно бесконечная рекурсия при разборе "
              "огромного каталога или повреждённого архива", "stack"),
    CrashCode(0xC0000135, "STATUS_DLL_NOT_FOUND",
              "установщику не хватает библиотеки — чаще всего это "
              "отсутствующий .NET Framework или Visual C++", "dll"),
    CrashCode(0xC0000139, "STATUS_ENTRYPOINT_NOT_FOUND",
              "в системе лежит библиотека не той версии, чем та, с которой "
              "собран установщик", "dll"),
    CrashCode(0xC0000142, "STATUS_DLL_INIT_FAILED",
              "библиотека не смогла инициализироваться (частая причина — "
              "блокировка антивирусом)", "dll", retryable=True),
    CrashCode(0xC000027B, "STATUS_STOWED_EXCEPTION",
              "внутреннее исключение приложения (обычно WinRT/XAML-код)",
              "internal"),
    CrashCode(0xC0000374, "STATUS_HEAP_CORRUPTION",
              "повреждение кучи процесса", "internal", retryable=True),
    CrashCode(0xC0000409, "STATUS_STACK_BUFFER_OVERRUN",
              "сработала защита компилятора (переполнение буфера или "
              "сторожевое срабатывание)", "stack"),
    CrashCode(0xC0000420, "STATUS_ASSERTION_FAILURE",
              "внутренняя проверка установщика не прошла", "internal"),
    CrashCode(0xC0000602, "STATUS_FAIL_FAST_EXCEPTION",
              "установщик сам решил аварийно завершиться (fail fast)", "internal"),
    CrashCode(0x80000003, "STATUS_BREAKPOINT",
              "в коде сработала точка останова — так ведут себя "
              "распаковщики защиты, увидев отладчик", "other"),
    # Этот код стоит вне полосы 0xC0000…, поэтому в таблице обязателен: так
    # завершаются бутстрапперы, написанные на .NET (у них падает управляемый
    # код, а Windows отдаёт код исключения CLR).
    CrashCode(0xE0434352, "CLR unhandled exception",
              "необработанное исключение .NET: бутстрапперу не хватило .NET "
              "нужной версии, либо он упал внутри управляемого кода (часто "
              "из-за вмешательства антивируса)", "other"),
)

_CRASH_BY_CODE: Dict[int, CrashCode] = {item.code: item for item in CRASH_CODES}


def _as_unsigned(rc: Optional[int]) -> Optional[int]:
    """Код возврата в беззнаковом 32-битном виде.

    Windows отдаёт код процесса как DWORD (``3221226525``), но тот же код
    может прийти и отрицательным (``-1073740771``) — приводим к одному виду.
    """
    if rc is None:
        return None
    return rc & 0xFFFFFFFF if rc < 0 else rc


def _unknown_crash(code: int) -> CrashCode:
    """Аварийное завершение с кодом, которого нет в таблице.

    Расшифровки у такого кода нет, и выдумывать её нельзя — но и общий совет
    «не хватило прав администратора» недопустим: код из полосы фатальных
    NTSTATUS означает, что процесс установщика уже работал и был оборван
    исключением. Повторять запуск вслепую тоже не стоит: сначала надо
    посмотреть, какой модуль назван в журнале событий.
    """
    return CrashCode(
        code, "",
        "аварийное завершение процесса: код NTSTATUS, которого нет в таблице "
        "известных. Установщик уже работал и был оборван исключением — к "
        "командной строке и правам администратора это отношения не имеет, и "
        "повышение прав причину не изменит",
        "other")


def crash_code(rc: Optional[int]) -> Optional[CrashCode]:
    """Расшифровка кода или ``None``, если это обычный код ошибки."""
    code = _as_unsigned(rc)
    if code is None:
        return None
    known = _CRASH_BY_CODE.get(code)
    if known is not None:
        return known
    low, high = NTSTATUS_FATAL_BAND
    if low <= code <= high:
        return _unknown_crash(code)
    return None


def is_crash_code(rc: Optional[int]) -> bool:
    """Упал ли процесс установщика (а не вернул код ошибки)."""
    return crash_code(rc) is not None


def is_retryable(rc: Optional[int]) -> bool:
    """Стоит ли повторить ровно ту же команду: падение могло быть разовым."""
    item = crash_code(rc)
    return bool(item and item.retryable)


# -- журнал событий Windows ---------------------------------------------------

#: Сколько последних записей «Ошибка приложения» запрашивать. Нужная — самая
#: свежая; запас нужен лишь на случай, когда в журнал успели упасть другие
#: программы.
EVENT_QUERY_LIMIT = 40

#: Имя провайдера, который пишет сведения о падении процесса.
_APP_ERROR_EVENT_ID = 1000

#: Как называются поля в разных версиях Windows. Первый вариант — Windows 10
#: и новее, второй — старые сборки и серверные редакции, третий приходит от
#: службы отчётов об ошибках.
_APP_FIELDS = ("appname", "faultingapplicationname", "application")
_MODULE_FIELDS = ("modname", "faultingmodulename", "module")
_MODULE_PATH_FIELDS = ("modpath", "faultingmodulepath", "modulepath")
_EXCEPTION_FIELDS = ("exceptioncode", "exception")
_OFFSET_FIELDS = ("offset", "faultingofficerelativeoffset")


@dataclass
class CrashEvent:
    """Одна запись журнала событий о падении процесса."""

    app: str = ""
    module: str = ""
    module_path: str = ""
    exception_code: str = ""
    offset: str = ""
    timestamp: str = ""
    report_id: str = ""
    provider: str = ""

    @property
    def is_ours(self) -> bool:
        return bool(self.app)


Runner = Callable[[Sequence[str], float], Tuple[int, str]]


def _default_runner(cmd: Sequence[str], timeout: float) -> Tuple[int, str]:
    """Запускает ``wevtutil`` и возвращает ``(код, текст)``."""
    kwargs: Dict[str, object] = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(list(cmd), stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=timeout,
                              **kwargs)  # type: ignore[arg-type]
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    return int(proc.returncode or 0), _decode(proc.stdout or b"")


def _decode(raw: bytes) -> str:
    """Текст wevtutil: UTF-8, а если не он — системная кодировка."""
    for encoding in ("utf-8-sig", "cp1251"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _local_name(tag: str) -> str:
    """Имя тега без пространства имён и в нижнем регистре."""
    return tag.rsplit("}", 1)[-1].casefold()


def base_name(path: str) -> str:
    """Имя файла из пути любого вида.

    В журнале событий имя процесса обычно записано полностью
    (``C:\\Games\\setup_hatred.exe``), а ``os.path.basename`` под Windows и под
    Linux разбирает разные разделители — поэтому путь приводится к одному
    виду заранее.
    """
    return os.path.basename(path.replace("\\", "/").rstrip("/"))


def _parse_time(value: str) -> Optional[float]:
    """``2026-10-14T01:23:45.6789012Z`` → метка времени (UTC)."""
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        import datetime as _dt

        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.timestamp()


def parse_application_errors(xml_text: str) -> List[CrashEvent]:
    """Разбирает выгрузку ``wevtutil qe Application /f:xml``.

    Читаются только записи провайдера «Application Error» (Event ID 1000):
    именно там лежит имя упавшего процесса, модуль с ошибкой и код
    исключения. Имена полей различаются между версиями Windows, поэтому
    сначала ищется поле по имени, а если имён нет — поля берутся по порядку,
    как их пишет сама Windows.
    """
    if not xml_text or "<Event" not in xml_text:
        return []
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return []

    events: List[CrashEvent] = []
    for element in root.iter():
        if _local_name(element.tag) != "event":
            continue
        event = _parse_event(element)
        if event is not None:
            events.append(event)
    return events


def _parse_event(element: "ElementTree.Element") -> Optional[CrashEvent]:
    system: Dict[str, str] = {}
    values: Dict[str, str] = {}
    ordered: List[str] = []
    for child in element:
        name = _local_name(child.tag)
        if name == "system":
            for field_element in child:
                field = _local_name(field_element.tag)
                if field == "provider":
                    system["provider"] = field_element.get("Name", "")
                elif field == "timecreated":
                    system["time"] = field_element.get("SystemTime", "")
                elif field == "eventid":
                    system["eventid"] = (field_element.text or "").strip()
        elif name == "eventdata":
            for data in child:
                if _local_name(data.tag) != "data":
                    continue
                text = (data.text or "").strip()
                ordered.append(text)
                label = (data.get("Name") or "").casefold()
                if label:
                    values[label] = text
    if system.get("eventid") not in (str(_APP_ERROR_EVENT_ID), ""):
        return None

    def pick(fields: Sequence[str], index: Optional[int] = None) -> str:
        for field in fields:
            if field in values:
                return values[field]
        if index is not None and 0 <= index < len(ordered):
            return ordered[index]
        return ""

    event = CrashEvent(
        app=pick(_APP_FIELDS, 0),
        module=pick(_MODULE_FIELDS, 3),
        module_path=pick(_MODULE_PATH_FIELDS),
        exception_code=pick(_EXCEPTION_FIELDS, 7),
        offset=pick(_OFFSET_FIELDS, 6),
        timestamp=system.get("time", ""),
        report_id=pick(("reportid",), None),
        provider=system.get("provider", ""),
    )
    if not event.app:
        return None
    return event


def read_crash_events(app_names: Iterable[str], since: Optional[float] = None,
                      runner: Optional[Runner] = None,
                      timeout: float = 30.0) -> List[CrashEvent]:
    """Читает из журнала событий падения указанных процессов.

    ``since`` (метка времени) отсекает старые записи: журнал хранит их
    неделями, и без фильтра в отчёт попало бы падение, случившееся до
    сегодняшней сборки. ``runner`` подменяется в тестах — сам модуль тогда
    не зависит от наличия ``wevtutil``.
    """
    wanted = {base_name(name).casefold() for name in app_names if name}
    if not wanted:
        return []
    query = f"*[System[(EventID={_APP_ERROR_EVENT_ID})]]"
    cmd = ["wevtutil.exe", "qe", "Application", f"/q:{query}", "/f:xml",
           "/rd:true", f"/c:{EVENT_QUERY_LIMIT}"]
    run = runner or _default_runner
    try:
        code, text = run(cmd, timeout)
    except Exception:  # noqa: BLE001 - журнал не должен ломать сборку
        return []
    if code != 0 or not text:
        return []

    result: List[CrashEvent] = []
    for event in parse_application_errors(text):
        if base_name(event.app).casefold() not in wanted:
            continue
        if since is not None:
            stamp = _parse_time(event.timestamp)
            # Записи без времени не выбрасываем: лучше лишний факт, чем
            # потерянная причина. Допуск в минуту закрывает расхождение
            # часов между записью в журнал и стартом установки.
            if stamp is not None and stamp < since - 60:
                continue
        result.append(event)
    return result


# -- отчёт о падении -----------------------------------------------------------

_SYSTEM_MODULES = (
    "ntdll", "kernel32", "kernelbase", "user32", "gdi32", "shell32", "shlwapi",
    "ole32", "oleaut32", "comctl32", "comdlg32", "combase", "rpcrt4", "sechost",
    "dbghelp", "ucrtbase", "msvcrt", "msvcp", "api-ms-win", "advapi32", "setupapi",
    "winmm", "imm32", "dwmapi", "uxtheme", "propsys", "version", "ws2_32",
)


def module_verdict(module: str, module_path: str,
                   installer_path: str = "") -> str:
    """Что говорит модуль, в котором упал установщик.

    Разница принципиальная: падение внутри самого установщика означает, что
    ему не подошёл дистрибутив, команда или условия установки, а падение в
    сторонней библиотеке — что в процесс влез чужой код (антивирус, оверлей,
    инжектор), и права администратора тут ни при чём.
    """
    if not module:
        return ""
    lowered = base_name(module).casefold()
    own = base_name(installer_path).casefold() if installer_path else ""
    if own and lowered == own:
        return ("падение произошло внутри самого установщика — это его "
                "собственный код или загруженная им библиотека, а не "
                "нехватка прав")
    path = (module_path or "").casefold()
    if path:
        if "\\windows\\" in path or "/windows/" in path:
            return ("упала системная библиотека — обычно это означает "
                    "вмешательство извне (антивирус, оверлей, устаревший "
                    "драйвер) либо повреждённые системные файлы")
        return ("упала сторонняя библиотека из " + os.path.dirname(module_path)
                + " — так ведут себя антивирусы, «ускорители» и оверлеи, "
                "которые внедряются в чужие процессы")
    if lowered.startswith(_SYSTEM_MODULES):
        return ("упала системная библиотека — обычно это означает "
                "вмешательство извне (антивирус, оверлей, устаревший "
                "драйвер) либо повреждённые системные файлы")
    return ("упал сторонний модуль — так ведут себя антивирусы, оверлеи и "
            "внедрённые в процесс установщика библиотеки")


def format_report(rc: Optional[int], attempt: str, command: str,
                  events: Sequence[CrashEvent], installer_path: str = "",
                  temp_line: str = "", version: str = "") -> str:
    """Собирает текст ``installer-crash.log`` — факты, без догадок.

    ``version`` — версия Portablizer. Она в отчёте не для красоты: по
    жалобе вида «установщик упал с кодом 0xC000041D» важно сразу понять,
    какая сборка это написала, — старые версии давали неверный диагноз.
    """
    code = crash_code(rc)
    lines = ["=== Аварийное завершение установщика =================",
             f"Время: {time.strftime('%Y-%m-%d %H:%M:%S')}"]
    if version:
        lines.append(f"Portablizer: {version}")
    if rc is not None:
        unsigned = _as_unsigned(rc) or 0
        lines.append(f"Код процесса: {unsigned} "
                     f"({unsigned - (1 << 32) if unsigned > 0x7FFFFFFF else unsigned}"
                     f", 0x{unsigned:08X})")
    if code is not None:
        lines.append(f"Расшифровка: {code.hint}")
    if attempt:
        lines.append(f"Сценарий: {attempt}")
    if command:
        lines.append(f"Команда: {command}")
    if temp_line:
        lines.append(temp_line)
    if not events:
        lines.append("")
        lines.append("Журнал событий Windows не дал записи об этом падении "
                     "(запись могла не успеть появиться или журнал недоступен).")
        return "\n".join(lines) + "\n"

    lines.append("")
    lines.append("Записи журнала событий Windows (Application, Event ID 1000):")
    for event in events:
        lines.append(f"  • {event.timestamp or 'без времени'}  {event.app}")
        if event.module:
            lines.append(f"      модуль с ошибкой: {event.module}"
                         + (f" ({event.module_path})" if event.module_path else ""))
        if event.exception_code:
            lines.append(f"      код исключения: {event.exception_code}"
                         + (f", смещение: {event.offset}" if event.offset else ""))
        if event.report_id:
            lines.append(f"      идентификатор отчёта: {event.report_id}")
        verdict = module_verdict(event.module, event.module_path, installer_path)
        if verdict:
            lines.append(f"      вывод: {verdict}")
    return "\n".join(lines) + "\n"


# -- подсказки -----------------------------------------------------------------

def crash_hints(rc: Optional[int], *, installer_path: str = "",
                event: Optional[CrashEvent] = None,
                is_gog: bool = False, is_inno: bool = False,
                space_note: str = "", relocated_to: str = "",
                retried: bool = False, progress_retry: str = "",
                suggest_unpacker: bool = False,
                unpacker_result: str = "",
                ) -> List[str]:
    """Подсказки под конкретное падение — вместо «смотрите журнал».

    Порядок подсказок — по вероятности причины для этого кода и этого
    установщика. Числа (место на диске, вес дистрибутива) подставляет
    вызывающий код: сам модуль ничего не измеряет, поэтому его подсказки
    проверяются без Windows и без реальных дисков.
    """
    item = crash_code(rc)
    if item is None:
        return []
    hints: List[str] = []

    hints.append(
        f"Установщик не отказался от работы, а упал: {describe(item)}. Код "
        "аварийного завершения не связан ни с командной строкой, ни с "
        "правами администратора: процесс уже шёл, когда исключение оборвало "
        "его на середине. Повышение прав причину не изменит."
    )

    if not item.name:
        # Кода нет в таблице: не притворяемся, что знаем причину, и не
        # повторяем запуск вслепую — сперва имя упавшего модуля.
        hints.append(
            f"Расшифровки у кода 0x{item.code:08X} нет — он не входит в "
            "таблицу известных. Portablizer не станет повторять запуск "
            f"вслепую: имя упавшего модуля записано в {CRASH_LOG_NAME} "
            "рядом с папкой портатива (и в portablizer.log) — по нему "
            "видно, кто именно уронил установщик: он сам или сторонний "
            "код в его процессе."
        )

    if event is not None and event.module:
        verdict = module_verdict(event.module, event.module_path, installer_path)
        hints.append(
            "Windows записала в журнал событий, где именно упал процесс: "
            f"модуль «{event.module}»"
            + (f" ({event.module_path})" if event.module_path else "")
            + (f", код исключения {event.exception_code}"
               if event.exception_code else "")
            + (f" — {verdict}." if verdict else ".")
            + f" Подробности — в {CRASH_LOG_NAME} рядом с папкой портатива."
        )

    if relocated_to:
        hints.append(
            "TEMP установщика перенесён из папки портатива на другой диск "
            f"({relocated_to}): на диске портатива места для распаковки не "
            "хватало. Папка временная и удаляется после сборки."
        )
    if space_note:
        hints.append(space_note)

    if is_gog:
        hints.append(
            "Это офлайн-установщик GOG: его части (.bin) должны лежать в той "
            "же папке и называться так же, как setup_*.exe — переименованные "
            "или недокачанные части он не находит и падает. Проверьте, что "
            "скачаны ВСЕ части и их размеры совпадают с указанными на сайте."
        )

    hints.append(
        "Проверьте, не мешает ли посторонний код: антивирус, «оптимизатор», "
        "оверлей записи экрана или игровая панель внедряются в чужой процесс "
        "и роняют его. Добавьте установщик (и Portablizer) в исключения "
        "антивируса и повторите сборку."
    )

    if retried:
        hints.append(
            "Portablizer уже повторил ровно ту же команду, и падение "
            "повторилось: значит дело не в разовой помехе, а в самом "
            "дистрибутиве, его целостности или в условиях на этом ПК."
        )

    if progress_retry:
        hints.append(progress_retry)

    if is_inno and not progress_retry:
        hints.append(
            "Установщик собран на Inno Setup: у него есть режим с окном "
            "прогресса — «/SILENT» вместо «/VERYSILENT». Если отрисовка "
            "тихого прогресса и была причиной падения, этот режим проходит. "
            "Ключ можно задать в поле «Доп. аргументы установки»."
        )

    if unpacker_result:
        hints.append(unpacker_result)
    if suggest_unpacker:
        hints.append(
            "Ещё один путь для падающего установщика — распаковка БЕЗ "
            "запуска: Inno Setup и NSIS это обычные контейнеры, и 7-Zip "
            "(7-zip.org) достаёт их содержимое, не выполняя код установщика. "
            "Поставьте 7-Zip и повторите сборку."
        )
    return hints


def _space_hints(item: CrashCode, *, is_gog: bool, temp_dir: str,
                 temp_free: int, need_bytes: int,
                 relocated_to: str) -> List[str]:
    """Подсказки про место: у GOG это причина падений номер один."""
    hints: List[str] = []
    if relocated_to:
        hints.append(
            "TEMP установщика перенесён из папки портатива на другой диск "
            f"({relocated_to}): на диске портатива места для распаковки не "
            "хватало. Папка временная и удаляется после сборки."
        )
        return hints
    if need_bytes > 0 and temp_free >= 0:
        if temp_free < need_bytes:
            hints.append(
                "Этого диска установщику не хватает: распаковка идёт через "
                "TEMP, поэтому свободными должны быть примерно два веса "
                "дистрибутива одновременно. Освободите место или укажите "
                "для портатива диск побольше."
            )
        else:
            hints.append(
                "Места в TEMP хватает (нужно около двух весов дистрибутива) "
                "— значит причина, скорее всего, не в диске."
            )
        return hints
    if is_gog or item.kind in ("callback", "io"):
        hints.append(
            "Проверьте свободное место на диске портатива: офлайн-установщик "
            "GOG распаковывает данные в TEMP и требует примерно два веса "
            "дистрибутива, поэтому «места достаточно по документации» и "
            "«места достаточно установщику» — не одно и то же."
        )
    return hints
