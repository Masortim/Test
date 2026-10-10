"""Выбор языка многоязычного установщика для портативной сборки.

Многоязычный установщик ставит в папку только те файлы, которые относятся к
выбранному при установке языку: текст интерфейса, субтитры, шрифты, локализационные
таблицы. Если сборка прошла на английском, а игре потом выставили русские
субтитры, файлов русского текста и шрифтов в портативе может не оказаться, и
субтитры выводятся без букв (остаются только знаки препинания). Поэтому язык
нужно выбрать ещё при сборке — тем же ключом, которым его выбрал бы человек
в окне установщика.

Синтаксис ключа зависит от движка установщика:

  * Inno Setup     — ``/LANG=<имя языка>`` из секции [Languages] сценария
                     (``/LANG=russian``, без учёта регистра);
  * NSIS           — ``/LANG=<LCID в десятичной записи>`` (``/LANG=1049``);
  * InstallShield  — ``/L0x<LCID в шестнадцатеричной записи>`` (``/L0x0419``).

Остальные движки язык ключом не выбирают (MSI переводится трансформом .mst,
WiX Burn и собственные bootstrapper'ы — своими средствами). Для них модуль
честно сообщает, что язык нужно выбрать в самом окне установщика или задать
ключ вручную в поле «Доп. аргументы».

Если ключ передан, а в установщике такого языка нет, движок ставит язык по
умолчанию и не падает — поэтому выбранный язык журналируется, а установщик
должен его содержать.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from .detect import InstallerType


@dataclass(frozen=True)
class InstallerLanguage:
    """Один язык, который можно выбрать при сборке портатива."""

    code: str         # короткий код для настроек: «ru», «pt-BR»
    title: str        # название в интерфейсе: «Русский»
    lcid: int         # идентификатор языка Windows (LCID)
    inno_name: str    # имя языка в секции [Languages] Inno Setup


#: Языки, которые чаще всего встречаются в многоязычных установщиках игр и
#: программ. Русский — первым: это основной сценарий, ради которого
#: выбор языка и появился.
LANGUAGES: List[InstallerLanguage] = [
    InstallerLanguage("ru", "Русский", 0x0419, "russian"),
    InstallerLanguage("en", "English", 0x0409, "english"),
    InstallerLanguage("uk", "Українська", 0x0422, "ukrainian"),
    InstallerLanguage("de", "Deutsch", 0x0407, "german"),
    InstallerLanguage("fr", "Français", 0x040C, "french"),
    InstallerLanguage("it", "Italiano", 0x0410, "italian"),
    InstallerLanguage("es", "Español", 0x0C0A, "spanish"),
    InstallerLanguage("pl", "Polski", 0x0415, "polish"),
    InstallerLanguage("pt-BR", "Português (Brasil)", 0x0416,
                      "brazilianportuguese"),
    InstallerLanguage("zh-CN", "简体中文", 0x0804, "chinesesimplified"),
    InstallerLanguage("ja", "日本語", 0x0411, "japanese"),
    InstallerLanguage("tr", "Türkçe", 0x041F, "turkish"),
]

_BY_CODE = {lang.code.lower(): lang for lang in LANGUAGES}

#: Признаки уже заданного языка в пользовательских аргументах. Если человек
#: сам написал ``/LANG=…`` или ``/L0x…``, второй ключ ставить нельзя.
_LANG_SWITCH_RE = re.compile(
    r"^(?:/LANG=|/L0x|/L\d|/L=|-LANG=|/langid=|-langid=)", re.IGNORECASE)


def find_language(code: str) -> Optional[InstallerLanguage]:
    """Язык по коду («ru», «RU», «pt-br») или ``None``.

    Пустая строка означает «как выбрано в самом установщике», поэтому тоже
    возвращает ``None``; различать эти случаи вызывающему коду не нужно —
    см. ``plan_language``.
    """
    key = (code or "").strip().lower()
    return _BY_CODE.get(key)


def supports_language_switch(installer_type: InstallerType) -> bool:
    """Умеет ли движок выбирать язык ключом командной строки."""
    return installer_type in (
        InstallerType.INNO, InstallerType.NSIS, InstallerType.INSTALLSHIELD)


def has_language_switch(args: Sequence[str]) -> bool:
    """Есть ли среди аргументов уже заданный язык установщика."""
    return any(_LANG_SWITCH_RE.match(str(a).strip()) for a in args)


def switch_for(installer_type: InstallerType,
               language: InstallerLanguage) -> Optional[str]:
    """Ключ выбора языка для движка или ``None``, если движок его не знает."""
    if installer_type == InstallerType.INNO:
        return f"/LANG={language.inno_name}"
    if installer_type == InstallerType.NSIS:
        return f"/LANG={language.lcid}"
    if installer_type == InstallerType.INSTALLSHIELD:
        return f"/L0x{language.lcid:04X}"
    return None


@dataclass
class LanguagePlan:
    """Что сделать с языком для данного установщика."""

    #: Аргументы, которые добавляются к команде установки (может быть пусто).
    args: List[str] = field(default_factory=list)
    #: Сообщение для журнала — почему язык передан или почему нет.
    message: str = ""
    #: ``info`` / ``warn`` — уровень, с которым писать сообщение в журнал.
    level: str = "info"


def plan_language(installer_type: InstallerType, code: str,
                  user_args: Sequence[str] = ()) -> LanguagePlan:
    """Аргументы выбора языка для установщика данного типа.

    ``code`` — код из ``LANGUAGES`` или пустая строка (язык по умолчанию).
    ``user_args`` — уже введённые пользователем аргументы: если в них есть
    выбор языка, Portablizer ничего не добавляет.
    """
    if not (code or "").strip():
        return LanguagePlan()

    language = find_language(code)
    if language is None:
        return LanguagePlan(
            message=f"Язык «{code}» не поддерживается Portablizer — "
                    "установщик выполнится с языком по умолчанию.",
            level="warn")

    if has_language_switch(user_args):
        return LanguagePlan(
            message=f"Язык {language.title} не передан: в доп. аргументах уже "
                    "задан выбор языка, он имеет приоритет.",
            level="warn")

    if not supports_language_switch(installer_type):
        return LanguagePlan(
            message=(f"Тип установщика «{installer_type.value}» не выбирает "
                     "язык ключом командной строки. Выберите язык в самом "
                     "окне установщика или укажите его в доп. аргументах; "
                     "иначе портатив получит язык по умолчанию."),
            level="warn")

    switch = switch_for(installer_type, language)
    if switch is None:  # страховка: supports_language_switch уже проверил тип
        return LanguagePlan(
            message=f"Язык {language.title} для этого установщика не задаётся.",
            level="warn")
    return LanguagePlan(
        args=[switch],
        message=(f"Язык установки: {language.title} (ключ {switch}). Если в "
                 "установщике нет этого языка, он поставит язык по "
                 "умолчанию — проверьте файлы App и субтитры в игре."),
    )
