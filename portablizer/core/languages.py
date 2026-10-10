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
from typing import Dict, List, Optional, Sequence, Tuple

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


# --- Представления языков в реестре, INI-эмуляторах и папках _Lang_SW ---------

@dataclass(frozen=True)
class LanguageRegistryProfile:
    """Форматы одного языка в реестре игр, INI-файлах и папках репаков."""

    code: str               # код из LANGUAGES («ru», «en», ...)
    english_name: str       # «Russian», «English», ...
    short_code: str         # 3-буквенный код: «rus», «eng», ...
    iso_code: str           # 2-буквенный код: «ru», «en», ...
    locale_hyphen: str      # «ru-RU», «en-US», ...
    locale_underscore: str  # «ru_RU», «en_US», ...
    lcid: int               # 0x0419 (1049), 0x0409 (1033), ...
    tokens: Tuple[str, ...] = ()


REGISTRY_PROFILES: Tuple[LanguageRegistryProfile, ...] = (
    LanguageRegistryProfile(
        code="ru",
        english_name="Russian",
        short_code="rus",
        iso_code="ru",
        locale_hyphen="ru-RU",
        locale_underscore="ru_RU",
        lcid=0x0419,
        tokens=(
            "ru", "rus", "russian", "ru-ru", "ru_ru", "ruru",
            "1049", "0419", "0x0419", "00000419",
            "рус", "русский", "русская",
        ),
    ),
    LanguageRegistryProfile(
        code="en",
        english_name="English",
        short_code="eng",
        iso_code="en",
        locale_hyphen="en-US",
        locale_underscore="en_US",
        lcid=0x0409,
        tokens=(
            "en", "eng", "enu", "english", "en-us", "en_us", "enus",
            "en-gb", "en_gb", "engb",
            "1033", "0409", "0x0409", "00000409",
            "анг", "англ", "английский", "английская",
        ),
    ),
    LanguageRegistryProfile(
        code="uk",
        english_name="Ukrainian",
        short_code="ukr",
        iso_code="uk",
        locale_hyphen="uk-UA",
        locale_underscore="uk_UA",
        lcid=0x0422,
        tokens=(
            "uk", "ukr", "ua", "ukrainian", "uk-ua", "uk_ua", "ukua",
            "1058", "0422", "0x0422", "00000422",
            "укр", "українська", "украинский",
        ),
    ),
    LanguageRegistryProfile(
        code="de",
        english_name="German",
        short_code="ger",
        iso_code="de",
        locale_hyphen="de-DE",
        locale_underscore="de_DE",
        lcid=0x0407,
        tokens=(
            "de", "ger", "deu", "german", "deutsch", "de-de", "de_de", "dede",
            "1031", "0407", "0x0407", "00000407",
            "нем", "немецкий",
        ),
    ),
    LanguageRegistryProfile(
        code="fr",
        english_name="French",
        short_code="fre",
        iso_code="fr",
        locale_hyphen="fr-FR",
        locale_underscore="fr_FR",
        lcid=0x040C,
        tokens=(
            "fr", "fre", "fra", "french", "francais", "français",
            "fr-fr", "fr_fr", "frfr",
            "1036", "040c", "0x040c", "0000040c",
            "фра", "французский",
        ),
    ),
    LanguageRegistryProfile(
        code="it",
        english_name="Italian",
        short_code="ita",
        iso_code="it",
        locale_hyphen="it-IT",
        locale_underscore="it_IT",
        lcid=0x0410,
        tokens=(
            "it", "ita", "italian", "italiano", "it-it", "it_it", "itit",
            "1040", "0410", "0x0410", "00000410",
            "ита", "итальянский",
        ),
    ),
    LanguageRegistryProfile(
        code="es",
        english_name="Spanish",
        short_code="spa",
        iso_code="es",
        locale_hyphen="es-ES",
        locale_underscore="es_ES",
        lcid=0x0C0A,
        tokens=(
            "es", "spa", "esp", "spanish", "espanol", "español",
            "es-es", "es_es", "eses", "es-mx", "es_mx", "esmx", "latam",
            "3082", "0c0a", "0x0c0a", "00000c0a",
            "1034", "040a", "0x040a", "0000040a",
            "исп", "испанский",
        ),
    ),
    LanguageRegistryProfile(
        code="pl",
        english_name="Polish",
        short_code="pol",
        iso_code="pl",
        locale_hyphen="pl-PL",
        locale_underscore="pl_PL",
        lcid=0x0415,
        tokens=(
            "pl", "pol", "polish", "polski", "pl-pl", "pl_pl", "plpl",
            "1045", "0415", "0x0415", "00000415",
            "пол", "польский",
        ),
    ),
    LanguageRegistryProfile(
        code="pt-BR",
        english_name="Brazilian",
        short_code="ptb",
        iso_code="pt",
        locale_hyphen="pt-BR",
        locale_underscore="pt_BR",
        lcid=0x0416,
        tokens=(
            "pt-br", "pt_br", "ptbr", "pt", "ptb", "bra", "por",
            "brazilian", "portuguese", "brazilianportuguese",
            "português", "portugues",
            "1046", "0416", "0x0416", "00000416", "2070", "0816", "0x0816",
        ),
    ),
    LanguageRegistryProfile(
        code="zh-CN",
        english_name="Chinese",
        short_code="chs",
        iso_code="zh",
        locale_hyphen="zh-CN",
        locale_underscore="zh_CN",
        lcid=0x0804,
        tokens=(
            "zh-cn", "zh_cn", "zhcn", "zh", "chs", "chi", "zho",
            "schinese", "chinese", "chinesesimplified", "simplifiedchinese",
            "2052", "0804", "0x0804", "00000804", "简体中文", "中文",
        ),
    ),
    LanguageRegistryProfile(
        code="ja",
        english_name="Japanese",
        short_code="jpn",
        iso_code="ja",
        locale_hyphen="ja-JP",
        locale_underscore="ja_JP",
        lcid=0x0411,
        tokens=(
            "ja", "jp", "jpn", "jap", "japanese", "ja-jp", "ja_jp", "jajp",
            "1041", "0411", "0x0411", "00000411", "日本語",
        ),
    ),
    LanguageRegistryProfile(
        code="tr",
        english_name="Turkish",
        short_code="tur",
        iso_code="tr",
        locale_hyphen="tr-TR",
        locale_underscore="tr_TR",
        lcid=0x041F,
        tokens=(
            "tr", "tur", "trk", "turkish", "türkçe", "turkce",
            "tr-tr", "tr_tr", "trtr",
            "1055", "041f", "0x041f", "0000041f",
        ),
    ),
)

_PROFILE_BY_CODE: Dict[str, LanguageRegistryProfile] = {
    p.code.lower(): p for p in REGISTRY_PROFILES
}

_TOKEN_TO_CODE: Dict[str, str] = {}
for _prof in REGISTRY_PROFILES:
    for _tok in _prof.tokens:
        _TOKEN_TO_CODE.setdefault(_tok.casefold(), _prof.code)

_TWO_LETTER_TOKENS = {
    p.iso_code.casefold() for p in REGISTRY_PROFILES
} | {"ua", "jp"}

_THREE_LETTER_TOKENS = {
    p.short_code.casefold() for p in REGISTRY_PROFILES
} | {
    "enu", "ukr", "deu", "fra", "esp", "bra", "por",
    "chi", "zho", "jap", "trk", "рус", "анг", "укр",
    "нем", "фра", "ита", "исп", "пол",
}

_DECIMAL_LCID_TOKENS: Dict[int, str] = {}
for _prof in REGISTRY_PROFILES:
    _DECIMAL_LCID_TOKENS[_prof.lcid] = _prof.code
_DECIMAL_LCID_TOKENS[1034] = "es"
_DECIMAL_LCID_TOKENS[2070] = "pt-BR"


def find_registry_profile(code: str) -> Optional[LanguageRegistryProfile]:
    """Профиль форматов языка для реестра/INI по коду из ``LANGUAGES``."""
    return _PROFILE_BY_CODE.get((code or "").strip().lower())


def identify_language_token(value: str) -> Optional[str]:
    """Определяет канонический код языка («ru», «en», ...) по строковому значению."""
    cleaned = (value or "").strip().strip("\"'")
    if not cleaned:
        return None
    low = cleaned.casefold()
    if low in _TOKEN_TO_CODE:
        return _TOKEN_TO_CODE[low]
    return None


def _match_case_style(template: str, replacement: str) -> str:
    """Подгоняет регистр ``replacement`` под образец ``template``."""
    if not template or not replacement:
        return replacement
    if template.isupper():
        return replacement.upper()
    if template.islower():
        return replacement.lower()
    if template[0].isupper() and template[1:].islower():
        return replacement[:1].upper() + replacement[1:].lower()
    return replacement


def convert_language_string(old_value: str, target_code: str) -> Optional[str]:
    """Переводит строковое языковое значение в тот же формат целевого языка.

    Примеры для ``target_code="ru"``:
      * ``"English"`` -> ``"Russian"``
      * ``"english"`` -> ``"russian"``
      * ``"ENG"``     -> ``"RUS"``
      * ``"en"``      -> ``"ru"``
      * ``"en-US"``   -> ``"ru-RU"``
      * ``"en_US"``   -> ``"ru_RU"``
      * ``"1033"``    -> ``"1049"``
      * ``"0409"``    -> ``"0419"``
      * ``"0x0409"``  -> ``"0x0419"``
    Возвращает ``None``, если ``old_value`` не распознано как обозначение языка.
    """
    profile = find_registry_profile(target_code)
    if profile is None:
        return None
    raw = (old_value or "").strip()
    if not raw:
        return profile.english_name
    low = raw.casefold()
    source_code = identify_language_token(raw)
    if source_code is None:
        return None

    # Шестнадцатеричный или десятичный LCID в строке
    if low.startswith("0x") and len(low) in (6, 10):
        width = len(raw) - 2
        prefix = raw[:2]
        hex_digits = f"{profile.lcid:0{width}X}"
        if raw[2:].islower():
            hex_digits = hex_digits.lower()
        return prefix + hex_digits
    if re.fullmatch(r"0[0-9a-fA-F]{3,7}", raw):
        width = len(raw)
        hex_digits = f"{profile.lcid:0{width}X}"
        if raw.islower():
            hex_digits = hex_digits.lower()
        return hex_digits
    if raw.isdigit():
        return str(profile.lcid)

    # Локаль с разделителем: en-US / en_US
    if "-" in raw and len(raw) in (5, 6):
        left, _, right = raw.partition("-")
        t_left, _, t_right = profile.locale_hyphen.partition("-")
        return f"{_match_case_style(left, t_left)}-{_match_case_style(right, t_right)}"
    if "_" in raw and len(raw) in (5, 6):
        left, _, right = raw.partition("_")
        t_left, _, t_right = profile.locale_underscore.partition("_")
        return f"{_match_case_style(left, t_left)}_{_match_case_style(right, t_right)}"

    # Двухбуквенный или трёхбуквенный код
    if low in _TWO_LETTER_TOKENS:
        return _match_case_style(raw, profile.iso_code)
    if low in _THREE_LETTER_TOKENS:
        return _match_case_style(raw, profile.short_code)

    # Имя для Steam-эмуляторов (schinese / tchinese / brazilian / ...)
    if low in ("schinese", "tchinese"):
        return "schinese" if profile.code == "zh-CN" else profile.english_name.lower()

    # Полное английское название (Russian / russian / RUSSIAN)
    return _match_case_style(raw, profile.english_name)


def convert_language_dword(old_value: int, target_code: str) -> Optional[int]:
    """Переводит числовой LCID в реестре (REG_DWORD) в LCID выбранного языка."""
    profile = find_registry_profile(target_code)
    if profile is None:
        return None
    if old_value in _DECIMAL_LCID_TOKENS:
        return profile.lcid
    return None

