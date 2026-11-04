"""Свежий подписанный TAP-драйвер взамен устаревшего вендорского.

Зачем это нужно
---------------
VPN-клиенты возят с собой TAP-Windows той версии, которая была актуальна в
день сборки их установщика. У PlanetVPN это ``9.24.2.1`` от 2019 года. В
драйвере ``tap0901.sys`` версий **до 9.26 включительно** найдено переполнение
буфера (CVE-2024-1305), и современная Windows отказывается его ставить:
срабатывает список уязвимых драйверов, а на Windows 11 ещё и «Целостность
памяти» (HVCI). Отказ при этом выглядит одинаково и у нашего Setup, и у
самого вендорского клиента — «Ошибка установки драйвера адаптера», потому
что оба ставят один и тот же заблокированный файл.

Комплектность, разрядность и Hardware ID тут уже ни при чём: сколько ни
чини комплект 2019 года, Windows его не примет. Лечится это только заменой
драйвера на актуальный — проект OpenVPN выпустил исправленную версию
``9.27.0`` и подписывает её своим каталогом.

Модуль ничего не устанавливает: он только СКАЧИВАЕТ официальный архив,
распаковывает его и проверяет подпись каталога. Установкой занимается
обычный путь NetStack, уже с повышением прав и под контролем пользователя.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import zipfile
from typing import Callable, List, Optional, Tuple

#: Исправленная версия tap-windows6 (CVE-2024-1305 закрыт в 9.27).
OFFICIAL_TAP_VERSION = "9.27.0"

#: Официальный архив проекта OpenVPN: подписанные .inf/.sys/.cat на все
#: разрядности сразу (amd64/i386/arm64).
OFFICIAL_TAP_URL = (
    "https://github.com/OpenVPN/tap-windows6/releases/download/"
    f"{OFFICIAL_TAP_VERSION}/dist.win10.zip"
)

#: Версии строго ниже этой Windows считает уязвимыми.
MIN_SAFE_VERSION: Tuple[int, ...] = (9, 27, 0, 0)

_USER_AGENT = "Portablizer/1.47 (+https://github.com/Masortim/Test)"

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")


def version_tuple(value: str) -> Tuple[int, ...]:
    """``11/29/2019,9.24.2.1`` -> ``(9, 24, 2, 1)``.

    В ``DriverVer`` дата идёт первой, поэтому берётся часть ПОСЛЕ запятой.
    Пустое или непонятное значение даёт пустой кортеж: неизвестную версию
    нельзя объявлять ни устаревшей, ни безопасной.
    """
    text = str(value or "").strip()
    if not text:
        return ()
    if "," in text:
        text = text.split(",", 1)[1].strip()
    matched = _VERSION_RE.search(text)
    if not matched:
        return ()
    parts = tuple(int(p) for p in matched.group(1).split("."))
    return parts + (0,) * (4 - len(parts))


def is_vulnerable_tap(driver_version: str) -> bool:
    """True, если версия TAP попадает под блокировку Windows.

    Неизвестная версия (пустой DriverVer) НЕ считается уязвимой: лучше
    промолчать, чем заменить рабочий вендорский комплект наугад.
    """
    parts = version_tuple(driver_version)
    if not parts:
        return False
    return parts < MIN_SAFE_VERSION


def download_official_tap(destination: str,
                          log: Optional[Callable[[str], None]] = None,
                          progress: Optional[Callable[[int, int], None]] = None,
                          cancel: Optional[Callable[[], bool]] = None,
                          timeout: float = 30.0) -> str:
    """Скачать и распаковать официальный TAP; вернуть папку с файлами.

    Сеть здесь такая же ненадёжная, как при загрузке редистрибутивов:
    оборванная закачка не должна оставлять огрызок архива, поэтому файл
    пишется в ``.part`` и переименовывается только целиком.
    """
    import urllib.request

    say = log or (lambda _message: None)
    os.makedirs(destination, exist_ok=True)
    archive = os.path.join(destination, "tap-windows.zip")
    temporary = archive + ".part"
    say(f"Скачиваю официальный TAP-Windows {OFFICIAL_TAP_VERSION} "
        "(проект OpenVPN)…")
    try:
        request = urllib.request.Request(OFFICIAL_TAP_URL, headers={
            "User-Agent": _USER_AGENT,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        })
        done = 0
        total = -1
        with urllib.request.urlopen(request, timeout=timeout) as response, \
                open(temporary, "wb") as fh:
            length = response.headers.get("Content-Length")
            try:
                total = int(length) if length else -1
            except (TypeError, ValueError):
                total = -1
            while True:
                if cancel is not None and cancel():
                    raise RuntimeError("загрузка отменена пользователем")
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if progress is not None:
                    progress(done, total)
        if total > 0 and done < total:
            raise IOError(
                f"получено {done} Б из {total} Б — соединение оборвалось")
        os.replace(temporary, archive)
    except Exception:
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise
    extracted = os.path.join(destination, "driver")
    try:
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                # Архив приходит из сети: пути вида ../../ не должны
                # вывести распаковку за пределы своей папки.
                target = os.path.normpath(os.path.join(extracted, name))
                if not target.startswith(os.path.abspath(extracted) + os.sep) \
                        and target != os.path.abspath(extracted):
                    raise ValueError(f"небезопасный путь в архиве: {name}")
            os.makedirs(extracted, exist_ok=True)
            zf.extractall(extracted)
    except zipfile.BadZipFile as exc:
        raise IOError(f"архив драйвера повреждён: {exc}") from exc
    finally:
        try:
            os.remove(archive)
        except OSError:
            pass
    say(f"Официальный драйвер распакован: {extracted}")
    return extracted


def check_catalog_signature(directory: str) -> Tuple[Optional[bool], str]:
    """Подписан ли ``.cat`` доверенным издателем (проверка самой Windows).

    Возвращает ``(None, ...)`` вне Windows: здесь подпись проверить нечем,
    но это не повод считать пакет плохим — при установке Windows проверит
    её сама и откажет, если что-то не так.
    """
    if os.name != "nt":
        return None, "подпись будет проверена Windows при установке"
    catalogs: List[str] = []
    for current, _dirs, files in os.walk(directory):
        for name in files:
            if name.lower().endswith(".cat"):
                catalogs.append(os.path.join(current, name))
    if not catalogs:
        return False, "в пакете нет каталога подписи (.cat)"
    path = catalogs[0].replace("'", "''")
    command = ("(Get-AuthenticodeSignature -LiteralPath '" + path + "').Status")
    try:
        done = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", command],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"подпись проверить не удалось: {exc}"
    status = (done.stdout or "").strip()
    if status.lower() == "valid":
        return True, "подпись каталога действительна"
    return False, f"подпись каталога: {status or 'неизвестна'}"


def cleanup(directory: str) -> None:
    """Убрать временную папку загрузки."""
    shutil.rmtree(directory, ignore_errors=True)
