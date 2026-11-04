"""Полный пакет драйвера — прямо из установщика, без установки в систему.

Зачем отдельный модуль
----------------------
``netstack`` умеет брать драйвер из ``App`` и из системы сборочного ПК
(``DriverStore``, ``Program Files\\TAP-Windows``). Но у этого есть предел:
если установщик VPN-клиента **не поставил** драйвер на машину сборки (или
поставил другую разрядность, или сборка вообще шла распаковкой без запуска),
брать его неоткуда, и портатив уезжал с одним ``OemVista.inf``. На чистом ПК
``pnputil`` отвечал «Не удается найти указанный файл»: рядом не было
``tap0901.sys``/``.cat``.

При этом установщик почти всегда **несёт драйвер внутри себя**: NSIS
раскладывает ``tap0901.sys``/``.cat``/``OemVista.inf`` в ``$PLUGINSDIR`` или
вложенным ``tap-windows-9.x.exe``, Inno — в ``{tmp}``, MSI — в CAB. Значит
пакет можно достать, не устанавливая ничего: распаковать контейнер
(``unpacker`` уже умеет 7-Zip/WinRAR/``tar.exe``), найти внутри пакет
драйвера и проверить, что он полный.

Что здесь есть
--------------
* :func:`harvest_into` — главная точка входа: вскрыть установщик (и
  вложенные установщики драйверов), скопировать найденные ПОЛНЫЕ пакеты в
  указанную папку и вернуть их описание. Временные файлы удаляются всегда.
* :func:`harvest_driver_packages` — то же без копирования; working directory
  принадлежит вызывающей стороне (она же его и удаляет).
* :func:`find_driver_installers` — вложенные установщики драйверов
  (``tap-windows-*.exe``, ``wintun.msi``, ...) в распакованном дереве.

Модуль ничего не устанавливает и не пишет в систему: только читает
установщик и пишет в рабочую папку. Если распаковщика на машине нет, это не
ошибка сборки — возвращается пустой отчёт, а ``netstack`` продолжает
работать по-старому (App + DriverStore).
"""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from . import netstack, unpacker

#: Сколько уровней вложенных установщиков вскрывать. VPN-клиент кладёт
#: ``tap-windows-9.24.2.exe`` внутрь своего NSIS — это уровень 2; глубже
#: начинается payload самой программы, драйверов там нет.
MAX_NESTED_DEPTH = 2

#: Потолок размера контейнера, который вскрываем: гигантские игровые
#: дистрибутивы распаковывать ради драйвера незачем.
MAX_INSTALLER_BYTES = 2 * 1024 * 1024 * 1024

#: Потолок файлов в распакованном дереве, чтобы не уйти в минуты.
MAX_SCANNED_FILES = 20_000


@dataclass
class HarvestReport:
    """Что удалось достать из установщика (для журнала сборки)."""

    packages: List["netstack.NetDriverPackage"] = field(default_factory=list)
    #: Человекочитаемые шаги: что вскрыли, что нашли, почему остановились.
    notes: List[str] = field(default_factory=list)
    #: Распаковщик, которым реально прочитали контейнер.
    extractor_used: str = ""

    @property
    def found(self) -> bool:
        return bool(self.packages)


def find_driver_installers(root: str,
                          max_files: int = MAX_SCANNED_FILES) -> List[str]:
    """Вложенные установщики драйверов внутри распакованного дерева.

    Ищутся те же имена, что ``netstack`` считает пакетными
    (``tap-windows-*.exe``, ``tapinstall-*.msi``, ``wintun.cab``,
    ``ovpn-dco-*.msi``): именно их вендор кладёт внутрь своего установщика.
    """
    found: List[str] = []
    if not root or not os.path.isdir(root):
        return found
    scanned = 0
    for current, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            scanned += 1
            if scanned > max_files:
                return found
            if netstack._PACKAGE_RE.search(name):
                found.append(os.path.join(current, name))
    return found


def _extract(container: str, destination: str,
             extractor: "unpacker.Extractor",
             runner: Optional[Callable] = None,
             timeout: Optional[float] = 300.0) -> bool:
    """Распаковать контейнер, не запуская его. Успех — если легли файлы."""
    try:
        if os.path.getsize(container) > MAX_INSTALLER_BYTES:
            return False
        os.makedirs(destination, exist_ok=True)
    except OSError:
        return False
    cmd = unpacker.extractor_argv(extractor, container, destination)
    run = runner or unpacker._default_runner
    try:
        code, _output = run(cmd, timeout)
    except Exception:  # noqa: BLE001 — распаковка не должна ронять сборку
        return False
    # 1 у 7-Zip — предупреждение, а не отказ: доставшееся всё равно годится.
    if code not in (0, 1):
        return False
    return any(files for _c, _d, files in os.walk(destination))


def _prune_to_package_files(package: "netstack.NetDriverPackage"
                            ) -> "netstack.NetDriverPackage":
    """Оставить в пакете только его собственные файлы.

    ``_package_from_directory`` собирает ВСЕХ соседей INF — для выделенного
    каталога DriverStore это правильно. Но в распакованном установщике INF
    нередко лежит в корне, рядом с payload самой программы: без отбора
    ``planetvpn.exe`` и ``resources/app.asar`` уехали бы в NetStack/Drivers.
    Ориентир — сам INF (``SourceDisksFiles`` + ``CatalogFile``), а не
    расширение файла. Утилита установки (tapinstall/devcon) сохраняется.
    """
    wanted = {os.path.normpath(rel.replace("/", os.sep)).lower()
              for rel in package.required_files if rel}
    base = os.path.dirname(package.inf_path)
    kept: List[str] = []
    for path in package.file_paths:
        rel = os.path.relpath(path, base).lower()
        name = os.path.basename(path).lower()
        is_tool = name.startswith(("tapinstall", "devcon")) and \
            name.endswith(".exe")
        if rel in wanted or name in wanted or is_tool:
            kept.append(path)
    package.file_paths = kept
    return _attach_local_tool(package)


def _attach_local_tool(package: "netstack.NetDriverPackage"
                       ) -> "netstack.NetDriverPackage":
    """Назвать вендорскую утилиту установки, лежащую рядом с INF.

    Скопировать ``tapinstall.exe`` недостаточно: без ``tool_path``
    ``provision_netstack`` оставлял ``entry["tool"]`` пустым, и Setup шёл
    запасным путём через SetupAPI вместо штатного tapinstall (сборка
    devcon), который создаёт devnode и ставит драйвер одной операцией.
    """
    for path in package.file_paths:
        name = os.path.basename(path).lower()
        if name.startswith(("tapinstall", "devcon")) and name.endswith(".exe"):
            package.tool_path = path
            break
    return package


def _packages_in(root: str, origin: str) -> List["netstack.NetDriverPackage"]:
    """Полные пакеты драйверов в дереве (неполные отбрасываются сразу).

    Ориентир — INF: так пакет описан и в DriverStore, и у вендора. Годится
    и TAP/ovpn-dco (``needs_install``), и wintun, если он поставлен с INF
    (``wintun.msi`` его содержит). Дистрибутив wintun из одного
    ``wintun.dll`` без INF здесь не собирается: устанавливать его нечем,
    такой файл и так уезжает вместе с самой программой.
    """
    result: List[netstack.NetDriverPackage] = []
    scanned = 0
    for current, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            scanned += 1
            if scanned > MAX_SCANNED_FILES:
                return result
            if not name.lower().endswith(".inf"):
                continue
            package = netstack._package_from_directory(
                os.path.join(current, name), origin)
            if package is None:
                continue
            # Ради этого модуль и написан: наружу идёт только ПАКЕТ ЦЕЛИКОМ,
            # иначе сборка снова получила бы «inf без sys» и красивый отчёт.
            package = _prune_to_package_files(package)
            if netstack.is_complete_driver_package(package):
                result.append(package)
    return result


def _collect(container: str, work: str, depth: int,
             extractor: "unpacker.Extractor", runner: Optional[Callable],
             arch: str, report: HarvestReport, label: str
             ) -> List["netstack.NetDriverPackage"]:
    """Вскрыть контейнер и собрать пакеты, рекурсивно вскрывая вложенные."""
    packages = _packages_in(work, "installer")
    if packages:
        report.notes.append(
            f"драйвер найден {label}: "
            + ", ".join(sorted({p.check_service or p.kind for p in packages})))
    if depth <= 0:
        return packages
    for index, nested in enumerate(find_driver_installers(work)):
        dest = os.path.join(work, f"_nested{index}")
        if not _extract(nested, dest, extractor, runner):
            continue
        packages.extend(_collect(
            nested, dest, depth - 1, extractor, runner, arch, report,
            f"во вложенном установщике {os.path.basename(nested)}"))
    return packages


def _extract_cabinet(container: str, destination: str) -> bool:
    """Достать кабинеты из ``.cab``/``.msi``/SFX-``.exe`` своим распаковщиком."""
    from . import cabinet

    try:
        if not cabinet.contains_cabinet(container):
            return False
        os.makedirs(destination, exist_ok=True)
        return bool(cabinet.extract_file(container, destination))
    except Exception:  # noqa: BLE001 — свой распаковщик тоже не должен ронять
        return False


def _collect_cabinet(root: str, depth: int, report: HarvestReport,
                     arch: str) -> List["netstack.NetDriverPackage"]:
    """Пакеты из распакованного кабинета + вложенные кабинеты/установщики."""
    from . import cabinet

    packages = _packages_in(root, "installer")
    if packages:
        report.notes.append(
            "драйвер найден в кабинете установщика: "
            + ", ".join(sorted({p.check_service or p.kind for p in packages})))
    if depth <= 0:
        return packages
    for index, nested in enumerate(find_driver_installers(root)):
        dest = os.path.join(root, f"_cab{index}")
        if not _extract_cabinet(nested, dest):
            continue
        try:
            inner = _collect_cabinet(dest, depth - 1, report, arch)
        except cabinet.CabinetError:
            continue
        if inner:
            report.notes.append(
                "драйвер найден во вложенном пакете "
                f"{os.path.basename(nested)}")
        packages.extend(inner)
    return packages


def harvest_driver_packages(installer_path: str, work_dir: str,
                            extractors: Optional[Sequence[
                                "unpacker.Extractor"]] = None,
                            runner: Optional[Callable] = None,
                            arch: str = "",
                            max_depth: int = MAX_NESTED_DEPTH
                            ) -> HarvestReport:
    """Достаёт полные пакеты драйверов из установщика, ничего не ставя.

    ``work_dir`` принадлежит ВЫЗЫВАЮЩЕЙ стороне: пути в возвращённых
    пакетах указывают внутрь него, поэтому удалять его можно только после
    того, как файлы скопированы (этим и занимается :func:`harvest_into`).

    Пустой отчёт — не ошибка, а «в этом установщике драйверов нет / нечем
    распаковать».
    """
    report = HarvestReport()
    if not installer_path or not os.path.isfile(installer_path):
        report.notes.append("установщик недоступен — драйверы из него не взяты")
        return report
    try:
        if os.path.getsize(installer_path) > MAX_INSTALLER_BYTES:
            report.notes.append("установщик слишком большой для распаковки "
                                "ради драйверов")
            return report
    except OSError:
        return report

    # Сначала собственный распаковщик кабинетов: он не требует ни 7-Zip, ни
    # tar.exe и читает CAB внутри .msi и SFX-.exe (IExpress/WiX). Именно так
    # драйвер достаётся на машине, где вообще нет сторонних распаковщиков.
    cab_root = os.path.join(work_dir, "cabinet")
    if _extract_cabinet(installer_path, cab_root):
        report.extractor_used = "cabinet"
        packages = _collect_cabinet(cab_root, max_depth, report, arch)
        if packages:
            report.packages = netstack._rank_system_packages(packages, arch)
            return report

    available = list(extractors) if extractors is not None else \
        unpacker.find_extractors()
    if not available:
        if not report.extractor_used:
            report.notes.append(
                "распаковщик не найден (7-Zip/WinRAR/tar.exe) — драйверы взяты "
                "только из App и системы этого ПК")
        return report

    for extractor in available:
        root = os.path.join(work_dir, extractor.style)
        if not _extract(installer_path, root, extractor, runner):
            continue
        report.extractor_used = extractor.name
        packages = _collect(installer_path, root, max_depth, extractor,
                            runner, arch, report,
                            f"внутри установщика ({extractor.name})")
        if packages:
            report.packages = netstack._rank_system_packages(packages, arch)
            return report
        report.notes.append(
            f"{extractor.name} вскрыл установщик, но полного пакета "
            "драйвера внутри нет")
    if not report.extractor_used:
        report.notes.append("ни один распаковщик не смог прочитать установщик")
    return report


def harvest_into(installer_path: str, destination: str,
                 extractors: Optional[Sequence["unpacker.Extractor"]] = None,
                 runner: Optional[Callable] = None,
                 arch: str = "") -> HarvestReport:
    """:func:`harvest_driver_packages` + копирование пакетов в ``destination``.

    Наружу отдаются пакеты с путями, уже лежащими в ``destination``, поэтому
    временная папка распаковки удаляется всегда и сборка не оставляет мусор.
    """
    report = HarvestReport()
    try:
        os.makedirs(destination, exist_ok=True)
    except OSError as exc:
        report.notes.append(f"некуда сложить драйверы из установщика: {exc}")
        return report
    work = tempfile.mkdtemp(prefix="portablizer-drivers-")
    try:
        report = harvest_driver_packages(
            installer_path, work, extractors=extractors, runner=runner,
            arch=arch)
        if not report.packages:
            return report
        moved: List[netstack.NetDriverPackage] = []
        for index, package in enumerate(report.packages):
            source_dir = os.path.dirname(package.inf_path)
            target = os.path.join(destination, f"pkg{index}")
            # Копируется ТОЛЬКО сам пакет (INF + его файлы), а не всё
            # распакованное дерево: INF может лежать в корне, где рядом
            # лежит payload всей программы на сотни мегабайт.
            sources = [package.inf_path] + list(package.file_paths)
            try:
                os.makedirs(target, exist_ok=True)
                for src in sources[:netstack._MAX_PACKAGE_FILES + 1]:
                    if not os.path.isfile(src):
                        continue
                    rel = os.path.relpath(src, source_dir)
                    if rel.startswith(os.pardir):
                        rel = os.path.basename(src)
                    dest = os.path.join(target, rel)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copy2(src, dest)
            except (OSError, shutil.Error):
                report.notes.append(
                    f"не удалось скопировать пакет {package.check_service}")
                continue
            rebased = netstack._package_from_directory(
                os.path.join(target, os.path.basename(package.inf_path)),
                package.origin)
            if rebased is not None:
                moved.append(_attach_local_tool(rebased))
        report.packages = moved
        return report
    finally:
        shutil.rmtree(work, ignore_errors=True)
