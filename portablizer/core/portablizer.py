"""Оркестратор процесса создания портативного приложения.

Порядок работы:
  1. detect          — определить движок установщика.
  2. plan            — построить команду тихой установки в целевую папку.
  3. snapshot(before)— снять состояние реестра (Windows).
  4. install         — запустить установщик тихо и изолированно, дождаться.
  5. snapshot(after) — снять состояние реестра и сохранить diff в portable.reg.
  6. detect_main_exe — найти главный exe установленной программы.
  7. gather_deps     — эвристически собрать/скопировать зависимости (VC++ и т.п.).
  8. launcher        — сгенерировать Launch.bat / launcher_config.json / launcher.py.

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
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from .. import __version__
from . import launcher as launcher_mod
from . import registry as reg_mod
from .detect import DetectionResult, InstallerType, detect_installer
from .logutil import Logger
from .silentargs import SilentPlan, build_silent_plan

ProgressCB = Callable[[int, str], None]

IS_WINDOWS = sys.platform.startswith("win")


@dataclass
class PortableOptions:
    installer_path: str
    output_dir: str                    # куда положить портативную папку
    app_name: str = ""                 # имя приложения (для папки/лончера)
    redirect_userdirs: bool = True     # изолировать AppData/Temp/...
    capture_registry: bool = True      # захватывать изменения реестра
    build_exe_launcher: bool = False   # генерировать launcher.py для сборки exe
    # Удалять следы установки (в т.ч. запись в «Установленные программы») с
    # компьютера, на котором создаётся портатив.
    cleanup_host: bool = True
    # Переносить ассоциации файлов/COM. По умолчанию выключено: чужому ПК это
    # не нужно, а портативность от этого только страдает.
    include_shell_integration: bool = False
    extra_install_args: List[str] = field(default_factory=list)
    extra_env: Dict[str, str] = field(default_factory=dict)
    install_timeout: int = 1800        # сек


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


class Portablizer:
    def __init__(self, logger: Logger,
                 progress: Optional[ProgressCB] = None,
                 cancel_event: Optional[threading.Event] = None) -> None:
        self.log = logger
        self.progress = progress or (lambda p, s: None)
        self.cancel = cancel_event or threading.Event()

    # -- вспомогательное ------------------------------------------------------
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

    def _prepare_output(self, portable_dir: str, app_dir: str,
                        data_dir: str) -> None:
        """Готовит чистый App и удаляет лончер от незавершённого запуска.

        ``PortableData`` намеренно сохраняется: пользователь мог повторно
        собрать уже используемый портатив, и удалять его настройки нельзя.
        Программные файлы, напротив, должны соответствовать только текущему
        установщику — иначе старый exe маскирует неудачную установку.
        """
        os.makedirs(portable_dir, exist_ok=True)
        if os.path.isdir(app_dir):
            shutil.rmtree(app_dir)
        elif os.path.exists(app_dir):
            os.remove(app_dir)
        os.makedirs(app_dir, exist_ok=True)
        os.makedirs(data_dir, exist_ok=True)

        for filename in (
            "Launch.bat", "LaunchHidden.vbs", "launcher.py",
            "launcher_config.json", "README_PORTABLE.txt", "portable.reg",
            "portable_machine.reg", "cleanup_host.reg", "install.log",
            "portablizer.log",
        ):
            path = os.path.join(portable_dir, filename)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.exists(path):
                    os.remove(path)
            except OSError as exc:
                raise RuntimeError(
                    f"Не удалось очистить старый файл результата: {path}: {exc}"
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
            self.progress(2, "Проверка входных данных")
            if not os.path.isfile(opts.installer_path):
                raise FileNotFoundError(f"Установщик не найден: {opts.installer_path}")

            name = self._safe_name(opts)
            portable_dir = os.path.join(opts.output_dir, f"{name}_Portable")
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

            # 2. План тихой установки
            self.progress(15, "Построение команды тихой установки")
            log_file = os.path.join(portable_dir, "install.log")
            plan = build_silent_plan(
                det.installer_type, opts.installer_path, app_dir,
                is_msi=det.is_msi, log_file=log_file,
                extra_args=opts.extra_install_args,
            )
            result.plan = plan
            self.log.info(f"Команда: {plan.display()}")
            for n in plan.notes:
                self.log.debug(f"  • {n}")

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

            # 4. Тихая установка
            self._check_cancel()
            self.progress(30, "Тихая установка в изолированном режиме")
            install_rc = self._run_install(plan, opts, app_dir, data_dir)

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

            # 6. Поиск главного exe. Не создаём заведомо сломанный Launch.bat:
            # отсутствие exe означает, что тихая установка фактически не дала
            # портативного результата, даже если установщик вернул код 0.
            self._check_cancel()
            self.progress(75, "Поиск главного исполняемого файла")
            main_exe = self._find_main_exe(app_dir, name)
            if not main_exe:
                rc_hint = (
                    "" if install_rc is None or install_rc in (0, 3010)
                    else f" (код установщика: {install_rc})"
                )
                raise RuntimeError(
                    "Установщик завершился, но в папке App не найден ни один "
                    f"исполняемый файл{rc_hint}. Портатив не создан. Возможно, "
                    "установщик не поддерживает тихий режим или использует "
                    "другие ключи. Проверьте portablizer.log (и install.log, "
                    "если он создан) и укажите подходящие ключи в поле "
                    "«Доп. аргументы установки»."
                )
            result.main_exe_rel = os.path.relpath(main_exe, portable_dir)
            self.log.ok(f"Главный exe: {result.main_exe_rel}")

            # 7. Зависимости и переменные среды
            self.progress(85, "Учёт зависимостей и переменных среды")
            path_prepend = self._collect_dep_dirs(app_dir, portable_dir)

            # 8. Генерация лончера
            self._check_cancel()
            self.progress(92, "Генерация портативного лончера")
            self._write_launcher(portable_dir, name, result.main_exe_rel,
                                 opts, path_prepend, capture)

            # 9. Уборка следов установки с ЭТОГО компьютера: программа не
            # должна остаться в списке «Установленные программы».
            self.progress(97, "Удаление следов установки с этого ПК")
            if capture is not None:
                self._cleanup_host(capture, opts, result)
            if opts.cleanup_host:
                self._cleanup_shortcuts(shortcuts_before, result)

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

        reg_path = os.path.join(portable_dir, "portable.reg")
        user_text = reg_mod.render_keys(after, user_keys, tokens)
        if reg_mod.has_entries(user_text):
            reg_mod.write_reg_file(reg_path, user_text)
            capture.reg_file = reg_path
            capture.has_root_token = launcher_mod.ROOT_TOKEN in user_text

        if machine_keys:
            machine_path = os.path.join(portable_dir, "portable_machine.reg")
            machine_text = reg_mod.render_keys(after, machine_keys, tokens)
            if reg_mod.has_entries(machine_text):
                reg_mod.write_reg_file(machine_path, machine_text)
                capture.machine_reg_file = machine_path

        capture.keys = launcher_mod.usable_registry_keys(portable_keys)
        capture.created_keys = launcher_mod.usable_registry_keys(
            [k for k in diff.new_keys if k in set(capture.keys)]
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
                    "Импортируйте cleanup_host.reg, чтобы убрать её."
                )
            return
        if not capture.cleanup_file or not IS_WINDOWS:
            return

        rc = self._reg_import(capture.cleanup_file)
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
        self.log.warn(
            "Не удалось полностью удалить следы установки (обычно нужны права "
            "администратора). Запустите cleanup_host.reg вручную: "
            f"{capture.cleanup_file}"
        )

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

    # -- установка ------------------------------------------------------------
    def _run_install(self, plan: SilentPlan, opts: PortableOptions,
                     app_dir: str, data_dir: str) -> Optional[int]:
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

        creationflags = 0x08000000  # CREATE_NO_WINDOW
        self.log.info("Запуск установщика (тихо, изолированно)...")
        try:
            if plan.raw_tail:
                cmdline = subprocess.list2cmdline(cmd) + " " + plan.raw_tail
                self.log.debug(f"cmdline: {cmdline}")
                proc = subprocess.Popen(cmdline, env=env,
                                        creationflags=creationflags)
            else:
                proc = subprocess.Popen(cmd, env=env,
                                        creationflags=creationflags)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Не удалось запустить установщик: {exc}") from exc

        start = time.time()
        while proc.poll() is None:
            if self.cancel.is_set():
                proc.terminate()
                raise RuntimeError("Установка отменена пользователем.")
            if time.time() - start > opts.install_timeout:
                proc.terminate()
                raise RuntimeError("Превышено время ожидания установки.")
            # плавный прогресс во время установки: 30 -> 60
            frac = min(1.0, (time.time() - start) / 60.0)
            self.progress(30 + int(30 * frac), "Тихая установка...")
            time.sleep(0.5)

        rc = proc.returncode
        if rc not in (0, 3010):  # 3010 = успех, требуется перезагрузка
            self.log.warn(f"Установщик вернул код {rc}. Проверьте install.log.")
        else:
            self.log.ok(f"Установка завершена (код {rc}).")

        # Проверим, что что-то реально установилось.
        try:
            entries = os.listdir(app_dir)
        except OSError:
            entries = []
        if not entries:
            self.log.warn(
                "Целевая папка пуста. Установщик мог проигнорировать ключ папки; "
                "проверяю перенаправленный профиль и системные каталоги установки."
            )
        return rc

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
                name_match = self._name_score(entry_name, keys) > 0
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
    def _find_main_exe(self, app_dir: str, name: str) -> Optional[str]:
        candidates: List[str] = []
        for root, _dirs, files in os.walk(app_dir):
            for f in files:
                if f.lower().endswith(".exe"):
                    candidates.append(os.path.join(root, f))
        if not candidates:
            return None

        name_l = name.lower()
        # Отсеиваем очевидные вспомогательные утилиты.
        bad = ("unins", "setup", "vcredist", "vc_redist", "dxsetup", "update",
               "helper", "crashpad", "crashreport", "install", "redist")

        def score(p: str) -> int:
            base = os.path.basename(p).lower()
            s = 0
            if name_l and name_l in base:
                s += 100
            if any(b in base for b in bad):
                s -= 60
            # exe в корне App/ обычно главный
            depth = os.path.relpath(p, app_dir).count(os.sep)
            s -= depth * 5
            try:
                s += min(30, int(os.path.getsize(p) / (1024 * 1024)))  # крупнее — вероятнее
            except OSError:
                pass
            return s

        candidates.sort(key=score, reverse=True)
        best = candidates[0]
        # Один uninstaller/setup.exe не является запускаемым приложением.
        return best if score(best) >= 0 else None

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

    # -- лончер ---------------------------------------------------------------
    def _write_launcher(self, portable_dir: str, name: str, main_exe_rel: str,
                        opts: PortableOptions, path_prepend: List[str],
                        capture: Optional[RegistryCapture] = None) -> None:
        has_registry = bool(
            capture and (capture.reg_file or capture.machine_reg_file
                         or capture.keys)
        )
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
        # config json (для launcher.exe)
        self._write_text(os.path.join(portable_dir, "launcher_config.json"),
                         launcher_mod.render_config_json(cfg), newline="\n")
        # launcher.py (опционально — для сборки launcher.exe)
        if opts.build_exe_launcher:
            self._write_text(os.path.join(portable_dir, "launcher.py"),
                             launcher_mod.render_py_launcher(cfg),
                             newline="\n")
        # README
        registry_note = (
            "portable.reg           - настройки программы (переносятся с папкой)\n"
            if capture and capture.reg_file else ""
        )
        self._write_text(
            os.path.join(portable_dir, "README_PORTABLE.txt"),
            _README.format(app_name=name, main_exe_rel=main_exe_rel,
                           registry_note=registry_note),
        )
        self.log.ok("Лончер и сопроводительные файлы созданы.")

    @staticmethod
    def _write_text(path: str, text: str, encoding: str = "utf-8",
                    newline: str = "\r\n") -> None:
        with open(path, "w", encoding=encoding, newline=newline) as fh:
            fh.write(text)


_README = """{app_name} — портативная версия
================================================================

Как пользоваться:
  1. Скопируйте ВСЮ эту папку на флешку, другой ПК или в любое место.
  2. Запустите Launch.bat — программа стартует в изолированном режиме.
     LaunchHidden.vbs запускает то же самое, но без окна консоли.

Устанавливать ничего не нужно: программа не появляется в списке
«Установленные программы» и не требует прав администратора.

Что внутри:
  App\\                  — установленная программа ({main_exe_rel})
  PortableData\\         — все пользовательские данные (AppData, Temp, настройки)
  Launch.bat            — портативный лончер (перенаправляет каталоги и env)
  LaunchHidden.vbs      — запуск без окна консоли
  launcher_config.json  — параметры лончера
{registry_note}  install.log           — подробный журнал установщика (если он поддерживается)
  portablizer.log       — журнал создания и диагностики портатива

Ключи запуска (Launch.bat):
  --nopause         не ждать нажатия клавиши
  --pause           всегда ждать нажатия клавиши перед закрытием
  --no-registry     вообще не трогать реестр
  --keep-registry   оставить настройки в реестре после выхода
  --reset           забыть сохранённые настройки и стартовать «с нуля»
  --help            справка
  -- <аргументы>    передать аргументы самой программе

Как это работает:
  • стандартные каталоги профиля (AppData, Temp, Документы и др.) на время
    работы перенаправляются в PortableData — программа не пишет в C:\\Users;
  • если программе нужны записи реестра, лончер перед стартом сохраняет
    прежнее состояние чужого ПК, подставляет настройки из портатива, а после
    выхода выгружает изменения обратно в папку и возвращает реестр как было;
  • путь портативной папки внутри настроек хранится маркером, поэтому смена
    буквы диска или компьютера ничего не ломает.

Полной виртуализации Windows лончер не выполняет: отдельные программы могут
обращаться к системным каталогам напрямую.

Если окно консоли закрывается сразу:
  • запустите Launch.bat из уже открытой консоли (cmd.exe) — вы увидите текст
    ошибки; при ненулевом коде возврата лончер сам делает паузу;
  • убедитесь, что папка App скопирована целиком вместе с Launch.bat;
  • подробности — в portablizer.log.

Сгенерировано Portablizer.
"""
