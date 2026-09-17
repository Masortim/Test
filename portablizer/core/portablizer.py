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
    extra_install_args: List[str] = field(default_factory=list)
    extra_env: Dict[str, str] = field(default_factory=dict)
    install_timeout: int = 1800        # сек


@dataclass
class PortableResult:
    success: bool
    portable_dir: str = ""
    main_exe_rel: str = ""
    detection: Optional[DetectionResult] = None
    plan: Optional[SilentPlan] = None
    reg_file: str = ""
    messages: List[str] = field(default_factory=list)


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
            "Launch.bat", "launcher.py", "launcher_config.json",
            "README_PORTABLE.txt", "portable.reg", "install.log",
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

            # 4. Тихая установка
            self._check_cancel()
            self.progress(30, "Тихая установка в изолированном режиме")
            install_rc = self._run_install(plan, opts, app_dir, data_dir)

            # 5. Снимок реестра ПОСЛЕ + diff
            after = {}
            if opts.capture_registry and IS_WINDOWS:
                self._check_cancel()
                self.progress(65, "Снимок реестра (после установки)")
                self.log.info("Делаю снимок реестра после установки...")
                after = reg_mod.snapshot()
                reg_text = reg_mod.diff_to_reg(before, after)
                reg_path = os.path.join(portable_dir, "portable.reg")
                with open(reg_path, "w", encoding="utf-16") as fh:
                    fh.write(reg_text)
                result.reg_file = reg_path
                self.log.ok(f"Изменения реестра сохранены: {reg_path}")

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
                                 opts, path_prepend)

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

    def _snapshot_install_locations(self, data_dir: str) -> Dict[str, Set[str]]:
        """Запоминает непосредственных потомков типовых мест установки."""
        snapshot: Dict[str, Set[str]] = {}
        for root, _priority, _owned in self._install_search_roots(data_dir):
            entries: Set[str] = set()
            try:
                with os.scandir(root) as iterator:
                    for entry in iterator:
                        entries.add(os.path.normcase(os.path.abspath(entry.path)))
            except OSError:
                pass
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
            try:
                entries = list(os.scandir(root))
            except OSError:
                continue
            for entry in entries:
                entry_path = os.path.abspath(entry.path)
                is_new = os.path.normcase(entry_path) not in old_entries
                name_match = self._name_score(entry.name, keys) > 0
                if not (is_new or name_match):
                    continue
                # Прямой exe безопасно копируем отдельно. Для каталога берём
                # всё его дерево (dll/resources должны остаться рядом).
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    is_exe = entry.is_file(follow_symlinks=False) and entry.name.lower().endswith(".exe")
                except OSError:
                    continue
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
                        opts: PortableOptions, path_prepend: List[str]) -> None:
        cfg = launcher_mod.LauncherConfig(
            app_name=name,
            target_exe_rel=main_exe_rel,
            data_dir_name="PortableData",
            apply_registry=opts.capture_registry,
            extra_env=opts.extra_env,
            path_prepend=path_prepend,
        )
        # Launch.bat — обязательно CRLF и UTF-8 без BOM: cmd.exe не переваривает
        # ни LF-концы строк в многострочных блоках, ни BOM в первой строке.
        bat = launcher_mod.render_bat(cfg)
        with open(os.path.join(portable_dir, "Launch.bat"), "w",
                  encoding="utf-8", newline="\r\n") as fh:
            fh.write(bat)
        # config json (для launcher.exe)
        with open(os.path.join(portable_dir, "launcher_config.json"), "w",
                  encoding="utf-8") as fh:
            fh.write(launcher_mod.render_config_json(cfg))
        # launcher.py (опционально — для сборки launcher.exe)
        if opts.build_exe_launcher:
            with open(os.path.join(portable_dir, "launcher.py"), "w",
                      encoding="utf-8") as fh:
                fh.write(launcher_mod.render_py_launcher(cfg))
        # README
        with open(os.path.join(portable_dir, "README_PORTABLE.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(_README.format(app_name=name, main_exe_rel=main_exe_rel))
        self.log.ok("Лончер и сопроводительные файлы созданы.")


_README = """{app_name} — портативная версия
================================================================

Как пользоваться:
  1. Скопируйте всю эту папку на флешку/другой ПК/в любое место.
  2. Запустите Launch.bat — программа стартует в изолированном режиме.

Что внутри:
  App\\                  — установленная программа ({main_exe_rel})
  PortableData\\         — все пользовательские данные (AppData, Temp, реестр-импорт)
  Launch.bat            — портативный лончер (перенаправляет каталоги и env)
  launcher_config.json  — параметры лончера
  portable.reg          — захваченные при установке изменения реестра (если были)
  install.log           — подробный журнал установщика (если он поддерживается)
  portablizer.log       — журнал создания и диагностики портатива

При запуске стандартные каталоги профиля (AppData, Temp и др.) перенаправляются
в PortableData. Отдельные программы могут обращаться к системным каталогам или
реестру напрямую — полную виртуализацию Windows этот лончер не выполняет.

Если окно консоли закрывается сразу:
  • запустите Launch.bat из уже открытой консоли (cmd.exe) — вы увидите текст
    ошибки; при ненулевом коде возврата лончер сам делает паузу;
  • проверьте, что путь в строке TARGET внутри Launch.bat указывает на
    существующий exe (его можно поправить вручную);
  • для запуска без паузы используйте: Launch.bat --nopause

Сгенерировано Portablizer.
"""
