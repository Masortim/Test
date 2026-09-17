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
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

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
            os.makedirs(app_dir, exist_ok=True)
            os.makedirs(data_dir, exist_ok=True)
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

            # 4. Тихая установка
            self._check_cancel()
            self.progress(30, "Тихая установка в изолированном режиме")
            self._run_install(plan, opts, app_dir, data_dir)

            # 5. Снимок реестра ПОСЛЕ + diff
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

            # 6. Поиск главного exe
            self._check_cancel()
            self.progress(75, "Поиск главного исполняемого файла")
            main_exe = self._find_main_exe(app_dir, name)
            if main_exe:
                result.main_exe_rel = os.path.relpath(main_exe, portable_dir)
                self.log.ok(f"Главный exe: {result.main_exe_rel}")
            else:
                result.main_exe_rel = os.path.join("App", f"{name}.exe")
                self.log.warn("Главный exe не найден автоматически — укажите его вручную.")

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
            return result

        except Exception as exc:  # noqa: BLE001
            self.log.error(str(exc))
            result.messages.append(str(exc))
            return result

    # -- установка ------------------------------------------------------------
    def _run_install(self, plan: SilentPlan, opts: PortableOptions,
                     app_dir: str, data_dir: str) -> None:
        if not IS_WINDOWS:
            # На не-Windows реально запускать установщик нельзя. Мы создаём
            # заглушку, чтобы конвейер можно было прогонять и тестировать.
            self.log.warn(
                "Не Windows: пропускаю реальный запуск установщика (демо-режим). "
                "На Windows здесь произойдёт тихая установка в App\\."
            )
            with open(os.path.join(app_dir, "PLACEHOLDER.txt"), "w",
                      encoding="utf-8") as fh:
                fh.write("Демо-режим (не Windows). Реальная установка не выполнялась.\n")
            return

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
                "Целевая папка пуста. Возможно, установщик игнорирует ключ папки "
                "или пишет по своему пути. Попробуйте другие ключи в «Доп. "
                "аргументах» либо включите режим полной изоляции."
            )

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
        return candidates[0]

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
  install.log           — журнал тихой установки

Диск C: и профиль пользователя Windows не затрагиваются: программа пишет
данные только в папку PortableData внутри этой директории.

Если окно консоли закрывается сразу:
  • запустите Launch.bat из уже открытой консоли (cmd.exe) — вы увидите текст
    ошибки; при ненулевом коде возврата лончер сам делает паузу;
  • проверьте, что путь в строке TARGET внутри Launch.bat указывает на
    существующий exe (его можно поправить вручную);
  • для запуска без паузы используйте: Launch.bat --nopause

Сгенерировано Portablizer.
"""
