"""Главное окно Portablizer (PySide6).

Компоновка сверху вниз:
  * Шапка: иконка, название, слоган.
  * Карточка 1 «Источник»: выбор exe/msi + автоопределение типа.
  * Карточка 2 «Назначение и параметры»: папка вывода, имя, чекбоксы изоляции,
    доп. аргументы, переменные среды.
  * Карточка 3 «Процесс»: прогресс-бар, статус, журнал.
  * Нижняя панель: кнопки «Создать портатив», «Отмена», «Открыть папку».
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from .. import __version__
from ..core.detect import detect_installer
from ..core.portablizer import PortableOptions, PortableResult
from . import style
from .worker import PortableWorker


def _resource(rel: str) -> str:
    """Путь к ресурсу и в исходниках, и внутри собранного exe (PyInstaller)."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, rel)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, rel)


def _card(title: str, badge: Optional[str] = None) -> "tuple[QFrame, QVBoxLayout]":
    frame = QFrame()
    frame.setObjectName("Card")
    outer = QVBoxLayout(frame)
    outer.setContentsMargins(18, 16, 18, 16)
    outer.setSpacing(12)
    header = QHBoxLayout()
    header.setSpacing(10)
    if badge:
        b = QLabel(badge)
        b.setObjectName("StepBadge")
        header.addWidget(b)
    t = QLabel(title)
    t.setObjectName("CardTitle")
    header.addWidget(t)
    header.addStretch(1)
    outer.addLayout(header)
    return frame, outer


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.worker: Optional[PortableWorker] = None
        self.last_result: Optional[PortableResult] = None

        self.setWindowTitle(
            f"Portablizer {__version__} — портативизатор установщиков"
        )
        self.setMinimumSize(940, 760)
        ico = _resource(os.path.join("resources", "app.ico"))
        if os.path.exists(ico):
            self.setWindowIcon(QIcon(ico))

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_header())

        # Прокручиваемая область с карточками.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        content.setObjectName("Root")
        scroll.setWidget(content)
        cl = QVBoxLayout(content)
        cl.setContentsMargins(22, 18, 22, 10)
        cl.setSpacing(16)

        cl.addWidget(self._build_source_card())
        cl.addWidget(self._build_options_card())
        cl.addWidget(self._build_process_card())
        cl.addStretch(1)
        outer.addWidget(scroll, 1)

        outer.addWidget(self._build_footer())

    # -- шапка ----------------------------------------------------------------
    def _build_header(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Root")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(22, 18, 22, 6)
        lay.setSpacing(14)

        png = _resource(os.path.join("resources", "app_256.png"))
        if os.path.exists(png):
            logo = QLabel()
            pm = QPixmap(png).scaled(56, 56, Qt.KeepAspectRatio,
                                     Qt.SmoothTransformation)
            logo.setPixmap(pm)
            lay.addWidget(logo)

        col = QVBoxLayout()
        col.setSpacing(2)
        title = QLabel(f"Portablizer {__version__}")
        title.setObjectName("Title")
        sub = QLabel("Создаёт переносимую папку из exe/msi-установщика "
                     "с изолированным пользовательским окружением")
        sub.setObjectName("Subtitle")
        col.addWidget(title)
        col.addWidget(sub)
        lay.addLayout(col)
        lay.addStretch(1)
        return w

    # -- карточка «Источник» --------------------------------------------------
    def _build_source_card(self) -> QFrame:
        frame, lay = _card("Источник — установщик программы", "1")
        row = QHBoxLayout()
        self.installer_edit = QLineEdit()
        self.installer_edit.setPlaceholderText("Выберите .exe или .msi установщик…")
        self.installer_edit.textChanged.connect(self._on_installer_changed)
        browse = QPushButton("Обзор…")
        browse.clicked.connect(self._browse_installer)
        row.addWidget(self.installer_edit, 1)
        row.addWidget(browse)
        lay.addLayout(row)

        self.detect_label = QLabel("Тип установщика: —")
        self.detect_label.setObjectName("Hint")
        lay.addWidget(self.detect_label)
        return frame

    # -- карточка «Параметры» -------------------------------------------------
    def _build_options_card(self) -> QFrame:
        frame, lay = _card("Назначение и параметры изоляции", "2")

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)

        grid.addWidget(QLabel("Папка вывода:"), 0, 0)
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Куда сохранить портативную папку…")
        out_browse = QPushButton("Обзор…")
        out_browse.clicked.connect(self._browse_output)
        grid.addWidget(self.output_edit, 0, 1)
        grid.addWidget(out_browse, 0, 2)

        grid.addWidget(QLabel("Имя приложения:"), 1, 0)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Напр. MyApp (по умолчанию — из имени файла)")
        grid.addWidget(self.name_edit, 1, 1, 1, 2)

        grid.addWidget(QLabel("Доп. аргументы установки:"), 2, 0)
        self.args_edit = QLineEdit()
        self.args_edit.setPlaceholderText("Необязательно, напр.: /COMPONENTS=main /NOICONS")
        grid.addWidget(self.args_edit, 2, 1, 1, 2)

        grid.addWidget(QLabel("Переменные среды:"), 3, 0)
        self.env_edit = QLineEdit()
        self.env_edit.setPlaceholderText("KEY1=VAL1; KEY2=VAL2 (добавятся в лончер)")
        grid.addWidget(self.env_edit, 3, 1, 1, 2)
        grid.setColumnStretch(1, 1)
        lay.addLayout(grid)

        # Чекбоксы изоляции
        checks = QGridLayout()
        checks.setHorizontalSpacing(20)
        checks.setVerticalSpacing(8)
        self.cb_redirect = QCheckBox("Изолировать AppData/Temp/профиль")
        self.cb_redirect.setChecked(True)
        self.cb_redirect.setToolTip(
            "Перенаправляет пользовательские каталоги внутрь портативной папки, "
            "чтобы программа не писала в C:\\Users\\…")
        self.cb_registry = QCheckBox("Переносить настройки из реестра")
        self.cb_registry.setChecked(True)
        self.cb_registry.setToolTip(
            "Снимает реестр до/после установки и переносит в портатив только "
            "настройки самой программы. Записи об установке (список "
            "«Установленные программы», автозапуск) не переносятся никогда.")
        self.cb_cleanup = QCheckBox("Убрать следы установки с этого ПК")
        self.cb_cleanup.setChecked(True)
        self.cb_cleanup.setToolTip(
            "После сборки удаляет программу из списка «Установленные "
            "программы», убирает созданные ярлыки и возвращает реестр этого "
            "компьютера в исходное состояние. Портатив при этом не страдает.")
        self.cb_integration = QCheckBox("Переносить ассоциации файлов и COM")
        self.cb_integration.setToolTip(
            "По умолчанию выключено: ассоциации меняют настройки чужой "
            "системы и портативности не добавляют. Включайте, только если без "
            "них программа не работает.")
        self.cb_exelauncher = QCheckBox("Создать LaunchPortable.exe в папке App")
        self.cb_exelauncher.setChecked(True)
        self.cb_exelauncher.setToolTip(
            "Кладёт готовый самодостаточный EXE в папку App. Его можно запускать "
            "двойным кликом: Python и ручная сборка не нужны, а изоляция "
            "AppData и реестра сохраняется.")
        self.cb_runtimes = QCheckBox("Встраивать Visual C++ / DirectX в портатив")
        self.cb_runtimes.setChecked(True)
        self.cb_runtimes.setToolTip(
            "Читает таблицы импорта установленной программы и приносит в "
            "портатив системные библиотеки, которых может не оказаться на "
            "чужом ПК: MSVCP110.dll, MSVCR100.dll, XINPUT1_3.dll, "
            "d3dx9_39.dll и подобные. Файлы берутся из комплекта установщика "
            "и из этого компьютера, а всё ненайденное попадает в отчёт "
            "redistributables.txt.")
        self.cb_fetch_runtimes = QCheckBox(
            "Скачивать недостающие пакеты с сайта Microsoft")
        self.cb_fetch_runtimes.setToolTip(
            "Если библиотеки нет ни в комплекте установщика, ни на этом ПК, "
            "Portablizer скачает официальный пакет (Visual C++ "
            "Redistributable, DirectX End-User Runtime) и достанет нужные "
            "файлы из него. Требуется интернет; по умолчанию выключено, "
            "чтобы сборка не ходила в сеть без спроса.")
        self.cb_full_runtimes = QCheckBox(
            "Полный комплект библиотек (все версии VC++ и DirectX)")
        self.cb_full_runtimes.setChecked(True)
        self.cb_full_runtimes.setToolTip(
            "Заранее приносит в портатив не только то, что программа "
            "импортирует сама, а весь каталог распространяемых библиотек: "
            "все версии Visual C++ 2005–2022 (MSVCP100.dll, MSVCR100.dll, "
            "MSVCP110.dll, MSVCR110.dll, msvcp140.dll…), весь DirectX "
            "End-User Runtime (XINPUT1_3.dll, d3dx9_24…43.dll, XAudio, "
            "XACT…), OpenAL, PhysX, VB6-runtime. Это закрывает и библиотеки, "
            "которые грузятся динамически или подключаются плагинами и "
            "модами: окно «отсутствует XINPUT1_3.dll» не возникает в "
            "принципе. Портатив становится заметно больше; снимите галочку, "
            "чтобы приносить только то, что требует таблица импорта.")
        self.cb_silent_redist = QCheckBox(
            "Ставить redistributables молча (без окон с «OK»)")
        self.cb_silent_redist.setChecked(True)
        self.cb_silent_redist.setToolTip(
            "Установщики игр и программ сами запускают свои предусловия — "
            "vcredist, DXSETUP, OpenAL, PhysX, .NET — и каждое показывает "
            "окно, которое приходится закрывать кнопкой «OK» (так ведёт "
            "себя, например, первый «Ведьмак»). Portablizer ставит эти "
            "пакеты заранее и в тихом режиме: мастер основной установки "
            "проходит их молча. Тем же способом добираются библиотеки, "
            "которых нет ни в комплекте, ни на этом ПК, а недостающие "
            "установщики кладутся в папку Redist портатива — на целевом ПК "
            "лончер поставит их так же молча, за один запрос UAC. "
            "Запускаются только опознанные распространяемые пакеты.")
        self.cb_runtimes.toggled.connect(self.cb_silent_redist.setEnabled)
        self.cb_runtimes.toggled.connect(self.cb_fetch_runtimes.setEnabled)
        self.cb_runtimes.toggled.connect(self.cb_full_runtimes.setEnabled)
        self.cb_assisted = QCheckBox("Разрешить окно мастера установки")
        self.cb_assisted.setToolTip(
            "Нужно старым установщикам InstallShield InstallScript 5/6 "
            "(программы и игры 1998–2002 годов): тихий режим у них работает "
            "только по файлу ответов setup.iss, а записать его может лишь "
            "человек. Если ни один тихий сценарий не сработал, Portablizer "
            "покажет мастер, запишет ваши ответы в setup.iss и перенесёт "
            "установленную программу в портатив. Требует вашего участия — "
            "оставьте выключенным для полностью автоматической сборки.")
        checks.addWidget(self.cb_redirect, 0, 0)
        checks.addWidget(self.cb_registry, 0, 1)
        checks.addWidget(self.cb_cleanup, 1, 0)
        checks.addWidget(self.cb_integration, 1, 1)
        checks.addWidget(self.cb_exelauncher, 2, 0)
        checks.addWidget(self.cb_assisted, 2, 1)
        checks.addWidget(self.cb_runtimes, 3, 0)
        checks.addWidget(self.cb_fetch_runtimes, 3, 1)
        checks.addWidget(self.cb_full_runtimes, 4, 0, 1, 2)
        checks.addWidget(self.cb_silent_redist, 5, 0, 1, 2)
        checks.setColumnStretch(2, 1)
        lay.addLayout(checks)

        hint = QLabel(
            "Подсказка: реальная тихая установка и работа с реестром "
            "выполняются только под Windows. Запускайте Portablizer от имени "
            "администратора — это нужно и для снимка HKLM, и для полной "
            "очистки следов установки с этого компьютера.")
        hint.setObjectName("Hint")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        return frame

    # -- карточка «Процесс» ---------------------------------------------------
    def _build_process_card(self) -> QFrame:
        frame, lay = _card("Процесс создания портатива", "3")
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFormat("Ожидание…")
        lay.addWidget(self.progress)

        # Вторая полоса — ход текущей операции. Скачивание DirectX (около
        # 100 МБ) и распаковка сотни кабинетов идут минутами: без отдельного
        # индикатора общая полоса замирала на одном проценте, и сборка
        # выглядела зависшей.
        self.detail_progress = QProgressBar()
        self.detail_progress.setObjectName("DetailProgress")
        self.detail_progress.setRange(0, 100)
        self.detail_progress.setValue(0)
        self.detail_progress.setTextVisible(True)
        self.detail_progress.setFormat("")
        self.detail_progress.setVisible(False)
        lay.addWidget(self.detail_progress)

        self.status_label = QLabel("Готов к работе.")
        self.status_label.setObjectName("Hint")
        lay.addWidget(self.status_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("Log")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(210)
        lay.addWidget(self.log_view)
        return frame

    # -- нижняя панель --------------------------------------------------------
    def _build_footer(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Root")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(22, 8, 22, 18)
        lay.setSpacing(12)

        self.open_btn = QPushButton("Открыть папку результата")
        self.open_btn.setObjectName("Ghost")
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(self._open_result)
        lay.addWidget(self.open_btn)
        lay.addStretch(1)

        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.setObjectName("Ghost")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel)
        lay.addWidget(self.cancel_btn)

        self.start_btn = QPushButton("Создать портатив  →")
        self.start_btn.setObjectName("Primary")
        self.start_btn.clicked.connect(self._start)
        lay.addWidget(self.start_btn)
        return w

    # -- обработчики ----------------------------------------------------------
    def _browse_installer(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Выберите установщик", "",
            "Установщики (*.exe *.msi);;Все файлы (*.*)")
        if path:
            self.installer_edit.setText(path)

    def _browse_output(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Папка для портатива", "")
        if path:
            self.output_edit.setText(path)

    def _on_installer_changed(self, path: str) -> None:
        if path and os.path.isfile(path):
            try:
                det = detect_installer(path)
                notes = []
                if det.requires_admin:
                    notes.append("нужны права администратора")
                if det.license_url:
                    notes.append("требует принятия лицензии")
                if det.has_zip_payload:
                    notes.append("внутри есть архив")
                suffix = f" — {', '.join(notes)}" if notes else ""
                self.detect_label.setText(
                    f"Тип установщика: {det.human}{suffix}")
            except Exception as exc:  # noqa: BLE001
                self.detect_label.setText(f"Тип установщика: ошибка ({exc})")
            if not self.output_edit.text().strip():
                self.output_edit.setText(os.path.dirname(path))
            if not self.name_edit.text().strip():
                self.name_edit.setText(
                    os.path.splitext(os.path.basename(path))[0])
        else:
            self.detect_label.setText("Тип установщика: —")

    def _parse_env(self) -> dict:
        env = {}
        raw = self.env_edit.text().strip()
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            if k.strip():
                env[k.strip()] = v.strip()
        return env

    @staticmethod
    def _parse_install_args(raw: str) -> list[str]:
        """Разбирает аргументы по правилам ``CommandLineToArgvW``.

        Простое ``str.split`` ломает значения вроде
        ``/DIR=\"C:\\Program Files\\App\"`` и передаёт установщику несколько
        неправильных аргументов. В отличие от POSIX-парсеров, Windows
        допускает обратные слеши перед кавычками, поэтому разбираем строку
        небольшим совместимым state machine.
        """
        args: list[str] = []
        current: list[str] = []
        token_started = False
        quoted = False
        i = 0
        raw = raw.strip()
        while i < len(raw):
            # Разделители — только пробел и табуляция. Раньше здесь по ошибке
            # стоял литерал " \\t" (пробел, ОБРАТНЫЙ СЛЕШ, буква «t»), поэтому
            # любой аргумент с буквой «t» рвался на части: «--silent»
            # превращался в «--silen», а пути ломались на каждом слеше.
            if raw[i] in " \t" and not quoted:
                if token_started:
                    args.append("".join(current))
                    current = []
                    token_started = False
                i += 1
                continue
            if raw[i] == "\\":
                token_started = True
                start = i
                while i < len(raw) and raw[i] == "\\":
                    i += 1
                slashes = i - start
                if i < len(raw) and raw[i] == '"':
                    current.extend("\\" * (slashes // 2))
                    if slashes % 2:
                        current.append('"')
                        i += 1
                    else:
                        quoted = not quoted
                        i += 1
                else:
                    current.extend("\\" * slashes)
                continue
            if raw[i] == '"':
                token_started = True
                quoted = not quoted
            else:
                token_started = True
                current.append(raw[i])
            i += 1
        if token_started or current or quoted:
            args.append("".join(current))
        return args

    def _collect_options(self) -> Optional[PortableOptions]:
        installer = self.installer_edit.text().strip()
        output = self.output_edit.text().strip()
        if not installer or not os.path.isfile(installer):
            QMessageBox.warning(self, "Portablizer",
                                "Укажите существующий файл установщика.")
            return None
        if not output:
            QMessageBox.warning(self, "Portablizer",
                                "Укажите папку для сохранения портатива.")
            return None
        os.makedirs(output, exist_ok=True)
        args = self._parse_install_args(self.args_edit.text())
        return PortableOptions(
            installer_path=installer,
            output_dir=output,
            app_name=self.name_edit.text().strip(),
            redirect_userdirs=self.cb_redirect.isChecked(),
            capture_registry=self.cb_registry.isChecked(),
            build_exe_launcher=self.cb_exelauncher.isChecked(),
            cleanup_host=self.cb_cleanup.isChecked(),
            include_shell_integration=self.cb_integration.isChecked(),
            allow_assisted_install=self.cb_assisted.isChecked(),
            bundle_runtimes=self.cb_runtimes.isChecked(),
            full_runtimes=(self.cb_runtimes.isChecked()
                           and self.cb_full_runtimes.isChecked()),
            download_runtimes=(self.cb_runtimes.isChecked()
                               and self.cb_fetch_runtimes.isChecked()),
            silent_runtime_install=(self.cb_runtimes.isChecked()
                                    and self.cb_silent_redist.isChecked()),
            extra_install_args=args,
            extra_env=self._parse_env(),
        )

    def _start(self) -> None:
        opts = self._collect_options()
        if not opts:
            return
        self.log_view.clear()
        self.progress.setValue(0)
        self._on_detail(0, "")
        self._set_running(True)

        self.worker = PortableWorker(opts)
        self.worker.log_line.connect(self._on_log)
        self.worker.progress.connect(self._on_progress)
        self.worker.detail.connect(self._on_detail)
        self.worker.finished_result.connect(self._on_finished)
        self.worker.start()

    def _cancel(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.status_label.setText("Отмена…")

    def _on_log(self, level: str, message: str) -> None:
        color = style.LEVEL_COLORS.get(level, style.TEXT)
        level_padded = self._escape(f"{level:<5}")
        self.log_view.appendHtml(
            f'<span style="color:{color}">'
            f'<b>{level_padded}</b> {self._escape(message)}</span>')
        sb = self.log_view.verticalScrollBar()
        sb.setValue(sb.maximum())

    @staticmethod
    def _escape(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;"))

    def _on_progress(self, percent: int, stage: str) -> None:
        self.progress.setValue(percent)
        self.progress.setFormat(f"{stage} — {percent}%")
        self.status_label.setText(stage)

    def _on_detail(self, percent: int, text: str) -> None:
        """Ход текущей операции: проценты загрузки или распаковки.

        ``text`` пустой — операция закончилась, полоса прячется. ``percent``
        меньше нуля — размер заранее неизвестен, показываем «бегущую»
        полосу, а не замерший ноль.
        """
        if not text:
            self.detail_progress.setVisible(False)
            self.detail_progress.setRange(0, 100)
            self.detail_progress.setValue(0)
            self.detail_progress.setFormat("")
            return
        self.detail_progress.setVisible(True)
        if percent < 0:
            self.detail_progress.setRange(0, 0)  # «бегущая» полоса
            self.detail_progress.setFormat(text)
        else:
            self.detail_progress.setRange(0, 100)
            self.detail_progress.setValue(max(0, min(100, percent)))
            self.detail_progress.setFormat(f"{text} — {percent}%")

    def _on_finished(self, result: PortableResult) -> None:
        self.last_result = result
        self._set_running(False)
        self.open_btn.setEnabled(
            bool(result.portable_dir and os.path.isdir(result.portable_dir))
        )
        self._on_detail(0, "")
        if result.success:
            self.progress.setFormat("Готово — 100%")
            self.status_label.setText(
                f"✔ Портатив создан: {result.portable_dir}")
            self.status_label.setObjectName("StatusOk")
            self.open_btn.setEnabled(True)

            details = [
                "Портативное приложение создано!",
                "",
                f"Папка: {result.portable_dir}",
            ]
            if result.portable_launcher_exe_rel:
                details.append(
                    "Запуск из EXE: " + result.portable_launcher_exe_rel
                    + " (рекомендуется)"
                )
                details.append(
                    "Запасной запуск: Launch.bat или LaunchHidden.vbs"
                )
            else:
                details.append(
                    "Запуск: Launch.bat (или LaunchHidden.vbs — без консоли)"
                )
            if result.companion_launchers:
                companion_files = [
                    f for f in result.companion_launchers
                    if (f.endswith(".exe") or f.endswith(".bat"))
                    and f not in ("Launch.bat", "Launch_Menu.bat")
                ]
                # Показываем оконные EXE как основной вариант, BAT с тем же
                # именем оставляем запасным и не дублируем в диалоге.
                companion_exes = {os.path.splitext(f)[0].casefold()
                                  for f in companion_files if f.endswith(".exe")}
                companion_files = [
                    f for f in companion_files
                    if f.endswith(".exe")
                    or os.path.splitext(f)[0].casefold() not in companion_exes
                ]
                if companion_files:
                    details += [
                        "",
                        "Дополнительные портативные запуски:",
                        *[f"  • {b}" for b in companion_files],
                    ]
                    configurators = [
                        name for name in companion_files
                        if "config" in name.casefold()
                        or "setting" in name.casefold()
                    ]
                    if configurators:
                        details += [
                            "",
                            "Сначала запустите конфигуратор, сохраните графику "
                            "и разрешение, затем запускайте игру обычным "
                            "способом. Настройки будут общими.",
                        ]
            if result.runtime_provided:
                details += [
                    "",
                    "В портатив добавлены системные библиотеки "
                    f"({len(result.runtime_provided)} шт.): "
                    + ", ".join(sorted(set(result.runtime_provided))[:8])
                    + ("…" if len(set(result.runtime_provided)) > 8 else ""),
                ]
            if result.runtime_stock:
                stock = sorted(set(result.runtime_stock))
                details += [
                    "",
                    f"Полный комплект «про запас»: принесено ещё {len(stock)} "
                    "библиотек (все версии VC++ и DirectX) — на случай "
                    "плагинов, модов и динамических загрузок: "
                    + ", ".join(stock[:6])
                    + ("…" if len(stock) > 6 else ""),
                ]
            if result.runtime_missing:
                details += [
                    "",
                    "⚠ Не удалось найти файлы: "
                    + ", ".join(sorted(set(result.runtime_missing))[:8])
                    + ".",
                    "Если программа не запустится на другом ПК, установите "
                    "там пакеты:",
                    *[f"  • {p}" for p in result.runtime_packages[:4]],
                    f"Полный список — в {result.runtime_report_rel or 'redistributables.txt'}.",
                ]
            details += [
                "",
                "Скопируйте папку целиком на флешку — установка на другом "
                "компьютере не потребуется.",
            ]
            if result.removed_from_installed_list:
                details += [
                    "",
                    "Из списка «Установленные программы» этого ПК убрано: "
                    + ", ".join(result.removed_from_installed_list),
                ]
            if result.cleanup_pending:
                details += [
                    "",
                    "⚠ Часть следов установки удалить не удалось (нужны права "
                    "администратора). Запустите cleanup_host.reg из папки "
                    "портатива от имени администратора.",
                ]
            QMessageBox.information(self, "Portablizer", "\n".join(details))
        else:
            self.progress.setFormat("Ошибка")
            msg = "\n\n".join(result.messages) or "См. журнал."
            # В однострочный статус берём только первую фразу: полный текст
            # с планом действий пользователь читает в диалоге.
            short = msg.split("\n", 1)[0]
            self.status_label.setText(f"✖ Не удалось: {short}")
            self.status_label.setObjectName("StatusErr")
            folder_hint = (
                f"\n\nДиагностика: {result.portable_dir}\\portablizer.log"
                if result.portable_dir else ""
            )
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Critical)
            box.setWindowTitle("Portablizer")
            box.setText("Не удалось создать портатив.")
            box.setInformativeText(f"{msg}{folder_hint}")
            box.exec()
        self.status_label.setStyleSheet(style.QSS)  # переприменить цвет

    def _open_result(self) -> None:
        if not self.last_result or not self.last_result.portable_dir:
            return
        path = self.last_result.portable_dir
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Portablizer", f"Не удалось открыть: {exc}")

    def _set_running(self, running: bool) -> None:
        self.start_btn.setEnabled(not running)
        self.cancel_btn.setEnabled(running)
        for w in (self.installer_edit, self.output_edit, self.name_edit,
                  self.args_edit, self.env_edit, self.cb_redirect,
                  self.cb_registry, self.cb_exelauncher, self.cb_cleanup,
                  self.cb_integration, self.cb_runtimes,
                  self.cb_fetch_runtimes, self.cb_assisted):
            w.setEnabled(not running)
        # Загрузка пакетов имеет смысл только вместе с самим переносом.
        self.cb_fetch_runtimes.setEnabled(
            not running and self.cb_runtimes.isChecked())


def run() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Portablizer")
    ico = _resource(os.path.join("resources", "app.ico"))
    if os.path.exists(ico):
        app.setWindowIcon(QIcon(ico))
    app.setStyleSheet(style.QSS)
    win = MainWindow()
    win.show()
    return app.exec()
