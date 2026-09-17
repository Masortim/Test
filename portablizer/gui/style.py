"""Тёмная тема (QSS) для интерфейса Portablizer.

Единый стиль: глубокий индиго-фон, акцентный фиолетовый, скруглённые элементы,
аккуратные отступы. Подобран под иконку приложения.
"""

ACCENT = "#7C5CFF"
ACCENT_HOVER = "#8E72FF"
ACCENT_PRESSED = "#6A49F0"
BG = "#14131F"
BG_CARD = "#1E1C2E"
BG_INPUT = "#262338"
TEXT = "#ECEAF6"
TEXT_DIM = "#9A96B3"
BORDER = "#332F49"
OK = "#3ECF8E"
WARN = "#F5A623"
ERR = "#FF5C77"

QSS = f"""
* {{
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    color: {TEXT};
}}
QMainWindow, QWidget#Root {{
    background: {BG};
}}
QLabel#Title {{
    font-size: 22px;
    font-weight: 700;
    color: {TEXT};
}}
QLabel#Subtitle {{
    font-size: 12px;
    color: {TEXT_DIM};
}}
QLabel#StepBadge {{
    background: {ACCENT};
    color: white;
    border-radius: 11px;
    min-width: 22px; max-width: 22px;
    min-height: 22px; max-height: 22px;
    font-weight: 700;
    qproperty-alignment: AlignCenter;
}}
QFrame#Card {{
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 14px;
}}
QLabel#CardTitle {{
    font-size: 14px;
    font-weight: 600;
}}
QLabel#Hint {{
    color: {TEXT_DIM};
    font-size: 11px;
}}
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox {{
    background: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 9px;
    padding: 8px 10px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
    border: 1px solid {ACCENT};
}}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {BG_INPUT};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    outline: none;
}}
QPushButton {{
    background: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 9px;
    padding: 9px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ border: 1px solid {ACCENT}; }}
QPushButton:pressed {{ background: {BG_CARD}; }}
QPushButton#Primary {{
    background: {ACCENT};
    border: 1px solid {ACCENT};
    color: white;
    padding: 11px 22px;
    font-size: 14px;
}}
QPushButton#Primary:hover {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
QPushButton#Primary:pressed {{ background: {ACCENT_PRESSED}; }}
QPushButton#Primary:disabled {{
    background: {BORDER}; border-color: {BORDER}; color: {TEXT_DIM};
}}
QPushButton#Ghost {{
    background: transparent;
    border: 1px solid {BORDER};
}}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 18px; height: 18px;
    border-radius: 5px;
    border: 1px solid {BORDER};
    background: {BG_INPUT};
}}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border: 1px solid {ACCENT};
    image: none;
}}
QProgressBar {{
    background: {BG_INPUT};
    border: none;
    border-radius: 7px;
    height: 14px;
    text-align: center;
    color: {TEXT};
    font-size: 11px;
}}
QProgressBar::chunk {{
    background: {ACCENT};
    border-radius: 7px;
}}
QPlainTextEdit#Log {{
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    background: #100F19;
    border: 1px solid {BORDER};
    border-radius: 10px;
}}
QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER}; border-radius: 5px; min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QLabel#StatusOk {{ color: {OK}; font-weight: 600; }}
QLabel#StatusWarn {{ color: {WARN}; font-weight: 600; }}
QLabel#StatusErr {{ color: {ERR}; font-weight: 600; }}
QToolTip {{
    background: {BG_CARD}; color: {TEXT};
    border: 1px solid {ACCENT}; border-radius: 6px; padding: 6px;
}}
"""

LEVEL_COLORS = {
    "DEBUG": TEXT_DIM,
    "INFO": TEXT,
    "WARN": WARN,
    "ERROR": ERR,
    "OK": OK,
}
