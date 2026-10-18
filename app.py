#!/usr/bin/env python3
"""Portablizer — единая точка входа для запуска и для сборки PyInstaller.

Запуск из исходников:
    python app.py

Сборка Windows-exe (на Windows):
    build.bat        (или см. .github/workflows/build-windows.yml для CI)
"""
import sys

from portablizer.gui.main_window import run

if __name__ == "__main__":
    sys.exit(run())
