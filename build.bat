@echo off
rem ============================================================================
rem  Portablizer — локальная сборка Windows-exe (запускать на Windows)
rem  Требуется установленный Python 3.10+ (python.org, "Add to PATH").
rem ============================================================================
setlocal
cd /d "%~dp0"

echo [1/4] Создаю виртуальное окружение...
py -3 -m venv .venv 2>nul || python -m venv .venv
call .venv\Scripts\activate.bat

echo [2/4] Устанавливаю зависимости...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller

echo [3/4] Собираю Portablizer.exe...
pyinstaller --noconfirm --clean portablizer.spec

echo [4/4] Готово.
echo Результат: "%~dp0dist\Portablizer.exe"
echo.
pause
endlocal
