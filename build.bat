@echo off
rem ============================================================================
rem  Portablizer — локальная сборка Windows-exe (запускать на Windows)
rem  Требуется установленный Python 3.10+ (python.org, "Add to PATH").
rem ============================================================================
setlocal
cd /d "%~dp0"

echo [1/5] Создаю виртуальное окружение...
py -3 -m venv .venv 2>nul || python -m venv .venv
call .venv\Scripts\activate.bat

echo [2/5] Устанавливаю зависимости...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller

echo [3/5] Собираю переносимый LaunchPortable.exe...
pyinstaller --noconfirm --clean portable_launcher.spec || goto :error
copy /y "dist\PortableLauncher.exe" "portablizer\resources\portable_launcher.exe" >nul || goto :error

echo [4/5] Собираю Portablizer.exe...
pyinstaller --noconfirm --clean portablizer.spec || goto :error

echo [5/5] Готово.
echo Результат: "%~dp0dist\Portablizer.exe"
echo Встроенный лончер: "%~dp0portablizer\resources\portable_launcher.exe"
echo.
pause
endlocal
exit /b 0

:error
echo.
echo ОШИБКА СБОРКИ. Проверьте сообщения выше.
pause
endlocal
exit /b 1
