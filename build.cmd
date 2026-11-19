@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   Сборка B818 LTE Panel в один .exe
echo ============================================
echo.
echo [1/2] Проверка/установка PyInstaller...
py -m pip install --upgrade --quiet pyinstaller || goto :err
echo [2/2] Сборка (займёт минуту-две)...
py -m PyInstaller --noconfirm --onefile --windowed --name "B818-LTE-Panel" ^
   --add-data "dashboard.html;." b818panel.py || goto :err
echo.
echo ============================================
echo   Готово:  dist\B818-LTE-Panel.exe
echo   Это самодостаточный файл — Python у других
echo   пользователей НЕ нужен. Можно просто отдать
echo   им этот один exe.
echo ============================================
pause
exit /b 0
:err
echo.
echo ОШИБКА сборки. Убедитесь, что установлен Python ( py --version ).
pause
exit /b 1
