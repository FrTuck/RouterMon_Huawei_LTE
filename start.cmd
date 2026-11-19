@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo   B818 LTE Panel
echo   ==============
echo   Введите пароль веб-интерфейса роутера для точного сигнала (RSRP/RSRQ/SINR)
echo   и данных устройства. Или просто нажмите Enter — панель откроется без входа
echo   (оператор, статус, трафик, сигнал в палочках).
echo.
py b818panel.py --ask-password
echo.
pause
