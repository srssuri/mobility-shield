@echo off
setlocal
set PY=C:\Users\Ogurigoat\AppData\Local\Programs\Python\Python312\python.exe
set DIR=%~dp0
if "%1"=="" (
    "%PY%" "%DIR%mobility_shield_gui.py"
) else (
    "%PY%" "%DIR%mobility_shield_cli.py" %*
)
endlocal