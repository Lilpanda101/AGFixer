@echo off
setlocal
chcp 65001 >nul
title AGFixer - v1.10.8
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0modules\launch.ps1"
set "AG_EXIT=%ERRORLEVEL%"
if not "%AG_EXIT%"=="0" pause
endlocal & exit /b %AG_EXIT%
