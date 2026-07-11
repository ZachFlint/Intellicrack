@echo off
title Intellicrack (no-elevate)
cd /d "%~dp0"
set "PATH=%LOCALAPPDATA%\pixi\bin;%PATH%"
pixi run python -m intellicrack --no-elevate --verbose
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" pause
exit /b %EXIT_CODE%
