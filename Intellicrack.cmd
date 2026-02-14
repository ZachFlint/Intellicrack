@echo off
title Intellicrack
cd /d "%~dp0"
pixi run python -m intellicrack --verbose
set "EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %EXIT_CODE%
