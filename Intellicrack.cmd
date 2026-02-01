@echo off
title Intellicrack
cd /d "%~dp0"
pixi run python -m intellicrack --verbose
pause
