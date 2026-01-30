@echo off
setlocal

:: This script calls an external Python script to do the actual work.
:: This is more robust than embedding Python code inside the batch file.

:: Change directory to the script's location (project root)
pushd %~dp0

echo --- NUL File Cleanup Script ---
echo Calling Python script: scripts\clean_nul.py
echo -----------------------------------------

:: Run the python script and then pause, regardless of the outcome.
call .\.pixi\envs\default\python.exe scripts\clean_nul.py

echo -----------------------------------------
echo Script execution finished.

popd
endlocal

echo.
echo Press any key to exit.
pause
