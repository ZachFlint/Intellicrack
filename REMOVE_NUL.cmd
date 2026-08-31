@echo off
REM This script calls an external Python script to do the actual work.
REM This is more robust than embedding Python code inside the batch file.

REM Change directory to the script's location (project root)
pushd "%~dp0"

echo --- NUL File Cleanup Script ---
echo Calling Python script: scripts\clean_nul.py
echo -----------------------------------------

REM Run the python script and then pause, regardless of the outcome.
call .\.pixi\envs\default\python.exe scripts\clean_nul.py
set "SCRIPT_RESULT=%ERRORLEVEL%"

echo -----------------------------------------
echo Script execution finished.

popd

echo.
echo Press any key to exit.
pause
exit /b %SCRIPT_RESULT%
