@echo off
setlocal
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%~dp0build.py" %*
) else (
    python "%~dp0build.py" %*
)
exit /b %errorlevel%
