@echo off
chcp 65001 >nul
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 -m scholar_access %*
) else (
    python -m scholar_access %*
)
endlocal
