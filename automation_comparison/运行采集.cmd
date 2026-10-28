@echo off
chcp 65001 >nul
set "PYTHONUTF8=1"
if exist "%USERPROFILE%\anaconda3\python.exe" (
  "%USERPROFILE%\anaconda3\python.exe" "%~dp0batch_collect.py" %*
) else (
  python "%~dp0batch_collect.py" %*
)
pause
