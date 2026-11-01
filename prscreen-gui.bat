@echo off
rem Double-click to open the prscreen page in your browser. Needs uv: https://docs.astral.sh/uv/
cd /d "%~dp0"
where uv >nul 2>nul || (
  echo uv is not installed. Install it from https://docs.astral.sh/uv/ and run this again.
  pause
  exit /b 1
)
rem Run through python -m, not prscreen.exe: Windows locks a running .exe, and a locked
rem prscreen.exe would stop "uv run" from updating the project the next time it starts.
uv run python -m prscreen gui
if errorlevel 1 (
  echo.
  echo prscreen could not start. If the message above says "Access is denied", another prscreen
  echo window is still open: close it and double-click this file again.
)
pause
