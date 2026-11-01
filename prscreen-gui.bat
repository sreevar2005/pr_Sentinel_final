@echo off
rem Double-click to open the prscreen page in your browser. Needs uv: https://docs.astral.sh/uv/
cd /d "%~dp0"
where uv >nul 2>nul || (
  echo uv is not installed. Install it from https://docs.astral.sh/uv/ and run this again.
  pause
  exit /b 1
)
uv run prscreen gui
pause
