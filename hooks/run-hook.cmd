: << 'CMDBLOCK'
@echo off
if "%~1"=="" exit /b 1
set "HOOK_DIR=%~dp0"
if exist "C:\Program Files\Git\bin\bash.exe" (
  "C:\Program Files\Git\bin\bash.exe" "%HOOK_DIR%%~1" %2 %3 %4 %5 %6 %7 %8 %9
  exit /b %ERRORLEVEL%
)
if exist "C:\Program Files (x86)\Git\bin\bash.exe" (
  "C:\Program Files (x86)\Git\bin\bash.exe" "%HOOK_DIR%%~1" %2 %3 %4 %5 %6 %7 %8 %9
  exit /b %ERRORLEVEL%
)
where bash >nul 2>nul
if %ERRORLEVEL% equ 0 (
  bash "%HOOK_DIR%%~1" %2 %3 %4 %5 %6 %7 %8 %9
  exit /b %ERRORLEVEL%
)
exit /b 0
CMDBLOCK

set -e
script_dir="$(cd "$(dirname "$0")" && pwd)"
script_name="${1:?missing hook script name}"
shift
exec bash "${script_dir}/${script_name}" "$@"
