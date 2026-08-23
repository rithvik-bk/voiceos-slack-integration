@echo off
rem Windows twin of run.sh. Same law: stdout is the MCP wire, diagnostics go to stderr (1>&2).
rem Same ladder: bun -> node >=22.18 native TypeScript -> local tsx -> npx tsx.
setlocal enableextensions
set "SCRIPT_DIR=%~dp0"

set "BUN="
if exist "%USERPROFILE%\.bun\bin\bun.exe" set "BUN=%USERPROFILE%\.bun\bin\bun.exe"
if not defined BUN for /f "delims=" %%i in ('where bun 2^>nul') do if not defined BUN set "BUN=%%i"
if defined BUN (
  "%BUN%" "%SCRIPT_DIR%server.ts" %*
  exit /b
)

set "NODE="
for /f "delims=" %%i in ('where node 2^>nul') do if not defined NODE set "NODE=%%i"
if defined NODE (
  "%NODE%" -e "const [a,b]=process.versions.node.split('.').map(Number);process.exit((a>=24||(a===23&&b>=6)||(a===22&&b>=18))?0:1)"
  if not errorlevel 1 (
    "%NODE%" "%SCRIPT_DIR%server.ts" %*
    exit /b
  )
  echo [run.cmd] node too old for native TypeScript; falling back to tsx. 1>&2
)

if exist "%SCRIPT_DIR%node_modules\.bin\tsx.cmd" (
  call "%SCRIPT_DIR%node_modules\.bin\tsx.cmd" "%SCRIPT_DIR%server.ts" %*
  exit /b
)
echo [run.cmd] Using npx (slow first launch). 1>&2
call npx --yes tsx "%SCRIPT_DIR%server.ts" %*
exit /b
