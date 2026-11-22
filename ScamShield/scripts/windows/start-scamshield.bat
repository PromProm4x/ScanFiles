@echo off
setlocal
set "PROJECT_ROOT=%~dp0..\.."

if /i "%~1"=="api" goto run_api
if /i "%~1"=="web" goto run_web

where pnpm >nul 2>nul
if errorlevel 1 (
  echo pnpm was not found. Install Node.js and pnpm, then reopen this window.
  exit /b 1
)

if not defined DATABASE_URL (
  echo DATABASE_URL is not set. ScamShield will use the built-in embedded database.
  echo To use an external PostgreSQL server, set DATABASE_URL in .env.
)

start "ScamShield API" "%ComSpec%" /k call "%~f0" api
start "ScamShield Web" "%ComSpec%" /k call "%~f0" web

echo.
echo ScamShield is starting up!
echo   - API Server: http://localhost:5000
echo   - Web App:    http://localhost:5173
echo.
exit /b 0

:run_api
cd /d "%PROJECT_ROOT%"
set "NODE_ENV=development"
set "PORT=5000"
pnpm --filter @workspace/api-server run build
if errorlevel 1 exit /b 1
pnpm --filter @workspace/api-server run start
exit /b %errorlevel%

:run_web
cd /d "%PROJECT_ROOT%"
set "PORT=5173"
set "BASE_PATH=/"
set "LOCAL_API_PROXY=1"
pnpm --filter @workspace/scamshield run dev
exit /b %errorlevel%
