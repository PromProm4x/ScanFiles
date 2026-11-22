@echo off
setlocal
cd /d "%~dp0"
call "scripts\windows\start-scamshield.bat" %*

