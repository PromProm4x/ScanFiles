@echo off
setlocal
cd /d "%~dp0ScamShield"
call "scripts\windows\start-scamshield.bat" %*

