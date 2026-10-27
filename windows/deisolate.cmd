@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deisolate.ps1" %*
