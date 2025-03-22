@echo off
IF EXIST "%PROGRAMFILES%\Git\bin\bash.exe" (
    "%PROGRAMFILES%\Git\bin\bash.exe" "%~dp0bootstrap" %*
) ELSE (
    powershell -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1" %*
) 