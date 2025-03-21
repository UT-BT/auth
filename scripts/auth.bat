@echo off
IF EXIST "%PROGRAMFILES%\Git\bin\bash.exe" (
    "%PROGRAMFILES%\Git\bin\bash.exe" "%~dp0auth" %*
) ELSE (
    powershell -ExecutionPolicy Bypass -File "%~dp0auth.ps1" %*
)