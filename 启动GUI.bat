@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -m disk_cleaner.cli.main gui
pause
