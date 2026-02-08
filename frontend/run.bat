@echo off
cd /d "%~dp0"
if not exist "node_modules" (
    echo Installing npm dependencies...
    call npm install
)
echo Starting React app on http://localhost:3000
call npm start
pause
