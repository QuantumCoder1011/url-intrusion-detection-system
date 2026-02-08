@echo off
cd /d "%~dp0"
echo Installing Python dependencies if needed...
pip install -q Flask Flask-CORS pandas scapy python-dotenv 2>nul
echo Starting Flask backend on http://localhost:5000
python app.py
pause
