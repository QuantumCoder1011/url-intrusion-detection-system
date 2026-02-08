# How to Run the Project

Use **two separate terminals** (or Command Prompt / PowerShell windows).

## Terminal 1 – Backend (Flask)

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Wait until you see: **Running on http://127.0.0.1:5000**

## Terminal 2 – Frontend (React)

```bash
cd frontend
npm install
npm start
```

Wait until the browser opens at **http://localhost:3000** (or open that URL yourself).

---

## Alternative: Run the batch files (Windows)

1. **Backend:** Double‑click `backend\run.bat`
2. **Frontend:** Double‑click `frontend\run.bat` (after the backend is running)

---

## Quick check

- Backend: open http://localhost:5000/api/health — you should see `{"status":"healthy",...}`
- Frontend: open http://localhost:3000 — you should see the URL Intrusion Detection System dashboard

Then upload `sample_data.csv` from the project root to test detection.
