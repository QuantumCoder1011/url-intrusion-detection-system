# Project Status and Next Steps

## Project Overview

This project is a full-stack URL-based Intrusion Detection System. It analyzes URLs from uploaded CSV/PCAP files and from a manual simulator input, then detects possible attacks using a hybrid detection approach:

- Rule-based detection using regular expressions.
- ML-based detection using a trained URL classifier.
- Dashboard visualization through a React frontend.
- Backend APIs through Flask.
- Detection storage through SQLAlchemy-backed database models.

The system is useful as an academic IDS/SOC-style project because it demonstrates file ingestion, attack detection, authentication, dashboard analytics, exports, and manual payload testing.

## What Has Been Done

### Backend Fixes and Improvements

- Fixed the file upload processing error in `backend/app.py`.
- Added the missing JSON export endpoint:
  - `GET /api/export/json`
- Improved CSV export:
  - `GET /api/export/csv`
  - CSV export now respects filters.
- Added backend support for filtering detections by:
  - attack type
  - source IP
  - file ID
  - severity
  - detection source
- Fixed `detection_source` handling so the frontend filter works correctly.
- Added missing backend dependencies:
  - `requests`
  - `psycopg2-binary`
  - `Flask-SQLAlchemy`
  - `PyJWT`
  - `bcrypt`
  - `scikit-learn`
  - `joblib`
- Improved environment variable handling:
  - `DATABASE_URL` now falls back to SQLite if blank.
  - `JWT_SECRET` now falls back safely if blank.
- Added safer production deployment settings in `render.yaml`.
- Created a backend virtual environment at `backend/.venv`.
- Added `.venv/` to `.gitignore`.

### Frontend Fixes and Improvements

- Repaired frontend dependencies.
- Fixed frontend build issues.
- Removed unused React variables and warnings.
- Confirmed `npm run build` completes successfully.
- Connected frontend export buttons to working backend routes.
- Connected detection-source filtering to the backend.

### Dataset and ML Work

- Added a deterministic full-coverage test dataset:
  - `full_attack_test_dataset.csv`
- Added a generator script:
  - `generate_full_attack_dataset.py`
- Trained the ML model:
  - `backend/models/url_detector_model.pkl`
- Verified the dataset against the actual detector with zero mismatches.

The generated dataset contains:

- 15 benign URLs.
- 8 SQL Injection rule cases.
- 8 XSS rule cases.
- 8 Directory Traversal rule cases.
- 8 Command Injection rule cases.
- 8 Suspicious Activity low-severity rule cases.
- 8 ML-focused cases.

Validation result:

```text
Command Injection: 10
Directory Traversal: 10
SQL Injection: 10
Suspicious Activity: 8
XSS: 10
None: 15

Rule detections: 40
ML detections: 8
Safe/None: 15
```

## How The System Works

### 1. User Login

The frontend starts with a login screen. In local/demo mode, the default credentials are:

```text
Username: admin
Password: admin123
```

After login, the backend returns a JWT token. This token is stored in local storage and sent with protected API requests.

### 2. File Upload Detection Flow

The user uploads a CSV or PCAP file from the dashboard.

For CSV files, the backend extracts URLs from columns such as:

- `url`
- `URL`
- `request`
- `path`
- `uri`

It also tries to extract:

- source IP
- timestamp

For each extracted URL:

1. The URL is decoded.
2. Rule-based detection runs first.
3. If no strong rule matches, ML prediction runs.
4. If ML does not detect anything, low-severity suspicious rules are checked.
5. Detections are stored in the database.
6. The frontend updates the dashboard and event table.

### 3. Manual Payload Simulator

The manual simulator input is a local test tool. It does not attack any external system.

It sends the entered URL or payload string to:

```text
POST /api/simulate-attack
```

The backend then runs the same detection logic used for uploaded files. This is useful for quickly testing examples such as:

```text
/search?q=' OR 1=1--
/comment?text=<script>alert(1)</script>
/download?file=../../../etc/passwd
/run?cmd=; whoami
```

### 4. Rule-Based Detection

Rule-based detection uses patterns in:

```text
backend/patterns.py
```

Current categories include:

- Command Injection
- Directory Traversal
- XSS
- SQL Injection
- Suspicious Activity

Detection priority is handled in:

```text
backend/detector.py
```

Current priority order:

1. Command Injection
2. Directory Traversal
3. XSS
4. SQL Injection
5. ML prediction
6. Low-severity suspicious rules

### 5. ML-Based Detection

The ML model is trained by:

```text
backend/train_model.py
```

The generated model is saved at:

```text
backend/models/url_detector_model.pkl
```

The ML detector is loaded by:

```text
backend/ml_detector.py
```

If the model predicts an attack and no strong rule has already matched, the detection is marked as:

```text
detection_source = ML
severity = Medium
```

### 6. Dashboard

The React dashboard shows:

- total detections
- attack type chart
- severity chart
- top source IPs
- file history
- final analysis summary
- event table

The event table supports filtering by:

- attack type
- source IP
- severity
- detection source

### 7. Export

The project supports:

```text
GET /api/export/csv
GET /api/export/json
```

Exports include detection data such as:

- URL
- source IP
- timestamp
- attack type
- severity
- confidence score
- detection source
- matched pattern

## How To Run The Project

### Backend

Open PowerShell:

```powershell
cd D:\url_irs\url-intrusion-detection-system\backend
.\.venv\Scripts\python.exe app.py
```

Backend URL:

```text
http://localhost:5000
```

Health check:

```text
http://localhost:5000/api/health
```

Note: backend startup can take some time because pandas, scikit-learn, and the ML model are imported.

### Frontend

Open another PowerShell terminal:

```powershell
cd D:\url_irs\url-intrusion-detection-system\frontend
npm start
```

Frontend URL:

```text
http://localhost:3000
```

### Build Frontend

```powershell
cd D:\url_irs\url-intrusion-detection-system\frontend
npm run build
```

This has been verified to compile successfully.

### Regenerate Full Test Dataset

```powershell
cd D:\url_irs\url-intrusion-detection-system
.\backend\.venv\Scripts\python.exe generate_full_attack_dataset.py
```

Output:

```text
full_attack_test_dataset.csv
```

### Retrain ML Model

```powershell
cd D:\url_irs\url-intrusion-detection-system\backend
.\.venv\Scripts\python.exe train_model.py
```

Output:

```text
backend/models/url_detector_model.pkl
```

## Important Files

```text
backend/app.py
```

Main Flask API application.

```text
backend/detector.py
```

Hybrid detection logic.

```text
backend/patterns.py
```

Rule-based regex patterns.

```text
backend/ml_detector.py
```

ML model loading and prediction.

```text
backend/train_model.py
```

ML training script.

```text
backend/database.py
```

Database operations.

```text
backend/models.py
```

SQLAlchemy models.

```text
frontend/src/App.js
```

Main React app.

```text
frontend/src/components/Dashboard.js
```

Dashboard charts and statistics.

```text
frontend/src/components/EventsTable.js
```

Detection event table and filters.

```text
frontend/src/components/FileUpload.js
```

CSV/PCAP upload UI.

```text
frontend/src/components/Simulator.js
```

Manual payload testing UI.

```text
full_attack_test_dataset.csv
```

Generated dataset for full testing.

## Current Limitations

- The ML model is trained on synthetic data, not a large real-world dataset.
- PCAP parsing is basic and mainly supports visible HTTP traffic.
- HTTPS payloads cannot be inspected from normal PCAP files unless decrypted.
- Rule management APIs exist, but custom rules are not fully integrated into the detector flow.
- The default local admin password should not be used in production.
- The frontend uses Create React App, which is older and can be upgraded later.
- There are no automated backend/frontend tests yet.

## Recommended Next Steps

### High Priority

1. Add automated backend tests with `pytest`.
2. Add a real frontend page for rule management.
3. Connect database-stored custom rules to the detector.
4. Add incident status fields:
   - New
   - Investigating
   - False Positive
   - Confirmed
   - Resolved
5. Add analyst notes for each detection.
6. Add date-range filtering.

### Medium Priority

1. Add more attack categories:
   - SSRF
   - Open Redirect
   - Local File Inclusion
   - Remote File Inclusion
   - LDAP Injection
   - NoSQL Injection
   - XXE
2. Add report generation:
   - PDF report
   - CSV export
   - JSON export
   - summary charts
3. Add better ML features:
   - URL length
   - entropy
   - special character count
   - path depth
   - parameter count
   - encoding count
4. Add model evaluation metrics in the dashboard.

### Production Readiness

1. Set a strong `JWT_SECRET`.
2. Set a secure `DEFAULT_ADMIN_PASSWORD`.
3. Configure PostgreSQL with `DATABASE_URL`.
4. Restrict CORS to the production frontend URL.
5. Add rate limiting to login.
6. Add database migrations with Flask-Migrate or Alembic.
7. Add Docker support.
8. Add `.env.example`.

## Suggested Final Project Direction

The project can be upgraded from:

```text
URL-based Intrusion Detection System
```

to:

```text
Hybrid URL Threat Detection and SOC Analysis Platform
```

The final version should include:

- CSV/PCAP/log upload.
- Manual URL simulation.
- Rule-based detection.
- ML-based detection.
- Custom rule management.
- Analyst workflow.
- Incident status tracking.
- Exportable reports.
- User roles.
- SIEM webhook integration.
- Production deployment support.

