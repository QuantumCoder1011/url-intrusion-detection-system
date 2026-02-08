# Dependency Check – URL Intrusion Detection System

## Backend (Python)

Required packages (see `backend/requirements.txt`):

| Package        | Used for              | Check |
|----------------|------------------------|--------|
| Flask          | Web API                | OK     |
| Flask-CORS     | Cross-origin requests  | OK     |
| pandas         | CSV processing         | OK     |
| scapy          | PCAP file parsing      | OK     |
| python-dotenv  | Environment variables  | OK     |

**To verify:** From project root:
```bash
cd backend
python check_dependencies.py
```

**To install all backend dependencies:**
```bash
cd backend
pip install -r requirements.txt
```

**To install if something is missing:** (replace with the package name from the script output)
```bash
pip install Flask Flask-CORS pandas scapy python-dotenv
```

---

## Frontend (Node.js)

Required packages (see `frontend/package.json`):

| Package         | Used for           | Check |
|-----------------|--------------------|--------|
| react           | UI library         | OK     |
| react-dom       | React DOM renderer | OK     |
| react-scripts   | Build & dev server | OK     |
| axios           | API requests       | OK     |
| chart.js        | Charts             | OK     |
| react-chartjs-2 | React charts       | OK     |

**To verify:** From project root:
```bash
cd frontend
npm ls react react-dom react-scripts axios chart.js react-chartjs-2
```

**To install all frontend dependencies:**
```bash
cd frontend
npm install
```

If you removed `node_modules` or cloned the repo fresh:
```bash
cd frontend
npm install
npm start
```

---

## Summary

- **Backend:** All required Python modules are present. Use `pip install -r backend/requirements.txt` if you need to reinstall.
- **Frontend:** All required npm packages are present (including `fork-ts-checker-webpack-plugin` 6.5.3). Use `npm install` in `frontend` if you need to reinstall.

You can run the project; no extra install steps are needed unless you’re on a new machine or after a clean clone.
