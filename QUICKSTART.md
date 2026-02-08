# Quick Start Guide

## Prerequisites Check
- ✅ Python 3.8+ installed
- ✅ Node.js 14+ installed
- ✅ npm or yarn installed

## Step 1: Backend Setup (Terminal 1)

```bash
# Navigate to backend directory
cd backend

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the Flask server
python app.py
```

You should see: `Running on http://127.0.0.1:5000`

## Step 2: Frontend Setup (Terminal 2)

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start the React development server
npm start
```

The browser should automatically open to `http://localhost:3000`

## Step 3: Test the System

1. **Upload Sample Data**: 
   - Use the `sample_data.csv` file in the root directory
   - Click "Upload & Analyze" in the web interface

2. **View Results**:
   - Check the Dashboard for statistics and charts
   - Review the Events Table for detailed detections

3. **Filter & Export**:
   - Use the filter dropdowns to filter by attack type or source IP
   - Click "Export CSV" or "Export JSON" to download results

## Troubleshooting

### Backend Issues
- **Port 5000 already in use**: Change the port in `backend/app.py` (last line)
- **Module not found**: Make sure virtual environment is activated and dependencies are installed
- **Permission errors**: Check file permissions for uploads directory

### Frontend Issues
- **Port 3000 already in use**: React will prompt to use another port
- **API connection errors**: Ensure backend is running on port 5000
- **npm install fails**: Try deleting `node_modules` and `package-lock.json`, then run `npm install` again

## Next Steps

- Create your own CSV files with URL data
- Test with PCAP files (network captures)
- Customize detection patterns in `backend/patterns.py` and `backend/detector.py`
- Extend the dashboard with additional visualizations

## Sample CSV Format

Your CSV files should have columns like:
- `url` or `URL` - The URL to analyze
- `source_ip` or `IP` - Source IP address (optional)
- `timestamp` or `Time` - Timestamp (optional)

Example:
```csv
timestamp,source_ip,url
2024-01-15 10:30:45,192.168.1.100,/index.php?id=1
2024-01-15 10:31:12,192.168.1.101,/login.php?user=admin
```
