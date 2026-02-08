# URL-based Intrusion Detection System

A full-stack web application for detecting malicious URLs in web traffic using pattern-based detection. This system can analyze CSV log files and PCAP network capture files to identify various types of cyber attacks.

## Features

- **Multi-format Support**: Analyze CSV log files and PCAP network captures
- **Comprehensive Detection**: Command Injection, Directory Traversal, XSS, SQL Injection (priority-based, one detection per URL)
- **Interactive Dashboard**: Real-time visualization of detected threats with charts and statistics
- **Filtering & Export**: Filter detections by attack type and source IP, export results to CSV/JSON
- **Modern UI**: Built with React.js and Chart.js for an intuitive user experience

## Technology Stack

### Backend
- **Python 3.x** - Core language
- **Flask** - Web framework and API
- **Pandas** - CSV data processing
- **Scapy** - PCAP file analysis
- **SQLite** - Database for storing detection results

### Frontend
- **React.js** - UI framework
- **Chart.js** - Data visualization
- **Axios** - HTTP client

## Project Structure

```
.
├── backend/
│   ├── app.py                 # Flask application and API endpoints
│   ├── patterns.py            # Attack regex patterns
│   ├── detector.py            # Priority-based URL detector (one result per URL)
│   ├── data_ingestion.py      # CSV and PCAP file processing
│   ├── database.py            # SQLite database operations
│   ├── requirements.txt       # Python dependencies
│   └── uploads/               # Temporary file storage (created automatically)
├── frontend/
│   ├── src/
│   │   ├── components/        # React components
│   │   │   ├── Dashboard.js
│   │   │   ├── EventsTable.js
│   │   │   ├── FileUpload.js
│   │   │   └── Header.js
│   │   ├── services/
│   │   │   └── api.js         # API service functions
│   │   ├── App.js
│   │   ├── App.css
│   │   ├── index.js
│   │   └── index.css
│   ├── public/
│   │   └── index.html
│   └── package.json
└── README.md
```

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Node.js 14 or higher
- npm or yarn

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
```

3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Run the Flask server:
```bash
python app.py
```

The backend will start on `http://localhost:5000`

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

The frontend will start on `http://localhost:3000` and automatically open in your browser.

## Usage

1. **Start the Backend**: Run the Flask server (see Backend Setup above)
2. **Start the Frontend**: Run the React development server (see Frontend Setup above)
3. **Upload Files**: Use the file upload component to upload CSV or PCAP files
4. **View Results**: Check the dashboard for statistics and the events table for detailed detections
5. **Filter & Export**: Use filters to narrow down results and export to CSV or JSON

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/upload` - Upload and analyze a file
- `GET /api/detections` - Get all detections (with optional filters)
- `GET /api/statistics` - Get summary statistics
- `GET /api/export/csv` - Export detections as CSV
- `GET /api/export/json` - Export detections as JSON
- `POST /api/clear` - Clear all detections from database

## Detected Attack Types

- SQL Injection
- Cross-Site Scripting (XSS)
- Directory Traversal
- Command Injection
- Server-Side Request Forgery (SSRF)
- Path Traversal
- File Inclusion
- LDAP Injection
- XML External Entity (XXE)

## Notes

- The system processes files offline (not real-time)
- Uploaded files are automatically deleted after processing
- Detection results are stored in SQLite database (`detections.db`)
- The system uses regex-based pattern matching for detection

## Development

### Backend Development
- The detection patterns can be extended in `patterns.py` and `detector.py`
- New file formats can be added in `data_ingestion.py`

### Frontend Development
- Components are modular and can be easily extended
- Chart configurations can be customized in `Dashboard.js`

## License

This project is developed for academic purposes.

## Author

**Vansh Shah**  
Roll No.: MCA2547  
Mentor: Prof. Puja Devgun
