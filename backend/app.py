"""
URL-based Intrusion Detection System - Flask API.

Hybrid Real-Time Intrusion Detection with ML, Authentication, Alerts, and SIEM.
"""

import os
import csv
from io import StringIO
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename

from detector import detect_attack
from data_ingestion import DataIngestion
from database import Database
from models import db as sqlalchemy_db
from auth import generate_token, require_auth
from alerts import send_alert
from siem_integration import send_to_siem

app = Flask(__name__)
CORS(app)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///detections.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

TESTING_MODE = os.environ.get('TESTING_MODE', 'True').lower() == 'true'
DEFAULT_ADMIN_USERNAME = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD') or ('admin123' if TESTING_MODE else None)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

sqlalchemy_db.init_app(app)

data_ingestion = DataIngestion()
db = Database()

with app.app_context():
    sqlalchemy_db.create_all()
    # Create a default admin for local/demo use. Production should set these env vars.
    if DEFAULT_ADMIN_PASSWORD and not db.get_user_by_username(DEFAULT_ADMIN_USERNAME):
        db.create_user(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, role='Admin')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'csv', 'pcap'}

# ==========================================
# Real-Time Monitoring Middleware
# ==========================================
@app.before_request
def monitor_real_time_traffic():
    """Intercepts incoming requests and analyzes them (simulating a WAF/IDS proxy)."""
    # Skip monitoring for our own API routes to prevent feedback loops, except if we want to monitor it.
    if request.path.startswith('/api/'):
        return

    # In a real WAF, this would analyze the raw URL of the intercepted request
    url = request.full_path
    source_ip = request.remote_addr

    detection = detect_attack(url)
    if detection:
        # Log to DB
        db.insert_detection({
            'url': url,
            'source_ip': source_ip,
            'timestamp': '',
            'attack_type': detection['attack_type'],
            'severity': detection['severity'],
            'confidence_score': detection.get('confidence_score'),
            'pattern_matched': detection.get('pattern_matched', ''),
            'detection_source': detection.get('detection_source', 'Rule')
        })
        
        # Alerts & SIEM
        if detection['severity'] == 'High':
            send_alert(detection['attack_type'], detection['severity'], source_ip, url)
        send_to_siem(url, detection['attack_type'], detection['severity'], source_ip)

# ==========================================
# Auth Endpoints
# ==========================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    
    user = db.get_user_by_username(username)
    if user and db.verify_password(password, user.password_hash):
        token = generate_token(user.id, user.role)
        return jsonify({'token': token, 'role': user.role})
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ==========================================
# Core Endpoints
# ==========================================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'URL Intrusion Detection System API is running'})

@app.route('/api/simulate-attack', methods=['POST'])
def simulate_attack():
    """Internal endpoint to safely test attack payloads without Cloudflare WAF interference."""
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    detection = detect_attack(url)
    
    if detection:
        result = {
            'url': url,
            'source_ip': '127.0.0.1 (Simulation)',
            'timestamp': '',
            'attack_type': detection['attack_type'],
            'severity': detection['severity'],
            'confidence_score': detection.get('confidence_score'),
            'pattern_matched': detection.get('pattern_matched', ''),
            'detection_source': detection.get('detection_source', 'Rule')
        }
        db.insert_detection(result)
        
        if detection['severity'] == 'High':
            send_alert(detection['attack_type'], detection['severity'], '127.0.0.1', url)
        send_to_siem(url, detection['attack_type'], detection['severity'], '127.0.0.1')
        
        return jsonify({'message': 'Attack Detected', 'detection': result}), 200
    
    return jsonify({'message': 'URL is safe', 'detection': None}), 200


@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only CSV and PCAP files are allowed'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        file_extension = filename.rsplit('.', 1)[1].lower()
        urls = data_ingestion.process_file(filepath, file_extension)

        results = []
        file_analysis_id = db.insert_file_analysis(filename, file_extension, 0)
        
        for url_data in urls:
            url = url_data.get('url', '')
            source_ip = url_data.get('source_ip', 'Unknown')
            timestamp = url_data.get('timestamp', '')

            detection = detect_attack(url)
            if detection:
                result = {
                    'url': url,
                    'source_ip': source_ip,
                    'timestamp': timestamp,
                    'attack_type': detection['attack_type'],
                    'severity': detection['severity'],
                    'confidence_score': detection.get('confidence_score'),
                    'pattern_matched': detection.get('pattern_matched', ''),
                    'detection_source': detection.get('detection_source', 'Rule')
                }
                results.append(result)
                db.insert_detection(result, file_analysis_id=file_analysis_id)
                
                # Integration with SIEM & Alerts
                if detection['severity'] == 'High':
                    send_alert(detection['attack_type'], detection['severity'], source_ip, url)
                send_to_siem(url, detection['attack_type'], detection['severity'], source_ip)

        # Update total attacks for this file analysis record.
        from models import FileAnalysis
        fa = sqlalchemy_db.session.get(FileAnalysis, file_analysis_id)
        if fa:
            fa.total_attacks_detected = len(results)
            sqlalchemy_db.session.commit()

        return jsonify({
            'message': 'File processed successfully',
            'total_urls': len(urls),
            'detected_attacks': len(results),
            'results': results,
        }), 200
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500
    finally:
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError:
                pass

@app.route('/api/detections', methods=['GET'])
def get_detections():
    attack_type = request.args.get('attack_type', None)
    source_ip = request.args.get('source_ip', None)
    file_id = request.args.get('file_id', type=int)
    severity = request.args.get('severity', None)
    detection_source = request.args.get('detection_source', None)
    detections = db.get_detections(
        attack_type=attack_type,
        source_ip=source_ip,
        file_id=file_id,
        severity=severity,
        detection_source=detection_source
    )
    return jsonify({'total': len(detections), 'detections': detections}), 200

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    file_id = request.args.get('file_id', type=int)
    severity = request.args.get('severity', None)
    stats = db.get_statistics(file_id=file_id, severity=severity)
    return jsonify(stats), 200

@app.route('/api/top-ips', methods=['GET'])
def get_top_ips():
    file_id = request.args.get('file_id', type=int)
    severity = request.args.get('severity', None)
    stats = db.get_statistics(file_id=file_id, severity=severity)
    return jsonify({'top_source_ips': stats.get('top_source_ips', [])}), 200

@app.route('/api/file-history', methods=['GET'])
def get_file_history():
    history = db.get_file_analysis_history()
    return jsonify({'file_history': history}), 200

@app.route('/api/clear-database', methods=['POST'])
@require_auth(role='Admin')
def clear_database():
    db.clear_all()
    return jsonify({'message': 'Database cleared successfully'}), 200

# ==========================================
# Rule Management Endpoints
# ==========================================
@app.route('/api/rules', methods=['GET'])
def get_rules():
    rules = db.get_rules()
    return jsonify({'rules': rules}), 200

@app.route('/api/rules', methods=['POST'])
@require_auth(role='Admin')
def add_rule():
    data = request.get_json()
    rule_id = db.add_rule(data['pattern'], data['attack_type'], data['priority'], data.get('enabled', True))
    return jsonify({'message': 'Rule added', 'id': rule_id}), 201

# ==========================================
# Export Endpoints
# ==========================================
EXPORT_FIELDNAMES = ['id', 'url', 'source_ip', 'timestamp', 'attack_type', 'severity', 'pattern_matched', 'confidence_score', 'detected_at', 'detection_source']

@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    detections = _get_filtered_detections_from_request()
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_FIELDNAMES, extrasaction='ignore')
    writer.writeheader()
    if detections:
        writer.writerows(detections)
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=detections.csv'})

@app.route('/api/export/json', methods=['GET'])
def export_json():
    detections = _get_filtered_detections_from_request()
    return jsonify({'total': len(detections), 'detections': detections}), 200

def _get_filtered_detections_from_request():
    return db.get_detections(
        attack_type=request.args.get('attack_type', None),
        source_ip=request.args.get('source_ip', None),
        file_id=request.args.get('file_id', type=int),
        severity=request.args.get('severity', None),
        detection_source=request.args.get('detection_source', None)
    )

if __name__ == '__main__':
    app.run(debug=False, port=5000)
