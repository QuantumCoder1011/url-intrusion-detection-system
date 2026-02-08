"""
URL-based Intrusion Detection System - Flask API.

Offline, rule-based analysis of uploaded CSV/PCAP-derived URLs.
Designed for security analysis workflows; APIs are structured for use
as a security analysis tool.

Extension notes:
- Real-time IDS: The same detector.detect_attack() can be called from a
  middleware or log tailer on live traffic; this API would then receive
  events instead of (or in addition to) file uploads.
- SIEM integration: Export and /statistics, /top-ips, /file-history endpoints
  provide analyst-friendly data that could be consumed by a SIEM or SOAR
  for dashboards and automated response.
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
import csv
from io import StringIO

from detector import detect_attack
from data_ingestion import DataIngestion
from database import Database

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'pcap'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

data_ingestion = DataIngestion()
db = Database()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'URL Intrusion Detection System API is running'})


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
        for url_data in urls:
            url = url_data.get('url', '')
            source_ip = url_data.get('source_ip', 'Unknown')
            timestamp = url_data.get('timestamp', '')

            # One URL -> one detection (priority-based)
            detection = detect_attack(url)
            if detection:
                result = {
                    'url': url,
                    'source_ip': source_ip,
                    'timestamp': timestamp,
                    'attack_type': detection['attack_type'],
                    'severity': detection['severity'],
                    'confidence_score': detection.get('confidence_score'),
                }
                results.append(result)
                db.insert_detection(result)

        db.insert_file_analysis(filename, file_extension, len(results))

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
    detections = db.get_detections(attack_type=attack_type, source_ip=source_ip)
    return jsonify({'total': len(detections), 'detections': detections}), 200


@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    stats = db.get_statistics()
    return jsonify(stats), 200


@app.route('/api/top-ips', methods=['GET'])
def get_top_ips():
    """Return top attacking IPs with attack count for analyst/SIEM use."""
    stats = db.get_statistics()
    return jsonify({
        'top_source_ips': stats.get('top_source_ips', []),
    }), 200


@app.route('/api/file-history', methods=['GET'])
def get_file_history():
    """Return recent file analysis history (file_name, type, upload_time, total_attacks)."""
    history = db.get_file_analysis_history()
    return jsonify({'file_history': history}), 200


@app.route('/api/clear-database', methods=['POST'])
def clear_database():
    """Delete all detections and file history; reset auto-increment IDs."""
    db.clear_all()
    return jsonify({'message': 'Database cleared successfully'}), 200


@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    attack_type = request.args.get('attack_type', None)
    source_ip = request.args.get('source_ip', None)
    detections = db.get_detections(attack_type=attack_type, source_ip=source_ip)

    output = StringIO()
    if detections:
        writer = csv.DictWriter(output, fieldnames=detections[0].keys(), extrasaction='ignore')
        writer.writeheader()
        writer.writerows(detections)

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=detections.csv'}
    )


@app.route('/api/export/json', methods=['GET'])
def export_json():
    attack_type = request.args.get('attack_type', None)
    source_ip = request.args.get('source_ip', None)
    detections = db.get_detections(attack_type=attack_type, source_ip=source_ip)
    return jsonify({'total': len(detections), 'detections': detections}), 200


if __name__ == '__main__':
    db.init_db()
    app.run(debug=True, port=5000)
