from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
import json
import csv
from io import StringIO, BytesIO

from detection_engine import DetectionEngine
from data_ingestion import DataIngestion
from database import Database

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'pcap'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize components
detection_engine = DetectionEngine()
data_ingestion = DataIngestion()
db = Database()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'URL Intrusion Detection System API is running'})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file upload and process it"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Extract URLs based on file type
            file_extension = filename.rsplit('.', 1)[1].lower()
            urls = data_ingestion.process_file(filepath, file_extension)
            
            # Analyze URLs for attacks
            results = []
            for url_data in urls:
                url = url_data.get('url', '')
                source_ip = url_data.get('source_ip', 'Unknown')
                timestamp = url_data.get('timestamp', '')
                
                detected_attacks = detection_engine.analyze_url(url)
                
                if detected_attacks:
                    for attack in detected_attacks:
                        result = {
                            'url': url,
                            'source_ip': source_ip,
                            'timestamp': timestamp,
                            'attack_type': attack['type'],
                            'severity': attack['severity'],
                            'pattern_matched': attack['pattern']
                        }
                        results.append(result)
                        # Store in database
                        db.insert_detection(result)
            
            # Clean up uploaded file
            os.remove(filepath)
            
            return jsonify({
                'message': 'File processed successfully',
                'total_urls': len(urls),
                'detected_attacks': len(results),
                'results': results
            }), 200
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500
    
    return jsonify({'error': 'Invalid file type. Only CSV and PCAP files are allowed'}), 400

@app.route('/api/detections', methods=['GET'])
def get_detections():
    """Get all detected attacks with optional filters"""
    attack_type = request.args.get('attack_type', None)
    source_ip = request.args.get('source_ip', None)
    
    detections = db.get_detections(attack_type=attack_type, source_ip=source_ip)
    return jsonify({
        'total': len(detections),
        'detections': detections
    }), 200

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get summary statistics for the dashboard"""
    stats = db.get_statistics()
    return jsonify(stats), 200

@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export detections as CSV"""
    attack_type = request.args.get('attack_type', None)
    source_ip = request.args.get('source_ip', None)
    
    detections = db.get_detections(attack_type=attack_type, source_ip=source_ip)
    
    output = StringIO()
    if detections:
        writer = csv.DictWriter(output, fieldnames=detections[0].keys())
        writer.writeheader()
        writer.writerows(detections)
    
    output.seek(0)
    csv_data = output.getvalue()
    output.close()
    
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=detections.csv'}
    )

@app.route('/api/export/json', methods=['GET'])
def export_json():
    """Export detections as JSON"""
    attack_type = request.args.get('attack_type', None)
    source_ip = request.args.get('source_ip', None)
    
    detections = db.get_detections(attack_type=attack_type, source_ip=source_ip)
    
    return jsonify({
        'total': len(detections),
        'detections': detections
    }), 200

@app.route('/api/clear', methods=['POST'])
def clear_database():
    """Clear all detections from database"""
    db.clear_all()
    return jsonify({'message': 'Database cleared successfully'}), 200

if __name__ == '__main__':
    db.init_db()
    app.run(debug=True, port=5000)
