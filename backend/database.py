import sqlite3
import os
import threading
from typing import List, Dict, Optional
from datetime import datetime

class Database:
    """Handles database operations for storing detection results. Uses one connection per thread (Flask uses multiple threads)."""
    
    def __init__(self, db_path: str = 'detections.db'):
        self.db_path = db_path
        self._local = threading.local()
    
    def get_connection(self):
        """Get or create a database connection for the current thread"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def init_db(self):
        """Initialize database with required tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                source_ip TEXT,
                timestamp TEXT,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                pattern_matched TEXT,
                detected_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
    
    def insert_detection(self, detection: Dict):
        """Insert a detection result into the database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO detections (url, source_ip, timestamp, attack_type, severity, pattern_matched)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            detection.get('url', ''),
            detection.get('source_ip', 'Unknown'),
            detection.get('timestamp', ''),
            detection.get('attack_type', ''),
            detection.get('severity', 'Medium'),
            detection.get('pattern_matched', '')
        ))
        
        conn.commit()
    
    def get_detections(self, attack_type: Optional[str] = None, source_ip: Optional[str] = None) -> List[Dict]:
        """Get detections with optional filters"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM detections WHERE 1=1'
        params = []
        
        if attack_type:
            query += ' AND attack_type = ?'
            params.append(attack_type)
        
        if source_ip:
            query += ' AND source_ip = ?'
            params.append(source_ip)
        
        query += ' ORDER BY detected_at DESC'
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        detections = []
        for row in rows:
            detections.append({
                'id': row['id'],
                'url': row['url'],
                'source_ip': row['source_ip'],
                'timestamp': row['timestamp'],
                'attack_type': row['attack_type'],
                'severity': row['severity'],
                'pattern_matched': row['pattern_matched'],
                'detected_at': row['detected_at']
            })
        
        return detections
    
    def get_statistics(self) -> Dict:
        """Get summary statistics for dashboard"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Total detections
        cursor.execute('SELECT COUNT(*) as total FROM detections')
        total = cursor.fetchone()['total']
        
        # Detections by attack type
        cursor.execute('''
            SELECT attack_type, COUNT(*) as count 
            FROM detections 
            GROUP BY attack_type
            ORDER BY count DESC
        ''')
        attack_types = {}
        for row in cursor.fetchall():
            attack_types[row['attack_type']] = row['count']
        
        # Detections by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM detections 
            GROUP BY severity
            ORDER BY count DESC
        ''')
        severities = {}
        for row in cursor.fetchall():
            severities[row['severity']] = row['count']
        
        # Top source IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count 
            FROM detections 
            WHERE source_ip != 'Unknown'
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_ips = []
        for row in cursor.fetchall():
            top_ips.append({
                'ip': row['source_ip'],
                'count': row['count']
            })
        
        return {
            'total_detections': total,
            'by_attack_type': attack_types,
            'by_severity': severities,
            'top_source_ips': top_ips
        }
    
    def clear_all(self):
        """Clear all detections from database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM detections')
        conn.commit()
