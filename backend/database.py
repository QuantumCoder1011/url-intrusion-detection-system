"""
Database layer for URL Intrusion Detection System.

Stores detection results and file analysis history. Uses one connection per thread
(Flask multi-threaded). Schema supports confidence scores and file metadata for
analyst usability; could be extended for SIEM integration (e.g. export to syslog).
"""

import sqlite3
import threading
from typing import List, Dict, Optional
from datetime import datetime

class Database:
    def __init__(self, db_path: str = 'detections.db'):
        self.db_path = db_path
        self._local = threading.local()

    def get_connection(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def init_db(self):
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
                confidence_score INTEGER,
                detected_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_type TEXT NOT NULL,
                upload_time TEXT NOT NULL,
                total_attacks_detected INTEGER NOT NULL DEFAULT 0
            )
        ''')

        # Migration: add confidence_score if missing (e.g. existing DBs)
        cursor.execute("PRAGMA table_info(detections)")
        cols = [row[1] for row in cursor.fetchall()]
        if 'confidence_score' not in cols:
            cursor.execute("ALTER TABLE detections ADD COLUMN confidence_score INTEGER")

        conn.commit()

    def insert_detection(self, detection: Dict):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO detections (url, source_ip, timestamp, attack_type, severity, pattern_matched, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            detection.get('url', ''),
            detection.get('source_ip', 'Unknown'),
            detection.get('timestamp', ''),
            detection.get('attack_type', ''),
            detection.get('severity', 'Medium'),
            detection.get('pattern_matched', ''),
            detection.get('confidence_score'),
        ))
        conn.commit()

    def insert_file_analysis(self, file_name: str, file_type: str, total_attacks: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_analysis (file_name, file_type, upload_time, total_attacks_detected)
            VALUES (?, ?, ?, ?)
        ''', (file_name, file_type, datetime.utcnow().isoformat() + 'Z', total_attacks))
        conn.commit()

    def get_detections(self, attack_type: Optional[str] = None, source_ip: Optional[str] = None) -> List[Dict]:
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
        return [_row_to_detection(row) for row in rows]

    def get_file_analysis_history(self) -> List[Dict]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, file_name, file_type, upload_time, total_attacks_detected
            FROM file_analysis ORDER BY upload_time DESC LIMIT 50
        ''')
        return [
            {
                'id': row['id'],
                'file_name': row['file_name'],
                'file_type': row['file_type'],
                'upload_time': row['upload_time'],
                'total_attacks_detected': row['total_attacks_detected'],
            }
            for row in cursor.fetchall()
        ]

    def get_statistics(self) -> Dict:
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) as total FROM detections')
        total = cursor.fetchone()['total']

        cursor.execute('''
            SELECT attack_type, COUNT(*) as count FROM detections
            GROUP BY attack_type ORDER BY count DESC
        ''')
        by_attack_type = {row['attack_type']: row['count'] for row in cursor.fetchall()}

        cursor.execute('''
            SELECT severity, COUNT(*) as count FROM detections
            GROUP BY severity ORDER BY count DESC
        ''')
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

        cursor.execute('''
            SELECT source_ip, COUNT(*) as count FROM detections
            WHERE source_ip != 'Unknown'
            GROUP BY source_ip ORDER BY count DESC LIMIT 10
        ''')
        top_source_ips = [{'ip': row['source_ip'], 'count': row['count']} for row in cursor.fetchall()]

        return {
            'total_detections': total,
            'by_attack_type': by_attack_type,
            'by_severity': by_severity,
            'top_source_ips': top_source_ips,
        }

    def clear_all(self):
        """Delete all detections and file history, and reset auto-increment IDs."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM detections')
        cursor.execute('DELETE FROM file_analysis')
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='detections'")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='file_analysis'")
        conn.commit()


def _row_to_detection(row) -> Dict:
    d = {
        'id': row['id'],
        'url': row['url'],
        'source_ip': row['source_ip'],
        'timestamp': row['timestamp'],
        'attack_type': row['attack_type'],
        'severity': row['severity'],
        'pattern_matched': row['pattern_matched'],
        'detected_at': row['detected_at'],
    }
    if 'confidence_score' in row.keys() and row['confidence_score'] is not None:
        d['confidence_score'] = row['confidence_score']
    return d
