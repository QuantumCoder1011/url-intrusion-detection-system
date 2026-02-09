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
                file_analysis_id INTEGER,
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
        if 'file_analysis_id' not in cols:
            cursor.execute("ALTER TABLE detections ADD COLUMN file_analysis_id INTEGER REFERENCES file_analysis(id)")

        conn.commit()

    def insert_detection(self, detection: Dict, file_analysis_id: Optional[int] = None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO detections (file_analysis_id, url, source_ip, timestamp, attack_type, severity, pattern_matched, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            file_analysis_id,
            detection.get('url', ''),
            detection.get('source_ip', 'Unknown'),
            detection.get('timestamp', ''),
            detection.get('attack_type', ''),
            detection.get('severity', 'Medium'),
            detection.get('pattern_matched', ''),
            detection.get('confidence_score'),
        ))
        conn.commit()

    def insert_file_analysis(self, file_name: str, file_type: str, total_attacks: int) -> int:
        """Insert file analysis record and return its id for linking detections."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_analysis (file_name, file_type, upload_time, total_attacks_detected)
            VALUES (?, ?, ?, ?)
        ''', (file_name, file_type, datetime.utcnow().isoformat() + 'Z', total_attacks))
        conn.commit()
        return cursor.lastrowid

    def get_detections(self, attack_type: Optional[str] = None, source_ip: Optional[str] = None,
                       file_id: Optional[int] = None, severity: Optional[str] = None) -> List[Dict]:
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
        if file_id is not None:
            query += ' AND file_analysis_id = ?'
            params.append(file_id)
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
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

    def get_statistics(self, file_id: Optional[int] = None, severity: Optional[str] = None) -> Dict:
        """Get detection statistics. If file_id or severity is set, filter accordingly."""
        conn = self.get_connection()
        cursor = conn.cursor()
        conditions = []
        params = []
        if file_id is not None:
            conditions.append('file_analysis_id = ?')
            params.append(file_id)
        if severity:
            conditions.append('severity = ?')
            params.append(severity)
        where = 'WHERE ' + ' AND '.join(conditions) if conditions else ''

        cursor.execute(f'SELECT COUNT(*) as total FROM detections {where}', params)
        total = cursor.fetchone()['total']

        cursor.execute(f'''
            SELECT attack_type, COUNT(*) as count FROM detections {where}
            GROUP BY attack_type ORDER BY count DESC
        ''', params)
        by_attack_type = {row['attack_type']: row['count'] for row in cursor.fetchall()}

        # Severity order: High, Medium, Low (High = highest severity; Low = lowest/informational)
        cursor.execute(f'''
            SELECT severity, COUNT(*) as count FROM detections {where}
            GROUP BY severity
        ''', params)
        severity_rows = cursor.fetchall()
        severity_order = ('High', 'Medium', 'Low')
        by_severity = {s: 0 for s in severity_order}
        for row in severity_rows:
            s = row['severity']
            if s in by_severity:
                by_severity[s] = row['count']
            else:
                by_severity[s] = row['count']

        top_conditions = ["source_ip != 'Unknown'"]
        top_params = []
        if file_id is not None:
            top_conditions.append('file_analysis_id = ?')
            top_params.append(file_id)
        if severity:
            top_conditions.append('severity = ?')
            top_params.append(severity)
        top_where = 'WHERE ' + ' AND '.join(top_conditions)
        cursor.execute(f'''
            SELECT source_ip, COUNT(*) as count FROM detections {top_where}
            GROUP BY source_ip ORDER BY count DESC LIMIT 10
        ''', top_params)
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
