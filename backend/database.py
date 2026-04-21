"""
Database layer for URL Intrusion Detection System.

Migrated to PostgreSQL using SQLAlchemy for scalability and SIEM integration.
Maintains backward compatibility with original raw SQL queries via ORM wrapping.
"""

from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy import func
from models import db, Detection, FileAnalysis, User, Rule
import bcrypt

class Database:
    def __init__(self):
        pass

    def init_db(self):
        # SQLAlchemy create_all() is handled in app.py now.
        pass

    def insert_detection(self, detection: Dict, file_analysis_id: Optional[int] = None):
        new_det = Detection(
            file_analysis_id=file_analysis_id,
            url=detection.get('url', ''),
            source_ip=detection.get('source_ip', 'Unknown'),
            timestamp=detection.get('timestamp', ''),
            attack_type=detection.get('attack_type', ''),
            severity=detection.get('severity', 'Medium'),
            pattern_matched=detection.get('pattern_matched', ''),
            confidence_score=detection.get('confidence_score'),
            detection_source=detection.get('detection_source', 'Rule')
        )
        db.session.add(new_det)
        db.session.commit()

    def insert_file_analysis(self, file_name: str, file_type: str, total_attacks: int) -> int:
        new_file = FileAnalysis(
            file_name=file_name,
            file_type=file_type,
            upload_time=datetime.utcnow().isoformat() + 'Z',
            total_attacks_detected=total_attacks
        )
        db.session.add(new_file)
        db.session.commit()
        return new_file.id

    def get_detections(self, attack_type: Optional[str] = None, source_ip: Optional[str] = None,
                       file_id: Optional[int] = None, severity: Optional[str] = None,
                       detection_source: Optional[str] = None) -> List[Dict]:
        query = Detection.query
        if attack_type:
            query = query.filter(Detection.attack_type == attack_type)
        if source_ip:
            query = query.filter(Detection.source_ip == source_ip)
        if file_id is not None:
            query = query.filter(Detection.file_analysis_id == file_id)
        if severity:
            query = query.filter(Detection.severity == severity)
        if detection_source:
            query = query.filter(Detection.detection_source == detection_source)
        
        query = query.order_by(Detection.detected_at.desc())
        rows = query.all()
        return [self._row_to_dict(row) for row in rows]

    def get_file_analysis_history(self) -> List[Dict]:
        rows = FileAnalysis.query.order_by(FileAnalysis.upload_time.desc()).limit(50).all()
        return [
            {
                'id': row.id,
                'file_name': row.file_name,
                'file_type': row.file_type,
                'upload_time': row.upload_time,
                'total_attacks_detected': row.total_attacks_detected,
            }
            for row in rows
        ]

    def get_statistics(self, file_id: Optional[int] = None, severity: Optional[str] = None) -> Dict:
        query = db.session.query(Detection)
        if file_id is not None:
            query = query.filter(Detection.file_analysis_id == file_id)
        if severity:
            query = query.filter(Detection.severity == severity)

        total = query.count()

        # by_attack_type
        attack_counts = query.with_entities(Detection.attack_type, func.count(Detection.id)).group_by(Detection.attack_type).all()
        by_attack_type = {row[0]: row[1] for row in attack_counts}

        # by_severity
        severity_counts = query.with_entities(Detection.severity, func.count(Detection.id)).group_by(Detection.severity).all()
        
        by_severity = {'High': 0, 'Medium': 0, 'Low': 0}
        for row in severity_counts:
            if row[0] in by_severity:
                by_severity[row[0]] = row[1]
            else:
                by_severity[row[0]] = row[1]

        # top_source_ips
        top_ips = query.filter(Detection.source_ip != 'Unknown').with_entities(Detection.source_ip, func.count(Detection.id)).group_by(Detection.source_ip).order_by(func.count(Detection.id).desc()).limit(10).all()
        
        top_source_ips = [{'ip': row[0], 'count': row[1]} for row in top_ips]

        return {
            'total_detections': total,
            'by_attack_type': by_attack_type,
            'by_severity': by_severity,
            'top_source_ips': top_source_ips,
        }

    def clear_all(self):
        db.session.query(Detection).delete()
        db.session.query(FileAnalysis).delete()
        db.session.commit()

    def _row_to_dict(self, row: Detection) -> Dict:
        return {
            'id': row.id,
            'url': row.url,
            'source_ip': row.source_ip,
            'timestamp': row.timestamp,
            'attack_type': row.attack_type,
            'severity': row.severity,
            'pattern_matched': row.pattern_matched or '',
            'confidence_score': row.confidence_score,
            'detected_at': row.detected_at.isoformat() + 'Z' if row.detected_at else None,
            'detection_source': row.detection_source
        }

    # Auth Methods
    def create_user(self, username, password, role='Analyst'):
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user = User(username=username, password_hash=pw_hash, role=role)
        db.session.add(user)
        db.session.commit()
        return user

    def get_user_by_username(self, username):
        return User.query.filter_by(username=username).first()

    def verify_password(self, password, pw_hash):
        return bcrypt.checkpw(password.encode('utf-8'), pw_hash.encode('utf-8'))

    # Rules Methods
    def get_rules(self):
        rules = Rule.query.all()
        return [{"id": r.id, "pattern": r.pattern, "attack_type": r.attack_type, "priority": r.priority, "enabled": r.enabled} for r in rules]

    def add_rule(self, pattern, attack_type, priority, enabled=True):
        rule = Rule(pattern=pattern, attack_type=attack_type, priority=priority, enabled=enabled)
        db.session.add(rule)
        db.session.commit()
        return rule.id
