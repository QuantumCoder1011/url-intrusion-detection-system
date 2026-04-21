import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class FileAnalysis(db.Model):
    __tablename__ = 'file_analysis'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    upload_time = db.Column(db.String(100), nullable=False)
    total_attacks_detected = db.Column(db.Integer, nullable=False, default=0)

class Detection(db.Model):
    __tablename__ = 'detections'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_analysis_id = db.Column(db.Integer, db.ForeignKey('file_analysis.id'), nullable=True)
    url = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(100), default='Unknown')
    timestamp = db.Column(db.String(100))
    attack_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    pattern_matched = db.Column(db.Text)
    confidence_score = db.Column(db.Integer)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    detection_source = db.Column(db.String(50), default='Rule')  # Rule, ML, Hybrid

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Analyst') # Admin, Analyst

class Rule(db.Model):
    __tablename__ = 'rules'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pattern = db.Column(db.Text, nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(50), nullable=False) # High, Medium, Low
    enabled = db.Column(db.Boolean, default=True)
