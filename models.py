from datetime import datetime
from flask_login import UserMixin
from app import db
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationship with scan results
    scan_results = db.relationship('ScanResult', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for guest scans
    target_url = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # light, medium, deep, network
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), default='running')  # running, completed, failed
    total_vulnerabilities = db.Column(db.Integer, default=0)
    high_severity = db.Column(db.Integer, default=0)
    medium_severity = db.Column(db.Integer, default=0)
    low_severity = db.Column(db.Integer, default=0)
    scan_config = db.Column(db.Text, nullable=True)  # JSON string of scan configuration
    
    # Relationship with vulnerabilities
    vulnerabilities = db.relationship('Vulnerability', backref='scan_result', lazy=True, cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'status': self.status,
            'total_vulnerabilities': self.total_vulnerabilities,
            'high_severity': self.high_severity,
            'medium_severity': self.medium_severity,
            'low_severity': self.low_severity,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
    
    def to_json(self):
        return json.dumps(self.to_dict())


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    vulnerability_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)  # URL, file path, etc.
    severity = db.Column(db.String(50), nullable=False)  # high, medium, low
    evidence = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    remediation_code = db.Column(db.Text, nullable=True)  # Code snippet for remediation
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'vulnerability_type': self.vulnerability_type,
            'description': self.description,
            'location': self.location,
            'severity': self.severity,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'remediation_code': self.remediation_code,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
