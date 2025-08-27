import os

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'phantom-strike-default-secret')
    DEBUG = os.environ.get('DEBUG', 'True') == 'True'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///phantom_strike.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'phantom-strike-jwt-secret')
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    
    # OAuth Configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # DeepAI Configuration
    DEEPAI_API_KEY = os.environ.get('DEEPAI_API_KEY', 'quickstart-QUdJIGlzIGNvbWluZy4uLi4K')
    
    # Scanning Configuration
    SCAN_TIMEOUT = 300  # 5 minutes
    MAX_GUEST_SCANS_PER_DAY = 3
    
    # Vulnerability Scanner Configuration
    SCAN_TYPES = {
        'light': {
            'timeout': 60,
            'checks': ['xss', 'sqli', 'csrf']
        },
        'medium': {
            'timeout': 180,
            'checks': ['xss', 'sqli', 'csrf', 'lfi', 'rfi', 'directory_traversal', 'auth_issues']
        },
        'deep': {
            'timeout': 300,
            'checks': ['xss', 'sqli', 'csrf', 'lfi', 'rfi', 'directory_traversal', 'auth_issues', 
                      'security_misconfigurations', 'sensitive_data_exposure', 'idor']
        },
        'network': {
            'timeout': 300,
            'ports': '1-1000'
        }
    }
