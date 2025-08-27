import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_jwt_extended import JWTManager

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
jwt = JWTManager()

def create_app():
    # Create and configure the app
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET", "phantom-strike-default-secret")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https
    
    # Configure database
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///phantom_strike.db")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Configure JWT
    app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "phantom-strike-jwt-secret")
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hour
    
    # Initialize Flask extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    jwt.init_app(app)
    
    with app.app_context():
        # Import models for table creation
        from models import User, ScanResult, Vulnerability
        
        # Create database tables
        db.create_all()
        
        # Register blueprints
        from auth import auth as auth_blueprint
        from routes import main as main_blueprint
        
        app.register_blueprint(auth_blueprint)
        app.register_blueprint(main_blueprint)
        
        # Configure user loader for Flask-Login
        from models import User
        
        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))
        
        return app
