import os
import sys
from datetime import datetime
from werkzeug.security import generate_password_hash
from app import create_app, db
from models import User
from sqlalchemy import text

def create_test_user(username, email, password):
    """Create a test user with given credentials"""
    app = create_app()
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            print(f"User with username '{username}' or email '{email}' already exists!")
            return False
        
        try:
            # Create user with raw SQL to avoid constructor issues
            password_hash = generate_password_hash(password)
            sql = text(f"""
                INSERT INTO user (username, email, password_hash, created_at) 
                VALUES (:username, :email, :password_hash, :created_at)
            """)
            
            db.session.execute(sql, {
                'username': username, 
                'email': email, 
                'password_hash': password_hash,
                'created_at': datetime.utcnow()
            })
            db.session.commit()
            
            print(f"Successfully created test user: {username} ({email})")
            print(f"Password: {password}")
            return True
        except Exception as e:
            print(f"Error creating user: {e}")
            db.session.rollback()
            return False

if __name__ == "__main__":
    # Create admin test user
    create_test_user("admin", "admin@phantomstrike.com", "Admin@123")
    
    # Create regular test user
    create_test_user("tester", "test@phantomstrike.com", "Test@123")