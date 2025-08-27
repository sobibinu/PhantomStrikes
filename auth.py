import os
import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from models import User
from app import db
from flask_jwt_extended import create_access_token

auth = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide both email and password', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            flash('Please check your login details and try again.', 'danger')
            return render_template('login.html')
        
        # Update last login time
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Log in the user
        login_user(user)
        
        # Create a JWT token
        access_token = create_access_token(identity=user.id)
        
        # Store the token in session
        session['jwt_token'] = access_token
        
        # Redirect to the dashboard
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('main.dashboard')
            
        flash('Login successful!', 'success')
        return redirect(next_page)
    
    return render_template('login.html')

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Basic form validation
        if not email or not username or not password:
            flash('Please fill in all required fields', 'danger')
            return render_template('login.html', signup_mode=True)
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('login.html', signup_mode=True)
        
        # Check if user already exists
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            flash('Email already registered', 'danger')
            return render_template('login.html', signup_mode=True)
        
        user_by_username = User.query.filter_by(username=username).first()
        if user_by_username:
            flash('Username already taken', 'danger')
            return render_template('login.html', signup_mode=True)
        
        # Create new user
        new_user = User(
            email=email,
            username=username,
            password_hash=generate_password_hash(password),
            created_at=datetime.utcnow()
        )
        
        # Add user to database
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('login.html', signup_mode=True)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('jwt_token', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@auth.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@auth.route('/oauth/google')
def oauth_google():
    # This would normally use a library like authlib or requests-oauthlib
    # to handle the OAuth flow. For simplicity, we're just redirecting
    # to a mock Google login page.
    client_id = current_app.config.get('GOOGLE_CLIENT_ID')
    redirect_uri = url_for('auth.oauth_google_callback', _external=True)
    
    # In a real implementation, redirect to Google's OAuth endpoint
    # For now, we'll just demonstrate the concept
    flash('OAuth implementation would redirect to Google here.', 'info')
    return redirect(url_for('main.index'))

@auth.route('/oauth/google/callback')
def oauth_google_callback():
    # This would normally process the callback from Google OAuth
    # For simplicity, we'll just create a demo user
    
    # In a real implementation, verify the state parameter and exchange
    # the authorization code for an access token, then use the access token
    # to fetch the user's profile information from Google
    
    # Check if the user already exists by OAuth ID
    demo_oauth_id = "123456789"
    user = User.query.filter_by(oauth_provider='google', oauth_id=demo_oauth_id).first()
    
    if not user:
        # Create a new user
        user = User(
            email=f"google_user_{demo_oauth_id}@example.com",
            username=f"google_user_{demo_oauth_id}",
            password_hash=generate_password_hash("not-used-with-oauth"),
            oauth_provider='google',
            oauth_id=demo_oauth_id,
            created_at=datetime.utcnow()
        )
        db.session.add(user)
        db.session.commit()
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Log in the user
    login_user(user)
    
    flash('Successfully logged in with Google!', 'success')
    return redirect(url_for('main.dashboard'))

@auth.route('/api/token', methods=['POST'])
def get_token():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    
    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400
        
    user = User.query.filter_by(email=email).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Create a new token
    access_token = create_access_token(identity=user.id)
    
    # Update last login time
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    return jsonify(access_token=access_token), 200
