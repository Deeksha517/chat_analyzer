import re
import os
import sqlite3
import hashlib
from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from flask_bcrypt import Bcrypt # type: ignore
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Secure session key

# Session expiration time (30 minutes)
SESSION_TIMEOUT = timedelta(minutes=30)

# Initialize bcrypt for password hashing
bcrypt = Bcrypt(app)

# Database connection helper
def get_db_connection():
    return sqlite3.connect('users.db')

# Password hashing using bcrypt
def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

# Check if user exists
def user_exists(username):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None

# Create new user
def create_user(username, password):
    if user_exists(username):
        return False  # Username already exists
    hashed_password = hash_password(password)
    with get_db_connection() as conn:
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Handle duplicate username

# Verify login credentials
def verify_user(username, password):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        return user and bcrypt.check_password_hash(user[0], password)

# Check password strength
def is_strong_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&])[A-Za-z\d!@#$%^&]{8,}$', password))


# Session expiration check
def is_session_expired():
    return 'last_activity' in session and datetime.now() - datetime.strptime(session['last_activity'], '%Y-%m-%d %H:%M:%S') > SESSION_TIMEOUT

# Update session activity timestamp
def update_session_activity():
    session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Routes
@app.route('/')
def home():
    return render_template('splash.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        
        # Check if the username already exists
        if user_exists(username):
            return render_template('register.html', error="Username already exists", password_error=None)
        
        # Check for weak password
        if not is_strong_password(password):
            return render_template('register.html', error=None, password_error="Weak password! Use at least 8 characters with uppercase, lowercase, numbers, and symbols.")
        
        # Create the user and handle success or failure
        if create_user(username, password):
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error="Error creating user", password_error=None)
    
    # Render the register page for GET request
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        if verify_user(username, password):
            session['username'] = username
            update_session_activity()
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or is_session_expired():
        session.pop('username', None)  # Log out user if session expired
        return redirect(url_for('login'))
    update_session_activity()
    return f"Welcome {session['username']}! You are logged in."

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)