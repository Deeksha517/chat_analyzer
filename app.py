import os
import re
from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from flask_bcrypt import Bcrypt # type: ignore
from flask_sqlalchemy import SQLAlchemy    # type: ignore
from flask_migrate import Migrate  # Import Flask-Migrate    # type: ignore
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Secure session key
app.config['SESSION_PERMANENT'] = False  # Ensure session expires

# Use PostgreSQL database from Render (Ensure DATABASE_URL is set in Render environment)
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set. Please configure it in your environment variables.")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database, bcrypt, and migration
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Enable migrations
bcrypt = Bcrypt(app)

# Session expiration time (30 minutes)
SESSION_TIMEOUT = timedelta(minutes=30)


# User model (Updated with password column)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Store hashed passwords


# Helper functions
def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def verify_password(hashed_password, password):
    return bcrypt.check_password_hash(hashed_password, password)

def user_exists(username):
    return User.query.filter_by(username=username).first() is not None

def create_user(username, email, password):
    if user_exists(username):
        return False  # Username already exists
    hashed_password = hash_password(password)
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return True

def get_user(username):
    return User.query.filter_by(username=username).first()

def is_strong_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$', password))

def is_session_expired():
    return 'last_activity' in session and datetime.now() - datetime.strptime(session['last_activity'], '%Y-%m-%d %H:%M:%S') > SESSION_TIMEOUT

def update_session_activity():
    session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# Routes
@app.route('/')
def home():
    return render_template('splash.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if user_exists(username):
            return render_template('register.html', error="Username already exists", password_error=None)

        if not is_strong_password(password):
            return render_template('register.html', error=None, password_error="Weak password! Use at least 8 characters with uppercase, lowercase, numbers, and symbols.")

        if create_user(username, email, password):
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error="Error creating user", password_error=None)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user(username)
        if user and verify_password(user.password, password):
            session['username'] = username
            update_session_activity()
            return redirect(url_for('dashboard'))

        return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session or is_session_expired():
        session.pop('username', None)
        return redirect(url_for('login'))

    update_session_activity()
    return f"Welcome {session['username']}! You are logged in."


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Render provides a PORT dynamically
    app.run(host="0.0.0.0", port=port)