import re
import os
import sqlite3
import hashlib
from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from flask_bcrypt import Bcrypt  # type: ignore
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session
from flask_socketio import SocketIO, emit # type: ignore



# Initialize Flask app
app = Flask(__name__)

# Set secret key securely
app.config['SECRET_KEY'] = os.urandom(24)  

# Configure session expiration (30 minutes)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Define session timeout duration (e.g., 30 minutes)
SESSION_TIMEOUT = timedelta(minutes=30)

# Session expiration check
def is_session_expired():
    if 'last_activity' not in session:
        return True  # If there's no last activity, session is expired

    last_activity_time = datetime.strptime(session['last_activity'], '%Y-%m-%d %H:%M:%S')
    return datetime.now() - last_activity_time > SESSION_TIMEOUT

# Update session activity timestamp
def update_session_activity():
    session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# Initialize Flask extensions
bcrypt = Bcrypt(app)  # Password hashing
socketio = SocketIO(app)  # Enables real-time messaging

# Database name
DB_NAME = 'users.db'

# Database connection helper
def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row  # Enables dictionary-style access
    return conn

# Password hashing using bcrypt
def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

# Check if user exists
def user_exists(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None

# Create new user
def create_user(username, password):
    if user_exists(username):
        return False  # Username already exists
    hashed_password = hash_password(password)
    with get_db() as conn:
        try:
            conn.execute("""
                INSERT INTO users (username, password, bio, interests, profile_pic) 
                VALUES (?, ?, 'Hey there! I am using Chat Analyzer.', '', 'default.jpg')
            """, (username, hashed_password))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Handle duplicate username

# Verify login credentials
def verify_user(username, password):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        return user and bcrypt.check_password_hash(user[0], password)

# Check password strength
def is_strong_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&])[A-Za-z\d!@#$%^&]{8,}$', password))

# Routes
@app.route('/')
def home():
    return render_template('splash.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if user_exists(username):
            return render_template('register.html', error="Username already exists", password_error=None)

        if not is_strong_password(password):
            return render_template('register.html', error=None, password_error="Weak password. Use uppercase, lowercase, number, and special character.")

        if create_user(username, password):
            session['username'] = username
            return redirect('/edit_profile')  # Redirect new users to profile setup

        return render_template('register.html', error="Registration failed", password_error=None)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()  # Assuming you have a function to get DB connection
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Accessing columns by index
            stored_password_hash = user[2]  # Password is the 3rd column
            bio = user[3]  # Bio is the 4th column
            interests = user[5]  # Interests is the 6th column
            
            if bcrypt.check_password_hash(stored_password_hash, password):
                session['username'] = username
                update_session_activity()

                # Check if this is the first-time user by verifying the bio and interests
                if bio == "Hey there! I am using ConvoIQ." and not interests:
                    return redirect('/edit_profile')  # Redirect first-time users to profile setup
                
                return redirect('/dashboard')  # Redirect returning users to the dashboard

        return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    if request.method == 'POST':
        bio = request.form['bio']
        interests = request.form['interests']
        profile_pic = request.files.get('profile_pic')
        remove_pic = request.form.get('remove_pic')

        profile_pic_dir = 'static/profile_pics'
        os.makedirs(profile_pic_dir, exist_ok=True)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_pic FROM users WHERE username=?", (username,))
            current_pic = cursor.fetchone()[0]

        pic_filename = current_pic

        if remove_pic and current_pic != "default.jpg":
            os.remove(os.path.join(profile_pic_dir, current_pic))
            pic_filename = "default.jpg"
        elif profile_pic:
            pic_filename = f"{username}.jpg"
            profile_pic.save(os.path.join(profile_pic_dir, pic_filename))

        # Update bio, interests, and profile_pic in the database
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET bio=?, interests=?, profile_pic=? WHERE username=?",
                           (bio, interests, pic_filename, username))
            conn.commit()

        return redirect(url_for('dashboard'))  # Redirect to the dashboard after profile is updated

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT bio, interests, profile_pic FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

    return render_template('edit_profile.html', user=dict(user))


@app.route('/dashboard')
def dashboard():
    if 'username' not in session or is_session_expired():
        session.pop('username', None)
        return redirect(url_for('login'))
    
    # Clear search results when returning to dashboard
    session.pop('search_results', None)  
    session.pop('current_index', None)  
    session.modified = True  # Ensure session updates
    
    update_session_activity()
    return render_template('dashboard.html', username=session['username'])

@app.route('/search_friends', methods=['GET', 'POST'])
def search_friends():
    session.setdefault('search_history', [])  # Ensures search history exists

    last_search = ""
    users = []

    if request.method == 'POST':
        query = request.form.get('query', "").strip()
        last_search = query

        if query and query not in session['search_history']:
            session['search_history'].insert(0, query)
            session['search_history'] = session['search_history'][:5]  # Keep last 5 searches
            session.modified = True  # Mark session as modified

        with get_db() as conn:
            conn.row_factory = sqlite3.Row  # Enable dictionary-like access
            cursor = conn.cursor()
            cursor.execute("SELECT username, bio, profile_pic FROM users WHERE LOWER(username) LIKE LOWER(?) LIMIT 10", (f"%{query}%",))
            result = cursor.fetchall()
            users = [dict(row) for row in result]  # Convert rows to dictionaries

        session['search_results'] = users  # Store search results
        session['current_index'] = 0  # Reset index
        session.modified = True  # Mark session as modified

    users = session.get('search_results', [])  # Retrieve safely
    user = users[session.get('current_index', 0)] if users else None  # Avoid errors

    return render_template('search.html', user=user, last_search=last_search, search_history=session['search_history'])

@app.route('/next_user')
def next_user():
    if session.get('search_results') and session.get('current_index', 0) < len(session['search_results']) - 1:
        session['current_index'] += 1
        session.modified = True
    return redirect(url_for('search_friends'))

@app.route('/prev_user')
def prev_user():
    if session.get('search_results') and session.get('current_index', 0) > 0:
        session['current_index'] -= 1
        session.modified = True
    return redirect(url_for('search_friends'))

@app.route('/profile/<username>')
def view_profile(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, bio, profile_pic, interests FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

    if not user:
        return "User not found."

    return render_template('profile.html', user=dict(user), is_owner=(session.get('username') == username))

@app.route('/chat/<username>')
def chat(username):
    if 'username' not in session or is_session_expired():
        session.pop('username', None)
        return redirect(url_for('login'))
    update_session_activity()

    return render_template('chat.html', username=username)

# Route to send a message
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    sender = session['username']
    receiver = data.get('receiver')
    message = data.get('message')

    if not receiver or not message:
        return jsonify({"error": "Receiver and message required"}), 400

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO messages (sender, receiver, message)
                VALUES (?, ?, ?)
            ''', (sender, receiver, message))
            conn.commit()

        # Emit real-time update
        socketio.emit('new_message', {'sender': sender, 'receiver': receiver, 'message': message})

        return jsonify({"success": True, "message": "Message sent successfully!"})

    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

# Route to fetch chat history
@app.route('/get_chat/<receiver>', methods=['GET'])
def get_chat(receiver):
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    sender = session['username']

    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT sender, receiver, message, timestamp
                FROM messages
                WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                ORDER BY timestamp ASC
            ''', (sender, receiver, receiver, sender))

            chat_history = [dict(row) for row in cursor.fetchall()]
            return jsonify(chat_history)

    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    
# Middleware: Check for session expiration on every request
@app.before_request
def check_session():
    # If no username is in session or session expired, log out
    if 'username' not in session or is_session_expired():
        session.pop('username', None)  # Remove expired session
        return redirect(url_for('login'))  # Redirect to login if session expired

    # Update session activity timestamp
    update_session_activity()

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
