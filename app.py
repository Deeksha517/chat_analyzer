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

def get_db():
    conn = sqlite3.connect('users.db')  # Ensure 'users.db' is the correct path
    conn.row_factory = sqlite3.Row  # Enables dictionary-style access
    return conn

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

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or is_session_expired():
        session.pop('username', None)  # Log out user if session expired
        return redirect(url_for('login'))
    
    # Clear search results when returning to the dashboard
    session.pop('search_results', None)
    session.pop('current_index', None)

    update_session_activity()
    return render_template('dashboard.html', username=session['username'])


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if user_exists(username):
            return render_template('register.html', error="Username already exists", password_error=None)

        # Hash password before saving
        hashed_password = hash_password(password)

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (username, password, bio, interests, profile_pic) 
                VALUES (?, ?, 'Hey there! I am using Chat Analyzer.', '', 'default.jpg')
            """, (username, hashed_password))
            conn.commit()

            session['username'] = username  # Store session with correct key
            return redirect('/edit_profile')  # Redirect new users to profile setup

        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username already exists", password_error=None)

        finally:
            conn.close()

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user['password'], password):
            session['username'] = username  # Store session with correct key

            # Check if the profile is incomplete
            if user['bio'] == "Hey there! I am using Chat Analyzer." and not user['interests']:
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
        remove_pic = request.form.get('remove_pic')  # Check if user wants to remove photo

        # Ensure the directory exists
        profile_pic_dir = 'static/profile_pics'
        if not os.path.exists(profile_pic_dir):
            os.makedirs(profile_pic_dir)

        # Fetch current user data
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_pic FROM users WHERE username=?", (username,))
            current_pic = cursor.fetchone()[0]

        # Handle profile picture logic
        if remove_pic:  # If the user chooses to remove the picture
            pic_filename = "default.jpg"
            if current_pic and current_pic != "default.jpg":
                os.remove(os.path.join(profile_pic_dir, current_pic))  # Delete old photo
        elif profile_pic:  # If user uploads a new picture
            pic_filename = f"{username}.jpg"
            profile_pic.save(os.path.join(profile_pic_dir, pic_filename))
        else:
            pic_filename = current_pic  # Keep the existing picture

        # Update the database
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET bio=?, interests=?, profile_pic=? WHERE username=?",
                           (bio, interests, pic_filename, username))
            conn.commit()

        return redirect(url_for('view_profile', username=username))

    # Fetch user data for pre-filling the form
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT bio, interests, profile_pic FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

    return render_template('edit_profile.html', user={
        "bio": user[0],
        "interests": user[1],
        "profile_pic": user[2]
    })

@app.route('/search_friends', methods=['GET', 'POST'])
def search_friends():
    session.setdefault('search_history', [])  # Ensure search history exists

    last_search = ""
    users = []

    # 🚀 Clear search results ONLY if coming from Dashboard (fresh GET request without results)
    if request.method == 'GET' and 'clear_results' in session:
        session.pop('search_results', None)
        session.pop('current_index', None)
        session.pop('clear_results', None)  # Remove flag after clearing
        session.modified = True  # Ensure session updates

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


@app.route('/browse_results', methods=['GET'])
def browse_results():
    if 'username' not in session or is_session_expired():
        session.pop('username', None)
        return redirect(url_for('login'))
    update_session_activity()

    search_results = session.get('search_results', [])
    index = session.get('current_index', 0)

    if not search_results:
        return render_template('search.html', message="No users found.")  # Redirect to search page with message

    # Get the username of the current user being viewed
    selected_user = search_results[index]
    
    # Fetch additional user details (bio, profile_pic, interests) from the database
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, bio, profile_pic, interests FROM users WHERE username = ?", (selected_user['username'],))
        user_data = cursor.fetchone()

    if not user_data:
        return render_template('search.html', message="User not found.")

    # Package the fetched user data into a dictionary
    user = {
        "username": user_data[0],
        "bio": user_data[1],
        "profile_pic": user_data[2] if user_data[2] else 'default.jpg',  # Handle missing profile_pic
        "interests": user_data[3]
    }

    # Pass the user data to the template
    return render_template('browse.html', user=user, index=index, total=len(search_results))



@app.route('/next_user')
def next_user():
    if 'search_results' in session and session['current_index'] < len(session['search_results']) - 1:
        session['current_index'] += 1
        # Automatically use session info for the redirection
        return redirect(url_for('browse_results'))

@app.route('/prev_user')
def prev_user():
    if 'search_results' in session and session['current_index'] > 0:
        session['current_index'] -= 1
        # Automatically use session info for the redirection
        return redirect(url_for('browse_results'))


@app.route('/profile/<username>')
def view_profile(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, bio, profile_pic, interests FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return "User not found."

    return render_template('profile.html', 
                           user=user, 
                           is_owner=(session.get('username') == username))  # Pass ownership flag


@app.route('/chat/<username>')
def chat(username):
    if 'username' not in session or is_session_expired():
        session.pop('username', None)
        return redirect(url_for('login'))
    update_session_activity()

    return render_template('chat.html', username=username)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)