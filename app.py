import re
import os
import sqlite3
import hashlib
from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from flask_bcrypt import Bcrypt # type: ignore
from datetime import datetime, timedelta
from flask_socketio import SocketIO, join_room, emit
from urllib.parse import urlparse




# 1. Near the top of app.py, define your inbox‑listing SQL
INBOX_QUERY = """
WITH all_msgs AS (
  SELECT receiver AS partner, message, timestamp
    FROM messages
   WHERE sender   = ?
  UNION
  SELECT sender   AS partner, message, timestamp
    FROM messages
   WHERE receiver = ?
)
SELECT partner,
       MAX(timestamp) AS last_time,
       (SELECT message
          FROM all_msgs m2
         WHERE m2.partner = all_msgs.partner
         ORDER BY timestamp DESC
         LIMIT 1
       )              AS last_message
  FROM all_msgs
 GROUP BY partner
 ORDER BY last_time DESC;
"""


# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-please-change'

# Session expiration time (30 minutes)
SESSION_TIMEOUT = timedelta(minutes=30)

# Initialize bcrypt for password hashing
bcrypt = Bcrypt(app)

socketio = SocketIO(app)

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn


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

@app.before_request
def refresh_session_timeout():
    # Skip public/auth routes
    if request.endpoint in ('login', 'register', 'edit_profile', 'logout'):
        return

    if 'username' in session:
        if is_session_expired():
            session.clear()
            return redirect(url_for('login'))
        update_session_activity()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if user_exists(username):
            return render_template('register.html',
                                   error="Username already exists",
                                   password_error=None)

        hashed_password = hash_password(password)
        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (username, password, bio, interests, profile_pic) 
                VALUES (?, ?, 'Hey there! I am using Chat Analyzer.', '', 'default.jpg')
            """, (username, hashed_password))
            conn.commit()

            # 1) Store session
            session['username'] = username
            # 2) Reset last-activity timestamp
            update_session_activity()

            # 3) Redirect new users to profile setup
            return redirect('/edit_profile')

        except sqlite3.IntegrityError:
            return render_template('register.html',
                                   error="Username already exists",
                                   password_error=None)
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
            # 1) Store session
            session['username'] = username
            # 2) Reset last-activity timestamp
            update_session_activity()

            # 3) First-time users to profile setup
            if (user['bio'] == "Hey there! I am using Chat Analyzer."
                    and not user['interests']):
                return redirect('/edit_profile')

            # 4) Returning users to dashboard
            return redirect('/dashboard')

        return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')



@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    if request.method == 'POST':
        bio = request.form['bio']
        gender = request.form['gender']  # Capture gender
        age_group = request.form['age_group']  # Capture age group
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

        # Update the database with gender and age group
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET bio=?, gender=?, age_group=?, interests=?, profile_pic=? WHERE username=?",
                           (bio, gender, age_group, interests, pic_filename, username))
            conn.commit()

        return redirect(url_for('view_profile', username=username))

    # Fetch user data for pre-filling the form
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT bio, gender, age_group, interests, profile_pic FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

    return render_template('edit_profile.html', user={
        "bio": user[0],
        "gender": user[1],
        "age_group": user[2],
        "interests": user[3],
        "profile_pic": user[4]
    })

    

@app.route('/search_friends', methods=['GET'])
def search_friends():
    # gather filters
    username  = request.args.get('username', "").strip()
    gender    = request.args.get('gender', "")
    age_group = request.args.get('age_group', "")
    interest  = request.args.get('interest', "").strip()

    filters = {'username': username, 'gender': gender, 'age_group': age_group, 'interest': interest}
    users = []
    has_filters = any(filters.values())

    if has_filters:
        sql    = "SELECT username, bio, profile_pic, gender, age_group, interests FROM users WHERE 1=1"
        params = []

        if username:
            sql    += " AND LOWER(username) LIKE LOWER(?)"
            params.append(f"%{username}%")
        if gender:
            sql    += " AND gender = ?"
            params.append(gender)
        if age_group:
            sql    += " AND age_group = ?"
            params.append(age_group)
        if interest:
            sql    += " AND LOWER(interests) LIKE LOWER(?)"
            params.append(f"%{interest}%")

        db  = get_db()
        cur = db.execute(sql + " ORDER BY username LIMIT 50", params)
        users = cur.fetchall()

    return render_template('browse.html',
                           users=users,
                           filters=filters,
                           has_filters=has_filters)




@app.route('/browse_results', methods=['GET'])
def browse_results():
    if 'username' not in session or is_session_expired():
        session.pop('username', None)
        return redirect(url_for('login'))
    update_session_activity()

    search_results = session.get('search_results', [])
    index = session.get('current_index', 0)

    if not search_results:
        return render_template('browse.html', user=None, last_search="", search_history=session.get('search_history', []))

    selected_user = search_results[index]

    # Fetch additional user details for display
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, bio, profile_pic, interests FROM users WHERE username = ?", (selected_user['username'],))
        user_data = cursor.fetchone()

    if not user_data:
        return render_template('browse.html', user=None, last_search="", search_history=session.get('search_history', []))

    user = {
        "username": user_data[0],
        "bio": user_data[1],
        "profile_pic": user_data[2] if user_data[2] else 'default.jpg',
        "interests": user_data[3]
    }

    return render_template('browse.html', user=user, last_search="", search_history=session.get('search_history', []))



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




@app.route('/chat/<username>', methods=['GET'])
def chat(username):
    # Check if the user is logged in, otherwise redirect to login
    if 'username' not in session:
        session.pop('username', None)
        return redirect(url_for('login'))

    sender = session['username']
    receiver = username

    # Fetch messages between sender and receiver from the database
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT sender, receiver, message, timestamp
                          FROM messages
                          WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                          ORDER BY timestamp ASC''', (sender, receiver, receiver, sender))
        messages = cursor.fetchall()

    # Get the previous page (referrer)
    referrer = request.referrer
    if referrer:
        back_url = urlparse(referrer).path
        # Avoid redirecting back to login or register pages
        if back_url in ['/login', '/register']:
            back_url = url_for('dashboard')  # Redirect to the dashboard if coming from login/register
    else:
        back_url = url_for('dashboard')  # Fallback to dashboard if referrer is not available

    # Render the chat page with the messages and back button URL
    return render_template('chat.html', username=username, messages=messages, back_url=back_url)

# Route to fetch chat history for a specific conversation
@app.route('/get_chat/<receiver>', methods=['GET'])
def get_chat(receiver):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    sender = session['username']
    
    # Fetch messages between sender and receiver
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT sender, receiver, message, timestamp
                          FROM messages
                          WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                          ORDER BY timestamp ASC''', (sender, receiver, receiver, sender))
        messages = cursor.fetchall()
    
    # Convert query results to a list of dictionaries for JSON response
    chat_history = [{
        'sender': msg['sender'],
        'receiver': msg['receiver'],
        'message': msg['message'],
        'timestamp': msg['timestamp']
    } for msg in messages]

    return jsonify(chat_history)

# Save message to the database
def save_message(sender, receiver, message, timestamp=None):
    if not timestamp:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO messages (sender, receiver, message, timestamp)
            VALUES (?, ?, ?, ?)
        """, (sender, receiver, message, timestamp))
        conn.commit()


@socketio.on('send_message')
def handle_send_message(data):
    sender   = data['sender']
    receiver = data['receiver']
    message  = data['message']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 1) Save to DB
    save_message(sender, receiver, message, timestamp)

    # 2) Emit to the chat room
    room = '_'.join(sorted([sender, receiver]))
    emit('receive_message', {
        'sender':    sender,
        'receiver':  receiver,
        'message':   message,
        'timestamp': timestamp
    }, room=room)

    # 3) Emit to the inbox room
    emit('new_message', {
        'from':      sender,
        'message':   message,
        'timestamp': timestamp
    }, room=f"inbox_{receiver}")

        
        
# 2. Add this new route after your existing @app.route(…) definitions
@app.route('/inbox')
def inbox():
    # a) Ensure the user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    user = session['username']

    # b) Run the SQL to get each conversation’s partner, last message & time
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(INBOX_QUERY, (user, user))
    rows = cursor.fetchall()
    conn.close()

    # c) Normalize for the template: use keys `user`, `last_message`, `timestamp`
    conversations = [
        {
            'user':         row['partner'],
            'last_message': row['last_message'],
            'timestamp':    row['last_time']
        }
        for row in rows
    ]

    return render_template('inbox.html', conversations=conversations)

@socketio.on('connect')
def on_connect():
    user = session.get('username')
    if user:
        join_room(f"inbox_{user}")
        
        

@socketio.on('join_room')
def on_join(data):
    username = data['username']
    receiver = data['receiver']
    
    if receiver is None:
        # Handle the case where receiver is None (you can skip, return, or set a default)
        return  # Or do something else, like using a default receiver
    
    # Sort the usernames (if both are valid) and create the room
    room = '_'.join(sorted([username, receiver]))
    
    # Join the room
    join_room(room)








@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))  # Redirect to login after logout

if __name__ == '__main__':
    socketio.run(app, debug=True)
