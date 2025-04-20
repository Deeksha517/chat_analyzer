import sqlite3

DB_NAME = 'users.db'

def initialize_database():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            print("✅ Connected to the database.")

            # Create 'users' table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    bio TEXT DEFAULT 'Hey there! I am using ConvoIQ.',
                    profile_pic TEXT DEFAULT 'default.jpg',
                    interests TEXT DEFAULT ''
                )
            ''')

            # Create 'messages' table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(sender) REFERENCES users(username),
                    FOREIGN KEY(receiver) REFERENCES users(username)
                )
            ''')

            conn.commit()
            print("✅ Tables created (if not already present).")

    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")

    finally:
        print("🔚 Script execution completed.")

if __name__ == "__main__":
    initialize_database()
