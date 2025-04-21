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

            # Add new columns if not present
            cursor.execute("PRAGMA table_info(users)")
            existing_columns = [col[1] for col in cursor.fetchall()]

            if 'gender' not in existing_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN gender TEXT DEFAULT 'Prefer not to say'")
                print("➕ Added 'gender' column.")

            if 'age_group' not in existing_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN age_group TEXT DEFAULT 'Not specified'")
                print("➕ Added 'age_group' column.")

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
            print("✅ Tables created or updated successfully.")

    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")

    finally:
        print("🔚 Script execution completed.")

if __name__ == "__main__":
    initialize_database()
