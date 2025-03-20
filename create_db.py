import sqlite3

try:
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    print("Connected to the database successfully.")

    # Drop old table if it exists
    cursor.execute("DROP TABLE IF EXISTS users")

    # Create new 'users' table with all necessary columns
    cursor.execute('''CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        bio TEXT DEFAULT 'Hey there! I am using Chat Analyzer.',
                        profile_pic TEXT DEFAULT 'default.jpg',
                        interests TEXT DEFAULT ''
                    )''')

    conn.commit()
    print("'users' table created successfully with profile fields.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    conn.close()
    print("Connection closed.")
