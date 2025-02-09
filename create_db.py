import sqlite3

try:
    # Connect to SQLite database (it will create the database if it doesn't exist)
    conn = sqlite3.connect('users.db')
    print("Connected to the database successfully.")

    # Create a cursor object
    cursor = conn.cursor()

    # Create the 'users' table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL)''')

    # Commit changes and close the connection
    conn.commit()
    print("'users' table created successfully.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    conn.close()
    print("Connection closed.")