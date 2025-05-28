import bcrypt
import sqlite3


def create_user_table():
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT)''')
        conn.commit()


def register_user(username, password):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=?', (username,))
        if c.fetchone():
            return False
        c.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
        conn.commit()
        return True


def authenticate_user(username, password):
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
        row = c.fetchone()
        if row:
            return bcrypt.checkpw(password.encode(), row[0])
        return False


def create_files_table():
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                filename TEXT,
                stored_name TEXT,
                hash TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
