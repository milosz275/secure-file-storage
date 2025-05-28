import bcrypt
import sqlite3


def create_user_table():
    """
    Create the 'users' table in the 'metadata.db' SQLite database if it does not exist.

    The table has two columns:
        - username (TEXT): Primary key for user identification.
        - password_hash (TEXT): Stores the bcrypt hashed password.

    Returns:
        None
    """
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT)''')
        conn.commit()


def register_user(username, password):
    """
    Register a new user with a hashed password in the database.

    Args:
        username (str): The username to register.
        password (str): The plaintext password for the user.

    Returns:
        bool: True if registration succeeded, False if username already exists.
    """
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
    """
    Authenticate a user by verifying the provided password against the stored hash.

    Args:
        username (str): The username to authenticate.
        password (str): The plaintext password to verify.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
        row = c.fetchone()
        if row:
            return bcrypt.checkpw(password.encode(), row[0])
        return False


def create_files_table():
    """
    Create the 'files' table in the 'metadata.db' SQLite database if it does not exist.

    The table stores metadata about uploaded files with columns:
        - id (INTEGER): Auto-incremented primary key.
        - username (TEXT): Owner of the file.
        - filename (TEXT): Original file name.
        - stored_name (TEXT): Internal stored file name.
        - hash (TEXT): Hash of the encrypted file.
        - uploaded_at (TIMESTAMP): Timestamp of upload, defaults to current time.

    Returns:
        None
    """
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
