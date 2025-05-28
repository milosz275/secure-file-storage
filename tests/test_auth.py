import sqlite3
from secure_file_storage.src import auth


def remove_testuser():
    """
    Remove the user with username 'testuser' from the database.

    This function is useful for cleaning up test data before running tests.
    """
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE username = ?', ('testuser',))
        conn.commit()


def test_register_and_authenticate():
    """
    Test the user registration and authentication workflow.

    - Creates the users table if it doesn't exist.
    - Removes any existing 'testuser' entry.
    - Registers a new user 'testuser' with password 'testpass'.
    - Asserts that the user can be authenticated successfully.
    """
    auth.create_user_table()
    remove_testuser()
    auth.register_user('testuser', 'testpass')
    assert auth.authenticate_user('testuser', 'testpass') is True
