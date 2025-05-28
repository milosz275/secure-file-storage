import sqlite3
from secure_file_storage.src import auth


def remove_testuser():
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE username = ?', ('testuser',))
        conn.commit()


def test_register_and_authenticate():
    auth.create_user_table()
    remove_testuser()
    auth.register_user('testuser', 'testpass')
    assert auth.authenticate_user('testuser', 'testpass') is True
