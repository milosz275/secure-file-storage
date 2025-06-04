"""Main module for Secure File Storage application"""

import os
import sys
import sqlite3
import uuid

from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash, session
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

from .version import __version__ as version
from .src import auth, encryption, logger, utils

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or 'fallback_insecure_key'

auth.create_user_table()
auth.create_files_table()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

# quick encrypt/decrypt
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# uploading to storage
STORAGE_FOLDER = os.path.join(BASE_DIR, 'storage')
os.makedirs(STORAGE_FOLDER, exist_ok=True)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure File Storage</title>
</head>
<body>
    <h1>Secure File Storage</h1>

    {% if session.username %}
        <p>Logged in as: <strong>{{ session.username }}</strong></p>
        <form action="/logout" method="GET"><input type="submit" value="Logout"></form>
    {% endif %}

    <h2>Register</h2>
    <form method="POST" action="/register">
        Username: <input name="username" type="text"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Register">
    </form>

    <h2>Authenticate</h2>
    <form method="POST" action="/auth">
        Username: <input name="username" type="text"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>

    <h2>Quick Encrypt & Download</h2>
    <form method="POST" action="/encrypt" enctype="multipart/form-data">
        Username: <input name="username" type="text"><br>
        Key: <input name="key" type="text"><br>
        File: <input type="file" name="file"><br>
        <input type="submit" value="Encrypt Now">
    </form>

    <h2>Quick Decrypt & Download</h2>
    <form method="POST" action="/decrypt" enctype="multipart/form-data">
        Username: <input name="username" type="text"><br>
        Key: <input name="key" type="text"><br>
        File: <input type="file" name="file"><br>
        <input type="submit" value="Decrypt Now">
    </form>

    <h2>Upload File to Storage</h2>
    <form method="POST" action="/upload" enctype="multipart/form-data">
        Username: <input name="username" type="text"><br>
        Key: <input name="key" type="text"><br>
        File: <input type="file" name="file"><br>
        <input type="submit" value="Upload & Encrypt">
    </form>

    <h2>View Your Stored Files</h2>
    <form method="GET" action="/files/">
        Username: <input name="username" type="text"><br>
        <input type="submit" value="List My Files">
    </form>
</body>
</html>
'''


@app.route('/')
def index():
    """
    Render the main page with HTML forms for registration, authentication,
    encryption/decryption, file upload, and file listing.

    Returns:
        str: Rendered HTML content.
    """
    return render_template_string(HTML_TEMPLATE, session=session)


@app.route('/version', methods=['GET'])
def get_version():
    """
    Returns:
        str: Secure File Storage version (e.g. "0.2.0")
    """
    return str(version)


@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user with provided username and password.

    Uses the `auth.register_user` function to add the user to the database.
    Logs the registration event and flashes a success or failure message.

    Returns:
        werkzeug.wrappers.Response: Redirect response to the main index page.
    """
    success = auth.register_user(
        request.form['username'], request.form['password'])
    if success:
        logger.logger.info(f"New user registered: {request.form['username']}")
        flash('User registered successfully')
    else:
        logger.logger.warning(
            f"Registration failed: username already exists ({request.form['username']})")
        flash('Username already exists. Please choose another one.')
    return redirect(url_for('index'))


@app.route('/auth', methods=['POST'])
def authenticate():
    """
    Authenticate user credentials from the login form.

    If authentication is successful, sets session username and logs the event.
    Otherwise, flashes an authentication failure message.

    Returns:
        werkzeug.wrappers.Response: Redirect response to the main index page.
    """
    if auth.authenticate_user(request.form['username'], request.form['password']):
        session['username'] = request.form['username']
        logger.logger.info(f"User authenticated: {request.form['username']}")
        flash('Authenticated successfully')
    else:
        flash('Authentication failed')
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    """
    Log out the current user by clearing the session username.

    Logs the logout event and flashes a logged out message.

    Returns:
        werkzeug.wrappers.Response: Redirect response to the main index page.
    """
    user = session.pop('username', None)
    if user:
        logger.logger.info(f"User logged out: {user}")
    flash('Logged out')
    return redirect(url_for('index'))


@app.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Encrypt an uploaded file with the provided key.

    Saves the uploaded file temporarily, encrypts it, logs the event,
    and returns the encrypted file as a download.

    Returns:
        flask.wrappers.Response: Encrypted file sent as attachment.
    """
    file = request.files['file']
    filename = secure_filename(file.filename or "uploaded_file")
    path = os.path.normpath(os.path.join(UPLOAD_FOLDER, filename))
    if os.path.commonpath([UPLOAD_FOLDER, path]) != UPLOAD_FOLDER:
        raise ValueError("Invalid file path")
    file.save(path)
    encryption.encrypt_file(path, request.form['key'].encode())
    encrypted_path = path + '.enc'
    h = utils.hash_file(encrypted_path)
    logger.logger.info(
        f"{request.form['username']} encrypted {filename}, hash: {h}")
    return send_file(encrypted_path, as_attachment=True)


@app.route('/decrypt', methods=['POST'])
def decrypt():
    """
    Decrypt an uploaded encrypted file with the provided key.

    Saves the uploaded encrypted file temporarily, decrypts it, logs the event,
    and returns the decrypted file as a download.

    Returns:
        flask.wrappers.Response: Decrypted file sent as attachment.
    """
    file = request.files['file']
    filename = secure_filename(file.filename or "uploaded_file.enc")
    path = os.path.normpath(os.path.join(UPLOAD_FOLDER, filename))
    if not path.startswith(UPLOAD_FOLDER):
        logger.logger.warning(f"Unauthorized file path: {path}")
        raise Exception("Invalid file path")
    file.save(path)
    encryption.decrypt_file(path, request.form['key'].encode())
    original_path = os.path.normpath(os.path.splitext(path)[0])
    if not original_path.startswith(UPLOAD_FOLDER):
        logger.logger.warning(f"Unauthorized file path: {original_path}")
        raise Exception("Invalid file path")
    logger.logger.info(f"{request.form['username']} decrypted {filename}")
    return send_file(original_path, as_attachment=True)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
    Handle file upload and encryption for persistent storage.

    GET: Returns a simple HTML form for uploading a file with username and key.
    POST:
        - Verifies user exists,
        - Saves and encrypts the uploaded file,
        - Stores metadata in the database,
        - Logs the upload event,
        - Redirects to the user's file list page.

    Returns:
        str or werkzeug.wrappers.Response: HTML form on GET or redirect on POST.
    """
    if request.method == 'GET':
        return '''
        <h2>Upload & Encrypt File</h2>
        <form method="POST" enctype="multipart/form-data">
            Username: <input name="username" type="text"><br>
            Key: <input name="key" type="text"><br>
            File: <input type="file" name="file"><br>
            <input type="submit" value="Upload">
        </form>
        '''

    username = request.form['username']
    if not username.isalnum():
        logger.logger.warning(f"Invalid username provided: {username}")
        flash('Invalid username. Please use only alphanumeric characters.')
        return redirect(url_for('index'))

    key = request.form['key'].encode()
    file = request.files['file']
    original_filename = file.filename or "uploaded_file"

    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM users WHERE username=?', (username,))
        if not c.fetchone():
            logger.logger.warning(
                f"Upload attempt by unknown user: {username}")
            flash('User does not exist. Please register first.')
            return redirect(url_for('index'))

    user_folder = os.path.normpath(os.path.join(STORAGE_FOLDER, username))
    if not user_folder.startswith(STORAGE_FOLDER):
        logger.logger.warning(
            f"Path traversal attempt detected for user: {username}")
        flash('Invalid username. Path traversal is not allowed.')
        return redirect(url_for('index'))
    os.makedirs(user_folder, exist_ok=True)

    stored_name = str(uuid.uuid4()) + '.enc'
    stored_path = os.path.join(user_folder, stored_name)

    import tempfile
    fd, temp_path = tempfile.mkstemp(
        dir=user_folder, prefix='upload_', suffix='.tmp')
    with os.fdopen(fd, 'wb') as tmp:
        tmp.write(file.read())

    encryption.encrypt_file(temp_path, key)
    os.rename(temp_path + '.enc', stored_path)
    os.remove(temp_path)

    file_hash = utils.hash_file(stored_path)

    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO files (username, filename, stored_name, hash)
            VALUES (?, ?, ?, ?)
        ''', (username, original_filename, stored_name, file_hash))
        conn.commit()

    logger.logger.info(
        f'File uploaded and encrypted: user={username}, file="{original_filename}", stored_as={stored_name}')
    flash(f'File "{original_filename}" uploaded and encrypted successfully.')
    return redirect(url_for('list_files', username=username))


@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    """
    Delete a file asset for the authenticated user.

    Args:
        file_id (int): The ID of the file to delete.

    Returns:
        werkzeug.wrappers.Response: Redirects to the user's file list.
    """
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute(
            'SELECT username, stored_name FROM files WHERE id=?', (file_id,))
        row = c.fetchone()
        if not row:
            logger.logger.warning(
                f"Delete attempt for non-existent file_id={file_id}")
            flash('File not found.')
            return redirect(url_for('index'))
        file_owner, stored_name = row

    if session.get('username') != file_owner:
        logger.logger.warning(
            f"Unauthorized delete attempt: session_user={session.get('username')}, file_owner={file_owner}, file_id={file_id}")
        return 'Access denied', 403

    stored_path = os.path.join(STORAGE_FOLDER, file_owner, stored_name)
    try:
        if os.path.exists(stored_path):
            os.remove(stored_path)
        with sqlite3.connect('metadata.db') as conn:
            c = conn.cursor()
            c.execute('DELETE FROM files WHERE id=?', (file_id,))
            conn.commit()
        logger.logger.info(
            f"File deleted: user={file_owner}, file_id={file_id}, stored_name={stored_name}")
        flash('File deleted successfully.')
    except Exception as e:
        logger.logger.error(
            f"Error deleting file: user={file_owner}, file_id={file_id}, error={e}")
        flash('Error deleting file.')
    return redirect(url_for('list_files', username=file_owner))


@app.route('/files/')
def list_files_query():
    """
    Handle file listing requests via query parameter.

    Validates session username matches requested username for security.

    Returns:
        str or tuple: HTML list of files or error with HTTP status.
    """
    username = request.args.get('username')
    if not username or session.get('username') != username:
        logger.logger.warning(
            f"Unauthorized file list access attempt: session_user={session.get('username')}, requested_user={username}")
        return 'Access denied', 403
    logger.logger.info(f"Listing files for user: {username}")
    return list_files(username)


@app.route('/files/<username>')
def list_files(username):
    """
    List all files uploaded by a given user.

    Args:
        username (str): The username whose files are to be listed.

    Returns:
        str: HTML page listing files with download and delete links.
    """
    if session.get('username') != username:
        logger.logger.warning(
            f"Unauthorized file list access attempt: session_user={session.get('username')}, requested_user={username}")
        return 'Access denied', 403
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute(
            'SELECT id, filename, uploaded_at FROM files WHERE username=?', (username,))
        files = c.fetchall()
    file_list_html = '<h2>Files for user: {}</h2><ul>'.format(username)
    for f in files:
        file_list_html += f'''
        <li>
            {f[1]} (uploaded: {f[2]})
            - <a href="/download/{f[0]}">Download/Decrypt</a>
            <form action="/delete/{f[0]}" method="POST" style="display:inline;">
                <button type="submit" onclick="return confirm('Are you sure you want to delete this file?');">Delete</button>
            </form>
        </li>
        '''
    file_list_html += '</ul>'
    file_list_html += '<a href="/">Back to main</a>'
    return file_list_html


@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
def download_file(file_id):
    """
    Allow the file owner to download and decrypt a stored file.

    GET: Presents a form to enter the decryption key.
    POST: Decrypts the file with the provided key and sends it for download.

    Args:
        file_id (int): The ID of the file to download.

    Returns:
        str or flask.wrappers.Response: HTML form or decrypted file download.
    """
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute(
            'SELECT username, filename, stored_name FROM files WHERE id=?', (file_id,))
        row = c.fetchone()
        if not row:
            logger.logger.warning(
                f"Download attempt for non-existent file_id={file_id}")
            return 'File not found', 404
        file_owner, original_filename, stored_name = row

    if session.get('username') != file_owner:
        logger.logger.warning(
            f"Unauthorized download attempt: session_user={session.get('username')}, file_owner={file_owner}, file_id={file_id}")
        return 'Access denied', 403

    stored_path = os.path.join(STORAGE_FOLDER, file_owner, stored_name)
    if not os.path.exists(stored_path):
        logger.logger.error(f"Stored file missing on server: {stored_path}")
        return 'File missing on server', 404

    if request.method == 'GET':
        return '''
        <h2>Enter decryption key to download file</h2>
        <form method="POST">
            Key: <input name="key" type="text"><br>
            <input type="submit" value="Download">
        </form>
        '''

    key = request.form['key'].encode()
    try:
        decryption_output = stored_path.replace('.enc', '')
        encryption.decrypt_file(stored_path, key)
    except Exception as e:
        logger.logger.warning(
            f"Decryption failed for user={file_owner}, file_id={file_id}, error={e}")
        flash("Decryption failed. Please check your key.")
        return redirect(url_for('download_file', file_id=file_id))

    logger.logger.info(
        f"File downloaded and decrypted: user={file_owner}, file=\"{original_filename}\", file_id={file_id}")
    return send_file(decryption_output, as_attachment=True, download_name=original_filename)


def main():
    """
    Entry point to start the Flask web application.

    Prints a warning if not running inside a virtual environment,
    then runs the Flask server on host 0.0.0.0 and port 5000.
    """
    if sys.prefix == sys.base_prefix:
        print("Warning: It looks like you're not running inside a virtual environment.")
    app.run(debug=False, host="0.0.0.0", port=5000)


if __name__ == '__main__':
    main()
