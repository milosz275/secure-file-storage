import os
import sqlite3
import uuid

from flask import Blueprint, request, render_template, send_file, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from cryptography.fernet import InvalidToken

from ...src import encryption, utils
from ...src.logger import logger

stor_bp = Blueprint('storage', __name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

# quick encrypt/decrypt
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# uploading to storage
STORAGE_FOLDER = os.path.join(BASE_DIR, 'storage')
os.makedirs(STORAGE_FOLDER, exist_ok=True)


@stor_bp.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Encrypt an uploaded file with the provided key.

    No authentication or username required.

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
    logger.info(
        f"Quick encrypt: {filename}, hash: {h}")
    return send_file(encrypted_path, as_attachment=True)


@stor_bp.route('/decrypt', methods=['POST'])
def decrypt():
    """
    Decrypt an uploaded encrypted file with the provided key.

    No authentication or username required.

    Saves the uploaded encrypted file temporarily, decrypts it, logs the event,
    and returns the decrypted file as a download.

    Returns:
        flask.wrappers.Response: Decrypted file sent as attachment.
    """
    file = request.files['file']
    filename = secure_filename(file.filename or "uploaded_file.enc")
    path = os.path.normpath(os.path.join(UPLOAD_FOLDER, filename))
    if not path.startswith(UPLOAD_FOLDER):
        logger.warning(f"Unauthorized file path: {path}")
        raise Exception("Invalid file path")
    file.save(path)
    try:
        encryption.decrypt_file(path, request.form['key'].encode())
    except InvalidToken:
        logger.warning(f"Decryption failed for file: {filename} (wrong key)")
        flash("Decryption failed: wrong key or corrupted file.")
        return redirect(url_for('common.index'))

    original_path = os.path.normpath(os.path.splitext(path)[0])
    if not original_path.startswith(UPLOAD_FOLDER):
        logger.warning(f"Unauthorized file path: {original_path}")
        raise Exception("Invalid file path")
    logger.info(f"Quick decrypt: {filename}")
    return send_file(original_path, as_attachment=True)


@stor_bp.route('/upload', methods=['GET', 'POST'])
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
        return render_template('upload.html')

    username = session.get('username')
    if not username:
        return redirect(url_for('common.index'))

    key = request.form['key'].encode()
    file = request.files['file']
    if not file:
        flash('Cannot upload an empty file.')
        return redirect(url_for('common.index'))
    original_filename = file.filename or "uploaded_file"

    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM users WHERE username=?', (username,))
        if not c.fetchone():
            logger.warning(
                f"Upload attempt by unknown user: {username}")
            flash('User does not exist. Please register first.')
            return redirect(url_for('common.index'))

    user_folder = os.path.normpath(os.path.join(STORAGE_FOLDER, username))
    if not user_folder.startswith(STORAGE_FOLDER):
        logger.warning(
            f"Path traversal attempt detected for user: {username}")
        flash('Invalid username. Path traversal is not allowed.')
        return redirect(url_for('common.index'))
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

    logger.info(
        f'File uploaded and encrypted: user={username}, file="{original_filename}", stored_as={stored_name}')
    flash(f'File "{original_filename}" uploaded and encrypted successfully.')
    return redirect(url_for('storage.list_files_query'))


@stor_bp.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    """
    Delete a file asset for the authenticated user.
    """
    username = session.get('username')
    if not username:
        logger.warning("Delete attempt with no session.")
        return redirect(url_for('common.index'))

    # checking if session is still valid
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM users WHERE username=?', (username,))
        if not c.fetchone():
            logger.warning(f"Invalid session for username: {username}")
            session.pop('username', None)
            return redirect(url_for('common.index'))

        c.execute(
            'SELECT username, stored_name FROM files WHERE id=?', (file_id,))
        row = c.fetchone()
        if not row:
            logger.warning(
                f"Delete attempt for non-existent file_id={file_id}")
            flash('File not found.')
            return redirect(url_for('common.index'))
        file_owner, stored_name = row

    if username != file_owner:
        logger.warning(
            f"Unauthorized delete attempt: session_user={username}, file_owner={file_owner}, file_id={file_id}")
        return 'Access denied', 403

    stored_path = os.path.join(STORAGE_FOLDER, file_owner, stored_name)
    try:
        if os.path.exists(stored_path):
            os.remove(stored_path)
        with sqlite3.connect('metadata.db') as conn:
            c = conn.cursor()
            c.execute('DELETE FROM files WHERE id=?', (file_id,))
            conn.commit()
        logger.info(
            f"File deleted: user={file_owner}, file_id={file_id}, stored_name={stored_name}")
        flash('File deleted successfully.')
    except Exception as e:
        logger.error(
            f"Error deleting file: user={file_owner}, file_id={file_id}, error={e}")
        flash('Error deleting file.')
    return redirect(url_for('storage.list_files_query'))


@stor_bp.route('/files/')
def list_files_query():
    """
    List files for the currently authenticated user (from session).

    Returns:
        str or tuple: HTML list of files or error with HTTP status.
    """
    username = session.get('username')
    if not username:
        logger.warning("File list access attempt with no session.")
        return redirect(url_for('common.index'))

    # checking if session is still valid
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM users WHERE username=?', (username,))
        if not c.fetchone():
            logger.warning(f"Invalid session for username: {username}")
            session.pop('username', None)
            return redirect(url_for('common.index'))

    logger.info(f"Listing files for user: {username}")
    return list_files_internal(username)


@stor_bp.route('/files')
def list_files_route():
    """
    Alias for /files/ for consistency.
    """
    return list_files_query()


def list_files_internal(username):
    """
    Internal function to list all files uploaded by a given user.
    """
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


@stor_bp.route('/download/<int:file_id>', methods=['GET', 'POST'])
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
    username = session.get('username')
    if not username:
        logger.warning("Download attempt with no session.")
        return redirect(url_for('common.index'))

    # checking if session is still valid
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM users WHERE username=?', (username,))
        if not c.fetchone():
            logger.warning(f"Invalid session for username: {username}")
            session.pop('username', None)
            return redirect(url_for('common.index'))

        c.execute(
            'SELECT username, filename, stored_name FROM files WHERE id=?', (file_id,))
        row = c.fetchone()
        if not row:
            logger.warning(
                f"Download attempt for non-existent file_id={file_id}")
            return 'File not found', 404
        file_owner, original_filename, stored_name = row

    if username != file_owner:
        logger.warning(
            f"Unauthorized download attempt: session_user={username}, file_owner={file_owner}, file_id={file_id}")
        return 'Access denied', 403

    stored_path = os.path.join(STORAGE_FOLDER, file_owner, stored_name)
    if not os.path.exists(stored_path):
        logger.error(f"Stored file missing on server: {stored_path}")
        return 'File missing on server', 404

    if request.method == 'GET':
        return render_template('download_key_form.html')

    key = request.form['key'].encode()
    try:
        decryption_output = stored_path.replace('.enc', '')
        encryption.decrypt_file(stored_path, key)
    except Exception as e:
        logger.warning(
            f"Decryption failed for user={file_owner}, file_id={file_id}, error={e}")
        flash("Decryption failed. Please check your key.")
        return redirect(url_for('storage.download_file', file_id=file_id))

    logger.info(
        f"File downloaded and decrypted: user={file_owner}, file=\"{original_filename}\", file_id={file_id}")
    return send_file(decryption_output, as_attachment=True, download_name=original_filename)
