"""Main module for Secure File Storage application"""

import os
import sqlite3
import uuid

from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash
from dotenv import load_dotenv

from .version import __version__ as version
from .src import auth, encryption, logger, utils

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or 'fallback_insecure_key'

auth.create_user_table()
auth.create_files_table()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure File Storage</title>
</head>
<body>
    <h1>Secure File Storage</h1>

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
    return render_template_string(HTML_TEMPLATE)


@app.route('/register', methods=['POST'])
def register():
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
    if auth.authenticate_user(request.form['username'], request.form['password']):
        logger.logger.info(f"User authenticated: {request.form['username']}")
        flash('Authenticated successfully')
    else:
        logger.logger.warning(
            f"Failed auth attempt: {request.form['username']}")
        flash('Authentication failed')
    return redirect(url_for('index'))


@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files['file']
    filename = file.filename or "uploaded_file"
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    encryption.encrypt_file(path, request.form['key'].encode())
    encrypted_path = path + '.enc'
    h = utils.hash_file(encrypted_path)
    logger.logger.info(
        f"{request.form['username']} encrypted {filename}, hash: {h}")
    return send_file(encrypted_path, as_attachment=True)


@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files['file']
    filename = file.filename or "uploaded_file.enc"
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    encryption.decrypt_file(path, request.form['key'].encode())
    original_path = path.replace('.enc', '')
    logger.logger.info(f"{request.form['username']} decrypted {filename}")
    return send_file(original_path, as_attachment=True)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
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
    key = request.form['key'].encode()
    file = request.files['file']
    original_filename = file.filename or "uploaded_file"

    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM users WHERE username=?', (username,))
        if not c.fetchone():
            flash('User does not exist. Please register first.')
            return redirect(url_for('index'))

    user_folder = os.path.join('storage', username)
    os.makedirs(user_folder, exist_ok=True)

    stored_name = str(uuid.uuid4()) + '.enc'
    stored_path = os.path.join(user_folder, stored_name)

    temp_path = os.path.join(user_folder, 'temp_' + original_filename)
    file.save(temp_path)

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

    flash(f'File "{original_filename}" uploaded and encrypted successfully.')
    return redirect(url_for('list_files', username=username))


@app.route('/files/')
def list_files_query():
    username = request.args.get('username')
    if not username:
        return 'Missing username', 400
    return list_files(username)


@app.route('/files/<username>')
def list_files(username):
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute(
            'SELECT id, filename, uploaded_at FROM files WHERE username=?', (username,))
        files = c.fetchall()
    file_list_html = '<h2>Files for user: {}</h2><ul>'.format(username)
    for f in files:
        file_list_html += f'<li>{f[1]} (uploaded: {f[2]}) - <a href="/download/{f[0]}">Download/Decrypt</a></li>'
    file_list_html += '</ul>'
    file_list_html += '<a href="/">Back to main</a>'
    return file_list_html


@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
def download_file(file_id):
    if request.method == 'GET':
        return '''
        <h2>Enter decryption key to download file</h2>
        <form method="POST">
            Key: <input name="key" type="text"><br>
            <input type="submit" value="Download">
        </form>
        '''
    key = request.form['key'].encode()
    with sqlite3.connect('metadata.db') as conn:
        c = conn.cursor()
        c.execute(
            'SELECT username, filename, stored_name FROM files WHERE id=?', (file_id,))
        row = c.fetchone()
        if not row:
            return 'File not found', 404
        username, original_filename, stored_name = row

    stored_path = os.path.join('storage', username, stored_name)
    if not os.path.exists(stored_path):
        return 'File missing on server', 404

    temp_dec_path = stored_path.replace('.enc', '.dec')
    encryption.decrypt_file(stored_path, key)

    return send_file(temp_dec_path, as_attachment=True, download_name=original_filename)


def main():
    app.run(debug=False, host="0.0.0.0", port=5000)


if __name__ == '__main__':
    main()
