"""Main module for Secure File Storage application"""

from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash
from dotenv import load_dotenv
import os

from .version import __version__ as version
from .src import auth, encryption, logger, utils

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or 'fallback_insecure_key'

auth.create_user_table()

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

    <h2>Encrypt File</h2>
    <form method="POST" action="/encrypt" enctype="multipart/form-data">
        Username: <input name="username" type="text"><br>
        Key: <input name="key" type="text"><br>
        File: <input type="file" name="file"><br>
        <input type="submit" value="Encrypt">
    </form>

    <h2>Decrypt File</h2>
    <form method="POST" action="/decrypt" enctype="multipart/form-data">
        Username: <input name="username" type="text"><br>
        Key: <input name="key" type="text"><br>
        File: <input type="file" name="file"><br>
        <input type="submit" value="Decrypt">
    </form>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/register', methods=['POST'])
def register():
    auth.register_user(request.form['username'], request.form['password'])
    logger.logger.info(f"New user registered: {request.form['username']}")
    flash('User registered successfully')
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


def main():
    app.run(debug=True, host="0.0.0.0", port=5000)


if __name__ == '__main__':
    main()
