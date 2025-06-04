from flask import Blueprint, request, redirect, url_for, flash, session

from ...src import auth
from ...src.logger import logger

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
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
        logger.info(f"New user registered: {request.form['username']}")
        session.pop('register_fail', None)
        flash('User registered successfully')
    else:
        logger.warning(
            f"Registration failed: username already exists ({request.form['username']})")
        session['register_fail'] = 'Username already exists. Please choose another one.'
    return redirect(url_for('common.index'))


@auth_bp.route('/auth', methods=['POST'])
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
        logger.info(f"User authenticated: {request.form['username']}")
        session.pop('auth_fail', None)
        flash('Authenticated successfully')
    else:
        session['auth_fail'] = 'Authentication failed'
    return redirect(url_for('common.index'))


@auth_bp.route('/logout')
def logout():
    """
    Log out the current user by clearing the session username.

    Logs the logout event and flashes a logged out message.

    Returns:
        werkzeug.wrappers.Response: Redirect response to the main index page.
    """
    user = session.pop('username', None)
    if user:
        logger.info(f"User logged out: {user}")
    flash('Logged out')
    return redirect(url_for('common.index'))
