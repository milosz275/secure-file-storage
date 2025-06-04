
from flask import Blueprint, render_template, session, jsonify

from ...version import __version__ as version

common_bp = Blueprint('common', __name__)


@common_bp.route('/')
def index():
    """
    Render the main page with HTML forms for registration, authentication,
    encryption/decryption, file upload, and file listing.

    Returns:
        str: Rendered HTML content.
    """
    session['version'] = version
    return render_template('index.html', session=session)


@common_bp.route('/version', methods=['GET'])
def get_version():
    """
    Returns:
        str: Secure File Storage version (e.g. "0.2.0")
    """
    return str(version)


@common_bp.route('/.well-known/appspecific/com.chrome.devtools.json')
def serve_devtools_config():
    """
    Serve a Chrome DevTools configuration JSON.

    This endpoint provides a JSON object with metadata for Chrome DevTools integration,
    such as the app name, version, frontend URL, and WebSocket debugger URL.
    It can be used by tools or browsers to discover debugging endpoints.

    Returns:
        flask.wrappers.Response: JSON response containing DevTools configuration.
    """
    return jsonify({
        "name": "My Flask App",
        "version": "1.0",
        "devtoolsFrontendUrl": "http://localhost:5000",
        "webSocketDebuggerUrl": "ws://localhost:5000/devtools"
    })
