
import shutil
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

@common_bp.route('/space', methods=['GET'])
def get_space_available():
    """
    Returns the total, used, and available disk space (in MB) on the server's filesystem.

    Returns:
        flask.wrappers.Response: JSON response with total, used, and available space in MB.
    """
    total, used, free = shutil.disk_usage("/")
    total_mb = total // (1024 * 1024)
    used_mb = used // (1024 * 1024)
    free_mb = free // (1024 * 1024)
    return jsonify({
        "total_mb": total_mb,
        "used_mb": used_mb,
        "available_mb": free_mb
    })
