"""Main module for Secure File Storage application"""

import os
import sys

from flask import Flask
from dotenv import load_dotenv

from .src import auth

from .src.routes.auth_routes import auth_bp
from .src.routes.common_routes import common_bp
from .src.routes.storage_routes import stor_bp

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or 'fallback_insecure_key'

app.register_blueprint(auth_bp)
app.register_blueprint(common_bp)
app.register_blueprint(stor_bp)

auth.create_user_table()
auth.create_files_table()


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
