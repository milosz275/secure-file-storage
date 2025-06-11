import os
from secrets import token_urlsafe


def ensure_env():
    """
    Ensures that a .env file exists in the current directory.

    If the .env file does not exist, this function creates it and writes a randomly
    generated SECRET_KEY and a COMPOSE_BAKE variable.

    Returns:
        None
    """
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write(f'SECRET_KEY={token_urlsafe(32)}\n')
            f.write(f'COMPOSE_BAKE=true\n')
