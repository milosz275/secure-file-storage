import os
from secrets import token_urlsafe

if not os.path.exists('.env'):
    with open('.env', 'w') as f:
        f.write(f'SECRET_KEY={token_urlsafe(32)}\n')
