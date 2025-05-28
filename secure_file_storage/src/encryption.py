import base64
from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()


def _format_key(user_input_key: bytes) -> bytes:
    """Ensure the user-provided key is 32 bytes, base64-encoded."""
    key = user_input_key.ljust(32, b'\0')[:32]
    return base64.urlsafe_b64encode(key)


def encrypt_file(file_path, key):
    formatted_key = _format_key(key)
    fernet = Fernet(formatted_key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)


def decrypt_file(encrypted_path, key):
    formatted_key = _format_key(key)
    fernet = Fernet(formatted_key)
    with open(encrypted_path, 'rb') as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(encrypted_path.replace('.enc', ''), 'wb') as dec_file:
        dec_file.write(decrypted)
