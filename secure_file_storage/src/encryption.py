import base64
from cryptography.fernet import Fernet


def generate_key():
    """
    Generate a secure random key for symmetric encryption.

    Returns:
        bytes: A base64-encoded 32-byte key suitable for Fernet encryption.
    """
    return Fernet.generate_key()


def _format_key(user_input_key: bytes) -> bytes:
    """
    Format and normalize the user-provided key to a 32-byte base64-encoded key.

    Pads or truncates the input key to exactly 32 bytes, then encodes it with URL-safe base64.

    Args:
        user_input_key (bytes): Raw key input by user.

    Returns:
        bytes: A properly formatted base64-encoded 32-byte key for Fernet.
    """
    key = user_input_key.ljust(32, b'\0')[:32]
    return base64.urlsafe_b64encode(key)


def encrypt_file(file_path, key):
    """
    Encrypt the contents of a file using the provided key.

    The encrypted output is saved to a new file with '.enc' appended to the original filename.

    Args:
        file_path (str): Path to the plaintext file to encrypt.
        key (bytes): Raw encryption key provided by the user.
    """
    formatted_key = _format_key(key)
    fernet = Fernet(formatted_key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)


def decrypt_file(encrypted_path, key):
    """
    Decrypt a previously encrypted file using the provided key.

    The decrypted file is saved by removing the '.enc' suffix from the encrypted file's name.

    Args:
        encrypted_path (str): Path to the encrypted '.enc' file.
        key (bytes): Raw decryption key provided by the user.
    """
    formatted_key = _format_key(key)
    fernet = Fernet(formatted_key)
    with open(encrypted_path, 'rb') as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(encrypted_path.replace('.enc', ''), 'wb') as dec_file:
        dec_file.write(decrypted)
