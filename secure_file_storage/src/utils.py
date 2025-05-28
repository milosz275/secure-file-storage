import hashlib


def hash_file(path):
    """
    Calculate the SHA-256 hash of a file's contents.

    Args:
        path (str): Path to the file to hash.

    Returns:
        str: Hexadecimal SHA-256 digest of the file.
    """
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()
