import os
from secure_file_storage.src import encryption


def test_encrypt_decrypt(tmp_path):
    key = encryption.generate_key()
    test_file = tmp_path / "test.txt"
    test_file.write_text("Secret content")

    encryption.encrypt_file(str(test_file), key)
    os.remove(test_file)
    encryption.decrypt_file(str(test_file) + '.enc', key)

    with open(test_file, 'r') as f:
        assert f.read() == "Secret content"
