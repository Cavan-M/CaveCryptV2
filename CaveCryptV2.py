# Author: Cavan McLellan
# Written with love on 2023-10-14
# Update 2023-10-17: Added error checking and dialog boxes
import os
import sys
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes
except ModuleNotFoundError:
    import time
    print("Performing First Time Setup...")
    os.system("cmd /c pip install cryptography")
    print("Setup Complete")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes


class PasswordToKey:
    def __init__(self, password):
        self.password = bytes(password, 'utf-8')
        self.digest = hashes.Hash(hashes.SHA3_256())
        self.digest.update(self.password)
        self.iv_digest = hashes.Hash(hashes.SHAKE128(16))
        self.iv_digest.update(bytes(password[::-1], 'utf-8'))
        self.iv = self.iv_digest.finalize()
        self.key = self.digest.finalize()

    def __str__(self):
        bytes_list = list(self.key)
        key_string = list()
        for x in bytes_list:
            key_string.append(hex(x).split('x')[-1])
        return str(key_string)

    def get_key(self):
        return self.key

    def get_iv(self):
        return self.iv


class CipherManager:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.cipher = Cipher(algorithms.AES256(self.key), modes.OFB(self.iv))
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
        self.cipherText = None
        self.plainText = None

    def encrypt(self, obj):
        self.cipherText = self.encryptor.update(obj) + self.encryptor.finalize()
        return self.cipherText

    def decrypt(self, obj):
        self.plainText = self.decryptor.update(obj) + self.decryptor.finalize()
        return self.plainText


class FileEncryptor:
    def __init__(self, file_location, password):
        self.file = file_location
        self.password = password

    def pad_file_extension(self):
        file_ext = self.file.split('.')[-1]
        pad = 8-len(file_ext)
        padded = file_ext
        for x in range(pad):
            padded += '~'
        return bytes(padded, 'ascii')

    def encrypt(self, save_location='encrypted'):
        save_file = open(save_location + ".cdrm", 'wb')
        enc_file = open(self.file, 'rb')
        save_file.write(self.pad_file_extension())
        key = PasswordToKey(self.password)
        c = CipherManager(key.get_key(), key.get_iv())
        save_file.write(c.encrypt(enc_file.read()))

    def decrypt(self, filename='decrypted'):
        enc_file = open(self.file, 'rb')
        key = PasswordToKey(self.password)
        c = CipherManager(key.get_key(), key.get_iv())
        ext = enc_file.read(8).decode('ascii').replace("~", '')
        save_file = open(filename + "." + ext, 'wb')
        save_file.write(c.decrypt(enc_file.read()))


if __name__ == "__main__":
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename
    from tkinter.simpledialog import askstring
    Tk().withdraw()
    file = askopenfilename(title="Open your file for Encryption/Decryption")
    if not file:
        sys.exit(0)
    entered_password = askstring(" ", 'Password')
    f = FileEncryptor(file, entered_password)
    if file.split('.')[-1] == 'cdrm':
        f.decrypt(askstring(" ", 'Name Your Decrypted File'))
    else:
        f.encrypt(askstring(" ", 'Name Your Encrypted File'))
