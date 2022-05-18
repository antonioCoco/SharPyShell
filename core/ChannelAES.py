from utils.Singleton import Singleton
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad


class ChannelAES(Singleton):
    hashed_password = None
    IV = None
    BS = 16

    def __init__(self, password):
        self.hashed_password = bytes.fromhex(password)
        self.IV = self.hashed_password[0:self.BS]

    def encrypt(self, plain_data):
        plain_data_pad = pad(plain_data, self.BS)
        aes = AES.new(self.hashed_password, AES.MODE_CBC, self.IV)
        encrypted_data = aes.encrypt(plain_data_pad)
        return encrypted_data

    def decrypt(self, encrypted_data):
        aes = AES.new(self.hashed_password, AES.MODE_CBC, self.IV)
        decrypted_data = aes.decrypt(encrypted_data)
        return unpad(decrypted_data, self.BS)
