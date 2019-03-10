from utils.Singleton import Singleton
from Crypto.Cipher import AES


class ChannelAES(Singleton):
    hashed_password = None
    IV = None
    BS = 16

    def __init__(self, password):
        self.hashed_password = password.decode('hex')
        self.IV = self.hashed_password[0:self.BS]

    def encrypt(self, plain_data):
        pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        plain_data_pad = pad(plain_data)
        aes = AES.new(self.hashed_password, AES.MODE_CBC, self.IV)
        encrypted_data = aes.encrypt(plain_data_pad)
        return encrypted_data

    def decrypt(self, encrypted_data):
        aes = AES.new(self.hashed_password, AES.MODE_CBC, self.IV)
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        decrypted_data = aes.decrypt(encrypted_data)
        return unpad(decrypted_data)