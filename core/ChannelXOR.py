from utils.Singleton import Singleton
from itertools import cycle

class ChannelXOR(Singleton):
    password = None

    def __init__(self, password):
        self.password = password

    def encrypt(self, plain_data):
        key = self.password
        xored = ''.join(chr(ord(x) ^ ord(y)) for (x, y) in list(zip(plain_data, cycle(key))))
        return xored

    def decrypt(self, encrypted_data):
        return str(self.encrypt(encrypted_data.decode('utf-8')))
