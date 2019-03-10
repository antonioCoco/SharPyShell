from utils.Singleton import Singleton


class ChannelXOR(Singleton):
    password = None

    def __init__(self, password):
        self.password = password.encode('utf-8')

    def encrypt(self, plain_data):
        key = self.password
        from itertools import izip, cycle
        xored = ''.join(chr(ord(x) ^ ord(y)) for (x, y) in izip(plain_data, cycle(key)))
        return bytearray(xored)

    def decrypt(self, encrypted_data):
        return self.encrypt(encrypted_data)