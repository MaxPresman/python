import hashlib
from base64 import encodestring, decodestring
from Crypto.Cipher import AES

try:
    import json
except ImportError:
    import simplejson as json


class PubnubCrypto2:

    def __init__(self):
        pass

    def pad(self, msg, block_size=16):

        padding = block_size - (len(msg) % block_size)
        return msg + chr(padding) * padding

    def depad(self, msg):

        return msg[0:-ord(msg[-1])]

    def getSecret(self, key):

        return hashlib.sha256(key).hexdigest()

    def encrypt(self, key, msg):
        secret = self.getSecret(key)
        initial16bytes = '0123456789012345'
        cipher = AES.new(secret[0:32], AES.MODE_CBC, initial16bytes)
        enc = encodestring(cipher.encrypt(self.pad(msg)))
        return enc

    def decrypt(self, key, msg):

        try:
            secret = self.getSecret(key)
            initial16bytes = '0123456789012345'
            cipher = AES.new(secret[0:32], AES.MODE_CBC, initial16bytes)
            plain = self.depad(cipher.decrypt(decodestring(msg)))
        except:
            return msg
        try:
            return json.loads(plain)
        except SyntaxError:
            return plain


class PubnubCrypto3:

    def __init__(self):
        pass

    def pad(self, msg, block_size=16):

        padding = block_size - (len(msg) % block_size)
        return msg + (chr(padding) * padding).encode('utf-8')

    def depad(self, msg):

        return msg[0:-ord(msg[-1])]

    def getSecret(self, key):

        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def encrypt(self, key, msg):

        secret = self.getSecret(key)
        initial16bytes = '0123456789012345'
        cipher = AES.new(secret[0:32], AES.MODE_CBC, initial16bytes)
        return encodestring(
            cipher.encrypt(self.pad(msg.encode('utf-8')))).decode('utf-8')

    def decrypt(self, key, msg):

        secret = self.getSecret(key)
        Initial16bytes = '0123456789012345'
        cipher = AES.new(secret[0:32], AES.MODE_CBC, Initial16bytes)
        return (cipher.decrypt(
            decodestring(msg.encode('utf-8')))).decode('utf-8')
