from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Hash import SHA384, SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256, md5
from typing import Tuple
import os, glob, string, random

AES_KEY_SIZE = 32

class KeyExport:
    def __init__(self, key: RSA.RsaKey):
        self._key = key
    def asBytes(self) -> bytes:
        return self._key.export_key('DER')
    def __bytes__(self):
        return self.asBytes()
    def asHex(self) -> str:
        return self.asBytes().hex()
    def identifier(self) -> str:
        hashed = sha256(self.asBytes()).hexdigest()
        return ':'.join(hashed[x:x+4] for x in range(0, len(hashed), 4))
    def key(self) -> RSA.RsaKey:
        return self._key
    def publicKey(self) -> 'KeyExport':
        return KeyExport(self._key.publickey())
    @staticmethod
    def load(file):
        data = open(file, 'rb').read()
        key = RSA.import_key(data)
        return KeyExport(key)

class HostKeyMap(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._changed = set()
    def containsHost(self, host: str) -> bool:
        return self.__contains__(host)
    def keyOf(self, host: str) -> RSA.RsaKey:
        return self.__getitem__(host)
    def identifierOf(self, host: str) -> str:
        return KeyExport(self.keyOf(host)).identifier()
    def verify(self, host: str, data: SHA384.SHA384Hash, signature: bytes):
        signer = pkcs1_15.new(self.__getitem__(host))
        try:
            signer.verify(data, signature)
            return True
        except ValueError:
            return False
    def makeTrust(self, host: str, key_der: bytes) -> None:
        key = RSA.import_key(key_der)
        self.__setitem__(host, key)
        self._changed.add(host)
    def __setitem__(self, host: str, key: RSA.RsaKey) -> None:
        super().__setitem__(host, key)
        self._changed.add(host)
    def save(self, dir: str) -> None:
        cur = os.getcwd()
        os.chdir(dir)
        for host in self._changed:
            open(host + '.pem', 'wb').write(self.__getitem__(host).export_key('PEM'))
        os.chdir(cur)
        self._changed.clear()
    @staticmethod
    def scan(dir: str) -> 'HostKeyMap':
        pairs = []
        cur = os.getcwd()
        os.chdir(dir)
        for pem in glob.iglob('*.pem'):
            host = os.path.splitext(pem)[0]
            key = RSA.import_key(open(pem, 'rb').read())
            pairs.append((host, key))
        os.chdir(cur)
        return HostKeyMap(pairs)

class LocalSecurity:
    def __init__(self, private: RSA.RsaKey, public: RSA.RsaKey):
        self._privateKey = private
        self._publicKey = public
        self._signer = pkcs1_15.new(self._privateKey)
        self._hash = SHA384.new()
    @staticmethod
    def generate() -> 'LocalSecurity':
        private = RSA.generate(1024)
        public = private.publickey()
        return LocalSecurity(private, public)
    @staticmethod
    def load(pem: str) -> 'LocalSecurity':
        private = open(pem, 'rb').read()
        private = RSA.import_key(private)
        public = private.publickey()
        return LocalSecurity(private, public)
    def save(self, pem: str) -> None:
        open(pem, 'wb').write(self._privateKey.export_key('PEM'))
    def export(self) -> KeyExport:
        return KeyExport(self._publicKey)
    def chunk(self, data: bytes):
        self._hash.update(data)
        return md5(data).digest()
    def finish(self) -> bytes:
        signature = self._signer.sign(self._hash)
        self._hash = SHA384.new()
        return signature

class RemoteSecurity:
    def __init__(self, hostKeyMap: HostKeyMap):
        self._map = hostKeyMap
    def verify(self, host: str, data: SHA384.SHA384Hash, signature: bytes) -> bool:
        return self._map.verify(host, data, signature)
    def verifyBytes(self, host: str, data: bytes, signature: bytes) -> bool:
        return self.verify(host, SHA384.new(data), signature)
    def isTrustedHost(self, host: str) -> bool:
        return self._map.containsHost(host)

def random_password(bits: int=10) -> Tuple[bytes, bytes, bytes]:
    candidates = string.ascii_letters + string.digits
    chars = random.choices(candidates, k=bits)
    random.shuffle(chars)
    password = ''.join(chars)
    salt = os.urandom(16)
    derived = derive_key(password.encode(), salt)
    return password, salt, derived

def derive_key(master: bytes, salt: bytes) -> bytes:
    return PBKDF2(master, salt, AES_KEY_SIZE, hmac_hash_module=SHA512)

def encrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)