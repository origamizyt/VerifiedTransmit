import socket, shutil, tempfile, os
from security import RemoteSecurity, HostKeyMap
from Crypto.Hash import SHA384
from hashlib import md5

class IntegrityError(Exception):
    pass

class Transmitter(RemoteSecurity):
    def __init__(self, hostKeyMap: HostKeyMap):
        super().__init__(hostKeyMap)
        self._hash = self._temp = self._fd = self._host = self._file = None
    def transmission(self, host: str, file: str) -> bool:
        print('New transmission from %s: %s' % (host, file))
        if self._host:
            return False
        self._host = host
        self._hash = SHA384.new()
        self._fd, self._temp = tempfile.mkstemp()
        self._file = file
        return True
    def chunk(self, data: bytes, expected_digest: bytes) -> None:
        if md5(data).digest() != expected_digest:
            raise IntegrityError
        os.write(self._fd, data)
        self._hash.update(data)
    def finish(self, expected_signature: bytes) -> bool:
        os.close(self._fd)
        ret = self.verify(self._host, self._hash, expected_signature)
        self._fd = self._host = None
        if not ret:
            os.unlink(self._temp)
            self._temp = self._file = None
            return False
        else:
            try:
                shutil.move(self._temp, self._file)
            except PermissionError:
                os.unlink(self._temp)
                raise
            self._temp = self._file = None
            return True
    def trusted(self) -> HostKeyMap:
        return self._map