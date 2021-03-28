import socket, msgpack, platform, os, math, tempfile, shutil
from response import Response, RespCode
from security import HostKeyMap, LocalSecurity, random_password, encrypt, decrypt, derive_key
from transmit import Transmitter, IntegrityError
from threading import Thread
from typing import List, Union, Optional, Callable
from hashlib import md5
from structsock import PeerDisconnect, StructuredSocket
import structsock

structsock.RECV_SIZE = 2**16

MD5_DIGEST_SIZE = 16
CHUNK_SIZE = 1024*1024

def computer_name() -> str:
    name = platform.node() or socket.getfqdn(socket.gethostname())
    return name

class Session:
    def __init__(self, client: StructuredSocket, server: 'Server'):
        self._client = client
        self._authorized = False
        self._server = server
        self._host = None
        self._basedir = server.basedir
    def _recv(self) -> bytes:
        return self._client.recv()
    def _send(self, data: Union[bytes, Response]) -> None:
        data = bytes(data)
        self._client.send(data)
    def _requireAuth(self) -> bool:
        if not self._authorized:
            self._send(Response(RespCode.RCE_UNAUTHORIZED))
            return False
        return True
    def prepare(self) -> None:
        name = self._recv().decode()
        self._host = name
        if self._server.isTrustedHost(name):
            self._authorized = True
            self._send(Response.ok())
            print('Authorized host connection:', name)
            print('Key identifier:', self._server.transmitter().trusted().identifierOf(name))
        else:
            self._send(Response.okbu())
            print('Unauthorized host connection:', name)
    def main(self) -> None:
        while True:
            data = self._recv()
            data = msgpack.unpackb(data)
            self._data(data)
    def _data(self, data: dict):
        op = data['type']
        if op == 'register':
            self._register()
        elif op == 'upload':
            if not self._requireAuth(): return
            path = data['dest']
            path = os.path.join(self._basedir, *path)
            if not path.startswith(self._basedir):
                self._send(Response(RespCode.RCE_INVALID_FSPATH))
                return
            total = data['total']
            self._upload(path, total)
        elif op == 'fstree':
            path = data.get('path')
            if path is None:
                path = self._basedir
            else:
                path = os.path.join(self._basedir, *path)
            if not path.startswith(self._basedir):
                self._send(Response(RespCode.RCE_INVALID_FSPATH))
                return
            self._fstree(path)
        elif op == 'fetch':
            path = data['path']
            path = os.path.join(self._basedir, path)
            if not path.startswith(self._basedir):
                print(path)
                self._send(Response(RespCode.RCE_INVALID_FSPATH))
                return
            self._fetch(path)
        else:
            self._send(Response(RespCode.RCE_NO_SUCH_COMMAND))
    def _fstree(self, path: str) -> None:
        files, dirs = [], []
        cur = os.getcwd()
        try:
            os.chdir(path)
            for entry in os.listdir():
                if os.path.isfile(entry): files.append(entry)
                elif os.path.isdir(entry): dirs.append(entry)
            base = path == self._basedir
            data = msgpack.packb({'files': files, 'dirs': dirs, 'base': base})
            self._send(Response.ok(data))
        except PermissionError:
            self._send(Response(RespCode.RCE_ACCESS_DENIED))
        finally:
            os.chdir(cur)
    def _register(self) -> None:
        if self._authorized:
            self._send(Response(RespCode.RCE_REGISTER_TWICE))
            return
        password, salt, derived = random_password()
        print(self._host + "'s registry password:", password)
        self._send(Response.ok(salt))
        data = self._recv()
        try:
            data = decrypt(derived, data)
            self._server.trustHost(self._host, data)    
            print('Added', self._host, 'to trusted hosts.')
            print('Key identifier is', self._server.transmitter().trusted().identifierOf(self._host))
            self._send(Response.ok())
            self._authorized = True
        except Exception:
            self._send(Response(RespCode.RCE_WRONG_PASSWORD))
    def _upload(self, destination: str, chunks: int) -> None:
        t = self._server.transmitter()
        if not t.transmission(self._host, destination):
            self._send(Response(RespCode.RCE_TRANSMITTER_OCCUPIED))
            return
        self._send(Response.ok())
        for i in range(chunks):
            print('\rUploading %i of %i chunks...' % (i+1, chunks), end='')
            while True:
                data = self._recv()
                chunk, digest = data[:-MD5_DIGEST_SIZE], data[-MD5_DIGEST_SIZE:]
                try:
                    t.chunk(chunk, digest)
                except IntegrityError:
                    self._send(Response(RespCode.RCE_INTEGRITY_FAIL))
                    continue # retry
                else:
                    self._send(Response.ok())
                    break
        print('\nUploaded %i chunks.' % chunks)
        signature = self._recv()
        try:
            if t.finish(signature):
                self._send(Response.ok())
            else:
                self._send(Response(RespCode.RCE_SIGNATURE_MISMATCH))
        except PermissionError:
            self._send(Response(RespCode.RCE_ACCESS_DENIED))
    def _fetch(self, path: str) -> None:
        try:
            size = os.path.getsize(path)
            total = math.ceil(size / CHUNK_SIZE)
            self._send(Response.ok(str(total)))
            stream = open(path, 'rb')
            hasher = md5()
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk: break
                hasher.update(chunk)
                self._send(chunk)
            self._send(hasher.digest())
            stream.close()
        except PermissionError:
            self._send(Response(RespCode.RCE_ACCESS_DENIED))
    def lifecycle(self, multithread: bool=False) -> None:
    
        if multithread:
            th = Thread(target=self.lifecycle, name='Session-%s' % self._client.getpeername()[0])
            th.start()
            return
        try:
            self.prepare()
            self.main()
        except PeerDisconnect:
            print(self._host or 'Unknown host', 'has disconnected.')
            self._client.close()
            self._server.transmitter().trusted().save('verified')

class Server:
    def __init__(self, port: int, basedir: str='D:\\'):
        self._transmitter = Transmitter(HostKeyMap.scan('verified'))
        self._sock = StructuredSocket()
        self._sock.bind(('0.0.0.0', port))
        self._stopped = False
        self.basedir = basedir
    def trustHost(self, host: str, key: bytes):
        self._transmitter.trusted().makeTrust(host, key)
    def isTrustedHost(self, host: str) -> bool:
        return self._transmitter.isTrustedHost(host)
    def prepare(self):
        self._sock.listen(5)
    def transmitter(self) -> Transmitter:
        return self._transmitter
    def serve(self, thread_join: bool = False) -> None:
        if thread_join:
            t = Thread(target=self.serve, name='ServerDaemon', daemon=True)
            t.start()
            return
        while not self._stopped:
            self._client, addr = self._sock.accept()
            print('Connection attempt from %s:%i' % addr)
            session = Session(self._client, self)
            session.lifecycle(True)
    def stop(self):
        self._stopped = True

class Client:
    def __init__(self, host: str, port: int):
        self._security = LocalSecurity.load('local.pem')
        self._sock = StructuredSocket()
        self._address = (host, port)
        self._authorized = False
        self._salt = None
    def _recv(self) -> bytes:
        return self._sock.recv()
    def _send(self, data: Union[bytes, dict]) -> None:
        if isinstance(data, dict):
            data = msgpack.packb(data)
        self._sock.send(data)
    def address(self):
        return self._address
    def connect(self) -> None:
        self._sock.connect(self._address)
        self._send(computer_name().encode())
        data = Response.unpack(self._recv())
        if data.code() == RespCode.RCS_OK:
            self._authorized = True
    def close(self) -> None:
        self._sock.close()
    def authorized(self) -> bool:
        return self._authorized
    def startRegister(self) -> Response:
        self._send({'type': 'register'})
        data = Response.unpack(self._recv())
        self._salt = data.description()
        return data
    def endRegister(self, password: bytes) -> Response:
        assert self._salt
        key = self._security.export().asBytes()
        aes_key = derive_key(password, self._salt)
        key = encrypt(aes_key, key)
        self._send(key)
        data = Response.unpack(self._recv())
        self._salt = None
        self._authorized = data.success()
        return data
    def fileSystem(self, path: Optional[List[str]]) -> Response:
        data = { 'type': 'fstree' }
        if path: data['path'] = path
        self._send(data)
        data = Response.unpack(self._recv())
        return data
    def upload(self, local: str, remote: str, chunk_callback: Optional[Callable[[int, int, bool], None]]=None) -> Response:
        total = math.ceil(os.path.getsize(local) / CHUNK_SIZE)
        self._send({ 'type': 'upload', 'dest': remote, 'total': total })
        data = Response.unpack(self._recv())
        if not data.success():
            return data
        stream = open(local, 'rb')
        count = 0
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            count += 1
            self._security.chunk(chunk)
            digest = md5(chunk).digest()
            while True:
                self._send(chunk+digest)
                data = Response.unpack(self._recv())
                if chunk_callback:
                    chunk_callback(count, total, data.error())
                if data.success():
                    break
        stream.close()
        signature = self._security.finish()
        self._send(signature)
        data = Response.unpack(self._recv())
        return data
    def fetch(self, local: str, remote: str, chunk_callback: Optional[Callable[[int, int], None]]=None) -> Response:
        self._send({ 'type': 'fetch', 'path': remote })
        data = Response.unpack(self._recv())
        if data.error():
            return data
        total = int(data.description())
        hasher = md5()
        fd, temp = tempfile.mkstemp()
        for i in range(total):
            chunk = self._recv()
            hasher.update(chunk)
            os.write(fd, chunk)
            if chunk_callback:
                chunk_callback(i+1, total)
        os.close(fd)
        digest = self._recv()
        if digest != hasher.digest():
            os.unlink(temp)
            return Response(RespCode.RCE_INTEGRITY_FAIL)
        else:
            shutil.move(temp, local)
            return Response.ok()