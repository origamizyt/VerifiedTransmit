from enum import IntEnum
from typing import Optional, Union, AnyStr
import msgpack

class RespCode(IntEnum):
    'The response code of the server.'
    # success codes
    RCS_OK = 0
    RCS_OK_BUT_UNAUTHORIZED = 1
    # error codes
    RCE_FAILED = 2
    RCE_UNAUTHORIZED = 3
    RCE_REGISTER_TWICE = 4
    RCE_INTEGRITY_FAIL = 5
    RCE_SIGNATURE_MISMATCH = 6
    RCE_WRONG_PASSWORD = 7
    RCE_INVALID_FSPATH = 8
    RCE_NO_SUCH_COMMAND = 9
    RCE_ACCESS_DENIED = 10
    RCE_TRANSMITTER_OCCUPIED = 11

class Response:
    'The response object sent by the server.'
    def __init__(self, code: Union[int, RespCode], desc: Optional[AnyStr]=None):
        if not isinstance(code, RespCode):
            code = RespCode(code)
        self._code = code
        self._desc = desc
    def pack(self) -> bytes:
        'Converts this object to bytes.'
        return msgpack.packb({
            'code': self._code.value,
            'desc': self._desc
        })
    def __bytes__(self) -> bytes:
        'Converts this object to bytes.'
        return self.pack()
    @staticmethod
    def unpack(data: bytes) -> 'Response':
        'Unpacks a response object from bytes.'
        data = msgpack.unpackb(data)
        data['code'] = RespCode(data['code'])
        return Response(**data)
    def success(self) -> bool:
        'Whether this response is a success.'
        return self._code in [RespCode.RCS_OK, RespCode.RCS_OK_BUT_UNAUTHORIZED]
    def error(self) -> bool:
        'Whether this response is an error.'
        return not self.success()
    def code(self) -> RespCode:
        'The code of this response.'
        return self._code
    def description(self) -> Optional[AnyStr]:
        'The description string of this response.'
        return self._desc
    @staticmethod
    def ok(desc: Optional[AnyStr]=None) -> 'Response':
        'Shortcut for Response(RespCode.RCS_OK, desc).'
        return Response(RespCode.RCS_OK, desc)
    @staticmethod
    def okbu(desc: Optional[AnyStr]=None) -> 'Response':
        'Shortcut for Response(RespCode.RCS_OK_BUT_UNAUTHORIZED, desc).'
        return Response(RespCode.RCS_OK_BUT_UNAUTHORIZED, desc)
    @staticmethod
    def failed(desc: Optional[AnyStr]=None) -> 'Response':
        'Shortcut for Response(RespCode.RCE_FAILED, desc).'
        return Response(RespCode.RCE_FAILED, desc)
    def __repr__(self):
        return 'Response({})'.format(self._code.name)