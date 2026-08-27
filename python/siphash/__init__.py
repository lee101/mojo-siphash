"""A Mojo-backed, hashlib-style implementation of SipHash-2-4."""

from __future__ import annotations

import binascii
import ctypes
import struct
from contextlib import contextmanager

from ._lib import lib

__version__ = "0.1.0"

_TWO_Q = struct.Struct("<QQ")
_EMPTY = (ctypes.c_ubyte * 1)()
_BYTES_ADDRESS = ctypes.pythonapi.PyBytes_AsString
_BYTES_ADDRESS.argtypes = [ctypes.py_object]
_BYTES_ADDRESS.restype = ctypes.c_void_p
_INIT = lib().msh_siphash24_init
_UPDATE = lib().msh_siphash24_update
_FINALIZE = lib().msh_siphash24_finalize


class _PyBuffer(ctypes.Structure):
    _fields_ = [
        ("buf", ctypes.c_void_p),
        ("obj", ctypes.py_object),
        ("len", ctypes.c_ssize_t),
        ("itemsize", ctypes.c_ssize_t),
        ("readonly", ctypes.c_int),
        ("ndim", ctypes.c_int),
        ("format", ctypes.c_char_p),
        ("shape", ctypes.POINTER(ctypes.c_ssize_t)),
        ("strides", ctypes.POINTER(ctypes.c_ssize_t)),
        ("suboffsets", ctypes.POINTER(ctypes.c_ssize_t)),
        ("internal", ctypes.c_void_p),
    ]


_GET_BUFFER = ctypes.pythonapi.PyObject_GetBuffer
_GET_BUFFER.argtypes = [ctypes.py_object, ctypes.POINTER(_PyBuffer), ctypes.c_int]
_GET_BUFFER.restype = ctypes.c_int
_RELEASE_BUFFER = ctypes.pythonapi.PyBuffer_Release
_RELEASE_BUFFER.argtypes = [ctypes.POINTER(_PyBuffer)]
_RELEASE_BUFFER.restype = None


def _buffer(value, *, name: str):
    """Validate a byte buffer without copying its storage."""
    if isinstance(value, bytes):
        return value
    try:
        view = memoryview(value)
    except TypeError as exc:
        raise TypeError(f"{name} must be a bytes-like object") from exc
    if view.ndim != 1 or view.itemsize != 1 or view.format != "B" or not view.c_contiguous:
        raise TypeError(
            f"{name} must be a one-dimensional, C-contiguous unsigned-byte buffer"
        )
    return view


def _bytes_address(data: bytes, offset=0) -> int:
    if not data:
        return ctypes.addressof(_EMPTY)
    return int(_BYTES_ADDRESS(data)) + offset


@contextmanager
def _exported_address(data, offset=0):
    """Hold a non-bytes buffer export while native code uses its address."""
    exported = _PyBuffer()
    _GET_BUFFER(data, ctypes.byref(exported), 0)
    try:
        yield int(exported.buf) + offset
    finally:
        _RELEASE_BUFFER(ctypes.byref(exported))


class SipHash_2_4:
    """SipHash-2-4 keyed hash with the API of the upstream ``siphash`` class."""

    digest_size = 16
    block_size = 64

    def __init__(self, secret, s=b""):
        self._key0, self._key1 = _TWO_Q.unpack(_buffer(secret, name="secret"))
        self._state = (ctypes.c_uint64 * 4)()
        _INIT(ctypes.addressof(self._state), self._key0, self._key1)
        self.s = b""
        self.b = 0
        self.update(s)

    def update(self, s):
        data = _buffer(s, name="s")
        length = len(data)
        offset = 0

        if self.s:
            needed = 8 - len(self.s)
            if length < needed:
                self.s += bytes(data)
                return self
            boundary = self.s + bytes(data[:needed])
            _UPDATE(ctypes.addressof(self._state), _bytes_address(boundary), 8)
            self.b += 8
            self.s = b""
            offset = needed

        consumed = ((length - offset) // 8) * 8
        if consumed:
            if isinstance(data, bytes):
                _UPDATE(
                    ctypes.addressof(self._state),
                    _bytes_address(data, offset),
                    consumed,
                )
            else:
                with _exported_address(data, offset) as address:
                    _UPDATE(ctypes.addressof(self._state), address, consumed)
            self.b += consumed
            offset += consumed
        self.s = bytes(data[offset:])
        return self

    def hash(self):
        return int(_FINALIZE(
            ctypes.addressof(self._state),
            _bytes_address(self.s),
            len(self.s),
            self.b + len(self.s),
        ))

    def digest(self):
        return struct.pack("<Q", self.hash())

    def hexdigest(self):
        return binascii.hexlify(self.digest())

    def copy(self):
        duplicate = SipHash_2_4.__new__(SipHash_2_4)
        duplicate._key0 = self._key0
        duplicate._key1 = self._key1
        duplicate._state = (ctypes.c_uint64 * 4)(*self._state)
        duplicate.s = self.s
        duplicate.b = self.b
        return duplicate


siphash24 = SipHash_2_4
SipHash24 = SipHash_2_4

__all__ = ["SipHash_2_4", "siphash24", "SipHash24"]
