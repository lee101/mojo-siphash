"""A Mojo-backed, hashlib-style implementation of SipHash-2-4."""

from __future__ import annotations

import binascii
import ctypes
import struct

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


def _bytes(value, *, name: str) -> bytes:
    """Return a stable byte copy of a supported input buffer.

    The native ABI receives only this private ``bytes`` object, never a
    caller-owned buffer.  That keeps its pointer valid for the full call and
    avoids interpreting typed or strided buffers as a different byte stream.
    """
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
    return view.tobytes()


def _address(data: bytes) -> int:
    """Get a non-null address for a private bytes object held by the caller."""
    if not data:
        return ctypes.addressof(_EMPTY)
    return int(_BYTES_ADDRESS(data))


class SipHash_2_4:
    """SipHash-2-4 keyed hash with the API of the upstream ``siphash`` class."""

    digest_size = 16
    block_size = 64

    def __init__(self, secret, s=b""):
        self._key0, self._key1 = _TWO_Q.unpack(_bytes(secret, name="secret"))
        self._state = (ctypes.c_uint64 * 4)()
        _INIT(ctypes.addressof(self._state), self._key0, self._key1)
        self.s = b""
        self.b = 0
        self.update(s)

    def update(self, s):
        # ``pending`` owns the storage passed to Mojo and remains live until
        # the C call returns.  It also ensures that partial blocks are always
        # byte-aligned, contiguous, and no more than seven bytes long.
        pending = self.s + _bytes(s, name="s")
        consumed = (len(pending) // 8) * 8
        if consumed:
            _UPDATE(ctypes.addressof(self._state), _address(pending), consumed)
        self.b += consumed
        self.s = pending[consumed:]
        return self

    def hash(self):
        return int(_FINALIZE(
            ctypes.addressof(self._state), _address(self.s), len(self.s), self.b + len(self.s)
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
