"""Load the compiled Mojo SipHash shared library."""

from __future__ import annotations

import ctypes
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
SRC = os.path.join(ROOT, "src", "siphash.mojo")
LIB = os.environ.get("MOJO_SIPHASH_LIB") or os.path.join(
    ROOT, "dist", "libmojo-siphash.so"
)

I = ctypes.c_int64
U64 = ctypes.c_uint64


class BuildError(RuntimeError):
    pass


def build(force: bool = False) -> str:
    """Build the shared library if it is missing or older than its source."""
    if os.environ.get("MOJO_SIPHASH_LIB") and os.path.exists(LIB) and not force:
        return LIB
    if not force and os.path.exists(LIB):
        if os.path.getmtime(LIB) >= os.path.getmtime(SRC):
            return LIB
    script = os.path.join(ROOT, "build", "build.sh")
    try:
        subprocess.run(
            ["bash", script], cwd=ROOT, check=True, capture_output=True,
            text=True, timeout=1800,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        stderr = getattr(exc, "stderr", None)
        raise BuildError((stderr or str(exc)).strip()[:4000]) from exc
    if not os.path.exists(LIB):
        raise BuildError(f"build succeeded without producing {LIB}")
    return LIB


_loaded: ctypes.CDLL | None = None


def lib() -> ctypes.CDLL:
    global _loaded
    if _loaded is None:
        _loaded = ctypes.CDLL(build())
        init = _loaded.msh_siphash24_init
        init.argtypes = [I, U64, U64]
        init.restype = None
        update = _loaded.msh_siphash24_update
        update.argtypes = [I, I, I]
        update.restype = None
        finalize = _loaded.msh_siphash24_finalize
        finalize.argtypes = [I, I, I, I]
        finalize.restype = U64
    return _loaded
