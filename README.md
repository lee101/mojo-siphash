# mojo-siphash

`mojo-siphash` is a from-source Mojo implementation of SipHash-2-4 with a
Python API compatible with the PyPI [`siphash`](https://pypi.org/project/siphash/)
package. SipHash is a keyed hash designed for short, untrusted inputs. It is
not a password hashing algorithm.

## Coverage

The covered API is the complete SipHash-2-4 surface exported by `siphash 0.0.1`:
`SipHash_2_4(secret, s=b"")`, plus its `siphash24` and `SipHash24` aliases.
Instances provide `update(s)`, `hash()`, `digest()`, `hexdigest()`, and `copy()`.
The upstream package only implements SipHash-2-4, so no other SipHash round
variants are part of this port. The original module's internal
`_doublesipround` helper is intentionally not public API here.

Inputs may be `bytes`, `bytearray`, or a one-dimensional C-contiguous
unsigned-byte buffer such as a `numpy.uint8` array. Other NumPy dtypes,
multidimensional buffers, and strided buffers are rejected rather than being
silently reinterpreted as bytes. Aligned bulk input stays zero-copy across the
native call; streaming retains a copy of only the final zero to seven bytes.

## Install

```bash
pixi install
pixi run build
pixi run test
```

The build creates `dist/libmojo-siphash.so`; Pixi adds `python/` to
`PYTHONPATH` for the commands above.

## Usage

```python
import siphash

key = bytes(range(16))
message = b"hello"
digest = siphash.SipHash_2_4(key, message)
assert digest.hexdigest() == b"81df675798b34f00"

stream = siphash.siphash24(key)
stream.update(b"hel").update(b"lo")
assert stream.hash() == digest.hash()
```

Run it with `pixi run python -c 'import siphash; print(siphash.siphash24(bytes(range(16)), b"hello").hexdigest())'`.

## Benchmarks

Measured with `pixi run bench` on an Intel Xeon E5-2697 v4 at 2.30 GHz, Linux
x86-64, Python 3.13.14. Times are best per-call wall times from five trials
after adaptive batching. `upstream / Mojo` above 1 means Mojo is faster.

| Function | Input | Mojo | upstream | upstream / Mojo |
|---|---:|---:|---:|---:|
| `SipHash_2_4.hash` | 64 bytes | 5.58 µs | 35.87 µs | 6.42x |
| `SipHash_2_4.hash` | 4 KiB | 8.32 µs | 1611.20 µs | 193.73x |
| `SipHash_2_4.hash` | 1 MiB | 647.00 µs | 395512.92 µs | 611.30x |

These are direct final-run results. The comparison is intentionally against
the target package's pure-Python implementation, not a native SipHash wheel.

SipHash compression is a dependency chain: each 8-byte block updates the
state consumed by the next block. It therefore has no correct data-parallel
inner loop to SIMD-vectorize or parallelize for a single hash. A GPU path is
also inappropriate: its arithmetic intensity does not justify device transfer,
and one message provides only one dependent stream, so launch and transfer
costs outweigh its small fixed per-block computation. The CPU implementation
remains the default and only path.

## How it works

`src/siphash.mojo` is a single compilation unit implementing little-endian
loads, fixed-width wrapping arithmetic, two compression rounds, and four
finalization rounds. Python keeps the hashlib-style partial block plus native
four-word state, passing their non-null addresses, byte lengths, and two
little-endian key words through three small `ctypes` C ABI calls. Mojo
reconstructs `UnsafePointer[UInt8, AnyOrigin[mut=True]]` and
`UnsafePointer[UInt64, AnyOrigin[mut=True]]`. Python exports contiguous buffer
storage directly for each aligned bulk region and copies only a boundary block
or the final partial block; no per-byte Python hashing or whole-message
buffering occurs. An allocated one-byte sentinel supplies the required non-null
address for empty messages.

Tests compare all 64 published SipHash vectors, block boundaries, randomized
large input, streaming state, copying, byte-buffer input, and zero-copy NumPy
bulk addresses against the real PyPI `siphash` package.
