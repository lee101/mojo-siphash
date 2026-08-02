"""Benchmark Mojo SipHash-2-4 against the upstream pure-Python package."""

from __future__ import annotations

import math
import os
import platform
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_DIR = os.path.join(ROOT, "python")

sys.path = [
    path
    for path in sys.path
    if os.path.realpath(path or os.getcwd()) != os.path.realpath(PYTHON_DIR)
]
import siphash as upstream

del sys.modules["siphash"]
sys.path.insert(0, PYTHON_DIR)
import siphash as mojo_siphash


def time_call(function, minimum_seconds=0.15, trials=5):
    loops = 1
    while True:
        start = time.perf_counter()
        for _ in range(loops):
            function()
        elapsed = time.perf_counter() - start
        if elapsed >= minimum_seconds:
            break
        loops *= max(2, int(minimum_seconds / max(elapsed, 1e-9)))
    best = math.inf
    for _ in range(trials):
        start = time.perf_counter()
        for _ in range(loops):
            function()
        best = min(best, (time.perf_counter() - start) / loops)
    return best


def machine() -> str:
    cpu = "unknown CPU"
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return f"{cpu}; {platform.system()} {platform.machine()}; Python {platform.python_version()}"


def main() -> None:
    key = bytes(range(16))
    cases = [("64 bytes", 64), ("4 KiB", 4 * 1024), ("1 MiB", 1024 * 1024)]
    print(f"Machine: {machine()}")
    print()
    print("| Function | Input | Mojo | upstream | upstream / Mojo |")
    print("|---|---:|---:|---:|---:|")
    for label, size in cases:
        data = bytes((index * 37 + 11) & 255 for index in range(size))
        ours = lambda: mojo_siphash.siphash24(key, data).hash()
        reference = lambda: upstream.siphash24(key, data).hash()
        assert ours() == reference()
        ours()
        mojo_seconds = time_call(ours)
        upstream_seconds = time_call(reference)
        print(
            f"| `SipHash_2_4.hash` | {label} | {mojo_seconds * 1e6:.2f} µs | "
            f"{upstream_seconds * 1e6:.2f} µs | {upstream_seconds / mojo_seconds:.2f}x |"
        )


if __name__ == "__main__":
    main()
