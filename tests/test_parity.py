from __future__ import annotations

import inspect
import struct

import numpy as np
import pytest

import siphash
from conftest import upstream_siphash as upstream


KEY = bytes(range(16))
VECTORS = (
    "310e0edd47db6f72", "fd67dc93c539f874", "5a4fa9d909806c0d", "2d7efbd796666785",
    "b7877127e09427cf", "8da699cd64557618", "cee3fe586e46c9cb", "37d1018bf50002ab",
    "6224939a79f5f593", "b0e4a90bdf82009e", "f3b9dd94c5bb5d7a", "a7ad6b22462fb3f4",
    "fbe50e86bc8f1e75", "903d84c02756ea14", "eef27a8e90ca23f7", "e545be4961ca29a1",
    "db9bc2577fcc2a3f", "9447be2cf5e99a69", "9cd38d96f0b3c14b", "bd6179a71dc96dbb",
    "98eea21af25cd6be", "c7673b2eb0cbf2d0", "883ea3e395675393", "c8ce5ccd8c030ca8",
    "94af49f6c650adb8", "eab8858ade92e1bc", "f315bb5bb835d817", "adcf6b0763612e2f",
    "a5c91da7acaa4dde", "716595876650a2a6", "28ef495c53a387ad", "42c341d8fa92d832",
    "ce7cf2722f512771", "e37859f94623f3a7", "381205bb1ab0e012", "ae97a10fd434e015",
    "b4a31508beff4d31", "81396229f0907902", "4d0cf49ee5d4dcca", "5c73336a76d8bf9a",
    "d0a704536ba93e0e", "925958fcd6420cad", "a915c29bc8067318", "952b79f3bc0aa6d4",
    "f21df2e41d4535f9", "87577519048f53a9", "10a56cf5dfcd9adb", "eb75095ccd986cd0",
    "51a9cb9ecba312e6", "96afadfc2ce666c7", "72fe52975a4364ee", "5a1645b276d592a1",
    "b274cb8ebf87870a", "6f9bb4203de7b381", "eaecb2a30b22a87f", "9924a43cc1315724",
    "bd838d3aafbf8db7", "0b1a2a3265d51aea", "135079a3231ce660", "932b2846e4d70666",
    "e1915f5cb1eca46c", "f325965ca16d629f", "575ff28e60381be5", "724506eb4c328a95",
)


def test_public_api_and_signatures_match_upstream():
    assert siphash.siphash24 is siphash.SipHash_2_4
    assert siphash.SipHash24 is siphash.SipHash_2_4
    assert tuple(inspect.signature(siphash.SipHash_2_4).parameters) == ("secret", "s")
    assert siphash.SipHash_2_4.digest_size == upstream.SipHash_2_4.digest_size == 16
    assert siphash.SipHash_2_4.block_size == upstream.SipHash_2_4.block_size == 64


def test_published_reference_vectors():
    message = bytes(range(64))
    for length, expected in enumerate(VECTORS):
        value = siphash.SipHash_2_4(KEY, message[:length])
        assert value.hexdigest() == expected.encode()
        assert value.digest() == bytes.fromhex(expected)
        assert value.hash() == upstream.SipHash_2_4(KEY, message[:length]).hash()


@pytest.mark.parametrize("length", [0, 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 65, 511, 4096])
def test_one_shot_parity_across_block_boundaries(length):
    data = bytes((index * 37 + 11) & 255 for index in range(length))
    key = bytes((index * 19 + 3) & 255 for index in range(16))
    ours = siphash.siphash24(key, data)
    reference = upstream.siphash24(key, data)
    assert ours.hash() == reference.hash()
    assert ours.digest() == reference.digest()
    assert ours.hexdigest() == reference.hexdigest()


def test_randomized_large_payload_parity():
    data = np.random.default_rng(20260802).integers(0, 256, 1_000_003, dtype=np.uint8).tobytes()
    assert siphash.SipHash_2_4(KEY, data).hash() == upstream.SipHash_2_4(KEY, data).hash()


def test_streaming_copy_and_internal_bookkeeping_match_upstream():
    chunks = [b"a", b"bcdefgh", b"ijk", b"", b"lmnopq", b"rstuvwxyz"]
    ours = siphash.SipHash_2_4(KEY)
    reference = upstream.SipHash_2_4(KEY)
    for chunk in chunks:
        assert ours.update(chunk) is ours
        assert reference.update(chunk) is reference
        assert (ours.hash(), ours.s, ours.b) == (reference.hash(), reference.s, reference.b)
    ours_copy, reference_copy = ours.copy(), reference.copy()
    ours.update(b" next")
    reference.update(b" next")
    assert ours.hash() == reference.hash()
    assert ours_copy.hash() == reference_copy.hash()


def test_bytearray_and_memoryview_input_are_accepted():
    data = bytearray(range(64))
    assert siphash.siphash24(KEY, data).hash() == upstream.siphash24(KEY, data).hash()
    assert siphash.siphash24(KEY, memoryview(data)).hash() == upstream.siphash24(KEY, memoryview(data)).hash()


def test_uint8_numpy_bulk_is_zero_copy_and_tail_is_retained(monkeypatch):
    data = np.arange(23, dtype=np.uint8)
    expected = siphash.siphash24(KEY, data.tobytes()).hash()
    calls = []
    native_update = siphash._UPDATE

    def recording_update(state, address, length):
        calls.append((address, length))
        native_update(state, address, length)

    monkeypatch.setattr(siphash, "_UPDATE", recording_update)
    value = siphash.siphash24(KEY)
    value.update(data)
    assert calls == [(data.ctypes.data, 16)]
    data[:] = 0
    assert value.hash() == expected


def test_numpy_buffer_offset_stays_zero_copy_across_partial_block(monkeypatch):
    data = np.arange(16, dtype=np.uint8)
    expected = siphash.siphash24(KEY, b"x" + data.tobytes()).hash()
    calls = []
    native_update = siphash._UPDATE

    def recording_update(state, address, length):
        calls.append((address, length))
        native_update(state, address, length)

    monkeypatch.setattr(siphash, "_UPDATE", recording_update)
    value = siphash.siphash24(KEY, b"x")
    value.update(data)
    assert calls[1] == (data.ctypes.data + 7, 8)
    data[:] = 0
    assert value.hash() == expected


@pytest.mark.parametrize(
    "data",
    [
        np.arange(8, dtype=np.uint16),
        np.arange(16, dtype=np.uint8)[::2],
        np.arange(8, dtype=np.uint8).reshape(2, 4),
    ],
)
def test_typed_or_noncontiguous_buffers_are_rejected(data):
    with pytest.raises(TypeError, match="unsigned-byte buffer"):
        siphash.siphash24(KEY, data)


def test_non_buffer_input_is_rejected_before_entering_native_code():
    with pytest.raises(TypeError, match="bytes-like"):
        siphash.siphash24(KEY, "not bytes")


def test_invalid_key_uses_the_upstream_struct_error():
    with pytest.raises(struct.error):
        siphash.SipHash_2_4(b"too short")
