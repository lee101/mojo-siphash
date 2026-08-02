"""SipHash-2-4 with a small C ABI for the Python bindings."""

comptime BPtr = UnsafePointer[UInt8, AnyOrigin[mut=True]]
comptime U64Ptr = UnsafePointer[UInt64, AnyOrigin[mut=True]]


@always_inline
def rotl(value: UInt64, amount: Int) -> UInt64:
    return (value << UInt64(amount)) | (value >> UInt64(64 - amount))


@always_inline
def load64_le(data: BPtr, offset: Int) -> UInt64:
    return (
        UInt64(data[offset])
        | (UInt64(data[offset + 1]) << 8)
        | (UInt64(data[offset + 2]) << 16)
        | (UInt64(data[offset + 3]) << 24)
        | (UInt64(data[offset + 4]) << 32)
        | (UInt64(data[offset + 5]) << 40)
        | (UInt64(data[offset + 6]) << 48)
        | (UInt64(data[offset + 7]) << 56)
    )


@always_inline
def sip_round(mut v0: UInt64, mut v1: UInt64, mut v2: UInt64, mut v3: UInt64):
    v0 += v1
    v1 = rotl(v1, 13) ^ v0
    v0 = rotl(v0, 32)
    v2 += v3
    v3 = rotl(v3, 16) ^ v2
    v0 += v3
    v3 = rotl(v3, 21) ^ v0
    v2 += v1
    v1 = rotl(v1, 17) ^ v2
    v2 = rotl(v2, 32)


def compress(state: U64Ptr, data: BPtr, length: Int):
    var v0 = state[0]
    var v1 = state[1]
    var v2 = state[2]
    var v3 = state[3]
    var offset = 0
    while offset + 8 <= length:
        var message = load64_le(data, offset)
        v3 ^= message
        sip_round(v0, v1, v2, v3)
        sip_round(v0, v1, v2, v3)
        v0 ^= message
        offset += 8
    state[0] = v0
    state[1] = v1
    state[2] = v2
    state[3] = v3


def finalize(state: U64Ptr, data: BPtr, length: Int, total: Int) -> UInt64:
    var v0 = state[0]
    var v1 = state[1]
    var v2 = state[2]
    var v3 = state[3]
    var last = UInt64(total & 255) << 56
    var tail = 0
    while tail < length:
        last |= UInt64(data[tail]) << UInt64(tail * 8)
        tail += 1

    v3 ^= last
    sip_round(v0, v1, v2, v3)
    sip_round(v0, v1, v2, v3)
    v0 ^= last
    v2 ^= UInt64(0xFF)
    sip_round(v0, v1, v2, v3)
    sip_round(v0, v1, v2, v3)
    sip_round(v0, v1, v2, v3)
    sip_round(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


@export("msh_siphash24_init")
def export_init(state_address: Int, key0: UInt64, key1: UInt64) abi("C"):
    var state = U64Ptr(unsafe_from_address=state_address)
    state[0] = UInt64(0x736F6D6570736575) ^ key0
    state[1] = UInt64(0x646F72616E646F6D) ^ key1
    state[2] = UInt64(0x6C7967656E657261) ^ key0
    state[3] = UInt64(0x7465646279746573) ^ key1


@export("msh_siphash24_update")
def export_update(state_address: Int, address: Int, length: Int) abi("C"):
    compress(
        U64Ptr(unsafe_from_address=state_address),
        BPtr(unsafe_from_address=address),
        length,
    )


@export("msh_siphash24_finalize")
def export_finalize(state_address: Int, address: Int, length: Int, total: Int) abi("C") -> UInt64:
    return finalize(
        U64Ptr(unsafe_from_address=state_address),
        BPtr(unsafe_from_address=address),
        length,
        total,
    )
