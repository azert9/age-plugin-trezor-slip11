def encode(hrp: str, payload: bytes) -> str:
    if not hrp:
        raise ValueError("human-readable part must not be empty")
    if any(ord(c) < 33 or ord(c) > 126 for c in hrp):
        raise ValueError("invalid character in human-readable part")
    if hrp.lower() != hrp and hrp.upper() != hrp:
        raise ValueError("mixed-case human-readable part")

    hrp = hrp.lower()
    data = _bytes_to_ints(payload, 8, 5, pad=True)

    # Six checksum symbols; the original Bech32 constant is 1.
    values = _hrp_expand(hrp) + data + [0] * 6
    polymod = _polymod(values) ^ 1
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]

    char_table = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    encoded_data = "".join(char_table[v] for v in data + checksum)
    return f"{hrp}1{encoded_data}"


def decode(s: str) -> tuple[str, bytes]:
    s = s.lower()

    sep = s.rfind("1")
    human_readable_part = s[:sep]
    data_part = s[sep + 1:]

    char_table = {c: i for i, c in enumerate("qpzry9x8gf2tvdw0s3jn54khce6mua7l")}
    data = [char_table[c] for c in data_part]

    _verify_checksum(human_readable_part, data)

    # Remove the six checksum symbols.
    return human_readable_part, _ints_to_bytes(data[:-6], 5)


def _polymod(values: list[int]) -> int:
    generator = [
        0x3B6A57B2,
        0x26508E6D,
        0x1EA119FA,
        0x3D4233DD,
        0x2A1462B3,
    ]

    chk = 1

    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value

        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]

    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _verify_checksum(hrp: str, data: list[int]):
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("invalid checksum")


def _ints_to_bytes(data: list[int], bits_per_int: int) -> bytes:
    acc = 0
    bits = 0
    ret = []

    maxv = (1 << 8) - 1
    max_acc = (1 << (bits_per_int + 8 - 1)) - 1

    for value in data:
        if value < 0 or (value >> bits_per_int):
            raise ValueError("invalid value for convertbits")

        acc = ((acc << bits_per_int) | value) & max_acc
        bits += bits_per_int

        while bits >= 8:
            bits -= 8
            ret.append((acc >> bits) & maxv)

    if bits >= bits_per_int:
        raise ValueError("excess padding")

    if ((acc << (8 - bits)) & maxv) != 0:
        raise ValueError("non-zero padding")

    return bytes(ret)


def _bytes_to_ints(data: bytes, from_bits: int, to_bits: int, *, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    result = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1

    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("invalid value for convertbits")
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits

        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & maxv)

    if pad:
        if bits:
            result.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise ValueError("invalid padding")

    return result
