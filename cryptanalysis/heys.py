"""A toy implementation of the substitution-permutation network
"""
from __future__ import annotations
import unittest


def basedecomp(n: int, base: int, showzero: bool = False, width: int = 0):
    """Decompose n into a sequence of mantissa and exponents, where exponents are powers of base
    and mantissa is in the range(0, base)
    """
    power = 1
    width_used = 0

    while n != 0:
        remainder = n % base
        if remainder > 0 or showzero:
            yield (remainder, power)
            width_used += 1
        n = n // base
        power = power * base

    if width > 0 and showzero:
        while width_used < width:
            yield (0, power)
            power *= base
            width_used += 1


def find_key(lookup: dict, val, default):
    """Given a dictionary, find the first key whose value matches the input
    value, unless no such key exists, in which case the input default is
    returned
    """
    for k, v in lookup.items():
        if v == val:
            return k
    return default


class Block:
    """A 16-bit block of data, could be plaintext, ciphertext, or intermediary state"""

    def __init__(self, val: int):
        if val < 0 or val >= 2**16:
            raise OverflowError("Exceeded 16-bit limit")
        self.val = val

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Block):
            return False
        return self.val == other.val

    def __repr__(self):
        return f"<16-bit Block 0x{self.val:04x}>"

    def substitute(self, lookup: dict[int, int]) -> Block:
        """Perform an S-box substitution using basedecomp and base-16 lookup table"""
        newval = 0
        for r, e in basedecomp(
            self.val, 16, True, 4
        ):  # TODO: remove magic number
            newval += lookup.get(r, r) * e
        return Block(newval)

    def invert_substitute(self, lookup: dict[int, int]) -> Block:
        """Perform the inverse of the S-box substitution"""
        newval = 0
        for r, e in basedecomp(self.val, 16, True, 4):
            newval += find_key(lookup, r, r) * e
        return Block(newval)

    def permute(self, lookup: dict[int, int]) -> Block:
        """Perform a permutation using basedecomp and base-2 lookup table"""
        newval = 0
        for _, e in basedecomp(self.val, 2):  # TODO: remove magic number
            newval += lookup.get(e, e)
        return Block(newval)

    def invert_permute(self, lookup: dict[int, int]) -> Block:
        """Perform the inverse of the input permutation"""
        newval = 0
        for _, e in basedecomp(self.val, 2):
            newval += find_key(lookup, e, e)
        return Block(newval)

    def __xor__(self, other: object) -> Block:
        """XOR with a 16-bit (round) key or another Block"""
        if isinstance(other, Block):
            return Block(self.val ^ other.val)
        elif isinstance(other, int):
            if other < 0 or other >= 2**16:
                raise OverflowError("Can only XOR with u16 integer")
            return Block(self.val ^ other)
        raise TypeError("XOR with Block not defined")

    def get_bit_1base(self, loc: int) -> int:
        """Get the bit at the specified location as either 1 or 0.

        loc follows big-endianness and starts at 1
        """
        if not (1 <= loc <= 16):
            raise IndexError("1-based bit loc must be between 1 and 16")
        # Left shift 1 by the appropriate number of bits and do a bit-wise AND;
        # if the result is 0, return 0, else return 1
        mask = 1 << (16 - loc)
        bit = self.val & mask

        return 0 if bit == 0 else 1


class HeysCipher:
    PERMUTATION = {
        0x8000: 0x8000,  # 1,
        0x4000: 0x0800,  # 2,
        0x2000: 0x0080,  # 3,
        0x1000: 0x0008,  # 4,
        0x0800: 0x4000,  # 5,
        0x0400: 0x0400,  # 6,
        0x0200: 0x0040,  # 7,
        0x0100: 0x0004,  # 8,
        0x0080: 0x2000,  # 9,
        0x0040: 0x0200,  # 10,
        0x0020: 0x0020,  # 11,
        0x0010: 0x0002,  # 12,
        0x0008: 0x1000,  # 13,
        0x0004: 0x0100,  # 14,
        0x0002: 0x0010,  # 15,
        0x0001: 0x0001,  # 16,
    }
    SBOX = {
        0x0: 0xE,
        0x1: 0x4,
        0x2: 0xD,
        0x3: 0x1,
        0x4: 0x2,
        0x5: 0xF,
        0x6: 0xB,
        0x7: 0x8,
        0x8: 0x3,
        0x9: 0xA,
        0xA: 0x6,
        0xB: 0xC,
        0xC: 0x5,
        0xD: 0x9,
        0xE: 0x0,
        0xF: 0x7,
    }

    def __init__(self, round_keys: list[int]):
        """Initialize a cipher by providing it with the round keys.
        There should be exactly five round keys and each should be a 16-bit unsigned int
        """
        if len(round_keys) != 5:
            raise ValueError("Incorrect number of round keys")
        for rkey in round_keys:
            if rkey < 0 or rkey >= 2**16:
                raise OverflowError("Round key must be 16-bit unsigned int")
        self.round_keys = round_keys

    def encrypt(self, plaintext: Block) -> Block:
        u1 = plaintext ^ self.round_keys[0]
        v1 = u1.substitute(self.SBOX)
        u2 = v1.permute(self.PERMUTATION) ^ self.round_keys[1]
        v2 = u2.substitute(self.SBOX)
        u3 = v2.permute(self.PERMUTATION) ^ self.round_keys[2]
        v3 = u3.substitute(self.SBOX)
        u4 = v3.permute(self.PERMUTATION) ^ self.round_keys[3]
        v4 = u4.substitute(self.SBOX)

        return v4 ^ self.round_keys[4]

    def decrypt(self, ciphertext: Block) -> Block:
        pt = ciphertext ^ self.round_keys[4]
        pt = pt.invert_substitute(self.SBOX)
        pt = pt ^ self.round_keys[3]
        pt = pt.invert_permute(self.PERMUTATION)
        pt = pt.invert_substitute(self.SBOX)
        pt = pt ^ self.round_keys[2]
        pt = pt.invert_permute(self.PERMUTATION)
        pt = pt.invert_substitute(self.SBOX)
        pt = pt ^ self.round_keys[1]
        pt = pt.invert_permute(self.PERMUTATION)
        pt = pt.invert_substitute(self.SBOX)
        pt = pt ^ self.round_keys[0]

        return pt

    def check_linear_approx(self, plaintext: Block, ciphertext: Block) -> bool:
        """ """


class TestBaseDecomp(unittest.TestCase):
    def test_basedecomp(self):
        for original in range(0, 0xFFFF + 1):
            for base in [2, 16]:
                recovered = 0
                for r, e in basedecomp(original, base):
                    recovered += r * e
                self.assertEqual(recovered, original)

    def test_substitution(self):
        block = Block(0xABCD)
        self.assertEqual(block.substitute(HeysCipher.SBOX), Block(0x6C59))

    def test_permutation(self):
        self.assertEqual(
            Block(0b1111000000000000).permute(HeysCipher.PERMUTATION),
            Block(0b1000100010001000),
        )
        self.assertEqual(
            Block(0b0000111100000000).permute(HeysCipher.PERMUTATION),
            Block(0b0100010001000100),
        )

    def test_invert_substitution(self):
        # Test invert by showing that inverting the substitute is identity
        for val in range(0x0000, 0xFFFF + 1):
            block = Block(val)
            self.assertEqual(
                block.substitute(HeysCipher.SBOX).invert_substitute(
                    HeysCipher.SBOX
                ),
                block,
            )

    def test_invert_permutation(self):
        # Test invert by showing that inverting the permute is identity
        for val in range(0x0000, 0xFFFF + 1):
            block = Block(val)
            self.assertEqual(
                block.permute(HeysCipher.PERMUTATION).invert_permute(
                    HeysCipher.PERMUTATION
                ),
                block,
            )

    def test_xor(self):
        block = Block(0b1111000000000000)
        self.assertEqual(block ^ 0b0000111111111111, Block(0xFFFF))

    def test_correctness(self):
        cipher = HeysCipher([1, 2, 3, 4, 5])
        for val in range(0x0000, 0xFFFF + 1):
            block = Block(val)
            self.assertEqual(cipher.decrypt(cipher.encrypt(block)), block)

    def test_get_bit(self):
        block = Block(0b1010101010101010)
        for loc in range(1, 16 + 1):
            self.assertEqual(block.get_bit_1base(loc), loc % 2)
