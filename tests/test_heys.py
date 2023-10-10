import unittest
from cryptanalysis.heys import basedecomp, Block, HeysCipher


class TestHeysModule(unittest.TestCase):
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
