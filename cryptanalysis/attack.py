from typing import Callable
from .heys import Block, HeysCipher


def read_inputs(input: str) -> list[Block]:
    """Read lines of input text file and output list of blocks

    Each line of input text file is a big-endian binary encoding:
    1010101010101010 in text file encodes a block Block(0b1010101010101010)
    """
    blocks = []
    with open(input) as f:
        for line in f.read().splitlines():
            block = Block(eval(f"0b{line}"))
            blocks.append(block)
    return blocks


def check_sec34_linear_approx(pt: Block, ct: Block, cipher: HeysCipher) -> bool:
    """Given a pair of known PT-CT and a cipher (for the round keys), return
    True iff the following linear relationship holds:

    U[4,6] + U[4,8] + U[4,14] + U[4,16] + P[5] + P[7] + P[8] == 0 (mod 2)

    This relationship is stated in Heys' paper (section 3.4)
    https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf, and the expected
    bias is 1/32
    """
    U4 = ct ^ cipher.round_keys[4]
    U4 = U4.invert_substitute(cipher.SBOX)

    binsum = (
        U4.get_bit_1base(6)
        + U4.get_bit_1base(8)
        + U4.get_bit_1base(14)
        + U4.get_bit_1base(16)
        + pt.get_bit_1base(5)
        + pt.get_bit_1base(7)
        + pt.get_bit_1base(8)
    )
    return binsum % 2 == 0


def get_bias(
    plaintexts: list[Block],
    ciphertexts: list[Block],
    guess: HeysCipher,
    check: Callable[..., bool],
) -> float:
    """Given list of pairs, a guess at the key, and some linear relationship, 
    compute the bias.

    get_bias(plaintexts, ciphertexts, guess, check_sec34_linear_approx)
    """
    n_pairs = len(plaintexts)
    bias = abs(
        sum(
            [
                check(plaintexts[i], ciphertexts[i], guess)
                for i in range(n_pairs)
            ]
        )
        / n_pairs
        - 0.5
    )
    return bias
