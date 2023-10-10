from random import randint, seed
from cryptanalysis.heys import HeysCipher, Block
from cryptanalysis.attack import check_sec34_linear_approx, get_bias

if __name__ == "__main__":
    seed(69420)
    round_keys = [randint(0, 0xffff) for _ in range(5)]
    print(round_keys)
    cipher = HeysCipher(round_keys)
    plaintexts = [Block(x) for x in range(0xffff+1)]
    ciphertexts = [cipher.encrypt(pt) for pt in plaintexts]
    bias = get_bias(plaintexts, ciphertexts, cipher, check_sec34_linear_approx)
    expected_bias = 1/32
    print(f"Expected bias {expected_bias}, observed bias {bias}")
