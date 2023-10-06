from heys import HeysCipher, Block


if __name__ == "__main__":
    round_keys = [0x6942, 0x1234, 0x5678, 0xABCD, 0xEFEF]
    cipher = HeysCipher(round_keys)

    for val in range(0x0000, 0xFFFF + 1):
        plaintext = Block(val)
        ciphertext = cipher.encrypt(plaintext)
        print(f"{plaintext} -> {ciphertext}")
