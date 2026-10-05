import os

os.system("")


BITS_IN_TEXT = 128

def receive_inputs(bits_in_text: int, bits_in_key: int) -> tuple:
    """
    Function to receive inputs from the user.
    Returns:
        tuple: A tuple containing the text and key provided by the user.
    """
    text = ""
    key = ""
    
    while (len(text)* 8 != bits_in_text):
        text = input(f"Enter the text (max {bits_in_text // 8} characters): ")
    
    while (len(key)* 8 != bits_in_key):
        key = input(f"Enter the key (max {bits_in_key // 8} characters): ")
    
    return text, key


def compare_encrypted_bytes(cifra1: bytes, cifra2: bytes) -> None:
    """
    Function to compare two lists of bits and print the differences.
    """

    if len(cifra1) != len(cifra2):
        raise ValueError("As cifras precisam ter o mesmo tamanho")
    
    diferent_bits = sum(bin(a ^ b).count("1") for a, b in zip(cifra1, cifra2))
    diferent_bytes = sum(a != b for a, b in zip(cifra1, cifra2))
    total_bits = len(cifra1) * 8


    def formatar(c1: bytes, c2: bytes, cor: str) -> str:
        return " ".join(
            f"{cor}{a:02x}\033[0m" if a != b else f"{a:02x}"
            for a, b in zip(c1, c2)
        )

    print(f"\nPrimeira cifra:", formatar(cifra1, cifra2, "\033[91m"))
    print(f"Segunda cifra:", formatar(cifra2, cifra1, "\033[92m"))
    print(f"\nBytes diferentes: {diferent_bytes}/{len(cifra1)}")
    print(f"Bits diferentes: {diferent_bits}/{total_bits} "
          f"({diferent_bits / total_bits:.1%})")

def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return p
