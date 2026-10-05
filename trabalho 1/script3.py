from aes import AES
from auxiliar import compare_encrypted_bytes

if __name__ == "__main__":

    nk = 8

    # key = input(f"\nChave ({4 * nk} caracteres): ").encode("utf-8")
    # text = input(f"Insira o texto: ").encode("utf-8")

    key = "0123456789abcdef0123456789ABCDEF".encode("utf-8")
    text = "Ola, mundo AES!".encode("utf-8")

    aes = AES(key, nk)
    encrypted_bytes = aes.encrypt(text)
    print("Cifrado (hex):", encrypted_bytes.hex())
    print("Decifrado    :", aes.decrypt(encrypted_bytes).decode("utf-8"))

    new_text = aes.flip_bit(text)

    new_encrypted_bytes = aes.encrypt(new_text)
    print("\nCifrado (hex):", new_encrypted_bytes.hex())
    print("Decifrado    :", aes.decrypt(new_encrypted_bytes).decode("utf-8"))

    compare_encrypted_bytes(encrypted_bytes, new_encrypted_bytes)