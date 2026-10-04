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


def compare_cifras(cifra1: list, cifra2: list) -> None:
    """
    Function to compare two lists of bits and print the differences.
    """
    differences = sum(bit1 != bit2 for bit1, bit2 in zip(cifra1, cifra2))


    print(f"\nFirst cifra: ")
    for i in range(len(cifra1)):
        if cifra1[i] != cifra2[i]:
            print(f"\033[91m{cifra1[i]}\033[0m")
        else:
            print(f"{cifra1[i]}")
    print(f"\nSecond cifra: ")
    for i in range(len(cifra2)):
            if cifra2[i] != cifra1[i]:
                print(f"\033[92m{cifra2[i]}\033[0m")
            else:
                print(f"{cifra2[i]}")

    print(f"\nNumber of different bits: {differences}/{len(cifra1)}")