
import random
from auxi import bits_list_to_text, change_bit, recieve_inputs, to_bits_list, compare_results, generate_cifra


BITS_IN_KEY = 256

text, key = recieve_inputs(BITS_IN_KEY)
text_bits = to_bits_list(text)
key_bits = to_bits_list(key)

criptography = generate_cifra(text_bits, key_bits)


if (random.randint(0, 1) == 1):
    text_bits = change_bit(text_bits)
    print(f"\nChanged text to: {bits_list_to_text(text_bits)} ({text_bits})")
else:
    key_bits = change_bit(key_bits)
    print(f"\nChanged key to: {bits_list_to_text(key_bits)} ({key_bits})")  

new_criptography = generate_cifra(text_bits, key_bits)

compare_results(criptography, new_criptography)