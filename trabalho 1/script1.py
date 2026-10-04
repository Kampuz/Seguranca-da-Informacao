import auxiliar
from aes import AES
BITS_IN_KEY = 128

text, key = auxiliar.receive_inputs(auxiliar.BITS_IN_TEXT, BITS_IN_KEY)

aes = AES(text, key, BITS_IN_KEY, 10, 128)


first_cifra = aes.generate_cifra()
aes.change_bit()
second_cifra = aes.generate_cifra()
auxiliar.compare_cifras(first_cifra, second_cifra)