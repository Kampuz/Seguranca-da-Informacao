import numpy as np


class AES:

    def __init__(self, text, key, bits_in_key, rounds, block_size):
        self.text = text
        self.key = key
        self.bits_in_key = bits_in_key
        self.rounds = rounds
        self.block_size = block_size

        self.text_bits = self.to_bits(text)
        self.key_bits = self.to_bits(key)
        
        self.block = self.create_state()
        self.round_keys = self.key_expansion()

    def to_bits(self, text: str) -> list:
        """
        Function to transform a text into a list of bits.
        Returns:
            list: A list containing the bits of the input text.
        """
        return list(text.encode('utf-8'))

    def to_str(self, bits_list: list) -> str:
        """
        Function to transform a list of bits into a text.
        Returns:
            str: The text represented by the input list of bits.
        """
        return bytes(bits_list).decode('utf-8', errors='ignore')

    def change_bit(self, text_bits: list) -> list:
        random_position = np.random.randint(0, len(text_bits) - 1)

        changed_bits = text_bits.copy()
        changed_bits[random_position] ^= 1  # Flip the bit at the random position
        print(f"\nChanged bit at position {random_position} from {text_bits[random_position]} to {changed_bits[random_position]}")

        return changed_bits

    def create_state(self):
        """
        Function to transform the text into a block of bits.
        Returns:
            list: A list containing the block of bits.
        """
        blocks = []

        if (len(self.text_bits) % 16 == 0):
            for i in range(0, 16):
                self.text_bits.append(16)
        else:
            difference = 16 - (len(self.text_bits) % 16)
            for i in range(0, difference):
                self.text_bits.append(difference)
        text_bits = self.to_bits(self.text)
        block = np.array(text_bits).reshape((4, 4), order='F')
        return block

    def key_expansion(self):
        """
        Function to expand the key into round keys.
        Returns:
            list: A list containing the round keys.
        """

        for i in range(self.round_keys):
