import numpy as np
import random
from auxiliar import gmul

class AES:

    MIX = np.array([[2, 3, 1, 1], [1, 2, 3, 1],
                    [1, 1, 2, 3], [3, 1, 1, 2]])
    INV_MIX = np.array([[0x0E, 0x0B, 0x0D, 0x09], [0x09, 0x0E, 0x0B, 0x0D],
                        [0x0D, 0x09, 0x0E, 0x0B], [0x0B, 0x0D, 0x09, 0x0E]])
    RCON = [
            0x00,
            0x01,
            0x02,
            0x04,
            0x08,
            0x10,
            0x20,
            0x40,
            0x80,
            0x1B,
            0x36]


    def __init__(self, key: bytes, nk: int = 4):
        self.NK = nk
        self.NR = nk + 6

        self.KEY_BYTES = 4 * nk
        self.sbox, self.inv_sbox = self.build_sboxes()
        self.sbox_np = np.array(self.sbox, dtype=np.uint8)
        self.inv_sbox_np = np.array(self.inv_sbox, dtype=np.uint8)
        self.words = self.key_expansion(key)

    def build_sboxes(self):
        """S-Box = inverso multiplicativo em GF(2^8) + transformação afim."""
        inv = [0] * 256
        for a in range(1, 256):
            for b in range(1, 256):
                if gmul(a, b) == 1:
                    inv[a] = b
                    break
        sbox = [0] * 256
        for x in range(256):
            b = inv[x]
            s = b
            for i in range(1, 5):                      # b ^ rotl(b,1..4) ^ 0x63
                s ^= ((b << i) | (b >> (8 - i))) & 0xFF
            sbox[x] = s ^ 0x63
        inv_sbox = [0] * 256
        for x in range(256):
            inv_sbox[sbox[x]] = x
        return sbox, inv_sbox

    def bytes_to_state(self, block: bytes) -> np.ndarray:
        """Converts a 16-byte block into a 4x4 state matrix."""
        return np.array(list(block), dtype=np.uint8).reshape(4, 4).T.copy()  # Transpose to match AES state representation

    def state_to_bytes(self, state: np.ndarray) -> bytes:
        """Converts a 4x4 state matrix back into a 16-byte block."""
        return bytes(state.T.flatten().tolist())  # Transpose back and flatten to a list
    
    def rot_word(self, word: list) -> list:
        """Rotates a word (4 bytes) left by one byte."""
        return word[1:] + word[:1]

    def sub_word(self, word: list) -> list:
        """Applies the S-box substitution to a word (4 bytes)."""
        return [self.sbox[b] for b in word]

    def key_expansion(self, key: bytes) -> list:
        """Retorna lista de 44 words (cada word = 4 bytes)."""
        if len(key) != self.KEY_BYTES:
            raise ValueError(f"A chave deve ter {self.KEY_BYTES} bytes")
        
        w = [list(key[4 * i:4 * i + 4]) for i in range(self.NK)]
        for i in range(self.NK, 4 * (self.NR + 1)):
            temp = w[i - 1][:]
            if i % self.NK == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp[0] ^= self.RCON[i // self.NK]               # XOR com Rcon
            elif self.NK > 6 and i % self.NK == 4:
                temp = self.sub_word(temp)
            w.append([w[i - self.NK][j] ^ temp[j] for j in range(4)])
        return w

    def round_key(self, round_num: int) -> np.ndarray:
        """Calcula a chave de rodada para uma palavra e número de rodada."""
        w = self.words
        return np.array([[w[4 * round_num + c][r] for c in range(4)] for r in range(4)], dtype=np.uint8)


    def add_round_key(self, state: np.ndarray, rk) -> np.ndarray:
        """XOR entre o estado e a chave de rodada."""
        return state ^ rk

    def sub_bytes(self, state: np.ndarray) -> np.ndarray:
        """Substitui cada byte do estado usando a S-box."""
        return self.sbox_np[state]

    def inv_sub_bytes(self, state: np.ndarray) -> np.ndarray:
        return self.inv_sbox_np[state]
    
    def shift_rows(self, state: np.ndarray) -> np.ndarray:
        """Desloca as linhas do estado."""
        out = state.copy()
        for r in range(1, 4):
            out[r] = np.roll(state[r], -r)
        return out

    def inv_shift_rows(self, state: np.ndarray) -> np.ndarray:
        out = state.copy()
        for r in range(1, 4):
            out[r] = np.roll(state[r], r)
        return out

    def mix(self, state: np.ndarray, matrix) -> np.ndarray:
        out = np.zeros((4,4), dtype=np.uint8)

        for c in range(4):
            for r in range(4):
                v = 0
                for k in range(4):
                    v ^= gmul(int(matrix[r][k]), int(state[k][c]))
                out[r][c] = v
        return out

    def mix_columns(self, state: np.ndarray) -> np.ndarray:
        return self.mix(state, self.MIX)
    def inv_mix_columns(self, state: np.ndarray) -> np.ndarray:
            return self.mix(state, self.INV_MIX)

    def encrypt_block(self, block: bytes, trace=None) -> bytes:
        state = self.add_round_key(self.bytes_to_state(block), self.round_key(0))

        if trace is not None:
            trace.append(self.state_to_bytes(state))
        for rnd in range(1, self.NR):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_key(rnd))
            if trace is not None:
                trace.append(self.state_to_bytes(state))
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_key(self.NR))
        
        if trace is not None:
            trace.append(self.state_to_bytes(state))
        return self.state_to_bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        state = self.add_round_key(self.bytes_to_state(block), self.round_key(self.NR))
        for rnd in range(self.NR - 1, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, self.round_key(rnd))
            state = self.inv_mix_columns(state)
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.round_key(0))
        return self.state_to_bytes(state)

    def encrypt(self, plaintext: bytes) -> bytes:
        n = 16 - len(plaintext) % 16
        data = plaintext + bytes([n]) * n
        return b"".join(self.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))

    def decrypt(self, ciphertext: bytes) -> bytes:
        data = b"".join(self.decrypt_block(ciphertext[i:i + 16]) for i in range(0, len(ciphertext), 16))
        return data[:-data[-1]]

    def flip_bit(self, data: bytes) -> bytes:
        pos = random.randrange(len(data)*8)
        d = bytearray(data)
        d[pos // 8] ^= 1 << (7 - pos % 8)
        print(f"\nBit alterado: posição {pos} (byte {pos // 8}, bit {pos % 8})")
        return bytes(d)