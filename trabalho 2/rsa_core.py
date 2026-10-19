"""
rsa_core.py - Implementação do RSA.

Contém:
  - mdc(a, b)                    : Máximo Divisor Comum (Euclides)
  - mdc_estendido(a, b)          : Euclides estendido
  - inverso_modular(a, m)        : inverso multiplicativo modular
  - eh_primo(n)                  : teste de primalidade (divisões + Miller-Rabin)
  - gerar_primo(bits)            : geração de primo aleatório
  - gerar_chaves(bits)           : par de chaves (publica, privada)
  - criptografar(texto, pub)     : str -> texto cifrado (hexadecimal)
  - descriptografar(cifra, priv) : texto cifrado -> str

A biblioteca secrets é usada para obter bytes aleatórios;
"""
import secrets

E_PADRAO = 65537
_PEQUENOS_PRIMOS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]


# ---------------------------------------------------------------- aritmética
def mdc(a: int, b: int) -> int:
    """Algoritmo de Euclides."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def mdc_estendido(a: int, b: int):
    """Retorna (g, x, y) tal que a*x + b*y = g = mdc(a, b). Versão iterativa."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inverso_modular(a: int, m: int) -> int:
    """Inverso multiplicativo de a módulo m (existe somente se mdc(a, m) == 1)."""
    g, x, _ = mdc_estendido(a % m, m)
    if g != 1:
        raise ValueError("Inverso modular não existe (mdc != 1).")
    return x % m


def exp_modular(base: int, exp: int, mod: int) -> int:
    """Exponenciação modular rápida (square-and-multiply)."""
    resultado = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            resultado = (resultado * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return resultado


# --------------------------------------------------------------- primalidade
def eh_primo(n: int, rodadas: int = 40) -> bool:
    """Divisões por primos pequenos + Miller-Rabin probabilístico."""
    if n < 2:
        return False
    for p in _PEQUENOS_PRIMOS:
        if n == p:
            return True
        if n % p == 0:
            return False
    # n - 1 = 2^s * d, com d ímpar
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rodadas):
        a = 2 + secrets.randbelow(n - 3)  # a em [2, n-2]
        x = exp_modular(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False  # composto
    return True


def gerar_primo(bits: int) -> int:
    """Gera um primo com exatamente 'bits' bits."""
    while True:
        c = secrets.randbits(bits)
        c |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1  # 2 bits altos (n terá bits cheios) e ímpar
        if eh_primo(c):
            return c


# -------------------------------------------------------------------- chaves
def gerar_chaves(bits: int = 1024):
    """
    Gera (chave_publica, chave_privada), cada uma como tupla (expoente, n).
    'bits' é o tamanho do módulo n.
    """
    if bits < 64:
        raise ValueError("Tamanho de chave muito pequeno (mínimo 64 bits).")
    while True:
        p = gerar_primo(bits // 2)
        q = gerar_primo(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        e = E_PADRAO
        if mdc(e, phi) != 1:
            continue
        d = inverso_modular(e, phi)
        return (e, n), (d, n)


# ---------------------------------------------------- texto <-> blocos numéricos
def _tam_bytes(n: int) -> int:
    return (n.bit_length() + 7) // 8


def criptografar(texto: str, chave_publica) -> str:
    """
    str -> UTF-8 -> blocos de (k-2) bytes, com prefixo 0x01 (preserva zeros à
    esquerda e garante bloco < n) -> c = m^e mod n.
    Retorna a cifra em hexadecimal (cada bloco com largura fixa de 2k dígitos).
    """
    e, n = chave_publica
    k = _tam_bytes(n)
    if k < 3:
        raise ValueError("Módulo n pequeno demais.")
    dados = texto.encode("utf-8")
    tam_bloco = k - 2
    saida = []
    for i in range(0, max(len(dados), 1), tam_bloco):
        bloco = dados[i:i + tam_bloco]
        m = int.from_bytes(b"\x01" + bloco, "big")
        c = exp_modular(m, e, n)
        saida.append(format(c, "0{}x".format(2 * k)))
    return "".join(saida)


def descriptografar(cifra_hex: str, chave_privada) -> str:
    """Inverso de criptografar(): m = c^d mod n, remove prefixo 0x01, decodifica UTF-8."""
    d, n = chave_privada
    k = _tam_bytes(n)
    larg = 2 * k
    if len(cifra_hex) % larg != 0:
        raise ValueError("Cifra com tamanho inválido para esta chave.")
    dados = bytearray()
    for i in range(0, len(cifra_hex), larg):
        c = int(cifra_hex[i:i + larg], 16)
        m = exp_modular(c, d, n)
        b = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if b[0] != 1:
            raise ValueError("Bloco inválido (chave incorreta ou dado corrompido).")
        dados += b[1:]
    return bytes(dados).decode("utf-8")


if __name__ == "__main__":
    import time
    t = time.time()
    pub, priv = gerar_chaves(1024)
    print(f"Chaves de 1024 bits geradas em {time.time() - t:.2f}s")
    msg = "Olá, RSA! Segurança da Informação ✔ " * 5
    c = criptografar(msg, pub)
    print("Cifra (início):", c[:64], "...")
    assert descriptografar(c, priv) == msg
    print("Teste OK.")
