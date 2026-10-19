"""
rsa_core.py  -  Implementação do algoritmo RSA "do zero".

Este módulo NÃO usa nenhuma biblioteca de criptografia (rsa, cryptography,
PyCrypto etc.). Toda a matemática é implementada aqui:

    1. mdc()               -> Máximo Divisor Comum (algoritmo de Euclides)
    2. mdc_estendido()     -> Euclides estendido (acha os coeficientes de Bézout)
    3. inverso_modular()   -> inverso multiplicativo modular (usa o item 2)
    4. exp_modular()       -> exponenciação modular rápida (square-and-multiply)
    5. eh_primo()          -> teste de primalidade (Miller-Rabin)
    6. gerar_primo()       -> gera um primo aleatório com N bits
    7. gerar_chaves()      -> gera o par de chaves (pública, privada)
    8. criptografar()      -> texto (str) -> cifra (str hexadecimal)
    9. descriptografar()   -> cifra (str hexadecimal) -> texto (str)

Resumo matemático do RSA:
    - Escolhem-se dois primos grandes p e q.
    - n = p * q                      (módulo, faz parte das duas chaves)
    - phi(n) = (p-1) * (q-1)         (função totiente de Euler)
    - e: expoente público, com mdc(e, phi) = 1
    - d: expoente privado, d = e^(-1) mod phi   (ou seja, e*d ≡ 1 mod phi)
    - Chave pública  = (e, n)   |   Chave privada = (d, n)
    - Cifrar:    c = m^e mod n
    - Decifrar:  m = c^d mod n

A única biblioteca importada é a "secrets" da biblioteca padrão do Python,
usada apenas para obter números aleatórios; ela não faz criptografia.

AVISO: este é um RSA didático ("textbook RSA", sem padding OAEP). Não deve
ser usado em sistemas reais.
"""

import secrets  # fonte de números aleatórios (biblioteca padrão)

# Expoente público padrão. 65537 = 2^16 + 1 é um primo muito usado na prática:
# é grande o bastante para ser seguro e tem poucos bits "1", o que deixa a
# cifragem rápida.
E_PADRAO = 65537

# Primos pequenos usados para descartar rapidamente candidatos óbvios
# (números divisíveis por eles) antes do teste de Miller-Rabin, que é mais caro.
_PRIMOS_PEQUENOS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                    31, 37, 41, 43, 47, 53, 59, 61, 67, 71]


# =============================================================================
# PARTE A - FUNÇÕES AUXILIARES DE TEORIA DOS NÚMEROS
# =============================================================================

def mdc(a: int, b: int) -> int:
    """
    Máximo Divisor Comum pelo algoritmo de Euclides.

    Ideia: mdc(a, b) = mdc(b, a mod b). Repete-se até o resto ser 0;
    o último valor não nulo é o MDC.
    Exemplo: mdc(48, 18) -> (48,18) -> (18,12) -> (12,6) -> (6,0) = 6.
    """
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b      # troca simultânea: novo a = b, novo b = resto
    return a


def mdc_estendido(a: int, b: int):
    """
    Algoritmo de Euclides estendido.

    Retorna a tupla (g, x, y) tal que:   a*x + b*y = g = mdc(a, b)
    (identidade de Bézout). Os coeficientes x e y são acumulados durante as
    divisões sucessivas. Versão iterativa, para não estourar a pilha de
    recursão com números de centenas de dígitos.
    """
    # (x0, y0) são os coeficientes de "a"; (x1, y1) são os de "b".
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b != 0:
        q = a // b                       # quociente da divisão inteira
        a, b = b, a - q * b              # passo de Euclides (b vira o resto)
        x0, x1 = x1, x0 - q * x1         # atualiza coeficientes de x
        y0, y1 = y1, y0 - q * y1         # atualiza coeficientes de y
    return a, x0, y0                     # a agora guarda o MDC


def inverso_modular(a: int, m: int) -> int:
    """
    Inverso multiplicativo modular: acha x tal que (a * x) mod m = 1.

    Só existe quando mdc(a, m) = 1. Pelo Euclides estendido,
    a*x + m*y = 1  =>  a*x ≡ 1 (mod m), logo x é o inverso procurado.
    No RSA calculamos d = inverso_modular(e, phi).
    """
    g, x, _ = mdc_estendido(a % m, m)
    if g != 1:
        raise ValueError("Inverso modular não existe (mdc(a, m) != 1).")
    return x % m                         # "% m" garante resultado positivo


def exp_modular(base: int, expoente: int, modulo: int) -> int:
    """
    Exponenciação modular rápida: calcula (base ** expoente) mod modulo.

    Calcular base**expoente diretamente geraria números gigantescos.
    O método "square-and-multiply" percorre os bits do expoente e reduz
    módulo n a cada passo, mantendo os números pequenos. Custo: O(log expoente).
    """
    resultado = 1
    base = base % modulo
    while expoente > 0:
        if expoente & 1:                          # bit atual do expoente é 1?
            resultado = (resultado * base) % modulo   # multiplica
        base = (base * base) % modulo             # eleva a base ao quadrado
        expoente >>= 1                            # passa para o próximo bit
    return resultado


# =============================================================================
# PARTE B - TESTE DE PRIMALIDADE E GERAÇÃO DE PRIMOS
# =============================================================================

def eh_primo(n: int, rodadas: int = 40) -> bool:
    """
    Teste de primalidade de Miller-Rabin (probabilístico).

    Base teórica (Pequeno Teorema de Fermat): se n é primo e 1 < a < n,
    então a^(n-1) ≡ 1 (mod n). Miller-Rabin refina isso escrevendo
    n-1 = 2^s * d (d ímpar) e verificando uma sequência de quadrados.

    - Se n é composto, cada rodada o detecta com probabilidade >= 3/4.
    - Com 40 rodadas, a chance de um composto passar é menor que 4^(-40).
    """
    if n < 2:
        return False

    # Passo 1: descarta rapidamente múltiplos de primos pequenos.
    for p in _PRIMOS_PEQUENOS:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Passo 2: decompõe n-1 = 2^s * d com d ímpar.
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Passo 3: repete o teste com várias bases aleatórias "a".
    for _ in range(rodadas):
        a = 2 + secrets.randbelow(n - 3)     # a sorteado em [2, n-2]
        x = exp_modular(a, d, n)             # x = a^d mod n
        if x == 1 or x == n - 1:
            continue                         # esta base não provou nada; próxima
        for _ in range(s - 1):               # eleva ao quadrado até s-1 vezes
            x = (x * x) % n
            if x == n - 1:
                break                        # passou nesta rodada
        else:
            return False                     # nunca chegou a n-1: COMPOSTO
    return True                              # passou em todas: provavelmente primo


def gerar_primo(bits: int) -> int:
    """
    Gera um número primo aleatório com exatamente 'bits' bits.

    Sorteia candidatos até que um passe no teste de Miller-Rabin.
    Pelo Teorema dos Números Primos, ~1 a cada ln(2^bits) números é primo,
    então poucas centenas de tentativas bastam para 512 bits.
    """
    while True:
        candidato = secrets.randbits(bits)
        # Força os dois bits mais altos em 1: garante o tamanho em bits e faz
        # com que p*q tenha o tamanho total desejado.
        # Força o bit menos significativo em 1: torna o número ímpar.
        candidato |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if eh_primo(candidato):
            return candidato


# =============================================================================
# PARTE C - GERAÇÃO DE CHAVES
# =============================================================================

def gerar_chaves(bits: int = 1024):
    """
    Gera dinamicamente um par de chaves RSA.

    Parâmetro 'bits': tamanho do módulo n (ex.: 1024). Cada primo tem ~bits/2.
    Retorna ((e, n), (d, n)) = (chave_publica, chave_privada).
    """
    if bits < 64:
        raise ValueError("Tamanho de chave muito pequeno (mínimo 64 bits).")
    while True:
        # 1) dois primos distintos
        p = gerar_primo(bits // 2)
        q = gerar_primo(bits - bits // 2)
        if p == q:
            continue
        # 2) módulo n e totiente de Euler phi(n) = (p-1)(q-1)
        n = p * q
        phi = (p - 1) * (q - 1)
        # 3) expoente público e: precisa ser coprimo com phi
        e = E_PADRAO
        if mdc(e, phi) != 1:
            continue                      # raro: sorteia outros primos
        # 4) expoente privado d: inverso de e módulo phi (e*d ≡ 1 mod phi)
        d = inverso_modular(e, phi)
        # p, q e phi são descartados aqui: quem os conhecer consegue achar d.
        return (e, n), (d, n)


# =============================================================================
# PARTE D - TEXTO <-> BLOCOS NUMÉRICOS <-> CIFRA
# =============================================================================
# O RSA só cifra INTEIROS menores que n. Para cifrar texto:
#   texto -> bytes (UTF-8) -> blocos de bytes -> inteiros -> m^e mod n.
# Cada bloco precisa ser < n; por isso o tamanho do bloco depende de n.

def _tamanho_em_bytes(n: int) -> int:
    """Quantidade de bytes necessária para representar n."""
    return (n.bit_length() + 7) // 8


def criptografar(texto: str, chave_publica) -> str:
    """
    Cifra uma string com a chave pública (e, n) e devolve a cifra em
    hexadecimal.

    Etapas:
      1. str -> bytes (UTF-8): suporta acentos e emojis.
      2. Divide os bytes em blocos de (k-2) bytes, onde k = tamanho de n em bytes.
      3. Coloca o byte 0x01 na frente de cada bloco. Motivos: (a) preserva
         bytes 0x00 iniciais, que se perderiam ao virar inteiro; (b) garante que
         o inteiro m tenha no máximo k-1 bytes e portanto m < n.
      4. Converte cada bloco em inteiro m e calcula c = m^e mod n.
      5. Escreve cada c como hexadecimal de largura fixa (2k dígitos) e
         concatena. A largura fixa permite separar os blocos na decifragem.
    """
    e, n = chave_publica
    k = _tamanho_em_bytes(n)
    if k < 3:
        raise ValueError("Módulo n pequeno demais.")
    dados = texto.encode("utf-8")                    # etapa 1
    tam_bloco = k - 2
    blocos_cifrados = []
    # max(len, 1) faz com que a string vazia também gere um bloco.
    for i in range(0, max(len(dados), 1), tam_bloco):    # etapa 2
        bloco = dados[i:i + tam_bloco]
        m = int.from_bytes(b"\x01" + bloco, "big")       # etapas 3 e 4a
        c = exp_modular(m, e, n)                         # etapa 4b: c = m^e mod n
        blocos_cifrados.append(format(c, "0{}x".format(2 * k)))   # etapa 5
    return "".join(blocos_cifrados)


def descriptografar(cifra_hex: str, chave_privada) -> str:
    """
    Operação inversa de criptografar(), usando a chave privada (d, n).

    Para cada bloco de 2k dígitos hexadecimais:
      1. c = inteiro do bloco;  m = c^d mod n   (recupera o inteiro original)
      2. converte m em bytes e remove o byte 0x01 inicial (o "marcador");
      3. concatena os bytes e decodifica de UTF-8 para str.
    """
    d, n = chave_privada
    k = _tamanho_em_bytes(n)
    largura = 2 * k                                  # dígitos hex por bloco
    if len(cifra_hex) % largura != 0:
        raise ValueError("Cifra com tamanho inválido para esta chave.")
    dados = bytearray()
    for i in range(0, len(cifra_hex), largura):
        c = int(cifra_hex[i:i + largura], 16)
        m = exp_modular(c, d, n)                     # m = c^d mod n
        b = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if b[0] != 1:                                # marcador ausente => erro
            raise ValueError("Bloco inválido (chave incorreta ou dado corrompido).")
        dados += b[1:]                               # descarta o marcador 0x01
    return bytes(dados).decode("utf-8")


# =============================================================================
# AUTOTESTE: python rsa_core.py
# =============================================================================
if __name__ == "__main__":
    import time
    inicio = time.time()
    publica, privada = gerar_chaves(1024)
    print(f"Chaves de 1024 bits geradas em {time.time() - inicio:.2f}s")
    print("e =", publica[0])
    print("n =", hex(publica[1])[:50], "...")
    mensagem = "Olá, RSA! Segurança da Informação ✔ " * 5
    cifra = criptografar(mensagem, publica)
    print("Cifra (início):", cifra[:64], "...")
    assert descriptografar(cifra, privada) == mensagem
    print("Teste OK: a mensagem decifrada é igual à original.")
