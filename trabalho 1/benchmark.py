import time
import platform
import os
import statistics
from aes import AES

N_BLOCOS = 200      # blocos cifrados por medição
REPETICOES = 5      # repete e usa a mediana (reduz ruído)


def ms_por_operacao(func, n):
    """Mede n chamadas de func e devolve ms por chamada."""
    t0 = time.perf_counter()
    for _ in range(n):
        func()
    return (time.perf_counter() - t0) * 1000 / n


def mediana(func, n):
    return statistics.median(ms_por_operacao(func, n) for _ in range(REPETICOES))


if __name__ == "__main__":
    print(f"Python {platform.python_version()} | {platform.platform()}")
    print(f"CPU: {platform.processor()} | núcleos: {os.cpu_count()}")
    print(f"{N_BLOCOS} blocos por medição, mediana de {REPETICOES} repetições\n")

    print(f"{'':8} {'Cifrar':>12} {'Decifrar':>12} {'Exp. chave':>12}")
    resultados = {}
    for nk in (4, 6, 8):
        chave = bytes(range(4 * nk))
        aes = AES(chave, nk)
        bloco = bytes(range(16))
        cifra = aes.encrypt_block(bloco)
        assert aes.decrypt_block(cifra) == bloco          # garante que está correto

        t_enc = mediana(lambda: aes.encrypt_block(bloco), N_BLOCOS)
        t_dec = mediana(lambda: aes.decrypt_block(cifra), N_BLOCOS)
        t_key = mediana(lambda: aes.key_expansion(chave), N_BLOCOS)
        resultados[nk] = (t_enc, t_dec, t_key)
        print(f"AES-{32 * nk:<4} {t_enc:>9.3f} ms {t_dec:>9.3f} ms {t_key:>9.3f} ms")

    base = resultados[4][0]
    print("\nCusto relativo da cifragem (AES-128 = 1,00):")
    for nk in (4, 6, 8):
        print(f"AES-{32 * nk}: {resultados[nk][0] / base:.2f}x")