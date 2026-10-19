"""
chat_server.py  -  Nó "servidor" do chat criptografado com RSA.

O servidor abre uma porta TCP e espera UM cliente conectar. Depois da conexão,
os dois nós se comportam de forma idêntica (par a par): cada um gera suas
chaves, os dois trocam as chaves públicas (handshake) e conversam com
mensagens cifradas.

PROTOCOLO DE REDE (texto ASCII, uma mensagem por linha, terminada em '\\n'):
    PUBKEY <e_hex> <n_hex>   -> handshake: anuncia a chave pública (e, n)
    MSG <cifra_hex>          -> mensagem cifrada com a chave pública do destinatário
    BYE                      -> pede o encerramento da conversa

Tudo que trafega pelo socket é hexadecimal/ASCII; o texto original das
mensagens NUNCA passa pela rede, apenas a cifra.

Uso:  python chat_server.py [porta]        (padrão: 5000)
"""

import socket
import sys
import threading
import time

import rsa_core   # <- nosso RSA feito do zero (Parte 2 do trabalho)

# Tamanho (em bits) do módulo n gerado por cada participante.
TAM_CHAVE = 1024


def log(tag: str, texto: str):
    """Imprime uma linha de log com hora e etiqueta, ex.: [12:00:01] [HANDSHAKE] ..."""
    print(f"[{time.strftime('%H:%M:%S')}] [{tag}] {texto}", flush=True)


def resumo(hexa: str, n: int = 16) -> str:
    """Encurta strings hexadecimais longas (mostra só o início) para manter o log curto."""
    return hexa if len(hexa) <= n else f"{hexa[:n]}... ({len(hexa)} hex)"


def enviar_linha(sock: socket.socket, linha: str):
    """Envia uma linha de texto pelo socket (acrescenta o '\\n' delimitador)."""
    sock.sendall((linha + "\n").encode("ascii"))


def sessao_chat(sock: socket.socket):
    """
    Executa toda a conversa sobre um socket TCP já conectado.
    É chamada tanto pelo servidor quanto pelo cliente: depois de conectados,
    os dois nós se comportam de forma idêntica (par a par).
    """
    # ------------------------------------------------------------------
    # 1) GERAÇÃO DAS CHAVES: cada nó cria seu próprio par, dinamicamente.
    # ------------------------------------------------------------------
    log("RSA", f"Gerando chaves de {TAM_CHAVE} bits...")
    pub, priv = rsa_core.gerar_chaves(TAM_CHAVE)
    log("RSA", f"Pública  e = {pub[0]}")
    log("RSA", f"Pública  n = {resumo(format(pub[1], 'x'))}")
    log("RSA", "Privada  d = (secreta, nunca enviada)")

    # ------------------------------------------------------------------
    # 2) HANDSHAKE: troca das chaves públicas pela rede.
    #    Cada lado envia a sua e lê a do outro. Como o envio é bufferizado
    #    pelo sistema, os dois podem enviar primeiro sem travar (sem deadlock).
    # ------------------------------------------------------------------
    log("HANDSHAKE", "Enviando minha chave pública...")
    enviar_linha(sock, f"PUBKEY {pub[0]:x} {pub[1]:x}")

    # makefile() transforma o socket em um "arquivo" para ler linha a linha.
    entrada = sock.makefile("r", encoding="ascii", newline="\n")
    linha = entrada.readline().strip()
    partes = linha.split()
    if len(partes) != 3 or partes[0] != "PUBKEY":
        log("ERRO", "Handshake inválido (sem PUBKEY).")
        return
    pub_remota = (int(partes[1], 16), int(partes[2], 16))   # (e, n) do outro nó
    log("HANDSHAKE", "Chave pública recebida:")
    log("HANDSHAKE", f"  e = {pub_remota[0]}")
    log("HANDSHAKE", f"  n = {resumo(format(pub_remota[1], 'x'))}")
    log("HANDSHAKE", "Concluído. Digite (/sair encerra).")

    # Sinaliza entre as threads que a conversa acabou.
    encerrar = threading.Event()

    # ------------------------------------------------------------------
    # 3) THREAD DE RECEPÇÃO: roda em paralelo, para podermos receber
    #    mensagens enquanto o usuário digita (conversa em tempo real).
    # ------------------------------------------------------------------
    def receber():
        try:
            for linha in entrada:                     # bloqueia até chegar uma linha
                linha = linha.strip()
                if linha == "BYE":
                    log("INFO", "O outro nó encerrou a conversa.")
                    break
                if linha.startswith("MSG "):
                    cifra = linha[4:]
                    log("REDE <-", resumo(cifra))
                    try:
                        # Decifra com a MINHA chave privada: m = c^d mod n.
                        texto = rsa_core.descriptografar(cifra, priv)
                    except Exception as erro:
                        log("ERRO", f"Falha ao descriptografar: {erro}")
                        continue
                    log("DECIFRADO", f"\"{texto}\"")
                    print(f"\n>>> Outro: {texto}\n", flush=True)
        except (OSError, ValueError):
            pass                                      # socket fechado
        finally:
            encerrar.set()
            log("INFO", "Conexão encerrada. Enter para sair.")

    # daemon=True: a thread morre junto com o programa principal.
    threading.Thread(target=receber, daemon=True).start()

    # ------------------------------------------------------------------
    # 4) LOOP DE ENVIO (thread principal): lê o teclado, cifra e envia.
    # ------------------------------------------------------------------
    try:
        while not encerrar.is_set():
            try:
                texto = input()
            except EOFError:
                break
            if encerrar.is_set():
                break
            if texto.strip() == "/sair":
                try:
                    enviar_linha(sock, "BYE")
                except OSError:
                    pass
                break
            if not texto:
                continue
            # Cifra com a chave PÚBLICA DO DESTINATÁRIO: c = m^e mod n.
            # Só quem tem a chave privada correspondente consegue ler.
            cifra = rsa_core.criptografar(texto, pub_remota)
            log("CIFRADO", f"\"{texto}\"")
            log("REDE ->", resumo(cifra))
            enviar_linha(sock, "MSG " + cifra)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main():
    # Porta vinda da linha de comando, ou 5000 por padrão.
    porta = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

    # Cria um socket TCP (AF_INET = IPv4, SOCK_STREAM = TCP).
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permite reutilizar a porta logo após fechar o programa.
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # "0.0.0.0" = aceita conexões de qualquer interface de rede.
    srv.bind(("0.0.0.0", porta))
    srv.listen(1)                      # fila de no máximo 1 conexão pendente

    log("SERVIDOR", f"Aguardando cliente na porta {porta}...")
    conexao, endereco = srv.accept()   # bloqueia até o cliente conectar
    srv.close()                        # não precisamos de mais conexões
    log("SERVIDOR", f"Cliente conectado: {endereco[0]}:{endereco[1]}")

    sessao_chat(conexao)               # handshake + conversa


if __name__ == "__main__":
    main()