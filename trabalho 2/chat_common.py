"""
chat_common.py - Lógica compartilhada entre servidor e cliente do chat.

Protocolo (texto, uma mensagem por linha, terminada em '\n'):
  PUBKEY <e_hex> <n_hex>   -> handshake: envia a chave pública
  MSG <cifra_hex>          -> mensagem cifrada com a chave pública do destinatário
  BYE                      -> encerra a conversa
"""
import socket
import threading
import time

import rsa_core

TAM_CHAVE = 1024


def log(tag: str, texto: str):
    print(f"[{time.strftime('%H:%M:%S')}] [{tag}] {texto}", flush=True)


def resumo(hexa: str, n: int = 60) -> str:
    return hexa if len(hexa) <= n else f"{hexa[:n]}... ({len(hexa)} hex)"


def enviar_linha(sock, linha: str):
    sock.sendall((linha + "\n").encode("ascii"))


def sessao_chat(sock: socket.socket, nome_local: str):
    """Executa handshake + conversa sobre um socket já conectado."""
    log("RSA", f"Gerando par de chaves de {TAM_CHAVE} bits...")
    pub, priv = rsa_core.gerar_chaves(TAM_CHAVE)
    log("RSA", f"Chave pública  e = {pub[0]}")
    log("RSA", f"Chave pública  n = {resumo(format(pub[1], 'x'))}")
    log("RSA", "Chave privada d = (mantida em segredo, nunca enviada)")

    # ---------------- HANDSHAKE: troca de chaves públicas ----------------
    log("HANDSHAKE", "Enviando minha chave pública ao outro nó...")
    enviar_linha(sock, f"PUBKEY {pub[0]:x} {pub[1]:x}")
    arq = sock.makefile("r", encoding="ascii", newline="\n")
    linha = arq.readline().strip()
    partes = linha.split()
    if len(partes) != 3 or partes[0] != "PUBKEY":
        log("ERRO", "Handshake inválido.")
        return
    pub_remota = (int(partes[1], 16), int(partes[2], 16))
    log("HANDSHAKE", "Chave pública do outro nó recebida:")
    log("HANDSHAKE", f"  e = {pub_remota[0]}")
    log("HANDSHAKE", f"  n = {resumo(format(pub_remota[1], 'x'))}")
    log("HANDSHAKE", "Handshake concluído. Canal pronto. Digite mensagens (/sair para encerrar).")

    parar = threading.Event()

    def receber():
        try:
            for linha in arq:
                linha = linha.strip()
                if linha == "BYE":
                    log("INFO", "O outro nó encerrou a conversa.")
                    break
                if linha.startswith("MSG "):
                    cifra = linha[4:]
                    log("REDE <-", f"Cifra recebida: {resumo(cifra)}")
                    try:
                        texto = rsa_core.descriptografar(cifra, priv)
                    except Exception as exc:
                        log("ERRO", f"Falha ao descriptografar: {exc}")
                        continue
                    log("DECIFRADO", f"Usando minha chave privada -> \"{texto}\"")
                    print(f"\n>>> Outro: {texto}\n", flush=True)
        except (OSError, ValueError):
            pass
        finally:
            parar.set()
            log("INFO", "Conexão finalizada. Pressione Enter para sair.")

    threading.Thread(target=receber, daemon=True).start()

    try:
        while not parar.is_set():
            try:
                texto = input()
            except EOFError:
                break
            if parar.is_set():
                break
            if texto.strip() == "/sair":
                try:
                    enviar_linha(sock, "BYE")
                except OSError:
                    pass
                break
            if not texto:
                continue
            cifra = rsa_core.criptografar(texto, pub_remota)
            log("CIFRADO", f"\"{texto}\" -> chave pública do destinatário")
            log("REDE ->", f"Enviando: {resumo(cifra)}")
            enviar_linha(sock, "MSG " + cifra)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
