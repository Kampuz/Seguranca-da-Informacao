"""
chat_client.py  -  Nó "cliente" do chat criptografado com RSA.

O cliente se conecta ao servidor e roda o mesmo código de conversa
(chat_common.sessao_chat): gera chaves, troca chaves públicas e conversa
com mensagens cifradas.

Uso:  python chat_client.py [host] [porta]     (padrão: 127.0.0.1 5000)
"""

import socket
import sys

import chat_common as cc


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    porta = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cc.log("CLIENTE", f"Conectando a {host}:{porta}...")
    sock.connect((host, porta))        # inicia a conexão TCP com o servidor
    cc.log("CLIENTE", "Conectado.")

    cc.sessao_chat(sock)               # handshake + conversa


if __name__ == "__main__":
    main()
