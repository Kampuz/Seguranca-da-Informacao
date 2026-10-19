"""
chat_client.py - Nó "cliente" do chat RSA.
Uso: python chat_client.py [host] [porta]   (padrão: 127.0.0.1 5000)
"""
import socket
import sys

import chat_common as cc


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    porta = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cc.log("CLIENTE", f"Conectando a {host}:{porta}...")
    sock.connect((host, porta))
    cc.log("CLIENTE", "Conectado.")
    cc.sessao_chat(sock, "Cliente")


if __name__ == "__main__":
    main()
