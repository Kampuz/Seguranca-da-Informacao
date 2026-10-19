"""
chat_server.py - Nó "servidor" do chat RSA.
Uso: python chat_server.py [porta]        (padrão: 5000, escuta em 0.0.0.0)
"""
import socket
import sys

import chat_common as cc


def main():
    porta = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", porta))
    srv.listen(1)
    cc.log("SERVIDOR", f"Aguardando cliente na porta {porta}...")
    conn, addr = srv.accept()
    srv.close()
    cc.log("SERVIDOR", f"Cliente conectado: {addr[0]}:{addr[1]}")
    cc.sessao_chat(conn, "Servidor")


if __name__ == "__main__":
    main()
