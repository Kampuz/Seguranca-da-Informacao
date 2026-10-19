"""
chat_server.py  -  Nó "servidor" do chat criptografado com RSA.

O servidor abre uma porta TCP e espera UM cliente conectar. Depois da conexão
ele roda exatamente o mesmo código do cliente (chat_common.sessao_chat):
gera chaves, troca chaves públicas (handshake) e conversa com mensagens cifradas.

Uso:  python chat_server.py [porta]        (padrão: 5000)
"""

import socket
import sys

import chat_common as cc


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

    cc.log("SERVIDOR", f"Aguardando cliente na porta {porta}...")
    conexao, endereco = srv.accept()   # bloqueia até o cliente conectar
    srv.close()                        # não precisamos de mais conexões
    cc.log("SERVIDOR", f"Cliente conectado: {endereco[0]}:{endereco[1]}")

    cc.sessao_chat(conexao)            # handshake + conversa


if __name__ == "__main__":
    main()
