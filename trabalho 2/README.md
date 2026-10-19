# Chat Seguro com RSA implementado do zero

Trabalho Prático – Segurança da Informação / Criptografia Aplicada
Python 3.13.5 · somente biblioteca padrão (`socket`, `threading`, `secrets`, `time`).
Nenhuma biblioteca de criptografia é utilizada.

## Arquivos

|Arquivo|Função|
|---|---|
|`rsa_core.py`|RSA: MDC, Euclides estendido, inverso modular, exponenciação modular, Miller-Rabin, geração de chaves, cifrar/decifrar texto|
|`chat_common.py`|Handshake, protocolo e logs, compartilhados por servidor e cliente|
|`chat_server.py`|Nó servidor (aguarda conexão)|
|`chat_client.py`|Nó cliente (conecta ao servidor)|

## Como executar

Abra **dois terminais** na pasta do projeto.

### Terminal 1 – servidor

``` txt

python chat_server.py 5000
```

### Terminal 2 – cliente

``` txt
python chat_client.py 127.0.0.1 5000
```

Para usar em duas máquinas, troque `127.0.0.1` pelo IP do servidor (e libere a porta no firewall).

Digite uma mensagem e pressione Enter para enviar. Digite `/sair` para encerrar.

Teste rápido do módulo RSA isolado: `python rsa_core.py`

## O que aparece nos logs

Cada nó mostra, em tempo real:

1. `[RSA]` – geração do par de chaves (1024 bits); a chave privada nunca é exibida nem enviada.
2. `[HANDSHAKE]` – envio da própria chave pública `(e, n)` e recebimento da chave do outro nó.
3. `[CIFRADO]` / `[REDE ->]` – mensagem em texto claro sendo cifrada com a **chave pública do destinatário** e a cifra (hexadecimal) que trafega na rede.
4. `[REDE <-]` / `[DECIFRADO]` – cifra recebida e o texto recuperado com a **chave privada** local.

Quem interceptar o tráfego (ex.: Wireshark na porta 5000) verá apenas `PUBKEY ...` e `MSG <hexadecimal ilegível>`.

## Protocolo

Texto, uma mensagem por linha: `PUBKEY <e> <n>` (handshake), `MSG <cifra_hex>`, `BYE`.

## Funcionamento do RSA implementado

- **Chaves:** dois primos p, q (Miller-Rabin com 40 rodadas), n = p·q, φ = (p−1)(q−1), e = 65537, d = e⁻¹ mod φ (Euclides estendido).
- **Texto → blocos:** string → UTF-8 → blocos de (k−2) bytes, k = tamanho de n em bytes. Cada bloco recebe o prefixo `0x01` (preserva zeros à esquerda e garante m < n) e vira um inteiro.
- **Cifrar:** c = mᵉ mod n (square-and-multiply). **Decifrar:** m = cᵈ mod n.
- **Saída:** blocos cifrados concatenados em hexadecimal, largura fixa por bloco.

## Limitações (didáticas)

- RSA sem padding OAEP é determinístico (mesma mensagem → mesma cifra) e vulnerável a ataques conhecidos.
- Não há autenticação das chaves públicas: um atacante ativo (man-in-the-middle) poderia trocar as chaves no handshake.
- `secrets` (biblioteca padrão) é usado apenas como fonte de números aleatórios.
