# Chat Seguro com RSA

Trabalho Prático - Segurança da Informação / Criptografia Aplicada
Python 3.13.5 · somente biblioteca padrão (`socket`, `threading`, `secrets`, `time`).
Nenhuma biblioteca de criptografia é utilizada.

## Conteúdo do pacote

| Arquivo | Descrição |
|---|---|
| `relatorio_teorico.pdf` | Parte 1: fundamentação teórica do RSA |
| `slides_rsa.pptx` | 12 slides para a apresentação |
| `rsa_core.py` | Parte 2: RSA (MDC, inverso modular, Miller-Rabin, chaves, cifrar/decifrar) |
| `chat_server.py` / `chat_client.py` | Parte 3: nós servidor e cliente do chat |
| `chat_common.py` | Código compartilhado do chat (handshake, mensagens, logs) |

## Como executar o chat

Abra **dois terminais** na pasta do projeto.

**Terminal 1 - servidor** (aguarda a conexão):
```
python chat_server.py 5000
```
**Terminal 2 - cliente** (inicia a conexão):
```
python chat_client.py 127.0.0.1 5000
```
Para usar em duas máquinas, troque `127.0.0.1` pelo IP do servidor e libere a porta no firewall.

Assim que conectam, os dois nós geram suas chaves e fazem o handshake automaticamente.
Digite uma mensagem e pressione Enter para enviar; `/sair` encerra a conversa.

Teste isolado do módulo RSA: `python rsa_core.py`

## Como visualizar os logs de criptografia

Os logs aparecem no próprio terminal, em tempo real, com hora e etiqueta:

| Etiqueta | O que mostra |
|---|---|
| `[RSA]` | Geração do par de chaves (a chave privada nunca é exibida nem enviada) |
| `[HANDSHAKE]` | Envio da minha chave pública `(e, n)` e recebimento da chave do outro nó |
| `[CIFRADO]` | Mensagem em texto claro sendo cifrada com a chave pública do destinatário |
| `[REDE ->]` | Cifra (hexadecimal) que efetivamente trafega pela rede |
| `[REDE <-]` | Cifra recebida |
| `[DECIFRADO]` | Texto recuperado com a minha chave privada |

Para comprovar que a interceptação só expõe dados ilegíveis, capture a porta do chat com o
Wireshark (filtro `tcp.port == 5000`): só aparecem as linhas `PUBKEY <e> <n>` (chaves públicas)
e `MSG <hexadecimal>`.

## Protocolo

Texto ASCII, uma mensagem por linha: `PUBKEY <e_hex> <n_hex>` (handshake), `MSG <cifra_hex>`, `BYE`.

## Funcionamento do RSA implementado

- **Chaves:** p e q primos (Miller-Rabin, 40 rodadas), n = p·q, φ = (p−1)(q−1), e = 65537,
  d = e⁻¹ mod φ (Euclides estendido). Módulo de 1024 bits por padrão.
- **Texto → blocos:** string → UTF-8 → blocos de (k−2) bytes (k = tamanho de n em bytes), com o
  prefixo `0x01` (preserva zeros à esquerda e garante m < n) → inteiros.
- **Cifrar:** c = mᵉ mod n. **Decifrar:** m = cᵈ mod n (exponenciação modular rápida).
- **Saída:** blocos cifrados concatenados em hexadecimal, com largura fixa por bloco.

## Limitações (didáticas)

- RSA sem padding OAEP é determinístico e maleável; não use em produção.
- As chaves públicas não são autenticadas: um atacante ativo (man-in-the-middle) poderia trocá-las
  no handshake.
