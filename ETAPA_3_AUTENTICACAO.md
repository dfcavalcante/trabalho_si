# Etapa 3 — Autenticação manual e integridade

## Execução

1. `python servidor.py` (servidor separado, sem segredos).
2. Em dois terminais, `python cliente.py` (nomes Alice e Bob, mesmo modo).
3. Alice: `/conversar Bob`. Aguarde aparecer o código de 16 caracteres nos DOIS terminais.
4. Alice e Bob devem COMPARAR o código fora deste chat — por voz presencial ou outro canal confiável. Sem conferência externa, não há autenticação da identidade.
5. Alice: `/confirmar Bob CODIGO`; Bob: `/confirmar Alice CODIGO`. Depois das duas confirmações, mensagens são habilitadas.
6. Alice: `/msg Bob Olá!`; Bob responde com `/msg Alice Recebido!`. Os registros `INTEGRIDADE` e `ACK` mostram autenticação e confirmação de processamento.

## Alterações

- `integridade.py`: impressão digital SHA-256 dos dados públicos da negociação e HMAC-SHA256 com comparação em tempo constante.
- `kdf.py`: além das chaves RC4, derivação independente de duas chaves HMAC por direção.
- `cliente.py`: bloqueio até confirmação manual, prova criptográfica entre pontas, HMAC de mensagem/ACK com ID e sequência, rejeição de adulterações e replays.
- `servidor.py`: apenas encaminhamento dos novos tipos `confirmacao` e `ack`, sem chaves.
- `testes_etapa3.py`: testes positivos e negativos para os dois modos.

## Observações de segurança e escopo

- O código é baseado na transcrição pública: nomes, valores públicos, modo e sessão. Cada usuário deve conferir o MESMO código por canal independente do servidor. Comparar o código pela própria conexão suspeita **não** protege de intermediário.
- Nomes são autodeclarados e não são contas/identidades persistentes: a conferência externa é essencial.
- ACK significa que o destinatário verificou e processou a mensagem, não que a leu ou armazenou em disco.
- TCP não oferece garantia de entrega após uma desconexão; o projeto registra pendentes mas ainda não implementa retransmissão. Não se deve reutilizar o fluxo RC4 para retransmitir uma mensagem recriptografada.
- O modo didático expõe materiais sensíveis intencionalmente e não deve ser empregado para sigilo real. RC4 continua apenas para demonstração acadêmica.
- O servidor continua podendo impedir entregas (negação de serviço) e não comprova a identidade dos usuários. Ainda faltam heartbeat, grupos e persistência.

## Testes

```bash
python testes.py
python testes_etapa1.py
python testes_etapa3.py
python testes_cliente_servidor.py
```
