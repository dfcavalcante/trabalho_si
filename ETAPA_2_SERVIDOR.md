# Etapa 2 — servidor independente dos participantes

Esta etapa separa o servidor de Alice, Bob e demais clientes. **Ainda não implementa grupos, autenticação da troca de chaves, HMAC, ACK ou heartbeat.** Os dados trafegam cifrados pelo RC4, mas o servidor intermediário não é autenticado e poderia substituir chaves públicas (MITM). Não use para comunicação sensível.

## Como executar

Python 3.10+; somente biblioteca padrão:

Terminal 1: `python servidor.py` (IP de escuta e porta; o padrão é `127.0.0.1:5000`).

Terminal 2: `python cliente.py`, usuário `Alice`, selecione modo `1` didático ou `2` seguro; informe IP e porta do servidor.

Terminal 3: `python cliente.py`, usuário `Bob`, **selecione o mesmo modo**; informe o mesmo endereço do servidor.

Você também pode executar `python app.py` e escolher o papel em cada terminal.

Em Alice:
- `/online` lista conexões registradas no servidor (não garante presença em tempo real)
- `/conversar Bob` inicia Diffie-Hellman com Bob, passando **somente chaves públicas** pelo servidor
- `/msg Bob Olá!` envia texto cifrado ao cliente Bob
- `/log` mostra caminho do log local
- `/sair` encerra

No terminal de Bob, após a troca DH, digite `/msg Alice Olá, Alice!`.

O servidor roteia `dh_inicio`, `dh_resposta`, `cifra`, mas **não importa** os módulos `dh`, `kdf` nem `rc4`, e não recebe chaves privadas ou segredo compartilhado. Os clientes derivam chaves RC4 distintas por direção a partir do segredo DH e de um identificador de sessão. Cada cliente pode se conectar em nome próprio; o nome ainda não constitui autenticação de identidade.

Modo seguro **significa grupo DH de 2048 bits no protótipo**: não significa segurança criptográfica end-to-end comprovada, porque RC4 e o protocolo de autenticação/integridade são ainda limitados.

## Testes

```
python testes.py
python testes_etapa1.py
python testes_cliente_servidor.py
```

O último teste sobe um servidor local e verifica as mensagens nos dois sentidos, tanto em modo didático como no modo de 2048 bits.

## Próximas etapas

- Autenticar os pares e a transcrição de Diffie-Hellman (comparação independente ou identidades pré-configuradas).
- HMAC/contadores de sequência para integridade, anti-replay e ACKs autenticados.
- Heartbeat para detecção de presença além do cadastro/conexão TCP.
- Grupos com políticas de ingresso/saída e múltiplas sessões ponto a ponto.

## Arquivos

- `servidor.py`: aceita múltiplos clientes, registro, listagem de conectados e relay
- `cliente.py`: realiza Diffie-Hellman, RC4 e mensagens de usuário
- `protocolo.py`: framing TCP JSON de tamanho limitado
- `app.py`: menu para executar servidor ou cliente
- `app_legado.py`: demonstração anterior Alice/Bob por conexão direta, preservada para consulta
- `dh.py`, `kdf.py`, `rc4.py`, `log.py`: operações criptográficas e auditabilidade da etapa anterior
