# Chat cifrado — RC4 + Diffie-Hellman feitos à mão

Chat entre usuários (Alice, Bob, …) com troca de chaves Diffie-Hellman e cifragem RC4 implementadas manualmente. Um servidor central só encaminha pacotes já cifrados. Cada usuário roda o próprio cliente, com uma interface web local.

## Arquitetura

```
 navegador ── HTTP local ──► web_app.py (cliente de Alice) ─┐
                                                            ├── TCP ──► servidor.py (relay)
 navegador ── HTTP local ──► web_app.py (cliente de Bob)  ──┘
```

- **`servidor.py` — relay.** Autentica o login de cada conexão, mantém a lista de usuários online (com heartbeat) e os grupos, e encaminha os pacotes entre clientes. **Não tem chaves DH nem RC4 e nunca vê texto claro.**
- **`cliente.py` — cliente.** Cada cliente faz a troca Diffie-Hellman diretamente com o outro (pelo relay), deriva as chaves, cifra com RC4 e autentica com HMAC. Toda a criptografia fica nas pontas.
- **`web_app.py` — interface.** Interface web local (FastAPI) para um cliente: um processo e uma porta por usuário. Exige login e sessão no navegador. A criptografia continua no `cliente.py`.

Bob não é mais o servidor: na versão antiga (`app_legado.py`) um dos lados escutava a conexão; agora os dois são clientes de um servidor independente.

### Fluxo de uma conversa

1. **Login no servidor:** usuário + senha, por desafio-resposta (HMAC sobre um nonce). A senha não trafega.
2. **Diffie-Hellman** entre os clientes, com parâmetros fixos e validação das chaves públicas.
3. **Autenticação da troca:** cada lado prova, com a credencial pré-compartilhada do par (`identidades/`), que participou daquela transcrição. Isso impede um intermediário de se passar pelo outro usuário.
4. **Derivação (HKDF-SHA256):** a partir do segredo `s`, quatro chaves independentes: RC4 e HMAC em cada direção. Todas são vinculadas à transcrição autenticada (identificador da sessão, modo, quem iniciou, quem respondeu e as duas chaves públicas). Outra sessão, outros participantes ou outra direção produzem chaves diferentes.
5. **Confirmação de chave** nos dois sentidos; só então as mensagens são liberadas.
6. **Mensagens:** cifradas com RC4 (descartando os 3072 primeiros bytes do fluxo), com HMAC, número de sequência contra replay e ACK autenticado.

Grupos usam o mesmo mecanismo: cada mensagem de grupo é enviada por um canal individual para cada membro.

## O que foi implementado à mão e o que usa biblioteca

| Componente | Implementação |
| --- | --- |
| RC4 (KSA, PRGA, descarte inicial) | **Manual** — `rc4.py` |
| Diffie-Hellman: exponenciação modular (square-and-multiply), Miller-Rabin, validação de parâmetros e chaves públicas | **Manual** — `dh.py`, sem `pow(x, y, p)` |
| HKDF (extract/expand) | Montado à mão sobre HMAC-SHA256 da biblioteca padrão (`hmac`, `hashlib`) — `kdf.py` |
| HMAC de integridade das mensagens, ACK e confirmações | `hmac` + `hashlib` (biblioteca padrão) — `integridade.py` |
| Prova de identidade entre pares | HMAC-SHA256 com chave pré-compartilhada — `identidades.py` |
| Senhas de login | PBKDF2-HMAC-SHA256 (`hashlib`) — `contas.py` |
| Números aleatórios (chaves privadas, nonces) | `secrets` (biblioteca padrão) |
| Interface web | FastAPI + Uvicorn (bibliotecas externas, sem papel criptográfico) |

Não usamos `cryptography`, `pycryptodome` nem outra biblioteca de criptografia de terceiros.

**Mudança em relação ao planejamento original.** O plano inicial previa somente a biblioteca padrão e nenhuma primitiva pronta. Depois, foi preciso autenticar a troca de chaves (sem isso, o DH puro aceita um intermediário), garantir a integridade das mensagens (RC4 sozinho é maleável) e proteger as senhas de login. Para isso usamos HMAC, SHA-256 e PBKDF2 da biblioteca padrão do Python, como **funções auxiliares**: o objeto do trabalho, RC4 e Diffie-Hellman, continua inteiramente manual. FastAPI e Uvicorn servem só para a interface web.

## Instalação

Python 3.8+.

```powershell
python -m pip install -r requirements-web.txt
```

No Linux/macOS, use `python3` em vez de `python` nos comandos abaixo.

## Primeiro uso

Execute no computador do servidor:

```powershell
python contas.py Alice          # pede a senha (mínimo de 10 caracteres)
python contas.py Bob
python provisionar.py Alice Bob # credencial de identidade do par
```

- As contas ficam em `dados_servidor/contas.json` (sem senha em claro).
- As credenciais ficam em `identidades/Alice.json` e `identidades/Bob.json`. Entregue cada arquivo apenas ao próprio usuário, por um canal confiável.
- As duas pastas estão no `.gitignore` e não devem ir para o repositório.

## Como rodar

Abra três terminais:

```powershell
python servidor.py   # Enter duas vezes: 127.0.0.1 e porta 5000
python web_app.py --usuario Alice --modo didatico --porta 8001
python web_app.py --usuario Bob   --modo didatico --porta 8002
```

Acesse http://127.0.0.1:8001 e http://127.0.0.1:8002 e faça login com a senha de cada usuário.

| Opção do `web_app.py` | Padrão | Uso |
| --- | --- | --- |
| `--modo` | `didatico` | `didatico` ou `seguro` (os dois lados precisam usar o mesmo) |
| `--servidor` | `127.0.0.1` | Endereço do servidor |
| `--porta-servidor` | `5000` | Porta do servidor |
| `--identidade` | `identidades/<usuario>.json` | Arquivo de credencial |

Também há um cliente de terminal: `python app.py` (menu) ou `python cliente.py`.

## Modos

- **Didático (p = 23, g = 5):** cada passo cabe na tela e dá para conferir na calculadora, inclusive as exponenciações com as chaves privadas.
- **Seguro (2048 bits, RFC 3526 grupo 14):** sessão real. O log registra as operações, mas **oculta os passos que dependem da chave privada**, o segredo `s` e as chaves derivadas, para não vazá-los.

### Auditoria completa do Diffie-Hellman

Para conferir todas as operações, inclusive as que o modo seguro oculta, há uma execução separada e determinística:

```powershell
python auditoria_dh.py                  # p = 23: a = 6, b = 15 → A = 8, B = 19, s = 2
python auditoria_dh.py --grupo seguro   # 2048 bits
```

Ela usa chaves privadas **fixas e públicas** (no modo de 2048 bits, derivadas de rótulos por SHA-256). Assim, toda execução dá os mesmos números. O log registra, sem abreviação:

- cada iteração do square-and-multiply (`anterior² mod p` e `× base mod p`);
- as chaves públicas, o segredo dos dois lados e a transcrição;
- o contexto HKDF e as quatro chaves derivadas.

O log de 2048 bits tem cerca de 14 MB e fica em `logs/`. Esses valores nunca são usados numa conversa real.

## Logs e evidências

Cada processo grava `logs/sessao_<data-hora>_<id>_<usuario>.log`, com cada passo numerado. Para a entrega:

- logs de Alice e Bob de uma sessão didática e de uma segura;
- logs de `auditoria_dh.py` (didático e seguro);
- saída dos testes;
- saída do terminal do servidor, que só encaminha conteúdo cifrado.

## Testes

```powershell
python testes.py               # vetores RC4, contas do DH, Miller-Rabin
python testes_etapa1.py        # parâmetros, HKDF, sigilo do log no modo seguro
python testes_etapa4.py        # credenciais de identidade entre pares
python testes_login.py         # login no servidor e na interface web
python testes_sessao.py        # chaves vinculadas à sessão, aos papéis e à direção
python testes_auditoria_dh.py  # auditoria DH determinística e completa
```

## Arquivos

| Arquivo | O que faz |
| --- | --- |
| `dh.py` | Diffie-Hellman: exponenciação modular, Miller-Rabin, chaves, validação |
| `rc4.py` | RC4: KSA, PRGA, descarte dos 3072 primeiros bytes |
| `kdf.py` | HKDF-SHA256: segredo `s` → chaves RC4 e HMAC por direção, vinculadas à sessão |
| `integridade.py` | Transcrição da troca, HMAC das mensagens, código de verificação |
| `identidades.py`, `provisionar.py` | Credenciais pré-compartilhadas entre pares |
| `contas.py` | Contas de login do servidor (PBKDF2) e desafio-resposta |
| `servidor.py` | Relay: login, presença, grupos, encaminhamento |
| `cliente.py` | Cliente: handshake, cifragem, filas, grupos |
| `web_app.py`, `web/static/index.html` | Interface web local |
| `protocolo.py` | Enquadramento dos pacotes JSON |
| `log.py` | Log numerado no terminal e em `logs/` |
| `auditoria_dh.py` | Execução determinística do DH com todos os valores |
| `app.py` | Menu de terminal (servidor, cliente, testes) |
| `app_legado.py` | Versão antiga ponto a ponto (Bob como servidor), mantida só para referência |
| `ETAPA_*.md`, `AUDITORIA_FINAL.md` | Histórico das etapas e revisão de segurança |

## Limitações conhecidas

- **Sem TLS.** A conexão com o servidor não tem proteção de transporte. As mensagens são cifradas de ponta a ponta, mas os metadados (quem fala com quem, grupos) e o desafio do login trafegam sem proteção. Quem capturar o desafio pode tentar adivinhar a senha offline. Use só em `127.0.0.1` ou numa rede local controlada.
- **Credenciais pré-compartilhadas.** A autenticação entre pares só vale se os arquivos de `identidades/` foram entregues por um canal confiável. Não há chaves públicas nem verificação de impressão digital independente.
- **RC4** tem fraquezas conhecidas e está aqui por exigência acadêmica; o descarte inicial e as chaves por sessão reduzem, mas não eliminam, esses problemas.
- Projeto acadêmico: não use com dados reais.
