# Etapa 5 — Interface web local

Esta etapa adiciona uma interface HTML/CSS/JavaScript atendida pelo **FastAPI local de cada cliente**. O servidor TCP `servidor.py` continua como encaminhador, sem acesso a chaves privadas ou plaintext das mensagens entre Alice e Bob.

## Instalação (PowerShell)

```powershell
python -m pip install -r requirements-web.txt
python provisionar.py Alice Bob  # somente se ainda não existem as identidades
```

**Segredos:** `identidades/Alice.json` e `identidades/Bob.json` contêm segredos compartilhados. Para uma demonstração local, podem ficar na mesma máquina, mas não compartilhe, publique ou faça commit da pasta `identidades/`. Em máquinas separadas, cada cliente deve receber apenas seu próprio arquivo por um canal confiável. Não execute um cliente web que carregue a identidade de outra pessoa.

## Três terminais

Terminal 1: `python servidor.py` (aceitar valores padrão de IP e porta)

Terminal 2:

```powershell
python web_app.py --usuario Alice --modo didatico --porta 8001
```

Terminal 3:

```powershell
python web_app.py --usuario Bob --modo didatico --porta 8002
```

Abra `http://127.0.0.1:8001` para Alice e `http://127.0.0.1:8002` para Bob. Se utilizar os arquivos `alice.json` e `bob.json` minúsculos, os nomes dos usuários também devem ser minúsculos. Os nomes devem coincidir EXATAMENTE com os do provisionamento.

### Como usar

1. Atualize a lista de usuários caso a outra pessoa tenha conectado depois.
2. Selecione `Bob` na interface de Alice.
3. Digite e envie a mensagem. O código inicia a negociação DH autenticada automaticamente e envia após concluir o handshake.
4. Acompanhe no painel direito as linhas numeradas das operações criptográficas, e no balão a confirmação de recebimento.
5. O modo `didatico` mostra mais detalhes; o modo `seguro` suprime segredos nos logs.

## Testes

```powershell
python testes.py
python testes_etapa1.py
python testes_etapa3.py
python testes_etapa4.py
python testes_cliente_servidor.py
python testes_web.py
```

## Arquitetura

- `servidor.py`: serviço TCP de encaminhamento (pacotes, nomes conectados).
- `cliente.py`: cliente criptográfico que conserva RC4, Diffie-Hellman, HKDF, HMAC e ACK.
- `web_app.py`: serviço FastAPI **local** com endpoints HTTP e atualização via WebSocket para o navegador.
- `web/static/index.html`: interface de mensagens e auditoria.

Não há banco de dados nem persistência de conversas. Mensagens aparecem na memória do navegador na sessão de uso; fechá-lo elimina o histórico visual. Os logs do Python continuam gravados em `logs/`.

## Limites da implementação

- A interface deve rodar somente em `127.0.0.1`. **A extremidade criptográfica é o processo Python local**, não o JavaScript do navegador. Não exponha a interface web pela rede sem acrescentar uma camada adequada de segurança e autenticação para o acesso HTTP.
- Lista `online` é um retrato das conexões TCP registrado pelo servidor e precisa ser atualizada; **não há heartbeat ainda**.
- A entrega é um chat privado de dois usuários por sessão. Grupos ainda não estão implementados.
- Os ACKs são autenticados, mas ainda não há sistema de retransmissão ou persistência de mensagens.
- Identidade usa segredo simétrico por par provisionado fora da rede; o primeiro cadastramento precisa ser confiável.
- Em modo didático, logs podem exibir valores sensíveis da demonstração: não os use com credenciais reais nem os publique.
- RC4 é mantido como exercício acadêmico conforme o escopo do trabalho.
