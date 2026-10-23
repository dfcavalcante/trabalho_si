# Trabalho SI — RC4 + Diffie-Hellman (versão acadêmica consolidada)

Projeto com cliente-servidor TCP, interface web local e criptografia ponta a ponta **didática**. RC4, Diffie-Hellman, SHA-256, HMAC-SHA256, HKDF e PBKDF2-HMAC-SHA256 são implementados em Python **sem `hashlib`, `hmac` ou dependência de biblioteca criptográfica para essas primitivas**. Somente `secrets` gera valores aleatórios. A interface web utiliza FastAPI/Uvicorn.

> IMPORTANTE: Implementações manuais de criptografia não são auditadas para produção. O RC4 possui vulnerabilidades conhecidas; o grupo didático com `p=23` não proporciona confidencialidade real. Mantenha tudo no `localhost` ou rede controlada.

## Arquitetura

- `servidor.py`: autentica usuários, lista conexões, gerencia salas e encaminha envelopes cifrados, sem segredos de conversa.
- `cliente.py`: Diffie-Hellman, autenticação da troca com credencial PSK confiável, HKDF, RC4 e HMAC.
- `web_app.py`: camada visual local e login; um processo por usuário.
- `primitivas_manuais.py`: SHA-256, HMAC, PBKDF2 em Python puro, com funções `sha256`, `hmac_sha256`, `pbkdf2_sha256`, `compare_digest`.
- `kdf.py`: HKDF e vinculação das chaves à transcrição (ID, modo, papéis e chaves DH).
- `dh.py` e `auditoria_dh.py`: DH manual e demonstração separada com expoentes FIXOS e PÚBLICOS, mostrando operações completas.
- `rc4.py` e `demonstracao_didatica.py`: KSA/PRGA/XOR e 256 passos do KSA para evidências.

## Configuração e primeiro uso

```powershell
python -m pip install -r requirements-web.txt
python preparar_demo.py Alice Bob Carlos
```

O `preparar_demo.py` é **somente para ambiente didático**: prepara contas e identidades compartilhadas. Em computadores diferentes, os arquivos `identidades/<usuário>.json` precisam ser distribuídos de forma confiável e devem permanecer secretos. Não publique `identidades/` ou `dados_servidor/`.

Em terminais separados:

```powershell
python servidor.py --espiao --host 127.0.0.1 --porta 5000
python web_app.py --usuario Alice --modo didatico --porta 8001
python web_app.py --usuario Bob --modo didatico --porta 8002
```

Acesse `http://127.0.0.1:8001` e `http://127.0.0.1:8002`. Faça login com as senhas configuradas na preparação.

## Auditoria e testes

```powershell
python auditoria_dh.py
python auditoria_dh.py --grupo seguro
python demonstracao_didatica.py
python executar_testes.py
```

- O modo `--espiao` registra envelopes **efetivamente encaminhados pelo servidor**, em hexadecimal; não é captura bruta de TCP. Pode expor metadados; use na demonstração local.
- A auditoria DH separada utiliza apenas chaves **fixas, públicas e deliberadamente inseguras**, para permitir rastrear cada operação sem vazar chaves de sessões reais.
- Em sessões reais, expoentes, segredos e chaves derivadas são ocultados dos logs por confidencialidade.
- O `executar_testes.py` usa 100 iterações de PBKDF2 **apenas dentro dos subprocessos de teste**, para evitar testes lentos. Isso **não representa o fator de custo do login normal**.

## Desempenho e compatibilidade do PBKDF2 manual

`contas.py` mantém o formato de contas e o algoritmo PBKDF2-HMAC-SHA256 de versões anteriores. O trabalho anterior usava 240.000 iterações em implementação nativa; em Python puro tal fator pode levar muito tempo em cada cadastro/login. Nesta versão, **novas contas usam 12.000 iterações por padrão** (`RC4_CHAT_PBKDF2_ITERACOES` permite configurar), uma redução da resistência contra tentativas de adivinhação de senhas. Esse é um compromisso didático, **não uma recomendação de segurança**. Contas antigas continuam contendo seu número de iterações e podem demorar para autenticar. Para ambiente acadêmico novo, use apenas contas de demonstração.

## Limitações

- Sem TLS no transporte cliente-servidor e na interface HTTP; não exponha na internet.
- Distribuição inicial das PSKs dos pares depende de canal confiável.
- Logs do modo espião revelam metadados do roteamento.
- A aplicação mantém RC4 exclusivamente por requisito acadêmico.
- Implementação manual de hash não possui análise contra canais laterais e pode ser lenta.
- Documentos `ETAPA_*.md` e `AUDITORIA_FINAL.md` descrevem etapas históricas; este README prevalece para esta versão consolidada.
