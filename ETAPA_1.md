# Etapa 1 — Chaves e registros

## Alterações

- `kdf.py`: a divisão de bytes do segredo foi substituída por HKDF-SHA256 (HMAC e SHA256 da biblioteca padrão), gerando chaves RC4 independentes de 32 bytes por direção. RC4 e aritmética DH continuam escritos manualmente.
- `dh.py`: parâmetros recebidos precisam corresponder exatamente a um dos grupos previstos. No grupo RFC 3526, as chaves públicas são verificadas no subgrupo de ordem `(p-1)//2`. A demonstração com `p=23` evita chaves públicas triviais. O modo seguro não expõe o expoente privado nem os resultados intermediários dependentes dele no log.
- `log.py`: suporte explícito ao modo didático, com nomes de arquivos exclusivos por sessão.
- `rc4.py`: rejeita chave vazia; em modo seguro, não registra permutação interna nem fluxo RC4.
- `app.py`: valida parâmetros recebidos, propaga o modo didático ao log e não registra texto claro de mensagens em sessões seguras. A conferência de sufixos públicos agora é identificada como **não autenticada**.
- `testes_etapa1.py`: casos novos de regressão de parâmetros, derivação, troca DH, ida e volta RC4 e proteção dos logs.

## Testar

```bash
python testes.py
python testes_etapa1.py
python app.py
```

Em terminais diferentes, selecionar primeiro `[1] Ser Bob`, depois `[2] Ser Alice`.

## Limites importantes

- Não há autenticação efetiva da troca DH. Um atacante ativo ainda poderia substituir as chaves públicas. Essa é a **próxima etapa**.
- Não há HMAC das mensagens, proteção contra replay, ACK, heartbeat, nem suporte a grupos.
- Logs no modo didático contêm dados secretos e não devem ser usados com conversas privadas reais.
- HKDF aqui utiliza um contexto fixo de versão; na próxima etapa ele deve ser ligado a um identificador de sessão e à transcrição autenticada da troca.
- A biblioteca padrão `hashlib`/`hmac` executa SHA-256/HMAC; caso o professor exija implementação manual também do KDF, essa parte deverá ser substituída por implementação didática própria com vetores de teste.
- RC4 é usado estritamente para a atividade acadêmica.
