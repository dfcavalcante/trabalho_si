# Chat cifrado — RC4 + Diffie-Hellman feitos à mão

Só Python 3.8+ e biblioteca padrão. Nada para instalar.

## Arquivos

| Arquivo | O que faz | Dono |
| --- | --- | --- |
| `dh.py` | Diffie-Hellman: exponenciação modular, Miller-Rabin, chaves, validação | Integrante 1 |
| `rc4.py` | RC4: KSA, PRGA, descarte dos 3072 primeiros bytes | Integrante 2 |
| `kdf.py` | Segredo `s` → duas chaves RC4 (uma por sentido) | Integrante 2 |
| `app.py` | Menu, rede (socket), chat, modo espião | Integrante 3 |
| `log.py` | Log numerado no terminal e em `logs/` | Integrante 3 |
| `testes.py` | Vetores de teste do RC4, conta do DH, Miller-Rabin | Todos |

## Como rodar

```bash
python3 testes.py      # deve terminar com "12/12 testes passaram"
python3 app.py         # abre o menu
```

No Windows, use `python` em vez de `python3`.

### Chat Alice ↔ Bob (na mesma máquina)

1. **Terminal 1:** `python3 app.py` → `1` (Bob) → escolha o modo → Enter na porta.
2. **Terminal 2:** `python3 app.py` → `2` (Alice) → Enter no IP e na porta.
3. A troca de chaves acontece sozinha e aparece linha a linha.
4. Confiram em voz alta as "digitais": o número de Alice em um terminal deve aparecer como "DELE" no outro.
5. Digitem mensagens. Comandos do chat:
   - `/espiao` mostra os bytes que passam pela rede (só cifrado)
   - `/verboso` mostra o RC4 byte a byte (i, j, fluxo, XOR)
   - `/log` mostra onde está o arquivo de log da sessão
   - `/sair` encerra

### Em dois computadores

Bob roda na máquina A; Alice usa o IP da máquina A (`ipconfig` no Windows, `ip a` no Linux). As duas precisam estar na mesma rede e a porta 5000 liberada no firewall.

## Modos

- **Didático (p = 23, g = 5):** cada passo cabe na tela e dá para conferir na calculadora. Usar nos blocos 3 e 4 do vídeo.
- **Seguro (2048 bits, RFC 3526 grupo 14):** o terminal mostra o resumo e o arquivo de log guarda os ~4 mil passos completos. Usar na demo final.

A opção `3` do menu roda o Diffie-Hellman de Alice e Bob no mesmo terminal, em modo didático, sem rede.

## Evidências para a entrega

Tudo fica em `logs/sessao_<data-hora>_<lado>.log`. Para a entrega, guardem:

- os logs de Alice e Bob de uma sessão didática e de uma segura;
- a saída de `python3 testes.py`;
- prints do `/espiao` ligado.

## Regra do projeto

Não usar `pow(x, y, p)`, `hashlib`, `cryptography`, `pycryptodome` nem nenhuma lib de criptografia. A única coisa do sistema que usamos é `secrets`, para sortear as chaves privadas com aleatoriedade segura.
