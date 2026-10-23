# Validação da entrega

Base consolidada: arquivos locais da versão 9 e alterações verificadas do commit b0751b2, combinados aos patches de auditoria RC4/espião e correção dos testes.

- Substituído `hashlib`/`hmac` por `primitivas_manuais.py` em `kdf.py`, `integridade.py`, `identidades.py` e `contas.py`.
- Mantidos os algoritmos RC4 e Diffie-Hellman manuais e derivação vinculada à transcrição.
- Servidor com modo `--espiao`; auditorias determinísticas DH e RC4.
- Preparação didática e execução conjunta da suíte.
- Última execução local: **13 suítes aprovadas; 0 falhas; 0 ausentes**.
- **Pendência de implantação**: tempos maiores de PBKDF2 manual, autenticação inicial dos pares e transporte sem TLS. Não utilizar para dados reais.
- **Demonstração**: mostrar no vídeo `auditoria_dh.py`, `demonstracao_didatica.py`, logs de dois clientes e relay; não confundir auditoria determinística com sessão real.

Não foi realizado commit remoto no GitHub. As modificações estão no ZIP completo.
