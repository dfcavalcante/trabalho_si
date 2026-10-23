# Etapa 6 — Presença com heartbeat

O servidor envia `ping` a cada 3 segundos. Cada cliente responde automaticamente com `pong`. Após 10 segundos sem resposta, o servidor fecha a conexão e publica um novo snapshot `presenca` para todos os clientes. Entradas e saídas também disparam notificações. A interface web recebe essas listas via WebSocket local e atualiza os indicadores Online/Offline sem clicar em Atualizar.

O heartbeat é um mecanismo de **disponibilidade de conexão** e não substitui a autenticação criptográfica entre Alice e Bob. PING/PONG são pacotes de controle no enlace cliente-servidor; não contêm chaves nem textos de mensagens. O servidor ainda não comprova a identidade da conexão através do heartbeat; a segurança das sessões criptográficas mantém seu mecanismo próprio de autenticação.

## Como rodar

1. `python servidor.py` (porta padrão 5000)
2. `python web_app.py --usuario Alice --modo didatico --porta 8001`
3. `python web_app.py --usuario Bob --modo didatico --porta 8002`
4. Abra localhost:8001 e localhost:8002. Ao fechar Bob, o indicador dele ficará Offline. Para detectar uma interrupção silenciosa, espere até 10 segundos (mais o tempo de varredura).

Para testar: `python testes_presenca.py`, `python testes_web.py` e `python testes.py`.
