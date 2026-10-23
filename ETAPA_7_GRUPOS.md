# Etapa 7 — Conversas em grupo (implementação didática)

## Como executar

1. Execute `python servidor.py` (porta 5000).
2. Para três participantes, distribua credenciais confiáveis por par antes de iniciar os clientes:
   - `python provisionar.py Alice Bob`
   - `python provisionar.py Alice Carlos`
   - `python provisionar.py Bob Carlos`
   - Não execute os comandos de novo sobre pares já provisionados.
   - Para máquinas distintas, cada pessoa recebe somente seu arquivo de identidade.
3. Inicie instâncias da web em portas diferentes:
   - `python web_app.py --usuario Alice --modo didatico --porta 8001`
   - `python web_app.py --usuario Bob --modo didatico --porta 8002`
   - `python web_app.py --usuario Carlos --modo didatico --porta 8003`
4. Na tela de Alice, clique **Criar** na seção Grupos e informe `Equipe`.
5. Escolha `Equipe`, clique **Adicionar membro** e inclua `Bob` e depois `Carlos`.
6. Selecione a sala e envie a primeira mensagem. O aplicativo negocia individualmente sessões autenticadas com Bob e Carlos e cifra cada cópia de forma independente.
7. Em Carlos, selecione `Equipe` e clique **Sair**. Mensagens futuras serão encaminhadas somente aos membros restantes.

## Modelo de segurança

- O servidor mantém nomes e listas de membros na memória, mas não executa RC4/DH nem recebe texto claro do conteúdo.
- As conversas de grupo fazem **fan-out**: a mensagem é cifrada separadamente para cada integrante com uma sessão ponto a ponto e HMAC/ACK individuais.
- O nome da sala fica visível ao servidor; portanto, **metadados de grupo não são confidenciais**.
- A autorização de grupo é conferida no encaminhamento de pacotes cifrados e na recepção do conteúdo.
- A alteração de membros restringe futuras entregas, mas não revoga cópias já recebidas nem oferece sigilo retroativo.
- Usuários novos precisam ter uma credencial de autenticação confiável compartilhada com cada outro membro com quem conversarão.
- A sala e os membros não persistem após reiniciar o servidor.
- O servidor não autentica os nomes dos usuários no registro inicial (o handshake entre pares é autenticado). A administração de grupos ainda não tem autenticação independente de identidade no servidor. Use somente numa rede local confiável e trate essa parte como protótipo acadêmico.
- Envio grupo exige que membros estejam conectados. Não há fila offline, troca de histórico, nem garantia de chegada a todos após queda de conexão.

## Verificação

`python testes_grupos.py`

Também podem ser executados `python testes.py`, `python testes_etapa3.py`, `python testes_etapa4.py`, `python testes_presenca.py`, `python testes_web.py`.
