# Etapa 9 — login e identidade no servidor

A aplicação agora requer dois cadastros distintos:

1. **Conta de login no servidor**: usuário + senha; PBKDF2-HMAC-SHA256 armazena um verificador no `dados_servidor/contas.json` (nunca senha em claro). O servidor envia desafio aleatório (nonce) e sal; o cliente responde com HMAC do desafio. **Uma conexão só entra na tabela de usuários e obtém permissão de administrar grupos após autenticar.**
2. **Credencial de autenticação ponto a ponto** em `identidades/`: chave pré-compartilhada entre cada par de usuários; utilizada para autenticar o Diffie-Hellman automático entre clientes. Senhas de login NÃO são chaves RC4 nem segredos DH.

## Primeiro uso (Windows/PowerShell)

Instale dependências: `python -m pip install -r requirements-web.txt`.

Crie as contas no **mesmo computador do servidor**:

```powershell
python contas.py Alice
python contas.py Bob
```

Digite senhas diferentes e fortes (o comando não exibe a senha). Não execute novamente para contas já existentes. As contas ficam no arquivo local `dados_servidor/contas.json`, excluído do Git pelo `.gitignore`.

Se necessário, crie as credenciais de chat entre os dois clientes (somente na configuração inicial):

```powershell
python provisionar.py Alice Bob
```

Preserve os arquivos `identidades/Alice.json` e `identidades/Bob.json` existentes: o cadastro de login não exige regenerá-los.

Abra três terminais:

```powershell
python servidor.py
python web_app.py --usuario Alice --modo didatico --porta 8001
python web_app.py --usuario Bob --modo didatico --porta 8002
```

Acesse `http://127.0.0.1:8001` e `http://127.0.0.1:8002` e faça login com o nome e a senha correspondentes. A interface web só conecta ao servidor após o login. A sessão no navegador utiliza cookie aleatório HttpOnly e SameSite=Strict; `/api/estado`, eventos, mensagens, grupos e WebSocket exigem sessão válida. O botão "Sair da conta" encerra a conexão do usuário.

> Cada porta web representa um processo de cliente associado a um usuário; o campo de login confirma essa identidade, não permite alternar o usuário de uma porta já iniciada.

## Evidências para o vídeo

- Sem login: API devolve HTTP 401; o cliente não aparece como conectado.
- Senha incorreta: servidor recusa registrar o usuário.
- Login válido: usuário aparece online e passa a poder criar grupos.
- Alice envia mensagem; Bob recebe e envia ACK autenticado; o servidor só vê cifrado.
- Logout: o usuário desaparece da lista de conectados.
- Credenciais RC4/DH permanecem somente nos clientes.

Execute: `python testes_login.py`, `python testes.py`, `python testes_etapa1.py`, `python testes_etapa4.py`.

## Limitações de segurança — importantes

Este login é adequado para **laboratório local controlado**, não é um substituto de TLS autenticado em redes abertas. O protocolo de desafio/resposta baseado em senha permite ataques de dicionário offline a quem capture uma negociação e, se a base de verificadores for comprometida, permite produzir provas de login. Como não há TLS, um intermediário ativo também pode interferir no tráfego de controle. Para produção, seria necessário TLS com validação do servidor e uma autenticação consolidada, além de bloqueio/rate-limit e procedimentos de troca de senha. O cadastro de identidades de ponta a ponta ainda exige canal confiável.

A auditoria didática imprime valores de segredos **somente em modo didático** e não deve ser usada com dados reais.
