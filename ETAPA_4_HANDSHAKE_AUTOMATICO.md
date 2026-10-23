# Etapa 4 — autenticação automática das sessões

O RC4 e os cálculos do Diffie-Hellman continuam nos clientes. O servidor apenas encaminha dados públicos e bytes cifrados.

## Provisionamento inicial obrigatório (fora do servidor)

No computador confiável usado para preparar a demonstração, execute:

```sh
python provisionar.py Alice Bob
```

Isso cria `identidades/Alice.json` e `identidades/Bob.json` com **o mesmo segredo aleatório de 256 bits**, diferente para cada par de usuários. Copie `Alice.json` **somente para Alice** e `Bob.json` **somente para Bob**, na pasta `identidades/` da instalação de cada um, usando um meio confiável (por exemplo, cópia presencial). Não envie os arquivos pelo servidor de chat. Não faça commit deles no Git: estão incluídos no `.gitignore`. Em demonstração com três usuários, faça o provisionamento de cada par (`Alice Bob`, `Alice Carlos`, `Bob Carlos`) em uma única máquina confiável e distribua os arquivos resultantes.

Este projeto usa **autenticação simétrica pré-compartilhada (PSK)**, não assinatura de chave pública. Isso evita dependências criptográficas externas, mas requer distribuição inicial confiável. Para redes com muitos usuários, uma infraestrutura de identidade com assinaturas seria mais escalável. Um segredo de par comprometido permite a um atacante se passar por qualquer participante daquele par.

## Operação

```sh
# terminal servidor
python servidor.py
# terminal Alice
python cliente.py
# terminal Bob
python cliente.py
```

Depois que ambos se conectam, basta digitar na Alice:

```
/msg Bob Olá, Bob!
```

O cliente inicia Diffie-Hellman automaticamente, aguarda uma prova HMAC da identidade de Bob vinculada às duas chaves públicas e ao contexto da sessão, calcula o segredo e envia uma confirmação contendo sua própria prova de identidade e a prova de posse da chave DH. Bob verifica ambas, devolve sua prova de posse e somente depois as mensagens pendentes são cifradas e transmitidas. Não há mais `/confirmar`.

Toda negociação continua registrada em log, com as fases `DH-*`, `IDENTIDADE`, `KEYCONF`, `AUTENTICA`, `CIFRA`, `INTEGRIDADE`, `ACK`. As provas HMAC não devem ser confundidas com a impressão digital apenas visual da transcrição.

## Testes

```sh
python testes.py
python testes_etapa1.py
python testes_etapa4.py
python testes_etapa3.py
python testes_cliente_servidor.py
```

`testes_cliente_servidor.py` exercita `/msg` sem negociação ou confirmação prévia nos modos didático e seguro; `testes_etapa3.py` repete os testes de adulteração, replay e ACK. `testes_etapa4.py` verifica alteração da transcrição e segredo divergente.

## Limitações para a apresentação

- O modo didático usa um grupo pequeno e expõe valores para auditoria: **não oferece sigilo real**.
- A segurança de identidade depende da distribuição confiável do segredo de par; não ocorre autenticação segura entre desconhecidos sem confiança prévia.
- Ainda faltam timeouts de handshake, revogação e rotação de credenciais, recuperação após desconexões, presença e grupos.
- RC4 continua sendo um algoritmo legado utilizado exclusivamente para a atividade acadêmica.
