# Auditoria técnica e roteiro de evidências — RC4 Chat

**Base analisada:** `trabalho_si_etapa7_grupos.zip`. **Escopo:** revisão estática e testes locais (não é pentest nem certificação).

## Resultado dos testes

Executados localmente: `testes.py`, `testes_etapa1.py`, `testes_etapa3.py`, `testes_etapa4.py`, `testes_cliente_servidor.py`, `testes_presenca.py`, `testes_grupos.py` e `testes_web.py`: os oito comandos concluíram com código 0. O `testes.py` informou 12/12. Os testes de integração incluem servidor/cliente, modo didático e modo seguro, HMAC/ACK, presença, grupos e web.

Adicionado `testes_auditoria_final.py`: reproduziu 2/2 **lacunas** de autenticação/controle de acesso no servidor. São testes que passam ao comprovar uma vulnerabilidade, não aprovação de segurança.

## Achados prioritários

1. **CRÍTICO — Registro de nomes sem autenticação no servidor.** `servidor.py::atender()` aceita `{'tipo':'registro','nome':'Alice'}` sem prova de titularidade. Qualquer conexão pode ocupar um nome enquanto ele está livre. A autenticação PSK entre pares pode impedir que essa conexão falsifique provas de identidade para outros clientes, mas não impede indisponibilidade/ocupação do nome, nem protege os comandos de administração que dependem do nome.
2. **ALTO — Administração de grupos baseada no nome registrado.** `grupo_criar`, `grupo_adicionar` e `grupo_sair` dependem de `nome`. A identidade do criador não é autenticada pelo servidor. Teste adversarial demonstra que uma conexão não autenticada pode criar uma sala como `Criador`.
3. **ALTO — Interface local: ausência de autenticação de leitura e proteção fraca de escrita.** `web_app.py` oferece `/api/estado` e `/api/eventos` sem autenticação; endpoints de escrita exigem apenas cabeçalho `X-Chat-Local: 1`, que não é um segredo. Manter bind em `127.0.0.1`, não expor a porta na rede, implementar token local aleatório por instância, validação de origem e proteção CSRF antes de uso fora do cenário didático.
4. **MÉDIO — Chaves de identidade pré-compartilhadas.** O handshake é automático depois que `identidades/*.json` foi distribuído por canal confiável. O provisionamento manual inicial é requisito operacional; não afirmar que o cadastro é seguro se os arquivos forem copiados por canal inseguro. Não enviar a pasta `identidades/` nem logs didáticos reais ao repositório.
5. **MÉDIO — Grupo não equivale a entrega atômica.** `cliente.py::mensagem_grupo()` percorre os destinatários e envia mensagens individualmente; um destinatário pode receber enquanto outro falha. Os ACKs são por destinatário. Grupos existem somente na memória do servidor.
6. **MÉDIO — Rastreabilidade x sigilo.** No modo didático, logs podem revelar segredo/chaves e são adequados somente a dados fictícios. No modo seguro, as iterações com expoentes privados são omitidas deliberadamente, pois revelariam bits da chave privada. Mostrar passo a passo completo apenas com números didáticos e a trilha de etapas sem valores privados no modo seguro.
7. **CRÍTICO PARA ALEGAÇÕES DE SEGURANÇA — RC4 é algoritmo legado.** Para o trabalho acadêmico, demonstrar confidencialidade funcional no cenário controlado, sem afirmar proteção moderna de produção.

## Plano de correção (ordem)

A. Autenticar o registro no **servidor** com identidade própria e desafio-resposta, ou credenciais de registro confiáveis; vincular cada conexão ao usuário autenticado. Não reutilizar diretamente os segredos DH da conversa no servidor. Revisar reconexão, revogação e tentativas com nome ocupado.

B. Fazer verificações de autorização da sala a partir da identidade autenticada. Adicionar testes de entrada como terceiro, tentativa de adicionar como não criador e tentativa de relay de grupo não autorizado.

C. Proteger a API web local e os endpoints de auditoria. Não publicar informações sensíveis desnecessárias; não ligar o serviço em 0.0.0.0 sem rever o modelo de confiança.

D. Adicionar testes negativos de adulteração das provas DH, MAC, sequência, parâmetros DH, permissões e indisponibilidade. Medir logs e saídas sem divulgar PSKs.

## Roteiro de evidências para o professor (até 30 minutos)

| Bloco | Evidência | Onde obter |
|---|---|---|
| 1 (2 min) | Arquitetura e papéis servidor vs. clientes | `servidor.py`, `cliente.py`, interface web |
| 2 (5 min) | Chave privada didática, chave pública e square-and-multiply numerado | `dh.py`, painel de auditoria de Alice |
| 3 (4 min) | Chave pública trocada via servidor e cálculo do mesmo segredo | Logs didáticos Alice e Bob + mensagens `dh_inicio`/`dh_resposta` |
| 4 (3 min) | Autenticação automática com PSK pré-provisionado e confirmação de chave | `identidades.py`, `cliente.py`; **sem mostrar PSK real** |
| 5 (3 min) | Derivação HKDF, RC4 KSA/PRGA e HMAC | `kdf.py`, `rc4.py`, `integridade.py`, logs didáticos |
| 6 (3 min) | Texto claro nas pontas / bytes cifrados no relay, ACK | Duas interfaces e log servidor; demonstrar uma mensagem |
| 7 (3 min) | Adulteração/replay rejeitados e testes dos vetores RC4 | `testes_etapa3.py`, `testes.py` |
| 8 (3 min) | Presença online/offline e saída por timeout | `testes_presenca.py`, UI |
| 9 (3 min) | Grupo com três clientes, chaves independentes por destinatário, saída de membro | `testes_grupos.py`, UI |
| 10 (1 min) | Limitações e conclusão | Este relatório |

**Duração estimada: 30 minutos.** Para respeitar o limite máximo, cortar pelo menos 2 minutos durante o ensaio.

## Check de evidências a salvar

- Captura do painel de logs didáticos em Alice e Bob, com linhas numeradas do DH; indicar que os valores de demonstração **não** são credenciais reais.
- Captura do log de encaminhamento no servidor sem texto claro; registrar o identificador de sessão e o caminho público da troca.
- Captura de uma mensagem recebida com ACK autenticado, depois adulteração/replay rejeitados.
- Captura do painel de presença: Alice e Bob online, Bob desconectado.
- Captura de grupo de Alice/Bob/Carlos com ACKs por destinatário e mensagem posterior à saída de Carlos.
- Saída dos testes originais e do teste adversarial, explicando expressamente as lacunas remanescentes.
- Verificar que nenhum `identidades/*.json` foi incluído no material público e que logs de sessões seguras não revelam chaves.

## Comandos de validação

```powershell
python testes.py
python testes_etapa1.py
python testes_etapa3.py
python testes_etapa4.py
python testes_cliente_servidor.py
python testes_presenca.py
python testes_grupos.py
python testes_web.py
python testes_auditoria_final.py
```

**Limitação de evidência:** os testes de integração utilizam sockets locais e validações automatizadas; não foi executado um teste de invasão em rede real, nem demonstrada formalmente a segurança do protocolo. Os nomes de usuários e permissões administrativas do servidor precisam de autenticação antes de declarar o sistema protegido contra usuários hostis.
