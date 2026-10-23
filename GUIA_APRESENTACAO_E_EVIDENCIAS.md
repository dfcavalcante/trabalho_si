# Guia final: evidências e apresentação do chat RC4 + Diffie-Hellman

## Origem e limite da validação
- Os arquivos de evidência foram gerados executando a base local `trabalho_si_versao_completa_criptografia_manual.zip`, consolidada antes das últimas mudanças no GitHub.
- A branch remota inspecionada em 23/10/2026 estava no commit `28dc1c7`; ela tem ainda o teste `testes_entrada_automatica.py` e mudanças no cadastro/login que **não foram executadas nesta máquina**, pois o download da branch remota não estava disponível para execução.
- A base local passou em **13 testes**, 0 falhas e 0 ausentes. A branch atual lista **14 testes**: executar `python executar_testes.py` no checkout atualizado para validação definitiva.
- O arquivo `gerar_evidencias.py` foi criado para usar as APIs de `Cliente`, `Servidor`, `contas` e `identidades` presentes tanto na base local quanto no commit remoto inspecionado.

## Rodada automática: três participantes e rastreabilidade real
1. Na pasta raiz de um checkout atualizado, copie `gerar_evidencias.py`.
2. Execute `python gerar_evidencias.py --modo didatico --saida evidencias`.
3. Execute `python gerar_evidencias.py --modo seguro --saida evidencias`.
4. Verifique em `evidencias/didatico/` e `evidencias/seguro/`: `log_alice.log`, `log_bob.log`, `captura_servidor.jsonl`, `trilha_correlacionada.json`, `resumo.json`.
5. Use o campo `sessao` do resumo para buscar o mesmo ID nas mensagens relay `dh_inicio`, `dh_resposta`, `confirmacao`, `cifra` e `ack`; identifique as chaves públicas em `chave_publica_hex` e os ciphertexts em `cifrado_hex`.
6. Essas execuções usam contas **efêmeras** em pasta temporária e não alteram usuários, credenciais ou dados locais existentes. Utilizam fator PBKDF2 reduzido pelo ambiente **somente para evidências didáticas**, nunca para uma implantação real.

## Provas que devem ser mostradas ao vivo
- **DH manual:** `python auditoria_dh.py` — exemplo p=23, g=5, a=6, b=15. A=8, B=19, segredo=2; passos completos do square-and-multiply.
- **DH com números grandes:** `python auditoria_dh.py --grupo seguro` — parâmetros 2048 bits e exemplo determinístico. Avisar que NÃO são as chaves de uma conversa real.
- **RC4 manual:** `python demonstracao_didatica.py` — KSA 256 iterações, PRGA/XOR e vetor `Key`/`Plaintext` => `BBF316E8D940AF0AD3`, com drop=0 só para comparar vetor conhecido; conversa real usa drop=3072.
- **Sessão real:** `python gerar_evidencias.py --modo didatico` — chaves efêmeras negociadas automaticamente, envio/recebimento Alice/Bob, servidor vê JSON de relay com ciphertext e metadados, ACKs autenticados.
- **Sessão 2048 bits:** `python gerar_evidencias.py --modo seguro` — a comunicação real mantém os valores secretos ocultos dos logs.
- **Integridade:** `python testes_etapa3.py` — HMAC inválido e replay são rejeitados; confirmação ACK.
- **Regressão:** `python executar_testes.py` — exibir total final do checkout usado no vídeo.

## Ordem sugerida de apresentação (até 30 min)
| Bloco | Tempo | Apresentação |
| --- | --- | --- |
| Escopo e arquitetura cliente–relay–cliente | 0:00–2:30 | Diagrama e arquivos `cliente.py`, `servidor.py` |
| DH manual, números públicos/privados, square-and-multiply | 2:30–8:30 | `auditoria_dh.py` e logs |
| Negociação automática autenticação PSK e transcrição | 8:30–12:30 | logs correlacionados de Alice e Bob e troca relay |
| HKDF, RC4 KSA/PRGA/XOR e evidência manual | 12:30–17:30 | `demonstracao_didatica.py`, `rc4.py` |
| Tráfego real, integridade, replay, ACK | 17:30–22:30 | `trilha_correlacionada.json`, testes etapa 3 |
| Interface web, login didático, presença e grupos | 22:30–26:30 | abrir dois clientes, enviar mensagens |
| 2048 bits, limitações e conclusão | 26:30–28:30 | evidência modo seguro e execução testes |

## Cuidados nas falas
- A conversa **estabelece DH e deriva chaves automaticamente após a configuração inicial** das identidades. A confiança inicial entre pares depende de PSK provisionada separadamente.
- A auditoria com expoentes fixos **não representa** a mesma sessão dinâmica capturada pelo relay. São provas complementares.
- O modo didático com p=23 permite recuperar o segredo facilmente; somente exemplifica a matemática, não segurança real.
- O servidor encaminha metadados e envelopes cifrados; é correto dizer que não obtém o plaintext pelo fluxo normal, mas não que não vê metadados.
- A captura salva é uma serialização de envelope JSON em hex, **não** um PCAP bruto ou bytes TCP exatos.
- O modo de entrada automática deixa de exigir senha na página local. É uma conveniência da demonstração, não uma autenticação forte diante de outros usuários com acesso à interface.
- O PBKDF2 manual em Python puro tem limitação de desempenho e os testes usam poucas iterações em ambiente efêmero.
- Não expor `identidades/*.json`, contas reais, segredos de sessão no modo 2048, nem usar o sistema para dados sensíveis.

## Checklist final antes de gravar
- [ ] Usar o checkout do último commit remoto e rodar novamente a suíte completa.
- [ ] Salvar a saída da suíte real mais recente com data e commit.
- [ ] Confirmar os cinco tipos de pacotes `dh_inicio`, `dh_resposta`, `confirmacao`, `cifra`, `ack` com mesmo ID.
- [ ] Confirmar dois textos recebidos e os ACKs dos dois lados.
- [ ] Abrir os logs e mostrar que os valores públicos e os IDs coincidem com a captura.
- [ ] Registrar a execução dos modos didático e seguro.
- [ ] Mostrar testes de adulteração/replay rejeitados.
- [ ] Gravar vídeo com menos de 30 minutos e participação dos integrantes.
