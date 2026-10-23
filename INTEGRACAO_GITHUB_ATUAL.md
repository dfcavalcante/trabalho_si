# Integração com a branch main atual

Este pacote reúne o código da versão consolidada local e as evidências capturadas.
**Não é um clone exato da branch main em 28dc1c7.** A branch atual contém ajustes posteriores de entrada automática, principalmente em `web_app.py`, `contas.py`, `identidades.py`, `preparar_demo.py` e `README.md`.

Para manter o login automático e o cadastro pelo terminal como decidido, **não sobrescreva esses arquivos do GitHub com a cópia presente neste ZIP**.

Integração correta: mantenha seu checkout atualizado e copie para a raiz apenas `gerar_evidencias.py` e `GUIA_APRESENTACAO_E_EVIDENCIAS.md`. A pasta `evidencias/` contém resultados capturados anteriormente com a base consolidada local: execute novamente `python gerar_evidencias.py --modo didatico`, `python gerar_evidencias.py --modo seguro` e `python executar_testes.py` no checkout atualizado antes de afirmar que estas evidências correspondem à main.

Segredos: não versione `identidades/`, `dados_servidor/` nem arquivos de configuração gerados com senhas.
