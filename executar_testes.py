"""Executa suites em processos separados, com resumo e codigo de saida confiavel."""
import os
import subprocess
import sys
from pathlib import Path

TESTES = [
    'testes_primitivas_manuais.py', 'testes.py', 'testes_etapa1.py', 'testes_etapa4.py',
    'testes_login.py', 'testes_cliente_servidor.py',
    'testes_etapa3.py', 'testes_grupos.py',
    'testes_presenca.py', 'testes_web.py',
    'testes_sessao.py', 'testes_auditoria_dh.py',
    'testes_demonstracao.py'
]

def main():
    raiz=Path(__file__).resolve().parent
    aprovados=[]; falhas=[]; ausentes=[]
    for nome in TESTES:
        arquivo=raiz/nome
        if not arquivo.is_file():
            ausentes.append(nome)
            print(f'[AUSENTE] {nome}',flush=True)
            continue
        print(f'\n[EXECUTANDO] {nome}', flush=True)
        try:
            env=os.environ.copy()
            # Testes usam fator reduzido explicitamente; NÃO muda a compatibilidade do protocolo.
            env['RC4_CHAT_PBKDF2_ITERACOES']='100'
            r=subprocess.run([sys.executable,str(arquivo)],cwd=raiz,timeout=100,env=env)
            (aprovados if r.returncode==0 else falhas).append(nome)
            print(f'[{"OK" if r.returncode==0 else "FALHOU"}] {nome} (exit={r.returncode})', flush=True)
        except subprocess.TimeoutExpired:
            falhas.append(nome)
            print(f'[TIMEOUT] {nome}',flush=True)
    print(f'\nRESULTADO: {len(aprovados)} aprovadas, {len(falhas)} falhas, {len(ausentes)} ausentes')
    if falhas: print('FALHAS:',', '.join(falhas))
    if ausentes: print('AUSENTES:',', '.join(ausentes))
    return 1 if falhas or ausentes else 0

if __name__=='__main__': sys.exit(main())
