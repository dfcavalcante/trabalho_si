"""Configuração acadêmica inicial, sem substituir credenciais já cadastradas.

Por padrão gera a senha de cada conta e a guarda em identidades/<usuário>.json,
para a interface web entrar sozinha. Use --perguntar-senha para digitá-las.
"""
import argparse
import secrets
from pathlib import Path
import contas
from contas import carregar, cadastrar, ler_senha
from identidades import provisionar_par, carregar as carregar_ids, senha_login, guardar_senha_login

# Senha gerada tem 144 bits aleatórios: o PBKDF2 não precisa compensar senha fraca,
# então um custo menor evita esperas de vários segundos no PBKDF2 em Python puro.
ITERACOES_SENHA_GERADA=min(1000,contas.ITERACOES)

def main():
    cli = argparse.ArgumentParser(description='Preparar contas e pares para demonstração local')
    cli.add_argument('usuarios', nargs='*', default=['Alice','Bob','Carlos'])
    cli.add_argument('--perguntar-senha', action='store_true', help='digitar as senhas em vez de gerá-las (login manual na web)')
    args = cli.parse_args()
    usuarios = args.usuarios or ['Alice','Bob','Carlos']
    if len(set(usuarios)) != len(usuarios):
        raise SystemExit('Nomes de usuário duplicados')
    pasta=Path('identidades')
    contas_existentes = carregar()
    for u in usuarios:
        if u in contas_existentes:
            print('[CONTA PRESERVADA]',u)
            if not senha_login(u,pasta/f'{u}.json'):
                print(f'  [AVISO] {u} não tem senha salva: o login na web será manual. Para entrar direto,'
                      ' apague dados_servidor/contas.json e a pasta identidades/ e rode de novo.')
        elif args.perguntar_senha:
            cadastrar(u,ler_senha(f'Senha de {u} (mínimo 10 caracteres): ',nova=True))
            print('[CONTA CRIADA]',u)
        else:
            senha=secrets.token_urlsafe(18)
            cadastrar(u,senha,iteracoes=ITERACOES_SENHA_GERADA)
            guardar_senha_login(u,senha,pasta)
            print('[CONTA CRIADA]',u,'(senha gerada; a interface web entra sozinha)')
    for i,a in enumerate(usuarios):
        for b in usuarios[i+1:]:
            a_ids = carregar_ids(a,pasta/f'{a}.json') if (pasta/f'{a}.json').exists() else {}
            b_ids = carregar_ids(b,pasta/f'{b}.json') if (pasta/f'{b}.json').exists() else {}
            if b in a_ids and a in b_ids:
                if a_ids[b]!=b_ids[a]:
                    raise SystemExit(f'ERRO: credenciais inconsistentes do par {a}/{b}')
                print('[PAR PRESERVADO]', a, b)
            elif b not in a_ids and a not in b_ids:
                provisionar_par(a,b,pasta)
                print('[PAR CRIADO]', a,b)
            else:
                raise SystemExit(f'ERRO: credencial parcial do par {a}/{b}; corrigir sem sobrescrever automaticamente')
    print('Concluído. Distribua cada arquivo de identidade apenas ao seu titular.')
    print('\nPróximos passos, cada um em um terminal:')
    print('  python servidor.py --host 127.0.0.1 --porta 5000')
    for n,u in enumerate(usuarios):
        print(f'  python web_app.py --usuario {u} --porta {8001+n}')
if __name__=='__main__': main()
