"""Configuração acadêmica inicial, sem substituir credenciais já cadastradas."""
import argparse
from pathlib import Path
from contas import carregar, cadastrar, ler_senha
from identidades import provisionar_par, carregar as carregar_ids

def main():
    cli = argparse.ArgumentParser(description='Preparar contas e pares para demonstração local')
    cli.add_argument('usuarios', nargs='*', default=['Alice','Bob','Carlos'])
    args = cli.parse_args()
    usuarios = args.usuarios or ['Alice','Bob','Carlos']
    if len(set(usuarios)) != len(usuarios):
        raise SystemExit('Nomes de usuário duplicados')
    contas = carregar()
    for u in usuarios:
        if u not in contas:
            senha=ler_senha(f'Senha de {u} (mínimo 10 caracteres): ',nova=True)
            cadastrar(u,senha)
            print('[CONTA CRIADA]',u)
        else:
            print('[CONTA PRESERVADA]',u)
    pasta=Path('identidades')
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
if __name__=='__main__': main()
