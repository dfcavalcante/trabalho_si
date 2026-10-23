"""Cadastro local de contas do SERVIDOR. Senhas não são salvas em claro.
O HMAC de desafio comprova conhecimento da senha sem transmiti-la no TCP.
Não substitui TLS/PAKE em produção; protege cenário acadêmico local.
"""
import argparse
import getpass
from primitivas_manuais import pbkdf2_sha256, hmac_sha256, compare_digest
import json
import os
from pathlib import Path
import re
import secrets
import sys

# Python puro: custo elevado; manter configurável e documentar limite acadêmico.
ITERACOES=int(os.environ.get('RC4_CHAT_PBKDF2_ITERACOES','12000'))
PADRAO=Path(__file__).resolve().parent/'dados_servidor'/'contas.json'

def carregar(caminho=PADRAO):
    path=Path(caminho)
    return json.loads(path.read_text('utf-8')) if path.exists() else {}

def cadastrar(nome,senha,caminho=PADRAO):
    if not re.fullmatch(r'[A-Za-z0-9]{1,24}',nome): raise ValueError('nome inválido')
    if len(senha)<10: raise ValueError('a senha deve ter pelo menos 10 caracteres')
    caminho=Path(caminho)
    base=carregar(caminho)
    if nome in base: raise ValueError('usuário já cadastrado')
    sal=secrets.token_bytes(16)
    verificador=pbkdf2_sha256(senha.encode(),sal,ITERACOES)
    base[nome]={'sal':sal.hex(),'iteracoes':ITERACOES,'verificador':verificador.hex()}
    caminho.parent.mkdir(parents=True,exist_ok=True)
    tmp=caminho.with_suffix('.tmp')
    with tmp.open('w',encoding='utf-8') as f: json.dump(base,f,indent=2)
    os.replace(tmp,caminho)
    if os.name!='nt': caminho.chmod(0o600)

def prova(senha,nome,sal,iteracoes,desafio):
    v=pbkdf2_sha256(senha.encode(),bytes.fromhex(sal),iteracoes)
    return hmac_sha256(v,b'RC4-CHAT-LOGIN-v1|'+nome.encode()+b'|'+bytes.fromhex(desafio)).hex()

def verificar(registro,nome,desafio,assinatura):
    esperado=hmac_sha256(bytes.fromhex(registro['verificador']),b'RC4-CHAT-LOGIN-v1|'+nome.encode()+b'|'+bytes.fromhex(desafio)).hex()
    return isinstance(assinatura,str) and compare_digest(esperado,assinatura)

def ler_senha(rotulo, nova=False):
    """Lê a senha sem eco num terminal de verdade; senão (Git Bash, console de IDE), com eco.

    nova=True pede confirmação e repete até ter pelo menos 10 caracteres.
    """
    if sys.stdin.isatty():
        print('(a senha não aparece enquanto você digita: digite e tecle Enter)', flush=True)
        ler=getpass.getpass
    else:
        print('[AVISO] este terminal não permite ocultar a senha; ela vai aparecer na tela.', flush=True)
        ler=input
    while True:
        senha=ler(rotulo)
        if not nova: return senha
        if len(senha)<10:
            print('A senha deve ter pelo menos 10 caracteres. Tente de novo.', flush=True)
        elif ler('Repetir senha: ')!=senha:
            print('As senhas não conferem. Tente de novo.', flush=True)
        else:
            return senha

def main():
    parser=argparse.ArgumentParser(description='Criar contas autorizadas no servidor RC4 Chat')
    parser.add_argument('nome'); args=parser.parse_args()
    senha=ler_senha('Senha para '+args.nome+' (min 10 caracteres): ',nova=True)
    cadastrar(args.nome,senha)
    print('Conta cadastrada no servidor:',args.nome)
if __name__=='__main__': main()
