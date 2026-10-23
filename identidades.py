"""Credenciais simétricas previamente distribuídas por canal confiável.

Não substitui assinaturas digitais: cada par de usuários conhece um segredo próprio.
"""
from primitivas_manuais import hmac_sha256, compare_digest
import json
import os
import secrets
from pathlib import Path


def arquivo_padrao(nome):
    return Path('identidades') / (nome + '.json')


def carregar(nome, caminho=None):
    caminho = Path(caminho) if caminho else arquivo_padrao(nome)
    if not caminho.is_file():
        raise ValueError(f'credenciais ausentes: {caminho}; provisionar antes da primeira conversa')
    dados=json.loads(caminho.read_text(encoding='utf-8'))
    if dados.get('usuario') != nome or not isinstance(dados.get('pares'),dict):
        raise ValueError('arquivo de identidade inválido')
    resultado={}
    for par, valor in dados['pares'].items():
        if not isinstance(par,str) or par==nome or not isinstance(valor,str) or len(valor)!=64:
            raise ValueError('identidade de par inválida')
        try: chave=bytes.fromhex(valor)
        except ValueError as exc: raise ValueError('chave inválida') from exc
        resultado[par]=chave
    return resultado


def provisionar_par(a,b,pasta='identidades'):
    """Executar em ambiente confiável e distribuir separadamente os arquivos gerados."""
    if a==b or not all(x.isalnum() and 1<=len(x)<=24 for x in (a,b)):
        raise ValueError('nomes inválidos')
    pasta=Path(pasta)
    pasta.mkdir(parents=True,exist_ok=True)
    chave=secrets.token_bytes(32).hex()
    for nome,outro in ((a,b),(b,a)):
        arq=pasta/(nome+'.json')
        if arq.exists():
            dados=json.loads(arq.read_text(encoding='utf-8'))
            if dados.get('usuario')!=nome: raise ValueError('identidade inválida')
        else: dados={'usuario':nome,'pares':{}}
        if outro in dados['pares']:
            raise ValueError('par já possui credencial; não sobrescrever sem coordenação')
        dados['pares'][outro]=chave
        arq.write_text(json.dumps(dados,indent=2),encoding='utf-8')
        try: os.chmod(arq,0o600)
        except OSError: pass
    return (pasta/(a+'.json'),pasta/(b+'.json'))


def senha_login(nome, caminho=None):
    """Senha de login gerada pelo preparar_demo.py, se houver (entrada automática na web)."""
    caminho = Path(caminho) if caminho else arquivo_padrao(nome)
    if not caminho.is_file():
        return None
    senha = json.loads(caminho.read_text(encoding='utf-8')).get('senha_login')
    return senha if isinstance(senha, str) and senha else None


def guardar_senha_login(nome, senha, pasta='identidades'):
    """Grava a senha de login no arquivo do próprio usuário (secreto, fora do Git)."""
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    arq = pasta/(nome+'.json')
    dados = json.loads(arq.read_text(encoding='utf-8')) if arq.exists() else {'usuario':nome,'pares':{}}
    if dados.get('usuario') != nome: raise ValueError('identidade inválida')
    dados['senha_login'] = senha
    arq.write_text(json.dumps(dados,indent=2),encoding='utf-8')
    try: os.chmod(arq,0o600)
    except OSError: pass


def prova(chave, transcricao, papel):
    from integridade import serializar
    return hmac_sha256(chave,b'chat-si-identidade-v1|'+papel.encode()+b'|'+serializar(transcricao)).hex()


def conferir(chave, transcricao, papel, valor):
    return isinstance(valor,str) and compare_digest(prova(chave,transcricao,papel),valor)
