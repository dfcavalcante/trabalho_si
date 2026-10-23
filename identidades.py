"""Credenciais simétricas previamente distribuídas por canal confiável.

Não substitui assinaturas digitais: cada par de usuários conhece um segredo próprio.
"""
import hashlib
import hmac
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


def prova(chave, transcricao, papel):
    from integridade import serializar
    return hmac.new(chave,b'chat-si-identidade-v1|'+papel.encode()+b'|'+serializar(transcricao),hashlib.sha256).hexdigest()


def conferir(chave, transcricao, papel, valor):
    return isinstance(valor,str) and hmac.compare_digest(prova(chave,transcricao,papel),valor)
