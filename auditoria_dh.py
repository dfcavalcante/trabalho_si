"""Demonstração determinística sem dados privados de conversas reais."""
import argparse
from pathlib import Path
import dh
import kdf
from log import Log, completo
from integridade import transcricao

def executar(grupo='didatico',pasta='logs'):
    params=dh.DIDATICO if grupo=='didatico' else dh.SEGURO
    p,g=params['p'],params['g']
    a,b=(6,15) if grupo=='didatico' else (123456789123456789,987654321987654321)
    log=Log('auditoria-'+grupo,pasta=pasta,didatico=True)
    try:
        log.passo('AVISO','chaves fixas, publicamente conhecidas e inadequadas para mensagens reais')
        log.passo('PARAM',f'p={completo(p)}, g={g}')
        log.passo('PRIV',f'Alice a={completo(a)}, Bob b={completo(b)}')
        A=dh.exp_mod(g,a,p,log,'DH-POW',tela=(grupo=='didatico'),completo=True)
        B=dh.exp_mod(g,b,p,log,'DH-POW',tela=(grupo=='didatico'),completo=True)
        log.passo('ENVIO',f'A={completo(A)}, B={completo(B)}')
        sa=dh.exp_mod(B,a,p,log,'SEGREDO',tela=(grupo=='didatico'),completo=True)
        sb=dh.exp_mod(A,b,p,log,'SEGREDO',tela=(grupo=='didatico'),completo=True)
        assert sa==sb
        log.passo('SEGREDO',f'igualdade conferida: s={completo(sa)}')
        ctx=kdf.contexto_sessao(transcricao('0'*24,grupo,'Alice','Bob',A,B))
        ch=kdf.derivar(sa,p,log,ctx)+kdf.derivar_autenticacao(sa,p,ctx)
        for i,k in enumerate(ch):log.passo('DERIVA',f'chave de demonstração {i}={k.hex()}')
        return {'A':A,'B':B,'s':sa,'a':a,'b':b,'log':log.caminho,'chaves':ch}
    finally: log.fechar()
if __name__=='__main__':
    arg=argparse.ArgumentParser();arg.add_argument('--grupo',choices=('didatico','seguro'),default='didatico');a=arg.parse_args();executar(a.grupo)
