"""Teste de segurança da autenticação automática por segredo de par."""
import json
import tempfile
from pathlib import Path
from identidades import carregar, provisionar_par, prova, conferir
from integridade import transcricao

def executar():
    with tempfile.TemporaryDirectory() as d:
        pasta=Path(d)
        try: carregar('Alice',pasta/'ausente.json')
        except ValueError: pass
        else: raise AssertionError('aceitou identidade ausente')
        a,b=provisionar_par('Alice','Bob',pasta)
        ka=carregar('Alice',a)['Bob']
        kb=carregar('Bob',b)['Alice']
        assert ka==kb and len(ka)==32
        trans=transcricao('a'*24,'didatico','Alice','Bob',8,19)
        tag=prova(ka,trans,'respondente')
        assert conferir(kb,trans,'respondente',tag)
        assert not conferir(kb,trans,'iniciador',tag)
        t2=dict(trans,pub_respondente='18')
        assert not conferir(kb,t2,'respondente',tag)
        assert not conferir(bytes(32),trans,'respondente',tag)
        try: provisionar_par('Alice','Bob',pasta)
        except ValueError: pass
        else: raise AssertionError('sobrescreveu credencial confiável')
    print('OK: provisionamento, confirmação da identidade, adulteração e ausência de credencial')

if __name__=='__main__': executar()
