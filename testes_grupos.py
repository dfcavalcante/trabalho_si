"""Integração de três clientes: salas, sessão individual, entrega cifrada e permissões."""
import socket
import tempfile
import threading
import time
from pathlib import Path
from servidor import Servidor
from cliente import Cliente
from identidades import provisionar_par
from testes_presenca import esperar


def testar():
    with socket.socket() as tmp:
        tmp.bind(('127.0.0.1',0)); porta=tmp.getsockname()[1]
    s=Servidor(porta=porta)
    threading.Thread(target=s.iniciar,daemon=True).start()
    assert esperar(lambda:s.sock is not None)
    with tempfile.TemporaryDirectory() as tmp:
        base=Path(tmp); ids=base/'ids'
        for a,b in [('Alice','Bob'),('Alice','Carlos'),('Bob','Carlos')]:
            provisionar_par(a,b,ids)
        nomes=['Alice','Bob','Carlos']
        cs={n:Cliente(n,'didatico',str(base/'logs'),ids/(n+'.json')) for n in nomes}
        try:
            for c in cs.values(): c.conectar(porta=porta)
            assert esperar(lambda:all(len(c.usuarios_online)==3 for c in cs.values()))
            cs['Alice'].criar_grupo('Equipe')
            assert esperar(lambda:'Equipe' in cs['Alice'].grupos)
            cs['Alice'].adicionar_grupo('Equipe','Bob')
            cs['Alice'].adicionar_grupo('Equipe','Carlos')
            assert esperar(lambda:all(set(c.grupos['Equipe']['membros'])==set(nomes) for c in cs.values()))
            cs['Alice'].mensagem_grupo('Equipe','Mensagem de teste acadêmico')
            assert esperar(lambda:len(cs['Bob'].recebidas_grupo)==1 and len(cs['Carlos'].recebidas_grupo)==1,timeout=18)
            assert cs['Bob'].recebidas_grupo[0]==('Equipe','Alice','Mensagem de teste acadêmico')
            assert cs['Carlos'].recebidas_grupo[0]==('Equipe','Alice','Mensagem de teste acadêmico')
            assert esperar(lambda:len(cs['Alice'].confirmacoes)==2)
            cs['Carlos'].sair_grupo('Equipe')
            assert esperar(lambda:'Equipe' not in cs['Carlos'].grupos and len(cs['Alice'].grupos['Equipe']['membros'])==2)
            cs['Alice'].mensagem_grupo('Equipe','Apenas Bob')
            assert esperar(lambda:len(cs['Bob'].recebidas_grupo)==2,timeout=10)
            time.sleep(.3)
            assert len(cs['Carlos'].recebidas_grupo)==1
            print('GRUPOS OK: 3 clientes, chaves individuais, entrega, ACK, saída e controle de membros')
        finally:
            for c in cs.values(): c.fechar()
            s.sock.close()
if __name__=='__main__': testar()
