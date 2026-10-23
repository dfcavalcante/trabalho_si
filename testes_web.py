"""Teste da API WEB local e integração com servidor real."""
import socket
import tempfile
import threading
import time
from pathlib import Path
from fastapi.testclient import TestClient
from servidor import Servidor
from cliente import Cliente
from identidades import provisionar_par
from contas import cadastrar
from web_app import PonteWeb, criar_app


def aguardar(fn, timeout=12):
    fim=time.monotonic()+timeout
    while time.monotonic()<fim:
        if fn(): return True
        time.sleep(.03)
    return False


def testar():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); porta=s.getsockname()[1]
    with tempfile.TemporaryDirectory() as tmp:
        pasta=Path(tmp)
        db=pasta/'contas.json'
        cadastrar('Alice','aliceSenhaForte123',db)
        cadastrar('Bob','bobSenhaForte123',db)
        servidor=Servidor(porta=porta,caminho_contas=db)
        threading.Thread(target=servidor.iniciar,daemon=True).start()
        assert aguardar(lambda: servidor.sock is not None)
        provisionar_par('Alice','Bob',pasta/'identidades')
        ponte=PonteWeb('Alice','didatico','127.0.0.1',porta,pasta/'identidades'/'Alice.json')
        bob=Cliente('Bob','didatico',str(pasta/'logs'),pasta/'identidades'/'Bob.json')
        try:
            bob.conectar(porta=porta,senha='bobSenhaForte123')
            with TestClient(criar_app(ponte)) as web:
                assert web.get('/').status_code==200
                assert web.post('/api/mensagem',json={'para':'Bob','texto':'sem login'}).status_code==401
                assert web.get('/api/estado').status_code==401
                login=web.post('/api/login',json={'usuario':'Alice','senha':'aliceSenhaForte123'})
                assert login.status_code==200, login.text
                assert web.get('/api/estado').json()['usuario']=='Alice'
                assert web.post('/api/usuarios',).status_code==200
                assert aguardar(lambda: 'Bob' in ponte.cliente.usuarios_online)
                envio=web.post('/api/mensagem',json={'para':'Bob','texto':'Olá via interface!'},)
                assert envio.status_code==200,envio.text
                assert aguardar(lambda: ('Alice','Olá via interface!') in bob.recebidas)
                assert aguardar(lambda: len(ponte.cliente.confirmacoes)>0)
                eventos=web.get('/api/eventos').json()
                assert any(e['tipo']=='saida' for e in eventos)
                assert any(e['tipo']=='ack' for e in eventos)
                assert any(e['tipo']=='auditoria' and 'DH-' in e['linha'] for e in eventos)
                print('WEB OK: HTML, listagem, envio cifrado, ACK e logs auditáveis')
        finally:
            bob.fechar()
            servidor.sock.close()
if __name__=='__main__': testar()
