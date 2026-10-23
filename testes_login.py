"""Testes de autenticação no servidor e login web (sem dados reais)."""
import socket, tempfile, threading, time
from pathlib import Path
from fastapi.testclient import TestClient
from servidor import Servidor
from cliente import Cliente
from protocolo import enviar, receber
from identidades import provisionar_par
from web_app import PonteWeb,criar_app
from contas import cadastrar

def esperar(cond, t=8):
    fim=time.monotonic()+t
    while time.monotonic()<fim:
        if cond(): return True
        time.sleep(.03)
    return False

def rodar():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);db=root/'contas.json'; ids=root/'identidades'
        cadastrar('Alice','aliceSenhaForte123',db)
        cadastrar('Bob','bobSenhaForte123',db)
        provisionar_par('Alice','Bob',ids)
        servidor=Servidor(porta=0,caminho_contas=db)
        threading.Thread(target=servidor.iniciar,daemon=True).start()
        assert esperar(lambda:servidor.sock is not None and servidor.porta>0)
        try:
            with socket.create_connection(('127.0.0.1',servidor.porta)) as sock:
                enviar(sock,{'tipo':'registro','nome':'Intruso'})
                assert receber(sock)['tipo']=='erro'
            with socket.create_connection(('127.0.0.1',servidor.porta)) as sock:
                enviar(sock,{'tipo':'registro','nome':'Alice'})
                assert receber(sock)['tipo']=='desafio_login'
                enviar(sock,{'tipo':'grupo_criar','grupo':'Fraude'})
                assert receber(sock)['tipo']=='erro'
            assert not servidor.clientes and 'Fraude' not in servidor.grupos
            ponte=PonteWeb('Alice','didatico','127.0.0.1',servidor.porta,ids/'Alice.json')
            bob=Cliente('Bob','didatico',str(root/'logs'),ids/'Bob.json')
            bob.conectar(porta=servidor.porta,senha='bobSenhaForte123')
            try:
                with TestClient(criar_app(ponte)) as web:
                    assert web.get('/api/estado').status_code==401
                    assert web.get('/api/eventos').status_code==401
                    assert web.post('/api/mensagem',json={'para':'Bob','texto':'Teste'}).status_code==401
                    assert web.post('/api/login',json={'usuario':'Alice','senha':'errada'}).status_code==401
                    assert 'Alice' not in servidor.clientes
                    login=web.post('/api/login',json={'usuario':'Alice','senha':'aliceSenhaForte123'})
                    assert login.status_code==200,login.text
                    assert esperar(lambda:'Alice' in servidor.clientes)
                    assert web.get('/api/estado').json()['usuario']=='Alice'
                    envio=web.post('/api/mensagem',json={'para':'Bob','texto':'Login funcional'})
                    assert envio.status_code==200,envio.text
                    assert esperar(lambda:('Alice','Login funcional') in bob.recebidas,12)
                    assert web.post('/api/grupos',json={'grupo':'Equipe'}).status_code==200
                    assert esperar(lambda:'Equipe' in servidor.grupos)
                    assert servidor.grupos['Equipe']['criador']=='Alice'
                    assert web.post('/api/logout').status_code==200
                    assert web.get('/api/estado').status_code==401
                    assert esperar(lambda:'Alice' not in servidor.clientes)
                    print('OK: login web, bloqueio anônimo, usuário autenticado e permissões de grupos')
            finally: bob.fechar()
        finally: servidor.sock.close()
if __name__=='__main__': rodar()
