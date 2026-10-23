"""Entrada automática na web: senha gerada no arquivo do usuário, sem tela de login."""
import tempfile, threading, time
from pathlib import Path
from fastapi.testclient import TestClient
from servidor import Servidor
from cliente import Cliente
from identidades import provisionar_par, guardar_senha_login, senha_login
from web_app import PonteWeb, criar_app
from contas import cadastrar

def esperar(cond, t=10):
    fim=time.monotonic()+t
    while time.monotonic()<fim:
        if cond(): return True
        time.sleep(.03)
    return False

def rodar():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp); db=root/'contas.json'; ids=root/'identidades'
        provisionar_par('Alice','Bob',ids)
        assert senha_login('Alice',ids/'Alice.json') is None
        cadastrar('Alice','senhaGeradaAlice123',db,iteracoes=50)
        guardar_senha_login('Alice','senhaGeradaAlice123',ids)
        assert senha_login('Alice',ids/'Alice.json')=='senhaGeradaAlice123'
        assert 'Bob' in __import__('identidades').carregar('Alice',ids/'Alice.json'), 'senha apagou as chaves de par'
        cadastrar('Bob','bobSenhaForte123',db)
        servidor=Servidor(porta=0,caminho_contas=db)
        threading.Thread(target=servidor.iniciar,daemon=True).start()
        assert esperar(lambda:servidor.sock is not None and servidor.porta>0)
        ponte=PonteWeb('Alice','didatico','127.0.0.1',servidor.porta,ids/'Alice.json',
                       senha_auto=senha_login('Alice',ids/'Alice.json'))
        threading.Thread(target=ponte.manter_conectado,args=(0.2,),daemon=True).start()
        bob=Cliente('Bob','didatico',str(root/'logs'),ids/'Bob.json')
        bob.conectar(porta=servidor.porta,senha='bobSenhaForte123')
        try:
            assert esperar(lambda:'Alice' in servidor.clientes), 'não conectou sozinho'
            with TestClient(criar_app(ponte)) as web:
                # Página vinda do cache com cookie de uma execução anterior: renova, sem tela de login.
                web.cookies.set('rc4_session','token-antigo')
                velho=web.get('/api/estado')
                assert velho.status_code==200 and 'rc4_session' in velho.cookies, velho.text
                pagina=web.get('/')  # abrir a página já autentica o navegador
                assert pagina.status_code==200 and pagina.headers['cache-control']=='no-store'
                estado=web.get('/api/estado')
                assert estado.status_code==200 and estado.json()['usuario']=='Alice'
                envio=web.post('/api/mensagem',json={'para':'Bob','texto':'Entrei sem senha'})
                assert envio.status_code==200,envio.text
                assert esperar(lambda:('Alice','Entrei sem senha') in bob.recebidas,12)
                assert web.post('/api/logout').status_code==200
                assert esperar(lambda:'Alice' not in servidor.clientes)
                time.sleep(1)
                assert 'Alice' not in servidor.clientes, 'reconectou depois do logout'
                assert web.post('/api/mensagem',json={'para':'Bob','texto':'x'}).status_code==401
                assert web.get('/api/estado').status_code==401, 'logout não pediu login de novo'
                assert web.get('/').status_code==200  # reabrir a página volta a entrar
                assert esperar(lambda:'Alice' in servidor.clientes), 'não voltou ao reabrir a página'
                assert web.get('/api/estado').status_code==200
            print('OK: entrada automática, página sem login, logout respeitado e reentrada ao reabrir')
        finally:
            bob.fechar()
            if ponte.cliente: ponte.cliente.fechar()
            servidor.sock.close()

if __name__=='__main__': rodar()
