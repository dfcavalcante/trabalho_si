"""Testa entrada, saída e detecção de cliente que deixa de responder ao heartbeat."""
import socket
import tempfile
import threading
import time
from pathlib import Path
from servidor import Servidor
from cliente import Cliente
from identidades import provisionar_par
from protocolo import enviar, receber


def esperar(cond, timeout=8):
    fim = time.monotonic() + timeout
    while time.monotonic() < fim:
        if cond(): return True
        time.sleep(.05)
    return False


def testar():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        porta = s.getsockname()[1]
    srv = Servidor(porta=porta)
    srv.heartbeat_interval=.2
    srv.heartbeat_timeout=.9
    threading.Thread(target=srv.iniciar, daemon=True).start()
    assert esperar(lambda: srv.sock is not None)
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        provisionar_par('Alice','Bob',root/'identidades')
        alice=Cliente('Alice', 'didatico', str(root/'logs'), root/'identidades'/'Alice.json')
        bob=Cliente('Bob','didatico',str(root/'logs'),root/'identidades'/'Bob.json')
        try:
            alice.conectar(porta=porta)
            assert esperar(lambda: 'Alice' in alice.usuarios_online)
            bob.conectar(porta=porta)
            assert esperar(lambda: 'Bob' in alice.usuarios_online and 'Alice' in bob.usuarios_online), 'entrada não publicada'
            bob.fechar()
            assert esperar(lambda: 'Bob' not in alice.usuarios_online), 'saída não publicada'
            # Cliente silencioso: registro manual sem thread de escuta, ignora ping.
            intruso=socket.create_connection(('127.0.0.1', porta))
            enviar(intruso, {'tipo':'registro','nome':'Silencioso'})
            assert receber(intruso)['tipo']=='registrado'
            assert esperar(lambda: 'Silencioso' in alice.usuarios_online), 'silencioso não entrou'
            assert esperar(lambda: 'Silencioso' not in alice.usuarios_online,timeout=5), 'timeout não removeu cliente silencioso'
            intruso.close()
            assert alice.ativo, 'alice desconectada indevidamente'
            print('PRESENÇA OK: entrada, saída, heartbeat, timeout e cliente responsivo')
        finally:
            bob.fechar();alice.fechar();srv.sock.close()

if __name__=='__main__': testar()
