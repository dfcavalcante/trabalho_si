"""Teste de ponta a ponta: relay sem chaves privadas e chat entre clientes."""
import socket
import threading
import time
import tempfile
from servidor import Servidor
from cliente import Cliente
from identidades import provisionar_par


def aguardar(condicao, segundos=8):
    fim=time.monotonic()+segundos
    while time.monotonic()<fim:
        if condicao(): return True
        time.sleep(.025)
    return False


def rodar(modo):
    server=Servidor('127.0.0.1',0)
    # Reservar socket inicialmente para receber a porta escolhida pelo SO.
    # iniciar() fará bind na porta que reservamos e liberamos.
    temp=socket.socket()
    temp.bind(('127.0.0.1',0))
    porta=temp.getsockname()[1]
    temp.close()
    server.porta=porta
    thread=threading.Thread(target=server.iniciar,daemon=True)
    thread.start()
    assert aguardar(lambda: server.sock is not None)
    with tempfile.TemporaryDirectory() as logs:
        from pathlib import Path
        ids=Path(logs)/'ids'
        provisionar_par('Alice','Bob',ids)
        alice=Cliente('Alice',modo,logs,ids/'Alice.json')
        bob=Cliente('Bob',modo,logs,ids/'Bob.json')
        try:
            alice.conectar('127.0.0.1',porta)
            bob.conectar('127.0.0.1',porta)
            alice.listar()
            assert aguardar(lambda: alice.evento.is_set())
            alice.evento.clear()
            alice.mensagem('Bob','Olá, Bob! 🔑')
            assert aguardar(lambda: 'Bob' in alice.sessoes and 'enviar' in alice.sessoes['Bob'])
            assert aguardar(lambda: 'Alice' in bob.sessoes and 'enviar' in bob.sessoes['Alice'])
            assert aguardar(lambda: alice._autenticada(alice.sessoes['Bob']) and bob._autenticada(bob.sessoes['Alice']))
            assert aguardar(lambda: ('Alice','Olá, Bob! 🔑') in bob.recebidas)
            bob.mensagem('Alice','Recebido com sucesso')
            assert aguardar(lambda: ('Bob','Recebido com sucesso') in alice.recebidas)
            assert all('privada' not in str(v) for v in server.clientes.values())
            print('OK:',modo,'mensagens nos dois sentidos, servidor sem DH/RC4')
        finally:
            alice.fechar()
            bob.fechar()
            server.sock.close()

if __name__=='__main__':
    rodar('didatico')
    rodar('seguro')
