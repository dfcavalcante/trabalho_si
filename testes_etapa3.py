"""Testes integrados de autenticação, HMAC, replay e ACK."""
import socket, threading, tempfile, time
from servidor import Servidor
from cliente import Cliente
import integridade
from identidades import provisionar_par
from pathlib import Path

def esperar(cond,limite=8):
    fim=time.monotonic()+limite
    while time.monotonic()<fim:
        if cond(): return True
        time.sleep(.02)
    return False

def executar(modo):
    temp=socket.socket();temp.bind(('127.0.0.1',0));porta=temp.getsockname()[1];temp.close()
    servidor=Servidor('127.0.0.1',porta)
    thread=threading.Thread(target=servidor.iniciar,daemon=True);thread.start()
    assert esperar(lambda: servidor.sock is not None)
    with tempfile.TemporaryDirectory() as d:
        ids=Path(d)/'ids'
        provisionar_par('Alice','Bob',ids)
        a=Cliente('Alice',modo,d,ids/'Alice.json');b=Cliente('Bob',modo,d,ids/'Bob.json')
        try:
            a.conectar('127.0.0.1',porta);b.conectar('127.0.0.1',porta)
            a.mensagem('Bob','Mensagem automática')
            assert esperar(lambda: ('Alice','Mensagem automática') in b.recebidas)
            assert esperar(lambda: a._autenticada(a.sessoes['Bob']) and b._autenticada(b.sessoes['Alice']))
            assert esperar(lambda: ('Bob',0) in a.confirmacoes)
            estado=a.sessoes['Bob']; seq=estado['seq_enviar']
            falso={'tipo':'cifra','id':estado['id'],'seq':seq,'hex':'12'}
            falso['mac']='00'*32
            a._relay('Bob',falso)
            assert esperar(lambda: any('HMAC inválido' in x for x in b.rejeicoes))
            assert b.sessoes['Alice']['seq_receber']==seq
            a.mensagem('Bob','Olá, Bob!')
            assert esperar(lambda: ('Alice','Olá, Bob!') in b.recebidas)
            assert esperar(lambda: ('Bob',seq) in a.confirmacoes)
            antes=len(b.recebidas)
            replay={'tipo':'cifra','id':estado['id'],'seq':seq,'hex':'12'}
            replay['mac']=integridade.etiqueta(estado['mac_enviar'],replay)
            a._relay('Bob',replay)
            assert esperar(lambda:any('replay' in x for x in b.rejeicoes))
            assert len(b.recebidas)==antes
            b.mensagem('Alice','ACK recebido')
            assert esperar(lambda: ('Bob','ACK recebido') in a.recebidas)
            print('SUCESSO',modo, 'autenticação automática, HMAC, adulteração, replay, ACK, ida/volta')
        finally:
            a.fechar();b.fechar();servidor.sock.close()

if __name__=='__main__':
    executar('didatico');executar('seguro')
