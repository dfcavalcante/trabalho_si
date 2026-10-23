"""Testes adicionais de auditoria acadêmica. Executar isoladamente."""
import socket, threading, time
from servidor import Servidor
from protocolo import enviar, receber

def esperar_porta(s):
    for _ in range(100):
        if s.sock is not None and s.porta: return
        time.sleep(.03)
    raise AssertionError('servidor não iniciou')

def teste_registro_sem_identidade():
    s=Servidor(host='127.0.0.1',porta=0)
    t=threading.Thread(target=s.iniciar,daemon=True);t.start();esperar_porta(s)
    c=socket.create_connection(('127.0.0.1',s.porta),timeout=5)
    try:
        enviar(c,{'tipo':'registro','nome':'Alice'})
        resposta=receber(c)
        assert resposta['tipo']=='registrado', resposta
        print('ACHADO CONFIRMADO: registro como Alice aceito SEM credencial no servidor')
    finally:
        c.close();s.sock.close()

def teste_grupo_criador_sem_identidade():
    s=Servidor(host='127.0.0.1',porta=0)
    threading.Thread(target=s.iniciar,daemon=True).start();esperar_porta(s)
    c=socket.create_connection(('127.0.0.1',s.porta),timeout=5)
    try:
        enviar(c,{'tipo':'registro','nome':'Criador'})
        assert receber(c)['tipo']=='registrado'
        enviar(c,{'tipo':'grupo_criar','grupo':'EquipeTeste'})
        limite=time.time()+2
        while time.time()<limite:
            with s.lock:
                if 'EquipeTeste' in s.grupos: break
            time.sleep(.02)
        assert s.grupos['EquipeTeste']['criador']=='Criador'
        print('ACHADO CONFIRMADO: nome não autenticado também pode criar sala e obter papel de criador')
    finally:
        c.close();s.sock.close()

if __name__=='__main__':
    teste_registro_sem_identidade()
    teste_grupo_criador_sem_identidade()
    print('2/2 cenários de auditoria reproduzidos (demonstram LACUNAS, não aprovação de segurança)')
