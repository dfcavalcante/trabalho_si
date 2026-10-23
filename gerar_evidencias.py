"""Gera evidências de uma sessão TCP real Alice <-> servidor <-> Bob.

Somente demonstração acadêmica. Cria contas/credenciais EFÊMERAS em diretório temporário,
sem acessar as contas reais e sem publicar senhas ou arquivos de identidade.
"""
import argparse
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path

from cliente import Cliente
from contas import cadastrar
from identidades import provisionar_par
from servidor import Servidor


def esperar(predicado, segundos=20):
    limite=time.monotonic()+segundos
    while time.monotonic()<limite:
        if predicado(): return True
        time.sleep(0.04)
    return False


def executar(modo='didatico', destino='evidencias'):
    saida=Path(destino).resolve()/modo
    saida.mkdir(parents=True, exist_ok=True)
    # O teste de demonstração usa senha forte gerada e poucas iterações para ser rápido.
    # Não modifica os parâmetros usados no cadastro real.
    with tempfile.TemporaryDirectory(prefix='chat_si_evidencia_') as temp:
        raiz=Path(temp)
        ids=raiz/'identidades'
        db=raiz/'contas.json'
        senha_alice='AliceSenhaDeTeste123!'
        senha_bob='BobSenhaDeTeste123!'
        cadastrar('Alice',senha_alice,db)
        cadastrar('Bob',senha_bob,db)
        provisionar_par('Alice','Bob',ids)
        servidor=Servidor(host='127.0.0.1',porta=0,caminho_contas=db,
                         espiao=True,pasta_capturas=raiz/'capturas')
        thread=threading.Thread(target=servidor.iniciar,daemon=True)
        thread.start()
        if not esperar(lambda:servidor.sock is not None and servidor.porta>0):
            raise RuntimeError('Servidor não iniciou')
        alice=Cliente('Alice',modo,str(raiz/'logs'),ids/'Alice.json')
        bob=Cliente('Bob',modo,str(raiz/'logs'),ids/'Bob.json')
        mensagem='EVIDENCIA: Alice enviou esta mensagem para Bob.'
        resposta='EVIDENCIA: Bob recebeu e respondeu para Alice.'
        try:
            alice.conectar(porta=servidor.porta,senha=senha_alice)
            bob.conectar(porta=servidor.porta,senha=senha_bob)
            alice.mensagem('Bob',mensagem)
            assert esperar(lambda: ('Alice',mensagem) in bob.recebidas,30), 'Bob não recebeu'
            assert esperar(lambda: ('Bob',0) in alice.confirmacoes,15), 'Alice não recebeu ACK'
            bob.mensagem('Alice',resposta)
            assert esperar(lambda: ('Bob',resposta) in alice.recebidas,30), 'Alice não recebeu resposta'
            assert esperar(lambda: ('Alice',0) in bob.confirmacoes,15), 'Bob não recebeu ACK'
            estado_a=alice.sessoes['Bob'];estado_b=bob.sessoes['Alice']
            assert estado_a['id']==estado_b['id'], 'IDs de sessão divergentes'
            assert alice._autenticada(estado_a) and bob._autenticada(estado_b)
            ident=estado_a['id']
            captura=raiz/'capturas'/'trafego_relay.jsonl'
            pacotes=[json.loads(l) for l in captura.read_text(encoding='utf-8').splitlines()]
            decodificados=[]
            for p in pacotes:
                dado=json.loads(bytes.fromhex(p['pacote_json_hex']).decode('utf-8'))
                decodificados.append((p,dado))
            da_sessao=[(p,d) for p,d in decodificados if d.get('id')==ident]
            tipos=[d.get('tipo') for _,d in da_sessao]
            assert {'dh_inicio','dh_resposta','confirmacao','cifra','ack'}.issubset(tipos), tipos
            cifrados=[(p,d) for p,d in da_sessao if d.get('tipo')=='cifra']
            assert len(cifrados)>=2
            for _,d in cifrados:
                assert d.get('hex') and d.get('mac') and d.get('seq') is not None
                assert mensagem.encode('utf-8').hex() not in d['hex']
                assert resposta.encode('utf-8').hex() not in d['hex']
            trilha=[{'origem':p['de'],'destino':p['para'],'tipo':d['tipo'],'sessao':ident,
                    'seq':d.get('seq'), 'chave_publica_hex':d.get('pub'),
                    'cifrado_hex':d.get('hex'), 'hmac_hex':d.get('mac')}
                   for p,d in da_sessao]
            (saida/'trilha_correlacionada.json').write_text(json.dumps(trilha,ensure_ascii=False,indent=2),encoding='utf-8')
            (saida/'captura_servidor.jsonl').write_text(captura.read_text(encoding='utf-8'),encoding='utf-8')
            for cliente,nome in ((alice,'alice'),(bob,'bob')):
                shutil.copyfile(cliente.log.caminho,saida/f'log_{nome}.log')
            resumo={'modo':modo,'sessao':ident,'alice_autenticada':True,'bob_autenticado':True,
                    'bob_recebeu':mensagem,'alice_recebeu':resposta,
                    'alice_ack':[list(x) for x in alice.confirmacoes],
                    'bob_ack':[list(x) for x in bob.confirmacoes],
                    'tipos_pacote':tipos,'pacotes_da_sessao':len(da_sessao),
                    'mensagens_cifradas':len(cifrados),
                    'validacoes':['DH automático','HMAC e ACK','cifragem RC4 distinta do texto claro','sessão idêntica nas duas pontas'],
                    'observacao':'Senhas de demonstração não são copiadas. Logs didáticos podem conter chaves de demonstração.'}
            (saida/'resumo.json').write_text(json.dumps(resumo,ensure_ascii=False,indent=2),encoding='utf-8')
            print('EVIDÊNCIA OK:',modo,'sessão',ident, 'pacotes',len(da_sessao),'pasta',saida,flush=True)
            return resumo
        finally:
            alice.fechar();bob.fechar()
            if servidor.sock: servidor.sock.close()

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--modo',choices=['didatico','seguro'],default='didatico')
    p.add_argument('--saida',default='evidencias')
    a=p.parse_args()
    executar(a.modo,a.saida)
