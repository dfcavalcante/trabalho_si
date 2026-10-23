"""Separação entre sessões: chaves RC4/HMAC vinculadas à negociação, aos papéis e à direção."""
import tempfile
import threading
import time
from pathlib import Path

import dh
import kdf
from cliente import Cliente
from contas import cadastrar
from identidades import provisionar_par
from integridade import transcricao
from servidor import Servidor


def chaves(s, p, trans):
    contexto = kdf.contexto_sessao(trans)
    return kdf.derivar(s, p, None, contexto) + kdf.derivar_autenticacao(s, p, contexto)


def unitario():
    p, s = 23, 2
    base = transcricao('a' * 24, 'didatico', 'Alice', 'Bob', 8, 19)
    ref = chaves(s, p, base)
    assert len(set(ref)) == 4, 'RC4 e HMAC, nas duas direções, precisam ser chaves distintas'
    variacoes = {
        'outra sessão': transcricao('b' * 24, 'didatico', 'Alice', 'Bob', 8, 19),
        'papéis trocados': transcricao('a' * 24, 'didatico', 'Bob', 'Alice', 19, 8),
        'outro participante': transcricao('a' * 24, 'didatico', 'Alice', 'Carol', 8, 19),
        'outra pública do iniciador': transcricao('a' * 24, 'didatico', 'Alice', 'Bob', 10, 19),
        'outra pública do respondente': transcricao('a' * 24, 'didatico', 'Alice', 'Bob', 8, 20),
        'outro modo': transcricao('a' * 24, 'seguro', 'Alice', 'Bob', 8, 19),
    }
    for nome, trans in variacoes.items():
        outras = chaves(s, p, trans)
        assert not set(outras) & set(ref), f'chave reaproveitada com {nome}'
    assert chaves(s, p, dict(base)) == ref, 'mesma negociação deve derivar as mesmas chaves'
    s_seguro = 5 + dh.SEGURO['p'] // 3
    assert chaves(s_seguro, dh.SEGURO['p'], base) != chaves(s_seguro + 1, dh.SEGURO['p'], base)


def esperar(cond, t=10):
    fim = time.monotonic() + t
    while time.monotonic() < fim:
        if cond(): return True
        time.sleep(.03)
    return False


def sessao(porta, root, ids, texto):
    alice = Cliente('Alice', 'didatico', str(root / 'logs'), ids / 'Alice.json')
    bob = Cliente('Bob', 'didatico', str(root / 'logs'), ids / 'Bob.json')
    alice.conectar(porta=porta, senha='aliceSenhaForte123')
    bob.conectar(porta=porta, senha='bobSenhaForte123')
    try:
        alice.mensagem('Bob', texto)
        assert esperar(lambda: ('Alice', texto) in bob.recebidas), 'mensagem não entregue'
        ea, eb = alice.sessoes['Bob'], bob.sessoes['Alice']
        assert ea['transcricao'] == eb['transcricao']
        assert ea['contexto'] == eb['contexto'] == kdf.contexto_sessao(ea['transcricao'])
        assert ea['transcricao']['iniciador'] == 'Alice' and ea['transcricao']['respondente'] == 'Bob'
        assert ea['mac_enviar'] == eb['mac_receber'] and ea['mac_receber'] == eb['mac_enviar']
        assert ea['mac_enviar'] != ea['mac_receber'], 'direções compartilham a chave HMAC'
        return ea['id'], ea['contexto'], ea['mac_enviar'], ea['mac_receber']
    finally:
        alice.fechar()
        bob.fechar()


def ponta_a_ponta():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        db, ids = root / 'contas.json', root / 'identidades'
        cadastrar('Alice', 'aliceSenhaForte123', db)
        cadastrar('Bob', 'bobSenhaForte123', db)
        provisionar_par('Alice', 'Bob', ids)
        servidor = Servidor(porta=0, caminho_contas=db)
        threading.Thread(target=servidor.iniciar, daemon=True).start()
        assert esperar(lambda: servidor.sock is not None and servidor.porta > 0)
        try:
            id1, ctx1, *mac1 = sessao(servidor.porta, root, ids, 'primeira sessão')
            assert esperar(lambda: not servidor.clientes)
            id2, ctx2, *mac2 = sessao(servidor.porta, root, ids, 'segunda sessão')
            assert id1 != id2 and ctx1 != ctx2
            assert not set(mac1) & set(mac2), 'chave HMAC reaproveitada entre sessões'
        finally:
            servidor.sock.close()


if __name__ == '__main__':
    unitario()
    ponta_a_ponta()
    print('OK: chaves vinculadas a sessão, papéis, públicas DH e direção; sessões distintas não compartilham chaves')
