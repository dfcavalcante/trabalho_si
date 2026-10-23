"""Testes adicionais da etapa 1. Executar: python testes_etapa1.py"""
import tempfile
from pathlib import Path

import dh
import kdf
from log import Log
from rc4 import RC4


def rodar():
    with tempfile.TemporaryDirectory() as tmp:
        didatico = Log('teste-didatico', pasta=tmp, didatico=True)
        seguro = Log('teste-seguro', pasta=tmp, didatico=False)
        try:
            dh.validar_parametros('didatico', 23, 5, didatico)
            dh.validar_parametros('seguro', dh.SEGURO['p'], 2, seguro)
            for params in [('didatico', 23, 2), ('seguro', 23, 5), ('errado', 23, 5)]:
                try:
                    dh.validar_parametros(*params, log=seguro)
                except ValueError:
                    continue
                raise AssertionError('grupo inesperado aceito')

            a, A = dh.gerar_chaves(23, 5, didatico)
            b, B = dh.gerar_chaves(23, 5, didatico)
            sa = dh.segredo(B, a, 23, didatico)
            sb = dh.segredo(A, b, 23, didatico)
            assert sa == sb
            kab1, kba1 = kdf.derivar(sa, 23, didatico)
            kab2, kba2 = kdf.derivar(sb, 23, didatico)
            assert kab1 == kab2 and kba1 == kba2
            assert kab1 != kba1 and len(kab1) == len(kba1) == 32
            texto = b'Mensagem academica'
            assert RC4(kab2).processar(RC4(kab1).processar(texto)) == texto

            p = dh.SEGURO['p']
            priv, pub = dh.gerar_chaves(p, 2, seguro, tela_detalhe=False)
            dh.validar_publica(pub, p, seguro)
            segredo = dh.segredo(pub, priv, p, seguro, tela_detalhe=False)
            chaves = kdf.derivar(segredo, p, seguro)
            RC4(chaves[0], seguro)
            conteudo = Path(seguro.caminho).read_text()
            assert str(priv) not in conteudo
            assert format(priv, 'b') not in conteudo
            assert segredo.to_bytes(256, 'big').hex() not in conteudo
            assert chaves[0].hex() not in conteudo
            assert 'S completo' not in conteudo
        finally:
            didatico.fechar()
            seguro.fechar()
    print('OK: grupos autorizados, rejeicoes, DH, HKDF, RC4, sigilo do log seguro')


if __name__ == '__main__':
    rodar()
