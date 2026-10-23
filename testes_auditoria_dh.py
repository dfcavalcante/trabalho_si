"""Testes da auditoria determinística do DH (todos os passos com valores completos)."""
import re
import tempfile
from pathlib import Path

import auditoria_dh
from log import completo


def executar():
    with tempfile.TemporaryDirectory() as pasta:
        r = auditoria_dh.executar('didatico', pasta)
        assert (r['A'], r['B'], r['s']) == (8, 19, 2), r
        log = Path(r['log']).read_text(encoding='utf-8')
        # Cada iteração mostra a operação inteira: 5^6 mod 23 começa com 1^2 = 1, 1 x 5 = 5.
        assert 'iter=   1 bit=1 | 1^2 mod p = 1 | 1 x 5 mod p = 5' in log
        assert 'resultado = 8' in log and 'resultado = 19' in log
        assert 'Alice: a = 6' in log and 'Bob:   b = 15' in log
        assert auditoria_dh.executar('didatico', pasta)['chaves'] == r['chaves'], 'não determinístico'

        r = auditoria_dh.executar('seguro', pasta)
        p = r['p']
        # pow() aparece só aqui, como oráculo independente do teste; a implementação não o usa.
        assert r['A'] == pow(2, r['a'], p) and r['B'] == pow(2, r['b'], p)
        assert r['s'] == pow(r['B'], r['a'], p) == pow(r['A'], r['b'], p)
        log = Path(r['log']).read_text(encoding='utf-8')
        linhas = [l for l in log.splitlines() if '| DH-POW ' in l or '| SEGREDO ' in l]
        iteracoes = [l for l in linhas if 'iter=' in l]
        esperado = 2 * len(format(r['a'], 'b')) + 2 * len(format(r['b'], 'b'))
        assert len(iteracoes) == esperado, (len(iteracoes), esperado)
        assert not any('...' in l or '[OCULTO]' in l or 'omitidos' in l for l in linhas)
        assert completo(r['s']) in log and completo(r['a']) in log
        # Uma iteração qualquer pode ser refeita à mão a partir da própria linha.
        m = re.search(r'bit=1 \| (0x[0-9a-f]+)\^2 mod p = (0x[0-9a-f]+) \| \2 x (\S+) mod p = (0x[0-9a-f]+)', log)
        anterior, quadrado, base, resultado = (int(v, 0) for v in m.groups())
        assert anterior * anterior % p == quadrado and quadrado * base % p == resultado
    print('OK: auditoria DH determinística, completa e conferível linha a linha (didático e 2048 bits)')


if __name__ == '__main__':
    executar()
