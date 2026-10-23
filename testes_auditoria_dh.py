"""Verificação de operações completas e reprodução da auditoria DH."""
from pathlib import Path
from tempfile import TemporaryDirectory
import auditoria_dh
with TemporaryDirectory() as d:
    a=auditoria_dh.executar('didatico',d)
    assert (a['A'],a['B'],a['s'])==(8,19,2)
    content=Path(a['log']).read_text(encoding='utf8')
    assert 'iter=' in content and '1^2 mod p = 1' in content
    assert a['chaves']==auditoria_dh.executar('didatico',d)['chaves']
    b=auditoria_dh.executar('seguro',d)
    assert b['A']==pow(2,b['a'], __import__('dh').SEGURO['p'])
    assert '...' not in Path(b['log']).read_text(encoding='utf8').split('DH-POW',1)[-1].split('DERIVA',1)[0]
print('OK: DH manual reproduzível e registro completo')
