"""Separação criptográfica da sessão, direção e papéis."""
import kdf
from integridade import transcricao

def keys(t):
    ctx=kdf.contexto_sessao(t)
    return kdf.derivar(2,23,None,ctx)+kdf.derivar_autenticacao(2,23,ctx)
base=transcricao('0'*24,'didatico','Alice','Bob',8,19)
ref=keys(base)
assert len(set(ref))==4
for campo,valor in [('id','1'*24),('modo','seguro'),('iniciador','Carol'),('pub_iniciador','a')]:
    t=dict(base);t[campo]=valor
    assert not set(ref).intersection(keys(t)),campo
assert keys(dict(base))==ref
print('OK: separação por sessão, direção, modo e identidade')
