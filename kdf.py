"""HKDF-SHA256: deriva duas chaves RC4 independentes a partir do segredo DH.

Usa somente a biblioteca padrão. HMAC/SHA256 são operações auxiliares à
negociação de chaves; RC4 e a aritmética DH permanecem implementados à mão.
"""
from primitivas_manuais import sha256, hmac_sha256
from integridade import serializar

def contexto_sessao(transcricao):
    return b"trabalho_si-sessao-v2|" + sha256(serializar(transcricao)).hex().encode()



def _expandir(prk, info, tamanho):
    resultado = b""
    bloco = b""
    contador = 1
    while len(resultado) < tamanho:
        bloco = hmac_sha256(prk, bloco + info + bytes([contador]))
        resultado += bloco
        contador += 1
    return resultado[:tamanho]


def derivar(s, p, log, contexto=b"trabalho_si-v1"):
    """Devolve (chave Alice->Bob, chave Bob->Alice), 32 bytes por sentido.

    Em uma fase futura, contexto deve incluir a transcrição autenticada e
    identificador da sessão, para vincular a derivação à negociação.
    """
    if not 1 <= s < p:
        raise ValueError("segredo DH fora do intervalo permitido")
    tamanho = (p.bit_length() + 7) // 8
    segredo_bytes = s.to_bytes(tamanho, "big")
    sal = sha256(b"trabalho_si|hkdf|sal|v1|" + contexto)
    prk = hmac_sha256(sal, segredo_bytes)
    chave_ab = _expandir(prk, b"RC4|Alice->Bob|" + contexto, 32)
    chave_ba = _expandir(prk, b"RC4|Bob->Alice|" + contexto, 32)
    if log:
        log.passo("DERIVA", f"HKDF-SHA256: entrada DH com {tamanho} bytes; contexto={contexto.hex()}")
        log.passo("DERIVA", "extract: PRK = HMAC-SHA256(sal, segredo DH)")
        log.passo("DERIVA", "expand: chaves RC4 independentes por direção (32 bytes cada)")
        log.passo("DERIVA", "Alice->Bob e Bob->Alice: chaves distintas; valores secretos omitidos")
    return chave_ab, chave_ba


def derivar_autenticacao(s, p, contexto):
    """Chaves HMAC em ambos os sentidos, separadas das chaves RC4."""
    if not 1 <= s < p:
        raise ValueError('segredo DH fora do intervalo')
    seg = s.to_bytes((p.bit_length()+7)//8, 'big')
    sal = sha256(b'trabalho_si|hkdf|sal|v1|' + contexto)
    prk = hmac_sha256(sal, seg)
    return (_expandir(prk, b'HMAC|iniciador->respondente|' + contexto, 32),
            _expandir(prk, b'HMAC|respondente->iniciador|' + contexto, 32))
