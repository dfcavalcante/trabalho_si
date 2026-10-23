"""HKDF-SHA256: deriva duas chaves RC4 independentes a partir do segredo DH.

Usa somente a biblioteca padrão. HMAC/SHA256 são operações auxiliares à
negociação de chaves; RC4 e a aritmética DH permanecem implementados à mão.
"""
import hashlib
import hmac

from integridade import serializar


def contexto_sessao(transcricao):
    """Contexto HKDF vinculado à negociação específica.

    A transcrição contém protocolo, identificador da sessão, modo, quem é
    iniciador e quem é respondente, e as duas chaves públicas DH. Qualquer
    diferença em um desses campos produz chaves RC4 e HMAC diferentes.
    """
    return b"trabalho_si-sessao-v2|" + hashlib.sha256(serializar(transcricao)).hexdigest().encode()


def _expandir(prk, info, tamanho):
    resultado = b""
    bloco = b""
    contador = 1
    while len(resultado) < tamanho:
        bloco = hmac.new(prk, bloco + info + bytes([contador]), hashlib.sha256).digest()
        resultado += bloco
        contador += 1
    return resultado[:tamanho]


def derivar(s, p, log, contexto=b"trabalho_si-v1"):
    """Devolve (chave Alice->Bob, chave Bob->Alice), 32 bytes por sentido.

    No cliente-servidor, contexto = contexto_sessao(transcrição) e os rótulos
    de direção significam iniciador->respondente e respondente->iniciador;
    os nomes dos participantes e seus papéis entram pela transcrição.
    """
    if not 1 <= s < p:
        raise ValueError("segredo DH fora do intervalo permitido")
    tamanho = (p.bit_length() + 7) // 8
    segredo_bytes = s.to_bytes(tamanho, "big")
    sal = hashlib.sha256(b"trabalho_si|hkdf|sal|v1|" + contexto).digest()
    prk = hmac.new(sal, segredo_bytes, hashlib.sha256).digest()
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
    sal = hashlib.sha256(b'trabalho_si|hkdf|sal|v1|' + contexto).digest()
    prk = hmac.new(sal, seg, hashlib.sha256).digest()
    return (_expandir(prk, b'HMAC|iniciador->respondente|' + contexto, 32),
            _expandir(prk, b'HMAC|respondente->iniciador|' + contexto, 32))
