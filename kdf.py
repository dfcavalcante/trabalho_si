"""Transforma o segredo s do Diffie-Hellman em duas chaves RC4 (uma por sentido)."""


def derivar(s, p, log):
    tamanho = (p.bit_length() + 7) // 8
    s_bytes = s.to_bytes(tamanho, "big")
    log.passo("DERIVA", f"s em {tamanho} bytes (hex) = {s_bytes.hex()}")
    if tamanho >= 32:
        meio = tamanho // 2
        chave_ab = s_bytes[:meio]
        chave_ba = s_bytes[meio:]
        log.passo("DERIVA", f"chave Alice->Bob = primeiros {meio} bytes = {chave_ab.hex()}")
        log.passo("DERIVA", f"chave Bob->Alice = últimos {tamanho - meio} bytes = {chave_ba.hex()}")
    else:
        # Modo didático: s cabe em 1 byte, então diferenciamos os sentidos com um sufixo.
        chave_ab = s_bytes + b"\x01"
        chave_ba = s_bytes + b"\x02"
        log.passo("DERIVA", f"(didático) chave Alice->Bob = s || 01 = {chave_ab.hex()}")
        log.passo("DERIVA", f"(didático) chave Bob->Alice = s || 02 = {chave_ba.hex()}")
    return chave_ab, chave_ba
