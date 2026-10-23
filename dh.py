"""Diffie-Hellman implementado à mão, com cada operação registrada.

Nada de pow(x, y, p) pronto nem bibliotecas de criptografia: a exponenciação
modular, o teste de primalidade e a validação são todos nossos.
"""
import secrets

from log import abreviar

# Modo didático: números pequenos, dá para conferir na calculadora.
DIDATICO = {"p": 23, "g": 5}

# Modo seguro: grupo 14 da RFC 3526 (primo de 2048 bits), gerador 2.
P_RFC3526_G14 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
SEGURO = {"p": P_RFC3526_G14, "g": 2}


def exp_mod(base, expoente, modulo, log=None, etapa="DH-POW", tela=True):
    """Square-and-multiply da esquerda para a direita, registrando cada bit."""
    bits = format(expoente, "b")
    if log:
        log.passo(etapa, f"calcular {abreviar(base)}^{abreviar(expoente)} mod {abreviar(modulo)} "
                         f"| expoente em binário tem {len(bits)} bits: {bits if len(bits) <= 64 else '(ver log)'}",
                  tela=tela)
    resultado = 1
    for i, bit in enumerate(bits, start=1):
        quadrado = (resultado * resultado) % modulo
        if bit == "1":
            resultado = (quadrado * base) % modulo
            acao = f"bit=1 -> quadrado={abreviar(quadrado)} -> x base={abreviar(resultado)}"
        else:
            resultado = quadrado
            acao = f"bit=0 -> quadrado={abreviar(quadrado)}"
        if log:
            log.passo(etapa, f"iter={i:>4} {acao}", tela=tela)
    if log:
        log.passo(etapa, f"resultado = {abreviar(resultado)}", tela=tela)
    return resultado


def miller_rabin(n, rodadas=20, log=None):
    """Teste de primalidade probabilístico, cada rodada registrada."""
    if n < 2:
        return False
    for pequeno in (2, 3, 5, 7, 11, 13):
        if n == pequeno:
            if log:
                log.passo("PRIMO", f"{n} é primo pequeno conhecido")
            return True
        if n % pequeno == 0:
            if log:
                log.passo("PRIMO", f"{abreviar(n)} divisível por {pequeno}: composto")
            return False
    # escreve n - 1 = 2^r * d com d ímpar
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    if log:
        log.passo("PRIMO", f"n-1 = 2^{r} * d, d={abreviar(d)}")
    for rodada in range(1, rodadas + 1):
        a = 2 + secrets.randbelow(n - 3)
        x = exp_mod(a, d, n)
        if x in (1, n - 1):
            if log:
                log.passo("PRIMO", f"rodada {rodada:>2}: testemunha a={abreviar(a)} -> passou")
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            if log:
                log.passo("PRIMO", f"rodada {rodada:>2}: testemunha a={abreviar(a)} -> COMPOSTO")
            return False
        if log:
            log.passo("PRIMO", f"rodada {rodada:>2}: testemunha a={abreviar(a)} -> passou")
    if log:
        log.passo("PRIMO", f"{abreviar(n)} é provavelmente primo ({rodadas} rodadas)")
    return True


def gerar_chaves(p, g, log, tela_detalhe=True):
    """Sorteia a chave privada e calcula a pública. Retorna (privada, publica)."""
    privada = 2 + secrets.randbelow(p - 3)  # 2 <= privada <= p - 2
    if p == 23 and g == 5:
        # No grupo didático, evitar chaves públicas triviais por reamostragem.
        while exp_mod(g, privada, p) not in range(2, p - 1):
            privada = 2 + secrets.randbelow(p - 3)
    if p.bit_length() <= 64:
        log.passo("PRIV", f"chave privada sorteada = {privada}")
    else:
        log.passo("PRIV", f"chave privada sorteada: {privada.bit_length()} bits; conteúdo protegido")
    if log and not getattr(log, "didatico", False):
        log.passo("DH-POW", "exponenciação modular com expoente privado: passos sigilosos omitidos")
    publica = exp_mod(g, privada, p, log if getattr(log, "didatico", False) else None, "DH-POW", tela=tela_detalhe)
    log.passo("PUB", f"chave pública = {abreviar(publica)}")
    return privada, publica


def validar_publica(valor, p, log):
    """Rejeita chaves públicas triviais (1, p-1 ou fora do intervalo)."""
    ok = 2 <= valor <= p - 2
    if ok and p == P_RFC3526_G14:
        q = (p - 1) // 2
        ok = exp_mod(valor, q, p) == 1
    log.passo("VALIDA", f"2 <= {abreviar(valor)} <= p-2 ? {'OK' if ok else 'REJEITADA'}")
    if not ok:
        raise ValueError("chave pública recebida inválida")


def segredo(publica_outro, privada, p, log, tela_detalhe=True):
    if log and not getattr(log, "didatico", False):
        log.passo("SEGREDO", "exponenciação com chave privada: passos sigilosos omitidos")
    s = exp_mod(publica_outro, privada, p, log if getattr(log, "didatico", False) else None, "SEGREDO", tela=tela_detalhe)
    log.passo("SEGREDO", f"segredo compartilhado s = {s if getattr(log, 'didatico', False) else '[OCULTO]'}")
    return s


def impressao_digital(valor):
    """Últimos 8 dígitos hex, para conferência em voz alta (anti-intermediário)."""
    return format(valor, "x")[-8:].upper().rjust(8, "0")


def validar_parametros(modo, p, g, log=None):
    """Aceita apenas parâmetros locais conhecidos, evitando grupos impostos pela rede."""
    if modo not in ("didatico", "seguro"):
        raise ValueError("modo de criptografia desconhecido")
    esperado = DIDATICO if modo == "didatico" else SEGURO
    ok = (p == esperado["p"] and g == esperado["g"])
    if log:
        log.passo("VALIDA", f"parâmetros do modo {modo}: {'OK' if ok else 'REJEITADOS'}")
    if not ok:
        raise ValueError("parâmetros Diffie-Hellman não correspondem ao grupo autorizado")
