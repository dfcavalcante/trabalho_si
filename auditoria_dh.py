"""Execução didática SEPARADA e determinística do Diffie-Hellman.

Usa chaves privadas FIXAS e públicas (nada aqui é segredo) para que o log
registre cada operação com todos os valores intermediários completos, sem
abreviações. O professor pode refazer as contas linha a linha e obter sempre
os mesmos números. As sessões reais do chat continuam ocultando os passos que
dependem de expoentes privados; NÃO reutilize estes valores em uma conversa.

    python auditoria_dh.py                  # grupo didático p=23, g=5
    python auditoria_dh.py --grupo seguro   # RFC 3526 grupo 14 (2048 bits)
"""
import argparse
import hashlib

import dh
import integridade
import kdf
from log import Log, completo

# Exemplo clássico, conferível na calculadora: A=8, B=19, s=2.
FIXOS_DIDATICO = (6, 15)
ID_AUDITORIA = "0" * 24


def fixos_seguro(p):
    """Expoentes de 2048 bits derivados de rótulos públicos: reprodutíveis, nunca secretos."""
    def expoente(rotulo):
        semente = b"".join(hashlib.sha256(rotulo + bytes([i])).digest() for i in range(8))
        return 2 + int.from_bytes(semente, "big") % (p - 3)
    return expoente(b"trabalho_si|auditoria-dh|Alice|"), expoente(b"trabalho_si|auditoria-dh|Bob|")


def executar(grupo="didatico", pasta="logs"):
    params = dh.DIDATICO if grupo == "didatico" else dh.SEGURO
    p, g = params["p"], params["g"]
    a, b = FIXOS_DIDATICO if grupo == "didatico" else fixos_seguro(p)
    log = Log(f"auditoria-dh-{grupo}", pasta=pasta, didatico=True)
    tela = p.bit_length() <= 64  # 2048 bits: tudo no arquivo, só o resumo no terminal
    try:
        log.passo("AVISO", "auditoria com chaves privadas FIXAS e públicas; não é uma sessão real")
        log.passo("PARAM", f"p = {completo(p)} ({p.bit_length()} bits)", tela=tela)
        log.passo("PARAM", f"g = {g}")
        dh.validar_parametros(grupo, p, g, log)
        log.passo("PRIV", f"Alice: a = {completo(a)}", tela=tela)
        log.passo("PRIV", f"Bob:   b = {completo(b)}", tela=tela)

        log.passo("DH-POW", "Alice calcula A = g^a mod p")
        A = dh.exp_mod(g, a, p, log, "DH-POW", tela=tela, completo=True)
        log.passo("DH-POW", "Bob calcula B = g^b mod p")
        B = dh.exp_mod(g, b, p, log, "DH-POW", tela=tela, completo=True)
        dh.validar_publica(A, p, log)
        dh.validar_publica(B, p, log)

        log.passo("SEGREDO", "Alice calcula s = B^a mod p")
        s_alice = dh.exp_mod(B, a, p, log, "SEGREDO", tela=tela, completo=True)
        log.passo("SEGREDO", "Bob calcula s = A^b mod p")
        s_bob = dh.exp_mod(A, b, p, log, "SEGREDO", tela=tela, completo=True)
        if s_alice != s_bob:
            raise AssertionError("segredos diferentes: implementação incorreta")
        log.passo("SEGREDO", f"B^a mod p == A^b mod p: s = {completo(s_alice)}", tela=tela)

        transcricao = integridade.transcricao(ID_AUDITORIA, grupo, "Alice", "Bob", A, B)
        contexto = kdf.contexto_sessao(transcricao)
        log.passo("DERIVA", f"transcrição = {integridade.serializar(transcricao).decode()}", tela=tela)
        log.passo("DERIVA", f"contexto HKDF = {contexto.decode()}")
        rc4_ir, rc4_ri = kdf.derivar(s_alice, p, log, contexto=contexto)
        mac_ir, mac_ri = kdf.derivar_autenticacao(s_alice, p, contexto)
        log.passo("DERIVA", f"RC4  iniciador->respondente = {rc4_ir.hex()}")
        log.passo("DERIVA", f"RC4  respondente->iniciador = {rc4_ri.hex()}")
        log.passo("DERIVA", f"HMAC iniciador->respondente = {mac_ir.hex()}")
        log.passo("DERIVA", f"HMAC respondente->iniciador = {mac_ri.hex()}")
        log.passo("FIM", f"log completo em {log.caminho}")
        return {"p": p, "g": g, "a": a, "b": b, "A": A, "B": B, "s": s_alice,
                "chaves": (rc4_ir, rc4_ri, mac_ir, mac_ri), "log": log.caminho}
    finally:
        log.fechar()


def main():
    parser = argparse.ArgumentParser(description="Auditoria determinística do Diffie-Hellman")
    parser.add_argument("--grupo", choices=["didatico", "seguro"], default="didatico")
    parser.add_argument("--pasta", default="logs")
    args = parser.parse_args()
    executar(args.grupo, args.pasta)


if __name__ == "__main__":
    main()
