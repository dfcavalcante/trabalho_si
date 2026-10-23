"""Demonstração reprodutível: TODOS os valores são públicos e somente didáticos.
Não executar com credenciais/chaves privadas de sessões reais.
"""
from pathlib import Path
from dh import DIDATICO, exp_mod
from rc4 import RC4
from log import Log


def executar():
    log = Log("DEMO", pasta="logs", limite_tela=300, didatico=True)
    try:
        p, g, a, b = 23, 5, 6, 15
        log.passo("PARAM", f"p={p}, g={g}; privadas fixas DIDÁTICAS: a={a}, b={b}")
        A = exp_mod(g, a, p, log, etapa="ALICE-PUB")
        B = exp_mod(g, b, p, log, etapa="BOB-PUB")
        log.passo("ENVIO", f"Alice -> Bob: chave PÚBLICA A={A}")
        log.passo("ENVIO", f"Bob -> Alice: chave PÚBLICA B={B}")
        sa = exp_mod(B, a, p, log, etapa="ALICE-SEG")
        sb = exp_mod(A, b, p, log, etapa="BOB-SEG")
        assert (A, B, sa, sb) == (8, 19, 2, 2)
        log.passo("PROVA", f"A={A}, B={B}, segredo Alice={sa}, segredo Bob={sb}; IGUAIS")
        # Aqui usa-se uma chave RC4 FIXA de teste, separada da KDF em produção.
        # O propósito é auditar cada uma das 256 iterações do KSA e os bytes PRGA/XOR.
        chave = b"Key"
        texto = b"Plaintext"
        log.passo("RC4-DEMO", f"chave do vetor de teste={chave.hex()} texto={texto!r} drop=0")
        cifra = RC4(chave, log=log, drop=0, nome="VETOR-RC4", auditoria_completa=True)
        criptografado = cifra.processar(texto)
        assert criptografado.hex().upper() == "BBF316E8D940AF0AD3"
        log.passo("CIFRA", f"cifrado integral hex={criptografado.hex().upper()}")
        texto_recuperado = RC4(chave, drop=0).processar(criptografado)
        assert texto_recuperado == texto
        log.passo("DECIFRA", f"texto recuperado={texto_recuperado!r}; teste OK")
        print(f"\nDEMONSTRAÇÃO DIDÁTICA OK. Log completo: {log.caminho}")
    finally:
        log.fechar()

if __name__ == "__main__":
    executar()
