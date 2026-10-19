"""Testes que viram evidência: vetores do RC4, exemplo do DH e Miller-Rabin."""
import dh
from rc4 import RC4


def checar(nome, obtido, esperado):
    ok = obtido == esperado
    print(f"[{'OK ' if ok else 'FALHOU'}] {nome}: obtido={obtido} esperado={esperado}")
    return ok


def rodar():
    resultados = []
    print("\n--- RC4: vetores de teste conhecidos (sem drop) ---")
    for chave, claro, esperado in [
        (b"Key", b"Plaintext", "bbf316e8d940af0ad3"),
        (b"Wiki", b"pedia", "1021bf0420"),
        (b"Secret", b"Attack at dawn", "45a01f645fc35b383552544b9bf5"),
    ]:
        resultados.append(checar(f"RC4({chave.decode()}, {claro.decode()})",
                                 RC4(chave, drop=0).processar(claro).hex(), esperado))

    print("\n--- RC4: cifrar e decifrar volta ao original ---")
    cif = RC4(b"chave-teste").processar(b"mensagem secreta")
    resultados.append(checar("ida e volta", RC4(b"chave-teste").processar(cif), b"mensagem secreta"))

    print("\n--- Exponenciação modular x calculadora ---")
    resultados.append(checar("5^6 mod 23", dh.exp_mod(5, 6, 23), 8))
    resultados.append(checar("5^15 mod 23", dh.exp_mod(5, 15, 23), 19))
    resultados.append(checar("19^6 mod 23 (segredo)", dh.exp_mod(19, 6, 23), 2))
    resultados.append(checar("8^15 mod 23 (segredo)", dh.exp_mod(8, 15, 23), 2))

    print("\n--- Miller-Rabin ---")
    resultados.append(checar("23 é primo", dh.miller_rabin(23), True))
    resultados.append(checar("561 (Carmichael) é composto", dh.miller_rabin(561), False))
    resultados.append(checar("primo RFC 3526 de 2048 bits", dh.miller_rabin(dh.P_RFC3526_G14, rodadas=5), True))

    print("\n--- DH modo seguro: os dois lados chegam ao mesmo segredo ---")
    p, g = dh.SEGURO["p"], dh.SEGURO["g"]
    import secrets
    a, b = 2 + secrets.randbelow(p - 3), 2 + secrets.randbelow(p - 3)
    A, B = dh.exp_mod(g, a, p), dh.exp_mod(g, b, p)
    resultados.append(checar("B^a == A^b", dh.exp_mod(B, a, p) == dh.exp_mod(A, b, p), True))

    print(f"\n{sum(resultados)}/{len(resultados)} testes passaram")
    return all(resultados)


if __name__ == "__main__":
    rodar()
