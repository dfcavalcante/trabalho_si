"""Chat cifrado Alice <-> Bob: Diffie-Hellman à mão + RC4 à mão.

Uso: python app.py   (abre o menu)
Só biblioteca padrão do Python. Nenhuma biblioteca de criptografia.
"""
import socket
import struct
import threading

import dh
import kdf
from log import Log, abreviar
from rc4 import RC4

PORTA_PADRAO = 5000


# ---------- rede: cada mensagem vai com 4 bytes de tamanho na frente ----------
def enviar(sock, dados):
    sock.sendall(struct.pack(">I", len(dados)) + dados)


def receber(sock):
    cabecalho = _receber_exato(sock, 4)
    if cabecalho is None:
        return None
    (tamanho,) = struct.unpack(">I", cabecalho)
    return _receber_exato(sock, tamanho)


def _receber_exato(sock, n):
    buf = b""
    while len(buf) < n:
        parte = sock.recv(n - len(buf))
        if not parte:
            return None
        buf += parte
    return buf


# ---------- troca de chaves ----------
def troca_de_chaves(sock, lado, log, modo=None):
    """Retorna (rc4_envio, rc4_recebimento). Bob escolhe os parâmetros, Alice confere."""
    if lado == "bob":
        params = dh.DIDATICO if modo == "didatico" else dh.SEGURO
        p, g = params["p"], params["g"]
        log.passo("PARAM", f"modo={modo} p={abreviar(p)} g={g}")
        enviar(sock, f"{modo}|{p:x}|{g}".encode())
        log.passo("ENVIO", "parâmetros públicos (modo, p, g) enviados para Alice")
    else:
        modo, p_hex, g_txt = receber(sock).decode().split("|")
        p, g = int(p_hex, 16), int(g_txt)
        log.passo("RECEBIDO", f"parâmetros de Bob: modo={modo} p={abreviar(p)} g={g}")
        if not dh.miller_rabin(p, log=log):
            raise ValueError("p recebido não é primo")

    detalhe_na_tela = modo == "didatico"  # no modo seguro o passo a passo vai completo só no arquivo
    privada, publica = dh.gerar_chaves(p, g, log, tela_detalhe=detalhe_na_tela)

    enviar(sock, format(publica, "x").encode())
    log.passo("ENVIO", f"minha chave pública enviada: {abreviar(publica)}")
    publica_outro = int(receber(sock).decode(), 16)
    log.passo("RECEBIDO", f"chave pública do outro lado: {abreviar(publica_outro)}")
    dh.validar_publica(publica_outro, p, log)

    s = dh.segredo(publica_outro, privada, p, log, tela_detalhe=detalhe_na_tela)

    minha, dele = dh.impressao_digital(publica), dh.impressao_digital(publica_outro)
    log.passo("CONFERE", f"digital da MINHA pública = {minha} | digital da pública DELE = {dele}")
    print(">>> Confiram em voz alta: os dois lados devem ver os mesmos números, trocados de posição.")

    chave_ab, chave_ba = kdf.derivar(s, p, log)
    if lado == "alice":
        return RC4(chave_ab, log, nome="RC4 A->B"), RC4(chave_ba, log, nome="RC4 B->A")
    return RC4(chave_ba, log, nome="RC4 B->A"), RC4(chave_ab, log, nome="RC4 A->B")


# ---------- chat ----------
def chat(sock, lado, log, rc4_envio, rc4_receb):
    estado = {"espiao": False, "ativo": True}
    nome_outro = "Bob" if lado == "alice" else "Alice"

    def recebedor():
        while estado["ativo"]:
            try:
                cifrado = receber(sock)
            except OSError:
                break
            if cifrado is None:
                print(f"\n[{nome_outro} saiu]")
                estado["ativo"] = False
                break
            if estado["espiao"]:
                print(f"\n[ESPIÃO] chegou pela rede: {cifrado.hex()}")
            claro = rc4_receb.processar(cifrado)
            log.passo("DECIFRA", f"cifrado={cifrado.hex()} -> claro={claro.decode(errors='replace')!r}", tela=False)
            print(f"\n{nome_outro}: {claro.decode(errors='replace')}\n> ", end="")

    threading.Thread(target=recebedor, daemon=True).start()
    print("\nChat pronto. Comandos: /espiao  /verboso  /log  /sair\n")
    while estado["ativo"]:
        try:
            texto = input("> ")
        except (EOFError, KeyboardInterrupt):
            break
        if texto == "/sair":
            break
        if texto == "/espiao":
            estado["espiao"] = not estado["espiao"]
            print(f"modo espião {'ligado' if estado['espiao'] else 'desligado'}")
            continue
        if texto == "/verboso":
            rc4_envio.verboso = rc4_receb.verboso = not rc4_envio.verboso
            print(f"RC4 verboso {'ligado' if rc4_envio.verboso else 'desligado'}")
            continue
        if texto == "/log":
            print(f"log desta sessão: {log.caminho}")
            continue
        if not texto:
            continue
        cifrado = rc4_envio.processar(texto.encode())
        log.passo("CIFRA", f"claro={texto!r} -> cifrado={cifrado.hex()}", tela=rc4_envio.verboso)
        if estado["espiao"]:
            print(f"[ESPIÃO] saiu para a rede: {cifrado.hex()}")
        enviar(sock, cifrado)
    estado["ativo"] = False
    sock.close()


# ---------- papéis ----------
def ser_bob():
    modo = escolher_modo()
    porta = int(input(f"Porta [{PORTA_PADRAO}]: ") or PORTA_PADRAO)
    log = Log("bob")
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind(("0.0.0.0", porta))
    servidor.listen(1)
    print(f"Bob aguardando Alice na porta {porta}...")
    sock, endereco = servidor.accept()
    servidor.close()
    log.passo("CONEXAO", f"Alice conectou de {endereco[0]}")
    envio, receb = troca_de_chaves(sock, "bob", log, modo)
    chat(sock, "bob", log, envio, receb)
    log.fechar()


def ser_alice():
    host = input("IP do Bob [127.0.0.1]: ") or "127.0.0.1"
    porta = int(input(f"Porta [{PORTA_PADRAO}]: ") or PORTA_PADRAO)
    log = Log("alice")
    sock = socket.create_connection((host, porta))
    log.passo("CONEXAO", f"conectada ao Bob em {host}:{porta}")
    envio, receb = troca_de_chaves(sock, "alice", log)
    chat(sock, "alice", log, envio, receb)
    log.fechar()


def demo_local():
    """Alice e Bob no mesmo terminal, modo didático: ideal para explicar no vídeo."""
    log = Log("demo")
    p, g = dh.DIDATICO["p"], dh.DIDATICO["g"]
    log.passo("PARAM", f"p={p} g={g}")
    dh.miller_rabin(p, log=log)
    print("\n--- Alice ---")
    a, A = dh.gerar_chaves(p, g, log)
    print("\n--- Bob ---")
    b, B = dh.gerar_chaves(p, g, log)
    print("\n--- Alice calcula o segredo com B ---")
    sa = dh.segredo(B, a, p, log)
    print("\n--- Bob calcula o segredo com A ---")
    sb = dh.segredo(A, b, p, log)
    log.passo("PROVA", f"Alice chegou a {sa}, Bob chegou a {sb}: {'IGUAIS' if sa == sb else 'DIFERENTES'}")
    log.passo("PROVA", f"conferência: {g}^({a}*{b}) mod {p} = {dh.exp_mod(g, a * b, p)}")
    print(f"\nlog salvo em {log.caminho}")
    log.fechar()


def escolher_modo():
    op = input("Modo: [1] didático (p=23)  [2] seguro (2048 bits)  > ").strip()
    return "didatico" if op == "1" else "seguro"


def main():
    while True:
        print("\n=== Chat cifrado RC4 + Diffie-Hellman ===")
        print("[1] Ser Bob (servidor)")
        print("[2] Ser Alice (cliente)")
        print("[3] Demonstração local do Diffie-Hellman (didático)")
        print("[4] Rodar testes")
        print("[0] Sair")
        op = input("> ").strip()
        if op == "1":
            ser_bob()
        elif op == "2":
            ser_alice()
        elif op == "3":
            demo_local()
        elif op == "4":
            import testes
            testes.rodar()
        elif op == "0":
            break


if __name__ == "__main__":
    main()
