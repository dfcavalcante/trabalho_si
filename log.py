"""Registro rastreável: cada passo vira uma linha numerada no terminal e no arquivo de log."""
import os
import secrets
from datetime import datetime


class Log:
    def __init__(self, lado, pasta="logs", limite_tela=160, didatico=False):
        self.lado = lado.upper()
        self.didatico = didatico
        self.contador = 0
        self.limite_tela = limite_tela
        os.makedirs(pasta, exist_ok=True)
        carimbo = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        sufixo = secrets.token_hex(3)
        self.caminho = os.path.join(pasta, f"sessao_{carimbo}_{sufixo}_{lado.lower()}.log")
        self.arquivo = open(self.caminho, "w", encoding="utf-8")

    def passo(self, etapa, detalhe, tela=True):
        self.contador += 1
        hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        linha = f"[{self.contador:04d}] {hora} | {self.lado} | {etapa:<8} | {detalhe}"
        self.arquivo.write(linha + "\n")
        self.arquivo.flush()
        if tela:
            # No terminal, números gigantes são abreviados; no arquivo vai tudo completo.
            if len(linha) > self.limite_tela:
                linha = linha[: self.limite_tela] + " ...(completo no log)"
            print(linha)

    def fechar(self):
        self.arquivo.close()


def abreviar(n, digitos=16):
    """Números pequenos em decimal (dá para conferir na calculadora);
    números grandes em hex, de forma curta: início...fim."""
    if n.bit_length() <= 64:
        return str(n)
    h = format(n, "x")
    if len(h) <= 2 * digitos:
        return h
    return f"{h[:digitos]}...{h[-digitos:]} ({n.bit_length()} bits)"


def completo(n):
    """Valor sem cortes, para auditoria: decimal se pequeno, hexadecimal se grande."""
    return str(n) if n.bit_length() <= 64 else "0x" + format(n, "x")
