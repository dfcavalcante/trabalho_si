"""RC4 implementado à mão (KSA + PRGA), com descarte inicial do fluxo."""


class RC4:
    def __init__(self, chave, log=None, drop=3072, nome="RC4"):
        self.log = log
        self.nome = nome
        self.verboso = False
        self.S = list(range(256))
        if log:
            log.passo("KSA", f"{nome}: chave de {len(chave)} bytes = {chave.hex()}")
            log.passo("KSA", f"{nome}: S inicial = {self.S[:16]}... (0 a 255)", tela=False)
        j = 0
        for i in range(256):
            j = (j + self.S[i] + chave[i % len(chave)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        if log:
            log.passo("KSA", f"{nome}: S após embaralhar (16 primeiros) = {self.S[:16]}")
            log.passo("KSA", f"{nome}: S completo = {self.S}", tela=False)
        self.i = 0
        self.j = 0
        for _ in range(drop):
            self._proximo_byte()
        if log and drop:
            log.passo("PRGA", f"{nome}: descartados os {drop} primeiros bytes do fluxo (RC4-drop)")

    def _proximo_byte(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]

    def processar(self, dados):
        """Cifra ou decifra (é a mesma operação: XOR com o fluxo)."""
        saida = bytearray()
        for n, byte in enumerate(dados):
            k = self._proximo_byte()
            saida.append(byte ^ k)
            if self.verboso and self.log:
                self.log.passo("PRGA", f"{self.nome}: byte {n}: i={self.i} j={self.j} "
                                       f"fluxo=0x{k:02x} entrada=0x{byte:02x} saida=0x{byte ^ k:02x}")
        return bytes(saida)
