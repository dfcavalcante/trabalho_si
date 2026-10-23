from pathlib import Path
import tempfile
from rc4 import RC4
from log import Log
from servidor import Servidor

def executar():
    with tempfile.TemporaryDirectory() as td:
        log=Log('prova', pasta=td, didatico=True)
        chave=b'Key'; claro=b'Plaintext'
        cifrado=RC4(chave,log,drop=0,auditoria_completa=True).processar(claro)
        log.fechar()
        assert cifrado.hex().upper()=='BBF316E8D940AF0AD3'
        linhas=Path(log.caminho).read_text(encoding='utf8').splitlines()
        assert sum('| KSA ' in x and 'iter=' in x for x in linhas)==256
        assert sum('| PRGA ' in x and 'XOR=' in x for x in linhas)==len(claro)
        servidor=Servidor(espiao=True,pasta_capturas=td)
        servidor.auditar_relay('Alice','Bob',{'tipo':'cifra','dados':'aabbcc'})
        captura=(Path(td)/'trafego_relay.jsonl').read_text(encoding='utf8')
        assert '616162626363' in captura # ciphertext hex serializado em JSON
    print('OK: 256 passos KSA, PRGA/XOR e captura do relay')
if __name__=='__main__': executar()
