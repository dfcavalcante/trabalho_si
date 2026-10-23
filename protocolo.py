"""Enquadramento de pacotes JSON com limite, independente do conteúdo cifrado."""
import json
import struct

MAX_PACOTE = 1024 * 1024


def enviar(sock, obj, trava=None):
    dados = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(dados) > MAX_PACOTE:
        raise ValueError('pacote excede limite')
    pacote = struct.pack('!I', len(dados)) + dados
    if trava is None:
        sock.sendall(pacote)
    else:
        with trava:
            sock.sendall(pacote)


def _exato(sock, n):
    buf = bytearray()
    while len(buf) < n:
        pedaco = sock.recv(n - len(buf))
        if not pedaco:
            raise ConnectionError('conexão encerrada')
        buf.extend(pedaco)
    return bytes(buf)


def receber(sock):
    (tam,) = struct.unpack('!I', _exato(sock, 4))
    if not 0 < tam <= MAX_PACOTE:
        raise ValueError('tamanho de pacote inválido')
    pacote = json.loads(_exato(sock, tam).decode('utf-8'))
    if not isinstance(pacote, dict) or not isinstance(pacote.get('tipo'), str):
        raise ValueError('pacote inválido')
    return pacote
