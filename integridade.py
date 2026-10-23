"""HMAC autenticado e vinculado à sessão, sem bibliotecas criptográficas externas."""
import hashlib
import hmac
import json


def serializar(dados):
    return json.dumps(dados, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf8')


def etiqueta(chave, dados):
    return hmac.new(chave, serializar(dados), hashlib.sha256).hexdigest()


def verificar(chave, dados, mac):
    return isinstance(mac, str) and hmac.compare_digest(etiqueta(chave, dados), mac)


def transcricao(identificador, modo, iniciador, respondente, pub_inic, pub_resp):
    return {'protocolo':'trabalho-si-v2', 'id':identificador, 'modo':modo,
            'iniciador':iniciador, 'respondente':respondente,
            'pub_iniciador':format(pub_inic,'x'), 'pub_respondente':format(pub_resp,'x')}


def codigo_verificacao(transcricao_dh):
    return hashlib.sha256(serializar(transcricao_dh)).hexdigest().upper()[:16]
