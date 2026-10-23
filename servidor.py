"""Servidor de encaminhamento: sem RC4, sem DH e sem acesso ao texto claro."""
import socket
import threading
import time
import secrets
import contas
from protocolo import enviar, receber


class Servidor:
    def __init__(self, host='127.0.0.1', porta=5000, caminho_contas=None):
        self.host, self.porta = host, porta
        self.caminho_contas = caminho_contas or contas.PADRAO
        self.clientes = {}  # nome -> (socket, lock de escrita)
        self.lock = threading.RLock()
        self.sock = None
        self.ultimo_pong = {}
        self.grupos = {}  # grupo -> {criador, membros}; sem chaves ou texto claro
        self.heartbeat_interval = 3.0
        self.heartbeat_timeout = 10.0

    def iniciar(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.porta))
        self.sock.listen(20)
        self.porta = self.sock.getsockname()[1]
        print(f'[SERVIDOR] Escutando em {self.host}:{self.porta}', flush=True)
        threading.Thread(target=self._vigiar_presenca, daemon=True).start()
        try:
            while True:
                conexao, _ = self.sock.accept()
                threading.Thread(target=self.atender, args=(conexao,), daemon=True).start()
        except OSError:
            pass
        finally:
            self.sock.close()

    def enviar_para(self, nome, pacote):
        with self.lock:
            destino = self.clientes.get(nome)
        if not destino:
            return False
        try:
            enviar(destino[0], pacote, destino[1])
            return True
        except (OSError, ConnectionError):
            return False

    def _publicar_presenca(self):
        with self.lock:
            usuarios = sorted(self.clientes)
            destinos = list(self.clientes.items())
        for _, (sock, trava) in destinos:
            try:
                enviar(sock, {'tipo':'presenca', 'nomes':usuarios}, trava)
            except (OSError, ConnectionError):
                pass

    def _notificar_grupos(self):
        with self.lock:
            grupos = {n: {'criador':g['criador'], 'membros':sorted(g['membros'])}
                      for n,g in self.grupos.items()}
            destinatarios = list(self.clientes)
        for nome in destinatarios:
            visiveis = {n:dict(g) for n,g in grupos.items() if nome in g['membros']}
            self.enviar_para(nome, {'tipo':'grupos','salas':visiveis})

    def _vigiar_presenca(self):
        """Desliga clientes que não respondem a desafios de liveness."""
        while self.sock is not None and self.sock.fileno() != -1:
            time.sleep(self.heartbeat_interval)
            agora = time.monotonic()
            with self.lock:
                snapshot = [(nome, *par, self.ultimo_pong.get(nome, 0))
                            for nome, par in self.clientes.items()]
            for nome, sock, trava, ultimo in snapshot:
                if agora - ultimo > self.heartbeat_timeout:
                    print(f'[TIMEOUT] {nome}: heartbeat sem resposta', flush=True)
                    try: sock.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                    try: sock.close()
                    except OSError: pass
                else:
                    try: enviar(sock, {'tipo':'ping'}, trava)
                    except (OSError, ConnectionError):
                        try: sock.shutdown(socket.SHUT_RDWR)
                        except OSError: pass
                        sock.close()

    def atender(self, conexao):
        nome = None
        trava = threading.Lock()
        try:
            cadastro = receber(conexao)
            candidato = cadastro.get('nome')
            if cadastro['tipo'] != 'registro' or not isinstance(candidato, str) or not 1 <= len(candidato) <= 24 or not candidato.isalnum():
                enviar(conexao, {'tipo':'erro','motivo':'nome de usuário inválido'})
                return
            # Autenticação ANTES do registro e das permissões administrativas.
            registro=contas.carregar(self.caminho_contas).get(candidato)
            if registro is None:
                enviar(conexao,{'tipo':'erro','motivo':'credenciais inválidas'},trava)
                return
            desafio=secrets.token_hex(32)
            enviar(conexao,{'tipo':'desafio_login','sal':registro['sal'],
                           'iteracoes':registro['iteracoes'],'desafio':desafio},trava)
            autenticacao=receber(conexao)
            if (autenticacao.get('tipo')!='prova_login' or
                not contas.verificar(registro,candidato,desafio,autenticacao.get('prova'))):
                enviar(conexao,{'tipo':'erro','motivo':'credenciais inválidas'},trava)
                return
            with self.lock:
                if candidato in self.clientes:
                    enviar(conexao, {'tipo':'erro','motivo':'usuário já conectado'})
                    return
                nome = candidato
                self.clientes[nome] = (conexao, trava)
                self.ultimo_pong[nome] = time.monotonic()
            enviar(conexao, {'tipo':'registrado','nome':nome}, trava)
            print(f'[ENTRADA] {nome}', flush=True)
            self._publicar_presenca()
            self._notificar_grupos()
            while True:
                pkt = receber(conexao)
                tipo = pkt['tipo']
                if tipo == 'pong':
                    with self.lock:
                        if self.clientes.get(nome, (None,))[0] is conexao:
                            self.ultimo_pong[nome] = time.monotonic()
                elif tipo == 'listar':
                    with self.lock:
                        usuarios = sorted(self.clientes)
                    enviar(conexao, {'tipo':'usuarios','nomes':usuarios}, trava)
                elif tipo == 'grupo_criar':
                    grupo = pkt.get('grupo')
                    if not isinstance(grupo,str) or not 1<=len(grupo)<=32 or not grupo.replace('_','').isalnum():
                        enviar(conexao, {'tipo':'erro','motivo':'nome de grupo inválido'}, trava)
                        continue
                    with self.lock:
                        if grupo in self.grupos:
                            erro='grupo já existe'
                        else:
                            self.grupos[grupo]={'criador':nome,'membros':{nome}}
                            erro=None
                    if erro: enviar(conexao,{'tipo':'erro','motivo':erro},trava)
                    else: self._notificar_grupos()
                elif tipo == 'grupo_adicionar':
                    grupo, membro = pkt.get('grupo'), pkt.get('usuario')
                    with self.lock:
                        g=self.grupos.get(grupo) if isinstance(grupo,str) else None
                        if not g or g['criador']!=nome: erro='somente o criador pode adicionar membros'
                        elif membro not in self.clientes: erro='usuário não está conectado'
                        else:
                            g['membros'].add(membro)
                            erro=None
                    if erro: enviar(conexao,{'tipo':'erro','motivo':erro},trava)
                    else: self._notificar_grupos()
                elif tipo == 'grupo_sair':
                    grupo=pkt.get('grupo')
                    with self.lock:
                        g=self.grupos.get(grupo) if isinstance(grupo,str) else None
                        if not g or nome not in g['membros']: erro='não participa do grupo'
                        else:
                            g['membros'].discard(nome)
                            if g['criador']==nome or not g['membros']:
                                del self.grupos[grupo]
                            erro=None
                    if erro: enviar(conexao,{'tipo':'erro','motivo':erro},trava)
                    else: self._notificar_grupos()
                elif tipo == 'grupo_envio':
                    grupo=pkt.get('grupo')
                    destinatarios=pkt.get('destinatarios')
                    with self.lock:
                        g=self.grupos.get(grupo) if isinstance(grupo,str) else None
                        permitidos=set(g['membros'])-{nome} if g and nome in g['membros'] else None
                    if permitidos is None or not isinstance(destinatarios,list) or not destinatarios or len(destinatarios)>40 or set(destinatarios)!=permitidos:
                        enviar(conexao,{'tipo':'erro','motivo':'destinatários de grupo inválidos'},trava)
                        continue
                    enviar(conexao,{'tipo':'grupo_validado','grupo':grupo,'membros':sorted(permitidos)},trava)
                elif tipo == 'relay':
                    destino = pkt.get('para')
                    conteudo = pkt.get('conteudo')
                    grupo_relay = pkt.get('grupo')
                    if not isinstance(destino, str) or not isinstance(conteudo, dict) or conteudo.get('tipo') not in ('dh_inicio','dh_resposta','confirmacao','cifra','ack'):
                        enviar(conexao, {'tipo':'erro','motivo':'encaminhamento inválido'}, trava)
                        continue
                    if grupo_relay is not None:
                        with self.lock:
                            g=self.grupos.get(grupo_relay) if isinstance(grupo_relay,str) else None
                            autorizado=bool(g and nome in g['membros'] and destino in g['membros'] and nome != destino and conteudo.get('tipo')=='cifra')
                        if not autorizado:
                            enviar(conexao,{'tipo':'erro','motivo':'envio de grupo não autorizado'},trava)
                            continue
                    envelope={'tipo':'relay','de':nome,'conteudo':conteudo}
                    if grupo_relay is not None: envelope['grupo']=grupo_relay
                    if not self.enviar_para(destino, envelope):
                        enviar(conexao, {'tipo':'erro','motivo':f'destinatário {destino} indisponível'}, trava)
                    else:
                        print(f'[RELAY] {nome} -> {destino}: {conteudo["tipo"]} (somente dados públicos/cifrados)', flush=True)
                else:
                    enviar(conexao, {'tipo':'erro','motivo':'comando desconhecido'}, trava)
        except (ConnectionError, OSError, ValueError, UnicodeError):
            pass
        finally:
            if nome:
                with self.lock:
                    if self.clientes.get(nome, (None,))[0] is conexao:
                        del self.clientes[nome]
                        self.ultimo_pong.pop(nome, None)
                self._publicar_presenca()
                self._notificar_grupos()
                print(f'[SAÍDA] {nome}', flush=True)
            conexao.close()


def main():
    host = input('Interface [127.0.0.1]: ').strip() or '127.0.0.1'
    porta = int(input('Porta [5000]: ').strip() or 5000)
    if not contas.carregar():
        print('[AVISO] Nenhuma conta cadastrada. Execute python contas.py NOME antes de conectar clientes.')
    Servidor(host, porta).iniciar()

if __name__ == '__main__':
    main()
