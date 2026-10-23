"""Cliente de chat ponto a ponto por servidor intermediário.

As chaves privadas, o segredo compartilhado e o estado RC4 nunca vão ao servidor.
Ainda NÃO há autenticação das chaves públicas nem MAC: uso acadêmico demonstrativo.
"""
import json
import secrets
import socket
import threading

import dh
import contas
import integridade
import kdf
import identidades
from log import Log, abreviar
from protocolo import enviar, receber
from rc4 import RC4


class Cliente:
    def __init__(self, nome, modo='didatico', pasta_logs='logs', caminho_identidade=None):
        self.nome = nome
        self.identidades = identidades.carregar(nome,caminho_identidade)
        self.fila = {}
        self.modo = modo
        self.log = Log(nome, pasta=pasta_logs, didatico=(modo == 'didatico'))
        self.sock = None
        self.trava_envio = threading.Lock()
        self.trava_sessoes = threading.RLock()
        self.sessoes = {}
        self.ativo = False
        self.recebidas = []
        self.confirmacoes = []
        self.usuarios_online = []
        self.rejeicoes = []
        self.grupos = {}
        self.recebidas_grupo = []
        self.confirmacoes_grupo = []
        self.pendentes_grupo = {}
        self.evento = threading.Event()

    def conectar(self, host='127.0.0.1', porta=5000, senha=None):
        self.sock = socket.create_connection((host, porta), timeout=5)
        self.sock.settimeout(None)
        enviar(self.sock, {'tipo':'registro','nome':self.nome}, self.trava_envio)
        resposta = receber(self.sock)
        if resposta['tipo']=='desafio_login':
            if not senha:
                self.sock.close()
                raise ValueError('senha de login necessária')
            assinatura=contas.prova(senha,self.nome,resposta['sal'],resposta['iteracoes'],resposta['desafio'])
            enviar(self.sock,{'tipo':'prova_login','prova':assinatura},self.trava_envio)
            resposta=receber(self.sock)
        if resposta['tipo'] != 'registrado':
            raise ValueError(resposta.get('motivo', 'registro rejeitado'))
        self.ativo = True
        self.log.passo('CONEXAO', f'conectado ao servidor {host}:{porta}')
        threading.Thread(target=self._escutar, daemon=True).start()

    def _mandar(self, pacote):
        enviar(self.sock, pacote, self.trava_envio)

    def _relay(self, para, conteudo):
        self._mandar({'tipo':'relay','para':para,'conteudo':conteudo})

    def listar(self):
        self._mandar({'tipo':'listar'})

    def criar_grupo(self, nome):
        self._mandar({'tipo':'grupo_criar','grupo':nome})

    def adicionar_grupo(self, grupo, nome):
        self._mandar({'tipo':'grupo_adicionar','grupo':grupo,'usuario':nome})

    def sair_grupo(self, grupo):
        self._mandar({'tipo':'grupo_sair','grupo':grupo})

    def mensagem_grupo(self, grupo, texto):
        info=self.grupos.get(grupo)
        if not info or self.nome not in info['membros']:
            raise ValueError('você não participa deste grupo')
        destinos=[n for n in info['membros'] if n!=self.nome]
        if not destinos: raise ValueError('grupo sem destinatários')
        if len(texto.encode('utf-8'))>64000: raise ValueError('mensagem de grupo excessiva')
        # Cada destinatário tem sessão RC4 individual e chaves independentes.
        # Conteúdo do grupo fica dentro do texto autenticado, nunca é confiado isoladamente.
        envelope=json.dumps({'__grupo_rc4_v1__':grupo,'texto':texto},ensure_ascii=False,separators=(',',':'))
        for destino in destinos:
            self.mensagem(destino,envelope)
        self.log.passo('GRUPO',f'envio para {grupo}: {len(destinos)} destinatários, canais individuais')
        return destinos

    def iniciar_conversa(self, outro):
        self._chave_par(outro)
        if outro == self.nome:
            raise ValueError('não é possível iniciar conversa consigo mesmo')
        params = dh.DIDATICO if self.modo == 'didatico' else dh.SEGURO
        p,g = params['p'],params['g']
        privada, publica = dh.gerar_chaves(p,g,self.log,tela_detalhe=self.modo=='didatico')
        identificador = secrets.token_hex(12)
        with self.trava_sessoes:
            self.sessoes[outro] = {'papel':'iniciador','id':identificador,'privada':privada,'publica':publica,'p':p,'g':g}
        self.log.passo('ENVIO', f'pedido de DH para {outro} id={identificador} publica={abreviar(publica)}')
        self._relay(outro, {'tipo':'dh_inicio','id':identificador,'modo':self.modo,'pub':format(publica,'x')})

    def _mensagem_relay(self, remetente, dados):
        tipo=dados.get('tipo')
        if tipo == 'dh_inicio':
            self._chave_par(remetente)
            modo=dados.get('modo')
            if modo != self.modo:
                self.log.passo('VALIDA', f'modo divergente de {remetente}, pedido rejeitado')
                return
            params = dh.DIDATICO if modo == 'didatico' else dh.SEGURO
            p,g=params['p'],params['g']
            dh.validar_parametros(modo,p,g,self.log)
            pub_remoto=int(dados['pub'],16)
            dh.validar_publica(pub_remoto,p,self.log)
            identificador=dados['id']
            if not isinstance(identificador,str) or len(identificador)!=24:
                raise ValueError('id DH inválido')
            priv,pub=dh.gerar_chaves(p,g,self.log,tela_detalhe=self.modo=='didatico')
            segredo=dh.segredo(pub_remoto,priv,p,self.log,tela_detalhe=self.modo=='didatico')
            trans = integridade.transcricao(identificador,self.modo,remetente,self.nome,pub_remoto,pub)
            self._estabelecer(remetente,'respondente',identificador,segredo,p,pub,pub_remoto)
            prova = identidades.prova(self._chave_par(remetente),trans,'respondente')
            self.log.passo('ENVIO', f'resposta DH para {remetente}: pública={abreviar(pub)}')
            self._relay(remetente,{'tipo':'dh_resposta','id':identificador,'pub':format(pub,'x'),'prova':prova})
        elif tipo == 'dh_resposta':
            with self.trava_sessoes:
                estado=self.sessoes.get(remetente)
            if not estado or estado['papel']!='iniciador' or estado['id']!=dados.get('id'):
                raise ValueError('resposta DH não solicitada')
            pub_remoto=int(dados['pub'],16)
            dh.validar_publica(pub_remoto,estado['p'],self.log)
            trans=integridade.transcricao(estado['id'],self.modo,self.nome,remetente,estado['publica'],pub_remoto)
            if not identidades.conferir(self._chave_par(remetente),trans,'respondente',dados.get('prova')):
                raise ValueError('prova de identidade do respondente inválida')
            segredo=dh.segredo(pub_remoto,estado['privada'],estado['p'],self.log,tela_detalhe=self.modo=='didatico')
            self._estabelecer(remetente,'iniciador',estado['id'],segredo,estado['p'],estado['publica'],pub_remoto)
            self._enviar_confirmacao(remetente,self.sessoes[remetente])
        elif tipo == 'confirmacao':
            with self.trava_sessoes:
                estado=self._sessao(remetente, dados)
                corpo={'tipo':'confirmacao','id':estado['id'],'papel':dados.get('papel')}
                if 'prova_identidade' in dados:
                    corpo['prova_identidade']=dados['prova_identidade']
                if corpo['papel'] == estado['papel'] or not integridade.verificar(estado['mac_receber'], corpo, dados.get('mac')):
                    raise ValueError('confirmação de sessão inválida')
                if estado['papel']=='respondente':
                    if not identidades.conferir(self._chave_par(remetente),estado['transcricao'],'iniciador',dados.get('prova_identidade')):
                        raise ValueError('prova de identidade do iniciador inválida')
                estado['confirmado_remoto']=True
                if estado['papel']=='respondente' and not estado['confirmado_local']:
                    self._enviar_confirmacao(remetente,estado)
                self.log.passo('AUTENTICA',f'prova criptográfica recebida de {remetente}; código={estado["codigo"]}')
                self._avisar_sessao(remetente,estado)
        elif tipo == 'cifra':
            with self.trava_sessoes:
                estado=self._sessao(remetente, dados)
                if not self._autenticada(estado):
                    raise ValueError('mensagem antes da autenticação')
                corpo={k:dados.get(k) for k in ('tipo','id','seq','hex')}
                if type(corpo['seq']) is not int or corpo['seq'] != estado['seq_receber']:
                    raise ValueError('sequência inesperada/replay')
                if not integridade.verificar(estado['mac_receber'],corpo,dados.get('mac')):
                    raise ValueError('HMAC inválido: mensagem adulterada')
                cifrado=bytes.fromhex(corpo['hex'])
                if len(cifrado)>65536: raise ValueError('mensagem excessiva')
                claro=estado['receber'].processar(cifrado).decode('utf-8')
                estado['seq_receber']+=1
                ack={'tipo':'ack','id':estado['id'],'seq':corpo['seq']}
                ack['mac']=integridade.etiqueta(estado['mac_enviar'],ack)
            try:
                objeto=json.loads(claro)
            except (ValueError,TypeError):
                objeto=None
            if isinstance(objeto,dict) and '__grupo_rc4_v1__' in objeto:
                grupo=objeto['__grupo_rc4_v1__']
                info=self.grupos.get(grupo)
                if not info or remetente not in info['membros'] or self.nome not in info['membros']:
                    raise ValueError('mensagem de grupo com membros não autorizados')
                self.recebidas_grupo.append((grupo,remetente,objeto.get('texto','')))
            else:
                self.recebidas.append((remetente,claro))
            self.log.passo('INTEGRIDADE',f'{remetente}: HMAC válido; seq={corpo["seq"]}')
            self.log.passo('DECIFRA',f'{remetente}: {len(cifrado)} bytes decifrados')
            self._relay(remetente,ack)
            if isinstance(objeto,dict) and '__grupo_rc4_v1__' in objeto:
                print(f'\n[GRUPO {objeto["__grupo_rc4_v1__"]} | {remetente}] {objeto.get("texto","")}\n> ',end='',flush=True)
            else:
                print(f'\n[{remetente}] {claro}\n> ',end='',flush=True)
            self.evento.set()
        elif tipo == 'ack':
            with self.trava_sessoes:
                estado=self._sessao(remetente,dados)
                corpo={k:dados.get(k) for k in ('tipo','id','seq')}
                if type(corpo['seq']) is not int or corpo['seq'] not in estado['pendentes']:
                    raise ValueError('ACK não solicitado ou repetido')
                if not integridade.verificar(estado['mac_receber'],corpo,dados.get('mac')):
                    raise ValueError('HMAC de ACK inválido')
                estado['pendentes'].remove(corpo['seq'])
            self.confirmacoes.append((remetente,corpo['seq']))
            self.log.passo('ACK',f'{remetente} confirmou recebimento da mensagem seq={corpo["seq"]}')
            self.evento.set()

    def _estabelecer(self, outro, papel, identificador, segredo, p, pub_local, pub_remota):
        nomes=(self.nome,outro) if papel=='iniciador' else (outro,self.nome)
        pub_inic,pub_resp=(pub_local,pub_remota) if papel=='iniciador' else (pub_remota,pub_local)
        transcricao=integridade.transcricao(identificador,self.modo,nomes[0],nomes[1],pub_inic,pub_resp)
        # Chaves vinculadas à transcrição autenticada: sessão, papéis, modo e públicas DH.
        contexto=kdf.contexto_sessao(transcricao)
        ch_inic,ch_resp=kdf.derivar(segredo,p,self.log,contexto=contexto)
        mac_inic,mac_resp=kdf.derivar_autenticacao(segredo,p,contexto)
        envio,receb=(ch_inic,ch_resp) if papel=='iniciador' else (ch_resp,ch_inic)
        mac_env,mac_rec=(mac_inic,mac_resp) if papel=='iniciador' else (mac_resp,mac_inic)
        with self.trava_sessoes:
            self.sessoes[outro]={'papel':papel,'id':identificador,'enviar':RC4(envio,self.log,nome=f'{self.nome}->{outro}'),
                                 'receber':RC4(receb,self.log,nome=f'{outro}->{self.nome}'),
                                 'mac_enviar':mac_env,'mac_receber':mac_rec,'seq_enviar':0,'seq_receber':0,
                                 'pendentes':set(),'transcricao':transcricao,'contexto':contexto,'codigo':integridade.codigo_verificacao(transcricao),
                                 'confirmado_local':False,'confirmado_remoto':False}
        self.log.passo('SESSAO',f'DH calculado com {outro}; impressão digital pública={integridade.codigo_verificacao(transcricao)}')
        self.log.passo('IDENTIDADE',f'credencial previamente confiável encontrada para {outro}; confirmação automática pendente')
        self.evento.set()

    def _sessao(self, outro, dados):
        estado=self.sessoes.get(outro)
        if not estado or 'receber' not in estado or dados.get('id')!=estado['id']:
            raise ValueError('pacote sem sessão estabelecida')
        return estado

    def _autenticada(self,estado):
        return estado['confirmado_local'] and estado['confirmado_remoto']

    def _avisar_sessao(self,outro,estado):
        if self._autenticada(estado):
            self.log.passo('AUTENTICA',f'sessão com {outro}: identidade pré-compartilhada e segredo confirmados automaticamente')
            print(f'\n[SESSÃO AUTENTICADA] {outro}: mensagens liberadas.\n> ',end='',flush=True)
            self.evento.set()
            pendentes=self.fila.pop(outro,[])
            for mensagem in pendentes:
                self._enviar_mensagem(outro,mensagem)

    def _chave_par(self,outro):
        chave=self.identidades.get(outro)
        if chave is None:
            raise ValueError(f'identidade não provisionada para {outro}')
        return chave

    def _enviar_confirmacao(self,outro,estado):
        corpo={'tipo':'confirmacao','id':estado['id'],'papel':estado['papel']}
        if estado['papel']=='iniciador':
            corpo['prova_identidade']=identidades.prova(self._chave_par(outro),estado['transcricao'],'iniciador')
        corpo['mac']=integridade.etiqueta(estado['mac_enviar'],corpo)
        estado['confirmado_local']=True
        self._relay(outro,corpo)
        self.log.passo('KEYCONF',f'prova automática de posse do segredo enviada para {outro}')

    def mensagem(self,outro,texto):
        self._chave_par(outro)
        if len(texto.encode('utf-8'))>65536: raise ValueError('mensagem excessiva')
        with self.trava_sessoes:
            estado=self.sessoes.get(outro)
            if not estado or 'enviar' not in estado or not self._autenticada(estado):
                self.fila.setdefault(outro,[]).append(texto)
                self.log.passo('FILA',f'mensagem para {outro} aguardando sessão autenticada')
                if not estado:
                    self.iniciar_conversa(outro)
                return
            self._enviar_mensagem(outro,texto)

    def _enviar_mensagem(self,outro,texto):
        estado=self.sessoes[outro]
        if not self._autenticada(estado):
            raise ValueError('sessão não autenticada')
        seq=estado['seq_enviar']
        cifrado=estado['enviar'].processar(texto.encode('utf-8'))
        corpo={'tipo':'cifra','id':estado['id'],'seq':seq,'hex':cifrado.hex()}
        corpo['mac']=integridade.etiqueta(estado['mac_enviar'],corpo)
        estado['seq_enviar']+=1
        estado['pendentes'].add(seq)
        self.log.passo('CIFRA',f'{outro}: seq={seq}, {len(cifrado)} bytes, HMAC-SHA256')
        grupo=None
        try:
            envelope=json.loads(texto)
            if isinstance(envelope,dict): grupo=envelope.get('__grupo_rc4_v1__')
        except (ValueError,TypeError): pass
        if grupo is not None:
            self._mandar({'tipo':'relay','para':outro,'grupo':grupo,'conteudo':corpo})
        else:
            self._relay(outro,corpo)

    def _escutar(self):
        while self.ativo:
            try:
                pacote=receber(self.sock)
                if pacote['tipo']=='relay':
                    self._mensagem_relay(pacote['de'],pacote['conteudo'])
                elif pacote['tipo']=='grupos':
                    self.grupos=pacote.get('salas',{})
                    self.evento.set()
                elif pacote['tipo']=='grupo_validado':
                    self.log.passo('GRUPO',f'servidor confirmou lista de membros: {pacote["grupo"]}')
                elif pacote['tipo']=='ping':
                    self._mandar({'tipo':'pong'})
                elif pacote['tipo'] in ('usuarios', 'presenca'):
                    self.usuarios_online = list(pacote['nomes'])
                    if pacote['tipo']=='usuarios':
                        print('\n[ONLINE] '+', '.join(pacote['nomes'])+'\n> ',end='',flush=True)
                    else:
                        self.log.passo('PRESENCA',f'usuários disponíveis: {", ".join(pacote["nomes"])}')
                    self.evento.set()
                elif pacote['tipo']=='erro':
                    print('\n[ERRO] '+pacote['motivo']+'\n> ',end='',flush=True)
            except (OSError,ConnectionError):
                break
            except (ValueError,KeyError,TypeError,UnicodeError) as exc:
                self.rejeicoes.append(str(exc))
                self.log.passo('ERRO',f'pacote rejeitado: {exc}')
                self.evento.set()
        self.ativo=False
        self.evento.set()
        print('\n[DESCONECTADO do servidor]',flush=True)

    def fechar(self):
        self.ativo=False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
        self.log.fechar()


def main():
    nome=input('Nome do usuário: ').strip()
    modo='didatico' if input('Modo [1] didático [2] seguro: ').strip()=='1' else 'seguro'
    host=input('Servidor [127.0.0.1]: ').strip() or '127.0.0.1'
    porta=int(input('Porta [5000]: ').strip() or 5000)
    import getpass
    senha=getpass.getpass('Senha de login: ')
    cliente=Cliente(nome,modo)
    try:
        cliente.conectar(host,porta,senha)
        print('Comandos: /online, /conversar NOME, /msg NOME TEXTO, /log, /sair')
        while cliente.ativo:
            cmd=input('> ').strip()
            try:
                if cmd=='/sair': break
                elif cmd=='/online': cliente.listar()
                elif cmd.startswith('/conversar '): cliente.iniciar_conversa(cmd.split(' ',1)[1].strip())
                elif cmd.startswith('/msg '):
                    _, destinatario, texto=cmd.split(' ',2)
                    cliente.mensagem(destinatario,texto)
                elif cmd=='/log': print(cliente.log.caminho)
                elif cmd: print('Comando desconhecido')
            except ValueError as exc:
                print('Erro:',exc)
    finally:
        cliente.fechar()

if __name__=='__main__':
    main()
