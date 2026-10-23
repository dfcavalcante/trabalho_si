"""Interface WEB LOCAL para Cliente RC4. Não move criptografia para o servidor central.

Iniciar: python web_app.py --usuario Alice --porta 8001
Cada usuário exige seu próprio processo/porta/arquivo de credenciais.
"""
import argparse
import asyncio
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, WebSocket, WebSocketDisconnect, Request, Response, Cookie
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from cliente import Cliente
import identidades

BASE = Path(__file__).resolve().parent

class Login(BaseModel):
    usuario: str
    senha: str

class Mensagem(BaseModel):
    para: str = Field(min_length=1, max_length=24, pattern=r'^[A-Za-z0-9]+$')
    texto: str = Field(min_length=1, max_length=65536)

class GrupoCriar(BaseModel):
    grupo: str = Field(min_length=1,max_length=32,pattern=r'^[A-Za-z0-9_]+$')

class GrupoAdicionar(GrupoCriar):
    usuario: str = Field(min_length=1,max_length=24,pattern=r'^[A-Za-z0-9]+$')

class GrupoMensagem(GrupoCriar):
    texto: str = Field(min_length=1,max_length=64000)

class PonteWeb:
    def __init__(self, usuario, modo, host, porta, identidade, senha_auto=None):
        self.nome, self.modo, self.identidade = usuario, modo, identidade
        self.senha_auto = senha_auto  # definida: entra sozinho, sem tela de login
        self.saiu = False  # logout explícito pausa a reconexão automática
        self.cliente = None
        self.login_lock = threading.RLock()
        self.tokens = {}
        self.host, self.porta = host, porta
        self.proximo_recebido = 0
        self.proximo_ack = 0
        self.proximo_grupo = 0
        self.proximo_erro = 0
        self.log_offset = 0
        self.eventos = []
        self.sequencia = 0
        self._mutex_thread = __import__('threading').RLock()

    def conectar(self, senha):
        """Login no servidor (desafio-resposta); devolve um token novo para o navegador."""
        with self.login_lock:
            if self.cliente is not None and self.cliente.ativo:
                raise RuntimeError('já existe sessão ativa nesta instância')
            c=Cliente(self.nome,self.modo,caminho_identidade=self.identidade)
            try:
                c.conectar(self.host,self.porta,senha)
                c.listar()
            except Exception:
                try: c.fechar()
                except Exception: pass
                raise
            self.cliente=c
            self.saiu=False
            self.proximo_recebido=self.proximo_ack=self.proximo_grupo=self.proximo_erro=0
            self.log_offset=0
            self.eventos=[]
            self.sequencia=0
            # No modo automático o navegador já recebeu token ao abrir a página; não invalidar.
            if not self.senha_auto: self.tokens.clear()
            return self.novo_token()

    def novo_token(self):
        with self.login_lock:
            token=secrets.token_urlsafe(32)
            self.tokens[token]=True
            return token

    def manter_conectado(self, intervalo=2.0):
        """Entrada automática: conecta assim que o servidor responder e reconecta se cair."""
        avisado=False
        while True:
            c=self.cliente
            if not self.saiu and (c is None or not c.ativo):
                try:
                    self.conectar(self.senha_auto)
                    print(f'[CONECTADO] {self.nome} entrou automaticamente no servidor {self.host}:{self.porta}',flush=True)
                    avisado=False
                except Exception as exc:
                    if not avisado:
                        print(f'[AGUARDANDO] servidor indisponível ou login recusado ({exc}); tentando a cada {intervalo:.0f} s',flush=True)
                        avisado=True
            time.sleep(intervalo)

    def registrar(self, tipo, **dados):
        with self._mutex_thread:
            self.sequencia += 1
            self.eventos.append({'n':self.sequencia, 'tipo':tipo, **dados})
            if len(self.eventos)>1500: self.eventos=self.eventos[-1500:]

    def atualizar(self):
        """Coleta alterações produzidas pelo cliente de rede; não lê chaves."""
        with self._mutex_thread:
            c=self.cliente
            if c is None:
                return {'conectado':False,'usuario':None,'modo':self.modo,'usuarios':[],
                        'grupos':{},'sessoes':{},'ultimo_evento':self.sequencia}
            while self.proximo_recebido<len(c.recebidas):
                de,texto=c.recebidas[self.proximo_recebido]; self.proximo_recebido+=1
                self.registrar('mensagem',de=de,texto=texto)
            while self.proximo_grupo<len(c.recebidas_grupo):
                grupo,de,texto=c.recebidas_grupo[self.proximo_grupo]; self.proximo_grupo+=1
                self.registrar('mensagem_grupo',grupo=grupo,de=de,texto=texto)
            while self.proximo_ack<len(c.confirmacoes):
                de,seq=c.confirmacoes[self.proximo_ack]; self.proximo_ack+=1
                self.registrar('ack',de=de,seq=seq)
            while self.proximo_erro<len(c.rejeicoes):
                motivo=c.rejeicoes[self.proximo_erro]; self.proximo_erro+=1
                self.registrar('erro',motivo=motivo)
            caminho=Path(c.log.caminho)
            if caminho.exists():
                with caminho.open('r',encoding='utf-8') as f:
                    f.seek(self.log_offset)
                    novas=f.readlines()
                    self.log_offset=f.tell()
                for linha in novas:
                    self.registrar('auditoria',linha=linha.rstrip('\n'))
            # O servidor fornece snapshot sob demanda; não significa heartbeat.
            sessoes={}
            with c.trava_sessoes:
                for par,s in c.sessoes.items():
                    sessoes[par]='autenticada' if 'enviar' in s and c._autenticada(s) else 'negociando'
            return {'conectado':c.ativo,'usuario':c.nome,'modo':c.modo,
                    'usuarios':list(c.usuarios_online),'grupos':dict(c.grupos),'sessoes':sessoes,
                    'ultimo_evento':self.sequencia}

    def desde(self, n):
        with self._mutex_thread:
            self.atualizar()
            return [x for x in self.eventos if x['n']>n]


def criar_app(ponte):
    @asynccontextmanager
    async def lifespan(app):
        try: yield
        finally:
            if ponte.cliente: ponte.cliente.fechar()

    app=FastAPI(title='RC4 Chat local', docs_url=None, redoc_url=None, lifespan=lifespan)

    def autenticar(token):
        with ponte.login_lock:
            if not token or token not in ponte.tokens:
                raise HTTPException(401,'faça login para continuar')
            return True

    def exigir_sessao(token, origem=None, host=None):
        autenticar(token)
        if origem is not None and origem not in ('http://'+host,'https://'+host):
            raise HTTPException(403,'origem não autorizada')

    def ativo():
        c=ponte.cliente
        if c is None or not c.ativo: raise HTTPException(503,'cliente desconectado; conectando ao servidor')
        return c

    @app.get('/')
    def home():
        resposta=FileResponse(BASE/'web'/'static'/'index.html')
        if ponte.senha_auto:
            # Entrada automática: a página já abre dentro do chat, sem tela de login.
            ponte.saiu=False
            resposta.set_cookie('rc4_session',ponte.novo_token(),httponly=True,samesite='strict',secure=False,path='/')
        return resposta

    @app.post('/api/login')
    def login(dados:Login, response:Response, request:Request):
        origem=request.headers.get('origin')
        if origem and origem not in ('http://'+request.headers.get('host',''),'https://'+request.headers.get('host','')):
            raise HTTPException(403,'origem não autorizada')
        if dados.usuario!=ponte.nome:
            raise HTTPException(401,'usuário inválido nesta instância')
        try:
            token=ponte.conectar(dados.senha or ponte.senha_auto or '')
        except RuntimeError as exc:
            raise HTTPException(409,str(exc)) from exc
        except Exception as exc:
            raise HTTPException(401,'login não autorizado ou servidor indisponível') from exc
        response.set_cookie('rc4_session',token,httponly=True,samesite='strict',secure=False,path='/')
        return {'autenticado':True,'usuario':ponte.nome}

    @app.post('/api/logout')
    def logout(response:Response,rc4_session:str|None=Cookie(None)):
        autenticar(rc4_session)
        with ponte.login_lock:
            ponte.saiu=True
            ponte.tokens.clear()
            if ponte.cliente: ponte.cliente.fechar()
            ponte.cliente=None
        response.delete_cookie('rc4_session',path='/')
        return {'encerrado':True}

    @app.get('/api/estado')
    def estado(rc4_session:str|None=Cookie(None)):
        autenticar(rc4_session)
        return ponte.atualizar()

    @app.get('/api/eventos')
    def eventos(desde:int=0,rc4_session:str|None=Cookie(None)):
        autenticar(rc4_session)
        return ponte.desde(max(0,desde))

    @app.post('/api/usuarios')
    def usuarios(rc4_session: str|None=Cookie(None)):
        autenticar(rc4_session)
        ativo().listar()
        return {'solicitado':True}

    @app.post('/api/mensagem')
    def mensagem(dados:Mensagem,rc4_session:str|None=Cookie(None)):
        autenticar(rc4_session)
        c=ativo()
        if dados.para==c.nome: raise HTTPException(400,'não pode conversar consigo mesmo')
        if len(dados.texto.encode('utf-8'))>65536: raise HTTPException(400,'mensagem excede 65536 bytes')
        try: c.mensagem(dados.para,dados.texto)
        except (ValueError,OSError) as e: raise HTTPException(400,str(e)) from e
        ponte.registrar('saida',para=dados.para,texto=dados.texto)
        return {'aceita':True,'estado':'aguardando ACK autenticado'}

    @app.post('/api/grupos')
    def grupo_criar(dados:GrupoCriar,rc4_session:str|None=Cookie(None)):
        autenticar(rc4_session)
        ativo().criar_grupo(dados.grupo)
        return {'solicitado':True}

    @app.post('/api/grupos/adicionar')
    def grupo_adicionar(dados:GrupoAdicionar,rc4_session:str|None=Cookie(None)):
        autenticar(rc4_session)
        ativo().adicionar_grupo(dados.grupo,dados.usuario)
        return {'solicitado':True}

    @app.post('/api/grupos/sair')
    def grupo_sair(dados:GrupoCriar,rc4_session:str|None=Cookie(None)):
        autenticar(rc4_session)
        ativo().sair_grupo(dados.grupo)
        return {'solicitado':True}

    @app.post('/api/grupos/mensagem')
    def mensagem_grupo(dados:GrupoMensagem,rc4_session:str|None=Cookie(None)):
        autenticar(rc4_session)
        destinos=ativo().mensagem_grupo(dados.grupo,dados.texto)
        ponte.registrar('saida_grupo',grupo=dados.grupo,texto=dados.texto,destinatarios=destinos)
        return {'aceita':True,'destinatarios':destinos}

    @app.websocket('/ws')
    async def ws(ws:WebSocket):
        origem=ws.headers.get('origin','')
        anfitriao=ws.headers.get('host','')
        token=ws.cookies.get('rc4_session')
        if (not token or token not in ponte.tokens or
            origem not in ('http://'+anfitriao,'https://'+anfitriao)):
            await ws.close(code=1008)
            return
        await ws.accept()
        cursor=0
        try:
            while True:
                if token not in ponte.tokens:
                    await ws.close(code=1008)
                    break
                eventos=ponte.desde(cursor)
                if eventos:
                    cursor=eventos[-1]['n']
                    await ws.send_json({'tipo':'eventos','itens':eventos})
                await ws.send_json({'tipo':'estado','dados':ponte.atualizar()})
                await asyncio.sleep(1)
        except (WebSocketDisconnect,RuntimeError,OSError): pass
    return app


def main():
    parser=argparse.ArgumentParser(description='Interface web local para o chat RC4')
    parser.add_argument('--usuario',required=True)
    parser.add_argument('--modo',choices=['didatico','seguro'],default='didatico')
    parser.add_argument('--porta',type=int,default=8001,help='porta HTTP local da interface')
    parser.add_argument('--servidor',default='127.0.0.1')
    parser.add_argument('--porta-servidor',type=int,default=5000)
    parser.add_argument('--identidade',default=None,help='arquivo de credencial do usuário')
    args=parser.parse_args()
    senha=identidades.senha_login(args.usuario,args.identidade)
    ponte=PonteWeb(args.usuario,args.modo,args.servidor,args.porta_servidor,args.identidade,senha_auto=senha)
    app=criar_app(ponte)
    if senha:
        threading.Thread(target=ponte.manter_conectado,daemon=True).start()
        print(f'Interface de {args.usuario} (entrada automática): http://127.0.0.1:{args.porta}',flush=True)
    else:
        print(f'Interface de {args.usuario} (login obrigatório; sem senha salva, rode python preparar_demo.py): '
              f'http://127.0.0.1:{args.porta}',flush=True)
    uvicorn.run(app,host='127.0.0.1',port=args.porta,log_level='warning')

if __name__=='__main__': main()
