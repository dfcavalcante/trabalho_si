"""Cria credenciais simétricas para um par antes da primeira conversa."""
import sys
from identidades import provisionar_par

if __name__=='__main__':
    if len(sys.argv)!=3:
        print('Uso: python provisionar.py Alice Bob')
        raise SystemExit(2)
    a,b=provisionar_par(sys.argv[1],sys.argv[2]); print('Arquivos gerados:',a,b)
    print('Distribua cada arquivo apenas ao participante correspondente, por um canal confiável.')
