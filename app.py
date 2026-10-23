"""Menu principal da arquitetura cliente-servidor."""
from cliente import main as iniciar_cliente
from servidor import main as iniciar_servidor


def main():
    while True:
        print('\n=== Chat RC4 | cliente-servidor ===')
        print('[1] Iniciar servidor independente')
        print('[2] Abrir cliente (Alice, Bob etc.)')
        print('[3] Executar testes criptográficos')
        print('[0] Sair')
        escolha=input('> ').strip()
        if escolha=='1': iniciar_servidor()
        elif escolha=='2': iniciar_cliente()
        elif escolha=='3':
            import testes
            testes.rodar()
        elif escolha=='0': return
        else: print('Opção inválida')

if __name__=='__main__':
    main()
