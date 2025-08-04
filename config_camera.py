

"""
Arquivo principal de interação com o usuário.
Solicita as informações da câmera e permite escolher qual função executar:
 - Força bruta SSH
 - Busca de exploits
 - Análise de firmware
"""


import os
import json

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'camera_info.json')

def solicitar_info_camera():
    # Tenta carregar informações salvas
    ip = ''
    porta = 22
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Corrige caso os dados estejam invertidos
                ip_salvo = data.get('ip', '')
                porta_salva = data.get('porta', 22)
                # Se ip_salvo for numérico e porta_salva for string, inverte
                if isinstance(ip_salvo, int) and isinstance(porta_salva, str):
                    ip = porta_salva
                    porta = ip_salvo
                else:
                    ip = ip_salvo
                    porta = porta_salva
        except Exception:
            pass
    print("\n--- Informações da câmera ---")
    print(f"IP atual: {ip if ip else '[não definido]'}")
    print(f"Porta atual: {porta}")
    novo_ip = input("Digite o IP da câmera (Enter para manter): ").strip()
    if novo_ip:
        ip = novo_ip
    nova_porta = input("Digite a porta (padrão 22, Enter para manter): ").strip()
    if nova_porta:
        if nova_porta.isdigit():
            porta = int(nova_porta)
    # Salva as informações
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump({'ip': ip, 'porta': porta}, f)
    except Exception:
        pass
    return ip, porta

def menu():
    print("\nEscolha a função desejada:")
    print("1 - Força bruta SSH")
    print("2 - Busca de exploits públicos")
    print("3 - Análise de firmware")
    print("4 - Capturar informações das portas 554/50000")
    print("0 - Sair")
    return input("Opção: ").strip()

def executar_bruteforce(ip, porta):
    try:
        import brute
        if hasattr(brute, 'main'):
            brute.main(ip, porta)
        else:
            print("\nNenhuma credencial funcionou ou função não implementada.")
    except Exception as e:
        print(f"\n[ERRO] Não foi possível executar o brute force: {e}")
    perguntar_outra_acao()

def executar_busca_exploits(ip, porta):
    try:
        import busca_exploits
        if hasattr(busca_exploits, 'main'):
            busca_exploits.main(ip, porta)
        else:
            print("\nBusca de exploits não implementada corretamente.")
    except Exception as e:
        print(f"\n[ERRO] Não foi possível executar a busca de exploits: {e}")
    perguntar_outra_acao()

def executar_analise_firmware():
    try:
        import analise_firmware
        if hasattr(analise_firmware, 'main'):
            analise_firmware.main()
        else:
            print("\nAnálise de firmware não implementada corretamente.")
    except Exception as e:
        print(f"\n[ERRO] Não foi possível executar a análise de firmware: {e}")
    perguntar_outra_acao()
def perguntar_outra_acao():
    resp = input("\nDeseja tentar outra opção? (s/n): ").strip().lower()
    if resp == 's':
        pass  # O loop principal continuará
    else:
        print("Saindo...")
        exit()

def capturar_info_portas(ip):
    import socket
    import sys
    print(f"\n--- Captura de informações das portas 554 (RTSP) e 50000 ---")
    portas = [554, 50000]
    for porta in portas:
        print(f"\nTestando porta {porta}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip, porta))
            # Tenta receber banner
            try:
                banner = s.recv(1024)
                if banner:
                    print(f"Banner recebido: {banner.decode(errors='ignore').strip()}")
                else:
                    print("Nenhum banner recebido.")
            except Exception:
                print("Não foi possível receber banner.")
            s.close()
        except Exception as e:
            print(f"Porta {porta} fechada ou sem resposta. Detalhe: {e}")
    print("\nSugestão: Para a porta 554 (RTSP), tente abrir o stream em um player como VLC ou ffmpeg.")
    print("Para a porta 50000, tente acessar via navegador ou usar nmap para identificar o serviço.")
    perguntar_outra_acao()

if __name__ == "__main__":
    ip, porta = solicitar_info_camera()
    while True:
        opcao = menu()
        if opcao == '1':
            executar_bruteforce(ip, porta)
        elif opcao == '2':
            executar_busca_exploits(ip, porta)
        elif opcao == '3':
            executar_analise_firmware()
        elif opcao == '4':
            capturar_info_portas(ip)
        elif opcao == '0':
            print("Saindo...")
            break
        else:
            print("Opção inválida.")
