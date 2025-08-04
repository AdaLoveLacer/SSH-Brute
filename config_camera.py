

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


PACOTE_LIMITE_DEFAULT = 10
global PACOTE_LIMITE
PACOTE_LIMITE = PACOTE_LIMITE_DEFAULT

def menu():
    global PACOTE_LIMITE
    print("\nEscolha a função desejada:")
    print("1 - Força bruta SSH")
    print("2 - Busca de exploits públicos")
    print("3 - Análise de firmware")
    print("4 - Capturar informações das portas 554/50000")
    print("5 - Ataque Man-in-the-Middle (MITM) ARP Spoofing [Requer administrador]")
    print(f"6 - Definir limite de pacotes do MITM (atual: {PACOTE_LIMITE})")
    print("7 - Floodar câmera e analisar tráfego (DoS/teste de bugs)")
    print("0 - Sair")
    return input("Opção: ").strip()


def executar_mitm_arp(ip):
    global PACOTE_LIMITE
    print("\n--- MITM ARP Spoofing ---")
    print("[IMPORTANTE] Rode este script como administrador/root!")
    # Detecta gateway padrão automaticamente (usando psutil, multiplataforma)
    gateway_ip_default = "192.168.18.1"
    try:
        import psutil
        gws = psutil.net_if_addrs()
        # psutil não retorna gateway diretamente, então usamos net_if_stats + net_if_addrs
        # Melhor abordagem: usar psutil.net_if_stats para pegar interfaces up, depois pegar gateway via net_if_addrs
        # Mas para gateway, o ideal é usar psutil.net_if_stats + psutil.net_if_addrs + psutil.net_connections
        # Porém, para gateway padrão, psutil não tem API direta, então usamos uma abordagem por conexões
        gws_conn = [c for c in psutil.net_connections(kind='inet') if c.raddr and c.status == psutil.CONN_ESTABLISHED]
        if gws_conn:
            # Pega o primeiro IP remoto de uma conexão estabelecida
            gateway_ip_default = gws_conn[0].raddr.ip
    except Exception:
        pass
    print(f"Gateway padrão detectado: {gateway_ip_default}")
    alterar_gateway = input("Deseja alterar o IP do gateway/roteador? (s/N): ").strip().lower()
    if alterar_gateway == 's':
        gateway_ip = input("Digite o novo IP do gateway/roteador: ").strip()
        if not gateway_ip:
            gateway_ip = gateway_ip_default
    else:
        gateway_ip = gateway_ip_default
    # Detecta interface de rede automaticamente (preferencialmente a que está conectada ao gateway)
    iface = None
    try:
        import psutil
        # Tenta encontrar a interface usada para o gateway detectado
        gw_ip = gateway_ip_default
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2 and addr.address and addr.address != '127.0.0.1':
                    # Verifica se a interface tem IP na mesma sub-rede do gateway
                    if gw_ip.startswith(addr.address.rsplit('.', 1)[0]):
                        iface = name
                        break
            if iface:
                break
        if not iface:
            # Se não encontrou, pega a primeira interface up e não loopback
            for name, stats in psutil.net_if_stats().items():
                if stats.isup and not name.lower().startswith('lo'):
                    iface = name
                    break
    except Exception:
        pass
    if iface:
        print(f"Interface de rede detectada: {iface}")
        iface_input = input(f"Interface de rede [{iface}]: ").strip()
        if iface_input:
            iface = iface_input
    else:
        iface = input("Interface de rede (ex: eth0, wlan0): ").strip()
    # Permite MAC manual
    mac_camera = input(f"MAC da câmera ({ip}) [Enter para tentar automático]: ").strip()
    mac_gateway = input(f"MAC do gateway ({gateway_ip}) [Enter para tentar automático]: ").strip()
    try:
        import mitm_arp_spoof
        print(f"[DEBUG] MAC camera digitado: {mac_camera}")
        print(f"[DEBUG] MAC gateway digitado: {mac_gateway}")
        if hasattr(mitm_arp_spoof, 'mitm_attack'):
            # Passa os MACs manualmente via variável global
            if mac_camera or mac_gateway:
                if not hasattr(mitm_arp_spoof, 'MANUAL_MACS'):
                    mitm_arp_spoof.MANUAL_MACS = {}
                if mac_camera:
                    mitm_arp_spoof.MANUAL_MACS[ip] = mac_camera.lower()
                if mac_gateway:
                    mitm_arp_spoof.MANUAL_MACS[gateway_ip] = mac_gateway.lower()
                print(f"[DEBUG] MANUAL_MACS enviado: {mitm_arp_spoof.MANUAL_MACS}")
            # Passa o limite de pacotes via variável global
            mitm_arp_spoof.PACOTE_LIMITE = PACOTE_LIMITE
            mitm_arp_spoof.mitm_attack(ip, gateway_ip, iface)
        else:
            print("Função mitm_attack não encontrada no módulo mitm_arp_spoof.")
    except Exception as e:
        import traceback
        print(f"[ERRO] Não foi possível executar o ataque MITM: {e}")
        print(traceback.format_exc())
    perguntar_outra_acao()

def executar_bruteforce(ip, porta):
    try:
        import brute
        import os
        # Garante que o wordlist.txt está atualizado e sem duplicatas
        wordlist_path = os.path.join(os.path.dirname(__file__), 'wordlist.txt')
        if os.path.exists(wordlist_path):
            combos = set()
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                    user, pwd = line.split(':', 1)
                    combos.add(f"{user.strip()}:{pwd.strip()}")
            # Regrava sem duplicatas
            with open(wordlist_path, 'w', encoding='utf-8') as f:
                for combo in sorted(combos):
                    f.write(combo + '\n')
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

# Nova função: floodar e analisar tráfego
def executar_floodar(ip):
    try:
        import subprocess
        interface = input("Interface de rede para captura [Ethernet]: ").strip()
        if not interface:
            interface = "Ethernet"
        subprocess.run(["python", "flodar.py", ip, interface])
    except Exception as e:
        print(f"[ERRO] Não foi possível executar o flood: {e}")
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
        elif opcao == '5':
            executar_mitm_arp(ip)
        elif opcao == '6':
            try:
                novo_limite = input(f"Digite o novo limite de pacotes para o MITM (atual: {PACOTE_LIMITE}): ").strip()
                if novo_limite.isdigit() and int(novo_limite) > 0:
                    PACOTE_LIMITE = int(novo_limite)
                    print(f"Novo limite definido: {PACOTE_LIMITE}")
                else:
                    print("Valor inválido. O limite deve ser um número inteiro positivo.")
            except Exception:
                print("Erro ao definir o limite.")
        elif opcao == '7':
            executar_floodar(ip)
        elif opcao == '0':
            print("Saindo...")
            break
        else:
            print("Opção inválida.")
