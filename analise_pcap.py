"""
Analisador de tráfego capturado (mitm_capture.pcap) para câmeras IP.
Realiza as seguintes análises:
- Busca por credenciais em texto claro (HTTP, RTSP, FTP, Telnet)
- Identificação de protocolos utilizados
- Extração de URLs e comandos
- Estatísticas de tráfego
- Sugestão de reconstrução de vídeo RTSP
- Salva última informação de gateway e nome da rede analisada

Uso: python analise_pcap.py [arquivo_pcap]
"""

import sys
from scapy.all import rdpcap, TCP, UDP, Raw
from collections import Counter
import re

import json
import os

# Protocolos e portas comuns
PROTO_PORTS = {
    'HTTP': 80,
    'RTSP': 554,
    'FTP': 21,
    'TELNET': 23,
    'ONVIF': 80,  # ONVIF geralmente usa HTTP
    'HTTPS': 443
}

# Regex para possíveis credenciais
CRED_REGEX = re.compile(rb'(Authorization: Basic [A-Za-z0-9+/=]+|login=\w+|senha=\w+|password=\w+|passwd=\w+|user=\w+)', re.I)


def print_banner():
    print("\n=== Análise de Tráfego MITM (PCAP) ===\n")

def get_proto(pkt):
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        return None
    for proto, port in PROTO_PORTS.items():
        if sport == port or dport == port:
            return proto
    return None

def main():

    print_banner()
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "mitm_capture.pcap"
    print(f"[INFO] Lendo arquivo: {pcap_file}")
    pkts = rdpcap(pcap_file)
    print(f"[INFO] Total de pacotes: {len(pkts)}")

    proto_counter = Counter()
    credenciais = set()
    urls = set()
    comandos = set()
    ips = set()

    # Para salvar info de gateway e nome da rede
    gateway_ip = None
    network_name = None

    for pkt in pkts:
        # Contagem de protocolos
        proto = get_proto(pkt)
        if proto:
            proto_counter[proto] += 1
        # Coleta de IPs
        if hasattr(pkt, 'src') and hasattr(pkt, 'dst'):
            ips.add(pkt.src)
            ips.add(pkt.dst)
        # Busca por credenciais, URLs e dados HTTP em texto claro
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            # Credenciais
            for m in CRED_REGEX.findall(payload):
                credenciais.add(m.decode(errors='ignore'))
            # URLs
            for url in re.findall(rb'(GET|POST|OPTIONS) (.+?) HTTP', payload):
                urls.add(url[1].decode(errors='ignore'))
            # Comandos RTSP
            for cmd in re.findall(rb'(DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN) rtsp://(.+?) ', payload):
                comandos.add(f"{cmd[0].decode()} rtsp://{cmd[1].decode()}")
            # HTTP puro: busca headers, corpo e possíveis dados sensíveis
            if b'HTTP/' in payload:
                try:
                    http_text = payload.decode(errors='ignore')
                    print('\n[HTTP TEXTO PURO DETECTADO]')
                    print(http_text)
                    # Busca por Authorization, Cookie, Basic Auth, etc
                    for line in http_text.splitlines():
                        if any(x in line.lower() for x in ['authorization', 'cookie', 'set-cookie', 'basic', 'token', 'password', 'senha', 'user', 'login']):
                            print('[Possível dado sensível]:', line)
                except Exception:
                    pass
            # Busca por base64 fácil (ex: Basic Auth)
            for m in re.findall(rb'Authorization: Basic ([A-Za-z0-9+/=]+)', payload):
                print('[Authorization Basic detectado]:', m.decode())
            # Gateway: procura por padrões comuns de IP de gateway
            gw_match = re.search(rb'gateway[=: ]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})', payload, re.I)
            if gw_match:
                gateway_ip = gw_match.group(1).decode()
            # Nome da rede: procura por SSID, network name, etc
            net_match = re.search(rb'(SSID|network name|nome da rede)[=: ]+([\w\-\s]+)', payload, re.I)
            if net_match:
                network_name = net_match.group(2).decode(errors='ignore').strip()

    # Se não achou, tenta heurística: gateway = menor IP
    if not gateway_ip and ips:
        try:
            ip_list = [str(ip) for ip in ips if isinstance(ip, (str, bytes))]
            ip_list = [ip.decode() if isinstance(ip, bytes) else ip for ip in ip_list]
            gateway_ip = sorted(ip_list)[0]
        except Exception:
            gateway_ip = None

    # Salva info em arquivo JSON
    info = {}
    if gateway_ip:
        info['gateway'] = gateway_ip
    if network_name:
        info['network_name'] = network_name
    if info:
        try:
            with open(os.path.join(os.path.dirname(__file__), 'ultima_rede.json'), 'w', encoding='utf-8') as f:
                json.dump(info, f, ensure_ascii=False, indent=2)
            print(f"\n[INFO] Última informação de gateway/nome de rede salva em ultima_rede.json: {info}")
        except Exception as e:
            print(f"[ERRO] Não foi possível salvar info de gateway/nome de rede: {e}")

    print("\n[PROTOCOLOS DETECTADOS]")
    for proto, count in proto_counter.items():
        print(f"- {proto}: {count} pacotes")
    print("\n[ENDEREÇOS IP ENVOLVIDOS]")
    for ip in ips:
        print(f"- {ip}")
    print("\n[URLS/REQUISIÇÕES HTTP/RTSP]")
    for url in urls:
        print(f"- {url}")
    print("\n[COMANDOS RTSP DETECTADOS]")
    for cmd in comandos:
        print(f"- {cmd}")
    print("\n[CREDENCIAIS EM TEXTO CLARO ENCONTRADAS]")
    for cred in credenciais:
        print(f"- {cred}")
    print("\n[ESTATÍSTICAS GERAIS]")
    print(f"Total de pacotes: {len(pkts)}")
    print(f"Total de IPs únicos: {len(ips)}")
    print(f"Total de URLs: {len(urls)}")
    print(f"Total de comandos RTSP: {len(comandos)}")
    print(f"Total de credenciais: {len(credenciais)}")
    print("\nSugestão: Para extrair vídeo RTSP, use Wireshark (Follow Stream) ou ferramentas como ffmpeg.")

if __name__ == "__main__":
    import threading
    import time
    import subprocess

    # Função para rodar brute force SSH em paralelo
    def run_brute():
        try:
            # Usa o Python do ambiente virtual ativo
            import sys
            import os
            subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), 'brute.py')])
        except Exception as e:
            print(f"[ERRO] Não foi possível iniciar brute force SSH em paralelo: {e}")

    # Inicia brute force em thread separada
    brute_thread = threading.Thread(target=run_brute, daemon=True)
    brute_thread.start()

    # Aguarda um pouco para garantir que brute force está rodando
    time.sleep(2)

    # Inicia análise do PCAP normalmente
    main()

    # Opcional: aguarda brute force terminar (ou não, pois é daemon)
