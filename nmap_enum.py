import subprocess

def main(ip, porta=None):
    print(f"\n--- Varredura Nmap (com scripts NSE) em {ip} ---")
    nmap_cmd = [
        "nmap",
        "-sV",
        "-O",
        "--script",
        "default,vuln,rtsp-methods,http-enum",
        "-p",
        f"22,80,554,50000",
        ip
    ]
    try:
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=300)
        print(result.stdout)
    except FileNotFoundError:
        print("[ERRO] Nmap não encontrado. Instale o nmap e tente novamente.")
    except Exception as e:
        print(f"[ERRO] Falha ao executar o nmap: {e}")
