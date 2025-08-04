import socket

def main(ip, porta):
    print(f"\n--- Banner Grabbing com Netcat (simulado via socket) ---")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, porta))
        banner = s.recv(1024)
        if banner:
            print(f"Banner recebido: {banner.decode(errors='ignore').strip()}")
        else:
            print("Nenhum banner recebido.")
        s.close()
    except Exception as e:
        print(f"Erro ao conectar: {e}")
    print("\nSugestão: Você pode tentar manualmente: nc {ip} {porta}")
