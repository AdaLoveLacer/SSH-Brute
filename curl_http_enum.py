import requests

def main(ip, porta=80):
    print(f"\n--- Enumeração HTTP com requests/curl ---")
    url = f"http://{ip}:{porta}/"
    try:
        resp = requests.get(url, timeout=5)
        print(f"Status: {resp.status_code}")
        print("Headers:")
        for k, v in resp.headers.items():
            print(f"  {k}: {v}")
        print("\nPrimeiros 300 caracteres da resposta:")
        print(resp.text[:300])
    except Exception as e:
        print(f"Erro ao conectar: {e}")
    print("\nSugestão: Tente também curl -I {url} ou curl --path-as-is para endpoints específicos.")
