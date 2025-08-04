import os
import sys
import platform
import subprocess
from collections import Counter

"""
Script: mitm_detection.py
Descrição: Detecta possíveis ataques Man-in-the-Middle (MitM) na rede local analisando o ARP table.
Funciona em Windows e Linux.
"""

def get_arp_table():
    if platform.system() == "Windows":
        output = subprocess.check_output("arp -a", shell=True, encoding="utf-8")
    else:
        output = subprocess.check_output(["arp", "-a"], encoding="utf-8")
    return output

def parse_arp_table(arp_output):
    macs = []
    for line in arp_output.splitlines():
        if platform.system() == "Windows":
            if "dinâmico" in line or "dynamic" in line:
                parts = line.split()
                if len(parts) >= 2:
                    macs.append(parts[1].lower())
        else:
            if "at" in line:
                parts = line.split()
                if len(parts) >= 4:
                    macs.append(parts[3].lower())
    return macs

def detect_mitm(macs):
    counter = Counter(macs)
    suspects = [mac for mac, count in counter.items() if count > 1]
    if suspects:
        print("[ALERTA] Possível ataque Man-in-the-Middle detectado!")
        for mac in suspects:
            print(f"MAC duplicado: {mac} - {counter[mac]} ocorrências")
    else:
        print("Nenhum ataque MitM detectado na tabela ARP.")

def main():
    print("--- Detecção de Man-in-the-Middle (MitM) via ARP ---")
    arp_output = get_arp_table()
    macs = parse_arp_table(arp_output)
    detect_mitm(macs)

if __name__ == "__main__":
    main()
