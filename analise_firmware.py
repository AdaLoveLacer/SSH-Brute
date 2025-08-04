import os

# Caminho padrão salvo para o firmware
FIRMWARE_PATH_FILE = os.path.join(os.path.dirname(__file__), 'firmware_path.txt')

def solicitar_firmware_path():
    path = ''
    if os.path.exists(FIRMWARE_PATH_FILE):
        try:
            with open(FIRMWARE_PATH_FILE, 'r', encoding='utf-8') as f:
                path = f.read().strip()
        except Exception:
            pass
    print("\n--- Análise de Firmware ---")
    print(f"Caminho atual do firmware: {path if path else '[não definido]'}")
    novo_path = input("Digite o caminho do firmware (.bin) (Enter para manter): ").strip()
    if novo_path:
        path = novo_path
    if not os.path.exists(path):
        print("Arquivo de firmware não encontrado. Atualize o caminho e tente novamente.")
        return
    # Salva o caminho para uso futuro
    try:
        with open(FIRMWARE_PATH_FILE, 'w', encoding='utf-8') as f:
            f.write(path)
    except Exception:
        pass
    print("\nInstruções para análise de firmware:")
    print("1. Instale o binwalk: pip install binwalk (ou use o instalador do site oficial)")
    print(f"2. Extraia o firmware com: binwalk -e '{path}'")
    print("3. Analise os arquivos extraídos em busca de senhas, scripts suspeitos ou backdoors.")
    print("4. Procure por arquivos como /etc/passwd, /etc/shadow, scripts .sh e binários customizados.")
    # Executa binwalk automaticamente se instalado
    try:
        import binwalk
        print("\nExecutando binwalk...")
        os.system(f"binwalk -e '{path}'")
    except ImportError:
        print("\n[Opcional] Instale o binwalk para extração automática.")

def main():
    solicitar_firmware_path()