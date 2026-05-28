import base64
import json
import os
import sys
import urllib.parse

input_file = sys.argv[1] if len(sys.argv) > 1 else 'backup_sonic.exp'
output_file = input_file.replace('.exp', '') + '_estruturado.json'

print(f"\nIniciando extração do arquivo: {input_file}")

if not os.path.exists(input_file):
    print(f"ERRO: O arquivo '{input_file}' não foi encontrado.")
    sys.exit(1)

try:
    with open(input_file, 'r', encoding='utf-8') as f:
        encoded_data = f.read()

    print("Decodificando Base64...")
    decoded_bytes = base64.b64decode(encoded_data)
    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')

    pares = decoded_text.split('&')
    config_dict = {}

    for par in pares:
        par = par.strip()
        
        if not par or '=' not in par:
            continue
            
        chave, valor = par.split('=', 1)
        
        chave = urllib.parse.unquote(chave)
        valor = urllib.parse.unquote(valor)
        
        config_dict[chave] = valor

    print("Salvando arquivo...")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(config_dict, f, indent=4, ensure_ascii=False)

    print("-" * 50)
    print(f"Extração Concluída!")
    print(f"O arquivo com os dados foi salvo como: {output_file}")
    print(f"Total de parâmetros extraídos: {len(config_dict)}")
    print("-" * 50)

except Exception as e:
    print(f"Ocorreu um erro inesperado: {e}")