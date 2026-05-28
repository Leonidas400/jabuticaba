import requests
import json

def fetch_firewall_swagger(url: str) -> str:
    """
    Ferramenta para baixar e expor o conteúdo bruto de uma documentação de API (Swagger/OpenAPI).
    Entrada: Apenas a URL direta para o arquivo .json ou .yaml.
    """
    try:
        # Headers simulando um navegador para evitar bloqueios de segurança do distribuidor
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/yaml, */*"
        }
        
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # Tenta carregar como JSON para validar a estrutura
        try:
            data = response.json()
            # Retorna o JSON minificado para economizar a janela de contexto (tokens) do OpenCode
            return json.dumps(data, separators=(',', ':'))
        except ValueError:
            # Se a resposta for um YAML, retorna o texto bruto
            return response.text
            
    except requests.exceptions.RequestException as e:
        return f"Falha ao obter a documentação na URL informada. Erro: {str(e)}"
