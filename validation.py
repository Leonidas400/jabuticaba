"""
validation.py — Validações para inserção de dados via interface administrativa.

Este módulo contém funções para validar dados antes de inserir no banco,
garantindo consistência e integridade dos checks CIS e endpoints.
"""

from database import api_checks_get_all, endpoints_get_all
from typing import Dict, List, Tuple
import importlib


def _get_vendor_handlers():
    """Dynamically load handlers for all supported vendors."""
    handlers = {}
    vendor_modules = {
        "sonicwall": "sonicwall_api",
        "fortigate": "fortigate_api",
        "pfsense": "pfsense_api",
    }
    for vendor, module_name in vendor_modules.items():
        try:
            module = importlib.import_module(module_name)
            handlers[vendor] = getattr(module, '_HANDLERS', {})
        except ImportError:
            handlers[vendor] = {}
    return handlers


_VENDOR_HANDLERS = _get_vendor_handlers()


def validate_api_check(data: Dict, current_id: int = None) -> Tuple[bool, str]:
    """
    Valida dados de um check CIS antes da inserção ou atualização.

    Args:
        data: Dicionário com dados do check
        current_id: ID do check atual (para edição), ignorado na checagem de duplicidade

    Returns:
        (is_valid, error_message)
    """
    required_fields = ["vendor_slug", "cid", "title", "category", "severity"]
    for field in required_fields:
        if not data.get(field, "").strip():
            return False, f"Campo obrigatório ausente: {field}"

    vendor_slug = data["vendor_slug"].strip()
    cid = data["cid"].strip()

    # Validar vendor_slug
    if vendor_slug not in ["sonicwall", "fortigate", "pfsense"]:
        return False, f"Vendor não suportado: {vendor_slug}"

    # Validar severidade
    valid_severities = ["Critical", "High", "Medium", "Low"]
    if data["severity"] not in valid_severities:
        return False, f"Severidade inválida. Deve ser uma de: {', '.join(valid_severities)}"

    # Validar categoria
    valid_categories = [
        "System Hardening", "Network Security", "Firewall Policy",
        "Logging & Monitoring", "Access Control", "VPN", "Encryption", "Senha e Complexidade"
    ]
    if data["category"] not in valid_categories:
        return False, f"Categoria inválida. Deve ser uma de: {', '.join(valid_categories)}"

    # Verificar unicidade do CID para o vendor
    existing_checks = api_checks_get_all(vendor_slug)
    for check in existing_checks:
        if check["cid"] == cid and check.get("id") != current_id:
            return False, f"CID '{cid}' já existe para o vendor '{vendor_slug}'"

    # Validar operator
    operator = data.get("operator", "handler")
    valid_operators = ["is_true", "is_false", "lte", "gte", "str_eq", "list_not_empty", "handler"]
    if operator not in valid_operators:
        return False, f"Operator inválido. Deve ser uma de: {', '.join(valid_operators)}"

    # Se operator é handler, validar handler_key
    if operator == "handler":
        handler_key = data.get("handler_key", "").strip()
        if not handler_key:
            return False, "handler_key obrigatório quando operator='handler'"

        vendor_handlers = _VENDOR_HANDLERS.get(vendor_slug, {})
        if handler_key not in vendor_handlers:
            available_handlers = list(vendor_handlers.keys())
            return False, f"handler_key '{handler_key}' não existe. Disponíveis: {', '.join(available_handlers)}"

    # Validar json_path se fornecido
    json_path = data.get("json_path", "").strip()
    if json_path and not json_path.replace(".", "").replace("[", "").replace("]", "").replace("_", "").isalnum():
        # Permitir apenas caracteres seguros em json_path
        pass  # Por enquanto, aceitar qualquer string

    return True, ""


def validate_endpoint(data: Dict, current_id: int = None) -> Tuple[bool, str]:
    """
    Valida dados de um endpoint antes da inserção ou atualização.

    Args:
        data: Dicionário com dados do endpoint
        current_id: ID do endpoint atual (para edição), ignorado na checagem de duplicidade

    Returns:
        (is_valid, error_message)
    """
    required_fields = ["vendor_slug", "section_name", "endpoint_path"]
    for field in required_fields:
        if not data.get(field, "").strip():
            return False, f"Campo obrigatório ausente: {field}"

    vendor_slug = data["vendor_slug"].strip()
    endpoint_path = data["endpoint_path"].strip()

    # Validar vendor_slug
    if vendor_slug not in ["sonicwall", "fortigate", "pfsense"]:
        return False, f"Vendor não suportado: {vendor_slug}"

    
    # Verificar unicidade do endpoint_path para o vendor
    existing_endpoints = endpoints_get_all(vendor_slug)
    for endpoint in existing_endpoints:
        if endpoint["endpoint_path"] == endpoint_path and endpoint.get("id") != current_id:
            return False, f"Endpoint '{endpoint_path}' já existe para o vendor '{vendor_slug}'"

    # Validar section_name
    section_name = data["section_name"].strip()
    if len(section_name) < 2:
        return False, "section_name deve ter pelo menos 2 caracteres"

    return True, ""


def validate_bulk_checks(checks_data: List[Dict]) -> Tuple[bool, str]:
    """
    Valida uma lista de checks CIS.

    Args:
        checks_data: Lista de dicionários com dados dos checks

    Returns:
        (is_valid, error_message)
    """
    if not checks_data:
        return False, "Lista de checks vazia"

    seen_cids = set()
    for i, check_data in enumerate(checks_data, 1):
        is_valid, error = validate_api_check(check_data)
        if not is_valid:
            return False, f"Check {i}: {error}"

        cid = check_data["cid"].strip()
        if cid in seen_cids:
            return False, f"Check {i}: CID '{cid}' duplicado na lista"

        seen_cids.add(cid)

    return True, ""


def validate_bulk_endpoints(endpoints_data: List[Dict]) -> Tuple[bool, str]:
    """
    Valida uma lista de endpoints.

    Args:
        endpoints_data: Lista de dicionários com dados dos endpoints

    Returns:
        (is_valid, error_message)
    """
    if not endpoints_data:
        return False, "Lista de endpoints vazia"

    seen_paths = set()
    for i, endpoint_data in enumerate(endpoints_data, 1):
        is_valid, error = validate_endpoint(endpoint_data)
        if not is_valid:
            return False, f"Endpoint {i}: {error}"

        path = endpoint_data["endpoint_path"].strip()
        if path in seen_paths:
            return False, f"Endpoint {i}: endpoint_path '{path}' duplicado na lista"

        seen_paths.add(path)

    return True, ""