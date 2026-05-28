"""
api_runner.py — Generic evaluator for DB-driven API checks.

Operators supported:
  is_true        — value is truthy (True, 1, "enable", "enabled", "yes", "true")
  is_false       — value is falsy or absent
  lte            — int(value) <= int(expected_value)
  gte            — int(value) >= int(expected_value)
  str_eq         — str(value).lower() == expected_value.lower()
  list_not_empty — value is a non-empty list
  handler        — fully handled by Python handler_key function

json_path: dot-notation relative to the endpoint's fetched data.
  e.g. "gateway_antivirus.enable" traverses data["gav"]["gateway_antivirus"]["enable"]
  Hyphens and underscores are tried as-is.
"""

"""
api_runner.py — Generic evaluator for DB-driven API checks.
"""

from database import api_checks_get_active

# ─────────────────────────────────────────────────────────────
# DEEP ACCESS & FUZZY MATCHING
# ─────────────────────────────────────────────────────────────
def _get_path(obj, path: str):
    """Traverse obj by dot-notation path with fuzzy matching (- vs _) and auto-unwrapping."""
    if not path or obj is None:
        return obj, True
    parts = path.split(".")
    cur = obj

    def _get_k(d, k):
        if not isinstance(d, dict): return None, False
        if k in d: return d[k], True
        if k.replace('_', '-') in d: return d[k.replace('_', '-')], True
        if k.replace('-', '_') in d: return d[k.replace('-', '_')], True
        return None, False

    def _search_first(d, k, depth=0):
        """Recursively search for the first key to bypass unpredictable API wrappers."""
        if depth > 3 or not isinstance(d, dict): return None, False
        v, f = _get_k(d, k)
        if f: return v, True
        for dv in d.values():
            if isinstance(dv, dict):
                v2, f2 = _search_first(dv, k, depth+1)
                if f2: return v2, True
        return None, False

    # 1. Encontra a primeira parte do caminho em qualquer lugar (ignora wrappers como "status", "system")
    v, found = _search_first(cur, parts[0])
    if not found:
        return None, False
    
    cur = v

    # 2. Continua a travessia estritamente para o resto do caminho
    for p in parts[1:]:
        if not isinstance(cur, dict):
            return None, False
        v, found = _get_k(cur, p)
        if found:
            cur = v
        else:
            return None, False
            
    return cur, True


def _truthy(v) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    if isinstance(v, str):
        return v.lower() in ("true", "1", "enable", "enabled", "yes", "on")
    return bool(v)


# ─────────────────────────────────────────────────────────────
# SINGLE CHECK EVALUATOR
# ─────────────────────────────────────────────────────────────
def evaluate_check(check: dict, data: dict) -> dict:
    endpoint = check.get("api_endpoint", "")
    json_path = check.get("json_path", "")
    operator = check.get("operator", "handler")
    expected = check.get("expected_value", "")

    endpoint_data = data.get(endpoint)

    passed = False
    cur_val = "—"
    detail = "Não avaliado"

    try:
        if operator == "is_true":
            val, found = _get_path(endpoint_data, json_path)
            passed = _truthy(val)
            cur_val = str(val) if val is not None else "ausente"
            detail = "Habilitado ✓" if passed else "Não habilitado"

        elif operator == "is_false":
            val, found = _get_path(endpoint_data, json_path)
            passed = not _truthy(val)
            cur_val = str(val) if val is not None else "ausente"
            detail = "Desabilitado ✓" if passed else "Habilitado — risco!"

        elif operator == "lte":
            val, found = _get_path(endpoint_data, json_path)
            if val is None:
                passed, cur_val, detail = False, "—", "Valor não encontrado"
            else:
                iv = int(val)
                passed = iv <= int(expected)
                cur_val = str(iv)
                detail = f"Valor: {iv} (máximo: {expected}) {'✓' if passed else '— excede limite'}"

        elif operator == "gte":
            val, found = _get_path(endpoint_data, json_path)
            if val is None:
                passed, cur_val, detail = False, "—", "Valor não encontrado"
            else:
                iv = int(val)
                passed = iv >= int(expected)
                cur_val = str(iv)
                detail = f"Valor: {iv} (mínimo: {expected}) {'✓' if passed else '— abaixo do mínimo'}"

        elif operator == "str_eq":
            val, found = _get_path(endpoint_data, json_path)
            if val is None:
                passed, cur_val, detail = False, "—", "Valor não encontrado"
            else:
                sv = str(val).lower()
                passed = sv == expected.lower()
                cur_val = str(val)
                detail = f"Valor: {val} {'✓' if passed else f'(esperado: {expected})'}"

        elif operator == "list_not_empty":
            lst = endpoint_data if isinstance(endpoint_data, list) else []
            passed = len(lst) > 0
            cur_val = f"{len(lst)} item(s)"
            detail = f"{len(lst)} item(s) configurado(s) {'✓' if passed else ''}" if passed else "Nenhum configurado"

        else:
            return None

    except Exception as e:
        passed, cur_val, detail = False, "—", f"Erro na avaliação: {e}"

    return _result(check, passed, cur_val, detail)


def _result(check: dict, passed: bool, cur_val: str, detail: str) -> dict:
    return {
        "id":             check.get("id"),
        "cid":            check["cid"],
        "title":          check["title"],
        "category":       check["category"],
        "severity":       check["severity"],
        "description":    check.get("description",""),
        "recommendation": check.get("recommendation",""),
        "status":         "PASS" if passed else "FAIL",
        "detail":         detail,
        "current_value":  str(cur_val) if cur_val is not None else "—",
        "pattern_type":   "api",
    }

def run_db_checks(vendor_slug: str, data: dict, handlers: dict) -> list:
    checks_def = api_checks_get_active(vendor_slug)
    results = []

    for chk in checks_def:
        operator = chk.get("operator", "handler")

        if operator == "handler":
            hkey = chk.get("handler_key", "")
            fn = handlers.get(hkey)
            if fn is None:
                results.append(_result(chk, False, "—", f"Handler '{hkey}' não registrado"))
                continue
            try:
                out = fn(chk, data)
                if out is None: continue
                if isinstance(out, list): results.extend(out)
                else: results.append(out)
            except Exception as e:
                results.append(_result(chk, False, "—", f"Erro no handler: {e}"))
        else:
            r = evaluate_check(chk, data)
            if r is not None:
                results.append(r)

    return results