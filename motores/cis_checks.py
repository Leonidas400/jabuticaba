"""
FortiGate CIS Benchmark v1.3.0 — Data-Driven Check Engine
Lê as regras diretamente do SQLite e audita o arquivo de configuração.
"""

import os
import re
import sqlite3
from datetime import datetime

# 1. Pega o caminho absoluto da pasta onde este arquivo (cis_checks.py) está (ou seja, a pasta motores/):
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Aponta direto para o banco de dados dentro dessa mesma pasta motores/
DB_PATH = os.path.join(BASE_DIR, 'cis_rules.db')

SEVERITY_WEIGHT = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1}

CATEGORIES = [
    "System Hardening",
    "Access Control",
    "Network Security",
    "Encryption",
    "Firewall Policy",
    "VPN",
    "Logging & Monitoring",
    "Resilience",
]

def _has(pattern, text):
    return bool(re.search(pattern, text, re.IGNORECASE | re.DOTALL))

def _val(pattern, text, default=None):
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1) if m else default

def _block(name, config):
    if name.lower() == "raw":
        return config
    pattern = rf"config\s+{re.escape(name)}\s([\s\S]*?)(?=\nconfig |\Z)"
    m = re.search(pattern, config, re.IGNORECASE)
    return m.group(1) if m else ""

def check(cid, title, category, severity, description, recommendation, passed, detail=""):
    return {
        "id": cid,
        "title": title,
        "category": category,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "status": "PASS" if passed else "FAIL",
        "detail": detail,
    }

def run_all_checks(config_text):
    results = []

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cis_rules_fortigate ORDER BY cis_id ASC")
        regras_db = cursor.fetchall()
    except Exception as e:
        raise Exception(f"ERRO FATAL DE BANCO: {e} | Caminho procurado: {DB_PATH}")
    finally:
        if 'conn' in locals():
            conn.close()

    for regra in regras_db:
        cid = regra["cis_id"]
        target_text = _block(regra["block"], config_text)
        
        pattern = regra["pattern"]
        expected = regra["expected_value"]
        has_or_not = regra["has_or_not_has"]
        
        passed = False
        detail_msg = regra["detail"]


        if not expected:
            # 1. REGRAS BOOLEANAS (Não espera valor, apenas verifica se a string existe)
            # Suporta o operador '&&' na string do banco para exigir múltiplos padrões (AND)
            if "&&" in pattern:
                sub_patterns = [p.strip() for p in pattern.split("&&")]
                found = all(_has(p, target_text) for p in sub_patterns)
            else:
                found = _has(pattern, target_text)

            passed = found if has_or_not == "has" else not found
            detail_msg += " (Encontrado)" if found else " (Não encontrado)"

        else:
            # 2. REGRAS DE COMPARAÇÃO DE VALOR
            # O pattern DEVE conter um grupo de captura (...), ex: set timeout (\d+)
            extracted_val = _val(pattern, target_text)

            if extracted_val is None:
                passed = False # Falha automática: esperava ler um valor, mas a configuração não existe
                detail_msg += " | Valor não encontrado no arquivo."
            else:
                detail_msg += f" | Valor lido: {extracted_val}"
                expected_str = str(expected).strip()

                # Comparação Numérica Dinâmica (<=, >=, <, >)
                if expected_str.startswith(("<=", ">=", "<", ">")):
                    try:
                        # Extrai apenas os números do expected_value do banco
                        limit = float(re.sub(r'[^\d.]', '', expected_str))
                        curr = float(extracted_val)
                        
                        if expected_str.startswith("<="): passed = curr <= limit
                        elif expected_str.startswith(">="): passed = curr >= limit
                        elif expected_str.startswith("<"): passed = curr < limit
                        elif expected_str.startswith(">"): passed = curr > limit
                    except ValueError:
                        passed = False
                        detail_msg += " | Erro: Falha na conversão numérica."

                # Comparação de Listas (Arrays separados por vírgula)
                elif "," in expected_str:
                    lista = [x.strip().lower() for x in expected_str.split(',')]
                    curr_lower = extracted_val.lower()

                    if has_or_not == "not_has": # Blacklist (ex: hostname padrão)
                        passed = curr_lower not in lista
                    else: # Whitelist (ex: modos HA permitidos)
                        passed = curr_lower in lista
                
                # Comparação Exata de String
                else:
                    if has_or_not == "not_has":
                        passed = extracted_val.lower() != expected_str.lower()
                    else:
                        passed = extracted_val.lower() == expected_str.lower()

        # Salva o resultado
        results.append(check(
            cid=cid,
            title=regra["title"],
            category=regra["categoria"],
            severity=regra["severity"],
            description=regra["description"],
            recommendation=regra["recommendation"],
            passed=passed,
            detail=detail_msg
        ))

    return results

def calculate_risk(results):
    total_w = sum(SEVERITY_WEIGHT[r["severity"]] for r in results)
    fail_w  = sum(SEVERITY_WEIGHT[r["severity"]] for r in results if r["status"] == "FAIL")
    score   = round(100 - (fail_w / total_w * 100)) if total_w else 100

    by_cat = {}
    for cat in CATEGORIES:
        group = [r for r in results if r["category"] == cat]
        if group:
            gw = sum(SEVERITY_WEIGHT[r["severity"]] for r in group)
            gf = sum(SEVERITY_WEIGHT[r["severity"]] for r in group if r["status"] == "FAIL")
            by_cat[cat] = {
                "total": len(group),
                "pass":  sum(1 for r in group if r["status"] == "PASS"),
                "fail":  sum(1 for r in group if r["status"] == "FAIL"),
                "score": round(100 - (gf / gw * 100)) if gw else 100,
            }

    by_sev = {}
    for sev in ["Critical", "High", "Medium", "Low"]:
        g = [r for r in results if r["severity"] == sev]
        by_sev[sev] = {
            "total": len(g),
            "pass":  sum(1 for r in g if r["status"] == "PASS"),
            "fail":  sum(1 for r in g if r["status"] == "FAIL"),
        }

    if score >= 85:
        level, color = "BAIXO",    "#22c55e"
    elif score >= 65:
        level, color = "MÉDIO",    "#f59e0b"
    elif score >= 40:
        level, color = "ALTO",     "#ef4444"
    else:
        level, color = "CRÍTICO",  "#dc2626"

    return {
        "score":        score,
        "risk_level":   level,
        "risk_color":   color,
        "total_checks": len(results),
        "passed":       sum(1 for r in results if r["status"] == "PASS"),
        "failed":       sum(1 for r in results if r["status"] == "FAIL"),
        "by_severity":  by_sev,
        "by_category":  by_cat,
    }