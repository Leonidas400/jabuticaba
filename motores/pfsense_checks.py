"""
pfSense Security Benchmark — Data-Driven Check Engine
Lê as regras diretamente do SQLite (cis_rules_pfsense) e audita o config.xml de forma global.
"""

import os
import re
import sqlite3
import xml.etree.ElementTree as ET

# Configura o caminho absoluto para o banco de dados na pasta do script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'cis_rules.db')

SEVERITY_WEIGHT = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1}

CATEGORIES = [
    "System Hardening",
    "Access Control",
    "Network Security",
    "Firewall Policy",
    "VPN",
    "Logging & Monitoring",
    "Services",
    "Resilience",
]

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

def run_pfsense_checks(config_text):
    results = []
    
    # 1. Conexão ao Banco de Dados SQLite
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cis_rules_pfsense ORDER BY cis_id ASC")
        regras_db = cursor.fetchall()
    except Exception as e:
        raise Exception(f"ERRO FATAL DE BANCO: {e} | Caminho procurado: {DB_PATH}")
    finally:
        if 'conn' in locals(): conn.close()

    # 2. Parse do Arquivo XML do pfSense
    raw_text = config_text
    try:
        root = ET.fromstring(raw_text.strip())
    except ET.ParseError:
        root = None # Se falhar, o motor fará fallback apenas para as regras Regex

    # 3. Execução Global do Motor
    for regra in regras_db:
        cid = regra["cis_id"]
        block = regra["block"]
        search_type = regra["search_type"]
        pattern = regra["pattern"]
        expected = regra["expected_value"]
        has_or_not = regra["has_or_not_has"]

        passed = False
        detail_msg = regra["detail"]
        val = None

        # -------------------------------------------------------------------
        # FASE A: EXTRAÇÃO DE DADOS (XPath, XPath Count ou Regex)
        # -------------------------------------------------------------------
        if search_type == "xpath":
            if root is not None:
                el = root.find(pattern)
                val = el.text if el is not None and el.text is not None else ""
            else:
                val = "" 

        elif search_type == "xpath_count":
            if root is not None:
                nodes = root.findall(pattern)
                val = str(len(nodes))
            else:
                val = "0"

        elif search_type == "regex":
            target_text = raw_text
            
            # Isolamento de Bloco (Se não for 'raw', tenta isolar nós específicos no XML)
            if block != "raw":
                if root is not None:
                    nodes = root.findall(block)
                    target_text = "\n".join([ET.tostring(n, encoding='unicode') for n in nodes]) if nodes else ""
                else:
                    # Fallback bruto via regex caso o XML não tenha sido parseado
                    b_tag = block.split('/')[-1]
                    matches = re.findall(rf"<{b_tag}>.*?</{b_tag}>", raw_text, re.DOTALL | re.IGNORECASE)
                    target_text = "\n".join(matches)

            # Suporte para Regex múltiplo (AND lógico com &&)
            if "&&" in pattern:
                sub_patterns = [p.strip() for p in pattern.split("&&")]
                found = all(bool(re.search(p, target_text, re.IGNORECASE | re.DOTALL)) for p in sub_patterns)
            else:
                found = bool(re.search(pattern, target_text, re.IGNORECASE | re.DOTALL))
            
            val = "FOUND" if found else "NOT_FOUND"

        # -------------------------------------------------------------------
        # FASE B: AVALIAÇÃO DO RESULTADO ESPERADO
        # -------------------------------------------------------------------
        if not expected:
            # Avaliação Booleana (quando a regra só verifica a existência/ausência de algo)
            if search_type == "regex":
                passed = (val == "FOUND") if has_or_not == "has" else (val == "NOT_FOUND")
                detail_msg += " (Encontrado)" if val == "FOUND" else " (Não encontrado)"
            else:
                exists = bool(val and str(val).strip())
                passed = exists if has_or_not == "has" else not exists
                detail_msg += f" | Valor lido: '{val}'" if exists else " (Ausente ou Vazio)"

        else:
            # Avaliação de Dados Parametrizados
            expected_str = str(expected).strip()
            
            # 1. Expressões Matemáticas (<=, >=, <, >)
            if expected_str.startswith(("<=", ">=", "<", ">")):
                op_match = re.match(r"(<=|>=|<|>)\s*([\d.]+)", expected_str)
                if op_match and val and str(val).strip():
                    try:
                        op = op_match.group(1)
                        limit = float(op_match.group(2))
                        curr = float(val)

                        if op == "<=": passed = curr <= limit
                        elif op == ">=": passed = curr >= limit
                        elif op == "<": passed = curr < limit
                        elif op == ">": passed = curr > limit
                        
                        detail_msg += f" | Lido: {curr} (Regra: {expected_str})"
                    except ValueError:
                        passed = False
                        detail_msg += f" | Erro de conversão numérica. Lido: '{val}'"
                else:
                    passed = False
                    detail_msg += " | Valor inválido ou ausente para avaliação matemática."

            # 2. Avaliação em Listas de Palavras Separadas por Vírgula
            elif "," in expected_str:
                lista = [x.strip().lower() for x in expected_str.split(',')]
                curr_lower = str(val).strip().lower()

                if has_or_not == "not_has": # Funciona como Blacklist (ex: hostname pfsense)
                    passed = curr_lower not in lista
                else: # Funciona como Whitelist
                    passed = curr_lower in lista
                    
                detail_msg += f" | Lido: '{val}'"
            
            # 3. Avaliação Exata de String
            else:
                curr_lower = str(val).strip().lower()
                target_lower = expected_str.lower()
                
                if has_or_not == "not_has":
                    passed = curr_lower != target_lower
                else:
                    passed = curr_lower == target_lower
                    
                detail_msg += f" | Lido: '{val}'"

        # Adiciona à lista final
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
        level, color = "BAIXO",   "#10b981"
    elif score >= 65:
        level, color = "MÉDIO",   "#f59e0b"
    elif score >= 40:
        level, color = "ALTO",    "#ef4444"
    else:
        level, color = "CRÍTICO", "#dc2626"

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