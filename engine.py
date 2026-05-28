from database import get_severity_weights

_DEFAULT_WEIGHTS = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1}


def _weights() -> dict:
    try:
        w = get_severity_weights()
        return w if w else _DEFAULT_WEIGHTS
    except Exception:
        return _DEFAULT_WEIGHTS


def calculate_risk(results: list) -> dict:
    sw = _weights()

    def w(r): return sw.get(r["severity"], 1)

    total_w = sum(w(r) for r in results)
    fail_w  = sum(w(r) for r in results if r["status"] == "FAIL")
    score   = round(100 - (fail_w / total_w * 100)) if total_w else 100

    cats = sorted(set(r["category"] for r in results))
    by_cat = {}
    for cat in cats:
        g  = [r for r in results if r["category"] == cat]
        gw = sum(w(r) for r in g)
        gf = sum(w(r) for r in g if r["status"] == "FAIL")
        by_cat[cat] = {
            "total": len(g),
            "pass":  sum(1 for r in g if r["status"] == "PASS"),
            "fail":  sum(1 for r in g if r["status"] == "FAIL"),
            "score": round(100 - (gf / gw * 100)) if gw else 100,
        }

    by_sev = {}
    for sev in ["Critical", "High", "Medium", "Low"]:
        g = [r for r in results if r["severity"] == sev]
        by_sev[sev] = {
            "total": len(g),
            "pass":  sum(1 for r in g if r["status"] == "PASS"),
            "fail":  sum(1 for r in g if r["status"] == "FAIL"),
            "weight": sw.get(sev, 1),
        }

    if score >= 85:   level, color = "BAIXO",   "#10b981"
    elif score >= 65: level, color = "MEDIO",   "#f59e0b"
    elif score >= 40: level, color = "ALTO",    "#ef4444"
    else:             level, color = "CRITICO", "#dc2626"

    return {
        "score": score, "risk_level": level, "risk_color": color,
        "total_checks": len(results),
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "failed": sum(1 for r in results if r["status"] == "FAIL"),
        "by_severity": by_sev, "by_category": by_cat,
        "weights_used": sw,
    }
