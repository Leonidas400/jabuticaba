"""
routes/public.py — Public API endpoints (test, analyze, pdf)
"""
import io
from datetime import datetime

from flask import Blueprint, request, jsonify, send_file

from engine import calculate_risk
from database import save_analysis

try:
    from pdf_report import generate_pdf
    PDF_OK = True
except ImportError:
    PDF_OK = False

bp = Blueprint("public", __name__)


def _default_port(vendor):
    return 443


def _get_rules_audit(vendor, data):
    try:
        if vendor == "sonicwall":
            from sonicwall_api import get_rules_audit
        elif vendor == "fortigate":
            from fortigate_api import get_rules_audit
        elif vendor == "pfsense":
            from pfsense_api import get_rules_audit
        else:
            return {}
        return get_rules_audit(data)
    except Exception as e:
        return {"error": str(e)}


def _make_client(vendor, host, user, pw, port, apikey):
    try:
        if vendor == "sonicwall":
            from sonicwall_api import SonicWallAPIClient
            return SonicWallAPIClient(host, user, pw, port), ""
        elif vendor == "fortigate":
            from fortigate_api import FortiGateAPIClient
            return FortiGateAPIClient(host, user, pw, port, api_key=apikey), ""
        elif vendor == "pfsense":
            from pfsense_api import PfSenseAPIClient
            return PfSenseAPIClient(host, user, pw, port, api_key=apikey), ""
        else:
            return None, f"Fabricante desconhecido: {vendor}"
    except Exception as e:
        return None, str(e)


def _run_checks(vendor, client):
    if vendor == "sonicwall":
        from sonicwall_api import run_api_checks
    elif vendor == "fortigate":
        from fortigate_api import run_api_checks
    elif vendor == "pfsense":
        from pfsense_api import run_api_checks
    else:
        raise ValueError(f"Vendor nao suportado: {vendor}")
    return run_api_checks(client)


def _get_device_info(vendor, client):
    try:
        if vendor == "sonicwall":
            info = client.get("reporting/device/current") or {}
            fw   = info.get("firmware_version") or (info.get("device") or {}).get("firmware_version", "-")
            mdl  = info.get("model") or (info.get("device") or {}).get("model", "SonicWall")
            return {"message": f"Conectado - {mdl} SonicOS {fw}", "firmware": fw, "model": mdl}
        elif vendor == "fortigate":
            info = client.get_raw("monitor/system/status") or {}
            res  = info.get("results", info)
            fw   = res.get("version", "-")
            mdl  = res.get("model_name", res.get("hostname", "FortiGate"))
            return {"message": f"Conectado - {mdl} FortiOS {fw}", "firmware": fw, "model": mdl}
        elif vendor == "pfsense":
            info = client.get("system/version") or {}
            fw   = (info.get("version") or info.get("data", {}).get("version", "-"))
            return {"message": f"Conectado - pfSense {fw}", "firmware": fw, "model": "pfSense"}
    except Exception:
        pass
    return {"message": "Conectado com sucesso"}


@bp.route("/api/test", methods=["POST"])
def api_test():
    d      = request.get_json() or {}
    vendor = d.get("vendor", "").lower()
    host   = d.get("host", "").strip()
    port   = int(d.get("port", _default_port(vendor)))
    user   = d.get("username", "").strip()
    pw     = d.get("password", "")
    apikey = d.get("api_key", "").strip()

    if not host:
        return jsonify({"ok": False, "error": "Host obrigatorio"}), 400

    client, err = _make_client(vendor, host, user, pw, port, apikey)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    ok, err = client.login()
    if not ok:
        return jsonify({"ok": False, "error": err})

    info = _get_device_info(vendor, client)
    client.logout()
    return jsonify({"ok": True, **info})


@bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    d       = request.get_json() or {}
    vendor  = d.get("vendor", "").lower()
    host    = d.get("host", "").strip()
    port    = int(d.get("port", _default_port(vendor)))
    user    = d.get("username", "").strip()
    pw      = d.get("password", "")
    apikey  = d.get("api_key", "").strip()
    company = d.get("company", host)

    if not host or not vendor:
        return jsonify({"error": "Host e fabricante sao obrigatorios"}), 400
    if not (user or apikey):
        return jsonify({"error": "Credenciais obrigatorias (usuario/senha ou API Key)"}), 400

    client, err = _make_client(vendor, host, user, pw, port, apikey)
    if err:
        return jsonify({"error": err}), 400

    ok, err = client.login()
    if not ok:
        return jsonify({"error": f"Falha no login: {err}"}), 401

    try:
        checks, raw = _run_checks(vendor, client)
    except Exception as e:
        client.logout()
        return jsonify({"error": f"Erro na analise: {e}"}), 500
    finally:
        client.logout()

    risk = calculate_risk(checks)
    save_analysis(company, vendor, "api",
                  risk["score"], risk["risk_level"],
                  risk["passed"], risk["failed"], risk["total_checks"])

    cis_checks  = [c for c in checks if not c["cid"].startswith("FWR")]
    rule_checks = [c for c in checks if c["cid"].startswith("FWR")]

    # ── Dedicated rules security audit ────────────────────────
    rules_audit = _get_rules_audit(vendor, raw)

    vendor_names = {"fortigate": "FortiGate", "pfsense": "pfSense", "sonicwall": "SonicWall"}

    return jsonify({
        "company":       company,
        "vendor":        vendor,
        "vendor_name":   vendor_names.get(vendor, vendor.title()),
        "version":       "live",
        "version_label": f"API Live - {host}",
        "benchmark":     f"{vendor_names.get(vendor, vendor)} CIS Benchmark (API)",
        "timestamp":     datetime.utcnow().isoformat() + "Z",
        "risk":          risk,
        "checks":        checks,
        "cis_checks":    cis_checks,
        "rule_checks":   rule_checks,
        "rules_audit":   rules_audit,
        "source":        "api",
    })


@bp.route("/api/pdf", methods=["POST"])
def api_pdf():
    if not PDF_OK:
        return jsonify({"error": "reportlab nao instalado"}), 500
    data = request.get_json()
    if not data:
        return jsonify({"error": "Dados invalidos"}), 400
    try:
        pdf_bytes = generate_pdf(data)
        company   = (data.get("company") or "report").replace(" ", "_")
        vendor    = (data.get("vendor") or "fw").upper()
        return send_file(
            io.BytesIO(pdf_bytes), mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{vendor}_CIS_{company}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
