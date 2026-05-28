"""
routes/admin.py — Admin panel API
Auth, stats, history, vendors/versions, CIS checks CRUD, severity weights.
"""
from functools import wraps

from flask import Blueprint, request, jsonify, session

from database import (
    get_stats, get_history, get_severity_weights, set_severity_weight,
    verify_admin_login, set_admin_password,
    admin_add_version, admin_update_version, admin_delete_version,
    get_vendors, get_versions, admin_update_vendor, admin_delete_vendor,
    api_checks_get_all, api_checks_get_active, api_checks_add,
    api_checks_update, api_checks_toggle, api_checks_delete,
    endpoints_get_all, endpoints_add, endpoints_update, endpoints_toggle, endpoints_delete,
    firewall_creds_get_all, firewall_creds_add, firewall_creds_update, firewall_creds_delete,
    firewall_creds_test_update,
    rule_defs_get_all, rule_defs_add, rule_defs_update, rule_defs_toggle, rule_defs_delete,
)
from validation import validate_api_check, validate_endpoint

bp = Blueprint("admin", __name__)


def require_admin(f):
    @wraps(f)
    def dec(*a, **kw):
        if not session.get("admin_ok"):
            return jsonify({"error": "Autenticacao necessaria", "auth_required": True}), 401
        return f(*a, **kw)
    return dec


# ── AUTH ─────────────────────────────────────────────────────
@bp.route("/api/admin/login", methods=["POST"])
def admin_login():
    d = request.get_json() or {}
    if verify_admin_login(d.get("password", "")):
        session.permanent = True
        session["admin_ok"] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Senha incorreta"}), 401


@bp.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin_ok", None)
    return jsonify({"ok": True})


@bp.route("/api/admin/auth-check")
def admin_auth_check():
    return jsonify({"authenticated": bool(session.get("admin_ok"))})


@bp.route("/api/admin/change-password", methods=["POST"])
@require_admin
def admin_change_pw():
    d = request.get_json() or {}
    if not verify_admin_login(d.get("current_password", "")):
        return jsonify({"ok": False, "error": "Senha atual incorreta"}), 400
    new_pw = d.get("new_password", "")
    if len(new_pw) < 6:
        return jsonify({"ok": False, "error": "Minimo 6 caracteres"}), 400
    set_admin_password(new_pw)
    return jsonify({"ok": True})


# ── STATS & HISTORY ──────────────────────────────────────────
@bp.route("/api/admin/stats")
@require_admin
def admin_stats():
    return jsonify({**get_stats(), "history": get_history(10)})


@bp.route("/api/admin/history")
@require_admin
def admin_history():
    return jsonify(get_history(50))


# ── VENDORS & VERSIONS ───────────────────────────────────────
@bp.route("/api/vendors")
def api_vendors():
    vendors = get_vendors()
    result = []
    for v in vendors:
        versions = get_versions(v["slug"])
        result.append({**dict(v), "versions": [dict(ver) for ver in versions]})
    return jsonify(result)


@bp.route("/api/admin/vendors/<int:vendor_id>", methods=["PUT"])
@require_admin
def admin_update_vendor_route(vendor_id):
    d = request.get_json() or {}
    slug = d.get("slug", "").strip()
    name = d.get("name", "").strip()
    icon = d.get("icon", "🔧").strip() or '🔧'
    base_url = d.get("base_url", "").strip()
    description = d.get("description", "").strip()
    min_firmware_version = d.get("min_firmware_version", "").strip()
    if not slug or not name or not base_url:
        return jsonify({"ok": False, "error": "slug, name e base_url obrigatorios"}), 400
    try:
        admin_update_vendor(vendor_id, slug, name, description, icon, base_url, min_firmware_version)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/vendors/<int:vendor_id>", methods=["DELETE"])
@require_admin
def admin_delete_vendor_route(vendor_id):
    try:
        admin_delete_vendor(vendor_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/versions", methods=["POST"])
@require_admin
def admin_add_ver():
    d = request.get_json() or {}
    vendor_id = d.get("vendor_id")
    version   = d.get("version", "").strip()
    label     = d.get("label", "").strip()
    min_fw    = d.get("min_firmware_version", "").strip()
    if not vendor_id or not version or not label:
        return jsonify({"ok": False, "error": "vendor_id, version e label obrigatorios"}), 400
    try:
        new_id = admin_add_version(int(vendor_id), version, label, min_fw)
        return jsonify({"ok": True, "id": new_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/versions/<int:version_id>", methods=["PUT"])
@require_admin
def admin_update_ver(version_id):
    d = request.get_json() or {}
    try:
        admin_update_version(
            version_id,
            label=d.get("label"),
            min_firmware_version=d.get("min_firmware_version"),
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/versions/<int:version_id>", methods=["DELETE"])
@require_admin
def admin_del_ver(version_id):
    try:
        admin_delete_version(version_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ── API CHECKS (DB-driven CIS checks for API mode) ───────────
@bp.route("/api/admin/api-checks")
@require_admin
def api_checks_list():
    vendor_slug = request.args.get("vendor")
    return jsonify(api_checks_get_all(vendor_slug))


@bp.route("/api/admin/api-checks", methods=["POST"])
@require_admin
def api_checks_create():
    d = request.get_json() or {}
    required = ["vendor_slug", "cid", "title", "category", "severity"]
    missing = [f for f in required if not d.get(f)]
    if missing:
        return jsonify({"ok": False, "error": f"Campos obrigatórios: {', '.join(missing)}"}), 400
    
    # Validar dados antes da inserção
    is_valid, error_msg = validate_api_check(d)
    if not is_valid:
        return jsonify({"ok": False, "error": error_msg}), 400
    
    try:
        new_id = api_checks_add(d)
        return jsonify({"ok": True, "id": new_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/api-checks/<int:check_id>", methods=["PUT"])
@require_admin
def api_checks_edit(check_id):
    d = request.get_json() or {}
    
    # Validar dados antes da atualização
    is_valid, error_msg = validate_api_check(d, current_id=check_id)
    if not is_valid:
        return jsonify({"ok": False, "error": error_msg}), 400
    
    try:
        api_checks_update(check_id, d)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/api-checks/<int:check_id>/toggle", methods=["POST"])
@require_admin
def api_checks_toggle_route(check_id):
    d = request.get_json() or {}
    active = int(d.get("active", 1))
    api_checks_toggle(check_id, active)
    return jsonify({"ok": True})


@bp.route("/api/admin/api-checks/<int:check_id>", methods=["DELETE"])
@require_admin
def api_checks_delete_route(check_id):
    try:
        api_checks_delete(check_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ── SEVERITY WEIGHTS ─────────────────────────────────────────
@bp.route("/api/admin/weights")
def api_weights():
    return jsonify(get_severity_weights())


@bp.route("/api/admin/weights", methods=["PUT"])
@require_admin
def api_set_weights():
    data = request.get_json() or {}
    for sev, w in data.items():
        if sev in ("Critical", "High", "Medium", "Low"):
            set_severity_weight(sev, int(w))
    return jsonify({"ok": True})


# ── API ENDPOINTS ────────────────────────────────────────────
@bp.route("/api/admin/endpoints", methods=["GET"])
@require_admin
def endpoints_list():
    vendor_slug = request.args.get("vendor_slug")
    endpoints = endpoints_get_all(vendor_slug)
    return jsonify(endpoints)


@bp.route("/api/admin/endpoints", methods=["POST"])
@require_admin
def endpoints_create():
    d = request.get_json() or {}
    
    # Preparar dados para validação
    validation_data = {
        "vendor_slug": d.get("vendor_slug"),
        "section_name": d.get("section_name"),
        "endpoint_path": d.get("endpoint_path"),
        "description": d.get("description", "")
    }
    
    # Validar dados antes da inserção
    is_valid, error_msg = validate_endpoint(validation_data)
    if not is_valid:
        return jsonify({"ok": False, "error": error_msg}), 400
    
    try:
        ep_id = endpoints_add(
            d.get("vendor_slug"),
            d.get("section_name"),
            d.get("endpoint_path"),
            d.get("description", "")
        )
        return jsonify({"ok": True, "id": ep_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/endpoints/<int:endpoint_id>", methods=["PUT"])
@require_admin
def endpoints_edit(endpoint_id):
    d = request.get_json() or {}
    
    # Preparar dados para validação
    validation_data = {
        "vendor_slug": d.get("vendor_slug"),
        "section_name": d.get("section_name"),
        "endpoint_path": d.get("endpoint_path"),
        "description": d.get("description", "")
    }
    
    # Validar dados antes da atualização
    is_valid, error_msg = validate_endpoint(validation_data, current_id=endpoint_id)
    if not is_valid:
        return jsonify({"ok": False, "error": error_msg}), 400
    
    try:
        endpoints_update(endpoint_id, d)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/endpoints/<int:endpoint_id>/toggle", methods=["POST"])
@require_admin
def endpoints_toggle_route(endpoint_id):
    d = request.get_json() or {}
    active = int(d.get("active", 1))
    endpoints_toggle(endpoint_id, active)
    return jsonify({"ok": True})


@bp.route("/api/admin/endpoints/<int:endpoint_id>", methods=["DELETE"])
@require_admin
def endpoints_delete_route(endpoint_id):
    try:
        endpoints_delete(endpoint_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ── FIREWALL CREDENTIALS CRUD ────────────────────────────────
@bp.route("/api/admin/firewall-credentials")
@require_admin
def firewall_creds_list():
    """List all firewall credentials (passwords NOT included)."""
    creds = firewall_creds_get_all()
    return jsonify(creds)


@bp.route("/api/admin/firewall-credentials", methods=["POST"])
@require_admin
def firewall_creds_create():
    """Add new firewall credential with encrypted storage."""
    d = request.get_json() or {}
    required = ["label", "vendor_slug", "hostname", "username", "password"]
    missing = [f for f in required if not d.get(f)]
    if missing:
        return jsonify({"ok": False, "error": f"Campos obrigatórios: {', '.join(missing)}"}), 400
    
    try:
        port = int(d.get("port", 443))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Porta deve ser um número"}), 400
    
    try:
        new_id = firewall_creds_add(
            label=d.get("label"),
            vendor_slug=d.get("vendor_slug"),
            hostname=d.get("hostname"),
            port=port,
            username=d.get("username"),
            password=d.get("password"),
            api_key=d.get("api_key", ""),
            description=d.get("description", "")
        )
        return jsonify({"ok": True, "id": new_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/firewall-credentials/<int:cred_id>", methods=["PUT"])
@require_admin
def firewall_creds_edit(cred_id):
    """Update firewall credential (only sent fields are updated)."""
    d = request.get_json() or {}
    
    try:
        port = int(d.get("port")) if d.get("port") else None
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Porta deve ser um número"}), 400
    
    try:
        firewall_creds_update(
            cred_id,
            label=d.get("label"),
            hostname=d.get("hostname"),
            port=port,
            username=d.get("username"),
            password=d.get("password"),
            api_key=d.get("api_key"),
            description=d.get("description"),
            active=d.get("active")
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/firewall-credentials/<int:cred_id>", methods=["DELETE"])
@require_admin
def firewall_creds_delete_route(cred_id):
    """Delete firewall credential."""
    try:
        firewall_creds_delete(cred_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/firewall-credentials/<int:cred_id>/test", methods=["POST"])
@require_admin
def firewall_creds_test(cred_id):
    """Test connection and update last_tested timestamp."""
    try:
        firewall_creds_test_update(cred_id)
        return jsonify({"ok": True, "message": "Conexão testada com sucesso"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ── RULE CHECK DEFINITIONS ───────────────────────────────────
@bp.route("/api/admin/rule-checks")
@require_admin
def rule_checks_list():
    vendor_slug = request.args.get("vendor")
    return jsonify(rule_defs_get_all(vendor_slug))


@bp.route("/api/admin/rule-checks", methods=["POST"])
@require_admin
def rule_checks_create():
    d = request.get_json() or {}
    required = ["vendor_slug", "name", "severity", "tag"]
    missing = [f for f in required if not d.get(f)]
    if missing:
        return jsonify({"ok": False, "error": f"Campos obrigatórios: {', '.join(missing)}"}), 400
    tag = d.get("tag", "").strip()[:60]
    if not tag:
        return jsonify({"ok": False, "error": "Tag é obrigatória"}), 400
    if not tag.replace("_", "").isalnum():
        return jsonify({"ok": False, "error": "Tag deve conter apenas letras, números e underscore"}), 400
    try:
        new_id = rule_defs_add(
            d["vendor_slug"], tag, d["name"],
            d.get("category", "Firewall Policy"),
            d["severity"],
            d.get("description", ""),
            d.get("recommendation", ""),
        )
        return jsonify({"ok": True, "id": new_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/rule-checks/<int:def_id>", methods=["PUT"])
@require_admin
def rule_checks_edit(def_id):
    d = request.get_json() or {}
    tag = d.get("tag", "").strip() if d.get("tag") else None
    if tag and not tag.replace("_", "").isalnum():
        return jsonify({"ok": False, "error": "Tag deve conter apenas letras, números e underscore"}), 400
    try:
        rule_defs_update(
            def_id,
            d.get("name", ""),
            d.get("category", "Firewall Policy"),
            d.get("severity", "High"),
            d.get("description", ""),
            d.get("recommendation", ""),
            tag=tag if tag else None,
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/api/admin/rule-checks/<int:def_id>/toggle", methods=["POST"])
@require_admin
def rule_checks_toggle_route(def_id):
    d = request.get_json() or {}
    rule_defs_toggle(def_id, int(d.get("active", 1)))
    return jsonify({"ok": True})


@bp.route("/api/admin/rule-checks/<int:def_id>", methods=["DELETE"])
@require_admin
def rule_checks_delete_route(def_id):
    try:
        rule_defs_delete(def_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
