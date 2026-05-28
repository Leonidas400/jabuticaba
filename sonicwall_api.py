"""
sonicwall_api.py — CIS Benchmark via SonicWall REST API (SonicOS 7.x)
Endpoints: https://sonicos-api.sonicwall.com/
"""

import requests, urllib3
from typing import Optional

from api_runner import run_db_checks, _result
from database import get_endpoints_by_vendor, rule_defs_get_disabled_tags

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────
# CLIENT
# ─────────────────────────────────────────────────────────────
class SonicWallAPIClient:
    def __init__(self, host, username, password, port=443, timeout=15):
        self.base    = f"https://{host}:{port}/api/sonicos"
        self.auth    = (username, password)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"Content-Type":"application/json","Accept":"application/json"})

    def login(self):
        try:
            r = self.session.post(f"{self.base}/auth", json={"override":True},
                                  auth=self.auth, timeout=self.timeout)
            if r.status_code in (200,201):
                tok = r.headers.get("Authorization")
                if tok: self.session.headers["Authorization"] = tok
                return True, ""
            try: msg = r.json().get("status",{}).get("info",[{}])[0].get("message","")
            except: msg = r.text[:100]
            return False, f"HTTP {r.status_code}: {msg}"
        except requests.ConnectionError: return False,"Não foi possível conectar. Verifique IP/porta e se a API está habilitada."
        except requests.Timeout:         return False,"Timeout na conexão."
        except Exception as e:           return False, str(e)

    def logout(self):
        try: self.session.delete(f"{self.base}/auth", timeout=5)
        except: pass

    def get(self, path):
        try:
            r = self.session.get(f"{self.base}/{path.lstrip('/')}", timeout=self.timeout)
            return r.json() if r.status_code == 200 else None
        except: return None

# ─────────────────────────────────────────────────────────────
# RISKY PORTS
# ─────────────────────────────────────────────────────────────
RISKY_PORTS = {
    22:"SSH", 23:"Telnet", 3389:"RDP",
    1521:"Oracle DB", 3306:"MySQL/MariaDB",
    5432:"PostgreSQL", 1433:"MSSQL", 5900:"VNC",
}

# ─────────────────────────────────────────────────────────────
# MAIN RUNNER — fetches data, then delegates to DB-driven runner
# ─────────────────────────────────────────────────────────────

def run_api_checks(client):
    endpoints_db = get_endpoints_by_vendor("sonicwall")
    data = {}

    for ep in endpoints_db:
        key = ep['section_name'].strip()
        path = ep['endpoint_path'].strip()

        response = client.get(path)

        if response:
            data[key] = response
        else:
            data[key] = {}

    try:
        data["_disabled_rule_tags"] = rule_defs_get_disabled_tags("sonicwall")
    except Exception:
        data["_disabled_rule_tags"] = set()

    return run_db_checks("sonicwall", data, _HANDLERS), ""

# ─────────────────────────────────────────────────────────────
# COMPLEX HANDLERS
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
# FIRMWARE HELPERS
# ─────────────────────────────────────────────────────────────
def _version_tuple(v: str):
    """'7.0.1-5055-R3' → (7, 0, 1) for comparison."""
    import re
    m = re.match(r'(\d+)\.(\d+)(?:\.(\d+))?', v or "")
    if m:
        return tuple(int(x) for x in m.groups() if x is not None)
    return (0,)


def _query_nvd_cves(version_str: str) -> dict:
    """Query NIST NVD for SonicWall SonicOS CVEs. Returns result dict."""
    import re, requests as _rq
    m = re.match(r'(\d+\.\d+(?:\.\d+)?)', version_str or "")
    if not m:
        return {"ok": False, "error": "versão não parseável"}
    clean = m.group(1)
    try:
        resp = _rq.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": f"SonicWall SonicOS {clean}", "resultsPerPage": 20},
            timeout=5,
            headers={"User-Agent": "CIS-Validator/4.0"},
        )
        if resp.status_code != 200:
            return {"ok": False, "error": f"HTTP {resp.status_code}"}
        vulns = resp.json().get("vulnerabilities", [])
        critical = high = 0
        cve_ids = []
        for v in vulns:
            cve   = v.get("cve", {})
            cid   = cve.get("id", "")
            sev   = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(key)
                if metrics:
                    sev = metrics[0].get("cvssData", {}).get("baseSeverity", "")
                    break
            if sev == "CRITICAL":
                critical += 1; cve_ids.append(cid)
            elif sev == "HIGH":
                high += 1; cve_ids.append(cid)
        return {"ok": True, "version": clean, "critical": critical, "high": high,
                "cve_ids": cve_ids[:5]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _h_firmware(chk, data):
    dev = data.get("Device") or {}
    ver = _deep_find(dev, "firmware_version") or ""
    model = _deep_find(dev, "model") or ""
    restart = str(_deep_find(dev, "restart_required") or "").lower() == "true"
    
    if not ver:
        return _result(chk, False, "—", "Não foi possível obter versão do firmware via API")

    issues = []
    ok = True

    try:
        from database import get_version_min_firmware
        import re as _re
        m_line = _re.match(r'(\d+)\.(\d+)', ver or "")
        ver_line = f"{m_line.group(1)}.{m_line.group(2)}" if m_line else ""
        min_ver = get_version_min_firmware("sonicwall", ver_line).strip() if ver_line else ""
    except Exception:
        min_ver = ""

    if min_ver and _version_tuple(ver) < _version_tuple(min_ver):
        ok = False
        issues.append(f"abaixo do mínimo ({min_ver})")

    nvd = _query_nvd_cves(ver)
    if nvd.get("ok"):
        if nvd["critical"] > 0 or nvd["high"] > 0:
            ok = False
            issues.append(f"Vulnerável ({nvd['critical']} CRIT, {nvd['high']} HIGH)")
    
    if restart: issues.append("reinicialização pendente")

    cur = f"{ver}" + (f" ({model})" if model else "")
    det = f"Firmware {cur} ✓" if ok else f"Firmware {cur} — " + " | ".join(issues)
    return _result(chk, ok, cur, det)


def _h_snmp(chk, data):
    snmp_raw = data.get("SNMP") or {}
    snmp_root = _deep_find(snmp_raw, "snmp") or snmp_raw
    enabled = _t(_deep_find(snmp_root, "enable"))
    v3_mand = _t(_deep_find(snmp_root, "mandatory"))
    ok = not enabled or v3_mand
    cur = f"en={_bv(enabled)} v3={_bv(v3_mand)}"
    det = "SNMP desabilitado ✓" if not enabled else ("SNMPv3 obrigatório ✓" if v3_mand else "SNMP ativo sem SNMPv3 obrigatório")
    return _result(chk, ok, cur, det)


def _h_snmp_community(chk, data):
    snmp = data.get("SNMP") or {}
    get_com  = str(_deep_find(snmp, "get_community_name")  or "").strip()
    trap_com = str(snmp.get("trap_community_name") or _deep_find(snmp, "trap_community") or "").strip()
    bad = []
    if get_com.lower()  == "public": bad.append("GET")
    if trap_com.lower() == "public": bad.append("TRAP")
    ok = not bad
    cur = f"GET={get_com or '—'} TRAP={trap_com or '—'}"
    det = "Community strings personalizadas ✓" if ok else f"Community 'public' detectada em: {', '.join(bad)}"
    return _result(chk, ok, cur, det)


def _h_snmp_hosts(chk, data):
    # host_1..host_4 restrict which hosts may query SNMP.
    # If all are empty the device accepts SNMP queries from ANY host.
    snmp   = _d(data.get("SNMP"), "snmp") or {}
    hosts  = [snmp.get(f"host_{i}", "") or "" for i in range(1, 5)]
    active = [h.strip() for h in hosts if h.strip() and h.strip() not in ("string", "0.0.0.0")]
    ok     = len(active) > 0
    cur    = ", ".join(active) if active else "nenhum"
    det    = (f"SNMP restrito a: {', '.join(active)} ✓" if ok
              else "Nenhum host SNMP configurado — qualquer host pode consultar o dispositivo!")
    return _result(chk, ok, cur, det)


def _h_gav_inbound(chk, data):
    gav = data.get("Gateway AV") or {}
    
    # Omni-Extractor: Procura "inbound" ou "protocol" em qualquer nível de profundidade
    def _find_inbound(d):
        if isinstance(d, dict):
            for k, v in d.items():
                if "inbound" in k.lower() or "protocol" in k.lower():
                    return v
                res = _find_inbound(v)
                if res: return res
        return None
        
    inbound = _find_inbound(gav)
    
    if not inbound:
        return _result(chk, False, "ausente", "Nenhum protocolo configurado no GAV Inbound")
        
    return _result(chk, True, "Todos ✓", "Protocolos Inbound mapeados ✓")


def _h_gav_outbound(chk, data):
    gav = data.get("Gateway AV") or {}
    
    # Omni-Extractor: Procura "outbound" ou "protocol" em qualquer nível de profundidade
    def _find_outbound(d):
        if isinstance(d, dict):
            for k, v in d.items():
                if "outbound" in k.lower() or "protocol" in k.lower():
                    return v
                res = _find_outbound(v)
                if res: return res
        return None
        
    outbound = _find_outbound(gav)
    
    if not outbound:
        return _result(chk, False, "ausente", "Nenhum protocolo configurado no GAV Outbound")
        
    return _result(chk, True, "Todos ✓", "Protocolos Outbound mapeados ✓")

def _extract_allow_rules(data):
    """Return list of unwrapped ALLOW access rules from data dict."""
    ar_data   = data.get("access_rules") or data.get("fw_base") or {}
    raw_items = _deep_find(ar_data, "access_rules") or ar_data or []
    if isinstance(raw_items, dict):
        raw_items = raw_items.get("access_rules") or list(raw_items.values())
    if not isinstance(raw_items, list):
        raw_items = []
    rules = []
    for item in raw_items:
        if isinstance(item, dict):
            if "ipv4" in item:   rules.append(item["ipv4"])
            elif "ipv6" in item: rules.append(item["ipv6"])
    if not rules and raw_items:
        rules = [r for r in raw_items if isinstance(r, dict)]
    return [r for r in rules
            if str(r.get("action","")).lower() in ("allow","permit","accept")]


def _botnet_mode(data) -> str:
    raw    = data.get("Botnet") or {}
    botnet = _deep_find(raw, "botnet") or raw
    if not isinstance(botnet, dict):
        return "off"
    conn = (botnet.get("block") or {}).get("connections") or {}
    if not isinstance(conn, dict) or not _t(conn.get("enable")):
        return "off"
    mode = str(conn.get("mode") or "").lower()
    if mode == "all":
        return "global"
    if "rule" in mode:
        return "per-rule"
    return "off"


def _geoip_mode(data) -> str:
    raw  = data.get("Geo IP") or {}
    geo  = _deep_find(raw, "geo_ip") or raw
    if not isinstance(geo, dict):
        return "off"
    conn = (geo.get("block") or {}).get("connections") or {}
    if not isinstance(conn, dict):
        return "off"
    if _t(conn.get("all")):
        return "global"
    if _t(conn.get("firewall_rule_based")):
        return "per-rule"
    return "off"


def _h_botnet_block(chk, data):
    mode = _botnet_mode(data)

    if mode == "global":
        return _result(chk, True, "global (all)",
                       "Botnet bloqueio global ativo — todas as conexoes ✓")

    if mode == "per-rule":
        allow  = _extract_allow_rules(data)
        active = [r for r in allow if _t(r.get("botnet_filter"))]
        ok     = len(active) > 0
        cur    = f"per-regra: {len(active)}/{len(allow)}"
        det    = (f"Modo per-regra: {len(active)}/{len(allow)} regras ALLOW com Botnet ativo ✓"
                  if ok else
                  "Modo per-regra: nenhuma regra ALLOW com Botnet Filter ativo!")
        return _result(chk, ok, cur, det)

    return _result(chk, False, "nao configurado",
                   "Botnet block desabilitado (connections.enable=false ou modo nao reconhecido)")


def _h_geoip_block(chk, data):
    mode = _geoip_mode(data)

    if mode == "global":
        return _result(chk, True, "global (all)",
                       "Geo-IP bloqueio global ativo — todas as conexoes ✓")

    if mode == "per-rule":
        allow  = _extract_allow_rules(data)
        active = [r for r in allow
                  if _t(_deep_find(r, "geo_ip_filter")) or _t(r.get("geo_ip_filter"))]
        ok     = len(active) > 0
        cur    = f"per-regra: {len(active)}/{len(allow)}"
        det    = (f"Modo per-regra: {len(active)}/{len(allow)} regras ALLOW com Geo-IP ativo ✓"
                  if ok else
                  "Modo per-regra: nenhuma regra ALLOW com Geo-IP Filter ativo!")
        return _result(chk, ok, cur, det)

    return _result(chk, False, "nao configurado",
                   "Geo-IP block nao configurado (nem global nem por regra)")


def _h_syslog(chk, data):
    raw  = data.get("Syslog") or {}
    # Tenta o caminho exato primeiro, depois o deep_find
    sls  = (_d(raw, "log", "syslog", "server") or 
            _d(raw, "syslog", "server") or 
            _deep_find(raw, "server") or 
            raw.get("server") or [])
            
    if not isinstance(sls, list):
        sls = [sls] if isinstance(sls, dict) else []
        
    active = [s for s in sls if _t(s.get("enabled", True))] 
    total  = len(sls)
    ok     = len(active) > 0
    cur    = f"{len(active)}/{total} ativo(s)" if total else "nenhum"
    det    = (f"{len(active)} servidor(es) syslog ativo(s) ✓" if ok
              else ("Servidores configurados mas todos desabilitados" if total
                    else "Syslog remoto não configurado"))
    return _result(chk, ok, cur, det)


def _h_vpn_weak(chk, data):
    ike = data.get("ike") or data.get("VPN") or {}
    props = (_deep_find(ike, "ike_phase1_proposals") or 
             _deep_find(ike, "proposals") or 
             _deep_find(ike, "phase1") or [])
             
    if not props and isinstance(ike, list):
        props = ike
    elif not props and isinstance(ike, dict):
        for k, v in ike.items():
            if isinstance(v, list): props = v; break
            
    if not props:
        return _result(chk, True, "nenhuma vpn", "Nenhuma configuração de VPN IKE encontrada no dispositivo ✓")
        
    weak = []
    for p in props:
        enc = str(_deep_find(p, "encryption") or "").upper()
        auth = str(_deep_find(p, "authentication") or "").upper()
        nm = str(_deep_find(p, "name") or "VPN")
        
        if "DES" in enc: weak.append(f"{nm}(DES)")
        if "MD5" in auth: weak.append(f"{nm}(MD5)")
        
    ok = len(weak) == 0
    cur = ", ".join(weak) if weak else "seguro"
    det = "Sem algoritmos fracos ✓" if ok else f"Algoritmos fracos: {', '.join(weak)}"
    return _result(chk, ok, cur, det)


def _h_access_rules(chk, data):
    ar_data = data.get("access_rules") or data.get("fw_base")
    if ar_data is None:
        return []
    disabled = data.get("_disabled_rule_tags") or set()
    rule_checks, rule_summary = _audit_rules(ar_data, chk, disabled, data=data)
    out = [rule_summary] if rule_summary else []
    out.extend(rule_checks)
    return out


# ─────────────────────────────────────────────────────────────
# CAPTURE ATP HANDLER
# ─────────────────────────────────────────────────────────────

def _h_capture_atp_filetypes(chk, data):
    atp      = data.get("capture_atp") or {}
    ft       = _deep_find(atp, "file_type") or {}
    required = ["exe", "pdf", "office", "officex", "archives"]
    missing  = [t for t in required if not _t(ft.get(t))]
    ok       = not missing
    cur      = "todos ✓" if ok else f"faltando: {', '.join(missing)}"
    det      = ("Todos os tipos de arquivo habilitados no Capture ATP ✓" if ok
                else f"Tipos não cobertos pelo Capture ATP: {', '.join(missing)}")
    return _result(chk, ok, cur, det)


# ─────────────────────────────────────────────────────────────
# TCP FLOOD PROTECTION HANDLER
# ─────────────────────────────────────────────────────────────

def _h_tcp_syn_mode(chk, data):
    tcp = data.get("TCP") or {}
    mode = _deep_find(tcp, "syn_flood_protection_mode") or _deep_find(tcp, "syn_flood_mode") or ""
    
    if not mode:
        return _result(chk, False, "ausente", "Modo de proteção SYN Flood não retornado pela API")
        
    mode_str = str(mode).lower()
    ok = "proxy" in mode_str or "watch" in mode_str or "strict" in mode_str
    return _result(chk, ok, mode_str, "Modo seguro ✓" if ok else f"Modo inseguro: {mode_str}")


# ─────────────────────────────────────────────────────────────
# ADMINISTRATION / GLOBAL HANDLERS
# ─────────────────────────────────────────────────────────────

def _adm(data):
    return data.get("Administration") or {}


def _adm_mgmt(data):
    adm = _adm(data)
    for path in (("management",), ("web_management",)):
        v = _d(adm, *path)
        if isinstance(v, dict):
            return v
    return adm 


def _adm_login(data):
    adm = _adm(data)
    for key in ("password", "admin", "administration"):
        v = adm.get(key)
        if isinstance(v, dict):
            return v
    return adm


def _adm_local_pwd(data):
    ls = _adm_login(data)
    for path in (
        ("local_user", "password_constraints"),
        ("local", "password", "complexity"),
        ("local", "password"),
        ("password_constraints",),
        ("password", "complexity"),
        ("password",),
    ):
        v = _d(ls, *path)
        if isinstance(v, dict):
            return v
    return {}


def _adm_lockout(data):
    ls = _adm_login(data)
    for path in (
        ("local_user", "lockout"),
        ("local", "lockout"),
        ("lockout",),
    ):
        v = _d(ls, *path)
        if isinstance(v, dict):
            return v
    return {}


def _h_admin_username(chk, data):
    ls  = _adm_login(data)
    name = None
    for path in (
        ("administrator", "name"),
        ("administrator_name",),
        ("admin", "name"),
        ("username",),
        ("name",),
    ):
        v = _d(ls, *path)
        if v:
            name = str(v)
            break
    if name is None:
        adm = _adm(data)
        name = adm.get("admin") or adm.get("username") or adm.get("name")
    if name is None:
        return _result(chk, True, "—", "Campo não disponível via API — verificar manualmente")
    is_default = name.strip().lower() in ("admin", "administrator", "root")
    return _result(chk, not is_default, name,
                   f"Usuário '{name}' personalizado ✓" if not is_default
                   else f"Usuário padrão '{name}' ainda em uso!")


def _h_admin_ssh(chk, data):
    adm = _adm(data)
    ssh = _deep_find(adm, "ssh_management") or _deep_find(adm, "ssh") or {}
    enabled = _t(_deep_find(ssh, "enable") if ssh else False)
    port = _safe_int(_deep_find(ssh, "port") or 22)
    if not enabled: return _result(chk, True, "desabilitado", "SSH desabilitado ✓")
    if port != 22: return _result(chk, True, str(port), f"SSH ativo na porta segura {port} ✓")
    return _result(chk, False, "22", "SSH ativo na porta padrão 22 — alterar porta ou desabilitar")


def _h_admin_https_port(chk, data):
    mgmt = _adm_mgmt(data)
    https = None
    for k in ("https", "web_management_https", "https_management"):
        https = mgmt.get(k)
        if isinstance(https, dict):
            break
    if https is None:
        port = _safe_int(mgmt.get("https_port") or mgmt.get("port") or 0)
    else:
        port = _safe_int(https.get("port") or 0)
    if port == 0:
        return _result(chk, True, "—", "Porta HTTPS mgmt — campo não disponível via API")
    ok = port != 443
    return _result(chk, ok, str(port),
                   f"Porta HTTPS gerenciamento {port} ✓" if ok
                   else "Porta HTTPS gerenciamento padrão 443 — alterar para porta não-padrão")


def _h_admin_http(chk, data):
    mgmt = _adm_mgmt(data)
    http = None
    for k in ("http", "http_management", "web_management_http"):
        http = mgmt.get(k)
        if isinstance(http, dict):
            break
    if http is None:
        return _result(chk, True, "—", "HTTP mgmt — campo não disponível via API")
    enabled = _t(http.get("enable"))
    return _result(chk, not enabled,
                   "disabled" if not enabled else "enabled",
                   "HTTP de gerenciamento desabilitado ✓" if not enabled
                   else "HTTP de gerenciamento ativo — desabilitar imediatamente!")

def _h_admin_idle(chk, data):
    adm = _adm(data)
    t = (_deep_find(adm, "idle_logout_time") or 
         _deep_find(adm, "session_timeout") or 
         _deep_find(adm, "timeout") or 
         _deep_find(adm, "administrator_timeout"))
    
    timeout = _safe_int(t) if t is not None else 0
    
    if timeout <= 0:
        return _result(chk, False, "ausente", "Valor de timeout não encontrado na configuração")
        
    ok = (timeout <= 10)
    return _result(chk, ok, str(timeout), f"Timeout {timeout} min ✓" if ok else f"Timeout excessivo: {timeout} min")


def _h_admin_access_list(chk, data):
    adm = _adm(data)
    acl = (_deep_find(adm, "allowed_hosts") or 
           _deep_find(adm, "ip_list") or 
           _deep_find(adm, "allowed_management_hosts") or 
           _deep_find(adm, "management_acl"))
           
    if acl is None:
        return _result(chk, False, "aberto", "ACL de gerenciamento não configurada (acesso global)")
        
    has_acl = False
    if isinstance(acl, bool): has_acl = acl
    elif isinstance(acl, list): has_acl = len(acl) > 0
    else: has_acl = _t(acl)
    
    return _result(chk, has_acl, "on" if has_acl else "off",
                   "ACL configurada ✓" if has_acl else "Nenhuma restrição de IP para gerenciamento")


def _h_admin_login_protection(chk, data):
    # 1. Pega a raiz da Administração
    adm = data.get("Administration") or data.get("administration") or {}
    
    # 2. Desce exatamente pelos degraus que você mapeou
    admin_block = adm.get("admin") or {}
    otp_block = admin_block.get("one_time_password") or {}
    
    # 3. Pega o status do totp
    otp = _t(otp_block.get("totp"))

    if not otp:
        return _result(chk, False, "false", "OTP está desabilitado ou não configurado")

    return _result(chk, True, "OTP", "Proteção de login ativa (OTP) ✓")


def _h_admin_login_info(chk, data):
    ls = _adm_login(data)
    lpi = _deep_find(ls, "login_page_info") or _deep_find(ls, "login_page") or {}
    show_host = _t(_deep_find(lpi, "show_hostname") or _deep_find(lpi, "hostname"))
    show_fw   = _t(_deep_find(lpi, "show_firmware") or _deep_find(lpi, "firmware_version"))

    if not isinstance(lpi, dict) or not lpi:
        return _result(chk, True, "padrão", "Nenhuma exposição explicitamente configurada na API ✓")

    ok = not show_host and not show_fw
    issues = []
    if show_host: issues.append("hostname visível")
    if show_fw:   issues.append("firmware visível")
    return _result(chk, ok, "oculto" if ok else "exposto",
                   "Hostname/firmware ocultos no login ✓" if ok
                   else f"Informações expostas: {', '.join(issues)}")


# ── Senha e Complexidade handlers ──────────────────────────────

def _h_pwd_complexity(chk, data):
    adm = _adm(data)
    pwd = _deep_find(adm, "password_constraints") or _deep_find(adm, "password") or adm
    enforced = _t(_deep_find(pwd, "enforce_complexity"))
    upper = _t(_deep_find(pwd, "require_uppercase") or _deep_find(pwd, "upper"))
    lower = _t(_deep_find(pwd, "require_lowercase") or _deep_find(pwd, "lower"))
    number = _t(_deep_find(pwd, "require_numeric") or _deep_find(pwd, "number"))
    special = _t(_deep_find(pwd, "require_special") or _deep_find(pwd, "special"))
    ok = enforced and upper and lower and number and special
    missing = [n for n, v in [("maiúscula", upper), ("minúscula", lower), ("número", number), ("símbolo", special)] if not v]
    cur = "completa" if ok else ("enforce=off" if not enforced else f"faltando: {', '.join(missing)}")
    det = "Complexidade total exigida ✓" if ok else ("Desabilitado" if not enforced else f"Faltando requisitos: {', '.join(missing)}")
    return _result(chk, ok, cur, det)


def _h_pwd_min_len(chk, data):
    adm = _adm(data)
    val = (_deep_find(adm, "minimum_length") or 
           _deep_find(adm, "min_password_length") or 
           _deep_find(adm, "min_length") or 
           _deep_find(adm, "length"))
           
    length = _safe_int(val) if val is not None else 0
    
    if length <= 0:
        return _result(chk, False, "ausente", "Tamanho mínimo de senha não configurado ou não legível na API")
        
    ok = (length >= 8)
    return _result(chk, ok, str(length), f"Comprimento {length} ✓" if ok else f"Comprimento {length} insuficiente")


def _h_pwd_expiry(chk, data):
    adm = _adm(data)
    pwd = _deep_find(adm, "password_constraints") or _deep_find(adm, "password") or adm
    exp = _deep_find(pwd, "expiry") or _deep_find(pwd, "password_age") or _deep_find(pwd, "expiration") or {}
    enabled = _t(exp.get("enable") if isinstance(exp, dict) else exp)
    days = _safe_int((exp.get("days") or exp.get("max_days") or 0) if isinstance(exp, dict) else 0)
    cur = f"{days}d" if enabled else "disabled"
    det = f"Expiração em {days} dias ✓" if enabled else "Expiração de senha desabilitada"
    return _result(chk, enabled, cur, det)

def _h_admin_lockout(chk, data):
    adm = _adm(data)
    lk = _deep_find(adm, "lockout") or _deep_find(adm, "administrator_lockout") or {}
    
    if isinstance(lk, dict) and lk:
        enabled = _t(_deep_find(lk, "enable"))
        attempts = _safe_int(_deep_find(lk, "attempts") or _deep_find(lk, "max_attempts") or _deep_find(lk, "count") or 0)
    else:
        enabled = _t(_deep_find(adm, "lockout_enable") or _deep_find(adm, "enable_lockout"))
        attempts = _safe_int(_deep_find(adm, "lockout_attempts") or _deep_find(adm, "max_login_attempts") or 0)
        
    if not enabled and attempts <= 0 and not isinstance(lk, dict):
        return _result(chk, False, "ausente (off)", "Configuração de lockout ausente na API")
        
    cur = f"{attempts} tentativas" if enabled else "off"
    ok = enabled
    det = f"Lockout habilitado ({attempts} tentativas) ✓" if ok else "Lockout desabilitado"
    return _result(chk, ok, cur, det)


# ─────────────────────────────────────────────────────────────
# WAN INTERFACE HANDLERS
# ─────────────────────────────────────────────────────────────

def _wan_ifaces(data):
    """Return list of unwrapped IPv4 interface dicts whose zone == 'wan'."""
    raw = data.get("interfaces_ipv4") or {}
    items = raw.get("interfaces") or []
    if not isinstance(items, list):
        return []
    ifaces = []
    for item in items:
        iface = item.get("ipv4") if isinstance(item, dict) and "ipv4" in item else item
        if isinstance(iface, dict):
            ifaces.append(iface)
    return [i for i in ifaces
            if str((i.get("ip_assignment") or {}).get("zone") or "").lower() == "wan"]


def _wan_mgmt_check(chk, data, section, field):
    """Generic WAN interface check: field in management/user_login must be false."""
    wans = _wan_ifaces(data)
    if not wans:
        return _result(chk, True, "—", "Nenhuma interface WAN encontrada via API")
    bad = [i.get("name") or "?" for i in wans if _t((i.get(section) or {}).get(field))]
    ok  = not bad
    cur = ", ".join(bad) if bad else "nenhuma"
    det = (f"Todas as interfaces WAN com {section}.{field} desabilitado ✓" if ok
           else f"Interfaces WAN com {section}.{field} habilitado: {', '.join(bad)}")
    return _result(chk, ok, cur, det)


def _h_wan_http(chk, data):
    return _wan_mgmt_check(chk, data, "management", "http")

def _h_wan_https(chk, data):
    return _wan_mgmt_check(chk, data, "management", "https")

def _h_wan_ssh(chk, data):
    return _wan_mgmt_check(chk, data, "management", "ssh")

def _h_wan_snmp(chk, data):
    # Ajustado de "SNMP" para "snmp" em minúsculo, pois é o valor interno procurado no JSON da API
    return _wan_mgmt_check(chk, data, "management", "snmp")

def _h_wan_ping(chk, data):
    return _wan_mgmt_check(chk, data, "management", "ping")

def _h_wan_user_http(chk, data):
    return _wan_mgmt_check(chk, data, "user_login", "http")

def _h_wan_user_https(chk, data):
    return _wan_mgmt_check(chk, data, "user_login", "https")

# ─────────────────────────────────────────────────────────────
# HANDLER REGISTRY
# ─────────────────────────────────────────────────────────────
_HANDLERS = {
    "sw_firmware":            _h_firmware,
    "sw_snmp":                _h_snmp,
    "sw_snmp_community":      _h_snmp_community,
    "sw_snmp_hosts":          _h_snmp_hosts,
    # TCP Flood Protection
    "sw_tcp_syn_mode":        _h_tcp_syn_mode,
    "sw_gav_inbound":         _h_gav_inbound,
    "sw_gav_outbound":        _h_gav_outbound,
    "sw_botnet_block":        _h_botnet_block,
    "sw_geoip_block":         _h_geoip_block,
    "sw_capture_atp_filetypes": _h_capture_atp_filetypes,
    # WAN interface management
    "sw_wan_http":              _h_wan_http,
    "sw_wan_https":             _h_wan_https,
    "sw_wan_ssh":               _h_wan_ssh,
    "sw_wan_snmp":              _h_wan_snmp,
    "sw_wan_ping":              _h_wan_ping,
    "sw_wan_user_http":         _h_wan_user_http,
    "sw_wan_user_https":        _h_wan_user_https,
    "sw_syslog":              _h_syslog,
    "sw_vpn_weak":            _h_vpn_weak,
    "sw_access_rules":        _h_access_rules,
    # Administration / global
    "sw_admin_username":      _h_admin_username,
    "sw_admin_ssh":           _h_admin_ssh,
    "sw_admin_https_port":    _h_admin_https_port,
    "sw_admin_http":          _h_admin_http,
    "sw_admin_idle":          _h_admin_idle,
    "sw_admin_access_list":   _h_admin_access_list,
    "sw_admin_login_protection": _h_admin_login_protection,
    "sw_admin_login_info":    _h_admin_login_info,
    # Senha e Complexidade
    "sw_pwd_complexity":      _h_pwd_complexity,
    "sw_pwd_min_len":         _h_pwd_min_len,
    "sw_pwd_expiry":          _h_pwd_expiry,
    "sw_admin_lockout":       _h_admin_lockout,
}

# ─────────────────────────────────────────────────────────────
# ACCESS RULES AUDIT
# ─────────────────────────────────────────────────────────────
def _extract_port(svc):
    """Try to extract a numeric port from a SonicWall service object."""
    if not isinstance(svc, dict): return None
    raw = (svc.get("port") or svc.get("dst_port") or svc.get("destination_port")
           or svc.get("begin_port") or svc.get("start_port"))
    if raw is None: return None
    try:
        p = int(str(raw).split("-")[0].strip())
        return p if 0 < p < 65536 else None
    except (ValueError, TypeError):
        return None


def _audit_rules(ar_data, summary_chk, disabled=None, data=None):
    if disabled is None: disabled = set()
    # Detect global protection modes — per-rule FWR checks are skipped when global
    _botnet_global = _botnet_mode(data) == "global" if data else False
    _geoip_global  = _geoip_mode(data)  == "global" if data else False
    raw_items = _d(ar_data, "access_rules") or ar_data or []
    if isinstance(raw_items, dict):
        raw_items = raw_items.get("access_rules") or list(raw_items.values())
    if not isinstance(raw_items, list):
        raw_items = []
    # SonicOS wraps each rule as {"ipv4": {...}} or {"ipv6": {...}}
    rules = []
    for item in raw_items:
        if isinstance(item, dict):
            if "ipv4" in item:
                rules.append(item["ipv4"])
            elif "ipv6" in item:
                rules.append(item["ipv6"])
    if not rules and raw_items:
        rules = [r for r in raw_items if isinstance(r, dict)]

    findings = []
    allow_rules = []

    for rule in rules:
        if not isinstance(rule, dict): continue
        action = str(rule.get("action","")).lower()
        if action not in ("allow","permit","accept"): continue
        allow_rules.append(rule)

    total = len(allow_rules)
    summary = _result(summary_chk, True, str(total),
                      f"{total} regras ALLOW inspecionadas")

    def _fc(cid, title, sev, desc, rec, ok, val, det):
        return {"id":None,"cid":cid,"title":title,"category":"Firewall Policy",
                "severity":sev,"description":desc,"recommendation":rec,
                "status":"PASS" if ok else "FAIL","detail":det,
                "current_value":str(val),"pattern_type":"api"}

    for rule in allow_rules:
        nm      = rule.get("name") or "sem_nome"
        enabled = rule.get("enable") if "enable" in rule else True
        src_addr = (rule.get("source") or {}).get("address") or {}
        src_name = src_addr.get("name") or src_addr.get("group") or ""
        src_any  = src_name.lower() == "any"
        dst_addr = (rule.get("destination") or {}).get("address") or {}
        dst_name = dst_addr.get("name") or dst_addr.get("group") or ""
        dst_any  = dst_name.lower() == "any"

        # ── FWR-1: DPI ────────────────────────────────────────
        if "dpi_off" not in disabled and not _t(rule.get("dpi")):
            findings.append(_fc("FWR-1", f"DPI desabilitado — {nm}", "High",
                "Regras ALLOW devem ter inspeção DPI ativa para detectar ameaças no tráfego.",
                f"Editar regra '{nm}' → habilitar DPI.",
                False, "DPI off", "DPI desabilitado nesta regra"))

        # ── FWR-2: DPI-SSL ────────────────────────────────────
        dpi_ssl = rule.get("DPI SSL") or {}
        if "dpi_ssl_off" not in disabled and _t(rule.get("dpi")) and not (_t(dpi_ssl.get("client")) and _t(dpi_ssl.get("server"))):
            missing_ssl = [s for s in ("client","server") if not _t(dpi_ssl.get(s))]
            findings.append(_fc("FWR-2", f"DPI-SSL incompleto — {nm}", "Medium",
                "DPI-SSL inspeciona tráfego HTTPS/TLS. Client e Server devem estar ativos.",
                f"Editar regra '{nm}' → DPI-SSL → habilitar Client e Server.",
                False, f"off: {', '.join(missing_ssl)}", f"DPI-SSL desabilitado: {', '.join(missing_ssl)}"))

        # ── FWR-3: Botnet Filter (só per-regra; global cobre tudo) ───
        if ("botnet_off" not in disabled and not _botnet_global
                and not _t(rule.get("botnet_filter"))):
            findings.append(_fc("FWR-3", f"Botnet Filter desabilitado — {nm}", "High",
                "Botnet Filter bloqueia comunicação com servidores C&C conhecidos.",
                f"Editar regra '{nm}' → habilitar Botnet Filter.",
                False, "off", "Botnet Filter desabilitado"))

        # ── FWR-4: Geo-IP Filter (só per-regra; global cobre tudo) ──
        geo_rule = rule.get("geo_ip_filter") or {}
        if ("geoip_off" not in disabled and not _geoip_global
                and not _t(geo_rule.get("enable"))):
            findings.append(_fc("FWR-4", f"Geo-IP Filter desabilitado — {nm}", "Medium",
                "Geo-IP Filter permite bloquear tráfego de países de alto risco.",
                f"Editar regra '{nm}' → habilitar Geo-IP Filter.",
                False, "off", "Geo-IP Filter desabilitado nesta regra"))

        # ── FWR-5: Source ANY ─────────────────────────────────
        if "any_src" not in disabled and src_any:
            findings.append(_fc("FWR-5", f"Origem ANY — {nm}", "High",
                "Origem ANY amplia a superfície de ataque, permitindo qualquer host iniciar conexão.",
                f"Restringir origem da regra '{nm}' ao menor escopo possível.",
                False, "ANY", "Origem ANY detectada"))

        # ── FWR-6: Destination ANY ────────────────────────────
        if "any_dst" not in disabled and dst_any:
            findings.append(_fc("FWR-6", f"Destino ANY — {nm}", "Medium",
                "Destino ANY permite acesso irrestrito a todos os hosts.",
                f"Restringir destino da regra '{nm}'.",
                False, "ANY", "Destino ANY detectado"))

        # ── FWR-7: Sem Logging ────────────────────────────────
        if "no_log" not in disabled and not _t(rule.get("logging")):
            findings.append(_fc("FWR-7", f"Logging desabilitado — {nm}", "Medium",
                "Regras ALLOW sem log impedem auditoria de tráfego.",
                f"Editar regra '{nm}' → habilitar Logging.",
                False, "off", "Sem logging nesta regra"))

        # ── FWR-8: Fragments permitidos ───────────────────────
        if "fragments" not in disabled and _t(rule.get("fragments")):
            findings.append(_fc("FWR-8", f"Fragmentos permitidos — {nm}", "Medium",
                "Permitir pacotes fragmentados pode ser explorado para evasão de inspeção.",
                f"Desabilitar 'fragments' na regra '{nm}' salvo necessidade justificada.",
                False, "on", "Pacotes fragmentados permitidos"))

        # ── FWR-9: Schedule expirado ──────────────────────────
        sch = rule.get("schedule") or {}
        if "schedule_exp" not in disabled and isinstance(sch, dict) and _t(_d(sch, "expired")):
            findings.append(_fc("FWR-9", f"Schedule expirado — {nm}", "High",
                "Regras com schedule expirado devem ser revisadas e removidas.",
                f"Remover ou atualizar o schedule da regra '{nm}'.",
                False, _d(sch, "name") or "schedule", "Schedule expirado"))

        # ── FWR-10: Regra desabilitada ────────────────────────
        if "disabled" not in disabled and not enabled:
            findings.append(_fc("FWR-10", f"Regra desabilitada — {nm}", "Low",
                "Regras ALLOW desabilitadas devem ser removidas para manter a política limpa.",
                f"Revisar e remover a regra '{nm}' se não for mais necessária.",
                False, "disabled", "Regra ALLOW desabilitada (candidata a remoção)"))

        # ── FWR-11: Sem uso (0 hits) ──────────────────────────
        if "no_hits" not in disabled:
            hits = rule.get("hit_count") or rule.get("hits") or rule.get("packets")
            if hits is not None:
                try:
                    if int(hits) == 0:
                        findings.append(_fc("FWR-11", f"Regra sem uso (0 hits) — {nm}", "Low",
                            "Regras sem tráfego podem ser obsoletas e devem ser revisadas.",
                            f"Verificar se a regra '{nm}' ainda é necessária.",
                            False, "0 hits", "Nenhum tráfego processado por esta regra"))
                except (ValueError, TypeError):
                    pass

    return findings, summary


# ─────────────────────────────────────────────────────────────
# STRUCTURED RULES AUDIT (used by public.py for dedicated tab)
# ─────────────────────────────────────────────────────────────
def get_rules_audit(data: dict) -> dict:
    """Return structured firewall rules security audit for SonicWall."""
    ar_data = data.get("access_rules") or data.get("fw_base")
    raw_items = _d(ar_data, "access_rules") or ar_data or []
    if isinstance(raw_items, dict):
        raw_items = raw_items.get("access_rules") or list(raw_items.values())
    if not isinstance(raw_items, list):
        raw_items = []
    # SonicOS wraps each rule as {"ipv4": {...}} or {"ipv6": {...}}
    rules_raw = []
    v4_count = v6_count = 0
    for item in raw_items:
        if isinstance(item, dict):
            if "ipv4" in item:
                rules_raw.append(item["ipv4"])
                v4_count += 1
            elif "ipv6" in item:
                rules_raw.append(item["ipv6"])
                v6_count += 1
    if not rules_raw and raw_items:
        rules_raw = [r for r in raw_items if isinstance(r, dict)]

    allow_rules = [r for r in rules_raw if isinstance(r, dict)
                   and str(r.get("action","")).lower() in ("allow","permit","accept")]
    deny_rules  = [r for r in rules_raw if isinstance(r, dict)
                   and str(r.get("action","")).lower() in ("deny","block","discard","drop")]

    disabled = data.get("_disabled_rule_tags") or set()
    # Detect global protection modes via real-API helpers
    _botnet_global = _botnet_mode(data) == "global"
    _geoip_global  = _geoip_mode(data)  == "global"
    findings = []
    counters = {
        "dpi_disabled": 0, "dpi_ssl_disabled": 0, "botnet_disabled": 0,
        "geoip_disabled": 0, "any_source": 0, "any_dest": 0,
        "no_logging": 0, "fragments": 0, "unused": 0,
    }

    for rule in allow_rules:
        nm       = rule.get("name") or "sem_nome"
        src_addr = (rule.get("source") or {}).get("address") or {}
        src_name = src_addr.get("name") or src_addr.get("group") or ""
        src_any  = src_name.lower() == "any"
        dst_addr = (rule.get("destination") or {}).get("address") or {}
        dst_name = dst_addr.get("name") or dst_addr.get("group") or ""
        dst_any  = dst_name.lower() == "any"

        if "dpi_off" not in disabled and not _t(rule.get("dpi")):
            counters["dpi_disabled"] += 1
            findings.append(_rule_finding("DPI Desabilitado", nm, "High",
                "DPI não está ativo nesta regra. Ameaças no tráfego não serão inspecionadas.",
                f"Editar '{nm}' → habilitar DPI.", "dpi_off"))

        dpi_ssl = rule.get("DPI SSL") or {}
        if "dpi_ssl_off" not in disabled and _t(rule.get("dpi")) and not (_t(dpi_ssl.get("client")) and _t(dpi_ssl.get("server"))):
            missing_ssl = [s for s in ("client","server") if not _t(dpi_ssl.get(s))]
            counters["dpi_ssl_disabled"] += 1
            findings.append(_rule_finding("DPI-SSL Incompleto", nm, "Medium",
                f"DPI-SSL desabilitado: {', '.join(missing_ssl)}. Tráfego TLS não será inspecionado.",
                f"Editar '{nm}' → DPI-SSL → habilitar Client e Server.", "dpi_ssl_off"))

        if ("botnet_off" not in disabled and not _botnet_global
                and not _t(rule.get("botnet_filter"))):
            counters["botnet_disabled"] += 1
            findings.append(_rule_finding("Botnet Filter Desabilitado", nm, "High",
                "Botnet Filter bloqueia comunicação com servidores C&C conhecidos.",
                f"Editar '{nm}' → habilitar Botnet Filter.", "botnet_off"))

        geo_rule = rule.get("geo_ip_filter") or {}
        if ("geoip_off" not in disabled and not _geoip_global
                and not _t(geo_rule.get("enable"))):
            counters["geoip_disabled"] += 1
            findings.append(_rule_finding("Geo-IP Filter Desabilitado", nm, "Medium",
                "Geo-IP Filter permite bloquear tráfego de países de alto risco.",
                f"Editar '{nm}' → habilitar Geo-IP Filter.", "geoip_off"))

        if "any_src" not in disabled and src_any:
            counters["any_source"] += 1
            findings.append(_rule_finding("Origem ANY", nm, "High",
                "Regra permite qualquer host como origem.",
                f"Restringir origem de '{nm}'.", "any_src"))

        if "any_dst" not in disabled and dst_any:
            counters["any_dest"] += 1
            findings.append(_rule_finding("Destino ANY", nm, "Medium",
                "Regra permite qualquer host como destino.",
                f"Restringir destino de '{nm}'.", "any_dst"))

        if "no_log" not in disabled and not _t(rule.get("logging")):
            counters["no_logging"] += 1
            findings.append(_rule_finding("Sem Logging", nm, "Medium",
                "Tráfego desta regra não é registrado.",
                f"Habilitar logging em '{nm}'.", "no_log"))

        if "fragments" not in disabled and _t(rule.get("fragments")):
            counters["fragments"] += 1
            findings.append(_rule_finding("Fragmentos Permitidos", nm, "Medium",
                "Pacotes fragmentados podem ser usados para evasão de inspeção.",
                f"Desabilitar 'fragments' em '{nm}' salvo necessidade justificada.", "fragments"))

        hits = rule.get("hit_count") or rule.get("hits")
        enabled = rule.get("enable") if "enable" in rule else True
        if ("disabled" not in disabled and not _t(enabled)) or \
           ("no_hits" not in disabled and hits is not None and _safe_int(hits) == 0):
            counters["unused"] += 1
            findings.append(_rule_finding("Regra Sem Uso / Desabilitada", nm, "Low",
                "Regra com 0 hits ou desabilitada é candidata a remoção.",
                f"Revisar e remover '{nm}' se obsoleta.", "unused"))

    return {
        "vendor":      "sonicwall",
        "total_rules": len(rules_raw),
        "ipv4_rules":  v4_count,
        "ipv6_rules":  v6_count,
        "allow_rules": len(allow_rules),
        "deny_rules":  len(deny_rules),
        "counters":    counters,
        "findings":    sorted(findings, key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3}.get(x["severity"],4)),
    }


def _rule_finding(check, rule_name, severity, detail, recommendation, tag):
    return {"check": check, "rule": rule_name, "severity": severity,
            "detail": detail, "recommendation": recommendation, "tag": tag}

def _safe_int(v):
    try: return int(v)
    except: return -1


# ─────────────────────────────────────────────────────────────
# HELPERS DE NAVEGAÇÃO PROFUNDA (DEEP FIND)
# ─────────────────────────────────────────────────────────────
def _deep_find(obj, key, max_depth=4, current_depth=0):
    """Busca recursivamente uma chave ignorando diferenças de hífen e underscore."""
    if not isinstance(obj, dict) or current_depth > max_depth:
        return None
    if key in obj: return obj[key]
    if key.replace('_', '-') in obj: return obj[key.replace('_', '-')]
    if key.replace('-', '_') in obj: return obj[key.replace('-', '_')]
    
    for v in obj.values():
        if isinstance(v, dict):
            res = _deep_find(v, key, max_depth, current_depth + 1)
            if res is not None: return res
    return None

def _d(obj,*keys):
    """Fallback antigo com resiliência de sintaxe"""
    for k in keys:
        if not isinstance(obj,dict) or k not in obj: 
            # tenta com underscore/hifen
            k_dash = k.replace('_', '-')
            k_under = k.replace('-', '_')
            if k_dash in obj: obj = obj[k_dash]
            elif k_under in obj: obj = obj[k_under]
            else: return None
        else:
            obj = obj[k]
    return obj

def _t(v):
    if v is None: return False
    if isinstance(v, bool): return v
    if isinstance(v, (int, float)): return v != 0
    return str(v).lower() in ("true","1","yes","enable","enabled","on","active")

def _f(v): return not _t(v)

def _bv(v):
    return "on" if _t(v) else ("—" if v is None else "off")



