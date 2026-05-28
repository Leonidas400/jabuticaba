"""
pfsense_api.py — CIS Benchmark via pfSense REST API
pfSense CE 2.7+ / pfSense Plus com API habilitada
Plugin: pfSense-pkg-API (https://github.com/jaredhendrickson13/pfsense-api)
Endpoint base: https://<host>/api/v1/
"""
import requests, urllib3
from api_runner import run_db_checks, _result
from vendor_base import _d, _t, _bv, _dl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PfSenseAPIClient:
    def __init__(self, host, username, password, port=443, timeout=15, api_key=""):
        self.base    = f"https://{host}:{port}/api/v1"
        self.auth    = (username, password)
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"Content-Type":"application/json","Accept":"application/json"})
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def login(self):
        if self.api_key:
            try:
                r = self.session.get(f"{self.base}/system/version", timeout=self.timeout)
                if r.status_code == 200: return True, ""
                return False, f"API Key inválida — HTTP {r.status_code}"
            except requests.ConnectionError: return False, "Não foi possível conectar."
            except requests.Timeout:         return False, "Timeout na conexão."
            except Exception as e:           return False, str(e)
        try:
            r = self.session.get(f"{self.base}/system/version",
                                 auth=self.auth, timeout=self.timeout)
            if r.status_code == 200:
                self.session.auth = self.auth
                return True, ""
            return False, f"HTTP {r.status_code} — Verifique credenciais e se o plugin API está instalado."
        except requests.ConnectionError: return False, "Não foi possível conectar."
        except requests.Timeout:         return False, "Timeout na conexão."
        except Exception as e:           return False, str(e)

    def logout(self): pass  # Stateless API

    def get(self, path):
        try:
            r = self.session.get(f"{self.base}/{path.lstrip('/')}", timeout=self.timeout)
            if r.status_code == 200:
                d = r.json()
                return d.get("data", d)
            return None
        except: return None


def run_api_checks(client):
    from vendor_base import run_api_checks_generic
    return run_api_checks_generic("pfsense", client, "pfsense_api")


# ─────────────────────────────────────────────────────────────
# COMPLEX HANDLERS
# ─────────────────────────────────────────────────────────────

def _h_version(chk, data):
    ver = _dv(data.get("version"),"version") or ""
    return _result(chk, bool(ver), ver or "—",
                   f"pfSense {ver} ✓" if ver else "Versão não obtida")


def _h_hostname(chk, data):
    hn = _dv(data.get("hostname"),"hostname") or ""
    default_hn = {"pfsense","pfsense","firewall","router",""}
    ok = hn.lower() not in {h.lower() for h in default_hn}
    return _result(chk, ok, hn or "—",
                   f"Hostname: {hn} ✓" if ok else "Hostname padrão")


def _h_ssh(chk, data):
    ssh = data.get("ssh") or {}
    ssh_en = _dv(ssh,"enabled") or _dv(ssh,"enable")
    ok = not _t(ssh_en)
    return _result(chk, ok, _bv(ssh_en),
                   "SSH desabilitado ✓" if ok else "SSH habilitado — verificar restrições")


def _h_timeout(chk, data):
    cfg = _dv(data.get("config"),"config") or data.get("config") or {}
    timeout = _dv(cfg,"system","timeout")
    tunables = data.get("tunable") or []
    for t in (tunables if isinstance(tunables,list) else []):
        if isinstance(t,dict) and "session" in str(t.get("tunable","")).lower():
            timeout = t.get("value")
    return _result(chk, timeout is not None,
                   str(timeout) if timeout else "—",
                   f"Timeout configurado: {timeout} ✓" if timeout else "Timeout não configurado")


def _h_admin_user(chk, data):
    users_raw = data.get("users") or []
    users = users_raw if isinstance(users_raw,list) else [users_raw]
    admin_users = [u for u in users if isinstance(u,dict) and
                   u.get("username","").lower() in ("admin","administrator")]
    ok = len(admin_users) > 0
    return _result(chk, ok,
                   f"{len(admin_users)} admin(s)",
                   "Usuário admin existe (senha deve ser verificada manualmente)" if ok
                   else "Admin não encontrado")


def _h_snmp_community(chk, data):
    snmp = data.get("snmp") or {}
    snmp_ro = _dv(snmp,"rocommunity") or _dv(snmp,"community")
    if not snmp_ro:
        return None
    pub = str(snmp_ro).strip().lower() == "public"
    return _result(chk, not pub, str(snmp_ro),
                   "Comunidade personalizada ✓" if not pub else "'public' detectada!")


def _h_ntp(chk, data):
    ntp = data.get("ntp") or {}
    ntp_svr = _dv(ntp,"timeservers") or _dv(ntp,"server")
    ok = bool(ntp_svr)
    return _result(chk, ok,
                   str(ntp_svr)[:40] if ntp_svr else "—",
                   "NTP configurado ✓" if ok else "NTP não configurado")


def _h_syslog(chk, data):
    syslog = data.get("syslog") or {}
    sl_en  = _dv(syslog,"enable") or _dv(syslog,"enabled")
    sl_svr = _dv(syslog,"remoteserver") or _dv(syslog,"server")
    ok = bool(sl_svr) and _t(sl_en)
    return _result(chk, ok,
                   str(sl_svr) if sl_svr else "—",
                   f"Syslog → {sl_svr} ✓" if ok else "Syslog remoto não configurado")


def _h_any_any(chk, data):
    fw_rules = data.get("firewall_rules") or []
    any_any = [r for r in (fw_rules if isinstance(fw_rules,list) else [])
               if isinstance(r,dict) and r.get("type","")=="pass"
               and str(r.get("source",{}).get("network","")).lower()=="any"
               and str(r.get("destination",{}).get("network","")).lower()=="any"]
    ok = len(any_any) == 0
    return _result(chk, ok,
                   f"{len(any_any)} regra(s)" if any_any else "Nenhuma",
                   "Sem regras ANY→ANY ✓" if ok else f"{len(any_any)} regra(s) PASS ANY→ANY!")


def _h_fw_log(chk, data):
    fw_rules = data.get("firewall_rules") or []
    no_log   = [r for r in (fw_rules if isinstance(fw_rules,list) else [])
                if isinstance(r,dict) and r.get("type","")=="pass" and not _t(r.get("log"))]
    ok = len(no_log) == 0
    return _result(chk, ok,
                   f"{len(no_log)} sem log" if no_log else "Todas com log",
                   "Todas as regras com log ✓" if ok else f"{len(no_log)} regra(s) sem log")


def _h_nat_risky(chk, data):
    nat_rules   = data.get("nat") or []
    risky_ports = {22:"SSH",23:"Telnet",3389:"RDP",3306:"MySQL",5432:"PostgreSQL"}
    risky_nat   = []
    for nr in (nat_rules if isinstance(nat_rules,list) else []):
        if not isinstance(nr,dict): continue
        lport = str(nr.get("local-port","") or nr.get("localport",""))
        dport = str(nr.get("destination",{}).get("port",""))
        for port,name in risky_ports.items():
            if str(port) in (lport+dport):
                risky_nat.append(f"{name}({port})")
    ok = len(risky_nat) == 0
    return _result(chk, ok,
                   ", ".join(risky_nat) if risky_nat else "Nenhum",
                   "Sem exposições críticas via NAT ✓" if ok
                   else f"Expostos: {', '.join(risky_nat)}")


def _h_block_private(chk, data):
    """WAN interfaces should block private networks."""
    ifaces = data.get("interfaces") or []
    ifaces_list = ifaces if isinstance(ifaces, list) else list(ifaces.values()) if isinstance(ifaces, dict) else []
    wan_ifaces = [i for i in ifaces_list if isinstance(i, dict) and
                  str(i.get("if","") or i.get("name","")).lower() in ("wan","wan1","wan2","pppoe","dhcp")]
    if not wan_ifaces:
        wan_ifaces = [i for i in ifaces_list if isinstance(i, dict) and
                      not _t(i.get("internal","")) and i.get("ipaddr","") not in ("","dhcp")]
    no_block = [i.get("if","") or i.get("name","") for i in wan_ifaces
                if not _t(i.get("blockpriv",""))]
    ok = len(no_block) == 0
    return _result(chk, ok,
                   f"{len(no_block)} interface(s) sem bloqueio" if no_block else "OK",
                   "Redes privadas bloqueadas na WAN ✓" if ok
                   else f"WAN sem bloqueio de privadas: {', '.join(no_block)}")


def _h_block_bogon(chk, data):
    """WAN interfaces should block bogon networks."""
    ifaces = data.get("interfaces") or []
    ifaces_list = ifaces if isinstance(ifaces, list) else list(ifaces.values()) if isinstance(ifaces, dict) else []
    wan_ifaces = [i for i in ifaces_list if isinstance(i, dict) and
                  str(i.get("if","") or i.get("name","")).lower() in ("wan","wan1","wan2","pppoe","dhcp")]
    if not wan_ifaces:
        wan_ifaces = [i for i in ifaces_list if isinstance(i, dict) and
                      not _t(i.get("internal","")) and i.get("ipaddr","") not in ("","dhcp")]
    no_block = [i.get("if","") or i.get("name","") for i in wan_ifaces
                if not _t(i.get("blockbogons",""))]
    ok = len(no_block) == 0
    return _result(chk, ok,
                   f"{len(no_block)} interface(s) sem bloqueio" if no_block else "OK",
                   "Bogons bloqueados na WAN ✓" if ok
                   else f"WAN sem bloqueio de bogons: {', '.join(no_block)}")


def _h_webgui_port(chk, data):
    """WebGUI should run on a non-default port (not 80 or 443)."""
    webgui = data.get("webgui") or {}
    port = str(webgui.get("port","") or webgui.get("loginpagecolor","")).strip()
    ok = bool(port) and port not in ("","80","443","0")
    return _result(chk, ok,
                   f"Porta {port}" if port else "Padrão (443)",
                   f"WebGUI na porta não padrão {port} ✓" if ok
                   else "WebGUI na porta padrão — recomendado usar porta alternativa")


def _h_vpn_tls(chk, data):
    """OpenVPN servers should use TLS authentication."""
    servers = data.get("openvpn") or []
    servers = servers if isinstance(servers, list) else [servers] if servers else []
    no_tls = [s.get("description","") or str(s.get("vpnid","")) for s in servers
              if isinstance(s, dict) and not _t(s.get("tlsauth_enable",""))]
    ok = not servers or len(no_tls) == 0
    return _result(chk, ok,
                   f"{len(no_tls)} sem TLS Auth" if no_tls else f"{len(servers)} servidor(es) com TLS",
                   "OpenVPN com TLS Auth ✓" if ok
                   else f"{len(no_tls)} servidor(es) sem TLS Auth")


def _h_vpn_cipher(chk, data):
    """OpenVPN servers should not use weak ciphers."""
    weak_ciphers = {"DES","RC2","RC4","BF","CAST5","NULL"}
    servers = data.get("openvpn") or []
    servers = servers if isinstance(servers, list) else [servers] if servers else []
    weak = []
    for s in servers:
        if not isinstance(s, dict): continue
        cipher = str(s.get("crypto","") or s.get("data_ciphers","")).upper()
        desc = s.get("description","") or str(s.get("vpnid",""))
        if any(w in cipher for w in weak_ciphers):
            weak.append(f"{desc}({cipher[:20]})")
    ok = not servers or len(weak) == 0
    return _result(chk, ok,
                   ", ".join(weak) if weak else "Ciphers fortes",
                   "OpenVPN sem cifras fracas ✓" if ok
                   else f"Cifras fracas: {', '.join(weak)}")


def _h_ipsec_weak(chk, data):
    """IPsec Phase1 should not use weak algorithms."""
    p1_list = data.get("ipsec_p1") or []
    p1_list = p1_list if isinstance(p1_list, list) else [p1_list] if p1_list else []
    weak = []
    for p in p1_list:
        if not isinstance(p, dict): continue
        enc   = str(p.get("encryption-algorithm","") or p.get("encr","")).upper()
        hsh   = str(p.get("hash-algorithm","") or p.get("hash","")).upper()
        name  = p.get("descr","") or p.get("ikeid","")
        if any(w in enc for w in ("DES","RC4","NULL")): weak.append(f"{name}(enc:{enc[:10]})")
        if "MD5" in hsh:                                 weak.append(f"{name}(hash:MD5)")
    ok = not p1_list or len(weak) == 0
    return _result(chk, ok,
                   ", ".join(weak) if weak else "Algoritmos fortes",
                   "IPsec Phase1 sem algoritmos fracos ✓" if ok
                   else f"Fraco: {', '.join(weak)}")


def _h_unbound_enabled(chk, data):
    """Unbound DNS resolver should be enabled."""
    unbound = data.get("unbound") or {}
    enabled = _dv(unbound,"enable") or _dv(unbound,"enabled")
    ok = _t(enabled)
    return _result(chk, ok, _bv(enabled),
                   "DNS Resolver (Unbound) habilitado ✓" if ok
                   else "DNS Resolver não habilitado")


def _h_log_blocks(chk, data):
    """Firewall should log blocked packets (default block rule logging)."""
    cfg = data.get("config") or {}
    syslog = data.get("syslog") or {}
    # Check if filter logging is enabled in syslog or config
    log_filter = (_dv(syslog,"filter") or _dv(cfg,"syslog","filter")
                  or _dv(cfg,"system","syslog","filter"))
    ok = _t(log_filter)
    return _result(chk, ok, _bv(log_filter),
                   "Log de tráfego bloqueado habilitado ✓" if ok
                   else "Log de bloqueios não configurado")


def _h_use_aliases(chk, data):
    """Firewall rules should use aliases rather than raw IPs."""
    aliases = data.get("firewall_aliases") or []
    aliases = aliases if isinstance(aliases, list) else []
    rules   = data.get("firewall_rules") or []
    rules   = rules   if isinstance(rules,   list) else []
    pass_rules = [r for r in rules if isinstance(r, dict) and r.get("type","") == "pass"]
    has_aliases = len(aliases) > 0
    ok = has_aliases
    return _result(chk, ok,
                   f"{len(aliases)} alias(es) definidos",
                   f"{len(aliases)} alias(es) configurados ✓" if ok
                   else "Nenhum alias definido — regras devem usar aliases")


def _h_pkg_update(chk, data):
    """Installed packages should be up to date."""
    packages = data.get("packages") or []
    packages = packages if isinstance(packages, list) else []
    outdated = [p.get("name","") for p in packages
                if isinstance(p, dict) and str(p.get("installed_version","")) != str(p.get("version",""))
                and p.get("installed_version","")]
    ok = len(outdated) == 0
    return _result(chk, ok,
                   f"{len(outdated)} desatualizado(s)" if outdated else f"{len(packages)} em dia",
                   "Todos os pacotes atualizados ✓" if ok
                   else f"Pacotes desatualizados: {', '.join(outdated[:5])}")


def _h_cert(chk, data):
    certs = data.get("cert") or []
    self_signed = [c for c in (certs if isinstance(certs,list) else [])
                   if isinstance(c,dict) and c.get("caref","")==""]
    ok = len(self_signed) == 0 or len(certs) > 1
    return _result(chk, ok,
                   f"{len(certs)} certificado(s)",
                   f"{len(certs)} certificado(s) configurado(s) ✓" if len(certs)>1
                   else "Apenas certificado padrão")


# ─────────────────────────────────────────────────────────────
# FWR-0: ACCESS RULES AUDIT
# ─────────────────────────────────────────────────────────────
def _h_access_rules(chk, data):
    """Audit all PASS rules (pfSense FWR-0)."""
    rules = data.get("firewall_rules") or []
    if not isinstance(rules, list): rules = []
    
    disabled = data.get("_disabled_rule_tags") or set()
    
    findings = []
    counters = {"risky_port":0, "any_src":0, "any_dst":0, "no_log":0, "disabled":0}
    
    RISKY_PORTS = {22:"SSH", 23:"Telnet", 3389:"RDP", 3306:"MySQL", 5432:"PostgreSQL", 1433:"MSSQL", 5900:"VNC"}
    
    for r in rules:
        if not isinstance(r, dict) or r.get("type") != "pass":
            continue
        nm = r.get("descr", "") or f"rule-{r.get('interface', '?')}"
        enabled = r.get("disabled") is None or not _t(r.get("disabled"))
        
        # Check: risky ports
        if "risky_port" not in disabled:
            dst_port = str(r.get("destination", {}).get("port", "")).strip()
            for port_int, label in RISKY_PORTS.items():
                port_str = str(port_int)
                if dst_port == port_str or dst_port.startswith(port_str+":") or ":"+port_str in dst_port:
                    findings.append(_result(chk, False, nm, f"Porta perigosa: {label}"))
                    counters["risky_port"] += 1
                    break
        
        # Check: source ANY
        if "any_src" not in disabled:
            src = str(r.get("source", {}).get("network", "")).lower()
            if src == "any":
                findings.append(_result(chk, False, nm, "Origem ANY detectada"))
                counters["any_src"] += 1
        
        # Check: destination ANY
        if "any_dst" not in disabled:
            dst = str(r.get("destination", {}).get("network", "")).lower()
            if dst == "any":
                findings.append(_result(chk, False, nm, "Destino ANY detectado"))
                counters["any_dst"] += 1
        
        # Check: no log
        if "no_log" not in disabled:
            if not _t(r.get("log")):
                findings.append(_result(chk, False, nm, "Logging desabilitado"))
                counters["no_log"] += 1
        
        # Check: disabled rule
        if "disabled" not in disabled and not enabled:
            findings.append(_result(chk, False, nm, "Regra desabilitada"))
            counters["disabled"] += 1
    
    total_issues = sum(counters.values())
    summary = _result(chk, total_issues == 0,
                    f"{len(rules)} regras inspecionadas",
                    f"{total_issues} problemas" if total_issues else "Nenhum problema")
    
    results = [summary]
    results.extend(findings)
    return results


# ─────────────────────────────────────────────────────────────
# HANDLER REGISTRY
# ─────────────────────────────────────────────────────────────
_HANDLERS = {
    "pf_version":        _h_version,
    "pf_hostname":       _h_hostname,
    "pf_ssh":            _h_ssh,
    "pf_timeout":        _h_timeout,
    "pf_admin_user":     _h_admin_user,
    "pf_snmp_community": _h_snmp_community,
    "pf_ntp":            _h_ntp,
    "pf_syslog":         _h_syslog,
    "pf_any_any":        _h_any_any,
    "pf_fw_log":         _h_fw_log,
    "pf_nat_risky":      _h_nat_risky,
    "pf_cert":           _h_cert,
    "pf_block_private":  _h_block_private,
    "pf_block_bogon":    _h_block_bogon,
    "pf_webgui_port":    _h_webgui_port,
    "pf_vpn_tls":        _h_vpn_tls,
    "pf_vpn_cipher":     _h_vpn_cipher,
    "pf_ipsec_weak":     _h_ipsec_weak,
    "pf_unbound_enabled":_h_unbound_enabled,
    "pf_log_blocks":     _h_log_blocks,
    "pf_use_aliases":    _h_use_aliases,
    "pf_pkg_update":     _h_pkg_update,
    "pf_access_rules":   _h_access_rules,
}


# ─────────────────────────────────────────────────────────────
# RISKY PORTS
# ─────────────────────────────────────────────────────────────
RISKY_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    3389:"RDP", 1521:"Oracle DB", 3306:"MySQL/MariaDB",
    5432:"PostgreSQL", 1433:"MSSQL", 5900:"VNC",
    6379:"Redis", 27017:"MongoDB", 11211:"Memcached",
}


# ─────────────────────────────────────────────────────────────
# STRUCTURED RULES AUDIT
# ─────────────────────────────────────────────────────────────
def get_rules_audit(data: dict) -> dict:
    """Return structured firewall rules security audit for pfSense."""
    rules_raw = data.get("firewall_rules") or []
    if not isinstance(rules_raw, list): rules_raw = []

    pass_rules  = [r for r in rules_raw if isinstance(r, dict) and r.get("type","") == "pass"]
    block_rules = [r for r in rules_raw if isinstance(r, dict) and r.get("type","") in ("block","reject")]

    disabled = data.get("_disabled_rule_tags") or set()
    findings = []
    counters = {"risky_ports":0,"any_source":0,"no_logging":0,"unused":0}

    for rule in pass_rules:
        iface = rule.get("interface","") or rule.get("if","") or "?"
        descr = rule.get("descr","") or rule.get("tracker","") or f"regra-{iface}"
        nm = descr if descr else f"iface:{iface}"
        enabled = rule.get("disabled") is None or not _t(rule.get("disabled"))

        # ── Portas perigosas no destino ────────────────────────
        if "risky_port" not in disabled:
            dst_port = str(rule.get("destination",{}).get("port","") or "").strip()
            if dst_port:
                for port_int, label in RISKY_PORTS.items():
                    port_str = str(port_int)
                    if dst_port == port_str or dst_port.startswith(port_str+":") or dst_port.endswith(":"+port_str):
                        counters["risky_ports"] += 1
                        src_any = str(rule.get("source",{}).get("network","")).lower() == "any"
                        findings.append(_pf_rf("Porta Perigosa: "+label, nm, "Critical" if src_any else "High",
                            f"Regra PASS para porta {port_int} ({label}){' com origem ANY' if src_any else ''}.",
                            f"Restringir ou remover regra '{nm}' — usar VPN para acesso a {label}.", f"port_{port_int}"))
                        break

        # ── Origem ANY ────────────────────────────────────────
        if "any_src" not in disabled:
            src_net = str(rule.get("source",{}).get("network","")).lower()
            src_any_flag = _t(rule.get("source",{}).get("any","")) or src_net == "any"
            if src_any_flag:
                counters["any_source"] += 1
                findings.append(_pf_rf("Origem ANY", nm, "High",
                    "Regra PASS aceita tráfego de qualquer origem.",
                    f"Restringir origem da regra '{nm}' ao menor escopo.", "any_src"))

        # ── Sem logging ───────────────────────────────────────
        if "no_log" not in disabled and not _t(rule.get("log")):
            counters["no_logging"] += 1
            findings.append(_pf_rf("Sem Logging", nm, "Medium",
                "Tráfego desta regra não é registrado.",
                f"Habilitar Log em '{nm}' para auditoria.", "no_log"))

        # ── Regra desabilitada ─────────────────────────────────
        if "disabled" not in disabled and not enabled:
            counters["unused"] += 1
            findings.append(_pf_rf("Regra Desabilitada", nm, "Low",
                "Regra desabilitada é candidata a remoção.",
                f"Revisar e remover '{nm}' se obsoleta.", "disabled"))

    return {
        "vendor":       "pfsense",
        "total_rules":  len(rules_raw),
        "allow_rules":  len(pass_rules),
        "deny_rules":   len(block_rules),
        "counters":     counters,
        "findings":     sorted(findings, key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3}.get(x["severity"],4)),
    }


def _pf_rf(check, rule_name, severity, detail, recommendation, tag):
    return {"check": check, "rule": rule_name, "severity": severity,
            "detail": detail, "recommendation": recommendation, "tag": tag}
