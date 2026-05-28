"""
fortigate_api.py — CIS Benchmark via FortiGate REST API (FortiOS 7.x)
Docs: https://fndn.fortinet.net/
Auth: API Key via header X-Auth-Token (recomendado) ou session: POST /logincheck
"""
import requests, urllib3
from api_runner import run_db_checks, _result
from vendor_base import _d, _t, _bv, _dl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortiGateAPIClient:
    def __init__(self, host, username, password, port=443, timeout=15, api_key=""):
        self.base    = f"https://{host}:{port}/api/v2"
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
                r = self.session.get(f"{self.base}/monitor/system/status", timeout=self.timeout)
                if r.status_code == 200: return True, ""
                return False, f"API Key inválida — HTTP {r.status_code}"
            except requests.ConnectionError: return False, "Não foi possível conectar."
            except requests.Timeout:         return False, "Timeout na conexão."
            except Exception as e:           return False, str(e)
        try:
            r = self.session.post(f"https://{self.base.split('/api')[0].split('://')[-1]}/logincheck",
                data={"username": self.auth[0], "secretkey": self.auth[1]},
                timeout=self.timeout, verify=False)
            if r.status_code == 200 and "APSCOOKIE" in r.cookies:
                self.session.cookies.update(r.cookies)
                csrf = r.cookies.get("ccsrftoken","").strip('"')
                if csrf: self.session.headers["X-CSRFTOKEN"] = csrf
                return True, ""
            return False, f"Login falhou — HTTP {r.status_code}"
        except requests.ConnectionError: return False, "Não foi possível conectar."
        except requests.Timeout:         return False, "Timeout na conexão."
        except Exception as e:           return False, str(e)

    def logout(self):
        try: self.session.post(f"{self.base.replace('/api/v2','')}/logout", timeout=5)
        except: pass

    def get(self, path):
        try:
            r = self.session.get(f"{self.base}/{path.lstrip('/')}", timeout=self.timeout)
            if r.status_code == 200:
                d = r.json()
                return d.get("results", d)
            return None
        except: return None

    def get_raw(self, path):
        try:
            r = self.session.get(f"{self.base}/{path.lstrip('/')}", timeout=self.timeout)
            return r.json() if r.status_code == 200 else None
        except: return None


def run_api_checks(client):
    from vendor_base import run_api_checks_generic
    return run_api_checks_generic("fortigate", client, "fortigate_api")


# ─────────────────────────────────────────────────────────────
# COMPLEX HANDLERS
# ─────────────────────────────────────────────────────────────

def _h_firmware(chk, data):
    raw = data.get("status")
    ver = _d(raw,"version") or _d(raw,"results","version") or ""
    return _result(chk, bool(ver), ver or "—",
                   f"FortiOS {ver} ✓" if ver else "Versão não obtida via API")


def _h_hostname(chk, data):
    g    = data.get("global") or {}
    host = _d(g,"hostname") or ""
    default_names = {"fortigate","fg","fgt","firewall",""}
    ok = host.lower() not in default_names
    return _result(chk, ok, host or "—",
                   f"Hostname: {host} ✓" if ok else "Hostname padrão detectado")


def _h_http_ifaces(chk, data):
    ifaces = data.get("interfaces") or []
    http_ifaces = [i.get("name","") for i in (ifaces if isinstance(ifaces,list) else [])
                   if "http" in str(i.get("allowaccess","")).lower()]
    ok = len(http_ifaces) == 0
    return _result(chk, ok,
                   ", ".join(http_ifaces) if http_ifaces else "nenhuma",
                   "HTTP desabilitado em todas interfaces ✓" if ok
                   else f"HTTP ativo em: {', '.join(http_ifaces)}")


def _h_telnet_ifaces(chk, data):
    ifaces = data.get("interfaces") or []
    telnet_ifaces = [i.get("name","") for i in (ifaces if isinstance(ifaces,list) else [])
                     if "telnet" in str(i.get("allowaccess","")).lower()]
    ok = len(telnet_ifaces) == 0
    return _result(chk, ok,
                   ", ".join(telnet_ifaces) if telnet_ifaces else "nenhuma",
                   "Telnet desabilitado ✓" if ok
                   else f"Telnet ativo em: {', '.join(telnet_ifaces)}")


def _h_snmp_public(chk, data):
    snmp_comm = data.get("snmp") or []
    public_comm = [c.get("name","") for c in (snmp_comm if isinstance(snmp_comm,list) else [])
                   if str(c.get("name","")).lower()=="public"]
    ok = len(public_comm) == 0
    return _result(chk, ok,
                   "'public' encontrada" if public_comm else "OK",
                   "Sem comunidade 'public' ✓" if ok else "Comunidade 'public' detectada!")


def _h_ntp(chk, data):
    ntp = data.get("ntp") or {}
    ntp_en = _d(ntp,"ntpsync") or _d(ntp,"syncinterval")
    ok = bool(ntp_en) and str(ntp_en).lower() not in ("disable","0")
    return _result(chk, ok, str(ntp_en) or "—",
                   "NTP habilitado ✓" if ok else "NTP desabilitado")


def _h_pol_av(chk, data):
    policies = data.get("firewall_pol") or []
    pol_no_av = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
                 if p.get("action")=="accept" and not p.get("av-profile","").strip()]
    ok = len(pol_no_av) == 0
    return _result(chk, ok,
                   f"{len(pol_no_av)} sem AV" if pol_no_av else "Todas com AV",
                   "Todas políticas com AV ✓" if ok
                   else f"{len(pol_no_av)} política(s) sem AV")


def _h_pol_ips(chk, data):
    policies = data.get("firewall_pol") or []
    pol_no_ips = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
                  if p.get("action")=="accept" and not p.get("ips-sensor","").strip()]
    ok = len(pol_no_ips) == 0
    return _result(chk, ok,
                   f"{len(pol_no_ips)} sem IPS" if pol_no_ips else "Todas com IPS",
                   "Todas políticas com IPS ✓" if ok
                   else f"{len(pol_no_ips)} política(s) sem IPS")


def _h_pol_log(chk, data):
    policies = data.get("firewall_pol") or []
    pol_no_log = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
                  if p.get("action")=="accept" and p.get("logtraffic","disable")=="disable"]
    ok = len(pol_no_log) == 0
    return _result(chk, ok,
                   f"{len(pol_no_log)} sem log" if pol_no_log else "Todas com log",
                   "Todas políticas com log ✓" if ok
                   else f"{len(pol_no_log)} política(s) sem log")


def _h_vpn_weak(chk, data):
    vpn_p1 = data.get("vpn_phase1") or []
    weak   = []
    for p in (vpn_p1 if isinstance(vpn_p1,list) else []):
        enc  = str(p.get("proposal","")).upper()
        name = p.get("name","")
        if "DES-" in enc and "3DES" not in enc: weak.append(f"{name}(DES)")
        if "-MD5" in enc:                        weak.append(f"{name}(MD5)")
    return _result(chk, not weak,
                   ", ".join(weak) if weak else "Nenhum fraco",
                   "Sem algoritmos fracos ✓" if not weak
                   else f"Fraco: {', '.join(weak)}")


def _h_pol_all_dst(chk, data):
    policies = data.get("firewall_pol") or []
    risky_dsts = ["all","0.0.0.0/0","0.0.0.0 0.0.0.0"]
    risky_pols = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
                  if p.get("action")=="accept"
                  and any(str(d).lower() in risky_dsts for d in [p.get("dstaddr","")])]
    ok = len(risky_pols) == 0
    return _result(chk, ok,
                   f"{len(risky_pols)} política(s)" if risky_pols else "Nenhuma",
                   "Sem políticas com destino 'all' ✓" if ok
                   else f"{len(risky_pols)} política(s) com destino 'all'")


def _h_admin_2fa(chk, data):
    admins = data.get("admin") or []
    no_2fa = [a.get("name","") for a in (admins if isinstance(admins,list) else [])
              if not a.get("two-factor","").strip() or a.get("two-factor","") == "disable"]
    ok = len(no_2fa) == 0
    return _result(chk, ok,
                   f"{len(no_2fa)} sem 2FA" if no_2fa else "Todos com 2FA",
                   "Todos admins com 2FA ✓" if ok
                   else f"{len(no_2fa)} admin(s) sem autenticação 2FA: {', '.join(no_2fa)}")


def _h_admin_trusted(chk, data):
    admins = data.get("admin") or []
    no_trusted = [a.get("name","") for a in (admins if isinstance(admins,list) else [])
                  if not a.get("trusthost1","") or a.get("trusthost1","") == "0.0.0.0 0.0.0.0"]
    ok = len(no_trusted) == 0
    return _result(chk, ok,
                   f"{len(no_trusted)} sem restrição" if no_trusted else "Todos restritos",
                   "Todos admins com trusted hosts ✓" if ok
                   else f"{len(no_trusted)} admin(s) sem trusted host: {', '.join(no_trusted)}")


def _h_pol_ssl(chk, data):
    policies = data.get("firewall_pol") or []
    no_ssl = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
              if p.get("action")=="accept" and not p.get("ssl-ssh-profile","").strip()]
    ok = len(no_ssl) == 0
    return _result(chk, ok,
                   f"{len(no_ssl)} sem SSL" if no_ssl else "Todas com SSL",
                   "Todas políticas com inspeção SSL ✓" if ok
                   else f"{len(no_ssl)} política(s) sem SSL inspection")


def _h_pol_webfilter(chk, data):
    policies = data.get("firewall_pol") or []
    no_wf = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
             if p.get("action")=="accept" and not p.get("webfilter-profile","").strip()]
    ok = len(no_wf) == 0
    return _result(chk, ok,
                   f"{len(no_wf)} sem Web Filter" if no_wf else "Todas com Web Filter",
                   "Todas políticas com Web Filter ✓" if ok
                   else f"{len(no_wf)} política(s) sem Web Filter")


def _h_pol_appctrl(chk, data):
    policies = data.get("firewall_pol") or []
    no_app = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
              if p.get("action")=="accept" and not p.get("application-list","").strip()]
    ok = len(no_app) == 0
    return _result(chk, ok,
                   f"{len(no_app)} sem App Control" if no_app else "Todas com App Control",
                   "Todas políticas com App Control ✓" if ok
                   else f"{len(no_app)} política(s) sem Application Control")


def _h_pol_dnsfilter(chk, data):
    policies = data.get("firewall_pol") or []
    no_dns = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
              if p.get("action")=="accept" and not p.get("dnsfilter-profile","").strip()]
    ok = len(no_dns) == 0
    return _result(chk, ok,
                   f"{len(no_dns)} sem DNS Filter" if no_dns else "Todas com DNS Filter",
                   "Todas políticas com DNS Filter ✓" if ok
                   else f"{len(no_dns)} política(s) sem DNS Filter")


def _h_pol_all_src(chk, data):
    policies = data.get("firewall_pol") or []
    risky_srcs = ["all","0.0.0.0/0","0.0.0.0 0.0.0.0"]
    risky_pols = [p.get("name","") for p in (policies if isinstance(policies,list) else [])
                  if p.get("action")=="accept"
                  and any(str(s).lower() in risky_srcs for s in [p.get("srcaddr","")])]
    ok = len(risky_pols) == 0
    return _result(chk, ok,
                   f"{len(risky_pols)} política(s)" if risky_pols else "Nenhuma",
                   "Sem políticas com origem 'all' ✓" if ok
                   else f"{len(risky_pols)} política(s) com origem 'all'")


def _h_vpn_phase2_weak(chk, data):
    phase2 = data.get("vpn_phase2") or []
    weak = []
    for p in (phase2 if isinstance(phase2,list) else []):
        enc = str(p.get("proposal","")).upper()
        name = p.get("name","")
        if "DES-" in enc and "3DES" not in enc: weak.append(f"{name}(DES)")
        if "-MD5" in enc:                        weak.append(f"{name}(MD5)")
        if "NULL" in enc:                        weak.append(f"{name}(NULL)")
    return _result(chk, not weak,
                   ", ".join(weak) if weak else "Nenhum fraco",
                   "Phase2 sem algoritmos fracos ✓" if not weak
                   else f"Fraco: {', '.join(weak)}")


def _h_sslvpn_cert(chk, data):
    sslvpn = data.get("sslvpn") or {}
    if isinstance(sslvpn, list):
        sslvpn = sslvpn[0] if sslvpn else {}
    auth = str(sslvpn.get("authmethod","") or sslvpn.get("auth-method","")).lower()
    cert = sslvpn.get("servercert","") or sslvpn.get("server-cert","")
    ok = bool(cert) and cert not in ("","self-sign","Fortinet_Factory")
    return _result(chk, ok,
                   str(cert) if cert else "—",
                   f"SSL-VPN com certificado: {cert} ✓" if ok
                   else "SSL-VPN sem certificado personalizado")


def _h_fortianalyzer(chk, data):
    faz = data.get("fortianalyzer") or {}
    if isinstance(faz, list):
        faz = faz[0] if faz else {}
    status = str(faz.get("status","") or faz.get("upload-option","")).lower()
    server = faz.get("server","") or faz.get("fortianalyzer-ip","")
    ok = bool(server) and status not in ("disable","")
    return _result(chk, ok,
                   str(server) if server else "—",
                   f"FortiAnalyzer → {server} ✓" if ok
                   else "FortiAnalyzer não configurado")


# ─────────────────────────────────────────────────────────────
# FWR-0: ACCESS RULES AUDIT
# ─────────────────────────────────────────────────────────────
def _h_access_rules(chk, data):
    """Audit all ACCEPT policies (FortiGate FWR-0)."""
    policies = data.get("firewall_pol") or []
    if not isinstance(policies, list):
        policies = []
    
    disabled = data.get("_disabled_rule_tags") or set()
    
    findings = []
    counters = {"no_prof":0, "any_src":0, "any_dst":0, "risky_port":0, "no_log":0, "unused":0, "disabled":0}
    
    for p in policies:
        if not isinstance(p, dict) or p.get("action") != "accept":
            continue
        nm = p.get("name", "?")
        enabled = p.get("status") != "disable"
        
        # Check: no profile (AV, IPS, etc.)
        if "no_prof" not in disabled:
            av_prof = p.get("av-profile", "").strip()
            ips_prof = p.get("ips-sensor", "").strip()
            wf_prof = p.get("webfilter-profile", "").strip()
            if not av_prof and not ips_prof:
                findings.append(_result(chk, False, nm, "Política sem perfis de segurança"))
                counters["no_prof"] += 1
        
        # Check: source all
        if "any_src" not in disabled:
            src = str(p.get("srcaddr", ""))
            if src in ("all", "0.0.0.0/0", "0.0.0.0 0.0.0.0"):
                findings.append(_result(chk, False, nm, "Origem 'all' detectada"))
                counters["any_src"] += 1
        
        # Check: destination all
        if "any_dst" not in disabled:
            dst = str(p.get("dstaddr", ""))
            if dst in ("all", "0.0.0.0/0", "0.0.0.0 0.0.0.0"):
                findings.append(_result(chk, False, nm, "Destino 'all' detectado"))
                counters["any_dst"] += 1
        
        # Check: risky ports
        if "risky_port" not in disabled:
            dst_port = str(p.get("dstport", ""))
            for port_int, label in RISKY_PORTS.items():
                port_str = str(port_int)
                if dst_port == port_str or dst_port.startswith(port_str+":") or ":"+port_str in dst_port:
                    findings.append(_result(chk, False, nm, f"Porta perigosa: {label}"))
                    counters["risky_port"] += 1
                    break
        
        # Check: no log
        if "no_log" not in disabled:
            logtraffic = str(p.get("logtraffic", "")).lower()
            if logtraffic not in ("utm", "all", "yes", "enable", "enabled"):
                findings.append(_result(chk, False, nm, "Logging desabilitado"))
                counters["no_log"] += 1
        
        # Check: disabled policy
        if "disabled" not in disabled and not enabled:
            findings.append(_result(chk, False, nm, "Política desabilitada"))
            counters["disabled"] += 1
        
        # Check: unused (0 bytes)
        if "unused" not in disabled:
            try:
                if p.get("bytes", 0) == 0:
                    findings.append(_result(chk, False, nm, "Política sem uso (0 bytes)"))
                    counters["unused"] += 1
            except:
                pass
    
    total_issues = sum(counters.values())
    summary = _result(chk, total_issues == 0, 
                    f"{len(policies)} políticas inspecionadas",
                    f"{total_issues} problemas encontrados" if total_issues else "Nenhum problema encontrado")
    
    results = [summary]
    results.extend(findings)
    return results


# ─────────────────────────────────────────────────────────────
# HANDLER REGISTRY
# ─────────────────────────────────────────────────────────────
_HANDLERS = {
    "fg_firmware":       _h_firmware,
    "fg_hostname":       _h_hostname,
    "fg_http_ifaces":    _h_http_ifaces,
    "fg_telnet_ifaces":  _h_telnet_ifaces,
    "fg_snmp_public":    _h_snmp_public,
    "fg_ntp":            _h_ntp,
    "fg_pol_av":         _h_pol_av,
    "fg_pol_ips":        _h_pol_ips,
    "fg_pol_log":        _h_pol_log,
    "fg_vpn_weak":       _h_vpn_weak,
    "fg_pol_all_dst":    _h_pol_all_dst,
    "fg_admin_2fa":      _h_admin_2fa,
    "fg_admin_trusted":  _h_admin_trusted,
    "fg_pol_ssl":        _h_pol_ssl,
    "fg_pol_webfilter":  _h_pol_webfilter,
    "fg_pol_appctrl":    _h_pol_appctrl,
    "fg_pol_dnsfilter":  _h_pol_dnsfilter,
    "fg_pol_all_src":    _h_pol_all_src,
    "fg_vpn_phase2_weak":_h_vpn_phase2_weak,
    "fg_sslvpn_cert":    _h_sslvpn_cert,
    "fg_fortianalyzer":  _h_fortianalyzer,
    "fg_access_rules":   _h_access_rules,
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
    """Return structured firewall rules security audit for FortiGate."""
    policies = data.get("firewall_pol") or []
    if not isinstance(policies, list): policies = []

    accept_pols = [p for p in policies if isinstance(p, dict) and p.get("action") == "accept"]
    deny_pols   = [p for p in policies if isinstance(p, dict) and p.get("action") == "deny"]

    disabled = data.get("_disabled_rule_tags") or set()
    findings = []
    counters = {"no_profiles":0,"risky_ports":0,"any_source":0,"no_logging":0,"unused":0}

    for pol in accept_pols:
        nm = pol.get("name") or str(pol.get("policyid","sem_nome"))

        # ── Políticas sem perfis de segurança ─────────────────
        if "no_prof" not in disabled:
            missing = []
            if not pol.get("av-profile","").strip():      missing.append("Antivirus")
            if not pol.get("ips-sensor","").strip():      missing.append("IPS")
            if not pol.get("webfilter-profile","").strip() and "webfilter-profile" in pol: missing.append("WebFilter")
            if missing:
                counters["no_profiles"] += 1
                findings.append(_rf("Perfis de Segurança Ausentes", nm, "High",
                    f"Perfis não aplicados: {', '.join(missing)}.",
                    f"Policy '{nm}' → Security Profiles → habilitar {', '.join(missing)}.", "no_prof"))

        # ── Origem ANY ────────────────────────────────────────
        if "any_src" not in disabled:
            srcaddr = pol.get("srcaddr") or []
            if isinstance(srcaddr, str): srcaddr = [{"name": srcaddr}]
            if any(str(s.get("name","")).lower() == "all" for s in (srcaddr if isinstance(srcaddr,list) else [])):
                counters["any_source"] += 1
                findings.append(_rf("Origem 'all'", nm, "High",
                    "Política aceita tráfego de qualquer origem.",
                    f"Restringir srcaddr da política '{nm}'.", "any_src"))

        # ── Destino ANY ───────────────────────────────────────
        if "any_dst" not in disabled:
            dstaddr = pol.get("dstaddr") or []
            if isinstance(dstaddr, str): dstaddr = [{"name": dstaddr}]
            if any(str(d.get("name","")).lower() == "all" for d in (dstaddr if isinstance(dstaddr,list) else [])):
                findings.append(_rf("Destino 'all'", nm, "Medium",
                    "Política permite acesso a qualquer destino.",
                    f"Restringir dstaddr da política '{nm}'.", "any_dst"))

        # ── Portas perigosas nos serviços ─────────────────────
        if "risky_port" not in disabled:
            services = pol.get("service") or []
            if isinstance(services, str): services = [{"name": services}]
            for svc in (services if isinstance(services, list) else []):
                svc_name = str(svc.get("name","")).upper()
                for port, label in RISKY_PORTS.items():
                    if label.upper() in svc_name or str(port) in svc_name:
                        counters["risky_ports"] += 1
                        findings.append(_rf(f"Porta Perigosa: {label}", nm, "High",
                            f"Serviço {label} (:{port}) permitido nesta política.",
                            f"Restringir ou remover o serviço {label} da política '{nm}'.", f"port_{port}"))
                        break

        # ── Sem logging ───────────────────────────────────────
        if "no_log" not in disabled and pol.get("logtraffic","disable") == "disable":
            counters["no_logging"] += 1
            findings.append(_rf("Logging Desabilitado", nm, "Medium",
                "Tráfego desta política não é registrado.",
                f"Editar política '{nm}' → Log Traffic → utm.", "no_log"))

        # ── Bytes = 0 (sem uso) ───────────────────────────────
        if "unused" not in disabled:
            bytes_val = pol.get("bytes") or pol.get("pkts") or pol.get("hit-count")
            if bytes_val is not None:
                try:
                    if int(bytes_val) == 0:
                        counters["unused"] += 1
                        findings.append(_rf("Política Sem Uso (0 bytes)", nm, "Low",
                            "Nenhum tráfego processado por esta política.",
                            f"Verificar se a política '{nm}' ainda é necessária.", "unused"))
                except (ValueError, TypeError):
                    pass

        # ── Política desabilitada ──────────────────────────────
        if "disabled" not in disabled and str(pol.get("status","enable")).lower() == "disable":
            counters["unused"] += 1
            findings.append(_rf("Política Desabilitada", nm, "Low",
                "Política desabilitada é candidata a remoção.",
                f"Revisar e remover política '{nm}' se obsoleta.", "disabled"))

    return {
        "vendor":       "fortigate",
        "total_rules":  len(policies),
        "allow_rules":  len(accept_pols),
        "deny_rules":   len(deny_pols),
        "counters":     counters,
        "findings":     sorted(findings, key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3}.get(x["severity"],4)),
    }


def _rf(check, rule_name, severity, detail, recommendation, tag):
    return {"check": check, "rule": rule_name, "severity": severity,
            "detail": detail, "recommendation": recommendation, "tag": tag}
