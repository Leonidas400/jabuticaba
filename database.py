"""
database.py — SQLite layer for CIS checks
All rules are stored in DB and queried at runtime.
"""

import sqlite3
import os
from cryptography.fernet import Fernet

DB_PATH = os.path.join(os.path.dirname(__file__), "cis_analyzer.db")

# ── ENCRYPTION ───────────────────────────────────────────────
# Generate or load encryption key for credentials
_KEY_FILE = os.path.join(os.path.dirname(__file__), ".cis_key")

def _get_cipher():
    """Get or create Fernet cipher for credential encryption."""
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(_KEY_FILE, 0o600)  # Read/write for owner only
    return Fernet(key)

def encrypt_credential(value: str) -> str:
    """Encrypt a password or API key."""
    if not value:
        return ""
    cipher = _get_cipher()
    return cipher.encrypt(value.encode()).decode()

def decrypt_credential(encrypted_value: str) -> str:
    """Decrypt a password or API key."""
    if not encrypted_value:
        return ""
    try:
        cipher = _get_cipher()
        return cipher.decrypt(encrypted_value.encode()).decode()
    except Exception:
        return ""


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # ── SCHEMA ──────────────────────────────────────────────
    c.executescript("""
    CREATE TABLE IF NOT EXISTS vendors (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        slug        TEXT UNIQUE NOT NULL,
        name        TEXT NOT NULL,
        description TEXT,
        icon        TEXT DEFAULT '🔥',
        base_url    TEXT DEFAULT '',
        active      INTEGER DEFAULT 1,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS versions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_id   INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
        version     TEXT NOT NULL,
        label       TEXT NOT NULL,
        active      INTEGER DEFAULT 1,
        is_default  INTEGER DEFAULT 0,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(vendor_id, version)
    );

    CREATE TABLE IF NOT EXISTS analysis_history (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        company     TEXT,
        vendor_slug TEXT,
        version     TEXT,
        score       INTEGER,
        risk_level  TEXT,
        passed      INTEGER,
        failed      INTEGER,
        total       INTEGER,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS admin_auth (
        id            INTEGER PRIMARY KEY,
        username      TEXT NOT NULL DEFAULT 'admin',
        password_hash TEXT NOT NULL,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS severity_weights (
        severity TEXT PRIMARY KEY,
        weight   INTEGER NOT NULL DEFAULT 5
    );

    INSERT OR IGNORE INTO severity_weights (severity, weight) VALUES
        ('Critical', 10), ('High', 6), ('Medium', 3), ('Low', 1);

    CREATE TABLE IF NOT EXISTS api_endpoints (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_slug     TEXT NOT NULL,
        section_name    TEXT NOT NULL,
        endpoint_path   TEXT NOT NULL,
        description     TEXT DEFAULT '',
        active          INTEGER DEFAULT 1,
        created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(vendor_slug, endpoint_path)
    );

    CREATE TRIGGER IF NOT EXISTS api_endpoints_updated
    AFTER UPDATE ON api_endpoints
    BEGIN
        UPDATE api_endpoints SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

    CREATE TABLE IF NOT EXISTS api_checks (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_slug     TEXT NOT NULL,
        cid             TEXT NOT NULL,
        title           TEXT NOT NULL,
        category        TEXT NOT NULL,
        severity        TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low')),
        description     TEXT DEFAULT '',
        recommendation  TEXT DEFAULT '',
        api_endpoint    TEXT DEFAULT '',
        json_path       TEXT DEFAULT '',
        operator        TEXT DEFAULT 'handler',
        expected_value  TEXT DEFAULT '',
        handler_key     TEXT DEFAULT '',
        active          INTEGER DEFAULT 1,
        created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(vendor_slug, cid)
    );

    CREATE TRIGGER IF NOT EXISTS api_checks_updated
    AFTER UPDATE ON api_checks
    BEGIN
        UPDATE api_checks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

    CREATE TABLE IF NOT EXISTS firewall_credentials (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        label           TEXT NOT NULL UNIQUE,
        vendor_slug     TEXT NOT NULL,
        hostname        TEXT NOT NULL,
        port            INTEGER DEFAULT 443,
        username        TEXT NOT NULL,
        password_encrypted TEXT NOT NULL,
        api_key_encrypted TEXT DEFAULT '',
        description     TEXT DEFAULT '',
        last_tested     DATETIME,
        active          INTEGER DEFAULT 1,
        created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TRIGGER IF NOT EXISTS firewall_credentials_updated
    AFTER UPDATE ON firewall_credentials
    BEGIN
        UPDATE firewall_credentials SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

    CREATE TABLE IF NOT EXISTS rule_check_defs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_slug     TEXT NOT NULL,
        tag             TEXT NOT NULL,
        name            TEXT NOT NULL,
        category        TEXT NOT NULL DEFAULT 'Firewall Policy',
        severity        TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low')),
        description     TEXT DEFAULT '',
        recommendation  TEXT DEFAULT '',
        active          INTEGER NOT NULL DEFAULT 1,
        created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(vendor_slug, tag)
    );
    """)

    conn.commit()
    try:
        conn.execute("ALTER TABLE vendors ADD COLUMN base_url TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE vendors ADD COLUMN min_firmware_version TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE versions ADD COLUMN min_firmware_version TEXT DEFAULT ''")
    except Exception:
        pass
    _seed(conn)
    conn.close()
    from canonical_checks import seed_api_checks
    seed_api_checks()
    seed_rule_check_defs()
    _migrate_firewall_creds_from_file()


def _migrate_firewall_creds_from_file():
    """Migrate credentials from 'Acesso temporario firewalls.txt' to database."""
    cred_file = os.path.join(os.path.dirname(__file__), "Acesso temporario firewalls.txt")
    if not os.path.exists(cred_file):
        return
    
    try:
        with open(cred_file, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        
        if len(lines) < 3:
            return  # Not enough lines to parse
        
        username = lines[0]
        password = lines[1]
        host_port = lines[2]  # e.g., "38.50.152.158:4343"
        
        # Parse hostname and port
        if ":" in host_port:
            hostname, port_str = host_port.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443
        else:
            hostname = host_port
            port = 443
        
        # Check if this credential is already in database
        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM firewall_credentials WHERE hostname=? AND username=?",
            (hostname, username)
        ).fetchone()
        conn.close()
        
        if not existing:
            # Add to database with label "Temporary Firewall"
            firewall_creds_add(
                label="SonicWall Temporario",
                vendor_slug="sonicwall",
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                description="Migrado de arquivo de texto em 2026-04-15"
            )
        
        # Remove the file after migration (after successful save to DB)
        try:
            os.remove(cred_file)
        except Exception:
            pass  # Silently fail if can't delete
    
    except Exception as e:
        # Log error but don't break init
        print(f"Erro ao migrar credenciais: {e}")


def _seed(conn):
    c = conn.cursor()

    # Skip if already seeded
    if c.execute("SELECT COUNT(*) FROM vendors").fetchone()[0] > 0:
        # Ensure vendors and endpoints are present for existing databases
        # SonicWall
        c.execute("INSERT OR IGNORE INTO vendors (slug,name,description,icon) VALUES (?,?,?,?)",
                  ("sonicwall", "SonicWall", "SonicWall Next-Gen Firewall (SonicOS)", "🔴"))
        sw_id = c.execute("SELECT id FROM vendors WHERE slug='sonicwall'").fetchone()[0]
        for ver,label,is_def in [("6.5","SonicWall SonicOS 6.5.x",0),("7.0","SonicWall SonicOS 7.0.x",0),("7.1","SonicWall SonicOS 7.1.x",1)]:
            c.execute("INSERT OR IGNORE INTO versions (vendor_id,version,label,is_default) VALUES (?,?,?,?)",
                      (sw_id, ver, label, is_def))
        
        # FortiGate
        c.execute("INSERT OR IGNORE INTO vendors (slug,name,description,icon) VALUES (?,?,?,?)",
                  ("fortigate", "FortiGate", "Fortinet FortiGate Next-Gen Firewall", "🟠"))
        fgt_id = c.execute("SELECT id FROM vendors WHERE slug='fortigate'").fetchone()[0]
        if not c.execute("SELECT COUNT(*) FROM versions WHERE vendor_id=?", (fgt_id,)).fetchone()[0]:
            for ver, label, is_def in [("7.0", "FortiGate 7.0.x", 0), ("7.2", "FortiGate 7.2.x", 0), ("7.4", "FortiGate 7.4.x", 1), ("7.6", "FortiGate 7.6.x", 0)]:
                c.execute("INSERT OR IGNORE INTO versions (vendor_id,version,label,is_default) VALUES (?,?,?,?)",
                          (fgt_id, ver, label, is_def))
        
        # pfSense
        c.execute("INSERT OR IGNORE INTO vendors (slug,name,description,icon) VALUES (?,?,?,?)",
                  ("pfsense", "pfSense", "Netgate pfSense Open Source Firewall", "🔵"))
        pfs_id = c.execute("SELECT id FROM vendors WHERE slug='pfsense'").fetchone()[0]
        if not c.execute("SELECT COUNT(*) FROM versions WHERE vendor_id=?", (pfs_id,)).fetchone()[0]:
            for ver, label, is_def in [("2.6", "pfSense 2.6.x", 0), ("2.7", "pfSense 2.7.x", 1), ("CE-2.7", "pfSense CE 2.7", 0)]:
                c.execute("INSERT OR IGNORE INTO versions (vendor_id,version,label,is_default) VALUES (?,?,?,?)",
                          (pfs_id, ver, label, is_def))
        
        # SonicWall endpoints
        sw_endpoints = [
            ("sonicwall", "Device", "reporting/status/system", "Informações do dispositivo"),
            ("sonicwall", "SNMP", "snmp/base", "Configurações SNMP"),
            ("sonicwall", "Gateway AV", "gateway-antivirus/base", "Sistema de antivírus"),
            ("sonicwall", "IPS", "intrusion-prevention/base", "Detecção de intrusão"),
            ("sonicwall", "Botnet", "botnet/base", "Detecção de botnets"),
            ("sonicwall", "Geo IP", "geo-ip/base", "Geolocalização de IPs"),
            ("sonicwall", "Content Filter", "content-filter/cfs/base", "Filtro de conteúdo"),
            ("sonicwall", "Aspy", "anti-spyware/base", "Detecção de spyware"),
            ("sonicwall", "Syslog", "log/syslog/syslog-servers", "Logs do sistema"),
            ("sonicwall", "TCP", "tcp", "Proteção contra flood TCP"),
            ("sonicwall", "DPI SSL", "dpi-ssl/client/base", "Proteção contra SSL/TLS"),
            ("sonicwall", "Administration", "administration/global", "Configurações de administração"),
            ("sonicwall", "Gav_cloud", "gateway-antivirus/cloud/base", "Sistema de antivírus em nuvem"),
            ("sonicwall", "capture_atp", "capture-atp/base", "Detecção de ameaças avançadas"),
            ("sonicwall", "fw_base", "firewall", "Configurações do firewall"),
            ("sonicwall", "access_rules", "access-rules/ipv4", "Regras de firewall IPv4"),
            ("sonicwall", "access_rules_v6", "access-rules/ipv6", "Regras de firewall IPv6"),
            ("sonicwall", "interfaces_ipv4", "interfaces/ipv4", "Configurações de interface IPv4"),
        ]
        for vendor_slug, section, path, desc in sw_endpoints:
            c.execute("INSERT OR IGNORE INTO api_endpoints (vendor_slug, section_name, endpoint_path, description) VALUES (?,?,?,?)",
                      (vendor_slug, section, path, desc))
        
        # FortiGate endpoints
        fgt_endpoints = [
            ("fortigate", "status", "monitor/system/status", "System status"),
            ("fortigate", "global", "cmdb/system/global", "Global settings"),
            ("fortigate", "admin", "cmdb/system/admin", "Admin users"),
            ("fortigate", "snmp", "cmdb/system/snmp/community", "SNMP settings"),
            ("fortigate", "snmpv3", "cmdb/system/snmp/v3-user", "SNMPv3 users"),
            ("fortigate", "ntp", "cmdb/system/ntp", "NTP settings"),
            ("fortigate", "dns", "cmdb/system/dns", "DNS settings"),
            ("fortigate", "logging", "cmdb/log/syslogd/setting", "Logging settings"),
            ("fortigate", "fortianalyzer", "cmdb/log.fortianalyzer/setting", "FortiAnalyzer"),
            ("fortigate", "pwd_policy", "cmdb/system/password-policy", "Password policy"),
            ("fortigate", "interfaces", "cmdb/system/interface", "Interfaces"),
            ("fortigate", "firewall_pol", "cmdb/firewall/policy", "Firewall policies"),
            ("fortigate", "av_profile", "cmdb/antivirus/profile", "AV profiles"),
            ("fortigate", "ips_sensor", "cmdb/ips/sensor", "IPS sensors"),
            ("fortigate", "web_filter", "cmdb/webfilter/profile", "Web filters"),
            ("fortigate", "app_ctrl", "cmdb/application/list", "App control"),
            ("fortigate", "dns_filter", "cmdb/dnsfilter/profile", "DNS filters"),
            ("fortigate", "email_filter", "cmdb/emailfilter/profile", "Email filters"),
            ("fortigate", "ssl_ssh_prof", "cmdb/firewall/ssl-ssh-profile", "SSL/SSH profiles"),
            ("fortigate", "vpn_phase1", "cmdb/vpn.ipsec/phase1-interface", "VPN Phase1"),
            ("fortigate", "vpn_phase2", "cmdb/vpn.ipsec/phase2-interface", "VPN Phase2"),
            ("fortigate", "sslvpn", "cmdb/vpn.ssl/settings", "SSL VPN"),
        ]
        for vendor_slug, section, path, desc in fgt_endpoints:
            c.execute("INSERT OR IGNORE INTO api_endpoints (vendor_slug, section_name, endpoint_path, description) VALUES (?,?,?,?)",
                      (vendor_slug, section, path, desc))
        
        # pfSense endpoints
        pfs_endpoints = [
            ("pfsense", "version", "system/version", "System version"),
            ("pfsense", "config", "system/config", "System config"),
            ("pfsense", "hostname", "system/hostname", "Hostname"),
            ("pfsense", "tunable", "system/tunable", "System tunables"),
            ("pfsense", "users", "user", "User accounts"),
            ("pfsense", "groups", "user/group", "User groups"),
            ("pfsense", "interfaces", "interface", "Interfaces"),
            ("pfsense", "firewall_rules", "firewall/rule", "Firewall rules"),
            ("pfsense", "firewall_aliases", "firewall/alias", "Firewall aliases"),
            ("pfsense", "nat", "firewall/nat/port_forward", "NAT rules"),
            ("pfsense", "syslog", "services/syslogd", "Syslog settings"),
            ("pfsense", "ntp", "services/ntpd", "NTP settings"),
            ("pfsense", "snmp", "services/snmpd", "SNMP settings"),
            ("pfsense", "unbound", "services/unbound", "Unbound DNS"),
            ("pfsense", "ssh", "system/ssh", "SSH settings"),
            ("pfsense", "cert", "system/certificate", "Certificates"),
            ("pfsense", "webgui", "system/webgui", "WebGUI settings"),
            ("pfsense", "openvpn", "services/openvpn/server", "OpenVPN servers"),
            ("pfsense", "ipsec_p1", "services/ipsec/phase1", "IPsec Phase1"),
            ("pfsense", "packages", "system/package", "Installed packages"),
        ]
        for vendor_slug, section, path, desc in pfs_endpoints:
            c.execute("INSERT OR IGNORE INTO api_endpoints (vendor_slug, section_name, endpoint_path, description) VALUES (?,?,?,?)",
                      (vendor_slug, section, path, desc))
        
        conn.commit()
        return

    # ── VENDORS ─────────────────────────────────────────────
    c.execute("INSERT INTO vendors (slug,name,description,icon) VALUES (?,?,?,?)",
              ("fortigate", "FortiGate", "Fortinet FortiGate Next-Gen Firewall", "🟠"))
    fgt_id = c.lastrowid

    c.execute("INSERT INTO vendors (slug,name,description,icon) VALUES (?,?,?,?)",
              ("pfsense", "pfSense", "Netgate pfSense Open Source Firewall", "🔵"))
    pfs_id = c.lastrowid

    # ── FORTIGATE VERSIONS ───────────────────────────────────
    fgt_versions = [
        ("7.0", "FortiGate 7.0.x", 0),
        ("7.2", "FortiGate 7.2.x", 0),
        ("7.4", "FortiGate 7.4.x", 1),
        ("7.6", "FortiGate 7.6.x", 0),
    ]
    fgt_ver_ids = {}
    for ver, label, is_def in fgt_versions:
        c.execute("INSERT INTO versions (vendor_id,version,label,is_default) VALUES (?,?,?,?)",
                  (fgt_id, ver, label, is_def))
        fgt_ver_ids[ver] = c.lastrowid

    # ── PFSENSE VERSIONS ─────────────────────────────────────
    pfs_versions = [
        ("2.6", "pfSense 2.6.x", 0),
        ("2.7", "pfSense 2.7.x", 1),
        ("CE-2.7", "pfSense CE 2.7", 0),
    ]
    pfs_ver_ids = {}
    for ver, label, is_def in pfs_versions:
        c.execute("INSERT INTO versions (vendor_id,version,label,is_default) VALUES (?,?,?,?)",
                  (pfs_id, ver, label, is_def))
        pfs_ver_ids[ver] = c.lastrowid

    # ── SONICWALL VENDOR / ENDPOINTS (compatible with API-2 mocks) ─────────────────
    c.execute("INSERT OR IGNORE INTO vendors (slug,name,description,icon) VALUES (?,?,?,?)",
              ("sonicwall", "SonicWall", "SonicWall Next-Gen Firewall (SonicOS)", "🔴"))
    sw_id = c.execute("SELECT id FROM vendors WHERE slug='sonicwall'").fetchone()[0]
    for ver, label, is_def in [("6.5", "SonicWall SonicOS 6.5.x", 0), ("7.0", "SonicWall SonicOS 7.0.x", 0), ("7.1", "SonicWall SonicOS 7.1.x", 1)]:
        c.execute("INSERT OR IGNORE INTO versions (vendor_id,version,label,is_default) VALUES (?,?,?,?)",
                  (sw_id, ver, label, is_def))
    sw_endpoints = [
        ("sonicwall", "Device", "reporting/status/system", "Informações do dispositivo"),
        ("sonicwall", "SNMP", "snmp/base", "Configurações SNMP"),
        ("sonicwall", "Gateway AV", "gateway-antivirus/base", "Sistema de antivírus"),
        ("sonicwall", "IPS", "intrusion-prevention/base", "Detecção de intrusão"),
        ("sonicwall", "Botnet", "botnet/base", "Detecção de botnets"),
        ("sonicwall", "Geo IP", "geo-ip/base", "Geolocalização de IPs"),
        ("sonicwall", "Content Filter", "content-filter/cfs/base", "Filtro de conteúdo"),
        ("sonicwall", "Aspy", "anti-spyware/base", "Detecção de spyware"),
        ("sonicwall", "Syslog", "log/syslog/base", "Logs do sistema"),
        ("sonicwall", "TCP", "tcp", "Proteção contra flood TCP"),
        ("sonicwall", "DPI SSL", "dpi-ssl/client/base", "Proteção contra SSL/TLS"),
        ("sonicwall", "Administration", "administration/global", "Configurações de administração"),
        ("sonicwall", "Gav_cloud", "gateway-antivirus/cloud/base", "Sistema de antivírus em nuvem"),
        ("sonicwall", "capture_atp", "capture-atp/base", "Detecção de ameaças avançadas"),
        ("sonicwall", "fw_base", "firewall", "Configurações do firewall"),
        ("sonicwall", "access_rules", "access-rules/ipv4", "Regras de firewall IPv4"),
        ("sonicwall", "access_rules_v6", "access-rules/ipv6", "Regras de firewall IPv6"),
        ("sonicwall", "interfaces_ipv4", "interfaces/ipv4", "Configurações de interface IPv4"),
    ]
    for vendor_slug, section, path, desc in sw_endpoints:
        c.execute("INSERT OR IGNORE INTO api_endpoints (vendor_slug, section_name, endpoint_path, description) VALUES (?,?,?,?)",
                  (vendor_slug, section, path, desc))

    conn.commit()
    print(f"[DB] Seeded {c.execute('SELECT COUNT(*) FROM versions').fetchone()[0]} versions")
    print(f"[DB] Seeded {c.execute('SELECT COUNT(*) FROM api_endpoints').fetchone()[0]} endpoints")


# ── QUERY HELPERS ────────────────────────────────────────────
def get_vendors():
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM vendors WHERE active=1 ORDER BY name").fetchall()]


def admin_update_vendor(vendor_id: int, slug: str, name: str, description: str = '',
                        icon: str = '🔧', base_url: str = '', min_firmware_version: str = ''):
    with get_db() as conn:
        conn.execute(
            "UPDATE vendors SET slug=?, name=?, description=?, icon=?, base_url=?, min_firmware_version=? WHERE id=?",
            (slug, name, description, icon, base_url, min_firmware_version, vendor_id))
        conn.commit()


def admin_delete_vendor(vendor_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM vendors WHERE id=?", (vendor_id,))
        conn.commit()


def get_versions(vendor_slug):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT v.*, vn.slug as vendor_slug, vn.name as vendor_name
            FROM versions v JOIN vendors vn ON v.vendor_id=vn.id
            WHERE vn.slug=? AND v.active=1 ORDER BY v.version DESC
        """, (vendor_slug,)).fetchall()]


def save_analysis(company, vendor_slug, version, score, risk_level, passed, failed, total):
    with get_db() as conn:
        conn.execute("""INSERT INTO analysis_history
            (company, vendor_slug, version, score, risk_level, passed, failed, total)
            VALUES (?,?,?,?,?,?,?,?)""",
            (company, vendor_slug, version, score, risk_level, passed, failed, total))
        conn.commit()


def get_history(limit=20):
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM analysis_history ORDER BY created_at DESC LIMIT ?",
            (limit,)).fetchall()]


def admin_add_version(vendor_id, version, label, min_firmware_version=''):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO versions (vendor_id,version,label,min_firmware_version) VALUES (?,?,?,?)",
            (vendor_id, version, label, min_firmware_version or ''))
        new_vid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
        return new_vid


def admin_update_version(version_id: int, label: str = None, min_firmware_version: str = None):
    """Update label and/or min_firmware_version for a version entry."""
    parts, params = [], []
    if label is not None:
        parts.append("label = ?"); params.append(label)
    if min_firmware_version is not None:
        parts.append("min_firmware_version = ?"); params.append(min_firmware_version)
    if not parts:
        return
    params.append(version_id)
    with get_db() as conn:
        conn.execute(f"UPDATE versions SET {', '.join(parts)} WHERE id=?", params)
        conn.commit()


def get_version_min_firmware(vendor_slug: str, version_line: str) -> str:
    """Return min_firmware_version for vendor+version line (e.g. 'sonicwall', '7.1').
    Falls back to vendor-level min_firmware_version if version row has none set."""
    with get_db() as conn:
        row = conn.execute("""
            SELECT v.min_firmware_version AS ver_min, vn.min_firmware_version AS vnd_min
            FROM versions v JOIN vendors vn ON v.vendor_id = vn.id
            WHERE vn.slug = ? AND v.version = ?
        """, (vendor_slug, version_line)).fetchone()
        if row:
            return row["ver_min"] or row["vnd_min"] or ""
        # No version row — fall back to vendor level
        vrow = conn.execute(
            "SELECT min_firmware_version FROM vendors WHERE slug=?", (vendor_slug,)).fetchone()
        return (vrow["min_firmware_version"] or "") if vrow else ""


def get_stats():
    with get_db() as conn:
        return {
            "vendors":    conn.execute("SELECT COUNT(*) FROM vendors WHERE active=1").fetchone()[0],
            "versions":   conn.execute("SELECT COUNT(*) FROM versions WHERE active=1").fetchone()[0],
            "api_checks": conn.execute("SELECT COUNT(*) FROM api_checks WHERE active=1").fetchone()[0],
            "analyses":   conn.execute("SELECT COUNT(*) FROM analysis_history").fetchone()[0],
        }


# ── AUTH ─────────────────────────────────────────────────────
import hashlib as _hashlib
import secrets as _secrets


def _hash_password(pw: str) -> str:
    salt = _secrets.token_hex(16)
    h = _hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}:{h}"


def _verify_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":")
        return _hashlib.sha256((salt + pw).encode()).hexdigest() == h
    except Exception:
        return False


def get_admin_password_hash():
    with get_db() as conn:
        row = conn.execute("SELECT password_hash FROM admin_auth LIMIT 1").fetchone()
        return row["password_hash"] if row else None


def set_admin_password(new_pw: str):
    h = _hash_password(new_pw)
    with get_db() as conn:
        if conn.execute("SELECT COUNT(*) FROM admin_auth").fetchone()[0] == 0:
            conn.execute("INSERT INTO admin_auth (password_hash) VALUES (?)", (h,))
        else:
            conn.execute("UPDATE admin_auth SET password_hash=?", (h,))
        conn.commit()


def verify_admin_login(password: str) -> bool:
    stored = get_admin_password_hash()
    if not stored:
        return password == "admin"
    return _verify_password(password, stored)


# ── API ENDPOINTS ────────────────────────────────────────────
def endpoints_get_all(vendor_slug=None):
    """Get all endpoints, optionally filtered by vendor_slug."""
    with get_db() as conn:
        if vendor_slug:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM api_endpoints WHERE vendor_slug=? ORDER BY section_name, endpoint_path",
                (vendor_slug,)).fetchall()]
        return [dict(r) for r in conn.execute(
            "SELECT * FROM api_endpoints ORDER BY vendor_slug, section_name, endpoint_path").fetchall()]


def endpoints_add(vendor_slug: str, section_name: str, endpoint_path: str, description: str = "") -> int:
    """Add a new endpoint. Auto-creates vendor if not exists."""
    with get_db() as conn:
        existing_vendor = conn.execute(
            "SELECT id FROM vendors WHERE slug=?", (vendor_slug,)
        ).fetchone()
        
        if not existing_vendor:
            conn.execute("""INSERT INTO vendors (slug, name, description, icon)
                VALUES (?, ?, ?, ?)""",
                (vendor_slug, vendor_slug.title(), f"{vendor_slug.title()} Firewall", "🔧"))
        
        cur = conn.execute("""INSERT INTO api_endpoints
            (vendor_slug, section_name, endpoint_path, description, active)
            VALUES (?, ?, ?, ?, 1)""",
            (vendor_slug, section_name, endpoint_path, description))
        conn.commit()
        return cur.lastrowid


def endpoints_update(endpoint_id: int, data: dict):
    """Update an existing endpoint."""
    with get_db() as conn:
        conn.execute("""UPDATE api_endpoints SET
            section_name=?, endpoint_path=?, description=?, active=?
            WHERE id=?""",
            (data.get('section_name'),
             data.get('endpoint_path'),
             data.get('description', ''),
             data.get('active', 1),
             endpoint_id))
        conn.commit()


def endpoints_toggle(endpoint_id: int, active: int):
    """Toggle endpoint active status."""
    with get_db() as conn:
        conn.execute("UPDATE api_endpoints SET active=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (active, endpoint_id))
        conn.commit()


def endpoints_delete(endpoint_id: int):
    """Delete an endpoint."""
    with get_db() as conn:
        conn.execute("DELETE FROM api_endpoints WHERE id=?", (endpoint_id,))
        conn.commit()


# ── SEVERITY WEIGHTS ─────────────────────────────────────────
def get_severity_weights() -> dict:
    with get_db() as conn:
        rows = conn.execute("SELECT severity, weight FROM severity_weights").fetchall()
        return {r["severity"]: r["weight"] for r in rows}


def set_severity_weight(severity: str, weight: int):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO severity_weights (severity, weight) VALUES (?,?)",
            (severity, weight))
        conn.commit()


def admin_delete_version(version_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM versions WHERE id=?", (version_id,))
        conn.commit()


# ── API CHECKS (DB-driven CIS checks for API mode) ───────────
def api_checks_get_all(vendor_slug=None):
    with get_db() as conn:
        if vendor_slug:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM api_checks WHERE vendor_slug=? ORDER BY cid",
                (vendor_slug,)).fetchall()]
        return [dict(r) for r in conn.execute(
            "SELECT * FROM api_checks ORDER BY vendor_slug, cid").fetchall()]


def api_checks_get_active(vendor_slug: str):
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM api_checks WHERE vendor_slug=? AND active=1 ORDER BY cid",
            (vendor_slug,)).fetchall()]


def api_checks_add(data: dict) -> int:
    with get_db() as conn:
        vendor_slug = data["vendor_slug"]
        existing_vendor = conn.execute(
            "SELECT id FROM vendors WHERE slug=?", (vendor_slug,)
        ).fetchone()
        
        if not existing_vendor:
            conn.execute("""INSERT INTO vendors (slug, name, description, icon)
                VALUES (?, ?, ?, ?)""",
                (vendor_slug, vendor_slug.title(), f"{vendor_slug.title()} Firewall", "🔧"))
        
        cur = conn.execute("""INSERT INTO api_checks
            (vendor_slug,cid,title,category,severity,description,recommendation,
             api_endpoint,json_path,operator,expected_value,handler_key,active)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (vendor_slug, data["cid"], data["title"],
             data["category"], data["severity"],
             data.get("description",""), data.get("recommendation",""),
             data.get("api_endpoint",""), data.get("json_path",""),
             data.get("operator","handler"), data.get("expected_value",""),
             data.get("handler_key",""), data.get("active",1)))
        conn.commit()
        return cur.lastrowid


def api_checks_update(check_id: int, data: dict):
    fields = ["title","category","severity","description","recommendation",
              "api_endpoint","json_path","operator","expected_value","handler_key","active"]
    updates = {k: v for k, v in data.items() if k in fields}
    if not updates:
        return
    with get_db() as conn:
        sets = ", ".join(f"{k}=?" for k in updates)
        conn.execute(f"UPDATE api_checks SET {sets} WHERE id=?",
                     (*updates.values(), check_id))
        conn.commit()


def api_checks_toggle(check_id: int, active: int):
    with get_db() as conn:
        conn.execute("UPDATE api_checks SET active=? WHERE id=?", (active, check_id))
        conn.commit()


def api_checks_delete(check_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM api_checks WHERE id=?", (check_id,))
        conn.commit()


def api_checks_count(vendor_slug=None):
    with get_db() as conn:
        if vendor_slug:
            return conn.execute(
                "SELECT COUNT(*) FROM api_checks WHERE vendor_slug=?",
                (vendor_slug,)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM api_checks").fetchone()[0]


# ── RULE CHECK DEFINITIONS ───────────────────────────────────
_RULE_CHECK_SEED = [
    # SonicWall
    ("sonicwall","dpi_off",     "DPI Desabilitado",           "Firewall Policy","High",
     "Regras ALLOW devem ter inspeção DPI ativa para detectar ameaças no tráfego.",
     "Editar a regra e habilitar DPI."),
    ("sonicwall","dpi_ssl_off", "DPI-SSL Incompleto",         "Firewall Policy","Medium",
     "DPI-SSL inspeciona tráfego HTTPS/TLS. Client e Server devem estar ativos.",
     "Editar a regra → DPI-SSL → habilitar Client e Server."),
    ("sonicwall","botnet_off",  "Botnet Filter Desabilitado", "Firewall Policy","High",
     "Botnet Filter bloqueia comunicação com servidores C&C conhecidos.",
     "Editar a regra e habilitar Botnet Filter."),
    ("sonicwall","geoip_off",   "Geo-IP Filter Desabilitado", "Firewall Policy","Medium",
     "Geo-IP Filter permite bloquear tráfego de países de alto risco.",
     "Editar a regra e habilitar Geo-IP Filter."),
    ("sonicwall","any_src",     "Origem ANY",                 "Firewall Policy","High",
     "Origem ANY amplia a superfície de ataque, permitindo qualquer host iniciar conexão.",
     "Restringir a origem ao menor escopo possível."),
    ("sonicwall","any_dst",     "Destino ANY",                "Firewall Policy","Medium",
     "Destino ANY permite acesso irrestrito a todos os hosts.",
     "Restringir o destino ao menor escopo possível."),
    ("sonicwall","no_log",      "Logging Desabilitado",       "Firewall Policy","Medium",
     "Regras ALLOW sem log impedem auditoria de tráfego.",
     "Editar a regra e habilitar Logging."),
    ("sonicwall","fragments",   "Fragmentos Permitidos",      "Firewall Policy","Medium",
     "Permitir pacotes fragmentados pode ser explorado para evasão de inspeção.",
     "Desabilitar 'fragments' na regra, salvo necessidade justificada."),
    ("sonicwall","schedule_exp","Schedule Expirado",          "Firewall Policy","High",
     "Regras com schedule expirado devem ser revisadas e removidas.",
     "Remover ou atualizar o schedule da regra."),
    ("sonicwall","disabled",    "Regra Desabilitada",         "Firewall Policy","Low",
     "Regras ALLOW desabilitadas devem ser removidas para manter a política limpa.",
     "Revisar e remover a regra se não for mais necessária."),
    ("sonicwall","no_hits",     "Regra Sem Uso (0 hits)",     "Firewall Policy","Low",
     "Regras sem tráfego podem ser obsoletas e devem ser revisadas.",
     "Verificar se a regra ainda é necessária."),
    # FortiGate
    ("fortigate","no_prof",    "Perfis de Segurança Ausentes","Firewall Policy","High",
     "Políticas ACCEPT devem ter Antivirus, IPS e WebFilter aplicados.",
     "Editar a política → Security Profiles → habilitar todos."),
    ("fortigate","any_src",    "Origem 'all'",                "Firewall Policy","High",
     "Política aceita tráfego de qualquer origem.",
     "Restringir srcaddr ao menor escopo possível."),
    ("fortigate","any_dst",    "Destino 'all'",               "Firewall Policy","Medium",
     "Política permite acesso a qualquer destino.",
     "Restringir dstaddr ao menor escopo possível."),
    ("fortigate","risky_port", "Porta Perigosa",              "Firewall Policy","High",
     "Serviços de alto risco (SSH, RDP, Telnet, BD) não devem ser expostos desnecessariamente.",
     "Restringir a política ou usar VPN para este acesso."),
    ("fortigate","no_log",     "Logging Desabilitado",        "Firewall Policy","Medium",
     "Tráfego sem log impede auditoria.",
     "Editar a política → Log Traffic → utm."),
    ("fortigate","unused",     "Política Sem Uso (0 bytes)",  "Firewall Policy","Low",
     "Nenhum tráfego processado por esta política.",
     "Verificar se a política ainda é necessária."),
    ("fortigate","disabled",   "Política Desabilitada",       "Firewall Policy","Low",
     "Política desabilitada é candidata a remoção.",
     "Revisar e remover a política se obsoleta."),
    # pfSense
    ("pfsense","risky_port", "Porta Perigosa",                "Firewall Policy","High",
     "Portas de alto risco (SSH, RDP, Telnet, BD) não devem ser expostas desnecessariamente.",
     "Restringir a regra ou usar VPN para este acesso."),
    ("pfsense","any_src",    "Origem ANY",                    "Firewall Policy","High",
     "Regra PASS aceita tráfego de qualquer origem.",
     "Restringir a origem ao menor escopo possível."),
    ("pfsense","any_dst",    "Destino ANY",                   "Firewall Policy","Medium",
     "Regra PASS permite acesso irrestrito a todos os destinos.",
     "Restringir o destino ao menor escopo possível."),
    ("pfsense","no_log",     "Sem Logging",                   "Firewall Policy","Medium",
     "Tráfego desta regra não é registrado.",
     "Habilitar Log na regra para auditoria."),
    ("pfsense","unused",     "Regra Sem Uso (0 hits)",        "Firewall Policy","Low",
     "Regras sem tráfego podem ser obsoletas.",
     "Verificar se a regra ainda é necessária."),
    ("pfsense","disabled",   "Regra Desabilitada",            "Firewall Policy","Low",
     "Regra desabilitada é candidata a remoção.",
     "Revisar e remover a regra se obsoleta."),
]


def seed_rule_check_defs():
    """Seed rule check definitions (INSERT OR IGNORE — never overwrites admin edits)."""
    conn = get_db()
    conn.executemany(
        """INSERT OR IGNORE INTO rule_check_defs
           (vendor_slug, tag, name, category, severity, description, recommendation)
           VALUES (?,?,?,?,?,?,?)""",
        _RULE_CHECK_SEED,
    )
    conn.commit()
    conn.close()


def rule_defs_get_all(vendor_slug=None):
    conn = get_db()
    if vendor_slug:
        rows = conn.execute(
            "SELECT * FROM rule_check_defs WHERE vendor_slug=? ORDER BY id",
            (vendor_slug,)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM rule_check_defs ORDER BY vendor_slug, id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def rule_defs_get_disabled_tags(vendor_slug: str) -> set:
    """Return set of tags that are disabled for this vendor."""
    conn = get_db()
    rows = conn.execute(
        "SELECT tag FROM rule_check_defs WHERE vendor_slug=? AND active=0",
        (vendor_slug,)).fetchall()
    conn.close()
    return {r["tag"] for r in rows}


def rule_defs_add(vendor_slug, tag, name, category, severity, description, recommendation) -> int:
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO rule_check_defs
           (vendor_slug, tag, name, category, severity, description, recommendation)
           VALUES (?,?,?,?,?,?,?)""",
        (vendor_slug, tag, name, category, severity, description, recommendation))
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return new_id


def rule_defs_update(def_id: int, name: str, category: str, severity: str,
                     description: str, recommendation: str, tag: str = None):
    conn = get_db()
    if tag:
        conn.execute(
            """UPDATE rule_check_defs
               SET tag=?, name=?, category=?, severity=?, description=?, recommendation=?
               WHERE id=?""",
            (tag, name, category, severity, description, recommendation, def_id))
    else:
        conn.execute(
            """UPDATE rule_check_defs
               SET name=?, category=?, severity=?, description=?, recommendation=?
               WHERE id=?""",
            (name, category, severity, description, recommendation, def_id))
    conn.commit()
    conn.close()


def rule_defs_toggle(def_id: int, active: int):
    conn = get_db()
    conn.execute("UPDATE rule_check_defs SET active=? WHERE id=?", (int(active), def_id))
    conn.commit()
    conn.close()


def rule_defs_delete(def_id: int):
    conn = get_db()
    conn.execute("DELETE FROM rule_check_defs WHERE id=?", (def_id,))
    conn.commit()
    conn.close()


# ── FIREWALL CREDENTIALS ─────────────────────────────────────
def firewall_creds_get_all():
    """Get all stored firewall credentials (passwords encrypted)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, label, vendor_slug, hostname, port, username, description, "
            "last_tested, active FROM firewall_credentials ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def firewall_creds_get_by_label(label: str):
    """Get credential by label, returning decrypted password."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM firewall_credentials WHERE label=?", (label,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        # Decrypt password and api_key for return
        d['password'] = decrypt_credential(d.get('password_encrypted', ''))
        d['api_key'] = decrypt_credential(d.get('api_key_encrypted', ''))
        return d


def firewall_creds_add(label: str, vendor_slug: str, hostname: str, port: int,
                       username: str, password: str, api_key: str = '', description: str = ''):
    """Add new firewall credential with encrypted storage. Auto-creates vendor if not exists."""
    with get_db() as conn:
        existing_vendor = conn.execute(
            "SELECT id FROM vendors WHERE slug=?", (vendor_slug,)
        ).fetchone()
        
        if not existing_vendor:
            conn.execute("""INSERT INTO vendors (slug, name, description, icon)
                VALUES (?, ?, ?, ?)""",
                (vendor_slug, vendor_slug.title(), f"{vendor_slug.title()} Firewall", "🔧"))
        
        enc_pw = encrypt_credential(password)
        enc_key = encrypt_credential(api_key) if api_key else ''
        conn.execute("""
            INSERT INTO firewall_credentials 
            (label, vendor_slug, hostname, port, username, password_encrypted, api_key_encrypted, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (label, vendor_slug, hostname, port, username, enc_pw, enc_key, description))
        conn.commit()
        return conn.lastrowid


def firewall_creds_update(cred_id: int, label: str = None, hostname: str = None,
                         port: int = None, username: str = None, password: str = None,
                         api_key: str = None, description: str = None, active: int = None):
    """Update firewall credential."""
    with get_db() as conn:
        updates = {}
        if label is not None:
            updates['label'] = label
        if hostname is not None:
            updates['hostname'] = hostname
        if port is not None:
            updates['port'] = port
        if username is not None:
            updates['username'] = username
        if password is not None:
            updates['password_encrypted'] = encrypt_credential(password)
        if api_key is not None:
            updates['api_key_encrypted'] = encrypt_credential(api_key) if api_key else ''
        if description is not None:
            updates['description'] = description
        if active is not None:
            updates['active'] = active
        
        if not updates:
            return
        
        set_clause = ', '.join([f"{k}=?" for k in updates.keys()])
        values = list(updates.values()) + [cred_id]
        conn.execute(f"UPDATE firewall_credentials SET {set_clause} WHERE id=?", values)
        conn.commit()


def firewall_creds_delete(cred_id: int):
    """Delete firewall credential."""
    with get_db() as conn:
        conn.execute("DELETE FROM firewall_credentials WHERE id=?", (cred_id,))
        conn.commit()


def firewall_creds_test_update(cred_id: int):
    """Update last_tested timestamp for a credential."""
    with get_db() as conn:
        conn.execute(
            "UPDATE firewall_credentials SET last_tested=CURRENT_TIMESTAMP WHERE id=?",
            (cred_id,))
        conn.commit()

def get_endpoints_by_vendor(vendor_slug: str) -> list:
    """Retorna a lista de endpoints ativos para um vendor específico."""
    with get_db() as conn:
        # 🔴 Colunas corrigidas de acordo com o seu banco:
        cursor = conn.execute(
            "SELECT section_name, endpoint_path FROM api_endpoints WHERE vendor_slug = ? AND active = 1",
            (vendor_slug,)
        )
        return [dict(row) for row in cursor.fetchall()]
