# CIS Validator API — Project Documentation

## Overview

Flask-based REST API for analyzing firewall security configurations against **CIS (Center for Internet Security) benchmarks**. Supports three major firewall vendors via live REST API analysis. All UI text and messages are in **Portuguese (PT-BR)**.

**Live URL:** `http://localhost:5000/` (public UI), `http://localhost:5000/admin` (admin panel)

---

## Directory Structure

```
CIS VALIDATOR API/
├── app.py                    # Flask entry point, route registration, server startup
├── requirements.txt          # Python dependencies
├── database.py               # SQLite schema, encryption, CRUD for all entities
├── engine.py                 # Risk scoring only (calculate_risk + _weights)
├── api_runner.py             # JSON-path evaluator for API-mode checks (simple operators)
├── canonical_checks.py       # Reference CIS check definitions (seed data for api_checks table)
├── pdf_report.py             # PDF report generation (ReportLab, 3 themes: light/dark/modern)
├── fortigate_api.py          # FortiGate REST client + vendor-specific handlers
├── pfsense_api.py            # pfSense REST client + handlers
├── sonicwall_api.py          # SonicWall REST client + handlers
├── cis_analyzer.db           # SQLite database (auto-created on first run)
├── .cis_key                  # Fernet encryption key (auto-generated, chmod 600)
├── routes/
│   ├── public.py             # /api/test, /api/analyze, /api/pdf
│   └── admin.py              # Admin CRUD + authentication endpoints
├── static/
│   ├── css/                  # Stylesheets
│   ├── js/app.js             # Public UI logic
│   └── js/admin.js           # Admin panel logic
└── templates/
    ├── index.html            # Public frontend (live API analysis only)
    └── admin.html            # Admin panel (manage checks, weights, credentials, versions)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Flask 3.0.0 |
| HTTP Client | requests 2.31.0, urllib3 2.1.0 |
| Database | SQLite 3 (via `sqlite3` stdlib) |
| Auth/Security | bcrypt 4.1.2, cryptography (Fernet) 41.0.7 |
| Reports | ReportLab 4.0.9 |
| Language | Python 3.7+ |

---

## Running the Project

```bash
python -m venv venv
source venv/Scripts/activate        # Windows
pip install -r requirements.txt
python app.py                        # Starts on 0.0.0.0:5000, debug=False
```

`init_db()` runs on startup: creates all tables, seeds vendors/versions/checks if empty, runs ALTER TABLE migrations. No manual migration needed.

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECRET_KEY` | `"cis-v4-api-only-2025"` | Flask session secret |

Session lifetime: 8 hours. Session key: `admin_ok` (boolean).

---

## Database Schema

### `vendors`
`id, slug, name, description, icon, base_url, min_firmware_version, active, created_at`
Seeded: `fortigate`, `pfsense`, `sonicwall`
- `min_firmware_version`: fallback global minimum firmware (superseded by version-level field)

### `versions`
`id, vendor_id, version, label, min_firmware_version, active, is_default, created_at`
- `min_firmware_version`: per-version-line minimum (e.g. "7.1.1-7040"). Takes priority over vendor-level.
- FortiGate: 7.0 / 7.2 / **7.4** (default) / 7.6
- pfSense: 2.6 / **2.7** (default) / CE-2.7
- SonicWall: 6.5 / 7.0 / **7.1** (default)

### `api_checks` (API mode)
`id, vendor_slug, cid, title, category, severity, description, recommendation, api_endpoint, json_path, operator, expected_value, handler_key, active, created_at, updated_at`

Operators: `is_true`, `is_false`, `lte`, `gte`, `str_eq`, `list_not_empty`, `handler`

### `rule_check_defs` (per-rule audit toggles)
`id, vendor_slug, tag, name, category, severity, description, recommendation, active, created_at`
- `UNIQUE(vendor_slug, tag)` — each tag maps to a FWR check (e.g. `dpi_off`, `botnet_off`)
- Inactive tags are loaded into `data["_disabled_rule_tags"]` at runtime and skip the corresponding FWR check

### `api_endpoints`
`id, vendor_slug, section_name, endpoint_path, description, active, created_at, updated_at`

### `analysis_history`
`id, company, vendor_slug, version, score, risk_level, passed, failed, total, created_at`

### `admin_auth`
`id, username, password_hash, created_at`
Format: `salt:sha256(salt+password)`. Default password `"admin"` if table is empty.

### `severity_weights`
`severity (PK), weight`
Defaults: Critical=10, High=6, Medium=3, Low=1

### `firewall_credentials`
`id, label, vendor_slug, hostname, port, username, password_encrypted, api_key_encrypted, description, last_tested, active, created_at, updated_at`
Passwords encrypted at rest with Fernet (key in `.cis_key`). Never exposed in API responses.

---

## API Endpoints

### Public Routes (`routes/public.py`)

#### `POST /api/test`
Test firewall connectivity.
```json
// Request
{ "vendor": "fortigate", "host": "192.168.1.1", "port": 443, "username": "admin", "password": "...", "api_key": "" }
// Response
{ "ok": true, "message": "...", "firmware": "7.4.3", "model": "FortiGate-100F" }
```

#### `POST /api/analyze`
Full CIS analysis via live API.
```json
// Request
{ "vendor": "sonicwall", "host": "...", "port": 443, "username": "admin", "password": "...", "api_key": "", "company": "Empresa XYZ" }
// Response (abbreviated)
{
  "company": "Empresa XYZ",
  "vendor": "sonicwall",
  "vendor_name": "SonicWall",
  "version": "7.1",
  "version_label": "SonicOS 7.1",
  "benchmark": "CIS SonicWall SonicOS 7.1",
  "timestamp": "2026-04-18T10:30:00",
  "risk": {
    "score": 72,
    "risk_level": "MEDIO",
    "risk_color": "#f59e0b",
    "total_checks": 48,
    "passed": 35,
    "failed": 13,
    "by_severity": { "Critical": { "total": 5, "pass": 4, "fail": 1, "weight": 10 } },
    "by_category": { "Access Control": { "total": 10, "pass": 8, "fail": 2, "score": 80 } },
    "weights_used": { "Critical": 10, "High": 6, "Medium": 3, "Low": 1 }
  },
  "checks": [...],
  "cis_checks": [...],
  "rule_checks": [...],
  "rules_audit": {...},
  "source": "api"
}
```

#### `POST /api/pdf`
Generate PDF from analysis result. Accepts full `/api/analyze` response body.
Returns `application/pdf` with filename `{VENDOR}_CIS_{COMPANY}_{DATE}.pdf`.

---

### Admin Routes (`routes/admin.py`)

All require `session["admin_ok"] = True` except login/auth-check.

#### Authentication
| Method | Endpoint | Body / Notes |
|--------|----------|--------------|
| POST | `/api/admin/login` | `{ password }` |
| POST | `/api/admin/logout` | — |
| GET | `/api/admin/auth-check` | Returns `{ authenticated }` |
| POST | `/api/admin/change-password` | `{ current_password, new_password }` |

#### Stats & History
| Method | Endpoint | Notes |
|--------|----------|-------|
| GET | `/api/admin/stats` | Counts + last 10 history entries |
| GET | `/api/admin/history` | Last 50 analysis runs |

#### Vendors & Versions
| Method | Endpoint | Notes |
|--------|----------|-------|
| GET | `/api/vendors` | Public, no auth. Returns vendors with nested `versions[]` array |
| PUT | `/api/admin/vendors/<id>` | Update slug, name, icon, base_url, description |
| DELETE | `/api/admin/vendors/<id>` | Delete vendor |
| POST | `/api/admin/versions` | Add version — body: `{ vendor_id, version, label, min_firmware_version }` |
| PUT | `/api/admin/versions/<id>` | Update label and/or min_firmware_version |
| DELETE | `/api/admin/versions/<id>` | Delete version |

#### API Checks (CIS checks, DB-driven)
| Method | Endpoint | Notes |
|--------|----------|-------|
| GET | `/api/admin/api-checks?vendor=<slug>` | |
| POST | `/api/admin/api-checks` | |
| PUT | `/api/admin/api-checks/<id>` | |
| POST | `/api/admin/api-checks/<id>/toggle` | `{ active: 0|1 }` |
| DELETE | `/api/admin/api-checks/<id>` | |

#### Rule Check Definitions (FWR per-rule audit toggles)
| Method | Endpoint | Notes |
|--------|----------|-------|
| GET | `/api/admin/rule-checks?vendor=<slug>` | |
| POST | `/api/admin/rule-checks` | Body: `{ vendor_slug, name, severity, tag?, category?, description?, recommendation? }` |
| PUT | `/api/admin/rule-checks/<id>` | |
| POST | `/api/admin/rule-checks/<id>/toggle` | `{ active: 0|1 }` |
| DELETE | `/api/admin/rule-checks/<id>` | |

#### API Endpoints
| Method | Endpoint |
|--------|----------|
| GET | `/api/admin/endpoints?vendor_slug=<slug>` |
| POST | `/api/admin/endpoints` |
| PUT | `/api/admin/endpoints/<id>` |
| POST | `/api/admin/endpoints/<id>/toggle` |
| DELETE | `/api/admin/endpoints/<id>` |

#### Other Admin
| Method | Endpoint | Notes |
|--------|----------|-------|
| GET/PUT | `/api/admin/weights` | Severity weights |
| GET/POST/PUT/DELETE | `/api/admin/firewall-credentials` | Stored creds (encrypted) |
| POST | `/api/admin/firewall-credentials/<id>/test` | Test connection, update last_tested |

---

## Business Logic

### Check Evaluation (`api_runner.py`)

**Operators:**
- `is_true` — Truthy values: `True, 1, "enable", "enabled", "yes", "true", "on"` → PASS
- `is_false` — Falsy or absent → PASS
- `lte` / `gte` — Numeric comparison → PASS
- `str_eq` — Case-insensitive string equality → PASS
- `list_not_empty` — Non-empty list → PASS
- `handler` — Delegates to Python handler function in vendor module

**JSON path traversal:** dot-notation (e.g., `gateway_antivirus.enable`) navigates nested dicts relative to the endpoint's data key. Missing path → `None`.

### Risk Scoring

```
score = 100 - (sum(weight * fail_count per severity) / sum(weight * total_count per severity) * 100)
```

| Score | Risk Level | Color |
|-------|-----------|-------|
| ≥ 85 | BAIXO (Low) | `#10b981` |
| 65–84 | MEDIO (Medium) | `#f59e0b` |
| 40–64 | ALTO (High) | `#ef4444` |
| < 40 | CRITICO (Critical) | `#dc2626` |

---

## Vendor API Clients

### FortiGate (`fortigate_api.py`)
- Base URL: `https://{host}:{port}/api/v2`
- Auth: API Key (Bearer) OR username/password (session cookie)
- Response unwrapping: extracts `results` key from API responses
- Key endpoints: `system/status`, `cmdb/system/*`, `cmdb/firewall/policy`, `cmdb/antivirus/profile`, `cmdb/vpn.ipsec/*`

### pfSense (`pfsense_api.py`)
- Base URL: `https://{host}:{port}/api/v1`
- Auth: API Key (Bearer) OR HTTP Basic
- Requires: `pfSense-pkg-API` plugin on device
- Stateless — no logout needed
- Response unwrapping: extracts `data` key
- Key endpoints: `system/version`, `system/config`, `user`, `interface`, `firewall/rule`, `services/*`

### SonicWall (`sonicwall_api.py`)
- Base URL: `https://{host}:{port}/api/sonicos`
- Auth: HTTP Basic → POST `/auth` → Bearer token in response `Authorization` header
- Response unwrapping: each endpoint returns `{"<key>": {...}}` — unwrapped per key in `run_api_checks()`

**SonicWall endpoints fetched at runtime:**

| data key | Endpoint path | Notes |
|----------|--------------|-------|
| `device` | `reporting/status/system` | Firmware version, model, restart_required |
| `management` | `system/base` | Web/SSH/HTTPS management settings. Unwraps `system` key. |
| `snmp` | `snmp/base` | SNMP config, community strings, host ACL |
| `gav` | `gateway-antivirus/base` | Gateway AV inbound/outbound |
| `ips` | `intrusion-prevention/base` | IPS enable |
| `botnet` | `botnet/base` | Botnet block mode: `connections.all` or `connections.firewall_rule_based` |
| `geo_ip` | `geo-ip/base` | GeoIP block mode: `connections.all` or `connections.firewall_rule_based` |
| `cfs` | `content-filter/cfs/base` | Content filter |
| `aspy` | `anti-spyware/base` | Anti-spyware |
| `syslog` | `log/syslog/syslog-servers` | Syslog server list. Checks `server[].enabled`. |
| `syn_flood` | `firewall/flood-protection/syn/base` | SYN flood (legacy CID 11.1) |
| `tcp_flood` | `firewall/flood-protection/tcp/base` | TCP flood protection (CID 17.x) |
| `ike` | `vpn/ike/phase1-proposals` | VPN IKE phase1 proposals |
| `dpi_ssl` | `dpi-ssl/client/base` | DPI-SSL TLS version settings |
| `pwd_policy` | `user/local/password-policy/base` | Local user password policy |
| `administration` | `administration/global` | Admin interface + password complexity. Unwraps `administration` key. |
| `access_rules` | `access-rules/ipv4` + `access-rules/ipv6` | Combined list. Each item unwrapped from `{"ipv4":{}}` or `{"ipv6":{}}`. |

**All clients:** `verify=False` (self-signed certs), 15-second timeout, `urllib3.disable_warnings()` suppresses SSL warnings.

---

## SonicWall CIS Checks (48 total)

| Group | CIDs | Category | Key checks |
|-------|------|----------|-----------|
| Firmware | 1.1 | System Hardening | Version vs min firmware (per version line), NVD CVE query, restart pending |
| Management | 2.1–2.4 | Access Control | HTTPS on, HTTP off, SSH off, idle timeout ≤10min |
| SNMP | 3.1–3.3 | Network Security | SNMPv3 mandatory, community ≠ public, host ACL configured |
| Gateway AV | 4.1–4.3 | Firewall Policy | Global enable, inbound protocols, outbound protocols |
| IPS | 5.1 | Firewall Policy | IPS enabled |
| Botnet | 6.1–6.2 | Network Security | Block mode (global/per-rule), logging |
| Geo-IP | 7.1–7.2 | Network Security | Block mode (global/per-rule), logging |
| CFS | 8.1–8.2 | Firewall Policy | CFS enabled, block-if-unavailable |
| Anti-Spyware | 9.1 | Firewall Policy | Enabled |
| Syslog | 10.1 | Logging & Monitoring | At least 1 active remote server |
| SYN Flood | 11.1 | Firewall Policy | SYN flood protection enabled |
| VPN IKE | 12.1 | VPN | No DES/MD5 proposals |
| DPI-SSL | 13.1–13.3 | Encryption | TLS 1.0 off, TLS 1.1 off, TLS 1.2 on |
| Password Policy | 14.1–14.2 | Access Control | Min length ≥8, lockout enabled (from `pwd_policy` endpoint) |
| Administration | 15.1–15.8 | Access Control / System Hardening | Admin username renamed, SSH port/disabled, HTTPS port changed, HTTP off, idle timeout, IP ACL, CAPTCHA/OTP, login info hidden |
| Senha e Complexidade | 16.1–16.4 | Senha e Complexidade | Complexity enforced, min length ≥8, expiry enabled, lockout (from `administration` endpoint) |
| TCP Flood | 17.1–17.9 | Firewall Policy | Strict compliance, handshake enforcement, checksum, drop SYN+data, drop invalid urgent, handshake timeout, SYN flood mode (not watch-and-report), blacklisting, DDoS on WAN |
| Access Rules | FWR-0 | Firewall Policy | Summary handler — triggers FWR-1 through FWR-11 per rule |

### FWR Per-Rule Checks (FWR-1 to FWR-11)

Each check runs against every ALLOW rule. Toggleable individually via `rule_check_defs` table.

| Tag | CID | Severity | Check |
|-----|-----|----------|-------|
| `dpi_off` | FWR-1 | High | DPI disabled on rule |
| `dpi_ssl_off` | FWR-2 | Medium | DPI-SSL client/server incomplete |
| `botnet_off` | FWR-3 | High | Botnet Filter off — **skipped if Botnet global mode (`all: true`)** |
| `geoip_off` | FWR-4 | Medium | Geo-IP Filter off — **skipped if GeoIP global mode (`all: true`)** |
| `any_src` | FWR-5 | High | Source = ANY |
| `any_dst` | FWR-6 | Medium | Destination = ANY |
| `no_log` | FWR-7 | Medium | Logging disabled |
| `fragments` | FWR-8 | Medium | Fragments allowed |
| `schedule_exp` | FWR-9 | High | Schedule expired |
| `disabled` | FWR-10 | Low | Rule is disabled (candidate for removal) |
| `no_hits` | FWR-11 | Low | Zero hit count |

### Botnet / Geo-IP Mode Detection

Both services support two deployment modes detected from `block.connections`:

| Field | Mode | Behavior |
|-------|------|----------|
| `"all": true` | Global — blocks all connections | CIS check PASS; FWR-3/FWR-4 suppressed |
| `"firewall_rule_based": true` | Per-rule — each rule decides | CIS check counts rules with module active; FWR-3/FWR-4 active |
| `{}` (empty) | Not configured | CIS check FAIL |

### Firmware Check Logic (CID 1.1)

1. Detect running version line (e.g. `"7.1.1-7040"` → line `"7.1"`)
2. Look up `versions.min_firmware_version` for `sonicwall / 7.1` — falls back to `vendors.min_firmware_version`
3. If running version < minimum → FAIL
4. Query NIST NVD API for CVEs against `SonicWall SonicOS <version>` — NVD unavailable → PASS with warning
5. Check `restart_required` field — pending restart → FAIL

---

## Check Result Object

```python
{
    "id": int,
    "cid": str,              # e.g., "1.1", "15.3", "FWR-1"
    "title": str,
    "category": str,
    "severity": str,         # "Critical" | "High" | "Medium" | "Low"
    "description": str,
    "recommendation": str,
    "status": "PASS" | "FAIL",
    "detail": str,
    "current_value": str,
    "pattern_type": str,     # always "api"
}
```

---

## Error Response Structure

```json
{ "error": "Human-readable message", "ok": false }
{ "error": "Autenticacao necessaria", "auth_required": true }
```

HTTP codes: `200` success, `400` bad request, `401` unauthorized, `500` server error.

---

## Authentication

**Default credentials:** username `admin`, password `admin` (if `admin_auth` table empty).

**Password storage:** `salt:sha256(salt+password)` in `admin_auth` table.

**First-run:** Immediately change password via `POST /api/admin/change-password`.

**Session:** `session["admin_ok"] = True`, 8-hour lifetime, cookie-based.

**Firewall credentials:** Encrypted with Fernet before storing in DB. Key in `.cis_key` (auto-generated, permissions `0o600`). Never returned in API responses.

---

## Notable Behaviors

1. All user-facing text is in **Portuguese (PT-BR)**
2. `*_api.py` files handle live API analysis; `engine.py` handles risk scoring only
3. Complex checks use **handler functions** (`operator="handler"`) receiving the full raw data dict
4. Handler may return `None` (skip), a single result dict, or a list of result dicts
5. The admin panel manages check definitions — changes take effect immediately on next analysis
6. `analysis_history` logs every analysis run with score and risk level
7. On startup, if file `Acesso temporario firewalls.txt` exists, credentials are migrated to DB and the file is deleted
8. `canonical_checks.py` is a **reference/seed file** — seeded via `INSERT OR IGNORE` so admin edits are preserved across restarts
9. `cid` values prefixed with `FWR-` are firewall rule checks (appear in `rule_checks[]`); others appear in `cis_checks[]`
10. `rule_check_defs` disabled tags are loaded once per analysis into `data["_disabled_rule_tags"]` and shared across the CIS handler and `get_rules_audit()`
11. **Botnet/GeoIP** FWR per-rule checks (FWR-3, FWR-4) are automatically suppressed when the respective service is in global mode (`connections.all: true`)
12. **Firmware min version** is stored per version line in `versions.min_firmware_version` (e.g. line "7.1" → min "7.1.1-7040"); falls back to `vendors.min_firmware_version`
13. Database schema migrations run as `ALTER TABLE ... ADD COLUMN` wrapped in `try/except` — safe to re-run on existing databases
