# Controles CIS — SonicWall SonicOS

> Benchmark: **CIS SonicWall SonicOS 7.x**  
> Total: **67 controles CIS** + **11 checks por regra (FWR)**  
> Atualizado em: 2026-04-21

---

## Resumo por Severidade

| Severidade | Qtd |
|-----------|-----|
| Critical  | 5   |
| High      | 34  |
| Medium    | 25  |
| Low       | 3   |
| **Total** | **67** |

---

## Mapa de Endpoints

| Grupo | Data Key | Endpoint API (`/api/sonicos/...`) |
|-------|----------|----------------------------------|
| 1 | `device` | `reporting/status/system` |
| 3 | `snmp` | `snmp/base` |
| 4 (4.1–4.3) | `gav` | `gateway-antivirus/base` |
| 4 (4.4) | `gav_cloud` | `gateway-antivirus/cloud/base` |
| 5 | `ips` | `intrusion-prevention/base` |
| 6 | `botnet` | `botnet/base` |
| 7 | `geo_ip` | `geo-ip/base` |
| 8 | `cfs` | `content-filter/cfs/base` |
| 9 | `aspy` | `anti-spyware/base` |
| 10 | `syslog` | `log/syslog/syslog-servers` |
| 11 | `syn_flood` | `firewall/flood-protection/syn/base` |
| 12 | `ike` | `vpn/ike/phase1-proposals` |
| 13 | `dpi_ssl` | `dpi-ssl/client/base` |
| 15 | `administration` | `administration/global` |
| 16 | `administration` | `administration/global` |
| 17 | `tcp_flood` | `firewall/flood-protection/tcp` |
| 18 | `capture_atp` | `capture-atp/base` |
| 19 | `fw_base` | `firewall` |
| 20 | `interfaces_ipv4` | `interfaces/ipv4` |
| FWR | `access_rules` | `access-rules/ipv4` + `access-rules/ipv6` |

---

## Grupo 1 — Firmware

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 1.1 | Firmware SonicOS | `reporting/status/system` | System Hardening | High |

---

## Grupo 3 — SNMP

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 3.1 | Protocolo SNMP | `snmp/base` | Network Security | High |
| 3.2 | Comunidade SNMP Padrão | `snmp/base` | Network Security | Critical |
| 3.3 | Restrição de Hosts SNMP | `snmp/base` | Network Security | High |

---

## Grupo 4 — Gateway Antivirus

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 4.1 | Gateway Antivirus Global | `gateway-antivirus/base` | Firewall Policy | High |
| 4.2 | GAV Inbound — Todos os Protocolos | `gateway-antivirus/base` | Firewall Policy | Medium |
| 4.3 | GAV Outbound — Todos os Protocolos | `gateway-antivirus/base` | Firewall Policy | Medium |
| 4.4 | GAV — Cloud Database | `gateway-antivirus/cloud/base` | Firewall Policy | High |

---

## Grupo 5 — IPS

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 5.1 | Intrusion Prevention System (IPS) | `intrusion-prevention/base` | Firewall Policy | High |

---

## Grupo 6 — Botnet

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 6.1 | Botnet — Bloqueio de Conexões | `botnet/base` | Network Security | High |
| 6.2 | Botnet — Registro de Eventos | `botnet/base` | Logging & Monitoring | Medium |

---

## Grupo 7 — Geo-IP

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 7.1 | Geo-IP — Bloqueio de Regiões | `geo-ip/base` | Network Security | Medium |
| 7.2 | Geo-IP — Registro de Eventos | `geo-ip/base` | Logging & Monitoring | Medium |

---

## Grupo 8 — Content Filter (CFS)

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 8.1 | Content Filter (CFS) | `content-filter/cfs/base` | Firewall Policy | Medium |
| 8.2 | CFS — Bloquear se Servidor Indisponível | `content-filter/cfs/base` | Firewall Policy | Medium |

---

## Grupo 9 — Anti-Spyware

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 9.1 | Anti-Spyware | `anti-spyware/base` | Firewall Policy | Medium |

---

## Grupo 10 — Syslog

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 10.1 | Servidor Syslog Remoto | `log/syslog/syslog-servers` | Logging & Monitoring | High |

---

## Grupo 11 — SYN Flood

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 11.1 | Proteção SYN Flood | `firewall/flood-protection/syn/base` | Firewall Policy | High |

---

## Grupo 12 — VPN IKE

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 12.1 | VPN — Sem Algoritmos Fracos (DES/MD5) | `vpn/ike/phase1-proposals` | VPN | High |

---

## Grupo 13 — DPI-SSL

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 13.1 | DPI-SSL Client | `dpi-ssl/client/base` | Encryption | High |
| 13.2 | DPI-SSL — Inspeção IPS | `dpi-ssl/client/base` | Encryption | High |
| 13.3 | DPI-SSL — Gateway Antivirus | `dpi-ssl/client/base` | Encryption | High |
| 13.4 | DPI-SSL — Anti-Spyware | `dpi-ssl/client/base` | Encryption | Medium |
| 13.5 | DPI-SSL — Application Firewall | `dpi-ssl/client/base` | Encryption | Medium |
| 13.6 | DPI-SSL — Content Filter | `dpi-ssl/client/base` | Encryption | Medium |
| 13.7 | DPI-SSL — Autenticação de Servidor | `dpi-ssl/client/base` | Encryption | High |
| 13.8 | DPI-SSL — Não Abrir Conexões com Falha | `dpi-ssl/client/base` | Encryption | Medium |

---

## Grupo 15 — Interface de Administração

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 15.1 | Nome do Superusuário Administrador | `administration/global` | Access Control | Critical |
| 15.2 | SSH de Gerenciamento | `administration/global` | Access Control | High |
| 15.3 | Porta HTTPS de Gerenciamento | `administration/global` | Access Control | Medium |
| 15.4 | HTTP de Gerenciamento | `administration/global` | Access Control | Critical |
| 15.5 | Timeout de Sessão Admin ≤ 10 min | `administration/global` | System Hardening | High |
| 15.6 | Restrição de Acesso ao Gerenciamento por IP | `administration/global` | Access Control | High |
| 15.7 | Proteção de Login Administrativo | `administration/global` | Access Control | Medium |
| 15.8 | Exposição de Informações na Página de Login | `administration/global` | System Hardening | Low |

---

## Grupo 16 — Senha e Complexidade

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 16.1 | Complexidade de Senha | `administration/global` | Senha e Complexidade | High |
| 16.2 | Comprimento Mínimo de Senha Admin ≥ 8 | `administration/global` | Senha e Complexidade | High |
| 16.3 | Expiração de Senha Admin | `administration/global` | Senha e Complexidade | Medium |
| 16.4 | Bloqueio de Conta | `administration/global` | Senha e Complexidade | High |

---

## Grupo 17 — Proteção TCP

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 17.1 | TCP Strict Compliance | `firewall/flood-protection/tcp` | Firewall Policy | Medium |
| 17.2 | TCP Handshake Enforcement | `firewall/flood-protection/tcp` | Firewall Policy | High |
| 17.3 | TCP Checksum Enforcement | `firewall/flood-protection/tcp` | Firewall Policy | Medium |
| 17.4 | Drop de SYN com Dados | `firewall/flood-protection/tcp` | Firewall Policy | High |
| 17.5 | Drop de Pacotes Urgent Inválidos | `firewall/flood-protection/tcp` | Firewall Policy | Medium |
| 17.6 | TCP Handshake Timeout | `firewall/flood-protection/tcp` | Firewall Policy | Medium |
| 17.7 | Modo de Proteção SYN Flood | `firewall/flood-protection/tcp` | Firewall Policy | High |
| 17.8 | SYN Flood Blacklisting | `firewall/flood-protection/tcp` | Firewall Policy | High |
| 17.9 | Proteção DDoS em Interfaces WAN | `firewall/flood-protection/tcp` | Firewall Policy | High |

---

## Grupo 18 — Capture ATP

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 18.1 | Capture ATP | `capture-atp/base` | Firewall Policy | High |
| 18.2 | Capture ATP — Tipos de Arquivo Cobertos | `capture-atp/base` | Firewall Policy | Medium |
| 18.3 | Capture ATP — Política de Veredicto | `capture-atp/base` | Firewall Policy | High |

---

## Grupo 19 — Configurações Base do Firewall

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 19.1 | Stealth Mode | `firewall` | Network Security | Medium |
| 19.2 | IP ID Randomization | `firewall` | Network Security | Low |
| 19.3 | Drop de Pacotes Source Routed | `firewall` | Network Security | High |
| 19.4 | Drop de Source Subnet Broadcast | `firewall` | Network Security | Medium |
| 19.5 | IP Checksum Enforcement | `firewall` | Firewall Policy | Medium |
| 19.6 | Control Plane Flood Protection | `firewall` | Firewall Policy | High |
| 19.7 | IPv6 — Routing Header Type 0 | `firewall` | Network Security | High |
| 19.8 | IPv6 — Extension Header Check | `firewall` | Network Security | Medium |

---

## Grupo 20 — Segurança em Interfaces WAN

> Checks aplicados apenas nas interfaces onde `ip_assignment.zone == "wan"`.

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| 20.1 | HTTP de Gerenciamento em Interface WAN | `interfaces/ipv4` | Access Control | Critical |
| 20.2 | HTTPS de Gerenciamento em Interface WAN | `interfaces/ipv4` | Access Control | High |
| 20.3 | SSH em Interfaces WAN | `interfaces/ipv4` | Access Control | High |
| 20.4 | SNMP em Interfaces WAN | `interfaces/ipv4` | Network Security | High |
| 20.5 | Ping em Interfaces WAN | `interfaces/ipv4` | Network Security | Medium |
| 20.6 | Login de Usuário HTTP em Interface WAN | `interfaces/ipv4` | Access Control | Critical |
| 20.7 | Login de Usuário HTTPS em Interface WAN | `interfaces/ipv4` | Access Control | High |

---

## Auditoria por Regra de Firewall (FWR)

> Checks executados individualmente em cada regra ALLOW da política.  
> FWR-3 e FWR-4 são suprimidos automaticamente quando Botnet/Geo-IP estiver em modo global.

| CID | Título | Endpoint | Categoria | Severidade |
|-----|--------|----------|-----------|-----------|
| FWR-0 | Regras ALLOW — Auditoria Geral (resumo) | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | Low |
| FWR-1 | DPI Desabilitado na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | High |
| FWR-2 | DPI-SSL Incompleto na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | Medium |
| FWR-3 | Botnet Filter Desabilitado na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | High |
| FWR-4 | Geo-IP Filter Desabilitado na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | Medium |
| FWR-5 | Origem ANY na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | High |
| FWR-6 | Destino ANY na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | Medium |
| FWR-7 | Logging Desabilitado na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | Medium |
| FWR-8 | Fragmentos Permitidos na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | Medium |
| FWR-9 | Schedule Expirado na Regra | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | High |
| FWR-10 | Regra Desabilitada (candidata a remoção) | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | Low |
| FWR-11 | Regra Sem Uso — 0 Hits | `access-rules/ipv4` + `access-rules/ipv6` | Firewall Policy | Low |
