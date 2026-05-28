"""
canonical_checks.py — Reference CIS check definitions for API-mode vendors.

Each check dict has:
  vendor_slug   : "sonicwall" | "fortigate" | "pfsense"
  cid           : unique identifier within vendor (e.g. "2.1", "FWR-1")
  title         : human-readable title (PT-BR)
  category      : e.g. "Access Control", "Firewall Policy"
  severity      : Critical | High | Medium | Low
  description   : what is being checked
  recommendation: remediation guidance (action only, no UI navigation path)
  api_endpoint  : key in data dict fetched by run_api_checks (e.g. "management")
  json_path     : dot-notation path within endpoint data (e.g. "system.management.web.https.enable")
  operator      : is_true | is_false | lte | gte | str_eq | list_not_empty | handler
  expected_value: for lte/gte/str_eq operators (string)
  handler_key   : name of Python handler function (for complex checks)

Operators:
  is_true        — value is truthy (True, 1, "enable", "enabled", "yes")
  is_false       — value is falsy or absent
  lte            — int(value) <= int(expected_value)
  gte            — int(value) >= int(expected_value)
  str_eq         — str(value).lower() == expected_value.lower()
  list_not_empty — value is a non-empty list
  handler        — evaluated entirely by Python handler_key function
"""

# ─────────────────────────────────────────────────────────────
# SONICWALL
# ─────────────────────────────────────────────────────────────
SONICWALL_CANONICAL = [
    # 1. FIRMWARE
    dict(vendor_slug="sonicwall", cid="1.1",
         title="Firmware SonicOS", category="System Hardening", severity="High",
         description="A versão do firmware deve ser identificada, estar acima da versão mínima recomendada e não possuir CVEs críticos ou altos conhecidos.",
         recommendation="Atualizar o firmware para a versão mínima configurada e verificar CVEs no NIST NVD.",
         api_endpoint="device", json_path="", operator="handler", expected_value="",
         handler_key="sw_firmware"),

     # 2.timeout

     dict(vendor_slug="sonicwall", cid="2.4",
         title="Timeout de Sessão Admin ≤ 10 min", category="System Hardening", severity="High",
         description="Sessões devem expirar em até 10 minutos.",
         recommendation="Configurar inactivity timeout ≤ 10 minutos.",
         api_endpoint="Administration", json_path="administration.idle_logout_time", operator="lte", expected_value="10",
         handler_key=""),

    # 3. SNMP
    dict(vendor_slug="sonicwall", cid="3.1",
         title="Protocolo SNMP", category="Network Security", severity="High",
         description="O SNMP deve estar desabilitado ou, se necessário, operar exclusivamente em SNMPv3. SNMPv1/v2 utilizam autenticação fraca e transmitem dados em texto claro.",
         recommendation="Desabilitar SNMP ou configurar snmp3.mandatory=true para forçar SNMPv3.",
         api_endpoint="SNMP", json_path="", operator="handler", expected_value="",
         handler_key="sw_snmp"),

    dict(vendor_slug="sonicwall", cid="3.2",
         title="Comunidade SNMP Padrão", category="Network Security", severity="Critical",
         description="As community strings GET e TRAP não devem usar o valor padrão 'public', amplamente conhecido e explorado por atacantes.",
         recommendation="Alterar get_community_name e trap_community_name para valores complexos e únicos.",
         api_endpoint="SNMP", json_path="", operator="handler", expected_value="",
         handler_key="sw_snmp_community"),

    dict(vendor_slug="sonicwall", cid="3.3",
         title="Restrição de Hosts SNMP", category="Network Security", severity="High",
         description="Sem hosts autorizados definidos, qualquer dispositivo da rede pode consultar o SNMP e obter informações sensíveis do equipamento.",
         recommendation="Configurar ao menos um host autorizado (host_1..host_4) para restringir o acesso SNMP.",
         api_endpoint="SNMP", json_path="", operator="handler", expected_value="",
         handler_key="sw_snmp_hosts"),

    # 4. GAV
    dict(vendor_slug="sonicwall", cid="4.1",
         title="Gateway Antivirus Global", category="Firewall Policy", severity="High",
         description="O Gateway Antivirus deve estar globalmente ativo para inspecionar ameaças em todo o tráfego antes que alcancem os endpoints.",
         recommendation="Habilitar Gateway Anti-Virus globalmente em gateway-antivirus/base.",
         api_endpoint="Gateway AV", json_path="gateway_antivirus.enable",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="4.2",
         title="GAV Inbound — Todos os Protocolos", category="Firewall Policy", severity="Medium",
         description="Inbound deve cobrir: http, ftp, imap, smtp, pop3, cifs_netbios, tcp_stream.",
         recommendation="Habilitar inspeção GAV inbound em todos os protocolos.",
         api_endpoint="Gateway AV", json_path="", operator="handler", expected_value="",
         handler_key="sw_gav_inbound"),

    dict(vendor_slug="sonicwall", cid="4.3",
         title="GAV Outbound — Todos os Protocolos", category="Firewall Policy", severity="Medium",
         description="Outbound deve cobrir: http, ftp, smtp, tcp_stream.",
         recommendation="Habilitar inspeção GAV outbound em todos os protocolos.",
         api_endpoint="Gateway AV", json_path="", operator="handler", expected_value="",
         handler_key="sw_gav_outbound"),

    dict(vendor_slug="sonicwall", cid="4.4",
         title="GAV — Cloud Database", category="Firewall Policy", severity="High",
         description="A base de dados de assinaturas em nuvem deve estar ativa para garantir detecção de ameaças recentes não presentes na base local.",
         recommendation="Habilitar anti_virus_database na configuração cloud do Gateway AV.",
         api_endpoint="Gav_cloud", json_path="gateway_antivirus.cloud.anti_virus_database",
         operator="is_true", expected_value="", handler_key=""),

    # 5. IPS
    dict(vendor_slug="sonicwall", cid="5.1",
         title="Intrusion Prevention System (IPS)", category="Firewall Policy", severity="High",
         description="O IPS deve estar ativo para detectar e bloquear tentativas de exploração de vulnerabilidades em tempo real.",
         recommendation="Habilitar Intrusion Prevention em intrusion-prevention/base.",
         api_endpoint="IPS", json_path="intrusion_prevention.enable",
         operator="is_true", expected_value="", handler_key=""),

    # 6. BOTNET
    dict(vendor_slug="sonicwall", cid="6.1",
         title="Botnet — Bloqueio de Conexões", category="Network Security", severity="High",
         description="Proteção botnet deve bloquear conexões C&C (modo global ou per-regra com todas as regras cobertas).",
         recommendation="Configurar bloqueio global (all) ou per-regra com Botnet Filter ativo em todas as regras ALLOW.",
         api_endpoint="Botnet", json_path="", operator="handler", expected_value="",
         handler_key="sw_botnet_block"),

    dict(vendor_slug="sonicwall", cid="6.2",
         title="Botnet — Registro de Eventos", category="Logging & Monitoring", severity="Medium",
         description="O registro de eventos de botnet deve estar ativo para permitir auditoria e resposta a incidentes envolvendo comunicação com servidores C&C.",
         recommendation="Habilitar logging de eventos Botnet em botnet/base.",
         api_endpoint="Botnet", json_path="botnet.logging",
         operator="is_true", expected_value="", handler_key=""),

    # 7. GEO-IP
    dict(vendor_slug="sonicwall", cid="7.1",
         title="Geo-IP — Bloqueio de Regiões", category="Network Security", severity="Medium",
         description="O filtro Geo-IP deve estar configurado para bloquear conexões originadas de regiões de alto risco, reduzindo a superfície de ataque externa.",
         recommendation="Configurar bloqueio de regiões via Geo-IP em modo global (all) ou per-regra.",
         api_endpoint="Geo IP", json_path="", operator="handler", expected_value="",
         handler_key="sw_geoip_block"),

    dict(vendor_slug="sonicwall", cid="7.2",
         title="Geo-IP — Registro de Eventos", category="Logging & Monitoring", severity="Medium",
         description="O registro de eventos Geo-IP deve estar ativo para rastrear bloqueios por região e identificar padrões de acesso suspeitos.",
         recommendation="Habilitar logging de eventos Geo-IP em geo-ip/base.",
         api_endpoint="Geo IP", json_path="geo_ip.logging",
         operator="is_true", expected_value="", handler_key=""),

    # 8. CFS
    dict(vendor_slug="sonicwall", cid="8.1",
         title="Content Filter (CFS)", category="Firewall Policy", severity="Medium",
         description="O Content Filter deve estar ativo para controlar o acesso a sites maliciosos, impróprios ou não relacionados ao trabalho.",
         recommendation="Habilitar Content Filter (CFS) em content-filter/cfs/base.",
         api_endpoint="Content Filter", json_path="content_filter.cfs.enable",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="8.2",
         title="CFS — Bloquear se Servidor Indisponível", category="Firewall Policy", severity="Medium",
         description="Block if server unavailable impede bypass quando CFS offline.",
         recommendation="Habilitar bloqueio quando servidor CFS estiver indisponível.",
         api_endpoint="Content Filter", json_path="content_filter.cfs.block_if_server_unavailable",
         operator="is_true", expected_value="", handler_key=""),

    # 9. ANTI-SPYWARE
    dict(vendor_slug="sonicwall", cid="9.1",
         title="Anti-Spyware", category="Firewall Policy", severity="Medium",
         description="O Anti-Spyware deve estar ativo para detectar e bloquear comunicações de spyware, adware e outros programas indesejados.",
         recommendation="Habilitar Anti-Spyware em anti-spyware/base.",
         api_endpoint="Aspy", json_path="anti_spyware.enable",
         operator="is_true", expected_value="", handler_key=""),

    # 10. SYSLOG
    dict(vendor_slug="sonicwall", cid="10.1",
         title="Servidor Syslog Remoto", category="Logging & Monitoring", severity="High",
         description="Pelo menos um servidor syslog remoto deve estar ativo para garantir que os logs não sejam perdidos em caso de comprometimento do dispositivo.",
         recommendation="Configurar e ativar ao menos um servidor syslog remoto em log/syslog/syslog-servers.",
         api_endpoint="Syslog", json_path="", operator="handler", expected_value="",
         handler_key="sw_syslog"),

    # 11. SYN FLOOD (lido do mesmo endpoint TCP)
    dict(vendor_slug="sonicwall", cid="11.1",
         title="Proteção SYN Flood", category="Firewall Policy", severity="High",
         description="A proteção SYN Flood deve estar ativa para mitigar ataques de negação de serviço baseados em inundação de pacotes SYN.",
         recommendation="Habilitar proteção SYN Flood em firewall/flood-protection/tcp.",
         api_endpoint="TCP", json_path="tcp.half_open_threshold",
         operator="is_true", expected_value="", handler_key=""),

    # 12. VPN IKE
    dict(vendor_slug="sonicwall", cid="12.1",
         title="VPN — Sem Algoritmos Fracos (DES/MD5)", category="VPN", severity="High",
         description="DES e MD5 são vulneráveis. Usar AES-256 e SHA-256.",
         recommendation="Remover propostas DES/MD5 do IKE Phase 1.",
         api_endpoint="...", json_path="", operator="handler", expected_value="",
         handler_key="sw_vpn_weak"),

    # 13. DPI-SSL
    dict(vendor_slug="sonicwall", cid="13.1",
         title="DPI-SSL Client", category="Encryption", severity="High",
         description="O DPI-SSL Client deve estar ativo para inspecionar tráfego TLS/HTTPS de saída.",
         recommendation="Habilitar enable no DPI-SSL Client.",
         api_endpoint="DPI SSL", json_path="dpi_ssl.client.enable",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="13.2",
         title="DPI-SSL — Inspeção IPS", category="Encryption", severity="High",
         description="IPS deve inspecionar tráfego decriptografado.",
         recommendation="Habilitar intrusion_prevention no DPI-SSL.",
         api_endpoint="DPI SSL", json_path="dpi_ssl.client.intrusion_prevention",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="13.3",
         title="DPI-SSL — Gateway Antivirus", category="Encryption", severity="High",
         description="Gateway AV deve analisar o conteúdo decriptografado.",
         recommendation="Habilitar gateway.anti_virus no DPI-SSL.",
         api_endpoint="DPI SSL", json_path="dpi_ssl.client.gateway.anti_virus",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="13.4",
         title="DPI-SSL — Anti-Spyware", category="Encryption", severity="Medium",
         description="Anti-Spyware deve analisar o tráfego decriptografado.",
         recommendation="Habilitar gateway.anti_spyware no DPI-SSL.",
         api_endpoint="DPI SSL", json_path="dpi_ssl.client.gateway.anti_spyware",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="13.5",
         title="DPI-SSL — Application Firewall", category="Encryption", severity="Medium",
         description="Application Firewall deve inspecionar o tráfego.",
         recommendation="Habilitar application_firewall no DPI-SSL.",
         api_endpoint="DPI SSL", json_path="dpi_ssl.client.application_firewall",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="13.6",
         title="DPI-SSL — Content Filter", category="Encryption", severity="Medium",
         description="Content Filter deve ser aplicado ao tráfego.",
         recommendation="Habilitar content_filter no DPI-SSL.",
         api_endpoint="DPI SSL", json_path="dpi_ssl.client.content_filter",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="13.7",
         title="DPI-SSL — Autenticação de Servidor", category="Encryption", severity="High",
         description="Garante que o DPI-SSL não aceite certificados inválidos silenciosamente.",
         recommendation="Habilitar authenticate_server no DPI-SSL.",
         api_endpoint="DPI SSL", json_path="dpi_ssl.client.authenticate_server",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="13.8",
         title="DPI-SSL — Não Abrir Conexões com Falha", category="Encryption", severity="Medium",
         description="Impede bypass silencioso caso falte recursos de DPI.",
         recommendation="Desabilitar open_failed_connections no DPI-SSL.",
         api_endpoint="DPI SSL", json_path="dpi_ssl.client.open_failed_connections",
         operator="is_false", expected_value="", handler_key=""),

     #14 passowrd complexity

     dict(vendor_slug="sonicwall", cid="14.1",
         title="Comprimento Mínimo de Senha ≥ 8", category="Access Control", severity="High",
         description="Senhas devem ter no mínimo 8 caracteres.",
         recommendation="Configurar comprimento mínimo de senha ≥ 8 caracteres.",
         api_endpoint="Administration", json_path="administration.password.minimum_length", operator="gte", expected_value="8",
         handler_key=""),

     dict(vendor_slug="sonicwall", cid="14.2",
         title="Lockout por Tentativas Falhas", category="Access Control", severity="High",
         description="Conta deve bloquear após tentativas falhas.",
         recommendation="Habilitar lockout por tentativas de login falhas.",
         api_endpoint="Administration", json_path="administration.user_lockout.enable", operator="is_true", expected_value="", handler_key=""),

    # 15. ADMINISTRATION — management interface security
    dict(vendor_slug="sonicwall", cid="15.1",
         title="Nome do Superusuário Administrador", category="Access Control", severity="Critical",
         description="O nome de usuário administrador padrão 'admin' deve ser alterado para um nome não óbvio, dificultando ataques de força bruta direcionados.",
         recommendation="Renomear o usuário administrador padrão para um nome personalizado e não previsível.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_admin_username"),

    dict(vendor_slug="sonicwall", cid="15.2",
         title="SSH de Gerenciamento", category="Access Control", severity="High",
         description="SSH na porta padrão 22 expõe o dispositivo a ataques de força bruta.",
         recommendation="Desabilitar SSH de gerenciamento ou alterar para porta não-padrão.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_admin_ssh"),

    dict(vendor_slug="sonicwall", cid="15.5",
         title="Timeout de Sessão Admin ≤ 10 min", category="System Hardening", severity="High",
         description="Sessões administrativas inativas devem expirar em até 10 minutos.",
         recommendation="Configurar idle timeout de gerenciamento ≤ 10 minutos.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_admin_idle"),

    dict(vendor_slug="sonicwall", cid="15.6",
         title="Restrição de Acesso ao Gerenciamento por IP", category="Access Control", severity="High",
         description="O acesso ao painel de gerenciamento deve ser restrito a endereços IP específicos.",
         recommendation="Configurar lista de IPs autorizados para acesso ao gerenciamento.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_admin_access_list"),

    dict(vendor_slug="sonicwall", cid="15.7",
         title="Proteção de Login Administrativo", category="Access Control", severity="Medium",
         description="Proteção adicional de login previne ataques automatizados de força bruta.",
         recommendation="Habilitar CAPTCHA ou autenticação de dois fatores (OTP) no login.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_admin_login_protection"),

    dict(vendor_slug="sonicwall", cid="15.8",
         title="Exposição de Informações na Página de Login", category="System Hardening", severity="Low",
         description="Exibir hostname e versão de firmware na página de login facilita reconhecimento.",
         recommendation="Desabilitar exibição de hostname e firmware na página de login.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_admin_login_info"),

    # 16. SENHA E COMPLEXIDADE — admin password policy (from administration/global)
    dict(vendor_slug="sonicwall", cid="16.1",
         title="Complexidade de Senha", category="Senha e Complexidade", severity="High",
         description="A política de complexidade deve exigir letras maiúsculas, minúsculas, números e símbolos.",
         recommendation="Habilitar enforce_complexity e ativar todos os requisitos de complexidade.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_pwd_complexity"),

    dict(vendor_slug="sonicwall", cid="16.2",
         title="Comprimento Mínimo de Senha Admin ≥ 8", category="Senha e Complexidade", severity="High",
         description="Senhas administrativas devem ter no mínimo 8 caracteres.",
         recommendation="Configurar comprimento mínimo de senha ≥ 8 caracteres.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_pwd_min_len"),

    dict(vendor_slug="sonicwall", cid="16.3",
         title="Expiração de Senha Admin", category="Senha e Complexidade", severity="Medium",
         description="Senhas devem expirar periodicamente para reduzir o risco de comprometimento.",
         recommendation="Habilitar expiração de senha e configurar máximo de 90 dias.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_pwd_expiry"),

    dict(vendor_slug="sonicwall", cid="16.4",
         title="Bloqueio de Conta", category="Senha e Complexidade", severity="High",
         description="Conta deve bloquear após tentativas de login falhas para prevenir força bruta.",
         recommendation="Habilitar lockout de conta após tentativas falhas de login.",
         api_endpoint="Administration", json_path="", operator="handler", expected_value="",
         handler_key="sw_admin_lockout"),

    # 17. PROTEÇÃO TCP
    dict(vendor_slug="sonicwall", cid="17.1",
         title="TCP Strict Compliance", category="Firewall Policy", severity="Medium",
         description="Strict compliance rejeita pacotes TCP que violam RFC 793.",
         recommendation="Habilitar enforce_strict_compliance na proteção TCP.",
         api_endpoint="TCP", json_path="tcp.enforce_strict_compliance",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="17.2",
         title="TCP Handshake Enforcement", category="Firewall Policy", severity="High",
         description="Handshake enforcement bloqueia conexões que não completam o three-way handshake.",
         recommendation="Habilitar handshake_enforcement na proteção TCP.",
         api_endpoint="TCP", json_path="tcp.handshake_enforcement",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="17.3",
         title="TCP Checksum Enforcement", category="Firewall Policy", severity="Medium",
         description="Checksum enforcement descarta pacotes TCP com checksum inválido.",
         recommendation="Habilitar checksum_enforcement na proteção TCP.",
         api_endpoint="TCP", json_path="tcp.checksum_enforcement",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="17.4",
         title="Drop de SYN com Dados", category="Firewall Policy", severity="High",
         description="Pacotes SYN com dados no payload são anômalos e frequentemente usados em ataques.",
         recommendation="Habilitar drop.syn_with_data na proteção TCP.",
         api_endpoint="TCP", json_path="tcp.drop.syn_with_data",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="17.5",
         title="Drop de Pacotes Urgent Inválidos", category="Firewall Policy", severity="Medium",
         description="Pacotes com flag URG inválido podem ser usados para evasão de IDS/IPS.",
         recommendation="Habilitar drop.invalid_urgent na proteção TCP.",
         api_endpoint="TCP", json_path="tcp.drop.invalid_urgent",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="17.6",
         title="TCP Handshake Timeout", category="Firewall Policy", severity="Medium",
         description="Timeout no handshake libera recursos de conexões incompletas (half-open).",
         recommendation="Habilitar enable_handshake_timeout na proteção TCP.",
         api_endpoint="TCP", json_path="tcp.enable_handshake_timeout",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="17.7",
         title="Modo de Proteção SYN Flood", category="Firewall Policy", severity="High",
         description="O modo 'watch-and-report' apenas registra ataques sem bloquear. Deve usar modo de bloqueio ativo.",
         recommendation="Alterar syn_flood_protection_mode para 'block-and-report' ou 'proxy-wan'.",
         api_endpoint="TCP", json_path="", operator="handler", expected_value="",
         handler_key="sw_tcp_syn_mode"),

    dict(vendor_slug="sonicwall", cid="17.8",
         title="SYN Flood Blacklisting", category="Firewall Policy", severity="High",
         description="Blacklisting bloqueia automaticamente IPs que excedem o threshold de SYN flood.",
         recommendation="Habilitar syn_flood_blacklisting na proteção TCP.",
         api_endpoint="TCP", json_path="tcp.syn_flood_blacklisting",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="17.9",
         title="Proteção DDoS em Interfaces WAN", category="Firewall Policy", severity="High",
         description="A proteção DDoS deve estar ativa nas interfaces WAN para mitigar ataques volumétricos.",
         recommendation="Habilitar ddos.on_wan_interfaces na proteção TCP.",
         api_endpoint="TCP", json_path="tcp.ddos.on_wan_interfaces",
         operator="is_true", expected_value="", handler_key=""),

    # 18. CAPTURE ATP
    dict(vendor_slug="sonicwall", cid="18.1",
         title="Capture ATP", category="Firewall Policy", severity="High",
         description="Capture ATP (sandbox em nuvem) analisa arquivos suspeitos antes de permitir a entrega.",
         recommendation="Habilitar Capture ATP para inspeção de arquivos em sandbox.",
         api_endpoint="capture_atp", json_path="capture_atp.enable",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="18.2",
         title="Capture ATP — Tipos de Arquivo Cobertos", category="Firewall Policy", severity="Medium",
         description="Capture ATP deve inspecionar todos os tipos de arquivo de alto risco: exe, pdf, office, officex e archives.",
         recommendation="Habilitar todos os tipos de arquivo (exe, pdf, office, officex, archives) no Capture ATP.",
         api_endpoint="capture_atp", json_path="", operator="handler", expected_value="",
         handler_key="sw_capture_atp_filetypes"),

    dict(vendor_slug="sonicwall", cid="18.3",
         title="Capture ATP — Política de Veredicto", category="Firewall Policy", severity="High",
         description="await_verdict 'allow' libera arquivos enquanto o sandbox analisa. 'block' segura o arquivo até o veredicto, evitando entrega de malware.",
         recommendation="Configurar await_verdict como 'block' no Capture ATP.",
         api_endpoint="capture_atp", json_path="capture_atp.await_verdict",
         operator="str_eq", expected_value="block", handler_key=""),

    # 19. FIREWALL BASE
    dict(vendor_slug="sonicwall", cid="19.1",
         title="Stealth Mode", category="Network Security", severity="Medium",
         description="Stealth mode oculta o firewall de varreduras de rede, não respondendo a probes não solicitados.",
         recommendation="Habilitar stealth_mode nas configurações base do firewall.",
         api_endpoint="fw_base", json_path="firewall.stealth_mode",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="19.2",
         title="IP ID Randomization", category="Network Security", severity="Low",
         description="Randomizar o IP ID impede fingerprinting do sistema operacional por análise de sequência de IDs.",
         recommendation="Habilitar randomize_id nas configurações base do firewall.",
         api_endpoint="fw_base", json_path="firewall.randomize_id",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="19.3",
         title="Drop de Pacotes Source Routed", category="Network Security", severity="High",
         description="Pacotes com roteamento de origem permitem ao atacante manipular o caminho do tráfego, contornando controles de segurança.",
         recommendation="Habilitar drop.source_routed nas configurações base do firewall.",
         api_endpoint="fw_base", json_path="firewall.drop.source_routed",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="19.4",
         title="Drop de Source Subnet Broadcast", category="Network Security", severity="Medium",
         description="Broadcasts direcionados podem ser usados em ataques de amplificação (ex.: Smurf). Descartar previne este vetor.",
         recommendation="Habilitar drop.source_subnet_broadcast nas configurações base do firewall.",
         api_endpoint="fw_base", json_path="firewall.drop.source_subnet_broadcast",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="19.5",
         title="IP Checksum Enforcement", category="Firewall Policy", severity="Medium",
         description="Descartar pacotes IP com checksum inválido previne evasão de inspeção via pacotes malformados.",
         recommendation="Habilitar ip.checksum_enforcement nas configurações base do firewall.",
         api_endpoint="fw_base", json_path="firewall.ip.checksum_enforcement",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="19.6",
         title="Control Plane Flood Protection", category="Firewall Policy", severity="High",
         description="Protege o plano de controle do firewall contra floods que podem esgotar recursos e causar instabilidade.",
         recommendation="Habilitar control_plane_flood_protection nas configurações base do firewall.",
         api_endpoint="fw_base", json_path="firewall.control_plane_flood_protection",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="19.7",
         title="IPv6 — Routing Header Type 0", category="Network Security", severity="High",
         description="IPv6 Routing Header Type 0 (RH0) foi descontinuado (RFC 5095) por permitir ataques de DoS e amplificação.",
         recommendation="Habilitar ipv6.drop.routing_header_0 nas configurações base do firewall.",
         api_endpoint="fw_base", json_path="firewall.ipv6.drop.routing_header_0",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="sonicwall", cid="19.8",
         title="IPv6 — Extension Header Check", category="Network Security", severity="Medium",
         description="Verificação de extension headers IPv6 detecta e descarta cabeçalhos malformados usados para evasão.",
         recommendation="Habilitar ipv6.extension_header_check nas configurações base do firewall.",
         api_endpoint="fw_base", json_path="firewall.ipv6.extension_header_check",
         operator="is_true", expected_value="", handler_key=""),

    # 20. WAN INTERFACE SECURITY
    dict(vendor_slug="sonicwall", cid="20.1",
         title="HTTP de Gerenciamento em Interface WAN", category="Access Control", severity="Critical",
         description="Expor HTTP de gerenciamento em interfaces WAN permite ataque man-in-the-middle e acesso não autenticado.",
         recommendation="Desabilitar management.http em todas as interfaces com zone=WAN.",
         api_endpoint="interfaces_ipv4", json_path="", operator="handler", expected_value="",
         handler_key="sw_wan_http"),

    dict(vendor_slug="sonicwall", cid="20.2",
         title="HTTPS de Gerenciamento em Interface WAN", category="Access Control", severity="High",
         description="Acesso HTTPS de gerenciamento direto pela WAN expõe o painel administrativo à internet.",
         recommendation="Desabilitar management.https em interfaces WAN ou restringir via ACL de gerenciamento.",
         api_endpoint="interfaces_ipv4", json_path="", operator="handler", expected_value="",
         handler_key="sw_wan_https"),

    dict(vendor_slug="sonicwall", cid="20.3",
         title="SSH em Interfaces WAN", category="Access Control", severity="High",
         description="SSH de gerenciamento exposto na WAN é alvo constante de ataques de força bruta.",
         recommendation="Desabilitar management.ssh em todas as interfaces com zone=WAN.",
         api_endpoint="interfaces_ipv4", json_path="", operator="handler", expected_value="",
         handler_key="sw_wan_ssh"),

    dict(vendor_slug="sonicwall", cid="20.4",
         title="SNMP em Interfaces WAN", category="Network Security", severity="High",
         description="SNMP exposto na WAN permite enumeração de informações do dispositivo por qualquer host externo.",
         recommendation="Desabilitar management.snmp em todas as interfaces com zone=WAN.",
         api_endpoint="interfaces_ipv4", json_path="", operator="handler", expected_value="",
         handler_key="sw_wan_snmp"),

    dict(vendor_slug="sonicwall", cid="20.5",
         title="Ping em Interfaces WAN", category="Network Security", severity="Medium",
         description="Responder a pings na WAN confirma a existência do dispositivo para atacantes (reduz stealth).",
         recommendation="Desabilitar management.ping em todas as interfaces com zone=WAN.",
         api_endpoint="interfaces_ipv4", json_path="", operator="handler", expected_value="",
         handler_key="sw_wan_ping"),

    dict(vendor_slug="sonicwall", cid="20.6",
         title="Login de Usuário HTTP em Interface WAN", category="Access Control", severity="Critical",
         description="Login de usuário via HTTP na WAN transmite credenciais em texto claro pela internet.",
         recommendation="Desabilitar user_login.http em todas as interfaces com zone=WAN.",
         api_endpoint="interfaces_ipv4", json_path="", operator="handler", expected_value="",
         handler_key="sw_wan_user_http"),

    dict(vendor_slug="sonicwall", cid="20.7",
         title="Login de Usuário HTTPS em Interface WAN", category="Access Control", severity="High",
         description="Portal de login de usuário exposto diretamente na WAN amplia a superfície de ataque.",
         recommendation="Desabilitar user_login.https em interfaces WAN ou restringir por ACL.",
         api_endpoint="interfaces_ipv4", json_path="", operator="handler", expected_value="",
         handler_key="sw_wan_user_https"),

    # FWR. ACCESS RULES AUDIT (complex handler)
    dict(vendor_slug="sonicwall", cid="FWR-0",
         title="Regras ALLOW — Auditoria Geral", category="Firewall Policy", severity="Low",
         description="Todas as regras ALLOW são inspecionadas.",
         recommendation="Revise periodicamente todas as regras ALLOW.",
         api_endpoint="access_rules", json_path="", operator="handler", expected_value="",
         handler_key="sw_access_rules"),
]

# ─────────────────────────────────────────────────────────────
# FORTIGATE
# ─────────────────────────────────────────────────────────────
FORTIGATE_CANONICAL = [
    dict(vendor_slug="fortigate", cid="1.1",
         title="Firmware FortiOS Identificado", category="System Hardening", severity="High",
         description="Versão do firmware deve ser identificada.",
         recommendation="Verificar e atualizar o firmware FortiOS.",
         api_endpoint="status", json_path="", operator="handler", expected_value="",
         handler_key="fg_firmware"),

    dict(vendor_slug="fortigate", cid="1.2",
         title="Hostname Personalizado", category="System Hardening", severity="Low",
         description="Hostname padrão identifica o fabricante.",
         recommendation="Alterar o hostname padrão.",
         api_endpoint="global", json_path="", operator="handler", expected_value="",
         handler_key="fg_hostname"),

    dict(vendor_slug="fortigate", cid="1.3",
         title="Timeout Admin ≤ 15 min", category="System Hardening", severity="High",
         description="Sessões admin devem expirar em até 15 minutos.",
         recommendation="Configurar idle timeout ≤ 15 minutos.",
         api_endpoint="global", json_path="admintimeout",
         operator="lte", expected_value="15", handler_key=""),

    dict(vendor_slug="fortigate", cid="1.4",
         title="HTTP de Gerenciamento Desabilitado", category="Access Control", severity="Critical",
         description="HTTP expõe credenciais em texto claro.",
         recommendation="Remover HTTP do allowaccess em todas as interfaces.",
         api_endpoint="interfaces", json_path="", operator="handler", expected_value="",
         handler_key="fg_http_ifaces"),

    dict(vendor_slug="fortigate", cid="1.5",
         title="Telnet Desabilitado", category="Access Control", severity="Critical",
         description="Telnet transmite dados sem criptografia.",
         recommendation="Remover Telnet do allowaccess em todas as interfaces.",
         api_endpoint="interfaces", json_path="", operator="handler", expected_value="",
         handler_key="fg_telnet_ifaces"),

    dict(vendor_slug="fortigate", cid="1.6",
         title="Autenticação de Dois Fatores para Admins", category="Access Control", severity="High",
         description="Contas admin devem exigir autenticação 2FA (FortiToken, Email ou SMS).",
         recommendation="Habilitar Two-Factor Authentication em todas as contas admin.",
         api_endpoint="admin", json_path="", operator="handler", expected_value="",
         handler_key="fg_admin_2fa"),

    dict(vendor_slug="fortigate", cid="1.7",
         title="Trusted Hosts Configurados para Admins", category="Access Control", severity="High",
         description="Contas admin devem ter trusted hosts definidos para restringir acesso por IP.",
         recommendation="Definir trusted hosts para cada conta admin.",
         api_endpoint="admin", json_path="", operator="handler", expected_value="",
         handler_key="fg_admin_trusted"),

    dict(vendor_slug="fortigate", cid="2.1",
         title="Comunidade SNMP 'public' Removida", category="Network Security", severity="Critical",
         description="Comunidade padrão 'public' é amplamente conhecida.",
         recommendation="Remover a comunidade SNMP 'public'.",
         api_endpoint="snmp", json_path="", operator="handler", expected_value="",
         handler_key="fg_snmp_public"),

    dict(vendor_slug="fortigate", cid="2.2",
         title="SNMPv3 Configurado", category="Network Security", severity="High",
         description="SNMPv3 oferece autenticação e criptografia.",
         recommendation="Criar usuários SNMPv3.",
         api_endpoint="snmpv3", json_path="", operator="list_not_empty", expected_value="",
         handler_key=""),

    dict(vendor_slug="fortigate", cid="2.3",
         title="NTP Sincronização Habilitada", category="System Hardening", severity="Medium",
         description="NTP garante timestamps corretos nos logs.",
         recommendation="Habilitar sincronização NTP.",
         api_endpoint="ntp", json_path="", operator="handler", expected_value="",
         handler_key="fg_ntp"),

    dict(vendor_slug="fortigate", cid="3.1",
         title="Syslog Remoto Configurado", category="Logging & Monitoring", severity="High",
         description="Logs devem ser enviados para servidor remoto.",
         recommendation="Configurar servidor syslog remoto.",
         api_endpoint="logging", json_path="status",
         operator="str_eq", expected_value="enable", handler_key=""),

    dict(vendor_slug="fortigate", cid="3.2",
         title="Política de Senha Habilitada", category="Access Control", severity="High",
         description="Política de senha deve estar ativa.",
         recommendation="Habilitar política de senhas.",
         api_endpoint="pwd_policy", json_path="status",
         operator="str_eq", expected_value="enable", handler_key=""),

    dict(vendor_slug="fortigate", cid="3.3",
         title="Comprimento Mínimo de Senha ≥ 8", category="Access Control", severity="High",
         description="Senhas devem ter no mínimo 8 caracteres.",
         recommendation="Configurar comprimento mínimo de senha ≥ 8 caracteres.",
         api_endpoint="pwd_policy", json_path="minimum-length",
         operator="gte", expected_value="8", handler_key=""),

    dict(vendor_slug="fortigate", cid="3.4",
         title="FortiAnalyzer Configurado", category="Logging & Monitoring", severity="High",
         description="Logs devem ser enviados ao FortiAnalyzer para correlação e retenção centralizada.",
         recommendation="Habilitar e configurar FortiAnalyzer.",
         api_endpoint="fortianalyzer", json_path="", operator="handler", expected_value="",
         handler_key="fg_fortianalyzer"),

    dict(vendor_slug="fortigate", cid="4.1",
         title="Perfil Antivirus Configurado", category="Firewall Policy", severity="High",
         description="Pelo menos um perfil AV deve estar configurado.",
         recommendation="Criar pelo menos um perfil Antivirus.",
         api_endpoint="av_profile", json_path="", operator="list_not_empty", expected_value="",
         handler_key=""),

    dict(vendor_slug="fortigate", cid="4.2",
         title="Sensor IPS Configurado", category="Firewall Policy", severity="High",
         description="Pelo menos um sensor IPS deve estar configurado.",
         recommendation="Criar pelo menos um sensor IPS.",
         api_endpoint="ips_sensor", json_path="", operator="list_not_empty", expected_value="",
         handler_key=""),

    dict(vendor_slug="fortigate", cid="4.3",
         title="Perfil Web Filter Configurado", category="Firewall Policy", severity="High",
         description="Pelo menos um perfil Web Filter deve estar configurado.",
         recommendation="Criar pelo menos um perfil Web Filter.",
         api_endpoint="web_filter", json_path="", operator="list_not_empty", expected_value="",
         handler_key=""),

    dict(vendor_slug="fortigate", cid="4.4",
         title="Perfil Application Control Configurado", category="Firewall Policy", severity="High",
         description="Pelo menos um perfil Application Control deve estar configurado.",
         recommendation="Criar pelo menos um perfil Application Control.",
         api_endpoint="app_ctrl", json_path="", operator="list_not_empty", expected_value="",
         handler_key=""),

    dict(vendor_slug="fortigate", cid="4.5",
         title="Perfil DNS Filter Configurado", category="Network Security", severity="Medium",
         description="Pelo menos um perfil DNS Filter deve estar configurado.",
         recommendation="Criar pelo menos um perfil DNS Filter.",
         api_endpoint="dns_filter", json_path="", operator="list_not_empty", expected_value="",
         handler_key=""),

    dict(vendor_slug="fortigate", cid="4.6",
         title="Perfil Email Filter Configurado", category="Firewall Policy", severity="Medium",
         description="Pelo menos um perfil Email Filter deve estar configurado para inspecionar SMTP/IMAP.",
         recommendation="Criar pelo menos um perfil Email Filter.",
         api_endpoint="email_filter", json_path="", operator="list_not_empty", expected_value="",
         handler_key=""),

    dict(vendor_slug="fortigate", cid="5.1",
         title="Políticas ACCEPT com Perfil AV", category="Firewall Policy", severity="High",
         description="Políticas de aceite devem aplicar perfil AV.",
         recommendation="Aplicar perfil Antivirus em todas as políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_av"),

    dict(vendor_slug="fortigate", cid="5.2",
         title="Políticas ACCEPT com Sensor IPS", category="Firewall Policy", severity="High",
         description="Políticas de aceite devem aplicar sensor IPS.",
         recommendation="Aplicar sensor IPS em todas as políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_ips"),

    dict(vendor_slug="fortigate", cid="5.3",
         title="Políticas ACCEPT com Logging", category="Logging & Monitoring", severity="Medium",
         description="Políticas de aceite devem gerar logs.",
         recommendation="Habilitar Log Traffic em todas as políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_log"),

    dict(vendor_slug="fortigate", cid="5.4",
         title="Políticas ACCEPT com SSL Inspection", category="Firewall Policy", severity="High",
         description="Políticas de aceite devem aplicar perfil de inspeção SSL/SSH.",
         recommendation="Aplicar perfil SSL Inspection em todas as políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_ssl"),

    dict(vendor_slug="fortigate", cid="5.5",
         title="Políticas ACCEPT com Web Filter", category="Firewall Policy", severity="High",
         description="Políticas de aceite devem aplicar perfil Web Filter.",
         recommendation="Aplicar Web Filter em todas as políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_webfilter"),

    dict(vendor_slug="fortigate", cid="5.6",
         title="Políticas ACCEPT com Application Control", category="Firewall Policy", severity="High",
         description="Políticas de aceite devem aplicar Application Control para visibilidade de apps.",
         recommendation="Aplicar Application Control em todas as políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_appctrl"),

    dict(vendor_slug="fortigate", cid="5.7",
         title="Políticas ACCEPT com DNS Filter", category="Network Security", severity="Medium",
         description="Políticas de aceite devem aplicar DNS Filter para bloquear domínios maliciosos.",
         recommendation="Aplicar DNS Filter em todas as políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_dnsfilter"),

    dict(vendor_slug="fortigate", cid="6.1",
         title="VPN — Sem Algoritmos Fracos", category="VPN", severity="High",
         description="DES e MD5 são vulneráveis em VPN.",
         recommendation="Remover propostas DES/MD5 do IPsec Phase 1.",
         api_endpoint="vpn_phase1", json_path="", operator="handler", expected_value="",
         handler_key="fg_vpn_weak"),

    dict(vendor_slug="fortigate", cid="6.2",
         title="VPN Phase2 — Sem Algoritmos Fracos", category="VPN", severity="High",
         description="Phase2 não deve usar DES, MD5 ou NULL como algoritmos de criptografia.",
         recommendation="Remover propostas fracas do IPsec Phase 2.",
         api_endpoint="vpn_phase2", json_path="", operator="handler", expected_value="",
         handler_key="fg_vpn_phase2_weak"),

    dict(vendor_slug="fortigate", cid="6.3",
         title="SSL-VPN com Certificado Personalizado", category="VPN", severity="High",
         description="SSL-VPN deve usar certificado de CA válida, não o certificado padrão Fortinet.",
         recommendation="Substituir o certificado padrão Fortinet_Factory por um certificado válido.",
         api_endpoint="sslvpn", json_path="", operator="handler", expected_value="",
         handler_key="fg_sslvpn_cert"),

    dict(vendor_slug="fortigate", cid="7.1",
         title="Sem Políticas ACCEPT para Destino 'all'", category="Firewall Policy", severity="Critical",
         description="Políticas com destino 'all' permitem acesso irrestrito.",
         recommendation="Restringir os destinos nas políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_all_dst"),

    dict(vendor_slug="fortigate", cid="7.2",
         title="Sem Políticas ACCEPT com Origem 'all'", category="Firewall Policy", severity="Critical",
         description="Políticas com origem 'all' permitem que qualquer host inicie conexões.",
         recommendation="Restringir os endereços de origem nas políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_pol_all_src"),

    # FWR-0: Auditoria de Políticas ACCEPT
    dict(vendor_slug="fortigate", cid="FWR-0",
         title="Políticas ACCEPT — Auditoria Geral", category="Firewall Policy", severity="Low",
         description="Todas as políticas ACCEPT são inspecionadas para configurações inseguras.",
         recommendation="Revise periodicamente todas as políticas ACCEPT.",
         api_endpoint="firewall_pol", json_path="", operator="handler", expected_value="",
         handler_key="fg_access_rules"),
]

# ─────────────────────────────────────────────────────────────
# PFSENSE
# ─────────────────────────────────────────────────────────────
PFSENSE_CANONICAL = [
    dict(vendor_slug="pfsense", cid="1.1",
         title="Versão pfSense Identificada", category="System Hardening", severity="High",
         description="Versão deve ser identificada e mantida atualizada.",
         recommendation="Verificar e atualizar a versão do pfSense.",
         api_endpoint="version", json_path="", operator="handler", expected_value="",
         handler_key="pf_version"),

    dict(vendor_slug="pfsense", cid="1.2",
         title="Hostname Personalizado", category="System Hardening", severity="Low",
         description="Hostname padrão identifica o fabricante.",
         recommendation="Alterar o hostname padrão.",
         api_endpoint="hostname", json_path="", operator="handler", expected_value="",
         handler_key="pf_hostname"),

    dict(vendor_slug="pfsense", cid="1.3",
         title="WebGUI via HTTPS", category="Access Control", severity="Critical",
         description="Interface web deve usar HTTPS.",
         recommendation="Configurar a WebGUI para usar HTTPS.",
         api_endpoint="webgui", json_path="protocol",
         operator="str_eq", expected_value="https", handler_key=""),

    dict(vendor_slug="pfsense", cid="1.4",
         title="SSH Desabilitado (ou restrito)", category="Access Control", severity="High",
         description="SSH deve estar desabilitado ou restrito a IPs específicos.",
         recommendation="Desabilitar ou restringir SSH a IPs específicos.",
         api_endpoint="ssh", json_path="", operator="handler", expected_value="",
         handler_key="pf_ssh"),

    dict(vendor_slug="pfsense", cid="1.5",
         title="Timeout de Sessão Configurado", category="System Hardening", severity="High",
         description="Sessões devem expirar por inatividade.",
         recommendation="Configurar timeout de sessão por inatividade.",
         api_endpoint="config", json_path="", operator="handler", expected_value="",
         handler_key="pf_timeout"),

    dict(vendor_slug="pfsense", cid="1.6",
         title="WebGUI em Porta Não Padrão", category="Access Control", severity="Medium",
         description="Mover a WebGUI para uma porta não padrão reduz exposição a scanners automatizados.",
         recommendation="Alterar a porta da WebGUI para uma porta não padrão.",
         api_endpoint="webgui", json_path="", operator="handler", expected_value="",
         handler_key="pf_webgui_port"),

    dict(vendor_slug="pfsense", cid="2.1",
         title="Usuário Admin com Senha Alterada", category="Access Control", severity="Critical",
         description="A senha padrão do admin deve ser alterada.",
         recommendation="Alterar a senha padrão do usuário admin.",
         api_endpoint="users", json_path="", operator="handler", expected_value="",
         handler_key="pf_admin_user"),

    dict(vendor_slug="pfsense", cid="2.2",
         title="SNMP Desabilitado", category="Network Security", severity="High",
         description="SNMP deve estar desabilitado ou usar SNMPv3.",
         recommendation="Desabilitar SNMP se não necessário.",
         api_endpoint="snmp", json_path="enable",
         operator="is_false", expected_value="", handler_key=""),

    dict(vendor_slug="pfsense", cid="2.3",
         title="Comunidade SNMP 'public' Removida", category="Network Security", severity="Critical",
         description="Comunidade padrão 'public' deve ser alterada.",
         recommendation="Alterar ou remover a community string 'public'.",
         api_endpoint="snmp", json_path="", operator="handler", expected_value="",
         handler_key="pf_snmp_community"),

    dict(vendor_slug="pfsense", cid="2.4",
         title="NTP Configurado", category="System Hardening", severity="Medium",
         description="NTP garante timestamps corretos nos logs.",
         recommendation="Habilitar e configurar servidores NTP.",
         api_endpoint="ntp", json_path="", operator="handler", expected_value="",
         handler_key="pf_ntp"),

    dict(vendor_slug="pfsense", cid="2.5",
         title="WAN — Bloquear Redes Privadas", category="Network Security", severity="High",
         description="Interfaces WAN devem bloquear endereços RFC1918 para evitar spoofing.",
         recommendation="Habilitar bloqueio de redes privadas na interface WAN.",
         api_endpoint="interfaces", json_path="", operator="handler", expected_value="",
         handler_key="pf_block_private"),

    dict(vendor_slug="pfsense", cid="2.6",
         title="WAN — Bloquear Redes Bogon", category="Network Security", severity="High",
         description="Interfaces WAN devem bloquear endereços bogon (IPs não roteáveis publicamente).",
         recommendation="Habilitar bloqueio de redes bogon na interface WAN.",
         api_endpoint="interfaces", json_path="", operator="handler", expected_value="",
         handler_key="pf_block_bogon"),

    dict(vendor_slug="pfsense", cid="3.1",
         title="Syslog Remoto Configurado", category="Logging & Monitoring", severity="High",
         description="Logs devem ir para servidor remoto.",
         recommendation="Configurar remote logging para servidor syslog.",
         api_endpoint="syslog", json_path="", operator="handler", expected_value="",
         handler_key="pf_syslog"),

    dict(vendor_slug="pfsense", cid="3.2",
         title="Log de Tráfego Bloqueado Habilitado", category="Logging & Monitoring", severity="Medium",
         description="O log do filtro de firewall deve estar habilitado para registrar pacotes bloqueados.",
         recommendation="Habilitar log de tráfego bloqueado.",
         api_endpoint="syslog", json_path="", operator="handler", expected_value="",
         handler_key="pf_log_blocks"),

    dict(vendor_slug="pfsense", cid="4.1",
         title="Sem Regras PASS ANY→ANY", category="Firewall Policy", severity="Critical",
         description="Regras PASS com origem e destino ANY são irrestritamente permissivas.",
         recommendation="Restringir origem e destino nas regras PASS.",
         api_endpoint="firewall_rules", json_path="", operator="handler", expected_value="",
         handler_key="pf_any_any"),

    dict(vendor_slug="pfsense", cid="4.2",
         title="Regras PASS com Logging", category="Logging & Monitoring", severity="Medium",
         description="Regras PASS devem gerar logs para auditoria.",
         recommendation="Habilitar log em todas as regras PASS.",
         api_endpoint="firewall_rules", json_path="", operator="handler", expected_value="",
         handler_key="pf_fw_log"),

    dict(vendor_slug="pfsense", cid="4.3",
         title="NAT sem Serviços Críticos Expostos", category="Firewall Policy", severity="High",
         description="Port forwards para serviços como SSH, RDP e bancos de dados são arriscados.",
         recommendation="Remover port forwards desnecessários para serviços críticos.",
         api_endpoint="nat", json_path="", operator="handler", expected_value="",
         handler_key="pf_nat_risky"),

    dict(vendor_slug="pfsense", cid="4.4",
         title="Regras de Firewall Usam Aliases", category="Firewall Policy", severity="Low",
         description="Regras devem referenciar aliases em vez de IPs diretos para facilitar manutenção.",
         recommendation="Criar aliases para IPs e redes utilizados nas regras de firewall.",
         api_endpoint="firewall_aliases", json_path="", operator="handler", expected_value="",
         handler_key="pf_use_aliases"),

    dict(vendor_slug="pfsense", cid="5.1",
         title="DNSSEC Habilitado (Unbound)", category="Network Security", severity="Medium",
         description="DNSSEC valida respostas DNS contra manipulação.",
         recommendation="Habilitar DNSSEC no DNS Resolver (Unbound).",
         api_endpoint="unbound", json_path="dnssec",
         operator="is_true", expected_value="", handler_key=""),

    dict(vendor_slug="pfsense", cid="5.2",
         title="Certificado SSL Personalizado", category="Encryption", severity="Medium",
         description="Certificado auto-assinado padrão deve ser substituído por CA válida.",
         recommendation="Importar certificado de uma CA confiável.",
         api_endpoint="cert", json_path="", operator="handler", expected_value="",
         handler_key="pf_cert"),

    dict(vendor_slug="pfsense", cid="5.3",
         title="DNS Resolver (Unbound) Habilitado", category="Network Security", severity="Medium",
         description="O resolver DNS local (Unbound) deve estar habilitado para controle de DNS.",
         recommendation="Habilitar DNS Resolver (Unbound).",
         api_endpoint="unbound", json_path="", operator="handler", expected_value="",
         handler_key="pf_unbound_enabled"),

    dict(vendor_slug="pfsense", cid="6.1",
         title="OpenVPN com TLS Authentication", category="VPN", severity="High",
         description="Servidores OpenVPN devem usar TLS Auth para proteção adicional contra ataques.",
         recommendation="Habilitar TLS Authentication nos servidores OpenVPN.",
         api_endpoint="openvpn", json_path="", operator="handler", expected_value="",
         handler_key="pf_vpn_tls"),

    dict(vendor_slug="pfsense", cid="6.2",
         title="OpenVPN sem Cifras Fracas", category="VPN", severity="High",
         description="Servidores OpenVPN não devem usar DES, RC4, RC2 ou cifras NULL.",
         recommendation="Usar AES-256 no canal de dados OpenVPN.",
         api_endpoint="openvpn", json_path="", operator="handler", expected_value="",
         handler_key="pf_vpn_cipher"),

    dict(vendor_slug="pfsense", cid="6.3",
         title="IPsec Phase1 sem Algoritmos Fracos", category="VPN", severity="High",
         description="IPsec Phase1 não deve usar DES, RC4 ou hash MD5.",
         recommendation="Usar AES-256 e SHA-256 no IPsec Phase 1.",
         api_endpoint="ipsec_p1", json_path="", operator="handler", expected_value="",
         handler_key="pf_ipsec_weak"),

    dict(vendor_slug="pfsense", cid="7.1",
         title="Pacotes Instalados Atualizados", category="System Hardening", severity="Medium",
         description="Todos os pacotes instalados devem estar na versão mais recente.",
         recommendation="Verificar e atualizar todos os pacotes instalados.",
         api_endpoint="packages", json_path="", operator="handler", expected_value="",
         handler_key="pf_pkg_update"),

    # FWR-0: Auditoria de Regras PASS
    dict(vendor_slug="pfsense", cid="FWR-0",
         title="Regras PASS — Auditoria Geral", category="Firewall Policy", severity="Low",
         description="Todas as regras PASS são inspecionadas para configurações inseguras.",
         recommendation="Revise periodicamente todas as regras PASS.",
         api_endpoint="firewall_rules", json_path="", operator="handler", expected_value="",
         handler_key="pf_access_rules"),
]

# ─────────────────────────────────────────────────────────────
# ALL_CANONICAL — flat list
# ─────────────────────────────────────────────────────────────
ALL_CANONICAL = SONICWALL_CANONICAL + FORTIGATE_CANONICAL + PFSENSE_CANONICAL

CANONICAL_BY_VENDOR = {
    "sonicwall": {c["cid"]: c for c in SONICWALL_CANONICAL},
    "fortigate":  {c["cid"]: c for c in FORTIGATE_CANONICAL},
    "pfsense":    {c["cid"]: c for c in PFSENSE_CANONICAL},
}


def seed_api_checks():
    """
    Populates the api_checks table ONLY with new rules.
    If a rule (vendor_slug + cid) already exists in the database, it is IGNORED.
    This makes the SQLite Database the single Source of Truth.
    """
    from database import get_db
    with get_db() as conn:
        for chk in ALL_CANONICAL:
            # O comando INSERT OR IGNORE garante que, se a regra já existir no banco,
            # o Python simplesmente pula para a próxima e não altera os seus dados.
            conn.execute("""INSERT OR IGNORE INTO api_checks
                (vendor_slug,cid,title,category,severity,description,recommendation,
                 api_endpoint,json_path,operator,expected_value,handler_key,active)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (chk["vendor_slug"], chk["cid"], chk["title"], chk["category"],
                 chk["severity"], chk["description"], chk["recommendation"],
                 chk.get("api_endpoint",""), chk.get("json_path",""),
                 chk.get("operator","handler"), chk.get("expected_value",""),
                 chk.get("handler_key","")))
            
        conn.commit()


def compare_with_canonical(vendor_slug: str) -> dict:
    """
    Compare DB api_checks vs canonical reference.
    Returns dict with lists: added (in DB not canonical), removed (in canonical not DB),
    modified (same cid but title/severity/description differs), matched (identical).
    """
    from database import get_db
    canonical = CANONICAL_BY_VENDOR.get(vendor_slug, {})
    with get_db() as conn:
        db_rows = {r["cid"]: dict(r) for r in conn.execute(
            "SELECT * FROM api_checks WHERE vendor_slug=?", (vendor_slug,)).fetchall()}

    COMPARE_FIELDS = ["title", "category", "severity", "description",
                      "recommendation", "operator", "expected_value", "handler_key"]

    added    = []   # in DB, not in canonical
    removed  = []   # in canonical, not in DB
    modified = []   # in both but fields differ
    matched  = []   # identical

    for cid, canon in canonical.items():
        if cid not in db_rows:
            removed.append(canon)
        else:
            db = db_rows[cid]
            diffs = {f: (canon.get(f), db.get(f)) for f in COMPARE_FIELDS
                     if str(canon.get(f,"")) != str(db.get(f,""))}
            if diffs:
                modified.append({"cid": cid, "diffs": diffs})
            else:
                matched.append(cid)

    for cid, row in db_rows.items():
        if cid not in canonical:
            added.append(row)

    return {"added": added, "removed": removed, "modified": modified, "matched": matched}
