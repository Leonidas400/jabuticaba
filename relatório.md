Tem no arquivo de comparação do fortigate, mas não tem na CIS:


# 1.6 Console output bandwidth
# 2.6 Password expiry
# 4.1 SSLv3 disabled
# 5.1 Deny-all policy
# 5.2 Any-any policy
# 6.1 SSL-VPN split tunneling
# 6.2 SSL-VPN idle timeout
# 6.3 IPSec strong encryption
# 6.4 IKEv2
# 7.3 Forward traffic log
# 7.4 Local traffic log
# 8.2 Config backup


Tem na CIs fortigate, mas não tem no arquivo de comparação:

2.1.2 Ensure 'Post-Login-Banner' is set (Automated)
2.1.3 Ensure timezone is properly configured (Manual)
2.1.8 Disable static keys for TLS (Automated)
2.1.11 Ensure CDN is enabled for improved GUI performance
(Manual)
2.1.12 Ensure single CPU core overloaded event is logged
(Manual)
2.1.13 Ensure Hostname is Not Displayed On Login GUI (Manual)


2.2.2 Ensure administrator password retries and lockout time are
configured (Automated)

2.3.2 Allow only trusted hosts in SNMPv3 (Manual)
2.3.3 Disable SNMPv3 Query Per User (Manual)
2.3.4 Enabling SNMP trap for memory usage (Manual)

2.4.1 Remove default admin user and create one with other name
(Manual)
2.4.3 Ensure admin accounts with different privileges have their
correct profiles assigned (Manual)
2.4.4 Ensure Admin idle timeout time is configured (Automated)
2.4.5 Ensure only encrypted access channels are enabled
(Manual)
2.4.6 Apply Local-in Policies (Manual)
2.4.7 Ensure default Admin ports are changed (Manual)
2.4.8 Virtual patching on the local-in management interface
(Manual)


2.5.1 Remove default admin user and create one with other name
(Manual)
2.5.2 Ensure all the login accounts having specific trusted hosts
enabled (Manual)
2.5.3 Ensure admin accounts with different privileges have their
correct profiles assigned (Manual)
2.5.4 Ensure Admin idle timeout time is configured (Automated)
2.5.6 Apply Local-in Policies (Manual)
2.5.7 Ensure default Admin ports are changed (Manual)
2.5.8 Virtual patching on the local-in management interface
(Manual)

2.6.2 Ensure "Monitor Interfaces" for High Availability devices is
enabled (Automated)
2.6.3 Ensure HA Reserved Management Interface is configured
(Manual)
2.6.4 Ensure High Availability Group-ID is configured (Manual)

3.1 Ensure that unused policies are reviewed regularly (Manual)
3.2 Ensure that policies do not use "ALL" as Service (Automated)

4.1.1 Detect Botnet connections (Manual)
4.2.3 Enable Outbreak Prevention Database (Manual)
4.2.4 Enable AI /heuristic based malware detection (Automated)
4.2.5 Enable grayware detection on antivirus (Automated)
4.2.6 Ensure inline scanning with FortiGuard AI-Based Sandbox
Service is enabled (Manual)
4.2.7 Enable CDR for proxy mode on XLSB, OpenOffice, and
RTF files (Manual)
4.3.1 Enable Botnet C&C Domain Blocking DNS Filter (Manual)
4.3.2 Ensure DNS Filter logs all DNS queries and responses
(Manual)
4.3.3 Apply DNS Filter Security Profile to Policies (Manual)
4.4.1 Create a Web Filtering Profile (Manual)
4.5.1 Block high risk categories on Application Control (Manual)
4.5.2 Block applications running on non-default ports (Manual)
4.5.3 Ensure all Application Control related traffic is logged
(Manual)

5.1.1 Enable Compromised Host Quarantine (Manual)
5.2.1.1 Ensure Security Fabric is Configured (Manual)

6.1.1 Apply a Trusted Signed Certificate for VPN Portal (Manual)
6.1.2 Enable Limited TLS Versions for SSL VPN (Manual)


Tem no arquivo de comparação do pfSense, mas não tem na CIS:

# 1.2 Domain
# 1.3 Timezone
# 1.6 SSH disabled or restricted
# 1.8 WebGUI port non-default
# 2.2 Default admin user renamed
# 2.3 Multiple users (not single admin)
# 3.1 Bogon networks blocked
# 3.2 Private networks blocked on WAN
# 3.3 SNMP community string
# 3.5 ARP spoofing / static ARP
# 4.1 Has firewall rules
# 4.3 Anti-lockout rule
# 4.5 Scrub / traffic normalization
# 5.3 IPSec strong proposal
# 5.4 VPN split tunneling
# 6.3 SNMP logging
# 7.1 DHCP lease time
# 7.3 UPnP disabled
# 7.4 mDNS/Avahi disabled
# 7.5 Captive portal
# 8.1 CARP/HA
# 8.3 Config revision history
