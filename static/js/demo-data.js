export const DEMO = `#config-version=FGT60F-7.0.5-FW-build0304-220922:opmode=0:vdom=0:user=admin
config system global
    set admintimeout 30
    set hostname fortigate
    set timezone 23
end
config system dns
    set primary 8.8.8.8
end
config system ntp
    set ntpsync enable
    set server "pool.ntp.org"
end
config system password-policy
    set status enable
    set minimum-length 6
end
config system interface
    edit "wan1"
        set allowaccess https ssh http telnet ping
    next
    edit "lan"
        set allowaccess https ssh
    next
end
config system snmp sysinfo
    set status enable
end
config system snmp community
    edit 1
        set name public
        set version v1
    next
end
config firewall policy
    edit 1
        set name "Allow_Internal_Out"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status enable
        set logtraffic utm
    next
    edit 2
        set name "Block_All"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set status enable
    next
end
config log syslogd setting
    set status disable
end
config log setting
    set resolve-ip disable
end
config vpn ssl settings
    set split-tunneling enable
    set idle-timeout 600
end
config vpn ipsec phase1-interface
    edit "vpn-hq"
        set proposal des-md5
        set ike-version 1
    next
end`;

export const DEMO_PFSENSE = `<?xml version="1.0"?>
<pfsense>
  <version>21.7</version>
  <system>
    <hostname>pfsense</hostname>
    <domain>localdomain</domain>
    <timezone>America/Sao_Paulo</timezone>
    <timeservers>pool.ntp.org</timeservers>
    <dnsserver>8.8.8.8</dnsserver>
    <webgui>
      <protocol>https</protocol>
      <port>443</port>
    </webgui>
    <user>
      <name>admin</name>
      <bcrypt-hash>$2y$10$DummyHashForDemoOnly1234567890abc</bcrypt-hash>
    </user>
  </system>
  <interfaces>
    <wan>
      <blockpriv/>
      <blockbogons/>
    </wan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><network>lan</network></source>
      <destination><any/></destination>
      <log/>
    </rule>
  </filter>
  <openvpn>
    <openvpn-server>
      <tls>DUMMYTLSKEY</tls>
      <crypto>AES-256-GCM</crypto>
    </openvpn-server>
  </openvpn>
  <syslog>
    <remoteserver>192.168.1.50</remoteserver>
  </syslog>
  <revision>
    <time>1700000000</time>
    <description>Demo config</description>
  </revision>
</pfsense>`;