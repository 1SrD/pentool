"""
Nmap output parser - extracts ports, services, versions from -sV output
Feeds the victim panel with actionable data + CVE hints.
"""
import re


# Service → common exploitation hints
SERVICE_HINTS = {
    "ftp":        ["Try anonymous login", "Check for vsftpd 2.3.4 backdoor (CVE-2011-2523)", "ftp -p <target>"],
    "ssh":        ["hydra -L users -P rockyou.txt ssh://<target>", "Check CVE-2008-0166 (Debian OpenSSL)", "ssh -oKexAlgorithms=+diffie-hellman-group1-sha1"],
    "telnet":     ["Plaintext protocol - sniff creds", "telnet <target>", "Try default creds"],
    "smtp":       ["smtp-user-enum -M VRFY -U users.txt -t <target>", "nmap --script smtp-enum-users"],
    "dns":        ["dig axfr @<target> <domain>", "dnsrecon -d <domain>", "Try zone transfer"],
    "http":       ["whatweb <target>", "ffuf -u http://<target>/FUZZ", "nikto -h <target>", "nuclei -u http://<target>"],
    "https":      ["sslscan <target>", "testssl.sh <target>", "Check cert for subdomains"],
    "pop3":       ["Plaintext creds", "Check SSL variant POP3S:995"],
    "msrpc":      ["rpcclient -U '' -N <target>", "impacket-rpcdump <target>"],
    "netbios-ssn":["enum4linux -a <target>", "smbclient -L //<target>/"],
    "microsoft-ds":["enum4linux -a <target>", "smbmap -H <target>", "smbclient -L //<target>/", "CVE-2017-0144 EternalBlue check"],
    "snmp":       ["snmpwalk -v2c -c public <target>", "onesixtyone -c community.txt <target>"],
    "ldap":       ["ldapsearch -x -H ldap://<target> -s base", "nmap --script ldap-* <target>"],
    "rdp":        ["rdesktop <target>", "xfreerdp /v:<target>", "CVE-2019-0708 BlueKeep check"],
    "mysql":      ["mysql -h <target> -u root", "hydra -L users -P rockyou.txt mysql://<target>"],
    "postgresql": ["psql -h <target> -U postgres", "Check for default creds postgres:postgres"],
    "mssql":      ["impacket-mssqlclient <target> -windows-auth", "nmap --script ms-sql-* <target>"],
    "redis":      ["redis-cli -h <target>", "No auth by default - try INFO, KEYS *"],
    "mongodb":    ["mongo <target>:27017", "No auth by default in old versions"],
    "elasticsearch":["curl http://<target>:9200/_cat/indices", "curl http://<target>:9200/_search"],
    "vnc":        ["vncviewer <target>", "nmap --script vnc-* <target>"],
    "x11":        ["xspy <target>:0", "xwininfo -tree -root -display <target>:0"],
    "tomcat":     ["Check /manager/html - default creds tomcat:tomcat", "msfconsole: use auxiliary/scanner/http/tomcat_mgr_login"],
    "jenkins":    ["Check /script console for RCE if creds leaked"],
    "weblogic":   ["CVE-2017-10271, CVE-2019-2725, CVE-2020-14882"],
    "wordpress":  ["wpscan --url http://<target>/ --enumerate u,p"],
    "drupal":     ["droopescan scan drupal -u http://<target>/"],
}

# Service fingerprints → CVE hints when version is detected
VERSION_CVES = [
    (r"vsftpd\s+2\.3\.4",        ["CVE-2011-2523 - vsftpd backdoor RCE"]),
    (r"ProFTPD\s+1\.3\.5",       ["CVE-2015-3306 - mod_copy RCE"]),
    (r"OpenSSH\s+7\.[0-5]",      ["CVE-2016-10009 - xauth command injection (check)"]),
    (r"OpenSSH\s+[0-6]\.",       ["Old OpenSSH - check user enumeration CVEs"]),
    (r"Apache\s+2\.4\.49",       ["CVE-2021-41773 - Path traversal RCE"]),
    (r"Apache\s+2\.4\.50",       ["CVE-2021-42013 - Path traversal RCE"]),
    (r"Apache\s+2\.2\.8",        ["Check for old Apache vulns"]),
    (r"Microsoft-IIS/6\.0",      ["CVE-2017-7269 - WebDAV buffer overflow"]),
    (r"Microsoft-IIS/7\.5",      ["Check IIS short name enumeration"]),
    (r"Samba\s+3\.0\.2[0-5]",    ["CVE-2007-2447 - username map script RCE"]),
    (r"Samba\s+4\.[0-5]",        ["CVE-2017-7494 - SambaCry (check pre-4.6.4)"]),
    (r"MS\s+SMB\s+Windows\s+7",  ["CVE-2017-0144 - EternalBlue"]),
    (r"Jenkins",                  ["CVE-2018-1000861 - Jenkins RCE (check version)"]),
    (r"Tomcat/[789]",            ["CVE-2017-12617 - PUT JSP RCE (check readonly)"]),
    (r"Drupal\s+7\.",            ["CVE-2018-7600 - Drupalgeddon2"]),
    (r"PHP/[45]\.",              ["Very old PHP - many CVEs"]),
]


class NmapParser:
    # Matches: "22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5"
    PORT_LINE = re.compile(
        r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
        r"(?P<state>open|closed|filtered|open\|filtered)\s+"
        r"(?P<service>\S+)"
        r"(?:\s+(?P<version>.+))?$",
        re.MULTILINE
    )

    OS_LINE = re.compile(r"^OS details:\s+(.+)$", re.MULTILINE)
    HOSTNAME_LINE = re.compile(r"Nmap scan report for\s+(\S+)(?:\s+\((\S+)\))?")

    @classmethod
    def parse(cls, text: str) -> dict:
        result = {
            "host": "",
            "ip": "",
            "os": "",
            "ports": [],
        }

        m = cls.HOSTNAME_LINE.search(text)
        if m:
            result["host"] = m.group(1)
            result["ip"] = m.group(2) or m.group(1)

        m = cls.OS_LINE.search(text)
        if m:
            result["os"] = m.group(1).strip()

        for match in cls.PORT_LINE.finditer(text):
            port_info = {
                "port":    int(match.group("port")),
                "proto":   match.group("proto"),
                "state":   match.group("state"),
                "service": match.group("service"),
                "version": (match.group("version") or "").strip(),
                "hints":   [],
                "cves":    [],
            }
            # Add service hints
            svc = port_info["service"].lower()
            for key, hints in SERVICE_HINTS.items():
                if key in svc:
                    port_info["hints"].extend(hints)
                    break

            # Add CVE hints from version
            version_str = port_info["version"]
            if version_str:
                for pattern, cves in VERSION_CVES:
                    if re.search(pattern, version_str, re.IGNORECASE):
                        port_info["cves"].extend(cves)

            result["ports"].append(port_info)

        return result

    @classmethod
    def format_victim_panel(cls, parsed: dict) -> str:
        """Format parsed data as a pretty text panel for display."""
        lines = []
        lines.append(f"╔{'═'*68}╗")
        lines.append(f"║  TARGET PROFILE".ljust(69) + "║")
        lines.append(f"╠{'═'*68}╣")
        lines.append(f"║  Host:  {parsed.get('host','unknown'):<58} ║")
        lines.append(f"║  IP:    {parsed.get('ip','unknown'):<58} ║")
        if parsed.get("os"):
            os_str = parsed['os'][:58]
            lines.append(f"║  OS:    {os_str:<58} ║")
        lines.append(f"║  Ports: {len(parsed.get('ports',[])):<58} ║")
        lines.append(f"╚{'═'*68}╝")
        lines.append("")

        for p in parsed.get("ports", []):
            lines.append(f"┌─ [{p['port']}/{p['proto']}] {p['service'].upper()} "
                         f"{'─'*(50 - len(p['service']))}┐")
            if p["version"]:
                lines.append(f"│  {p['version'][:66]}")
            if p["hints"]:
                lines.append(f"│")
                lines.append(f"│  ▸ HINTS:")
                for h in p["hints"][:3]:
                    lines.append(f"│     • {h[:60]}")
            if p["cves"]:
                lines.append(f"│")
                lines.append(f"│  ▸ CVEs:")
                for c in p["cves"]:
                    lines.append(f"│     ⚠ {c[:60]}")
            lines.append(f"└{'─'*68}")
            lines.append("")

        return "\n".join(lines)
