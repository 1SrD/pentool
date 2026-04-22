"""
Hydra / Medusa module - brute force credential attacks
"""
import threading
from .base_module import BaseModule


import os as _os
_BASE = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_WL = _os.path.join(_BASE, "wordlists")

def _wl(path):
    return path if _os.path.exists(path) else ""

COMMON_WORDLISTS = {
    # ── Built-in (siempre disponibles) ───────────────────────────
    "[built-in] usernames":         _os.path.join(_WL, "usernames", "usernames.txt"),
    "[built-in] passwords-common":  _os.path.join(_WL, "bruteforce", "passwords-common.txt"),
    "[built-in] passwords-webapp":  _os.path.join(_WL, "bruteforce", "passwords-webapp.txt"),
    # ── System ───────────────────────────────────────────────────
    "[system] rockyou":             _wl("/usr/share/wordlists/rockyou.txt"),
    "[system] fasttrack":           _wl("/usr/share/wordlists/fasttrack.txt"),
    "[system] top-usernames":       _wl("/usr/share/seclists/Usernames/top-usernames-shortlist.txt"),
    "[system] usernames-large":     _wl("/usr/share/seclists/Usernames/Names/names.txt"),
    "[system] passwords-10k":       _wl("/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"),
    "[system] passwords-100k":      _wl("/usr/share/seclists/Passwords/Common-Credentials/100k-most-common.txt"),
    "[system] default-creds":       _wl("/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv"),
    # ── Custom ───────────────────────────────────────────────────
    "[custom path]":                "",
}

# ── Auto-fill per protocol ───────────────────────────────────────────────────
# When user picks a protocol, these defaults populate the form automatically.
PROTOCOL_DEFAULTS = {
    "ssh":            {"port": "22",   "username": "root",          "threads": "8",  "hint": "Cuidado: SSH con muchos threads bloquea"},
    "ftp":            {"port": "21",   "username": "anonymous",     "threads": "16", "hint": "Prueba anonymous:anonymous primero"},
    "http-get":       {"port": "80",   "username": "admin",         "threads": "16", "hint": "HTTP Basic Auth"},
    "http-post-form": {"port": "80",   "username": "admin",         "threads": "8",  "hint": "Configura form path, params y fail string"},
    "smb":            {"port": "445",  "username": "administrator", "threads": "1",  "hint": "SMB: usa 1 thread o te bloquean"},
    "rdp":            {"port": "3389", "username": "administrator", "threads": "4",  "hint": "RDP lento, 4 threads max"},
    "telnet":         {"port": "23",   "username": "admin",         "threads": "8",  "hint": "Prueba credenciales por defecto"},
    "mysql":          {"port": "3306", "username": "root",          "threads": "16", "hint": "root:<empty> o root:root"},
    "mssql":          {"port": "1433", "username": "sa",            "threads": "8",  "hint": "sa:<empty> es común"},
    "postgresql":     {"port": "5432", "username": "postgres",      "threads": "8",  "hint": "postgres:postgres"},
    "smtp":           {"port": "25",   "username": "admin",         "threads": "8",  "hint": "Para enumerar usuarios primero usa smtp-user-enum"},
    "pop3":           {"port": "110",  "username": "admin",         "threads": "8",  "hint": ""},
    "imap":           {"port": "143",  "username": "admin",         "threads": "8",  "hint": ""},
}

PROTOCOLS = ["ssh", "ftp", "http-get", "http-post-form", "smb", "rdp",
             "telnet", "mysql", "mssql", "postgresql", "smtp", "pop3", "imap"]


class HydraModule(BaseModule):
    def build_hydra_command(self, target: str, options: dict) -> list[str]:
        protocol = options.get("protocol", "ssh")
        port = options.get("port", "")
        username = options.get("username", "")
        userlist = options.get("userlist", "")
        password = options.get("password", "")
        passlist = options.get("passlist", "/usr/share/wordlists/rockyou.txt")
        threads = options.get("threads", "16")

        cmd = ["hydra"]

        # User specification
        if username:
            cmd.extend(["-l", username])
        elif userlist:
            cmd.extend(["-L", userlist])
        else:
            cmd.extend(["-l", "admin"])

        # Password specification
        if password:
            cmd.extend(["-p", password])
        else:
            cmd.extend(["-P", passlist])

        # Threads and options
        cmd.extend(["-t", threads])
        cmd.append("-V")  # verbose - show each attempt

        if options.get("stop_on_success"):
            cmd.append("-f")

        # Target + port
        target_str = target
        if port:
            target_str = f"-s {port} {target}"
            cmd.extend(["-s", port])

        cmd.append(target)

        # Protocol specific
        if protocol == "http-post-form":
            form_path = options.get("form_path", "/login")
            form_params = options.get("form_params", "username=^USER^&password=^PASS^")
            fail_string = options.get("fail_string", "Invalid")
            cmd.append(f"{protocol}:{form_path}:{form_params}:F={fail_string}")
        else:
            cmd.append(protocol)

        return cmd

    def build_medusa_command(self, target: str, options: dict) -> list[str]:
        protocol = options.get("protocol", "ssh")
        username = options.get("username", "")
        passlist = options.get("passlist", "/usr/share/wordlists/rockyou.txt")
        threads = options.get("threads", "16")

        cmd = ["medusa", "-h", target]
        if username:
            cmd.extend(["-u", username])
        cmd.extend(["-P", passlist, "-M", protocol, "-t", threads])
        return cmd

    def execute(self, target: str, options: dict, save_output: bool = False):
        tool = options.get("tool", "hydra")
        if tool == "hydra":
            cmd = self.build_hydra_command(target, options)
        else:
            cmd = self.build_medusa_command(target, options)
        t = threading.Thread(target=self.run_command, args=(cmd, target, save_output), daemon=True)
        t.start()
