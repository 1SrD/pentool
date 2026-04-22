"""
Preset system - save and load common configurations.
Ships with built-in presets for OSCP/HTB/THM workflows.
"""
import json
from pathlib import Path


PRESETS_DIR = Path(__file__).resolve().parent.parent / "presets"
PRESETS_DIR.mkdir(exist_ok=True)


BUILTIN_PRESETS = {
    # ── NMAP ──────────────────────────────────────────────────────
    "nmap-oscp-initial": {
        "module": "nmap",
        "description": "OSCP-style initial scan - top 1000 + service/version + default scripts",
        "options": {
            "scan_type": "-sS", "ports": "top1000", "timing": "-T4",
            "sV": True, "sC": True, "O": False, "A": False, "verbose": True,
        }
    },
    "nmap-full-aggressive": {
        "module": "nmap",
        "description": "Full TCP scan - all ports, aggressive, slower but thorough",
        "options": {
            "scan_type": "-sS", "ports": "all", "timing": "-T4",
            "sV": True, "sC": True, "O": True, "A": True, "verbose": True,
        }
    },
    "nmap-fast-discovery": {
        "module": "nmap",
        "description": "Quick discovery - top 100 ports, no scripts",
        "options": {
            "scan_type": "-sS", "ports": "top100", "timing": "-T4",
            "sV": False, "sC": False, "verbose": False,
        }
    },
    "nmap-stealth": {
        "module": "nmap",
        "description": "Stealth scan - slow and quiet (IDS evasion)",
        "options": {
            "scan_type": "-sS", "ports": "top1000", "timing": "-T1",
            "sV": False, "sC": False, "verbose": False,
        }
    },
    "nmap-udp": {
        "module": "nmap",
        "description": "UDP scan - top ports (slow, needs root)",
        "options": {
            "scan_type": "-sU", "ports": "top100", "timing": "-T4",
            "verbose": True,
        }
    },
    # ── FFUF ──────────────────────────────────────────────────────
    "ffuf-web-quick": {
        "module": "ffuf",
        "description": "Quick directory scan with common wordlist",
        "options": {
            "tool": "ffuf",
            "wordlist_key": "[built-in] common",
            "extensions": ".php,.html,.txt",
            "filter_codes": "404,403",
            "threads": "40", "recursion": False,
        }
    },
    "ffuf-web-deep": {
        "module": "ffuf",
        "description": "Deep scan with recursion and extensions",
        "options": {
            "tool": "ffuf",
            "wordlist_key": "[built-in] big",
            "extensions": ".php,.html,.txt,.bak,.old,.zip",
            "filter_codes": "404",
            "threads": "50", "recursion": True,
        }
    },
    "ffuf-api-discovery": {
        "module": "ffuf",
        "description": "API endpoint discovery",
        "options": {
            "tool": "ffuf",
            "wordlist_key": "[built-in] api-endpoints",
            "extensions": ".json,.xml",
            "filter_codes": "404",
            "threads": "40",
        }
    },
    # ── HYDRA ─────────────────────────────────────────────────────
    "hydra-ssh-common": {
        "module": "hydra",
        "description": "SSH brute with common creds",
        "options": {
            "tool": "hydra", "protocol": "ssh",
            "username": "root",
            "passlist_key": "[built-in] passwords-common",
            "threads": "16", "stop_on_success": True,
        }
    },
    "hydra-ftp-anonymous": {
        "module": "hydra",
        "description": "FTP brute with common creds",
        "options": {
            "tool": "hydra", "protocol": "ftp",
            "username": "anonymous",
            "passlist_key": "[built-in] passwords-common",
            "threads": "16", "stop_on_success": True,
        }
    },
    "hydra-http-form": {
        "module": "hydra",
        "description": "HTTP POST form brute",
        "options": {
            "tool": "hydra", "protocol": "http-post-form",
            "username": "admin",
            "passlist_key": "[built-in] passwords-webapp",
            "form_path": "/login.php",
            "form_params": "username=^USER^&password=^PASS^",
            "fail_string": "Invalid",
            "threads": "8", "stop_on_success": True,
        }
    },
    # ── NIKTO / NUCLEI ────────────────────────────────────────────
    "nuclei-critical-only": {
        "module": "nikto",
        "description": "Nuclei - critical & high severity only",
        "options": {
            "tool": "nuclei",
            "severity": ["critical", "high"],
            "tags": "cve,rce,sqli",
            "rate": "150",
        }
    },
    "nuclei-full-cve": {
        "module": "nikto",
        "description": "Nuclei - all CVE templates",
        "options": {
            "tool": "nuclei",
            "severity": ["critical", "high", "medium"],
            "tags": "cve",
            "rate": "200",
        }
    },
    # ── AD ────────────────────────────────────────────────────────
    "cme-smb-null": {
        "module": "ad",
        "description": "CME SMB null session check",
        "options": {
            "tool": "cme", "protocol": "smb",
            "username": "", "password": "",
            "action": "enum",
        }
    },
    # ── RECON ─────────────────────────────────────────────────────
    "recon-passive-full": {
        "module": "recon",
        "description": "Full passive recon: whois + dig + theHarvester",
        "options": {
            "whois": True, "dig": True, "harvester": True,
        }
    },
}


class PresetManager:
    def __init__(self):
        self.builtin = BUILTIN_PRESETS
        self.custom = {}
        self.load_custom()

    def load_custom(self):
        custom_file = PRESETS_DIR / "custom.json"
        if custom_file.exists():
            try:
                with open(custom_file) as f:
                    self.custom = json.load(f)
            except Exception:
                self.custom = {}

    def save_custom(self):
        custom_file = PRESETS_DIR / "custom.json"
        with open(custom_file, "w") as f:
            json.dump(self.custom, f, indent=2)

    def all(self) -> dict:
        return {**self.builtin, **self.custom}

    def for_module(self, module: str) -> dict:
        return {k: v for k, v in self.all().items() if v["module"] == module}

    def save_preset(self, name: str, module: str, description: str, options: dict):
        self.custom[name] = {
            "module": module,
            "description": description,
            "options": options,
        }
        self.save_custom()

    def delete(self, name: str) -> bool:
        if name in self.custom:
            del self.custom[name]
            self.save_custom()
            return True
        return False
