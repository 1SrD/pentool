"""
Nikto / Nuclei module - vulnerability scanning
"""
import threading
from .base_module import BaseModule


NUCLEI_SEVERITIES = ["critical", "high", "medium", "low", "info"]

NUCLEI_TAGS = [
    "cve", "lfi", "rce", "sqli", "xss", "ssrf", "idor",
    "exposure", "misconfig", "default-login", "takeover", "wordpress"
]


class NiktoModule(BaseModule):
    def build_nikto_command(self, target: str, options: dict) -> list[str]:
        cmd = ["nikto", "-h", target]

        port = options.get("port", "")
        if port:
            cmd.extend(["-p", port])

        if options.get("ssl"):
            cmd.append("-ssl")

        if options.get("no_ssl_check"):
            cmd.append("-nossl")

        tuning = options.get("tuning", "")
        if tuning:
            cmd.extend(["-Tuning", tuning])

        if options.get("follow_redirects"):
            cmd.append("-followredirects")

        user_agent = options.get("user_agent", "")
        if user_agent:
            cmd.extend(["-useragent", user_agent])

        return cmd

    def build_nuclei_command(self, target: str, options: dict) -> list[str]:
        cmd = ["nuclei", "-u", target]

        # Severity filter
        severity = options.get("severity", [])
        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        # Tags filter
        tags = options.get("tags", [])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        # Templates path
        templates = options.get("templates", "")
        if templates:
            cmd.extend(["-t", templates])

        # Rate limiting
        rate = options.get("rate", "150")
        cmd.extend(["-rate-limit", rate])

        # Concurrency
        concurrency = options.get("concurrency", "25")
        cmd.extend(["-c", concurrency])

        if options.get("silent"):
            cmd.append("-silent")

        if options.get("json_output"):
            import os
            from datetime import datetime
            os.makedirs("output", exist_ok=True)
            safe = target.replace("/", "_").replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            cmd.extend(["-json-export", f"output/nuclei_{safe}_{ts}.json"])

        return cmd

    def execute(self, target: str, options: dict, save_output: bool = False):
        tool = options.get("tool", "nikto")
        if tool == "nikto":
            cmd = self.build_nikto_command(target, options)
        else:
            cmd = self.build_nuclei_command(target, options)
        t = threading.Thread(target=self.run_command, args=(cmd, target, save_output), daemon=True)
        t.start()
