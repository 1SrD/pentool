"""
Nmap module - port scanning and service enumeration
"""
import threading
from .base_module import BaseModule


class NmapModule(BaseModule):
    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["nmap"]

        # Scan type
        scan_type = options.get("scan_type", "")
        if scan_type == "-sS":
            cmd.append("-sS")
        elif scan_type == "-sT":
            cmd.append("-sT")
        elif scan_type == "-sU":
            cmd.append("-sU")

        # Extra flags
        if options.get("sV"):
            cmd.append("-sV")
        if options.get("sC"):
            cmd.append("-sC")
        if options.get("O"):
            cmd.append("-O")
        if options.get("A"):
            cmd.append("-A")
        if options.get("verbose"):
            cmd.append("-v")

        # Timing
        timing = options.get("timing", "-T3")
        cmd.append(timing)

        # Ports
        ports = options.get("ports", "all")
        if ports == "all":
            cmd.extend(["-p", "-"])
        elif ports == "top100":
            cmd.extend(["--top-ports", "100"])
        elif ports == "top1000":
            cmd.extend(["--top-ports", "1000"])
        elif ports == "common":
            cmd.extend(["-p", "21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080,8443"])
        elif ports == "custom":
            custom = options.get("custom_ports", "1-1000")
            cmd.extend(["-p", custom])

        # Output format
        if options.get("output_xml"):
            import os
            from datetime import datetime
            os.makedirs("output", exist_ok=True)
            safe = target.replace("/", "_").replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            cmd.extend(["-oX", f"output/nmap_{safe}_{ts}.xml"])

        cmd.append(target)
        return cmd

    def execute(self, target: str, options: dict, save_output: bool = False):
        cmd = self.build_command(target, options)
        t = threading.Thread(target=self.run_command, args=(cmd, target, save_output), daemon=True)
        t.start()
