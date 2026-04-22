"""
Passive Recon Module
whois, dig, host, theHarvester, sublist3r, dnsrecon
"""
import threading
from .base_module import BaseModule


class ReconModule(BaseModule):
    def build_whois(self, target: str) -> list[str]:
        return ["whois", target]

    def build_dig(self, target: str, record_type: str = "ANY") -> list[str]:
        return ["dig", target, record_type, "+noall", "+answer"]

    def build_dig_axfr(self, target: str, nameserver: str = "") -> list[str]:
        cmd = ["dig", "axfr", target]
        if nameserver:
            cmd.append(f"@{nameserver}")
        return cmd

    def build_host(self, target: str) -> list[str]:
        return ["host", "-a", target]

    def build_harvester(self, target: str, sources: str = "all") -> list[str]:
        return ["theHarvester", "-d", target, "-b", sources, "-l", "500"]

    def build_sublist3r(self, target: str) -> list[str]:
        return ["sublist3r", "-d", target]

    def build_dnsrecon(self, target: str) -> list[str]:
        return ["dnsrecon", "-d", target, "-t", "std"]

    def build_amass(self, target: str) -> list[str]:
        return ["amass", "enum", "-passive", "-d", target]

    def execute(self, target: str, options: dict, save_output: bool = False):
        tool = options.get("tool", "whois")
        cmd_builders = {
            "whois":        lambda: self.build_whois(target),
            "dig":          lambda: self.build_dig(target, options.get("record_type","ANY")),
            "dig-axfr":     lambda: self.build_dig_axfr(target, options.get("nameserver","")),
            "host":         lambda: self.build_host(target),
            "theHarvester": lambda: self.build_harvester(target, options.get("sources","all")),
            "sublist3r":    lambda: self.build_sublist3r(target),
            "dnsrecon":     lambda: self.build_dnsrecon(target),
            "amass":        lambda: self.build_amass(target),
        }
        builder = cmd_builders.get(tool, cmd_builders["whois"])
        cmd = builder()
        t = threading.Thread(target=self.run_command, args=(cmd, target, save_output), daemon=True)
        t.start()
