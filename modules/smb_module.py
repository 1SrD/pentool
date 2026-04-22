"""
SMB / NetBIOS module
enum4linux, smbclient, smbmap, rpcclient, nbtscan
"""
import threading
from .base_module import BaseModule


class SMBModule(BaseModule):
    def build_enum4linux(self, target: str, options: dict) -> list[str]:
        mode = options.get("mode", "all")  # all, users, shares, policy, groups
        flag_map = {
            "all": "-a", "users": "-U", "shares": "-S",
            "policy": "-P", "groups": "-G",
        }
        return ["enum4linux", flag_map.get(mode, "-a"), target]

    def build_smbclient_list(self, target: str, options: dict) -> list[str]:
        username = options.get("username", "")
        password = options.get("password", "")
        cmd = ["smbclient", "-L", f"//{target}/"]
        if username:
            cmd.extend(["-U", f"{username}%{password}"])
        else:
            cmd.extend(["-N"])  # null session
        return cmd

    def build_smbclient_connect(self, target: str, options: dict) -> list[str]:
        share = options.get("share", "")
        username = options.get("username", "")
        password = options.get("password", "")
        cmd = ["smbclient", f"//{target}/{share}"]
        if username:
            cmd.extend(["-U", f"{username}%{password}"])
        else:
            cmd.extend(["-N"])
        return cmd

    def build_smbmap(self, target: str, options: dict) -> list[str]:
        username = options.get("username", "")
        password = options.get("password", "")
        cmd = ["smbmap", "-H", target]
        if username:
            cmd.extend(["-u", username, "-p", password])
        else:
            cmd.extend(["-u", "anonymous"])
        return cmd

    def build_rpcclient(self, target: str, options: dict) -> list[str]:
        username = options.get("username", "")
        password = options.get("password", "")
        cmd = ["rpcclient", "-U", f"{username}%{password}", target]
        return cmd

    def build_nbtscan(self, target: str) -> list[str]:
        return ["nbtscan", "-r", target]

    def build_nmap_smb(self, target: str) -> list[str]:
        """Nmap with SMB vuln scripts"""
        return ["nmap", "-p", "139,445", "--script",
                "smb-vuln*,smb-enum*,smb-os-discovery,smb2-security-mode",
                target]

    def execute(self, target: str, options: dict, save_output: bool = False):
        tool = options.get("tool", "enum4linux")
        builders = {
            "enum4linux":         lambda: self.build_enum4linux(target, options),
            "smbclient-list":     lambda: self.build_smbclient_list(target, options),
            "smbclient-connect":  lambda: self.build_smbclient_connect(target, options),
            "smbmap":             lambda: self.build_smbmap(target, options),
            "rpcclient":          lambda: self.build_rpcclient(target, options),
            "nbtscan":            lambda: self.build_nbtscan(target),
            "nmap-smb":           lambda: self.build_nmap_smb(target),
        }
        cmd = builders.get(tool, builders["enum4linux"])()
        t = threading.Thread(target=self.run_command, args=(cmd, target, save_output), daemon=True)
        t.start()
