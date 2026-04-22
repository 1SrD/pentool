"""
Session Manager - multi-target persistence
Each session represents a target/engagement with its findings, notes, command history.
"""
import json
import os
from datetime import datetime
from pathlib import Path


SESSIONS_DIR = Path(__file__).resolve().parent.parent / "sessions"
SESSIONS_DIR.mkdir(exist_ok=True)


class Session:
    def __init__(self, name: str, target: str = "", platform: str = "generic"):
        self.name = name
        self.target = target
        self.platform = platform  # generic, htb, thm, lab
        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        self.notes = ""
        self.tags = []
        self.findings = []        # list of Finding dicts
        self.history = []         # list of executed commands
        self.parsed_services = {} # port -> service info (from nmap parsing)
        self.loot = []            # creds, hashes, files found

    def to_dict(self):
        return {
            "name": self.name,
            "target": self.target,
            "platform": self.platform,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "notes": self.notes,
            "tags": self.tags,
            "findings": self.findings,
            "history": self.history,
            "parsed_services": self.parsed_services,
            "loot": self.loot,
        }

    @classmethod
    def from_dict(cls, d):
        s = cls(d["name"], d.get("target",""), d.get("platform","generic"))
        s.created_at      = d.get("created_at", s.created_at)
        s.updated_at      = d.get("updated_at", s.updated_at)
        s.notes           = d.get("notes", "")
        s.tags            = d.get("tags", [])
        s.findings        = d.get("findings", [])
        s.history         = d.get("history", [])
        s.parsed_services = d.get("parsed_services", {})
        s.loot            = d.get("loot", [])
        return s

    def add_finding(self, title: str, severity: str, description: str = "",
                    evidence: str = "", recommendation: str = ""):
        self.findings.append({
            "id": len(self.findings) + 1,
            "title": title,
            "severity": severity,  # critical, high, medium, low, info
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat(),
        })
        self.touch()

    def add_history(self, command: str, module: str, duration_s: float = 0,
                    exit_code: int = 0):
        self.history.append({
            "id": len(self.history) + 1,
            "command": command,
            "module": module,
            "timestamp": datetime.now().isoformat(),
            "duration_s": duration_s,
            "exit_code": exit_code,
        })
        self.touch()

    def add_loot(self, kind: str, value: str, context: str = ""):
        """kind: cred, hash, token, file, cookie, key"""
        self.loot.append({
            "id": len(self.loot) + 1,
            "kind": kind,
            "value": value,
            "context": context,
            "timestamp": datetime.now().isoformat(),
        })
        self.touch()

    def touch(self):
        self.updated_at = datetime.now().isoformat()


class SessionManager:
    def __init__(self):
        self.sessions: dict[str, Session] = {}
        self.active: Session | None = None
        self.load_all()

    def load_all(self):
        for f in SESSIONS_DIR.glob("*.json"):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                s = Session.from_dict(data)
                self.sessions[s.name] = s
            except Exception:
                continue

    def create(self, name: str, target: str = "", platform: str = "generic") -> Session:
        if name in self.sessions:
            return self.sessions[name]
        s = Session(name, target, platform)
        self.sessions[name] = s
        self.save(s)
        return s

    def set_active(self, name: str) -> Session | None:
        if name in self.sessions:
            self.active = self.sessions[name]
            return self.active
        return None

    def save(self, session: Session):
        safe = "".join(c for c in session.name if c.isalnum() or c in "-_")
        path = SESSIONS_DIR / f"{safe}.json"
        with open(path, "w") as f:
            json.dump(session.to_dict(), f, indent=2)

    def save_active(self):
        if self.active:
            self.save(self.active)

    def delete(self, name: str):
        if name in self.sessions:
            safe = "".join(c for c in name if c.isalnum() or c in "-_")
            path = SESSIONS_DIR / f"{safe}.json"
            if path.exists():
                path.unlink()
            del self.sessions[name]
            if self.active and self.active.name == name:
                self.active = None

    def rename(self, old: str, new: str):
        if old not in self.sessions or new in self.sessions:
            return False
        s = self.sessions.pop(old)
        s.name = new
        self.sessions[new] = s
        self.save(s)
        # delete old file
        safe = "".join(c for c in old if c.isalnum() or c in "-_")
        old_path = SESSIONS_DIR / f"{safe}.json"
        if old_path.exists():
            old_path.unlink()
        return True

    def list_names(self) -> list[str]:
        return sorted(self.sessions.keys(),
                      key=lambda n: self.sessions[n].updated_at,
                      reverse=True)
