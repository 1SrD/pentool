"""
FFUF module - web fuzzing with SecLists integration.

Mode → Auto wordlist mapping (MODE_DEFAULTS) makes the UI one-click:
the user picks a Fuzz Mode and everything (category, wordlist, extensions,
filters) adapts automatically. The user can override afterwards.

Output uses ffuf's interactive mode (-c for color) because base_module
runs via PTY and handles ANSI cleanly.
"""
import os as _os
import threading
import urllib.request
from .base_module import BaseModule


_BASE    = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_WL_DIR  = _os.path.join(_BASE, "wordlists")
_CACHE   = _os.path.join(_WL_DIR, "seclists_cache")
_SECLISTS_RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"


# ── Wordlist catalog ─────────────────────────────────────────────────────────
WORDLIST_CATEGORIES: dict[str, dict[str, str]] = {
    "Discovery - Web Content": {
        "common (dirb)":              "Discovery/Web-Content/common.txt",
        "big (dirb)":                 "Discovery/Web-Content/big.txt",
        "raft-small-directories":     "Discovery/Web-Content/raft-small-directories.txt",
        "raft-medium-directories":    "Discovery/Web-Content/raft-medium-directories.txt",
        "raft-large-directories":     "Discovery/Web-Content/raft-large-directories.txt",
        "raft-small-files":           "Discovery/Web-Content/raft-small-files.txt",
        "raft-medium-files":          "Discovery/Web-Content/raft-medium-files.txt",
        "raft-large-files":           "Discovery/Web-Content/raft-large-files.txt",
        "directory-list-2.3-small":   "Discovery/Web-Content/directory-list-2.3-small.txt",
        "directory-list-2.3-medium":  "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "directory-list-2.3-large":   "Discovery/Web-Content/directory-list-2.3-large.txt",
        "quickhits":                  "Discovery/Web-Content/quickhits.txt",
        "CGIs":                       "Discovery/Web-Content/CGIs.txt",
    },
    "Discovery - API": {
        "api/api-endpoints":          "Discovery/Web-Content/api/api-endpoints.txt",
        "api/common":                 "Discovery/Web-Content/api/common.txt",
        "api/objects":                "Discovery/Web-Content/api/objects.txt",
        "api/actions":                "Discovery/Web-Content/api/actions.txt",
    },
    "DNS - Subdomains": {
        "subdomains-top1million-5000":   "Discovery/DNS/subdomains-top1million-5000.txt",
        "subdomains-top1million-20000":  "Discovery/DNS/subdomains-top1million-20000.txt",
        "subdomains-top1million-110000": "Discovery/DNS/subdomains-top1million-110000.txt",
        "bitquark-subdomains-top100000": "Discovery/DNS/bitquark-subdomains-top100000.txt",
        "dns-Jhaddix":                   "Discovery/DNS/dns-Jhaddix.txt",
        "fierce-hostlist":               "Discovery/DNS/fierce-hostlist.txt",
    },
    "VHost": {
        "subdomains-top1million-5000 (VHost)": "Discovery/DNS/subdomains-top1million-5000.txt",
    },
    "Discovery - Parameters": {
        "burp-parameter-names":      "Discovery/Web-Content/burp-parameter-names.txt",
        "parameter-names":           "Discovery/Web-Content/parameter-names.txt",
    },
    "Technology-Specific": {
        "CMS/wp-plugins":            "Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
        "CMS/wordpress":             "Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "CMS/drupal-themes":         "Discovery/Web-Content/CMS/drupal-themes.fuzz.txt",
        "CMS/joomla-plugins":        "Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
        "Tomcat":                    "Discovery/Web-Content/tomcat.txt",
        "Nginx":                     "Discovery/Web-Content/nginx.txt",
        "IIS":                       "Discovery/Web-Content/IIS.fuzz.txt",
        "PHP":                       "Discovery/Web-Content/PHP.fuzz.txt",
    },
    "[local fallback]": {
        "common (built-in)":        "_LOCAL_/web/common.txt",
        "big (built-in)":           "_LOCAL_/web/big.txt",
        "api-endpoints (built-in)": "_LOCAL_/web/api-endpoints.txt",
        "subdomains (built-in)":    "_LOCAL_/dns/subdomains.txt",
    },
    "[custom path]": {
        "custom path":              "_CUSTOM_",
    },
}


# ── Auto-select per fuzz mode ────────────────────────────────────────────────
# When user selects a mode in the UI, these defaults are applied automatically.
# Format: mode -> (category, wordlist_name, extensions, filter_codes, recommended_threads)
MODE_DEFAULTS = {
    "directory": {
        "category":     "Discovery - Web Content",
        "wordlist":     "raft-medium-directories",
        "extensions":   ".php,.html,.txt",
        "filter_codes": "404,403",
        "threads":      "40",
        "hint":         "Busca directorios/archivos en http://target/FUZZ",
    },
    "subdomain": {
        "category":     "DNS - Subdomains",
        "wordlist":     "subdomains-top1million-5000",
        "extensions":   "",
        "filter_codes": "",
        "threads":      "100",
        "hint":         "Subdominios: http://FUZZ.target  (necesita wildcard DNS)",
    },
    "vhost": {
        "category":     "VHost",
        "wordlist":     "subdomains-top1million-5000 (VHost)",
        "extensions":   "",
        "filter_codes": "",
        "threads":      "50",
        "hint":         "VHost: Host: FUZZ.target.tld  (filtra por size tras primer scan)",
    },
    "parameter-get": {
        "category":     "Discovery - Parameters",
        "wordlist":     "burp-parameter-names",
        "extensions":   "",
        "filter_codes": "404",
        "threads":      "40",
        "hint":         "Parámetros GET: http://target/?FUZZ=test",
    },
    "parameter-value": {
        "category":     "Discovery - Parameters",
        "wordlist":     "burp-parameter-names",
        "extensions":   "",
        "filter_codes": "404",
        "threads":      "40",
        "hint":         "Valores de parámetro: http://target/?id=FUZZ",
    },
    "files": {
        "category":     "Discovery - Web Content",
        "wordlist":     "raft-medium-files",
        "extensions":   ".php,.bak,.old,.zip,.tar.gz,.conf",
        "filter_codes": "404,403",
        "threads":      "40",
        "hint":         "Solo archivos (no directorios), con extensiones comunes",
    },
    "api": {
        "category":     "Discovery - API",
        "wordlist":     "api/api-endpoints",
        "extensions":   "",
        "filter_codes": "404",
        "threads":      "40",
        "hint":         "Endpoints de API: /v1/FUZZ, /api/FUZZ",
    },
    "wordpress": {
        "category":     "Technology-Specific",
        "wordlist":     "CMS/wordpress",
        "extensions":   "",
        "filter_codes": "404",
        "threads":      "40",
        "hint":         "Paths específicos de WordPress",
    },
    "custom": {
        "category":     "Discovery - Web Content",
        "wordlist":     "common (dirb)",
        "extensions":   "",
        "filter_codes": "",
        "threads":      "40",
        "hint":         "Pon 'FUZZ' donde quieras (URL, body, header, cookie)",
    },
}


def _search_paths(relative_path: str) -> list[str]:
    return [
        _os.path.join("/usr/share/seclists",  relative_path),
        _os.path.join("/usr/share/wordlists/seclists", relative_path),
        _os.path.join("/usr/share/wordlists", _os.path.basename(relative_path)),
        _os.path.join(_CACHE, relative_path),
    ]


def resolve_wordlist(category: str, name: str) -> tuple[str, str]:
    """Return (path, source) where source in {system, cache, builtin, missing, custom}."""
    if category == "[custom path]":
        return ("", "custom")

    entry = WORDLIST_CATEGORIES.get(category, {}).get(name, "")

    if entry.startswith("_LOCAL_/"):
        path = _os.path.join(_WL_DIR, entry.replace("_LOCAL_/", ""))
        return (path, "builtin" if _os.path.exists(path) else "missing")

    for candidate in _search_paths(entry):
        if _os.path.exists(candidate):
            if "seclists" in candidate.lower():
                return (candidate, "system")
            if _CACHE in candidate:
                return (candidate, "cache")
            return (candidate, "system")

    return ("", "missing")


def download_wordlist(category: str, name: str, progress_cb=None) -> tuple[bool, str]:
    entry = WORDLIST_CATEGORIES.get(category, {}).get(name, "")
    if not entry or entry.startswith("_LOCAL_") or entry == "_CUSTOM_":
        return (False, "Not downloadable")

    url = f"{_SECLISTS_RAW}/{entry}"
    dest = _os.path.join(_CACHE, entry)
    _os.makedirs(_os.path.dirname(dest), exist_ok=True)

    try:
        if progress_cb:
            progress_cb(f"Downloading {entry}...")
        req = urllib.request.Request(url, headers={"User-Agent": "PenTool/2.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
        with open(dest, "wb") as f:
            f.write(data)
        return (True, dest)
    except Exception as e:
        return (False, str(e))


# ─── FFUF Module ─────────────────────────────────────────────────────────────

class FfufModule(BaseModule):
    def build_command(self, target: str, options: dict) -> list[str]:
        wordlist = options.get("wordlist", "")
        if not wordlist or not _os.path.exists(wordlist):
            wordlist = _os.path.join(_WL_DIR, "web", "common.txt")

        fuzz_mode = options.get("fuzz_mode", "directory")

        # Build URL per mode
        url = target.strip()
        if not url.startswith("http"):
            url = "http://" + url
        url = url.rstrip("/")

        if fuzz_mode == "directory" or fuzz_mode == "files" or fuzz_mode == "wordpress":
            if "FUZZ" not in url:
                url = f"{url}/FUZZ"
        elif fuzz_mode == "subdomain":
            from urllib.parse import urlparse
            p = urlparse(url)
            url = f"{p.scheme}://FUZZ.{p.netloc}"
        elif fuzz_mode == "vhost":
            pass  # URL unchanged; Host header fuzzes
        elif fuzz_mode == "parameter-get":
            if "FUZZ" not in url:
                url = f"{url}/?FUZZ=test"
        elif fuzz_mode == "parameter-value":
            if "FUZZ" not in url:
                param = options.get("param_name", "id")
                url = f"{url}/?{param}=FUZZ"
        elif fuzz_mode == "api":
            if "FUZZ" not in url:
                url = f"{url}/FUZZ"
        elif fuzz_mode == "custom":
            body = options.get("body", "")
            headers = options.get("headers", "")
            cookies = options.get("cookies", "")
            if "FUZZ" not in url and "FUZZ" not in body and "FUZZ" not in headers and "FUZZ" not in cookies:
                url = f"{url}/FUZZ"

        # -c = color output (we strip ANSI in base_module anyway, but -c
        # also makes ffuf keep the live progress counter format we throttle)
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-c"]

        method = options.get("method", "GET")
        if method and method != "GET":
            cmd.extend(["-X", method])

        body = options.get("body", "").strip()
        if body:
            cmd.extend(["-d", body])

        headers_raw = options.get("headers", "").strip()
        if headers_raw:
            for line in headers_raw.splitlines():
                line = line.strip()
                if line and ":" in line:
                    cmd.extend(["-H", line])

        cookies = options.get("cookies", "").strip()
        if cookies:
            cmd.extend(["-H", f"Cookie: {cookies}"])

        if fuzz_mode == "vhost":
            host_header = options.get("vhost_host", "FUZZ.target.com")
            cmd.extend(["-H", f"Host: {host_header}"])

        ext = options.get("extensions", "").strip()
        if ext:
            cmd.extend(["-e", ext])

        mc = options.get("match_codes", "").strip()
        if mc:
            cmd.extend(["-mc", mc])
        fc = options.get("filter_codes", "").strip()
        if fc:
            cmd.extend(["-fc", fc])
        fs = options.get("filter_size", "").strip()
        if fs:
            cmd.extend(["-fs", fs])
        fw = options.get("filter_words", "").strip()
        if fw:
            cmd.extend(["-fw", fw])
        fl = options.get("filter_lines", "").strip()
        if fl:
            cmd.extend(["-fl", fl])

        threads = options.get("threads", "40")
        cmd.extend(["-t", str(threads)])

        rate = options.get("rate", "").strip()
        if rate:
            cmd.extend(["-rate", rate])

        if options.get("recursion"):
            depth = options.get("recursion_depth", "2")
            cmd.extend(["-recursion", "-recursion-depth", str(depth)])

        if options.get("follow_redirects"):
            cmd.append("-r")

        timeout = options.get("timeout", "").strip()
        if timeout:
            cmd.extend(["-timeout", timeout])

        if options.get("output_json"):
            from datetime import datetime
            _os.makedirs("output", exist_ok=True)
            safe = target.replace("/", "_").replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            cmd.extend(["-o", f"output/ffuf_{safe}_{ts}.json", "-of", "json"])

        return cmd

    def execute(self, target: str, options: dict, save_output: bool = False):
        cmd = self.build_command(target, options)
        t = threading.Thread(
            target=self.run_command, args=(cmd, target, save_output), daemon=True
        )
        t.start()
