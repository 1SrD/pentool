# ⬡ PenTool v2

**Ethical Hacking Toolkit — desktop GUI pro para pentesting y CTFs**
Desarrollado por [1SrD](https://github.com/1SrD)

> ⚠️ Solo para entornos autorizados: CTFs, laboratorios, bug bounty con scope, o sistemas propios.

---

## 🎯 Features v2

### Core
- **Multi-session manager** — gestiona múltiples targets/engagements con persistencia JSON
- **Victim Panel** — auto-parsea nmap y muestra puertos, servicios, CVEs en cards con hints
- **Findings dashboard** — etiquetado por severidad (critical/high/medium/low/info) con resumen visual
- **Command history** — historial navegable con re-ejecución un-clic
- **HTML reports** — genera reportes profesionales con severity summary y findings
- **Preset system** — 14 presets built-in (OSCP initial, web recon, stealth, etc.) + custom
- **Reverse shell listener** — nc/rlwrap listener integrado con 12 payloads y TTY upgrade
- **Cheatsheets** — 9 cheatsheets integradas: Linux/Win privesc, AD, pivoting, file transfer, reverse shells, msfvenom, hash cracking, SQLi

### Módulos de ataque
| Módulo | Tools | Uso |
|---|---|---|
| **NMAP** | nmap | Port scanning, service/version, NSE scripts, auto-parse |
| **RECON** | whois, dig, host, theHarvester, sublist3r, dnsrecon, amass | Recon pasivo |
| **FFUF** | ffuf, gobuster | Web fuzzing, directory enumeration |
| **SMB** | enum4linux, smbclient, smbmap, rpcclient, nbtscan | SMB/NetBIOS enum |
| **AD** | CME/netexec, kerbrute, GetNPUsers, GetUserSPNs, secretsdump, bloodhound | Active Directory |
| **HYDRA** | hydra, medusa | Brute force (SSH/FTP/HTTP/SMB/RDP/MySQL/MSSQL...) |
| **VULN** | nikto, nuclei | Vulnerability scanning con filtros de severidad |
| **EXPL** | searchsploit, msfvenom, PEASS downloader | Exploitation helpers |
| **PAYLOADS** | built-in | 10 generadores: reverse shells, LFI, SQLi, XSS, file upload bypass... |
| **MSF** | msfconsole | Search exploits por CVE, run, generate RC scripts |
| **LISTENER** | nc, rlwrap | Catch reverse shells + TTY upgrade automático |

### Wordlists integradas
| Categoría | Wordlists |
|---|---|
| Web | common, big, api-endpoints |
| DNS | subdomains |
| Usernames | usernames-common |
| Passwords | passwords-common, passwords-webapp, credential-pairs |

Fallback automático: si las wordlists del sistema no existen (dirb, seclists), usa las del repo.

---

## 🚀 Instalación

### Clonar y ejecutar
```bash
git clone https://github.com/1SrD/pentool.git
cd pentool
python3 main.py
```

Sin dependencias pip. Solo Python 3.10+ stdlib y Tkinter.

### Tkinter (si falta)
```bash
sudo apt install python3-tk -y
```

### Herramientas externas (opcional pero recomendado)
```bash
# Básicas
sudo apt install nmap ffuf gobuster hydra medusa nikto -y

# Recon
sudo apt install whois dnsutils theharvester -y

# SMB / AD
sudo apt install enum4linux smbclient smbmap nbtscan -y
sudo apt install impacket-scripts kerbrute bloodhound-python -y

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# netexec (sucesor de CME)
pipx install netexec

# Metasploit
sudo apt install metasploit-framework -y

# rlwrap (mejor UX en listener)
sudo apt install rlwrap -y
```

---

## 📁 Estructura del proyecto

```
pentool/
├── main.py                      # App Tkinter v2 (UI 3-columnas)
├── core/                        # Lógica transversal
│   ├── session.py               # Multi-session manager
│   ├── parser.py                # Nmap parser + CVE detection
│   ├── presets.py               # Preset system (14 built-in)
│   ├── report.py                # HTML report generator
│   └── listener.py              # Reverse shell listener + payloads
├── modules/                     # Módulos de ataque
│   ├── base_module.py           # Clase base con session integration
│   ├── nmap_module.py
│   ├── recon_module.py          # whois, dig, theHarvester...
│   ├── ffuf_module.py
│   ├── smb_module.py            # enum4linux, smbclient...
│   ├── ad_module.py             # CME, kerbrute, impacket...
│   ├── hydra_module.py
│   ├── nikto_module.py
│   ├── exploit_module.py        # searchsploit, msfvenom, PEASS
│   ├── msf_module.py
│   ├── script_gen.py            # Payload generators
│   └── cheatsheets.py           # 9 cheatsheets integradas
├── wordlists/                   # Wordlists built-in con fallback
│   ├── web/
│   ├── dns/
│   ├── usernames/
│   └── bruteforce/
├── sessions/                    # Sessions persistidas (auto-creada)
├── reports/                     # Reportes HTML generados
├── presets/                     # Custom presets del usuario
├── output/                      # Output capturado (opt-in)
└── scripts/                     # Scripts/payloads generados
```

---

## 🔧 Workflow típico (OSCP/HTB)

1. **Crear sesión** — sidebar izquierdo, botón `+ New`, nombre y target
2. **Nmap initial scan** — pestaña NMAP, preset `nmap-oscp-initial`, START
3. **Revisar Victim Panel** — pestaña derecha `VICTIM`, ve puertos + CVEs auto-detectados
4. **Enumeration** — según los servicios: SMB, AD, FFUF, Recon
5. **Brute force** — HYDRA con wordlists apropiadas
6. **Exploitation** — EXPL/MSF con searchsploit o msfvenom
7. **Listener** — pestaña LISTENER, arranca netcat, genera payload con LHOST/LPORT auto
8. **Post-ex** — CHEATS tab con Linux/Windows privesc + download scripts (linpeas, winpeas)
9. **Registrar findings** — botón `+ Add` en pestaña FINDINGS con severidad
10. **Generar reporte** — sidebar `📊 Report` → HTML auto en `reports/` + abre en browser

---

## 💾 Persistencia

Todo se guarda automáticamente:
- **Sessions** → `sessions/<name>.json` (target, notes, findings, history, loot, parsed nmap)
- **Custom presets** → `presets/custom.json`
- **Reports** → `reports/report_<session>_<timestamp>.html`
- **Output** (opcional) → `output/<tool>_<target>_<timestamp>.txt`

En `.gitignore` están `sessions/`, `reports/`, `output/`, `scripts/` — nada sensible sube al repo.

---

## 🗺️ Subir al repo

```bash
git add .
git commit -m "feat: v2 - pro features (sessions, findings, reports, victim panel, listener, cheatsheets)"
git push
```

---

## 📜 Licencia

MIT License

---

## 👤 Autor

**1SrD** — [github.com/1SrD](https://github.com/1SrD) · [linkedin.com/in/dervis-music](https://linkedin.com/in/dervis-music)
Offensive Security path: eJPT → OSCP · target firms: Tarlogic, Zerolynx, S21Sec
