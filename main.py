"""
PenTool v2 - Ethical Hacking Toolkit (Pro)
Author: 1SrD (Dervis)
License: MIT
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import threading
import os
import sys
import webbrowser
import subprocess
from datetime import datetime

# Add project root to path
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from modules import (
    NmapModule, FfufModule, HydraModule, NiktoModule, MetasploitModule,
    ReconModule, ADModule, SMBModule, ExploitModule,
    WORDLIST_CATEGORIES, MODE_DEFAULTS, resolve_wordlist, download_wordlist,
    COMMON_WORDLISTS, PROTOCOLS, PROTOCOL_DEFAULTS, NUCLEI_SEVERITIES,
    SCRIPTS, generate_script, save_script, PRIVESC_SCRIPTS,
    CHEATSHEETS, list_cheatsheets, get_cheatsheet,
)
from core import (
    Session, SessionManager, NmapParser, PresetManager,
    generate_report, ShellListener, REVERSE_SHELL_PAYLOADS,
    TTY_UPGRADE_COMMANDS, get_local_ips,
)

# ─── Theme ────────────────────────────────────────────────────────────────────
C = {
    "bg":           "#0a0c11",
    "bg2":          "#11141c",
    "bg3":          "#181d28",
    "bg4":          "#1f2535",
    "border":       "#242b3d",
    "border_hi":    "#3a4259",
    "accent":       "#00ff9d",
    "accent_dim":   "#008c55",
    "accent2":      "#00aaff",
    "accent3":      "#9d5cff",
    "red":          "#ff4560",
    "red_bright":   "#ff2d55",
    "yellow":       "#ffd166",
    "orange":       "#ff9500",
    "text":         "#c8d0e0",
    "text_dim":     "#5a6070",
    "text_bright":  "#eef2f8",
    "success":      "#00ff9d",
    "warning":      "#ffd166",
    "error":        "#ff4560",
    "running":      "#00aaff",
}

SEVERITY_COLORS = {
    "critical": C["red_bright"],
    "high":     C["red"],
    "medium":   C["orange"],
    "low":      C["yellow"],
    "info":     C["accent2"],
}

FONT_MONO = ("JetBrains Mono", 10)
FONT_MONO_S = ("JetBrains Mono", 9)
FONT_UI = ("DejaVu Sans", 10)
FONT_BOLD = ("DejaVu Sans", 10, "bold")

BANNER = r"""
 ██████╗ ███████╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗
 ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║
 ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║
 ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║   ██║██║
 ██║     ███████╗██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
"""


class PenToolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PenTool v2  //  Ethical Hacking Toolkit")
        self.geometry("1500x900")
        self.minsize(1200, 750)
        self.configure(bg=C["bg"])

        # State
        self.sessions = SessionManager()
        self.presets = PresetManager()
        self.listener = None
        self._active_module = None

        # Ensure at least one session exists
        if not self.sessions.sessions:
            self.sessions.create("default", "", "generic")
        self.sessions.set_active(self.sessions.list_names()[0])

        self._setup_styles()
        self._build_ui()
        self._refresh_session_list()
        self._refresh_findings()
        self._refresh_history()

    # ─── Styling ──────────────────────────────────────────────────────────────

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        # Notebook
        style.configure("TNotebook", background=C["bg2"], borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=C["bg3"], foreground=C["text_dim"],
                        font=("JetBrains Mono", 9, "bold"), padding=[12, 6],
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", C["bg"])],
                  foreground=[("selected", C["accent"])])
        # Combobox
        style.configure("TCombobox",
                        fieldbackground=C["bg"], background=C["bg3"],
                        foreground=C["text_bright"], arrowcolor=C["accent"],
                        bordercolor=C["border"], lightcolor=C["border"],
                        darkcolor=C["border"])
        style.map("TCombobox",
                  fieldbackground=[("readonly", C["bg"])],
                  selectbackground=[("readonly", C["bg3"])],
                  selectforeground=[("readonly", C["accent"])])
        self.option_add("*TCombobox*Listbox*Background", C["bg"])
        self.option_add("*TCombobox*Listbox*Foreground", C["text_bright"])
        self.option_add("*TCombobox*Listbox*selectBackground", C["accent_dim"])
        self.option_add("*TCombobox*Listbox*selectForeground", C["bg"])
        self.option_add("*TCombobox*Listbox*Font", ("JetBrains Mono", 9))

    # ─── Widget helpers ───────────────────────────────────────────────────────

    def _frame(self, parent, bg=None, **kw):
        return tk.Frame(parent, bg=bg or C["bg2"], **kw)

    def _label(self, parent, text, size=9, bold=False, fg=None, bg=None):
        font = ("JetBrains Mono", size, "bold") if bold else ("JetBrains Mono", size)
        return tk.Label(parent, text=text, font=font,
                        fg=fg or C["text"], bg=bg or C["bg2"])

    def _section(self, parent, title):
        f = tk.Frame(parent, bg=C["bg2"])
        f.pack(fill="x", pady=(10, 2), padx=4)
        tk.Label(f, text=f"──  {title}",
                 font=("JetBrains Mono", 8, "bold"),
                 fg=C["accent_dim"], bg=C["bg2"]).pack(anchor="w")
        return f

    def _entry(self, parent, default="", width=None):
        e = tk.Entry(parent, font=FONT_MONO_S,
                     fg=C["text_bright"], bg=C["bg"],
                     insertbackground=C["accent"], relief="flat", bd=5,
                     highlightthickness=1,
                     highlightcolor=C["accent2"],
                     highlightbackground=C["border"])
        if default:
            e.insert(0, default)
        if width:
            e.config(width=width)
        return e

    def _combo(self, parent, values, default=0):
        v = tk.StringVar(value=values[default] if values else "")
        c = ttk.Combobox(parent, textvariable=v, values=values,
                         font=FONT_MONO_S, state="readonly")
        c._var = v
        return c

    def _check(self, parent, label, default=False):
        v = tk.BooleanVar(value=default)
        c = tk.Checkbutton(parent, text=label, variable=v,
                           font=FONT_MONO_S,
                           fg=C["text"], bg=C["bg2"],
                           activebackground=C["bg2"],
                           activeforeground=C["accent"],
                           selectcolor=C["bg3"], relief="flat", cursor="hand2")
        c._var = v
        return c

    def _row(self, parent, label, widget_fn, **kw):
        row = tk.Frame(parent, bg=C["bg2"])
        row.pack(fill="x", padx=4, pady=2)
        tk.Label(row, text=label, font=FONT_MONO_S,
                 fg=C["text"], bg=C["bg2"], width=15, anchor="w").pack(side="left")
        w = widget_fn(row, **kw)
        w.pack(side="left", fill="x", expand=True)
        return w

    def _button(self, parent, text, command, variant="primary"):
        colors = {
            "primary":   (C["accent"],    C["bg"],     "#00cc7a"),
            "secondary": (C["bg4"],       C["text"],   C["bg3"]),
            "danger":    (C["red"],       "#fff",      "#cc0033"),
            "ghost":     (C["bg2"],       C["text_dim"], C["bg3"]),
            "accent2":   (C["accent2"],   C["bg"],     "#0088cc"),
        }
        bg, fg, active = colors.get(variant, colors["primary"])
        font = ("JetBrains Mono", 9, "bold") if variant != "ghost" else ("JetBrains Mono", 9)
        return tk.Button(parent, text=text, command=command,
                         font=font, fg=fg, bg=bg,
                         activebackground=active, activeforeground=fg,
                         relief="flat", cursor="hand2", bd=0)

    # ─── UI Layout ────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Top bar
        top = tk.Frame(self, bg=C["bg2"], height=50)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        tk.Label(top, text="⬡ PENTOOL",
                 font=("JetBrains Mono", 16, "bold"),
                 fg=C["accent"], bg=C["bg2"]).pack(side="left", padx=18)

        tk.Label(top, text="v2 // Ethical Hacking Toolkit // by 1SrD",
                 font=("JetBrains Mono", 8),
                 fg=C["text_dim"], bg=C["bg2"]).pack(side="left")

        # Session indicator
        self._session_label = tk.Label(top, text="",
                                       font=("JetBrains Mono", 9, "bold"),
                                       fg=C["accent2"], bg=C["bg2"])
        self._session_label.pack(side="right", padx=18)

        # Status bar
        self._status_var = tk.StringVar(value="  ● Ready")
        self._status_bar = tk.Label(self, textvariable=self._status_var,
                                    font=("JetBrains Mono", 9),
                                    fg=C["text_dim"], bg=C["bg2"], anchor="w", padx=14)
        self._status_bar.pack(fill="x", side="bottom", ipady=6)

        # Main 3-column layout: sessions | modules | terminal+panels
        main = tk.PanedWindow(self, orient="horizontal",
                              bg=C["border"], sashwidth=3, sashrelief="flat")
        main.pack(fill="both", expand=True)

        # Left: sessions sidebar
        sessions_frame = tk.Frame(main, bg=C["bg2"], width=200)
        main.add(sessions_frame, minsize=180)

        # Center: module tabs
        center = tk.Frame(main, bg=C["bg2"], width=440)
        main.add(center, minsize=420)

        # Right: terminal + panels
        right = tk.Frame(main, bg=C["bg"])
        main.add(right, minsize=550)

        self._build_sessions_sidebar(sessions_frame)
        self._build_center_tabs(center)
        self._build_right_panel(right)

    # ─── Sessions sidebar ─────────────────────────────────────────────────────

    def _build_sessions_sidebar(self, parent):
        hdr = tk.Frame(parent, bg=C["bg2"], height=35)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  SESSIONS",
                 font=("JetBrains Mono", 8, "bold"),
                 fg=C["accent_dim"], bg=C["bg2"]).pack(side="left", padx=10, pady=8)

        # Session listbox
        lb_wrap = tk.Frame(parent, bg=C["bg"])
        lb_wrap.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        self._sessions_lb = tk.Listbox(lb_wrap,
                                       font=FONT_MONO_S,
                                       fg=C["text"], bg=C["bg"],
                                       selectbackground=C["accent_dim"],
                                       selectforeground=C["bg"],
                                       activestyle="none",
                                       relief="flat", bd=0,
                                       highlightthickness=0)
        self._sessions_lb.pack(fill="both", expand=True)
        self._sessions_lb.bind("<<ListboxSelect>>", self._on_session_select)
        self._sessions_lb.bind("<Double-Button-1>", lambda e: self._rename_session())

        # Target display (for active session)
        target_box = tk.Frame(parent, bg=C["bg3"])
        target_box.pack(fill="x", padx=8, pady=4)

        tk.Label(target_box, text="TARGET",
                 font=("JetBrains Mono", 7, "bold"),
                 fg=C["accent_dim"], bg=C["bg3"]).pack(anchor="w", padx=10, pady=(8, 2))

        self._target_entry = tk.Entry(target_box, font=("JetBrains Mono", 11, "bold"),
                                      fg=C["accent"], bg=C["bg"],
                                      insertbackground=C["accent"],
                                      relief="flat", bd=6,
                                      highlightthickness=1,
                                      highlightcolor=C["accent"],
                                      highlightbackground=C["border"])
        self._target_entry.pack(fill="x", padx=6, pady=(0, 8))
        self._target_entry.bind("<FocusOut>", lambda e: self._save_target())
        self._target_entry.bind("<Return>", lambda e: self._save_target())

        # Buttons
        btns = tk.Frame(parent, bg=C["bg2"])
        btns.pack(fill="x", padx=8, pady=(2, 6))

        self._button(btns, "+ New", self._new_session, "primary")\
            .pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 2))
        self._button(btns, "Del", self._delete_session, "danger")\
            .pack(side="left", fill="x", expand=True, ipady=4, padx=(2, 0))

        # Quick actions
        actions = tk.Frame(parent, bg=C["bg2"])
        actions.pack(fill="x", padx=8, pady=(2, 8))

        self._button(actions, "📊  Report", self._generate_report, "accent2")\
            .pack(fill="x", ipady=5, pady=2)

        # Platform selector
        plat_frame = tk.Frame(parent, bg=C["bg2"])
        plat_frame.pack(fill="x", padx=8, pady=(6, 8))
        tk.Label(plat_frame, text="PLATFORM",
                 font=("JetBrains Mono", 7, "bold"),
                 fg=C["accent_dim"], bg=C["bg2"]).pack(anchor="w")
        self._platform_combo = ttk.Combobox(
            plat_frame,
            values=["generic", "htb", "thm", "oscp-lab", "client-work"],
            state="readonly", font=FONT_MONO_S)
        self._platform_combo.pack(fill="x", pady=(2, 0))
        self._platform_combo.set("generic")
        self._platform_combo.bind("<<ComboboxSelected>>", lambda e: self._save_platform())

        # Notes area
        tk.Label(parent, text="  NOTES",
                 font=("JetBrains Mono", 7, "bold"),
                 fg=C["accent_dim"], bg=C["bg2"]).pack(anchor="w", padx=10, pady=(4, 2))

        self._notes_text = scrolledtext.ScrolledText(
            parent, height=8, font=FONT_MONO_S,
            fg=C["text"], bg=C["bg"],
            insertbackground=C["accent"],
            relief="flat", bd=0, padx=8, pady=6,
            wrap="word")
        self._notes_text.pack(fill="both", expand=False, padx=8, pady=(0, 8))
        self._notes_text.bind("<FocusOut>", lambda e: self._save_notes())

    # ─── Center tabs (modules) ────────────────────────────────────────────────

    def _build_center_tabs(self, parent):
        # Preset bar on top
        preset_bar = tk.Frame(parent, bg=C["bg3"])
        preset_bar.pack(fill="x")
        tk.Label(preset_bar, text="  PRESET",
                 font=("JetBrains Mono", 7, "bold"),
                 fg=C["accent_dim"], bg=C["bg3"]).pack(side="left", padx=10, pady=8)

        self._preset_combo = ttk.Combobox(preset_bar, state="readonly",
                                          font=FONT_MONO_S, width=32)
        self._preset_combo.pack(side="left", padx=4, pady=6)
        self._preset_combo.bind("<<ComboboxSelected>>", self._on_preset_select)

        self._button(preset_bar, "Load", self._load_preset, "secondary")\
            .pack(side="left", ipady=3, padx=3)
        self._button(preset_bar, "Save", self._save_preset_dialog, "secondary")\
            .pack(side="left", ipady=3, padx=3)

        # Main notebook
        self._tabs = ttk.Notebook(parent)
        self._tabs.pack(fill="both", expand=True, padx=6, pady=6)

        # Build all tabs
        self._tabs.add(self._build_nmap_tab(),     text=" NMAP ")
        self._tabs.add(self._build_recon_tab(),    text=" RECON ")
        self._tabs.add(self._build_ffuf_tab(),     text=" FFUF ")
        self._tabs.add(self._build_smb_tab(),      text=" SMB ")
        self._tabs.add(self._build_ad_tab(),       text=" AD ")
        self._tabs.add(self._build_hydra_tab(),    text=" HYDRA ")
        self._tabs.add(self._build_nikto_tab(),    text=" VULN ")
        self._tabs.add(self._build_exploit_tab(),  text=" EXPL ")
        self._tabs.add(self._build_sgen_tab(),     text=" PAYLOADS ")
        self._tabs.add(self._build_msf_tab(),      text=" MSF ")
        self._tabs.add(self._build_listener_tab(), text=" LISTENER ")
        self._tabs.add(self._build_cheats_tab(),   text=" CHEATS ")

        self._tabs.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # Action bar
        action_bar = tk.Frame(parent, bg=C["bg2"])
        action_bar.pack(fill="x", padx=6, pady=(4, 8))

        self._start_btn = self._button(action_bar, "▶  START", self._on_start, "primary")
        self._start_btn.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 3))

        self._stop_btn = self._button(action_bar, "■  STOP", self._on_stop, "danger")
        self._stop_btn.pack(side="left", fill="x", expand=True, ipady=8, padx=3)

        self._button(action_bar, "⌫  Clear", self._clear_terminal, "ghost")\
            .pack(side="left", ipady=8, padx=(3, 0))

        # Save output checkbox
        save_frame = tk.Frame(parent, bg=C["bg2"])
        save_frame.pack(fill="x", padx=10, pady=(0, 4))
        self._save_output_var = tk.BooleanVar(value=False)
        tk.Checkbutton(save_frame, text="Guardar output en fichero (output/)",
                       variable=self._save_output_var,
                       font=("JetBrains Mono", 8),
                       fg=C["text_dim"], bg=C["bg2"],
                       activebackground=C["bg2"],
                       selectcolor=C["bg3"], relief="flat").pack(anchor="w")

    # ─── Tabs ─────────────────────────────────────────────────────────────────

    def _build_nmap_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])

        self._section(f, "Scan Type")
        self._nmap_scan_type = self._row(f, "Mode", self._combo,
            values=["-sS (SYN stealth)", "-sT (TCP connect)", "-sU (UDP)"], default=0)

        self._section(f, "Ports")
        self._nmap_ports = self._row(f, "Port range", self._combo,
            values=["all (1-65535)", "top100", "top1000", "common", "custom"], default=2)
        self._nmap_custom_ports = self._row(f, "Custom", self._entry, default="80,443,8080")

        self._section(f, "Scripts & Detection")
        r = tk.Frame(f, bg=C["bg2"]); r.pack(fill="x", padx=4)
        self._nmap_sV = self._check(r, "-sV version"); self._nmap_sV.pack(side="left")
        self._nmap_sC = self._check(r, "-sC scripts"); self._nmap_sC.pack(side="left")
        r2 = tk.Frame(f, bg=C["bg2"]); r2.pack(fill="x", padx=4)
        self._nmap_O = self._check(r2, "-O   OS"); self._nmap_O.pack(side="left")
        self._nmap_A = self._check(r2, "-A   aggr."); self._nmap_A.pack(side="left")
        r3 = tk.Frame(f, bg=C["bg2"]); r3.pack(fill="x", padx=4)
        self._nmap_v = self._check(r3, "-v   verbose"); self._nmap_v.pack(side="left")
        self._nmap_xml = self._check(r3, "Save XML"); self._nmap_xml.pack(side="left")

        self._section(f, "Timing")
        self._nmap_timing = self._row(f, "Timing", self._combo,
            values=["-T0", "-T1", "-T2", "-T3 (normal)", "-T4 (aggressive)", "-T5"],
            default=4)

        # Helper for CVE auto-detection notice
        notice = tk.Frame(f, bg=C["bg3"])
        notice.pack(fill="x", padx=4, pady=(12, 4))
        tk.Label(notice,
                 text="  ℹ  Nmap output auto-parseado para Victim Panel",
                 font=("JetBrains Mono", 8),
                 fg=C["accent2"], bg=C["bg3"]).pack(anchor="w", padx=8, pady=6)
        return f

    def _build_recon_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Tool")
        self._recon_tool = self._row(f, "Tool", self._combo,
            values=["whois", "dig", "dig-axfr", "host", "theHarvester",
                    "sublist3r", "dnsrecon", "amass"], default=0)

        self._section(f, "DNS options")
        self._recon_record_type = self._row(f, "Record type", self._combo,
            values=["ANY","A","AAAA","MX","NS","TXT","CNAME","SOA"], default=0)
        self._recon_ns = self._row(f, "Nameserver", self._entry, default="")

        self._section(f, "theHarvester")
        self._recon_sources = self._row(f, "Sources", self._combo,
            values=["all", "google", "bing", "duckduckgo", "baidu", "certspotter",
                    "crtsh", "hackertarget"], default=0)
        return f

    def _build_ffuf_tab(self):
        # Scrollable frame because this tab has a lot of options
        outer = tk.Frame(self._tabs, bg=C["bg2"])
        canvas = tk.Canvas(outer, bg=C["bg2"], highlightthickness=0)
        vsb = tk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        f = tk.Frame(canvas, bg=C["bg2"])
        canvas.create_window((0, 0), window=f, anchor="nw")

        def _resize(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            # Make inner frame fill width
            canvas.itemconfig(canvas.find_all()[0], width=event.width)
        canvas.bind("<Configure>", _resize)
        f.bind("<Configure>",
               lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # ── FUZZ MODE ─────────────────────────────────────────────────────
        self._section(f, "Fuzz Mode")
        self._ffuf_fuzz_mode = self._row(f, "Mode", self._combo,
            values=[
                "directory",       # http://target/FUZZ
                "files",           # only files with extensions
                "subdomain",       # http://FUZZ.target
                "vhost",           # Host: FUZZ.target
                "parameter-get",   # ?FUZZ=test
                "parameter-value", # ?id=FUZZ
                "api",             # API endpoint discovery
                "wordpress",       # WordPress-specific paths
                "custom",          # user puts FUZZ wherever
            ], default=0)

        hint_frame = tk.Frame(f, bg=C["bg3"])
        hint_frame.pack(fill="x", padx=4, pady=(2, 4))
        self._ffuf_mode_hint = tk.Label(hint_frame,
            text="  ℹ  " + MODE_DEFAULTS["directory"]["hint"],
            font=("JetBrains Mono", 8),
            fg=C["accent2"], bg=C["bg3"],
            wraplength=380, justify="left")
        self._ffuf_mode_hint.pack(anchor="w", padx=8, pady=6)
        # On mode change: auto-fill category, wordlist, extensions, filter codes, threads
        self._ffuf_fuzz_mode.bind("<<ComboboxSelected>>",
                                   lambda e: self._on_ffuf_mode_change())

        # Optional fields for specific modes
        self._ffuf_param_name = self._row(f, "Param name", self._entry, default="id")
        self._ffuf_vhost_host = self._row(f, "VHost Host:", self._entry,
                                           default="FUZZ.target.com")

        # ── WORDLIST ───────────────────────────────────────────────────────
        self._section(f, "Wordlist")

        # Category selector
        categories = list(WORDLIST_CATEGORIES.keys())
        self._ffuf_wl_cat = self._row(f, "Category", self._combo,
            values=categories, default=0)
        self._ffuf_wl_cat.bind("<<ComboboxSelected>>",
                                lambda e: self._refresh_ffuf_wordlists())

        # Wordlist within category
        self._ffuf_wl_name = self._row(f, "Wordlist", self._combo,
            values=list(WORDLIST_CATEGORIES[categories[0]].keys()), default=0)
        self._ffuf_wl_name.bind("<<ComboboxSelected>>",
                                 lambda e: self._update_wordlist_status())

        # Status line + download button
        status_row = tk.Frame(f, bg=C["bg2"])
        status_row.pack(fill="x", padx=4, pady=(4, 2))
        self._ffuf_wl_status = tk.Label(status_row,
            text="",
            font=("JetBrains Mono", 8),
            fg=C["text_dim"], bg=C["bg2"],
            anchor="w", justify="left", wraplength=380)
        self._ffuf_wl_status.pack(side="left", fill="x", expand=True)

        download_btn_row = tk.Frame(f, bg=C["bg2"])
        download_btn_row.pack(fill="x", padx=4, pady=(0, 4))
        self._ffuf_download_btn = self._button(
            download_btn_row, "⬇  Download from SecLists",
            self._download_selected_wordlist, "accent2")
        self._ffuf_download_btn.pack(fill="x", ipady=4)

        # Custom path
        self._ffuf_custom_wl = self._row(f, "Custom path", self._entry, default="")

        # ── HTTP ───────────────────────────────────────────────────────────
        self._section(f, "HTTP")
        self._ffuf_method = self._row(f, "Method", self._combo,
            values=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
            default=0)

        # Headers (multiline)
        tk.Label(f, text="  Headers (one per line, format Key: Value)",
                 font=("JetBrains Mono", 8),
                 fg=C["text_dim"], bg=C["bg2"]).pack(anchor="w", padx=8, pady=(4, 0))
        self._ffuf_headers = scrolledtext.ScrolledText(
            f, height=3, font=FONT_MONO_S,
            fg=C["text_bright"], bg=C["bg"],
            insertbackground=C["accent"], relief="flat", bd=0,
            padx=6, pady=4, wrap="word")
        self._ffuf_headers.pack(fill="x", padx=6, pady=(0, 4))
        self._ffuf_headers.insert("1.0",
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64)")

        self._ffuf_cookies = self._row(f, "Cookies", self._entry,
            default="")

        tk.Label(f, text="  POST Body (if method != GET)",
                 font=("JetBrains Mono", 8),
                 fg=C["text_dim"], bg=C["bg2"]).pack(anchor="w", padx=8, pady=(4, 0))
        self._ffuf_body = tk.Text(f, height=2, font=FONT_MONO_S,
            fg=C["text_bright"], bg=C["bg"],
            insertbackground=C["accent"], relief="flat", bd=0,
            padx=6, pady=4, wrap="word")
        self._ffuf_body.pack(fill="x", padx=6, pady=(0, 4))

        # ── FILTERS ────────────────────────────────────────────────────────
        self._section(f, "Filters")
        self._ffuf_mc  = self._row(f, "Match codes",  self._entry, default="")
        self._ffuf_fc  = self._row(f, "Filter codes", self._entry, default="404,403")
        self._ffuf_fs  = self._row(f, "Filter size",  self._entry, default="")
        self._ffuf_fw  = self._row(f, "Filter words", self._entry, default="")
        self._ffuf_fl  = self._row(f, "Filter lines", self._entry, default="")
        self._ffuf_ext = self._row(f, "Extensions",   self._entry,
                                    default=".php,.html,.txt")

        # ── PERFORMANCE ────────────────────────────────────────────────────
        self._section(f, "Performance")
        self._ffuf_threads = self._row(f, "Threads",  self._entry, default="40")
        self._ffuf_rate    = self._row(f, "Rate/sec", self._entry, default="")
        self._ffuf_timeout = self._row(f, "Timeout",  self._entry, default="10")

        r = tk.Frame(f, bg=C["bg2"]); r.pack(fill="x", padx=4)
        self._ffuf_rec = self._check(r, "Recursion");               self._ffuf_rec.pack(side="left")
        self._ffuf_follow = self._check(r, "Follow redirects");    self._ffuf_follow.pack(side="left")
        r2 = tk.Frame(f, bg=C["bg2"]); r2.pack(fill="x", padx=4)
        self._ffuf_json = self._check(r2, "Save JSON output");     self._ffuf_json.pack(side="left")

        # Initialize status
        self._update_wordlist_status()

        return outer

    def _on_ffuf_mode_change(self):
        """
        When fuzz mode changes, auto-select:
          - Category & wordlist
          - Extensions
          - Filter codes
          - Recommended threads
          - Update hint
        User can still override any field afterwards.
        """
        mode = self._ffuf_fuzz_mode._var.get()
        defaults = MODE_DEFAULTS.get(mode, {})

        # Update hint
        self._ffuf_mode_hint.config(text="  ℹ  " + defaults.get("hint", ""))

        # Auto-select category
        cat = defaults.get("category", "")
        if cat and cat in WORDLIST_CATEGORIES:
            self._ffuf_wl_cat._var.set(cat)
            # Refresh wordlist combo for the new category
            names = list(WORDLIST_CATEGORIES[cat].keys())
            self._ffuf_wl_name["values"] = names
            # Auto-select specific wordlist
            wl = defaults.get("wordlist", "")
            if wl in names:
                self._ffuf_wl_name._var.set(wl)
            elif names:
                self._ffuf_wl_name._var.set(names[0])

        # Auto-fill extensions / filter / threads
        ext = defaults.get("extensions", "")
        self._ffuf_ext.delete(0, "end"); self._ffuf_ext.insert(0, ext)

        fc = defaults.get("filter_codes", "")
        self._ffuf_fc.delete(0, "end"); self._ffuf_fc.insert(0, fc)

        threads = defaults.get("threads", "40")
        self._ffuf_threads.delete(0, "end"); self._ffuf_threads.insert(0, threads)

        # Refresh wordlist status indicator
        self._update_wordlist_status()

    def _refresh_ffuf_wordlists(self):
        cat = self._ffuf_wl_cat._var.get()
        names = list(WORDLIST_CATEGORIES.get(cat, {}).keys())
        self._ffuf_wl_name["values"] = names
        if names:
            self._ffuf_wl_name._var.set(names[0])
        self._update_wordlist_status()

    def _update_wordlist_status(self):
        """Update status label and download button visibility."""
        cat = self._ffuf_wl_cat._var.get()
        name = self._ffuf_wl_name._var.get()
        path, source = resolve_wordlist(cat, name)

        if source == "system":
            self._ffuf_wl_status.config(
                text=f"  ✓  System: {path}",
                fg=C["success"])
            self._ffuf_download_btn.config(state="disabled")
        elif source == "cache":
            self._ffuf_wl_status.config(
                text=f"  ✓  Downloaded: {path}",
                fg=C["success"])
            self._ffuf_download_btn.config(state="disabled")
        elif source == "builtin":
            self._ffuf_wl_status.config(
                text=f"  ✓  Built-in: wordlists/{path.split('/wordlists/',1)[-1]}",
                fg=C["accent2"])
            self._ffuf_download_btn.config(state="disabled")
        elif source == "custom":
            self._ffuf_wl_status.config(
                text="  ⚙  Enter custom path below",
                fg=C["text_dim"])
            self._ffuf_download_btn.config(state="disabled")
        else:  # missing
            self._ffuf_wl_status.config(
                text=f"  ⚠  Not installed. Download or install SecLists.",
                fg=C["warning"])
            self._ffuf_download_btn.config(state="normal")

    def _download_selected_wordlist(self):
        cat = self._ffuf_wl_cat._var.get()
        name = self._ffuf_wl_name._var.get()

        self._write_terminal(f"\n  ⬇  Downloading '{name}' from SecLists...\n", "hint")
        self._set_status(f"Downloading {name}...", "running")

        def _do():
            ok, result = download_wordlist(cat, name,
                progress_cb=lambda m: self._write_terminal(f"  {m}\n", "info"))
            if ok:
                self._write_terminal(f"  ✓  Saved: {result}\n\n", "success")
                self._set_status("Download complete", "success")
            else:
                self._write_terminal(f"  ✗  Failed: {result}\n\n", "error")
                self._set_status("Download failed", "error")
            self.after(0, self._update_wordlist_status)

        threading.Thread(target=_do, daemon=True).start()

    def _build_smb_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Tool")
        self._smb_tool = self._row(f, "Tool", self._combo,
            values=["enum4linux", "smbclient-list", "smbclient-connect",
                    "smbmap", "rpcclient", "nbtscan", "nmap-smb"], default=0)

        self._section(f, "Credentials (null session = empty)")
        self._smb_user = self._row(f, "Username", self._entry, default="")
        self._smb_pass = self._row(f, "Password", self._entry, default="")

        self._section(f, "Share (for smbclient-connect)")
        self._smb_share = self._row(f, "Share", self._entry, default="")

        self._section(f, "enum4linux mode")
        self._smb_mode = self._row(f, "Mode", self._combo,
            values=["all", "users", "shares", "policy", "groups"], default=0)
        return f

    def _build_ad_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Tool")
        self._ad_tool = self._row(f, "Tool", self._combo,
            values=["cme", "netexec", "kerbrute-enum", "kerbrute-spray",
                    "GetNPUsers", "GetUserSPNs", "secretsdump", "bloodhound"],
            default=1)

        self._section(f, "Domain & Creds")
        self._ad_domain = self._row(f, "Domain", self._entry, default="")
        self._ad_user = self._row(f, "Username", self._entry, default="")
        self._ad_pass = self._row(f, "Password", self._entry, default="")
        self._ad_hash = self._row(f, "NTLM hash", self._entry, default="")

        self._section(f, "CME/Netexec")
        self._ad_proto = self._row(f, "Protocol", self._combo,
            values=["smb", "winrm", "ldap", "ssh", "mssql", "wmi", "rdp"], default=0)
        self._ad_action = self._row(f, "Action", self._combo,
            values=["enum", "shares", "users", "pass-pol", "sessions",
                    "loggedon-users", "local-auth", "sam", "lsa", "ntds"],
            default=0)

        self._section(f, "Kerbrute")
        self._ad_userlist = self._row(f, "User list", self._entry,
            default="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt")
        return f

    def _build_hydra_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Tool & Protocol")
        self._hydra_tool = self._row(f, "Tool", self._combo,
            values=["hydra", "medusa"], default=0)
        self._hydra_proto = self._row(f, "Protocol", self._combo,
            values=PROTOCOLS, default=0)
        # Auto-fill on protocol change
        self._hydra_proto.bind("<<ComboboxSelected>>",
                               lambda e: self._on_hydra_proto_change())

        # Hint line
        hint_frame = tk.Frame(f, bg=C["bg3"])
        hint_frame.pack(fill="x", padx=4, pady=(2, 4))
        self._hydra_hint = tk.Label(hint_frame,
            text="  ℹ  " + PROTOCOL_DEFAULTS.get(PROTOCOLS[0], {}).get("hint",""),
            font=("JetBrains Mono", 8),
            fg=C["accent2"], bg=C["bg3"],
            wraplength=380, justify="left")
        self._hydra_hint.pack(anchor="w", padx=8, pady=6)

        self._hydra_port = self._row(f, "Port", self._entry,
            default=PROTOCOL_DEFAULTS.get(PROTOCOLS[0], {}).get("port","22"))

        self._section(f, "Credentials")
        self._hydra_user = self._row(f, "Username", self._entry,
            default=PROTOCOL_DEFAULTS.get(PROTOCOLS[0], {}).get("username","admin"))

        ulist_keys = list(COMMON_WORDLISTS.keys())
        self._hydra_ulist_combo = self._row(f, "User list", self._combo,
            values=ulist_keys, default=0)
        plist_keys = list(COMMON_WORDLISTS.keys())
        self._hydra_plist_combo = self._row(f, "Pass list", self._combo,
            values=plist_keys, default=1)
        self._hydra_custom_plist = self._row(f, "Custom path", self._entry, default="")
        self._hydra_pass = self._row(f, "Single pass", self._entry, default="")

        self._section(f, "HTTP Form (solo si protocol = http-post-form)")
        self._hydra_fpath = self._row(f, "Form path", self._entry, default="/login")
        self._hydra_fparams = self._row(f, "Params", self._entry,
            default="username=^USER^&password=^PASS^")
        self._hydra_ffail = self._row(f, "Fail string", self._entry, default="Invalid")

        self._section(f, "Options")
        self._hydra_threads = self._row(f, "Threads", self._entry,
            default=PROTOCOL_DEFAULTS.get(PROTOCOLS[0], {}).get("threads","16"))
        r = tk.Frame(f, bg=C["bg2"]); r.pack(fill="x", padx=4)
        self._hydra_stop = self._check(r, "Stop on success", default=True)
        self._hydra_stop.pack(side="left")
        return f

    def _on_hydra_proto_change(self):
        """Auto-fill port, username, threads based on selected protocol."""
        proto = self._hydra_proto._var.get()
        defaults = PROTOCOL_DEFAULTS.get(proto, {})

        self._hydra_hint.config(text="  ℹ  " + defaults.get("hint", ""))

        port = defaults.get("port", "")
        self._hydra_port.delete(0, "end"); self._hydra_port.insert(0, port)

        user = defaults.get("username", "")
        self._hydra_user.delete(0, "end"); self._hydra_user.insert(0, user)

        threads = defaults.get("threads", "16")
        self._hydra_threads.delete(0, "end"); self._hydra_threads.insert(0, threads)

    def _build_nikto_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Tool")
        self._nikto_tool = self._row(f, "Tool", self._combo,
            values=["nikto", "nuclei"], default=1)

        self._section(f, "Nikto")
        self._nikto_port = self._row(f, "Port", self._entry, default="")
        r = tk.Frame(f, bg=C["bg2"]); r.pack(fill="x", padx=4)
        self._nikto_ssl = self._check(r, "Force SSL"); self._nikto_ssl.pack(side="left")
        self._nikto_fr = self._check(r, "Follow redirects"); self._nikto_fr.pack(side="left")

        self._section(f, "Nuclei - Severity")
        sev = tk.Frame(f, bg=C["bg2"]); sev.pack(fill="x", padx=4)
        self._nuclei_sev = {}
        for s in NUCLEI_SEVERITIES:
            v = tk.BooleanVar(value=(s in ["critical", "high"]))
            tk.Checkbutton(sev, text=s, variable=v,
                           font=("JetBrains Mono", 8),
                           fg=C["text"], bg=C["bg2"],
                           activebackground=C["bg2"],
                           selectcolor=C["bg3"], relief="flat").pack(side="left", padx=2)
            self._nuclei_sev[s] = v

        self._section(f, "Nuclei - Tags")
        self._nuclei_tags = self._row(f, "Tags", self._entry, default="cve,rce,lfi")
        self._nuclei_rate = self._row(f, "Rate limit", self._entry, default="150")
        r2 = tk.Frame(f, bg=C["bg2"]); r2.pack(fill="x", padx=4)
        self._nuclei_json = self._check(r2, "JSON export"); self._nuclei_json.pack(side="left")
        return f

    def _build_exploit_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Tool")
        self._expl_tool = self._row(f, "Tool", self._combo,
            values=["searchsploit", "msfvenom", "download"], default=0)

        self._section(f, "Searchsploit")
        self._expl_query = self._row(f, "Query/CVE", self._entry, default="eternalblue")
        r = tk.Frame(f, bg=C["bg2"]); r.pack(fill="x", padx=4)
        self._expl_cve = self._check(r, "Search by CVE"); self._expl_cve.pack(side="left")
        self._expl_exact = self._check(r, "Exact match"); self._expl_exact.pack(side="left")

        self._section(f, "Msfvenom payload generator")
        self._expl_payload = self._row(f, "Payload", self._combo,
            values=[
                "linux/x64/shell_reverse_tcp",
                "linux/x64/meterpreter/reverse_tcp",
                "windows/x64/shell_reverse_tcp",
                "windows/x64/meterpreter/reverse_tcp",
                "windows/shell_reverse_tcp",
                "windows/meterpreter/reverse_tcp",
                "php/reverse_php",
                "java/jsp_shell_reverse_tcp",
                "java/shell_reverse_tcp",
                "python/shell_reverse_tcp",
            ], default=0)
        self._expl_fmt = self._row(f, "Format", self._combo,
            values=["elf", "exe", "dll", "asp", "aspx", "jsp", "war",
                    "raw", "py", "ps1"], default=0)
        self._expl_lhost = self._row(f, "LHOST", self._entry, default="10.10.14.1")
        self._expl_lport = self._row(f, "LPORT", self._entry, default="4444")
        self._expl_encoder = self._row(f, "Encoder", self._combo,
            values=["(none)", "x86/shikata_ga_nai", "x64/xor", "cmd/powershell_base64"],
            default=0)

        self._section(f, "Download privesc scripts")
        self._expl_script = self._row(f, "Script", self._combo,
            values=list(PRIVESC_SCRIPTS.keys()), default=0)
        return f

    def _build_sgen_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Payload Type")
        script_list = list(SCRIPTS.keys())

        lb_frame = tk.Frame(f, bg=C["bg"])
        lb_frame.pack(fill="x", padx=4, pady=4)
        sb = tk.Scrollbar(lb_frame, orient="vertical")
        self._sgen_lb = tk.Listbox(lb_frame,
                                    listvariable=tk.StringVar(value=script_list),
                                    font=FONT_MONO_S,
                                    fg=C["text"], bg=C["bg"],
                                    selectbackground=C["accent_dim"],
                                    selectforeground=C["bg"],
                                    relief="flat", height=8,
                                    yscrollcommand=sb.set,
                                    highlightthickness=0)
        sb.config(command=self._sgen_lb.yview)
        self._sgen_lb.pack(side="left", fill="x", expand=True)
        sb.pack(side="right", fill="y")
        self._sgen_lb.selection_set(0)

        self._section(f, "Parameters")
        self._sgen_lhost = self._row(f, "LHOST", self._entry, default="10.10.14.1")
        self._sgen_lport = self._row(f, "LPORT", self._entry, default="4444")
        self._sgen_domain = self._row(f, "Domain", self._entry, default="example.com")
        self._sgen_fname = self._row(f, "Filename", self._entry, default="shell")
        self._sgen_param = self._row(f, "PHP param", self._entry, default="cmd")

        btn = tk.Frame(f, bg=C["bg2"]); btn.pack(fill="x", padx=4, pady=6)
        self._button(btn, "Preview", self._preview_script, "accent2")\
            .pack(side="left", ipady=5, fill="x", expand=True, padx=(0, 3))
        self._button(btn, "Save", self._save_script_file, "secondary")\
            .pack(side="left", ipady=5, fill="x", expand=True)
        return f

    def _build_msf_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Action")
        self._msf_action = self._row(f, "Action", self._combo,
            values=["search exploits", "run exploit", "generate RC script"], default=0)

        self._section(f, "Search")
        self._msf_search_type = self._row(f, "Type", self._combo,
            values=["keyword", "cve", "platform", "type"], default=0)
        self._msf_query = self._row(f, "Query", self._entry, default="eternalblue")

        self._section(f, "Exploit Options")
        self._msf_module = self._row(f, "Module", self._entry,
            default="exploit/windows/smb/ms17_010_eternalblue")
        self._msf_payload = self._row(f, "Payload", self._entry,
            default="windows/x64/shell_reverse_tcp")
        self._msf_lhost = self._row(f, "LHOST", self._entry, default="10.10.14.1")
        self._msf_lport = self._row(f, "LPORT", self._entry, default="4444")
        self._msf_extra = self._row(f, "Extra opts", self._entry, default="")
        return f

    def _build_listener_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])

        self._section(f, "Listener")
        # Show local IPs
        ips = get_local_ips()
        ip_info = tk.Frame(f, bg=C["bg3"])
        ip_info.pack(fill="x", padx=4, pady=(2, 8))
        tk.Label(ip_info, text="  📡  YOUR IPs:",
                 font=("JetBrains Mono", 8, "bold"),
                 fg=C["accent_dim"], bg=C["bg3"]).pack(anchor="w", padx=8, pady=(6, 0))
        for ip in ips:
            tk.Label(ip_info, text=f"     {ip}",
                     font=("JetBrains Mono", 9),
                     fg=C["accent"], bg=C["bg3"]).pack(anchor="w", padx=8)
        tk.Label(ip_info, text=" ", bg=C["bg3"]).pack(pady=2)

        self._listener_port = self._row(f, "Port", self._entry, default="4444")
        r = tk.Frame(f, bg=C["bg2"]); r.pack(fill="x", padx=4)
        self._listener_rlwrap = self._check(r, "Use rlwrap (better line edit)", default=True)
        self._listener_rlwrap.pack(side="left")

        btn = tk.Frame(f, bg=C["bg2"]); btn.pack(fill="x", padx=4, pady=8)
        self._button(btn, "▶ Start Listener", self._start_listener, "primary")\
            .pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 3))
        self._button(btn, "■ Stop", self._stop_listener, "danger")\
            .pack(side="left", fill="x", expand=True, ipady=6)

        self._section(f, "Reverse Shell Payloads")
        payload_frame = tk.Frame(f, bg=C["bg3"])
        payload_frame.pack(fill="x", padx=4, pady=4)

        self._payload_lb_var = tk.StringVar(value=list(REVERSE_SHELL_PAYLOADS.keys()))
        lb_wrap = tk.Frame(payload_frame, bg=C["bg"])
        lb_wrap.pack(fill="x", padx=4, pady=4)
        sb = tk.Scrollbar(lb_wrap, orient="vertical")
        self._payload_lb = tk.Listbox(lb_wrap, listvariable=self._payload_lb_var,
                                       font=FONT_MONO_S, fg=C["text"], bg=C["bg"],
                                       selectbackground=C["accent_dim"],
                                       selectforeground=C["bg"],
                                       relief="flat", height=6, bd=0,
                                       highlightthickness=0,
                                       yscrollcommand=sb.set)
        sb.config(command=self._payload_lb.yview)
        self._payload_lb.pack(side="left", fill="x", expand=True)
        sb.pack(side="right", fill="y")
        self._payload_lb.selection_set(0)

        self._button(payload_frame, "Show payload (LHOST=your_ip, LPORT=port)",
                     self._show_payload, "secondary")\
            .pack(fill="x", padx=4, pady=(0, 6), ipady=4)

        self._section(f, "TTY Upgrade Commands")
        tty_frame = tk.Frame(f, bg=C["bg3"])
        tty_frame.pack(fill="x", padx=4, pady=4)
        for label, cmd in TTY_UPGRADE_COMMANDS:
            row = tk.Frame(tty_frame, bg=C["bg3"])
            row.pack(fill="x", padx=6, pady=2)
            tk.Label(row, text=f"  {label}:",
                     font=("JetBrains Mono", 8, "bold"),
                     fg=C["accent2"], bg=C["bg3"], anchor="w").pack(anchor="w")
            entry = tk.Entry(row, font=FONT_MONO_S,
                             fg=C["text_bright"], bg=C["bg"], relief="flat", bd=4,
                             readonlybackground=C["bg"])
            entry.insert(0, cmd)
            entry.config(state="readonly")
            entry.pack(fill="x", pady=(0, 2))
        return f

    def _build_cheats_tab(self):
        f = tk.Frame(self._tabs, bg=C["bg2"])
        self._section(f, "Cheatsheets")
        cheat_list = list_cheatsheets()

        lb_frame = tk.Frame(f, bg=C["bg"])
        lb_frame.pack(fill="x", padx=4, pady=4)
        self._cheat_lb = tk.Listbox(lb_frame,
                                     listvariable=tk.StringVar(value=cheat_list),
                                     font=FONT_MONO_S,
                                     fg=C["text"], bg=C["bg"],
                                     selectbackground=C["accent_dim"],
                                     selectforeground=C["bg"],
                                     relief="flat", height=10, bd=0,
                                     highlightthickness=0)
        self._cheat_lb.pack(fill="x")
        self._cheat_lb.selection_set(0)

        self._button(f, "Show in Terminal", self._show_cheatsheet, "primary")\
            .pack(fill="x", padx=4, pady=6, ipady=6)

        return f

    # ─── Right panel: terminal + victim panel + findings ──────────────────────

    def _build_right_panel(self, parent):
        # Notebook with: Terminal, Victim Panel, Findings, History
        self._right_tabs = ttk.Notebook(parent)
        self._right_tabs.pack(fill="both", expand=True, padx=2, pady=2)

        # Terminal
        term_frame = tk.Frame(self._right_tabs, bg=C["bg"])
        self._right_tabs.add(term_frame, text=" TERMINAL ")
        self._terminal = scrolledtext.ScrolledText(
            term_frame, font=FONT_MONO, bg=C["bg"], fg=C["text"],
            insertbackground=C["accent"], relief="flat", bd=0,
            state="disabled", wrap="word", padx=12, pady=10)
        self._terminal.pack(fill="both", expand=True)
        self._configure_terminal_tags()
        self._print_welcome()

        # Victim Panel
        victim_frame = tk.Frame(self._right_tabs, bg=C["bg"])
        self._right_tabs.add(victim_frame, text=" VICTIM ")
        self._build_victim_panel(victim_frame)

        # Findings
        find_frame = tk.Frame(self._right_tabs, bg=C["bg"])
        self._right_tabs.add(find_frame, text=" FINDINGS ")
        self._build_findings_panel(find_frame)

        # History
        hist_frame = tk.Frame(self._right_tabs, bg=C["bg"])
        self._right_tabs.add(hist_frame, text=" HISTORY ")
        self._build_history_panel(hist_frame)

    def _configure_terminal_tags(self):
        t = self._terminal
        t.tag_configure("cmd",       foreground=C["accent2"], font=("JetBrains Mono", 10, "bold"))
        t.tag_configure("info",      foreground="#7b8aaa")
        t.tag_configure("output",    foreground=C["text"])
        t.tag_configure("separator", foreground=C["border"])
        t.tag_configure("success",   foreground=C["success"], font=("JetBrains Mono", 10, "bold"))
        t.tag_configure("warning",   foreground=C["warning"])
        t.tag_configure("error",     foreground=C["error"],   font=("JetBrains Mono", 10, "bold"))
        t.tag_configure("hint",      foreground=C["accent3"])
        t.tag_configure("accent",    foreground=C["accent"])

    def _print_welcome(self):
        self._write_terminal(BANNER, "accent")
        self._write_terminal("\n  v2.0  //  Ethical Hacking Toolkit  //  by 1SrD\n", "hint")
        self._write_terminal("  Sessions · Findings · Reports · Presets · Listener · Cheatsheets\n\n", "info")
        self._write_terminal("  ⚠  Use only against systems you own or are authorized to test.\n\n", "warning")

    def _build_victim_panel(self, parent):
        hdr = tk.Frame(parent, bg=C["bg2"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="  VICTIM PROFILE",
                 font=("JetBrains Mono", 9, "bold"),
                 fg=C["accent_dim"], bg=C["bg2"]).pack(side="left", padx=10, pady=8)
        self._button(hdr, "Refresh", self._refresh_victim, "ghost")\
            .pack(side="right", padx=8, ipady=3)

        self._victim_canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0)
        v_scroll = tk.Scrollbar(parent, orient="vertical", command=self._victim_canvas.yview)
        self._victim_canvas.configure(yscrollcommand=v_scroll.set)
        v_scroll.pack(side="right", fill="y")
        self._victim_canvas.pack(side="left", fill="both", expand=True)

        self._victim_inner = tk.Frame(self._victim_canvas, bg=C["bg"])
        self._victim_canvas.create_window((0, 0), window=self._victim_inner, anchor="nw")
        self._victim_inner.bind("<Configure>",
                                lambda e: self._victim_canvas.configure(
                                    scrollregion=self._victim_canvas.bbox("all")))

        self._refresh_victim()

    def _refresh_victim(self):
        # Clear
        for w in self._victim_inner.winfo_children():
            w.destroy()

        session = self.sessions.active
        if not session or not session.parsed_services:
            tk.Label(self._victim_inner,
                     text="\n  No nmap data yet.\n  Run an nmap scan with -sV to populate this panel.\n",
                     font=FONT_MONO_S, fg=C["text_dim"], bg=C["bg"],
                     justify="left").pack(anchor="w", padx=20, pady=20)
            return

        p = session.parsed_services

        # Header card
        header = tk.Frame(self._victim_inner, bg=C["bg3"])
        header.pack(fill="x", padx=12, pady=12)
        tk.Label(header, text=f"   🎯  {p.get('host','unknown')}",
                 font=("JetBrains Mono", 13, "bold"),
                 fg=C["accent"], bg=C["bg3"]).pack(anchor="w", padx=10, pady=(10, 2))
        tk.Label(header, text=f"      {p.get('ip','')}  ·  {p.get('os','OS unknown')[:60]}",
                 font=FONT_MONO_S,
                 fg=C["text_dim"], bg=C["bg3"]).pack(anchor="w", padx=10, pady=(0, 10))

        # Port cards
        for port in p.get("ports", []):
            self._render_port_card(self._victim_inner, port)

    def _render_port_card(self, parent, port):
        card = tk.Frame(parent, bg=C["bg2"])
        card.pack(fill="x", padx=12, pady=4)

        # Header row
        header = tk.Frame(card, bg=C["bg2"])
        header.pack(fill="x", padx=10, pady=(8, 4))

        tk.Label(header,
                 text=f"[{port['port']}/{port['proto']}]",
                 font=("JetBrains Mono", 10, "bold"),
                 fg=C["accent2"], bg=C["bg2"]).pack(side="left")
        tk.Label(header,
                 text=f"  {port['service'].upper()}",
                 font=("JetBrains Mono", 10, "bold"),
                 fg=C["accent"], bg=C["bg2"]).pack(side="left")
        if port["state"] == "open":
            tk.Label(header, text="  ● open",
                     font=FONT_MONO_S, fg=C["success"], bg=C["bg2"]).pack(side="left")

        if port.get("version"):
            tk.Label(card, text=f"    {port['version'][:80]}",
                     font=FONT_MONO_S, fg=C["text"], bg=C["bg2"],
                     wraplength=500, justify="left").pack(anchor="w", padx=10)

        # CVEs (red alert)
        if port.get("cves"):
            for cve in port["cves"]:
                cve_frame = tk.Frame(card, bg=C["bg2"])
                cve_frame.pack(fill="x", padx=10, pady=2)
                tk.Label(cve_frame, text="    ⚠ ",
                         font=FONT_MONO_S, fg=C["red"], bg=C["bg2"]).pack(side="left")
                tk.Label(cve_frame, text=cve[:70],
                         font=("JetBrains Mono", 8, "bold"),
                         fg=C["red"], bg=C["bg2"],
                         wraplength=450, justify="left").pack(side="left")

        # Hints
        if port.get("hints"):
            hints_frame = tk.Frame(card, bg=C["bg2"])
            hints_frame.pack(fill="x", padx=10, pady=(2, 8))
            tk.Label(hints_frame, text="    💡  hints:",
                     font=("JetBrains Mono", 8, "bold"),
                     fg=C["accent3"], bg=C["bg2"]).pack(anchor="w")
            for h in port["hints"][:3]:
                tk.Label(hints_frame, text=f"       • {h[:70]}",
                         font=FONT_MONO_S,
                         fg=C["text_dim"], bg=C["bg2"],
                         wraplength=480, justify="left").pack(anchor="w")

    def _build_findings_panel(self, parent):
        hdr = tk.Frame(parent, bg=C["bg2"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="  FINDINGS",
                 font=("JetBrains Mono", 9, "bold"),
                 fg=C["accent_dim"], bg=C["bg2"]).pack(side="left", padx=10, pady=8)

        self._button(hdr, "+ Add", self._add_finding_dialog, "primary")\
            .pack(side="right", padx=4, ipady=3)
        self._button(hdr, "Refresh", self._refresh_findings, "ghost")\
            .pack(side="right", padx=4, ipady=3)

        # Summary bar
        self._findings_summary = tk.Frame(parent, bg=C["bg2"])
        self._findings_summary.pack(fill="x", padx=8, pady=4)

        # Findings list
        self._findings_canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0)
        v_scroll = tk.Scrollbar(parent, orient="vertical",
                                command=self._findings_canvas.yview)
        self._findings_canvas.configure(yscrollcommand=v_scroll.set)
        v_scroll.pack(side="right", fill="y")
        self._findings_canvas.pack(side="left", fill="both", expand=True)

        self._findings_inner = tk.Frame(self._findings_canvas, bg=C["bg"])
        self._findings_canvas.create_window((0, 0), window=self._findings_inner, anchor="nw")
        self._findings_inner.bind("<Configure>",
                                  lambda e: self._findings_canvas.configure(
                                      scrollregion=self._findings_canvas.bbox("all")))

    def _refresh_findings(self):
        # Clear summary
        for w in self._findings_summary.winfo_children():
            w.destroy()
        for w in self._findings_inner.winfo_children():
            w.destroy()

        session = self.sessions.active
        if not session:
            return

        # Summary boxes
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in session.findings:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1

        for sev in ["critical", "high", "medium", "low", "info"]:
            box = tk.Frame(self._findings_summary, bg=C["bg3"])
            box.pack(side="left", fill="x", expand=True, padx=2)
            tk.Label(box, text=str(counts[sev]),
                     font=("JetBrains Mono", 14, "bold"),
                     fg=SEVERITY_COLORS[sev], bg=C["bg3"]).pack(pady=(6, 0))
            tk.Label(box, text=sev.upper(),
                     font=("JetBrains Mono", 7),
                     fg=C["text_dim"], bg=C["bg3"]).pack(pady=(0, 6))

        if not session.findings:
            tk.Label(self._findings_inner,
                     text="\n  No findings yet. Click [+ Add] to record one.\n",
                     font=FONT_MONO_S, fg=C["text_dim"], bg=C["bg"],
                     justify="left").pack(anchor="w", padx=20, pady=20)
            return

        # Sort by severity
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(session.findings,
                         key=lambda f: order.get(f.get("severity","info"), 4))

        for finding in sorted_f:
            self._render_finding(self._findings_inner, finding)

    def _render_finding(self, parent, f):
        sev = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, C["accent2"])

        card = tk.Frame(parent, bg=C["bg2"])
        card.pack(fill="x", padx=10, pady=3)

        # Left border color strip
        strip = tk.Frame(card, bg=color, width=4)
        strip.pack(side="left", fill="y")

        inner = tk.Frame(card, bg=C["bg2"])
        inner.pack(side="left", fill="x", expand=True, padx=8, pady=8)

        # Header
        head = tk.Frame(inner, bg=C["bg2"])
        head.pack(fill="x")
        tk.Label(head, text=f"#{f.get('id','?')}  {f.get('title','(no title)')}",
                 font=("JetBrains Mono", 10, "bold"),
                 fg=C["text_bright"], bg=C["bg2"],
                 wraplength=400, justify="left").pack(side="left")
        tk.Label(head, text=sev.upper(),
                 font=("JetBrains Mono", 8, "bold"),
                 fg=color, bg=C["bg2"]).pack(side="right")

        if f.get("description"):
            tk.Label(inner, text=f.get("description","")[:200],
                     font=FONT_MONO_S, fg=C["text"], bg=C["bg2"],
                     wraplength=500, justify="left").pack(anchor="w", pady=(4, 0))

        # Delete button
        del_btn = tk.Button(inner, text="✕",
                            font=("JetBrains Mono", 9),
                            fg=C["text_dim"], bg=C["bg2"],
                            activebackground=C["red"], activeforeground="#fff",
                            relief="flat", cursor="hand2", bd=0,
                            command=lambda fid=f.get("id"): self._delete_finding(fid))
        del_btn.pack(anchor="ne", pady=(4, 0))

    def _build_history_panel(self, parent):
        hdr = tk.Frame(parent, bg=C["bg2"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="  COMMAND HISTORY",
                 font=("JetBrains Mono", 9, "bold"),
                 fg=C["accent_dim"], bg=C["bg2"]).pack(side="left", padx=10, pady=8)
        self._button(hdr, "Refresh", self._refresh_history, "ghost")\
            .pack(side="right", padx=4, ipady=3)

        self._hist_canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0)
        v_scroll = tk.Scrollbar(parent, orient="vertical",
                                command=self._hist_canvas.yview)
        self._hist_canvas.configure(yscrollcommand=v_scroll.set)
        v_scroll.pack(side="right", fill="y")
        self._hist_canvas.pack(side="left", fill="both", expand=True)

        self._hist_inner = tk.Frame(self._hist_canvas, bg=C["bg"])
        self._hist_canvas.create_window((0, 0), window=self._hist_inner, anchor="nw")
        self._hist_inner.bind("<Configure>",
                              lambda e: self._hist_canvas.configure(
                                  scrollregion=self._hist_canvas.bbox("all")))

    def _refresh_history(self):
        for w in self._hist_inner.winfo_children():
            w.destroy()
        session = self.sessions.active
        if not session or not session.history:
            tk.Label(self._hist_inner,
                     text="\n  No commands executed yet.\n",
                     font=FONT_MONO_S, fg=C["text_dim"], bg=C["bg"]).pack(anchor="w", padx=20, pady=20)
            return

        for h in reversed(session.history[-80:]):
            self._render_history_item(self._hist_inner, h)

    def _render_history_item(self, parent, h):
        card = tk.Frame(parent, bg=C["bg2"])
        card.pack(fill="x", padx=10, pady=2)

        exit_code = h.get("exit_code", 0)
        color = C["success"] if exit_code == 0 else C["warning"] if exit_code > 0 else C["error"]

        head = tk.Frame(card, bg=C["bg2"])
        head.pack(fill="x", padx=10, pady=(6, 2))

        tk.Label(head, text=f"[{h.get('module','?').upper()}]",
                 font=("JetBrains Mono", 8, "bold"),
                 fg=C["accent3"], bg=C["bg2"]).pack(side="left")
        tk.Label(head, text=h.get("timestamp","")[:19].replace("T", " "),
                 font=("JetBrains Mono", 8),
                 fg=C["text_dim"], bg=C["bg2"]).pack(side="left", padx=8)
        tk.Label(head, text=f"● exit {exit_code}",
                 font=("JetBrains Mono", 8),
                 fg=color, bg=C["bg2"]).pack(side="right")

        cmd_label = tk.Label(card, text=f"  $ {h.get('command','')}",
                             font=FONT_MONO_S,
                             fg=C["accent2"], bg=C["bg2"],
                             wraplength=500, justify="left", anchor="w")
        cmd_label.pack(fill="x", padx=10, pady=(0, 6))

        # Re-run button on hover? Just click
        cmd_label.bind("<Button-1>",
                       lambda e, c=h.get("command",""): self._rerun_command(c))

    # ─── Terminal helpers ─────────────────────────────────────────────────────

    def _write_terminal(self, text, tag="output"):
        def _do():
            self._terminal.config(state="normal")
            self._terminal.insert("end", text, tag)
            self._terminal.see("end")
            self._terminal.config(state="disabled")
        self.after(0, _do)

    def _clear_terminal(self):
        self._terminal.config(state="normal")
        self._terminal.delete("1.0", "end")
        self._terminal.config(state="disabled")
        self._print_welcome()

    def _set_status(self, msg, level="info"):
        color_map = {
            "info":    C["text_dim"],
            "running": C["accent2"],
            "success": C["success"],
            "error":   C["error"],
            "warning": C["warning"],
        }
        def _do():
            self._status_var.set(f"  ●  {msg}")
            self._status_bar.config(fg=color_map.get(level, C["text_dim"]))
        self.after(0, _do)

    # ─── Session management ───────────────────────────────────────────────────

    def _refresh_session_list(self):
        self._sessions_lb.delete(0, "end")
        names = self.sessions.list_names()
        for name in names:
            s = self.sessions.sessions[name]
            marker = "● " if self.sessions.active and self.sessions.active.name == name else "  "
            display = f"{marker}{name}"
            if s.target:
                display += f"  · {s.target[:15]}"
            self._sessions_lb.insert("end", display)

        if self.sessions.active:
            idx = names.index(self.sessions.active.name)
            self._sessions_lb.selection_set(idx)
            self._target_entry.delete(0, "end")
            self._target_entry.insert(0, self.sessions.active.target)
            self._notes_text.delete("1.0", "end")
            self._notes_text.insert("1.0", self.sessions.active.notes)
            self._platform_combo.set(self.sessions.active.platform)
            self._session_label.config(text=f"  SESSION  {self.sessions.active.name}")

    def _on_session_select(self, event):
        sel = self._sessions_lb.curselection()
        if not sel:
            return
        display = self._sessions_lb.get(sel[0]).strip()
        name = display.replace("●", "").strip().split("  ·")[0].strip()
        if name in self.sessions.sessions:
            self.sessions.set_active(name)
            self._refresh_session_list()
            self._refresh_victim()
            self._refresh_findings()
            self._refresh_history()

    def _new_session(self):
        name = simpledialog.askstring("New Session", "Session name:",
                                       parent=self)
        if not name:
            return
        target = simpledialog.askstring("New Session", "Target (IP/URL, optional):",
                                         parent=self) or ""
        self.sessions.create(name, target)
        self.sessions.set_active(name)
        self._refresh_session_list()
        self._refresh_victim()
        self._refresh_findings()
        self._refresh_history()

    def _delete_session(self):
        if not self.sessions.active:
            return
        if len(self.sessions.sessions) <= 1:
            messagebox.showwarning("Cannot delete",
                                   "At least one session must exist.")
            return
        if messagebox.askyesno("Delete session",
                               f"Delete session '{self.sessions.active.name}'? This cannot be undone."):
            name = self.sessions.active.name
            self.sessions.delete(name)
            first = self.sessions.list_names()[0]
            self.sessions.set_active(first)
            self._refresh_session_list()
            self._refresh_victim()
            self._refresh_findings()
            self._refresh_history()

    def _rename_session(self):
        if not self.sessions.active:
            return
        new = simpledialog.askstring("Rename",
                                      f"New name for '{self.sessions.active.name}':",
                                      parent=self)
        if new:
            self.sessions.rename(self.sessions.active.name, new)
            self._refresh_session_list()

    def _save_target(self):
        if self.sessions.active:
            self.sessions.active.target = self._target_entry.get().strip()
            self.sessions.save_active()
            self._refresh_session_list()

    def _save_notes(self):
        if self.sessions.active:
            self.sessions.active.notes = self._notes_text.get("1.0", "end").strip()
            self.sessions.save_active()

    def _save_platform(self):
        if self.sessions.active:
            self.sessions.active.platform = self._platform_combo.get()
            self.sessions.save_active()

    # ─── Findings management ──────────────────────────────────────────────────

    def _add_finding_dialog(self):
        if not self.sessions.active:
            return
        dialog = tk.Toplevel(self)
        dialog.title("Add Finding")
        dialog.geometry("600x500")
        dialog.configure(bg=C["bg2"])
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(dialog, text="Add Finding",
                 font=("JetBrains Mono", 14, "bold"),
                 fg=C["accent"], bg=C["bg2"]).pack(pady=10)

        # Title
        tk.Label(dialog, text="Title",
                 font=FONT_MONO_S, fg=C["text"], bg=C["bg2"]).pack(anchor="w", padx=20)
        title_e = tk.Entry(dialog, font=FONT_MONO,
                           fg=C["text_bright"], bg=C["bg"],
                           insertbackground=C["accent"], relief="flat", bd=5)
        title_e.pack(fill="x", padx=20, pady=(2, 8))

        # Severity
        tk.Label(dialog, text="Severity",
                 font=FONT_MONO_S, fg=C["text"], bg=C["bg2"]).pack(anchor="w", padx=20)
        sev_v = tk.StringVar(value="medium")
        sev_frame = tk.Frame(dialog, bg=C["bg2"])
        sev_frame.pack(fill="x", padx=20, pady=(2, 8))
        for s in ["critical", "high", "medium", "low", "info"]:
            tk.Radiobutton(sev_frame, text=s, variable=sev_v, value=s,
                           font=FONT_MONO_S,
                           fg=SEVERITY_COLORS[s], bg=C["bg2"],
                           activebackground=C["bg2"],
                           selectcolor=C["bg3"],
                           relief="flat").pack(side="left", padx=4)

        # Description
        tk.Label(dialog, text="Description",
                 font=FONT_MONO_S, fg=C["text"], bg=C["bg2"]).pack(anchor="w", padx=20)
        desc_t = scrolledtext.ScrolledText(dialog, height=4, font=FONT_MONO_S,
                                           fg=C["text_bright"], bg=C["bg"],
                                           relief="flat", bd=0, padx=8, pady=6)
        desc_t.pack(fill="x", padx=20, pady=(2, 8))

        # Evidence
        tk.Label(dialog, text="Evidence (command output, screenshots, etc.)",
                 font=FONT_MONO_S, fg=C["text"], bg=C["bg2"]).pack(anchor="w", padx=20)
        ev_t = scrolledtext.ScrolledText(dialog, height=5, font=FONT_MONO_S,
                                          fg=C["text_bright"], bg=C["bg"],
                                          relief="flat", bd=0, padx=8, pady=6)
        ev_t.pack(fill="x", padx=20, pady=(2, 8))

        # Recommendation
        tk.Label(dialog, text="Recommendation",
                 font=FONT_MONO_S, fg=C["text"], bg=C["bg2"]).pack(anchor="w", padx=20)
        rec_t = scrolledtext.ScrolledText(dialog, height=3, font=FONT_MONO_S,
                                           fg=C["text_bright"], bg=C["bg"],
                                           relief="flat", bd=0, padx=8, pady=6)
        rec_t.pack(fill="x", padx=20, pady=(2, 8))

        # Buttons
        btns = tk.Frame(dialog, bg=C["bg2"])
        btns.pack(fill="x", padx=20, pady=12)

        def save():
            title = title_e.get().strip()
            if not title:
                messagebox.showwarning("Missing", "Title is required.")
                return
            self.sessions.active.add_finding(
                title=title,
                severity=sev_v.get(),
                description=desc_t.get("1.0", "end").strip(),
                evidence=ev_t.get("1.0", "end").strip(),
                recommendation=rec_t.get("1.0", "end").strip(),
            )
            self.sessions.save_active()
            self._refresh_findings()
            dialog.destroy()

        self._button(btns, "Save", save, "primary")\
            .pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 4))
        self._button(btns, "Cancel", dialog.destroy, "secondary")\
            .pack(side="left", fill="x", expand=True, ipady=8)

    def _delete_finding(self, fid):
        if not self.sessions.active:
            return
        self.sessions.active.findings = [
            f for f in self.sessions.active.findings if f.get("id") != fid]
        self.sessions.save_active()
        self._refresh_findings()

    # ─── Preset management ────────────────────────────────────────────────────

    def _on_tab_changed(self, event):
        # Update preset list based on active tab
        mod = self._active_module_name()
        self._refresh_preset_combo(mod)

    def _active_module_name(self):
        tab_idx = self._tabs.index("current")
        # Must match the order in _build_center_tabs
        names = ["nmap", "recon", "ffuf", "smb", "ad", "hydra", "nikto",
                 "exploit", "sgen", "msf", "listener", "cheats"]
        return names[tab_idx] if tab_idx < len(names) else ""

    def _refresh_preset_combo(self, module):
        presets = {k: v for k, v in self.presets.all().items()
                   if v["module"] == module}
        values = ["(none)"] + list(presets.keys())
        self._preset_combo["values"] = values
        self._preset_combo.set("(none)")

    def _on_preset_select(self, event):
        pass

    def _load_preset(self):
        name = self._preset_combo.get()
        if name == "(none)" or name not in self.presets.all():
            return
        preset = self.presets.all()[name]
        self._apply_preset(preset["module"], preset["options"])
        self._write_terminal(f"\n  ✓ Preset '{name}' cargado\n\n", "success")

    def _apply_preset(self, module, options):
        """Apply preset options to the UI widgets of the corresponding module."""
        if module == "nmap":
            self._set_combo_starts_with(self._nmap_scan_type, options.get("scan_type",""))
            self._set_combo_starts_with(self._nmap_ports, options.get("ports",""))
            self._set_combo_starts_with(self._nmap_timing, options.get("timing",""))
            for key, var in [("sV",self._nmap_sV), ("sC",self._nmap_sC),
                             ("O",self._nmap_O), ("A",self._nmap_A),
                             ("verbose",self._nmap_v), ("output_xml",self._nmap_xml)]:
                if key in options:
                    var._var.set(options[key])
        elif module == "ffuf":
            # Old-style preset: just try to find wordlist in any category
            if "wordlist_key" in options:
                wl_key = options["wordlist_key"]
                for cat, wls in WORDLIST_CATEGORIES.items():
                    if wl_key in wls:
                        self._ffuf_wl_cat._var.set(cat)
                        self._refresh_ffuf_wordlists()
                        self._ffuf_wl_name._var.set(wl_key)
                        self._update_wordlist_status()
                        break
            for k, w in [("extensions",self._ffuf_ext), ("filter_codes",self._ffuf_fc),
                          ("threads",self._ffuf_threads)]:
                if k in options:
                    w.delete(0, "end")
                    w.insert(0, options[k])
            if "recursion" in options:
                self._ffuf_rec._var.set(options["recursion"])
        elif module == "hydra":
            for k, w in [("protocol",self._hydra_proto), ("tool",self._hydra_tool)]:
                if k in options:
                    w._var.set(options[k])
            for k, w in [("username",self._hydra_user),("form_path",self._hydra_fpath),
                          ("form_params",self._hydra_fparams),("fail_string",self._hydra_ffail),
                          ("threads",self._hydra_threads)]:
                if k in options:
                    w.delete(0, "end"); w.insert(0, options[k])
            if "stop_on_success" in options:
                self._hydra_stop._var.set(options["stop_on_success"])
        elif module == "nikto":
            if "tool" in options:
                self._nikto_tool._var.set(options["tool"])
            if "severity" in options:
                for s, v in self._nuclei_sev.items():
                    v.set(s in options["severity"])
            if "tags" in options:
                self._nuclei_tags.delete(0, "end")
                self._nuclei_tags.insert(0, options["tags"])
            if "rate" in options:
                self._nuclei_rate.delete(0, "end")
                self._nuclei_rate.insert(0, options["rate"])

    def _set_combo_starts_with(self, combo, prefix):
        """Set combobox to first value that starts with prefix."""
        if not prefix:
            return
        for v in combo["values"]:
            if v.startswith(prefix) or prefix in v:
                combo._var.set(v)
                return

    def _save_preset_dialog(self):
        name = simpledialog.askstring("Save Preset",
                                      "Preset name:", parent=self)
        if not name:
            return
        desc = simpledialog.askstring("Save Preset",
                                      "Description:", parent=self) or ""
        module = self._active_module_name()
        # Snapshot current options - simplified
        options = self._snapshot_options(module)
        self.presets.save_preset(name, module, desc, options)
        self._refresh_preset_combo(module)
        messagebox.showinfo("Saved", f"Preset '{name}' saved.")

    def _snapshot_options(self, module):
        """Capture current widget state for a module."""
        opts = {}
        if module == "nmap":
            opts = {
                "scan_type": self._nmap_scan_type._var.get().split()[0],
                "ports": self._nmap_ports._var.get().split()[0],
                "timing": self._nmap_timing._var.get().split()[0],
                "sV": self._nmap_sV._var.get(),
                "sC": self._nmap_sC._var.get(),
                "O": self._nmap_O._var.get(),
                "A": self._nmap_A._var.get(),
                "verbose": self._nmap_v._var.get(),
                "output_xml": self._nmap_xml._var.get(),
            }
        elif module == "ffuf":
            opts = {
                "wordlist_key": self._ffuf_wl_name._var.get(),
                "fuzz_mode": self._ffuf_fuzz_mode._var.get(),
                "method": self._ffuf_method._var.get(),
                "extensions": self._ffuf_ext.get(),
                "match_codes": self._ffuf_mc.get(),
                "filter_codes": self._ffuf_fc.get(),
                "threads": self._ffuf_threads.get(),
                "recursion": self._ffuf_rec._var.get(),
            }
        return opts

    # ─── Action dispatch ──────────────────────────────────────────────────────

    def _get_target(self):
        return self._target_entry.get().strip()

    def _on_start(self):
        target = self._get_target()
        if not target and self._active_module_name() not in ("listener", "sgen", "cheats", "exploit"):
            messagebox.showwarning("No target", "Set a target IP/URL first.")
            return

        self._save_target()

        module = self._active_module_name()
        handlers = {
            "nmap":     self._run_nmap,
            "recon":    self._run_recon,
            "ffuf":     self._run_ffuf,
            "smb":      self._run_smb,
            "ad":       self._run_ad,
            "hydra":    self._run_hydra,
            "nikto":    self._run_nikto,
            "exploit":  self._run_exploit,
            "sgen":     lambda t: self._preview_script(),
            "msf":      self._run_msf,
            "listener": lambda t: self._start_listener(),
            "cheats":   lambda t: self._show_cheatsheet(),
        }
        handler = handlers.get(module)
        if handler:
            handler(target)

    def _on_stop(self):
        if self._active_module:
            self._active_module.stop()
        if self.listener:
            self.listener.stop()

    def _run_nmap(self, target):
        scan_val = self._nmap_scan_type._var.get().split()[0]
        ports_val = self._nmap_ports._var.get().split()[0]
        timing_val = self._nmap_timing._var.get().split()[0]
        options = {
            "scan_type": scan_val,
            "ports": ports_val,
            "custom_ports": self._nmap_custom_ports.get().strip(),
            "timing": timing_val,
            "sV": self._nmap_sV._var.get(),
            "sC": self._nmap_sC._var.get(),
            "O": self._nmap_O._var.get(),
            "A": self._nmap_A._var.get(),
            "verbose": self._nmap_v._var.get(),
            "output_xml": self._nmap_xml._var.get(),
        }
        m = NmapModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        m.execute(target, options, self._save_output_var.get())
        # After a delay, refresh the victim panel
        self.after(3000, self._refresh_victim)

    def _run_recon(self, target):
        options = {
            "tool": self._recon_tool._var.get(),
            "record_type": self._recon_record_type._var.get(),
            "nameserver": self._recon_ns.get().strip(),
            "sources": self._recon_sources._var.get(),
        }
        m = ReconModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        m.execute(target, options, self._save_output_var.get())

    def _run_ffuf(self, target):
        # Resolve wordlist
        cat = self._ffuf_wl_cat._var.get()
        name = self._ffuf_wl_name._var.get()
        if cat == "[custom path]":
            wordlist = self._ffuf_custom_wl.get().strip()
        else:
            wordlist, source = resolve_wordlist(cat, name)
            if source == "missing":
                self._write_terminal(
                    f"\n  ⚠  Wordlist '{name}' no está disponible.\n"
                    f"     Usa el botón 'Download' o instala SecLists.\n\n",
                    "warning")
                # Fallback to built-in common
                import os as _os
                wordlist = _os.path.join(ROOT, "wordlists", "web", "common.txt")
                self._write_terminal(
                    f"  ℹ  Usando fallback: wordlists/web/common.txt\n\n",
                    "hint")

        options = {
            "wordlist":      wordlist,
            "fuzz_mode":     self._ffuf_fuzz_mode._var.get(),
            "param_name":    self._ffuf_param_name.get().strip(),
            "vhost_host":    self._ffuf_vhost_host.get().strip(),
            "method":        self._ffuf_method._var.get(),
            "headers":       self._ffuf_headers.get("1.0", "end").strip(),
            "cookies":       self._ffuf_cookies.get().strip(),
            "body":          self._ffuf_body.get("1.0", "end").strip(),
            "extensions":    self._ffuf_ext.get().strip(),
            "match_codes":   self._ffuf_mc.get().strip(),
            "filter_codes":  self._ffuf_fc.get().strip(),
            "filter_size":   self._ffuf_fs.get().strip(),
            "filter_words":  self._ffuf_fw.get().strip(),
            "filter_lines":  self._ffuf_fl.get().strip(),
            "threads":       self._ffuf_threads.get().strip(),
            "rate":          self._ffuf_rate.get().strip(),
            "timeout":       self._ffuf_timeout.get().strip(),
            "recursion":     self._ffuf_rec._var.get(),
            "follow_redirects": self._ffuf_follow._var.get(),
            "output_json":   self._ffuf_json._var.get(),
        }
        m = FfufModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        m.execute(target, options, self._save_output_var.get())

    def _run_smb(self, target):
        options = {
            "tool": self._smb_tool._var.get(),
            "username": self._smb_user.get().strip(),
            "password": self._smb_pass.get().strip(),
            "share": self._smb_share.get().strip(),
            "mode": self._smb_mode._var.get(),
        }
        m = SMBModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        m.execute(target, options, self._save_output_var.get())

    def _run_ad(self, target):
        options = {
            "tool": self._ad_tool._var.get(),
            "protocol": self._ad_proto._var.get(),
            "action": self._ad_action._var.get(),
            "domain": self._ad_domain.get().strip(),
            "username": self._ad_user.get().strip(),
            "password": self._ad_pass.get().strip(),
            "hash": self._ad_hash.get().strip(),
            "userlist": self._ad_userlist.get().strip(),
        }
        m = ADModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        m.execute(target, options, self._save_output_var.get())

    def _run_hydra(self, target):
        plist_key = self._hydra_plist_combo._var.get()
        if plist_key == "[custom path]":
            passlist = self._hydra_custom_plist.get().strip()
        else:
            passlist = COMMON_WORDLISTS.get(plist_key, "")

        ulist_key = self._hydra_ulist_combo._var.get()
        userlist = COMMON_WORDLISTS.get(ulist_key, "")

        options = {
            "tool": self._hydra_tool._var.get(),
            "protocol": self._hydra_proto._var.get(),
            "port": self._hydra_port.get().strip(),
            "username": self._hydra_user.get().strip(),
            "userlist": userlist,
            "passlist": passlist,
            "password": self._hydra_pass.get().strip(),
            "threads": self._hydra_threads.get().strip(),
            "stop_on_success": self._hydra_stop._var.get(),
            "form_path": self._hydra_fpath.get().strip(),
            "form_params": self._hydra_fparams.get().strip(),
            "fail_string": self._hydra_ffail.get().strip(),
        }
        m = HydraModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        m.execute(target, options, self._save_output_var.get())

    def _run_nikto(self, target):
        selected_sev = [s for s, v in self._nuclei_sev.items() if v.get()]
        options = {
            "tool": self._nikto_tool._var.get(),
            "port": self._nikto_port.get().strip(),
            "ssl": self._nikto_ssl._var.get(),
            "follow_redirects": self._nikto_fr._var.get(),
            "severity": selected_sev,
            "tags": [t.strip() for t in self._nuclei_tags.get().split(",") if t.strip()],
            "rate": self._nuclei_rate.get().strip(),
            "json_output": self._nuclei_json._var.get(),
        }
        m = NiktoModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        m.execute(target, options, self._save_output_var.get())

    def _run_exploit(self, target):
        tool = self._expl_tool._var.get()
        m = ExploitModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        if tool == "searchsploit":
            query = self._expl_query.get().strip()
            options = {
                "tool": "searchsploit",
                "cve": self._expl_cve._var.get(),
                "exact": self._expl_exact._var.get(),
            }
            m.execute(query, options, self._save_output_var.get())
        elif tool == "msfvenom":
            encoder = self._expl_encoder._var.get()
            encoder = "" if encoder == "(none)" else encoder
            options = {
                "tool": "msfvenom",
                "payload": self._expl_payload._var.get(),
                "format": self._expl_fmt._var.get(),
                "lhost": self._expl_lhost.get().strip(),
                "lport": self._expl_lport.get().strip(),
                "encoder": encoder,
                "output": f"scripts/payload.{self._expl_fmt._var.get()}",
            }
            os.makedirs("scripts", exist_ok=True)
            m.execute(target or "payload", options, self._save_output_var.get())
        elif tool == "download":
            options = {"tool": "download", "script_name": self._expl_script._var.get()}
            m.execute("", options, self._save_output_var.get())

    def _run_msf(self, target):
        action = self._msf_action._var.get()
        m = MetasploitModule(self._write_terminal, self._set_status, self.sessions.active)
        self._active_module = m
        if action == "search exploits":
            options = {"search_type": self._msf_search_type._var.get()}
            m.search_exploits(self._msf_query.get().strip(), options)
        elif action == "run exploit":
            options = {
                "module": self._msf_module.get().strip(),
                "payload": self._msf_payload.get().strip(),
                "lhost": self._msf_lhost.get().strip(),
                "lport": self._msf_lport.get().strip(),
                "extra_opts": self._msf_extra.get().strip(),
            }
            m.run_exploit(target, options)
        else:
            options = {
                "module": self._msf_module.get().strip(),
                "payload": self._msf_payload.get().strip(),
                "lhost": self._msf_lhost.get().strip(),
                "lport": self._msf_lport.get().strip(),
            }
            path, content = m.generate_rc_only(target, options)
            self._write_terminal(f"\n  RC script: {path}\n\n", "success")
            self._write_terminal(content, "hint")

    # ─── Script generator ─────────────────────────────────────────────────────

    def _get_sgen_options(self):
        return {
            "lhost": self._sgen_lhost.get().strip(),
            "lport": self._sgen_lport.get().strip(),
            "domain": self._sgen_domain.get().strip(),
            "filename": self._sgen_fname.get().strip(),
            "param": self._sgen_param.get().strip(),
            "target": self._get_target(),
        }

    def _get_selected_script(self):
        sel = self._sgen_lb.curselection()
        return list(SCRIPTS.keys())[sel[0]] if sel else None

    def _preview_script(self):
        name = self._get_selected_script()
        if not name:
            return
        content = generate_script(name, self._get_sgen_options())
        self._right_tabs.select(0)  # switch to terminal
        self._write_terminal(f"\n{'─'*60}\n", "separator")
        self._write_terminal(f"  SCRIPT  {name}\n", "cmd")
        self._write_terminal(f"{'─'*60}\n\n", "separator")
        self._write_terminal(content, "output")
        self._write_terminal(f"\n{'─'*60}\n\n", "separator")

    def _save_script_file(self):
        name = self._get_selected_script()
        if not name:
            return
        content = generate_script(name, self._get_sgen_options())
        path = save_script(name, content)
        self._write_terminal(f"\n  ✓ Saved: {path}\n\n", "success")

    # ─── Listener ─────────────────────────────────────────────────────────────

    def _start_listener(self):
        port = self._listener_port.get().strip()
        if not port.isdigit():
            messagebox.showwarning("Invalid port", "Port must be numeric.")
            return
        self.listener = ShellListener(self._write_terminal, self._set_status)
        self._right_tabs.select(0)  # switch to terminal
        self.listener.start(port, self._listener_rlwrap._var.get())

    def _stop_listener(self):
        if self.listener:
            self.listener.stop()

    def _show_payload(self):
        sel = self._payload_lb.curselection()
        if not sel:
            return
        name = list(REVERSE_SHELL_PAYLOADS.keys())[sel[0]]
        template = REVERSE_SHELL_PAYLOADS[name]

        # Use listener port + first non-loopback IP
        port = self._listener_port.get().strip() or "4444"
        ips = [ip for ip in get_local_ips() if ip != "127.0.0.1"]
        lhost = ips[0] if ips else "YOUR_IP"

        payload = template.replace("{lhost}", lhost).replace("{lport}", port)

        self._right_tabs.select(0)
        self._write_terminal(f"\n{'─'*60}\n", "separator")
        self._write_terminal(f"  PAYLOAD  {name}\n", "cmd")
        self._write_terminal(f"  LHOST    {lhost}\n", "info")
        self._write_terminal(f"  LPORT    {port}\n", "info")
        self._write_terminal(f"{'─'*60}\n\n", "separator")
        self._write_terminal(payload + "\n\n", "accent")
        self._write_terminal(f"{'─'*60}\n\n", "separator")

    # ─── Cheatsheets ──────────────────────────────────────────────────────────

    def _show_cheatsheet(self):
        sel = self._cheat_lb.curselection()
        if not sel:
            return
        name = list_cheatsheets()[sel[0]]
        content = get_cheatsheet(name)
        self._right_tabs.select(0)
        self._write_terminal(f"\n{content}\n\n", "hint")

    # ─── History re-run ───────────────────────────────────────────────────────

    def _rerun_command(self, cmd):
        if messagebox.askyesno("Re-run command",
                               f"Re-run this command?\n\n{cmd[:200]}"):
            # Execute in a new thread
            self._right_tabs.select(0)
            self._write_terminal(f"\n  ▶ Re-running: {cmd}\n\n", "cmd")
            def _exec():
                try:
                    proc = subprocess.Popen(
                        cmd, shell=True,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1)
                    for line in proc.stdout:
                        self._write_terminal(line, "output")
                except Exception as e:
                    self._write_terminal(f"  ERROR: {e}\n", "error")
            threading.Thread(target=_exec, daemon=True).start()

    # ─── Report ───────────────────────────────────────────────────────────────

    def _generate_report(self):
        if not self.sessions.active:
            return
        path = generate_report(self.sessions.active)
        self._write_terminal(f"\n  ✓ Report generated: {path}\n\n", "success")
        # Open in browser
        try:
            webbrowser.open(f"file://{os.path.abspath(path)}")
        except Exception:
            pass


def main():
    app = PenToolApp()
    app.mainloop()


if __name__ == "__main__":
    main()
