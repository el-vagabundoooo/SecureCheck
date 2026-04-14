import customtkinter as ctk
from tkinter import scrolledtext, messagebox
import tkinter as tk
import threading
import os
import sys
import webbrowser
from datetime import datetime
from PIL import Image, ImageTk
import io

# ─── THEME ───────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ─── COLOUR PALETTE ──────────────────────────────────────────────────────────
BG_MAIN     = "#f0f4f8"
BG_SIDEBAR  = "#1a3a5c"
BG_CARD     = "#ffffff"
ACCENT_BLUE = "#1a6fc4"
ACCENT_DARK = "#0d2d4f"
RED         = "#c0392b"
YELLOW      = "#f39c12"
GREEN       = "#27ae60"
BLUE_INFO   = "#2980b9"
TEXT_MAIN   = "#1a1a2e"
TEXT_MUTED  = "#6b7280"
WHITE       = "#ffffff"

RISK_COLOURS = {
    "HIGH":   RED,
    "MEDIUM": YELLOW,
    "LOW":    GREEN,
    "INFO":   BLUE_INFO,
}

RISK_BG = {
    "HIGH":   "#fdf0f0",
    "MEDIUM": "#fffbf0",
    "LOW":    "#f0fdf4",
    "INFO":   "#f0f8ff",
}

class SecureCheckApp(ctk.CTk):
    """
    Main application window. Inherits from ctk.CTk which is
    customtkinter's replacement for tkinter.Tk — the root window.

    customtkinter wraps standard tkinter widgets with modern styling.
    The appearance_mode ("light"/"dark") and color_theme ("blue") set
    the global theme for all ctk widgets.
    """
    def __init__(self):
        super().__init__()

        self.title("SecureCheck — Security Audit & Phishing Analyzer")
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.configure(fg_color=BG_MAIN)
        self.resizable(True, True)

        # State variables
        self.audit_data    = None
        self.phishing_data = None
        self.is_scanning   = False

        self._build_layout()
        self._show_home()

    # ══════════════════════════════════════════════════════════════════════════
    # LAYOUT BUILDER
    # ══════════════════════════════════════════════════════════════════════════
    def _build_layout(self):
        """
        Builds the two-panel layout:
        Left panel  — dark blue sidebar with navigation buttons
        Right panel — main content area (switches between views)

        grid() geometry manager is used here instead of pack().
        grid() gives precise control over row/column placement and
        weight (which rows/columns expand when window is resized).
        columnconfigure(1, weight=1) means column 1 (right panel)
        takes all available horizontal space when resized.
        """
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── SIDEBAR ──────────────────────────────────────────────────────────
        self.sidebar = ctk.CTkFrame(self, fg_color=BG_SIDEBAR,
                                    corner_radius=0, width=220)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(10, weight=1)

        # Logo / title in sidebar
        ctk.CTkLabel(
            self.sidebar,
            text="🔒 SecureCheck",
            font=ctk.CTkFont(family="Arial", size=18, weight="bold"),
            text_color=WHITE
        ).grid(row=0, column=0, padx=20, pady=(28, 4), sticky="w")

        ctk.CTkLabel(
            self.sidebar,
            text="Security Audit Tool",
            font=ctk.CTkFont(family="Arial", size=11),
            text_color="#8db4d8"
        ).grid(row=1, column=0, padx=20, pady=(0, 24), sticky="w")

        # Navigation buttons
        nav_items = [
            ("🏠  Home",          self._show_home),
            ("🔍  Security Audit", self._show_audit),
            ("🎣  Phishing Scan",  self._show_phishing),
            ("📊  Run Full Scan",  self._show_fullscan),
            ("📂  View Reports",   self._show_reports),
        ]

        self.nav_buttons = []
        for i, (label, cmd) in enumerate(nav_items):
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                command=cmd,
                fg_color="transparent",
                text_color=WHITE,
                hover_color="#2a5a8c",
                anchor="w",
                font=ctk.CTkFont(family="Arial", size=13),
                corner_radius=6,
                height=40,
            )
            btn.grid(row=i + 2, column=0, padx=12, pady=3, sticky="ew")
            self.nav_buttons.append(btn)

        # Version label at bottom
        ctk.CTkLabel(
            self.sidebar,
            text="v2.0 · Juan Lacia · 2026",
            font=ctk.CTkFont(family="Arial", size=10),
            text_color="#4a7aaa"
        ).grid(row=11, column=0, padx=20, pady=20, sticky="sw")

        # ── MAIN CONTENT AREA ─────────────────────────────────────────────
        self.main_frame = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

    # ══════════════════════════════════════════════════════════════════════════
    # VIEW SWITCHER
    # ══════════════════════════════════════════════════════════════════════════
    def _clear_main(self):
        """
        Destroys all widgets currently in the main frame.
        winfo_children() returns a list of all child widgets.
        We iterate and destroy each one before building a new view.
        This is the standard tkinter pattern for switching views
        without a framework — simpler than maintaining multiple frames.
        """
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def _set_active_nav(self, index):
        """Highlights the active nav button."""
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.configure(fg_color=ACCENT_BLUE)
            else:
                btn.configure(fg_color="transparent")

    # ══════════════════════════════════════════════════════════════════════════
    # HOME VIEW
    # ══════════════════════════════════════════════════════════════════════════
    def _show_home(self):
        self._clear_main()
        self._set_active_nav(0)

        scroll = ctk.CTkScrollableFrame(self.main_frame, fg_color=BG_MAIN)
        scroll.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        scroll.grid_columnconfigure(0, weight=1)

        # Header
        header = ctk.CTkFrame(scroll, fg_color=ACCENT_DARK, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Welcome to SecureCheck",
            font=ctk.CTkFont(family="Arial", size=26, weight="bold"),
            text_color=WHITE
        ).grid(row=0, column=0, padx=32, pady=(28, 4), sticky="w")

        ctk.CTkLabel(
            header,
            text="Personal Security Audit & Phishing Email Analyzer",
            font=ctk.CTkFont(family="Arial", size=13),
            text_color="#8db4d8"
        ).grid(row=1, column=0, padx=32, pady=(0, 24), sticky="w")

        # KPI cards
        kpi_frame = ctk.CTkFrame(scroll, fg_color=BG_MAIN)
        kpi_frame.grid(row=1, column=0, sticky="ew", padx=24, pady=24)
        for i in range(3):
            kpi_frame.grid_columnconfigure(i, weight=1)

        kpis = [
            ("🔍", "Security Audit", "Scans open ports, firewall,\nSMB exposure & Wi-Fi security"),
            ("🎣", "Phishing Analyzer", "Analyses email headers, URLs,\nVirusTotal & HIBP checks"),
            ("📊", "HTML Reports", "Professional risk-rated reports\ngenerated after every scan"),
        ]

        for i, (icon, title, desc) in enumerate(kpis):
            card = ctk.CTkFrame(kpi_frame, fg_color=BG_CARD,
                                corner_radius=10,
                                border_width=1, border_color="#dde3ec")
            card.grid(row=0, column=i, padx=8, pady=0, sticky="nsew")

            ctk.CTkLabel(card, text=icon,
                         font=ctk.CTkFont(size=32)).pack(pady=(20, 6))
            ctk.CTkLabel(card, text=title,
                         font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
                         text_color=TEXT_MAIN).pack()
            ctk.CTkLabel(card, text=desc,
                         font=ctk.CTkFont(family="Arial", size=11),
                         text_color=TEXT_MUTED,
                         justify="center").pack(pady=(4, 20))

        # Quick start buttons
        qs_frame = ctk.CTkFrame(scroll, fg_color=BG_MAIN)
        qs_frame.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 16))
        qs_frame.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkLabel(
            qs_frame,
            text="Quick Start",
            font=ctk.CTkFont(family="Arial", size=16, weight="bold"),
            text_color=TEXT_MAIN
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

        quick_actions = [
            ("Run Security Audit", self._show_audit,   ACCENT_BLUE),
            ("Analyse Email",      self._show_phishing, "#1a8c5a"),
            ("Full Scan",          self._show_fullscan, "#6a1a8c"),
        ]
        for i, (label, cmd, colour) in enumerate(quick_actions):
            ctk.CTkButton(
                qs_frame, text=label, command=cmd,
                fg_color=colour, hover_color=ACCENT_DARK,
                font=ctk.CTkFont(family="Arial", size=13, weight="bold"),
                height=44, corner_radius=8
            ).grid(row=1, column=i, padx=6, sticky="ew")

        # Warning notice
        warn_card = ctk.CTkFrame(scroll, fg_color="#fff8f0",
                                 corner_radius=8,
                                 border_width=1, border_color="#f39c12")
        warn_card.grid(row=3, column=0, sticky="ew", padx=24, pady=(8, 24))
        ctk.CTkLabel(
            warn_card,
            text="⚠️  Legal Notice: Run audits only on systems and networks you own or have explicit permission to test. Unauthorised scanning is illegal.",
            font=ctk.CTkFont(family="Arial", size=11),
            text_color="#7a4a00",
            wraplength=700,
            justify="left"
        ).pack(padx=16, pady=12)

    # ══════════════════════════════════════════════════════════════════════════
    # SECURITY AUDIT VIEW
    # ══════════════════════════════════════════════════════════════════════════
    def _show_audit(self):
        self._clear_main()
        self._set_active_nav(1)
        self._build_scan_view(
            title="Security Audit",
            subtitle="Scans your local machine for open ports, firewall status, SMB exposure, and Wi-Fi security",
            icon="🔍",
            scan_fn=self._run_audit_thread,
        )

    def _show_phishing(self):
        self._clear_main()
        self._set_active_nav(2)
        self._build_phishing_view()

    def _show_fullscan(self):
        self._clear_main()
        self._set_active_nav(3)
        self._build_fullscan_view()

    # ══════════════════════════════════════════════════════════════════════════
    # SCAN VIEW BUILDER (reusable for audit)
    # ══════════════════════════════════════════════════════════════════════════
    def _build_scan_view(self, title, subtitle, icon, scan_fn):
        """
        Builds a generic scan view with a header, start button,
        and live log output area. Used for the Security Audit view.

        CTkScrollableFrame provides a scrollable container —
        content that overflows vertically becomes scrollable.

        The log area uses tkinter's Text widget (not CTk) because
        we need tag-based coloured text output. CTkTextbox doesn't
        support tags. We configure tags manually:
          text.tag_config("HIGH", foreground=RED)
        Then insert with: text.insert(END, message, "HIGH")
        """
        self.main_frame.grid_rowconfigure(0, weight=1)

        container = ctk.CTkFrame(self.main_frame, fg_color=BG_MAIN)
        container.grid(row=0, column=0, sticky="nsew")
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(2, weight=1)

        # Header
        hdr = ctk.CTkFrame(container, fg_color=ACCENT_DARK, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text=f"{icon}  {title}",
                     font=ctk.CTkFont(family="Arial", size=22, weight="bold"),
                     text_color=WHITE).grid(row=0, column=0, padx=28,
                                            pady=(22,4), sticky="w")
        ctk.CTkLabel(hdr, text=subtitle,
                     font=ctk.CTkFont(family="Arial", size=12),
                     text_color="#8db4d8").grid(row=1, column=0, padx=28,
                                                pady=(0,18), sticky="w")

        # Control row
        ctrl = ctk.CTkFrame(container, fg_color=BG_MAIN)
        ctrl.grid(row=1, column=0, sticky="ew", padx=24, pady=16)

        self.scan_btn = ctk.CTkButton(
            ctrl, text=f"▶  Start {title}",
            command=scan_fn,
            fg_color=ACCENT_BLUE,
            hover_color=ACCENT_DARK,
            font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
            height=44, width=200, corner_radius=8
        )
        self.scan_btn.pack(side="left")

        self.progress_label = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Arial", size=12),
            text_color=TEXT_MUTED
        )
        self.progress_label.pack(side="left", padx=16)

        # Log output
        log_frame = ctk.CTkFrame(container, fg_color=BG_CARD,
                                 corner_radius=8,
                                 border_width=1, border_color="#dde3ec")
        log_frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 24))
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame,
            bg="#0d1117", fg="#e6edf3",
            font=("Consolas", 11),
            wrap="word",
            padx=16, pady=12,
            relief="flat",
            state="disabled",
            insertbackground=WHITE,
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")

        scrollbar = ctk.CTkScrollbar(log_frame, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        # Colour tags for log
        self.log_text.tag_config("HIGH",   foreground="#ff6b6b")
        self.log_text.tag_config("MEDIUM", foreground="#ffa94d")
        self.log_text.tag_config("LOW",    foreground="#69db7c")
        self.log_text.tag_config("INFO",   foreground="#74c0fc")
        self.log_text.tag_config("HEADER", foreground="#a5d8ff",
                                 font=("Consolas", 11, "bold"))
        self.log_text.tag_config("NORMAL", foreground="#e6edf3")

        self._log("SecureCheck ready. Press Start to begin scan.\n", "INFO")

    def _log(self, message, tag="NORMAL"):
        """
        Thread-safe log writer.

        GUI frameworks are not thread-safe — you cannot update
        tkinter widgets from a background thread directly.
        after(0, callback) schedules the callback to run on
        the main thread's event loop at the next opportunity.
        This is the correct tkinter pattern for thread-safe updates.

        state="disabled" on the Text widget prevents user editing.
        We temporarily set it to "normal" to insert text, then
        back to "disabled" to lock it again.
        """
        def _write():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", message + "\n", tag)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.after(0, _write)

    # ══════════════════════════════════════════════════════════════════════════
    # AUDIT THREAD
    # ══════════════════════════════════════════════════════════════════════════
    def _run_audit_thread(self):
        """
        Runs the security audit in a background thread.

        threading.Thread() creates a new thread — a separate
        execution path that runs concurrently with the main thread.
        daemon=True means the thread is killed automatically when
        the main window closes — no orphaned processes.

        Without threading, the scan would block the entire GUI —
        the window would freeze and become unresponsive for the
        1-3 minutes the nmap scan takes. Threading keeps the GUI
        responsive while the scan runs in the background.
        """
        if self.is_scanning:
            return
        self.is_scanning = True
        self.scan_btn.configure(state="disabled", text="⏳ Scanning...")
        self.after(0, lambda: self.progress_label.configure(
            text="Scan in progress — this may take 1-3 minutes..."))

        def run():
            try:
                # Redirect stdout to log
                import sys
                from io import StringIO

                sys.stdout = LogRedirector(self._log)

                from modules.audit import run_audit
                self.audit_data = run_audit()

                sys.stdout = sys.__stdout__

                self.after(0, self._on_audit_complete)
            except Exception as e:
                sys.stdout = sys.__stdout__
                self._log(f"ERROR: {e}", "HIGH")
                self.after(0, self._reset_scan_btn)

        threading.Thread(target=run, daemon=True).start()

    def _on_audit_complete(self):
        self._reset_scan_btn()
        self.progress_label.configure(
            text=f"✅ Scan complete — {self.audit_data['summary']['high']} HIGH, "
                 f"{self.audit_data['summary']['medium']} MEDIUM findings")
        self._show_results_popup(audit_data=self.audit_data)

    def _reset_scan_btn(self):
        self.is_scanning = False
        self.scan_btn.configure(state="normal", text="▶  Start Security Audit")

    # ══════════════════════════════════════════════════════════════════════════
    # PHISHING VIEW
    # ══════════════════════════════════════════════════════════════════════════
    def _build_phishing_view(self):
        self.main_frame.grid_rowconfigure(0, weight=1)

        container = ctk.CTkFrame(self.main_frame, fg_color=BG_MAIN)
        container.grid(row=0, column=0, sticky="nsew")
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(2, weight=1)

        # Header
        hdr = ctk.CTkFrame(container, fg_color=ACCENT_DARK, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="🎣  Phishing Email Analyzer",
                     font=ctk.CTkFont(family="Arial", size=22, weight="bold"),
                     text_color=WHITE).grid(row=0, column=0, padx=28,
                                            pady=(22,4), sticky="w")
        ctk.CTkLabel(hdr,
                     text="Paste raw email below (include headers for best results). Type or paste, then click Analyse.",
                     font=ctk.CTkFont(family="Arial", size=12),
                     text_color="#8db4d8").grid(row=1, column=0, padx=28,
                                                pady=(0,18), sticky="w")

        # Controls
        ctrl = ctk.CTkFrame(container, fg_color=BG_MAIN)
        ctrl.grid(row=1, column=0, sticky="ew", padx=24, pady=12)

        self.phish_btn = ctk.CTkButton(
            ctrl, text="▶  Analyse Email",
            command=self._run_phishing_thread,
            fg_color="#1a8c5a", hover_color="#0d5a3a",
            font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
            height=44, width=200, corner_radius=8
        )
        self.phish_btn.pack(side="left")

        ctk.CTkButton(
            ctrl, text="Clear",
            command=self._clear_email_input,
            fg_color=TEXT_MUTED, hover_color=ACCENT_DARK,
            font=ctk.CTkFont(family="Arial", size=13),
            height=44, width=100, corner_radius=8
        ).pack(side="left", padx=8)

        self.phish_progress = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Arial", size=12),
            text_color=TEXT_MUTED
        )
        self.phish_progress.pack(side="left", padx=16)

        # Email input area
        input_frame = ctk.CTkFrame(container, fg_color=BG_CARD,
                                   corner_radius=8,
                                   border_width=1, border_color="#dde3ec")
        input_frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0,24))
        input_frame.grid_rowconfigure(0, weight=1)
        input_frame.grid_columnconfigure(0, weight=1)

        self.email_input = tk.Text(
            input_frame,
            bg="#f8fafc", fg=TEXT_MAIN,
            font=("Consolas", 11),
            wrap="word",
            padx=16, pady=12,
            relief="flat",
            insertbackground=ACCENT_BLUE,
        )
        self.email_input.grid(row=0, column=0, sticky="nsew")

        scrollbar = ctk.CTkScrollbar(input_frame,
                                     command=self.email_input.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.email_input.configure(yscrollcommand=scrollbar.set)

        # Placeholder text
        placeholder = ("Paste the full raw email here — include all headers.\n\n"
                       "To get headers in Gmail: Open email → ⋮ menu → Show original\n"
                       "To get headers in Outlook: File → Properties\n\n"
                       "Example header lines to look for:\n"
                       "From: sender@domain.com\n"
                       "Reply-To: different@otherdomain.xyz\n"
                       "Received-SPF: fail\n"
                       "Subject: URGENT — Verify your account NOW\n")
        self.email_input.insert("1.0", placeholder)
        self.email_input.configure(fg="#9ca3af")

        def on_focus_in(e):
            if self.email_input.get("1.0", "end-1c") == placeholder.strip():
                self.email_input.delete("1.0", "end")
                self.email_input.configure(fg=TEXT_MAIN)

        def on_focus_out(e):
            if not self.email_input.get("1.0", "end-1c").strip():
                self.email_input.insert("1.0", placeholder)
                self.email_input.configure(fg="#9ca3af")

        self.email_input.bind("<FocusIn>",  on_focus_in)
        self.email_input.bind("<FocusOut>", on_focus_out)
        self._placeholder_text = placeholder.strip()

    def _clear_email_input(self):
        self.email_input.delete("1.0", "end")
        self.email_input.configure(fg=TEXT_MAIN)

    def _run_phishing_thread(self):
        if self.is_scanning:
            return
        raw_email = self.email_input.get("1.0", "end-1c").strip()
        if not raw_email or raw_email == self._placeholder_text:
            messagebox.showwarning("No Input",
                                   "Please paste an email before analysing.")
            return

        self.is_scanning = True
        self.phish_btn.configure(state="disabled", text="⏳ Analysing...")
        self.phish_progress.configure(text="Analysing email — checking URLs, VirusTotal, HIBP...")

        def run():
            try:
                import sys
                sys.stdout = LogRedirector(None)
                from modules.phishing import run_phishing_analysis
                self.phishing_data = run_phishing_analysis(raw_email)
                sys.stdout = sys.__stdout__
                self.after(0, self._on_phishing_complete)
            except Exception as e:
                sys.stdout = sys.__stdout__
                self.after(0, lambda: messagebox.showerror(
                    "Error", f"Analysis failed: {e}"))
                self.after(0, lambda: self.phish_btn.configure(
                    state="normal", text="▶  Analyse Email"))
                self.is_scanning = False

        threading.Thread(target=run, daemon=True).start()

    def _on_phishing_complete(self):
        self.is_scanning = False
        self.phish_btn.configure(state="normal", text="▶  Analyse Email")
        self.phish_progress.configure(
            text=f"✅ Complete — Risk Score: {self.phishing_data['score']}/100 — {self.phishing_data['risk_label']}")
        self._show_results_popup(phishing_data=self.phishing_data)

    # ══════════════════════════════════════════════════════════════════════════
    # FULL SCAN VIEW
    # ══════════════════════════════════════════════════════════════════════════
    def _build_fullscan_view(self):
        self.main_frame.grid_rowconfigure(0, weight=1)

        container = ctk.CTkFrame(self.main_frame, fg_color=BG_MAIN)
        container.grid(row=0, column=0, sticky="nsew")
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(2, weight=1)

        hdr = ctk.CTkFrame(container, fg_color=ACCENT_DARK, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="📊  Full Scan",
                     font=ctk.CTkFont(family="Arial", size=22, weight="bold"),
                     text_color=WHITE).grid(row=0, column=0, padx=28,
                                            pady=(22,4), sticky="w")
        ctk.CTkLabel(hdr,
                     text="Runs Security Audit and Phishing Analysis together — generates one combined report",
                     font=ctk.CTkFont(family="Arial", size=12),
                     text_color="#8db4d8").grid(row=1, column=0, padx=28,
                                                pady=(0,18), sticky="w")

        content = ctk.CTkScrollableFrame(container, fg_color=BG_MAIN)
        content.grid(row=1, column=0, sticky="nsew", padx=24, pady=16)
        content.grid_columnconfigure(0, weight=1)

        # Step 1 — Email input
        ctk.CTkLabel(content, text="Step 1 — Paste Email to Analyse (optional)",
                     font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
                     text_color=TEXT_MAIN).grid(row=0, column=0,
                                                sticky="w", pady=(0,8))

        self.full_email_input = tk.Text(
            content, height=10,
            bg="#f8fafc", fg=TEXT_MAIN,
            font=("Consolas", 11),
            wrap="word", padx=12, pady=10, relief="flat",
        )
        self.full_email_input.grid(row=1, column=0, sticky="ew", pady=(0,16))

        ctk.CTkLabel(content, text="Step 2 — Run Full Scan",
                     font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
                     text_color=TEXT_MAIN).grid(row=2, column=0,
                                                sticky="w", pady=(0,8))

        self.full_btn = ctk.CTkButton(
            content, text="▶  Run Full Scan",
            command=self._run_full_thread,
            fg_color="#6a1a8c", hover_color="#3d0f55",
            font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
            height=48, corner_radius=8
        )
        self.full_btn.grid(row=3, column=0, sticky="ew", pady=(0,12))

        self.full_progress = ctk.CTkLabel(
            content, text="",
            font=ctk.CTkFont(family="Arial", size=12),
            text_color=TEXT_MUTED
        )
        self.full_progress.grid(row=4, column=0, sticky="w")

    def _run_full_thread(self):
        if self.is_scanning:
            return
        raw_email = self.full_email_input.get("1.0", "end-1c").strip()
        self.is_scanning = True
        self.full_btn.configure(state="disabled", text="⏳ Running full scan...")
        self.full_progress.configure(text="Phase 1/2 — Security Audit running...")

        def run():
            try:
                import sys
                sys.stdout = LogRedirector(None)

                from modules.audit    import run_audit
                from modules.phishing import run_phishing_analysis

                self.audit_data = run_audit()
                self.after(0, lambda: self.full_progress.configure(
                    text="Phase 2/2 — Phishing analysis running..."))

                if raw_email:
                    self.phishing_data = run_phishing_analysis(raw_email)

                sys.stdout = sys.__stdout__
                self.after(0, self._on_full_complete)
            except Exception as e:
                sys.stdout = sys.__stdout__
                self.after(0, lambda: messagebox.showerror(
                    "Error", f"Full scan failed: {e}"))
                self.after(0, lambda: self.full_btn.configure(
                    state="normal", text="▶  Run Full Scan"))
                self.is_scanning = False

        threading.Thread(target=run, daemon=True).start()

    def _on_full_complete(self):
        self.is_scanning = False
        self.full_btn.configure(state="normal", text="▶  Run Full Scan")
        self.full_progress.configure(text="✅ Full scan complete")
        self._show_results_popup(
            audit_data=self.audit_data,
            phishing_data=self.phishing_data
        )

    # ══════════════════════════════════════════════════════════════════════════
    # REPORTS VIEW
    # ══════════════════════════════════════════════════════════════════════════
    def _show_reports(self):
        self._clear_main()
        self._set_active_nav(4)

        container = ctk.CTkFrame(self.main_frame, fg_color=BG_MAIN)
        container.grid(row=0, column=0, sticky="nsew")
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(container, fg_color=ACCENT_DARK, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="📂  Saved Reports",
                     font=ctk.CTkFont(family="Arial", size=22, weight="bold"),
                     text_color=WHITE).grid(row=0, column=0, padx=28,
                                            pady=(22,4), sticky="w")
        ctk.CTkLabel(hdr,
                     text="All generated reports are saved in the output/ folder. Click to open in browser.",
                     font=ctk.CTkFont(family="Arial", size=12),
                     text_color="#8db4d8").grid(row=1, column=0, padx=28,
                                                pady=(0,18), sticky="w")

        scroll = ctk.CTkScrollableFrame(container, fg_color=BG_MAIN)
        scroll.grid(row=1, column=0, sticky="nsew", padx=24, pady=16)
        scroll.grid_columnconfigure(0, weight=1)

        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        reports = sorted(
            [f for f in os.listdir(output_dir) if f.endswith(".html")],
            reverse=True
        )

        if not reports:
            ctk.CTkLabel(scroll,
                         text="No reports yet. Run a scan to generate your first report.",
                         font=ctk.CTkFont(family="Arial", size=13),
                         text_color=TEXT_MUTED).grid(row=0, column=0,
                                                     pady=40)
        else:
            for i, filename in enumerate(reports):
                filepath = os.path.abspath(os.path.join(output_dir, filename))
                card = ctk.CTkFrame(scroll, fg_color=BG_CARD,
                                    corner_radius=8,
                                    border_width=1, border_color="#dde3ec")
                card.grid(row=i, column=0, sticky="ew", pady=4)
                card.grid_columnconfigure(0, weight=1)

                ts = filename.replace("securecheck_report_", "").replace(".html", "")
                try:
                    dt = datetime.strptime(ts, "%Y%m%d_%H%M%S")
                    display_time = dt.strftime("%B %d, %Y at %H:%M:%S")
                except Exception:
                    display_time = ts

                ctk.CTkLabel(card,
                             text=f"📄  {display_time}",
                             font=ctk.CTkFont(family="Arial", size=13,
                                              weight="bold"),
                             text_color=TEXT_MAIN).grid(row=0, column=0,
                                                        padx=16, pady=(12,2),
                                                        sticky="w")
                ctk.CTkLabel(card, text=filename,
                             font=ctk.CTkFont(family="Arial", size=11),
                             text_color=TEXT_MUTED).grid(row=1, column=0,
                                                         padx=16, pady=(0,12),
                                                         sticky="w")
                ctk.CTkButton(card, text="Open in Browser",
                              command=lambda fp=filepath: webbrowser.open(f"file:///{fp}"),
                              fg_color=ACCENT_BLUE, hover_color=ACCENT_DARK,
                              width=160, height=32, corner_radius=6,
                              font=ctk.CTkFont(family="Arial", size=12)
                              ).grid(row=0, column=1, rowspan=2,
                                     padx=16, pady=12)

    # ══════════════════════════════════════════════════════════════════════════
    # RESULTS POPUP WINDOW
    # ══════════════════════════════════════════════════════════════════════════
    def _show_results_popup(self, audit_data=None, phishing_data=None):
        """
        Creates a Toplevel window — a secondary window attached to
        the main application. Toplevel() creates an independent window
        that shares the same event loop as the root window.

        transient(self) makes the popup stay on top of the main window.
        grab_set() makes the popup modal — the main window is
        temporarily unresponsive until the popup is closed.

        We first generate the HTML report file, then render a
        summary of findings directly in the popup window for
        immediate in-app feedback.
        """
        # Generate and save the report
        from modules.report import generate_report
        filepath = generate_report(
            audit_data=audit_data,
            phishing_data=phishing_data
        )

        # Build popup
        popup = ctk.CTkToplevel(self)
        popup.title("SecureCheck — Scan Results")
        popup.geometry("800x620")
        popup.transient(self)
        popup.grab_set()
        popup.configure(fg_color=BG_MAIN)

        popup.grid_columnconfigure(0, weight=1)
        popup.grid_rowconfigure(1, weight=1)

        # Popup header
        hdr = ctk.CTkFrame(popup, fg_color=ACCENT_DARK, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(hdr, text="✅  Scan Complete",
                     font=ctk.CTkFont(family="Arial", size=20, weight="bold"),
                     text_color=WHITE).grid(row=0, column=0, padx=24,
                                            pady=(18,4), sticky="w")
        ctk.CTkLabel(hdr,
                     text="Review your findings below. Open the full HTML report for complete details.",
                     font=ctk.CTkFont(family="Arial", size=12),
                     text_color="#8db4d8").grid(row=1, column=0, padx=24,
                                                pady=(0,14), sticky="w")

        # Scrollable results area
        scroll = ctk.CTkScrollableFrame(popup, fg_color=BG_MAIN)
        scroll.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        scroll.grid_columnconfigure(0, weight=1)

        row_idx = 0

        # ── Audit summary ─────────────────────────────────────────────────
        if audit_data:
            s = audit_data["summary"]
            summary_frame = ctk.CTkFrame(scroll, fg_color=BG_CARD,
                                         corner_radius=8,
                                         border_width=1, border_color="#dde3ec")
            summary_frame.grid(row=row_idx, column=0, sticky="ew",
                               padx=20, pady=(16, 8))
            summary_frame.grid_columnconfigure((0,1,2), weight=1)
            row_idx += 1

            ctk.CTkLabel(summary_frame, text="Security Audit Summary",
                         font=ctk.CTkFont(family="Arial", size=14,
                                          weight="bold"),
                         text_color=TEXT_MAIN).grid(
                row=0, column=0, columnspan=3,
                padx=16, pady=(14,10), sticky="w")

            for ci, (val, label, colour) in enumerate([
                (str(s["high"]),   "HIGH Risk",   RED),
                (str(s["medium"]), "MEDIUM Risk", YELLOW),
                (str(s["total"]),  "Total",       ACCENT_BLUE),
            ]):
                ctk.CTkLabel(summary_frame, text=val,
                             font=ctk.CTkFont(family="Arial", size=28,
                                              weight="bold"),
                             text_color=colour).grid(
                    row=1, column=ci, padx=16, pady=(0,4))
                ctk.CTkLabel(summary_frame, text=label,
                             font=ctk.CTkFont(family="Arial", size=11),
                             text_color=TEXT_MUTED).grid(
                    row=2, column=ci, padx=16, pady=(0,14))

            # Individual findings
            for f in audit_data.get("all_findings", []):
                self._render_finding_card(scroll, f, row_idx)
                row_idx += 1

        # ── Phishing summary ──────────────────────────────────────────────
        if phishing_data and "error" not in phishing_data:
            score      = phishing_data["score"]
            risk_label = phishing_data["risk_label"]
            score_colour = (RED if score >= 51 else
                           (YELLOW if score >= 26 else GREEN))

            ph_frame = ctk.CTkFrame(scroll, fg_color=BG_CARD,
                                    corner_radius=8,
                                    border_width=1, border_color="#dde3ec")
            ph_frame.grid(row=row_idx, column=0, sticky="ew",
                          padx=20, pady=(16 if not audit_data else 8, 8))
            ph_frame.grid_columnconfigure(1, weight=1)
            row_idx += 1

            ctk.CTkLabel(ph_frame,
                         text=str(score),
                         font=ctk.CTkFont(family="Arial", size=36,
                                          weight="bold"),
                         text_color=score_colour).grid(
                row=0, column=0, rowspan=2, padx=20, pady=16)

            ctk.CTkLabel(ph_frame,
                         text=f"Phishing Risk Score — {risk_label}",
                         font=ctk.CTkFont(family="Arial", size=14,
                                          weight="bold"),
                         text_color=TEXT_MAIN).grid(
                row=0, column=1, padx=12, pady=(16,4), sticky="w")

            ctk.CTkLabel(ph_frame,
                         text=f"From: {phishing_data['from']}",
                         font=ctk.CTkFont(family="Arial", size=11),
                         text_color=TEXT_MUTED).grid(
                row=1, column=1, padx=12, pady=(0,16), sticky="w")

            for f in phishing_data.get("findings", []):
                self._render_finding_card(scroll, f, row_idx)
                row_idx += 1

        # ── Buttons ───────────────────────────────────────────────────────
        btn_frame = ctk.CTkFrame(popup, fg_color=BG_MAIN)
        btn_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=16)

        ctk.CTkButton(
            btn_frame,
            text="📂  Open Full HTML Report",
            command=lambda: webbrowser.open(
                f"file:///{os.path.abspath(filepath)}"),
            fg_color=ACCENT_BLUE, hover_color=ACCENT_DARK,
            font=ctk.CTkFont(family="Arial", size=13, weight="bold"),
            height=44, corner_radius=8
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_frame, text="Close",
            command=popup.destroy,
            fg_color=TEXT_MUTED, hover_color="#374151",
            font=ctk.CTkFont(family="Arial", size=13),
            height=44, width=100, corner_radius=8
        ).pack(side="left")

    def _render_finding_card(self, parent, finding, row_idx):
        """
        Renders a single finding as a colour-coded card.
        The left border colour and background colour both
        reflect the risk level using the RISK_COLOURS dict.
        """
        risk    = finding.get("risk", "INFO")
        colour  = RISK_COLOURS.get(risk, BLUE_INFO)
        bg      = RISK_BG.get(risk, "#f0f8ff")
        check   = finding.get("check",       finding.get("detail", "Finding"))
        explain = finding.get("explanation", "")

        card = ctk.CTkFrame(parent, fg_color=bg,
                            corner_radius=6,
                            border_width=1, border_color=colour)
        card.grid(row=row_idx, column=0, sticky="ew", padx=20, pady=3)
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text=risk,
                     font=ctk.CTkFont(family="Arial", size=10, weight="bold"),
                     text_color=WHITE,
                     fg_color=colour,
                     corner_radius=3,
                     width=70).grid(row=0, column=0, padx=(10,8),
                                    pady=(10,2), sticky="nw")

        ctk.CTkLabel(card, text=check,
                     font=ctk.CTkFont(family="Arial", size=12, weight="bold"),
                     text_color=TEXT_MAIN,
                     anchor="w").grid(row=0, column=1, padx=(0,10),
                                      pady=(10,2), sticky="ew")

        ctk.CTkLabel(card, text=explain,
                     font=ctk.CTkFont(family="Arial", size=11),
                     text_color=TEXT_MUTED,
                     anchor="w",
                     wraplength=580,
                     justify="left").grid(row=1, column=0, columnspan=2,
                                          padx=10, pady=(0,10), sticky="ew")


# ─── LOG REDIRECTOR ───────────────────────────────────────────────────────────
class LogRedirector:
    """
    Redirects Python's stdout (print statements) to either
    the GUI log widget or /dev/null during threaded scans.

    The audit and phishing modules use print() extensively
    for terminal output. When running in the GUI we either:
    1. Redirect prints to the log widget (audit view)
    2. Suppress them entirely (phishing/full scan views)

    write() is called by Python's print() internals.
    flush() is required by the stdout interface contract.
    """
    def __init__(self, log_fn):
        self.log_fn = log_fn

    def write(self, text):
        if self.log_fn and text.strip():
            clean = text.strip()
            if "[HIGH]" in clean or "HIGH" in clean:
                self.log_fn(clean, "HIGH")
            elif "[MEDIUM]" in clean or "MEDIUM" in clean:
                self.log_fn(clean, "MEDIUM")
            elif "[LOW]" in clean or "LOW" in clean:
                self.log_fn(clean, "LOW")
            elif "[INFO]" in clean or "[*]" in clean:
                self.log_fn(clean, "INFO")
            else:
                self.log_fn(clean, "NORMAL")

    def flush(self):
        pass


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SecureCheckApp()
    app.mainloop()