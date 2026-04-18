import json
import ipaddress
import hashlib
import re
import queue
import socket
import ssl
import subprocess
import sys
import time
import threading
import tkinter as tk
import ctypes
from pathlib import Path
from tkinter import messagebox


APP_TITLE = "SMART FOX Control"
POLL_INTERVAL_MS = 100
MAX_SCAN_TARGETS = 1024

THEME = {
    "bg": "#030711",
    "header_top": "#0b2544",
    "header_mid": "#0a1c35",
    "header_bottom": "#071425",
    "panel_left": "#0a1322",
    "panel_right": "#091321",
    "panel_card": "#0d1a2f",
    "panel_card_soft": "#0b1728",
    "text_primary": "#e7f2ff",
    "text_secondary": "#9bbad7",
    "text_muted": "#6f8daa",
    "accent": "#23b8ff",
    "accent_soft": "#6fd6ff",
    "entry_bg": "#050d1a",
    "entry_border": "#1d3f65",
    "entry_focus": "#2f86c7",
    "log_bg": "#020811",
    "log_text": "#9fe5ff",
    "scroll_bg": "#205f92",
    "scroll_active": "#2f7fbe",
    "scroll_trough": "#051223",
    "ok": "#37d67a",
    "warn": "#f1aa42",
    "error": "#ff6b81",
    "edge_light": "#2f4f76",
    "edge_dark": "#06101f",
    "btn_shadow": "#0a1a2e",
}

FONT_DISPLAY = ("Segoe UI Semibold", 25)
FONT_TITLE = ("Segoe UI Semibold", 15)
FONT_BODY = ("Segoe UI", 10)
FONT_BODY_BOLD = ("Segoe UI Semibold", 10)
FONT_MONO = ("Consolas", 10)

MAIN_CONFIG_FIELDS = [
    ("LISTEN_HOST", "Local Bind Address"),
    ("LISTEN_PORT", "Local Bind Port"),
    ("CONNECT_IP", "Remote Endpoint IP"),
    ("CONNECT_PORT", "Remote Endpoint Port"),
    ("FAKE_SNI", "TLS Server Name (SNI)"),
]

ADVANCED_CONFIG_FIELDS = [
    ("MAX_CONNECTIONS", "Maximum Concurrent Connections"),
    ("MAX_CONNECTIONS_PER_IP", "Per-Client Connection Limit"),
    ("HANDSHAKE_TIMEOUT_SEC", "Handshake Timeout (sec)"),
    ("RELAY_IDLE_TIMEOUT_SEC", "Relay Idle Timeout (sec)"),
    ("CONNECT_TIMEOUT_SEC", "Outbound Connect Timeout (sec)"),
    ("CONNECT_RETRY_COUNT", "Connect Retry Count"),
    ("CONNECT_RETRY_DELAY_SEC", "Retry Delay (sec)"),
    ("RELAY_BUFFER_SIZE", "Relay Buffer Size (bytes)"),
    ("SOCKET_SNDBUF", "Socket Send Buffer (bytes)"),
    ("SOCKET_RCVBUF", "Socket Receive Buffer (bytes)"),
    ("ENABLE_TCP_NODELAY", "Enable TCP_NODELAY (true/false)"),
]

CONFIG_DEFAULTS = {
    "MAX_CONNECTIONS": 2048,
    "MAX_CONNECTIONS_PER_IP": 128,
    "HANDSHAKE_TIMEOUT_SEC": 2.0,
    "RELAY_IDLE_TIMEOUT_SEC": 120.0,
    "CONNECT_TIMEOUT_SEC": 4.0,
    "CONNECT_RETRY_COUNT": 2,
    "CONNECT_RETRY_DELAY_SEC": 0.25,
    "RELAY_BUFFER_SIZE": 65536,
    "SOCKET_SNDBUF": 262144,
    "SOCKET_RCVBUF": 262144,
    "ENABLE_TCP_NODELAY": True,
}


def _is_windows_admin() -> bool:
    if not sys.platform.startswith("win"):
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin():
    params = subprocess.list2cmdline(sys.argv)
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            None,
            1,
        )
    except Exception as exc:
        raise RuntimeError(f"failed to request admin privileges: {exc}") from exc

    if ret <= 32:
        raise RuntimeError(f"failed to request admin privileges, code={ret}")


def _ensure_admin_or_exit():
    if _is_windows_admin():
        return
    _relaunch_as_admin()
    sys.exit(0)


def _get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self._icon_image = None
        self.root.title(APP_TITLE)
        self.root.geometry("1180x780")
        self.root.minsize(980, 660)

        self.base_dir = _get_app_dir()
        self.config_path = self.base_dir / "config.json"
        self.main_path = self.base_dir / "main.py"

        self._set_window_icon()

        self.proc = None
        self.output_queue: queue.Queue[str] = queue.Queue()
        self.output_thread = None
        self.scan_thread = None

        self.vars: dict[str, tk.StringVar] = {}
        self.status_var = tk.StringVar(value="OFFLINE")
        self.status_color = tk.StringVar(value="#f59e0b")
        self.test_sni_list_var = tk.StringVar(value="")
        self.test_ip_var = tk.StringVar(value="")
        self.test_port_var = tk.StringVar(value="443")
        self.test_timeout_var = tk.StringVar(value="2.5")
        self.test_retry_var = tk.StringVar(value="2")
        self.header_animation_enabled = True
        self.up_speed_var = tk.StringVar(value="0 B/s")
        self.down_speed_var = tk.StringVar(value="0 B/s")
        self.total_up_var = tk.StringVar(value="0 B")
        self.total_down_var = tk.StringVar(value="0 B")
        self.active_conn_var = tk.StringVar(value="0")

        self._init_config_vars()
        self._build_menubar()
        self._build_ui()
        self.set_status("OFFLINE", THEME["warn"])
        self.load_config_to_form()
        self._bind_shortcuts()
        self._poll_output_queue()
        self._animate_header()

    def _find_app_icon_path(self) -> Path | None:
        icon_dir = self.base_dir / "icon"
        if not icon_dir.exists():
            return None

        png_icons = sorted(icon_dir.glob("*.png"))
        if png_icons:
            return png_icons[0]

        return None

    def _set_window_icon(self):
        try:
            icon_path = self._find_app_icon_path()
            if icon_path is None:
                return
            self._icon_image = tk.PhotoImage(file=str(icon_path))
            self.root.iconphoto(True, self._icon_image)
        except Exception:
            # Keep startup resilient even if icon format/path is unsupported.
            pass

    def _build_menubar(self):
        menubar = tk.Menu(
            self.root,
            bg=THEME["panel_left"],
            fg=THEME["text_primary"],
            activebackground="#18456e",
            activeforeground="#ffffff",
            tearoff=0,
        )

        file_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=THEME["panel_left"],
            fg=THEME["text_primary"],
            activebackground="#18456e",
            activeforeground="#ffffff",
        )
        file_menu.add_command(
            label="Reload Config\tCtrl+R", command=self.load_config_to_form
        )
        file_menu.add_command(
            label="Save Config\tCtrl+S", command=self.save_form_to_config
        )
        file_menu.add_separator()
        file_menu.add_command(label="Exit\tCtrl+Q", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        core_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=THEME["panel_left"],
            fg=THEME["text_primary"],
            activebackground="#18456e",
            activeforeground="#ffffff",
        )
        core_menu.add_command(label="Start Core\tF5", command=self.start_core)
        core_menu.add_command(label="Stop Core\tF6", command=self.stop_core)
        core_menu.add_command(label="Restart Core\tF7", command=self.restart_core)
        menubar.add_cascade(label="Core", menu=core_menu)

        scan_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=THEME["panel_left"],
            fg=THEME["text_primary"],
            activebackground="#18456e",
            activeforeground="#ffffff",
        )
        scan_menu.add_command(label="Check Test Inputs", command=self.check_test_inputs)
        scan_menu.add_command(label="Quick SNI Test", command=self.run_quick_sni_test)
        scan_menu.add_command(label="Strong SNI Test", command=self.run_strong_sni_test)
        menubar.add_cascade(label="Scanner", menu=scan_menu)

        settings_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=THEME["panel_left"],
            fg=THEME["text_primary"],
            activebackground="#18456e",
            activeforeground="#ffffff",
        )
        settings_menu.add_command(
            label="Advanced Network Options",
            command=self.open_advanced_settings,
        )
        settings_menu.add_command(
            label="Connection Limits",
            command=self.open_limits_settings,
        )
        menubar.add_cascade(label="Settings", menu=settings_menu)

        view_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=THEME["panel_left"],
            fg=THEME["text_primary"],
            activebackground="#18456e",
            activeforeground="#ffffff",
        )
        view_menu.add_command(label="Clear Logs\tCtrl+L", command=self.clear_logs)
        view_menu.add_command(
            label="Toggle Header Animation",
            command=self.toggle_header_animation,
        )
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=THEME["panel_left"],
            fg=THEME["text_primary"],
            activebackground="#18456e",
            activeforeground="#ffffff",
        )
        help_menu.add_command(label="Quick Guide", command=self.show_quick_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.configure(menu=menubar)

    def _bind_shortcuts(self):
        self.root.bind_all("<Control-r>", lambda _e: self.load_config_to_form())
        self.root.bind_all("<Control-s>", lambda _e: self.save_form_to_config())
        self.root.bind_all("<Control-l>", lambda _e: self.clear_logs())
        self.root.bind_all("<Control-q>", lambda _e: self.on_close())
        self.root.bind_all("<F5>", lambda _e: self.start_core())
        self.root.bind_all("<F6>", lambda _e: self.stop_core())
        self.root.bind_all("<F7>", lambda _e: self.restart_core())

    def _build_ui(self):
        self.root.configure(bg=THEME["bg"])

        self.header = tk.Canvas(
            self.root,
            height=130,
            bg=THEME["bg"],
            highlightthickness=0,
            bd=0,
        )
        self.header.pack(fill="x", padx=14, pady=(14, 8))

        self.header.create_rectangle(0, 0, 2000, 130, fill=THEME["bg"], outline="")
        self.header.create_rectangle(
            0, 0, 2000, 55, fill=THEME["header_top"], outline=""
        )
        self.header.create_rectangle(
            0, 55, 2000, 95, fill=THEME["header_mid"], outline=""
        )
        self.header.create_rectangle(
            0, 95, 2000, 130, fill=THEME["header_bottom"], outline=""
        )
        self.header.create_oval(920, -120, 1220, 180, fill="#0e325e", outline="")
        self.header.create_oval(980, -90, 1320, 200, fill="#0a2749", outline="")
        self.header.create_line(0, 92, 2000, 92, fill=THEME["accent"], width=2)
        self.header.create_text(
            24,
            28,
            anchor="w",
            text="/// SMART FOX",
            fill=THEME["accent_soft"],
            font=FONT_DISPLAY,
        )
        self.header.create_text(
            24,
            88,
            anchor="w",
            text="SNI Spoofing Control Center",
            fill=THEME["text_secondary"],
            font=("Segoe UI", 12),
        )
        self.scan_line = self.header.create_line(
            0, 124, 1100, 124, fill="#1a78b7", width=1
        )
        self.scan_dir = -2

        body = tk.Frame(self.root, bg=THEME["bg"])
        body.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        left = tk.Frame(
            body,
            bg=THEME["panel_left"],
            highlightthickness=1,
            highlightbackground=THEME["edge_light"],
            bd=2,
            relief="ridge",
        )
        left.pack(side="left", fill="both", padx=(0, 10), ipadx=10, ipady=8)
        left.configure(width=380)
        left.pack_propagate(False)

        right = tk.Frame(
            body,
            bg=THEME["panel_right"],
            highlightthickness=1,
            highlightbackground=THEME["edge_light"],
            bd=2,
            relief="ridge",
        )
        right.pack(side="right", fill="both", expand=True, ipadx=10, ipady=8)

        form_title = tk.Label(
            left,
            text="PRIMARY CONFIG",
            bg=THEME["panel_left"],
            fg=THEME["accent_soft"],
            font=FONT_TITLE,
        )
        form_title.pack(anchor="w", padx=12, pady=(12, 10))

        tk.Label(
            left,
            text="Only the essential fields are shown here.\nOpen Settings menu for advanced tuning.",
            justify="left",
            bg=THEME["panel_left"],
            fg=THEME["text_muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 8))

        form_scroll_container = tk.Frame(left, bg=THEME["panel_left"])
        form_scroll_container.pack(fill="both", expand=True, padx=6)

        self.form_canvas = tk.Canvas(
            form_scroll_container,
            bg=THEME["panel_left"],
            highlightthickness=0,
            bd=0,
            relief="flat",
        )
        self.form_canvas.pack(side="left", fill="both", expand=True)

        form_scrollbar = self._make_soft_scrollbar(
            form_scroll_container,
            command=self.form_canvas.yview,
        )
        form_scrollbar.pack(side="right", fill="y")
        self.form_canvas.configure(yscrollcommand=form_scrollbar.set)

        self.form_inner = tk.Frame(self.form_canvas, bg=THEME["panel_left"])
        self.form_window = self.form_canvas.create_window(
            (0, 0), window=self.form_inner, anchor="nw"
        )

        self.form_inner.bind("<Configure>", self._on_form_inner_configure)
        self.form_canvas.bind("<Configure>", self._on_form_canvas_configure)
        self.form_canvas.bind("<MouseWheel>", self._on_form_mousewheel)

        for key, label in MAIN_CONFIG_FIELDS:
            self._add_field(self.form_inner, key, label)

        controls = tk.Frame(left, bg=THEME["panel_left"])
        controls.pack(side="bottom", fill="x", padx=12, pady=(12, 12))

        self.btn_reload = self._make_action_button(
            controls,
            text="Reload",
            command=self.load_config_to_form,
            tone="neutral",
        )
        self.btn_reload.pack(fill="x", pady=(0, 8))

        self.btn_save = self._make_action_button(
            controls,
            text="Save Config",
            command=self.save_form_to_config,
            tone="primary",
        )
        self.btn_save.pack(fill="x", pady=(0, 8))

        self.btn_start = self._make_action_button(
            controls,
            text="Start Core",
            command=self.start_core,
            tone="success",
        )
        self.btn_start.pack(fill="x", pady=(0, 8))

        self.btn_stop = self._make_action_button(
            controls,
            text="Stop Core",
            command=self.stop_core,
            tone="danger",
        )
        self.btn_stop.configure(state="disabled")
        self.btn_stop.pack(fill="x")

        status_panel = tk.Frame(right, bg=THEME["panel_right"])
        status_panel.pack(fill="x", padx=12, pady=(12, 6))

        tk.Label(
            status_panel,
            text="STATUS",
            bg=THEME["panel_right"],
            fg=THEME["accent_soft"],
            font=FONT_TITLE,
        ).pack(side="left")

        self.status_label = tk.Label(
            status_panel,
            textvariable=self.status_var,
            bg="#16324b",
            fg="#e9f8ff",
            font=FONT_BODY_BOLD,
            padx=12,
            pady=5,
            relief="raised",
            bd=1,
        )
        self.status_label.pack(side="right")

        scanner = tk.Frame(
            right,
            bg=THEME["panel_card_soft"],
            highlightthickness=1,
            highlightbackground=THEME["edge_light"],
            bd=2,
            relief="ridge",
        )
        scanner.pack(fill="x", padx=12, pady=(0, 8), ipady=8)

        tk.Label(
            scanner,
            text="SIMPLE TEST PANEL",
            bg=THEME["panel_card_soft"],
            fg=THEME["accent_soft"],
            font=FONT_BODY_BOLD,
        ).pack(anchor="w", padx=10, pady=(8, 4))

        sni_row = tk.Frame(scanner, bg=THEME["panel_card_soft"])
        sni_row.pack(fill="x", padx=10, pady=4)
        self._mini_label(sni_row, "SNI List")
        self._make_entry(sni_row, self.test_sni_list_var).pack(fill="x", ipady=5)

        target_row = tk.Frame(scanner, bg=THEME["panel_card_soft"])
        target_row.pack(fill="x", padx=10, pady=4)
        self._mini_label(target_row, "Target IP")
        self._make_entry(target_row, self.test_ip_var, width=20).pack(
            side="left", fill="x", expand=True, ipady=5, padx=(0, 6)
        )
        self._mini_label(target_row, "Port")
        self._make_entry(target_row, self.test_port_var, width=7).pack(
            side="left", ipady=5
        )

        config_row = tk.Frame(scanner, bg=THEME["panel_card_soft"])
        config_row.pack(fill="x", padx=10, pady=4)
        self._mini_label(config_row, "Timeout")
        self._make_entry(config_row, self.test_timeout_var, width=8).pack(
            side="left", ipady=5, padx=(0, 8)
        )
        self._mini_label(config_row, "Retries")
        self._make_entry(config_row, self.test_retry_var, width=6).pack(
            side="left", ipady=5
        )

        scan_buttons = tk.Frame(scanner, bg=THEME["panel_card_soft"])
        scan_buttons.pack(fill="x", padx=10, pady=(6, 8))
        self.btn_check_inputs = self._make_action_button(
            scan_buttons,
            text="Check Inputs",
            command=self.check_test_inputs,
            tone="scan",
        )
        self.btn_check_inputs.pack(side="left", padx=(0, 8))

        self.btn_quick_test = self._make_action_button(
            scan_buttons,
            text="Quick Test",
            command=self.run_quick_sni_test,
            tone="primary",
        )
        self.btn_quick_test.pack(side="left", padx=(0, 8))

        self.btn_strong_test = self._make_action_button(
            scan_buttons,
            text="Strong Test",
            command=self.run_strong_sni_test,
            tone="success",
        )
        self.btn_strong_test.pack(side="left")

        traffic = tk.Frame(
            right,
            bg=THEME["panel_card_soft"],
            highlightthickness=1,
            highlightbackground=THEME["edge_light"],
            bd=2,
            relief="ridge",
        )
        traffic.pack(fill="x", padx=12, pady=(0, 8), ipady=8)

        tk.Label(
            traffic,
            text="LIVE TRAFFIC",
            bg=THEME["panel_card_soft"],
            fg=THEME["accent_soft"],
            font=FONT_BODY_BOLD,
        ).pack(anchor="w", padx=10, pady=(8, 4))

        speed_row = tk.Frame(traffic, bg=THEME["panel_card_soft"])
        speed_row.pack(fill="x", padx=10, pady=(2, 2))
        tk.Label(
            speed_row,
            text="Upload",
            bg=THEME["panel_card_soft"],
            fg="#9dc4df",
            font=FONT_BODY_BOLD,
        ).pack(side="left")
        tk.Label(
            speed_row,
            textvariable=self.up_speed_var,
            bg=THEME["panel_card_soft"],
            fg="#8ee4ff",
            font=FONT_BODY_BOLD,
        ).pack(side="left", padx=(8, 20))
        tk.Label(
            speed_row,
            text="Download",
            bg=THEME["panel_card_soft"],
            fg="#9dc4df",
            font=FONT_BODY_BOLD,
        ).pack(side="left")
        tk.Label(
            speed_row,
            textvariable=self.down_speed_var,
            bg=THEME["panel_card_soft"],
            fg="#7bffb9",
            font=FONT_BODY_BOLD,
        ).pack(side="left", padx=(8, 0))

        total_row = tk.Frame(traffic, bg=THEME["panel_card_soft"])
        total_row.pack(fill="x", padx=10, pady=(2, 6))
        tk.Label(
            total_row,
            text="Total Up",
            bg=THEME["panel_card_soft"],
            fg="#7c9dbc",
            font=FONT_BODY,
        ).pack(side="left")
        tk.Label(
            total_row,
            textvariable=self.total_up_var,
            bg=THEME["panel_card_soft"],
            fg=THEME["text_primary"],
            font=FONT_BODY,
        ).pack(side="left", padx=(6, 16))
        tk.Label(
            total_row,
            text="Total Down",
            bg=THEME["panel_card_soft"],
            fg="#7c9dbc",
            font=FONT_BODY,
        ).pack(side="left")
        tk.Label(
            total_row,
            textvariable=self.total_down_var,
            bg=THEME["panel_card_soft"],
            fg=THEME["text_primary"],
            font=FONT_BODY,
        ).pack(side="left", padx=(6, 16))
        tk.Label(
            total_row,
            text="Active",
            bg=THEME["panel_card_soft"],
            fg="#7c9dbc",
            font=FONT_BODY,
        ).pack(side="left")
        tk.Label(
            total_row,
            textvariable=self.active_conn_var,
            bg=THEME["panel_card_soft"],
            fg=THEME["text_primary"],
            font=FONT_BODY,
        ).pack(side="left", padx=(6, 0))

        logs_title = tk.Label(
            right,
            text="RUNTIME LOGS",
            bg=THEME["panel_right"],
            fg=THEME["text_secondary"],
            font=FONT_BODY_BOLD,
        )
        logs_title.pack(anchor="w", padx=12, pady=(0, 6))

        log_container = tk.Frame(
            right,
            bg=THEME["panel_card"],
            highlightthickness=1,
            highlightbackground=THEME["edge_light"],
            bd=2,
            relief="ridge",
        )
        log_container.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.log_text = tk.Text(
            log_container,
            bg=THEME["log_bg"],
            fg=THEME["log_text"],
            insertbackground=THEME["log_text"],
            selectbackground="#184973",
            font=FONT_MONO,
            bd=1,
            relief="sunken",
            wrap="word",
        )
        self.log_text.pack(side="left", fill="both", expand=True)

        scroll = self._make_soft_scrollbar(log_container, command=self.log_text.yview)
        scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scroll.set)

        self.log("[ui] panel initialized")

    def _on_form_inner_configure(self, _event):
        self.form_canvas.configure(scrollregion=self.form_canvas.bbox("all"))

    def _on_form_canvas_configure(self, event):
        self.form_canvas.itemconfigure(self.form_window, width=event.width)

    def _on_form_mousewheel(self, event):
        self.form_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _mini_label(self, parent: tk.Widget, text: str):
        tk.Label(
            parent,
            text=text,
            bg=THEME["panel_card_soft"],
            fg=THEME["text_secondary"],
            font=FONT_BODY_BOLD,
        ).pack(side="left", padx=(0, 6))

    def _make_soft_scrollbar(self, parent: tk.Widget, command):
        return tk.Scrollbar(
            parent,
            orient="vertical",
            command=command,
            bg=THEME["scroll_bg"],
            activebackground=THEME["scroll_active"],
            troughcolor=THEME["scroll_trough"],
            relief="flat",
            bd=0,
            highlightthickness=0,
            width=12,
        )

    def _make_entry(self, parent: tk.Widget, textvariable: tk.StringVar, width=None):
        kwargs = {
            "textvariable": textvariable,
            "bg": THEME["entry_bg"],
            "fg": THEME["text_primary"],
            "insertbackground": THEME["text_primary"],
            "relief": "sunken",
            "bd": 1,
            "highlightthickness": 1,
            "highlightbackground": THEME["edge_light"],
            "highlightcolor": THEME["entry_focus"],
            "font": FONT_BODY,
        }
        if width is not None:
            kwargs["width"] = width
        return tk.Entry(parent, **kwargs)

    def _make_action_button(self, parent: tk.Widget, text: str, command, tone: str):
        tones = {
            "neutral": ("#18324e", "#24517a", "#d9efff"),
            "primary": ("#1661a0", "#1f79c7", "#f2f9ff"),
            "success": ("#0d6c4d", "#169869", "#edfff8"),
            "danger": ("#8f2b3e", "#b23a52", "#fff2f5"),
            "scan": ("#18537f", "#2071ad", "#f2fbff"),
        }
        bg, hover_bg, fg = tones.get(tone, tones["primary"])

        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover_bg,
            activeforeground="#ffffff",
            font=FONT_BODY_BOLD,
            bd=1,
            cursor="hand2",
            padx=12,
            pady=8,
            relief="raised",
            overrelief="sunken",
            highlightthickness=1,
            highlightbackground=THEME["edge_light"],
        )

        def on_enter(_event):
            if btn.cget("state") == "normal":
                btn.configure(bg=hover_bg)

        def on_leave(_event):
            if btn.cget("state") == "normal":
                btn.configure(bg=bg)

        def on_press(_event):
            if btn.cget("state") == "normal":
                btn.configure(relief="sunken")

        def on_release(_event):
            if btn.cget("state") == "normal":
                btn.configure(relief="raised")

        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        btn.bind("<ButtonPress-1>", on_press)
        btn.bind("<ButtonRelease-1>", on_release)
        return btn

    def _init_config_vars(self):
        all_fields = MAIN_CONFIG_FIELDS + ADVANCED_CONFIG_FIELDS
        for key, _label in all_fields:
            if key in self.vars:
                continue
            default_value = CONFIG_DEFAULTS.get(key, "")
            if key == "ENABLE_TCP_NODELAY":
                default_value = str(bool(default_value)).lower()
            self.vars[key] = tk.StringVar(value=str(default_value))

    def _open_settings_dialog(self, title: str, fields: list[tuple[str, str]]):
        top = tk.Toplevel(self.root)
        top.title(title)
        top.geometry("540x560")
        top.minsize(460, 420)
        top.configure(bg=THEME["panel_right"])
        top.transient(self.root)
        top.grab_set()

        tk.Label(
            top,
            text=title,
            bg=THEME["panel_right"],
            fg=THEME["accent_soft"],
            font=FONT_TITLE,
        ).pack(anchor="w", padx=14, pady=(14, 8))

        container = tk.Frame(top, bg=THEME["panel_right"])
        container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        canvas = tk.Canvas(
            container, bg=THEME["panel_right"], highlightthickness=0, bd=0
        )
        canvas.pack(side="left", fill="both", expand=True)

        scrollbar = self._make_soft_scrollbar(container, command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)

        inner = tk.Frame(canvas, bg=THEME["panel_right"])
        window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_inner_config(_e):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_config(e):
            canvas.itemconfigure(window, width=e.width)

        inner.bind("<Configure>", on_inner_config)
        canvas.bind("<Configure>", on_canvas_config)

        for key, label in fields:
            card = tk.Frame(
                inner,
                bg=THEME["panel_card_soft"],
                highlightthickness=1,
                highlightbackground=THEME["edge_light"],
                bd=2,
                relief="ridge",
            )
            card.pack(fill="x", padx=6, pady=6)
            tk.Label(
                card,
                text=label,
                bg=THEME["panel_card_soft"],
                fg=THEME["text_secondary"],
                font=FONT_BODY_BOLD,
                anchor="w",
            ).pack(fill="x", padx=10, pady=(8, 4))
            self._make_entry(card, self.vars[key]).pack(
                fill="x", padx=10, pady=(0, 10), ipady=5
            )

        footer = tk.Frame(top, bg=THEME["panel_right"])
        footer.pack(fill="x", padx=12, pady=(0, 12))
        self._make_action_button(
            footer,
            text="Save",
            command=lambda: self._save_from_dialog(top),
            tone="primary",
        ).pack(side="left")
        self._make_action_button(
            footer,
            text="Close",
            command=top.destroy,
            tone="neutral",
        ).pack(side="left", padx=(8, 0))

    def _save_from_dialog(self, dialog: tk.Toplevel):
        if self.save_form_to_config(show_success=False):
            self.log("[settings] updated")
            dialog.destroy()

    def open_advanced_settings(self):
        fields = [
            ("HANDSHAKE_TIMEOUT_SEC", "Handshake Timeout (sec)"),
            ("RELAY_IDLE_TIMEOUT_SEC", "Relay Idle Timeout (sec)"),
            ("CONNECT_TIMEOUT_SEC", "Outbound Connect Timeout (sec)"),
            ("CONNECT_RETRY_COUNT", "Connect Retry Count"),
            ("CONNECT_RETRY_DELAY_SEC", "Retry Delay (sec)"),
            ("RELAY_BUFFER_SIZE", "Relay Buffer Size (bytes)"),
            ("SOCKET_SNDBUF", "Socket Send Buffer (bytes)"),
            ("SOCKET_RCVBUF", "Socket Receive Buffer (bytes)"),
            ("ENABLE_TCP_NODELAY", "Enable TCP_NODELAY (true/false)"),
        ]
        self._open_settings_dialog("Advanced Network Options", fields)

    def open_limits_settings(self):
        fields = [
            ("MAX_CONNECTIONS", "Maximum Concurrent Connections"),
            ("MAX_CONNECTIONS_PER_IP", "Per-Client Connection Limit"),
        ]
        self._open_settings_dialog("Connection Limits", fields)

    def _parse_token_list(self, raw: str) -> list[str]:
        for sep in [",", "\n", "\t", ";"]:
            raw = raw.replace(sep, " ")
        return [item.strip() for item in raw.split(" ") if item.strip()]

    def _expand_ip_targets(self, raw: str) -> list[str]:
        result: list[str] = []
        for token in self._parse_token_list(raw):
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                hosts = list(network.hosts())
                if len(hosts) > MAX_SCAN_TARGETS:
                    raise ValueError(
                        f"CIDR target too large ({len(hosts)} hosts), max={MAX_SCAN_TARGETS}"
                    )
                result.extend(str(ip) for ip in hosts)
            else:
                ipaddress.ip_address(token)
                result.append(token)

        if len(result) > MAX_SCAN_TARGETS:
            raise ValueError(
                f"Too many targets ({len(result)}), max={MAX_SCAN_TARGETS}"
            )

        return result

    def _start_scan_job(self, title: str, worker):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scanner Busy", "Another scan is already running.")
            return

        self.log(f"[scan] {title} started")
        self.btn_quick_test.configure(state="disabled")
        self.btn_strong_test.configure(state="disabled")
        self.btn_check_inputs.configure(state="disabled")

        def wrapped():
            try:
                worker()
            except Exception as exc:
                self.output_queue.put(f"[scan][error] {exc}\n")
            finally:
                self.output_queue.put(f"[scan] {title} finished\n")
                self.root.after(0, self._finish_scan_ui_state)

        self.scan_thread = threading.Thread(target=wrapped, daemon=True)
        self.scan_thread.start()

    def _finish_scan_ui_state(self):
        self.btn_quick_test.configure(state="normal")
        self.btn_strong_test.configure(state="normal")
        self.btn_check_inputs.configure(state="normal")

    def _check_tcp_open(self, host: str, port: int, timeout: float) -> float:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return (time.perf_counter() - start) * 1000

    def _check_tls_sni(
        self, ip: str, port: int, sni: str, timeout: float
    ) -> tuple[float, str]:
        start = time.perf_counter()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as tls_sock:
                negotiated = tls_sock.version() or "UNKNOWN"
        return (time.perf_counter() - start) * 1000, negotiated

    def _check_tls_sni_profile(
        self,
        ip: str,
        port: int,
        sni: str,
        timeout: float,
        minimum_tls_version: ssl.TLSVersion | None,
        maximum_tls_version: ssl.TLSVersion | None,
    ) -> str:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if minimum_tls_version is not None:
            context.minimum_version = minimum_tls_version
        if maximum_tls_version is not None:
            context.maximum_version = maximum_tls_version
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as tls_sock:
                return tls_sock.version() or "UNKNOWN"

    def _strong_tls_profiles(
        self,
    ) -> list[tuple[str, ssl.TLSVersion | None, ssl.TLSVersion | None]]:
        profiles: list[tuple[str, ssl.TLSVersion | None, ssl.TLSVersion | None]] = []
        if hasattr(ssl, "TLSVersion"):
            tv = ssl.TLSVersion
            if hasattr(tv, "TLSv1_3"):
                profiles.append(("TLS1.3", tv.TLSv1_3, tv.TLSv1_3))
            if hasattr(tv, "TLSv1_2"):
                profiles.append(("TLS1.2", tv.TLSv1_2, tv.TLSv1_2))
            if hasattr(tv, "TLSv1_1"):
                profiles.append(("TLS1.1", tv.TLSv1_1, tv.TLSv1_1))
        profiles.append(("AUTO", None, None))
        return profiles

    def _simplify_exception(self, exc: Exception) -> str:
        text = str(exc).strip().lower()
        if "timed out" in text:
            return "timeout"
        if "refused" in text:
            return "connection refused"
        if "unreachable" in text:
            return "network unreachable"
        if "name" in text and "resolve" in text:
            return "dns error"
        if "certificate" in text:
            return "tls certificate error"
        if not text:
            return exc.__class__.__name__
        return text[:80]

    def _validate_test_inputs(self) -> tuple[str, int, list[str], float, int]:
        ip = self.test_ip_var.get().strip()
        if not ip:
            raise ValueError("Target IP is required")
        ipaddress.ip_address(ip)

        port = int(self.test_port_var.get().strip())
        if not (1 <= port <= 65535):
            raise ValueError("Port must be in range 1..65535")

        timeout = float(self.test_timeout_var.get().strip())
        if timeout <= 0:
            raise ValueError("Timeout must be positive")

        retries = int(self.test_retry_var.get().strip())
        if not (1 <= retries <= 10):
            raise ValueError("Retries must be in range 1..10")

        targets = self._parse_token_list(self.test_sni_list_var.get())
        if not targets:
            raise ValueError("At least one SNI is required")
        if len(targets) > MAX_SCAN_TARGETS:
            raise ValueError(
                f"Too many SNI targets ({len(targets)}), max={MAX_SCAN_TARGETS}"
            )

        return ip, port, targets, timeout, retries

    def check_test_inputs(self):
        try:
            ip, port, targets, timeout, retries = self._validate_test_inputs()
        except Exception as exc:
            self.log(f"[test] Input error: {exc}")
            return

        self.log(
            f"[test] ready: ip={ip}:{port} sni_count={len(targets)} timeout={timeout}s retries={retries}"
        )

    def run_quick_sni_test(self):
        def worker():
            ip, port, targets, timeout, _retries = self._validate_test_inputs()
            sni = targets[0]
            try:
                _ms, tls_ver = self._check_tls_sni(ip, port, sni, timeout)
            except Exception as exc:
                reason = self._simplify_exception(exc)
                self.output_queue.put(
                    f"[result] SNI='{sni}' on {ip}:{port} -> NOT CONNECTED (reason: {reason})\n"
                )
            else:
                self.output_queue.put(
                    f"[result] SNI='{sni}' on {ip}:{port} -> CONNECTED (tls={tls_ver})\n"
                )

        self._start_scan_job("quick SNI test", worker)

    def run_strong_sni_test(self):
        def worker():
            ip, port, targets, timeout, retries = self._validate_test_inputs()
            profiles = self._strong_tls_profiles()

            self.output_queue.put(
                f"[test] strong test started: {len(targets)} SNI on {ip}:{port} with {retries} retries\n"
            )

            ok_count = 0
            for sni in targets:
                connected = False
                success_tls = "-"
                last_reason = "unknown"

                for _attempt in range(1, retries + 1):
                    for _profile_name, min_v, max_v in profiles:
                        try:
                            tls_ver = self._check_tls_sni_profile(
                                ip,
                                port,
                                sni,
                                timeout,
                                minimum_tls_version=min_v,
                                maximum_tls_version=max_v,
                            )
                        except Exception as exc:
                            last_reason = self._simplify_exception(exc)
                            continue

                        connected = True
                        success_tls = tls_ver
                        break

                    if connected:
                        break
                    time.sleep(0.12)

                if connected:
                    ok_count += 1
                    self.output_queue.put(
                        f"[result] SNI='{sni}' on {ip}:{port} -> CONNECTED (tls={success_tls})\n"
                    )
                else:
                    self.output_queue.put(
                        f"[result] SNI='{sni}' on {ip}:{port} -> NOT CONNECTED (reason: {last_reason})\n"
                    )

            self.output_queue.put(
                f"[summary] connected={ok_count} not_connected={len(targets) - ok_count} total={len(targets)}\n"
            )

        self._start_scan_job("strong SNI test", worker)

    def _add_field(self, parent: tk.Frame, key: str, label: str):
        wrapper = tk.Frame(
            parent,
            bg=THEME["panel_card_soft"],
            highlightthickness=1,
            highlightbackground=THEME["edge_light"],
            bd=2,
            relief="ridge",
        )
        wrapper.pack(fill="x", padx=12, pady=7)

        tk.Label(
            wrapper,
            text=label,
            bg=THEME["panel_card_soft"],
            fg=THEME["text_secondary"],
            font=FONT_BODY_BOLD,
            anchor="w",
        ).pack(fill="x", padx=10, pady=(8, 4))

        var = tk.StringVar()
        self.vars[key] = var

        entry = self._make_entry(wrapper, var)
        entry.pack(fill="x", padx=10, pady=(0, 10), ipady=7)

    def _animate_header(self):
        if not self.header_animation_enabled:
            self.root.after(120, self._animate_header)
            return

        y1, y2 = (
            self.header.coords(self.scan_line)[1],
            self.header.coords(self.scan_line)[3],
        )
        if y1 <= 72:
            self.scan_dir = 2
        elif y1 >= 124:
            self.scan_dir = -2
        self.header.move(self.scan_line, 0, self.scan_dir)
        self.root.after(40, self._animate_header)

    def clear_logs(self):
        self.log_text.delete("1.0", "end")
        self.log("[ui] logs cleared")

    def toggle_header_animation(self):
        self.header_animation_enabled = not self.header_animation_enabled
        state = "enabled" if self.header_animation_enabled else "disabled"
        self.log(f"[ui] header animation {state}")

    def restart_core(self):
        self.stop_core()
        self.start_core()

    def show_quick_guide(self):
        messagebox.showinfo(
            "Quick Guide",
            "1) Fill the main configuration fields on the left panel and click Save Config.\n"
            "2) In SIMPLE TEST PANEL, set Target IP and Port.\n"
            "3) Enter one or more domains in SNI List (separate by space or comma).\n"
            "4) Click Check Inputs to validate your test settings.\n"
            "5) Quick Test checks only the first SNI quickly.\n"
            "6) Strong Test runs retries with multiple TLS profiles.\n"
            "7) Output is simple: CONNECTED or NOT CONNECTED.\n"
            "8) If test results are good, click Start Core.",
        )

    def show_about(self):
        messagebox.showinfo(
            "About SMART FOX",
            "SMART FOX Control\n"
            "Modern GUI for SNI Spoofing Core\n\n"
            "Original upstream project:\n"
            "SNI-Spoofing by patterniha\n"
            "https://github.com/patterniha/SNI-Spoofing\n\n"
            "Thank you to the original creator for building and sharing the base project.",
        )

    def _format_rate(self, value_bps: int) -> str:
        if value_bps < 1024:
            return f"{value_bps} B/s"
        if value_bps < 1024 * 1024:
            return f"{value_bps / 1024.0:.1f} KB/s"
        return f"{value_bps / (1024.0 * 1024.0):.2f} MB/s"

    def _try_update_speed_from_line(self, line: str) -> bool:
        m = re.search(
            r"\[speed\]\s+up_bps=(\d+)\s+down_bps=(\d+)\s+total_up=([^\s]+)\s+total_down=([^\s]+)\s+active=(\d+)",
            line,
        )
        if not m:
            return False

        up_bps = int(m.group(1))
        down_bps = int(m.group(2))
        self.up_speed_var.set(self._format_rate(up_bps))
        self.down_speed_var.set(self._format_rate(down_bps))
        self.total_up_var.set(m.group(3))
        self.total_down_var.set(m.group(4))
        self.active_conn_var.set(m.group(5))
        return True

    def _friendly_log_line(self, raw: str) -> str:
        line = raw.strip()
        if not line:
            return ""

        if line.startswith("[result]"):
            return line.replace("[result] ", "")
        if line.startswith("[summary]"):
            return "Final result: " + line.replace("[summary] ", "")
        if line.startswith("[test]"):
            return line.replace("[test] ", "")

        if "[startup][ok]" in line:
            return "[startup] Initial connectivity to target server succeeded."
        if "[startup][fail]" in line:
            return "[startup] Initial connectivity to target server failed. Check IP/Port and network route."
        if "LISTEN_HOST is 0.0.0.0" in line:
            return "[warning] Service is listening on all interfaces (0.0.0.0)."
        if "Suppressed Windows socket shutdown race" in line:
            return "[warning] A Windows socket shutdown race was handled safely."
        if "connect attempt" in line and "failed" in line:
            return "[connect] Connection attempt to target failed; retrying."
        if "connection handler crashed" in line.lower():
            return "[error] Connection handler crashed."
        if "Task was destroyed but it is pending" in line:
            return "[error] Async task shutdown was incomplete."
        if "SMART FOX" == line:
            return "[core] SMART FOX core started."
        if "ERROR asyncio" in line:
            return "[error] Internal asyncio error detected."
        if "WARNING" in line:
            return "[warning] Core warning detected."
        if "INFO" in line and "sni_spoofing" in line:
            return "[info] Core is running."

        return line

    def log(self, text: str):
        self.log_text.insert("end", text.rstrip() + "\n")
        self.log_text.see("end")

    def set_status(self, text: str, color: str):
        self.status_var.set(text)
        self.status_color.set(color)
        bg = "#284d35"
        if text.upper() == "OFFLINE":
            bg = "#5a4726"
        elif text.upper() == "ERROR":
            bg = "#5a2633"
        self.status_label.configure(bg=bg, fg="#f3fbff")

    def load_config_to_form(self):
        try:
            with self.config_path.open("r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as exc:
            messagebox.showerror("Config Error", f"Failed to read config.json\n{exc}")
            self.log(f"[error] failed to load config: {exc}")
            return

        defaults = CONFIG_DEFAULTS
        for key, var in self.vars.items():
            value = cfg.get(key, defaults.get(key, ""))
            if key == "ENABLE_TCP_NODELAY":
                value = str(bool(value)).lower()
            var.set(str(value))

        self.test_sni_list_var.set(str(cfg.get("FAKE_SNI", "")))
        self.test_ip_var.set(str(cfg.get("CONNECT_IP", "")))
        self.test_port_var.set(str(cfg.get("CONNECT_PORT", "443")))
        self.log("[config] loaded")

    def _form_to_typed_config(self) -> dict:
        cfg = {k: v.get().strip() for k, v in self.vars.items()}
        try:
            cfg["LISTEN_PORT"] = int(cfg["LISTEN_PORT"])
            cfg["CONNECT_PORT"] = int(cfg["CONNECT_PORT"])
            cfg["MAX_CONNECTIONS"] = int(cfg["MAX_CONNECTIONS"])
            cfg["MAX_CONNECTIONS_PER_IP"] = int(cfg["MAX_CONNECTIONS_PER_IP"])
            cfg["HANDSHAKE_TIMEOUT_SEC"] = float(cfg["HANDSHAKE_TIMEOUT_SEC"])
            cfg["RELAY_IDLE_TIMEOUT_SEC"] = float(cfg["RELAY_IDLE_TIMEOUT_SEC"])
            cfg["CONNECT_TIMEOUT_SEC"] = float(cfg["CONNECT_TIMEOUT_SEC"])
            cfg["CONNECT_RETRY_COUNT"] = int(cfg["CONNECT_RETRY_COUNT"])
            cfg["CONNECT_RETRY_DELAY_SEC"] = float(cfg["CONNECT_RETRY_DELAY_SEC"])
            cfg["RELAY_BUFFER_SIZE"] = int(cfg["RELAY_BUFFER_SIZE"])
            cfg["SOCKET_SNDBUF"] = int(cfg["SOCKET_SNDBUF"])
            cfg["SOCKET_RCVBUF"] = int(cfg["SOCKET_RCVBUF"])
        except ValueError as exc:
            raise ValueError("Numeric fields contain invalid values") from exc

        bool_token = str(cfg["ENABLE_TCP_NODELAY"]).strip().lower()
        if bool_token not in ("true", "false"):
            raise ValueError("ENABLE_TCP_NODELAY must be true or false")
        cfg["ENABLE_TCP_NODELAY"] = bool_token == "true"

        if not cfg["FAKE_SNI"]:
            raise ValueError("FAKE_SNI must not be empty")

        return cfg

    def save_form_to_config(self, show_success: bool = True) -> bool:
        try:
            cfg = self._form_to_typed_config()
            with self.config_path.open("w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception as exc:
            messagebox.showerror("Save Error", f"Failed to save config\n{exc}")
            self.log(f"[error] failed to save config: {exc}")
            return False

        self.log("[config] saved")
        if show_success:
            messagebox.showinfo("Saved", "Configuration updated successfully.")
        return True

    def start_core(self):
        if self.proc and self.proc.poll() is None:
            self.log("[core] already running")
            return

        if not self.save_form_to_config(show_success=False):
            return

        cmd = self._build_core_command()
        try:
            self.proc = subprocess.Popen(
                cmd,
                cwd=str(self.base_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            messagebox.showerror("Start Error", f"Failed to start main.py\n{exc}")
            self.log(f"[error] failed to start core: {exc}")
            self.set_status("ERROR", THEME["error"])
            return

        self.set_status("ONLINE", THEME["ok"])
        self.up_speed_var.set("0 B/s")
        self.down_speed_var.set("0 B/s")
        self.total_up_var.set("0 B")
        self.total_down_var.set("0 B")
        self.active_conn_var.set("0")
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.log("[core] started")

        self.output_thread = threading.Thread(
            target=self._read_process_output, daemon=True
        )
        self.output_thread.start()

    def _build_core_command(self) -> list[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable, "--run-core"]
        return [sys.executable, str(self.main_path)]

    def _read_process_output(self):
        assert self.proc is not None
        stream = self.proc.stdout
        if stream is None:
            return
        try:
            for line in stream:
                self.output_queue.put(line)
        finally:
            self.output_queue.put("[core] process output stream closed\n")

    def stop_core(self):
        if not self.proc or self.proc.poll() is not None:
            self.log("[core] not running")
            self.set_status("OFFLINE", THEME["warn"])
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            return

        self.log("[core] stopping...")
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

        self.set_status("OFFLINE", THEME["warn"])
        self.up_speed_var.set("0 B/s")
        self.down_speed_var.set("0 B/s")
        self.active_conn_var.set("0")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.log("[core] stopped")

    def _poll_output_queue(self):
        while True:
            try:
                line = self.output_queue.get_nowait()
            except queue.Empty:
                break
            else:
                if self._try_update_speed_from_line(line):
                    continue
                self.log(self._friendly_log_line(line))

        if self.proc and self.proc.poll() is not None:
            self.set_status("OFFLINE", THEME["warn"])
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")

        self.root.after(POLL_INTERVAL_MS, self._poll_output_queue)

    def on_close(self):
        self.stop_core()
        self.root.destroy()


if __name__ == "__main__":
    if "--run-core" in sys.argv:
        from main import run_core

        run_core()
        sys.exit(0)

    try:
        _ensure_admin_or_exit()
    except Exception as exc:
        print(f"[fatal] {exc}")
        sys.exit(1)

    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
