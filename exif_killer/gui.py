"""Desktop GUI for Exif Killer."""

from __future__ import annotations

import os
import re
import threading
import traceback
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from tkinter import TclError, filedialog, messagebox, simpledialog
from typing import Optional

import customtkinter as ctk
from tkinterdnd2 import DND_FILES, TkinterDnD

from .constants import SUPPORTED_EXTENSIONS
from .models import BatchResult, CleanResult, ScanResult, ToolConfig, VerificationResult
from .reporting import write_report
from .service import MetadataToolService
from .translations import get_current_language, get_text, toggle_language
from .version import DISPLAY_VERSION

COLORS = {
    "bg": "#0f1419",
    "panel": "#18212b",
    "panel_alt": "#1f2c38",
    "accent": "#2ec27e",
    "accent_hover": "#269e67",
    "text": "#f2f4f8",
    "muted": "#9eb0c0",
    "border": "#30414f",
}

FONTS = {
    "title": ("Consolas", 24, "bold"),
    "subtitle": ("Consolas", 12),
    "button": ("Consolas", 12, "bold"),
    "body": ("Consolas", 11),
    "small": ("Consolas", 10),
}

TIMESTAMP_MODES = ("auto", "keep", "epoch", "random", "custom")

# Built from the single source of truth so new formats show up in the file
# picker automatically instead of silently being unselectable.
SUPPORTED_FILE_GLOBS = " ".join(f"*{ext}" for ext in SUPPORTED_EXTENSIONS)


class DnDCTk(ctk.CTk):
    """CustomTkinter root with tkdnd support loaded into the Tk interpreter."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)


class ExifKillerApp:
    """Desktop GUI built on top of the shared MetadataToolService."""

    def __init__(self) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        self.root = DnDCTk(fg_color=COLORS["bg"])
        self.root.title(f"Exif Killer {DISPLAY_VERSION}")
        self.root.geometry("1180x860")
        self.root.minsize(1024, 720)
        self._main_thread = threading.get_ident()
        self.root.report_callback_exception = self._handle_tk_exception

        self.files: list[str] = []
        self.output_dir: Optional[str] = None
        self.overwrite = False
        self.is_busy = False
        self.current_batch: Optional[BatchResult] = None
        self.timestamp_value: Optional[str] = None

        self.profile_var = ctk.StringVar(value="safe")
        self.timestamp_var = ctk.StringVar(value="auto")
        self.status_var = ctk.StringVar(value=self.t("status_ready"))

        self._set_icon()
        self._build_ui()
        self._refresh_text()
        self._center_window()

    def t(self, key: str) -> str:
        return get_text(key)

    def _set_icon(self) -> None:
        icon_path = Path(__file__).resolve().parent.parent / "logo.png"
        if not icon_path.exists():
            return
        try:
            from PIL import Image, ImageTk

            image = Image.open(icon_path)
            photo = ImageTk.PhotoImage(image)
            self.root._icon_photo = photo
            self.root.iconphoto(True, photo)
        except Exception:
            return

    def _build_ui(self) -> None:
        self.main_frame = ctk.CTkFrame(self.root, fg_color=COLORS["bg"], corner_radius=0)
        self.main_frame.pack(fill="both", expand=True, padx=16, pady=16)

        self._build_header()

        content = ctk.CTkFrame(self.main_frame, fg_color=COLORS["bg"], corner_radius=0)
        content.pack(fill="both", expand=True)

        left = ctk.CTkFrame(content, fg_color=COLORS["bg"], corner_radius=0)
        left.pack(side="left", fill="both", expand=False, padx=(0, 10))

        right = ctk.CTkFrame(content, fg_color=COLORS["bg"], corner_radius=0)
        right.pack(side="left", fill="both", expand=True)

        self._build_drop_zone(left)
        self._build_file_queue(left)
        self._build_controls(left)
        self._build_progress(left)
        self._build_details(right)
        self._build_terminal()
        self._setup_drag_drop()

    def _build_header(self) -> None:
        header = ctk.CTkFrame(
            self.main_frame,
            fg_color=COLORS["panel"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        header.pack(fill="x", pady=(0, 12))

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=18, pady=16)

        self.title_label = ctk.CTkLabel(
            title_frame,
            text=self.t("title"),
            text_color=COLORS["text"],
            font=FONTS["title"],
        )
        self.title_label.pack(anchor="w")

        self.subtitle_label = ctk.CTkLabel(
            title_frame,
            text=self.t("subtitle"),
            text_color=COLORS["muted"],
            font=FONTS["subtitle"],
        )
        self.subtitle_label.pack(anchor="w", pady=(4, 0))

        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.pack(side="right", padx=18, pady=16)

        self.profile_label = ctk.CTkLabel(
            actions,
            text=self.t("profile_label"),
            text_color=COLORS["muted"],
            font=FONTS["small"],
        )
        self.profile_label.grid(row=0, column=0, padx=(0, 8), sticky="e")

        profile_selector = ctk.CTkFrame(actions, fg_color="transparent")
        profile_selector.grid(row=0, column=1, padx=(0, 12))

        self.profile_safe_button = ctk.CTkRadioButton(
            profile_selector,
            text=self.t("safe"),
            variable=self.profile_var,
            value="safe",
            text_color=COLORS["text"],
            font=FONTS["small"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["muted"],
        )
        self.profile_safe_button.pack(side="left", padx=(0, 8))

        self.profile_aggressive_button = ctk.CTkRadioButton(
            profile_selector,
            text=self.t("aggressive"),
            variable=self.profile_var,
            value="aggressive",
            text_color=COLORS["text"],
            font=FONTS["small"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["muted"],
        )
        self.profile_aggressive_button.pack(side="left")

        self.timestamp_label = ctk.CTkLabel(
            actions,
            text=self.t("timestamp_label"),
            text_color=COLORS["muted"],
            font=FONTS["small"],
        )
        self.timestamp_label.grid(row=1, column=0, padx=(0, 8), pady=(8, 0), sticky="e")

        self.timestamp_menu = ctk.CTkOptionMenu(
            actions,
            variable=self.timestamp_var,
            values=list(TIMESTAMP_MODES),
            command=self._on_timestamp_change,
            fg_color=COLORS["panel_alt"],
            button_color=COLORS["panel_alt"],
            button_hover_color=COLORS["border"],
            text_color=COLORS["text"],
            font=FONTS["small"],
            width=130,
        )
        self.timestamp_menu.grid(row=1, column=1, padx=(0, 12), pady=(8, 0), sticky="w")

        self.settings_button = ctk.CTkButton(
            actions,
            text=self.t("settings"),
            command=self._show_settings,
            fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"],
            text_color=COLORS["text"],
            font=FONTS["button"],
            width=110,
        )
        self.settings_button.grid(row=0, column=2, padx=(0, 8))

        self.lang_button = ctk.CTkButton(
            actions,
            text=get_current_language().upper(),
            command=self._toggle_language,
            fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"],
            text_color=COLORS["text"],
            font=FONTS["button"],
            width=64,
        )
        self.lang_button.grid(row=0, column=3)

    def _build_drop_zone(self, parent) -> None:
        self.drop_frame = ctk.CTkFrame(
            parent,
            width=340,
            height=140,
            fg_color=COLORS["panel"],
            corner_radius=16,
            border_width=2,
            border_color=COLORS["border"],
        )
        self.drop_frame.pack(fill="x", pady=(0, 12))
        self.drop_frame.pack_propagate(False)

        self.drop_title = ctk.CTkLabel(
            self.drop_frame,
            text=self.t("drop_title"),
            text_color=COLORS["text"],
            font=FONTS["button"],
        )
        self.drop_title.pack(pady=(34, 6))

        self.drop_hint = ctk.CTkLabel(
            self.drop_frame,
            text=self.t("drop_hint"),
            text_color=COLORS["muted"],
            font=FONTS["small"],
            wraplength=280,
            justify="center",
        )
        self.drop_hint.pack()

        for widget in (self.drop_frame, self.drop_title, self.drop_hint):
            widget.bind("<Button-1>", lambda _event: self.add_files())

    def _build_file_queue(self, parent) -> None:
        queue_panel = self._panel(parent, self.t("file_queue"))
        self.queue_panel = queue_panel
        queue_panel.pack(fill="both", expand=True, pady=(0, 12))

        self.file_box = ctk.CTkTextbox(
            queue_panel,
            fg_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=FONTS["body"],
            border_width=0,
            wrap="none",
        )
        self.file_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.file_box.insert("1.0", self.t("no_files"))
        self.file_box.configure(state="disabled")

    def _build_controls(self, parent) -> None:
        controls = ctk.CTkFrame(parent, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 12))

        self.add_button = self._action_button(controls, self.t("add_files"), self.add_files)
        self.add_button.grid(row=0, column=0, padx=(0, 8), pady=(0, 8), sticky="ew")

        self.add_folder_button = self._action_button(
            controls, self.t("add_folder"), self.add_folder
        )
        self.add_folder_button.grid(row=0, column=1, padx=(0, 8), pady=(0, 8), sticky="ew")

        self.scan_button = self._action_button(controls, self.t("scan"), self.scan_files)
        self.scan_button.grid(row=0, column=2, padx=(0, 0), pady=(0, 8), sticky="ew")

        self.clean_button = self._action_button(controls, self.t("clean"), self.clean_files)
        self.clean_button.grid(row=1, column=0, padx=(0, 8), sticky="ew")

        self.export_button = self._action_button(
            controls, self.t("export"), self.export_report
        )
        self.export_button.grid(row=1, column=1, padx=(0, 8), sticky="ew")
        self.export_button.configure(state="disabled")

        self.clear_button = self._action_button(controls, self.t("clear"), self.clear_files)
        self.clear_button.grid(row=1, column=2, sticky="nsew")

        for column in range(3):
            controls.grid_columnconfigure(column, weight=1)

    def _build_progress(self, parent) -> None:
        panel = self._panel(parent, self.t("status"))
        self.progress_panel = panel
        panel.pack(fill="x", pady=(0, 12))

        self.progress_bar = ctk.CTkProgressBar(panel, progress_color=COLORS["accent"])
        self.progress_bar.pack(fill="x", padx=10, pady=(0, 8))
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(
            panel,
            textvariable=self.status_var,
            text_color=COLORS["muted"],
            font=FONTS["small"],
        )
        self.status_label.pack(anchor="w", padx=10, pady=(0, 10))

        self.mode_label = ctk.CTkLabel(
            panel,
            text=self._build_mode_line(),
            text_color=COLORS["muted"],
            font=FONTS["small"],
            justify="left",
        )
        self.mode_label.pack(anchor="w", padx=10, pady=(0, 10))

    def _build_details(self, parent) -> None:
        details_panel = self._panel(parent, self.t("details"))
        self.details_panel = details_panel
        details_panel.pack(fill="both", expand=True, pady=(0, 12))

        self.details_box = ctk.CTkTextbox(
            details_panel,
            fg_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=FONTS["body"],
            border_width=0,
            wrap="word",
        )
        self.details_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.details_box.insert("1.0", self.t("no_details"))
        self.details_box.configure(state="disabled")

    def _build_terminal(self) -> None:
        terminal_panel = self._panel(self.main_frame, self.t("terminal"))
        self.terminal_panel = terminal_panel
        terminal_panel.pack(fill="both", expand=False)

        self.log_box = ctk.CTkTextbox(
            terminal_panel,
            height=180,
            fg_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=FONTS["body"],
            border_width=0,
            wrap="word",
        )
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log(f"[*] Exif Killer {DISPLAY_VERSION}")
        self.log("[*] Offline-first mode active.")

    def _panel(self, parent, title: str):
        panel = ctk.CTkFrame(
            parent,
            fg_color=COLORS["panel"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        label = ctk.CTkLabel(
            panel,
            text=title,
            text_color=COLORS["text"],
            font=FONTS["button"],
        )
        label.pack(anchor="w", padx=12, pady=(10, 8))
        panel._title_label = label
        return panel

    def _action_button(self, parent, text: str, command):
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color="#08120d",
            font=FONTS["button"],
            height=40,
        )

    def _center_window(self) -> None:
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _setup_drag_drop(self) -> None:
        self.drop_frame.drop_target_register(DND_FILES)
        self.drop_frame.dnd_bind("<<Drop>>", self._on_drop)
        self.drop_frame.dnd_bind("<<DragEnter>>", self._on_drag_enter)
        self.drop_frame.dnd_bind("<<DragLeave>>", self._on_drag_leave)

    def _on_drop(self, event) -> None:
        if self.is_busy:
            self.log(f"[!] {self.t('busy')}")
            return
        self._on_drag_leave(None)
        paths = self._parse_dropped_paths(event.data)
        self._add_paths(paths)

    def _on_drag_enter(self, event) -> None:
        self.drop_frame.configure(border_color=COLORS["accent"])

    def _on_drag_leave(self, event) -> None:
        self.drop_frame.configure(border_color=COLORS["border"])

    def _parse_dropped_paths(self, data: str) -> list[str]:
        if "{" not in data:
            return [value for value in data.split() if value]
        found = re.findall(r"\{([^}]+)\}", data)
        remaining = re.sub(r"\{[^}]+\}", "", data).strip()
        if remaining:
            found.extend(value for value in remaining.split() if value)
        return found

    def add_files(self) -> None:
        if self.is_busy:
            self.log(f"[!] {self.t('busy')}")
            return
        selections = filedialog.askopenfilenames(
            title=self.t("add_files"),
            filetypes=[
                ("Supported files", SUPPORTED_FILE_GLOBS),
                ("All files", "*.*"),
            ],
        )
        if selections:
            self._add_paths(list(selections))

    def add_folder(self) -> None:
        if self.is_busy:
            self.log(f"[!] {self.t('busy')}")
            return
        selected = filedialog.askdirectory(title=self.t("select_folder_to_queue"))
        if selected:
            self._add_paths([selected])

    def _add_paths(self, raw_paths: list[str]) -> None:
        service = MetadataToolService(ToolConfig(profile=self._get_profile(), recursive=True))
        supported, unsupported = service.discover_inputs(raw_paths)

        added = 0
        for file_path in supported:
            if file_path not in self.files:
                self.files.append(file_path)
                added += 1

        if added:
            self.log(f"[*] {self.t('files_added').format(count=added)}")

        if unsupported:
            self.log(f"[!] {self.t('unsupported_skipped').format(count=len(unsupported))}")

        self._refresh_file_box()

    def scan_files(self) -> None:
        if self.is_busy:
            self.log(f"[!] {self.t('busy')}")
            return
        if not self.files:
            self.log(f"[!] {self.t('nothing_to_scan')}")
            return
        self.log(f"[*] {self.t('scan_started')}")
        self._run_background_task("scan", self._scan_worker)

    def clean_files(self) -> None:
        if self.is_busy:
            self.log(f"[!] {self.t('busy')}")
            return
        if not self.files:
            self.log(f"[!] {self.t('nothing_to_clean')}")
            return
        if self.overwrite and not messagebox.askyesno(
            self.t("settings"),
            "Overwrite mode is enabled. Continue?",
        ):
            return
        self.log(f"[*] {self.t('clean_started')}")
        self._run_background_task("clean", self._clean_worker)

    def export_report(self) -> None:
        if self.current_batch is None:
            self.log(f"[!] {self.t('no_report')}")
            return

        path = filedialog.asksaveasfilename(
            title=self.t("export"),
            initialfile=f"exif-killer-{self.current_batch.command}-report.json",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("CSV report", "*.csv")],
        )
        if not path:
            return

        report_format = "csv" if path.lower().endswith(".csv") else "json"
        try:
            write_report(self.current_batch, path, report_format)
            self.log(f"[*] {self.t('report_saved').format(path=Path(path).resolve())}")
        except Exception as exc:
            self.log(f"[!] {self.t('report_failed').format(error=exc)}")

    def clear_files(self) -> None:
        if self.is_busy:
            self.log(f"[!] {self.t('busy')}")
            return
        self.files.clear()
        self.current_batch = None
        self.progress_bar.set(0)
        self.status_var.set(self.t("status_ready"))
        self._refresh_file_box()
        self._set_details(self.t("no_details"))
        self.log("[*] Queue cleared.")

    def _show_settings(self) -> None:
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(self.t("settings_title"))
        dialog.geometry("480x220")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ctk.CTkFrame(dialog, fg_color=COLORS["panel"])
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        output_label = ctk.CTkLabel(
            frame,
            text=self.t("output_dir"),
            text_color=COLORS["text"],
            font=FONTS["button"],
        )
        output_label.pack(anchor="w", pady=(12, 6), padx=12)

        entry_frame = ctk.CTkFrame(frame, fg_color="transparent")
        entry_frame.pack(fill="x", padx=12)

        output_var = ctk.StringVar(value=self.output_dir or "")
        output_entry = ctk.CTkEntry(
            entry_frame,
            textvariable=output_var,
            fg_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
        )
        output_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        def choose_folder() -> None:
            selected = filedialog.askdirectory(title=self.t("choose_folder"))
            if selected:
                output_var.set(selected)

        ctk.CTkButton(
            entry_frame,
            text=self.t("choose_folder"),
            command=choose_folder,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color="#08120d",
            font=FONTS["button"],
            width=120,
        ).pack(side="left")

        overwrite_var = ctk.BooleanVar(value=self.overwrite)
        overwrite_switch = ctk.CTkSwitch(
            frame,
            text=self.t("overwrite"),
            variable=overwrite_var,
            text_color=COLORS["text"],
            progress_color=COLORS["accent"],
            button_color=COLORS["accent"],
            button_hover_color=COLORS["accent_hover"],
        )
        overwrite_switch.pack(anchor="w", padx=12, pady=(20, 18))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", padx=12, pady=(0, 12))

        def save_settings() -> None:
            value = output_var.get().strip()
            self.output_dir = value or None
            self.overwrite = overwrite_var.get()
            self._refresh_mode_label()
            dialog.destroy()

        ctk.CTkButton(
            buttons,
            text=self.t("save"),
            command=save_settings,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color="#08120d",
            font=FONTS["button"],
            width=120,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            buttons,
            text=self.t("cancel"),
            command=dialog.destroy,
            fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"],
            text_color=COLORS["text"],
            font=FONTS["button"],
            width=120,
        ).pack(side="left")

    def _toggle_language(self) -> None:
        toggle_language()
        self._refresh_text()

    def _refresh_text(self) -> None:
        self.root.title(f"{self.t('title')} {DISPLAY_VERSION}")
        self.title_label.configure(text=self.t("title"))
        self.subtitle_label.configure(text=self.t("subtitle"))
        self.drop_title.configure(text=self.t("drop_title"))
        self.drop_hint.configure(text=self.t("drop_hint"))
        self.queue_panel._title_label.configure(text=self.t("file_queue"))
        self.progress_panel._title_label.configure(text=self.t("status"))
        self.details_panel._title_label.configure(text=self.t("details"))
        self.terminal_panel._title_label.configure(text=self.t("terminal"))
        self.add_button.configure(text=self.t("add_files"))
        self.add_folder_button.configure(text=self.t("add_folder"))
        self.scan_button.configure(text=self.t("scan"))
        self.clean_button.configure(text=self.t("clean"))
        self.clear_button.configure(text=self.t("clear"))
        self.export_button.configure(text=self.t("export"))
        self.settings_button.configure(text=self.t("settings"))
        self.profile_label.configure(text=self.t("profile_label"))
        self.profile_safe_button.configure(text=self.t("safe"))
        self.profile_aggressive_button.configure(text=self.t("aggressive"))
        self.timestamp_label.configure(text=self.t("timestamp_label"))
        self.lang_button.configure(text=get_current_language().upper())
        self.status_var.set(self.t("status_ready") if not self.is_busy else self.status_var.get())
        self._refresh_mode_label()
        self._refresh_file_box()
        if self.current_batch is None:
            self._set_details(self.t("no_details"))
        else:
            self._set_details(self._format_batch_details(self.current_batch))

    def _run_background_task(self, task_name: str, worker) -> None:
        self.is_busy = True
        self.progress_bar.set(0)
        self._set_controls_state("disabled")
        self.status_var.set(task_name.capitalize())
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

    def _scan_worker(self) -> None:
        service = self._make_service()
        batch = service.scan_paths(self.files, progress_callback=self._progress_callback)
        self._finish_batch(batch)

    def _clean_worker(self) -> None:
        service = self._make_service()
        batch = service.clean_paths(self.files, progress_callback=self._progress_callback)
        self._finish_batch(batch)

    def _finish_batch(self, batch: BatchResult) -> None:
        self.root.after(0, lambda: self._apply_batch(batch))

    def _apply_batch(self, batch: BatchResult) -> None:
        self.is_busy = False
        self.current_batch = batch
        self._set_controls_state("normal")
        self.progress_bar.set(1 if batch.results else 0)
        self.status_var.set(self.t("complete"))
        self._set_details(self._format_batch_details(batch))
        self.log(
            "[*] "
            + self.t("batch_summary").format(
                clean=batch.clean_count,
                warning=batch.warning_count,
                error=batch.error_count,
                unsupported=len(batch.unsupported_inputs),
            )
        )

    def _make_service(self) -> MetadataToolService:
        return MetadataToolService(
            ToolConfig(
                profile=self._get_profile(),
                output_dir=self.output_dir,
                overwrite=self.overwrite,
                recursive=True,
                timestamp_mode=self._get_timestamp_mode(),
                timestamp_value=self.timestamp_value,
            ),
            logger=self.log,
        )

    def _progress_callback(self, current: int, total: int, file_path: str) -> None:
        def apply() -> None:
            progress = 0 if total == 0 else current / total
            self.progress_bar.set(progress)
            self.status_var.set(
                self.t("processing").format(
                    current=current,
                    total=total,
                    name=os.path.basename(file_path),
                )
            )

        self.root.after(0, apply)

    def _set_controls_state(self, state: str) -> None:
        self.add_button.configure(state=state)
        self.add_folder_button.configure(state=state)
        self.scan_button.configure(state=state)
        self.clean_button.configure(state=state)
        self.clear_button.configure(state=state)
        self.export_button.configure(state=state if self.current_batch else "disabled")
        self.settings_button.configure(state=state)
        self.profile_safe_button.configure(state=state)
        self.profile_aggressive_button.configure(state=state)
        self.timestamp_menu.configure(state=state)
        self.lang_button.configure(state=state)

    def _refresh_file_box(self) -> None:
        self.file_box.configure(state="normal")
        self.file_box.delete("1.0", "end")
        if not self.files:
            self.file_box.insert("1.0", self.t("no_files"))
        else:
            for index, file_path in enumerate(self.files, start=1):
                self.file_box.insert(
                    "end",
                    f"{index:02d}. {os.path.basename(file_path)}\n    {file_path}\n\n",
                )
        self.file_box.configure(state="disabled")
        self._refresh_mode_label()
        self.export_button.configure(
            state="normal" if self.current_batch and not self.is_busy else "disabled"
        )

    def _set_details(self, text: str) -> None:
        self.details_box.configure(state="normal")
        self.details_box.delete("1.0", "end")
        self.details_box.insert("1.0", text)
        self.details_box.configure(state="disabled")

    def _format_batch_details(self, batch: BatchResult) -> str:
        lines = [
            f"{self.t('overview')}",
            f"{self.t('status')}: {batch.command}",
            self._build_mode_line(),
            self.t("batch_summary").format(
                clean=batch.clean_count,
                warning=batch.warning_count,
                error=batch.error_count,
                unsupported=len(batch.unsupported_inputs),
            ),
        ]

        for result in batch.results:
            lines.extend(["", "-" * 72])
            lines.extend(self._format_result_details(result))

        return "\n".join(lines)

    def _format_result_details(self, result: ScanResult | CleanResult | VerificationResult) -> list[str]:
        lines = [
            result.input_path,
            f"{self.t('type')}: {result.file_type}",
            f"{self.t('status')}: {result.status}",
            f"{self.t('profile')}: {self._get_profile()}",
            f"{self.t('metadata_fields')}: {result.before_count}",
            f"{self.t('hash_before')}: {result.sha256_before or '-'}",
        ]

        if isinstance(result, ScanResult):
            findings = result.findings
        else:
            lines.append(f"{self.t('output_path')}: {result.output_path}")
            lines.append(f"{self.t('hash_after')}: {result.sha256_after or '-'}")
            lines.append(f"{self.t('removed_fields')}: {len(result.removed_fields)}")
            if result.removed_fields:
                lines.extend(f"  - {field}" for field in result.removed_fields[:12])
            findings = result.remaining_findings

        if result.warnings:
            lines.append(self.t("warnings") + ":")
            lines.extend(f"  - {warning}" for warning in result.warnings[:12])

        if findings:
            grouped = defaultdict(list)
            for finding in findings:
                grouped[finding.category].append(f"{finding.key}: {finding.value}")
            lines.append(self.t("findings") + ":")
            for category, values in sorted(grouped.items()):
                lines.append(f"  [{category}]")
                lines.extend(f"    - {value}" for value in values[:8])

        if result.error:
            lines.append(f"error: {result.error}")

        return lines

    def log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"
        try:
            if threading.get_ident() == self._main_thread:
                self._append_log(line)
            else:
                self.root.after(0, lambda: self._append_log(line))
        except Exception:
            print(line, end="", flush=True)

    def _append_log(self, line: str) -> None:
        try:
            self.log_box.insert("end", line)
            self.log_box.see("end")
        except Exception:
            print(line, end="", flush=True)

    def _get_profile(self) -> str:
        profile = self.profile_var.get()
        return profile if profile in {"safe", "aggressive"} else "safe"

    def _get_timestamp_mode(self) -> str:
        mode = self.timestamp_var.get()
        if mode not in TIMESTAMP_MODES:
            return "auto"
        # 'custom' without a date would be rejected by the service; fall back.
        if mode == "custom" and not self.timestamp_value:
            return "auto"
        return mode

    def _on_timestamp_change(self, mode: str) -> None:
        if mode != "custom":
            self.timestamp_value = None
            self.log(f"[*] {self.t('timestamp_set').format(mode=mode)}")
            return

        answer = simpledialog.askstring(
            self.t("timestamp_label"),
            self.t("timestamp_prompt"),
            initialvalue=self.timestamp_value or "2020-01-01",
            parent=self.root,
        )
        if not answer or not self._validate_timestamp_value(answer.strip()):
            if answer is not None:
                messagebox.showerror(
                    self.t("timestamp_label"), self.t("timestamp_invalid")
                )
            self.timestamp_var.set("auto")
            self.timestamp_value = None
            return

        self.timestamp_value = answer.strip()
        self.log(f"[*] {self.t('timestamp_custom_set').format(date=self.timestamp_value)}")

    @staticmethod
    def _validate_timestamp_value(value: str) -> bool:
        for pattern in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                datetime.strptime(value, pattern)
                return True
            except ValueError:
                continue
        return False

    def _handle_tk_exception(self, exc_type, exc_value, exc_traceback) -> None:
        details = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        print(details, flush=True)
        try:
            self.log(f"[GUI-ERROR] {exc_value}")
        except Exception:
            pass
        try:
            if self.root.winfo_exists():
                messagebox.showerror(
                    "Exif Killer Error",
                    f"An unexpected GUI error occurred:\n\n{exc_value}",
                    parent=self.root,
                )
        except (TclError, Exception):
            pass

    def _build_mode_line(self) -> str:
        if self.overwrite:
            output_mode = self.t("overwrite_mode")
        elif self.output_dir:
            output_mode = f"{self.t('custom_output_mode')}: {self.output_dir}"
        else:
            output_mode = self.t("same_folder_mode")
        return (
            f"{self.t('queue_count')}: {len(self.files)}\n"
            f"{self.t('output_mode')}: {output_mode}"
        )

    def _refresh_mode_label(self) -> None:
        self.mode_label.configure(text=self._build_mode_line())

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    """GUI entry point."""
    app = ExifKillerApp()
    app.run()
    return 0
