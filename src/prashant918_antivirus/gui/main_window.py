"""
Prashant918 Advanced Antivirus - GUI Application

Modern GUI interface with proper dependency handling.
"""

import os
import sys
import threading
import queue
import time
from typing import Dict, Any, Optional, List
from datetime import datetime

# Check for tkinter availability
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False
    print("Warning: tkinter not available. GUI functionality disabled.")

# Import other modules with error handling
try:
    from ..antivirus.engine import AdvancedThreatDetectionEngine
    ENGINE_AVAILABLE = True
except ImportError:
    ENGINE_AVAILABLE = False
    print("Warning: Antivirus engine not available")

try:
    from ..core.quarantine import QuarantineManager
    QUARANTINE_AVAILABLE = True
except ImportError:
    QUARANTINE_AVAILABLE = False
    print("Warning: Quarantine manager not available")

try:
    from ..antivirus.signatures import AdvancedSignatureManager
    SIGNATURES_AVAILABLE = True
except ImportError:
    SIGNATURES_AVAILABLE = False
    print("Warning: Signature manager not available")

try:
    from ..core.realtime_monitor import RealtimeMonitor
    MONITOR_AVAILABLE = True
except ImportError:
    MONITOR_AVAILABLE = False
    print("Warning: Real-time monitor not available")

try:
    from ..antivirus.logger import SecureLogger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    # Create a simple logger replacement
    class SecureLogger:
        def __init__(self, name):
            self.name = name
        def info(self, msg): print(f"INFO: {msg}")
        def warning(self, msg): print(f"WARNING: {msg}")
        def error(self, msg): print(f"ERROR: {msg}")

try:
    from ..utils import format_bytes, format_duration
    UTILS_AVAILABLE = True
except ImportError:
    UTILS_AVAILABLE = False
    def format_bytes(size): return f"{size} bytes"
    def format_duration(seconds): return f"{seconds:.2f}s"

class AntivirusGUI:
    """Main GUI application with dependency checking"""
    
    def __init__(self):
        if not TKINTER_AVAILABLE:
            raise ImportError("tkinter is required for GUI functionality")
        
        self.logger = SecureLogger("GUI")
        
        # Initialize components with availability checks
        self.threat_engine = None
        self.quarantine_manager = None
        self.signature_manager = None
        self.realtime_monitor = None
        
        if ENGINE_AVAILABLE:
            try:
                self.threat_engine = AdvancedThreatDetectionEngine()
            except Exception as e:
                self.logger.error(f"Failed to initialize threat engine: {e}")
        
        if QUARANTINE_AVAILABLE:
            try:
                self.quarantine_manager = QuarantineManager()
            except Exception as e:
                self.logger.error(f"Failed to initialize quarantine manager: {e}")
        
        if SIGNATURES_AVAILABLE:
            try:
                self.signature_manager = AdvancedSignatureManager()
            except Exception as e:
                self.logger.error(f"Failed to initialize signature manager: {e}")
        
        if MONITOR_AVAILABLE:
            try:
                self.realtime_monitor = RealtimeMonitor()
            except Exception as e:
                self.logger.error(f"Failed to initialize real-time monitor: {e}")
        
        # GUI state
        self.scanning = False
        self.monitoring = False
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("Prashant918 Advanced Antivirus")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Configure style
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except:
            pass  # Use default theme if clam not available
        
        # Create GUI components
        self._create_menu()
        self._create_main_interface()
        self._create_status_bar()
        
        # Start status updates
        self._start_status_updates()
    
    def _create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        
        if self.threat_engine:
            file_menu.add_command(label="Scan File...", command=self._scan_file)
            file_menu.add_command(label="Scan Folder...", command=self._scan_folder)
        else:
            file_menu.add_command(label="Scan File... (Unavailable)", state=tk.DISABLED)
            file_menu.add_command(label="Scan Folder... (Unavailable)", state=tk.DISABLED)
        
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        if self.signature_manager:
            tools_menu.add_command(label="Update Signatures", command=self._update_signatures)
        else:
            tools_menu.add_command(label="Update Signatures (Unavailable)", state=tk.DISABLED)
        
        if self.quarantine_manager:
            tools_menu.add_command(label="Quarantine Manager", command=self._open_quarantine_manager)
        else:
            tools_menu.add_command(label="Quarantine Manager (Unavailable)", state=tk.DISABLED)
        
        if self.realtime_monitor:
            tools_menu.add_command(label="Real-time Protection", command=self._toggle_realtime_protection)
        else:
            tools_menu.add_command(label="Real-time Protection (Unavailable)", state=tk.DISABLED)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)
    
    def _create_main_interface(self):
        """Create main interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Scan tab
        self._create_scan_tab()
        
        # Protection tab
        self._create_protection_tab()
        
        # Quarantine tab (only if available)
        if self.quarantine_manager:
            self._create_quarantine_tab()
        
        # Statistics tab (only if available)
        if self.signature_manager:
            self._create_statistics_tab()
        
        # Logs tab
        self._create_logs_tab()
    
    def _create_scan_tab(self):
        """Create scan tab"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Scan")
        
        if not self.threat_engine:
            # Show unavailable message
            unavailable_label = ttk.Label(
                scan_frame, 
                text="Scan functionality is not available.\nPlease check that all dependencies are installed.",
                font=("Arial", 12),
                foreground="red"
            )
            unavailable_label.pack(expand=True)
            return
        
        # Scan options frame
        options_frame = ttk.LabelFrame(scan_frame, text="Scan Options")
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Scan type
        ttk.Label(options_frame, text="Scan Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.scan_type = tk.StringVar(value="quick")
        ttk.Radiobutton(options_frame, text="Quick Scan", variable=self.scan_type, value="quick").grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(options_frame, text="Full Scan", variable=self.scan_type, value="full").grid(row=0, column=2, sticky=tk.W, padx=5)
        ttk.Radiobutton(options_frame, text="Custom Scan", variable=self.scan_type, value="custom").grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Scan path
        ttk.Label(options_frame, text="Scan Path:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.scan_path = tk.StringVar()
        path_entry = ttk.Entry(options_frame, textvariable=self.scan_path, width=50)
        path_entry.grid(row=1, column=1, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
        ttk.Button(options_frame, text="Browse", command=self._browse_scan_path).grid(row=1, column=3, padx=5, pady=5)
        
        # Scan buttons
        button_frame = ttk.Frame(options_frame)
        button_frame.grid(row=2, column=0, columnspan=4, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self._start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self._stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(scan_frame, text="Scan Progress")
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_label = ttk.Label(progress_frame, text="Ready to scan")
        self.progress_label.pack(pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(scan_frame, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Results tree
        columns = ("File", "Status", "Threat", "Action")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=200)
        
        # Scrollbars for results tree
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky=tk.NSEW)
        v_scrollbar.grid(row=0, column=1, sticky=tk.NS)
        h_scrollbar.grid(row=1, column=0, sticky=tk.EW)
        
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
    
    def _create_protection_tab(self):
        """Create real-time protection tab"""
        protection_frame = ttk.Frame(self.notebook)
        self.notebook.add(protection_frame, text="Protection")
        
        if not self.realtime_monitor:
            # Show unavailable message
            unavailable_label = ttk.Label(
                protection_frame, 
                text="Real-time protection is not available.\nPlease check that all dependencies are installed.",
                font=("Arial", 12),
                foreground="red"
            )
            unavailable_label.pack(expand=True)
            return
        
        # Protection status
        status_frame = ttk.LabelFrame(protection_frame, text="Protection Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.protection_status = ttk.Label(status_frame, text="Real-time Protection: Disabled", font=("Arial", 12, "bold"))
        self.protection_status.pack(pady=10)
        
        self.protection_button = ttk.Button(status_frame, text="Enable Protection", command=self._toggle_protection)
        self.protection_button.pack(pady=5)
        
        # Protection settings
        settings_frame = ttk.LabelFrame(protection_frame, text="Protection Settings")
        settings_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.monitor_downloads = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Monitor Downloads", variable=self.monitor_downloads).pack(anchor=tk.W, padx=10, pady=2)
        
        self.monitor_usb = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Monitor USB Devices", variable=self.monitor_usb).pack(anchor=tk.W, padx=10, pady=2)
        
        self.monitor_network = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Monitor Network Activity", variable=self.monitor_network).pack(anchor=tk.W, padx=10, pady=2)
        
        # Recent threats
        threats_frame = ttk.LabelFrame(protection_frame, text="Recent Threats")
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        threat_columns = ("Time", "File", "Threat", "Action")
        self.threats_tree = ttk.Treeview(threats_frame, columns=threat_columns, show="headings", height=10)
        
        for col in threat_columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=150)
        
        threats_scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=threats_scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        threats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _create_quarantine_tab(self):
        """Create quarantine management tab"""
        quarantine_frame = ttk.Frame(self.notebook)
        self.notebook.add(quarantine_frame, text="Quarantine")
        
        # Quarantine controls
        controls_frame = ttk.Frame(quarantine_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(controls_frame, text="Refresh", command=self._refresh_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Restore Selected", command=self._restore_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Delete Selected", command=self._delete_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Clean Old Items", command=self._clean_quarantine).pack(side=tk.LEFT, padx=5)
        
        # Quarantine list
        quarantine_columns = ("ID", "Original Path", "Threat", "Date", "Status")
        self.quarantine_tree = ttk.Treeview(quarantine_frame, columns=quarantine_columns, show="headings", height=20)
        
        for col in quarantine_columns:
            self.quarantine_tree.heading(col, text=col)
            self.quarantine_tree.column(col, width=200)
        
        quarantine_scrollbar = ttk.Scrollbar(quarantine_frame, orient=tk.VERTICAL, command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=quarantine_scrollbar.set)
        
        self.quarantine_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)
        quarantine_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Load quarantine items
        self._refresh_quarantine()
    
    def _create_statistics_tab(self):
        """Create statistics tab"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statistics")
        
        # Statistics display
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=30, width=80)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Refresh button
        ttk.Button(stats_frame, text="Refresh Statistics", command=self._refresh_statistics).pack(pady=5)
        
        # Load initial statistics
        self._refresh_statistics()
    
    def _create_logs_tab(self):
        """Create logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Log controls
        log_controls = ttk.Frame(logs_frame)
        log_controls.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(log_controls, text="Log Level:").pack(side=tk.LEFT, padx=5)
        self.log_level = tk.StringVar(value="INFO")
        log_level_combo = ttk.Combobox(log_controls, textvariable=self.log_level, values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        log_level_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(log_controls, text="Refresh", command=self._refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="Clear", command=self._clear_logs).pack(side=tk.LEFT, padx=5)
        
        # Log display
        self.log_text = scrolledtext.ScrolledText(logs_frame, height=25, width=100)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def _create_status_bar(self):
        """Create status bar"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(self.status_bar, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Signature status
        if self.signature_manager:
            self.signature_status = ttk.Label(self.status_bar, text="Signatures: Loading...")
        else:
            self.signature_status = ttk.Label(self.status_bar, text="Signatures: Unavailable")
        self.signature_status.pack(side=tk.RIGHT, padx=5)
    
    def _start_status_updates(self):
        """Start periodic status updates"""
        def update_status():
            try:
                # Update signature count
                if self.signature_manager:
                    try:
                        stats = self.signature_manager.get_signature_stats()
                        total_sigs = stats.get('hash_signatures', 0) + stats.get('pattern_signatures', 0)
                        self.signature_status.config(text=f"Signatures: {total_sigs}")
                    except Exception as e:
                        self.signature_status.config(text="Signatures: Error")
                
                # Update protection status
                if self.realtime_monitor:
                    if self.monitoring:
                        self.protection_status.config(text="Real-time Protection: Enabled", foreground="green")
                        self.protection_button.config(text="Disable Protection")
                    else:
                        self.protection_status.config(text="Real-time Protection: Disabled", foreground="red")
                        self.protection_button.config(text="Enable Protection")
                
            except Exception as e:
                self.logger.error(f"Status update error: {e}")
            
            # Schedule next update
            self.root.after(5000, update_status)  # Update every 5 seconds
        
        update_status()
    
    def _scan_file(self):
        """Scan single file"""
        if not self.threat_engine:
            messagebox.showerror("Error", "Scan functionality not available")
            return
            
        file_path = filedialog.askopenfilename(title="Select file to scan")
        if file_path:
            self.scan_path.set(file_path)
            self._start_scan()
    
    def _scan_folder(self):
        """Scan folder"""
        if not self.threat_engine:
            messagebox.showerror("Error", "Scan functionality not available")
            return
            
        folder_path = filedialog.askdirectory(title="Select folder to scan")
        if folder_path:
            self.scan_path.set(folder_path)
            self._start_scan()
    
    def _browse_scan_path(self):
        """Browse for scan path"""
        if self.scan_type.get() == "custom":
            path = filedialog.askdirectory(title="Select folder to scan")
        else:
            path = filedialog.askopenfilename(title="Select file to scan")
        
        if path:
            self.scan_path.set(path)
    
    def _start_scan(self):
        """Start scanning process"""
        if self.scanning or not self.threat_engine:
            return
        
        scan_path = self.scan_path.get()
        if not scan_path:
            messagebox.showerror("Error", "Please select a file or folder to scan")
            return
        
        if not os.path.exists(scan_path):
            messagebox.showerror("Error", "Selected path does not exist")
            return
        
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self._scan_worker, args=(scan_path,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def _scan_worker(self, scan_path):
        """Worker thread for scanning"""
        try:
            if os.path.isfile(scan_path):
                files_to_scan = [scan_path]
            else:
                files_to_scan = []
                for root, dirs, files in os.walk(scan_path):
                    for file in files:
                        files_to_scan.append(os.path.join(root, file))
            
            total_files = len(files_to_scan)
            scanned_files = 0
            
            for file_path in files_to_scan:
                if not self.scanning:
                    break
                
                try:
                    # Update progress
                    progress = (scanned_files / total_files) * 100 if total_files > 0 else 0
                    self.root.after(0, self._update_progress, progress, f"Scanning: {os.path.basename(file_path)}")
                    
                    # Scan file
                    result = self.threat_engine.scan_file(file_path)
                    
                    # Add result to tree
                    status = result['classification']
                    threat = "Clean"
                    action = "None"
                    
                    if result['detections']:
                        threat = result['detections'][0].get('threat_name', 'Unknown')
                        if status in ['MALICIOUS', 'SUSPICIOUS']:
                            action = "Quarantine"
                    
                    self.root.after(0, self._add_scan_result, file_path, status, threat, action)
                    
                    scanned_files += 1
                    
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
                    self.root.after(0, self._add_scan_result, file_path, "ERROR", str(e), "None")
            
            # Scan completed
            self.root.after(0, self._scan_completed)
            
        except Exception as e:
            self.logger.error(f"Scan worker error: {e}")
            self.root.after(0, self._scan_completed)
    
    def _update_progress(self, progress, status):
        """Update progress bar and status"""
        self.progress_var.set(progress)
        self.progress_label.config(text=status)
        self.status_label.config(text=status)
    
    def _add_scan_result(self, file_path, status, threat, action):
        """Add scan result to tree"""
        # Color code based on status
        tags = ()
        if status == "MALICIOUS":
            tags = ("malicious",)
        elif status == "SUSPICIOUS":
            tags = ("suspicious",)
        elif status == "ERROR":
            tags = ("error",)
        
        self.results_tree.insert("", tk.END, values=(
            os.path.basename(file_path),
            status,
            threat,
            action
        ), tags=tags)
        
        # Configure tag colors
        self.results_tree.tag_configure("malicious", background="#ffcccc")
        self.results_tree.tag_configure("suspicious", background="#ffffcc")
        self.results_tree.tag_configure("error", background="#cccccc")
    
    def _scan_completed(self):
        """Handle scan completion"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set(100)
        self.progress_label.config(text="Scan completed")
        self.status_label.config(text="Scan completed")
        
        messagebox.showinfo("Scan Complete", "File scan has been completed.")
    
    def _stop_scan(self):
        """Stop scanning process"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_label.config(text="Scan stopped")
        self.status_label.config(text="Ready")
    
    def _toggle_protection(self):
        """Toggle real-time protection"""
        if not self.realtime_monitor:
            messagebox.showerror("Error", "Real-time protection not available")
            return
            
        if self.monitoring:
            self.realtime_monitor.stop_monitoring()
            self.monitoring = False
            messagebox.showinfo("Protection", "Real-time protection disabled")
        else:
            try:
                self.realtime_monitor.start_monitoring(["."])
                self.monitoring = True
                messagebox.showinfo("Protection", "Real-time protection enabled")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to enable protection: {e}")
    
    def _update_signatures(self):
        """Update threat signatures"""
        if not self.signature_manager:
            messagebox.showerror("Error", "Signature manager not available")
            return
            
        def update_worker():
            try:
                self.root.after(0, lambda: self.status_label.config(text="Updating signatures..."))
                success = self.signature_manager.update_from_cloud()
                
                if success:
                    self.root.after(0, lambda: messagebox.showinfo("Update", "Signatures updated successfully"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Update", "Signature update failed"))
                
                self.root.after(0, lambda: self.status_label.config(text="Ready"))
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Update failed: {e}"))
                self.root.after(0, lambda: self.status_label.config(text="Ready"))
        
        update_thread = threading.Thread(target=update_worker)
        update_thread.daemon = True
        update_thread.start()
    
    def _refresh_quarantine(self):
        """Refresh quarantine list"""
        if not self.quarantine_manager:
            return
            
        # Clear existing items
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        
        try:
            # Load quarantine items
            items = self.quarantine_manager.list_quarantined_items()
            
            for item in items:
                self.quarantine_tree.insert("", tk.END, values=(
                    item['quarantine_id'][:8] + "...",
                    item['original_path'],
                    item['threat_name'],
                    item['quarantined_at'][:19] if item['quarantined_at'] else "",
                    item['status']
                ))
        except Exception as e:
            self.logger.error(f"Failed to refresh quarantine: {e}")
    
    def _restore_selected(self):
        """Restore selected quarantine item"""
        if not self.quarantine_manager:
            return
            
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an item to restore")
            return
        
        item = self.quarantine_tree.item(selection[0])
        quarantine_id = item['values'][0]
        
        if messagebox.askyesno("Confirm", "Are you sure you want to restore this file?"):
            try:
                result = self.quarantine_manager.restore_file(quarantine_id)
                if result['success']:
                    messagebox.showinfo("Success", "File restored successfully")
                    self._refresh_quarantine()
                else:
                    messagebox.showerror("Error", f"Restore failed: {result['error']}")
            except Exception as e:
                messagebox.showerror("Error", f"Restore failed: {e}")
    
    def _delete_selected(self):
        """Delete selected quarantine item"""
        if not self.quarantine_manager:
            return
            
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an item to delete")
            return
        
        item = self.quarantine_tree.item(selection[0])
        quarantine_id = item['values'][0]
        
        if messagebox.askyesno("Confirm", "Are you sure you want to permanently delete this file?"):
            try:
                result = self.quarantine_manager.delete_quarantined_file(quarantine_id)
                if result['success']:
                    messagebox.showinfo("Success", "File deleted successfully")
                    self._refresh_quarantine()
                else:
                    messagebox.showerror("Error", f"Delete failed: {result['error']}")
            except Exception as e:
                messagebox.showerror("Error", f"Delete failed: {e}")
    
    def _clean_quarantine(self):
        """Clean old quarantine items"""
        if not self.quarantine_manager:
            return
            
        if messagebox.askyesno("Confirm", "Clean old quarantine items (older than 30 days)?"):
            try:
                count = self.quarantine_manager.cleanup_old_items()
                messagebox.showinfo("Cleanup", f"Cleaned {count} old items")
                self._refresh_quarantine()
            except Exception as e:
                messagebox.showerror("Error", f"Cleanup failed: {e}")
    
    def _refresh_statistics(self):
        """Refresh statistics display"""
        if not self.signature_manager:
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, "Statistics not available - signature manager not loaded")
            return
            
        try:
            stats = self.signature_manager.get_threat_statistics()
            
            stats_text = f"""
THREAT DETECTION STATISTICS
===========================

Total Scans: {stats.get('total_scans', 0)}
Threats Detected: {stats.get('threats_detected', 0)}
Clean Files: {stats.get('clean_files', 0)}

Threat Types:
"""
            
            for threat_type, count in stats.get('threat_types', {}).items():
                stats_text += f"  {threat_type}: {count}\n"
            
            stats_text += f"""
Severity Distribution:
"""
            
            for severity, count in stats.get('severity_distribution', {}).items():
                stats_text += f"  {severity}: {count}\n"
            
            if self.quarantine_manager:
                quarantine_stats = self.quarantine_manager.get_quarantine_stats()
                stats_text += f"""

QUARANTINE STATISTICS
====================

Total Items: {sum(quarantine_stats.get('status_counts', {}).values())}
Quarantined: {quarantine_stats.get('status_counts', {}).get('QUARANTINED', 0)}
Restored: {quarantine_stats.get('status_counts', {}).get('RESTORED', 0)}
Deleted: {quarantine_stats.get('status_counts', {}).get('DELETED', 0)}

Disk Usage: {quarantine_stats.get('total_size_mb', 0)} MB
"""
            
            if self.threat_engine:
                engine_status = self.threat_engine.get_engine_status()
                stats_text += f"""

ENGINE STATUS
=============

Initialized: {engine_status.get('initialized', False)}
ML Models Loaded: {engine_status.get('ml_models_loaded', False)}
Signature Count: {engine_status.get('signature_count', 0)}
Cache Size: {engine_status.get('cache_size', 0)}
"""
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats_text)
            
        except Exception as e:
            self.logger.error(f"Error refreshing statistics: {e}")
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, f"Error loading statistics: {e}")
    
    def _refresh_logs(self):
        """Refresh log display"""
        # This would read from log files and display recent entries
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(1.0, "Log functionality not yet implemented")
    
    def _clear_logs(self):
        """Clear log display"""
        self.log_text.delete(1.0, tk.END)
    
    def _open_quarantine_manager(self):
        """Open quarantine manager (switch to quarantine tab)"""
        if self.quarantine_manager:
            # Switch to quarantine tab
            for i in range(self.notebook.index("end")):
                if self.notebook.tab(i, "text") == "Quarantine":
                    self.notebook.select(i)
                    break
        else:
            messagebox.showerror("Error", "Quarantine manager not available")
    
    def _toggle_realtime_protection(self):
        """Toggle real-time protection (same as _toggle_protection)"""
        self._toggle_protection()
    
    def _show_about(self):
        """Show about dialog"""
        try:
            from .. import __version__, __author__
        except ImportError:
            __version__ = "2.0.0"
            __author__ = "Prashant918 Security Team"
        
        about_text = f"""
Prashant918 Advanced Antivirus
Version: {__version__}
Author: {__author__}

Enterprise-grade cybersecurity solution with:
• Multi-layered threat detection
• AI/ML powered analysis
• Real-time monitoring
• Oracle database backend
• Advanced quarantine system

© 2024 Prashant918 Security Solutions

Component Status:
• Threat Engine: {'Available' if self.threat_engine else 'Unavailable'}
• Quarantine Manager: {'Available' if self.quarantine_manager else 'Unavailable'}
• Signature Manager: {'Available' if self.signature_manager else 'Unavailable'}
• Real-time Monitor: {'Available' if self.realtime_monitor else 'Unavailable'}
        """
        
        messagebox.showinfo("About", about_text)
    
    def run(self):
        """Run the GUI application"""
        try:
            self.logger.info("Starting GUI application")
            self.root.mainloop()
        except Exception as e:
            self.logger.error(f"GUI application error: {e}")
            if TKINTER_AVAILABLE:
                messagebox.showerror("Error", f"Application error: {e}")


def main():
    """Main entry point for GUI"""
    try:
        if not TKINTER_AVAILABLE:
            print("Error: tkinter is required for GUI functionality")
            print("Please install tkinter or use the command-line interface instead")
            sys.exit(1)
        
        app = AntivirusGUI()
        app.run()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()