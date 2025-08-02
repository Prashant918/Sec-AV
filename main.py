#!/usr/bin/env python3
"""
Prashant918 Advanced Antivirus - Enhanced Main Entry Point
Supports CLI, GUI, and Web interfaces with comprehensive error handling
"""

import sys
import os
import traceback
from pathlib import Path

# Version check - must be first
if sys.version_info < (3, 8):
    print("Error: Python 3.8 or higher is required")
    print(f"Current version: {sys.version}")
    sys.exit(1)

# Add src to path for development
project_root = Path(__file__).parent
src_path = project_root / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

class AntivirusLauncher:
    """Enhanced launcher for Prashant918 Advanced Antivirus with multiple interface support"""
    
    def __init__(self):
        self.logger = None
        self.initialized = False
        self.components = {}
        self.interface_mode = None
        
    def initialize(self):
        """Initialize the antivirus system"""
        try:
            self._init_logger()
            self._ensure_directories()
            self._init_components()
            self.initialized = True
            return True
        except Exception as e:
            print(f"Initialization failed: {e}")
            if "--debug" in sys.argv:
                traceback.print_exc()
            return False
    
    def _init_logger(self):
        """Initialize secure logger with fallback"""
        try:
            from prashant918_antivirus.logger import SecureLogger
            self.logger = SecureLogger("Main")
            self.logger.info("Secure logger initialized")
        except ImportError:
            import logging
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("Main")
            self.logger.warning("Using basic logger - SecureLogger not available")
    
    def _ensure_directories(self):
        """Create necessary directories with secure permissions"""
        directories = [
            Path.home() / ".prashant918_antivirus" / "logs",
            Path.home() / ".prashant918_antivirus" / "quarantine",
            Path.home() / ".prashant918_antivirus" / "config",
            Path.home() / ".prashant918_antivirus" / "data",
            Path.home() / ".prashant918_antivirus" / "models",
            Path.home() / ".prashant918_antivirus" / "temp",
        ]
        
        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                # Set secure permissions on Unix-like systems
                if os.name != 'nt':
                    os.chmod(directory, 0o700)
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Could not create directory {directory}: {e}")
    
    def _init_components(self):
        """Initialize core components with safe imports"""
        components_to_load = [
            ("scanner", "prashant918_antivirus.core.scanner", "FileScanner"),
            ("engine", "prashant918_antivirus.core.engine", "UnifiedThreatEngine"),
            ("quarantine", "prashant918_antivirus.core.quarantine", "QuarantineManager"),
            ("monitor", "prashant918_antivirus.core.realtime_monitor", "RealtimeMonitor"),
            ("service", "prashant918_antivirus.service.service_manager", "ServiceManager"),
        ]
        
        for name, module_path, class_name in components_to_load:
            try:
                component = self._safe_import(module_path, class_name)
                if component:
                    self.components[name] = component
                    if self.logger:
                        self.logger.info(f"Component '{name}' loaded successfully")
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Component '{name}' failed to load: {e}")
        
        # Initialize RealtimeMonitor with dependencies
        if "monitor" in self.components and "engine" in self.components and "quarantine" in self.components:
            try:
                self.components["monitor"] = self.components["monitor"](
                    threat_engine=self.components["engine"],
                    quarantine_manager=self.components["quarantine"]
                )
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Failed to initialize RealtimeMonitor with dependencies: {e}")
    
    def _safe_import(self, module_path, class_name=None):
        """Safely import a module or class"""
        try:
            module = __import__(module_path, fromlist=[class_name] if class_name else [])
            if class_name:
                return getattr(module, class_name)
            return module
        except ImportError as e:
            if self.logger:
                self.logger.debug(f"Import failed for {module_path}: {e}")
            return None
    
    def determine_interface_mode(self, args):
        """Determine which interface to launch based on arguments"""
        if "--gui" in args or "gui" in args:
            return "gui"
        elif "--web" in args or "web" in args:
            return "web"
        elif "--cli" in args or "cli" in args or len(args) > 1:
            return "cli"
        else:
            # Interactive mode selection
            return self._interactive_mode_selection()
    
    def _interactive_mode_selection(self):
        """Interactive mode selection when no specific mode is specified"""
        try:
            print("\nPrashant918 Advanced Antivirus")
            print("=" * 40)
            print("Select interface mode:")
            print("1. Command Line Interface (CLI)")
            print("2. Graphical User Interface (GUI)")
            print("3. Web Interface")
            print("4. Exit")
            
            while True:
                try:
                    choice = input("\nEnter your choice (1-4): ").strip()
                    if choice == "1":
                        return "cli"
                    elif choice == "2":
                        return "gui"
                    elif choice == "3":
                        return "web"
                    elif choice == "4":
                        print("Goodbye!")
                        sys.exit(0)
                    else:
                        print("Invalid choice. Please enter 1, 2, 3, or 4.")
                except KeyboardInterrupt:
                    print("\nOperation cancelled by user")
                    sys.exit(0)
        except Exception:
            # Fallback to CLI if interactive selection fails
            return "cli"
    
    def launch_cli(self):
        """Launch command line interface"""
        try:
            # Try to import and run the main CLI
            cli_module = self._safe_import("prashant918_antivirus.cli")
            if cli_module and hasattr(cli_module, "main"):
                if self.logger:
                    self.logger.info("Launching CLI interface")
                cli_module.main()
            else:
                # Fallback to basic CLI
                self._fallback_cli()
        except Exception as e:
            print(f"CLI error: {e}")
            if "--debug" in sys.argv:
                traceback.print_exc()
            self._fallback_cli()
    
    def launch_gui(self):
        """Launch graphical user interface"""
        try:
            # Check if tkinter is available
            try:
                import tkinter as tk
                from tkinter import messagebox
            except ImportError:
                print("Error: GUI requires tkinter which is not available")
                print("Please install tkinter or use CLI mode instead")
                print("On Ubuntu/Debian: sudo apt-get install python3-tk")
                print("On CentOS/RHEL: sudo yum install tkinter")
                return False
            
            # Try to import and run the GUI
            gui_module = self._safe_import("prashant918_antivirus.gui.main_window")
            if gui_module and hasattr(gui_module, "main"):
                if self.logger:
                    self.logger.info("Launching GUI interface")
                print("Starting GUI interface...")
                gui_module.main()
            else:
                # Fallback GUI using basic tkinter
                self._fallback_gui()
                
        except Exception as e:
            print(f"GUI error: {e}")
            if "--debug" in sys.argv:
                traceback.print_exc()
            
            # Ask user if they want to try CLI instead
            try:
                choice = input("GUI failed to start. Would you like to try CLI mode? (y/n): ").lower()
                if choice in ['y', 'yes']:
                    self.launch_cli()
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
    
    def launch_web(self):
        """Launch web interface"""
        try:
            # Try to import and run the web interface
            web_module = self._safe_import("prashant918_antivirus.web.app")
            if web_module and hasattr(web_module, "create_app"):
                if self.logger:
                    self.logger.info("Launching web interface")
                
                print("Starting web interface...")
                print("Web interface will be available at: http://127.0.0.1:5000")
                print("Press Ctrl+C to stop the server")
                
                # Create and run the web app
                app = web_module.create_app()
                
                # Get host and port from command line args or use defaults
                host = "127.0.0.1"
                port = 5000
                debug = "--debug" in sys.argv
                
                for i, arg in enumerate(sys.argv):
                    if arg == "--host" and i + 1 < len(sys.argv):
                        host = sys.argv[i + 1]
                    elif arg == "--port" and i + 1 < len(sys.argv):
                        try:
                            port = int(sys.argv[i + 1])
                        except ValueError:
                            print(f"Invalid port number: {sys.argv[i + 1]}")
                
                app.run(host=host, port=port, debug=debug)
                
            else:
                print("Error: Web interface components not available")
                print("Please ensure Flask and related dependencies are installed")
                print("Run: pip install Flask Flask-CORS Flask-SocketIO")
                return False
                
        except Exception as e:
            print(f"Web interface error: {e}")
            if "--debug" in sys.argv:
                traceback.print_exc()
            
            # Ask user if they want to try another interface
            try:
                choice = input("Web interface failed to start. Would you like to try GUI mode? (y/n): ").lower()
                if choice in ['y', 'yes']:
                    self.launch_gui()
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
    
    def _fallback_cli(self):
        """Fallback CLI with basic functionality"""
        print("\nPrashant918 Advanced Antivirus - Basic Mode")
        print("=" * 50)
        
        if len(sys.argv) > 1:
            command = sys.argv[1].lower()
            
            if command in ["--help", "-h", "help"]:
                self._show_help()
            elif command in ["--version", "-v", "version"]:
                print("Version: 1.0.3")
            elif command == "info":
                self._show_system_info()
            elif command == "gui":
                self.launch_gui()
            elif command == "web":
                self.launch_web()
            else:
                print(f"Unknown command: {command}")
                self._show_help()
        else:
            self._show_help()
    
    def _fallback_gui(self):
        """Fallback GUI with basic tkinter interface"""
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox
            
            root = tk.Tk()
            root.title("Prashant918 Advanced Antivirus")
            root.geometry("600x400")
            root.resizable(True, True)
            
            # Main frame
            main_frame = ttk.Frame(root, padding="20")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # Title
            title_label = ttk.Label(main_frame, text="Prashant918 Advanced Antivirus", 
                                  font=("Arial", 16, "bold"))
            title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
            
            # Status
            status_label = ttk.Label(main_frame, text="Basic GUI Mode - Limited Functionality")
            status_label.grid(row=1, column=0, columnspan=2, pady=(0, 20))
            
            # Components status
            components_frame = ttk.LabelFrame(main_frame, text="Component Status", padding="10")
            components_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
            
            row = 0
            for name, component in self.components.items():
                status = "Available" if component else "Not Available"
                color = "green" if component else "red"
                
                ttk.Label(components_frame, text=f"{name.title()}:").grid(row=row, column=0, sticky=tk.W)
                status_lbl = ttk.Label(components_frame, text=status, foreground=color)
                status_lbl.grid(row=row, column=1, sticky=tk.W, padx=(10, 0))
                row += 1
            
            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.grid(row=3, column=0, columnspan=2, pady=20)
            
            def show_info():
                info = f"""Prashant918 Advanced Antivirus
Version: 1.0.3
Initialized: {self.initialized}
Available Components: {len(self.components)}

For full functionality, please ensure all dependencies are installed:
pip install -r requirements.txt"""
                messagebox.showinfo("System Information", info)
            
            def launch_full_gui():
                root.destroy()
                self.launch_gui()
            
            ttk.Button(button_frame, text="System Info", command=show_info).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Try Full GUI", command=launch_full_gui).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Exit", command=root.quit).pack(side=tk.LEFT, padx=5)
            
            # Configure grid weights
            root.columnconfigure(0, weight=1)
            root.rowconfigure(0, weight=1)
            main_frame.columnconfigure(0, weight=1)
            
            if self.logger:
                self.logger.info("Starting fallback GUI")
            
            root.mainloop()
            
        except Exception as e:
            print(f"Fallback GUI error: {e}")
            messagebox.showerror("Error", f"GUI Error: {e}")
    
    def _show_help(self):
        """Show help information"""
        print("\nUsage: python main.py [mode] [options]")
        print("\nInterface Modes:")
        print("  cli, --cli           Launch command-line interface")
        print("  gui, --gui           Launch graphical user interface")
        print("  web, --web           Launch web interface")
        print("  (no mode)            Interactive mode selection")
        print("\nGeneral Options:")
        print("  help, --help, -h     Show this help message")
        print("  version, --version   Show version information")
        print("  info                 Show system information")
        print("  --debug              Enable debug mode")
        print("\nWeb Interface Options:")
        print("  --host HOST          Web server host (default: 127.0.0.1)")
        print("  --port PORT          Web server port (default: 5000)")
        print("\nCLI Commands (when in CLI mode):")
        print("  scan PATH            Scan files or directories")
        print("  monitor start/stop   Control real-time monitoring")
        print("  service install      Install as system service")
        print("\nExamples:")
        print("  python main.py                    # Interactive mode selection")
        print("  python main.py gui                # Launch GUI")
        print("  python main.py web --port 8080    # Launch web on port 8080")
        print("  python main.py cli scan /path     # CLI scan")
        print("\nFor full functionality, ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
    
    def _show_system_info(self):
        """Show basic system information"""
        print(f"\nSystem Information:")
        print(f"Python Version: {sys.version}")
        print(f"Platform: {sys.platform}")
        print(f"Project Root: {project_root}")
        print(f"Initialized: {self.initialized}")
        print(f"Available Components: {list(self.components.keys())}")
        print(f"Interface Mode: {self.interface_mode}")
        
        # Show component details
        if self.components:
            print(f"\nComponent Details:")
            for name, component in self.components.items():
                status = "✓ Available" if component else "✗ Not Available"
                print(f"  {name.title()}: {status}")
    
    def run(self, args):
        """Main run method"""
        self.interface_mode = self.determine_interface_mode(args)
        
        if self.interface_mode == "gui":
            return self.launch_gui()
        elif self.interface_mode == "web":
            return self.launch_web()
        elif self.interface_mode == "cli":
            return self.launch_cli()
        else:
            print("Invalid interface mode")
            return False

def display_banner():
    """Display application banner"""
    try:
        import pyfiglet
        from termcolor import colored
        
        banner = pyfiglet.figlet_format("P918 Antivirus", font="slant")
        print(colored(banner, "cyan"))
        print(colored("Advanced AI-Powered Cybersecurity Platform", "green"))
        print(colored("Multi-Interface Support: CLI | GUI | Web", "blue"))
        print(colored("=" * 60, "blue"))
        
    except ImportError:
        print("Prashant918 Advanced Antivirus")
        print("Advanced AI-Powered Cybersecurity Platform")
        print("Multi-Interface Support: CLI | GUI | Web")
        print("=" * 60)

def main():
    """Main entry point with comprehensive error handling and interface selection"""
    try:
        # Display banner
        display_banner()
        
        # Initialize antivirus launcher
        launcher = AntivirusLauncher()
        
        if not launcher.initialize():
            print("Failed to initialize antivirus system")
            print("This may be due to missing dependencies or configuration issues.")
            print("Please run: pip install -r requirements.txt")
            
            # Still allow basic functionality
            print("\nContinuing with limited functionality...")
        
        # Run the selected interface
        launcher.run(sys.argv)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        if "--debug" in sys.argv:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()