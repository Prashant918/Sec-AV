#!/usr/bin/env python3
"""
Prashant918 Advanced Antivirus - Interface Launcher
Provides easy access to CLI, GUI, and Web interfaces
"""

import sys
import os
import subprocess
import webbrowser
import time
from pathlib import Path
from typing import Optional

class InterfaceLauncher:
    """Launcher for different antivirus interfaces"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.main_script = self.project_root / "main.py"
        
    def launch_cli(self, args: list = None):
        """Launch CLI interface"""
        cmd = [sys.executable, str(self.main_script), "cli"]
        if args:
            cmd.extend(args)
        
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nCLI interface stopped")
    
    def launch_gui(self):
        """Launch GUI interface"""
        cmd = [sys.executable, str(self.main_script), "gui"]
        
        try:
            print("Starting GUI interface...")
            subprocess.run(cmd)
        except Exception as e:
            print(f"Failed to start GUI: {e}")
            return False
        return True
    
    def launch_web(self, host: str = "127.0.0.1", port: int = 5000, open_browser: bool = True):
        """Launch web interface"""
        cmd = [sys.executable, str(self.main_script), "web", "--host", host, "--port", str(port)]
        
        try:
            print(f"Starting web interface on http://{host}:{port}")
            
            if open_browser:
                # Open browser after a short delay
                def open_browser_delayed():
                    time.sleep(2)
                    webbrowser.open(f"http://{host}:{port}")
                
                import threading
                browser_thread = threading.Thread(target=open_browser_delayed)
                browser_thread.daemon = True
                browser_thread.start()
            
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nWeb interface stopped")
        except Exception as e:
            print(f"Failed to start web interface: {e}")
            return False
        return True
    
    def show_interface_menu(self):
        """Show interactive interface selection menu"""
        while True:
            print("\n" + "="*50)
            print("Prashant918 Advanced Antivirus - Interface Launcher")
            print("="*50)
            print("1. Command Line Interface (CLI)")
            print("2. Graphical User Interface (GUI)")
            print("3. Web Interface (Browser)")
            print("4. Web Interface (Custom Settings)")
            print("5. System Information")
            print("6. Exit")
            print("-"*50)
            
            try:
                choice = input("Select interface (1-6): ").strip()
                
                if choice == "1":
                    print("\nLaunching CLI interface...")
                    self.launch_cli()
                
                elif choice == "2":
                    print("\nLaunching GUI interface...")
                    if not self.launch_gui():
                        input("Press Enter to continue...")
                
                elif choice == "3":
                    print("\nLaunching web interface...")
                    self.launch_web()
                
                elif choice == "4":
                    self._custom_web_settings()
                
                elif choice == "5":
                    self._show_system_info()
                    input("Press Enter to continue...")
                
                elif choice == "6":
                    print("Goodbye!")
                    break
                
                else:
                    print("Invalid choice. Please select 1-6.")
                    
            except KeyboardInterrupt:
                print("\nOperation cancelled")
                break
            except Exception as e:
                print(f"Error: {e}")
                input("Press Enter to continue...")
    
    def _custom_web_settings(self):
        """Configure custom web interface settings"""
        try:
            print("\nWeb Interface Configuration")
            print("-" * 30)
            
            # Get host
            host = input("Host (default: 127.0.0.1): ").strip()
            if not host:
                host = "127.0.0.1"
            
            # Get port
            port_input = input("Port (default: 5000): ").strip()
            try:
                port = int(port_input) if port_input else 5000
            except ValueError:
                print("Invalid port number, using default 5000")
                port = 5000
            
            # Ask about browser
            open_browser = input("Open browser automatically? (y/n, default: y): ").strip().lower()
            open_browser = open_browser != 'n'
            
            print(f"\nStarting web interface on http://{host}:{port}")
            self.launch_web(host, port, open_browser)
            
        except KeyboardInterrupt:
            print("\nConfiguration cancelled")
    
    def _show_system_info(self):
        """Show system information"""
        print("\nSystem Information")
        print("-" * 30)
        print(f"Python Version: {sys.version}")
        print(f"Platform: {sys.platform}")
        print(f"Project Root: {self.project_root}")
        print(f"Main Script: {self.main_script}")
        print(f"Script Exists: {self.main_script.exists()}")
        
        # Check dependencies
        print("\nDependency Check:")
        dependencies = [
            ("tkinter", "GUI support"),
            ("flask", "Web interface"),
            ("pyfiglet", "Banner display"),
            ("termcolor", "Colored output"),
        ]
        
        for dep, desc in dependencies:
            try:
                __import__(dep)
                status = "✓ Available"
            except ImportError:
                status = "✗ Not Available"
            print(f"  {dep:12} - {desc:20} - {status}")

def main():
    """Main launcher entry point"""
    launcher = InterfaceLauncher()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "cli":
            launcher.launch_cli(sys.argv[2:])
        elif command == "gui":
            launcher.launch_gui()
        elif command == "web":
            launcher.launch_web()
        elif command == "menu":
            launcher.show_interface_menu()
        else:
            print(f"Unknown command: {command}")
            print("Available commands: cli, gui, web, menu")
    else:
        launcher.show_interface_menu()

if __name__ == "__main__":
    main()
