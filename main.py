#!/usr/bin/env python3
"""
Prashant918 Advanced Antivirus - Main Entry Point
Enhanced with proper error handling and cross-platform compatibility
"""

import sys
import os
import traceback
from pathlib import Path
from typing import Optional, Dict, Any

# Ensure proper Python version
if sys.version_info < (3, 8):
    print("Error: Python 3.8 or higher is required")
    sys.exit(1)

# Add src directory to Python path for development mode
project_root = Path(__file__).parent.absolute()
src_path = project_root / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

class AntivirusSystem:
    """Centralized antivirus system manager"""
    
    def __init__(self):
        self.logger = None
        self.components = {}
        self.initialized = False
        
    def initialize(self) -> bool:
        """Initialize all antivirus components"""
        try:
            # Initialize logger first
            self._init_logger()
            
            # Check and create necessary directories
            self._ensure_directories()
            
            # Initialize core components
            self._init_components()
            
            self.initialized = True
            if self.logger:
                self.logger.info("Antivirus system initialized successfully")
            return True
            
        except Exception as e:
            print(f"Failed to initialize antivirus system: {e}")
            if "--debug" in sys.argv:
                traceback.print_exc()
            return False
    
    def _init_logger(self):
        """Initialize secure logger"""
        try:
            from prashant918_antivirus.logger import SecureLogger
            self.logger = SecureLogger("AntivirusSystem")
        except ImportError:
            print("Warning: SecureLogger not available, using basic logging")
            import logging
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("AntivirusSystem")
    
    def _ensure_directories(self):
        """Ensure all necessary directories exist"""
        directories = [
            "logs", "quarantine", "config", "signatures", 
            "models", "temp", "data"
        ]
        
        for dir_name in directories:
            dir_path = Path(dir_name)
            dir_path.mkdir(parents=True, exist_ok=True)
            
            # Set secure permissions on Unix-like systems
            if hasattr(os, 'chmod'):
                try:
                    os.chmod(dir_path, 0o700)
                except (OSError, PermissionError):
                    pass  # Ignore permission errors on some systems
    
    def _init_components(self):
        """Initialize antivirus components with graceful degradation"""
        components_to_load = [
            ("scanner", "prashant918_antivirus.antivirus.scanner", "FileScanner"),
            ("engine", "prashant918_antivirus.antivirus.engine", "AdvancedThreatDetectionEngine"),
            ("ml_detector", "prashant918_antivirus.antivirus.ml_detector", "EnsembleMLDetector"),
            ("quarantine", "prashant918_antivirus.core.quarantine", "QuarantineManager"),
            ("monitor", "prashant918_antivirus.core.realtime_monitor", "RealtimeMonitor"),
        ]
        
        for component_name, module_path, class_name in components_to_load:
            try:
                module = self._safe_import(module_path)
                if module and hasattr(module, class_name):
                    component_class = getattr(module, class_name)
                    self.components[component_name] = component_class()
                    if self.logger:
                        self.logger.info(f"Loaded {component_name} successfully")
                else:
                    if self.logger:
                        self.logger.warning(f"Component {component_name} not available")
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Failed to load {component_name}: {e}")
    
    def _safe_import(self, module_path: str):
        """Safely import a module"""
        try:
            parts = module_path.split('.')
            module = __import__(module_path, fromlist=[parts[-1]])
            return module
        except ImportError as e:
            if self.logger:
                self.logger.debug(f"Import failed for {module_path}: {e}")
            return None
    
    def run_cli(self):
        """Run the command-line interface"""
        try:
            cli_module = self._safe_import("prashant918_antivirus.cli")
            if cli_module and hasattr(cli_module, "main"):
                cli_module.main()
            else:
                self._fallback_cli()
        except Exception as e:
            print(f"CLI error: {e}")
            if "--debug" in sys.argv:
                traceback.print_exc()
            sys.exit(1)
    
    def _fallback_cli(self):
        """Fallback CLI when main CLI is not available"""
        print("Prashant918 Advanced Antivirus")
        print("=" * 40)
        print("CLI module not fully available.")
        print("\nTo install all dependencies:")
        print("pip install -r requirements.txt")
        print("\nFor development installation:")
        print("pip install -e .")
        
        if len(sys.argv) > 1:
            if sys.argv[1] in ["--help", "-h"]:
                print("\nAvailable commands:")
                print("  scan <path>     - Scan files/directories")
                print("  info           - Show system information")
                print("  --version      - Show version")
            elif sys.argv[1] == "--version":
                print("Version: 1.0.2")
            elif sys.argv[1] == "info":
                self._show_system_info()
        
        sys.exit(1)
    
    def _show_system_info(self):
        """Show basic system information"""
        print(f"Python Version: {sys.version}")
        print(f"Platform: {sys.platform}")
        print(f"Architecture: {os.uname().machine if hasattr(os, 'uname') else 'Unknown'}")
        print(f"Available Components: {list(self.components.keys())}")

def display_banner():
    """Display application banner"""
    try:
        import pyfiglet
        from termcolor import colored
        
        banner = pyfiglet.figlet_format("P918 Antivirus", font="slant")
        print(colored(banner, "cyan"))
        print(colored("Advanced AI-Powered Cybersecurity Platform", "green"))
        print(colored("=" * 50, "blue"))
        
    except ImportError:
        print("Prashant918 Advanced Antivirus")
        print("Advanced AI-Powered Cybersecurity Platform")
        print("=" * 50)

def main():
    """Main entry point with comprehensive error handling"""
    try:
        # Display banner
        display_banner()
        
        # Initialize antivirus system
        antivirus = AntivirusSystem()
        
        if not antivirus.initialize():
            print("Failed to initialize antivirus system")
            sys.exit(1)
        
        # Run CLI
        antivirus.run_cli()
        
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