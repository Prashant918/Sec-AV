"""
Prashant918 Advanced Antivirus - Enhanced Command Line Interface
Cross-platform CLI with proper dependency handling and graceful degradation
"""

import os
import sys
import json
import time
import threading
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any

# Core imports with error handling
try:
    from .logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from .config import secure_config
except ImportError:
    secure_config = type('Config', (), {'get': lambda self, key, default=None: default})()

try:
    from .exceptions import AntivirusError
except ImportError:
    class AntivirusError(Exception):
        pass

# Optional imports for enhanced functionality
try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

class AntivirusCLI:
    """Enhanced command-line interface for Prashant918 Antivirus"""
    
    def __init__(self):
        self.logger = SecureLogger("CLI")
        self.threat_engine = None
        self.quarantine_manager = None
        self.realtime_monitor = None
        self.service_manager = None
        
        # Initialize components
        self._initialize_components()

    def _initialize_components(self):
        """Initialize antivirus components with graceful degradation"""
        components = [
            ("threat_engine", "prashant918_antivirus.antivirus.engine", "AdvancedThreatDetectionEngine"),
            ("quarantine_manager", "prashant918_antivirus.core.quarantine", "QuarantineManager"),
            ("realtime_monitor", "prashant918_antivirus.core.realtime_monitor", "RealtimeMonitor"),
        ]
        
        for attr_name, module_path, class_name in components:
            try:
                module = __import__(module_path, fromlist=[class_name])
                if hasattr(module, class_name):
                    component_class = getattr(module, class_name)
                    if attr_name == "realtime_monitor":
                        # RealtimeMonitor needs threat_engine and quarantine_manager
                        setattr(self, attr_name, component_class(
                            threat_engine=self.threat_engine,
                            quarantine_manager=self.quarantine_manager
                        ))
                    else:
                        setattr(self, attr_name, component_class())
                    self.logger.info(f"Loaded {attr_name} successfully")
                else:
                    self.logger.warning(f"Component {class_name} not found in {module_path}")
            except ImportError as e:
                self.logger.warning(f"Could not load {attr_name}: {e}")
            except Exception as e:
                self.logger.error(f"Error initializing {attr_name}: {e}")

        # Initialize service manager with proper config
        try:
            from .service.service_manager import create_service_manager
            self.service_manager = create_service_manager()
            self.logger.info("Loaded service_manager successfully")
        except ImportError as e:
            self.logger.warning(f"Could not load service_manager: {e}")
        except Exception as e:
            self.logger.error(f"Error initializing service_manager: {e}")

    def run(self):
        """Run the CLI application"""
        parser = self._create_parser()
        args = parser.parse_args()
        
        try:
            if hasattr(args, 'func'):
                args.func(args)
            else:
                parser.print_help()
        except KeyboardInterrupt:
            self._print_info("Operation cancelled by user")
        except Exception as e:
            self._print_error(f"Command failed: {e}")
            if args.debug if hasattr(args, 'debug') else False:
                import traceback
                traceback.print_exc()

    def _create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="Prashant918 Advanced Antivirus - Enterprise Security Solution",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  prashant918-antivirus scan /path/to/file
  prashant918-antivirus info
  prashant918-antivirus service install
  prashant918-antivirus monitor start
            """
        )
        
        parser.add_argument('--version', action='version', version='1.0.2')
        parser.add_argument('--debug', action='store_true', help='Enable debug output')
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan files or directories')
        scan_parser.add_argument('path', help='Path to scan')
        scan_parser.add_argument('--recursive', '-r', action='store_true', 
                               help='Scan directories recursively')
        scan_parser.add_argument('--output', '-o', help='Output file for results')
        scan_parser.add_argument('--format', choices=['table', 'json', 'csv'], 
                               default='table', help='Output format')
        scan_parser.set_defaults(func=self.scan_command)
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Show system information')
        info_parser.set_defaults(func=self.info_command)
        
        # Service command
        service_parser = subparsers.add_parser('service', help='Manage antivirus service')
        service_parser.add_argument('service_action', 
                                  choices=['install', 'uninstall', 'start', 'stop', 'status'],
                                  help='Service action')
        service_parser.set_defaults(func=self.service_command)
        
        # Monitor command
        monitor_parser = subparsers.add_parser('monitor', help='Manage real-time monitoring')
        monitor_parser.add_argument('monitor_action', 
                                  choices=['start', 'stop', 'status'],
                                  help='Monitor action')
        monitor_parser.add_argument('--paths', nargs='+', 
                                  help='Paths to monitor')
        monitor_parser.set_defaults(func=self.monitor_command)
        
        return parser

    def scan_command(self, args):
        """Handle scan command"""
        if not self.threat_engine:
            self._print_error("Threat engine not available")
            return
        
        try:
            self._print_info(f"Scanning: {args.path}")
            
            path = Path(args.path)
            if not path.exists():
                self._print_error(f"Path does not exist: {args.path}")
                return
            
            results = []
            
            if path.is_file():
                result = self.threat_engine.scan_file(str(path))
                results.append(result)
            elif path.is_dir():
                if args.recursive:
                    for file_path in path.rglob('*'):
                        if file_path.is_file():
                            result = self.threat_engine.scan_file(str(file_path))
                            results.append(result)
                else:
                    for file_path in path.iterdir():
                        if file_path.is_file():
                            result = self.threat_engine.scan_file(str(file_path))
                            results.append(result)
            
            self._display_scan_results(results, args.format)
            
            if args.output:
                self._save_results(results, args.output, args.format)
                self._print_success(f"Results saved to: {args.output}")
                
        except Exception as e:
            self._print_error(f"Scan failed: {e}")

    def info_command(self, args):
        """Handle info command"""
        try:
            info = self._collect_system_info()
            self._display_system_info(info)
        except Exception as e:
            self._print_error(f"Failed to get system info: {e}")

    def service_command(self, args):
        """Handle service management commands"""
        if not self.service_manager:
            self._print_error("Service manager not available")
            return
        
        try:
            if args.service_action == 'install':
                self._print_info("Installing antivirus service...")
                if self.service_manager.install_service():
                    self._print_success("Service installed successfully")
                else:
                    self._print_error("Service installation failed")
            
            elif args.service_action == 'uninstall':
                self._print_info("Uninstalling antivirus service...")
                if self.service_manager.uninstall_service():
                    self._print_success("Service uninstalled successfully")
                else:
                    self._print_error("Service uninstallation failed")
            
            elif args.service_action == 'start':
                self._print_info("Starting antivirus service...")
                if self.service_manager.start_service():
                    self._print_success("Service started successfully")
                else:
                    self._print_error("Service start failed")
            
            elif args.service_action == 'stop':
                self._print_info("Stopping antivirus service...")
                if self.service_manager.stop_service():
                    self._print_success("Service stopped successfully")
                else:
                    self._print_error("Service stop failed")
            
            elif args.service_action == 'status':
                status = self.service_manager.get_service_status()
                self._display_service_status(status)
            
        except Exception as e:
            self._print_error(f"Service command failed: {e}")

    def monitor_command(self, args):
        """Handle monitor commands"""
        if not self.realtime_monitor:
            self._print_error("Real-time monitor not available")
            return
        
        try:
            if args.monitor_action == 'start':
                paths = args.paths or [
                    str(Path.home() / "Downloads"),
                    str(Path.home() / "Desktop"),
                    str(Path.home() / "Documents")
                ]
                
                self._print_info(f"Starting monitoring for paths: {paths}")
                if self.realtime_monitor.start_monitoring(paths):
                    self._print_success("Real-time monitoring started")
                else:
                    self._print_error("Failed to start monitoring")
            
            elif args.monitor_action == 'stop':
                self._print_info("Stopping real-time monitoring...")
                if self.realtime_monitor.stop_monitoring():
                    self._print_success("Real-time monitoring stopped")
                else:
                    self._print_error("Failed to stop monitoring")
            
            elif args.monitor_action == 'status':
                status = self.realtime_monitor.get_status()
                self._display_monitor_status(status)
                
        except Exception as e:
            self._print_error(f"Monitor command failed: {e}")

    def _collect_system_info(self):
        """Collect system information"""
        info = {
            'system': {
                'platform': sys.platform,
                'python_version': sys.version,
                'architecture': os.uname().machine if hasattr(os, 'uname') else 'unknown'
            },
            'components': {
                'threat_engine': self.threat_engine is not None,
                'quarantine_manager': self.quarantine_manager is not None,
                'realtime_monitor': self.realtime_monitor is not None,
                'service_manager': self.service_manager is not None
            }
        }
        
        if HAS_PSUTIL:
            try:
                info['system'].update({
                    'cpu_count': psutil.cpu_count(),
                    'memory_total': psutil.virtual_memory().total,
                    'memory_available': psutil.virtual_memory().available,
                    'disk_usage': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent
                })
            except Exception:
                pass
        
        return info

    def _display_system_info(self, info):
        """Display system information"""
        if HAS_RICH:
            table = Table(title="System Information")
            table.add_column("Category", style="cyan")
            table.add_column("Details", style="green")
            
            # System info
            for key, value in info['system'].items():
                table.add_row(key.replace('_', ' ').title(), str(value))
            
            # Components
            table.add_row("", "")  # Separator
            table.add_row("Components", "")
            for component, available in info['components'].items():
                status = "✓ Available" if available else "✗ Not Available"
                table.add_row(f"  {component.replace('_', ' ').title()}", status)
            
            console.print(table)
        else:
            print("\n=== System Information ===")
            for key, value in info['system'].items():
                print(f"{key.replace('_', ' ').title()}: {value}")
            
            print("\n=== Components ===")
            for component, available in info['components'].items():
                status = "✓ Available" if available else "✗ Not Available"
                print(f"{component.replace('_', ' ').title()}: {status}")

    def _display_scan_results(self, results, format_type):
        """Display scan results"""
        if format_type == 'json':
            print(json.dumps([result.__dict__ if hasattr(result, '__dict__') else result 
                            for result in results], indent=2))
        elif format_type == 'csv':
            print("file_path,threat_level,confidence,detection_method")
            for result in results:
                if hasattr(result, 'file_path'):
                    print(f"{result.file_path},{result.threat_level},{result.confidence},{result.detection_method}")
        else:  # table format
            if HAS_RICH:
                table = Table(title="Scan Results")
                table.add_column("File", style="cyan")
                table.add_column("Status", style="green")
                table.add_column("Confidence", style="yellow")
                table.add_column("Method", style="blue")
                
                for result in results:
                    if hasattr(result, 'file_path'):
                        table.add_row(
                            str(result.file_path),
                            str(result.threat_level.value if hasattr(result.threat_level, 'value') else result.threat_level),
                            f"{result.confidence:.2f}",
                            result.detection_method
                        )
                
                console.print(table)
            else:
                print("\n=== Scan Results ===")
                for result in results:
                    if hasattr(result, 'file_path'):
                        print(f"File: {result.file_path}")
                        print(f"Status: {result.threat_level}")
                        print(f"Confidence: {result.confidence:.2f}")
                        print(f"Method: {result.detection_method}")
                        print("-" * 40)

    def _display_service_status(self, status):
        """Display service status"""
        if HAS_RICH:
            panel = Panel.fit(
                f"Service: {'Running' if status.get('running', False) else 'Stopped'}\n"
                f"Platform: {status.get('platform', 'Unknown')}\n"
                f"Uptime: {status.get('uptime', 0):.1f} seconds",
                title="Service Status"
            )
            console.print(panel)
        else:
            print("\n=== Service Status ===")
            print(f"Running: {'Yes' if status.get('running', False) else 'No'}")
            print(f"Platform: {status.get('platform', 'Unknown')}")
            print(f"Uptime: {status.get('uptime', 0):.1f} seconds")

    def _display_monitor_status(self, status):
        """Display monitor status"""
        if HAS_RICH:
            panel = Panel.fit(
                f"Monitoring: {'Active' if status.get('is_monitoring', False) else 'Inactive'}\n"
                f"Paths: {len(status.get('monitored_paths', []))}\n"
                f"Events: {status.get('stats', {}).get('events_processed', 0)}",
                title="Monitor Status"
            )
            console.print(panel)
        else:
            print("\n=== Monitor Status ===")
            print(f"Active: {'Yes' if status.get('is_monitoring', False) else 'No'}")
            print(f"Monitored Paths: {len(status.get('monitored_paths', []))}")
            print(f"Events Processed: {status.get('stats', {}).get('events_processed', 0)}")

    def _save_results(self, results, output_file, format_type):
        """Save results to file"""
        with open(output_file, 'w') as f:
            if format_type == 'json':
                json.dump([result.__dict__ if hasattr(result, '__dict__') else result 
                         for result in results], f, indent=2)
            elif format_type == 'csv':
                f.write("file_path,threat_level,confidence,detection_method\n")
                for result in results:
                    if hasattr(result, 'file_path'):
                        f.write(f"{result.file_path},{result.threat_level},{result.confidence},{result.detection_method}\n")

    def _print_success(self, message):
        """Print success message"""
        if HAS_RICH:
            console.print(f"✓ {message}", style="green")
        else:
            print(f"✓ {message}")

    def _print_error(self, message):
        """Print error message"""
        if HAS_RICH:
            console.print(f"✗ {message}", style="red")
        else:
            print(f"✗ {message}")

    def _print_warning(self, message):
        """Print warning message"""
        if HAS_RICH:
            console.print(f"⚠ {message}", style="yellow")
        else:
            print(f"⚠ {message}")

    def _print_info(self, message):
        """Print info message"""
        if HAS_RICH:
            console.print(f"ℹ {message}", style="blue")
        else:
            print(f"ℹ {message}")

def main():
    """Main CLI entry point"""
    try:
        cli = AntivirusCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()