"""
Prashant918 Advanced Antivirus - Enhanced CLI
Cross-platform command-line interface with comprehensive functionality
"""

import os
import sys
import json
import time
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse

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
    class AntivirusError(Exception): pass

# Optional imports for enhanced functionality
try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False
    click = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.text import Text
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
    psutil = None

# Package info
try:
    from . import __version__, __author__
except ImportError:
    __version__ = "1.0.2"
    __author__ = "Prashant918"

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
            ("service_manager", "prashant918_antivirus.service.service_manager", "ServiceManager"),
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
    
    def display_banner(self):
        """Display application banner"""
        if HAS_RICH:
            banner_text = f"""
╔══════════════════════════════════════════════════════════════╗
║                 Prashant918 Advanced Antivirus              ║
║                Enterprise Cybersecurity Solution            ║
║                                                              ║
║  Version: {__version__:<10} Author: {__author__:<25} ║
║                                                              ║
║  🛡️  Multi-layered Threat Detection                         ║
║  🤖  AI/ML Powered Analysis                                  ║
║  🔍  Real-time Monitoring                                    ║
║  🏢  Cross-platform Compatibility                           ║
╚══════════════════════════════════════════════════════════════╝
            """
            console.print(Panel(banner_text, style="bold blue"))
        else:
            print("=" * 60)
            print("         Prashant918 Advanced Antivirus")
            print("        Enterprise Cybersecurity Solution")
            print("")
            print(f"  Version: {__version__}    Author: {__author__}")
            print("")
            print("  🛡️  Multi-layered Threat Detection")
            print("  🤖  AI/ML Powered Analysis")
            print("  🔍  Real-time Monitoring")
            print("  🏢  Cross-platform Compatibility")
            print("=" * 60)
    
    def scan_command(self, path: str, recursive: bool = True, output: Optional[str] = None, 
                    format_type: str = "table") -> bool:
        """Scan files or directories for threats"""
        try:
            if not self.threat_engine:
                self._print_error("Threat detection engine not available")
                return False
            
            path_obj = Path(path)
            if not path_obj.exists():
                self._print_error(f"Path does not exist: {path}")
                return False
            
            # Collect files to scan
            files_to_scan = self._collect_files(path_obj, recursive)
            
            if not files_to_scan:
                self._print_warning("No files found to scan")
                return True
            
            self._print_info(f"Scanning {len(files_to_scan)} files...")
            
            # Perform scan
            results = self._perform_scan(files_to_scan)
            
            # Display results
            self._display_scan_results(results, format_type)
            
            # Save results if requested
            if output:
                self._save_results(results, output, format_type)
            
            # Summary
            threats_found = sum(1 for r in results if r.get('threat_level') in ['malware', 'critical'])
            suspicious_found = sum(1 for r in results if r.get('threat_level') == 'suspicious')
            
            if threats_found > 0:
                self._print_error(f"Scan completed: {threats_found} threats found, {suspicious_found} suspicious files")
                return False
            else:
                self._print_success(f"Scan completed: No threats found, {suspicious_found} suspicious files")
                return True
                
        except Exception as e:
            self._print_error(f"Scan failed: {e}")
            return False
    
    def _collect_files(self, path: Path, recursive: bool) -> List[str]:
        """Collect files to scan"""
        files = []
        
        try:
            if path.is_file():
                files.append(str(path))
            elif path.is_dir():
                if recursive:
                    for file_path in path.rglob("*"):
                        if file_path.is_file():
                            files.append(str(file_path))
                else:
                    for file_path in path.iterdir():
                        if file_path.is_file():
                            files.append(str(file_path))
        except Exception as e:
            self.logger.error(f"Error collecting files: {e}")
        
        return files
    
    def _perform_scan(self, files: List[str]) -> List[Dict[str, Any]]:
        """Perform scan on files"""
        results = []
        
        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Scanning files...", total=len(files))
                
                for file_path in files:
                    try:
                        progress.update(task, description=f"Scanning: {Path(file_path).name}")
                        
                        scan_result = self.threat_engine.scan_file(file_path)
                        
                        result = {
                            'file_path': file_path,
                            'file_name': Path(file_path).name,
                            'threat_level': scan_result.threat_level.value,
                            'threat_name': scan_result.threat_name,
                            'confidence': scan_result.confidence,
                            'detection_method': scan_result.detection_method,
                            'scan_time': scan_result.scan_time,
                            'file_size': self._get_file_size(file_path)
                        }
                        
                        results.append(result)
                        progress.advance(task)
                        
                    except Exception as e:
                        self.logger.error(f"Error scanning {file_path}: {e}")
                        results.append({
                            'file_path': file_path,
                            'file_name': Path(file_path).name,
                            'threat_level': 'error',
                            'error': str(e)
                        })
                        progress.advance(task)
        else:
            for i, file_path in enumerate(files, 1):
                try:
                    print(f"Scanning ({i}/{len(files)}): {Path(file_path).name}")
                    
                    scan_result = self.threat_engine.scan_file(file_path)
                    
                    result = {
                        'file_path': file_path,
                        'file_name': Path(file_path).name,
                        'threat_level': scan_result.threat_level.value,
                        'threat_name': scan_result.threat_name,
                        'confidence': scan_result.confidence,
                        'detection_method': scan_result.detection_method,
                        'scan_time': scan_result.scan_time,
                        'file_size': self._get_file_size(file_path)
                    }
                    
                    results.append(result)
                    
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
                    results.append({
                        'file_path': file_path,
                        'file_name': Path(file_path).name,
                        'threat_level': 'error',
                        'error': str(e)
                    })
        
        return results
    
    def _display_scan_results(self, results: List[Dict[str, Any]], format_type: str):
        """Display scan results"""
        if format_type == "json":
            print(json.dumps(results, indent=2, default=str))
            return
        
        if HAS_RICH and format_type == "table":
            table = Table(title="Scan Results")
            table.add_column("File", style="cyan")
            table.add_column("Status", style="white")
            table.add_column("Threat", style="red")
            table.add_column("Confidence", style="yellow")
            table.add_column("Size", style="green")
            
            for result in results:
                status_style = self._get_status_style(result.get('threat_level', 'unknown'))
                
                table.add_row(
                    result.get('file_name', 'Unknown'),
                    Text(result.get('threat_level', 'unknown').upper(), style=status_style),
                    result.get('threat_name', '') or '',
                    f"{result.get('confidence', 0):.2f}" if result.get('confidence') else '',
                    self._format_file_size(result.get('file_size', 0))
                )
            
            console.print(table)
        else:
            # Simple text output
            print("\nScan Results:")
            print("-" * 80)
            print(f"{'File':<30} {'Status':<12} {'Threat':<20} {'Confidence':<10}")
            print("-" * 80)
            
            for result in results:
                print(f"{result.get('file_name', 'Unknown')[:29]:<30} "
                      f"{result.get('threat_level', 'unknown').upper():<12} "
                      f"{(result.get('threat_name') or '')[:19]:<20} "
                      f"{result.get('confidence', 0):.2f}")
    
    def _get_status_style(self, threat_level: str) -> str:
        """Get Rich style for threat level"""
        styles = {
            'clean': 'green',
            'suspicious': 'yellow',
            'malware': 'red',
            'critical': 'bold red',
            'error': 'magenta'
        }
        return styles.get(threat_level.lower(), 'white')
    
    def _get_file_size(self, file_path: str) -> int:
        """Get file size safely"""
        try:
            return Path(file_path).stat().st_size
        except Exception:
            return 0
    
    def _format_file_size(self, size: int) -> str:
        """Format file size for display"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def _save_results(self, results: List[Dict[str, Any]], output_path: str, format_type: str):
        """Save scan results to file"""
        try:
            with open(output_path, 'w') as f:
                if format_type == "json":
                    json.dump(results, f, indent=2, default=str)
                elif format_type == "csv":
                    f.write("File,Status,Threat,Confidence,Size\n")
                    for result in results:
                        f.write(f'"{result.get("file_name", "")}",')
                        f.write(f'"{result.get("threat_level", "")}",')
                        f.write(f'"{result.get("threat_name", "")}",')
                        f.write(f'{result.get("confidence", 0):.2f},')
                        f.write(f'{result.get("file_size", 0)}\n')
            
            self._print_success(f"Results saved to: {output_path}")
            
        except Exception as e:
            self._print_error(f"Failed to save results: {e}")
    
    def info_command(self) -> bool:
        """Display system and antivirus information"""
        try:
            self._print_info("System Information:")
            
            # System info
            system_info = self._get_system_info()
            self._display_system_info(system_info)
            
            # Component status
            self._print_info("\nComponent Status:")
            self._display_component_status()
            
            # Configuration info
            config_info = self._get_config_info()
            if config_info:
                self._print_info("\nConfiguration:")
                self._display_config_info(config_info)
            
            return True
            
        except Exception as e:
            self._print_error(f"Info command failed: {e}")
            return False
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        import platform
        
        info = {
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            }
        }
        
        if HAS_PSUTIL:
            try:
                memory = psutil.virtual_memory()
                info['memory'] = {
                    'total_gb': memory.total / (1024**3),
                    'available_gb': memory.available / (1024**3),
                    'used_percent': memory.percent
                }
                
                disk = psutil.disk_usage('/')
                info['disk'] = {
                    'total_gb': disk.total / (1024**3),
                    'free_gb': disk.free / (1024**3),
                    'used_percent': (disk.used / disk.total) * 100
                }
            except Exception as e:
                self.logger.debug(f"Error getting system stats: {e}")
        
        return info
    
    def _display_system_info(self, info: Dict[str, Any]):
        """Display system information"""
        if HAS_RICH:
            table = Table(title="System Information")
            table.add_column("Component", style="cyan")
            table.add_column("Details", style="white")
            
            # Platform info
            platform_info = info.get("platform", {})
            table.add_row("Operating System", 
                         f"{platform_info.get('system', 'Unknown')} {platform_info.get('release', '')}")
            table.add_row("Architecture", platform_info.get("machine", "Unknown"))
            table.add_row("Processor", platform_info.get("processor", "Unknown"))
            
            # Memory info
            memory_info = info.get("memory", {})
            if memory_info:
                table.add_row("Total Memory", f"{memory_info.get('total_gb', 0):.1f} GB")
                table.add_row("Available Memory", f"{memory_info.get('available_gb', 0):.1f} GB")
                table.add_row("Memory Usage", f"{memory_info.get('used_percent', 0):.1f}%")
            
            # Disk info
            disk_info = info.get("disk", {})
            if disk_info:
                table.add_row("Total Disk", f"{disk_info.get('total_gb', 0):.1f} GB")
                table.add_row("Free Disk", f"{disk_info.get('free_gb', 0):.1f} GB")
                table.add_row("Disk Usage", f"{disk_info.get('used_percent', 0):.1f}%")
            
            console.print(table)
        else:
            platform_info = info.get("platform", {})
            print(f"OS: {platform_info.get('system', 'Unknown')} {platform_info.get('release', '')}")
            print(f"Architecture: {platform_info.get('machine', 'Unknown')}")
            
            memory_info = info.get("memory", {})
            if memory_info:
                print(f"Memory: {memory_info.get('total_gb', 0):.1f} GB total, "
                      f"{memory_info.get('available_gb', 0):.1f} GB available")
    
    def _display_component_status(self):
        """Display component status"""
        components = {
            'Threat Engine': self.threat_engine is not None,
            'Quarantine Manager': self.quarantine_manager is not None,
            'Real-time Monitor': self.realtime_monitor is not None,
            'Service Manager': self.service_manager is not None
        }
        
        if HAS_RICH:
            table = Table(title="Component Status")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="white")
            
            for component, available in components.items():
                status = Text("✅ Available" if available else "❌ Not Available",
                            style="green" if available else "red")
                table.add_row(component, status)
            
            console.print(table)
        else:
            for component, available in components.items():
                status = "✅ Available" if available else "❌ Not Available"
                print(f"{component}: {status}")
    
    def _get_config_info(self) -> Dict[str, Any]:
        """Get configuration information"""
        try:
            return {
                'ML Threshold': secure_config.get('detection.ml_threshold', 0.85),
                'Real-time Monitoring': secure_config.get('monitoring.enabled', True),
                'Auto Updates': secure_config.get('updates.auto_update', True),
                'Quarantine Enabled': secure_config.get('quarantine.enabled', True)
            }
        except Exception as e:
            self.logger.debug(f"Error getting config info: {e}")
            return {}
    
    def _display_config_info(self, config_info: Dict[str, Any]):
        """Display configuration information"""
        if HAS_RICH:
            table = Table(title="Configuration")
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="white")
            
            for key, value in config_info.items():
                table.add_row(key, str(value))
            
            console.print(table)
        else:
            for key, value in config_info.items():
                print(f"{key}: {value}")
    
    def service_command(self, action: str) -> bool:
        """Handle service management commands"""
        try:
            if not self.service_manager:
                self._print_error("Service manager not available")
                return False
            
            if action == "install":
                success = self.service_manager.install_service()
                if success:
                    self._print_success("Service installed successfully")
                else:
                    self._print_error("Service installation failed")
                return success
                
            elif action == "uninstall":
                success = self.service_manager.uninstall_service()
                if success:
                    self._print_success("Service uninstalled successfully")
                else:
                    self._print_error("Service uninstallation failed")
                return success
                
            elif action == "start":
                success = self.service_manager.start_service()
                if success:
                    self._print_success("Service started successfully")
                else:
                    self._print_error("Service start failed")
                return success
                
            elif action == "stop":
                success = self.service_manager.stop_service()
                if success:
                    self._print_success("Service stopped successfully")
                else:
                    self._print_error("Service stop failed")
                return success
                
            elif action == "status":
                status = self.service_manager.get_service_status()
                self._display_service_status(status)
                return True
                
            else:
                self._print_error(f"Unknown service action: {action}")
                return False
                
        except Exception as e:
            self._print_error(f"Service command failed: {e}")
            return False
    
    def _display_service_status(self, status: Dict[str, Any]):
        """Display service status"""
        if HAS_RICH:
            table = Table(title="Service Status")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")
            
            for key, value in status.items():
                if key != "monitor_status":  # Skip complex nested data
                    table.add_row(key.replace('_', ' ').title(), str(value))
            
            console.print(table)
        else:
            print("Service Status:")
            for key, value in status.items():
                if key != "monitor_status":
                    print(f"  {key.replace('_', ' ').title()}: {value}")
    
    def monitor_command(self, action: str, paths: Optional[List[str]] = None) -> bool:
        """Handle real-time monitoring commands"""
        try:
            if not self.realtime_monitor:
                self._print_error("Real-time monitor not available")
                return False
            
            if action == "start":
                if not paths:
                    paths = [
                        str(Path.home() / "Downloads"),
                        str(Path.home() / "Desktop"),
                        str(Path.home() / "Documents")
                    ]
                
                success = self.realtime_monitor.start_monitoring(paths)
                if success:
                    self._print_success(f"Real-time monitoring started for {len(paths)} paths")
                else:
                    self._print_error("Failed to start real-time monitoring")
                return success
                
            elif action == "stop":
                self.realtime_monitor.stop_monitoring()
                self._print_success("Real-time monitoring stopped")
                return True
                
            elif action == "status":
                status = self.realtime_monitor.get_status()
                self._display_monitor_status(status)
                return True
                
            else:
                self._print_error(f"Unknown monitor action: {action}")
                return False
                
        except Exception as e:
            self._print_error(f"Monitor command failed: {e}")
            return False
    
    def _display_monitor_status(self, status: Dict[str, Any]):
        """Display monitor status"""
        if HAS_RICH:
            table = Table(title="Real-time Monitor Status")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")
            
            # Basic status
            table.add_row("Monitoring", "✅ Active" if status.get('is_monitoring') else "❌ Inactive")
            table.add_row("Uptime", f"{status.get('current_uptime', 0):.1f} seconds")
            table.add_row("Monitored Paths", str(len(status.get('monitored_paths', []))))
            
            # Processor stats
            processor_stats = status.get('processor_stats', {})
            if processor_stats:
                table.add_row("Events Processed", str(processor_stats.get('events_processed', 0)))
                table.add_row("Threats Detected", str(processor_stats.get('threats_detected', 0)))
                table.add_row("Files Quarantined", str(processor_stats.get('files_quarantined', 0)))
            
            console.print(table)
        else:
            print("Real-time Monitor Status:")
            print(f"  Monitoring: {'Active' if status.get('is_monitoring') else 'Inactive'}")
            print(f"  Uptime: {status.get('current_uptime', 0):.1f} seconds")
            print(f"  Monitored Paths: {len(status.get('monitored_paths', []))}")
            
            processor_stats = status.get('processor_stats', {})
            if processor_stats:
                print(f"  Events Processed: {processor_stats.get('events_processed', 0)}")
                print(f"  Threats Detected: {processor_stats.get('threats_detected', 0)}")
    
    def _print_success(self, message: str):
        """Print success message"""
        if HAS_RICH:
            console.print(f"✅ {message}", style="green")
        else:
            print(f"✅ {message}")
    
    def _print_error(self, message: str):
        """Print error message"""
        if HAS_RICH:
            console.print(f"❌ {message}", style="red")
        else:
            print(f"❌ {message}")
    
    def _print_warning(self, message: str):
        """Print warning message"""
        if HAS_RICH:
            console.print(f"⚠️ {message}", style="yellow")
        else:
            print(f"⚠️ {message}")
    
    def _print_info(self, message: str):
        """Print info message"""
        if HAS_RICH:
            console.print(f"ℹ️ {message}", style="blue")
        else:
            print(f"ℹ️ {message}")

def main():
    """Main CLI entry point"""
    try:
        cli = AntivirusCLI()
        
        # Create argument parser
        parser = argparse.ArgumentParser(
            description="Prashant918 Advanced Antivirus CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s scan /path/to/file
  %(prog)s scan /path/to/directory --recursive
  %(prog)s scan /path --output results.json --format json
  %(prog)s info
  %(prog)s service install
  %(prog)s service start
  %(prog)s monitor start
            """
        )
        
        parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan files or directories for threats')
        scan_parser.add_argument('path', help='Path to scan')
        scan_parser.add_argument('--recursive', '-r', action='store_true', default=True,
                               help='Scan directories recursively (default: True)')
        scan_parser.add_argument('--output', '-o', help='Output file for results')
        scan_parser.add_argument('--format', '-f', choices=['table', 'json', 'csv'], 
                               default='table', help='Output format (default: table)')
        
        # Info command
        subparsers.add_parser('info', help='Display system and antivirus information')
        
        # Service command
        service_parser = subparsers.add_parser('service', help='Manage antivirus service')
        service_parser.add_argument('action', choices=['install', 'uninstall', 'start', 'stop', 'status'],
                                  help='Service action')
        
        # Monitor command
        monitor_parser = subparsers.add_parser('monitor', help='Manage real-time monitoring')
        monitor_parser.add_argument('action', choices=['start', 'stop', 'status'],
                                  help='Monitor action')
        monitor_parser.add_argument('--paths', nargs='+', help='Paths to monitor')
        
        # Parse arguments
        args = parser.parse_args()
        
        # Display banner
        cli.display_banner()
        
        # Handle commands
        if args.command == 'scan':
            success = cli.scan_command(args.path, args.recursive, args.output, args.format)
            sys.exit(0 if success else 1)
            
        elif args.command == 'info':
            success = cli.info_command()
            sys.exit(0 if success else 1)
            
        elif args.command == 'service':
            success = cli.service_command(args.action)
            sys.exit(0 if success else 1)
            
        elif args.command == 'monitor':
            success = cli.monitor_command(args.action, args.paths)
            sys.exit(0 if success else 1)
            
        else:
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ CLI error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()