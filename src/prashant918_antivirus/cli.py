"""
Prashant918 Advanced Antivirus - Command Line Interface

Main CLI entry point for the cybersecurity platform providing
comprehensive command-line tools for threat detection and management.
"""

import os
import sys
import argparse
import json
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

# Handle optional dependencies gracefully
try:
    import click
    CLICK_AVAILABLE = True
except ImportError:
    CLICK_AVAILABLE = False
    print("Warning: click not available, using basic argument parsing")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: rich not available, using basic output")
    
    # Create a simple console replacement
    class SimpleConsole:
        def print(self, *args, **kwargs):
            print(*args)
        
        def __getattr__(self, name):
            return lambda *args, **kwargs: None
    
    console = SimpleConsole()

# Package imports with error handling
try:
    from . import __version__, __author__
except ImportError:
    __version__ = "2.0.0"
    __author__ = "Prashant918 Security Team"

try:
    from .utils import (
        initialize, get_system_info, check_dependencies,
        format_bytes, format_duration, PerformanceTimer
    )
except ImportError:
    print("Warning: utils module not available")
    
    def initialize(*args, **kwargs):
        return {"status": "error", "message": "Utils not available"}
    
    def get_system_info():
        return {"error": "System info not available"}
    
    def check_dependencies():
        return {"status": "error", "message": "Dependency check not available"}
    
    def format_bytes(size):
        return f"{size} bytes"
    
    def format_duration(seconds):
        return f"{seconds:.2f}s"
    
    class PerformanceTimer:
        def __init__(self, name):
            self.name = name
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

try:
    from .exceptions import AntivirusError, handle_exception
except ImportError:
    print("Warning: exceptions module not available")
    
    class AntivirusError(Exception):
        pass
    
    def handle_exception(error, logger_func, reraise=True):
        logger_func(f"Error: {error}")
        if reraise:
            raise error

# CLI implementation with and without click
if CLICK_AVAILABLE:
    @click.group()
    @click.version_option(version=__version__, prog_name="Prashant918 Advanced Antivirus")
    @click.option('--config', '-c', help='Configuration file path')
    @click.option('--verbose', '-v', is_flag=True, help='Verbose output')
    @click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
    @click.pass_context
    def main(ctx, config, verbose, quiet):
        """
        Prashant918 Advanced Antivirus - Enterprise Cybersecurity Solution
        
        A comprehensive cybersecurity platform providing advanced threat detection,
        real-time monitoring, and enterprise-grade protection capabilities.
        """
        # Ensure context object exists
        ctx.ensure_object(dict)
        
        # Store global options
        ctx.obj['config'] = config
        ctx.obj['verbose'] = verbose
        ctx.obj['quiet'] = quiet
        
        # Set console verbosity
        if quiet and hasattr(console, 'quiet'):
            console.quiet = True
        
        # Display banner if not quiet
        if not quiet:
            display_banner()

    @main.command()
    @click.argument('path', type=click.Path(exists=True))
    @click.option('--recursive', '-r', is_flag=True, help='Scan recursively')
    @click.option('--output', '-o', help='Output file for results')
    @click.option('--format', 'output_format', type=click.Choice(['json', 'table', 'csv']), 
                  default='table', help='Output format')
    @click.option('--threads', '-t', type=int, default=4, help='Number of threads')
    @click.pass_context
    def scan(ctx, path, recursive, output, output_format, threads):
        """Scan files or directories for threats"""
        try:
            with PerformanceTimer("Scan operation"):
                # Try to import antivirus engine
                try:
                    from .antivirus.engine import AdvancedThreatDetectionEngine
                    engine = AdvancedThreatDetectionEngine()
                except ImportError:
                    console.print("❌ Antivirus engine not available. Please check dependencies.", style="red")
                    return
                
                console.print("🔧 Initializing antivirus engine...", style="yellow")
                
                # Collect files to scan
                files_to_scan = collect_files(path, recursive)
                
                if not files_to_scan:
                    console.print("❌ No files found to scan", style="red")
                    return
                
                console.print(f"📁 Found {len(files_to_scan)} files to scan", style="green")
                
                # Perform scanning with progress bar
                results = perform_scan(engine, files_to_scan, threads)
                
                # Display results
                display_scan_results(results, output_format)
                
                # Save results if output specified
                if output:
                    save_results(results, output, output_format)
                    console.print(f"💾 Results saved to {output}", style="green")
        
        except Exception as e:
            handle_exception(e, console.print, reraise=False)
            sys.exit(1)

    @main.command()
    @click.option('--show-system', is_flag=True, help='Show system information')
    @click.option('--show-deps', is_flag=True, help='Show dependency status')
    @click.option('--show-config', is_flag=True, help='Show configuration')
    @click.option('--show-stats', is_flag=True, help='Show statistics')
    @click.pass_context
    def info(ctx, show_system, show_deps, show_config, show_stats):
        """Display system and application information"""
        try:
            if show_system:
                system_info = get_system_info()
                display_system_info(system_info)
            
            if show_deps:
                deps_info = check_dependencies()
                display_dependencies_info(deps_info)
            
            if show_config:
                try:
                    from .antivirus.config import secure_config
                    config_info = {"status": "Config loaded successfully"}
                    display_config_info(config_info)
                except ImportError:
                    console.print("❌ Configuration module not available", style="red")
            
            if show_stats:
                try:
                    from .antivirus.signatures import AdvancedSignatureManager
                    signature_manager = AdvancedSignatureManager()
                    stats = signature_manager.get_threat_statistics()
                    display_threat_statistics(stats)
                except ImportError:
                    console.print("❌ Statistics module not available", style="red")
            
            if not any([show_system, show_deps, show_config, show_stats]):
                # Show basic info by default
                console.print(f"Prashant918 Advanced Antivirus v{__version__}", style="bold")
                console.print(f"Author: {__author__}")
                console.print("\nUse --help for available options")
        
        except Exception as e:
            handle_exception(e, console.print, reraise=False)
            sys.exit(1)

else:
    # Fallback implementation without click
    def main():
        """Main CLI function without click"""
        import argparse
        
        parser = argparse.ArgumentParser(
            description="Prashant918 Advanced Antivirus - Enterprise Cybersecurity Solution"
        )
        parser.add_argument('--version', action='version', version=f'Prashant918 Advanced Antivirus {__version__}')
        parser.add_argument('--config', '-c', help='Configuration file path')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan files or directories')
        scan_parser.add_argument('path', help='Path to scan')
        scan_parser.add_argument('--recursive', '-r', action='store_true', help='Scan recursively')
        scan_parser.add_argument('--output', '-o', help='Output file for results')
        scan_parser.add_argument('--format', choices=['json', 'table', 'csv'], default='table', help='Output format')
        scan_parser.add_argument('--threads', '-t', type=int, default=4, help='Number of threads')
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Show system information')
        info_parser.add_argument('--show-system', action='store_true', help='Show system information')
        info_parser.add_argument('--show-deps', action='store_true', help='Show dependency status')
        info_parser.add_argument('--show-config', action='store_true', help='Show configuration')
        info_parser.add_argument('--show-stats', action='store_true', help='Show statistics')
        
        args = parser.parse_args()
        
        if not args.quiet:
            display_banner()
        
        if args.command == 'scan':
            handle_scan_command(args)
        elif args.command == 'info':
            handle_info_command(args)
        else:
            parser.print_help()

def display_banner():
    """Display application banner"""
    if RICH_AVAILABLE:
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
║  🏢  Enterprise Oracle Backend                               ║
╚══════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner_text, style="bold blue"))
    else:
        print("="*60)
        print("         Prashant918 Advanced Antivirus")
        print("        Enterprise Cybersecurity Solution")
        print("")
        print(f"  Version: {__version__}    Author: {__author__}")
        print("")
        print("  🛡️  Multi-layered Threat Detection")
        print("  🤖  AI/ML Powered Analysis")
        print("  🔍  Real-time Monitoring")
        print("  🏢  Enterprise Oracle Backend")
        print("="*60)

def collect_files(path: str, recursive: bool) -> List[str]:
    """Collect files to scan"""
    files = []
    path_obj = Path(path)
    
    if path_obj.is_file():
        files.append(str(path_obj))
    elif path_obj.is_dir():
        if recursive:
            for file_path in path_obj.rglob('*'):
                if file_path.is_file():
                    files.append(str(file_path))
        else:
            for file_path in path_obj.iterdir():
                if file_path.is_file():
                    files.append(str(file_path))
    
    return files

def perform_scan(engine, files: List[str], threads: int) -> List[Dict[str, Any]]:
    """Perform scanning with progress tracking"""
    results = []
    
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Scanning files...", total=len(files))
            
            for i, file_path in enumerate(files):
                try:
                    result = engine.scan_file(file_path)
                    results.append(result)
                    
                    # Update progress
                    progress.update(
                        task, 
                        advance=1, 
                        description=f"Scanning: {os.path.basename(file_path)}"
                    )
                    
                except Exception as e:
                    results.append({
                        "file_path": file_path,
                        "error": str(e),
                        "classification": "ERROR"
                    })
    else:
        # Simple progress without rich
        for i, file_path in enumerate(files):
            print(f"Scanning {i+1}/{len(files)}: {os.path.basename(file_path)}")
            try:
                result = engine.scan_file(file_path)
                results.append(result)
            except Exception as e:
                results.append({
                    "file_path": file_path,
                    "error": str(e),
                    "classification": "ERROR"
                })
    
    return results

def display_scan_results(results: List[Dict[str, Any]], format_type: str):
    """Display scan results in specified format"""
    if format_type == 'table':
        display_results_table(results)
    elif format_type == 'json':
        print(json.dumps(results, indent=2))
    elif format_type == 'csv':
        display_results_csv(results)

def display_results_table(results: List[Dict[str, Any]]):
    """Display results in table format"""
    if RICH_AVAILABLE:
        table = Table(title="Scan Results")
        
        table.add_column("File", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Threats", style="red")
        table.add_column("Score", style="yellow")
        table.add_column("Size", style="green")
        
        for result in results:
            file_path = result.get("file_path", "Unknown")
            classification = result.get("classification", "Unknown")
            threat_count = len(result.get("detections", []))
            threat_score = result.get("threat_score", 0.0)
            file_size = result.get("file_size", 0)
            
            # Color code status
            if classification == "CLEAN":
                status_style = "green"
            elif classification in ["SUSPICIOUS", "POTENTIALLY_UNWANTED"]:
                status_style = "yellow"
            elif classification == "MALICIOUS":
                status_style = "red"
            else:
                status_style = "white"
            
            table.add_row(
                os.path.basename(file_path),
                Text(classification, style=status_style),
                str(threat_count),
                f"{threat_score:.2f}",
                format_bytes(file_size)
            )
        
        console.print(table)
    else:
        # Simple table without rich
        print("\nScan Results:")
        print("-" * 80)
        print(f"{'File':<30} {'Status':<15} {'Threats':<8} {'Score':<8} {'Size':<10}")
        print("-" * 80)
        
        for result in results:
            file_path = result.get("file_path", "Unknown")
            classification = result.get("classification", "Unknown")
            threat_count = len(result.get("detections", []))
            threat_score = result.get("threat_score", 0.0)
            file_size = result.get("file_size", 0)
            
            print(f"{os.path.basename(file_path)[:29]:<30} {classification:<15} {threat_count:<8} {threat_score:<8.2f} {format_bytes(file_size):<10}")
    
    # Summary
    total_files = len(results)
    clean_files = sum(1 for r in results if r.get("classification") == "CLEAN")
    threat_files = total_files - clean_files
    
    print(f"\n📊 Summary: {total_files} files scanned, {clean_files} clean, {threat_files} threats detected")

def display_results_csv(results: List[Dict[str, Any]]):
    """Display results in CSV format"""
    print("File,Status,Threats,Score,Size")
    for result in results:
        file_path = result.get("file_path", "")
        classification = result.get("classification", "")
        threat_count = len(result.get("detections", []))
        threat_score = result.get("threat_score", 0.0)
        file_size = result.get("file_size", 0)
        
        print(f'"{os.path.basename(file_path)}","{classification}",{threat_count},{threat_score},{file_size}')

def display_system_info(info: Dict[str, Any]):
    """Display system information"""
    if RICH_AVAILABLE:
        table = Table(title="System Information")
        table.add_column("Component", style="cyan")
        table.add_column("Details", style="white")
        
        # Platform info
        platform_info = info.get("platform", {})
        table.add_row("Operating System", f"{platform_info.get('system', 'Unknown')} {platform_info.get('release', '')}")
        table.add_row("Architecture", platform_info.get("machine", "Unknown"))
        table.add_row("Processor", platform_info.get("processor", "Unknown"))
        
        # Memory info
        memory_info = info.get("memory", {})
        table.add_row("Total Memory", f"{memory_info.get('total_gb', 0):.1f} GB")
        table.add_row("Available Memory", f"{memory_info.get('available_gb', 0):.1f} GB")
        table.add_row("Memory Usage", f"{memory_info.get('used_percent', 0):.1f}%")
        
        console.print(table)
    else:
        print("\nSystem Information:")
        print("-" * 40)
        platform_info = info.get("platform", {})
        print(f"OS: {platform_info.get('system', 'Unknown')} {platform_info.get('release', '')}")
        print(f"Architecture: {platform_info.get('machine', 'Unknown')}")
        
        memory_info = info.get("memory", {})
        print(f"Memory: {memory_info.get('total_gb', 0):.1f} GB total, {memory_info.get('available_gb', 0):.1f} GB available")

def display_dependencies_info(deps: Dict[str, Any]):
    """Display dependency information"""
    if RICH_AVAILABLE:
        table = Table(title="Dependencies Status")
        table.add_column("Package", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Version", style="yellow")
        table.add_column("Required", style="green")
        
        # Required dependencies
        for package, info in deps.get("required", {}).items():
            status = "✅ Available" if info["available"] else "❌ Missing"
            status_style = "green" if info["available"] else "red"
            
            table.add_row(
                package,
                Text(status, style=status_style),
                info.get("version", "N/A"),
                info.get("requirement", "N/A")
            )
        
        console.print(table)
    else:
        print("\nDependencies Status:")
        print("-" * 60)
        for package, info in deps.get("required", {}).items():
            status = "✅ Available" if info["available"] else "❌ Missing"
            print(f"{package:<20} {status:<15} {info.get('version', 'N/A'):<15}")
    
    # Summary
    missing_required = deps.get("missing_required", [])
    if missing_required:
        print(f"\n❌ Missing required dependencies: {', '.join(missing_required)}")
    else:
        print("\n✅ All required dependencies are available")

def display_config_info(config_info: Dict[str, Any]):
    """Display configuration information"""
    print("\nConfiguration Status:")
    print("-" * 30)
    for key, value in config_info.items():
        print(f"{key}: {value}")

def display_threat_statistics(stats: Dict[str, Any]):
    """Display threat statistics"""
    print("\nThreat Statistics:")
    print("-" * 30)
    for key, value in stats.items():
        print(f"{key}: {value}")

def save_results(results: List[Dict[str, Any]], output_path: str, format_type: str):
    """Save scan results to file"""
    with open(output_path, 'w') as f:
        if format_type == 'json':
            json.dump(results, f, indent=2)
        elif format_type == 'csv':
            f.write("File,Status,Threats,Score,Size\n")
            for result in results:
                f.write(f'"{os.path.basename(result.get("file_path", ""))}",')
                f.write(f'"{result.get("classification", "")}",')
                f.write(f'{len(result.get("detections", []))},')
                f.write(f'{result.get("threat_score", 0.0)},')
                f.write(f'{result.get("file_size", 0)}\n')

def handle_scan_command(args):
    """Handle scan command for non-click version"""
    try:
        from .antivirus.engine import AdvancedThreatDetectionEngine
        engine = AdvancedThreatDetectionEngine()
    except ImportError:
        print("❌ Antivirus engine not available. Please check dependencies.")
        return
    
    print("🔧 Initializing antivirus engine...")
    
    files_to_scan = collect_files(args.path, args.recursive)
    
    if not files_to_scan:
        print("❌ No files found to scan")
        return
    
    print(f"📁 Found {len(files_to_scan)} files to scan")
    
    results = perform_scan(engine, files_to_scan, args.threads)
    display_scan_results(results, args.format)
    
    if args.output:
        save_results(results, args.output, args.format)
        print(f"💾 Results saved to {args.output}")

def handle_info_command(args):
    """Handle info command for non-click version"""
    if args.show_system:
        system_info = get_system_info()
        display_system_info(system_info)
    
    if args.show_deps:
        deps_info = check_dependencies()
        display_dependencies_info(deps_info)
    
    if args.show_config:
        try:
            from .antivirus.config import secure_config
            config_info = {"status": "Config loaded successfully"}
            display_config_info(config_info)
        except ImportError:
            print("❌ Configuration module not available")
    
    if args.show_stats:
        try:
            from .antivirus.signatures import AdvancedSignatureManager
            signature_manager = AdvancedSignatureManager()
            stats = signature_manager.get_threat_statistics()
            display_threat_statistics(stats)
        except ImportError:
            print("❌ Statistics module not available")
    
    if not any([args.show_system, args.show_deps, args.show_config, args.show_stats]):
        print(f"Prashant918 Advanced Antivirus v{__version__}")
        print(f"Author: {__author__}")
        print("\nUse --help for available options")

if __name__ == '__main__':
    main()