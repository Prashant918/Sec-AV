"""
Prashant918 Advanced Antivirus - Main Entry Point

Main application entry point with proper error handling and dependency management.
"""

import sys
import os
import traceback
from typing import Optional

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 9):
        print(f"Error: Python 3.9 or later is required. Current version: {sys.version_info.major}.{sys.version_info.minor}")
        sys.exit(1)

def check_basic_dependencies():
    """Check for basic required dependencies"""
    missing_deps = []
    
    # Check for absolutely essential dependencies
    essential_deps = ['os', 'sys', 'json', 'time', 'threading']
    for dep in essential_deps:
        try:
            __import__(dep)
        except ImportError:
            missing_deps.append(dep)
    
    if missing_deps:
        print(f"Error: Missing essential dependencies: {', '.join(missing_deps)}")
        sys.exit(1)

def safe_import_module(module_name: str, package: Optional[str] = None):
    """Safely import a module with error handling"""
    try:
        if package:
            return __import__(f"{package}.{module_name}", fromlist=[module_name])
        else:
            return __import__(module_name)
    except ImportError as e:
        print(f"Warning: Could not import {module_name}: {e}")
        return None

def main():
    """Main entry point with comprehensive error handling"""
    try:
        # Check Python version first
        check_python_version()
        
        # Check basic dependencies
        check_basic_dependencies()
        
        # Try to import and run CLI
        cli_module = safe_import_module('cli', 'prashant918_antivirus')
        if cli_module and hasattr(cli_module, 'main'):
            cli_module.main()
        else:
            # Fallback to basic functionality
            print("Prashant918 Advanced Antivirus")
            print("CLI module not available. Please check dependencies.")
            print("\nTo install dependencies, run:")
            print("pip install -r requirements.txt")
            
            # Show basic help
            if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
                print("\nBasic usage:")
                print("  prashant918-av scan <path>     # Scan files")
                print("  prashant918-av info            # Show system info")
                print("  prashant918-av --version       # Show version")
            
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        if '--debug' in sys.argv:
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()