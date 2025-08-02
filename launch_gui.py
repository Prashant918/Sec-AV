#!/usr/bin/env python3
"""
Prashant918 Advanced Antivirus - GUI Launcher
Quick launcher for the graphical interface
"""

import sys
import os
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent
src_path = project_root / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

def main():
    """Launch GUI directly"""
    try:
        # Try to launch GUI directly
        from prashant918_antivirus.gui.main_window import main as gui_main
        print("Starting Prashant918 Advanced Antivirus GUI...")
        gui_main()
    except ImportError as e:
        print(f"GUI components not available: {e}")
        print("Please install required dependencies:")
        print("pip install -r requirements.txt")
        
        # Fallback to main launcher
        try:
            import subprocess
            main_script = project_root / "main.py"
            subprocess.run([sys.executable, str(main_script), "gui"])
        except Exception as fallback_error:
            print(f"Fallback launcher also failed: {fallback_error}")
            sys.exit(1)
    except Exception as e:
        print(f"GUI launch error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
