#!/usr/bin/env python3
"""
Prashant918 Advanced Antivirus - Web Launcher
Quick launcher for the web interface
"""

import sys
import os
import webbrowser
import time
import threading
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent
src_path = project_root / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

def open_browser_delayed(url, delay=3):
    """Open browser after delay"""
    time.sleep(delay)
    webbrowser.open(url)

def main():
    """Launch web interface directly"""
    try:
        # Try to launch web interface directly
        from prashant918_antivirus.web.app import create_app
        
        print("Starting Prashant918 Advanced Antivirus Web Interface...")
        print("Web interface will be available at: http://127.0.0.1:5000")
        print("Press Ctrl+C to stop the server")
        
        # Open browser in background
        browser_thread = threading.Thread(
            target=open_browser_delayed, 
            args=("http://127.0.0.1:5000",)
        )
        browser_thread.daemon = True
        browser_thread.start()
        
        # Create and run app
        app = create_app()
        app.run(host="127.0.0.1", port=5000, debug=False)
        
    except ImportError as e:
        print(f"Web components not available: {e}")
        print("Please install required dependencies:")
        print("pip install Flask Flask-CORS Flask-SocketIO")
        
        # Fallback to main launcher
        try:
            import subprocess
            main_script = project_root / "main.py"
            subprocess.run([sys.executable, str(main_script), "web"])
        except Exception as fallback_error:
            print(f"Fallback launcher also failed: {fallback_error}")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nWeb server stopped")
    except Exception as e:
        print(f"Web launch error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
