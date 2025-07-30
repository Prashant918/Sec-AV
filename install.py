#!/usr/bin/env python3
"""
Prashant918 Advanced Antivirus - Universal Installer
Cross-platform installation script with dependency management
"""
import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class AntivirusInstaller:
    """Universal installer for Prashant918 Advanced Antivirus"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.architecture = platform.machine().lower()
        self.python_version = sys.version_info
        self.project_root = Path(__file__).parent.absolute()
        
        # Installation status
        self.installation_log = []
        self.errors = []
        
    def log(self, message: str, level: str = "INFO"):
        """Log installation messages"""
        log_entry = f"[{level}] {message}"
        self.installation_log.append(log_entry)
        print(log_entry)
    
    def error(self, message: str):
        """Log error messages"""
        self.errors.append(message)
        self.log(message, "ERROR")
    
    def check_prerequisites(self) -> bool:
        """Check system prerequisites"""
        self.log("Checking system prerequisites...")
        
        # Check Python version
        if self.python_version < (3, 8):
            self.error(f"Python 3.8+ required, found {self.python_version.major}.{self.python_version.minor}")
            return False
        
        self.log(f"Python version: {self.python_version.major}.{self.python_version.minor}.{self.python_version.micro}")
        
        # Check platform support
        supported_platforms = ["windows", "linux", "darwin"]
        if self.platform not in supported_platforms:
            self.error(f"Unsupported platform: {self.platform}")
            return False
        
        self.log(f"Platform: {self.platform} ({self.architecture})")
        
        # Check pip availability
        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"], 
                         check=True, capture_output=True)
            self.log("pip is available")
        except subprocess.CalledProcessError:
            self.error("pip is not available or not working")
            return False
        
        # Check virtual environment capability
        try:
            subprocess.run([sys.executable, "-m", "venv", "--help"], 
                         check=True, capture_output=True)
            self.log("venv module is available")
        except subprocess.CalledProcessError:
            self.log("venv module not available, will use system Python", "WARNING")
        
        return True
    
    def create_virtual_environment(self, venv_path: Path) -> bool:
        """Create virtual environment"""
        try:
            self.log(f"Creating virtual environment at {venv_path}")
            
            if venv_path.exists():
                self.log("Removing existing virtual environment")
                shutil.rmtree(venv_path)
            
            subprocess.run([
                sys.executable, "-m", "venv", str(venv_path)
            ], check=True)
            
            self.log("Virtual environment created successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.error(f"Failed to create virtual environment: {e}")
            return False
    
    def get_venv_python(self, venv_path: Path) -> str:
        """Get path to Python executable in virtual environment"""
        if self.platform == "windows":
            return str(venv_path / "Scripts" / "python.exe")
        else:
            return str(venv_path / "bin" / "python")
    
    def get_venv_pip(self, venv_path: Path) -> str:
        """Get path to pip executable in virtual environment"""
        if self.platform == "windows":
            return str(venv_path / "Scripts" / "pip.exe")
        else:
            return str(venv_path / "bin" / "pip")
    
    def upgrade_pip(self, pip_executable: str) -> bool:
        """Upgrade pip to latest version"""
        try:
            self.log("Upgrading pip...")
            subprocess.run([
                pip_executable, "install", "--upgrade", "pip", "setuptools", "wheel"
            ], check=True)
            self.log("pip upgraded successfully")
            return True
        except subprocess.CalledProcessError as e:
            self.error(f"Failed to upgrade pip: {e}")
            return False
    
    def install_dependencies(self, pip_executable: str) -> bool:
        """Install dependencies from requirements.txt"""
        requirements_file = self.project_root / "requirements.txt"
        
        if not requirements_file.exists():
            self.error("requirements.txt not found")
            return False
        
        try:
            self.log("Installing dependencies...")
            
            # Install with specific flags for better compatibility
            cmd = [
                pip_executable, "install", 
                "-r", str(requirements_file),
                "--no-cache-dir",
                "--prefer-binary"
            ]
            
            # Add platform-specific flags
            if self.platform == "linux":
                cmd.extend(["--only-binary=all"])
            
            subprocess.run(cmd, check=True)
            self.log("Dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.error(f"Failed to install dependencies: {e}")
            return False
    
    def install_package(self, pip_executable: str) -> bool:
        """Install the antivirus package"""
        try:
            self.log("Installing Prashant918 Advanced Antivirus...")
            
            # Install in editable mode for development
            subprocess.run([
                pip_executable, "install", "-e", "."
            ], check=True, cwd=self.project_root)
            
            self.log("Package installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.error(f"Failed to install package: {e}")
            return False
    
    def setup_directories(self) -> bool:
        """Set up necessary directories"""
        try:
            self.log("Setting up directories...")
            
            home_dir = Path.home()
            antivirus_dir = home_dir / ".prashant918_antivirus"
            
            directories = [
                antivirus_dir,
                antivirus_dir / "logs",
                antivirus_dir / "quarantine",
                antivirus_dir / "signatures", 
                antivirus_dir / "config",
                antivirus_dir / "models",
                antivirus_dir / "temp",
                antivirus_dir / "data"
            ]
            
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
                
                # Set secure permissions on Unix-like systems
                if hasattr(os, 'chmod') and self.platform != "windows":
                    try:
                        os.chmod(directory, 0o700)
                    except (OSError, PermissionError):
                        self.log(f"Could not set permissions for {directory}", "WARNING")
            
            self.log(f"Directories created at: {antivirus_dir}")
            return True
            
        except Exception as e:
            self.error(f"Failed to setup directories: {e}")
            return False
    
    def test_installation(self, python_executable: str) -> bool:
        """Test the installation"""
        try:
            self.log("Testing installation...")
            
            # Test import
            test_script = """
import sys
try:
    import prashant918_antivirus
    print(f"SUCCESS: Package imported successfully")
    print(f"Version: {prashant918_antivirus.__version__}")
    sys.exit(0)
except ImportError as e:
    print(f"ERROR: Failed to import package: {e}")
    sys.exit(1)
"""
            
            result = subprocess.run([
                python_executable, "-c", test_script
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Installation test passed")
                self.log(result.stdout.strip())
                return True
            else:
                self.error(f"Installation test failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.error(f"Failed to test installation: {e}")
            return False
    
    def create_activation_script(self, venv_path: Path) -> bool:
        """Create activation script for the virtual environment"""
        try:
            if self.platform == "windows":
                script_name = "activate_antivirus.bat"
                script_content = f"""@echo off
call "{venv_path}\\Scripts\\activate.bat"
echo Prashant918 Advanced Antivirus environment activated
echo Use 'prashant918-antivirus --help' to get started
"""
            else:
                script_name = "activate_antivirus.sh"
                script_content = f"""#!/bin/bash
source "{venv_path}/bin/activate"
echo "Prashant918 Advanced Antivirus environment activated"
echo "Use 'prashant918-antivirus --help' to get started"
"""
            
            script_path = self.project_root / script_name
            with open(script_path, "w") as f:
                f.write(script_content)
            
            # Make executable on Unix-like systems
            if self.platform != "windows":
                os.chmod(script_path, 0o755)
            
            self.log(f"Activation script created: {script_path}")
            return True
            
        except Exception as e:
            self.error(f"Failed to create activation script: {e}")
            return False
    
    def install(self, use_venv: bool = True) -> bool:
        """Main installation process"""
        self.log("Starting Prashant918 Advanced Antivirus installation...")
        
        # Check prerequisites
        if not self.check_prerequisites():
            return False
        
        if use_venv:
            # Create virtual environment
            venv_path = self.project_root / "antivirus_env"
            if not self.create_virtual_environment(venv_path):
                self.log("Falling back to system Python installation", "WARNING")
                use_venv = False
        
        # Determine Python and pip executables
        if use_venv:
            python_executable = self.get_venv_python(venv_path)
            pip_executable = self.get_venv_pip(venv_path)
        else:
            python_executable = sys.executable
            pip_executable = sys.executable + " -m pip"
        
        # Upgrade pip
        if not self.upgrade_pip(pip_executable):
            return False
        
        # Install dependencies
        if not self.install_dependencies(pip_executable):
            return False
        
        # Install package
        if not self.install_package(pip_executable):
            return False
        
        # Setup directories
        if not self.setup_directories():
            return False
        
        # Test installation
        if not self.test_installation(python_executable):
            return False
        
        # Create activation script if using venv
        if use_venv:
            self.create_activation_script(venv_path)
        
        self.log("Installation completed successfully!")
        self.print_success_message(use_venv)
        
        return True
    
    def print_success_message(self, use_venv: bool):
        """Print success message with usage instructions"""
        print("\n" + "="*60)
        print("🎉 Prashant918 Advanced Antivirus installed successfully!")
        print("="*60)
        
        if use_venv:
            if self.platform == "windows":
                print("To activate the environment, run:")
                print("  .\\activate_antivirus.bat")
            else:
                print("To activate the environment, run:")
                print("  source ./activate_antivirus.sh")
        
        print("\nAvailable commands:")
        print("  prashant918-antivirus --help    # Show help")
        print("  prashant918-antivirus scan <path>  # Scan files")
        print("  prashant918-av-gui              # Launch GUI")
        print("  prashant918-av-service install  # Install service")
        
        print("\nFor more information, visit:")
        print("  https://github.com/prashant918/advanced-antivirus")
        print("="*60)

def main():
    """Main installer entry point"""
    installer = AntivirusInstaller()
    
    # Parse command line arguments
    use_venv = "--no-venv" not in sys.argv
    
    try:
        success = installer.install(use_venv=use_venv)
        
        if not success:
            print("\n❌ Installation failed!")
            print("Errors encountered:")
            for error in installer.errors:
                print(f"  - {error}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️  Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error during installation: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
