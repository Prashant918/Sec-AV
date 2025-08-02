#!/usr/bin/env python3
"""
Install optional dependencies for Prashant918 Advanced Antivirus
"""

import subprocess
import sys
import os
from pathlib import Path

def install_package(package_name, description=""):
    """Install a package using pip"""
    try:
        print(f"Installing {package_name}... {description}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(f"✓ {package_name} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install {package_name}: {e}")
        return False

def check_package(package_name):
    """Check if a package is already installed"""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False

def main():
    """Install optional dependencies"""
    print("Prashant918 Advanced Antivirus - Dependency Installer")
    print("=" * 60)
    
    # Core dependencies that should always be installed
    core_packages = [
        ("yara-python", "YARA pattern matching for signature detection"),
        ("tensorflow", "Neural network ML detection"),
        ("scapy", "Network packet analysis"),
        ("numpy", "Numerical computing for ML"),
        ("scikit-learn", "Machine learning algorithms"),
        ("pandas", "Data analysis and manipulation"),
    ]
    
    # Optional dependencies
    optional_packages = [
        ("cx_Oracle", "Oracle database support"),
        ("pytest", "Testing framework"),
        ("black", "Code formatting"),
        ("flake8", "Code linting"),
        ("mypy", "Static type checking"),
    ]
    
    print("Installing core optional dependencies...")
    print("-" * 40)
    
    success_count = 0
    total_count = len(core_packages)
    
    for package, description in core_packages:
        # Check if already installed
        module_name = package.replace("-", "_").replace("_python", "")
        if package == "scikit-learn":
            module_name = "sklearn"
        elif package == "cx_Oracle":
            module_name = "cx_Oracle"
        
        if check_package(module_name):
            print(f"✓ {package} already installed")
            success_count += 1
        else:
            if install_package(package, description):
                success_count += 1
    
    print(f"\nCore dependencies: {success_count}/{total_count} installed successfully")
    
    # Ask about optional dependencies
    print("\nOptional dependencies (for development):")
    print("-" * 40)
    
    install_optional = input("Install optional development dependencies? (y/N): ").lower().startswith('y')
    
    if install_optional:
        for package, description in optional_packages:
            module_name = package.replace("-", "_")
            if not check_package(module_name):
                install_package(package, description)
            else:
                print(f"✓ {package} already installed")
    
    # Create YARA rules directory
    print("\nSetting up YARA rules...")
    yara_dir = Path("yara_rules")
    yara_dir.mkdir(exist_ok=True)
    
    # Create default YARA rules if they don't exist
    malware_rule = yara_dir / "malware_generic.yar"
    if not malware_rule.exists():
        with open(malware_rule, 'w') as f:
            f.write('''rule Generic_Malware_Strings
{
    meta:
        description = "Generic malware string patterns"
        author = "Advanced Antivirus"
    
    strings:
        $s1 = "backdoor" nocase
        $s2 = "keylogger" nocase
        $s3 = "trojan" nocase
        $s4 = "rootkit" nocase
        $s5 = "ransomware" nocase
    
    condition:
        any of them
}''')
        print("✓ Created default YARA rules")
    
    print("\n" + "=" * 60)
    print("Installation complete!")
    print("\nTo verify installation, run:")
    print("  python main.py info")
    print("\nTo start the antivirus:")
    print("  python main.py")

if __name__ == "__main__":
    main()
