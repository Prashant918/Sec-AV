#!/usr/bin/env python3
"""
Setup script for Prashant918 Advanced Antivirus
Enhanced with GUI support and multiple interface options
"""

import os
import sys
import shutil
from pathlib import Path
from setuptools import setup, find_packages, Command

# Read version
def get_version():
    version_file = Path("src/prashant918_antivirus/__init__.py")
    if version_file.exists():
        with open(version_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip('"\'')
    return "1.0.3"

version = get_version()

# Read README
readme_file = Path("README.md")
long_description = ""
if readme_file.exists():
    with open(readme_file, 'r', encoding='utf-8') as f:
        long_description = f.read()

class CleanCommand(Command):
    """Custom clean command"""
    description = "Clean build artifacts"
    user_options = []
    
    def initialize_options(self):
        pass
    
    def finalize_options(self):
        pass
    
    def run(self):
        """Clean build artifacts"""
        dirs_to_remove = [
            "build", "dist", "*.egg-info", "__pycache__",
            ".pytest_cache", ".mypy_cache", ".coverage", "htmlcov"
        ]
        
        for pattern in dirs_to_remove:
            for path in Path(".").glob(pattern):
                if path.is_dir():
                    shutil.rmtree(path)
                    print(f"Removed directory: {path}")
                elif path.is_file():
                    path.unlink()
                    print(f"Removed file: {path}")
        
        # Remove Python cache files
        for path in Path(".").rglob("*.pyc"):
            path.unlink()
        for path in Path(".").rglob("*.pyo"):
            path.unlink()

class PostInstallCommand(Command):
    """Post-installation setup"""
    description = "Post-installation setup and configuration"
    user_options = []
    
    def initialize_options(self):
        pass
    
    def finalize_options(self):
        pass
    
    def run(self):
        """Run post-installation setup"""
        try:
            self._create_directories()
            self._set_permissions()
            self._create_desktop_shortcuts()
            print("Post-installation setup completed successfully")
        except Exception as e:
            print(f"Warning: Post-installation setup failed: {e}")
    
    def _create_directories(self):
        """Create necessary directories"""
        base_dir = Path.home() / ".prashant918_antivirus"
        directories = [
            base_dir / "logs",
            base_dir / "quarantine", 
            base_dir / "config",
            base_dir / "data",
            base_dir / "models",
            base_dir / "temp",
            base_dir / "backups"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"Created directory: {directory}")
    
    def _set_permissions(self):
        """Set secure permissions on directories"""
        if os.name != 'nt':  # Unix-like systems
            base_dir = Path.home() / ".prashant918_antivirus"
            try:
                os.chmod(base_dir, 0o700)
                for subdir in base_dir.iterdir():
                    if subdir.is_dir():
                        os.chmod(subdir, 0o700)
            except Exception as e:
                print(f"Warning: Could not set permissions: {e}")
    
    def _create_desktop_shortcuts(self):
        """Create desktop shortcuts for GUI"""
        try:
            desktop = Path.home() / "Desktop"
            if desktop.exists() and os.name != 'nt':
                # Create .desktop file for Linux
                desktop_file = desktop / "Prashant918-Antivirus.desktop"
                content = f"""[Desktop Entry]
Name=Prashant918 Advanced Antivirus
Comment=AI-Powered Cybersecurity Platform
Exec={sys.executable} -m prashant918_antivirus.gui.main_window
Icon=security
Terminal=false
Type=Application
Categories=Security;System;
"""
                with open(desktop_file, 'w') as f:
                    f.write(content)
                os.chmod(desktop_file, 0o755)
                print(f"Created desktop shortcut: {desktop_file}")
        except Exception as e:
            print(f"Could not create desktop shortcuts: {e}")

# Setup configuration
setup(
    name="prashant918-advanced-antivirus",
    version=version,
    author="Prashant918",
    author_email="prashant918@example.com",
    description="Advanced AI-powered antivirus system with GUI, CLI, and Web interfaces",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/prashant918/advanced-antivirus",
    project_urls={
        "Bug Reports": "https://github.com/prashant918/advanced-antivirus/issues",
        "Source": "https://github.com/prashant918/advanced-antivirus",
        "Documentation": "https://prashant918-antivirus.readthedocs.io",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", 
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: Utilities",
        "Environment :: X11 Applications",
        "Environment :: Win32 (MS Windows)",
        "Environment :: MacOS X",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.8",
    install_requires=[
        "psutil>=5.8.0,<6.0.0",
        "requests>=2.25.0,<3.0.0",
        "cryptography>=40.0.0,<43.0.0",
        "Pillow>=10.0.0,<11.0.0",
        "Flask>=3.0.0,<4.0.0",
        "Flask-CORS>=4.0.0,<5.0.0",
        "Flask-SocketIO>=5.0.0,<6.0.0",
        "Werkzeug>=3.0.0,<4.0.0",
        "watchdog>=3.0.0,<5.0.0",
        "PyYAML>=6.0.0,<7.0.0",
        "jsonschema>=4.0.0,<5.0.0",
        "colorlog>=6.0.0,<8.0.0",
        "aiofiles>=0.8.0,<1.0.0",
        "aiohttp>=3.8.0,<4.0.0",
        "dnspython>=2.2.0,<3.0.0",
        "urllib3>=2.0.0,<3.0.0",
        "pyfiglet",
        "termcolor",
        "click",
        "rich",
        "packaging",
    ],
    extras_require={
        "ml": [
            "numpy>=1.21.0,<2.0.0",
            "scikit-learn>=1.0.0,<2.0.0",
            "pandas>=1.3.0,<3.0.0",
            "tensorflow>=2.8.0,<3.0.0",
        ],
        "advanced": [
            "scapy>=2.4.5,<3.0.0",
            "yara-python>=4.2.0,<5.0.0",
        ],
        "oracle": [
            "cx_Oracle>=8.0.0,<9.0.0",
        ],
        "dev": [
            "pytest>=7.0.0,<9.0.0",
            "black>=23.0.0,<25.0.0",
            "flake8>=6.0.0,<8.0.0",
            "mypy>=1.0.0,<2.0.0",
        ],
        "all": [
            "numpy>=1.21.0,<2.0.0",
            "scikit-learn>=1.0.0,<2.0.0", 
            "pandas>=1.3.0,<3.0.0",
            "tensorflow>=2.8.0,<3.0.0",
            "scapy>=2.4.5,<3.0.0",
            "yara-python>=4.2.0,<5.0.0",
            "cx_Oracle>=8.0.0,<9.0.0",
            "pytest>=7.0.0,<9.0.0",
            "black>=23.0.0,<25.0.0",
            "flake8>=6.0.0,<8.0.0",
            "mypy>=1.0.0,<2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "prashant918-antivirus=prashant918_antivirus.cli:main",
            "p918av=prashant918_antivirus.cli:main",
            "prashant918-av-gui=prashant918_antivirus.gui.main_window:main",
            "prashant918-av-web=prashant918_antivirus.web.app:main",
            "prashant918-av-service=prashant918_antivirus.service.service_manager:main",
            "prashant918-launcher=prashant918_antivirus.launcher:main",
        ],
        "gui_scripts": [
            "prashant918-antivirus-gui=prashant918_antivirus.gui.main_window:main",
        ],
    },
    package_data={
        "prashant918_antivirus": [
            "config/*.json",
            "config/*.yaml", 
            "yara_rules/*.yar",
            "models/*.pkl",
            "models/*.h5",
            "web/templates/*.html",
            "web/static/css/*.css",
            "web/static/js/*.js",
            "web/static/images/*",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    cmdclass={
        "clean": CleanCommand,
        "install": PostInstallCommand,
    },
)