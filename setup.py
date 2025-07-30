#!/usr/bin/env python3
"""
Setup script for Prashant918 Advanced Antivirus
Optimized installation with automatic dependency management
"""

import os
import sys
import shutil
from pathlib import Path
from setuptools import setup, find_packages, Command

# Ensure minimum Python version
if sys.version_info < (3, 8):
    print("Error: Python 3.8 or higher is required")
    sys.exit(1)

# Get the long description from README
here = Path(__file__).parent.absolute()
long_description = ""
readme_path = here / "README.md"
if readme_path.exists():
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()

# Version information
version = "1.0.2"


class CleanCommand(Command):
    """Custom clean command to remove build artifacts"""
    
    description = "Clean build artifacts and temporary files"
    user_options = []
    
    def initialize_options(self):
        pass
    
    def finalize_options(self):
        pass
    
    def run(self):
        """Clean build artifacts"""
        artifacts = [
            "build",
            "dist", 
            "*.egg-info",
            "__pycache__",
            "*.pyc",
            "*.pyo",
            ".pytest_cache",
            ".mypy_cache",
            ".coverage",
            "htmlcov"
        ]
        
        for pattern in artifacts:
            for path in Path(".").glob(pattern):
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                    print(f"Removed directory: {path}")
                else:
                    path.unlink(missing_ok=True)
                    print(f"Removed file: {path}")


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


# Setup configuration
setup(
    name="prashant918-advanced-antivirus",
    version=version,
    author="Prashant918",
    author_email="prashant918@example.com",
    description="Advanced AI-powered antivirus system with behavioral analysis and cloud intelligence",
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
    ],
    python_requires=">=3.8",
    install_requires=[
        "psutil>=5.8.0,<6.0.0",
        "requests>=2.25.0,<3.0.0",
        "cryptography>=40.0.0,<43.0.0",
        "Pillow>=10.0.0,<11.0.0",
        "Flask>=3.0.0,<4.0.0",
        "Flask-CORS>=4.0.0,<5.0.0",
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
            "scikit-learn>=1.3.0,<1.5.0",
            "pandas>=2.0.0,<2.3.0",
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
            "scikit-learn>=1.3.0,<1.5.0",
            "pandas>=2.0.0,<2.3.0",
            "scapy>=2.4.5,<3.0.0",
            "yara-python>=4.2.0,<5.0.0",
            "cx_Oracle>=8.0.0,<9.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "prashant918-antivirus=prashant918_antivirus.cli:main",
            "p918av=prashant918_antivirus.cli:main",
            "prashant918-av-gui=prashant918_antivirus.gui.main_window:main",
            "prashant918-av-service=prashant918_antivirus.service.service_manager:main",
        ],
    },
    include_package_data=True,
    package_data={
        "prashant918_antivirus": [
            "data/*.json",
            "data/*.yaml",
            "config/*.yar",
            "models/*.pkl",
            "models/*.h5",
        ],
    },
    cmdclass={
        "clean": CleanCommand,
        "install": PostInstallCommand,
    },
    zip_safe=False,
)