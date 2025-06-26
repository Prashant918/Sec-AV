#!/usr/bin/env python3
"""
Advanced Cybersecurity Software - Setup Configuration
Enterprise-grade antivirus and threat detection system
"""

import os
import sys
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext
from setuptools.command.install import install
from setuptools.command.develop import develop
from distutils.version import LooseVersion
import subprocess
import platform

# Minimum Python version check
if sys.version_info < (3, 9):
    raise RuntimeError("This package requires Python 3.9 or later")

# Package metadata
PACKAGE_NAME = "prashant918-advanced-antivirus"
VERSION = "2.0.0"
DESCRIPTION = "Advanced Enterprise Cybersecurity and Threat Detection System"
LONG_DESCRIPTION = """
Prashant918 Advanced Antivirus is a comprehensive cybersecurity solution that provides:

- Multi-layered threat detection using AI/ML, signatures, and heuristics
- Real-time monitoring and behavioral analysis
- Advanced malware detection with YARA rules
- Oracle database backend for enterprise scalability
- Encrypted quarantine and secure logging
- Cloud threat intelligence integration
- Network traffic analysis and monitoring
- Memory scanning and rootkit detection
- Automated threat response and remediation

Features:
- Machine Learning ensemble models for zero-day detection
- Advanced static and dynamic analysis
- Behavioral pattern recognition
- Fuzzy hashing and similarity detection
- Enterprise-grade Oracle database integration
- Secure configuration management with encryption
- Comprehensive audit logging and compliance reporting
- Real-time threat intelligence feeds
- Automated signature updates
- Cross-platform compatibility (Windows, Linux, macOS)

This software is designed for enterprise environments requiring robust
cybersecurity protection with advanced threat detection capabilities.
"""

AUTHOR = "Prashant918 Security Team"
AUTHOR_EMAIL = "security@prashant918.com"
URL = "https://github.com/prashant918/advanced-antivirus"
LICENSE = "Proprietary"

# Platform-specific dependencies
WINDOWS_DEPS = [
    "pywin32>=306; sys_platform == 'win32'",
    "wmi>=1.5.1; sys_platform == 'win32'",
    "python-registry>=1.4; sys_platform == 'win32'",
    "python-evtx>=0.8.1; sys_platform == 'win32'",
    "win10toast>=0.9; sys_platform == 'win32'",
]

LINUX_DEPS = [
    "python-prctl>=1.8.1; sys_platform == 'linux'",
]

MACOS_DEPS = [
    "pyobjc>=9.2; sys_platform == 'darwin'",
]

# Core dependencies
CORE_DEPS = [
    # Database and ORM
    "cx_Oracle>=8.3.0",
    "oracledb>=1.4.2",
    "sqlalchemy>=2.0.0",
    "alembic>=1.12.0",
    "sqlalchemy-pool>=1.3.0",
    
    # Security and Cryptography
    "cryptography>=41.0.0",
    "bcrypt>=4.0.1",
    "passlib>=1.7.4",
    "pyjwt>=2.8.0",
    "oauthlib>=3.2.2",
    
    # HTTP and Networking
    "requests>=2.31.0",
    "certifi>=2023.7.22",
    "charset-normalizer>=3.2.0",
    "idna>=3.4",
    "urllib3>=2.0.4",
    "aiohttp>=3.8.5",
    
    # System and Process Monitoring
    "psutil>=5.9.0",
    "py-cpuinfo>=9.0.0",
    
    # Machine Learning and AI
    "numpy>=1.24.0",
    "pandas>=2.0.0",
    "scikit-learn>=1.3.0",
    "tensorflow>=2.13.0",
    "joblib>=1.3.0",
    "scipy>=1.11.0",
    
    # Security Analysis Tools
    "yara-python>=4.3.1",
    "python-magic>=0.4.27",
    "pefile>=2023.2.7",
    "ssdeep>=3.4",
    "tlsh>=4.5.0",
    
    # Date and Time
    "python-dateutil>=2.8.2",
    "pytz>=2023.3",
    "tzdata>=2023.3",
    
    # Compatibility
    "six>=1.16.0",
    
    # CLI and UI
    "termcolor>=2.3.0",
    "pyfiglet>=0.8.0",
    "colorama>=0.4.6",
    "rich>=13.5.2",
    "click>=8.1.7",
    "tqdm>=4.66.1",
    
    # Configuration and Validation
    "pydantic>=2.3.0",
    "pyyaml>=6.0.1",
    "validators>=0.22.0",
    
    # Logging and Monitoring
    "colorlog>=6.7.0",
    
    # File Processing
    "pathlib2>=2.3.7",
    "watchdog>=3.0.0",
    
    # Compression and Archives
    "py7zr>=0.20.6",
    
    # Network Security
    "scapy>=2.5.0",
    "dpkt>=1.9.8",
    
    # Additional Security Tools
    "volatility3>=2.4.1",
    "binwalk>=2.3.4",
]

# Optional dependencies for enhanced features
OPTIONAL_DEPS = {
    'advanced_ml': [
        "torch>=2.0.0",
        "transformers>=4.33.2",
        "xgboost>=1.7.0",
        "lightgbm>=4.0.0",
    ],
    'cloud': [
        "boto3>=1.28.57",
        "azure-storage-blob>=12.17.0",
        "google-cloud-storage>=2.10.0",
    ],
    'monitoring': [
        "prometheus-client>=0.17.1",
        "statsd>=4.0.1",
        "datadog>=0.47.0",
    ],
    'forensics': [
        "volatility>=2.6.1",
        "rekall>=1.7.2",
        "autopsy>=4.19.0",
    ],
    'reverse_engineering': [
        "radare2-r2pipe>=1.8.0",
        "angr>=9.2.70",
        "capstone>=5.0.1",
        "keystone-engine>=0.9.2",
    ],
    'web': [
        "flask>=2.3.3",
        "fastapi>=0.103.0",
        "uvicorn>=0.23.2",
        "jinja2>=3.1.2",
    ],
    'reporting': [
        "reportlab>=4.0.4",
        "matplotlib>=3.7.2",
        "seaborn>=0.12.2",
        "plotly>=5.15.0",
    ]
}

# Development dependencies
DEV_DEPS = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-asyncio>=0.21.0",
    "black>=23.7.0",
    "flake8>=6.0.0",
    "mypy>=1.5.0",
    "pre-commit>=3.4.0",
    "bandit>=1.7.5",
    "safety>=2.3.5",
    "sphinx>=7.2.0",
    "sphinx-rtd-theme>=1.3.0",
]

# All dependencies combined
ALL_DEPS = CORE_DEPS + WINDOWS_DEPS + LINUX_DEPS + MACOS_DEPS

# Flatten optional dependencies
for deps in OPTIONAL_DEPS.values():
    ALL_DEPS.extend(deps)

class CustomBuildExt(build_ext):
    """Custom build extension to handle platform-specific compilation"""
    
    def build_extensions(self):
        # Platform-specific compilation flags
        if platform.system() == "Windows":
            for ext in self.extensions:
                ext.extra_compile_args = ['/O2', '/W3']
        else:
            for ext in self.extensions:
                ext.extra_compile_args = ['-O3', '-Wall', '-Wextra']
        
        super().build_extensions()

class PostInstallCommand(install):
    """Post-installation setup"""
    
    def run(self):
        install.run(self)
        self.execute(self._post_install, [], msg="Running post-install setup")
    
    def _post_install(self):
        """Post-installation tasks"""
        print("Setting up Prashant918 Advanced Antivirus...")
        
        # Create necessary directories
        directories = [
            "data",
            "data/yara_rules",
            "logs",
            "config",
            "quarantine",
            "models",
            "signatures"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            print(f"Created directory: {directory}")
        
        # Set permissions on Unix-like systems
        if os.name != 'nt':
            for directory in ["logs", "config", "quarantine"]:
                if os.path.exists(directory):
                    os.chmod(directory, 0o700)
        
        print("Post-installation setup completed successfully!")

class PostDevelopCommand(develop):
    """Post-development setup"""
    
    def run(self):
        develop.run(self)
        self.execute(self._post_develop, [], msg="Running post-develop setup")
    
    def _post_develop(self):
        """Post-development tasks"""
        print("Setting up development environment...")
        
        # Install pre-commit hooks
        try:
            subprocess.check_call(["pre-commit", "install"])
            print("Pre-commit hooks installed successfully!")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("Warning: Could not install pre-commit hooks")
        
        print("Development environment setup completed!")

# C Extensions for performance-critical components
extensions = [
    Extension(
        "prashant918_antivirus.core.fast_scanner",
        sources=["src/extensions/fast_scanner.c"],
        include_dirs=["src/extensions/include"],
        libraries=["m"] if platform.system() != "Windows" else [],
        extra_compile_args=["-O3"] if platform.system() != "Windows" else ["/O2"],
    ),
    Extension(
        "prashant918_antivirus.core.crypto_utils",
        sources=["src/extensions/crypto_utils.c"],
        include_dirs=["src/extensions/include"],
        libraries=["crypto", "ssl"] if platform.system() != "Windows" else [],
        extra_compile_args=["-O3"] if platform.system() != "Windows" else ["/O2"],
    ),
]

# Entry points for command-line tools
entry_points = {
    'console_scripts': [
        'prashant918-av=prashant918_antivirus.cli:main',
        'prashant918-scan=prashant918_antivirus.scanner:main',
        'prashant918-update=prashant918_antivirus.updater:main',
        'prashant918-config=prashant918_antivirus.config_manager:main',
        'prashant918-quarantine=prashant918_antivirus.quarantine:main',
        'prashant918-monitor=prashant918_antivirus.monitor:main',
    ],
    'gui_scripts': [
        'prashant918-av-gui=prashant918_antivirus.gui:main',
    ]
}

# Package data
package_data = {
    'prashant918_antivirus': [
        'data/*.json',
        'data/*.yaml',
        'data/yara_rules/*.yar',
        'data/yara_rules/*.yara',
        'data/signatures/*.db',
        'config/*.conf',
        'config/*.ini',
        'templates/*.html',
        'templates/*.xml',
        'static/css/*.css',
        'static/js/*.js',
        'static/images/*',
    ]
}

# Classifiers for PyPI
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: System Administrators",
    "Intended Audience :: Information Technology",
    "Topic :: Security",
    "Topic :: System :: Monitoring",
    "Topic :: System :: Systems Administration",
    "License :: Other/Proprietary License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: C",
    "Operating System :: OS Independent",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: POSIX :: Linux",
    "Operating System :: MacOS",
    "Environment :: Console",
    "Environment :: No Input/Output (Daemon)",
]

# Keywords for search
keywords = [
    "antivirus", "cybersecurity", "malware", "threat-detection",
    "security", "virus-scanner", "enterprise-security", "ai-security",
    "machine-learning", "behavioral-analysis", "yara", "oracle",
    "real-time-protection", "threat-intelligence", "forensics"
]

def read_file(filename):
    """Read file contents"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return ""

# Setup configuration
setup(
    name=PACKAGE_NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    url=URL,
    license=LICENSE,
    
    # Package discovery
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data=package_data,
    include_package_data=True,
    
    # Dependencies
    install_requires=CORE_DEPS + WINDOWS_DEPS + LINUX_DEPS + MACOS_DEPS,
    extras_require=OPTIONAL_DEPS,
    python_requires=">=3.9",
    
    # Entry points
    entry_points=entry_points,
    
    # C Extensions
    ext_modules=extensions,
    cmdclass={
        'build_ext': CustomBuildExt,
        'install': PostInstallCommand,
        'develop': PostDevelopCommand,
    },
    
    # Metadata
    classifiers=classifiers,
    keywords=keywords,
    project_urls={
        "Documentation": "https://docs.prashant918.com/antivirus",
        "Source": "https://github.com/prashant918/advanced-antivirus",
        "Tracker": "https://github.com/prashant918/advanced-antivirus/issues",
        "Changelog": "https://github.com/prashant918/advanced-antivirus/blob/main/CHANGELOG.md",
    },
    
    # Additional metadata
    zip_safe=False,
    platforms=["any"],
    
    # Testing
    test_suite="tests",
    tests_require=DEV_DEPS,
)
