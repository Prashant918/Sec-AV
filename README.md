# Upcoming Major Cybersecurity Software

**Very Soon: A groundbreaking software release in cybersecurity!**

This project introduces a powerful command-line tool designed to create and detect threats and risks in files or software. It leverages advanced analysis techniques to determine whether a file is harmful or safe.

## Key Features

- **Threat & Risk Detection:** Analyze files or software for potential threats and risks.
- **File Content Analysis:** Determine if a file is harmful or safe using intelligent scanning.
- **Command-Line Only:** The tool is available exclusively for command-line usage, ensuring lightweight and efficient operation for professionals.

## Availability

- The software will be released soon.
- Stay tuned for updates and detailed documentation.

-------------------------------------------------------X=X-------------------------------------------------------

# Prashant918 Advanced Antivirus - Complete Installation, Setup & Usage Guide

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [Post-Installation Setup](#post-installation-setup)
4. [Configuration](#configuration)
5. [Usage Guide](#usage-guide)
6. [Service Management](#service-management)
7. [Troubleshooting](#troubleshooting)
8. [Uninstallation](#uninstallation)

## System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **RAM**: 1GB minimum (2GB recommended)
- **Disk Space**: 500MB free space
- **Internet**: Required for updates and cloud intelligence
- **Operating System**: 
  - Windows 10/11 (x64, x86)
  - Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+)
  - macOS 10.14+ (Intel and Apple Silicon)

### Python Version Check
Before installation, verify your Python version:
```bash
python --version
# or
python3 --version
```

## Installation Methods

### Method 1: Using pip (Recommended)

#### Basic Installation
```bash
pip install prashant918-advanced-antivirus
```

#### Full Installation with All Features
```bash
pip install prashant918-advanced-antivirus[all]
```

#### Feature-Specific Installation
```bash
# Machine Learning features only
pip install prashant918-advanced-antivirus[ml]

# Advanced scanning features
pip install prashant918-advanced-antivirus[advanced]

# Oracle database support
pip install prashant918-advanced-antivirus[oracle]

# Development tools
pip install prashant918-advanced-antivirus[dev]
```

### Method 2: Platform-Specific Installers

The project includes platform-specific installers in the `build_complete_package.sh` script:

#### Windows Installation
1. Download `install_windows.bat` from the installers directory
2. Run as administrator:
```batch
install_windows.bat
```

#### Linux Installation
1. Download `install_linux.sh`
2. Make executable and run:
```bash
chmod +x install_linux.sh
./install_linux.sh
```

#### macOS Installation
1. Download `install_macos.sh`
2. Make executable and run:
```bash
chmod +x install_macos.sh
./install_macos.sh
```

### Method 3: From Source

#### Clone and Install
```bash
git clone https://github.com/prashant918/advanced-antivirus.git
cd advanced-antivirus
pip install -e .[all]
```

#### Using the Universal Installer
The project includes a universal installer (`install.py`) that handles cross-platform installation:

```bash
python install.py
```

**Installer Options:**
- `--no-venv`: Skip virtual environment creation
- Default behavior creates a virtual environment for isolation

## Post-Installation Setup

### Automatic Setup
The `setup.py` includes a `PostInstallCommand` that automatically:

1. **Creates necessary directories** in `~/.prashant918_antivirus/`:
   - `logs/` - Application logs
   - `quarantine/` - Quarantined files
   - `config/` - Configuration files
   - `data/` - Database files
   - `models/` - ML models
   - `temp/` - Temporary files
   - `backups/` - System backups

2. **Sets secure permissions** (Unix-like systems):
   - Directory permissions: `0o700` (owner read/write/execute only)

3. **Initializes configuration** with default values from `config/default_config.json`

4. **Sets up database** (SQLite by default)

### Manual Verification
Verify installation using the test script:
```bash
python test_installation.py
```

This script tests:
- Module imports
- CLI commands
- Core functionality
- Threat detection
- Quarantine system
- Service manager
- Dependencies

## Configuration

### Configuration Files
The antivirus uses `SecureConfig` class from `src/prashant918_antivirus/config.py` for encrypted configuration management.

#### Default Configuration Location
- **Linux/macOS**: `~/.prashant918_antivirus/config/`
- **Windows**: `%USERPROFILE%\.prashant918_antivirus\config\`

#### Configuration Files Structure
- `secure_config.enc` - Encrypted main configuration
- `config.key` - Encryption key
- `config.salt` - Encryption salt
- `config_backup.enc` - Configuration backup

#### Key Configuration Sections

**Security Settings:**
```json
{
  "security": {
    "max_file_size": 104857600,
    "quarantine_encryption": true,
    "secure_delete": true
  }
}
```

**Detection Thresholds:**
```json
{
  "detection": {
    "ml_threshold": 0.85,
    "heuristic_threshold": 0.75,
    "behavioral_threshold": 0.80,
    "signature_threshold": 0.90
  }
}
```

**Monitoring Paths:**
```json
{
  "monitoring": {
    "paths": [
      "~/Downloads",
      "~/Desktop", 
      "~/Documents"
    ],
    "real_time_scan": true
  }
}
```

## Usage Guide

### Command Line Interface (CLI)

The antivirus provides several CLI commands defined in `src/prashant918_antivirus/cli.py`:

#### Available Commands
```bash
# Main command
prashant918-antivirus --help

# Short alias
p918av --help
```

#### File Scanning
```bash
# Scan a single file
prashant918-antivirus scan /path/to/file

# Scan a directory
prashant918-antivirus scan /path/to/directory

# Recursive directory scan
prashant918-antivirus scan /path/to/directory --recursive

# Save results to file
prashant918-antivirus scan /path/to/file --output results.json
```

#### System Information
```bash
# Display system and antivirus information
prashant918-antivirus info
```

#### Real-time Monitoring
```bash
# Start real-time monitoring
prashant918-antivirus monitor start

# Stop real-time monitoring
prashant918-antivirus monitor stop

# Check monitoring status
prashant918-antivirus monitor status
```

### Graphical User Interface (GUI)

Launch the GUI application:
```bash
prashant918-av-gui
```

The GUI (`src/prashant918_antivirus/gui/main_window.py`) provides:
- **Scan Tab**: File and directory scanning with progress tracking
- **Protection Tab**: Real-time protection controls
- **Quarantine Tab**: Quarantine management
- **Statistics Tab**: System statistics and threat information
- **Logs Tab**: System logs viewing

### Web Interface

The project includes a comprehensive web interface (`web/index.html`) with:
- **Admin Panel**: Accessible with API keys
- **Debug Console**: Online debugging capabilities
- **System Monitoring**: Real-time status and statistics
- **API Documentation**: Interactive API reference

#### Admin Access
Use one of these API keys for admin access:
- `P918AV_ADMIN_2024_SECURE_KEY_v1.0.2`
- `PRASHANT918_MASTER_ACCESS_TOKEN`
- `ADV_ANTIVIRUS_DEBUG_ACCESS_2024`

### Python API Usage

```python
from prashant918_antivirus import UnifiedThreatEngine, FileScanner

# Initialize threat engine
engine = UnifiedThreatEngine()

# Scan a file
result = engine.scan_file("/path/to/file")
print(f"Threat Level: {result.threat_level}")
print(f"Confidence: {result.confidence}")

# Use file scanner
scanner = FileScanner()
scan_results = scanner.scan_directory("/path/to/directory")
```

## Service Management

### Service Installation and Management

The `ServiceManager` class in `src/prashant918_antivirus/service/service_manager.py` provides cross-platform service management.

#### Install as System Service
```bash
# Install service (requires admin/root privileges)
sudo prashant918-av-service install

# Start service
sudo prashant918-av-service start

# Stop service
sudo prashant918-av-service stop

# Check service status
prashant918-av-service status

# Uninstall service
sudo prashant918-av-service uninstall
```

#### Platform-Specific Service Details

**Windows Service:**
- Service Name: `Prashant918Antivirus`
- Uses Windows Service Framework
- Requires `pywin32` package

**Linux Service (systemd):**
- Service File: `/etc/systemd/system/prashant918antivirus.service`
- User: `antivirus` (created automatically)
- Auto-start enabled

**macOS Service (launchd):**
- Plist File: `/Library/LaunchDaemons/com.prashant918.antivirus.plist`
- Runs at system startup

### Service Features
- **Real-time Monitoring**: Continuous file system monitoring
- **Automatic Updates**: Signature and engine updates
- **Background Maintenance**: Log cleanup and optimization
- **Threat Response**: Automatic quarantine and alerting

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors
**Solution**: Run with administrator/root privileges
```bash
# Linux/macOS
sudo prashant918-av-service install

# Windows (run as administrator)
prashant918-av-service install
```

#### 2. Module Not Found Errors
**Solution**: Ensure all dependencies are installed
```bash
pip install prashant918-advanced-antivirus[all]
```

#### 3. Service Installation Failed
**Causes and Solutions**:
- **Missing dependencies**: Install platform-specific packages
  ```bash
  # Windows
  pip install pywin32
  
  # Linux
  pip install python-systemd
  ```
- **Insufficient privileges**: Run as administrator/root
- **Service already exists**: Uninstall existing service first

#### 4. Database Connection Issues
**Solutions**:
- Check database configuration in `secure_config`
- Verify SQLite file permissions
- For Oracle: Check connection parameters and network connectivity

#### 5. Real-time Monitoring Not Working
**Solutions**:
- Check monitoring configuration in `secure_config`
- Verify file system permissions
- Ensure monitoring paths exist and are accessible

### Diagnostic Commands

```bash
# Test installation
python test_installation.py

# Check system information
prashant918-antivirus info

# Verify service status
prashant918-av-service status

# Check logs
tail -f ~/.prashant918_antivirus/logs/antivirus.log
```

### Getting Help

- **GitHub Issues**: https://github.com/prashant918/advanced-antivirus/issues
- **Email**: prashant918@example.com
- **Documentation**: Check `README.md` and `INSTALLATION_GUIDE.md`

## Uninstallation

### Complete Removal

1. **Stop and uninstall service**:
```bash
sudo prashant918-av-service stop
sudo prashant918-av-service uninstall
```

2. **Remove package**:
```bash
pip uninstall prashant918-advanced-antivirus
```

3. **Remove user data** (optional):
```bash
# Linux/macOS
rm -rf ~/.prashant918_antivirus

# Windows
rmdir /s %USERPROFILE%\.prashant918_antivirus
```

4. **Clean up virtual environment** (if used):
```bash
# Remove virtual environment directory
rm -rf antivirus_env
```

### Selective Removal

**Remove only service**:
```bash
sudo prashant918-av-service uninstall
```

**Keep configuration and data**:
```bash
pip uninstall prashant918-advanced-antivirus
# Keep ~/.prashant918_antivirus directory
```

## Advanced Features

### Automated Upgrade System
The antivirus includes an automated upgrade system (`src/prashant918_antivirus/upgrade/`) with:
- **Auto-upgrader**: Automatic version checking and updates
- **System Adaptation**: Performance adjustment based on device capabilities
- **Rollback Management**: Automatic rollback on failed updates
- **Configuration Migration**: Seamless config updates between versions

### Machine Learning Detection
When installed with ML features:
```bash
pip install prashant918-advanced-antivirus[ml]
```

Provides:
- **Ensemble ML Models**: Multiple algorithms for threat detection
- **Behavioral Analysis**: Pattern recognition for zero-day threats
- **Adaptive Learning**: Continuous improvement based on new threats

### Cloud Intelligence Integration
Configure cloud services in the configuration:
```json
{
  "cloud": {
    "enabled": true,
    "virustotal_api_key": "your_api_key",
    "malwarebazaar_api_key": "your_api_key"
  }
}
```

This comprehensive guide covers all aspects of installation, setup, and usage for the Prashant918 Advanced Antivirus system. The modular architecture allows for flexible deployment scenarios, from basic file scanning to enterprise-grade real-time protection services.