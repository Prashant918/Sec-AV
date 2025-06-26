# Prashant918 Advanced Antivirus - Installation Guide

## Overview

This guide provides comprehensive instructions for installing and deploying Prashant918 Advanced Antivirus across different platforms and environments.

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10+, Linux (Ubuntu 18.04+), macOS 10.15+
- **Python**: 3.9 or later
- **Memory**: 4GB RAM
- **Storage**: 1GB free disk space
- **Network**: Internet connection for updates

### Recommended Requirements
- **Memory**: 8GB+ RAM
- **Storage**: 5GB+ free disk space
- **Database**: Oracle Database 19c+ (for enterprise features)
- **CPU**: Multi-core processor for optimal performance

## Installation Methods

### Method 1: Wheel Package Installation (Recommended)

#### Linux/macOS

# Download and extract the distribution package
tar -xzf prashant918-advanced-antivirus-*.tar.gz
cd prashant918-advanced-antivirus-*

# Run the installation script
chmod +x install_package.sh
./install_package.sh

# Verify installation
prashant918-av --version


#### Windows

# Extract the distribution package
# Double-click the .zip file or use:
powershell Expand-Archive prashant918-advanced-antivirus-*.zip

# Navigate to extracted folder
cd prashant918-advanced-antivirus-*

# Run installation script
install_package.bat

# Verify installation
prashant918-av --version


### Method 2: Manual Installation

#### Prerequisites

# Install Python 3.9+ if not already installed
# Ubuntu/Debian
sudo apt update
sudo apt install python3.9 python3.9-pip python3.9-venv

# CentOS/RHEL
sudo yum install python39 python39-pip

# macOS (using Homebrew)
brew install python@3.9

# Windows: Download from python.org


#### Install from Wheel

# Create virtual environment (recommended)
python3 -m venv antivirus-env
source antivirus-env/bin/activate  # Linux/macOS
# OR
antivirus-env\Scripts\activate.bat  # Windows

# Install the wheel package
pip install prashant918_advanced_antivirus-*.whl

# Verify installation
python -c "import prashant918_antivirus; print('Installation successful')"


### Method 3: Development Installation

#### From Source

# Clone the repository
git clone https://github.com/prashant918/advanced-antivirus.git
cd advanced-antivirus

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate.bat  # Windows

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt


#### Build from Source

# Install build tools
pip install build wheel

# Build the package
python -m build

# Install the built wheel
pip install dist/*.whl


## Database Setup (Enterprise Features)

### Oracle Database Configuration

#### 1. Install Oracle Database

# Download Oracle Database 19c or later
# Follow Oracle's installation guide for your platform


#### 2. Create Database User

-- Connect as SYSDBA
sqlplus / as sysdba

-- Create tablespace
CREATE TABLESPACE antivirus_data
DATAFILE 'antivirus_data.dbf' SIZE 1G
AUTOEXTEND ON NEXT 100M MAXSIZE 10G;

-- Create user
CREATE USER antivirus_user IDENTIFIED BY SecurePassword123!
DEFAULT TABLESPACE antivirus_data
TEMPORARY TABLESPACE temp;

-- Grant privileges
GRANT CONNECT, RESOURCE TO antivirus_user;
GRANT CREATE SESSION TO antivirus_user;
GRANT CREATE TABLE TO antivirus_user;
GRANT CREATE SEQUENCE TO antivirus_user;
GRANT CREATE TRIGGER TO antivirus_user;
GRANT UNLIMITED TABLESPACE TO antivirus_user;


#### 3. Configure Connection

# Edit configuration file
nano config/database.conf

# Add database connection details
[database]
host = localhost
port = 1521
service_name = XEPDB1
username = antivirus_user
password = SecurePassword123!
pool_size = 10
max_overflow = 20


### Alternative: SQLite (Development/Testing)

# For development or testing, SQLite can be used
# No additional setup required - database file will be created automatically


## Configuration

### Basic Configuration

# Create configuration directory
mkdir -p ~/.config/prashant918-antivirus

# Copy default configuration
cp config/default.conf ~/.config/prashant918-antivirus/

# Edit configuration
nano ~/.config/prashant918-antivirus/default.conf


### Configuration Options

#### Security Settings

[security]
max_file_size = 104857600  # Maximum file size to scan (100MB)
quarantine_encryption = true  # Encrypt quarantined files
secure_delete = true  # Securely delete threats
anti_tampering = true  # Enable anti-tampering protection


#### Detection Settings

[detection]
ml_threshold = 0.85  # ML detection threshold (0.0-1.0)
heuristic_enabled = true  # Enable heuristic detection
behavioral_analysis = true  # Enable behavioral analysis
zero_day_detection = true  # Enable zero-day detection
signature_updates = true  # Enable automatic signature updates
cloud_intelligence = true  # Enable cloud threat intelligence


#### Monitoring Settings

[monitoring]
real_time_enabled = true  # Enable real-time monitoring
kernel_hooks = true  # Enable kernel-level hooks (Linux/Windows)
process_monitoring = true  # Monitor process activities
network_monitoring = true  # Monitor network activities
file_integrity = true  # Enable file integrity monitoring


#### Logging Settings

[logging]
level = INFO  # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
encrypted_logs = true  # Encrypt log files
audit_trail = true  # Enable audit trail
max_log_size = 52428800  # Maximum log file size (50MB)
log_retention_days = 30  # Log retention period


## Service Installation

### Linux (systemd)

#### Create Service File

sudo nano /etc/systemd/system/prashant918-antivirus.service



[Unit]
Description=Prashant918 Advanced Antivirus Service
After=network.target

[Service]
Type=simple
User=antivirus
Group=antivirus
WorkingDirectory=/opt/prashant918-antivirus
ExecStart=/usr/local/bin/prashant918-av monitor --start
ExecStop=/usr/local/bin/prashant918-av monitor --stop
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/prashant918-antivirus

[Install]
WantedBy=multi-user.target


#### Enable and Start Service

# Create service user
sudo useradd -r -s /bin/false antivirus

# Set permissions
sudo chown -R antivirus:antivirus /opt/prashant918-antivirus

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable prashant918-antivirus
sudo systemctl start prashant918-antivirus

# Check status
sudo systemctl status prashant918-antivirus


### Windows Service

#### Install as Windows Service

# Run as Administrator
prashant918-av service --install

# Start service
net start Prashant918Antivirus

# Set to start automatically
sc config Prashant918Antivirus start= auto


#### Manual Service Creation

# Create service using sc command
sc create Prashant918Antivirus ^
  binPath= "C:\Python39\Scripts\prashant918-av.exe monitor --start" ^
  DisplayName= "Prashant918 Advanced Antivirus" ^
  start= auto

# Start service
sc start Prashant918Antivirus


### macOS (launchd)

#### Create Launch Daemon

sudo nano /Library/LaunchDaemons/com.prashant918.antivirus.plist



<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.prashant918.antivirus</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/prashant918-av</string>
        <string>monitor</string>
        <string>--start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/prashant918-antivirus.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/prashant918-antivirus-error.log</string>
</dict>
</plist>


#### Load and Start Service

# Load service
sudo launchctl load /Library/LaunchDaemons/com.prashant918.antivirus.plist

# Start service
sudo launchctl start com.prashant918.antivirus

# Check status
sudo launchctl list | grep prashant918


## Verification and Testing

### Basic Functionality Test

# Test CLI commands
prashant918-av --help
prashant918-av info --show-system
prashant918-av info --show-deps

# Test scanning
echo "test file content" > test.txt
prashant918-av scan test.txt
rm test.txt


### Service Test

# Linux
sudo systemctl status prashant918-antivirus
sudo journalctl -u prashant918-antivirus -f

# Windows
sc query Prashant918Antivirus
eventvwr.msc  # Check Windows Event Viewer

# macOS
sudo launchctl list | grep prashant918
tail -f /var/log/prashant918-antivirus.log


### Database Connection Test

# Test database connectivity
prashant918-av info --show-config
python -c "
from prashant918_antivirus.core.database import db_manager
print('Database health:', db_manager.health_check())
"


## Troubleshooting

### Common Issues

#### 1. Import Errors

# Check Python path
python -c "import sys; print(sys.path)"

# Reinstall package
pip uninstall prashant918-advanced-antivirus
pip install prashant918_advanced_antivirus-*.whl


#### 2. Database Connection Issues

# Check Oracle client installation
python -c "import cx_Oracle; print(cx_Oracle.version)"

# Test connection manually
sqlplus antivirus_user/SecurePassword123!@localhost:1521/XEPDB1


#### 3. Permission Issues

# Linux/macOS - Fix permissions
sudo chown -R $USER:$USER ~/.config/prashant918-antivirus
chmod 755 ~/.config/prashant918-antivirus
chmod 600 ~/.config/prashant918-antivirus/*.conf

# Windows - Run as Administrator
# Right-click Command Prompt -> "Run as administrator"


#### 4. Service Issues

# Linux - Check service logs
sudo journalctl -u prashant918-antivirus --no-pager

# Windows - Check Event Viewer
eventvwr.msc
# Navigate to Windows Logs > Application

# macOS - Check system logs
sudo log show --predicate 'process == "prashant918-av"' --last 1h


### Log Files

#### Default Log Locations
- **Linux**: `/var/log/prashant918-antivirus/` or `~/.local/share/prashant918-antivirus/logs/`
- **Windows**: `%APPDATA%\Prashant918\Antivirus\logs\`
- **macOS**: `~/Library/Logs/Prashant918Antivirus/`

#### Log Types
- `antivirus.log` - Main application log
- `scanner.log` - Scan operation logs
- `monitor.log` - Real-time monitoring logs
- `database.log` - Database operation logs
- `error.log` - Error and exception logs

## Uninstallation

### Complete Removal

#### Linux/macOS

# Stop service
sudo systemctl stop prashant918-antivirus  # Linux
sudo launchctl unload /Library/LaunchDaemons/com.prashant918.antivirus.plist  # macOS

# Remove service files
sudo rm /etc/systemd/system/prashant918-antivirus.service  # Linux
sudo rm /Library/LaunchDaemons/com.prashant918.antivirus.plist  # macOS

# Uninstall package
pip uninstall prashant918-advanced-antivirus

# Remove configuration and data
rm -rf ~/.config/prashant918-antivirus
rm -rf ~/.local/share/prashant918-antivirus
sudo rm -rf /opt/prashant918-antivirus

# Remove service user (Linux)
sudo userdel antivirus


#### Windows

# Stop and remove service
net stop Prashant918Antivirus
sc delete Prashant918Antivirus

# Uninstall package
pip uninstall prashant918-advanced-antivirus

# Remove configuration (run in Command Prompt)
rmdir /s "%APPDATA%\Prashant918"
rmdir /s "%PROGRAMDATA%\Prashant918"


## Support and Resources

### Documentation
- **User Manual**: https://docs.prashant918.com/antivirus/user-guide
- **API Reference**: https://docs.prashant918.com/antivirus/api
- **Configuration Guide**: https://docs.prashant918.com/antivirus/configuration

### Support Channels
- **Email**: security@prashant918.com
- **GitHub Issues**: https://github.com/prashant918/advanced-antivirus/issues
- **Community Forum**: https://community.prashant918.com

### Enterprise Support
- **Professional Services**: enterprise@prashant918.com
- **Training**: training@prashant918.com
- **Custom Development**: development@prashant918.com

---

© 2024 Prashant918 Security Solutions. All rights reserved.


This comprehensive wheel package and installation system provides:

1. **Complete wheel distribution** with all dependencies
2. **Cross-platform build scripts** (Linux/macOS and Windows)
3. **Automated installation and deployment** scripts
4. **Service integration** for all major platforms
5. **Comprehensive documentation** and troubleshooting guides
6. **Enterprise-ready configuration** options
7. **Professional packaging** with checksums and verification

The package is now ready for distribution and can be easily installed across different environments while maintaining security and functionality.
