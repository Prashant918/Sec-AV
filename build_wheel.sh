#!/bin/bash

# Prashant918 Advanced Antivirus - Wheel Build Script
# This script builds a comprehensive wheel package with all dependencies

set -e  # Exit on any error

echo "🔧 Building Prashant918 Advanced Antivirus Wheel Package..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Python version
print_status "Checking Python version..."
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
required_version="3.9.0"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    print_error "Python 3.9+ required. Current version: $python_version"
    exit 1
fi

print_success "Python version check passed: $python_version"

# Create virtual environment
print_status "Creating virtual environment..."
if [ -d "venv" ]; then
    print_warning "Virtual environment already exists. Removing..."
    rm -rf venv
fi

python3 -m venv venv
source venv/bin/activate

print_success "Virtual environment created and activated"

# Upgrade pip and install build tools
print_status "Upgrading pip and installing build tools..."
pip install --upgrade pip
pip install --upgrade setuptools wheel build twine

# Install build dependencies
print_status "Installing build dependencies..."
pip install -r requirements.txt

# Clean previous builds
print_status "Cleaning previous builds..."
rm -rf build/
rm -rf dist/
rm -rf *.egg-info/
rm -rf src/*.egg-info/

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p data/yara_rules
mkdir -p config
mkdir -p logs
mkdir -p quarantine
mkdir -p models
mkdir -p signatures
mkdir -p temp

# Copy default configuration files
print_status "Setting up default configuration..."
cat > config/default.conf << 'EOF'
[database]
host = localhost
port = 1521
service_name = XEPDB1
username = antivirus_user
password = SecurePassword123!

[security]
max_file_size = 104857600
quarantine_encryption = true
secure_delete = true

[detection]
ml_threshold = 0.85
heuristic_enabled = true
behavioral_analysis = true

[logging]
level = INFO
encrypted_logs = true
max_log_size = 52428800
EOF

# Create sample YARA rules
print_status "Creating sample YARA rules..."
cat > data/yara_rules/sample.yar << 'EOF'
rule Sample_Malware_Detection
{
    meta:
        description = "Sample malware detection rule"
        author = "Prashant918 Security Team"
        date = "2024-01-01"
    
    strings:
        $s1 = "malware" nocase
        $s2 = "virus" nocase
        $s3 = "trojan" nocase
    
    condition:
        any of them
}
EOF

# Build source distribution
print_status "Building source distribution..."
python -m build --sdist

# Build wheel
print_status "Building wheel distribution..."
python -m build --wheel

# Verify wheel
print_status "Verifying wheel..."
wheel_file=$(ls dist/*.whl | head -n1)
if [ -f "$wheel_file" ]; then
    print_success "Wheel built successfully: $wheel_file"
    
    # Check wheel contents
    print_status "Checking wheel contents..."
    python -m zipfile -l "$wheel_file"
    
    # Install wheel in test environment
    print_status "Testing wheel installation..."
    pip install "$wheel_file"
    
    # Test import
    print_status "Testing package import..."
    python -c "import prashant918_antivirus; print('Package imported successfully')"
    
    print_success "Wheel verification completed successfully!"
else
    print_error "Wheel build failed!"
    exit 1
fi

# Create installation script
print_status "Creating installation script..."
cat > install_package.sh << 'EOF'
#!/bin/bash

# Prashant918 Advanced Antivirus Installation Script

echo "Installing Prashant918 Advanced Antivirus..."

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
required_version="3.9.0"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.9+ required. Current version: $python_version"
    exit 1
fi

# Install wheel
wheel_file=$(ls dist/*.whl | head -n1)
if [ -f "$wheel_file" ]; then

if [ -f "$wheel_file" ]; then
    echo "Installing wheel: $wheel_file"
    pip install "$wheel_file"
    
    # Verify installation
    echo "Verifying installation..."
    python3 -c "import prashant918_antivirus; print(f'Successfully installed Prashant918 Advanced Antivirus v{prashant918_antivirus.__version__}')"
    
    echo "Installation completed successfully!"
    echo ""
    echo "Usage:"
    echo "  prashant918-av --help                 # Show help"
    echo "  prashant918-av scan /path/to/scan     # Scan files"
    echo "  prashant918-av update                 # Update signatures"
    echo "  prashant918-av info --show-system     # Show system info"
    echo ""
else
    echo "Error: Wheel file not found in dist/ directory"
    exit 1
fi
EOF

chmod +x install_package.sh

# Create requirements bundle
print_status "Creating requirements bundle..."
pip freeze > requirements_frozen.txt

# Create distribution package
print_status "Creating distribution package..."
dist_name="prashant918-advanced-antivirus-${python_version}-$(date +%Y%m%d)"
mkdir -p "packages/$dist_name"

# Copy files to distribution
cp dist/*.whl "packages/$dist_name/"
cp dist/*.tar.gz "packages/$dist_name/"
cp requirements.txt "packages/$dist_name/"
cp requirements_frozen.txt "packages/$dist_name/"
cp install_package.sh "packages/$dist_name/"
cp README.md "packages/$dist_name/" 2>/dev/null || echo "README.md not found, skipping..."

# Create distribution info
cat > "packages/$dist_name/DISTRIBUTION_INFO.txt" << EOF
Prashant918 Advanced Antivirus Distribution Package
==================================================

Build Date: $(date)
Python Version: $python_version
Platform: $(uname -s) $(uname -m)
Builder: $(whoami)@$(hostname)

Contents:
- Wheel package (.whl)
- Source distribution (.tar.gz)
- Requirements files
- Installation script
- Documentation

Installation:
1. Run: chmod +x install_package.sh
2. Run: ./install_package.sh

Or manually:
pip install *.whl

System Requirements:
- Python 3.9+
- Oracle Database (for enterprise features)
- 4GB+ RAM recommended
- 1GB+ disk space

For support: security@prashant918.com
EOF

# Create archive
print_status "Creating distribution archive..."
cd packages
tar -czf "${dist_name}.tar.gz" "$dist_name"
cd ..

print_success "Distribution package created: packages/${dist_name}.tar.gz"

# Generate checksums
print_status "Generating checksums..."
cd packages
sha256sum "${dist_name}.tar.gz" > "${dist_name}.sha256"
md5sum "${dist_name}.tar.gz" > "${dist_name}.md5"
cd ..

# Create deployment script
print_status "Creating deployment script..."
cat > deploy_package.sh << 'EOF'
#!/bin/bash

# Prashant918 Advanced Antivirus Deployment Script

echo "Deploying Prashant918 Advanced Antivirus..."

# Check if running as root (for system-wide installation)
if [ "$EUID" -eq 0 ]; then
    echo "Running as root - system-wide installation"
    INSTALL_PREFIX="/opt/prashant918-antivirus"
    SERVICE_USER="antivirus"
else
    echo "Running as user - local installation"
    INSTALL_PREFIX="$HOME/.local/prashant918-antivirus"
fi

# Create installation directory
mkdir -p "$INSTALL_PREFIX"

# Extract package
latest_package=$(ls packages/*.tar.gz | sort -V | tail -n1)
if [ -f "$latest_package" ]; then
    echo "Extracting: $latest_package"
    tar -xzf "$latest_package" -C "$INSTALL_PREFIX" --strip-components=1
else
    echo "Error: No package found"
    exit 1
fi

# Install package
cd "$INSTALL_PREFIX"
chmod +x install_package.sh
./install_package.sh

# Create service user (if root)
if [ "$EUID" -eq 0 ]; then
    if ! id "$SERVICE_USER" &>/dev/null; then
        echo "Creating service user: $SERVICE_USER"
        useradd -r -s /bin/false -d "$INSTALL_PREFIX" "$SERVICE_USER"
    fi
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_PREFIX"
    chmod 750 "$INSTALL_PREFIX"
fi

# Create systemd service (if root and systemd available)
if [ "$EUID" -eq 0 ] && command -v systemctl &> /dev/null; then
    echo "Creating systemd service..."
    cat > /etc/systemd/system/prashant918-antivirus.service << EOSERVICE
[Unit]
Description=Prashant918 Advanced Antivirus Service
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_PREFIX
ExecStart=/usr/local/bin/prashant918-av monitor --start
ExecStop=/usr/local/bin/prashant918-av monitor --stop
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOSERVICE

    systemctl daemon-reload
    systemctl enable prashant918-antivirus
    echo "Service created and enabled"
fi

echo "Deployment completed successfully!"
echo "Installation location: $INSTALL_PREFIX"

if [ "$EUID" -eq 0 ]; then
    echo "Start service: systemctl start prashant918-antivirus"
    echo "Check status: systemctl status prashant918-antivirus"
fi
EOF

chmod +x deploy_package.sh

# Create uninstall script
print_status "Creating uninstall script..."
cat > uninstall_package.sh << 'EOF'
#!/bin/bash

# Prashant918 Advanced Antivirus Uninstall Script

echo "Uninstalling Prashant918 Advanced Antivirus..."

# Stop service if running
if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet prashant918-antivirus; then
        echo "Stopping service..."
        systemctl stop prashant918-antivirus
    fi
    
    if systemctl is-enabled --quiet prashant918-antivirus; then
        echo "Disabling service..."
        systemctl disable prashant918-antivirus
    fi
    
    if [ -f /etc/systemd/system/prashant918-antivirus.service ]; then
        echo "Removing service file..."
        rm /etc/systemd/system/prashant918-antivirus.service
        systemctl daemon-reload
    fi
fi

# Uninstall Python package
echo "Uninstalling Python package..."
pip uninstall -y prashant918-advanced-antivirus

# Remove installation directory (if exists)
if [ "$EUID" -eq 0 ]; then
    INSTALL_PREFIX="/opt/prashant918-antivirus"
else
    INSTALL_PREFIX="$HOME/.local/prashant918-antivirus"
fi

if [ -d "$INSTALL_PREFIX" ]; then
    echo "Removing installation directory: $INSTALL_PREFIX"
    rm -rf "$INSTALL_PREFIX"
fi

# Remove service user (if root)
if [ "$EUID" -eq 0 ]; then
    if id "antivirus" &>/dev/null; then
        echo "Removing service user..."
        userdel antivirus
    fi
fi

echo "Uninstallation completed!"
EOF

chmod +x uninstall_package.sh

# Create comprehensive test script
print_status "Creating test script..."
cat > test_package.sh << 'EOF'
#!/bin/bash

# Prashant918 Advanced Antivirus Test Script

echo "Testing Prashant918 Advanced Antivirus Package..."

# Test basic import
echo "Testing package import..."
python3 -c "
import prashant918_antivirus
print(f'✅ Package version: {prashant918_antivirus.__version__}')
print(f'✅ Author: {prashant918_antivirus.__author__}')
"

# Test CLI commands
echo "Testing CLI commands..."

echo "  Testing help command..."
prashant918-av --help > /dev/null && echo "  ✅ Help command works"

echo "  Testing info command..."
prashant918-av info --show-system > /dev/null && echo "  ✅ Info command works"

echo "  Testing dependency check..."
prashant918-av info --show-deps > /dev/null && echo "  ✅ Dependency check works"

# Test core functionality
echo "Testing core functionality..."

echo "  Testing configuration..."
python3 -c "
try:
    from prashant918_antivirus.core.config import SecureConfig
    config = SecureConfig()
    print('  ✅ Configuration system works')
except Exception as e:
    print(f'  ❌ Configuration test failed: {e}')
"

echo "  Testing utilities..."
python3 -c "
try:
    from prashant918_antivirus.utils import get_system_info, check_dependencies
    info = get_system_info()
    deps = check_dependencies()
    print('  ✅ Utilities work')
except Exception as e:
    print(f'  ❌ Utilities test failed: {e}')
"

# Create test file for scanning
echo "Creating test file for scanning..."
echo "This is a test file for antivirus scanning" > test_file.txt

echo "  Testing file scanning..."
prashant918-av scan test_file.txt --format json > /dev/null && echo "  ✅ File scanning works"

# Cleanup
rm -f test_file.txt

echo "Package testing completed!"
EOF

chmod +x test_package.sh

# Run tests
print_status "Running package tests..."
./test_package.sh

# Create documentation
print_status "Creating documentation..."
cat > PACKAGE_README.md << 'EOF'
# Prashant918 Advanced Antivirus - Distribution Package

## Overview

This package contains the complete Prashant918 Advanced Antivirus solution, an enterprise-grade cybersecurity platform with advanced threat detection capabilities.

## Features

- 🛡️ Multi-layered threat detection (AI/ML, signatures, heuristics)
- 🤖 Machine learning ensemble models for zero-day detection
- 🔍 Real-time file system monitoring
- 🏢 Enterprise Oracle database backend
- 🔐 Encrypted quarantine and secure logging
- 🌐 Cloud threat intelligence integration
- 📊 Comprehensive reporting and analytics

## System Requirements

- **Operating System**: Windows 10+, Linux (Ubuntu 18.04+), macOS 10.15+
- **Python**: 3.9 or later
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 1GB free disk space
- **Database**: Oracle Database 19c+ (for enterprise features)

## Installation

### Quick Installation

```bash
# Extract the package
tar -xzf prashant918-advanced-antivirus-*.tar.gz
cd prashant918-advanced-antivirus-*

# Run installation script
chmod +x install_package.sh
./install_package.sh
