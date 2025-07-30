#!/bin/bash

# Prashant918 Advanced Antivirus - Complete Package Builder
# Cross-platform build script with comprehensive error handling

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
PACKAGE_NAME="prashant918-advanced-antivirus"
VERSION="1.0.2"
PYTHON_MIN_VERSION="3.8"
BUILD_DIR="build"
DIST_DIR="dist"
VENV_DIR="build_env"

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Linux*)     PLATFORM=linux;;
        Darwin*)    PLATFORM=macos;;
        CYGWIN*|MINGW*|MSYS*) PLATFORM=windows;;
        *)          PLATFORM=unknown;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64) ARCH=x64;;
        i386|i686)    ARCH=x86;;
        arm64|aarch64) ARCH=arm64;;
        armv7l)       ARCH=armv7;;
        *)            ARCH=unknown;;
    esac
    
    log_info "Detected platform: $PLATFORM-$ARCH"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    log_info "Python version: $PYTHON_VERSION"
    
    # Check if Python version meets minimum requirement
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
        log_error "Python $PYTHON_MIN_VERSION or higher is required"
        exit 1
    fi
    
    # Check for required tools
    local required_tools=("pip" "git")
    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            log_error "$tool is not installed"
            exit 1
        fi
    done
    
    log_success "Prerequisites check passed"
}

# Clean previous builds
clean_build() {
    log_info "Cleaning previous builds..."
    
    # Remove build directories
    rm -rf "$BUILD_DIR" "$DIST_DIR" "$VENV_DIR"
    rm -rf *.egg-info
    rm -rf src/*.egg-info
    
    # Remove Python cache
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    find . -type f -name "*.pyo" -delete 2>/dev/null || true
    
    log_success "Build cleanup completed"
}

# Create virtual environment
create_venv() {
    log_info "Creating build virtual environment..."
    
    python3 -m venv "$VENV_DIR"
    
    # Activate virtual environment
    if [[ "$PLATFORM" == "windows" ]]; then
        source "$VENV_DIR/Scripts/activate"
    else
        source "$VENV_DIR/bin/activate"
    fi
    
    # Upgrade pip and build tools
    pip install --upgrade pip setuptools wheel build twine
    
    log_success "Virtual environment created and activated"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    # Install core dependencies
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
    else
        log_warning "requirements.txt not found, installing minimal dependencies"
        pip install psutil requests cryptography Pillow Flask watchdog PyYAML
    fi
    
    # Install platform-specific dependencies
    case "$PLATFORM" in
        windows)
            pip install pywin32
            ;;
        linux)
            pip install python-systemd
            ;;
    esac
    
    # Install optional ML dependencies
    log_info "Installing ML dependencies..."
    pip install numpy scikit-learn pandas || log_warning "ML dependencies installation failed"
    
    # Install advanced scanning dependencies
    log_info "Installing advanced scanning dependencies..."
    pip install scapy yara-python || log_warning "Advanced scanning dependencies installation failed"
    
    log_success "Dependencies installed"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    # Install test dependencies
    pip install pytest pytest-cov
    
    # Run tests if test directory exists
    if [[ -d "tests" ]]; then
        python -m pytest tests/ -v --cov=src/prashant918_antivirus --cov-report=html
        log_success "Tests completed"
    else
        log_warning "No tests directory found, skipping tests"
    fi
}

# Build package
build_package() {
    log_info "Building package..."
    
    # Build source distribution and wheel
    python -m build
    
    # Verify build
    if [[ -d "$DIST_DIR" ]] && [[ $(ls -1 "$DIST_DIR" | wc -l) -gt 0 ]]; then
        log_success "Package built successfully"
        log_info "Built packages:"
        ls -la "$DIST_DIR"
    else
        log_error "Package build failed"
        exit 1
    fi
}

# Create platform-specific installers
create_installers() {
    log_info "Creating platform-specific installers..."
    
    local installer_dir="installers"
    mkdir -p "$installer_dir"
    
    case "$PLATFORM" in
        windows)
            create_windows_installer
            ;;
        linux)
            create_linux_installer
            ;;
        macos)
            create_macos_installer
            ;;
    esac
}

# Create Windows installer
create_windows_installer() {
    log_info "Creating Windows installer..."
    
    # Create Windows batch installer
    cat > "installers/install_windows.bat" << 'EOF'
@echo off
echo Installing Prashant918 Advanced Antivirus...

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

REM Install package
pip install prashant918-advanced-antivirus[all]

if errorlevel 1 (
    echo Installation failed
    pause
    exit /b 1
)

echo Installation completed successfully!
echo.
echo Available commands:
echo   prashant918-antivirus --help
echo   prashant918-av-gui
echo   prashant918-av-service install
echo.
pause
EOF

    log_success "Windows installer created"
}

# Create Linux installer
create_linux_installer() {
    log_info "Creating Linux installer..."
    
    # Create Linux shell installer
    cat > "installers/install_linux.sh" << 'EOF'
#!/bin/bash

set -e

echo "Installing Prashant918 Advanced Antivirus..."

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed"
    echo "Please install Python 3.8 or higher using your package manager"
    exit 1
fi

# Check Python version
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "Python 3.8 or higher is required"
    exit 1
fi

# Install package
echo "Installing package..."
pip3 install --user prashant918-advanced-antivirus[all]

echo "Installation completed successfully!"
echo ""
echo "Available commands:"
echo "  prashant918-antivirus --help"
echo "  prashant918-av-gui"
echo "  sudo prashant918-av-service install"
echo ""
echo "Note: You may need to add ~/.local/bin to your PATH"
EOF

    chmod +x "installers/install_linux.sh"
    log_success "Linux installer created"
}

# Create macOS installer
create_macos_installer() {
    log_info "Creating macOS installer..."
    
    # Create macOS shell installer
    cat > "installers/install_macos.sh" << 'EOF'
#!/bin/bash

set -e

echo "Installing Prashant918 Advanced Antivirus..."

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed"
    echo "Please install Python 3.8 or higher from https://python.org or using Homebrew"
    exit 1
fi

# Check Python version
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "Python 3.8 or higher is required"
    exit 1
fi

# Install package
echo "Installing package..."
pip3 install --user prashant918-advanced-antivirus[all]

echo "Installation completed successfully!"
echo ""
echo "Available commands:"
echo "  prashant918-antivirus --help"
echo "  prashant918-av-gui"
echo "  sudo prashant918-av-service install"
echo ""
echo "Note: You may need to add ~/Library/Python/*/bin to your PATH"
EOF

    chmod +x "installers/install_macos.sh"
    log_success "macOS installer created"
}

# Create documentation
create_documentation() {
    log_info "Creating documentation..."
    
    local docs_dir="docs"
    mkdir -p "$docs_dir"
    
    # Create installation guide
    cat > "$docs_dir/INSTALLATION.md" << EOF
# Prashant918 Advanced Antivirus - Installation Guide

## System Requirements

- Python 3.8 or higher
- 1GB RAM minimum (2GB recommended)
- 500MB free disk space
- Internet connection for updates

## Platform Support

- Windows 10/11 (x64, x86)
- Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+)
- macOS 10.14+ (Intel and Apple Silicon)

## Installation Methods

### Method 1: Using pip (Recommended)

\`\`\`bash
pip install prashant918-advanced-antivirus[all]
\`\`\`

### Method 2: Platform-specific Installers

#### Windows
1. Download and run \`install_windows.bat\`
2. Follow the on-screen instructions

#### Linux
1. Download and run \`install_linux.sh\`
2. Make executable: \`chmod +x install_linux.sh\`
3. Run: \`./install_linux.sh\`

#### macOS
1. Download and run \`install_macos.sh\`
2. Make executable: \`chmod +x install_macos.sh\`
3. Run: \`./install_macos.sh\`

### Method 3: From Source

\`\`\`bash
git clone https://github.com/prashant918/advanced-antivirus.git
cd advanced-antivirus
pip install -e .[all]
\`\`\`

## Post-Installation

### Command Line Usage
\`\`\`bash
# Scan a file
prashant918-antivirus scan /path/to/file

# Show system information
prashant918-antivirus info

# Install as service
sudo prashant918-av-service install
\`\`\`

### GUI Usage
\`\`\`bash
prashant918-av-gui
\`\`\`

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run with administrator/root privileges
2. **Module Not Found**: Ensure all dependencies are installed
3. **Service Installation Failed**: Check system compatibility

### Getting Help

- GitHub Issues: https://github.com/prashant918/advanced-antivirus/issues
- Email: prashant918@example.com
- Documentation: Check README.md for detailed information

## Uninstallation

\`\`\`bash
# Stop and uninstall service
sudo prashant918-av-service uninstall

# Remove package
pip uninstall prashant918-advanced-antivirus
\`\`\`
EOF

    log_success "Documentation created"
}

# Package verification
verify_package() {
    log_info "Verifying package..."
    
    # Test installation in clean environment
    local test_venv="test_env"
    python3 -m venv "$test_venv"
    
    if [[ "$PLATFORM" == "windows" ]]; then
        source "$test_venv/Scripts/activate"
    else
        source "$test_venv/bin/activate"
    fi
    
    # Install from built wheel
    local wheel_file=$(ls "$DIST_DIR"/*.whl | head -n1)
    if [[ -f "$wheel_file" ]]; then
        pip install "$wheel_file"
        
        # Test import
        python -c "import prashant918_antivirus; print('Package import successful')"
        
        # Test CLI
        prashant918-antivirus --version
        
        log_success "Package verification completed"
    else
        log_error "No wheel file found for verification"
        exit 1
    fi
    
    # Cleanup test environment
    deactivate
    rm -rf "$test_venv"
}

# Create release package
create_release() {
    log_info "Creating release package..."
    
    local release_dir="release"
    mkdir -p "$release_dir"
    
    # Copy distribution files
    cp -r "$DIST_DIR"/* "$release_dir/"
    
    # Copy installers
    cp -r installers "$release_dir/"
    
    # Copy documentation
    cp -r docs "$release_dir/"
    cp README.md "$release_dir/" 2>/dev/null || true
    cp LICENSE "$release_dir/" 2>/dev/null || true
    
    # Create release archive
    local release_name="${PACKAGE_NAME}-${VERSION}-${PLATFORM}-${ARCH}"
    
    if command -v tar &> /dev/null; then
        tar -czf "${release_name}.tar.gz" -C "$release_dir" .
        log_success "Release archive created: ${release_name}.tar.gz"
    fi
    
    if command -v zip &> /dev/null; then
        (cd "$release_dir" && zip -r "../${release_name}.zip" .)
        log_success "Release archive created: ${release_name}.zip"
    fi
}

# Main build process
main() {
    log_info "Starting build process for $PACKAGE_NAME v$VERSION"
    
    detect_platform
    check_prerequisites
    clean_build
    create_venv
    install_dependencies
    
    # Optional: Run tests
    if [[ "${RUN_TESTS:-false}" == "true" ]]; then
        run_tests
    fi
    
    build_package
    create_installers
    create_documentation
    verify_package
    create_release
    
    log_success "Build process completed successfully!"
    log_info "Release files are available in the release/ directory"
    
    # Cleanup
    if [[ "${KEEP_BUILD_ENV:-false}" != "true" ]]; then
        deactivate 2>/dev/null || true
        rm -rf "$VENV_DIR"
        log_info "Build environment cleaned up"
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h          Show this help message"
        echo "  --test              Run tests during build"
        echo "  --keep-env          Keep build environment after completion"
        echo "  --clean-only        Only clean previous builds"
        echo ""
        echo "Environment variables:"
        echo "  RUN_TESTS=true      Run tests during build"
        echo "  KEEP_BUILD_ENV=true Keep build environment"
        exit 0
        ;;
    --test)
        export RUN_TESTS=true
        ;;
    --keep-env)
        export KEEP_BUILD_ENV=true
        ;;
    --clean-only)
        clean_build
        exit 0
        ;;
esac

# Run main build process
main "$@"