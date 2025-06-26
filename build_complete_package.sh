#!/bin/bash

# Complete package build script with all components

echo "🚀 Building Complete Prashant918 Advanced Antivirus Package..."

# Run the main build script
./build_wheel.sh

# Create additional components
echo "📦 Creating additional package components..."

# Create documentation package
mkdir -p packages/documentation
cp -r docs/* packages/documentation/ 2>/dev/null || echo "No docs directory found"
cp README.md packages/documentation/
cp INSTALLATION_GUIDE.md packages/documentation/
cp CHANGELOG.md packages/documentation/ 2>/dev/null || echo "No changelog found"

# Create configuration templates
mkdir -p packages/config-templates
cp config/*.conf packages/config-templates/ 2>/dev/null || echo "No config files found"

# Create sample data
mkdir -p packages/sample-data
cp -r data/* packages/sample-data/ 2>/dev/null || echo "No sample data found"

# Create enterprise deployment package
mkdir -p packages/enterprise-deployment
cat > packages/enterprise-deployment/deploy-enterprise.sh << 'EOF'
#!/bin/bash
# Enterprise deployment script
echo "Deploying Prashant918 Advanced Antivirus Enterprise Edition..."

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root for enterprise deployment"
    exit 1
fi

# Create enterprise user and directories
useradd -r -s /bin/false -d /opt/prashant918-antivirus prashant918-av
mkdir -p /
