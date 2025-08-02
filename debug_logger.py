#!/usr/bin/env python3
"""
Debug script to identify logger initialization issues
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent.absolute()
src_path = project_root / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

def test_logger_initialization():
    """Test logger initialization step by step"""
    print("=== Logger Initialization Debug ===")
    
    try:
        print("1. Testing basic imports...")
        from prashant918_antivirus.logger import SecureLogger
        print("   ✓ SecureLogger imported successfully")
        
        print("2. Testing logger creation...")
        logger = SecureLogger("TestLogger")
        print("   ✓ SecureLogger created successfully")
        
        print("3. Testing basic logging...")
        logger.info("Test message")
        print("   ✓ Basic logging works")
        
        return True
        
    except Exception as e:
        print(f"   ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_directory_creation():
    """Test directory creation"""
    print("\n=== Directory Creation Debug ===")
    
    try:
        directories = [
            Path.home() / ".prashant918_antivirus" / "logs",
            Path.home() / ".prashant918_antivirus" / "quarantine",
            Path.home() / ".prashant918_antivirus" / "config",
        ]
        
        for directory in directories:
            print(f"Creating: {directory}")
            directory.mkdir(parents=True, exist_ok=True)
            if os.name != 'nt':
                os.chmod(directory, 0o700)
            print(f"   ✓ Created: {directory}")
        
        return True
        
    except Exception as e:
        print(f"   ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_config_access():
    """Test configuration access"""
    print("\n=== Configuration Debug ===")
    
    try:
        from prashant918_antivirus.config import secure_config
        print("   ✓ Config imported successfully")
        
        # Test basic config access
        test_value = secure_config.get('logging', {})
        print(f"   ✓ Config access works: {type(test_value)}")
        
        return True
        
    except Exception as e:
        print(f"   ✗ Config error: {e}")
        return False

def main():
    """Main debug function"""
    print("Starting antivirus system debug...")
    
    # Test directory creation first
    if not test_directory_creation():
        print("Directory creation failed!")
        return False
    
    # Test configuration
    config_ok = test_config_access()
    
    # Test logger initialization
    if not test_logger_initialization():
        print("Logger initialization failed!")
        return False
    
    print("\n=== All Tests Passed ===")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
