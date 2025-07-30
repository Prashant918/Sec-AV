#!/usr/bin/env python3
"""
Prashant918 Advanced Antivirus - Installation Test Script
Comprehensive testing to ensure all components work correctly
"""
import os
import sys
import time
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any

def test_imports() -> Dict[str, bool]:
    """Test all critical imports"""
    print("Testing imports...")
    
    results = {}
    
    # Core imports
    core_modules = [
        'src.prashant918_antivirus',
        'src.prashant918_antivirus.cli',
        'src.prashant918_antivirus.config',
        'src.prashant918_antivirus.utils',
        'src.prashant918_antivirus.database',
        'src.prashant918_antivirus.logger',
        'src.prashant918_antivirus.exceptions'
    ]
    
    for module in core_modules:
        try:
            __import__(module)
            results[module] = True
            print(f"  ✅ {module}")
        except ImportError as e:
            results[module] = False
            print(f"  ❌ {module}: {e}")
    
    # Component imports
    component_modules = [
        'src.prashant918_antivirus.antivirus.engine',
        'src.prashant918_antivirus.antivirus.ml_detector',
        'src.prashant918_antivirus.core.quarantine',
        'src.prashant918_antivirus.core.realtime_monitor',
        'src.prashant918_antivirus.service.service_manager'
    ]
    
    for module in component_modules:
        try:
            __import__(module)
            results[module] = True
            print(f"  ✅ {module}")
        except ImportError as e:
            results[module] = False
            print(f"  ❌ {module}: {e}")
    
    return results

def test_cli_commands() -> Dict[str, bool]:
    """Test CLI commands"""
    print("\nTesting CLI commands...")
    
    results = {}
    
    # Test CLI help
    try:
        result = subprocess.run([
            sys.executable, '-m', 'src.prashant918_antivirus.cli', '--help'
        ], capture_output=True, text=True, timeout=30)
        
        results['cli_help'] = result.returncode == 0
        if results['cli_help']:
            print("  ✅ CLI help command")
        else:
            print(f"  ❌ CLI help command: {result.stderr}")
    except Exception as e:
        results['cli_help'] = False
        print(f"  ❌ CLI help command: {e}")
    
    # Test CLI info command
    try:
        result = subprocess.run([
            sys.executable, '-m', 'src.prashant918_antivirus.cli', 'info'
        ], capture_output=True, text=True, timeout=30)
        
        results['cli_info'] = result.returncode == 0
        if results['cli_info']:
            print("  ✅ CLI info command")
        else:
            print(f"  ❌ CLI info command: {result.stderr}")
    except Exception as e:
        results['cli_info'] = False
        print(f"  ❌ CLI info command: {e}")
    
    return results

def test_core_functionality() -> Dict[str, bool]:
    """Test core functionality"""
    print("\nTesting core functionality...")
    
    results = {}
    
    # Test configuration
    try:
        from src.prashant918_antivirus.config import secure_config
        
        # Test basic config operations
        test_value = secure_config.get('test.key', 'default')
        secure_config.set('test.key', 'test_value')
        retrieved_value = secure_config.get('test.key')
        
        results['config'] = retrieved_value == 'test_value'
        if results['config']:
            print("  ✅ Configuration system")
        else:
            print("  ❌ Configuration system")
    except Exception as e:
        results['config'] = False
        print(f"  ❌ Configuration system: {e}")
    
    # Test database
    try:
        from src.prashant918_antivirus.database import DatabaseManager
        
        db = DatabaseManager()
        health = db.health_check()
        
        results['database'] = health.get('status') == 'healthy'
        if results['database']:
            print("  ✅ Database system")
        else:
            print(f"  ❌ Database system: {health}")
    except Exception as e:
        results['database'] = False
        print(f"  ❌ Database system: {e}")
    
    # Test utilities
    try:
        from src.prashant918_antivirus.utils import get_system_info, calculate_file_hash
        
        # Test system info
        sys_info = get_system_info()
        
        # Test file hash with a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content")
            tmp_path = tmp.name
        
        file_hash = calculate_file_hash(tmp_path)
        os.unlink(tmp_path)
        
        results['utils'] = bool(sys_info and file_hash)
        if results['utils']:
            print("  ✅ Utility functions")
        else:
            print("  ❌ Utility functions")
    except Exception as e:
        results['utils'] = False
        print(f"  ❌ Utility functions: {e}")
    
    return results

def test_threat_detection() -> Dict[str, bool]:
    """Test threat detection components"""
    print("\nTesting threat detection...")
    
    results = {}
    
    # Test ML detector
    try:
        from src.prashant918_antivirus.antivirus.ml_detector import EnsembleMLDetector
        
        ml_detector = EnsembleMLDetector()
        initialized = ml_detector.initialize()
        
        results['ml_detector'] = initialized
        if results['ml_detector']:
            print("  ✅ ML detector")
        else:
            print("  ❌ ML detector initialization failed")
    except Exception as e:
        results['ml_detector'] = False
        print(f"  ❌ ML detector: {e}")
    
    # Test threat engine
    try:
        from src.prashant918_antivirus.antivirus.engine import AdvancedThreatDetectionEngine
        
        engine = AdvancedThreatDetectionEngine()
        
        # Test with a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content for scanning")
            tmp_path = tmp.name
        
        scan_result = engine.scan_file(tmp_path)
        os.unlink(tmp_path)
        
        results['threat_engine'] = scan_result is not None
        if results['threat_engine']:
            print("  ✅ Threat detection engine")
        else:
            print("  ❌ Threat detection engine")
    except Exception as e:
        results['threat_engine'] = False
        print(f"  ❌ Threat detection engine: {e}")
    
    return results

def test_quarantine_system() -> Dict[str, bool]:
    """Test quarantine system"""
    print("\nTesting quarantine system...")
    
    results = {}
    
    try:
        from src.prashant918_antivirus.core.quarantine import QuarantineManager
        
        quarantine = QuarantineManager()
        
        # Create a test file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test malware content")
            tmp_path = tmp.name
        
        # Test quarantine
        quarantine_id = quarantine.quarantine_file(
            tmp_path, "Test Threat", "Test Detection"
        )
        
        # Test list
        items = quarantine.list_quarantined_files()
        
        # Test statistics
        stats = quarantine.get_quarantine_statistics()
        
        results['quarantine'] = bool(quarantine_id and items and stats)
        if results['quarantine']:
            print("  ✅ Quarantine system")
        else:
            print("  ❌ Quarantine system")
            
    except Exception as e:
        results['quarantine'] = False
        print(f"  ❌ Quarantine system: {e}")
    
    return results

def test_service_manager() -> Dict[str, bool]:
    """Test service manager"""
    print("\nTesting service manager...")
    
    results = {}
    
    try:
        from src.prashant918_antivirus.service.service_manager import ServiceManager
        
        service = ServiceManager()
        status = service.get_service_status()
        
        results['service_manager'] = bool(status)
        if results['service_manager']:
            print("  ✅ Service manager")
        else:
            print("  ❌ Service manager")
    except Exception as e:
        results['service_manager'] = False
        print(f"  ❌ Service manager: {e}")
    
    return results

def test_dependencies() -> Dict[str, bool]:
    """Test optional dependencies"""
    print("\nTesting optional dependencies...")
    
    results = {}
    
    dependencies = [
        'psutil', 'requests', 'cryptography', 'flask', 'rich', 'click',
        'numpy', 'sklearn', 'watchdog', 'pyfiglet', 'termcolor'
    ]
    
    for dep in dependencies:
        try:
            if dep == 'sklearn':
                import sklearn
            else:
                __import__(dep)
            results[dep] = True
            print(f"  ✅ {dep}")
        except ImportError:
            results[dep] = False
            print(f"  ❌ {dep}")
    
    return results

def generate_report(test_results: Dict[str, Dict[str, bool]]) -> str:
    """Generate test report"""
    report = []
    report.append("=" * 60)
    report.append("PRASHANT918 ANTIVIRUS INSTALLATION TEST REPORT")
    report.append("=" * 60)
    report.append(f"Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Python Version: {sys.version}")
    report.append(f"Platform: {sys.platform}")
    report.append("")
    
    total_tests = 0
    passed_tests = 0
    
    for category, tests in test_results.items():
        report.append(f"{category.upper()}:")
        report.append("-" * 30)
        
        for test_name, result in tests.items():
            status = "PASS" if result else "FAIL"
            report.append(f"  {test_name}: {status}")
            total_tests += 1
            if result:
                passed_tests += 1
        
        report.append("")
    
    report.append("SUMMARY:")
    report.append("-" * 30)
    report.append(f"Total Tests: {total_tests}")
    report.append(f"Passed: {passed_tests}")
    report.append(f"Failed: {total_tests - passed_tests}")
    report.append(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    report.append("")
    
    if passed_tests == total_tests:
        report.append("🎉 ALL TESTS PASSED! Installation is successful.")
    else:
        report.append("⚠️  Some tests failed. Please check the installation.")
    
    report.append("=" * 60)
    
    return "\n".join(report)

def main():
    """Main test function"""
    print("🔍 Starting Prashant918 Antivirus Installation Tests...")
    print("=" * 60)
    
    # Add src to Python path
    src_path = Path(__file__).parent / "src"
    if src_path.exists():
        sys.path.insert(0, str(src_path))
    
    # Run all tests
    test_results = {
        'imports': test_imports(),
        'cli_commands': test_cli_commands(),
        'core_functionality': test_core_functionality(),
        'threat_detection': test_threat_detection(),
        'quarantine_system': test_quarantine_system(),
        'service_manager': test_service_manager(),
        'dependencies': test_dependencies()
    }
    
    # Generate and display report
    report = generate_report(test_results)
    print("\n" + report)
    
    # Save report to file
    report_file = Path("installation_test_report.txt")
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"\n📄 Test report saved to: {report_file}")
    
    # Return exit code based on results
    all_passed = all(
        all(tests.values()) for tests in test_results.values()
    )
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())