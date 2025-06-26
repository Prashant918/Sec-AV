"""
Prashant918 Advanced Antivirus - Dependency Checker

Comprehensive dependency checking and installation guidance.
"""

import sys
import importlib
import subprocess
import platform
from typing import Dict, List, Tuple, Optional

class DependencyChecker:
    """Check and validate all dependencies"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.architecture = platform.machine().lower()
        self.python_version = sys.version_info
        
        # Define dependency categories
        self.dependencies = {
            'essential': {
                'requests': {'min_version': '2.31.0', 'description': 'HTTP library'},
                'cryptography': {'min_version': '41.0.0', 'description': 'Cryptographic library'},
                'psutil': {'min_version': '5.9.0', 'description': 'System monitoring'},
                'termcolor': {'min_version': '2.3.0', 'description': 'Terminal colors'},
                'pyfiglet': {'min_version': '0.8.0', 'description': 'ASCII art text'},
            },
            'database': {
                'sqlalchemy': {'min_version': '2.0.0', 'description': 'SQL toolkit'},
                'cx_Oracle': {'min_version': '8.3.0', 'description': 'Oracle database driver', 'optional': True},
                'oracledb': {'min_version': '1.4.2', 'description': 'Oracle database driver', 'optional': True},
            },
            'machine_learning': {
                'numpy': {'min_version': '1.24.0', 'description': 'Numerical computing'},
                'pandas': {'min_version': '2.0.0', 'description': 'Data analysis'},
                'scikit-learn': {'min_version': '1.3.0', 'description': 'Machine learning'},
                'tensorflow': {'min_version': '2.13.0', 'description': 'Deep learning', 'optional': True},
                'joblib': {'min_version': '1.3.0', 'description': 'Parallel computing'},
                'scipy': {'min_version': '1.11.0', 'description': 'Scientific computing'},
            },
            'security': {
                'yara-python': {'min_version': '4.3.1', 'description': 'YARA pattern matching', 'optional': True},
                'python-magic': {'min_version': '0.4.27', 'description': 'File type detection', 'optional': True},
                'pefile': {'min_version': '2023.2.7', 'description': 'PE file analysis', 'optional': True},
            },
            'ui': {
                'rich': {'min_version': '13.5.2', 'description': 'Rich terminal output', 'optional': True},
                'click': {'min_version': '8.1.7', 'description': 'Command line interface', 'optional': True},
                'flask': {'min_version': '2.3.3', 'description': 'Web framework', 'optional': True},
            },
            'platform_specific': {
                'pywin32': {'min_version': '306', 'description': 'Windows API', 'platforms': ['windows']},
                'wmi': {'min_version': '1.5.1', 'description': 'Windows WMI', 'platforms': ['windows']},
                'python-prctl': {'min_version': '1.8.1', 'description': 'Process control', 'platforms': ['linux']},
                'pyobjc': {'min_version': '9.2', 'description': 'macOS Objective-C bridge', 'platforms': ['darwin']},
            }
        }
    
    def check_python_version(self) -> Dict[str, any]:
        """Check Python version compatibility"""
        min_version = (3, 9)
        current_version = self.python_version[:2]
        
        compatible = current_version >= min_version
        
        return {
            'compatible': compatible,
            'current_version': f"{current_version[0]}.{current_version[1]}",
            'min_version': f"{min_version[0]}.{min_version[1]}",
            'message': 'Compatible' if compatible else f'Python {min_version[0]}.{min_version[1]}+ required'
        }
    
    def check_dependency(self, package_name: str, requirements: Dict) -> Dict[str, any]:
        """Check individual dependency"""
        result = {
            'name': package_name,
            'available': False,
            'version': None,
            'compatible': False,
            'required_version': requirements.get('min_version'),
            'description': requirements.get('description', ''),
            'optional': requirements.get('optional', False),
            'platform_specific': 'platforms' in requirements,
            'error': None
        }
        
        # Check platform compatibility
        if 'platforms' in requirements:
            if self.platform not in requirements['platforms']:
                result['error'] = f"Not required on {self.platform}"
                result['compatible'] = True  # Not required = compatible
                return result
        
        # Try to import the package
        try:
            # Handle special cases for package names
            import_name = package_name
            if package_name == 'yara-python':
                import_name = 'yara'
            elif package_name == 'python-magic':
                import_name = 'magic'
            elif package_name == 'scikit-learn':
                import_name = 'sklearn'
            elif package_name == 'python-prctl':
                import_name = 'prctl'
            
            module = importlib.import_module(import_name)
            result['available'] = True
            
            # Try to get version
            version = None
            for attr in ['__version__', 'version', 'VERSION']:
                if hasattr(module, attr):
                    version = getattr(module, attr)
                    break
            
            if version:
                result['version'] = str(version)
                # Simple version comparison (not perfect but works for most cases)
                try:
                    result['compatible'] = self._compare_versions(version, requirements['min_version'])
                except:
                    result['compatible'] = True  # Assume compatible if can't compare
            else:
                result['version'] = 'unknown'
                result['compatible'] = True  # Assume compatible if version unknown
                
        except ImportError as e:
            result['error'] = str(e)
        except Exception as e:
            result['error'] = f"Unexpected error: {e}"
        
        return result
    
    def _compare_versions(self, current: str, required: str) -> bool:
        """Simple version comparison"""
        try:
            # Remove any non-numeric suffixes
            current_clean = current.split('+')[0].split('-')[0].split('rc')[0].split('a')[0].split('b')[0]
            required_clean = required.split('+')[0].split('-')[0].split('rc')[0].split('a')[0].split('b')[0]
            
            current_parts = [int(x) for x in current_clean.split('.')]
            required_parts = [int(x) for x in required_clean.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(current_parts), len(required_parts))
            current_parts.extend([0] * (max_len - len(current_parts)))
            required_parts.extend([0] * (max_len - len(required_parts)))
            
            return current_parts >= required_parts
        except:
            return True  # Assume compatible if comparison fails
    
    def check_all_dependencies(self) -> Dict[str, any]:
        """Check all dependencies"""
        results = {
            'python_version': self.check_python_version(),
            'categories': {},
            'summary': {
                'total_checked': 0,
                'available': 0,
                'compatible': 0,
                'missing_essential': [],
                'missing_optional': [],
                'incompatible': []
            }
        }
        
        for category, packages in self.dependencies.items():
            category_results = {}
            
            for package_name, requirements in packages.items():
                dep_result = self.check_dependency(package_name, requirements)
                category_results[package_name] = dep_result
                
                results['summary']['total_checked'] += 1
                if dep_result['available']:
                    results['summary']['available'] += 1
                if dep_result['compatible']:
                    results['summary']['compatible'] += 1
                
                if not dep_result['available']:
                    if dep_result['optional']:
                        results['summary']['missing_optional'].append(package_name)
                    else:
                        results['summary']['missing_essential'].append(package_name)
                elif not dep_result['compatible']:
                    results['summary']['incompatible'].append(package_name)
            
            results['categories'][category] = category_results
        
        return results
