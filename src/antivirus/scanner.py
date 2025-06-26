import os
import time
from pathlib import Path
from typing import List, Dict, Generator
from termcolor import colored
from .engine import AntivirusEngine
from .signatures import SignatureDatabase
from .detector import ThreatDetector

class FileScanner:
    """File and directory scanner with real-time scanning capabilities"""
    
    def __init__(self):
        self.engine = AntivirusEngine()
        self.signatures_db = SignatureDatabase()
        self.detector = ThreatDetector()
        self.scan_extensions = {
            '.exe', '.dll', '.sys', '.bat', '.cmd', '.com', '.scr', '.pif',
            '.vbs', '.js', '.jar', '.zip', '.rar', '.7z', '.doc', '.docx',
            '.xls', '.xlsx', '.pdf', '.rtf', '.txt', '.py', '.php', '.asp',
            '.jsp', '.html', '.htm', '.xml', '.sql'
        }
        self.excluded_dirs = {
            'System Volume Information', '$Recycle.Bin', 'Windows',
            'Program Files', 'Program Files (x86)', 'ProgramData'
        }
    
    def should_scan_file(self, file_path: str) -> bool:
        """Determine if file should be scanned"""
        try:
            path = Path(file_path)
            
            # Check file extension
            if path.suffix.lower() not in self.scan_extensions:
                return False
            
            # Check file size (skip very large files for performance)
            if path.stat().st_size > 500 * 1024 * 1024:  # 500MB
                return False
            
            # Check if file is accessible
            if not os.access(file_path, os.R_OK):
                return False
            
            return True
        except Exception:
            return False
    
    def scan_file(self, file_path: str, quarantine: bool = False) -> Dict:
        """Scan a single file"""
        print(colored(f"Scanning: {file_path}", 'cyan'))
        
        if not self.should_scan_file(file_path):
            return {
                'status': 'skipped',
                'reason': 'File type not supported or file too large'
            }
        
        result = self.engine.scan_file(file_path, self.signatures_db, self.detector)
        
        # Handle infected files
        if result['status'] == 'infected' and quarantine:
            threat_name = result.get('threat_name', 'Unknown-Threat')
            if self.engine.quarantine_file(file_path, threat_name):
                result['quarantined'] = True
        
        return result
    
    def scan_directory(self, directory_path: str, recursive: bool = True, 
                      quarantine: bool = False) -> Generator[Dict, None, None]:
        """Scan directory and yield results for each file"""
        directory = Path(directory_path)
        
        if not directory.exists() or not directory.is_dir():
            yield {
                'status': 'error',
                'message': f"Directory not found: {directory_path}"
            }
            return
        
        print(colored(f"Starting directory scan: {directory_path}", 'blue'))
        
        try:
            if recursive:
                file_iterator = directory.rglob('*')
            else:
                file_iterator = directory.iterdir()
            
            for item in file_iterator:
                if item.is_file():
                    # Skip excluded directories
                    if any(excluded in str(item.parent) for excluded in self.excluded_dirs):
                        continue
                    
                    result = self.scan_file(str(item), quarantine)
                    result['file_path'] = str(item)
                    yield result
                    
        except PermissionError:
            yield {
                'status': 'error',
                'message': f"Permission denied accessing: {directory_path}"
            }
        except Exception as e:
            yield {
                'status': 'error',
                'message': f"Error scanning directory: {e}"
            }
    
    def quick_scan(self, quarantine: bool = False) -> Dict:
        """Perform quick scan of common locations"""
        print(colored("Starting Quick Scan...", 'yellow'))
        
        # Common locations to scan
        scan_locations = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            "/tmp" if os.name != 'nt' else os.environ.get('TEMP', ''),
        ]
        
        results = {
            'scan_type': 'quick',
            'start_time': time.time(),
            'files_scanned': 0,
            'threats_found': 0,
            'infected_files': [],
            'suspicious_files': [],
            'errors': []
        }
        
        for location in scan_locations:
            if location and os.path.exists(location):
                print(colored(f"Scanning location: {location}", 'cyan'))
                
                for result in self.scan_directory(location, recursive=False, quarantine=quarantine):
                    if result['status'] == 'infected':
                        results['threats_found'] += 1
                        results['infected_files'].append(result)
                    elif result['status'] == 'suspicious':
                        results['suspicious_files'].append(result)
                    elif result['status'] == 'error':
                        results['errors'].append(result)
                    
                    if result['status'] in ['clean', 'infected', 'suspicious']:
                        results['files_scanned'] += 1
        
        results['end_time'] = time.time()
        results['scan_duration'] = results['end_time'] - results['start_time']
        
        return results
    
    def full_scan(self, quarantine: bool = False) -> Dict:
        """Perform full system scan"""
        print(colored("Starting Full System Scan...", 'yellow'))
        
        # Determine root directory based on OS
        if os.name == 'nt':  # Windows
            scan_root = "C:\\"
        else:  # Unix-like systems
            scan_root = os.path.expanduser("~")  # Scan user directory for safety
        
        results = {
            'scan_type': 'full',
            'start_time': time.time(),
            'files_scanned': 0,
            'threats_found': 0,
            'infected_files': [],
            'suspicious_files': [],
            'errors': []
        }
        
        print(colored(f"Scanning from root: {scan_root}", 'cyan'))
        
        for result in self.scan_directory(scan_root, recursive=True, quarantine=quarantine):
            if result['status'] == 'infected':
                results['threats_found'] += 1
                results['infected_files'].append(result)
                print(colored(f"THREAT FOUND: {result.get('threat_name')} in {result.get('file_path')}", 'red'))
            elif result['status'] == 'suspicious':
                results['suspicious_files'].append(result)
                print(colored(f"SUSPICIOUS: {result.get('file_path')}", 'yellow'))
            elif result['status'] == 'error':
                results['errors'].append(result)
            
            if result['status'] in ['clean', 'infected', 'suspicious']:
                results['files_scanned'] += 1
                
                # Print progress every 100 files
                if results['files_scanned'] % 100 == 0:
                    print(colored(f"Progress: {results['files_scanned']} files scanned, {results['threats_found']} threats found", 'blue'))
        
        results['end_time'] = time.time()
        results['scan_duration'] = results['end_time'] - results['start_time']
        
        return results
    
    def get_scan_report(self, scan_results: Dict) -> str:
        """Generate detailed scan report"""
        report = f"""
{colored('='*60, 'cyan')}
{colored('ANTIVIRUS SCAN REPORT', 'cyan')}
{colored('='*60, 'cyan')}

Scan Type: {scan_results['scan_type'].upper()}
Scan Duration: {scan_results['scan_duration']:.2f} seconds
Files Scanned: {scan_results['files_scanned']}
Threats Found: {scan_results['threats_found']}
Suspicious Files: {len(scan_results['suspicious_files'])}
Errors: {len(scan_results['errors'])}

"""
        
        if scan_results['infected_files']:
            report += colored("\nINFECTED FILES:\n", 'red')
            for infected in scan_results['infected_files']:
                report += f"  • {infected.get('file_path', 'Unknown')}\n"
                report += f"    Threat: {infected.get('threat_name', 'Unknown')}\n"
                report += f"    Method: {infected.get('detection_method', 'Unknown')}\n\n"
        
        if scan_results['suspicious_files']:
            report += colored("\nSUSPICIOUS FILES:\n", 'yellow')
            for suspicious in scan_results['suspicious_files']:
                report += f"  • {suspicious.get('file_path', 'Unknown')}\n"
                indicators = suspicious.get('suspicious_indicators', [])
                for indicator in indicators:
                    report += f"    - {indicator}\n"
                report += "\n"
        
        if scan_results['errors']:
            report += colored("\nERRORS:\n", 'red')
            for error in scan_results['errors'][:10]:  # Show first 10 errors
                report += f"  • {error.get('message', 'Unknown error')}\n"
        
        report += colored('='*60, 'cyan')
        return report
