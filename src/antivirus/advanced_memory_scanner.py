import psutil
import ctypes
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import logging
import re
import os
import platform

class MemoryThreatType(Enum):
    PROCESS_INJECTION = "process_injection"
    ROOTKIT_SIGNATURE = "rootkit_signature"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    HIDDEN_PROCESS = "hidden_process"
    MEMORY_CORRUPTION = "memory_corruption"
    SHELLCODE = "shellcode"

@dataclass
class MemoryThreat:
    process_id: int
    process_name: str
    threat_type: MemoryThreatType
    threat_description: str
    memory_address: Optional[int]
    confidence: float
    evidence: Dict
    timestamp: float

class AdvancedMemoryScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Platform-specific configurations
        self.is_windows = platform.system() == "Windows"
        self.is_linux = platform.system() == "Linux"
        
        # Rootkit signatures
        self.rootkit_signatures = self._load_rootkit_signatures()
        
        # Shellcode patterns
        self.shellcode_patterns = self._load_shellcode_patterns()
        
        # Process whitelist
        self.process_whitelist = set(config.get('process_whitelist', [
            'System', 'Registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
            'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe'
        ]))
        
        # Scanning state
        self.scanning = False
        self.scan_thread = None
        
        # Detection results
        self.detected_threats = []
        
        # Windows API functions (if on Windows)
        if self.is_windows:
            self._init_windows_api()
    
    def _init_windows_api(self):
        """Initialize Windows API functions"""
        try:
            self.kernel32 = ctypes.windll.kernel32
            self.ntdll = ctypes.windll.ntdll
            self.psapi = ctypes.windll.psapi
            
            # Define necessary structures and constants
            self.PROCESS_QUERY_INFORMATION = 0x0400
            self.PROCESS_VM_READ = 0x0010
            self.MEM_COMMIT = 0x1000
            self.PAGE_EXECUTE_READ = 0x20
            self.PAGE_EXECUTE_READWRITE = 0x40
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Windows API: {e}")
    
    def _load_rootkit_signatures(self) -> List[Dict]:
        """Load known rootkit signatures"""
        return [
            {
                'name': 'ZeroAccess',
                'patterns': [b'\x8B\xFF\x55\x8B\xEC\x83\xEC\x10', b'\x33\xC0\x64\x8B\x00'],
                'description': 'ZeroAccess rootkit signature'
            },
            {
                'name': 'Necurs',
                'patterns': [b'\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x20'],
                'description': 'Necurs rootkit signature'
            },
            {
                'name': 'Alureon',
                'patterns': [b'\x8B\x4C\x24\x04\x56\x8B\x74\x24\x0C'],
                'description': 'Alureon/TDL rootkit signature'
            },
            {
                'name': 'Generic_Rootkit',
                'patterns': [b'\\Device\\', b'\\SystemRoot\\', b'ZwQuerySystemInformation'],
                'description': 'Generic rootkit patterns'
            }
        ]
    
    def _load_shellcode_patterns(self) -> List[bytes]:
        """Load common shellcode patterns"""
        return [
            # Common x86 shellcode patterns
            b'\x31\xc0\x50\x68',  # xor eax,eax; push eax; push
            b'\x89\xe5\x31\xc0',  # mov ebp,esp; xor eax,eax
            b'\x31\xdb\x53\x43',  # xor ebx,ebx; push ebx; inc ebx
            b'\x6a\x30\x58\xcd\x2e',  # push 30h; pop eax; int 2eh
            b'\xeb\xfe',  # jmp $-2 (infinite loop)
            
            # x64 shellcode patterns
            b'\x48\x31\xc0',  # xor rax,rax
            b'\x48\x89\xe5',  # mov rbp,rsp
            b'\x48\x83\xec',  # sub rsp,
            
            # Common API hashing patterns
            b'\x13\x89\xe5\x31',
            b'\x64\x8b\x30',  # mov esi, [fs:30h]
        ]
    
    def start_continuous_scan(self, interval: int = 60):
        """Start continuous memory scanning"""
        if self.scanning:
            return
        
        self.scanning = True
        self.scan_thread = threading.Thread(
            target=self._continuous_scan_loop,
            args=(interval,),
            daemon=True
        )
        self.scan_thread.start()
        self.logger.info("Continuous memory scanning started")
    
    def stop_continuous_scan(self):
        """Stop continuous memory scanning"""
        self.scanning = False
        if self.scan_thread:
            self.scan_thread.join(timeout=10)
        self.logger.info("Continuous memory scanning stopped")
    
    def _continuous_scan_loop(self, interval: int):
        """Continuous scanning loop"""
        while self.scanning:
            try:
                self.scan_all_processes()
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"Error in continuous scan: {e}")
                time.sleep(5)
    
    def scan_all_processes(self) -> List[MemoryThreat]:
        """Scan all running processes for memory threats"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    
                    # Skip whitelisted processes
                    if proc_info['name'] in self.process_whitelist:
                        continue
                    
                    # Scan individual process
                    process_threats = self.scan_process_memory(proc_info['pid'])
                    threats.extend(process_threats)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error scanning all processes: {e}")
        
        # Update detected threats
        self.detected_threats.extend(threats)
        
        # Limit stored threats
        max_threats = self.config.get('max_stored_threats', 1000)
        if len(self.detected_threats) > max_threats:
            self.detected_threats = self.detected_threats[-max_threats:]
        
        return threats
    
    def scan_process_memory(self, process_id: int) -> List[MemoryThreat]:
        """Scan specific process memory for threats"""
        threats = []
        
        try:
            process = psutil.Process(process_id)
            process_name = process.name()
            
            # Check for process injection
            injection_threats = self._detect_process_injection(process_id, process_name)
            threats.extend(injection_threats)
            
            # Check for hidden processes
            if self._is_hidden_process(process_id):
                threats.append(MemoryThreat(
                    process_id=process_id,
                    process_name=process_name,
                    threat_type=MemoryThreatType.HIDDEN_PROCESS,
                    threat_description="Process appears to be hidden from normal enumeration",
                    memory_address=None,
                    confidence=0.8,
                    evidence={'detection_method': 'process_enumeration_discrepancy'},
                    timestamp=time.time()
                ))
            
            # Scan process memory for signatures
            if self.is_windows:
                memory_threats = self._scan_process_memory_windows(process_id, process_name)
                threats.extend(memory_threats)
            elif self.is_linux:
                memory_threats = self._scan_process_memory_linux(process_id, process_name)
                threats.extend(memory_threats)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.debug(f"Cannot access process {process_id}: {e}")
        except Exception as e:
            self.logger.error(f"Error scanning process {process_id}: {e}")
        
        return threats
    
    def _detect_process_injection(self, process_id: int, process_name: str) -> List[MemoryThreat]:
        """Detect process injection techniques"""
        threats = []
        
        try:
            process = psutil.Process(process_id)
            
            # Check memory usage patterns
            memory_info = process.memory_info()
            
            # Suspicious memory patterns
            if memory_info.rss > 500 * 1024 * 1024:  # > 500MB
                # Check if process should normally use this much memory
                if not self._is_memory_intensive_process(process_name):
                    threats.append(MemoryThreat(
                        process_id=process_id,
                        process_name=process_name,
                        threat_type=MemoryThreatType.PROCESS_INJECTION,
                        threat_description="Unusual memory usage pattern detected",
                        memory_address=None,
                        confidence=0.4,
                        evidence={
                            'memory_usage': memory_info.rss,
                            'detection_reason': 'excessive_memory_usage'
                        },
                        timestamp=time.time()
                    ))
            
            # Check for unusual thread count
            try:
                thread_count = process.num_threads()
                if thread_count > 100:  # Suspicious thread count
                    threats.append(MemoryThreat(
                        process_id=process_id,
                        process_name=process_name,
                        threat_type=MemoryThreatType.PROCESS_INJECTION,
                        threat_description="Unusual thread count detected",
                        memory_address=None,
                        confidence=0.5,
                        evidence={
                            'thread_count': thread_count,
                            'detection_reason': 'excessive_threads'
                        },
                        timestamp=time.time()
                    ))
            except:
                pass
            
        except Exception as e:
            self.logger.debug(f"Error detecting process injection for {process_id}: {e}")
        
        return threats
    
    def _scan_process_memory_windows(self, process_id: int, process_name: str) -> List[MemoryThreat]:
        """Scan process memory on Windows"""
        threats = []
        
        if not self.is_windows:
            return threats
        
        try:
            # Open process handle
            process_handle = self.kernel32.OpenProcess(
                self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ,
                False,
                process_id
            )
            
            if not process_handle:
                return threats
            
            try:
                # Enumerate memory regions
                address = 0
                while address < 0x7FFFFFFF:  # User space limit
                    mbi = self._query_memory_info(process_handle, address)
                    if not mbi:
                        address += 0x1000  # Page size
                        continue
                    
                    # Check for executable memory regions
                    if (mbi['Protect'] & (self.PAGE_EXECUTE_READ | self.PAGE_EXECUTE_READWRITE) and
                        mbi['State'] & self.MEM_COMMIT):
                        
                        # Read memory content
                        memory_content = self._read_process_memory(
                            process_handle, 
                            mbi['BaseAddress'], 
                            min(mbi['RegionSize'], 4096)  # Read first 4KB
                        )
                        
                        if memory_content:
                            # Check for rootkit signatures
                            rootkit_matches = self._check_rootkit_signatures(memory_content)
                            for match in rootkit_matches:
                                threats.append(MemoryThreat(
                                    process_id=process_id,
                                    process_name=process_name,
                                    threat_type=MemoryThreatType.ROOTKIT_SIGNATURE,
                                    threat_description=f"Rootkit signature detected: {match['name']}",
                                    memory_address=mbi['BaseAddress'],
                                    confidence=0.9,
                                    evidence={
                                        'signature_name': match['name'],
                                        'signature_description': match['description'],
                                        'memory_region_size': mbi['RegionSize']
                                    },
                                    timestamp=time.time()
                                ))
                            
                            # Check for shellcode patterns
                            if self._contains_shellcode(memory_content):
                                threats.append(MemoryThreat(
                                    process_id=process_id,
                                    process_name=process_name,
                                    threat_type=MemoryThreatType.SHELLCODE,
                                    threat_description="Potential shellcode detected in memory",
                                    memory_address=mbi['BaseAddress'],
                                    confidence=0.7,
                                    evidence={
                                        'memory_region_size': mbi['RegionSize'],
                                        'detection_method': 'pattern_matching'
                                    },
                                    timestamp=time.time()
                                ))
                    
                    address = mbi['BaseAddress'] + mbi['RegionSize']
                    
            finally:
                self.kernel32.CloseHandle(process_handle)
                
        except Exception as e:
            self.logger.debug(f"Error scanning Windows process memory {process_id}: {e}")
        
        return threats
    
    def _scan_process_memory_linux(self, process_id: int, process_name: str) -> List[MemoryThreat]:
        """Scan process memory on Linux"""
        threats = []
        
        try:
            # Read process maps
            maps_path = f"/proc/{process_id}/maps"
            if not os.path.exists(maps_path):
                return threats
            
            with open(maps_path, 'r') as f:
                maps_content = f.read()
            
            # Parse memory maps
            for line in maps_content.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                address_range = parts[0]
                permissions = parts[1]
                
                # Check for executable regions
                if 'x' in permissions:
                    try:
                        # Try to read memory content
                        mem_path = f"/proc/{process_id}/mem"
                        start_addr, end_addr = address_range.split('-')
                        start_addr = int(start_addr, 16)
                        end_addr = int(end_addr, 16)
                        
                        # Read small portion of memory
                        read_size = min(end_addr - start_addr, 4096)
                        
                        with open(mem_path, 'rb') as mem_file:
                            mem_file.seek(start_addr)
                            memory_content = mem_file.read(read_size)
                            
                            # Check for suspicious patterns
                            if self._contains_shellcode(memory_content):
                                threats.append(MemoryThreat(
                                    process_id=process_id,
                                    process_name=process_name,
                                    threat_type=MemoryThreatType.SHELLCODE,
                                    threat_description="Potential shellcode detected in memory",
                                    memory_address=start_addr,
                                    confidence=0.6,
                                    evidence={
                                        'memory_region': address_range,
                                        'permissions': permissions
                                    },
                                    timestamp=time.time()
                                ))
                    
                    except (PermissionError, OSError):
                        # Cannot read memory, skip
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Error scanning Linux process memory {process_id}: {e}")
        
        return threats
    
    def _query_memory_info(self, process_handle, address):
        """Query memory information for Windows process"""
        try:
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong)
                ]
            
            mbi = MEMORY_BASIC_INFORMATION()
            result = self.kernel32.VirtualQueryEx(
                process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            )
            
            if result:
                return {
                    'BaseAddress': mbi.BaseAddress,
                    'RegionSize': mbi.RegionSize,
                    'State': mbi.State,
                    'Protect': mbi.Protect
                }
            
        except Exception as e:
            self.logger.debug(f"Error querying memory info: {e}")
        
        return None
    
    def _read_process_memory(self, process_handle, address, size):
        """Read process memory on Windows"""
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            result = self.kernel32.ReadProcessMemory(
                process_handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read)
            )
            
            if result and bytes_read.value > 0:
                return buffer.raw[:bytes_read.value]
                
        except Exception as e:
            self.logger.debug(f"Error reading process memory: {e}")
        
        return None
    
    def _check_rootkit_signatures(self, memory_content: bytes) -> List[Dict]:
        """Check memory content against rootkit signatures"""
        matches = []
        
        for signature in self.rootkit_signatures:
            for pattern in signature['patterns']:
                if pattern in memory_content:
                    matches.append(signature)
                    break
        
        return matches
    
    def _contains_shellcode(self, memory_content: bytes) -> bool:
        """Check if memory content contains shellcode patterns"""
        for pattern in self.shellcode_patterns:
            if pattern in memory_content:
                return True
        
        # Additional heuristic checks
        if len(memory_content) < 50:
            return False
        
        # Check for high entropy (common in shellcode)
        entropy = self._calculate_entropy(memory_content)
        if entropy > 7.0:  # High entropy threshold
            return True
        
        # Check for NOP sleds
        nop_count = memory_content.count(b'\x90')  # x86 NOP instruction
        if nop_count > len(memory_content) * 0.1:  # > 10% NOPs
            return True
        
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _is_hidden_process(self, process_id: int) -> bool:
        """Check if process is hidden from normal enumeration"""
        # This is a simplified check - in reality, this would involve
        # more sophisticated techniques like direct system call enumeration
        try:
            # Try to access process through different methods
            psutil_accessible = True
            try:
                psutil.Process(process_id)
            except psutil.NoSuchProcess:
                psutil_accessible = False
            
            # On Windows, try direct API access
            if self.is_windows:
                try:
                    handle = self.kernel32.OpenProcess(
                        self.PROCESS_QUERY_INFORMATION,
                        False,
                        process_id
                    )
                    api_accessible = handle != 0
                    if handle:
                        self.kernel32.CloseHandle(handle)
                except:
                    api_accessible = False
                
                # If accessible through API but not psutil, might be hidden
                return api_accessible and not psutil_accessible
            
        except Exception:
            pass
        
        return False
    
    def _is_memory_intensive_process(self, process_name: str) -> bool:
        """Check if process is known to be memory intensive"""
        memory_intensive_processes = {
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe',
            'photoshop.exe', 'premiere.exe', 'blender.exe',
            'java.exe', 'javaw.exe', 'idea64.exe', 'code.exe'
        }
        
        return process_name.lower() in memory_intensive_processes
    
    def get_detected_threats(self, limit: int = 100) -> List[Dict]:
        """Get recently detected memory threats"""
        recent_threats = self.detected_threats[-limit:]
        return [
            {
                'process_id': threat.process_id,
                'process_name': threat.process_name,
                'threat_type': threat.threat_type.value,
                'description': threat.threat_description,
                'confidence': threat.confidence,
                'timestamp': threat.timestamp,
                'evidence': threat.evidence
            }
            for threat in recent_threats
        ]
    
    def get_scan_statistics(self) -> Dict:
        """Get memory scanning statistics"""
        if not self.detected_threats:
            return {
                'total_threats': 0,
                'threat_types': {},
                'avg_confidence': 0.0,
                'last_scan': None
            }
        
        threat_types = {}
        for threat in self.detected_threats:
            threat_type = threat.threat_type.value
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        avg_confidence = sum(t.confidence for t in self.detected_threats) / len(self.detected_threats)
        last_scan = max(t.timestamp for t in self.detected_threats)
        
        return {
            'total_threats': len(self.detected_threats),
            'threat_types': threat_types,
            'avg_confidence': avg_confidence,
            'last_scan': last_scan
        }
    
    def clear_threat_history(self):
        """Clear detected threat history"""
        self.detected_threats.clear()
        self.logger.info("Memory threat history cleared")