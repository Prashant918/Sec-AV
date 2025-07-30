import psutil
import threading
import time
import json
import os
import platform
from typing import Dict, List, Set, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import hashlib
from collections import defaultdict, deque

class BehaviorType(Enum):
    FILE_OPERATION = "file_operation"
    NETWORK_ACTIVITY = "network_activity"
    REGISTRY_CHANGE = "registry_change"
    PROCESS_CREATION = "process_creation"
    MEMORY_INJECTION = "memory_injection"
    CRYPTO_ACTIVITY = "crypto_activity"
    SUSPICIOUS_API = "suspicious_api"

@dataclass
class BehaviorEvent:
    timestamp: float
    process_id: int
    process_name: str
    behavior_type: BehaviorType
    details: Dict
    risk_score: float = 0.0

class BehavioralAnalysisEngine:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Platform detection
        self.platform = platform.system().lower()
        
        # Event storage
        max_events = config.get('max_events', 10000)
        self.behavior_events = deque(maxlen=max_events)
        self.process_behaviors = defaultdict(list)
        
        # Monitoring state
        self.monitoring = False
        self.monitor_thread = None
        
        # Behavior patterns
        self.malware_patterns = self._load_malware_patterns()
        
        # Callbacks for detected threats
        self.threat_callbacks: List[Callable] = []
        
        # Process whitelist - platform specific
        default_whitelist = self._get_default_whitelist()
        self.process_whitelist = set(config.get('process_whitelist', default_whitelist))
        
        # Risk thresholds
        self.risk_thresholds = config.get('risk_thresholds', {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.9
        })
        
        # Process tracking
        self.process_history = defaultdict(list)
        self.last_process_scan = 0
        
        # Performance tracking
        self.performance_stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'processing_time': 0.0
        }
    
    def _get_default_whitelist(self) -> List[str]:
        """Get default process whitelist based on platform"""
        if self.platform == 'windows':
            return [
                'explorer.exe', 'svchost.exe', 'winlogon.exe', 'csrss.exe',
                'lsass.exe', 'smss.exe', 'wininit.exe', 'services.exe',
                'dwm.exe', 'conhost.exe', 'audiodg.exe'
            ]
        elif self.platform == 'linux':
            return [
                'systemd', 'kthreadd', 'ksoftirqd', 'init'
            ]
        elif self.platform == 'darwin':  # macOS
            return [
                'kernel_task', 'launchd', 'UserEventAgent', 'cfprefsd',
                'loginwindow', 'Dock', 'Finder', 'WindowServer'
            ]
        else:
            return []
    
    def _load_malware_patterns(self) -> Dict:
        """Load known malware behavior patterns"""
        return {
            'ransomware': {
                'file_operations': {
                    'mass_encryption': {'weight': 0.8, 'threshold': 50},
                    'file_extensions': {
                        'weight': 0.6, 
                        'patterns': ['.encrypted', '.locked', '.crypto', '.crypt', '.enc']
                    },
                    'ransom_notes': {
                        'weight': 0.9, 
                        'patterns': ['README', 'DECRYPT', 'RANSOM', 'RECOVERY', 'HOW_TO_DECRYPT']
                    }
                },
                'network_activity': {
                    'tor_communication': {'weight': 0.7},
                    'bitcoin_addresses': {'weight': 0.8}
                }
            },
            'trojan': {
                'process_creation': {
                    'suspicious_spawning': {'weight': 0.6},
                    'system_process_masquerading': {'weight': 0.8}
                },
                'network_activity': {
                    'c2_communication': {'weight': 0.9},
                    'data_exfiltration': {'weight': 0.7}
                }
            },
            'cryptominer': {
                'process_creation': {
                    'mining_processes': {
                        'weight': 0.8, 
                        'patterns': ['xmrig', 'cpuminer', 'cgminer', 'bfgminer', 'sgminer']
                    },
                    'high_cpu_usage': {'weight': 0.6, 'threshold': 80}
                },
                'network_activity': {
                    'mining_pools': {
                        'weight': 0.9, 
                        'patterns': ['pool', 'stratum', 'mining']
                    }
                }
            },
            'spyware': {
                'file_operations': {
                    'keylogger_files': {
                        'weight': 0.8,
                        'patterns': ['keylog', 'keystroke', 'password', 'credential']
                    }
                },
                'network_activity': {
                    'data_theft': {'weight': 0.7}
                }
            }
        }
    
    def start_monitoring(self):
        """Start behavioral monitoring"""
        if self.monitoring:
            self.logger.warning("Behavioral monitoring already running")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Behavioral monitoring started")
    
    def stop_monitoring(self):
        """Stop behavioral monitoring"""
        if not self.monitoring:
            return
        
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        self.logger.info("Behavioral monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        monitor_interval = self.config.get('monitor_interval', 1)
        
        while self.monitoring:
            try:
                start_time = time.time()
                
                # Monitor running processes
                self._monitor_processes()
                
                # Monitor network connections
                self._monitor_network()
                
                # Analyze accumulated behaviors
                self._analyze_behaviors()
                
                # Update performance stats
                processing_time = time.time() - start_time
                self.performance_stats['processing_time'] += processing_time
                
                # Sleep for the remaining interval
                sleep_time = max(0, monitor_interval - processing_time)
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _monitor_processes(self):
        """Monitor process activities"""
        current_time = time.time()
        
        # Limit process scanning frequency
        if current_time - self.last_process_scan < 5:  # Scan every 5 seconds
            return
        
        self.last_process_scan = current_time
        
        try:
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    name = proc_info['name']
                    
                    current_processes.add(pid)
                    
                    # Skip whitelisted processes
                    if name and name.lower() in [p.lower() for p in self.process_whitelist]:
                        continue
                    
                    # Check for new processes
                    if pid not in self.process_history:
                        self._handle_new_process(proc_info)
                    
                    # Check for suspicious CPU usage
                    cpu_percent = proc_info.get('cpu_percent', 0)
                    if cpu_percent and cpu_percent > 80:
                        self._handle_high_cpu_usage(proc_info)
                    
                    # Check for process masquerading
                    if self._is_process_masquerading(name):
                        self._handle_process_masquerading(proc_info)
                    
                    # Update process history
                    self.process_history[pid].append({
                        'timestamp': current_time,
                        'cpu_percent': cpu_percent,
                        'memory_percent': proc_info.get('memory_percent', 0)
                    })
                    
                    # Limit history size
                    if len(self.process_history[pid]) > 100:
                        self.process_history[pid] = self.process_history[pid][-50:]
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Clean up history for terminated processes
            terminated_pids = set(self.process_history.keys()) - current_processes
            for pid in terminated_pids:
                del self.process_history[pid]
                    
        except Exception as e:
            self.logger.error(f"Error monitoring processes: {e}")
    
    def _handle_new_process(self, proc_info: Dict):
        """Handle detection of new process"""
        try:
            pid = proc_info['pid']
            name = proc_info['name']
            
            # Check for suspicious process names
            suspicious_names = [
                'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                'regsvr32.exe', 'rundll32.exe', 'mshta.exe'
            ]
            
            if name and name.lower() in [s.lower() for s in suspicious_names]:
                event = BehaviorEvent(
                    timestamp=time.time(),
                    process_id=pid,
                    process_name=name,
                    behavior_type=BehaviorType.PROCESS_CREATION,
                    details={
                        'reason': 'suspicious_process_name',
                        'process_name': name,
                        'create_time': proc_info.get('create_time', 0)
                    },
                    risk_score=0.5
                )
                self._add_behavior_event(event)
        
        except Exception as e:
            self.logger.debug(f"Error handling new process: {e}")
    
    def _handle_high_cpu_usage(self, proc_info: Dict):
        """Handle high CPU usage detection"""
        try:
            pid = proc_info['pid']
            name = proc_info['name']
            cpu_percent = proc_info['cpu_percent']
            
            # Check if this is a known CPU-intensive process
            if not self._is_cpu_intensive_process(name):
                event = BehaviorEvent(
                    timestamp=time.time(),
                    process_id=pid,
                    process_name=name,
                    behavior_type=BehaviorType.PROCESS_CREATION,
                    details={
                        'reason': 'high_cpu_usage',
                        'cpu_usage': cpu_percent,
                        'memory_usage': proc_info.get('memory_percent', 0)
                    },
                    risk_score=0.4
                )
                self._add_behavior_event(event)
        
        except Exception as e:
            self.logger.debug(f"Error handling high CPU usage: {e}")
    
    def _handle_process_masquerading(self, proc_info: Dict):
        """Handle process masquerading detection"""
        try:
            pid = proc_info['pid']
            name = proc_info['name']
            
            event = BehaviorEvent(
                timestamp=time.time(),
                process_id=pid,
                process_name=name,
                behavior_type=BehaviorType.PROCESS_CREATION,
                details={
                    'reason': 'process_masquerading',
                    'suspicious_name': name
                },
                risk_score=0.8
            )
            self._add_behavior_event(event)
        
        except Exception as e:
            self.logger.debug(f"Error handling process masquerading: {e}")
    
    def _monitor_network(self):
        """Monitor network connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    # Check for suspicious connections
                    if self._is_suspicious_connection(conn):
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            proc_name = proc.name() if proc else "unknown"
                            
                            event = BehaviorEvent(
                                timestamp=time.time(),
                                process_id=conn.pid or 0,
                                process_name=proc_name,
                                behavior_type=BehaviorType.NETWORK_ACTIVITY,
                                details={
                                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                    'connection_type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                                    'reason': 'suspicious_destination'
                                },
                                risk_score=0.6
                            )
                            self._add_behavior_event(event)
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
        except Exception as e:
            self.logger.error(f"Error monitoring network: {e}")
    
    def _is_process_masquerading(self, process_name: str) -> bool:
        """Check if process is masquerading as a system process"""
        if not process_name:
            return False
        
        # Get system processes based on platform
        if self.platform == 'windows':
            system_processes = {
                'svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe',
                'lsass.exe', 'smss.exe', 'wininit.exe', 'services.exe'
            }
        elif self.platform == 'linux':
            system_processes = {
                'systemd', 'kthreadd', 'ksoftirqd', 'init'
            }
        else:
            return False
        
        process_lower = process_name.lower()
        
        # Check for slight variations in system process names
        for sys_proc in system_processes:
            sys_proc_lower = sys_proc.lower()
            if process_lower != sys_proc_lower:
                # Check for character substitution (e.g., svchost.exe -> svch0st.exe)
                if self._similar_strings(process_lower, sys_proc_lower, threshold=0.8):
                    return True
        
        return False
    
    def _is_suspicious_connection(self, conn) -> bool:
        """Check if network connection is suspicious"""
        if not conn.raddr:
            return False
        
        # Check for connections to suspicious ports
        suspicious_ports = self.config.get('suspicious_ports', [
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337
        ])
        
        if conn.raddr.port in suspicious_ports:
            return True
        
        # Check for Tor network (simplified detection)
        if conn.raddr.port in [9050, 9051]:
            return True
        
        # Check for connections to private IP ranges from public IPs (potential tunneling)
        try:
            import ipaddress
            local_ip = ipaddress.ip_address(conn.laddr.ip)
            remote_ip = ipaddress.ip_address(conn.raddr.ip)
            
            # Suspicious if connecting from private to private on unusual ports
            if (local_ip.is_private and remote_ip.is_private and 
                conn.raddr.port > 10000):
                return True
                
        except (ValueError, AttributeError):
            pass
        
        return False
    
    def _is_cpu_intensive_process(self, process_name: str) -> bool:
        """Check if process is known to be CPU intensive"""
        if not process_name:
            return False
        
        cpu_intensive_processes = self.config.get('cpu_intensive_processes', [
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe',
            'photoshop.exe', 'premiere.exe', 'blender.exe',
            'java.exe', 'javaw.exe', 'idea64.exe', 'code.exe',
            'python.exe', 'node.exe', 'gcc', 'clang'
        ])
        
        return process_name.lower() in [p.lower() for p in cpu_intensive_processes]
    
    def _similar_strings(self, s1: str, s2: str, threshold: float = 0.8) -> bool:
        """Check if two strings are similar using simple character matching"""
        if len(s1) != len(s2):
            return False
        
        if not s1 or not s2:
            return False
        
        matches = sum(c1 == c2 for c1, c2 in zip(s1, s2))
        similarity = matches / len(s1)
        return similarity >= threshold
    
    def _add_behavior_event(self, event: BehaviorEvent):
        """Add a behavior event to the analysis queue"""
        self.behavior_events.append(event)
        self.process_behaviors[event.process_id].append(event)
        self.performance_stats['events_processed'] += 1
        
        # Trigger immediate analysis for high-risk events
        if event.risk_score >= self.risk_thresholds['high']:
            self._analyze_process_behavior(event.process_id)
    
    def _analyze_behaviors(self):
        """Analyze accumulated behaviors for threats"""
        try:
            # Analyze behaviors for each process
            for process_id in list(self.process_behaviors.keys()):
                self._analyze_process_behavior(process_id)
            
            # Clean up old events
            self._cleanup_old_events()
            
        except Exception as e:
            self.logger.error(f"Error analyzing behaviors: {e}")
    
    def _analyze_process_behavior(self, process_id: int):
        """Analyze behavior patterns for a specific process"""
        try:
            events = self.process_behaviors.get(process_id, [])
            if not events:
                return
            
            # Group events by type
            event_groups = defaultdict(list)
            for event in events:
                event_groups[event.behavior_type].append(event)
            
            # Calculate overall risk score
            total_risk = 0.0
            pattern_matches = []
            
            # Check against known malware patterns
            for malware_type, patterns in self.malware_patterns.items():
                match_score = self._match_behavior_pattern(event_groups, patterns)
                if match_score > 0.5:
                    pattern_matches.append((malware_type, match_score))
                    total_risk = max(total_risk, match_score)
            
            # Trigger threat callback if risk is significant
            if total_risk >= self.risk_thresholds['medium']:
                threat_info = {
                    'process_id': process_id,
                    'process_name': events[0].process_name if events else 'unknown',
                    'risk_score': total_risk,
                    'pattern_matches': pattern_matches,
                    'event_count': len(events),
                    'behaviors': [asdict(event) for event in events[-10:]]  # Last 10 events
                }
                
                self._trigger_threat_detection(threat_info)
                
        except Exception as e:
            self.logger.error(f"Error analyzing process behavior for PID {process_id}: {e}")
    
    def _match_behavior_pattern(self, event_groups: Dict, patterns: Dict) -> float:
        """Match event groups against malware behavior patterns"""
        try:
            total_score = 0.0
            matched_patterns = 0
            
            for behavior_category, pattern_rules in patterns.items():
                # Map behavior category to enum
                behavior_enum = None
                for bt in BehaviorType:
                    if bt.value.replace('_', '') == behavior_category.replace('_', ''):
                        behavior_enum = bt
                        break
                
                if not behavior_enum or behavior_enum not in event_groups:
                    continue
                
                events = event_groups[behavior_enum]
                pattern_score = self._evaluate_pattern_rules(events, pattern_rules)
                
                if pattern_score > 0:
                    total_score += pattern_score
                    matched_patterns += 1
            
            # Normalize score
            return total_score / len(patterns) if patterns else 0.0
            
        except Exception as e:
            self.logger.debug(f"Error matching behavior pattern: {e}")
            return 0.0
    
    def _evaluate_pattern_rules(self, events: List[BehaviorEvent], rules: Dict) -> float:
        """Evaluate specific pattern rules against events"""
        try:
            max_score = 0.0
            
            for rule_name, rule_config in rules.items():
                rule_score = 0.0
                weight = rule_config.get('weight', 0.5)
                
                if rule_name == 'mass_encryption':
                    # Check for rapid file operations
                    file_ops = len([e for e in events if 'file_operation' in str(e.details)])
                    threshold = rule_config.get('threshold', 50)
                    if file_ops >= threshold:
                        rule_score = weight
                
                elif rule_name == 'file_extensions':
                    # Check for suspicious file extensions
                    patterns = rule_config.get('patterns', [])
                    for event in events:
                        details_str = str(event.details).lower()
                        if any(pattern.lower() in details_str for pattern in patterns):
                            rule_score = weight
                            break
                
                elif rule_name == 'high_cpu_usage':
                    # Check for high CPU usage
                    threshold = rule_config.get('threshold', 80)
                    for event in events:
                        cpu_usage = event.details.get('cpu_usage', 0)
                        if cpu_usage >= threshold:
                            rule_score = weight
                            break
                
                elif rule_name == 'mining_processes':
                    # Check for mining process patterns
                    patterns = rule_config.get('patterns', [])
                    for event in events:
                        process_name = event.process_name.lower()
                        if any(pattern.lower() in process_name for pattern in patterns):
                            rule_score = weight
                            break
                
                max_score = max(max_score, rule_score)
            
            return max_score
            
        except Exception as e:
            self.logger.debug(f"Error evaluating pattern rules: {e}")
            return 0.0
    
    def _trigger_threat_detection(self, threat_info: Dict):
        """Trigger threat detection callbacks"""
        self.logger.warning(f"Behavioral threat detected: {threat_info}")
        self.performance_stats['threats_detected'] += 1
        
        for callback in self.threat_callbacks:
            try:
                callback(threat_info)
            except Exception as e:
                self.logger.error(f"Error in threat callback: {e}")
    
    def _cleanup_old_events(self):
        """Clean up old behavior events"""
        try:
            current_time = time.time()
            retention_period = self.config.get('event_retention_hours', 24) * 3600
            
            # Clean up process behaviors
            for process_id in list(self.process_behaviors.keys()):
                events = self.process_behaviors[process_id]
                recent_events = [e for e in events if current_time - e.timestamp < retention_period]
                
                if recent_events:
                    self.process_behaviors[process_id] = recent_events
                else:
                    del self.process_behaviors[process_id]
                    
        except Exception as e:
            self.logger.error(f"Error cleaning up old events: {e}")
    
    def add_threat_callback(self, callback: Callable):
        """Add a callback for threat detection"""
        if callable(callback):
            self.threat_callbacks.append(callback)
        else:
            raise ValueError("Callback must be callable")
    
    def get_process_risk_score(self, process_id: int) -> float:
        """Get risk score for a specific process"""
        events = self.process_behaviors.get(process_id, [])
        if not events:
            return 0.0
        
        return max(event.risk_score for event in events)
    
    def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent behavior events"""
        recent_events = list(self.behavior_events)[-limit:]
        return [asdict(event) for event in recent_events]
    
    def export_behavior_data(self, filepath: str):
        """Export behavior data to JSON file"""
        try:
            data = {
                'events': [asdict(event) for event in self.behavior_events],
                'process_behaviors': {
                    str(pid): [asdict(event) for event in events]
                    for pid, events in self.process_behaviors.items()
                },
                'performance_stats': self.performance_stats,
                'export_timestamp': time.time()
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            self.logger.info(f"Behavior data exported to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error exporting behavior data: {e}")
    
    def get_statistics(self) -> Dict:
        """Get behavioral analysis statistics"""
        stats = self.performance_stats.copy()
        
        # Add current state information
        stats.update({
            'monitoring_active': self.monitoring,
            'total_events_stored': len(self.behavior_events),
            'processes_tracked': len(self.process_behaviors),
            'threat_callbacks_registered': len(self.threat_callbacks),
            'platform': self.platform
        })
        
        # Calculate rates if applicable
        if stats['events_processed'] > 0:
            stats['avg_processing_time'] = stats['processing_time'] / stats['events_processed']
            stats['threat_detection_rate'] = stats['threats_detected'] / stats['events_processed']
        else:
            stats['avg_processing_time'] = 0.0
            stats['threat_detection_rate'] = 0.0
        
        return stats
    
    def reset_statistics(self):
        """Reset performance statistics"""
        self.performance_stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'processing_time': 0.0
        }
        self.logger.info("Performance statistics reset")
    
    def clear_all_data(self):
        """Clear all stored behavioral data"""
        self.behavior_events.clear()
        self.process_behaviors.clear()
        self.process_history.clear()
        self.reset_statistics()
        self.logger.info("All behavioral data cleared")