"""
Real-time Monitor - Enhanced file system and threat monitoring
"""

import os
import time
import threading
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum

try:
    from ..logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from ..exceptions import AntivirusError
except ImportError:
    class AntivirusError(Exception):
        pass

# Optional imports
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    Observer = None
    FileSystemEventHandler = None
    FileSystemEvent = None

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatAction(Enum):
    """Action to take on threat detection"""
    NONE = "none"
    ALERT = "alert"
    QUARANTINE = "quarantine"
    DELETE = "delete"

@dataclass
class ThreatDetection:
    """Represents a detected threat"""
    file_path: str
    threat_name: str
    threat_level: ThreatLevel
    confidence: float
    detection_method: str
    timestamp: float
    action_taken: ThreatAction
    metadata: Dict[str, Any]

class FileSystemMonitorHandler(FileSystemEventHandler):
    """File system event handler for real-time monitoring"""
    
    def __init__(self, callback: Callable[[str, str], None]):
        super().__init__()
        self.callback = callback
        self.logger = SecureLogger("FileSystemMonitor")
        
        # Monitored file extensions
        self.monitored_extensions = {
            '.exe', '.dll', '.sys', '.com', '.scr', '.pif', '.bat', '.cmd',
            '.vbs', '.js', '.jar', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.ppt', '.pptx', '.zip', '.rar', '.7z', '.tar', '.gz'
        }
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self._handle_file_event(event.src_path, "created")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self._handle_file_event(event.src_path, "modified")
    
    def on_moved(self, event):
        """Handle file move events"""
        if not event.is_directory:
            self._handle_file_event(event.dest_path, "moved")
    
    def _handle_file_event(self, file_path: str, event_type: str):
        """Handle file system events"""
        try:
            path = Path(file_path)
            
            # Check if we should monitor this file
            if path.suffix.lower() in self.monitored_extensions:
                self.logger.debug(f"File {event_type}: {file_path}")
                self.callback(file_path, event_type)
                
        except Exception as e:
            self.logger.error(f"Error handling file event: {e}")

class RealtimeMonitor:
    """Enhanced real-time monitoring system"""
    
    def __init__(self, threat_engine=None, quarantine_manager=None):
        self.logger = SecureLogger("RealtimeMonitor")
        self.threat_engine = threat_engine
        self.quarantine_manager = quarantine_manager
        
        # Monitoring state
        self.is_monitoring = False
        self.observer = None
        self.monitored_paths: Set[str] = set()
        self.start_time = None
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'files_scanned': 0,
            'scan_errors': 0
        }
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Event handlers
        self.threat_callbacks: List[Callable] = []
        
        # Check dependencies
        if not HAS_WATCHDOG:
            self.logger.warning("Watchdog not available - file system monitoring disabled")
    
    def start_monitoring(self, paths: List[str]) -> bool:
        """Start real-time monitoring of specified paths"""
        try:
            if not HAS_WATCHDOG:
                self.logger.error("Cannot start monitoring - watchdog not available")
                return False
            
            if self.is_monitoring:
                self.logger.warning("Monitoring already active")
                return True
            
            # Validate paths
            valid_paths = []
            for path_str in paths:
                path = Path(path_str)
                if path.exists():
                    valid_paths.append(str(path.absolute()))
                else:
                    self.logger.warning(f"Path does not exist: {path}")
            
            if not valid_paths:
                self.logger.error("No valid paths to monitor")
                return False
            
            # Initialize observer
            self.observer = Observer()
            handler = FileSystemMonitorHandler(self._handle_file_event)
            
            # Schedule monitoring for each path
            for path in valid_paths:
                self.observer.schedule(handler, path, recursive=True)
                self.monitored_paths.add(path)
                self.logger.info(f"Monitoring path: {path}")
            
            # Start observer
            self.observer.start()
            self.is_monitoring = True
            self.start_time = time.time()
            
            self.logger.info(f"Real-time monitoring started for {len(valid_paths)} paths")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self) -> bool:
        """Stop real-time monitoring"""
        try:
            if not self.is_monitoring:
                self.logger.warning("Monitoring not active")
                return True
            
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=5.0)
                self.observer = None
            
            self.is_monitoring = False
            self.monitored_paths.clear()
            self.start_time = None
            
            self.logger.info("Real-time monitoring stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
            return False
    
    def _handle_file_event(self, file_path: str, event_type: str):
        """Handle file system events"""
        try:
            with self.lock:
                self.stats['events_processed'] += 1
            
            # Skip if no threat engine available
            if not self.threat_engine:
                self.logger.debug(f"No threat engine - skipping scan of {file_path}")
                return
            
            # Scan file in separate thread to avoid blocking
            scan_thread = threading.Thread(
                target=self._scan_file_async,
                args=(file_path, event_type),
                daemon=True
            )
            scan_thread.start()
            
        except Exception as e:
            self.logger.error(f"Error handling file event: {e}")
    
    def _scan_file_async(self, file_path: str, event_type: str):
        """Scan file asynchronously"""
        try:
            self.logger.debug(f"Scanning file: {file_path}")
            
            with self.lock:
                self.stats['files_scanned'] += 1
            
            # Perform scan
            result = self.threat_engine.scan_file(file_path)
            
            # Check if threat detected
            if result.get('status') == 'infected':
                threat = ThreatDetection(
                    file_path=file_path,
                    threat_name=result.get('threat_name', 'Unknown'),
                    threat_level=ThreatLevel.HIGH,
                    confidence=result.get('confidence', 0.0),
                    detection_method=result.get('detection_method', 'realtime'),
                    timestamp=time.time(),
                    action_taken=ThreatAction.QUARANTINE,
                    metadata={
                        'event_type': event_type,
                        'scan_result': result
                    }
                )
                
                self._handle_threat(threat)
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            with self.lock:
                self.stats['scan_errors'] += 1
    
    def _handle_threat(self, threat: ThreatDetection):
        """Handle detected threat"""
        try:
            self.logger.critical(f"THREAT DETECTED: {threat.threat_name} in {threat.file_path}")
            
            # Take action based on configuration
            action_taken = False
            
            if threat.action_taken == ThreatAction.QUARANTINE and self.quarantine_manager:
                try:
                    quarantine_id = self.quarantine_manager.quarantine_file(
                        threat.file_path,
                        threat.threat_name,
                        threat.detection_method,
                        threat.metadata
                    )
                    
                    if quarantine_id:
                        self.logger.info(f"File quarantined: {threat.file_path} -> {quarantine_id}")
                        self.stats['files_quarantined'] += 1
                        action_taken = True
                    
                except Exception as e:
                    self.logger.error(f"Quarantine failed: {e}")
            
            if not action_taken and threat.action_taken == ThreatAction.DELETE:
                try:
                    Path(threat.file_path).unlink()
                    self.logger.info(f"Threat file deleted: {threat.file_path}")
                    action_taken = True
                    
                except Exception as e:
                    self.logger.error(f"File deletion failed: {e}")
            
            # Send alert regardless of action taken
            self._send_alert(
                threat.file_path,
                f"THREAT: {threat.threat_name}",
                threat.confidence,
                threat.threat_level
            )
            
            self.stats['threats_detected'] += 1
            
        except Exception as e:
            self.logger.error(f"Error handling threat: {e}")
    
    def _send_alert(self, file_path: str, message: str, confidence: float, threat_level: ThreatLevel):
        """Send threat alert"""
        try:
            alert_data = {
                'timestamp': time.time(),
                'file_path': file_path,
                'message': message,
                'confidence': confidence,
                'threat_level': threat_level.value
            }
            
            # Call registered callbacks
            for callback in self.threat_callbacks:
                try:
                    callback(alert_data)
                except Exception as e:
                    self.logger.error(f"Error in threat callback: {e}")
            
            # Log alert
            self.logger.warning(f"ALERT: {message} (confidence: {confidence:.2f})")
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")
    
    def add_threat_callback(self, callback: Callable):
        """Add threat detection callback"""
        if callable(callback):
            self.threat_callbacks.append(callback)
        else:
            raise ValueError("Callback must be callable")
    
    def remove_threat_callback(self, callback: Callable):
        """Remove threat detection callback"""
        if callback in self.threat_callbacks:
            self.threat_callbacks.remove(callback)
    
    def add_monitored_path(self, path: str) -> bool:
        """Add path to monitoring"""
        try:
            abs_path = str(Path(path).absolute())
            
            if not Path(abs_path).exists():
                self.logger.error(f"Path does not exist: {path}")
                return False
            
            if abs_path in self.monitored_paths:
                self.logger.info(f"Path already monitored: {path}")
                return True
            
            # If monitoring is active, restart with new paths
            if self.is_monitoring:
                current_paths = list(self.monitored_paths)
                current_paths.append(abs_path)
                
                self.stop_monitoring()
                return self.start_monitoring(current_paths)
            else:
                self.monitored_paths.add(abs_path)
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to add monitored path: {e}")
            return False
    
    def remove_monitored_path(self, path: str) -> bool:
        """Remove path from monitoring"""
        try:
            abs_path = str(Path(path).absolute())
            
            if abs_path not in self.monitored_paths:
                self.logger.info(f"Path not monitored: {path}")
                return True
            
            # Restart monitoring with updated paths
            if self.is_monitoring:
                current_paths = list(self.monitored_paths)
                current_paths.remove(abs_path)
                
                self.stop_monitoring()
                if current_paths:
                    return self.start_monitoring(current_paths)
                else:
                    return True
            else:
                self.monitored_paths.discard(abs_path)
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to remove monitored path: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        uptime = time.time() - self.start_time if self.start_time else 0
        
        return {
            'is_monitoring': self.is_monitoring,
            'monitored_paths': list(self.monitored_paths),
            'current_uptime': uptime,
            'start_time': self.start_time,
            'processor_stats': self.stats.copy(),
            'has_watchdog': HAS_WATCHDOG,
            'has_threat_engine': self.threat_engine is not None,
            'has_quarantine_manager': self.quarantine_manager is not None
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        with self.lock:
            return self.stats.copy()
    
    def reset_statistics(self):
        """Reset monitoring statistics"""
        with self.lock:
            self.stats = {
                'events_processed': 0,
                'threats_detected': 0,
                'files_quarantined': 0,
                'files_scanned': 0,
                'scan_errors': 0
            }