"""
Prashant918 Advanced Antivirus - Enhanced Real-time Monitor
Cross-platform real-time file system monitoring with threat detection
"""

import os
import sys
import time
import threading
import queue
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum

# Platform detection
import platform
PLATFORM = platform.system().lower()

# Core imports with error handling
try:
    from ..logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from ..config import secure_config
except ImportError:
    secure_config = type('Config', (), {'get': lambda self, key, default=None: default})()

try:
    from ..exceptions import AntivirusError
except ImportError:
    class AntivirusError(Exception): pass

# Optional imports for enhanced functionality
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    Observer = None
    FileSystemEventHandler = None
    FileSystemEvent = None

# Platform-specific imports
if PLATFORM == "windows":
    try:
        import win32file
        import win32con
        import win32api
        HAS_WIN32 = True
    except ImportError:
        HAS_WIN32 = False
elif PLATFORM == "linux":
    try:
        import select
        HAS_INOTIFY = True
    except ImportError:
        HAS_INOTIFY = False
elif PLATFORM == "darwin":
    try:
        import select
        HAS_FSEVENTS = True
    except ImportError:
        HAS_FSEVENTS = False

class EventType(Enum):
    """File system event types"""
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"
    ACCESSED = "accessed"

class ThreatAction(Enum):
    """Actions to take when threat is detected"""
    QUARANTINE = "quarantine"
    DELETE = "delete"
    ALERT = "alert"
    BLOCK = "block"

@dataclass
class FileSystemEvent:
    """File system event data structure"""
    event_type: EventType
    file_path: str
    timestamp: datetime
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ThreatDetection:
    """Threat detection result"""
    file_path: str
    threat_name: str
    threat_level: str
    confidence: float
    detection_method: str
    action_taken: ThreatAction
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

class FileSystemEventProcessor:
    """Process file system events and detect threats"""
    
    def __init__(self, threat_engine=None, quarantine_manager=None):
        self.logger = SecureLogger("EventProcessor")
        self.threat_engine = threat_engine
        self.quarantine_manager = quarantine_manager
        
        # Event processing
        self.event_queue = queue.Queue(maxsize=10000)
        self.processing_thread = None
        self.is_processing = False
        
        # Configuration
        self.monitored_extensions = set(secure_config.get("monitoring.extensions", [
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", 
            ".jar", ".app", ".deb", ".rpm", ".dmg", ".msi", ".pkg"
        ]))
        
        self.excluded_paths = set(secure_config.get("monitoring.excluded_paths", [
            "/proc", "/sys", "/dev", "/tmp", "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64", "/System", "/Library/Caches"
        ]))
        
        # Scan cache to avoid duplicate scans
        self.scan_cache = {}
        self.cache_timeout = 300  # 5 minutes
        self.cache_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'files_blocked': 0,
            'cache_hits': 0,
            'processing_errors': 0
        }
    
    def start_processing(self):
        """Start event processing"""
        if self.is_processing:
            return
        
        self.is_processing = True
        self.processing_thread = threading.Thread(target=self._process_events, daemon=True)
        self.processing_thread.start()
        
        self.logger.info("Event processing started")
    
    def stop_processing(self):
        """Stop event processing"""
        self.is_processing = False
        
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5)
        
        self.logger.info("Event processing stopped")
    
    def queue_event(self, event: FileSystemEvent):
        """Queue file system event for processing"""
        try:
            if not self._should_process_event(event):
                return
            
            self.event_queue.put(event, timeout=1)
            
        except queue.Full:
            self.logger.warning("Event queue is full, dropping event")
        except Exception as e:
            self.logger.error(f"Failed to queue event: {e}")
    
    def _should_process_event(self, event: FileSystemEvent) -> bool:
        """Check if event should be processed"""
        try:
            file_path = Path(event.file_path)
            
            # Check if file exists (for created/modified events)
            if event.event_type in [EventType.CREATED, EventType.MODIFIED]:
                if not file_path.exists() or not file_path.is_file():
                    return False
            
            # Check file extension
            if file_path.suffix.lower() not in self.monitored_extensions:
                return False
            
            # Check excluded paths
            file_str = str(file_path.absolute()).lower()
            for excluded_path in self.excluded_paths:
                if excluded_path.lower() in file_str:
                    return False
            
            # Check cache to avoid duplicate processing
            with self.cache_lock:
                cache_key = f"{event.file_path}_{event.event_type.value}"
                current_time = time.time()
                
                if cache_key in self.scan_cache:
                    last_scan_time = self.scan_cache[cache_key]
                    if current_time - last_scan_time < self.cache_timeout:
                        self.stats['cache_hits'] += 1
                        return False
                
                self.scan_cache[cache_key] = current_time
                
                # Clean old cache entries
                if len(self.scan_cache) > 1000:
                    self._clean_cache()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking event: {e}")
            return False
    
    def _process_events(self):
        """Main event processing loop"""
        while self.is_processing:
            try:
                # Get event from queue with timeout
                try:
                    event = self.event_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Process the event
                self._handle_event(event)
                self.stats['events_processed'] += 1
                
                # Mark task as done
                self.event_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Event processing error: {e}")
                self.stats['processing_errors'] += 1
    
    def _handle_event(self, event: FileSystemEvent):
        """Handle individual file system event"""
        try:
            # Skip if no threat engine available
            if not self.threat_engine:
                return
            
            # Scan file for threats
            scan_result = self.threat_engine.scan_file(event.file_path)
            
            if scan_result.threat_level.value in ['malware', 'critical']:
                threat_detection = ThreatDetection(
                    file_path=event.file_path,
                    threat_name=scan_result.threat_name or "Unknown threat",
                    threat_level=scan_result.threat_level.value,
                    confidence=scan_result.confidence,
                    detection_method=scan_result.detection_method,
                    action_taken=ThreatAction.QUARANTINE,
                    timestamp=datetime.now(),
                    metadata={
                        'event_type': event.event_type.value,
                        'scan_result': {
                            'heuristic_score': scan_result.heuristic_score,
                            'behavioral_score': scan_result.behavioral_score,
                            'ml_score': scan_result.ml_score,
                            'signature_score': scan_result.signature_score
                        }
                    }
                )
                
                self._handle_threat(threat_detection)
                
            elif scan_result.threat_level.value == 'suspicious':
                # Log suspicious files but don't quarantine
                self.logger.warning(f"Suspicious file detected: {event.file_path}")
                self._send_alert(event.file_path, "Suspicious file detected", scan_result.confidence)
            
        except Exception as e:
            self.logger.error(f"Error handling event for {event.file_path}: {e}")
    
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
    
    def _send_alert(self, file_path: str, message: str, confidence: float, 
                   threat_level: str = "unknown"):
        """Send threat alert"""
        try:
            alert_data = {
                'timestamp': datetime.now().isoformat(),
                'file_path': file_path,
                'message': message,
                'confidence': confidence,
                'threat_level': threat_level,
                'hostname': platform.node()
            }
            
            # Log alert
            self.logger.warning(f"ALERT: {message} - {file_path} (confidence: {confidence:.2f})")
            
            # Store alert (could be extended to send notifications)
            self._store_alert(alert_data)
            
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")
    
    def _store_alert(self, alert_data: Dict[str, Any]):
        """Store alert data"""
        try:
            # Simple file-based alert storage
            alerts_dir = Path.home() / ".prashant918_antivirus" / "alerts"
            alerts_dir.mkdir(parents=True, exist_ok=True)
            
            alert_file = alerts_dir / f"alert_{int(time.time())}.json"
            with open(alert_file, 'w') as f:
                json.dump(alert_data, f, indent=2)
            
        except Exception as e:
            self.logger.debug(f"Failed to store alert: {e}")
    
    def _clean_cache(self):
        """Clean old cache entries"""
        try:
            current_time = time.time()
            expired_keys = []
            
            for key, timestamp in self.scan_cache.items():
                if current_time - timestamp > self.cache_timeout:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.scan_cache[key]
            
        except Exception as e:
            self.logger.debug(f"Cache cleanup error: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return self.stats.copy()

class WatchdogEventHandler(FileSystemEventHandler):
    """Watchdog event handler"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        super().__init__()
        self.event_processor = event_processor
        self.logger = SecureLogger("WatchdogHandler")
    
    def on_created(self, event):
        """Handle file creation"""
        if not event.is_directory:
            fs_event = FileSystemEvent(
                event_type=EventType.CREATED,
                file_path=event.src_path,
                timestamp=datetime.now()
            )
            self.event_processor.queue_event(fs_event)
    
    def on_modified(self, event):
        """Handle file modification"""
        if not event.is_directory:
            fs_event = FileSystemEvent(
                event_type=EventType.MODIFIED,
                file_path=event.src_path,
                timestamp=datetime.now()
            )
            self.event_processor.queue_event(fs_event)
    
    def on_moved(self, event):
        """Handle file move"""
        if not event.is_directory:
            fs_event = FileSystemEvent(
                event_type=EventType.MOVED,
                file_path=event.dest_path,
                timestamp=datetime.now(),
                metadata={'src_path': event.src_path}
            )
            self.event_processor.queue_event(fs_event)

class GenericRealtimeMonitor:
    """Generic cross-platform monitor using watchdog"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        self.logger = SecureLogger("GenericMonitor")
        self.event_processor = event_processor
        self.observers = []
        self.is_monitoring = False
    
    def start_monitoring(self, paths: List[str]):
        """Start monitoring specified paths"""
        if not HAS_WATCHDOG:
            self.logger.warning("Watchdog not available, using generic monitor")
            self.is_monitoring = True
            return
        
        for path in paths:
            if os.path.exists(path):
                event_handler = WatchdogEventHandler(self.event_processor)
                observer = Observer()
                observer.schedule(event_handler, path, recursive=True)
                observer.start()
                self.observers.append(observer)
    
    def stop_monitoring(self):
        """Stop monitoring"""
        for observer in self.observers:
            observer.stop()
            observer.join()
        self.observers.clear()
        self.is_monitoring = False

class WindowsRealtimeMonitor:
    """Windows-specific real-time monitor"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        self.logger = SecureLogger("WindowsMonitor")
        self.event_processor = event_processor
        self.monitoring_threads = []
        self.is_monitoring = False
        self.stop_event = threading.Event()
    
    def start_monitoring(self, paths: List[str]):
        """Start Windows-specific monitoring"""
        if not HAS_WIN32:
            self.logger.warning("Win32 API not available, falling back to generic monitor")
            return False
        
        try:
            self.stop_monitoring()
            self.stop_event.clear()
            
            for path in paths:
                if Path(path).exists():
                    thread = threading.Thread(
                        target=self._monitor_directory,
                        args=(path,),
                        daemon=True
                    )
                    thread.start()
                    self.monitoring_threads.append(thread)
                    self.logger.info(f"Started Windows monitoring: {path}")
                else:
                    self.logger.warning(f"Path does not exist: {path}")
            
            self.is_monitoring = True
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start Windows monitoring: {e}")
            return False
    
    def _monitor_directory(self, path: str):
        """Monitor directory using Windows API"""
        try:
            path_handle = win32file.CreateFile(
                path,
                win32file.GENERIC_READ,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            while not self.stop_event.is_set():
                try:
                    results = win32file.ReadDirectoryChangesW(
                        path_handle,
                        1024,
                        True,
                        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                        win32con.FILE_NOTIFY_CHANGE_CREATION,
                        None,
                        None
                    )
                    
                    for action, filename in results:
                        if self.stop_event.is_set():
                            break
                        
                        full_path = os.path.join(path, filename)
                        event_type = self._map_windows_action(action)
                        
                        if event_type:
                            fs_event = FileSystemEvent(
                                event_type=event_type,
                                file_path=full_path,
                                timestamp=datetime.now()
                            )
                            self.event_processor.queue_event(fs_event)
                
                except Exception as e:
                    if not self.stop_event.is_set():
                        self.logger.error(f"Error in Windows directory monitoring: {e}")
                    break
            
            win32file.CloseHandle(path_handle)
            
        except Exception as e:
            self.logger.error(f"Failed to monitor directory {path}: {e}")
    
    def _map_windows_action(self, action: int) -> Optional[EventType]:
        """Map Windows file action to EventType"""
        action_map = {
            win32con.FILE_ACTION_ADDED: EventType.CREATED,
            win32con.FILE_ACTION_MODIFIED: EventType.MODIFIED,
            win32con.FILE_ACTION_REMOVED: EventType.DELETED,
            win32con.FILE_ACTION_RENAMED_OLD_NAME: EventType.MOVED,
            win32con.FILE_ACTION_RENAMED_NEW_NAME: EventType.MOVED,
        }
        return action_map.get(action)
    
    def stop_monitoring(self):
        """Stop Windows monitoring"""
        try:
            self.stop_event.set()
            
            for thread in self.monitoring_threads:
                thread.join(timeout=5)
            
            self.monitoring_threads.clear()
            self.is_monitoring = False
            self.logger.info("Windows monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping Windows monitoring: {e}")
    
    def is_active(self) -> bool:
        """Check if monitoring is active"""
        return self.is_monitoring and any(thread.is_alive() for thread in self.monitoring_threads)

class LinuxRealtimeMonitor:
    """Linux-specific real-time monitor using inotify"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        self.logger = SecureLogger("LinuxMonitor")
        self.event_processor = event_processor
        self.monitoring_thread = None
        self.is_monitoring = False
        self.stop_event = threading.Event()
        self.watch_descriptors = {}
    
    def start_monitoring(self, paths: List[str]):
        """Start Linux inotify monitoring"""
        if not HAS_INOTIFY:
            self.logger.warning("inotify not available, falling back to generic monitor")
            return False
        
        try:
            import inotify.adapters
            
            self.stop_monitoring()
            self.stop_event.clear()
            
            self.inotify = inotify.adapters.InotifyTree(paths)
            
            self.monitoring_thread = threading.Thread(
                target=self._monitor_events,
                daemon=True
            )
            self.monitoring_thread.start()
            
            self.is_monitoring = True
            self.logger.info(f"Started Linux inotify monitoring for: {paths}")
            return True
            
        except ImportError:
            self.logger.warning("inotify library not available")
            return False
        except Exception as e:
            self.logger.error(f"Failed to start Linux monitoring: {e}")
            return False
    
    def _monitor_events(self):
        """Monitor inotify events"""
        try:
            for event in self.inotify.event_gen(yield_nones=False):
                if self.stop_event.is_set():
                    break
                
                (_, type_names, path, filename) = event
                
                if filename:
                    full_path = os.path.join(path, filename)
                    event_type = self._map_inotify_event(type_names)
                    
                    if event_type:
                        fs_event = FileSystemEvent(
                            event_type=event_type,
                            file_path=full_path,
                            timestamp=datetime.now()
                        )
                        self.event_processor.queue_event(fs_event)
        
        except Exception as e:
            if not self.stop_event.is_set():
                self.logger.error(f"Error in Linux inotify monitoring: {e}")
    
    def _map_inotify_event(self, type_names: List[str]) -> Optional[EventType]:
        """Map inotify event types to EventType"""
        if 'IN_CREATE' in type_names:
            return EventType.CREATED
        elif 'IN_MODIFY' in type_names:
            return EventType.MODIFIED
        elif 'IN_DELETE' in type_names:
            return EventType.DELETED
        elif 'IN_MOVED_TO' in type_names or 'IN_MOVED_FROM' in type_names:
            return EventType.MOVED
        return None
    
    def stop_monitoring(self):
        """Stop Linux monitoring"""
        try:
            self.stop_event.set()
            
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=5)
            
            self.is_monitoring = False
            self.logger.info("Linux monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping Linux monitoring: {e}")
    
    def is_active(self) -> bool:
        """Check if monitoring is active"""
        return self.is_monitoring and (
            self.monitoring_thread and self.monitoring_thread.is_alive()
        )

class MacOSRealtimeMonitor:
    """macOS-specific real-time monitor using FSEvents"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        self.logger = SecureLogger("MacOSMonitor")
        self.event_processor = event_processor
        self.is_monitoring = False
    
    def start_monitoring(self, paths: List[str]):
        """Start macOS FSEvents monitoring"""
        self.logger.warning("macOS FSEvents monitoring not implemented, falling back to generic monitor")
        return False
    
    def stop_monitoring(self):
        """Stop macOS monitoring"""
        self.is_monitoring = False
    
    def is_active(self) -> bool:
        """Check if monitoring is active"""
        return self.is_monitoring

class RealtimeMonitor:
    """Main real-time monitoring coordinator"""
    
    def __init__(self, threat_engine=None, quarantine_manager=None):
        self.logger = SecureLogger("RealtimeMonitor")
        
        # Initialize event processor
        self.event_processor = FileSystemEventProcessor(threat_engine, quarantine_manager)
        
        # Choose platform-specific monitor
        self.platform_monitor = self._create_platform_monitor()
        
        # Monitoring state
        self.is_monitoring = False
        self.monitored_paths = set()
        self.start_time = None
        
        # Statistics
        self.stats = {
            'monitoring_sessions': 0,
            'total_uptime': 0,
            'paths_monitored': 0,
            'platform_monitor': type(self.platform_monitor).__name__
        }
    
    def _create_platform_monitor(self):
        """Create appropriate platform-specific monitor"""
        if PLATFORM == "windows" and HAS_WIN32:
            return WindowsRealtimeMonitor(self.event_processor)
        elif PLATFORM == "linux" and HAS_INOTIFY:
            return LinuxRealtimeMonitor(self.event_processor)
        elif PLATFORM == "darwin" and HAS_FSEVENTS:
            return MacOSRealtimeMonitor(self.event_processor)
        else:
            self.logger.info(f"Using generic monitor for platform: {PLATFORM}")
            return GenericRealtimeMonitor(self.event_processor)
    
    def start_monitoring(self, paths: List[str]):
        """Start real-time monitoring"""
        try:
            if self.is_monitoring:
                self.logger.warning("Monitoring already active")
                return True
            
            # Validate paths
            valid_paths = []
            for path in paths:
                path_obj = Path(path)
                if path_obj.exists():
                    valid_paths.append(str(path_obj.absolute()))
                else:
                    self.logger.warning(f"Path does not exist: {path}")
            
            if not valid_paths:
                self.logger.error("No valid paths to monitor")
                return False
            
            # Start event processor
            self.event_processor.start_processing()
            
            # Start platform-specific monitoring
            if self.platform_monitor.start_monitoring(valid_paths):
                self.is_monitoring = True
                self.monitored_paths = set(valid_paths)
                self.start_time = time.time()
                self.stats['monitoring_sessions'] += 1
                self.stats['paths_monitored'] = len(valid_paths)
                
                self.logger.info(f"Real-time monitoring started for {len(valid_paths)} paths")
                return True
            else:
                self.event_processor.stop_processing()
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        try:
            if not self.is_monitoring:
                return
            
            # Stop platform monitor
            self.platform_monitor.stop_monitoring()
            
            # Stop event processor
            self.event_processor.stop_processing()
            
            # Update statistics
            if self.start_time:
                session_uptime = time.time() - self.start_time
                self.stats['total_uptime'] += session_uptime
            
            self.is_monitoring = False
            self.monitored_paths.clear()
            self.start_time = None
            
            self.logger.info("Real-time monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
    
    def add_monitored_path(self, path: str) -> bool:
        """Add path to monitoring"""
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                self.logger.error(f"Path does not exist: {path}")
                return False
            
            abs_path = str(path_obj.absolute())
            
            if abs_path in self.monitored_paths:
                self.logger.info(f"Path already monitored: {path}")
                return True
            
            # Restart monitoring with updated paths
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
        try:
            current_uptime = 0
            if self.is_monitoring and self.start_time:
                current_uptime = time.time() - self.start_time
            
            processor_stats = self.event_processor.get_statistics()
            
            return {
                'is_monitoring': self.is_monitoring,
                'platform_monitor_active': self.platform_monitor.is_active() if hasattr(self.platform_monitor, 'is_active') else self.is_monitoring,
                'monitored_paths': list(self.monitored_paths),
                'current_uptime': current_uptime,
                'total_uptime': self.stats['total_uptime'] + current_uptime,
                'monitoring_sessions': self.stats['monitoring_sessions'],
                'platform_monitor': self.stats['platform_monitor'],
                'processor_stats': processor_stats,
                'capabilities': {
                    'has_watchdog': HAS_WATCHDOG,
                    'has_win32': HAS_WIN32,
                    'has_inotify': HAS_INOTIFY,
                    'has_fsevents': HAS_FSEVENTS,
                    'platform': PLATFORM
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting status: {e}")
            return {'error': str(e)}
    
    def _get_uptime(self) -> float:
        """Get current session uptime"""
        if self.is_monitoring and self.start_time:
            return time.time() - self.start_time
        return 0.0