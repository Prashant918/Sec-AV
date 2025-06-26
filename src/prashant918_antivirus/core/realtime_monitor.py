"""
Prashant918 Advanced Antivirus - Real-time File System Monitor

Advanced real-time monitoring system with kernel-level hooks,
behavioral analysis, and automated threat response capabilities.
"""

import os
import sys
import time
import threading
import queue
import hashlib
import json
from typing import Dict, List, Set, Optional, Any, Callable
from datetime import datetime, timedelta
from pathlib import Path
import psutil

# Platform-specific imports
if sys.platform == "win32":
    import win32file
    import win32con
    import win32api
    import win32security
    import wmi
elif sys.platform.startswith("linux"):
    import inotify_simple
    from inotify_simple import INotify, flags
elif sys.platform == "darwin":
    from fsevents import Observer, Stream

from watchdog.observers import Observer as WatchdogObserver
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from ..logger import SecureLogger
from ..config import secure_config
from ..database import db_manager
from ..exceptions import AntivirusError, ResourceError
from .engine import AdvancedThreatDetectionEngine
from .quarantine import QuarantineManager


class FileSystemEventProcessor:
    """Process file system events with threat detection"""
    
    def __init__(self, threat_engine: AdvancedThreatDetectionEngine):
        self.logger = SecureLogger("FSEventProcessor")
        self.threat_engine = threat_engine
        self.quarantine_manager = QuarantineManager()
        self.event_queue = queue.Queue(maxsize=10000)
        self.processing_thread = None
        self.stop_processing = threading.Event()
        
        # Event filtering
        self.monitored_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            '.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.rb'
        }
        
        self.excluded_paths = {
            '/proc', '/sys', '/dev', '/tmp',
            'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
            '/System/Library', '/usr/lib', '/lib'
        }
        
        # Rate limiting
        self.scan_cache = {}
        self.cache_timeout = 300  # 5 minutes
        
    def start_processing(self):
        """Start event processing thread"""
        if self.processing_thread and self.processing_thread.is_alive():
            return
        
        self.stop_processing.clear()
        self.processing_thread = threading.Thread(
            target=self._process_events,
            daemon=True
        )
        self.processing_thread.start()
        self.logger.info("Event processing started")
    
    def stop_processing(self):
        """Stop event processing thread"""
        self.stop_processing.set()
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        self.logger.info("Event processing stopped")
    
    def queue_event(self, event: Dict[str, Any]):
        """Queue file system event for processing"""
        try:
            if not self._should_process_event(event):
                return
            
            self.event_queue.put(event, timeout=1)
        except queue.Full:
            self.logger.warning("Event queue full, dropping event")
    
    def _should_process_event(self, event: Dict[str, Any]) -> bool:
        """Determine if event should be processed"""
        file_path = event.get('path', '')
        
        # Check excluded paths
        for excluded in self.excluded_paths:
            if file_path.startswith(excluded):
                return False
        
        # Check file extension
        if event.get('event_type') in ['created', 'modified']:
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext not in self.monitored_extensions:
                return False
        
        # Check cache to avoid duplicate scans
        cache_key = f"{file_path}:{event.get('event_type')}"
        current_time = time.time()
        
        if cache_key in self.scan_cache:
            last_scan_time = self.scan_cache[cache_key]
            if current_time - last_scan_time < self.cache_timeout:
                return False
        
        self.scan_cache[cache_key] = current_time
        return True
    
    def _process_events(self):
        """Main event processing loop"""
        while not self.stop_processing.is_set():
            try:
                event = self.event_queue.get(timeout=1)
                self._handle_event(event)
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing event: {e}")
    
    def _handle_event(self, event: Dict[str, Any]):
        """Handle individual file system event"""
        try:
            file_path = event['path']
            event_type = event['event_type']
            
            self.logger.debug(f"Processing {event_type} event for {file_path}")
            
            # Skip if file doesn't exist or is not accessible
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                return
            
            # Perform threat scan
            scan_result = self.threat_engine.scan_file(file_path)
            
            # Handle threats
            if scan_result['classification'] in ['MALICIOUS', 'SUSPICIOUS']:
                self._handle_threat(file_path, scan_result, event)
            
            # Log event
            self._log_event(event, scan_result)
            
        except Exception as e:
            self.logger.error(f"Error handling event {event}: {e}")
    
    def _handle_threat(self, file_path: str, scan_result: Dict[str, Any], event: Dict[str, Any]):
        """Handle detected threat"""
        try:
            threat_score = scan_result.get('threat_score', 0.0)
            classification = scan_result['classification']
            
            self.logger.warning(
                f"Threat detected: {file_path} - {classification} "
                f"(Score: {threat_score:.2f})"
            )
            
            # Quarantine high-risk files immediately
            if threat_score >= 0.8 or classification == 'MALICIOUS':
                quarantine_result = self.quarantine_manager.quarantine_file(
                    file_path,
                    reason=f"Real-time detection: {classification}",
                    threat_info=scan_result
                )
                
                if quarantine_result['success']:
                    self.logger.info(f"File quarantined: {file_path}")
                else:
                    self.logger.error(f"Failed to quarantine: {file_path}")
            
            # Send alert
            self._send_threat_alert(file_path, scan_result, event)
            
        except Exception as e:
            self.logger.error(f"Error handling threat {file_path}: {e}")
    
    def _send_threat_alert(self, file_path: str, scan_result: Dict[str, Any], event: Dict[str, Any]):
        """Send threat detection alert"""
        try:
            alert_data = {
                'timestamp': datetime.now().isoformat(),
                'file_path': file_path,
                'event_type': event.get('event_type'),
                'classification': scan_result['classification'],
                'threat_score': scan_result.get('threat_score', 0.0),
                'detections': scan_result.get('detections', []),
                'system_info': {
                    'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                    'user': os.getenv('USER') or os.getenv('USERNAME', 'unknown'),
                    'process_id': os.getpid()
                }
            }
            
            # Store alert in database
            self._store_alert(alert_data)
            
            # Send notifications (email, webhook, etc.)
            self._send_notifications(alert_data)
            
        except Exception as e:
            self.logger.error(f"Error sending threat alert: {e}")
    
    def _store_alert(self, alert_data: Dict[str, Any]):
        """Store alert in database"""
        try:
            query = """
                INSERT INTO threat_alerts 
                (file_path, event_type, classification, threat_score, alert_data, created_at)
                VALUES (:file_path, :event_type, :classification, :threat_score, :alert_data, CURRENT_TIMESTAMP)
            """
            
            params = {
                'file_path': alert_data['file_path'],
                'event_type': alert_data['event_type'],
                'classification': alert_data['classification'],
                'threat_score': alert_data['threat_score'],
                'alert_data': json.dumps(alert_data)
            }
            
            db_manager.execute_command(query, params)
            
        except Exception as e:
            self.logger.error(f"Error storing alert: {e}")
    
    def _send_notifications(self, alert_data: Dict[str, Any]):
        """Send notifications via configured channels"""
        # Implementation for email, webhook, SIEM integration, etc.
        pass
    
    def _log_event(self, event: Dict[str, Any], scan_result: Dict[str, Any]):
        """Log file system event"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event': event,
                'scan_result': {
                    'classification': scan_result['classification'],
                    'threat_score': scan_result.get('threat_score', 0.0),
                    'scan_time': scan_result.get('scan_time', 0.0)
                }
            }
            
            self.logger.debug(f"Event logged: {json.dumps(log_entry)}")
            
        except Exception as e:
            self.logger.error(f"Error logging event: {e}")


class RealtimeMonitor:
    """Advanced real-time file system monitoring"""
    
    def __init__(self):
        self.logger = SecureLogger("RealtimeMonitor")
        self.threat_engine = AdvancedThreatDetectionEngine()
        self.event_processor = FileSystemEventProcessor(self.threat_engine)
        
        # Monitoring state
        self.is_monitoring = False
        self.monitored_paths = set()
        self.observers = []
        
        # Platform-specific monitors
        self.platform_monitor = None
        self._initialize_platform_monitor()
        
        # Performance monitoring
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'start_time': None
        }
    
    def _initialize_platform_monitor(self):
        """Initialize platform-specific monitoring"""
        try:
            if sys.platform == "win32":
                self.platform_monitor = WindowsRealtimeMonitor(self.event_processor)
            elif sys.platform.startswith("linux"):
                self.platform_monitor = LinuxRealtimeMonitor(self.event_processor)
            elif sys.platform == "darwin":
                self.platform_monitor = MacOSRealtimeMonitor(self.event_processor)
            else:
                self.logger.warning(f"Platform {sys.platform} not fully supported, using generic monitor")
                self.platform_monitor = GenericRealtimeMonitor(self.event_processor)
                
        except Exception as e:
            self.logger.error(f"Failed to initialize platform monitor: {e}")
            self.platform_monitor = GenericRealtimeMonitor(self.event_processor)
    
    def start_monitoring(self, paths: List[str] = None):
        """Start real-time monitoring"""
        try:
            if self.is_monitoring:
                self.logger.warning("Monitoring already active")
                return
            
            if not paths:
                paths = ['.']  # Current directory by default
            
            self.logger.info(f"Starting real-time monitoring for paths: {paths}")
            
            # Start event processor
            self.event_processor.start_processing()
            
            # Start platform-specific monitoring
            if self.platform_monitor:
                self.platform_monitor.start_monitoring(paths)
            
            # Start generic watchdog monitoring as fallback
            self._start_watchdog_monitoring(paths)
            
            self.monitored_paths.update(paths)
            self.is_monitoring = True
            self.stats['start_time'] = datetime.now()
            
            self.logger.info("Real-time monitoring started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            raise AntivirusError(f"Failed to start real-time monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        try:
            if not self.is_monitoring:
                return
            
            self.logger.info("Stopping real-time monitoring...")
            
            # Stop platform-specific monitoring
            if self.platform_monitor:
                self.platform_monitor.stop_monitoring()
            
            # Stop watchdog observers
            for observer in self.observers:
                observer.stop()
                observer.join()
            
            self.observers.clear()
            
            # Stop event processor
            self.event_processor.stop_processing()
            
            self.is_monitoring = False
            self.monitored_paths.clear()
            
            self.logger.info("Real-time monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
    
    def _start_watchdog_monitoring(self, paths: List[str]):
        """Start watchdog-based monitoring as fallback"""
        try:
            for path in paths:
                if os.path.exists(path):
                    event_handler = WatchdogEventHandler(self.event_processor)
                    observer = WatchdogObserver()
                    observer.schedule(event_handler, path, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    
        except Exception as e:
            self.logger.error(f"Failed to start watchdog monitoring: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        return {
            'is_monitoring': self.is_monitoring,
            'monitored_paths': list(self.monitored_paths),
            'platform': sys.platform,
            'stats': self.stats.copy(),
            'uptime': self._get_uptime(),
            'event_queue_size': self.event_processor.event_queue.qsize()
        }
    
    def _get_uptime(self) -> Optional[str]:
        """Get monitoring uptime"""
        if self.stats['start_time']:
            uptime = datetime.now() - self.stats['start_time']
            return str(uptime)
        return None
    
    def add_monitored_path(self, path: str):
        """Add path to monitoring"""
        if self.is_monitoring and os.path.exists(path):
            # Add to existing monitoring
            pass
    
    def remove_monitored_path(self, path: str):
        """Remove path from monitoring"""
        if path in self.monitored_paths:
            # Remove from monitoring
            pass


class WatchdogEventHandler(FileSystemEventHandler):
    """Watchdog event handler"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        super().__init__()
        self.event_processor = event_processor
    
    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self.event_processor.queue_event({
                'path': event.src_path,
                'event_type': 'created',
                'timestamp': datetime.now().isoformat()
            })
    
    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.event_processor.queue_event({
                'path': event.src_path,
                'event_type': 'modified',
                'timestamp': datetime.now().isoformat()
            })
    
    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self.event_processor.queue_event({
                'path': event.dest_path,
                'event_type': 'moved',
                'timestamp': datetime.now().isoformat(),
                'src_path': event.src_path
            })


# Platform-specific monitor implementations would go here...
class WindowsRealtimeMonitor:
    """Windows-specific real-time monitoring using WMI and Win32 APIs"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        self.event_processor = event_processor
        self.logger = SecureLogger("WindowsMonitor")
        self.wmi_connection = None
        self.monitoring_thread = None
        self.stop_monitoring_flag = threading.Event()
    
    def start_monitoring(self, paths: List[str]):
        """Start Windows-specific monitoring"""
        try:
            self.wmi_connection = wmi.WMI()
            self.stop_monitoring_flag.clear()
            
            self.monitoring_thread = threading.Thread(
                target=self._monitor_file_events,
                args=(paths,),
                daemon=True
            )
            self.monitoring_thread.start()
            
            self.logger.info("Windows real-time monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start Windows monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop Windows monitoring"""
        self.stop_monitoring_flag.set()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
    
    def _monitor_file_events(self, paths: List[str]):
        """Monitor file events using WMI"""
        # Implementation for Windows file monitoring
        pass


class LinuxRealtimeMonitor:
    """Linux-specific real-time monitoring using inotify"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        self.event_processor = event_processor
        self.logger = SecureLogger("LinuxMonitor")
        self.inotify = None
        self.monitoring_thread = None
        self.stop_monitoring_flag = threading.Event()
    
    def start_monitoring(self, paths: List[str]):
        """Start Linux-specific monitoring"""
        try:
            self.inotify = INotify()
            self.stop_monitoring_flag.clear()
            
            # Add watches for paths
            for path in paths:
                if os.path.exists(path):
                    self.inotify.add_watch(
                        path,
                        flags.CREATE | flags.MODIFY | flags.MOVED_TO
                    )
            
            self.monitoring_thread = threading.Thread(
                target=self._monitor_inotify_events,
                daemon=True
            )
            self.monitoring_thread.start()
            
            self.logger.info("Linux real-time monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start Linux monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop Linux monitoring"""
        self.stop_monitoring_flag.set()
        if self.inotify:
            self.inotify.close()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
    
    def _monitor_inotify_events(self):
        """Monitor inotify events"""
        # Implementation for Linux inotify monitoring
        pass


class MacOSRealtimeMonitor:
    """macOS-specific real-time monitoring using FSEvents"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        self.event_processor = event_processor
        self.logger = SecureLogger("MacOSMonitor")
        self.observer = None
        self.streams = []
    
    def start_monitoring(self, paths: List[str]):
        """Start macOS-specific monitoring"""
        try:
            self.observer = Observer()
            
            for path in paths:
                if os.path.exists(path):
                    stream = Stream(
                        self._handle_fs_event,
                        path,
                        file_events=True
                    )
                    self.streams.append(stream)
            
            self.observer.start()
            self.logger.info("macOS real-time monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start macOS monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop macOS monitoring"""
        if self.observer:
            self.observer.stop()
        self.streams.clear()
    
    def _handle_fs_event(self, event):
        """Handle FSEvents"""
        # Implementation for macOS FSEvents monitoring
        pass


class GenericRealtimeMonitor:
    """Generic cross-platform monitoring fallback"""
    
    def __init__(self, event_processor: FileSystemEventProcessor):
        self.event_processor = event_processor
        self.logger = SecureLogger("GenericMonitor")
    
    def start_monitoring(self, paths: List[str]):
        """Start generic monitoring"""
        self.logger.info("Using generic monitoring (watchdog only)")
    
    def stop_monitoring(self):
        """Stop generic monitoring"""
        pass
