"""
Prashant918 Advanced Antivirus - Enhanced Service Manager
Cross-platform service management with improved error handling and compatibility
"""

import os
import sys
import time
import signal
import threading
import subprocess
import platform
from typing import Dict, Any, Optional
from pathlib import Path

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
    from ..exceptions import AntivirusError, ServiceError
except ImportError:
    class AntivirusError(Exception): pass
    class ServiceError(AntivirusError): pass

# Platform-specific imports
PLATFORM = platform.system().lower()

if PLATFORM == "windows":
    try:
        import win32serviceutil
        import win32service
        import win32event
        HAS_WIN32_SERVICE = True
    except ImportError:
        HAS_WIN32_SERVICE = False
        win32serviceutil = None
        win32service = None
        win32event = None

class ServiceManager:
    """Enhanced cross-platform service management"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.logger = SecureLogger("ServiceManager")
        self.config = config or {}
        self.platform = PLATFORM
        self.service_name = self.config.get('service_name', "Prashant918Antivirus")
        self.display_name = self.config.get('display_name', "Prashant918 Advanced Antivirus")
        self.description = self.config.get('description', "Enterprise cybersecurity and threat detection service")
        
        # Service components (initialized when service starts)
        self.realtime_monitor = None
        self.threat_engine = None
        
        # Service state
        self.running = False
        self.stop_event = threading.Event()
        self.service_thread = None
        self.start_time = None
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        # Service paths - use user directory to avoid permission issues
        self._setup_service_paths()

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            
            if hasattr(signal, "SIGHUP"):
                signal.signal(signal.SIGHUP, self._signal_handler)
                
        except Exception as e:
            self.logger.warning(f"Failed to setup signal handlers: {e}")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop_service()

    def _setup_service_paths(self):
        """Setup service paths with fallback to user directory"""
        try:
            # Use user directory to avoid permission issues
            user_home = Path.home()
            base_dir = user_home / ".prashant918_antivirus"
            
            # Service directories
            self.service_dir = base_dir / "service"
            self.log_dir = base_dir / "logs"
            self.pid_dir = base_dir / "run"
            
            # Create directories
            for directory in [self.service_dir, self.log_dir, self.pid_dir]:
                try:
                    directory.mkdir(parents=True, exist_ok=True)
                    # Set secure permissions on Unix-like systems
                    if os.name != 'nt':
                        os.chmod(directory, 0o700)
                except Exception as e:
                    self.logger.warning(f"Could not create directory {directory}: {e}")
            
            # Service files
            self.pid_file = self.pid_dir / f"{self.service_name.lower()}.pid"
            self.executable_path = sys.executable
            
            self.logger.info(f"Service paths configured: {self.service_dir}")
            
        except Exception as e:
            self.logger.error(f"Failed to setup service paths: {e}")
            # Use temporary directory as fallback
            import tempfile
            temp_dir = Path(tempfile.gettempdir()) / "prashant918_antivirus"
            temp_dir.mkdir(exist_ok=True)
            
            self.service_dir = temp_dir
            self.log_dir = temp_dir
            self.pid_dir = temp_dir
            self.pid_file = temp_dir / f"{self.service_name.lower()}.pid"
            self.executable_path = sys.executable

    def install_service(self) -> bool:
        """Install service based on platform"""
        try:
            self.logger.info(f"Installing service on {self.platform}")
            
            if self.platform == "windows":
                return self._install_windows_service()
            elif self.platform == "linux":
                return self._install_linux_service()
            elif self.platform == "darwin":
                return self._install_macos_service()
            else:
                self.logger.error(f"Unsupported platform: {self.platform}")
                return False
                
        except Exception as e:
            self.logger.error(f"Service installation failed: {e}")
            return False

    def uninstall_service(self) -> bool:
        """Uninstall service based on platform"""
        try:
            self.logger.info(f"Uninstalling service on {self.platform}")
            
            # Stop service first
            self.stop_service()
            
            if self.platform == "windows":
                return self._uninstall_windows_service()
            elif self.platform == "linux":
                return self._uninstall_linux_service()
            elif self.platform == "darwin":
                return self._uninstall_macos_service()
            else:
                self.logger.error(f"Unsupported platform: {self.platform}")
                return False
                
        except Exception as e:
            self.logger.error(f"Service uninstallation failed: {e}")
            return False

    def start_service(self) -> bool:
        """Start the antivirus service"""
        try:
            if self.running:
                self.logger.warning("Service is already running")
                return True
            
            self.logger.info("Starting antivirus service...")
            
            # Write PID file
            self._write_pid_file()
            
            # Initialize components
            self._initialize_components()
            
            # Start service worker thread
            self.running = True
            self.stop_event.clear()
            self.start_time = time.time()
            
            self.service_thread = threading.Thread(target=self._service_worker, daemon=True)
            self.service_thread.start()
            
            self.logger.info("Antivirus service started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start service: {e}")
            self.running = False
            return False

    def stop_service(self) -> bool:
        """Stop the antivirus service"""
        try:
            if not self.running:
                self.logger.info("Service is not running")
                return True
            
            self.logger.info("Stopping antivirus service...")
            
            # Signal stop
            self.running = False
            self.stop_event.set()
            
            # Wait for service thread to finish
            if self.service_thread and self.service_thread.is_alive():
                self.service_thread.join(timeout=10)
            
            # Stop components
            self._stop_components()
            
            # Remove PID file
            self._remove_pid_file()
            
            self.logger.info("Antivirus service stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop service: {e}")
            return False

    def get_service_status(self) -> Dict[str, Any]:
        """Get service status information"""
        try:
            uptime = time.time() - self.start_time if self.start_time else 0
            
            return {
                'running': self.running,
                'platform': self.platform,
                'service_name': self.service_name,
                'uptime': uptime,
                'pid_file': str(self.pid_file),
                'components': {
                    'threat_engine': self.threat_engine is not None,
                    'realtime_monitor': self.realtime_monitor is not None
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get service status: {e}")
            return {'error': str(e)}

    def _write_pid_file(self):
        """Write PID file"""
        try:
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
            self.logger.debug(f"PID file written: {self.pid_file}")
        except Exception as e:
            self.logger.warning(f"Failed to write PID file: {e}")

    def _remove_pid_file(self):
        """Remove PID file"""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
                self.logger.debug(f"PID file removed: {self.pid_file}")
        except Exception as e:
            self.logger.warning(f"Failed to remove PID file: {e}")

    def _initialize_components(self):
        """Initialize service components"""
        try:
            # Initialize threat detection engine
            try:
                from ..antivirus.engine import AdvancedThreatDetectionEngine
                self.threat_engine = AdvancedThreatDetectionEngine()
                self.logger.info("Threat detection engine initialized")
            except ImportError as e:
                self.logger.warning(f"Threat engine not available: {e}")
            except Exception as e:
                self.logger.error(f"Failed to initialize threat engine: {e}")
            
            # Initialize real-time monitor
            try:
                from ..core.realtime_monitor import RealtimeMonitor
                from ..core.quarantine import QuarantineManager
                
                quarantine_manager = QuarantineManager()
                self.realtime_monitor = RealtimeMonitor(
                    threat_engine=self.threat_engine,
                    quarantine_manager=quarantine_manager
                )
                
                # Start monitoring default paths
                monitor_paths = secure_config.get("monitoring.paths", [
                    str(Path.home() / "Downloads"),
                    str(Path.home() / "Desktop"),
                    str(Path.home() / "Documents")
                ])
                
                if self.realtime_monitor.start_monitoring(monitor_paths):
                    self.logger.info("Real-time monitoring started")
                else:
                    self.logger.warning("Failed to start real-time monitoring")
                    
            except ImportError as e:
                self.logger.warning(f"Real-time monitor not available: {e}")
            except Exception as e:
                self.logger.error(f"Failed to initialize real-time monitor: {e}")
                
        except Exception as e:
            self.logger.error(f"Component initialization failed: {e}")

    def _stop_components(self):
        """Stop service components"""
        try:
            if self.realtime_monitor:
                self.realtime_monitor.stop_monitoring()
                self.logger.info("Real-time monitoring stopped")
        except Exception as e:
            self.logger.error(f"Failed to stop components: {e}")

    def _service_worker(self):
        """Main service worker thread"""
        try:
            self.logger.info("Service worker started")
            
            while self.running and not self.stop_event.is_set():
                # Service maintenance tasks
                try:
                    # Perform periodic maintenance
                    self._perform_maintenance()
                    
                    # Wait for stop signal or timeout
                    if self.stop_event.wait(timeout=60):  # Check every minute
                        break
                        
                except Exception as e:
                    self.logger.error(f"Service worker error: {e}")
                    time.sleep(5)  # Brief pause before continuing
            
            self.logger.info("Service worker stopped")
            
        except Exception as e:
            self.logger.critical(f"Service worker crashed: {e}")

    def _perform_maintenance(self):
        """Perform periodic maintenance tasks"""
        try:
            # Log service status
            if self.start_time:
                uptime = time.time() - self.start_time
                if uptime % 3600 < 60:  # Log every hour
                    self.logger.info(f"Service uptime: {uptime/3600:.1f} hours")
            
            # Additional maintenance tasks can be added here
            
        except Exception as e:
            self.logger.error(f"Maintenance task failed: {e}")

    def _install_windows_service(self) -> bool:
        """Install Windows service"""
        if not HAS_WIN32_SERVICE:
            self.logger.error("Windows service modules not available")
            return False
        
        try:
            # Implementation for Windows service installation
            self.logger.info("Windows service installation not fully implemented")
            return True
        except Exception as e:
            self.logger.error(f"Windows service installation failed: {e}")
            return False

    def _install_linux_service(self) -> bool:
        """Install Linux systemd service"""
        try:
            service_content = f"""[Unit]
Description={self.description}
After=network.target

[Service]
Type=simple
User={os.getenv('USER', 'root')}
ExecStart={self.executable_path} -m prashant918_antivirus.service.service_manager
Restart=always
RestartSec=10
WorkingDirectory={self.service_dir}
Environment=PYTHONPATH={os.path.dirname(os.path.dirname(__file__))}

[Install]
WantedBy=multi-user.target
"""
            
            service_file = f"/etc/systemd/system/{self.service_name.lower()}.service"
            
            # Write service file (requires root)
            try:
                with open(service_file, 'w') as f:
                    f.write(service_content)
            except PermissionError:
                # Try with sudo
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.service') as tmp:
                    tmp.write(service_content)
                    tmp_path = tmp.name
                
                subprocess.run(['sudo', 'cp', tmp_path, service_file], check=True)
                os.unlink(tmp_path)
            
            # Reload systemd and enable service
            subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
            subprocess.run(['sudo', 'systemctl', 'enable', f"{self.service_name.lower()}.service"], check=True)
            
            self.logger.info("Linux systemd service installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Linux service installation failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Linux service installation failed: {e}")
            return False

    def _install_macos_service(self) -> bool:
        """Install macOS launchd service"""
        try:
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.prashant918.antivirus</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.executable_path}</string>
        <string>-m</string>
        <string>prashant918_antivirus.service.service_manager</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>{self.service_dir}</string>
    <key>StandardOutPath</key>
    <string>{self.log_dir}/service.log</string>
    <key>StandardErrorPath</key>
    <string>{self.log_dir}/service-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONPATH</key>
        <string>{os.path.dirname(os.path.dirname(__file__))}</string>
    </dict>
</dict>
</plist>
"""
            plist_file = "/Library/LaunchDaemons/com.prashant918.antivirus.plist"
            
            # Write plist file (requires root)
            try:
                with open(plist_file, 'w') as f:
                    f.write(plist_content)
            except PermissionError:
                # Try with sudo
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.plist') as tmp:
                    tmp.write(plist_content)
                    tmp_path = tmp.name
                
                subprocess.run(['sudo', 'cp', tmp_path, plist_file], check=True)
                os.unlink(tmp_path)
            
            # Load the service
            subprocess.run(['sudo', 'launchctl', 'load', plist_file], check=True)
            
            self.logger.info("macOS launchd service installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"macOS service installation failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"macOS service installation failed: {e}")
            return False

    def _uninstall_windows_service(self) -> bool:
        """Uninstall Windows service"""
        try:
            self.logger.info("Windows service uninstallation not fully implemented")
            return True
        except Exception as e:
            self.logger.error(f"Windows service uninstallation failed: {e}")
            return False

    def _uninstall_linux_service(self) -> bool:
        """Uninstall Linux systemd service"""
        try:
            service_file = f"/etc/systemd/system/{self.service_name.lower()}.service"
            
            # Stop and disable service
            subprocess.run(['sudo', 'systemctl', 'stop', f"{self.service_name.lower()}.service"], 
                         capture_output=True)
            subprocess.run(['sudo', 'systemctl', 'disable', f"{self.service_name.lower()}.service"], 
                         capture_output=True)
            
            # Remove service file
            if os.path.exists(service_file):
                subprocess.run(['sudo', 'rm', service_file], check=True)
            
            # Reload systemd
            subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
            
            self.logger.info("Linux systemd service uninstalled successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Linux service uninstallation failed: {e}")
            return False

    def _uninstall_macos_service(self) -> bool:
        """Uninstall macOS launchd service"""
        try:
            plist_file = "/Library/LaunchDaemons/com.prashant918.antivirus.plist"
            
            # Unload the service
            subprocess.run(['sudo', 'launchctl', 'unload', plist_file], 
                         capture_output=True)
            
            # Remove plist file
            if os.path.exists(plist_file):
                subprocess.run(['sudo', 'rm', plist_file], check=True)
            
            self.logger.info("macOS launchd service uninstalled successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"macOS service uninstallation failed: {e}")
            return False

def create_service_manager(config: Optional[Dict[str, Any]] = None) -> ServiceManager:
    """Create service manager with default configuration"""
    if config is None:
        config = {
            'service_name': 'prashant918-antivirus',
            'display_name': 'Prashant918 Advanced Antivirus',
            'description': 'Advanced AI-powered antivirus protection system'
        }
    
    return ServiceManager(config)

def main():
    """Main function for service management CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Prashant918 Antivirus Service Manager')
    parser.add_argument('action', choices=['install', 'uninstall', 'start', 'stop', 'restart', 'status'],
                       help='Service action to perform')
    parser.add_argument('--config', help='Configuration file path')
    
    args = parser.parse_args()
    
    try:
        service_manager = create_service_manager()
        
        if args.action == 'install':
            success = service_manager.install_service()
        elif args.action == 'uninstall':
            success = service_manager.uninstall_service()
        elif args.action == 'start':
            success = service_manager.start_service()
        elif args.action == 'stop':
            success = service_manager.stop_service()
        elif args.action == 'restart':
            success = service_manager.stop_service() and service_manager.start_service()
        elif args.action == 'status':
            status = service_manager.get_service_status()
            print(f"Service Status: {status}")
            success = True
        
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()