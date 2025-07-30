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
    
    def __init__(self):
        self.logger = SecureLogger("ServiceManager")
        self.platform = PLATFORM
        self.service_name = "Prashant918Antivirus"
        self.display_name = "Prashant918 Advanced Antivirus"
        self.description = "Enterprise cybersecurity and threat detection service"
        
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
        
        # Service paths
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
    
    def _setup_service_paths(self):
        """Setup service-related paths"""
        try:
            # Get the current script path
            if hasattr(sys, 'frozen'):
                # Running as compiled executable
                self.executable_path = sys.executable
            else:
                # Running as Python script
                self.executable_path = sys.executable
                self.script_path = str(Path(__file__).absolute())
            
            # Service directories
            if PLATFORM == "windows":
                self.service_dir = Path("C:/ProgramData/Prashant918Antivirus")
            else:
                self.service_dir = Path("/var/lib/prashant918-antivirus")
            
            self.log_dir = self.service_dir / "logs"
            self.pid_file = self.service_dir / "service.pid"
            
            # Create directories
            self.service_dir.mkdir(parents=True, exist_ok=True)
            self.log_dir.mkdir(parents=True, exist_ok=True)
            
        except Exception as e:
            self.logger.error(f"Failed to setup service paths: {e}")
    
    def install_service(self) -> bool:
        """Install service on the system"""
        try:
            self.logger.info(f"Installing service on {self.platform}")
            
            if self.platform == "windows":
                return self._install_windows_service()
            elif self.platform == "linux":
                return self._install_linux_service()
            elif self.platform == "darwin":
                return self._install_macos_service()
            else:
                self.logger.error(f"Service installation not supported on {self.platform}")
                return False
                
        except Exception as e:
            self.logger.error(f"Service installation failed: {e}")
            return False
    
    def uninstall_service(self) -> bool:
        """Uninstall service from the system"""
        try:
            self.logger.info(f"Uninstalling service from {self.platform}")
            
            # Stop service first
            self.stop_service()
            
            if self.platform == "windows":
                return self._uninstall_windows_service()
            elif self.platform == "linux":
                return self._uninstall_linux_service()
            elif self.platform == "darwin":
                return self._uninstall_macos_service()
            else:
                self.logger.error(f"Service uninstallation not supported on {self.platform}")
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
            
            # Stop real-time monitoring
            if self.realtime_monitor:
                try:
                    self.realtime_monitor.stop_monitoring()
                except Exception as e:
                    self.logger.error(f"Error stopping real-time monitor: {e}")
            
            # Wait for service thread to finish
            if self.service_thread and self.service_thread.is_alive():
                self.service_thread.join(timeout=10)
            
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
            uptime = 0
            if self.running and self.start_time:
                uptime = time.time() - self.start_time
            
            monitor_status = None
            if self.realtime_monitor:
                try:
                    monitor_status = self.realtime_monitor.get_status()
                except Exception as e:
                    self.logger.debug(f"Error getting monitor status: {e}")
            
            return {
                "running": self.running,
                "platform": self.platform,
                "service_name": self.service_name,
                "pid": os.getpid(),
                "uptime": uptime,
                "start_time": self.start_time,
                "monitor_status": monitor_status,
                "components": {
                    "threat_engine": self.threat_engine is not None,
                    "realtime_monitor": self.realtime_monitor is not None
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get service status: {e}")
            return {"error": str(e)}
    
    def run_as_service(self):
        """Main entry point when running as a service"""
        try:
            self.logger.info("Running as service...")
            
            if not self.start_service():
                self.logger.error("Failed to start service")
                return
            
            # Keep service running until stop signal
            while self.running and not self.stop_event.is_set():
                try:
                    self.stop_event.wait(1)
                except KeyboardInterrupt:
                    break
            
            self.stop_service()
            
        except Exception as e:
            self.logger.error(f"Service execution error: {e}")
        finally:
            self.logger.info("Service execution completed")
    
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
    
    def _service_worker(self):
        """Service worker thread for maintenance tasks"""
        try:
            self.logger.info("Service worker thread started")
            
            while self.running and not self.stop_event.is_set():
                try:
                    # Perform maintenance every 5 minutes
                    if self.stop_event.wait(300):  # 5 minutes
                        break
                    
                    if self.running:
                        self._perform_maintenance()
                        
                except Exception as e:
                    self.logger.error(f"Error in service worker: {e}")
            
            self.logger.info("Service worker thread stopped")
            
        except Exception as e:
            self.logger.error(f"Service worker thread error: {e}")
    
    def _perform_maintenance(self):
        """Perform periodic maintenance tasks"""
        try:
            self.logger.debug("Performing maintenance tasks...")
            
            # Update signatures if enabled
            if secure_config.get("updates.auto_update", True):
                try:
                    # This would update threat signatures
                    pass
                except Exception as e:
                    self.logger.debug(f"Signature update failed: {e}")
            
            # Clean up logs if enabled
            if secure_config.get("logging.cleanup_enabled", True):
                try:
                    self._cleanup_logs()
                except Exception as e:
                    self.logger.debug(f"Log cleanup failed: {e}")
            
            # Database maintenance
            try:
                # This would perform database cleanup
                pass
            except Exception as e:
                self.logger.debug(f"Database maintenance failed: {e}")
                
        except Exception as e:
            self.logger.error(f"Maintenance task error: {e}")
    
    def _cleanup_logs(self):
        """Clean up old log files"""
        try:
            max_age_days = secure_config.get("logging.max_age_days", 30)
            max_age_seconds = max_age_days * 24 * 3600
            current_time = time.time()
            
            for log_file in self.log_dir.glob("*.log"):
                try:
                    file_age = current_time - log_file.stat().st_mtime
                    if file_age > max_age_seconds:
                        log_file.unlink()
                        self.logger.debug(f"Removed old log file: {log_file}")
                except Exception as e:
                    self.logger.debug(f"Failed to remove log file {log_file}: {e}")
                    
        except Exception as e:
            self.logger.debug(f"Log cleanup error: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        self.logger.info(f"Received signal {signum}")

        if signum in [signal.SIGTERM, signal.SIGINT]:
            self.stop_service()
        elif hasattr(signal, "SIGHUP") and signum == signal.SIGHUP:
            # Reload configuration
            self.logger.info("Reloading configuration...")

    def _write_pid_file(self):
        """Write PID file to service directory"""
        try:
            with open(self.pid_file, "w") as f:
                f.write(str(os.getpid()))
        except Exception as e:
            self.logger.error(f"Failed to write PID file: {e}")
    
    def _remove_pid_file(self):
        """Remove PID file from service directory"""
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
        except Exception as e:
            self.logger.error(f"Failed to remove PID file: {e}")
    
    def _install_windows_service(self) -> bool:
        """Install Windows service"""
        try:
            import win32serviceutil
            import win32service
            import win32event

            # Create service class
            class AntivirusService(win32serviceutil.ServiceFramework):
                _svc_name_ = self.service_name
                _svc_display_name_ = self.display_name
                _svc_description_ = self.description

                def __init__(self, args):
                    win32serviceutil.ServiceFramework.__init__(self, args)
                    self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
                    self.service_manager = ServiceManager()

                def SvcStop(self):
                    self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                    self.service_manager.stop_service()
                    win32event.SetEvent(self.hWaitStop)

                def SvcDoRun(self):
                    self.service_manager.run_as_service()

            # Install service
            win32serviceutil.InstallService(
                AntivirusService,
                self.service_name,
                self.display_name,
                description=self.description,
            )

            self.logger.info("Windows service installed successfully")
            return True

        except ImportError:
            self.logger.error("pywin32 not available for Windows service installation")
            return False
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
User=antivirus
Group=antivirus
ExecStart={sys.executable} -m prashant918_antivirus.service.service_manager
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

            service_file = f"/etc/systemd/system/{self.service_name.lower()}.service"

            with open(service_file, "w") as f:
                f.write(service_content)

            # Reload systemd and enable service
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(
                ["systemctl", "enable", f"{self.service_name.lower()}.service"],
                check=True,
            )

            self.logger.info("Linux systemd service installed successfully")
            return True

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
        <string>{sys.executable}</string>
        <string>-m</string>
        <string>prashant918_antivirus.service.service_manager</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/prashant918-antivirus.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/prashant918-antivirus-error.log</string>
</dict>
</plist>
"""

            plist_file = "/Library/LaunchDaemons/com.prashant918.antivirus.plist"

            with open(plist_file, "w") as f:
                f.write(plist_content)

            # Load service
            subprocess.run(["launchctl", "load", plist_file], check=True)

            self.logger.info("macOS launchd service installed successfully")
            return True

        except Exception as e:
            self.logger.error(f"macOS service installation failed: {e}")
            return False

    def _uninstall_windows_service(self) -> bool:
        """Uninstall Windows service"""
        try:
            import win32serviceutil

            win32serviceutil.RemoveService(self.service_name)
            self.logger.info("Windows service uninstalled successfully")
            return True

        except ImportError:
            self.logger.error(
                "pywin32 not available for Windows service uninstallation"
            )
            return False
        except Exception as e:
            self.logger.error(f"Windows service uninstallation failed: {e}")
            return False

    def _uninstall_linux_service(self) -> bool:
        """Uninstall Linux systemd service"""
        try:
            service_file = f"/etc/systemd/system/{self.service_name.lower()}.service"

            # Stop and disable service
            subprocess.run(
                ["systemctl", "stop", f"{self.service_name.lower()}.service"],
                check=False,
            )
            subprocess.run(
                ["systemctl", "disable", f"{self.service_name.lower()}.service"],
                check=False,
            )

            # Remove service file
            if os.path.exists(service_file):
                os.remove(service_file)

            # Reload systemd
            subprocess.run(["systemctl", "daemon-reload"], check=True)

            self.logger.info("Linux systemd service uninstalled successfully")
            return True

        except Exception as e:
            self.logger.error(f"Linux service uninstallation failed: {e}")
            return False

    def _uninstall_macos_service(self) -> bool:
        """Uninstall macOS launchd service"""
        try:
            plist_file = "/Library/LaunchDaemons/com.prashant918.antivirus.plist"

            # Unload service
            subprocess.run(["launchctl", "unload", plist_file], check=False)

            # Remove plist file
            if os.path.exists(plist_file):
                os.remove(plist_file)

            self.logger.info("macOS launchd service uninstalled successfully")
            return True

        except Exception as e:
            self.logger.error(f"macOS service uninstallation failed: {e}")
            return False


def main():
    """Main entry point for service"""
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        service_manager = ServiceManager()

        if command == "install":
            if service_manager.install_service():
                print("Service installed successfully")
            else:
                print("Service installation failed")
                sys.exit(1)

        elif command == "uninstall":
            if service_manager.uninstall_service():
                print("Service uninstalled successfully")
            else:
                print("Service uninstallation failed")
                sys.exit(1)

        elif command == "start":
            if service_manager.start_service():
                print("Service started successfully")
                # Keep running
                try:
                    while service_manager.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    service_manager.stop_service()
            else:
                print("Service start failed")
                sys.exit(1)

        elif command == "stop":
            if service_manager.stop_service():
                print("Service stopped successfully")
            else:
                print("Service stop failed")
                sys.exit(1)

        elif command == "status":
            status = service_manager.get_service_status()
            print(f"Service Status: {status}")

        else:
            print("Usage: service_manager.py [install|uninstall|start|stop|status]")
            sys.exit(1)

    else:
        # Run as service
        service_manager = ServiceManager()
        service_manager.run_as_service()


if __name__ == "__main__":
    main()
    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        try:
            if signum in (signal.SIGTERM, signal.SIGINT):
                self.logger.info(f"Received signal {signum}, stopping service...")
                self.stop_service()
            elif signum == signal.SIGHUP:
                self.logger.info("Received SIGHUP, reloading configuration...")
                # Reload configuration
                try:
                    secure_config.reload()
                except Exception as e:
                    self.logger.error(f"Failed to reload configuration: {e}")
                    
        except Exception as e:
            self.logger.error(f"Signal handler error: {e}")
    
    def _write_pid_file(self):
        """Write PID file"""
        try:
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
        except Exception as e:
            self.logger.warning(f"Failed to write PID file: {e}")
    
    def _remove_pid_file(self):
        """Remove PID file"""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
        except Exception as e:
            self.logger.warning(f"Failed to remove PID file: {e}")
    
    def _install_windows_service(self) -> bool:
        """Install Windows service"""
        try:
            if not HAS_WIN32_SERVICE:
                self.logger.error("pywin32 not available for Windows service installation")
                return False
            
            # Create service class
            class AntivirusService(win32serviceutil.ServiceFramework):
                _svc_name_ = self.service_name
                _svc_display_name_ = self.display_name
                _svc_description_ = self.description
                _svc_deps_ = None
                
                def __init__(self, args):
                    win32serviceutil.ServiceFramework.__init__(self, args)
                    self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
                    self.service_manager = ServiceManager()
                
                def SvcStop(self):
                    self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                    self.service_manager.stop_service()
                    win32event.SetEvent(self.hWaitStop)
                
                def SvcDoRun(self):
                    try:
                        self.service_manager.run_as_service()
                    except Exception as e:
                        import servicemanager
                        servicemanager.LogErrorMsg(f"Service error: {e}")
            
            # Install service
            win32serviceutil.InstallService(
                AntivirusService,
                self.service_name,
                self.display_name,
                description=self.description,
                startType=win32service.SERVICE_AUTO_START
            )
            
            self.logger.info("Windows service installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Windows service installation failed: {e}")
            return False
    
    def _install_linux_service(self) -> bool:
        """Install Linux systemd service"""
        try:
            # Create service user if it doesn't exist
            self._create_service_user()
            
            service_content = f"""[Unit]
Description={self.description}
After=network.target
Wants=network.target

[Service]
Type=simple
User=prashant918-av
Group=prashant918-av
ExecStart={self.executable_path} -m prashant918_antivirus.service.service_manager
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=30
Environment=PYTHONPATH={os.path.dirname(os.path.dirname(__file__))}
WorkingDirectory={self.service_dir}
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={self.service_dir}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
"""
            
            service_file = f"/etc/systemd/system/{self.service_name.lower()}.service"
            
            # Write service file (requires root)
            try:
                with open(service_file, "w") as f:
                    f.write(service_content)
            except PermissionError:
                # Try with sudo
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.service') as tmp:
                    tmp.write(service_content)
                    tmp_path = tmp.name
                
                subprocess.run(['sudo', 'cp', tmp_path, service_file], check=True)
                os.unlink(tmp_path)
            
            # Set proper permissions
            subprocess.run(['sudo', 'chmod', '644', service_file], check=True)
            
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
                with open(plist_file, "w") as f:
                    f.write(plist_content)
            except PermissionError:
                # Try with sudo
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.plist') as tmp:
                    tmp.write(plist_content)
                    tmp_path = tmp.name
                
                subprocess.run(['sudo', 'cp', tmp_path, plist_file], check=True)
                os.unlink(tmp_path)
            
            # Set proper permissions
            subprocess.run(['sudo', 'chmod', '644', plist_file], check=True)
            subprocess.run(['sudo', 'chown', 'root:wheel', plist_file], check=True)
            
            # Load service
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
            if not HAS_WIN32_SERVICE:
                self.logger.error("pywin32 not available for Windows service uninstallation")
                return False
            
            win32serviceutil.RemoveService(self.service_name)
            self.logger.info("Windows service uninstalled successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Windows service uninstallation failed: {e}")
            return False
    
    def _uninstall_linux_service(self) -> bool:
        """Uninstall Linux systemd service"""
        try:
            service_file = f"/etc/systemd/system/{self.service_name.lower()}.service"
            
            # Stop and disable service
            subprocess.run(['sudo', 'systemctl', 'stop', f"{self.service_name.lower()}.service"], check=False)
            subprocess.run(['sudo', 'systemctl', 'disable', f"{self.service_name.lower()}.service"], check=False)
            
            # Remove service file
            if os.path.exists(service_file):
                subprocess.run(['sudo', 'rm', service_file], check=True)
            
            # Reload systemd
            subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
            
            self.logger.info("Linux systemd service uninstalled successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Linux service uninstallation failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Linux service uninstallation failed: {e}")
            return False
    
    def _uninstall_macos_service(self) -> bool:
        """Uninstall macOS launchd service"""
        try:
            plist_file = "/Library/LaunchDaemons/com.prashant918.antivirus.plist"
            
            # Unload service
            subprocess.run(['sudo', 'launchctl', 'unload', plist_file], check=False)
            
            # Remove plist file
            if os.path.exists(plist_file):
                subprocess.run(['sudo', 'rm', plist_file], check=True)
            
            self.logger.info("macOS launchd service uninstalled successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"macOS service uninstallation failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"macOS service uninstallation failed: {e}")
            return False
    
    def _create_service_user(self):
        """Create service user for Linux"""
        try:
            # Check if user exists
            result = subprocess.run(['id', 'prashant918-av'], capture_output=True)
            if result.returncode == 0:
                return  # User already exists
            
            # Create system user
            subprocess.run([
                'sudo', 'useradd', '--system', '--no-create-home',
                '--shell', '/bin/false', 'prashant918-av'
            ], check=True)
            
            # Set ownership of service directory
            subprocess.run([
                'sudo', 'chown', '-R', 'prashant918-av:prashant918-av', 
                str(self.service_dir)
            ], check=True)
            
            self.logger.info("Service user created successfully")
            
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to create service user: {e}")
        except Exception as e:
            self.logger.warning(f"Service user creation error: {e}")

def main():
    """Main entry point for service management"""
    try:
        import argparse
        
        parser = argparse.ArgumentParser(description="Prashant918 Antivirus Service Manager")
        parser.add_argument('command', nargs='?', choices=['install', 'uninstall', 'start', 'stop', 'status', 'run'],
                          help='Service command')
        
        args = parser.parse_args()
        
        service_manager = ServiceManager()
        
        if args.command == 'install':
            success = service_manager.install_service()
            print("Service installed successfully" if success else "Service installation failed")
            sys.exit(0 if success else 1)
            
        elif args.command == 'uninstall':
            success = service_manager.uninstall_service()
            print("Service uninstalled successfully" if success else "Service uninstallation failed")
            sys.exit(0 if success else 1)
            
        elif args.command == 'start':
            success = service_manager.start_service()
            if success:
                print("Service started successfully")
                # Keep running
                try:
                    while service_manager.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    service_manager.stop_service()
            else:
                print("Service start failed")
            sys.exit(0 if success else 1)
            
        elif args.command == 'stop':
            success = service_manager.stop_service()
            print("Service stopped successfully" if success else "Service stop failed")
            sys.exit(0 if success else 1)
            
        elif args.command == 'status':
            status = service_manager.get_service_status()
            print("Service Status:")
            for key, value in status.items():
                print(f"  {key}: {value}")
            sys.exit(0)
            
        elif args.command == 'run':
            # Run as service (used by service managers)
            service_manager.run_as_service()
            
        else:
            # No command provided, run as service
            service_manager.run_as_service()
            
    except KeyboardInterrupt:
        print("\nService interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Service manager error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
