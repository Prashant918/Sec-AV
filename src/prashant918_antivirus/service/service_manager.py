"""
Prashant918 Advanced Antivirus - Service Manager

Cross-platform service management for running antivirus as a system service.
"""

import os
import sys
import time
import signal
import threading
import subprocess
from typing import Dict, Any, Optional
import platform

from ..core.realtime_monitor import RealtimeMonitor
from ..core.engine import AdvancedThreatDetectionEngine
from ..logger import SecureLogger
from ..config import secure_config
from ..exceptions import AntivirusError


class ServiceManager:
    """Cross-platform service management"""
    
    def __init__(self):
        self.logger = SecureLogger("ServiceManager")
        self.platform = platform.system().lower()
        self.service_name = "Prashant918Antivirus"
        self.display_name = "Prashant918 Advanced Antivirus"
        self.description = "Enterprise cybersecurity and threat detection service"
        
        # Service components
        self.realtime_monitor = None
        self.threat_engine = None
        
        # Service state
        self.running = False
        self.stop_event = threading.Event()
        
        # Signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._signal_handler)
    
    def install_service(self) -> bool:
        """Install service on the system"""
        try:
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
        """Start the service"""
        try:
            if self.running:
                self.logger.warning("Service is already running")
                return True
            
            self.logger.info("Starting antivirus service...")
            
            # Initialize components
            self.threat_engine = AdvancedThreatDetectionEngine()
            self.realtime_monitor = RealtimeMonitor()
            
            # Start real-time monitoring
            monitor_paths = secure_config.get("monitoring.paths", ["."])
            self.realtime_monitor.start_monitoring(monitor_paths)
            
            # Start service worker thread
            self.running = True
            self.stop_event.clear()
            
            service_thread = threading.Thread(target=self._service_worker, daemon=True)
            service_thread.start()
            
            self.logger.info("Antivirus service started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start service: {e}")
            return False
    
    def stop_service(self) -> bool:
        """Stop the service"""
        try:
            if not self.running:
                self.logger.warning("Service is not running")
                return True
            
            self.logger.info("Stopping antivirus service...")
            
            # Signal stop
            self.running = False
            self.stop_event.set()
            
            # Stop real-time monitoring
            if self.realtime_monitor:
                self.realtime_monitor.stop_monitoring()
            
            self.logger.info("Antivirus service stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop service: {e}")
            return False
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get service status"""
        status = {
            "running": self.running,
            "platform": self.platform,
            "service_name": self.service_name,
            "pid": os.getpid(),
            "uptime": None
        }
        
        if self.realtime_monitor:
            monitor_status = self.realtime_monitor.get_status()
            status.update(monitor_status)
        
        return status
    
    def run_as_service(self):
        """Run as a service (main service entry point)"""
        try:
            self.logger.info("Running as service...")
            
            if not self.start_service():
                sys.exit(1)
            
            # Keep service running
            while self.running and not self.stop_event.is_set():
                time.sleep(1)
            
            self.stop_service()
            
        except Exception as e:
            self.logger.error(f"Service runtime error: {e}")
            sys.exit(1)
    
    def _service_worker(self):
        """Main service worker thread"""
        try:
            while self.running and not self.stop_event.is_set():
                # Perform periodic maintenance tasks
                self._perform_maintenance()
                
                # Wait for next cycle
                self.stop_event.wait(300)  # 5 minutes
                
        except Exception as e:
            self.logger.error(f"Service worker error: {e}")
    
    def _perform_maintenance(self):
        """Perform periodic maintenance tasks"""
        try:
            # Update signatures periodically
            if secure_config.get("maintenance.auto_update_signatures", True):
                # Update every 4 hours
                pass
            
            # Clean up old logs
            if secure_config.get("maintenance.auto_cleanup_logs", True):
                # Cleanup daily
                pass
            
            # Database maintenance
            if secure_config.get("maintenance.auto_db_maintenance", True):
                # Maintenance weekly
                pass
                
        except Exception as e:
            self.logger.error(f"Maintenance task error: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        self.logger.info(f"Received signal {signum}")
        
        if signum in [signal.SIGTERM, signal.SIGINT]:
            self.stop_service()
        elif hasattr(signal, 'SIGHUP') and signum == signal.SIGHUP:
            # Reload configuration
            self.logger.info("Reloading configuration...")
    
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
                description=self.description
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
            
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            # Reload systemd and enable service
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", f"{self.service_name.lower()}.service"], check=True)
            
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
            
            with open(plist_file, 'w') as f:
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
            self.logger.error("pywin32 not available for Windows service uninstallation")
            return False
        except Exception as e:
            self.logger.error(f"Windows service uninstallation failed: {e}")
            return False
    
    def _uninstall_linux_service(self) -> bool:
        """Uninstall Linux systemd service"""
        try:
            service_file = f"/etc/systemd/system/{self.service_name.lower()}.service"
            
            # Stop and disable service
            subprocess.run(["systemctl", "stop", f"{self.service_name.lower()}.service"], check=False)
            subprocess.run(["systemctl", "disable", f"{self.service_name.lower()}.service"], check=False)
            
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
