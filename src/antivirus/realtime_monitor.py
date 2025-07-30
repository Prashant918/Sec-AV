import os
import time
import threading
import psutil
import hashlib
from typing import Dict, List, Callable, Optional
from pathlib import Path
from termcolor import colored
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import queue
import json


class FileSystemMonitor(FileSystemEventHandler):
    """Monitor file system changes in real-time"""

    def __init__(self, callback: Callable):
        super().__init__()
        self.callback = callback
        self.monitored_extensions = {
            ".exe",
            ".dll",
            ".sys",
            ".bat",
            ".cmd",
            ".scr",
            ".vbs",
            ".js",
            ".jar",
            ".zip",
            ".rar",
            ".doc",
            ".docx",
            ".pdf",
        }
        self.suspicious_locations = {
            "temp_dirs": ["/tmp", "/var/tmp", "%TEMP%", "%TMP%"],
            "startup_dirs": ["startup", "autostart"],
            "system_dirs": ["system32", "syswow64"],
        }

    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self._process_file_event("created", event.src_path)

    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self._process_file_event("modified", event.src_path)

    def on_moved(self, event):
        """Handle file move events"""
        if not event.is_directory:
            self._process_file_event("moved", event.dest_path, event.src_path)

    def _process_file_event(
        self, event_type: str, file_path: str, old_path: str = None
    ):
        """Process file system events"""
        try:
            file_ext = Path(file_path).suffix.lower()

            # Only monitor specific file types
            if file_ext in self.monitored_extensions:
                event_data = {
                    "type": event_type,
                    "path": file_path,
                    "old_path": old_path,
                    "timestamp": time.time(),
                    "size": (
                        os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    ),
                    "is_suspicious_location": self._is_suspicious_location(file_path),
                }

                self.callback(event_data)

        except Exception as e:
            print(colored(f"Error processing file event: {e}", "red"))

    def _is_suspicious_location(self, file_path: str) -> bool:
        """Check if file is in a suspicious location"""
        file_path_lower = file_path.lower()

        for category, locations in self.suspicious_locations.items():
            for location in locations:
                if location.lower() in file_path_lower:
                    return True

        return False


class ProcessMonitor:
    """Monitor running processes for suspicious behavior"""

    def __init__(self):
        self.monitored_processes = {}
        self.suspicious_processes = set()
        self.monitoring = False
        self.monitor_thread = None

        self.suspicious_process_names = {
            "miners": ["xmrig", "cpuminer", "cgminer", "bfgminer"],
            "remote_access": ["teamviewer", "anydesk", "vnc", "rdp"],
            "system_tools": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
            "network_tools": ["netcat", "nmap", "wireshark", "tcpdump"],
        }

    def start_monitoring(self):
        """Start process monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_processes)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            print(colored("Process monitoring started", "green"))

    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print(colored("Process monitoring stopped", "yellow"))

    def _monitor_processes(self):
        """Monitor processes continuously"""
        while self.monitoring:
            try:
                current_processes = {}

                for proc in psutil.process_iter(
                    ["pid", "name", "exe", "cmdline", "cpu_percent", "memory_info"]
                ):
                    try:
                        proc_info = proc.info
                        pid = proc_info["pid"]

                        current_processes[pid] = {
                            "name": proc_info["name"],
                            "exe": proc_info["exe"],
                            "cmdline": proc_info["cmdline"],
                            "cpu_percent": proc_info["cpu_percent"],
                            "memory_mb": (
                                proc_info["memory_info"].rss / 1024 / 1024
                                if proc_info["memory_info"]
                                else 0
                            ),
                            "timestamp": time.time(),
                        }

                        # Check for suspicious processes
                        if self._is_suspicious_process(proc_info):
                            self.suspicious_processes.add(pid)
                            self._alert_suspicious_process(pid, proc_info)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Detect new processes
                new_processes = set(current_processes.keys()) - set(
                    self.monitored_processes.keys()
                )
                for pid in new_processes:
                    self._alert_new_process(pid, current_processes[pid])

                self.monitored_processes = current_processes
                time.sleep(5)  # Check every 5 seconds

            except Exception as e:
                print(colored(f"Error in process monitoring: {e}", "red"))
                time.sleep(10)

    def _is_suspicious_process(self, proc_info: Dict) -> bool:
        """Check if process is suspicious"""
        name = proc_info.get("name", "").lower()
        exe = proc_info.get("exe", "").lower() if proc_info.get("exe") else ""
        cmdline = " ".join(proc_info.get("cmdline", [])).lower()

        # Check against suspicious process names
        for category, names in self.suspicious_process_names.items():
            for suspicious_name in names:
                if suspicious_name in name or suspicious_name in exe:
                    return True

        # Check for suspicious command line arguments
        suspicious_cmdline_patterns = [
            "powershell -encodedcommand",
            "cmd /c echo",
            "wscript.exe",
            "regsvr32 /s",
            "rundll32.exe",
        ]

        for pattern in suspicious_cmdline_patterns:
            if pattern in cmdline:
                return True

        return False

    def _alert_suspicious_process(self, pid: int, proc_info: Dict):
        """Alert about suspicious process"""
        print(colored(f"⚠️ SUSPICIOUS PROCESS DETECTED:", "yellow"))
        print(colored(f"  PID: {pid}", "yellow"))
        print(colored(f"  Name: {proc_info.get('name', 'Unknown')}", "yellow"))
        print(colored(f"  Path: {proc_info.get('exe', 'Unknown')}", "yellow"))

    def _alert_new_process(self, pid: int, proc_info: Dict):
        """Alert about new process (if suspicious)"""
        if self._is_suspicious_process(proc_info):
            print(colored(f"🔍 NEW SUSPICIOUS PROCESS:", "cyan"))
            print(colored(f"  PID: {pid}", "cyan"))
            print(colored(f"  Name: {proc_info.get('name', 'Unknown')}", "cyan"))

    def get_process_statistics(self) -> Dict:
        """Get process monitoring statistics"""
        return {
            "total_processes": len(self.monitored_processes),
            "suspicious_processes": len(self.suspicious_processes),
            "high_cpu_processes": len(
                [
                    p
                    for p in self.monitored_processes.values()
                    if p.get("cpu_percent", 0) > 80
                ]
            ),
            "high_memory_processes": len(
                [
                    p
                    for p in self.monitored_processes.values()
                    if p.get("memory_mb", 0) > 500
                ]
            ),
        }


class NetworkMonitor:
    """Monitor network connections for suspicious activity"""

    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.suspicious_connections = []
        self.known_malicious_ips = set()
        self.suspicious_ports = {
            "common_backdoors": [1337, 31337, 12345, 54321],
            "remote_access": [3389, 5900, 5901, 4899],
            "p2p_networks": [6881, 6882, 6883, 6884, 6885],
        }

    def start_monitoring(self):
        """Start network monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_network)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            print(colored("Network monitoring started", "green"))

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print(colored("Network monitoring stopped", "yellow"))

    def _monitor_network(self):
        """Monitor network connections"""
        while self.monitoring:
            try:
                connections = psutil.net_connections(kind="inet")

                for conn in connections:
                    if conn.status == psutil.CONN_ESTABLISHED:
                        self._analyze_connection(conn)

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                print(colored(f"Error in network monitoring: {e}", "red"))
                time.sleep(30)

    def _analyze_connection(self, connection):
        """Analyze individual network connection"""
        try:
            if connection.raddr:
                remote_ip = connection.raddr.ip
                remote_port = connection.raddr.port
                local_port = connection.laddr.port

                # Check for suspicious ports
                if self._is_suspicious_port(remote_port) or self._is_suspicious_port(
                    local_port
                ):
                    self._alert_suspicious_connection(connection, "Suspicious port")

                # Check for known malicious IPs
                if remote_ip in self.known_malicious_ips:
                    self._alert_suspicious_connection(connection, "Known malicious IP")

                # Check for unusual connection patterns
                if self._is_unusual_connection(connection):
                    self._alert_suspicious_connection(
                        connection, "Unusual connection pattern"
                    )

        except Exception as e:
            print(colored(f"Error analyzing connection: {e}", "red"))

    def _is_suspicious_port(self, port: int) -> bool:
        """Check if port is suspicious"""
        for category, ports in self.suspicious_ports.items():
            if port in ports:
                return True
        return False

    def _is_unusual_connection(self, connection) -> bool:
        """Check for unusual connection patterns"""
        # This is a simplified check
        # In reality, you'd implement more sophisticated analysis

        if connection.raddr:
            remote_ip = connection.raddr.ip

            # Check for connections to private IP ranges from public IPs
            if self._is_private_ip(remote_ip):
                return False

            # Check for connections to unusual ports
            if connection.raddr.port > 49152:  # Dynamic/private ports
                return True

        return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        private_ranges = [
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
            "127.",
        ]

        return any(ip.startswith(prefix) for prefix in private_ranges)

    def _alert_suspicious_connection(self, connection, reason: str):
        """Alert about suspicious network connection"""
        print(colored(f"🌐 SUSPICIOUS NETWORK CONNECTION:", "red"))
        print(colored(f"  Reason: {reason}", "red"))
        print(colored(f"  Local: {connection.laddr}", "red"))
        if connection.raddr:
            print(colored(f"  Remote: {connection.raddr}", "red"))
        print(colored(f"  Status: {connection.status}", "red"))


class RealTimeProtection:
    """Main real-time protection system"""

    def __init__(self, scanner_callback: Optional[Callable] = None):
        self.file_monitor = FileSystemMonitor(self._handle_file_event)
        self.process_monitor = ProcessMonitor()
        self.network_monitor = NetworkMonitor()
        self.observer = Observer()
        self.scanner_callback = scanner_callback
        self.event_queue = queue.Queue()
        self.monitoring_paths = []
        self.is_active = False

        # Statistics
        self.stats = {
            "files_monitored": 0,
            "threats_detected": 0,
            "suspicious_activities": 0,
            "start_time": None,
        }

    def start_protection(self, paths: List[str] = None):
        """Start real-time protection"""
        try:
            if paths is None:
                paths = (
                    [os.path.expanduser("~"), "/tmp"]
                    if os.name != "nt"
                    else [os.environ.get("USERPROFILE", ""), os.environ.get("TEMP", "")]
                )

            self.monitoring_paths = paths
            self.stats["start_time"] = time.time()

            # Start file system monitoring
            for path in paths:
                if os.path.exists(path):
                    self.observer.schedule(self.file_monitor, path, recursive=True)
                    print(colored(f"Monitoring path: {path}", "green"))

            self.observer.start()

            # Start process and network monitoring
            self.process_monitor.start_monitoring()
            self.network_monitor.start_monitoring()

            self.is_active = True
            print(colored("🛡️ Real-time protection ACTIVATED", "green"))

        except Exception as e:
            print(colored(f"Error starting real-time protection: {e}", "red"))

    def stop_protection(self):
        """Stop real-time protection"""
        try:
            self.is_active = False

            # Stop file system monitoring
            self.observer.stop()
            self.observer.join()

            # Stop process and network monitoring
            self.process_monitor.stop_monitoring()
            self.network_monitor.stop_monitoring()

            print(colored("🛡️ Real-time protection DEACTIVATED", "yellow"))

        except Exception as e:
            print(colored(f"Error stopping real-time protection: {e}", "red"))

    def _handle_file_event(self, event_data: Dict):
        """Handle file system events"""
        try:
            self.stats["files_monitored"] += 1

            # Check if file is suspicious
            if self._is_suspicious_file_event(event_data):
                self.stats["suspicious_activities"] += 1
                print(colored(f"🔍 Suspicious file activity detected:", "yellow"))
                print(colored(f"  Type: {event_data['type']}", "yellow"))
                print(colored(f"  Path: {event_data['path']}", "yellow"))

                # Trigger scan if callback is provided
                if self.scanner_callback and os.path.exists(event_data["path"]):
                    threading.Thread(
                        target=self._scan_suspicious_file,
                        args=(event_data["path"],),
                        daemon=True,
                    ).start()

        except Exception as e:
            print(colored(f"Error handling file event: {e}", "red"))

    def _is_suspicious_file_event(self, event_data: Dict) -> bool:
        """Check if file event is suspicious"""
        # File created in suspicious location
        if event_data["is_suspicious_location"]:
            return True

        # Large file created quickly
        if (
            event_data["type"] == "created" and event_data["size"] > 10 * 1024 * 1024
        ):  # >10MB
            return True

        # Executable file created
        if Path(event_data["path"]).suffix.lower() in [".exe", ".scr", ".bat", ".cmd"]:
            return True

        return False

    def _scan_suspicious_file(self, file_path: str):
        """Scan suspicious file"""
        try:
            if self.scanner_callback:
                print(colored(f"🔍 Scanning suspicious file: {file_path}", "cyan"))
                result = self.scanner_callback(file_path)

                if result and result.get("status") == "infected":
                    self.stats["threats_detected"] += 1
                    print(colored(f"🚨 THREAT DETECTED in real-time scan!", "red"))
                    print(colored(f"  File: {file_path}", "red"))
                    print(
                        colored(
                            f"  Threat: {result.get('threat_name', 'Unknown')}", "red"
                        )
                    )

        except Exception as e:
            print(colored(f"Error scanning suspicious file: {e}", "red"))

    def get_protection_status(self) -> Dict:
        """Get real-time protection status"""
        uptime = (
            time.time() - self.stats["start_time"] if self.stats["start_time"] else 0
        )

        return {
            "is_active": self.is_active,
            "uptime_seconds": uptime,
            "monitored_paths": self.monitoring_paths,
            "statistics": self.stats,
            "process_stats": self.process_monitor.get_process_statistics(),
            "suspicious_connections": len(self.network_monitor.suspicious_connections),
        }

    def add_monitoring_path(self, path: str):
        """Add new path to monitoring"""
        if os.path.exists(path) and path not in self.monitoring_paths:
            self.observer.schedule(self.file_monitor, path, recursive=True)
            self.monitoring_paths.append(path)
            print(colored(f"Added monitoring path: {path}", "green"))

    def remove_monitoring_path(self, path: str):
        """Remove path from monitoring"""
        if path in self.monitoring_paths:
            # Note: watchdog doesn't have a direct way to unschedule specific paths
            # In a production system, you'd need to restart the observer
            self.monitoring_paths.remove(path)
            print(colored(f"Removed monitoring path: {path}", "yellow"))
