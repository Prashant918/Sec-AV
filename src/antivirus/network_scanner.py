import socket
import threading
import time
import subprocess
import re
import psutil
from typing import Dict, List, Tuple, Optional
from termcolor import colored
import ipaddress
import json


class NetworkSecurityScanner:
    """Advanced network security scanner"""

    def __init__(self):
        self.scan_results = {}
        self.suspicious_connections = []
        self.malicious_domains = self._load_malicious_domains()
        self.suspicious_ports = self._load_suspicious_ports()
        self.network_interfaces = self._get_network_interfaces()

    def _load_malicious_domains(self) -> List[str]:
        """Load known malicious domains"""
        return [
            "malware-domain.com",
            "phishing-site.net",
            "trojan-c2.org",
            "botnet-command.info",
            "ransomware-payment.biz",
            "fake-bank.com",
            "scam-lottery.net",
        ]

    def _load_suspicious_ports(self) -> Dict[str, List[int]]:
        """Load suspicious port ranges"""
        return {
            "backdoors": [1337, 31337, 12345, 54321, 9999, 40421, 40422],
            "trojans": [2023, 2115, 3024, 4092, 5321, 5400, 5401, 5402],
            "remote_access": [3389, 5900, 5901, 4899, 6129, 6667],
            "p2p_malware": [6881, 6882, 6883, 6884, 6885, 6886, 6887],
            "botnet_c2": [6666, 7777, 8080, 8888, 9090],
            "crypto_mining": [3333, 4444, 8332, 8333, 9332, 9333],
        }

    def _get_network_interfaces(self) -> List[Dict]:
        """Get network interface information"""
        interfaces = []

        try:
            for interface_name, addresses in psutil.net_if_addrs().items():
                interface_info = {"name": interface_name, "addresses": []}

                for addr in addresses:
                    if addr.family == socket.AF_INET:  # IPv4
                        interface_info["addresses"].append(
                            {
                                "type": "IPv4",
                                "address": addr.address,
                                "netmask": addr.netmask,
                                "broadcast": addr.broadcast,
                            }
                        )
                    elif addr.family == socket.AF_INET6:  # IPv6
                        interface_info["addresses"].append(
                            {
                                "type": "IPv6",
                                "address": addr.address,
                                "netmask": addr.netmask,
                            }
                        )

                if interface_info["addresses"]:
                    interfaces.append(interface_info)

        except Exception as e:
            print(colored(f"Error getting network interfaces: {e}", "red"))

        return interfaces

    def scan_network_connections(self) -> Dict:
        """Scan current network connections for threats"""
        print(colored("🌐 Scanning network connections...", "blue"))

        scan_result = {
            "total_connections": 0,
            "suspicious_connections": [],
            "malicious_connections": [],
            "connection_summary": {},
            "scan_time": time.time(),
        }

        try:
            connections = psutil.net_connections(kind="inet")
            scan_result["total_connections"] = len(connections)

            for conn in connections:
                analysis = self._analyze_connection(conn)

                if analysis["is_malicious"]:
                    scan_result["malicious_connections"].append(analysis)
                elif analysis["is_suspicious"]:
                    scan_result["suspicious_connections"].append(analysis)

                # Update connection summary
                status = conn.status
                scan_result["connection_summary"][status] = (
                    scan_result["connection_summary"].get(status, 0) + 1
                )

            print(
                colored(
                    f"Network scan completed: {len(scan_result['malicious_connections'])} malicious, "
                    f"{len(scan_result['suspicious_connections'])} suspicious connections",
                    "green",
                )
            )

        except Exception as e:
            scan_result["error"] = str(e)
            print(colored(f"Error scanning network connections: {e}", "red"))

        return scan_result

    def _analyze_connection(self, connection) -> Dict:
        """Analyze individual network connection"""
        analysis = {
            "local_address": (
                f"{connection.laddr.ip}:{connection.laddr.port}"
                if connection.laddr
                else "Unknown"
            ),
            "remote_address": (
                f"{connection.raddr.ip}:{connection.raddr.port}"
                if connection.raddr
                else "Unknown"
            ),
            "status": connection.status,
            "pid": connection.pid,
            "process_name": "Unknown",
            "is_suspicious": False,
            "is_malicious": False,
            "threat_indicators": [],
        }

        # Get process information
        try:
            if connection.pid:
                process = psutil.Process(connection.pid)
                analysis["process_name"] = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        if connection.raddr:
            remote_ip = connection.raddr.ip
            remote_port = connection.raddr.port

            # Check for malicious domains/IPs
            if self._is_malicious_ip(remote_ip):
                analysis["is_malicious"] = True
                analysis["threat_indicators"].append("Known malicious IP")

            # Check for suspicious ports
            port_category = self._check_suspicious_port(remote_port)
            if port_category:
                analysis["is_suspicious"] = True
                analysis["threat_indicators"].append(
                    f"Suspicious port: {port_category}"
                )

            # Check for unusual connections
            if self._is_unusual_connection(connection):
                analysis["is_suspicious"] = True
                analysis["threat_indicators"].append("Unusual connection pattern")

            # Check for geographic anomalies (simulated)
            if self._is_suspicious_geography(remote_ip):
                analysis["is_suspicious"] = True
                analysis["threat_indicators"].append(
                    "Connection to suspicious geographic location"
                )

        return analysis

    def _is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is known to be malicious"""
        # Simulate malicious IP detection
        malicious_ips = ["192.168.100.50", "10.0.0.100", "172.16.0.50"]
        return ip in malicious_ips

    def _check_suspicious_port(self, port: int) -> Optional[str]:
        """Check if port is suspicious"""
        for category, ports in self.suspicious_ports.items():
            if port in ports:
                return category
        return None

    def _is_unusual_connection(self, connection) -> bool:
        """Check for unusual connection patterns"""
        if not connection.raddr:
            return False

        # Check for connections to high ports
        if connection.raddr.port > 49152:  # Dynamic/private ports
            return True

        # Check for connections from system processes to external IPs
        try:
            if connection.pid:
                process = psutil.Process(connection.pid)
                system_processes = ["svchost.exe", "system", "winlogon.exe"]
                if process.name().lower() in system_processes:
                    if not self._is_private_ip(connection.raddr.ip):
                        return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return False

    def _is_suspicious_geography(self, ip: str) -> bool:
        """Check if IP is from suspicious geographic location"""
        # Simulate geographic checking
        # In production, this would use GeoIP databases
        try:
            # Check if IP is from known suspicious ranges
            suspicious_ip_ranges = [
                "203.0.113.",  # TEST-NET-3 (RFC 5737)
                "198.51.100.",  # TEST-NET-2 (RFC 5737)
                "192.0.2.",  # TEST-NET-1 (RFC 5737)
            ]

            for suspicious_range in suspicious_ip_ranges:
                if ip.startswith(suspicious_range):
                    return True

            return False
        except Exception:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except (ipaddress.AddressValueError, ValueError):
            return False

    def scan_open_ports(
        self, target_ip: str = None, port_range: tuple = (1, 1024)
    ) -> Dict:
        """Scan for open ports on target IP"""
        if target_ip is None:
            target_ip = "127.0.0.1"  # Scan localhost by default

        print(
            colored(
                f"🔍 Scanning ports {port_range[0]}-{port_range[1]} on {target_ip}...",
                "blue",
            )
        )

        scan_result = {
            "target_ip": target_ip,
            "port_range": port_range,
            "open_ports": [],
            "suspicious_ports": [],
            "services_detected": {},
            "scan_time": time.time(),
        }

        start_port, end_port = port_range

        for port in range(start_port, min(end_port + 1, 65536)):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    scan_result["open_ports"].append(port)

                    # Check if port is suspicious
                    port_category = self._check_suspicious_port(port)
                    if port_category:
                        scan_result["suspicious_ports"].append(
                            {"port": port, "category": port_category}
                        )

                    # Try to identify service
                    service = self._identify_service(target_ip, port)
                    if service:
                        scan_result["services_detected"][port] = service

                sock.close()

            except Exception:
                continue

        print(
            colored(
                f"Port scan completed: {len(scan_result['open_ports'])} open ports found",
                "green",
            )
        )

        if scan_result["suspicious_ports"]:
            print(
                colored(
                    f"⚠️ {len(scan_result['suspicious_ports'])} suspicious ports detected!",
                    "yellow",
                )
            )

        return scan_result

    def _identify_service(self, ip: str, port: int) -> Optional[str]:
        """Try to identify service running on port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))

            # Send a simple HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                response = sock.recv(1024).decode("utf-8", errors="ignore")
                if "HTTP" in response:
                    return "HTTP Server"

            # Check for SSH
            elif port == 22:
                response = sock.recv(1024).decode("utf-8", errors="ignore")
                if "SSH" in response:
                    return "SSH Server"

            # Check for FTP
            elif port == 21:
                response = sock.recv(1024).decode("utf-8", errors="ignore")
                if "220" in response:
                    return "FTP Server"

            # Check for SMTP
            elif port == 25:
                response = sock.recv(1024).decode("utf-8", errors="ignore")
                if "220" in response:
                    return "SMTP Server"

            sock.close()
            return "Unknown Service"

        except Exception:
            return None

    def detect_network_anomalies(self) -> Dict:
        """Detect network anomalies and suspicious activities"""
        print(colored("🔍 Detecting network anomalies...", "blue"))

        anomalies = {
            "dns_anomalies": [],
            "traffic_anomalies": [],
            "connection_anomalies": [],
            "bandwidth_anomalies": [],
            "scan_time": time.time(),
        }

        # Check DNS queries
        dns_anomalies = self._check_dns_anomalies()
        anomalies["dns_anomalies"] = dns_anomalies

        # Check traffic patterns
        traffic_anomalies = self._check_traffic_patterns()
        anomalies["traffic_anomalies"] = traffic_anomalies

        # Check connection patterns
        connection_anomalies = self._check_connection_patterns()
        anomalies["connection_anomalies"] = connection_anomalies

        # Check bandwidth usage
        bandwidth_anomalies = self._check_bandwidth_anomalies()
        anomalies["bandwidth_anomalies"] = bandwidth_anomalies

        total_anomalies = sum(len(v) for v in anomalies.values() if isinstance(v, list))

        if total_anomalies > 0:
            print(colored(f"⚠️ {total_anomalies} network anomalies detected", "yellow"))
        else:
            print(colored("✅ No network anomalies detected", "green"))

        return anomalies

    def _check_dns_anomalies(self) -> List[str]:
        """Check for DNS-related anomalies"""
        anomalies = []

        # Simulate DNS anomaly detection
        if self._random_chance(0.2):  # 20% chance for demo
            anomalies.extend(
                [
                    "Unusual DNS query volume detected",
                    "DNS queries to suspicious domains",
                    "DNS tunneling activity suspected",
                ]
            )

        return anomalies

    def _check_traffic_patterns(self) -> List[str]:
        """Check for unusual traffic patterns"""
        anomalies = []

        # Simulate traffic pattern analysis
        if self._random_chance(0.15):  # 15% chance for demo
            anomalies.extend(
                [
                    "Unusual outbound traffic volume",
                    "Suspicious data exfiltration pattern",
                    "Encrypted traffic to unknown destinations",
                ]
            )

        return anomalies

    def _check_connection_patterns(self) -> List[str]:
        """Check for unusual connection patterns"""
        anomalies = []

        # Simulate connection pattern analysis
        if self._random_chance(0.1):  # 10% chance for demo
            anomalies.extend(
                [
                    "Multiple connections to same external IP",
                    "Rapid connection establishment/teardown",
                    "Connections during unusual hours",
                ]
            )

        return anomalies

    def _check_bandwidth_anomalies(self) -> List[str]:
        """Check for bandwidth usage anomalies"""
        anomalies = []

        try:
            # Get current network statistics
            net_io = psutil.net_io_counters()

            # Simulate bandwidth anomaly detection
            if self._random_chance(0.12):  # 12% chance for demo
                anomalies.extend(
                    [
                        "Unusual bandwidth consumption detected",
                        "Potential data exfiltration activity",
                        "Suspicious upload/download ratio",
                    ]
                )

        except Exception as e:
            anomalies.append(f"Error checking bandwidth: {str(e)}")

        return anomalies

    def _random_chance(self, probability: float) -> bool:
        """Generate random chance for simulation"""
        import random

        return random.random() < probability

    def monitor_network_traffic(self, duration: int = 60) -> Dict:
        """Monitor network traffic for specified duration"""
        print(
            colored(f"📊 Monitoring network traffic for {duration} seconds...", "blue")
        )

        monitoring_result = {
            "duration": duration,
            "start_time": time.time(),
            "traffic_summary": {},
            "suspicious_activities": [],
            "connection_events": [],
        }

        start_stats = psutil.net_io_counters()
        start_time = time.time()

        # Monitor for specified duration
        time.sleep(duration)

        end_stats = psutil.net_io_counters()
        end_time = time.time()

        # Calculate traffic statistics
        bytes_sent = end_stats.bytes_sent - start_stats.bytes_sent
        bytes_recv = end_stats.bytes_recv - start_stats.bytes_recv
        packets_sent = end_stats.packets_sent - start_stats.packets_sent
        packets_recv = end_stats.packets_recv - start_stats.packets_recv

        monitoring_result["traffic_summary"] = {
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_recv,
            "packets_sent": packets_sent,
            "packets_received": packets_recv,
            "avg_bytes_per_second": (bytes_sent + bytes_recv) / duration,
            "avg_packets_per_second": (packets_sent + packets_recv) / duration,
        }

        # Analyze for suspicious activities
        if bytes_sent > 100 * 1024 * 1024:  # > 100MB sent
            monitoring_result["suspicious_activities"].append(
                "High outbound data volume"
            )

        if packets_sent > 10000:  # > 10k packets
            monitoring_result["suspicious_activities"].append(
                "High packet transmission rate"
            )

        monitoring_result["end_time"] = end_time

        print(
            colored(
                f"Traffic monitoring completed: {bytes_sent + bytes_recv} bytes transferred",
                "green",
            )
        )

        return monitoring_result

    def generate_network_report(self, scan_results: Dict) -> str:
        """Generate comprehensive network security report"""
        report = f"""
{colored('='*70, 'cyan')}
{colored('NETWORK SECURITY SCAN REPORT', 'cyan')}
{colored('='*70, 'cyan')}

Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_results.get('scan_time', time.time())))}

NETWORK INTERFACES:
"""

        for interface in self.network_interfaces:
            report += f"  • {interface['name']}\n"
            for addr in interface["addresses"]:
                report += f"    - {addr['type']}: {addr['address']}\n"

        if "total_connections" in scan_results:
            report += f"""
CONNECTION ANALYSIS:
  Total Connections: {scan_results['total_connections']}
  Malicious Connections: {len(scan_results.get('malicious_connections', []))}
  Suspicious Connections: {len(scan_results.get('suspicious_connections', []))}
"""

        if scan_results.get("malicious_connections"):
            report += colored("\nMALICIOUS CONNECTIONS:\n", "red")
            for conn in scan_results["malicious_connections"]:
                report += f"  • {conn['remote_address']} ({conn['process_name']})\n"
                for indicator in conn["threat_indicators"]:
                    report += f"    - {indicator}\n"

        if scan_results.get("suspicious_connections"):
            report += colored("\nSUSPICIOUS CONNECTIONS:\n", "yellow")
            for conn in scan_results["suspicious_connections"][:10]:  # Show first 10
                report += f"  • {conn['remote_address']} ({conn['process_name']})\n"
                for indicator in conn["threat_indicators"]:
                    report += f"    - {indicator}\n"

        if "open_ports" in scan_results:
            report += f"""
PORT SCAN RESULTS:
  Target: {scan_results.get('target_ip', 'Unknown')}
  Open Ports: {len(scan_results['open_ports'])}
  Suspicious Ports: {len(scan_results.get('suspicious_ports', []))}
"""

            if scan_results.get("suspicious_ports"):
                report += colored("\nSUSPICIOUS PORTS:\n", "yellow")
                for port_info in scan_results["suspicious_ports"]:
                    report += f"  • Port {port_info['port']}: {port_info['category']}\n"

        report += colored("=" * 70, "cyan")
        return report

    def get_network_statistics(self) -> Dict:
        """Get network scanning statistics"""
        return {
            "total_scans_performed": len(self.scan_results),
            "suspicious_connections_found": len(self.suspicious_connections),
            "network_interfaces_detected": len(self.network_interfaces),
            "malicious_domains_in_database": len(self.malicious_domains),
        }
