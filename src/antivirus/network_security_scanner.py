import socket
import threading
import time
import struct
import asyncio
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import ipaddress
import ssl
import hashlib
import json
from collections import defaultdict, deque

# Try to import optional dependencies
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from scapy.all import *
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

class NetworkThreatType(Enum):
    MALICIOUS_DOMAIN = "malicious_domain"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    PORT_SCAN = "port_scan"
    DGA_DOMAIN = "dga_domain"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    BOTNET_ACTIVITY = "botnet_activity"
    PHISHING_SITE = "phishing_site"

@dataclass
class NetworkThreat:
    threat_type: NetworkThreatType
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    threat_description: str
    confidence: float
    evidence: Dict
    timestamp: float

class SSLAnalyzer:
    """Simple SSL/TLS certificate analyzer"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def analyze_certificate(self, hostname: str, port: int = 443) -> Dict:
        """Analyze SSL certificate for suspicious indicators"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'is_suspicious': self._is_suspicious_cert(cert)
                    }
        except Exception as e:
            self.logger.debug(f"SSL analysis failed for {hostname}:{port}: {e}")
            return {'error': str(e)}
    
    def _is_suspicious_cert(self, cert: Dict) -> bool:
        """Check if certificate has suspicious characteristics"""
        try:
            # Check for self-signed certificates
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            
            if subject == issuer:
                return True
            
            # Check for suspicious common names
            common_name = subject.get('commonName', '').lower()
            suspicious_patterns = ['localhost', '127.0.0.1', 'test', 'example']
            
            if any(pattern in common_name for pattern in suspicious_patterns):
                return True
            
            return False
            
        except Exception:
            return False

class NetworkSecurityScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Network monitoring state
        self.monitoring = False
        self.monitor_thread = None
        
        # Threat detection
        self.detected_threats = deque(maxlen=config.get('max_threats', 10000))
        self.connection_tracker = defaultdict(list)
        
        # Malicious indicators
        self.malicious_domains = set()
        self.malicious_ips = set()
        self.suspicious_ports = {4444, 5555, 6666, 7777, 8888, 9999, 31337}
        
        # DGA detection
        self.dga_patterns = self._load_dga_patterns()
        
        # Traffic analysis
        self.traffic_stats = defaultdict(int)
        self.connection_counts = defaultdict(int)
        
        # Load threat intelligence
        self._load_threat_intelligence()
        
        # DNS monitoring
        self.dns_queries = deque(maxlen=1000)
        
        # SSL/TLS analysis
        self.ssl_analyzer = SSLAnalyzer()
        
        # Performance tracking
        self.performance_stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'dns_queries_analyzed': 0,
            'ssl_connections_analyzed': 0
        }
    
    def _load_threat_intelligence(self):
        """Load threat intelligence feeds"""
        try:
            # Load from configuration or external sources
            threat_feeds = self.config.get('threat_feeds', {})
            
            # Malicious domains
            if 'malicious_domains' in threat_feeds:
                self.malicious_domains.update(threat_feeds['malicious_domains'])
            
            # Malicious IPs
            if 'malicious_ips' in threat_feeds:
                self.malicious_ips.update(threat_feeds['malicious_ips'])
            
            # Add some default known malicious indicators
            default_malicious_domains = {
                'malware.com', 'phishing.net', 'badsite.org',
                'c2server.ru', 'botnet.tk'
            }
            self.malicious_domains.update(default_malicious_domains)
            
            self.logger.info(f"Loaded {len(self.malicious_domains)} malicious domains and {len(self.malicious_ips)} malicious IPs")
            
        except Exception as e:
            self.logger.error(f"Error loading threat intelligence: {e}")
    
    def _load_dga_patterns(self) -> List[Dict]:
        """Load Domain Generation Algorithm patterns"""
        return [
            {
                'name': 'conficker',
                'pattern': r'^[a-z]{8,12}\.(com|net|org|info|biz)$',
                'entropy_threshold': 3.5
            },
            {
                'name': 'cryptolocker',
                'pattern': r'^[a-z]{12,16}\.(com|ru|net)$',
                'entropy_threshold': 4.0
            },
            {
                'name': 'generic_dga',
                'pattern': r'^[a-z]{10,20}\.(tk|ml|ga|cf)$',
                'entropy_threshold': 3.8
            }
        ]
    
    def start_monitoring(self, interface: Optional[str] = None):
        """Start network monitoring"""
        if self.monitoring:
            self.logger.warning("Network monitoring already running")
            return
        
        if not HAS_SCAPY:
            self.logger.error("Scapy not available, network monitoring disabled")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_network_traffic,
            args=(interface,),
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info("Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        self.logger.info("Network monitoring stopped")
    
    def _monitor_network_traffic(self, interface: Optional[str]):
        """Monitor network traffic using packet capture"""
        try:
            if not HAS_SCAPY:
                self.logger.error("Scapy not available for packet capture")
                return
            
            # Start packet capture
            sniff(
                iface=interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.monitoring,
                store=False
            )
        except Exception as e:
            self.logger.error(f"Error monitoring network traffic: {e}")
    
    def _process_packet(self, packet):
        """Process captured network packet"""
        try:
            self.performance_stats['packets_processed'] += 1
            
            # Extract packet information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Track connection
                self._track_connection(src_ip, dst_ip, protocol)
                
                # Analyze different protocols
                if TCP in packet:
                    self._analyze_tcp_packet(packet)
                elif UDP in packet:
                    self._analyze_udp_packet(packet)
                elif DNS in packet:
                    self._analyze_dns_packet(packet)
                
                # Check for malicious IPs
                self._check_malicious_ips(src_ip, dst_ip, packet)
                
                # Detect suspicious patterns
                self._detect_suspicious_patterns(packet)
                
        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")
    
    def _analyze_tcp_packet(self, packet):
        """Analyze TCP packet for threats"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Check for suspicious ports
            if dst_port in self.suspicious_ports:
                threat = NetworkThreat(
                    threat_type=NetworkThreatType.SUSPICIOUS_TRAFFIC,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol="TCP",
                    threat_description=f"Connection to suspicious port {dst_port}",
                    confidence=0.6,
                    evidence={
                        'suspicious_port': dst_port,
                        'packet_size': len(packet)
                    },
                    timestamp=time.time()
                )
                self._add_threat(threat)
            
            # Detect port scanning
            self._detect_port_scan(src_ip, dst_ip, dst_port)
            
            # Analyze payload for C2 patterns
            if Raw in packet:
                self._analyze_payload_for_c2(packet, src_ip, dst_ip, src_port, dst_port)
            
        except Exception as e:
            self.logger.debug(f"Error analyzing TCP packet: {e}")
    
    def _analyze_udp_packet(self, packet):
        """Analyze UDP packet for threats"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Check for DNS tunneling
            if dst_port == 53 and Raw in packet:
                self._detect_dns_tunneling(packet)
            
            # Check for suspicious UDP traffic
            if dst_port in self.suspicious_ports:
                threat = NetworkThreat(
                    threat_type=NetworkThreatType.SUSPICIOUS_TRAFFIC,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol="UDP",
                    threat_description=f"UDP traffic to suspicious port {dst_port}",
                    confidence=0.5,
                    evidence={
                        'suspicious_port': dst_port,
                        'packet_size': len(packet)
                    },
                    timestamp=time.time()
                )
                self._add_threat(threat)
                
        except Exception as e:
            self.logger.debug(f"Error analyzing UDP packet: {e}")
    
    def _analyze_dns_packet(self, packet):
        """Analyze DNS packet for threats"""
        try:
            if DNSQR in packet:
                query_name = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                
                # Store DNS query
                self.dns_queries.append({
                    'query': query_name,
                    'timestamp': time.time(),
                    'source_ip': packet[IP].src
                })
                self.performance_stats['dns_queries_analyzed'] += 1
                
                # Check against malicious domains
                if query_name in self.malicious_domains:
                    threat = NetworkThreat(
                        threat_type=NetworkThreatType.MALICIOUS_DOMAIN,
                        source_ip=packet[IP].src,
                        destination_ip=packet[IP].dst,
                        source_port=packet[UDP].sport if UDP in packet else 0,
                        destination_port=packet[UDP].dport if UDP in packet else 0,
                        protocol="DNS",
                        threat_description=f"DNS query to known malicious domain: {query_name}",
                        confidence=0.9,
                        evidence={
                            'domain': query_name,
                            'query_type': packet[DNSQR].qtype
                        },
                        timestamp=time.time()
                    )
                    self._add_threat(threat)
                
                # Check for DGA domains
                if self._is_dga_domain(query_name):
                    threat = NetworkThreat(
                        threat_type=NetworkThreatType.DGA_DOMAIN,
                        source_ip=packet[IP].src,
                        destination_ip=packet[IP].dst,
                        source_port=packet[UDP].sport if UDP in packet else 0,
                        destination_port=packet[UDP].dport if UDP in packet else 0,
                        protocol="DNS",
                        threat_description=f"Potential DGA domain detected: {query_name}",
                        confidence=0.7,
                        evidence={
                            'domain': query_name,
                            'dga_indicators': self._get_dga_indicators(query_name)
                        },
                        timestamp=time.time()
                    )
                    self._add_threat(threat)
                    
        except Exception as e:
            self.logger.debug(f"Error analyzing DNS packet: {e}")
    
    def _detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int):
        """Detect port scanning activity"""
        current_time = time.time()
        
        # Track connections from source IP
        key = f"{src_ip}->{dst_ip}"
        self.connection_tracker[key].append({
            'port': dst_port,
            'timestamp': current_time
        })
        
        # Clean old connections (older than 60 seconds)
        self.connection_tracker[key] = [
            conn for conn in self.connection_tracker[key]
            if current_time - conn['timestamp'] < 60
        ]
        
        # Check for port scan pattern
        recent_connections = self.connection_tracker[key]
        unique_ports = set(conn['port'] for conn in recent_connections)
        
        # If many unique ports accessed in short time, it's likely a port scan
        if len(unique_ports) > 10:
            threat = NetworkThreat(
                threat_type=NetworkThreatType.PORT_SCAN,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=0,
                destination_port=0,
                protocol="TCP",
                threat_description=f"Port scan detected from {src_ip} to {dst_ip}",
                confidence=0.8,
                evidence={
                    'unique_ports_accessed': len(unique_ports),
                    'time_window': 60,
                    'ports': list(unique_ports)
                },
                timestamp=current_time
            )
            self._add_threat(threat)
    
    def _detect_dns_tunneling(self, packet):
        """Detect DNS tunneling attempts"""
        try:
            if DNSQR in packet:
                query_name = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                
                # Check for suspicious characteristics
                suspicious_indicators = []
                
                # Very long subdomain names
                subdomains = query_name.split('.')
                for subdomain in subdomains[:-2]:  # Exclude TLD and domain
                    if len(subdomain) > 50:
                        suspicious_indicators.append('long_subdomain')
                
                # High entropy in subdomain
                for subdomain in subdomains[:-2]:
                    if self._calculate_entropy(subdomain.encode()) > 4.0:
                        suspicious_indicators.append('high_entropy')
                
                # Base64-like patterns
                if len(subdomains) > 0 and re.match(r'^[A-Za-z0-9+/=]+$', subdomains[0]) and len(subdomains[0]) > 20:
                    suspicious_indicators.append('base64_pattern')
                
                # If multiple indicators, flag as potential tunneling
                if len(suspicious_indicators) >= 2:
                    threat = NetworkThreat(
                        threat_type=NetworkThreatType.SUSPICIOUS_TRAFFIC,
                        source_ip=packet[IP].src,
                        destination_ip=packet[IP].dst,
                        source_port=packet[UDP].sport,
                        destination_port=packet[UDP].dport,
                        protocol="DNS",
                        threat_description=f"Potential DNS tunneling detected: {query_name}",
                        confidence=0.6,
                        evidence={
                            'domain': query_name,
                            'suspicious_indicators': suspicious_indicators
                        },
                        timestamp=time.time()
                    )
                    self._add_threat(threat)
                    
        except Exception as e:
            self.logger.debug(f"Error detecting DNS tunneling: {e}")
    
    def _analyze_payload_for_c2(self, packet, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Analyze packet payload for C2 communication patterns"""
        try:
            payload = packet[Raw].load
            
            # Check for common C2 patterns
            c2_indicators = []
            
            # Base64 encoded data
            base64_pattern = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
            if base64_pattern.search(payload):
                c2_indicators.append('base64_data')
            
            # Encrypted/compressed data (high entropy)
            if len(payload) > 100 and self._calculate_entropy(payload) > 7.0:
                c2_indicators.append('high_entropy_payload')
            
            # Common C2 keywords
            c2_keywords = [b'cmd', b'exec', b'shell', b'download', b'upload', b'screenshot']
            for keyword in c2_keywords:
                if keyword in payload.lower():
                    c2_indicators.append(f'keyword_{keyword.decode()}')
            
            # HTTP-based C2 patterns
            if b'HTTP' in payload:
                # Check for suspicious User-Agent strings
                suspicious_agents = [b'curl', b'wget', b'python', b'powershell']
                for agent in suspicious_agents:
                    if agent in payload.lower():
                        c2_indicators.append(f'suspicious_user_agent_{agent.decode()}')
            
            # If multiple indicators, flag as potential C2
            if len(c2_indicators) >= 2:
                threat = NetworkThreat(
                    threat_type=NetworkThreatType.C2_COMMUNICATION,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol="TCP",
                    threat_description="Potential C2 communication detected",
                    confidence=0.7,
                    evidence={
                        'c2_indicators': c2_indicators,
                        'payload_size': len(payload)
                    },
                    timestamp=time.time()
                )
                self._add_threat(threat)
                
        except Exception as e:
            self.logger.debug(f"Error analyzing payload for C2: {e}")
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Check if domain matches DGA patterns"""
        try:
            for pattern_info in self.dga_patterns:
                pattern = pattern_info['pattern']
                entropy_threshold = pattern_info['entropy_threshold']
                
                # Check regex pattern
                if re.match(pattern, domain.lower()):
                    # Check entropy
                    domain_entropy = self._calculate_entropy(domain.encode())
                    if domain_entropy >= entropy_threshold:
                        return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking DGA domain: {e}")
            return False
    
    def _get_dga_indicators(self, domain: str) -> List[str]:
        """Get DGA indicators for a domain"""
        indicators = []
        
        try:
            # Calculate entropy
            entropy = self._calculate_entropy(domain.encode())
            if entropy > 3.5:
                indicators.append(f'high_entropy_{entropy:.2f}')
            
            # Check for random-looking patterns
            if re.match(r'^[a-z]{8,20}$', domain.split('.')[0]):
                indicators.append('random_string_pattern')
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    indicators.append(f'suspicious_tld_{tld}')
            
        except Exception as e:
            self.logger.debug(f"Error getting DGA indicators: {e}")
        
        return indicators
    
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
                import math
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_malicious_ips(self, src_ip: str, dst_ip: str, packet):
        """Check for communication with malicious IPs"""
        malicious_ip = None
        direction = None
        
        if src_ip in self.malicious_ips:
            malicious_ip = src_ip
            direction = "inbound"
        elif dst_ip in self.malicious_ips:
            malicious_ip = dst_ip
            direction = "outbound"
        
        if malicious_ip:
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
            
            threat = NetworkThreat(
                threat_type=NetworkThreatType.MALICIOUS_DOMAIN,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                threat_description=f"Communication with known malicious IP: {malicious_ip}",
                confidence=0.9,
                evidence={
                    'malicious_ip': malicious_ip,
                    'direction': direction
                },
                timestamp=time.time()
            )
            self._add_threat(threat)
    
    def _detect_suspicious_patterns(self, packet):
        """Detect various suspicious network patterns"""
        try:
            # Detect data exfiltration patterns
            if Raw in packet and len(packet[Raw].load) > 1000:
                # Large outbound data transfers
                if self._is_outbound_traffic(packet):
                    self._check_data_exfiltration(packet)
            
            # Detect beaconing behavior
            self._detect_beaconing(packet)
            
        except Exception as e:
            self.logger.debug(f"Error detecting suspicious patterns: {e}")
    
    def _is_outbound_traffic(self, packet) -> bool:
        """Check if traffic is outbound (simplified)"""
        try:
            src_ip = ipaddress.ip_address(packet[IP].src)
            dst_ip = ipaddress.ip_address(packet[IP].dst)
            
            # Check if source is private and destination is public
            return src_ip.is_private and not dst_ip.is_private
        except:
            return False
    
    def _check_data_exfiltration(self, packet):
        """Check for potential data exfiltration"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload_size = len(packet[Raw].load)
            
            # Track large transfers
            transfer_key = f"{src_ip}->{dst_ip}"
            current_time = time.time()
            
            if transfer_key not in self.traffic_stats:
                self.traffic_stats[transfer_key] = {
                    'total_bytes': 0,
                    'start_time': current_time,
                    'packet_count': 0
                }
            
            stats = self.traffic_stats[transfer_key]
            stats['total_bytes'] += payload_size
            stats['packet_count'] += 1
            
            # Check for suspicious transfer patterns
            time_window = current_time - stats['start_time']
            if time_window > 60:  # Reset after 1 minute
                if stats['total_bytes'] > 10 * 1024 * 1024:  # > 10MB
                    protocol = "TCP" if TCP in packet else "UDP"
                    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
                    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
                    
                    threat = NetworkThreat(
                        threat_type=NetworkThreatType.DATA_EXFILTRATION,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        protocol=protocol,
                        threat_description=f"Potential data exfiltration: {stats['total_bytes']} bytes transferred",
                        confidence=0.6,
                        evidence={
                            'total_bytes': stats['total_bytes'],
                            'time_window': time_window,
                            'packet_count': stats['packet_count']
                        },
                        timestamp=current_time
                    )
                    self._add_threat(threat)
                
                # Reset stats
                del self.traffic_stats[transfer_key]
                
        except Exception as e:
            self.logger.debug(f"Error checking data exfiltration: {e}")
    
    def _detect_beaconing(self, packet):
        """Detect beaconing behavior (regular C2 communication)"""
        try:
            if TCP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport
                
                # Track connection timing
                connection_key = f"{src_ip}->{dst_ip}:{dst_port}"
                current_time = time.time()
                
                if connection_key not in self.connection_tracker:
                    self.connection_tracker[connection_key] = []
                
                self.connection_tracker[connection_key].append(current_time)
                
                # Keep only recent connections (last 10 minutes)
                recent_connections = [
                    t for t in self.connection_tracker[connection_key]
                    if current_time - t < 600
                ]
                self.connection_tracker[connection_key] = recent_connections
                
                # Check for regular intervals (beaconing)
                if len(recent_connections) >= 5:
                    intervals = []
                    for i in range(1, len(recent_connections)):
                        interval = recent_connections[i] - recent_connections[i-1]
                        intervals.append(interval)
                    
                    # Check if intervals are regular (low variance)
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                        
                        # If variance is low and interval is reasonable for beaconing
                        if variance < 10 and 30 <= avg_interval <= 300:  # 30s to 5min intervals
                            threat = NetworkThreat(
                                threat_type=NetworkThreatType.C2_COMMUNICATION,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                source_port=packet[TCP].sport,
                                destination_port=dst_port,
                                protocol="TCP",
                                threat_description=f"Potential beaconing detected (avg interval: {avg_interval:.1f}s)",
                                confidence=0.7,
                                evidence={
                                    'avg_interval': avg_interval,
                                    'variance': variance,
                                    'connection_count': len(recent_connections)
                                },
                                timestamp=current_time
                            )
                            self._add_threat(threat)
                            
        except Exception as e:
            self.logger.debug(f"Error detecting beaconing: {e}")
    
    def _track_connection(self, src_ip: str, dst_ip: str, protocol: int):
        """Track network connections for analysis"""
        connection_key = f"{src_ip}->{dst_ip}:{protocol}"
        self.connection_counts[connection_key] += 1
    
    def _add_threat(self, threat: NetworkThreat):
        """Add detected threat to the list"""
        self.detected_threats.append(threat)
        self.performance_stats['threats_detected'] += 1
        self.logger.warning(f"Network threat detected: {threat.threat_description}")
    
    async def scan_url_reputation(self, url: str) -> Dict:
        """Scan URL reputation using multiple sources"""
        try:
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            reputation_data = {
                'url': url,
                'domain': domain,
                'is_malicious': False,
                'confidence': 0.0,
                'sources': []
            }
            
            # Check against known malicious domains
            if domain in self.malicious_domains:
                reputation_data['is_malicious'] = True
                reputation_data['confidence'] = 0.9
                reputation_data['sources'].append('local_blacklist')
            
            # Check for DGA characteristics
            if self._is_dga_domain(domain):
                reputation_data['is_malicious'] = True
                reputation_data['confidence'] = max(reputation_data['confidence'], 0.7)
                reputation_data['sources'].append('dga_detection')
            
            # Analyze SSL certificate if HTTPS
            if parsed_url.scheme == 'https':
                ssl_analysis = self.ssl_analyzer.analyze_certificate(domain)
                if ssl_analysis.get('is_suspicious'):
                    reputation_data['confidence'] = max(reputation_data['confidence'], 0.5)
                    reputation_data['sources'].append('ssl_analysis')
                reputation_data['ssl_info'] = ssl_analysis
            
            return reputation_data
            
        except Exception as e:
            self.logger.error(f"Error scanning URL reputation: {e}")
            return {
                'url': url,
                'error': str(e),
                'is_malicious': False,
                'confidence': 0.0
            }
    
    def scan_network_connections(self) -> List[Dict]:
        """Scan current network connections for threats"""
        threats = []
        
        try:
            import psutil
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    # Check for suspicious connections
                    threat_info = self._analyze_connection(conn)
                    if threat_info:
                        threats.append(threat_info)
                        
        except Exception as e:
            self.logger.error(f"Error scanning network connections: {e}")
        
        return threats
    
    def _analyze_connection(self, conn) -> Optional[Dict]:
        """Analyze a single network connection"""
        try:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            
            threat_indicators = []
            confidence = 0.0
            
            # Check against malicious IPs
            if remote_ip in self.malicious_ips:
                threat_indicators.append('malicious_ip')
                confidence = max(confidence, 0.9)
            
            # Check for suspicious ports
            if remote_port in self.suspicious_ports:
                threat_indicators.append('suspicious_port')
                confidence = max(confidence, 0.6)
            
            # Check for unusual private-to-private connections
            try:
                local_ip = ipaddress.ip_address(conn.laddr.ip)
                remote_ip_obj = ipaddress.ip_address(remote_ip)
                
                if (local_ip.is_private and remote_ip_obj.is_private and 
                    remote_port > 10000):
                    threat_indicators.append('unusual_private_connection')
                    confidence = max(confidence, 0.4)
                    
            except ValueError:
                pass
            
            # Return threat info if any indicators found
            if threat_indicators:
                return {
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_address': f"{remote_ip}:{remote_port}",
                    'protocol': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                    'status': conn.status,
                    'threat_indicators': threat_indicators,
                    'confidence': confidence,
                    'timestamp': time.time()
                }
            
        except Exception as e:
            self.logger.debug(f"Error analyzing connection: {e}")
        
        return None
    
    def get_dns_statistics(self) -> Dict:
        """Get DNS query statistics"""
        try:
            current_time = time.time()
            recent_queries = [
                q for q in self.dns_queries 
                if current_time - q['timestamp'] < 3600  # Last hour
            ]
            
            # Count unique domains
            unique_domains = set(q['query'] for q in recent_queries)
            
            # Count queries by source IP
            source_counts = defaultdict(int)
            for query in recent_queries:
                source_counts[query['source_ip']] += 1
            
            # Identify top queried domains
            domain_counts = defaultdict(int)
            for query in recent_queries:
                domain_counts[query['query']] += 1
            
            top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                'total_queries_last_hour': len(recent_queries),
                'unique_domains': len(unique_domains),
                'top_source_ips': dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
                'top_domains': dict(top_domains),
                'suspicious_queries': self._get_suspicious_dns_queries()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting DNS statistics: {e}")
            return {}
    
    def _get_suspicious_dns_queries(self) -> List[Dict]:
        """Get suspicious DNS queries from recent history"""
        suspicious = []
        
        try:
            current_time = time.time()
            recent_queries = [
                q for q in self.dns_queries 
                if current_time - q['timestamp'] < 3600  # Last hour
            ]
            
            for query in recent_queries:
                domain = query['query']
                
                # Check for DGA domains
                if self._is_dga_domain(domain):
                    suspicious.append({
                        'domain': domain,
                        'source_ip': query['source_ip'],
                        'timestamp': query['timestamp'],
                        'reason': 'dga_domain',
                        'indicators': self._get_dga_indicators(domain)
                    })
                
                # Check for malicious domains
                elif domain in self.malicious_domains:
                    suspicious.append({
                        'domain': domain,
                        'source_ip': query['source_ip'],
                        'timestamp': query['timestamp'],
                        'reason': 'malicious_domain'
                    })
                
                # Check for suspicious patterns
                elif self._has_suspicious_dns_patterns(domain):
                    suspicious.append({
                        'domain': domain,
                        'source_ip': query['source_ip'],
                        'timestamp': query['timestamp'],
                        'reason': 'suspicious_pattern'
                    })
            
        except Exception as e:
            self.logger.debug(f"Error getting suspicious DNS queries: {e}")
        
        return suspicious[-50:]  # Return last 50 suspicious queries
    
    def _has_suspicious_dns_patterns(self, domain: str) -> bool:
        """Check for suspicious DNS patterns"""
        try:
            # Very long domain names
            if len(domain) > 100:
                return True
            
            # Many subdomains
            if domain.count('.') > 5:
                return True
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # High entropy in domain name
            if self._calculate_entropy(domain.encode()) > 4.5:
                return True
            
            return False
            
        except Exception:
            return False
    
    def get_network_statistics(self) -> Dict:
        """Get comprehensive network security statistics"""
        try:
            current_time = time.time()
            
            # Recent threats (last 24 hours)
            recent_threats = [
                t for t in self.detected_threats 
                if current_time - t.timestamp < 86400
            ]
            
            # Threat type distribution
            threat_types = defaultdict(int)
            for threat in recent_threats:
                threat_types[threat.threat_type.value] += 1
            
            # Top source IPs
            source_ips = defaultdict(int)
            for threat in recent_threats:
                source_ips[threat.source_ip] += 1
            
            # Top destination IPs
            dest_ips = defaultdict(int)
            for threat in recent_threats:
                dest_ips[threat.destination_ip] += 1
            
            stats = {
                'monitoring_active': self.monitoring,
                'total_threats_detected': len(self.detected_threats),
                'threats_last_24h': len(recent_threats),
                'threat_type_distribution': dict(threat_types),
                'top_source_ips': dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
                'top_destination_ips': dict(sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
                'performance_stats': self.performance_stats.copy(),
                'dns_statistics': self.get_dns_statistics(),
                'malicious_indicators_loaded': {
                    'domains': len(self.malicious_domains),
                    'ips': len(self.malicious_ips)
                }
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting network statistics: {e}")
            return {}
    
    def export_threats(self, filepath: str, format: str = 'json'):
        """Export detected threats to file"""
        try:
            threats_data = []
            
            for threat in self.detected_threats:
                threat_dict = {
                    'threat_type': threat.threat_type.value,
                    'source_ip': threat.source_ip,
                    'destination_ip': threat.destination_ip,
                    'source_port': threat.source_port,
                    'destination_port': threat.destination_port,
                    'protocol': threat.protocol,
                    'description': threat.threat_description,
                    'confidence': threat.confidence,
                    'evidence': threat.evidence,
                    'timestamp': threat.timestamp
                }
                threats_data.append(threat_dict)
            
            if format.lower() == 'json':
                with open(filepath, 'w') as f:
                    json.dump(threats_data, f, indent=2, default=str)
            elif format.lower() == 'csv':
                import csv
                with open(filepath, 'w', newline='') as f:
                    if threats_data:
                        writer = csv.DictWriter(f, fieldnames=threats_data[0].keys())
                        writer.writeheader()
                        writer.writerows(threats_data)
            
            self.logger.info(f"Exported {len(threats_data)} threats to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error exporting threats: {e}")
    
    def add_malicious_indicator(self, indicator: str, indicator_type: str):
        """Add a malicious indicator to the database"""
        try:
            if indicator_type.lower() == 'domain':
                self.malicious_domains.add(indicator.lower())
                self.logger.info(f"Added malicious domain: {indicator}")
            elif indicator_type.lower() == 'ip':
                self.malicious_ips.add(indicator)
                self.logger.info(f"Added malicious IP: {indicator}")
            else:
                raise ValueError(f"Unknown indicator type: {indicator_type}")
                
        except Exception as e:
            self.logger.error(f"Error adding malicious indicator: {e}")
    
    def remove_malicious_indicator(self, indicator: str, indicator_type: str):
        """Remove a malicious indicator from the database"""
        try:
            if indicator_type.lower() == 'domain':
                self.malicious_domains.discard(indicator.lower())
                self.logger.info(f"Removed malicious domain: {indicator}")
            elif indicator_type.lower() == 'ip':
                self.malicious_ips.discard(indicator)
                self.logger.info(f"Removed malicious IP: {indicator}")
            else:
                raise ValueError(f"Unknown indicator type: {indicator_type}")
                
        except Exception as e:
            self.logger.error(f"Error removing malicious indicator: {e}")
    
    def clear_threat_history(self):
        """Clear all detected threat history"""
        self.detected_threats.clear()
        self.connection_tracker.clear()
        self.traffic_stats.clear()
        self.connection_counts.clear()
        self.dns_queries.clear()
        
        # Reset performance stats
        self.performance_stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'dns_queries_analyzed': 0,
            'ssl_connections_analyzed': 0
        }
        
        self.logger.info("Network threat history cleared")
    
    def get_recent_threats(self, limit: int = 100) -> List[Dict]:
        """Get recent network threats"""
        recent_threats = list(self.detected_threats)[-limit:]
        
        return [
            {
                'threat_type': threat.threat_type.value,
                'source_ip': threat.source_ip,
                'destination_ip': threat.destination_ip,
                'source_port': threat.source_port,
                'destination_port': threat.destination_port,
                'protocol': threat.protocol,
                'description': threat.threat_description,
                'confidence': threat.confidence,
                'evidence': threat.evidence,
                'timestamp': threat.timestamp
            }
            for threat in recent_threats
        ]
    
    def update_threat_intelligence(self, threat_feeds: Dict):
        """Update threat intelligence with new feeds"""
        try:
            updated_domains = 0
            updated_ips = 0
            
            # Update malicious domains
            if 'malicious_domains' in threat_feeds:
                new_domains = set(threat_feeds['malicious_domains'])
                self.malicious_domains.update(new_domains)
                updated_domains = len(new_domains)
            
            # Update malicious IPs
            if 'malicious_ips' in threat_feeds:
                new_ips = set(threat_feeds['malicious_ips'])
                self.malicious_ips.update(new_ips)
                updated_ips = len(new_ips)
            
            # Update DGA patterns
            if 'dga_patterns' in threat_feeds:
                self.dga_patterns.extend(threat_feeds['dga_patterns'])
            
            self.logger.info(f"Updated threat intelligence: {updated_domains} domains, {updated_ips} IPs")
            
        except Exception as e:
            self.logger.error(f"Error updating threat intelligence: {e}")