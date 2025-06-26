import os
import sys
import pyfiglet
from termcolor import colored
import random
import time
import io
from typing import Iterable

# Import antivirus modules
try:
    from src.antivirus.scanner import FileScanner
    from src.antivirus.config import AntivirusConfig
    from src.antivirus.logger import AntivirusLogger
    from src.antivirus.ml_detector import MLThreatDetector
    from src.antivirus.realtime_monitor import RealTimeProtection
    from src.antivirus.cloud_intel import CloudThreatIntelligence
    from src.antivirus.memory_scanner import MemoryScanner
    from src.antivirus.network_scanner import NetworkSecurityScanner
    from src.antivirus.phishing_detector import PhishingDetector
    from src.antivirus.communication_monitor import CommunicationMonitor
    ANTIVIRUS_AVAILABLE = True
    ADVANCED_FEATURES = True
    PHISHING_PROTECTION = True
except ImportError:
    ANTIVIRUS_AVAILABLE = False
    ADVANCED_FEATURES = False
    PHISHING_PROTECTION = False
    print(colored("Warning: Advanced antivirus modules not available. Some features may be limited.", 'yellow'))

# Check if the terminal supports color
def can_do_color(no_color: bool | None = None, force_color: bool | None = None) -> bool:
    """Check if the terminal supports color output."""
    if no_color is not None and no_color:
        return False
    if force_color is not None and force_color:
        return True

    if os.environ.get("ANSI_COLORS_DISABLED"):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True

    if os.environ.get("TERM") == "dumb":
        return False
    if not hasattr(sys.stdout, "fileno"):
        return False

    try:
        return os.isatty(sys.stdout.fileno())
    except io.UnsupportedOperation:
        return sys.stdout.isatty()

# Colors to choose from
colors = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', 'grey']

# Fonts to choose from
fonts = ['slant', 'big', 'block', 'bubble', 'digital', 'isometric1', 'letters', 'alligator', 
         'banner3-D', 'doh', 'epic', 'fuzzy', 'larry3d', 'lean', 'mini', 'script', 'standard']

# Cybersecurity related messages
security_messages = [
    "Stay Safe Online!",
    "Protect Your Data",
    "Security First",
    "Cyber Vigilance",
    "Digital Defense",
    "Secure Computing",
    "Privacy Matters",
    "Trust but Verify",
    "AI-Powered Protection",
    "Advanced Threat Detection",
    "Phishing Protection",
    "Communication Security"
]

def print_colored(text: str, color: str) -> None:
    """Print text in a specified color if terminal supports it."""
    if can_do_color():
        print(colored(text, color))
    else:
        print(text)

def print_colored_iterable(items: Iterable[str], color: str) -> None:   
    """Print each item in an iterable in a specified color."""
    for item in items:
        print_colored(item, color)

def greet():
    """Greet the user with a personalized message"""
    username = os.getenv('USER') or os.getenv('USERNAME') or 'User'
    print(colored(f"Hello, {username}! Hope you're having a great day!", 'blue'))
    print()

def display_banner(text="Prashant918", font=None, color=None):
    """Display a colorful ASCII art banner"""
    if font is None:
        font = random.choice(fonts)
    if color is None:
        color = random.choice(colors)
    
    try:
        ascii_art = pyfiglet.figlet_format(text, font=font)
        print(colored(ascii_art, color))
    except Exception:
        print(colored(f"\n=== {text} ===\n", color))

def display_welcome():
    """Display welcome message with banner"""
    display_banner("Prashant918")
    print(colored("Welcome to Prashant918 - Advanced AI-Powered Cybersecurity Suite", 'cyan'))
    print(colored("=" * 75, 'cyan'))
    
    if ANTIVIRUS_AVAILABLE:
        print(colored("✓ Core antivirus protection enabled", 'green'))
    else:
        print(colored("⚠ Core antivirus modules not loaded", 'yellow'))
    
    if ADVANCED_FEATURES:
        print(colored("✓ Advanced AI/ML threat detection enabled", 'green'))
        print(colored("✓ Real-time monitoring enabled", 'green'))
        print(colored("✓ Cloud threat intelligence enabled", 'green'))
        print(colored("✓ Memory scanning enabled", 'green'))
        print(colored("✓ Network security scanning enabled", 'green'))
    else:
        print(colored("⚠ Advanced features not available", 'yellow'))
    
    if PHISHING_PROTECTION:
        print(colored("✓ Phishing & fake call protection enabled", 'green'))
        print(colored("✓ Real-time communication monitoring enabled", 'green'))
    else:
        print(colored("⚠ Phishing protection not available", 'yellow'))

def display_random_message():
    """Display a random cybersecurity message"""
    message = random.choice(security_messages)
    color = random.choice(colors)
    font = random.choice(fonts)
    
    try:
        ascii_message = pyfiglet.figlet_format(message, font=font)
        print(colored(ascii_message, color))
    except Exception:
        print(colored(f"\n*** {message} ***\n", color))

def display_loading(duration=2):
    """Display a loading animation"""
    print(colored("Processing", 'yellow'), end="")
    for _ in range(duration * 4):
        print(".", end="", flush=True)
        time.sleep(0.25)
    print(colored(" Done!", 'green'))

def display_result(is_safe, filename):
    """Display analysis result"""
    if is_safe:
        result_text = "SAFE"
        result_color = 'green'
        message = f"File '{filename}' appears to be safe"
    else:
        result_text = "THREAT DETECTED"
        result_color = 'red'
        message = f"WARNING: File '{filename}' may contain threats"
    
    display_banner(result_text, color=result_color)
    print(colored(message, result_color))

def perform_advanced_file_scan(scanner, ml_detector, cloud_intel, filename):
    """Perform advanced file scan using all available technologies"""
    print(colored(f"🔬 Performing advanced multi-layer scan on: {filename}", 'cyan'))
    
    # Stage 1: Traditional signature scan
    print(colored("  Stage 1: Signature-based detection...", 'blue'))
    display_loading(2)
    traditional_result = scanner.scan_file(filename, quarantine=False)
    
    # Stage 2: ML-based analysis
    print(colored("  Stage 2: AI/ML threat analysis...", 'blue'))
    display_loading(3)
    file_info = scanner.engine.get_file_info(filename)
    ml_result = ml_detector.analyze_behavioral_patterns(filename, file_info)
    
    # Stage 3: Cloud intelligence check
    print(colored("  Stage 3: Cloud threat intelligence...", 'blue'))
    display_loading(4)
    file_hash = file_info.get('hash_sha256', '')
    cloud_result = cloud_intel.analyze_file_comprehensive(filename, file_hash)
    
    # Aggregate results
    print(colored("\n🔍 ADVANCED SCAN RESULTS", 'cyan'))
    print(colored("="*50, 'cyan'))
    
    # Traditional scan results
    print(colored("Traditional Scan:", 'yellow'))
    if traditional_result['status'] == 'infected':
        print(colored(f"  ❌ THREAT: {traditional_result.get('threat_name', 'Unknown')}", 'red'))
    elif traditional_result['status'] == 'suspicious':
        print(colored(f"  ⚠️ SUSPICIOUS: Multiple indicators", 'yellow'))
    else:
        print(colored(f"  ✅ CLEAN: No signatures matched", 'green'))
    
    # ML analysis results
    print(colored("\nAI/ML Analysis:", 'yellow'))
    ml_score = ml_result.get('ml_threat_score', 0)
    threat_type = ml_result.get('predicted_threat_type', 'Unknown')
    risk_level = ml_result.get('risk_level', 'Low')
    
    print(colored(f"  Threat Score: {ml_score:.2f}/1.0", 'white'))
    print(colored(f"  Predicted Type: {threat_type}", 'white'))
    print(colored(f"  Risk Level: {risk_level}", 'white'))
    
    if ml_result.get('is_anomaly'):
        print(colored(f"  🤖 AI DETECTION: Anomalous behavior detected", 'red'))
    
    # Cloud intelligence results
    print(colored("\nCloud Intelligence:", 'yellow'))
    cloud_verdict = cloud_result.get('overall_verdict', 'unknown')
    confidence = cloud_result.get('confidence_score', 0)
    
    print(colored(f"  Verdict: {cloud_verdict.upper()}", 'white'))
    print(colored(f"  Confidence: {confidence:.2f}", 'white'))
    
    reputation = cloud_result.get('reputation_check', {})
    if reputation.get('threat_names'):
        print(colored(f"  Known Threats: {', '.join(reputation['threat_names'][:3])}", 'red'))
    
    # Final result
    print(colored("\n🎯 FINAL RESULT", 'cyan'))
    print(colored("="*20, 'cyan'))
    
    # Determine overall threat level
    threat_indicators = 0
    if traditional_result['status'] in ['infected', 'suspicious']:
        threat_indicators += 2
    if ml_score > 0.6:
        threat_indicators += 2
    if cloud_verdict in ['malicious', 'suspicious']:
        threat_indicators += 2
    
    if threat_indicators >= 4:
        print(colored("🚨 HIGH THREAT - IMMEDIATE ACTION REQUIRED", 'red'))
        print(colored("  Recommendation: Quarantine and investigate", 'red'))
    elif threat_indicators >= 2:
        print(colored("⚠️ MEDIUM THREAT - CAUTION ADVISED", 'yellow'))
        print(colored("  Recommendation: Monitor and restrict access", 'yellow'))
    else:
        print(colored("✅ LOW THREAT - FILE APPEARS SAFE", 'green'))
        print(colored("  Recommendation: File can be used normally", 'green'))

def menu():
    """Display the main menu options"""
    print(colored("\n" + "="*60, 'cyan'))
    print(colored("🛡️  PRASHANT918 ADVANCED CYBERSECURITY SUITE  🛡️", 'cyan'))
    print(colored("="*60, 'cyan'))
    
    # Core scanning options
    print(colored("📋  SCANNING:", 'magenta'))
    print(colored("1. 🔍 Quick System Scan", 'yellow'))
    print(colored("2. 🖥️  Full System Scan", 'yellow'))
    print(colored("3. 📁 Advanced File Analysis", 'yellow'))
    
    # Advanced features
    if ADVANCED_FEATURES:
        print(colored("\n🚀 ADVANCED FEATURES:", 'magenta'))
        print(colored("4. 🤖 AI/ML Threat Detection", 'yellow'))
        print(colored("5. 🧠 Memory Scanner", 'yellow'))
        print(colored("6. 🌐 Network Security Scan", 'yellow'))
        print(colored("7. ☁️  Cloud Threat Intelligence", 'yellow'))
        print(colored("8. 🔄 Real-time Protection", 'yellow'))
    
    # System options
    print(colored("\n⚙️ SYSTEM:", 'magenta'))
    print(colored("9. 📊 View Scan Reports", 'yellow'))
    print(colored("10. ⚙️ Settings & Configuration", 'yellow'))
    print(colored("11. 🆘 Support & Issues", 'yellow'))
    print(colored("12. 🚪 Exit", 'yellow'))
    print(colored("="*60, 'cyan'))

def show_advanced_ml_menu(ml_detector):
    """Show AI/ML detection menu"""
    print(colored("\n🤖 AI/ML THREAT DETECTION", 'cyan'))
    print(colored("="*40, 'cyan'))
    print(colored("1. Analyze File with ML", 'yellow'))
    print(colored("2. Behavioral Pattern Analysis", 'yellow'))
    print(colored("3. Update ML Model", 'yellow'))
    print(colored("4. View ML Statistics", 'yellow'))
    print(colored("5. Back to Main Menu", 'yellow'))
    
    choice = input(colored("Enter your choice (1-5): ", 'cyan'))
    
    if choice == '1':
        filename = input(colored("Enter file path for ML analysis: ", 'cyan'))
        if os.path.exists(filename):
            print(colored("🤖 Performing AI/ML analysis...", 'blue'))
            file_info = {'path': filename, 'size': os.path.getsize(filename)}
            result = ml_detector.analyze_behavioral_patterns(filename, file_info)
            
            print(colored(f"\nML Threat Score: {result.get('ml_threat_score', 0):.2f}", 'white'))
            print(colored(f"Predicted Type: {result.get('predicted_threat_type', 'Unknown')}", 'white'))
            print(colored(f"Risk Level: {result.get('risk_level', 'Low')}", 'white'))
            
            if result.get('behavioral_matches'):
                print(colored("\nBehavioral Matches:", 'yellow'))
                for match in result['behavioral_matches']:
                    print(colored(f"  • {match['name']}: {match['description']}", 'white'))
        else:
            print(colored("File not found!", 'red'))
    
    elif choice == '4':
        print(colored("\n📊 ML DETECTION STATISTICS", 'green'))
        print(colored("Model Status: Active", 'white'))
        print(colored("Feature Extraction: Enabled", 'white'))
        print(colored("Behavioral Analysis: Enabled", 'white'))
        print(colored("Anomaly Detection: Enabled", 'white'))

def show_memory_scanner_menu(memory_scanner):
    """Show memory scanner menu"""
    print(colored("\n🧠 MEMORY SCANNER", 'cyan'))
    print(colored("="*30, 'cyan'))
    print(colored("1. Scan Specific Process", 'yellow'))
    print(colored("2. Scan All Processes", 'yellow'))
    print(colored("3. Rootkit Detection", 'yellow'))
    print(colored("4. Memory Statistics", 'yellow'))
    print(colored("5. Back to Main Menu", 'yellow'))
    
    choice = input(colored("Enter your choice (1-5): ", 'cyan'))
    
    if choice == '1':
        try:
            pid = int(input(colored("Enter Process ID (PID): ", 'cyan')))
            result = memory_scanner.scan_process_memory(pid)
            
            if 'error' not in result:
                print(colored(f"\nProcess: {result['process_name']} (PID: {pid})", 'white'))
                print(colored(f"Threat Score: {result['threat_score']}/100", 'white'))
                
                if result['threats_found']:
                    print(colored("Threats Found:", 'red'))
                    for threat in result['threats_found']:
                        print(colored(f"  • {threat}", 'red'))
            else:
                print(colored(f"Error: {result['error']}", 'red'))
        except ValueError:
            print(colored("Invalid PID format!", 'red'))
    
    elif choice == '2':
        print(colored("⚠️ This will scan all processes and may take time. Continue? (y/n)", 'yellow'))
        if input().lower() == 'y':
            result = memory_scanner.scan_all_processes()
            print(colored(f"\nScan Summary:", 'green'))
            print(colored(f"  Processes Scanned: {result['scanned_processes']}", 'white'))
            print(colored(f"  Threats Detected: {result['threats_detected']}", 'white'))
            print(colored(f"  High Risk: {len(result['high_risk_processes'])}", 'white'))
    
    elif choice == '3':
        result = memory_scanner.detect_rootkits()
        if result['rootkits_detected']:
            print(colored("🚨 ROOTKITS DETECTED:", 'red'))
            for rootkit in result['rootkits_detected']:
                print(colored(f"  • {rootkit}", 'red'))
        else:
            print(colored("✅ No rootkits detected", 'green'))

def show_network_scanner_menu(network_scanner):
    """Show network scanner menu"""
    print(colored("\n🌐 NETWORK SECURITY SCANNER", 'cyan'))
    print(colored("="*40, 'cyan'))
    print(colored("1. Scan Network Connections", 'yellow'))
    print(colored("2. Port Scan", 'yellow'))
    print(colored("3. Network Anomaly Detection", 'yellow'))
    print(colored("4. Monitor Network Traffic", 'yellow'))
    print(colored("5. Back to Main Menu", 'yellow'))
    
    choice = input(colored("Enter your choice (1-5): ", 'cyan'))
    
    if choice == '1':
        result = network_scanner.scan_network_connections()
        print(colored(f"\nConnections Scanned: {result['total_connections']}", 'white'))
        print(colored(f"Malicious: {len(result['malicious_connections'])}", 'red'))
        print(colored(f"Suspicious: {len(result['suspicious_connections'])}", 'yellow'))
    
    elif choice == '2':
        target = input(colored("Enter target IP (or press Enter for localhost): ", 'cyan'))
        if not target:
            target = '127.0.0.1'
        
        result = network_scanner.scan_open_ports(target, (1, 1000))
        print(colored(f"\nOpen Ports on {target}: {len(result['open_ports'])}", 'white'))
        if result['suspicious_ports']:
            print(colored("Suspicious Ports:", 'yellow'))
            for port_info in result['suspicious_ports']:
                print(colored(f"  • Port {port_info['port']}: {port_info['category']}", 'yellow'))
    
    elif choice == '3':
        result = network_scanner.detect_network_anomalies()
        total_anomalies = sum(len(v) for v in result.values() if isinstance(v, list))
        print(colored(f"\nNetwork Anomalies Detected: {total_anomalies}", 'white'))
        
        for category, anomalies in result.items():
            if isinstance(anomalies, list) and anomalies:
                print(colored(f"{category.replace('_', ' ').title()}:", 'yellow'))
                for anomaly in anomalies:
                    print(colored(f"  • {anomaly}", 'white'))

def show_cloud_intel_menu(cloud_intel):
    """Show cloud intelligence menu"""
    print(colored("\n☁️ CLOUD THREAT INTELLIGENCE", 'cyan'))
    print(colored("="*40, 'cyan'))
    print(colored("1. Check File Reputation", 'yellow'))
    print(colored("2. Check URL Safety", 'yellow'))
    print(colored("3. Check IP Reputation", 'yellow'))
    print(colored("4. Update Threat Feeds", 'yellow'))
    print(colored("5. Intelligence Statistics", 'yellow'))
    print(colored("6. Back to Main Menu", 'yellow'))
    
    choice = input(colored("Enter your choice (1-6): ", 'cyan'))
    
    if choice == '1':
        filename = input(colored("Enter file path: ", 'cyan'))
        if os.path.exists(filename):
            import hashlib
            with open(filename, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            result = cloud_intel.api.check_file_reputation(file_hash)
            print(colored(f"\nFile Hash: {file_hash[:16]}...", 'white'))
            print(colored(f"Reputation Score: {result.get('reputation_score', 0)}", 'white'))
            
            if result.get('threat_names'):
                print(colored("Known Threats:", 'red'))
                for threat in result['threat_names']:
                    print(colored(f"  • {threat}", 'red'))
        else:
            print(colored("File not found!", 'red'))
    
    elif choice == '2':
        url = input(colored("Enter URL to check: ", 'cyan'))
        result = cloud_intel.check_url_safety(url)
        print(colored(f"\nURL: {url}", 'white'))
        print(colored(f"Reputation Score: {result.get('reputation_score', 0)}", 'white'))
        print(colored(f"Is Malicious: {result.get('is_malicious', False)}", 'white'))
    
    elif choice == '4':
        cloud_intel.update_threat_feeds()

def show_realtime_protection_menu(realtime_protection):
    """Show real-time protection menu"""
    print(colored("\n🔄 REAL-TIME PROTECTION", 'cyan'))
    print(colored("="*35, 'cyan'))
    
    status = realtime_protection.get_protection_status()
    
    if status['is_active']:
        print(colored("Status: ✅ ACTIVE", 'green'))
        print(colored(f"Uptime: {status['uptime_seconds']:.0f} seconds", 'white'))
        print(colored(f"Files Monitored: {status['statistics']['files_monitored']}", 'white'))
        print(colored(f"Threats Detected: {status['statistics']['threats_detected']}", 'white'))
        
        print(colored("\n1. Stop Protection", 'yellow'))
        print(colored("2. View Statistics", 'yellow'))
        print(colored("3. Back to Main Menu", 'yellow'))
        
        choice = input(colored("Enter your choice (1-3): ", 'cyan'))
        
        if choice == '1':
            realtime_protection.stop_protection()
        elif choice == '2':
            print(colored("\n📊 PROTECTION STATISTICS", 'green'))
            for key, value in status['statistics'].items():
                print(colored(f"  {key.replace('_', ' ').title()}: {value}", 'white'))
    else:
        print(colored("Status: ❌ INACTIVE", 'red'))
        print(colored("\n1. Start Protection", 'yellow'))
        print(colored("2. Back to Main Menu", 'yellow'))
        
        choice = input(colored("Enter your choice (1-2): ", 'cyan'))
        
        if choice == '1':
            paths = [os.path.expanduser("~")]
            realtime_protection.start_protection(paths)

def show_phishing_protection_menu(phishing_detector, comm_monitor):
    """Show phishing protection menu"""
    print(colored("\n🛡️ PHISHING & FAKE CALL PROTECTION", 'cyan'))
    print(colored("="*50, 'cyan'))
    print(colored("1. Analyze Email for Phishing", 'yellow'))
    print(colored("2. Check Phone Call Authenticity", 'yellow'))
    print(colored("3. Analyze Text Message", 'yellow'))
    print(colored("4. Check URL Safety", 'yellow'))
    print(colored("5. Real-time Communication Monitor", 'yellow'))
    print(colored("6. View Protection Statistics", 'yellow'))
    print(colored("7. Report Fake Call/Phishing", 'yellow'))
    print(colored("8. Back to Main Menu", 'yellow'))
    
    choice = input(colored("Enter your choice (1-8): ", 'cyan'))
    
    if choice == '1':
        # Analyze Email
        print(colored("\n📧 EMAIL PHISHING ANALYSIS", 'blue'))
        sender = input(colored("Enter sender email: ", 'cyan'))
        subject = input(colored("Enter email subject: ", 'cyan'))
        print(colored("Enter email content (press Enter twice to finish):", 'cyan'))
        
        content_lines = []
        while True:
            line = input()
            if line == "":
                break
            content_lines.append(line)
        
        content = "\n".join(content_lines)
        
        if content:
            result = phishing_detector.analyze_email_content(content, sender, subject)
            
            print(colored(f"\n📊 ANALYSIS RESULTS:", 'cyan'))
            print(colored(f"Is Phishing: {result['is_phishing']}", 'white'))
            print(colored(f"Confidence Score: {result['confidence_score']:.2f}", 'white'))
            print(colored(f"Risk Level: {result['risk_level']}", 'white'))
            print(colored(f"Recommended Action: {result['recommended_action']}", 'white'))
            
            if result['indicators']:
                print(colored("\nThreat Indicators:", 'yellow'))
                for indicator in result['indicators']:
                    print(colored(f"  • {indicator}", 'white'))
        else:
            print(colored("No content provided", 'red'))
    
    elif choice == '2':
        # Check Phone Call
        print(colored("\n📞 FAKE CALL DETECTION", 'blue'))
        phone_number = input(colored("Enter phone number: ", 'cyan'))
        print(colored("Enter call content/transcript (optional, press Enter to skip):", 'cyan'))
        call_content = input()
        
        result = phishing_detector.analyze_phone_call(phone_number, call_content)
        
        print(colored(f"\n📊 CALL ANALYSIS RESULTS:", 'cyan'))
        print(colored(f"Is Fake Call: {result['is_fake_call']}", 'white'))
        print(colored(f"Confidence Score: {result['confidence_score']:.2f}", 'white'))
        print(colored(f"Call Type: {result['call_type']}", 'white'))
        print(colored(f"Risk Level: {result['risk_level']}", 'white'))
        print(colored(f"Recommended Action: {result['recommended_action']}", 'white'))
        
        if result['indicators']:
            print(colored("\nSuspicious Indicators:", 'yellow'))
            for indicator in result['indicators']:
                print(colored(f"  • {indicator}", 'white'))
    
    elif choice == '3':
        # Analyze Text Message
        print(colored("\n💬 MESSAGE ANALYSIS", 'blue'))
        sender = input(colored("Enter sender (phone/username): ", 'cyan'))
        platform = input(colored("Enter platform (SMS/WhatsApp/Telegram): ", 'cyan')) or "SMS"
        message_content = input(colored("Enter message content: ", 'cyan'))
        
        result = phishing_detector.analyze_message(message_content, sender, platform)
        
        print(colored(f"\n📊 MESSAGE ANALYSIS RESULTS:", 'cyan'))
        print(colored(f"Is Suspicious: {result['is_suspicious']}", 'white'))
        print(colored(f"Confidence Score: {result['confidence_score']:.2f}", 'white'))
        print(colored(f"Risk Level: {result['risk_level']}", 'white'))
        print(colored(f"Recommended Action: {result['recommended_action']}", 'white'))
        
        if result['indicators']:
            print(colored("\nSuspicious Indicators:", 'yellow'))
            for indicator in result['indicators']:
                print(colored(f"  • {indicator}", 'white'))
    
    elif choice == '4':
        # Check URL Safety
        print(colored("\n🔗 URL SAFETY CHECK", 'blue'))
        url = input(colored("Enter URL to check: ", 'cyan'))
        
        # Use the URL analysis from phishing detector
        url_result = phishing_detector._analyze_single_url(url)
        
        print(colored(f"\n📊 URL ANALYSIS RESULTS:", 'cyan'))
        print(colored(f"Safety Score: {1 - url_result['score']:.2f}/1.0", 'white'))
        print(colored(f"Risk Level: {'High' if url_result['score'] > 0.7 else 'Medium' if url_result['score'] > 0.4 else 'Low'}", 'white'))
        
        if url_result['indicators']:
            print(colored("\nSafety Indicators:", 'yellow'))
            for indicator in url_result['indicators']:
                print(colored(f"  • {indicator}", 'white'))
    
    elif choice == '5':
        # Real-time Communication Monitor
        print(colored("\n📡 REAL-TIME COMMUNICATION MONITOR", 'blue'))
        status = comm_monitor.get_monitoring_status()
        
        if status['is_active']:
            print(colored("Status: ✅ ACTIVE", 'green'))
            print(colored(f"Uptime: {status['uptime_seconds']:.0f} seconds", 'white'))
            print(colored(f"Files Monitored: {status['statistics']['files_monitored']}", 'white'))
            print(colored(f"Threats Detected: {status['statistics']['threats_detected']}", 'white'))
            
            print(colored("\n1. Stop Monitoring", 'yellow'))
            print(colored("2. View Statistics", 'yellow'))
            print(colored("3. Back to Main Menu", 'yellow'))
            
            choice = input(colored("Enter your choice (1-3): ", 'cyan'))
            
            if choice == '1':
                comm_monitor.stop_monitoring()
            elif choice == '2':
                print(colored("\n📊 MONITORING STATISTICS", 'green'))
                for key, value in status['statistics'].items():
                    print(colored(f"  {key.replace('_', ' ').title()}: {value}", 'white'))
        else:
            print(colored("Status: ❌ INACTIVE", 'red'))
            print(colored("\n1. Start Monitoring", 'yellow'))
            print(colored("2. Back to Main Menu", 'yellow'))
            
            choice = input(colored("Enter your choice (1-2): ", 'cyan'))
            
            if choice == '1':
                paths = [os.path.expanduser("~")]
                comm_monitor.start_monitoring(paths)

def main():
    """Main function to demonstrate display functionality"""
    try:
        # Initialize all components
        scanner = None
        logger = None
        ml_detector = None
        realtime_protection = None
        cloud_intel = None
        memory_scanner = None
        network_scanner = None
        phishing_detector = None
        comm_monitor = None
        
        if ANTIVIRUS_AVAILABLE:
            scanner = FileScanner()
            logger = AntivirusLogger()
            logger.log_scan_start("system_startup", "application_launch")
        
        if ADVANCED_FEATURES:
            ml_detector = MLThreatDetector()
            cloud_intel = CloudThreatIntelligence()
            memory_scanner = MemoryScanner()
            network_scanner = NetworkSecurityScanner()
            
            # Initialize real-time protection with scanner callback
            if scanner:
                realtime_protection = RealTimeProtection(
                    scanner_callback=lambda path: scanner.scan_file(path, quarantine=True)
                )
        
        if PHISHING_PROTECTION:
            phishing_detector = PhishingDetector()
            comm_monitor = CommunicationMonitor()
        
        # Display initial welcome and demo
        display_welcome()
        time.sleep(1)
        display_random_message()
        time.sleep(1)
        
        # Start the interactive menu
        while True:
            menu()
            choice = input(colored("Enter your choice (1-12): ", 'cyan'))
            
            if choice == '1':
                # Quick System Scan
                if ANTIVIRUS_AVAILABLE and scanner:
                    print(colored("🔍 Starting Quick System Scan...", 'blue'))
                    if logger:
                        logger.log_scan_start("quick_scan", "system_locations")
                    
                    results = scanner.quick_scan(quarantine=True)
                    print(scanner.get_scan_report(results))
                    
                    if logger:
                        logger.log_scan_complete(
                            "quick_scan", 
                            results['files_scanned'], 
                            results['threats_found'], 
                            results['scan_duration']
                        )
                else:
                    print(colored("Quick scan not available - antivirus modules not loaded", 'red'))
                
            elif choice == '2':
                # Full System Scan
                if ANTIVIRUS_AVAILABLE and scanner:
                    print(colored("🖥️ Starting Full System Scan...", 'blue'))
                    print(colored("⚠️ This may take a long time. Press Ctrl+C to cancel.", 'yellow'))
                    
                    try:
                        if logger:
                            logger.log_scan_start("full_scan", "entire_system")
                        
                        results = scanner.full_scan(quarantine=True)
                        print(scanner.get_scan_report(results))
                        
                        if logger:
                            logger.log_scan_complete(
                                "full_scan", 
                                results['files_scanned'], 
                                results['threats_found'], 
                                results['scan_duration']
                            )
                    except KeyboardInterrupt:
                        print(colored("\n\nFull scan cancelled by user", 'yellow'))
                else:
                    print(colored("Full scan not available - antivirus modules not loaded", 'red'))
                    
            elif choice == '3':
                # Advanced File Analysis
                print(colored("📁 Advanced File Analysis", 'blue'))
                filename = input(colored("Enter the file path to analyze: ", 'cyan'))
                
                if os.path.exists(filename):
                    if ADVANCED_FEATURES and scanner and ml_detector and cloud_intel:
                        perform_advanced_file_scan(scanner, ml_detector, cloud_intel, filename)
                        if logger:
                            logger.log_scan_start("advanced_file_scan", filename)
                    elif ANTIVIRUS_AVAILABLE and scanner:
                        # Fallback to basic scan
                        result = scanner.scan_file(filename, quarantine=True)
                        if result['status'] == 'infected':
                            print(colored(f"\n🚨 THREAT DETECTED! 🚨", 'red'))
                            print(colored(f"Threat: {result.get('threat_name', 'Unknown')}", 'red'))
                        elif result['status'] == 'suspicious':
                            print(colored(f"\n⚠️ SUSPICIOUS FILE ⚠️", 'yellow'))
                        else:
                            print(colored(f"\n✅ FILE IS CLEAN ✅", 'green'))
                    else:
                        print(colored("Advanced analysis not available", 'red'))
                else:
                    print(colored(f"File '{filename}' not found.", 'red'))
            
            elif choice == '4' and ADVANCED_FEATURES:
                # AI/ML Threat Detection
                show_advanced_ml_menu(ml_detector)
                
            elif choice == '5' and ADVANCED_FEATURES:
                # Memory Scanner
                show_memory_scanner_menu(memory_scanner)
                
            elif choice == '6' and ADVANCED_FEATURES:
                # Network Security Scan
                show_network_scanner_menu(network_scanner)
                
            elif choice == '7' and ADVANCED_FEATURES:
                # Cloud Threat Intelligence
                show_cloud_intel_menu(cloud_intel)
                
            elif choice == '8' and ADVANCED_FEATURES:
                # Real-time Protection
                show_realtime_protection_menu(realtime_protection)
                
            elif choice == '9':
                # View Scan Reports
                if ANTIVIRUS_AVAILABLE:
                    logger = AntivirusLogger()
                    recent_logs = logger.get_recent_logs(24)
                    
                    print(colored("\n📊 RECENT SCAN ACTIVITY (Last 24 hours)", 'cyan'))
                    print(colored("="*60, 'cyan'))
                    
                    if recent_logs:
                        for log_entry in recent_logs[-20:]:
                            if "THREAT DETECTED" in log_entry:
                                print(colored(log_entry, 'red'))
                            elif "Scan completed" in log_entry:
                                print(colored(log_entry, 'green'))
                            elif "Error" in log_entry:
                                print(colored(log_entry, 'yellow'))
                            else:
                                print(colored(log_entry, 'white'))
                    else:
                        print(colored("No recent scan activity found", 'yellow'))
                else:
                    print(colored("Scan reports not available - modules not loaded", 'red'))
                
            elif choice == '10':
                # Settings & Configuration
                if ANTIVIRUS_AVAILABLE:
                    config = AntivirusConfig()
                    
                    print(colored("\n⚙️ ANTIVIRUS CONFIGURATION", 'cyan'))
                    print(colored("="*40, 'cyan'))
                    print(colored("1. View Current Config", 'yellow'))
                    print(colored("2. Reset to Defaults", 'yellow'))
                    print(colored("3. Back to Main Menu", 'yellow'))
                    
                    config_choice = input(colored("Enter your choice (1-3): ", 'cyan'))
                    
                    if config_choice == '1':
                        print(colored("\nCurrent Configuration:", 'green'))
                        for section, settings in config.config.items():
                            print(colored(f"\n{section.upper()}:", 'yellow'))
                            for key, value in settings.items():
                                print(colored(f"  {key}: {value}", 'white'))
                    elif config_choice == '2':
                        if config.reset_to_defaults():
                            print(colored("Configuration reset to defaults successfully!", 'green'))
                        else:
                            print(colored("Failed to reset configuration", 'red'))
                else:
                    print(colored("Configuration not available - modules not loaded", 'red'))
                
            elif choice == '11':
                # Support & Issues
                print(colored("🆘 Support & Issues", 'blue'))
                print(colored("For technical support and issue reporting:", 'cyan'))
                print(colored("• Email: prashant.maurya9207@gmail.com", 'white'))
                print(colored("• GitHub: https://github.com/Prashant918/Project/issues", 'white'))
                print(colored("• Documentation: Check README.md for detailed information", 'white'))
                print(colored("\nAdvanced Features Status:", 'cyan'))
                print(colored(f"• Core Antivirus: {'✅ Available' if ANTIVIRUS_AVAILABLE else '❌ Not Available'}", 'white'))
                print(colored(f"• AI/ML Detection: {'✅ Available' if ADVANCED_FEATURES else '❌ Not Available'}", 'white'))
                print(colored(f"• Real-time Protection: {'✅ Available' if ADVANCED_FEATURES else '❌ Not Available'}", 'white'))
                print(colored(f"• Cloud Intelligence: {'✅ Available' if ADVANCED_FEATURES else '❌ Not Available'}", 'white'))
                print(colored(f"• Phishing Protection: {'✅ Available' if PHISHING_PROTECTION else '❌ Not Available'}", 'white'))
                
            elif choice == '12':
                # Exit
                print(colored("🚪 Shutting down Prashant918 Advanced Cybersecurity Suite...", 'blue'))
                
                # Stop real-time protection if active
                if ADVANCED_FEATURES and realtime_protection:
                    status = realtime_protection.get_protection_status()
                    if status['is_active']:
                        realtime_protection.stop_protection()
                
                if logger:
                    logger.log_scan_complete("application_shutdown", 0, 0, 0)
                
                display_banner("Goodbye!")
                print(colored("Thank you for using Prashant918! Stay secure! 🛡️", 'green'))
                print(colored("Advanced AI-powered protection at your service! 🤖", 'cyan'))
                break
                
            else:
                print(colored("Invalid option. Please try again.", 'red'))
                
    except KeyboardInterrupt:
        print(colored("\n\nProgram interrupted by user. Goodbye!", 'yellow'))
        sys.exit(0)
    except Exception as e:
        print(colored(f"An error occurred: {e}", 'red'))
        if ANTIVIRUS_AVAILABLE and 'logger' in locals() and logger:
            logger.log_error("main_application", str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()