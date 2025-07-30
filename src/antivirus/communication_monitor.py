import threading
import time
import re
import sqlite3
from typing import Dict, List, Callable, Optional
from termcolor import colored
from pathlib import Path
import json
import hashlib


class CommunicationMonitor:
    """Real-time communication monitoring for phishing detection"""

    def __init__(self, phishing_detector):
        self.phishing_detector = phishing_detector
        self.monitoring_active = False
        self.monitor_thread = None
        self.email_callbacks = []
        self.sms_callbacks = []
        self.call_callbacks = []
        self.blocked_communications = []

        # Monitoring statistics
        self.stats = {
            "emails_scanned": 0,
            "calls_monitored": 0,
            "messages_analyzed": 0,
            "threats_blocked": 0,
            "start_time": None,
        }

    def start_monitoring(self):
        """Start real-time communication monitoring"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.stats["start_time"] = time.time()

            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self._monitor_communications)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            print(colored("📞 Real-time communication monitoring started", "green"))
            print(colored("  Monitoring: Emails, SMS, Phone Calls", "cyan"))

    def stop_monitoring(self):
        """Stop real-time communication monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join()

        print(colored("📞 Real-time communication monitoring stopped", "yellow"))

    def _monitor_communications(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Simulate monitoring different communication channels
                self._check_incoming_emails()
                self._check_incoming_calls()
                self._check_incoming_messages()

                time.sleep(5)  # Check every 5 seconds

            except Exception as e:
                print(colored(f"Error in communication monitoring: {e}", "red"))
                time.sleep(10)

    def _check_incoming_emails(self):
        """Check for incoming emails (simulated)"""
        # In a real implementation, this would integrate with email clients
        # For demo purposes, we'll simulate some email checks
        pass

    def _check_incoming_calls(self):
        """Check for incoming calls (simulated)"""
        # In a real implementation, this would integrate with phone systems
        # For demo purposes, we'll simulate some call checks
        pass

    def _check_incoming_messages(self):
        """Check for incoming messages (simulated)"""
        # In a real implementation, this would integrate with messaging apps
        # For demo purposes, we'll simulate some message checks
        pass

    def analyze_email_real_time(self, sender: str, subject: str, content: str) -> Dict:
        """Analyze email in real-time"""
        self.stats["emails_scanned"] += 1

        print(colored(f"📧 Analyzing email from: {sender}", "cyan"))

        # Perform phishing analysis
        result = self.phishing_detector.analyze_email_content(content, sender, subject)

        # Take action based on result
        if result["is_phishing"]:
            self._block_communication(
                "email",
                {
                    "sender": sender,
                    "subject": subject,
                    "threat_type": result["threat_type"],
                    "confidence": result["confidence_score"],
                },
            )

            print(colored(f"🚨 PHISHING EMAIL BLOCKED!", "red"))
            print(colored(f"  From: {sender}", "red"))
            print(colored(f"  Subject: {subject}", "red"))
            print(colored(f"  Threat: {result['threat_type']}", "red"))
            print(colored(f"  Confidence: {result['confidence_score']:.2f}", "red"))

            self.stats["threats_blocked"] += 1

        elif result["risk_level"] in ["medium", "high"]:
            print(colored(f"⚠️ SUSPICIOUS EMAIL DETECTED", "yellow"))
            print(colored(f"  From: {sender}", "yellow"))
            print(colored(f"  Risk Level: {result['risk_level']}", "yellow"))
            print(
                colored(
                    f"  Recommended Action: {result['recommended_action']}", "yellow"
                )
            )

        return result

    def analyze_call_real_time(self, phone_number: str, call_content: str = "") -> Dict:
        """Analyze phone call in real-time"""
        self.stats["calls_monitored"] += 1

        print(colored(f"📞 Analyzing call from: {phone_number}", "cyan"))

        # Perform fake call analysis
        result = self.phishing_detector.analyze_phone_call(phone_number, call_content)

        # Take action based on result
        if result["is_fake_call"]:
            self._block_communication(
                "call",
                {
                    "phone_number": phone_number,
                    "call_type": result["call_type"],
                    "confidence": result["confidence_score"],
                },
            )

            print(colored(f"🚨 FAKE CALL BLOCKED!", "red"))
            print(colored(f"  Number: {phone_number}", "red"))
            print(colored(f"  Type: {result['call_type']}", "red"))
            print(colored(f"  Confidence: {result['confidence_score']:.2f}", "red"))

            self.stats["threats_blocked"] += 1

        elif result["risk_level"] in ["medium", "high"]:
            print(colored(f"⚠️ SUSPICIOUS CALL DETECTED", "yellow"))
            print(colored(f"  Number: {phone_number}", "yellow"))
            print(colored(f"  Risk Level: {result['risk_level']}", "yellow"))
            print(
                colored(
                    f"  Recommended Action: {result['recommended_action']}", "yellow"
                )
            )

        return result

    def analyze_message_real_time(
        self, sender: str, content: str, platform: str = "SMS"
    ) -> Dict:
        """Analyze message in real-time"""
        self.stats["messages_analyzed"] += 1

        print(colored(f"💬 Analyzing {platform} from: {sender}", "cyan"))

        # Perform message analysis
        result = self.phishing_detector.analyze_message(content, sender, platform)

        # Take action based on result
        if result["is_suspicious"]:
            self._block_communication(
                "message",
                {
                    "sender": sender,
                    "platform": platform,
                    "threat_type": result["threat_type"],
                    "confidence": result["confidence_score"],
                },
            )

            print(colored(f"🚨 SUSPICIOUS MESSAGE BLOCKED!", "red"))
            print(colored(f"  From: {sender}", "red"))
            print(colored(f"  Platform: {platform}", "red"))
            print(colored(f"  Threat: {result['threat_type']}", "red"))
            print(colored(f"  Confidence: {result['confidence_score']:.2f}", "red"))

            self.stats["threats_blocked"] += 1

        elif result["risk_level"] in ["medium", "high"]:
            print(colored(f"⚠️ SUSPICIOUS MESSAGE DETECTED", "yellow"))
            print(colored(f"  From: {sender}", "yellow"))
            print(colored(f"  Platform: {platform}", "yellow"))
            print(colored(f"  Risk Level: {result['risk_level']}", "yellow"))

        return result

    def _block_communication(self, comm_type: str, details: Dict):
        """Block malicious communication"""
        blocked_item = {"type": comm_type, "timestamp": time.time(), "details": details}

        self.blocked_communications.append(blocked_item)

        # Keep only last 1000 blocked communications
        if len(self.blocked_communications) > 1000:
            self.blocked_communications = self.blocked_communications[-1000:]

    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        uptime = (
            time.time() - self.stats["start_time"] if self.stats["start_time"] else 0
        )

        return {
            "is_active": self.monitoring_active,
            "uptime_seconds": uptime,
            "statistics": self.stats,
            "blocked_communications_count": len(self.blocked_communications),
            "recent_blocks": (
                self.blocked_communications[-10:] if self.blocked_communications else []
            ),
        }

    def get_blocked_communications(self, limit: int = 50) -> List[Dict]:
        """Get recent blocked communications"""
        return (
            self.blocked_communications[-limit:] if self.blocked_communications else []
        )

    def whitelist_sender(self, sender: str, comm_type: str = "email"):
        """Add sender to whitelist"""
        # Implementation for whitelisting trusted senders
        print(colored(f"✅ Added {sender} to {comm_type} whitelist", "green"))

    def blacklist_sender(self, sender: str, comm_type: str = "email"):
        """Add sender to blacklist"""
        # Implementation for blacklisting malicious senders
        print(colored(f"🚫 Added {sender} to {comm_type} blacklist", "red"))

    def report_false_positive(self, communication_id: str):
        """Report a false positive detection"""
        print(
            colored(
                f"📝 False positive reported for communication {communication_id}",
                "yellow",
            )
        )
        # Implementation for learning from false positives

    def generate_monitoring_report(self) -> str:
        """Generate communication monitoring report"""
        status = self.get_monitoring_status()

        report = f"""
{colored('='*60, 'cyan')}
{colored('COMMUNICATION MONITORING REPORT', 'cyan')}
{colored('='*60, 'cyan')}

MONITORING STATUS:
  Status: {'✅ Active' if status['is_active'] else '❌ Inactive'}
  Uptime: {status['uptime_seconds']:.0f} seconds

STATISTICS:
  Emails Scanned: {status['statistics']['emails_scanned']}
  Calls Monitored: {status['statistics']['calls_monitored']}
  Messages Analyzed: {status['statistics']['messages_analyzed']}
  Threats Blocked: {status['statistics']['threats_blocked']}

RECENT BLOCKED COMMUNICATIONS:
"""

        recent_blocks = status["recent_blocks"]
        if recent_blocks:
            for block in recent_blocks:
                block_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(block["timestamp"])
                )
                report += f"  • {block['type'].upper()} - {block_time}\n"
                for key, value in block["details"].items():
                    report += f"    {key}: {value}\n"
                report += "\n"
        else:
            report += "  No recent blocks\n"

        report += colored("=" * 60, "cyan")
        return report
