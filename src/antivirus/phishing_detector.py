import re
import requests
import hashlib
import time
import threading
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import dns.resolver
from termcolor import colored
import sqlite3
from pathlib import Path
import json
import base64

class PhishingDetector:
    """Advanced phishing and fake call detection system"""
    
    def __init__(self):
        self.phishing_patterns = self._load_phishing_patterns()
        self.suspicious_domains = self._load_suspicious_domains()
        self.fake_call_indicators = self._load_fake_call_indicators()
        self.url_cache = self._init_url_cache()
        self.real_time_monitoring = False
        self.detection_stats = {
            'phishing_emails_blocked': 0,
            'malicious_links_blocked': 0,
            'fake_calls_detected': 0,
            'suspicious_messages_flagged': 0
        }
    
    def _load_phishing_patterns(self) -> Dict[str, List[str]]:
        """Load phishing detection patterns"""
        return {
            'urgent_language': [
                'urgent', 'immediate action required', 'act now', 'limited time',
                'expires today', 'verify immediately', 'suspend', 'locked',
                'click here now', 'confirm identity', 'update payment'
            ],
            'financial_scams': [
                'bank account', 'credit card', 'payment failed', 'billing',
                'refund', 'tax refund', 'lottery', 'inheritance',
                'investment opportunity', 'crypto', 'bitcoin'
            ],
            'credential_harvesting': [
                'login', 'password', 'username', 'verify account',
                'security alert', 'suspicious activity', 'sign in',
                'confirm details', 'update information'
            ],
            'tech_support_scams': [
                'microsoft', 'apple', 'google', 'virus detected',
                'computer infected', 'tech support', 'call immediately',
                'remote access', 'fix computer', 'security warning'
            ],
            'social_engineering': [
                'congratulations', 'winner', 'selected', 'prize',
                'free gift', 'claim now', 'exclusive offer',
                'limited spots', 'act fast', 'dont miss out'
            ]
        }
    
    def _load_suspicious_domains(self) -> List[str]:
        """Load known suspicious domains and patterns"""
        return [
            # Fake banking domains
            'secure-bank-update.com', 'verify-paypal.net', 'amazon-security.org',
            'apple-id-locked.com', 'microsoft-support.net', 'google-verify.org',
            
            # Phishing patterns
            'bit.ly', 'tinyurl.com', 'short.link', 't.co',  # URL shorteners
            
            # Suspicious TLDs
            '.tk', '.ml', '.ga', '.cf', '.click', '.download',
            
            # Typosquatting examples
            'gooogle.com', 'microsooft.com', 'paypaI.com', 'amazom.com',
            'facebok.com', 'twiter.com', 'linkedln.com', 'instgram.com'
        ]
    
    def _load_fake_call_indicators(self) -> Dict[str, List[str]]:
        """Load fake call detection indicators"""
        return {
            'robocall_patterns': [
                'this is not a sales call', 'final notice', 'legal action',
                'warranty expiring', 'auto warranty', 'student loan',
                'credit card debt', 'irs', 'social security'
            ],
            'tech_support_calls': [
                'microsoft calling', 'apple support', 'computer virus',
                'windows license', 'refund department', 'tech support',
                'remote access', 'computer problem', 'security breach'
            ],
            'financial_scam_calls': [
                'bank security', 'credit card fraud', 'suspicious charges',
                'account verification', 'payment required', 'debt collector',
                'loan approval', 'investment opportunity', 'crypto trading'
            ],
            'government_impersonation': [
                'irs calling', 'social security administration', 'medicare',
                'tax debt', 'arrest warrant', 'legal department',
                'court case', 'government agency', 'federal investigation'
            ]
        }
    
    def _init_url_cache(self) -> sqlite3.Connection:
        """Initialize URL reputation cache"""
        try:
            db_path = Path("phishing_cache.db")
            conn = sqlite3.connect(str(db_path), check_same_thread=False)
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS url_reputation (
                    url_hash TEXT PRIMARY KEY,
                    url TEXT,
                    is_malicious BOOLEAN,
                    threat_type TEXT,
                    confidence_score REAL,
                    last_checked TIMESTAMP,
                    source TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS phone_reputation (
                    phone_number TEXT PRIMARY KEY,
                    is_suspicious BOOLEAN,
                    call_type TEXT,
                    report_count INTEGER,
                    last_reported TIMESTAMP
                )
            ''')
            
            conn.commit()
            return conn
            
        except Exception as e:
            print(colored(f"Error initializing phishing cache: {e}", 'red'))
            return None
    
    def analyze_email_content(self, email_content: str, sender: str = "", subject: str = "") -> Dict:
        """Analyze email content for phishing indicators"""
        analysis_result = {
            'is_phishing': False,
            'confidence_score': 0.0,
            'threat_type': 'unknown',
            'indicators': [],
            'risk_level': 'low',
            'recommended_action': 'allow'
        }
        
        content_lower = email_content.lower()
        subject_lower = subject.lower()
        sender_lower = sender.lower()
        
        # Check for phishing patterns
        pattern_matches = 0
        total_patterns = 0
        
        for category, patterns in self.phishing_patterns.items():
            category_matches = 0
            for pattern in patterns:
                total_patterns += 1
                if pattern in content_lower or pattern in subject_lower:
                    pattern_matches += 1
                    category_matches += 1
                    analysis_result['indicators'].append(f"{category}: {pattern}")
            
            if category_matches > 0:
                if category == 'urgent_language' and category_matches >= 2:
                    analysis_result['confidence_score'] += 0.3
                elif category == 'financial_scams' and category_matches >= 1:
                    analysis_result['confidence_score'] += 0.4
                elif category == 'credential_harvesting' and category_matches >= 1:
                    analysis_result['confidence_score'] += 0.5
                elif category == 'tech_support_scams' and category_matches >= 1:
                    analysis_result['confidence_score'] += 0.4
                elif category == 'social_engineering' and category_matches >= 2:
                    analysis_result['confidence_score'] += 0.2
        
        # Check sender reputation
        sender_score = self._analyze_sender_reputation(sender)
        analysis_result['confidence_score'] += sender_score
        
        # Extract and analyze URLs
        urls = self._extract_urls(email_content)
        url_analysis = self._analyze_urls(urls)
        analysis_result['confidence_score'] += url_analysis['malicious_score']
        analysis_result['indicators'].extend(url_analysis['indicators'])
        
        # Check for suspicious attachments (if any)
        attachment_score = self._check_suspicious_attachments(email_content)
        analysis_result['confidence_score'] += attachment_score
        
        # Determine final verdict
        if analysis_result['confidence_score'] >= 0.8:
            analysis_result['is_phishing'] = True
            analysis_result['risk_level'] = 'critical'
            analysis_result['recommended_action'] = 'block'
            analysis_result['threat_type'] = 'high_confidence_phishing'
        elif analysis_result['confidence_score'] >= 0.6:
            analysis_result['is_phishing'] = True
            analysis_result['risk_level'] = 'high'
            analysis_result['recommended_action'] = 'quarantine'
            analysis_result['threat_type'] = 'likely_phishing'
        elif analysis_result['confidence_score'] >= 0.4:
            analysis_result['risk_level'] = 'medium'
            analysis_result['recommended_action'] = 'warn'
            analysis_result['threat_type'] = 'suspicious'
        elif analysis_result['confidence_score'] >= 0.2:
            analysis_result['risk_level'] = 'low'
            analysis_result['recommended_action'] = 'flag'
            analysis_result['threat_type'] = 'potentially_suspicious'
        
        # Update statistics
        if analysis_result['is_phishing']:
            self.detection_stats['phishing_emails_blocked'] += 1
        
        return analysis_result
    
    def _analyze_sender_reputation(self, sender: str) -> float:
        """Analyze sender reputation"""
        if not sender:
            return 0.1
        
        sender_lower = sender.lower()
        score = 0.0
        
        # Check for suspicious sender patterns
        suspicious_patterns = [
            'noreply', 'no-reply', 'donotreply', 'security-alert',
            'account-verification', 'support-team', 'customer-service'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in sender_lower:
                score += 0.1
        
        # Check domain reputation
        try:
            domain = sender.split('@')[1] if '@' in sender else sender
            if domain in self.suspicious_domains:
                score += 0.4
            
            # Check for suspicious TLDs
            for tld in ['.tk', '.ml', '.ga', '.cf', '.click']:
                if domain.endswith(tld):
                    score += 0.3
                    break
        except:
            score += 0.2
        
        return min(score, 0.5)
    
    def _extract_urls(self, content: str) -> List[str]:
        """Extract URLs from content"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        # Also look for domain patterns without protocol
        domain_pattern = r'(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?'
        domains = re.findall(domain_pattern, content)
        
        # Add http:// to domains
        for domain in domains:
            if not domain.startswith(('http://', 'https://')):
                urls.append(f"http://{domain}")
        
        return list(set(urls))  # Remove duplicates
    
    def _analyze_urls(self, urls: List[str]) -> Dict:
        """Analyze URLs for malicious indicators"""
        analysis = {
            'malicious_score': 0.0,
            'indicators': [],
            'malicious_urls': [],
            'suspicious_urls': []
        }
        
        for url in urls:
            url_score = self._analyze_single_url(url)
            analysis['malicious_score'] += url_score['score']
            analysis['indicators'].extend(url_score['indicators'])
            
            if url_score['score'] >= 0.7:
                analysis['malicious_urls'].append(url)
                self.detection_stats['malicious_links_blocked'] += 1
            elif url_score['score'] >= 0.4:
                analysis['suspicious_urls'].append(url)
        
        # Normalize score
        if urls:
            analysis['malicious_score'] = min(analysis['malicious_score'] / len(urls), 1.0)
        
        return analysis
    
    def _analyze_single_url(self, url: str) -> Dict:
        """Analyze a single URL for malicious indicators"""
        result = {
            'score': 0.0,
            'indicators': []
        }
        
        try:
            # Check cache first
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            cached_result = self._get_cached_url_result(url_hash)
            if cached_result:
                return {
                    'score': cached_result['confidence_score'],
                    'indicators': [f"Cached: {cached_result['threat_type']}"]
                }
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            # Check against known malicious domains
            if domain in self.suspicious_domains:
                result['score'] += 0.8
                result['indicators'].append(f"Known malicious domain: {domain}")
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl']
            if any(shortener in domain for shortener in shorteners):
                result['score'] += 0.3
                result['indicators'].append("URL shortener detected")
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                'secure', 'verify', 'update', 'confirm', 'login',
                'account', 'suspended', 'locked', 'expired'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in domain or pattern in path:
                    result['score'] += 0.1
                    result['indicators'].append(f"Suspicious pattern: {pattern}")
            
            # Check for typosquatting
            legitimate_domains = [
                'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
                'paypal.com', 'facebook.com', 'twitter.com', 'linkedin.com'
            ]
            
            for legit_domain in legitimate_domains:
                if self._is_typosquatting(domain, legit_domain):
                    result['score'] += 0.6
                    result['indicators'].append(f"Possible typosquatting of {legit_domain}")
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    result['score'] += 0.4
                    result['indicators'].append(f"Suspicious TLD: {tld}")
            
            # Cache the result
            self._cache_url_result(url_hash, url, result['score'] >= 0.5, 
                                 'malicious' if result['score'] >= 0.7 else 'suspicious',
                                 result['score'])
            
        except Exception as e:
            result['indicators'].append(f"URL analysis error: {str(e)}")
        
        return result
    
    def _is_typosquatting(self, domain: str, legitimate_domain: str) -> bool:
        """Check if domain is typosquatting a legitimate domain"""
        # Simple Levenshtein distance check
        if len(domain) == 0 or len(legitimate_domain) == 0:
            return False
        
        # Calculate edit distance
        distance = self._levenshtein_distance(domain, legitimate_domain)
        
        # Consider it typosquatting if distance is 1-3 and domains are similar length
        return (1 <= distance <= 3 and 
                abs(len(domain) - len(legitimate_domain)) <= 2 and
                domain != legitimate_domain)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_suspicious_attachments(self, content: str) -> float:
        """Check for suspicious attachment indicators"""
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.zip', '.rar'
        ]
        
        score = 0.0
        for ext in suspicious_extensions:
            if ext in content.lower():
                score += 0.2
        
        return min(score, 0.4)
    
    def analyze_phone_call(self, phone_number: str, call_content: str = "") -> Dict:
        """Analyze phone call for fake call indicators"""
        analysis_result = {
            'is_fake_call': False,
            'confidence_score': 0.0,
            'call_type': 'unknown',
            'indicators': [],
            'risk_level': 'low',
            'recommended_action': 'allow'
        }
        
        # Check phone number reputation
        number_score = self._analyze_phone_number(phone_number)
        analysis_result['confidence_score'] += number_score['score']
        analysis_result['indicators'].extend(number_score['indicators'])
        
        # Analyze call content if available
        if call_content:
            content_score = self._analyze_call_content(call_content)
            analysis_result['confidence_score'] += content_score['score']
            analysis_result['indicators'].extend(content_score['indicators'])
            analysis_result['call_type'] = content_score['call_type']
        
        # Determine final verdict
        if analysis_result['confidence_score'] >= 0.8:
            analysis_result['is_fake_call'] = True
            analysis_result['risk_level'] = 'critical'
            analysis_result['recommended_action'] = 'block'
        elif analysis_result['confidence_score'] >= 0.6:
            analysis_result['is_fake_call'] = True
            analysis_result['risk_level'] = 'high'
            analysis_result['recommended_action'] = 'warn'
        elif analysis_result['confidence_score'] >= 0.4:
            analysis_result['risk_level'] = 'medium'
            analysis_result['recommended_action'] = 'flag'
        
        # Update statistics
        if analysis_result['is_fake_call']:
            self.detection_stats['fake_calls_detected'] += 1
        
        return analysis_result
    
    def _analyze_phone_number(self, phone_number: str) -> Dict:
        """Analyze phone number for suspicious patterns"""
        result = {
            'score': 0.0,
            'indicators': []
        }
        
        # Check cached reputation
        cached_result = self._get_cached_phone_result(phone_number)
        if cached_result and cached_result['is_suspicious']:
            result['score'] += 0.6
            result['indicators'].append(f"Known suspicious number (reported {cached_result['report_count']} times)")
        
        # Check for suspicious number patterns
        if phone_number.startswith(('1-800', '1-888', '1-877', '1-866')):
            result['score'] += 0.2
            result['indicators'].append("Toll-free number (common for robocalls)")
        
        # Check for spoofed numbers (simplified check)
        if len(phone_number.replace('-', '').replace(' ', '')) != 10:
            result['score'] += 0.3
            result['indicators'].append("Invalid phone number format")
        
        return result
    
    def _analyze_call_content(self, content: str) -> Dict:
        """Analyze call content for fake call indicators"""
        result = {
            'score': 0.0,
            'indicators': [],
            'call_type': 'unknown'
        }
        
        content_lower = content.lower()
        
        # Check against fake call patterns
        for category, patterns in self.fake_call_indicators.items():
            matches = 0
            for pattern in patterns:
                if pattern in content_lower:
                    matches += 1
                    result['indicators'].append(f"{category}: {pattern}")
            
            if matches > 0:
                if category == 'robocall_patterns':
                    result['score'] += 0.4
                    result['call_type'] = 'robocall'
                elif category == 'tech_support_calls':
                    result['score'] += 0.6
                    result['call_type'] = 'tech_support_scam'
                elif category == 'financial_scam_calls':
                    result['score'] += 0.5
                    result['call_type'] = 'financial_scam'
                elif category == 'government_impersonation':
                    result['score'] += 0.7
                    result['call_type'] = 'government_impersonation'
        
        return result
    
    def analyze_message(self, message_content: str, sender: str = "", platform: str = "") -> Dict:
        """Analyze text message or chat message for phishing"""
        analysis_result = {
            'is_suspicious': False,
            'confidence_score': 0.0,
            'threat_type': 'unknown',
            'indicators': [],
            'risk_level': 'low',
            'recommended_action': 'allow'
        }
        
        # Use similar logic to email analysis but adapted for messages
        content_lower = message_content.lower()
        
        # Check for urgent/scam language
        urgent_patterns = [
            'click here', 'act now', 'limited time', 'expires soon',
            'verify account', 'suspended', 'locked', 'urgent'
        ]
        
        for pattern in urgent_patterns:
            if pattern in content_lower:
                analysis_result['confidence_score'] += 0.2
                analysis_result['indicators'].append(f"Urgent language: {pattern}")
        
        # Extract and analyze URLs
        urls = self._extract_urls(message_content)
        if urls:
            url_analysis = self._analyze_urls(urls)
            analysis_result['confidence_score'] += url_analysis['malicious_score']
            analysis_result['indicators'].extend(url_analysis['indicators'])
        
        # Check for financial scam indicators
        financial_patterns = ['prize', 'winner', 'lottery', 'refund', 'payment']
        for pattern in financial_patterns:
            if pattern in content_lower:
                analysis_result['confidence_score'] += 0.3
                analysis_result['indicators'].append(f"Financial scam indicator: {pattern}")
        
        # Determine verdict
        if analysis_result['confidence_score'] >= 0.6:
            analysis_result['is_suspicious'] = True
            analysis_result['risk_level'] = 'high'
            analysis_result['recommended_action'] = 'block'
            analysis_result['threat_type'] = 'phishing_message'
        elif analysis_result['confidence_score'] >= 0.4:
            analysis_result['risk_level'] = 'medium'
            analysis_result['recommended_action'] = 'warn'
            analysis_result['threat_type'] = 'suspicious_message'
        
        # Update statistics
        if analysis_result['is_suspicious']:
            self.detection_stats['suspicious_messages_flagged'] += 1
        
        return analysis_result
    
    def _get_cached_url_result(self, url_hash: str) -> Optional[Dict]:
        """Get cached URL analysis result"""
        if not self.url_cache:
            return None
        
        try:
            cursor = self.url_cache.execute(
                'SELECT * FROM url_reputation WHERE url_hash = ? AND last_checked > ?',
                (url_hash, time.time() - 3600)  # Cache for 1 hour
            )
            row = cursor.fetchone()
            
            if row:
                return {
                    'is_malicious': bool(row[2]),
                    'threat_type': row[3],
                    'confidence_score': row[4]
                }
        except Exception:
            pass
        
        return None
    
    def _cache_url_result(self, url_hash: str, url: str, is_malicious: bool, 
                         threat_type: str, confidence_score: float):
        """Cache URL analysis result"""
        if not self.url_cache:
            return
        
        try:
            self.url_cache.execute('''
                INSERT OR REPLACE INTO url_reputation 
                (url_hash, url, is_malicious, threat_type, confidence_score, last_checked, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (url_hash, url, is_malicious, threat_type, confidence_score, time.time(), 'local_analysis'))
            
            self.url_cache.commit()
        except Exception:
            pass
    
    def _get_cached_phone_result(self, phone_number: str) -> Optional[Dict]:
        """Get cached phone number reputation"""
        if not self.url_cache:
            return None
        
        try:
            cursor = self.url_cache.execute(
                'SELECT * FROM phone_reputation WHERE phone_number = ?',
                (phone_number,)
            )
            row = cursor.fetchone()
            
            if row:
                return {
                    'is_suspicious': bool(row[1]),
                    'call_type': row[2],
                    'report_count': row[3]
                }
        except Exception:
            pass
        
        return None
    
    def report_phone_number(self, phone_number: str, call_type: str):
        """Report a phone number as suspicious"""
        if not self.url_cache:
            return
        
        try:
            # Check if number exists
            cursor = self.url_cache.execute(
                'SELECT report_count FROM phone_reputation WHERE phone_number = ?',
                (phone_number,)
            )
            row = cursor.fetchone()
            
            if row:
                # Update existing record
                new_count = row[0] + 1
                self.url_cache.execute('''
                    UPDATE phone_reputation 
                    SET report_count = ?, is_suspicious = ?, last_reported = ?
                    WHERE phone_number = ?
                ''', (new_count, True, time.time(), phone_number))
            else:
                # Insert new record
                self.url_cache.execute('''
                    INSERT INTO phone_reputation 
                    (phone_number, is_suspicious, call_type, report_count, last_reported)
                    VALUES (?, ?, ?, ?, ?)
                ''', (phone_number, True, call_type, 1, time.time()))
            
            self.url_cache.commit()
            print(colored(f"Phone number {phone_number} reported as {call_type}", 'yellow'))
            
        except Exception as e:
            print(colored(f"Error reporting phone number: {e}", 'red'))
    
    def get_detection_statistics(self) -> Dict:
        """Get phishing detection statistics"""
        return self.detection_stats.copy()
    
    def start_real_time_monitoring(self):
        """Start real-time phishing protection"""
        self.real_time_monitoring = True
        print(colored("🛡️ Real-time phishing protection started", 'green'))
    
    def stop_real_time_monitoring(self):
        """Stop real-time phishing protection"""
        self.real_time_monitoring = False
        print(colored("🛡️ Real-time phishing protection stopped", 'yellow'))
    
    def generate_protection_report(self) -> str:
        """Generate comprehensive protection report"""
        stats = self.get_detection_statistics()
        
        report = f"""
{colored('='*60, 'cyan')}
{colored('PHISHING PROTECTION REPORT', 'cyan')}
{colored('='*60, 'cyan')}

DETECTION STATISTICS:
  Phishing Emails Blocked: {stats['phishing_emails_blocked']}
  Malicious Links Blocked: {stats['malicious_links_blocked']}
  Fake Calls Detected: {stats['fake_calls_detected']}
  Suspicious Messages Flagged: {stats['suspicious_messages_flagged']}

PROTECTION STATUS:
  Real-time Monitoring: {'✅ Active' if self.real_time_monitoring else '❌ Inactive'}
  
THREAT CATEGORIES MONITORED:
  ✓ Phishing Emails
  ✓ Malicious URLs
  ✓ Fake Phone Calls
  ✓ Suspicious Text Messages
  ✓ Social Engineering Attacks
  ✓ Financial Scams
  ✓ Tech Support Scams

{colored('='*60, 'cyan')}
"""
        return report
