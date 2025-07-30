import requests
import hashlib
import json
import time
import threading
from typing import Dict, List, Optional, Tuple
from termcolor import colored
import sqlite3
from pathlib import Path


class ThreatIntelligenceAPI:
    """Interface for cloud-based threat intelligence services"""

    def __init__(self):
        self.api_endpoints = {
            "virustotal": "https://www.virustotal.com/vtapi/v2/",
            "malwarebytes": "https://api.malwarebytes.com/v1/",
            "hybrid_analysis": "https://www.hybrid-analysis.com/api/v2/",
            "urlvoid": "https://api.urlvoid.com/v1/",
        }

        self.api_keys = {
            "virustotal": "demo_key",  # In production, use real API keys
            "malwarebytes": "demo_key",
            "hybrid_analysis": "demo_key",
            "urlvoid": "demo_key",
        }

        self.cache_db = self._init_cache_db()
        self.request_limits = {
            "virustotal": {"requests_per_minute": 4, "last_request": 0},
            "malwarebytes": {"requests_per_minute": 10, "last_request": 0},
            "hybrid_analysis": {"requests_per_minute": 5, "last_request": 0},
        }

    def _init_cache_db(self) -> sqlite3.Connection:
        """Initialize local cache database"""
        try:
            db_path = Path("threat_intel_cache.db")
            conn = sqlite3.connect(str(db_path), check_same_thread=False)

            # Create tables
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_reputation (
                    hash TEXT PRIMARY KEY,
                    reputation_score INTEGER,
                    threat_names TEXT,
                    scan_results TEXT,
                    last_updated TIMESTAMP,
                    source TEXT
                )
            """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS url_reputation (
                    url TEXT PRIMARY KEY,
                    reputation_score INTEGER,
                    categories TEXT,
                    last_updated TIMESTAMP,
                    source TEXT
                )
            """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    reputation_score INTEGER,
                    country TEXT,
                    categories TEXT,
                    last_updated TIMESTAMP,
                    source TEXT
                )
            """
            )

            conn.commit()
            return conn

        except Exception as e:
            print(colored(f"Error initializing cache database: {e}", "red"))
            return None

    def check_file_reputation(self, file_hash: str, hash_type: str = "sha256") -> Dict:
        """Check file reputation using multiple threat intelligence sources"""
        try:
            # Check cache first
            cached_result = self._get_cached_file_reputation(file_hash)
            if cached_result:
                return cached_result

            # Query multiple sources
            reputation_data = {
                "hash": file_hash,
                "hash_type": hash_type,
                "reputation_score": 0,
                "threat_names": [],
                "scan_results": {},
                "sources_checked": [],
                "confidence": 0.0,
            }

            # Simulate VirusTotal check
            vt_result = self._check_virustotal_file(file_hash)
            if vt_result:
                reputation_data["scan_results"]["virustotal"] = vt_result
                reputation_data["sources_checked"].append("virustotal")
                if vt_result.get("positives", 0) > 0:
                    reputation_data["reputation_score"] += vt_result["positives"] * 10
                    reputation_data["threat_names"].extend(
                        vt_result.get("threat_names", [])
                    )

            # Simulate Hybrid Analysis check
            ha_result = self._check_hybrid_analysis_file(file_hash)
            if ha_result:
                reputation_data["scan_results"]["hybrid_analysis"] = ha_result
                reputation_data["sources_checked"].append("hybrid_analysis")
                if ha_result.get("threat_score", 0) > 50:
                    reputation_data["reputation_score"] += ha_result["threat_score"]
                    reputation_data["threat_names"].extend(
                        ha_result.get("threat_names", [])
                    )

            # Calculate confidence based on number of sources
            reputation_data["confidence"] = min(
                len(reputation_data["sources_checked"]) / 3.0, 1.0
            )

            # Cache the result
            self._cache_file_reputation(file_hash, reputation_data)

            return reputation_data

        except Exception as e:
            print(colored(f"Error checking file reputation: {e}", "red"))
            return {"error": str(e)}

    def _check_virustotal_file(self, file_hash: str) -> Optional[Dict]:
        """Simulate VirusTotal file check"""
        try:
            # Simulate API rate limiting
            if not self._check_rate_limit("virustotal"):
                return None

            # Simulate VirusTotal response
            # In production, this would make actual API calls
            simulated_response = {
                "response_code": 1,
                "positives": 0,
                "total": 70,
                "threat_names": [],
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

            # Simulate some known malicious hashes
            known_malicious = {
                "5d41402abc4b2a76b9719d911017c592": {
                    "positives": 65,
                    "threat_names": ["EICAR-Test-File", "Test.File.EICAR_HDB-1"],
                },
                "44d88612fea8a8f36de82e1278abb02f": {
                    "positives": 45,
                    "threat_names": ["Trojan.Generic", "Malware.Heuristic"],
                },
            }

            if file_hash in known_malicious:
                simulated_response.update(known_malicious[file_hash])

            return simulated_response

        except Exception as e:
            print(colored(f"Error in VirusTotal check: {e}", "red"))
            return None

    def _check_hybrid_analysis_file(self, file_hash: str) -> Optional[Dict]:
        """Simulate Hybrid Analysis file check"""
        try:
            if not self._check_rate_limit("hybrid_analysis"):
                return None

            # Simulate Hybrid Analysis response
            simulated_response = {
                "threat_score": 0,
                "verdict": "no specific threat",
                "threat_names": [],
                "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

            # Simulate some analysis results
            if file_hash == "5d41402abc4b2a76b9719d911017c592":
                simulated_response.update(
                    {
                        "threat_score": 100,
                        "verdict": "malicious",
                        "threat_names": ["EICAR Test File"],
                    }
                )

            return simulated_response

        except Exception as e:
            print(colored(f"Error in Hybrid Analysis check: {e}", "red"))
            return None

    def check_url_reputation(self, url: str) -> Dict:
        """Check URL reputation"""
        try:
            # Check cache first
            cached_result = self._get_cached_url_reputation(url)
            if cached_result:
                return cached_result

            reputation_data = {
                "url": url,
                "reputation_score": 0,
                "categories": [],
                "sources_checked": [],
                "is_malicious": False,
            }

            # Simulate URL reputation check
            malicious_domains = [
                "malware.com",
                "phishing.net",
                "scam.org",
                "trojan.info",
                "virus.biz",
            ]

            for domain in malicious_domains:
                if domain in url.lower():
                    reputation_data["reputation_score"] = 100
                    reputation_data["categories"] = ["malware", "phishing"]
                    reputation_data["is_malicious"] = True
                    break

            # Cache the result
            self._cache_url_reputation(url, reputation_data)

            return reputation_data

        except Exception as e:
            print(colored(f"Error checking URL reputation: {e}", "red"))
            return {"error": str(e)}

    def check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP address reputation"""
        try:
            # Check cache first
            cached_result = self._get_cached_ip_reputation(ip_address)
            if cached_result:
                return cached_result

            reputation_data = {
                "ip": ip_address,
                "reputation_score": 0,
                "country": "Unknown",
                "categories": [],
                "is_malicious": False,
            }

            # Simulate IP reputation check
            malicious_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25"]

            if ip_address in malicious_ips:
                reputation_data.update(
                    {
                        "reputation_score": 85,
                        "categories": ["botnet", "malware_c2"],
                        "is_malicious": True,
                    }
                )

            # Cache the result
            self._cache_ip_reputation(ip_address, reputation_data)

            return reputation_data

        except Exception as e:
            print(colored(f"Error checking IP reputation: {e}", "red"))
            return {"error": str(e)}

    def _check_rate_limit(self, service: str) -> bool:
        """Check API rate limits"""
        if service not in self.request_limits:
            return True

        current_time = time.time()
        last_request = self.request_limits[service]["last_request"]
        requests_per_minute = self.request_limits[service]["requests_per_minute"]

        # Simple rate limiting: wait if last request was too recent
        time_since_last = current_time - last_request
        min_interval = 60.0 / requests_per_minute

        if time_since_last < min_interval:
            return False

        self.request_limits[service]["last_request"] = current_time
        return True

    def _get_cached_file_reputation(self, file_hash: str) -> Optional[Dict]:
        """Get cached file reputation"""
        try:
            if not self.cache_db:
                return None

            cursor = self.cache_db.execute(
                "SELECT * FROM file_reputation WHERE hash = ? AND last_updated > ?",
                (file_hash, time.time() - 3600),  # Cache for 1 hour
            )

            row = cursor.fetchone()
            if row:
                return {
                    "hash": row[0],
                    "reputation_score": row[1],
                    "threat_names": json.loads(row[2]) if row[2] else [],
                    "scan_results": json.loads(row[3]) if row[3] else {},
                    "cached": True,
                }

            return None

        except Exception as e:
            print(colored(f"Error getting cached file reputation: {e}", "red"))
            return None

    def _cache_file_reputation(self, file_hash: str, reputation_data: Dict):
        """Cache file reputation data"""
        try:
            if not self.cache_db:
                return

            self.cache_db.execute(
                """
                INSERT OR REPLACE INTO file_reputation 
                (hash, reputation_score, threat_names, scan_results, last_updated, source)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    file_hash,
                    reputation_data.get("reputation_score", 0),
                    json.dumps(reputation_data.get("threat_names", [])),
                    json.dumps(reputation_data.get("scan_results", {})),
                    time.time(),
                    "cloud_intel",
                ),
            )

            self.cache_db.commit()

        except Exception as e:
            print(colored(f"Error caching file reputation: {e}", "red"))

    def _get_cached_url_reputation(self, url: str) -> Optional[Dict]:
        """Get cached URL reputation"""
        try:
            if not self.cache_db:
                return None

            cursor = self.cache_db.execute(
                "SELECT * FROM url_reputation WHERE url = ? AND last_updated > ?",
                (url, time.time() - 1800),  # Cache for 30 minutes
            )

            row = cursor.fetchone()
            if row:
                return {
                    "url": row[0],
                    "reputation_score": row[1],
                    "categories": json.loads(row[2]) if row[2] else [],
                    "cached": True,
                }

            return None

        except Exception as e:
            print(colored(f"Error getting cached URL reputation: {e}", "red"))
            return None

    def _cache_url_reputation(self, url: str, reputation_data: Dict):
        """Cache URL reputation data"""
        try:
            if not self.cache_db:
                return

            self.cache_db.execute(
                """
                INSERT OR REPLACE INTO url_reputation 
                (url, reputation_score, categories, last_updated, source)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    url,
                    reputation_data.get("reputation_score", 0),
                    json.dumps(reputation_data.get("categories", [])),
                    time.time(),
                    "cloud_intel",
                ),
            )

            self.cache_db.commit()

        except Exception as e:
            print(colored(f"Error caching URL reputation: {e}", "red"))

    def _get_cached_ip_reputation(self, ip_address: str) -> Optional[Dict]:
        """Get cached IP reputation"""
        try:
            if not self.cache_db:
                return None

            cursor = self.cache_db.execute(
                "SELECT * FROM ip_reputation WHERE ip = ? AND last_updated > ?",
                (ip_address, time.time() - 3600),  # Cache for 1 hour
            )

            row = cursor.fetchone()
            if row:
                return {
                    "ip": row[0],
                    "reputation_score": row[1],
                    "country": row[2],
                    "categories": json.loads(row[3]) if row[3] else [],
                    "cached": True,
                }

            return None

        except Exception as e:
            print(colored(f"Error getting cached IP reputation: {e}", "red"))
            return None

    def _cache_ip_reputation(self, ip_address: str, reputation_data: Dict):
        """Cache IP reputation data"""
        try:
            if not self.cache_db:
                return

            self.cache_db.execute(
                """
                INSERT OR REPLACE INTO ip_reputation 
                (ip, reputation_score, country, categories, last_updated, source)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    ip_address,
                    reputation_data.get("reputation_score", 0),
                    reputation_data.get("country", "Unknown"),
                    json.dumps(reputation_data.get("categories", [])),
                    time.time(),
                    "cloud_intel",
                ),
            )

            self.cache_db.commit()

        except Exception as e:
            print(colored(f"Error caching IP reputation: {e}", "red"))
