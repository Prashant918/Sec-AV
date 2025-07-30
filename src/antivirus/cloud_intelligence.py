import asyncio
import aiohttp
import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging
from enum import Enum

class ThreatIntelSource(Enum):
    VIRUSTOTAL = "virustotal"
    MALWAREBAZAAR = "malwarebazaar"
    HYBRID_ANALYSIS = "hybrid_analysis"
    INTERNAL_DB = "internal_db"

@dataclass
class ThreatIntelligence:
    file_hash: str
    threat_name: Optional[str]
    threat_family: Optional[str]
    confidence: float
    source: ThreatIntelSource
    last_seen: float
    detection_count: int
    total_scans: int
    metadata: Dict

class CloudIntelligenceEngine:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # API configurations
        self.api_keys = config.get('api_keys', {})
        self.api_limits = config.get('api_limits', {})
        self.cache_ttl = config.get('cache_ttl', 3600)  # 1 hour
        
        # Local cache for threat intelligence
        self.threat_cache = {}
        self.reputation_cache = {}
        
        # Rate limiting
        self.rate_limiters = {}
        
        # Session for HTTP requests
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'AdvancedAntivirus/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def get_file_reputation(self, file_path: str) -> Optional[ThreatIntelligence]:
        """Get file reputation from multiple threat intelligence sources"""
        try:
            # Calculate file hash
            file_hash = await self._calculate_file_hash(file_path)
            
            # Check cache first
            cached_result = self._get_cached_reputation(file_hash)
            if cached_result:
                return cached_result
            
            # Query multiple sources
            tasks = []
            
            if self.api_keys.get('virustotal'):
                tasks.append(self._query_virustotal(file_hash))
            
            if self.api_keys.get('malwarebazaar'):
                tasks.append(self._query_malwarebazaar(file_hash))
            
            if self.api_keys.get('hybrid_analysis'):
                tasks.append(self._query_hybrid_analysis(file_hash))
            
            # Execute queries concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            combined_result = self._combine_intelligence_results(file_hash, results)
            
            # Cache result
            if combined_result:
                self._cache_reputation(file_hash, combined_result)
            
            return combined_result
            
        except Exception as e:
            self.logger.error(f"Error getting file reputation for {file_path}: {e}")
            return None
    
    async def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            raise
    
    async def _query_virustotal(self, file_hash: str) -> Optional[ThreatIntelligence]:
        """Query VirusTotal API for file reputation"""
        try:
            if not await self._check_rate_limit('virustotal'):
                return None
            
            api_key = self.api_keys['virustotal']
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            
            params = {
                'apikey': api_key,
                'resource': file_hash
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('response_code') == 1:
                        # File found in VirusTotal
                        positives = data.get('positives', 0)
                        total = data.get('total', 0)
                        
                        # Determine threat name
                        scans = data.get('scans', {})
                        threat_names = [
                            scan_result.get('result')
                            for scan_result in scans.values()
                            if scan_result.get('detected') and scan_result.get('result')
                        ]
                        
                        threat_name = max(set(threat_names), key=threat_names.count) if threat_names else None
                        
                        confidence = positives / total if total > 0 else 0.0
                        
                        return ThreatIntelligence(
                            file_hash=file_hash,
                            threat_name=threat_name,
                            threat_family=self._extract_threat_family(threat_name),
                            confidence=confidence,
                            source=ThreatIntelSource.VIRUSTOTAL,
                            last_seen=time.time(),
                            detection_count=positives,
                            total_scans=total,
                            metadata={
                                'scan_date': data.get('scan_date'),
                                'permalink': data.get('permalink'),
                                'detailed_scans': scans
                            }
                        )
                
        except Exception as e:
            self.logger.error(f"Error querying VirusTotal: {e}")
        
        return None
    
    async def _query_malwarebazaar(self, file_hash: str) -> Optional[ThreatIntelligence]:
        """Query MalwareBazaar API for file reputation"""
        try:
            if not await self._check_rate_limit('malwarebazaar'):
                return None
            
            url = "https://mb-api.abuse.ch/api/v1/"
            
            data = {
                'query': 'get_info',
                'hash': file_hash
            }
            
            async with self.session.post(url, data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    if result.get('query_status') == 'ok':
                        data = result.get('data', [])
                        if data:
                            sample = data[0]
                            
                            return ThreatIntelligence(
                                file_hash=file_hash,
                                threat_name=sample.get('signature'),
                                threat_family=sample.get('family'),
                                confidence=0.8,  # High confidence for MalwareBazaar
                                source=ThreatIntelSource.MALWAREBAZAAR,
                                last_seen=time.time(),
                                detection_count=1,
                                total_scans=1,
                                metadata={
                                    'first_seen': sample.get('first_seen'),
                                    'last_seen': sample.get('last_seen'),
                                    'file_type': sample.get('file_type'),
                                    'file_size': sample.get('file_size'),
                                    'tags': sample.get('tags', [])
                                }
                            )
                
        except Exception as e:
            self.logger.error(f"Error querying MalwareBazaar: {e}")
        
        return None
    
    async def _query_hybrid_analysis(self, file_hash: str) -> Optional[ThreatIntelligence]:
        """Query Hybrid Analysis API for file reputation"""
        try:
            if not await self._check_rate_limit('hybrid_analysis'):
                return None
            
            api_key = self.api_keys.get('hybrid_analysis')
            if not api_key:
                return None
            
            url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
            
            headers = {
                'api-key': api_key,
                'User-Agent': 'Falcon Sandbox'
            }
            
            data = {
                'hash': file_hash
            }
            
            async with self.session.post(url, headers=headers, data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    if result and len(result) > 0:
                        sample = result[0]
                        
                        threat_score = sample.get('threat_score', 0)
                        verdict = sample.get('verdict')
                        
                        confidence = threat_score / 100.0 if threat_score else 0.0
                        
                        return ThreatIntelligence(
                            file_hash=file_hash,
                            threat_name=verdict,
                            threat_family=sample.get('type_short'),
                            confidence=confidence,
                            source=ThreatIntelSource.HYBRID_ANALYSIS,
                            last_seen=time.time(),
                            detection_count=1 if threat_score > 50 else 0,
                            total_scans=1,
                            metadata={
                                'threat_score': threat_score,
                                'analysis_start_time': sample.get('analysis_start_time'),
                                'environment_id': sample.get('environment_id'),
                                'submit_name': sample.get('submit_name')
                            }
                        )
                
        except Exception as e:
            self.logger.error(f"Error querying Hybrid Analysis: {e}")
        
        return None
    
    def _combine_intelligence_results(self, file_hash: str, results: List) -> Optional[ThreatIntelligence]:
        """Combine results from multiple threat intelligence sources"""
        valid_results = [r for r in results if isinstance(r, ThreatIntelligence)]
        
        if not valid_results:
            return None
        
        # Weighted combination based on source reliability
        source_weights = {
            ThreatIntelSource.VIRUSTOTAL: 0.4,
            ThreatIntelSource.MALWAREBAZAAR: 0.3,
            ThreatIntelSource.HYBRID_ANALYSIS: 0.2,
            ThreatIntelSource.INTERNAL_DB: 0.1
        }
        
        # Calculate weighted confidence
        total_confidence = 0.0
        total_weight = 0.0
        
        threat_names = []
        threat_families = []
        combined_metadata = {}
        
        for result in valid_results:
            weight = source_weights.get(result.source, 0.1)
            total_confidence += result.confidence * weight
            total_weight += weight
            
            if result.threat_name:
                threat_names.append(result.threat_name)
            
            if result.threat_family:
                threat_families.append(result.threat_family)
            
            combined_metadata[result.source.value] = result.metadata
        
        # Normalize confidence
        final_confidence = total_confidence / total_weight if total_weight > 0 else 0.0
        
        # Determine most common threat name and family
        most_common_threat = max(set(threat_names), key=threat_names.count) if threat_names else None
        most_common_family = max(set(threat_families), key=threat_families.count) if threat_families else None
        
        # Calculate total detections
        total_detections = sum(r.detection_count for r in valid_results)
        total_scans = sum(r.total_scans for r in valid_results)
        
        return ThreatIntelligence(
            file_hash=file_hash,
            threat_name=most_common_threat,
            threat_family=most_common_family,
            confidence=final_confidence,
            source=ThreatIntelSource.INTERNAL_DB,  # Combined result
            last_seen=time.time(),
            detection_count=total_detections,
            total_scans=total_scans,
            metadata=combined_metadata
        )
    
    def _extract_threat_family(self, threat_name: Optional[str]) -> Optional[str]:
        """Extract threat family from threat name"""
        if not threat_name:
            return None
        
        # Common threat family patterns
        family_patterns = {
            'trojan': ['trojan', 'backdoor', 'rat'],
            'ransomware': ['ransom', 'crypto', 'locker'],
            'adware': ['adware', 'pup', 'potentially unwanted'],
            'spyware': ['spyware', 'keylogger', 'stealer'],
            'worm': ['worm', 'conficker'],
            'virus': ['virus', 'infector']
        }
        
        threat_lower = threat_name.lower()
        
        for family, patterns in family_patterns.items():
            if any(pattern in threat_lower for pattern in patterns):
                return family
        
        return 'unknown'
    
    async def _check_rate_limit(self, source: str) -> bool:
        """Check if API rate limit allows request"""
        current_time = time.time()
        
        if source not in self.rate_limiters:
            self.rate_limiters[source] = {
                'requests': [],
                'limit': self.api_limits.get(source, 100),
                'window': 3600  # 1 hour window
            }
        
        limiter = self.rate_limiters[source]
        
        # Remove old requests outside the window
        limiter['requests'] = [
            req_time for req_time in limiter['requests']
            if current_time - req_time < limiter['window']
        ]
        
        # Check if we can make another request
        if len(limiter['requests']) >= limiter['limit']:
            return False
        
        # Add current request
        limiter['requests'].append(current_time)
        return True
    
    def _get_cached_reputation(self, file_hash: str) -> Optional[ThreatIntelligence]:
        """Get cached reputation result"""
        if file_hash in self.reputation_cache:
            cached_data, timestamp = self.reputation_cache[file_hash]
            
            # Check if cache is still valid
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
            else:
                # Remove expired cache entry
                del self.reputation_cache[file_hash]
        
        return None
    
    def _cache_reputation(self, file_hash: str, reputation: ThreatIntelligence):
        """Cache reputation result"""
        self.reputation_cache[file_hash] = (reputation, time.time())
        
        # Limit cache size
        max_cache_size = self.config.get('max_cache_size', 10000)
        if len(self.reputation_cache) > max_cache_size:
            # Remove oldest entries
            sorted_cache = sorted(
                self.reputation_cache.items(),
                key=lambda x: x[1][1]  # Sort by timestamp
            )
            
            # Keep only the newest entries
            self.reputation_cache = dict(sorted_cache[-max_cache_size//2:])
    
    async def submit_sample(self, file_path: str, source: ThreatIntelSource = ThreatIntelSource.VIRUSTOTAL) -> bool:
        """Submit sample for analysis"""
        try:
            if source == ThreatIntelSource.VIRUSTOTAL:
                return await self._submit_to_virustotal(file_path)
            elif source == ThreatIntelSource.HYBRID_ANALYSIS:
                return await self._submit_to_hybrid_analysis(file_path)
            
        except Exception as e:
            self.logger.error(f"Error submitting sample {file_path}: {e}")
        
        return False
    
    async def _submit_to_virustotal(self, file_path: str) -> bool:
        """Submit file to VirusTotal for analysis"""
        try:
            api_key = self.api_keys.get('virustotal')
            if not api_key:
                return False
            
            url = "https://www.virustotal.com/vtapi/v2/file/scan"
            
            with open(file_path, 'rb') as f:
                data = aiohttp.FormData()
                data.add_field('apikey', api_key)
                data.add_field('file', f, filename=file_path.split('/')[-1])
                
                async with self.session.post(url, data=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get('response_code') == 1
            
        except Exception as e:
            self.logger.error(f"Error submitting to VirusTotal: {e}")
        
        return False
    
    async def _submit_to_hybrid_analysis(self, file_path: str) -> bool:
        """Submit file to Hybrid Analysis"""
        try:
            api_key = self.api_keys.get('hybrid_analysis')
            if not api_key:
                return False
            
            url = "https://www.hybrid-analysis.com/api/v2/submit/file"
            
            headers = {
                'api-key': api_key,
                'User-Agent': 'Falcon Sandbox'
            }
            
            with open(file_path, 'rb') as f:
                data = aiohttp.FormData()
                data.add_field('file', f, filename=file_path.split('/')[-1])
                data.add_field('environment_id', '300')  # Windows 10 64-bit
                
                async with self.session.post(url, headers=headers, data=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        return 'job_id' in result
            
        except Exception as e:
            self.logger.error(f"Error submitting to Hybrid Analysis: {e}")
        
        return False
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            'reputation_cache_size': len(self.reputation_cache),
            'cache_hit_rate': getattr(self, '_cache_hits', 0) / max(getattr(self, '_cache_requests', 1), 1),
            'api_requests_today': {
                source: len(limiter['requests'])
                for source, limiter in self.rate_limiters.items()
            }
        }
    
    def clear_cache(self):
        """Clear all cached data"""
        self.reputation_cache.clear()
        self.threat_cache.clear()
        self.logger.info("Cloud intelligence cache cleared")
