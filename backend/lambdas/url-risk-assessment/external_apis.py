"""
External API Integration Service for HTTPS Shield

This module handles integration with external intelligence sources:
- Google Safe Browsing API
- VirusTotal API
- PhishTank API
- WHOIS lookups

Author: HTTPS Shield Extension Team
Version: 1.0.0
"""

import json
import os
import asyncio
import aiohttp
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, quote
from logger_config import setup_logger, log_error, log_performance_metric, log_api_request

# Configure logging
logger = setup_logger(__name__)

class ExternalAPIService:
    """
    Service for integrating with external threat intelligence APIs
    """
    
    def __init__(self):
        self.session = None
        self.api_keys = self._load_api_keys()
        self.timeout = 5  # 5 second timeout for external APIs
    
    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from environment variables"""
        return {
            'google_safebrowsing': os.environ.get('GOOGLE_SAFEBROWSING_API_KEY'),
            'virustotal': os.environ.get('VIRUSTOTAL_API_KEY'),
            'phishtank': os.environ.get('PHISHTANK_API_KEY'),
            'whois': os.environ.get('WHOIS_API_KEY')
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def check_google_safebrowsing(self, url: str) -> Dict[str, Any]:
        """
        Check URL against Google Safe Browsing API
        
        Args:
            url: The URL to check
            
        Returns:
            Dictionary with Safe Browsing results
        """
        if not self.api_keys['google_safebrowsing']:
            logger.warning("Google Safe Browsing API key not configured")
            return self._empty_safebrowsing_result()
        
        try:
            start_time = time.time()
            session = await self._get_session()
            
            # Prepare Safe Browsing API request
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_keys['google_safebrowsing']}"
            
            payload = {
                "client": {
                    "clientId": "https-shield-extension",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            # Make API request
            log_api_request(logger, 'google_safebrowsing', url)
            
            async with session.post(api_url, json=payload) as response:
                response.raise_for_status()
                data = await response.json()
                
                # Log performance
                request_time = (time.time() - start_time) * 1000
                log_performance_metric(logger, 'google_safebrowsing_api', request_time)
                
                return self._process_safebrowsing_response(data)
                
        except asyncio.TimeoutError:
            logger.warning("Google Safe Browsing API timeout")
            return self._empty_safebrowsing_result()
        except Exception as e:
            log_error(logger, e, {'operation': 'google_safebrowsing', 'url': url})
            return self._empty_safebrowsing_result()
    
    def _process_safebrowsing_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process Google Safe Browsing API response"""
        threats = data.get('matches', [])
        
        result = {
            'is_safe': len(threats) == 0,
            'threat_count': len(threats),
            'threats': [],
            'risk_score': 0.0,
            'api_source': 'google_safebrowsing'
        }
        
        for threat in threats:
            threat_type = threat.get('threatType', 'UNKNOWN')
            platform = threat.get('platformType', 'UNKNOWN')
            
            result['threats'].append({
                'type': threat_type,
                'platform': platform,
                'severity': self._get_threat_severity(threat_type)
            })
        
        # Calculate risk score based on threats
        if threats:
            max_severity = max(self._get_threat_severity(t.get('threatType', '')) for t in threats)
            result['risk_score'] = min(max_severity * 25, 100)  # Scale to 0-100
        
        return result
    
    def _get_threat_severity(self, threat_type: str) -> float:
        """Get threat severity score (0-4)"""
        severity_map = {
            'MALWARE': 4.0,
            'SOCIAL_ENGINEERING': 3.5,
            'UNWANTED_SOFTWARE': 2.5,
            'POTENTIALLY_HARMFUL_APPLICATION': 2.0,
            'UNKNOWN': 1.0
        }
        return severity_map.get(threat_type, 1.0)
    
    def _empty_safebrowsing_result(self) -> Dict[str, Any]:
        """Return empty Safe Browsing result"""
        return {
            'is_safe': True,
            'threat_count': 0,
            'threats': [],
            'risk_score': 0.0,
            'api_source': 'google_safebrowsing',
            'error': 'API not available'
        }
    
    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        """
        Check URL against VirusTotal API
        
        Args:
            url: The URL to check
            
        Returns:
            Dictionary with VirusTotal results
        """
        if not self.api_keys['virustotal']:
            logger.warning("VirusTotal API key not configured")
            return self._empty_virustotal_result()
        
        try:
            start_time = time.time()
            session = await self._get_session()
            
            # Prepare VirusTotal API request
            api_url = "https://www.virustotal.com/vtapi/v2/url/report"
            
            params = {
                'apikey': self.api_keys['virustotal'],
                'resource': url,
                'scan': 0  # Don't trigger new scan, just get existing results
            }
            
            # Make API request
            log_api_request(logger, 'virustotal', url)
            
            async with session.get(api_url, params=params) as response:
                response.raise_for_status()
                data = await response.json()
                
                # Log performance
                request_time = (time.time() - start_time) * 1000
                log_performance_metric(logger, 'virustotal_api', request_time)
                
                return self._process_virustotal_response(data)
                
        except asyncio.TimeoutError:
            logger.warning("VirusTotal API timeout")
            return self._empty_virustotal_result()
        except Exception as e:
            log_error(logger, e, {'operation': 'virustotal', 'url': url})
            return self._empty_virustotal_result()
    
    def _process_virustotal_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process VirusTotal API response"""
        response_code = data.get('response_code', 0)
        
        if response_code != 1:
            # URL not found in VirusTotal database
            return self._empty_virustotal_result()
        
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        
        result = {
            'is_safe': positives == 0,
            'detections': positives,
            'total_scanners': total,
            'detection_ratio': f"{positives}/{total}",
            'risk_score': 0.0,
            'api_source': 'virustotal',
            'scan_date': data.get('scan_date', ''),
            'permalink': data.get('permalink', '')
        }
        
        # Calculate risk score based on detection ratio
        if total > 0:
            detection_rate = positives / total
            result['risk_score'] = min(detection_rate * 100, 100)
        
        return result
    
    def _empty_virustotal_result(self) -> Dict[str, Any]:
        """Return empty VirusTotal result"""
        return {
            'is_safe': True,
            'detections': 0,
            'total_scanners': 0,
            'detection_ratio': '0/0',
            'risk_score': 0.0,
            'api_source': 'virustotal',
            'error': 'API not available'
        }
    
    async def check_phishtank(self, url: str) -> Dict[str, Any]:
        """
        Check URL against PhishTank API
        
        Args:
            url: The URL to check
            
        Returns:
            Dictionary with PhishTank results
        """
        try:
            start_time = time.time()
            session = await self._get_session()
            
            # Prepare PhishTank API request
            api_url = "https://checkurl.phishtank.com/checkurl/"
            
            data = {
                'url': url,
                'format': 'json',
                'app_key': self.api_keys.get('phishtank', 'https-shield-extension')
            }
            
            # Make API request
            log_api_request(logger, 'phishtank', url)
            
            async with session.post(api_url, data=data) as response:
                response.raise_for_status()
                result = await response.json()
                
                # Log performance
                request_time = (time.time() - start_time) * 1000
                log_performance_metric(logger, 'phishtank_api', request_time)
                
                return self._process_phishtank_response(result)
                
        except asyncio.TimeoutError:
            logger.warning("PhishTank API timeout")
            return self._empty_phishtank_result()
        except Exception as e:
            log_error(logger, e, {'operation': 'phishtank', 'url': url})
            return self._empty_phishtank_result()
    
    def _process_phishtank_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process PhishTank API response"""
        results = data.get('results', {})
        
        is_phish = results.get('in_database', False)
        is_valid = results.get('valid', True)
        
        result = {
            'is_safe': not is_phish,
            'in_database': is_phish,
            'is_valid': is_valid,
            'phish_id': results.get('phish_id', 0),
            'risk_score': 100.0 if is_phish else 0.0,
            'api_source': 'phishtank',
            'verified': results.get('verified', False),
            'submission_time': results.get('submission_time', '')
        }
        
        return result
    
    def _empty_phishtank_result(self) -> Dict[str, Any]:
        """Return empty PhishTank result"""
        return {
            'is_safe': True,
            'in_database': False,
            'is_valid': True,
            'phish_id': 0,
            'risk_score': 0.0,
            'api_source': 'phishtank',
            'error': 'API not available'
        }
    
    async def lookup_whois(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for domain
        
        Args:
            domain: The domain to look up
            
        Returns:
            Dictionary with WHOIS results
        """
        try:
            start_time = time.time()
            session = await self._get_session()
            
            # Use a WHOIS API service (example with whoisjson.com)
            api_url = f"https://whoisjson.com/api/v1/whois"
            
            params = {
                'domain': domain
            }
            
            if self.api_keys.get('whois'):
                params['key'] = self.api_keys['whois']
            
            # Make API request
            log_api_request(logger, 'whois', domain)
            
            async with session.get(api_url, params=params) as response:
                response.raise_for_status()
                data = await response.json()
                
                # Log performance
                request_time = (time.time() - start_time) * 1000
                log_performance_metric(logger, 'whois_api', request_time)
                
                return self._process_whois_response(data)
                
        except asyncio.TimeoutError:
            logger.warning("WHOIS API timeout")
            return self._empty_whois_result()
        except Exception as e:
            log_error(logger, e, {'operation': 'whois', 'domain': domain})
            return self._empty_whois_result()
    
    def _process_whois_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process WHOIS API response"""
        result = {
            'domain': data.get('domain', ''),
            'registrar': data.get('registrar', ''),
            'creation_date': data.get('creation_date', ''),
            'expiration_date': data.get('expiration_date', ''),
            'updated_date': data.get('updated_date', ''),
            'name_servers': data.get('name_servers', []),
            'status': data.get('status', []),
            'age_days': 0,
            'risk_score': 0.0,
            'api_source': 'whois'
        }
        
        # Calculate domain age
        if result['creation_date']:
            try:
                from datetime import datetime
                creation_date = datetime.fromisoformat(result['creation_date'].replace('Z', '+00:00'))
                age_days = (datetime.utcnow().replace(tzinfo=creation_date.tzinfo) - creation_date).days
                result['age_days'] = age_days
                
                # Calculate risk score based on age (newer domains are riskier)
                if age_days < 30:
                    result['risk_score'] = 80.0
                elif age_days < 90:
                    result['risk_score'] = 60.0
                elif age_days < 365:
                    result['risk_score'] = 40.0
                else:
                    result['risk_score'] = 10.0
                    
            except Exception:
                pass
        
        return result
    
    def _empty_whois_result(self) -> Dict[str, Any]:
        """Return empty WHOIS result"""
        return {
            'domain': '',
            'registrar': '',
            'creation_date': '',
            'expiration_date': '',
            'age_days': 0,
            'risk_score': 0.0,
            'api_source': 'whois',
            'error': 'API not available'
        }
    
    async def get_combined_intelligence(self, url: str) -> Dict[str, Any]:
        """
        Get combined intelligence from all external sources
        
        Args:
            url: The URL to analyze
            
        Returns:
            Combined intelligence results
        """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        try:
            # Run all API checks concurrently
            tasks = [
                self.check_google_safebrowsing(url),
                self.check_virustotal(url),
                self.check_phishtank(url),
                self.lookup_whois(domain)
            ]
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            safebrowsing_result = results[0] if not isinstance(results[0], Exception) else self._empty_safebrowsing_result()
            virustotal_result = results[1] if not isinstance(results[1], Exception) else self._empty_virustotal_result()
            phishtank_result = results[2] if not isinstance(results[2], Exception) else self._empty_phishtank_result()
            whois_result = results[3] if not isinstance(results[3], Exception) else self._empty_whois_result()
            
            # Combine results
            combined = {
                'google_safebrowsing': safebrowsing_result,
                'virustotal': virustotal_result,
                'phishtank': phishtank_result,
                'whois': whois_result,
                'combined_risk_score': 0.0,
                'threat_indicators': [],
                'domain_age': whois_result.get('age_days', 0),
                'reputation_score': 0.0
            }
            
            # Calculate combined risk score
            risk_scores = [
                safebrowsing_result.get('risk_score', 0.0),
                virustotal_result.get('risk_score', 0.0),
                phishtank_result.get('risk_score', 0.0),
                whois_result.get('risk_score', 0.0)
            ]
            
            # Weighted average (higher weight for threat detection APIs)
            weights = [0.3, 0.3, 0.3, 0.1]
            combined['combined_risk_score'] = sum(score * weight for score, weight in zip(risk_scores, weights))
            
            # Collect threat indicators
            if not safebrowsing_result.get('is_safe', True):
                combined['threat_indicators'].extend(safebrowsing_result.get('threats', []))
            
            if not virustotal_result.get('is_safe', True):
                combined['threat_indicators'].append(f"VirusTotal: {virustotal_result.get('detection_ratio', '0/0')}")
            
            if not phishtank_result.get('is_safe', True):
                combined['threat_indicators'].append("PhishTank: Known phishing site")
            
            # Calculate reputation score (inverse of risk)
            combined['reputation_score'] = max(0.0, 1.0 - (combined['combined_risk_score'] / 100.0))
            
            return combined
            
        except Exception as e:
            log_error(logger, e, {'operation': 'combined_intelligence', 'url': url})
            return {
                'google_safebrowsing': self._empty_safebrowsing_result(),
                'virustotal': self._empty_virustotal_result(),
                'phishtank': self._empty_phishtank_result(),
                'whois': self._empty_whois_result(),
                'combined_risk_score': 0.0,
                'threat_indicators': [],
                'domain_age': 0,
                'reputation_score': 0.5,
                'error': 'External intelligence gathering failed'
            }


# Create global instance
external_api_service = ExternalAPIService()