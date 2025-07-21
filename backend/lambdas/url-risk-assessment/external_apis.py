"""
External API Integration Service for HTTPS Shield

This module handles integration with external intelligence sources using urllib3:
- Google Safe Browsing API
- VirusTotal API
- WHOIS lookups

Author: HTTPS Shield Extension Team
Version: 3.0.0 (Function-based)
"""

import json
import os
import time
import urllib3
import xml.etree.ElementTree as ET
from typing import Dict, Any
from urllib.parse import urlparse, urlencode
from logger_config import setup_logger, log_error, log_performance_metric

# Configure logging
logger = setup_logger(__name__)

# Disable urllib3 warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global HTTP manager
http = urllib3.PoolManager(
    timeout=urllib3.Timeout(connect=10, read=10),
    retries=urllib3.Retry(total=3, backoff_factor=0.3)
)

def _load_api_keys() -> Dict[str, str]:
    """Load API keys from environment variables"""
    return {
        'google_safebrowsing': os.environ.get('GOOGLE_SAFEBROWSING_API_KEY'),
        'virustotal': os.environ.get('VIRUSTOTAL_API_KEY'),
        'whois': os.environ.get('WHOIS_API_KEY')
    }

def check_google_safebrowsing(url: str) -> Dict[str, Any]:
    """
    Check URL against Google Safe Browsing API
    
    Args:
        url: The URL to check
        
    Returns:
        Dictionary with Safe Browsing results or None if API unavailable
    """
    api_keys = _load_api_keys()
    
    if not api_keys['google_safebrowsing']:
        logger.warning("Google Safe Browsing API key not configured")
        return None
    
    try:
        start_time = time.time()
        
        # Prepare Safe Browsing API request
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_keys['google_safebrowsing']}"
        
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
        
        logger.info(f"Calling Google Safe Browsing API for URL: {url[:50]}...")
        logger.info(f"Google Safe Browsing request payload: {json.dumps(payload, indent=2)}")
        
        response = http.request(
            'POST',
            api_url,
            body=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        
        # Log performance
        request_time = (time.time() - start_time) * 1000
        log_performance_metric(logger, 'google_safebrowsing_api', request_time)
        
        if response.status == 200:
            data = json.loads(response.data.decode('utf-8'))
            logger.info(f"Google Safe Browsing response: {json.dumps(data, indent=2)}")
            return _process_safebrowsing_response(data)
        else:
            logger.error(f"Google Safe Browsing API error: {response.status} - {response.data.decode('utf-8')}")
            return None
            
    except Exception as e:
        log_error(logger, e, {'operation': 'google_safebrowsing', 'url': url})
        return None

def _process_safebrowsing_response(data: Dict[str, Any]) -> Dict[str, Any]:
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
            'severity': _get_threat_severity(threat_type)
        })
    
    # Calculate risk score based on threats
    if threats:
        max_severity = max(_get_threat_severity(t.get('threatType', '')) for t in threats)
        result['risk_score'] = min(max_severity * 25, 100)  # Scale to 0-100
    
    return result

def _get_threat_severity(threat_type: str) -> float:
    """Get threat severity score (0-4)"""
    severity_map = {
        'MALWARE': 4.0,
        'SOCIAL_ENGINEERING': 3.5,
        'UNWANTED_SOFTWARE': 2.5,
        'POTENTIALLY_HARMFUL_APPLICATION': 2.0,
        'UNKNOWN': 1.0
    }
    return severity_map.get(threat_type, 1.0)

def check_virustotal(url: str) -> Dict[str, Any]:
    """
    Check URL against VirusTotal API
    
    Args:
        url: The URL to check
        
    Returns:
        Dictionary with VirusTotal results or None if API unavailable
    """
    api_keys = _load_api_keys()
    
    if not api_keys['virustotal']:
        logger.warning("VirusTotal API key not configured")
        return None
    
    try:
        start_time = time.time()
        
        # Prepare VirusTotal API request
        params = {
            'apikey': api_keys['virustotal'],
            'resource': url,
            'scan': 0  # Don't trigger new scan, just get existing results
        }
        
        api_url = f"https://www.virustotal.com/vtapi/v2/url/report?{urlencode(params)}"
        
        logger.info(f"Calling VirusTotal API for URL: {url[:50]}...")
        
        response = http.request('GET', api_url)
        
        # Log performance
        request_time = (time.time() - start_time) * 1000
        log_performance_metric(logger, 'virustotal_api', request_time)
        
        if response.status == 200:
            data = json.loads(response.data.decode('utf-8'))
            logger.info(f"VirusTotal response: {json.dumps(data, indent=2)}")
            return _process_virustotal_response(data)
        else:
            logger.error(f"VirusTotal API error: {response.status} - {response.data.decode('utf-8')}")
            return None
            
    except Exception as e:
        log_error(logger, e, {'operation': 'virustotal', 'url': url})
        return None

def _process_virustotal_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Process VirusTotal API response"""
    response_code = data.get('response_code', 0)
    
    if response_code != 1:
        # URL not found in VirusTotal database
        logger.info("URL not found in VirusTotal database")
        return None
    
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

def lookup_whois(domain: str) -> Dict[str, Any]:
    """
    Perform WHOIS lookup for domain using WhoisXMLAPI
    
    Args:
        domain: The domain to look up
        
    Returns:
        Dictionary with WHOIS results or None if API unavailable
    """
    api_keys = _load_api_keys()
    
    if not api_keys.get('whois'):
        logger.warning("WHOIS API key not configured")
        return None
    
    try:
        start_time = time.time()
        
        # Use WhoisXMLAPI service with GET request (returns XML by default)
        params = {
            'domainName': domain,
            'apiKey': api_keys['whois']
        }
        
        api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?{urlencode(params)}"
        
        logger.info(f"Calling WhoisXMLAPI for domain: {domain}")
        
        response = http.request('GET', api_url)
        
        # Log performance
        request_time = (time.time() - start_time) * 1000
        log_performance_metric(logger, 'whois_api', request_time)
        
        # Log raw response for debugging
        raw_response = response.data.decode('utf-8')
        logger.info(f"WHOIS API response status: {response.status}")
        logger.info(f"WHOIS API raw response: {raw_response[:500]}...")  # Log first 500 chars
        
        if response.status == 200:
            if not raw_response.strip():
                logger.error("WHOIS API returned empty response")
                return None
            
            try:
                # Parse XML response
                data = _parse_whois_xml(raw_response)
                if data:
                    logger.info(f"WHOIS response parsed successfully: {json.dumps(data, indent=2)}")
                    return _process_whois_response(data)
                else:
                    logger.error("Failed to parse WHOIS XML response")
                    return None
            except Exception as e:
                logger.error(f"WHOIS API parsing error: {e}")
                logger.error(f"Raw response was: {raw_response}")
                return None
        else:
            logger.error(f"WHOIS API error: {response.status} - {raw_response}")
            return None
            
    except Exception as e:
        log_error(logger, e, {'operation': 'whois', 'domain': domain})
        return None

def _parse_whois_xml(xml_response: str) -> Dict[str, Any]:
    """Parse WhoisXMLAPI XML response and convert to JSON-like dict"""
    try:
        root = ET.fromstring(xml_response)
        
        # Extract key fields from XML
        whois_record = {
            'WhoisRecord': {
                'domainName': _get_xml_text(root, 'domainName'),
                'registrarName': _get_xml_text(root, 'registrarName'),
                'createdDate': _get_xml_text(root, 'createdDate'),
                'updatedDate': _get_xml_text(root, 'updatedDate'),
                'expiresDate': _get_xml_text(root, 'expiresDate'),
                'estimatedDomainAge': _get_xml_text(root, 'estimatedDomainAge'),
                'nameServers': {
                    'hostNames': [addr.text for addr in root.findall('.//nameServers/hostNames/Address') if addr.text]
                },
                'status': _get_xml_text(root, 'status'),
                'contactEmail': _get_xml_text(root, 'contactEmail')
            }
        }
        
        return whois_record
        
    except ET.ParseError as e:
        logger.error(f"XML parsing error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error parsing WHOIS XML: {e}")
        return None

def _get_xml_text(root, tag: str) -> str:
    """Helper function to safely get text from XML element"""
    element = root.find(tag)
    return element.text if element is not None and element.text else ''

def _process_whois_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Process WhoisXMLAPI response"""
    whois_record = data.get('WhoisRecord', {})
    
    # Check if there's a data error (domain not found, etc.)
    data_error = whois_record.get('dataError', '')
    if data_error == 'MISSING_WHOIS_DATA':
        logger.info(f"WHOIS data not available for domain: {whois_record.get('domainName', 'unknown')}")
        return None
    
    result = {
        'domain': whois_record.get('domainName', ''),
        'registrar': whois_record.get('registrarName', ''),
        'creation_date': whois_record.get('createdDate', ''),
        'expiration_date': whois_record.get('expiresDate', ''),
        'updated_date': whois_record.get('updatedDate', ''),
        'name_servers': whois_record.get('nameServers', {}).get('hostNames', []),
        'status': whois_record.get('status', ''),
        'age_days': whois_record.get('estimatedDomainAge', 0),
        'risk_score': 0.0,
        'api_source': 'whoisxmlapi'
    }
    
    # Use estimatedDomainAge if available, otherwise calculate from creation date
    age_days = 0
    
    # Try to get age from estimatedDomainAge field first
    if result['age_days'] and str(result['age_days']).isdigit():
        age_days = int(result['age_days'])
    elif result['creation_date']:
        try:
            from datetime import datetime
            # Handle different date formats from WhoisXMLAPI
            creation_date_str = result['creation_date']
            if 'T' in creation_date_str:
                # ISO format with timezone
                creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
            else:
                # Simple date format
                creation_date = datetime.strptime(creation_date_str, '%Y-%m-%d')
            
            age_days = (datetime.utcnow().replace(tzinfo=creation_date.tzinfo if creation_date.tzinfo else None) - creation_date).days
        except Exception as e:
            logger.warning(f"Could not parse creation date: {result['creation_date']}, error: {e}")
            age_days = 0
    
    # Update the result with the calculated age
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
    
    return result

def get_combined_intelligence(url: str) -> Dict[str, Any]:
    """
    Get combined intelligence from all external sources
    
    Args:
        url: The URL to analyze
        
    Returns:
        Combined intelligence results
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    logger.info(f"Starting combined intelligence gathering for URL: {url}")
    
    try:
        # Call all APIs sequentially
        safebrowsing_result = check_google_safebrowsing(url)
        virustotal_result = check_virustotal(url)
        whois_result = lookup_whois(domain)
        
        # Combine results (only include APIs that returned data)
        combined = {
            'combined_risk_score': 0.0,
            'threat_indicators': [],
            'domain_age': 0,
            'reputation_score': 0.5  # Default neutral reputation
        }
        
        # Add API results only if they succeeded
        if safebrowsing_result:
            combined['google_safebrowsing'] = safebrowsing_result
            logger.info(f"Google Safe Browsing result: {safebrowsing_result}")
        else:
            logger.warning("Google Safe Browsing API failed or returned no data")
            
        if virustotal_result:
            combined['virustotal'] = virustotal_result
            logger.info(f"VirusTotal result: {virustotal_result}")
        else:
            logger.warning("VirusTotal API failed or returned no data")
            
        if whois_result:
            combined['whois'] = whois_result
            combined['domain_age'] = whois_result.get('age_days', 0)
            logger.info(f"WHOIS result: {whois_result}")
        else:
            logger.warning("WHOIS API failed or returned no data")
        
        # Calculate combined risk score only from available APIs
        risk_scores = []
        weights = []
        
        if safebrowsing_result:
            risk_scores.append(safebrowsing_result.get('risk_score', 0.0))
            weights.append(0.5)  # Higher weight for threat detection
        
        if virustotal_result:
            risk_scores.append(virustotal_result.get('risk_score', 0.0))
            weights.append(0.4)  # High weight for malware detection
        
        if whois_result:
            risk_scores.append(whois_result.get('risk_score', 0.0))
            weights.append(0.1)  # Lower weight for domain age
        
        # Calculate weighted average if we have any API results
        if risk_scores:
            total_weight = sum(weights)
            combined['combined_risk_score'] = sum(score * weight for score, weight in zip(risk_scores, weights)) / total_weight
            logger.info(f"Combined risk score calculated: {combined['combined_risk_score']}")
        else:
            logger.warning("No external API results available for risk calculation")
        
        # Collect threat indicators from successful APIs
        if safebrowsing_result and not safebrowsing_result.get('is_safe', True):
            combined['threat_indicators'].extend(safebrowsing_result.get('threats', []))
        
        if virustotal_result and not virustotal_result.get('is_safe', True):
            combined['threat_indicators'].append(f"VirusTotal: {virustotal_result.get('detection_ratio', '0/0')}")
        
        # Calculate reputation score (inverse of risk)
        combined['reputation_score'] = max(0.0, 1.0 - (combined['combined_risk_score'] / 100.0))
        
        logger.info(f"Combined intelligence result: {combined}")
        return combined
        
    except Exception as e:
        log_error(logger, e, {'operation': 'combined_intelligence', 'url': url})
        return {
            'combined_risk_score': 0.0,
            'threat_indicators': [],
            'domain_age': 0,
            'reputation_score': 0.5,
            'error': 'External intelligence gathering failed'
        }

def is_test_url(url: str) -> bool:
    """
    Check if URL is a test URL that should have shorter cache TTL
    
    Args:
        url: The URL to check
        
    Returns:
        True if it's a test URL
    """
    test_domains = [
        'testsafebrowsing.appspot.com',
        'malware.testing.google.test',
        'test.com',
        'example.com'
    ]
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
    for test_domain in test_domains:
        if test_domain in domain:
            return True
    
    return False