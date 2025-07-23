"""
External API Integration Service for HTTPS Shield

This module handles integration with external intelligence sources using urllib3:
- Google Safe Browsing API
- VirusTotal API
- WHOIS lookups
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
    """Process Google Safe Browsing API response with binary scoring"""
    threats = data.get('matches', [])
    
    # Binary score: 1 if any threats found, 0 if empty response
    binary_score = 1 if len(threats) > 0 else 0
    
    result = {
        'extracted_score': binary_score,       # For aggregation (binary 0/1)
        'full_response': data,                 # Preserve full response for LLM context
        'is_safe': len(threats) == 0,
        'threat_count': len(threats),
        'threats': [],
        'risk_score': binary_score * 100,      # Convert to 0-100 scale for compatibility
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
    """Process VirusTotal API response with detection ratio scoring"""
    response_code = data.get('response_code', 0)
    
    if response_code != 1:
        # URL not found in VirusTotal database
        logger.info("URL not found in VirusTotal database")
        return None
    
    positives = data.get('positives', 0)
    total = data.get('total', 1)  # Avoid division by zero, default to 1
    
    # Calculate detection ratio (0.0 to 1.0)
    ratio_score = positives / total if total > 0 else 0.0
    
    result = {
        'extracted_score': ratio_score,        # For aggregation (0.0-1.0 ratio)
        'full_response': data,                 # Preserve full response for LLM context
        'is_safe': positives == 0,
        'detections': positives,
        'total_scanners': total,
        'detection_ratio': f"{positives}/{total}",
        'risk_score': ratio_score * 100,       # Convert to 0-100 scale for compatibility
        'api_source': 'virustotal',
        'scan_date': data.get('scan_date', ''),
        'permalink': data.get('permalink', '')
    }
    
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
    """Process WhoisXMLAPI response with heuristic scoring"""
    whois_record = data.get('WhoisRecord', {})
    
    # Check if there's a data error (domain not found, etc.)
    data_error = whois_record.get('dataError', '')
    if data_error == 'MISSING_WHOIS_DATA':
        logger.info(f"WHOIS data not available for domain: {whois_record.get('domainName', 'unknown')}")
        return None
    
    # Calculate domain age in days
    age_days = _calculate_domain_age_days(whois_record)
    
    # Calculate 5 sub-signals for heuristic scoring
    age_score = _calculate_domain_age_risk(age_days)
    reg_length_score = _calculate_registration_length_risk(whois_record)
    registrar_score = _calculate_registrar_reputation_risk(whois_record)
    privacy_score = _calculate_privacy_proxy_risk(whois_record)
    country_score = _calculate_country_mismatch_risk(whois_record)
    
    # Weighted combination of sub-signals (total = 1.0)
    heuristic_score = (
        age_score * 0.3 +           # Domain age (30%)
        reg_length_score * 0.2 +    # Registration length (20%)
        registrar_score * 0.2 +     # Registrar reputation (20%)
        privacy_score * 0.15 +      # Privacy/proxy usage (15%)
        country_score * 0.15        # Country mismatch (15%)
    )
    
    result = {
        'extracted_score': heuristic_score,    # For aggregation (0.0-1.0 heuristic)
        'full_response': data,                 # Preserve full response for LLM context
        'domain': whois_record.get('domainName', ''),
        'registrar': whois_record.get('registrarName', ''),
        'creation_date': whois_record.get('createdDate', ''),
        'expiration_date': whois_record.get('expiresDate', ''),
        'updated_date': whois_record.get('updatedDate', ''),
        'name_servers': whois_record.get('nameServers', {}).get('hostNames', []),
        'status': whois_record.get('status', ''),
        'age_days': age_days,
        'risk_score': heuristic_score * 100,   # Convert to 0-100 scale for compatibility
        'api_source': 'whoisxmlapi',
        # Sub-signal breakdown for debugging
        'sub_signals': {
            'domain_age_risk': age_score,
            'registration_length_risk': reg_length_score,
            'registrar_reputation_risk': registrar_score,
            'privacy_proxy_risk': privacy_score,
            'country_mismatch_risk': country_score
        }
    }
    
    return result

def _calculate_domain_age_days(whois_record: Dict[str, Any]) -> int:
    """Calculate domain age in days from WHOIS record"""
    age_days = 0
    
    # Try to get age from estimatedDomainAge field first
    estimated_age = whois_record.get('estimatedDomainAge', 0)
    if estimated_age and str(estimated_age).isdigit():
        age_days = int(estimated_age)
    elif whois_record.get('createdDate'):
        try:
            from datetime import datetime
            # Handle different date formats from WhoisXMLAPI
            creation_date_str = whois_record.get('createdDate', '')
            if 'T' in creation_date_str:
                # ISO format with timezone
                creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
            else:
                # Simple date format
                creation_date = datetime.strptime(creation_date_str, '%Y-%m-%d')
            
            age_days = (datetime.utcnow().replace(tzinfo=creation_date.tzinfo if creation_date.tzinfo else None) - creation_date).days
        except Exception as e:
            logger.warning(f"Could not parse creation date: {creation_date_str}, error: {e}")
            age_days = 0
    
    return max(0, age_days)

def _calculate_domain_age_risk(age_days: int) -> float:
    """Calculate risk score based on domain age (newer = higher risk)"""
    if age_days <= 0:
        return 1.0  # No age data = high risk
    
    # Exponential decay: newer domains are much riskier
    # 2 years (730 days) to reach very low risk
    return max(0.0, 1.0 - (age_days / 730.0))

def _calculate_registration_length_risk(whois_record: Dict[str, Any]) -> float:
    """Calculate risk based on registration period length"""
    try:
        from datetime import datetime
        created_str = whois_record.get('createdDate', '')
        expires_str = whois_record.get('expiresDate', '')
        
        if not created_str or not expires_str:
            return 0.5  # No data = medium risk
        
        # Parse dates
        if 'T' in created_str:
            created = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
        else:
            created = datetime.strptime(created_str, '%Y-%m-%d')
            
        if 'T' in expires_str:
            expires = datetime.fromisoformat(expires_str.replace('Z', '+00:00'))
        else:
            expires = datetime.strptime(expires_str, '%Y-%m-%d')
        
        # Calculate registration length in years
        reg_length_days = (expires - created).days
        reg_length_years = reg_length_days / 365.25
        
        # Short-term registrations are riskier
        if reg_length_years <= 1:
            return 0.8  # 1 year or less = high risk
        elif reg_length_years <= 2:
            return 0.6  # 2 years = medium-high risk
        elif reg_length_years <= 5:
            return 0.3  # 2-5 years = medium-low risk
        else:
            return 0.1  # 5+ years = low risk
            
    except Exception as e:
        logger.warning(f"Could not calculate registration length: {e}")
        return 0.5  # Error = medium risk

def _calculate_registrar_reputation_risk(whois_record: Dict[str, Any]) -> float:
    """Calculate risk based on registrar reputation"""
    registrar = whois_record.get('registrarName', '').lower()
    
    # Registrar risk mapping based on known reputation
    REGISTRAR_RISK_MAP = {
        # Reputable registrars (low risk)
        'godaddy': 0.1, 'namecheap': 0.1, 'markmonitor': 0.05,
        'cloudflare': 0.1, 'google': 0.05, 'amazon': 0.05,
        'verisign': 0.05, 'network solutions': 0.1,
        'enom': 0.2, 'tucows': 0.2, 'gandi': 0.1,
        
        # High-risk registrars often used by malicious actors
        'freenom': 0.9, 'domains4bitcoins': 0.8,
        'privacyprotect.org': 0.7, 'whoisguard': 0.6,
        
        # Medium-risk or unknown registrars
        'namebright': 0.4, 'dynadot': 0.3
    }
    
    # Check for exact matches or partial matches
    for known_registrar, risk in REGISTRAR_RISK_MAP.items():
        if known_registrar in registrar:
            return risk
    
    # Default for unknown registrars
    return 0.5

def _calculate_privacy_proxy_risk(whois_record: Dict[str, Any]) -> float:
    """Calculate risk based on privacy/proxy service usage"""
    # Check multiple fields for privacy indicators
    fields_to_check = [
        whois_record.get('registrarName', ''),
        whois_record.get('contactEmail', ''),
        whois_record.get('status', ''),
        str(whois_record.get('registrant', {}))  # Convert to string for checking
    ]
    
    privacy_keywords = [
        'privacy', 'whoisguard', 'domains by proxy', 'redacted',
        'protect', 'private', 'proxy', 'masked', 'hidden',
        'privacyprotect', 'domainsbyproxy', 'whoisprotection'
    ]
    
    # Check all fields for privacy keywords
    for field in fields_to_check:
        field_lower = field.lower()
        for keyword in privacy_keywords:
            if keyword in field_lower:
                return 0.7  # Privacy protection = medium-high risk
    
    return 0.2  # No privacy protection = low risk

def _calculate_country_mismatch_risk(whois_record: Dict[str, Any]) -> float:
    """Calculate risk based on registrant vs hosting country mismatch"""
    # For now, implement basic logic - could be enhanced with IP geolocation
    registrant_country = ''
    
    # Try to extract country from registrant info
    registrant = whois_record.get('registrant', {})
    if isinstance(registrant, dict):
        registrant_country = registrant.get('countryCode', '') or registrant.get('country', '')
    
    # If no registrant country data, return medium risk
    if not registrant_country:
        return 0.4
    
    # High-risk country codes often associated with malicious domains
    high_risk_countries = ['tk', 'ml', 'ga', 'cf']  # Freenom domains
    medium_risk_countries = ['ru', 'cn']  # Countries with higher cybercrime activity
    
    registrant_country_lower = registrant_country.lower()
    
    if registrant_country_lower in high_risk_countries:
        return 0.8
    elif registrant_country_lower in medium_risk_countries:
        return 0.6
    else:
        return 0.2  # Most countries = low risk

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