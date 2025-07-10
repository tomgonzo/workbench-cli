"""
Vulnerability data enrichment utilities.

This module provides functionality to enhance vulnerability data with external sources
including NVD, EPSS scores, and CISA KEV data.
"""

import json
import requests
import time
import logging
import os
import threading
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# External API configurations
EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Rate limiting settings
NVD_RATE_LIMIT_NO_KEY = 5  # requests per 30 seconds without API key
NVD_RATE_LIMIT_WITH_KEY = 50  # requests per 30 seconds with API key
EPSS_RATE_LIMIT = 100  # requests per minute
REQUEST_TIMEOUT = 30  # seconds

# Module-level cache for NVD data to persist across function calls
_NVD_CACHE: Dict[str, Dict[str, Any]] = {}


class RateLimiter:
    """Thread-safe rate limiter for API requests."""
    
    def __init__(self, max_workers: int, delay: float):
        self.max_workers = max_workers
        self.delay = delay
        self._last_request_time = 0
        self._lock = threading.Lock()
    
    def wait(self) -> None:
        """Wait if necessary to respect rate limits."""
        with self._lock:
            current_time = time.time()
            elapsed = current_time - self._last_request_time
            
            if elapsed < self.delay:
                sleep_time = self.delay - elapsed
                time.sleep(sleep_time)
                
            self._last_request_time = time.time()


def enrich_vulnerabilities(cve_list: List[str], 
                          nvd_enrichment: bool = True,
                          epss_enrichment: bool = True,
                          cisa_kev_enrichment: bool = True,
                          api_timeout: int = 30) -> Dict[str, Dict[str, Any]]:
    """
    Enrich vulnerability data with external sources.
    
    Args:
        cve_list: List of CVE IDs to enrich
        nvd_enrichment: Whether to fetch CVE descriptions from NVD
        epss_enrichment: Whether to fetch EPSS scores from FIRST
        cisa_kev_enrichment: Whether to fetch known exploit information
        api_timeout: Timeout for external API calls in seconds
        
    Returns:
        Dict mapping CVE IDs to their external data
    """
    if not cve_list:
        return {}
    
    return _fetch_external_vulnerability_data(
        cve_list, 
        nvd_enrichment, 
        epss_enrichment, 
        cisa_kev_enrichment,
        api_timeout
    )


def create_enriched_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    enable_dynamic_risk_scoring: bool = True
) -> List[Dict[str, Any]]:
    """
    Create format-agnostic enriched vulnerability objects from vulnerability data.
    
    This function creates standardized vulnerability objects that include external
    enrichment and dynamic risk scoring. Format-specific generators can then
    convert these to their specific formats (CycloneDX, SARIF, SPDX, etc.).
    
    Args:
        vulnerabilities: List of vulnerability dictionaries from Workbench API
        external_data: Pre-fetched external enrichment data (optional)
        enable_dynamic_risk_scoring: Whether to apply dynamic risk scoring
        
    Returns:
        List of enriched vulnerability dictionaries with standardized format-agnostic metadata
    """
    from .risk_adjustments import calculate_dynamic_risk
    
    # Validate external data
    external_data = external_data or {}
    
    enriched_vulnerabilities = []
    
    for vuln in vulnerabilities:
        try:
            cve = vuln.get("cve", "UNKNOWN")
            ext_data = external_data.get(cve, {})
            
            # Create enriched vulnerability object
            enriched_vuln = _create_enriched_vulnerability(vuln, ext_data, enable_dynamic_risk_scoring)
            enriched_vulnerabilities.append(enriched_vuln)
            
        except Exception as e:
            logger.error(f"Failed to enrich vulnerability {vuln.get('cve', 'UNKNOWN')}: {e}")
            # Include original vulnerability as fallback
            enriched_vulnerabilities.append(vuln.copy())
            continue
    
    return enriched_vulnerabilities


def _create_enriched_vulnerability(
    vuln: Dict[str, Any], 
    ext_data: Dict[str, Any],
    enable_dynamic_risk_scoring: bool
) -> Dict[str, Any]:
    """
    Create a format-agnostic enriched vulnerability object.
    
    This creates a standardized vulnerability object that can be consumed by
    any format-specific generator (CycloneDX, SARIF, SPDX, etc.).
    """
    from .risk_adjustments import calculate_dynamic_risk
    
    # Start with original vulnerability data
    enriched_vuln = vuln.copy()
    
    # Add external enrichment data
    if ext_data:
        # Add external data under a standardized key
        enriched_vuln["external_enrichment"] = ext_data.copy()
        
        # Merge important external fields into top level for convenience
        if ext_data.get("nvd_description"):
            enriched_vuln["enriched_description"] = ext_data["nvd_description"]
        if ext_data.get("epss_score") is not None:
            enriched_vuln["epss_score"] = ext_data["epss_score"]
        if ext_data.get("epss_percentile") is not None:
            enriched_vuln["epss_percentile"] = ext_data["epss_percentile"]
        if ext_data.get("cisa_kev"):
            enriched_vuln["cisa_known_exploited"] = ext_data["cisa_kev"]
        if ext_data.get("nvd_cwe"):
            enriched_vuln["cwe_ids"] = ext_data["nvd_cwe"]
        if ext_data.get("nvd_references"):
            enriched_vuln["external_references"] = ext_data["nvd_references"]
    
    # Calculate dynamic risk if enabled
    if enable_dynamic_risk_scoring:
        try:
            dynamic_risk_adjustment = calculate_dynamic_risk(vuln, ext_data)
            enriched_vuln["dynamic_risk"] = {
                "original_level": dynamic_risk_adjustment.original_level.value,
                "adjusted_level": dynamic_risk_adjustment.adjusted_level.value,
                "adjustment_reason": dynamic_risk_adjustment.adjustment_reason,
                "priority_context": dynamic_risk_adjustment.priority_context,
                "suppressed": dynamic_risk_adjustment.suppressed,
                "high_risk_indicator": dynamic_risk_adjustment.high_risk_indicator,
                "high_risk_evidence": dynamic_risk_adjustment.high_risk_evidence,
                "was_promoted": dynamic_risk_adjustment.was_promoted,
                "was_demoted": dynamic_risk_adjustment.was_demoted
            }
        except Exception as e:
            logger.warning(f"Failed to calculate dynamic risk for {vuln.get('cve', 'UNKNOWN')}: {e}")
    
    return enriched_vuln


def _fetch_external_vulnerability_data(cve_list: List[str], 
                                     nvd_enrichment: bool = True,
                                     epss_enrichment: bool = True, 
                                     cisa_kev_enrichment: bool = True,
                                     timeout: int = 30) -> Dict[str, Dict[str, Any]]:
    """
    Fetch external vulnerability data from multiple sources.
    
    Returns:
        Dict mapping CVE IDs to their external data
    """
    external_data = {}
    
    # Initialize data structure
    for cve in cve_list:
        external_data[cve] = {
            "epss_score": None,
            "epss_percentile": None,
            "cisa_kev": False,
            "exploitdb_count": 0,
            "nvd_description": None,
            "nvd_cwe": None,
            "nvd_references": [],
            "full_cvss_vector": None,
            "attack_vector_detail": None
        }
    
    # Fetch data from different sources
    try:
        if epss_enrichment:
            epss_data = _fetch_epss_scores(cve_list, timeout)
            for cve, data in epss_data.items():
                if cve in external_data:
                    external_data[cve].update(data)
    except Exception as e:
        logger.warning(f"Failed to fetch EPSS data: {e}")
    
    try:
        if cisa_kev_enrichment:
            kev_data = _fetch_cisa_kev_data(cve_list, timeout)
            for cve in kev_data:
                if cve in external_data:
                    external_data[cve]["cisa_kev"] = True
    except Exception as e:
        logger.warning(f"Failed to fetch CISA KEV data: {e}")
    
    try:
        if nvd_enrichment:
            nvd_data = _fetch_nvd_data(cve_list, timeout)
            for cve, data in nvd_data.items():
                if cve in external_data:
                    external_data[cve].update(data)
    except Exception as e:
        logger.warning(f"Failed to fetch NVD data: {e}")
    
    return external_data


def _fetch_epss_scores(cve_list: List[str], timeout: int = 30) -> Dict[str, Dict[str, Any]]:
    """Fetch EPSS scores from FIRST API."""
    epss_data = {}
    
    # EPSS API supports batch queries
    batch_size = 100  # API limit
    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i:i + batch_size]
        cve_param = ",".join(batch)
        
        try:
            response = requests.get(
                f"{EPSS_API_URL}?cve={cve_param}",
                timeout=timeout,
                headers={"User-Agent": "Workbench-CLI/1.0"}
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get("status") == "OK" and "data" in data:
                for item in data["data"]:
                    cve = item.get("cve")
                    epss_val = item.get("epss")
                    percentile_val = item.get("percentile")
                    
                    if cve and epss_val is not None and percentile_val is not None:
                        try:
                            epss_score = float(epss_val)
                            epss_percentile = float(percentile_val)
                            # Only include if we have valid data (not just defaults)
                            if epss_score >= 0 and epss_percentile >= 0:
                                epss_data[cve] = {
                                    "epss_score": epss_score,
                                    "epss_percentile": epss_percentile
                                }
                        except (ValueError, TypeError):
                            # Skip invalid data
                            logger.debug(f"Invalid EPSS data for {cve}: epss={epss_val}, percentile={percentile_val}")
                            continue
            
            # Rate limiting
            time.sleep(1)
            
        except Exception as e:
            logger.warning(f"Failed to fetch EPSS data for batch {i//batch_size + 1}: {e}")
    
    return epss_data


def _fetch_cisa_kev_data(cve_list: List[str], timeout: int = 30) -> List[str]:
    """Fetch CISA Known Exploited Vulnerabilities data."""
    try:
        response = requests.get(
            CISA_KEV_URL,
            timeout=timeout,
            headers={"User-Agent": "Workbench-CLI/1.0"}
        )
        response.raise_for_status()
        
        kev_data = response.json()
        known_exploited = set()
        
        if "vulnerabilities" in kev_data:
            for vuln in kev_data["vulnerabilities"]:
                cve = vuln.get("cveID")
                if cve and cve in cve_list:
                    known_exploited.add(cve)
        
        return list(known_exploited)
        
    except Exception as e:
        logger.warning(f"Failed to fetch CISA KEV data: {e}")
        return []


def _fetch_nvd_data(cve_list: List[str], timeout: int = 30) -> Dict[str, Dict[str, Any]]:
    """
    Fetch detailed CVE information from NVD API 2.0 with enhanced performance and reliability.
    
    Improvements:
    - Concurrent processing with rate limiting
    - Exponential backoff retry logic
    - Persistent module-level caching for duplicate requests
    - API key support for higher rate limits
    - Progress tracking for large CVE lists
    """
    nvd_data = {}
    
    if not cve_list:
        return nvd_data
    
    # Check for API key in environment variables
    api_key = os.environ.get('NVD_API_KEY')
    max_workers = 5 if api_key else 2  # Higher concurrency with API key
    rate_limit_delay = 0.6 if api_key else 6  # 50 requests per 30s with key, 5 per 30s without
    
    # Initialize rate limiter
    rate_limiter = RateLimiter(max_workers, rate_limit_delay)
    
    logger.info(f"Fetching NVD data for {len(cve_list)} CVEs using {'API key' if api_key else 'public rate limits'}")
    
    # Filter out already cached CVEs
    cves_to_fetch = [cve for cve in cve_list if cve not in _NVD_CACHE]
    
    if not cves_to_fetch:
        logger.info("All CVEs found in cache")
        return {cve: _NVD_CACHE[cve] for cve in cve_list if cve in _NVD_CACHE}
    
    # Process CVEs concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_cve = {
            executor.submit(_fetch_single_cve_nvd, cve, api_key, rate_limiter, timeout): cve
            for cve in cves_to_fetch
        }
        
        # Collect results with progress tracking
        completed = 0
        for future in as_completed(future_to_cve):
            cve = future_to_cve[future]
            completed += 1
            
            try:
                result = future.result()
                if result:
                    nvd_data[cve] = result
                    _NVD_CACHE[cve] = result  # Cache successful results
                
                if completed % 10 == 0 or completed == len(cves_to_fetch):
                    logger.info(f"Processed {completed}/{len(cves_to_fetch)} CVEs")
                    
            except Exception as e:
                logger.warning(f"Failed to fetch NVD data for {cve}: {e}")
    
    # Include cached results in the return data
    for cve in cve_list:
        if cve in _NVD_CACHE and cve not in nvd_data:
            nvd_data[cve] = _NVD_CACHE[cve]
    
    return nvd_data


def _fetch_single_cve_nvd(cve: str, api_key: Optional[str], rate_limiter: 'RateLimiter', 
                         timeout: int) -> Optional[Dict[str, Any]]:
    """Fetch a single CVE from NVD with retry logic and rate limiting."""
    headers = {"User-Agent": "FossID-Workbench-CLI/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    
    max_retries = 3
    base_delay = 1.0
    
    for attempt in range(max_retries):
        try:
            # Wait for rate limiter
            rate_limiter.wait()
            
            response = requests.get(
                f"{NVD_API_URL}?cveId={cve}",
                timeout=timeout,
                headers=headers
            )
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited for {cve}, waiting {retry_after}s")
                time.sleep(retry_after)
                continue
            
            response.raise_for_status()
            
            data = response.json()
            if "vulnerabilities" in data and data["vulnerabilities"]:
                return _parse_nvd_vulnerability(data["vulnerabilities"][0]["cve"])
            
            return None
            
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Request failed for {cve}, retrying in {delay}s: {e}")
                time.sleep(delay)
            else:
                logger.error(f"Failed to fetch {cve} after {max_retries} attempts: {e}")
                raise
    
    return None


def _parse_nvd_vulnerability(vuln_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse NVD vulnerability data into standardized format."""
    # Extract description
    description = "No description available"
    if "descriptions" in vuln_data:
        for desc in vuln_data["descriptions"]:
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break
    
    # Extract CWE information
    cwe_ids = []
    if "weaknesses" in vuln_data:
        for weakness in vuln_data["weaknesses"]:
            if weakness.get("type") == "Primary":
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_ids.append(desc.get("value", ""))
    
    # Extract references
    references = []
    if "references" in vuln_data:
        for ref in vuln_data["references"][:10]:  # Increased to 10 references
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })
    
    # Extract full CVSS vector
    full_cvss_vector = None
    cvss_score = None
    exploitability_score = None
    impact_score = None
    cvss3_metrics = {}

    if "metrics" in vuln_data:
        for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_type in vuln_data["metrics"]:
                metrics = vuln_data["metrics"][metric_type]
                if metrics:
                    metric_entry = metrics[0]
                    cvss_data = metric_entry.get("cvssData", {})
                    full_cvss_vector = cvss_data.get("vectorString")
                    cvss_score = cvss_data.get("baseScore")

                    # Collect detailed metrics for v3 / v3.1
                    if metric_type.startswith("cvssMetricV3"):
                        keys_map = {
                            "attackVector": "attack_vector",
                            "attackComplexity": "attack_complexity",
                            "privilegesRequired": "privileges_required",
                            "userInteraction": "user_interaction",
                            "scope": "scope",
                            "confidentialityImpact": "confidentiality",
                            "integrityImpact": "integrity",
                            "availabilityImpact": "availability",
                        }
                        for k_src, k_dst in keys_map.items():
                            if cvss_data.get(k_src):
                                cvss3_metrics[k_dst] = cvss_data[k_src]

                    exploitability_score = metric_entry.get("exploitabilityScore") or exploitability_score
                    impact_score = metric_entry.get("impactScore") or impact_score
                break
    
    return {
        "nvd_description": description,
        "nvd_cwe": cwe_ids,
        "nvd_references": references,
        "full_cvss_vector": full_cvss_vector,
        "cvss_score": cvss_score,
        "nvd_published": vuln_data.get("published"),
        "nvd_last_modified": vuln_data.get("lastModified"),
        "exploitability_score": exploitability_score,
        "impact_score": impact_score,
        "cvss3_metrics": cvss3_metrics
    }


# Security metadata processing functions

def build_cvss_vector(vuln: Dict[str, Any]) -> str:
    """
    Build a CVSS vector string from available vulnerability data.
    
    This function consolidates CVSS vector building logic that was previously
    duplicated across different format generators.
    """
    version = vuln.get("cvss_version", "3.1")
    
    vector_parts = [f"CVSS:{version}"]
    
    # Attack Vector
    av = vuln.get("attack_vector", "")
    if av:
        av_map = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P"}
        vector_parts.append(f"AV:{av_map.get(av, av[0] if av else 'N')}")
    
    # Attack Complexity
    ac = vuln.get("attack_complexity", "")
    if ac:
        ac_map = {"LOW": "L", "HIGH": "H"}
        vector_parts.append(f"AC:{ac_map.get(ac, ac[0] if ac else 'L')}")
    
    # Availability Impact
    a = vuln.get("availability_impact", "")
    if a:
        a_map = {"NONE": "N", "LOW": "L", "HIGH": "H"}
        vector_parts.append(f"A:{a_map.get(a, a[0] if a else 'N')}")
    
    return "/".join(vector_parts) if len(vector_parts) > 1 else "CVSS vector not available"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_version_ranges(references: List[Dict[str, Any]]) -> str:
    """Extract version information from NVD references where possible."""
    version_patterns = []
    
    for ref in references:
        url = ref.get("url", "").lower()
        tags = [tag.lower() for tag in ref.get("tags", [])]
        
        # Look for vendor advisory URLs that often contain version info
        if any(tag in ["vendor advisory", "patch", "mitigation"] for tag in tags):
            # Common patterns in vendor URLs
            if "github.com" in url and "/releases/" in url:
                # GitHub release pages often have version info
                version_patterns.append("See GitHub releases for affected versions")
            elif any(vendor in url for vendor in ["apache.org", "nodejs.org", "golang.org", "python.org"]):
                version_patterns.append("Check vendor advisory for version details")
    
    if version_patterns:
        return "; ".join(set(version_patterns))  # Remove duplicates
    
    return ""


__all__ = [
    # Main enrichment functions
    "enrich_vulnerabilities",
    "create_enriched_vulnerabilities",
    
    # Security metadata processing
    "build_cvss_vector",
    "extract_version_ranges",
    
    # Rate limiting
    "RateLimiter",
    
    # Cache access for internal use
    "_NVD_CACHE",
] 