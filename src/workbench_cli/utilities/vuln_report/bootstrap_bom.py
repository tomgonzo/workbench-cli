"""
BOM bootstrapping for API-powered vulnerability report generation.

This module provides component metadata gathering using the Workbench Components API.
Used exclusively by the generation flow to bootstrap BOMs with component information
from vulnerabilities. Format-specific generators can then read from this enriched data.

The augmentation flow works entirely with existing SBOM data and does not use this module.
"""

import logging
import os
from typing import Dict, Any, Optional, Tuple, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from ...api.components_api import ComponentsAPI
from ...exceptions import ApiError, NetworkError

logger = logging.getLogger(__name__)

# Cache to avoid repeated API lookups per component-version
_COMPONENT_ECOSYSTEM_CACHE: Dict[Tuple[str, str], str] = {}
# Cache for full component records
_COMPONENT_INFO_CACHE: Dict[Tuple[str, str], Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _progress_message(message: str, quiet: bool = False) -> None:
    """Print progress message if not in quiet mode."""
    if not quiet:
        print(f"    {message}")


def _extract_component_pairs(vulnerabilities: List[Dict[str, Any]]) -> Set[Tuple[str, str]]:
    """Extract unique (name, version) pairs from vulnerabilities."""
    pairs = set()
    for vuln in vulnerabilities:
        name = vuln.get("component_name")
        version = vuln.get("component_version")
        if name and version:
            pairs.add((name, version))
    return pairs


# ---------------------------------------------------------------------------
# Main BOM Bootstrapping Interface
# ---------------------------------------------------------------------------

def bootstrap_bom_from_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
    quiet: bool = False
) -> List[Dict[str, Any]]:
    """
    Bootstrap BOM with component metadata from vulnerabilities using Workbench API.
    
    This is the main interface for the generation flow that builds BOMs from vulnerabilities.
    Creates format-agnostic component data that format-specific generators can use.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        quiet: If True, suppress progress messages
        
    Returns:
        List of component dictionaries with enriched metadata suitable for any format
    """
    # Get component count first for initial message
    component_list = _extract_components_from_vulnerabilities(vulnerabilities)
    
    if not quiet:
        print(f"\n🔧 Bootstrapping BOM with {len(component_list)} Components")
    
    fetch_component_info(vulnerabilities, quiet=True)  # Always suppress internal logging
    
    if not quiet:
        print("✅ Component Metadata Retrieved")
    return component_list


# ---------------------------------------------------------------------------
# Component Information Cache Management
# ---------------------------------------------------------------------------

def fetch_component_info(vulnerabilities: List[Dict[str, Any]], quiet: bool = False) -> None:
    """Fetch component information for all unique components in parallel."""
    if not vulnerabilities:
        return
    
    # Extract unique component/version pairs
    unique_components = _extract_component_pairs(vulnerabilities)
    
    # Filter components that need fetching
    components_to_fetch = _filter_components_to_fetch(unique_components)
    if not components_to_fetch:
        return  # All components already cached
    
    # Get credentials directly from environment
    api_url = os.getenv("WORKBENCH_URL")
    api_user = os.getenv("WORKBENCH_USER") 
    api_token = os.getenv("WORKBENCH_TOKEN")
    credentials = (api_url, api_user, api_token)
    
    # Fetch component information in parallel
    successful_fetches = _fetch_components_parallel(components_to_fetch, credentials)


def _filter_components_to_fetch(unique_components: Set[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Filter components that need to be fetched (not cached or missing license data)."""
    components_to_fetch = []
    for name, version in unique_components:
        cache_key = (name, version)
        cached = _COMPONENT_INFO_CACHE.get(cache_key)
        if not cached or (not cached.get("license_identifier") and not cached.get("license_name")):
            components_to_fetch.append((name, version))
    return components_to_fetch


def _fetch_components_parallel(
    components_to_fetch: List[Tuple[str, str]], 
    credentials: Tuple[str, str, str]
) -> int:
    """Fetch components in parallel and return number of successful fetches."""
    api_url, api_user, api_token = credentials
    successful_fetches = 0
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Submit all fetch tasks
        future_to_component = {
            executor.submit(_fetch_single_component_info, name, version, api_url, api_user, api_token): (name, version)
            for name, version in components_to_fetch
        }
        
        # Process results as they complete
        for future in as_completed(future_to_component):
            name, version = future_to_component[future]
            try:
                info = future.result()
                _COMPONENT_INFO_CACHE[(name, version)] = info
                if info:  # Only count non-empty results as successful
                    successful_fetches += 1
            except Exception as e:
                logger.debug(f"Failed to fetch component info for {name}@{version}: {e}")
                # Store empty dict to avoid re-fetching
                _COMPONENT_INFO_CACHE[(name, version)] = {}
    
    return successful_fetches


def _fetch_single_component_info(component_name: str, component_version: str, 
                                api_url: str, api_user: str, api_token: str) -> Dict[str, Any]:
    """Fetch component information for a single component."""
    try:
        api_client = ComponentsAPI(api_url, api_user, api_token)
        info = api_client.get_component_information(component_name, component_version) or {}
        return info
    except (ApiError, NetworkError, Exception):
        logger.debug(f"Component information lookup failed for {component_name}@{component_version}", exc_info=True)
        return {}


def get_component_info(component_name: str, component_version: Optional[str]) -> Dict[str, Any]:
    """
    Return cached Workbench component record with fallback to API.
    
    This is the public interface for getting component information that format-specific
    generators can use to enrich their components with Workbench metadata.
    """
    if not component_name or not component_version:
        return {}

    cache_key = (component_name, component_version)
    if cache_key in _COMPONENT_INFO_CACHE:
        return _COMPONENT_INFO_CACHE[cache_key]

    try:
        # Get credentials directly from environment
        api_url = os.getenv("WORKBENCH_URL")
        api_user = os.getenv("WORKBENCH_USER")
        api_token = os.getenv("WORKBENCH_TOKEN")
        
        api_client = ComponentsAPI(api_url, api_user, api_token)
        info = api_client.get_component_information(component_name, component_version) or {}
        _COMPONENT_INFO_CACHE[cache_key] = info
        return info
    except (ApiError, NetworkError, Exception):
        logger.debug("Component information lookup failed", exc_info=True)
        return {}


# ---------------------------------------------------------------------------
# Component Extraction Utilities
# ---------------------------------------------------------------------------

def _extract_components_from_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract unique components from vulnerability data."""
    components = []
    seen_components = set()
    
    for vuln in vulnerabilities:
        name, version = vuln.get("component_name"), vuln.get("component_version")
        if name and version:
            key = (name, version)
            if key not in seen_components:
                seen_components.add(key)
                components.append({
                    "name": name,
                    "version": version,
                    "source": "vulnerability_data"
                })
    
    return components


# ---------------------------------------------------------------------------
# Ecosystem Detection Utilities
# ---------------------------------------------------------------------------

def detect_package_ecosystem(
    component_name: str,
    component_version: Optional[str] = None,
    purl: Optional[str] = None,
) -> str:
    """
    Detect package ecosystem using purl_type from Components API.
    
    This provides format-agnostic ecosystem detection that can be used by
    any format-specific generator (CycloneDX, SPDX, etc.).
    """
    if component_version:
        cache_key = (component_name, component_version)
        if cache_key in _COMPONENT_ECOSYSTEM_CACHE:
            return _COMPONENT_ECOSYSTEM_CACHE[cache_key]

        # Get component info from cache or API
        info = _COMPONENT_INFO_CACHE.get(cache_key) or get_component_info(component_name, component_version)
        
        if info and info.get("purl_type"):
            ecosystem = info["purl_type"]
            _COMPONENT_ECOSYSTEM_CACHE[cache_key] = ecosystem
            return ecosystem

    # Default fallback
    return "generic"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    # Main bootstrapping interface
    "bootstrap_bom_from_vulnerabilities",
    
    # Component information access
    "get_component_info",
    "fetch_component_info",
    
    # Component extraction
    "_extract_components_from_vulnerabilities",
    
    # Ecosystem detection
    "detect_package_ecosystem",
    
    # Cache access for internal use
    "_COMPONENT_ECOSYSTEM_CACHE",
    "_COMPONENT_INFO_CACHE",
] 