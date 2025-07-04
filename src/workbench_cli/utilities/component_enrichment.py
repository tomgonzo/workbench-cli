"""
Workbench‐specific component enrichment helpers.

This module centralises all logic required to enrich vulnerability results with
component-level metadata that can be fetched from a Workbench instance.  The
functions were previously implemented in utilities.sarif_converter but have
been moved here for better separation of concerns.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Any, Optional, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..api.components_api import ComponentsAPI
from ..exceptions import ApiError, NetworkError

logger = logging.getLogger(__name__)

# Cache to avoid repeated API lookups per component-version
_COMPONENT_ECOSYSTEM_CACHE: Dict[Tuple[str, str], str] = {}
# Cache for full component records
_COMPONENT_INFO_CACHE: Dict[Tuple[str, str], Dict[str, Any]] = {}


def prefetch_component_info(vulnerabilities: List[Dict[str, Any]], quiet: bool = False) -> None:
    """Pre-fetch component information for all unique components in parallel.
    
    This function identifies all unique component/version pairs from the vulnerabilities
    and fetches their information from the Workbench API in parallel, populating the
    cache so that subsequent calls to _get_component_info are instant.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        quiet: If True, suppress progress messages
    """
    if not vulnerabilities:
        return
    
    # Extract unique component/version pairs
    unique_components = set()
    for vuln in vulnerabilities:
        component_name = vuln.get("component_name")
        component_version = vuln.get("component_version")
        if component_name and component_version:
            unique_components.add((component_name, component_version))
    
    # Filter out already cached components
    components_to_fetch = [
        (name, version) for name, version in unique_components 
        if (name, version) not in _COMPONENT_INFO_CACHE
    ]
    
    if not components_to_fetch:
        return  # All components already cached
    
    # Check if we have API credentials
    api_url = os.getenv("WORKBENCH_URL")
    api_user = os.getenv("WORKBENCH_USER")
    api_token = os.getenv("WORKBENCH_TOKEN")
    
    if not (api_url and api_user and api_token):
        # No credentials, populate cache with empty dictionaries
        for name, version in components_to_fetch:
            _COMPONENT_INFO_CACHE[(name, version)] = {}
        return
    
    if not quiet:
        print(f"    🔧 Pre-fetching component information for {len(components_to_fetch)} components...")
    
    # Fetch component information in parallel
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
    
    if not quiet and successful_fetches > 0:
        print(f"    ✅ Component information retrieved for {successful_fetches} components")


def _fetch_single_component_info(component_name: str, component_version: str, 
                                api_url: str, api_user: str, api_token: str) -> Dict[str, Any]:
    """Fetch component information for a single component (used by prefetch_component_info)."""
    try:
        api_client = ComponentsAPI(api_url, api_user, api_token)
        info = api_client.get_component_information(component_name, component_version) or {}
        return info
    except (ApiError, NetworkError, Exception):
        # Best-effort enrichment – no hard failure
        logger.debug(f"Component information lookup failed for {component_name}@{component_version}", exc_info=True)
        return {}


def _get_component_info(component_name: str, component_version: Optional[str]) -> Dict[str, Any]:
    """Return a cached Workbench component record.

    If the current process has not yet looked up this *(name, version)* pair it
    will call the Components API and cache the result for the remainder of the
    CLI execution.  When credentials are not configured we simply return an
    empty dict so SARIF generation can continue in *offline* mode.
    
    Note: This function now primarily serves as a fallback for cases where
    prefetch_component_info hasn't been called. For best performance, use
    prefetch_component_info before calling SARIF generation functions.
    """
    if not component_name or not component_version:
        return {}

    cache_key = (component_name, component_version)
    if cache_key in _COMPONENT_INFO_CACHE:
        return _COMPONENT_INFO_CACHE[cache_key]

    api_url = os.getenv("WORKBENCH_URL")
    api_user = os.getenv("WORKBENCH_USER")
    api_token = os.getenv("WORKBENCH_TOKEN")

    # CLI guarantees these are set, but this function may be imported in test
    # contexts where they are missing.
    if not (api_url and api_user and api_token):
        return {}

    try:
        api_client = ComponentsAPI(api_url, api_user, api_token)
        info = api_client.get_component_information(component_name, component_version) or {}
        _COMPONENT_INFO_CACHE[cache_key] = info
        return info
    except (ApiError, NetworkError, Exception):  # pragma: no cover – network issues
        # Best-effort enrichment – no hard failure.
        logger.debug("Component information lookup failed", exc_info=True)
        return {}


def _detect_package_ecosystem(
    component_name: str,
    component_version: Optional[str] = None,
    purl: Optional[str] = None,
) -> str:
    """Best-effort guess of the package ecosystem for *component_name*.

    Detection strategy (in order):
      1. If *purl* is supplied, parse its *type* segment.
      2. If *(name, version)* is available, query the Components API which
         usually stores a canonical PURL.
      3. Fallback to heuristics on the component name.
    """

    # 1. Parse the provided PURL if present
    if purl and purl.startswith("pkg:"):
        try:
            return purl[4:].split("/", 1)[0]
        except Exception:
            pass  # Fall back to other methods

    # 2. Use cache or query Components API when we have a version
    if component_version:
        cache_key = (component_name, component_version)
        if cache_key in _COMPONENT_ECOSYSTEM_CACHE:
            return _COMPONENT_ECOSYSTEM_CACHE[cache_key]

        # Use cached component information if available (populated by prefetch_component_info)
        info = _COMPONENT_INFO_CACHE.get(cache_key)
        if not info:
            # Fall back to direct API call if not cached (for backward compatibility)
            info = _get_component_info(component_name, component_version)
        
        if info:
            # Prefer full PURL if available
            purl_from_api = info.get("purl")
            if not purl_from_api and info.get("purl_type"):
                p_type = info.get("purl_type")
                p_namespace = info.get("purl_namespace")
                p_name = info.get("purl_name") or component_name
                p_ver = info.get("purl_version") or component_version
                namespace_part = f"{p_namespace}/" if p_namespace else ""
                purl_from_api = f"pkg:{p_type}/{namespace_part}{p_name}@{p_ver}"

            if purl_from_api and purl_from_api.startswith("pkg:"):
                ecosystem = purl_from_api[4:].split("/", 1)[0]
                _COMPONENT_ECOSYSTEM_CACHE[cache_key] = ecosystem
                return ecosystem
            elif info.get("purl_type"):
                ecosystem = info["purl_type"]
                _COMPONENT_ECOSYSTEM_CACHE[cache_key] = ecosystem
                return ecosystem

    # 3. Heuristic fallback (legacy logic)
    if "/" in component_name:
        if component_name.startswith(("org.", "com.")):
            return "maven"
        elif "@" in component_name:
            return "npm"
        elif component_name.count(".") >= 2:  # Likely a Java package
            return "maven"
        else:
            return "generic"
    elif any(component_name.startswith(prefix) for prefix in ["org.", "com.", "net.", "io."]):
        return "maven"
    elif component_name.count(".") >= 2:  # Likely a Java package
        return "maven"
    else:
        return "generic"


__all__ = [
    "_COMPONENT_ECOSYSTEM_CACHE",
    "_COMPONENT_INFO_CACHE",
    "_get_component_info",
    "_detect_package_ecosystem",
    "prefetch_component_info",  # New function for pre-fetching
] 