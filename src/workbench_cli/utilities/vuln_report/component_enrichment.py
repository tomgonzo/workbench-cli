"""
Workbench‐specific component enrichment helpers.

This module centralises all logic required to enrich vulnerability results with
component-level metadata that can be fetched from a Workbench instance.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Any, Optional, Tuple, List, TYPE_CHECKING
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from ...api.components_api import ComponentsAPI
from ...exceptions import ApiError, NetworkError

if TYPE_CHECKING:
    from ...api import WorkbenchAPI

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
    "cache_components_from_cyclonedx",  # Populate cache from SBOM
    # New generic helpers (format-dispatching)
    "fetch_sbom",
    "cache_components_from_sbom",
] 


# ---------------------------------------------------------------------------
# CycloneDX SBOM helper
# ---------------------------------------------------------------------------

def cache_components_from_cyclonedx(sbom_path: str, quiet: bool = False) -> int:
    """Parse *sbom_path* and cache component records.

    The function iterates through each *component* entry in the JSON SBOM and
    populates the ``_COMPONENT_INFO_CACHE`` so that later calls to
    :pyfunc:`prefetch_component_info` / :pyfunc:`_get_component_info` do not
    need to hit the Workbench API.

    It is *best effort* – if the file cannot be parsed the cache remains
    unchanged and the function returns 0.

    Parameters
    ----------
    sbom_path:
        Path to a CycloneDX JSON file.
    quiet:
        Suppress informational output when *True*.

    Returns
    -------
    int
        Number of component entries added to the cache.
    """
    import json

    added = 0

    if not os.path.isfile(sbom_path):
        return 0

    try:
        with open(sbom_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        logger.debug(f"Failed to parse CycloneDX SBOM at {sbom_path}: {exc}")
        return 0

    for comp in data.get("components", []):
        name = comp.get("name")
        version = comp.get("version")
        if not name or not version:
            continue

        key = (name, version)
        if key in _COMPONENT_INFO_CACHE:
            continue  # already cached

        # Only store a subset of fields that the rest of the codebase relies on
        cache_entry: Dict[str, Any] = {
            "purl": comp.get("purl"),
            # Older SBOMs might store purl_type/namespace/name/version separately
            "purl_type": comp.get("purl_type"),
            "purl_namespace": comp.get("purl_namespace"),
            "purl_name": comp.get("purl_name"),
            "purl_version": comp.get("purl_version"),
            # NEW – cache additional metadata useful for later enrichment
            "licenses": comp.get("licenses"),
            "author": comp.get("author") or (comp.get("supplier") or {}).get("name"),
            "publisher": comp.get("publisher"),
        }

        _COMPONENT_INFO_CACHE[key] = cache_entry
        added += 1

    if added and not quiet:
        print(f"    ✅ Loaded component metadata for {added} components from CycloneDX SBOM")

    return added 


# ---------------------------------------------------------------------------
# CycloneDX SBOM download helper (reused by handlers)
# ---------------------------------------------------------------------------


def download_cyclonedx_sbom(
    workbench: "WorkbenchAPI",
    scan_code: str,
    *,
    include_vex: bool = True,
    params: Optional[argparse.Namespace] = None,
    quiet: bool = False,
) -> Optional[str]:
    """Generate & download a scan-level CycloneDX SBOM from Workbench.

    Returns a path to a temporary JSON file on success, or *None* on failure.

    The logic mirrors the report-generation flow in *download_reports.py* but is
    packaged as a standalone utility to avoid code duplication across
    handlers.
    """

    import tempfile

    report_type = "cyclone_dx"

    try:
        is_async = report_type in workbench.ASYNC_REPORT_TYPES

        if is_async and not quiet:
            print("    Generating CycloneDX SBOM asynchronously…")

        if is_async:
            process_id = workbench.generate_scan_report(
                scan_code,
                report_type=report_type,
                include_vex=include_vex,
            )

            # Adopt the same waiting strategy as *download_reports* for
            # consistency (3-second interval, up to scan_number_of_tries)
            workbench._wait_for_process(
                process_description=f"CycloneDX report generation (Process ID: {process_id})",
                check_function=workbench.check_scan_report_status,
                check_args={"process_id": process_id, "scan_code": scan_code},
                status_accessor=lambda d: d.get("progress_state", "UNKNOWN"),
                success_values={"FINISHED"},
                failure_values={"FAILED", "CANCELLED", "ERROR"},
                max_tries=getattr(params, "scan_number_of_tries", 60) if params else 60,
                wait_interval=3,
                progress_indicator=not quiet,
            )

            response = workbench.download_scan_report(process_id)
        else:
            if not quiet:
                print("    Generating CycloneDX SBOM (synchronous)…")
            response = workbench.generate_scan_report(
                scan_code,
                report_type=report_type,
                include_vex=include_vex,
            )

        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            if hasattr(response, "content") and response.content is not None:
                tmp.write(response.content.decode("utf-8"))
            else:
                tmp.write(getattr(response, "text", str(response)))

            if not quiet:
                print(f"    ✅ SBOM downloaded → {tmp.name}")

            return tmp.name

    except Exception as exc:
        logger.debug(f"CycloneDX SBOM download failed: {exc}")
        return None 


# ---------------------------------------------------------------------------
# Generic SBOM helpers (format-dispatching)
# ---------------------------------------------------------------------------


def fetch_sbom(
    workbench: "WorkbenchAPI",
    scan_code: str,
    *,
    sbom_format: str = "cyclonedx",
    include_vex: bool = True,
    params: Optional[argparse.Namespace] = None,
    quiet: bool = False,
) -> Optional[str]:
    """Download a scan-level SBOM in *sbom_format* from Workbench.

    At present only the *cyclonedx* format is fully supported. Additional
    formats (e.g. *spdx3*) will be added incrementally – callers should be
    prepared for the function to return *None* when the requested format is
    not yet implemented.

    The returned value is a path to a temporary file holding the SBOM JSON
    content (or *None* on failure).
    """

    fmt_normalised = sbom_format.lower()

    if fmt_normalised in {"cyclonedx", "cyclone_dx", "cdx"}:
        # Delegate to the existing CycloneDX helper for now – we keep the
        # original function so that other modules remain backwards compatible.
        path = download_cyclonedx_sbom(
            workbench,
            scan_code,
            include_vex=include_vex,
            params=params,
            quiet=quiet,
        )

        # Expose on *params* for downstream reuse (optional)
        if path and params is not None:
            setattr(params, "_cyclonedx_sbom_path", path)

        return path

    elif fmt_normalised in {"spdx3", "spdx"}:
        if not quiet:
            print("    ℹ️  SPDX SBOM download not yet implemented – skipping")
        return None

    else:
        raise ValueError(f"Unsupported SBOM format '{sbom_format}' requested")


def cache_components_from_sbom(
    sbom_path: str,
    *,
    sbom_format: str = "cyclonedx",
    quiet: bool = False,
) -> int:
    """Populate the component-info cache from *sbom_path*.

    The helper dispatches to format-specific caching functions.  It returns the
    number of component records added to the cache.
    """

    fmt_normalised = sbom_format.lower()

    if fmt_normalised in {"cyclonedx", "cyclone_dx", "cdx"}:
        return cache_components_from_cyclonedx(sbom_path, quiet=quiet)

    elif fmt_normalised in {"spdx3", "spdx", "spdx_json"}:
        return cache_components_from_spdx(sbom_path, quiet=quiet)

    else:
        raise ValueError(f"Unsupported SBOM format '{sbom_format}' for caching")


# ---------------------------------------------------------------------------
# SPDX helper – *stub* implementation (to be expanded in follow-up work)
# ---------------------------------------------------------------------------


def cache_components_from_spdx(sbom_path: str, quiet: bool = False) -> int:  # pragma: no cover – stub
    """Parse an SPDX 3.0 JSON SBOM and cache components.

    The current implementation is a *stub* that simply returns 0 so that the
    rest of the export pipeline functions even when SPDX support is not yet
    available.
    """

    if not quiet:
        logger.debug("SPDX SBOM parsing not yet implemented – nothing cached")
    return 0 