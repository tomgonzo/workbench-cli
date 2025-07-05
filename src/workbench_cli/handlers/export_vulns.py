# workbench_cli/handlers/export_vulns.py

import logging
import argparse
import tempfile
import os
from typing import TYPE_CHECKING, List, Dict, Any, Optional

from ..utilities.error_handling import handler_error_wrapper
from ..utilities.vuln_report.sarif_generator import save_vulns_to_sarif
from ..utilities.vuln_report.cyclonedx_generator import save_vulns_to_cyclonedx, build_cyclonedx_from_components
from ..utilities.vuln_report.spdx_generator import save_vulns_to_spdx
from ..utilities.vuln_report.vulnerability_enricher import enrich_vulnerabilities
from ..utilities.vuln_report.component_enrichment import (
    prefetch_component_info,
    cache_components_from_sbom,
    fetch_sbom,
)
from ..exceptions import (
    ApiError,
    NetworkError,
    ProcessTimeoutError,
    ProcessError
)

if TYPE_CHECKING:
    from ..api import WorkbenchAPI

logger = logging.getLogger("workbench-cli")


@handler_error_wrapper
def handle_export_vulns(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'export-vulns' command. Exports vulnerability results in various formats.
    
    Args:
        workbench: The Workbench API client
        params: Command line parameters
        
    Returns:
        bool: True if the operation was successful
    """
    
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Validate format
    supported_formats = ['sarif', 'cyclonedx', 'spdx3']
    if params.format not in supported_formats:
        raise ProcessError(f"Unsupported format '{params.format}'. Supported formats: {', '.join(supported_formats)}")
    
    # Check format-specific dependencies
    _check_format_dependencies(params.format)
    
    # Resolve project and scan (find only)
    if not params.quiet:
        print(f"\nResolving scan for {params.format.upper()} export...")
    project_code = workbench.resolve_project(params.project_name, create_if_missing=False)
    scan_code, scan_id = workbench.resolve_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=False,
        params=params
    )
    
    # Ensure scan processes are idle before fetching results
    if not params.quiet:
        print("\nEnsuring scan processes are idle before fetching vulnerability data...")
    try:
        workbench.ensure_scan_is_idle(scan_code, params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        logger.warning(f"Could not verify scan completion for '{scan_code}': {e}. Proceeding anyway.")
        if not params.quiet:
            print("\nWarning: Could not verify scan completion status. Results may be incomplete.")
    
    # ------------------------------------------------------------------
    # 1. Fetch vulnerability list & built-in VEX
    # ------------------------------------------------------------------
    vulnerabilities = _fetch_vulnerabilities_and_vex(workbench, scan_code, params)

    # ------------------------------------------------------------------
    # 2. Enrich component metadata (Workbench Components API or SBOM cache)
    # ------------------------------------------------------------------
    _enrich_components(workbench, vulnerabilities, scan_code, params)

    # ------------------------------------------------------------------
    # 3. External vulnerability enrichment (NVD / EPSS / KEV)
    # ------------------------------------------------------------------
    external_data = _perform_external_vulnerability_enrichment(vulnerabilities, params)

    # ------------------------------------------------------------------
    # 4. Apply dynamic scoring (VEX suppression, EPSS / KEV promotion)
    # ------------------------------------------------------------------
    _apply_dynamic_scoring(vulnerabilities, external_data, params)

    # Handle CycloneDX export first because it uses a slightly different generation flow
    if params.format == 'cyclonedx':
        if not params.quiet:
            print(f"\n📤 Exporting {params.format.upper()} report...")
        return _handle_cyclonedx_export(
            workbench=workbench,
            scan_code=scan_code,
            vulnerabilities=vulnerabilities,
            external_data=external_data,
            params=params,
        )

    # Proceed with the original path for SARIF and SPDX3
    # Export to the requested format
    if not params.quiet:
        print(f"\n📤 Exporting {params.format.upper()} report...")
    
    try:
        if params.format == 'sarif':
            save_vulns_to_sarif(
                filepath=params.output,
                vulnerabilities=vulnerabilities,
                scan_code=scan_code,
                external_data=external_data,
                nvd_enrichment=getattr(params, 'enrich_nvd', False),
                epss_enrichment=getattr(params, 'enrich_epss', False),
                cisa_kev_enrichment=getattr(params, 'enrich_cisa_kev', False),
                api_timeout=getattr(params, 'external_timeout', 30),
                enable_vex_suppression=not getattr(params, 'disable_dynamic_risk_scoring', False),
                quiet=getattr(params, 'quiet', False)
            )
        elif params.format == 'spdx3':
            save_vulns_to_spdx(
                filepath=params.output,
                vulnerabilities=vulnerabilities,
                scan_code=scan_code,
                external_data=external_data,
                nvd_enrichment=getattr(params, 'enrich_nvd', False),
                epss_enrichment=getattr(params, 'enrich_epss', False),
                cisa_kev_enrichment=getattr(params, 'enrich_cisa_kev', False),
                api_timeout=getattr(params, 'external_timeout', 30),
                enable_vex_suppression=not getattr(params, 'disable_dynamic_risk_scoring', False),
                quiet=getattr(params, 'quiet', False)
            )
        
        if not params.quiet:
            print(f"\n✅ {params.format.upper()} export completed successfully!")
            print(f"📄 Report saved to: {params.output}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to export {params.format.upper()}: {e}")
        if isinstance(e, (ApiError, NetworkError, ProcessTimeoutError, ProcessError)):
            raise
        else:
            raise ProcessError(f"Failed to export vulnerability data to {params.format.upper()} format: {str(e)}")


def _check_format_dependencies(format_name: str) -> None:
    """Check if required dependencies are available for the specified format."""
    if format_name == 'cyclonedx':
        try:
            import cyclonedx
        except ImportError:
            raise ProcessError(
                "CycloneDX format requires the 'cyclonedx-python-lib' package. "
                "This should be installed automatically with workbench-cli. "
                "Try reinstalling: pip install --force-reinstall workbench-cli"
            )
    elif format_name == 'spdx3':
        try:
            import spdx_tools
        except ImportError:
            raise ProcessError(
                "SPDX 3.0 format requires the 'spdx-tools' package. "
                "This should be installed automatically with workbench-cli. "
                "Try reinstalling: pip install --force-reinstall workbench-cli"
            )
    # SARIF format has no external dependencies

def _fetch_vulnerabilities_and_vex(
    workbench: "WorkbenchAPI",
    scan_code: str,
    params: argparse.Namespace,
) -> List[Dict[str, Any]]:
    """Retrieve vulnerabilities from Workbench (with severity filter) and print VEX summary."""
    if not params.quiet:
        print("\n🔍 Fetching data from Workbench…")

    vulnerabilities = workbench.list_vulnerabilities(scan_code)

    # Severity filter
    if getattr(params, "severity_threshold", None):
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_level = sev_order.get(params.severity_threshold.lower(), 0)
        vulnerabilities = [v for v in vulnerabilities if sev_order.get(v.get("severity", "").lower(), 0) >= min_level]

    if not params.quiet:
        from ..utilities.vuln_report.sarif_generator import (
            _calculate_severity_distribution,
            _format_severity_breakdown_compact,
        )
        dist = _calculate_severity_distribution(vulnerabilities)
        print(
            f"📋 Retrieved {len(vulnerabilities)} Vulnerabilities {_format_severity_breakdown_compact(dist)}"
        )
        _display_vex_summary(vulnerabilities, indent="   ")

    return vulnerabilities


def _enrich_components(
    workbench: "WorkbenchAPI",
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    params: argparse.Namespace,
) -> None:
    """Prefetch component info via Components API or SBOM cache."""
    if not vulnerabilities:
        return

    if not params.quiet:
        print("\n🔧 Retrieving Component Information…")

    # CycloneDX: early SBOM download → cache components
    if params.format in {"cyclonedx", "spdx3"}:
        sbom_path = fetch_sbom(
            workbench,
            scan_code,
            sbom_format=params.format,
            include_vex=True,
            params=params,
            quiet=True,
        )
        if sbom_path:
            cache_components_from_sbom(sbom_path, sbom_format=params.format, quiet=True)

    # Parallel Components API prefetch
    unique = {
        (v.get("component_name"), v.get("component_version"))
        for v in vulnerabilities
        if v.get("component_name") and v.get("component_version")
    }
    prefetch_component_info(vulnerabilities, quiet=True)
    if not params.quiet:
        print(f"   • Component information retrieved for {len(unique)} Components")


def _perform_external_vulnerability_enrichment(
    vulnerabilities: List[Dict[str, Any]],
    params: argparse.Namespace,
) -> Dict[str, Dict[str, Any]]:
    nvd = getattr(params, "enrich_nvd", False)
    epss = getattr(params, "enrich_epss", False)
    kev = getattr(params, "enrich_cisa_kev", False)
    timeout = getattr(params, "external_timeout", 30)

    ext_data = _perform_external_enrichment(
        vulnerabilities,
        nvd,
        epss,
        kev,
        timeout,
    )
    return ext_data


def _apply_dynamic_scoring(
    vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]],
    params: argparse.Namespace,
) -> None:
    enable_vex_suppression = not getattr(params, "disable_dynamic_risk_scoring", False)
    _display_dynamic_scoring(vulnerabilities, enable_vex_suppression, external_data)


# ---------------------------------------------------------------------------
# Helper: Download CycloneDX SBOM (best-effort)
# ---------------------------------------------------------------------------


def _handle_cyclonedx_export(
     workbench: "WorkbenchAPI", 
     scan_code: str, 
     vulnerabilities: List[Dict[str, Any]], 
     external_data: Dict[str, Dict[str, Any]], 
     params: argparse.Namespace
 ) -> bool:
     """
     Generate a CycloneDX 1.6 report enriched with vulnerability data.
 
     The strategy is:
     1. We already have the full vulnerability list (and any external enrichment).
     2. We *attempt* to fetch the scan-level CycloneDX SBOM from Workbench so we
        can retain rich component metadata & dependency graph.  If this fails
        for any reason we simply fall back to building a fresh SBOM from the
        vulnerability list alone.
     """
     import os
     import tempfile

     # Reuse SBOM if already downloaded during component enrichment
     base_sbom_path: Optional[str] = getattr(params, "_cyclonedx_sbom_path", None)

     # If the early download failed (no cached path), we simply build a fresh
     # SBOM directly from the vulnerabilities rather than trying a second
     # download – this avoids redundant Workbench requests (slow when
     # enrichment is enabled).

     # 2. Generate & save the enriched CycloneDX report --------------------------------------
     save_vulns_to_cyclonedx(
         filepath=params.output,
         vulnerabilities=vulnerabilities,
         scan_code=scan_code,
         external_data=external_data,
         nvd_enrichment=getattr(params, "enrich_nvd", False),
         epss_enrichment=getattr(params, "enrich_epss", False),
         cisa_kev_enrichment=getattr(params, "enrich_cisa_kev", False),
         enable_vex_suppression=not getattr(params, "disable_dynamic_risk_scoring", False),
         quiet=getattr(params, "quiet", False),
         base_sbom_path=base_sbom_path,
     )

     if not params.quiet:
         print("\n✅ CycloneDX export completed successfully!")
         print(f"📄 Report saved to: {params.output}")

     # 3. Clean up temp file -----------------------------------------------------------------
     if base_sbom_path and os.path.exists(base_sbom_path):
         try:
             os.unlink(base_sbom_path)
         except OSError:
             pass  # ignore cleanup errors

     return True


def _perform_external_enrichment(
    vulnerabilities: List[Dict[str, Any]], 
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool,
    api_timeout: int
) -> Dict[str, Dict[str, Any]]:
    """Perform external enrichment and display status messages."""
    import os
    
    # Show enrichment status
    enrichment_sources = []
    if nvd_enrichment:
        enrichment_sources.append("NVD")
    if epss_enrichment:
        enrichment_sources.append("EPSS")
    if cisa_kev_enrichment:
        enrichment_sources.append("CISA KEV")
    
    if enrichment_sources:
        print(f"\n🔍 External Enrichment: {', '.join(enrichment_sources)}")
        
        # Get unique CVEs for display
        from ..utilities.vuln_report.sarif_generator import _extract_unique_cves
        unique_cves = _extract_unique_cves(vulnerabilities)
        
        # Show custom NVD message if NVD enrichment is enabled
        if nvd_enrichment and unique_cves:
            print(f"   📋 Fetching additional details for {len(unique_cves)} CVEs from NVD")
            if not os.environ.get('NVD_API_KEY'):
                print(f"   💡 For faster performance, set the 'NVD_API_KEY' environment variable")
        
        # Perform the actual enrichment with suppressed logging
        # Temporarily increase logging level to suppress INFO messages
        import logging
        nvd_logger = logging.getLogger('workbench_cli.utilities.vuln_report.vulnerability_enricher')
        original_level = nvd_logger.level
        nvd_logger.setLevel(logging.WARNING)
        
        try:
            external_data = enrich_vulnerabilities(
                unique_cves, 
                nvd_enrichment,
                epss_enrichment,
                cisa_kev_enrichment,
                api_timeout
            )
        finally:
            nvd_logger.setLevel(original_level)
        
        # Show EPSS results if EPSS enrichment was enabled
        if epss_enrichment and external_data:
            epss_count = sum(1 for cve_data in external_data.values() if cve_data.get('epss_score') is not None)
            if epss_count > 0:
                print(f"   📊 EPSS scores retrieved for {epss_count} CVEs")
        
        return external_data
    else:
        print(f"\n🔍 External Enrichment: DISABLED")
        return {}


def _display_vex_summary(vulnerabilities: List[Dict[str, Any]], indent: str = "") -> None:
    """Display VEX assessment information in a concise format."""
    from ..utilities.vuln_report.sarif_generator import _count_vex_assessments
    vex_counts = _count_vex_assessments(vulnerabilities)
    
    if vex_counts["total_with_vex"] > 0:
        print(f"{indent}• Retrieved VEX for {vex_counts['total_with_vex']}/{len(vulnerabilities)} CVEs [Status: {vex_counts['with_status']}, Response: {vex_counts['with_response']}]")


def _display_dynamic_scoring(
    vulnerabilities: List[Dict[str, Any]], 
    enable_vex_suppression: bool,
    external_data: Dict[str, Dict[str, Any]]
) -> None:
    """Display dynamic scoring information including both suppressions and promotions."""
    from ..utilities.vuln_report.sarif_generator import _count_high_risk_vulnerabilities, _count_vex_assessments
    
    print(f"\n🔧 Dynamic Scoring:")
    
    # Show VEX suppression
    vex_counts = _count_vex_assessments(vulnerabilities)
    if enable_vex_suppression and vex_counts["total_with_vex"] > 0:
        if vex_counts["suppressed"] > 0:
            print(f"   • VEX Risk: {vex_counts['suppressed']} CVEs Suppressed")
        else:
            print(f"   • VEX Suppression: Enabled (no CVEs Suppressed)")
    else:
        print(f"   • VEX Suppression: {'Enabled' if enable_vex_suppression else 'Disabled'}")
    
    # Show high-risk vulnerability information with promotion details
    if external_data:
        high_risk_counts = _count_high_risk_vulnerabilities(vulnerabilities, external_data)
        
        # Show EPSS promotions
        if high_risk_counts.get("high_epss", 0) > 0:
            print(f"   • EPSS Risk: {high_risk_counts['high_epss']} CVEs Escalated")
        
        # Show CISA KEV if present
        if high_risk_counts.get("cisa_kev", 0) > 0:
            print(f"   • CISA KEV: {high_risk_counts['cisa_kev']} CVEs Escalated")
    
    # Show VEX-based promotions (exploitable CVEs get promoted to 'error' level)
    if vex_counts["total_with_vex"] > 0 and vex_counts["exploitable"] > 0:
        print(f"   • VEX Risk: {vex_counts['exploitable']} CVEs Escalated") 