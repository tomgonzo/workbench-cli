# workbench_cli/handlers/export_sarif.py

import logging
import argparse
from typing import TYPE_CHECKING, List, Dict, Any

from ..utilities.error_handling import handler_error_wrapper
from ..utilities.vuln_report.sarif_generator import save_vulns_to_sarif
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
def handle_export_sarif(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'export-sarif' command. Exports vulnerability results in SARIF format.
    
    Args:
        workbench: The Workbench API client
        params: Command line parameters
        
    Returns:
        bool: True if the operation was successful
    """
    
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Resolve project and scan (find only)
    if not params.quiet:
        print("\nResolving scan for SARIF export...")
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
    
    # Fetch vulnerability data
    if not params.quiet:
        print("\n🔍 Fetching data from Workbench...")
    try:
        vulnerabilities = workbench.list_vulnerabilities(scan_code)
        
        # Apply severity filtering if specified
        severity_threshold_text = ""
        if getattr(params, 'severity_threshold', None):
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            min_severity = severity_order.get(params.severity_threshold.lower(), 0)
            original_count = len(vulnerabilities)
            vulnerabilities = [
                vuln for vuln in vulnerabilities
                if severity_order.get(vuln.get('severity', '').lower(), 0) >= min_severity
            ]
            severity_threshold_text = f" (Severity Threshold: {params.severity_threshold.upper()})"
        else:
            severity_threshold_text = ""
        
        # Extract configuration values from parameters
        nvd_enrichment = getattr(params, 'enrich_nvd', False)
        epss_enrichment = getattr(params, 'enrich_epss', False)
        cisa_kev_enrichment = getattr(params, 'enrich_cisa_kev', False)
        api_timeout = getattr(params, 'external_timeout', 30)
        enable_vex_suppression = not getattr(params, 'disable_vex_suppression', False)
        quiet = getattr(params, 'quiet', False)
        
        if not vulnerabilities:
            if not params.quiet:
                print("⚠️  No vulnerabilities found in the scan.")
                print("An empty SARIF report will be generated.")
            external_data = {}
        else:
            if not params.quiet:
                # Step 1: Show vulnerability and VEX retrieval
                print(f"\n📋 Retrieving Vulnerabilities and VEX...")
                
                # Combine vulnerability count and severity breakdown in one line
                from ..utilities.vuln_report.sarif_generator import _calculate_severity_distribution, _format_severity_breakdown_compact
                severity_dist = _calculate_severity_distribution(vulnerabilities)
                severity_breakdown = _format_severity_breakdown_compact(severity_dist)
                print(f"   • Retrieved {len(vulnerabilities)} Vulnerabilities{severity_threshold_text} {severity_breakdown}")
                _display_vex_summary(vulnerabilities, indent="   ")
                
                # Step 2: Pre-fetch component information
                print(f"\n🔧 Retrieving Component Information...")
                from ..utilities.vuln_report.component_enrichment import prefetch_component_info
                
                # Count unique components before fetching
                unique_components = list(set(
                    f"{vuln.get('component_name', 'Unknown')}@{vuln.get('component_version', 'Unknown')}"
                    for vuln in vulnerabilities 
                    if vuln.get("component_name") and vuln.get("component_version")
                ))
                component_count = len(unique_components)
                
                prefetch_component_info(vulnerabilities, quiet=True)  # Always quiet to suppress progress messages
                print(f"   • Component information retrieved for {component_count} Components")
                
                # Step 3: Perform external enrichment and display status
                external_data = _perform_external_enrichment(
                    vulnerabilities, 
                    nvd_enrichment,
                    epss_enrichment,
                    cisa_kev_enrichment,
                    api_timeout
                )
                
                # Step 4: Show Dynamic Scoring section
                _display_dynamic_scoring(
                    vulnerabilities, 
                    enable_vex_suppression,
                    external_data
                )
            else:
                # Still need to fetch external data for SARIF generation, but quietly
                from ..utilities.vuln_report.sarif_generator import _fetch_external_enrichment_data
                from ..utilities.vuln_report.component_enrichment import prefetch_component_info
                
                # Pre-fetch component information quietly (no progress messages)
                prefetch_component_info(vulnerabilities, quiet=True)
                
                external_data = _fetch_external_enrichment_data(
                    vulnerabilities, 
                    nvd_enrichment,
                    epss_enrichment,
                    cisa_kev_enrichment,
                    api_timeout
                )
        
        # Export to SARIF
        if not params.quiet:
            print(f"\n📤 Exporting SARIF report...")
        save_vulns_to_sarif(
            filepath=params.output,
            vulnerabilities=vulnerabilities,
            scan_code=scan_code,
            external_data=external_data,
            nvd_enrichment=nvd_enrichment,
            epss_enrichment=epss_enrichment,
            cisa_kev_enrichment=cisa_kev_enrichment,
            api_timeout=api_timeout,
            enable_vex_suppression=enable_vex_suppression,
            quiet=quiet
        )
        
        if not params.quiet:
            print(f"\n✅ SARIF export completed successfully!")
            print(f"📄 Report saved to: {params.output}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to export SARIF: {e}")
        if isinstance(e, (ApiError, NetworkError, ProcessTimeoutError, ProcessError)):
            raise
        else:
            raise ProcessError(f"Failed to export vulnerability data to SARIF format: {str(e)}")


# Configuration function removed - CLI arguments now used directly


def _perform_external_enrichment(
    vulnerabilities: List[Dict[str, Any]], 
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool,
    api_timeout: int
) -> Dict[str, Dict[str, Any]]:
    """Perform external enrichment and display status messages."""
    import os
    from ..utilities.vuln_report.sarif_generator import _fetch_external_enrichment_data
    
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
        nvd_logger = logging.getLogger('workbench_cli.utilities.vulnerability_enricher')
        original_level = nvd_logger.level
        nvd_logger.setLevel(logging.WARNING)
        
        try:
            external_data = _fetch_external_enrichment_data(
                vulnerabilities, 
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