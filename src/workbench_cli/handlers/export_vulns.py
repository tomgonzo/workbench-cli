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
from ..utilities.vuln_report.component_enrichment import prefetch_component_info, cache_components_from_cyclonedx
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
    
    # Fetch and enrich vulnerability data (applies to all formats)
    vulnerabilities, external_data = _fetch_and_enrich_vulnerabilities(workbench, scan_code, params)

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
                enable_vex_suppression=not getattr(params, 'disable_vex_suppression', False),
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
                enable_vex_suppression=not getattr(params, 'disable_vex_suppression', False),
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


def _fetch_and_enrich_vulnerabilities(
    workbench: "WorkbenchAPI", 
    scan_code: str, 
    params: argparse.Namespace
) -> tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """
    Fetch vulnerability data from Workbench and enrich it with external data.
    
    Returns:
        Tuple of (vulnerabilities, external_data)
    """
    # Fetch vulnerability data
    if not params.quiet:
        print("\n🔍 Fetching data from Workbench...")
    
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
            print("An empty report will be generated.")
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

            # ------------------------------------------------------------
            # CycloneDX: attempt to download SBOM early so we can populate
            # the component-info cache before hitting the API. This avoids
            # unnecessary network calls when the SBOM already has the data.
            # ------------------------------------------------------------
            if params.format == "cyclonedx":
                sbom_path = _attempt_download_cyclonedx_sbom(workbench, scan_code, params)
                if sbom_path:
                    cache_components_from_cyclonedx(sbom_path, quiet=True)
                    # The helper stores the temp file path on *params* for
                    # later reuse by _handle_cyclonedx_export.

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
            # Still need to fetch external data for report generation, but quietly
            from ..utilities.vuln_report.sarif_generator import _fetch_external_enrichment_data
            
            # Pre-fetch component information quietly (no progress messages)
            prefetch_component_info(vulnerabilities, quiet=True)
            
            # Fetch external data if any enrichment is enabled
            if nvd_enrichment or epss_enrichment or cisa_kev_enrichment:
                from ..utilities.vuln_report.sarif_generator import _extract_unique_cves
                unique_cves = _extract_unique_cves(vulnerabilities)
                external_data = enrich_vulnerabilities(
                    unique_cves, 
                    nvd_enrichment, 
                    epss_enrichment, 
                    cisa_kev_enrichment,
                    api_timeout
                )
            else:
                external_data = {}
    
    return vulnerabilities, external_data


# ---------------------------------------------------------------------------
# Helper: Download CycloneDX SBOM (best-effort)
# ---------------------------------------------------------------------------


def _attempt_download_cyclonedx_sbom(
    workbench: "WorkbenchAPI",
    scan_code: str,
    params: argparse.Namespace,
) -> Optional[str]:
    """Return path to a temporary CycloneDX SBOM or *None* on failure.

    If we already downloaded the SBOM earlier in this session the cached path
    stored on *params* (``_cyclonedx_sbom_path``) is returned.
    """

    if getattr(params, "_cyclonedx_sbom_path", None):
        return params._cyclonedx_sbom_path  # type: ignore[attr-defined]

    try:
        report_type = "cyclone_dx"
        is_async = report_type in workbench.ASYNC_REPORT_TYPES

        if not params.quiet:
            print("    📦 Downloading CycloneDX SBOM from Workbench …")

        if is_async:
            process_id = workbench.generate_scan_report(
                scan_code, report_type=report_type, include_vex=True
            )

            workbench._wait_for_process(
                process_description=f"CycloneDX report generation (Process ID: {process_id})",
                check_function=workbench.check_scan_report_status,
                check_args={"process_id": process_id, "scan_code": scan_code},
                status_accessor=lambda d: d.get("progress_state", "UNKNOWN"),
                success_values={"FINISHED"},
                failure_values={"FAILED", "CANCELLED", "ERROR"},
                max_tries=getattr(params, "scan_number_of_tries", 60),
                wait_interval=3,
                progress_indicator=False,
            )

            response = workbench.download_scan_report(process_id)
        else:
            response = workbench.generate_scan_report(
                scan_code, report_type=report_type, include_vex=True
            )

        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            if hasattr(response, "content") and response.content is not None:
                tmp.write(response.content.decode("utf-8"))
            else:
                tmp.write(getattr(response, "text", str(response)))

            sbom_path = tmp.name

        params._cyclonedx_sbom_path = sbom_path  # cache for later reuse
        return sbom_path

    except Exception as exc:
        logger.debug(f"CycloneDX SBOM download failed: {exc}")
        return None


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
         enable_vex_suppression=not getattr(params, "disable_vex_suppression", False),
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


def _extract_vulnerabilities_from_cyclonedx_report(cyclonedx_path: str) -> List[Dict[str, Any]]:
    """
    Extract vulnerability data from a CycloneDX report for external enrichment.
    
    Args:
        cyclonedx_path: Path to the CycloneDX JSON file
        
    Returns:
        List of vulnerability dictionaries compatible with enrichment functions
    """
    import json
    
    vulnerabilities = []
    
    try:
        with open(cyclonedx_path, 'r', encoding='utf-8') as f:
            cyclonedx_data = json.load(f)
        
        # Create component lookup by bom-ref
        components_by_ref = {}
        if 'components' in cyclonedx_data:
            for component in cyclonedx_data['components']:
                bom_ref = component.get('bom-ref')
                if bom_ref:
                    components_by_ref[bom_ref] = component
        
        # Extract vulnerabilities
        if 'vulnerabilities' in cyclonedx_data:
            for vuln in cyclonedx_data['vulnerabilities']:
                cve = vuln.get('id', 'UNKNOWN')
                
                # Find affected components
                affected_components = []
                if 'affects' in vuln:
                    for affect in vuln['affects']:
                        ref = affect.get('ref')
                        if ref and ref in components_by_ref:
                            affected_components.append(components_by_ref[ref])
                
                # Create vulnerability records for each affected component
                for component in affected_components:
                    vuln_record = {
                        'cve': cve,
                        'component_name': component.get('name', 'Unknown'),
                        'component_version': component.get('version', 'Unknown'),
                        'id': f"{cve}-{component.get('name', 'Unknown')}-{component.get('version', 'Unknown')}",
                    }
                    
                    # Extract severity and score from ratings
                    if 'ratings' in vuln and vuln['ratings']:
                        # Use the first rating as base
                        first_rating = vuln['ratings'][0]
                        if 'severity' in first_rating:
                            vuln_record['severity'] = first_rating['severity'].lower()
                        if 'score' in first_rating:
                            vuln_record['base_score'] = str(first_rating['score'])
                    
                    # Extract VEX analysis state
                    if 'analysis' in vuln:
                        analysis = vuln['analysis']
                        if 'state' in analysis:
                            vuln_record['vex_assessment'] = {
                                'status': analysis['state'],
                                'response': analysis.get('response', []),
                                'justification': analysis.get('justification', ''),
                                'detail': analysis.get('detail', ''),
                            }
                    
                    vulnerabilities.append(vuln_record)
        
        logger.debug(f"Extracted {len(vulnerabilities)} vulnerabilities from CycloneDX report")
        return vulnerabilities
        
    except Exception as e:
        logger.error(f"Failed to extract vulnerabilities from CycloneDX report: {e}")
        return []


def _perform_external_enrichment_for_cyclonedx(
    vulnerabilities: List[Dict[str, Any]], 
    params: argparse.Namespace,
    quiet: bool = False
) -> Dict[str, Dict[str, Any]]:
    """
    Perform external enrichment for CycloneDX vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        params: Command line parameters
        quiet: Whether to suppress output messages
        
    Returns:
        Dictionary of external enrichment data keyed by CVE
    """
    # Extract configuration values from parameters
    nvd_enrichment = getattr(params, 'enrich_nvd', False)
    epss_enrichment = getattr(params, 'enrich_epss', False)
    cisa_kev_enrichment = getattr(params, 'enrich_cisa_kev', False)
    api_timeout = getattr(params, 'external_timeout', 30)
    
    if not (nvd_enrichment or epss_enrichment or cisa_kev_enrichment):
        if not quiet:
            print(f"\n🔍 External Enrichment: DISABLED")
        return {}
    
    # Show enrichment status
    enrichment_sources = []
    if nvd_enrichment:
        enrichment_sources.append("NVD")
    if epss_enrichment:
        enrichment_sources.append("EPSS")
    if cisa_kev_enrichment:
        enrichment_sources.append("CISA KEV")
    
    if not quiet:
        print(f"\n🔍 External Enrichment: {', '.join(enrichment_sources)}")
    
    # Get unique CVEs for enrichment
    unique_cves = list(set(
        vuln.get('cve', 'UNKNOWN') 
        for vuln in vulnerabilities 
        if vuln.get('cve') and vuln.get('cve') != 'UNKNOWN'
    ))
    
    if not unique_cves:
        if not quiet:
            print("   • No CVEs found for enrichment")
        return {}
    
    # Show custom NVD message if NVD enrichment is enabled
    if nvd_enrichment and unique_cves:
        if not quiet:
            print(f"   📋 Fetching additional details for {len(unique_cves)} CVEs from NVD")
            if not os.environ.get('NVD_API_KEY'):
                print(f"   💡 For faster performance, set the 'NVD_API_KEY' environment variable")
    
    # Perform the actual enrichment with suppressed logging
    # Temporarily increase logging level to suppress INFO messages
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
    if epss_enrichment and external_data and not quiet:
        epss_count = sum(1 for cve_data in external_data.values() if cve_data.get('epss_score') is not None)
        if epss_count > 0:
            print(f"   📊 EPSS scores retrieved for {epss_count} CVEs")
    
    return external_data


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