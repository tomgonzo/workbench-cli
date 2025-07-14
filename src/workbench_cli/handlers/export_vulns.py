# workbench_cli/handlers/export_vulns.py

import logging
import argparse
import os
from typing import TYPE_CHECKING, List, Dict, Any, Optional, Tuple

from ..utilities.error_handling import handler_error_wrapper
from ..utilities.vuln_report.sarif_generator import save_vulns_to_sarif
from ..utilities.vuln_report.cyclonedx_generator import save_vulns_to_cyclonedx
from ..utilities.vuln_report.spdx_generator import save_vulns_to_spdx
from ..utilities.vuln_report.cve_data_gathering import enrich_vulnerabilities
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
    
    # Extract common parameters once
    common_params = _extract_common_params(params)
    
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
    # 2. Determine export flow and gather external enrichment data
    # ------------------------------------------------------------------
    export_flow = _determine_export_flow(params)
    
    if not params.quiet:
        print(f"   • Using {export_flow} approach")
    
    external_data = _perform_external_enrichment(
        vulnerabilities, 
        common_params['nvd_enrichment'],
        common_params['epss_enrichment'],
        common_params['cisa_kev_enrichment'],
        common_params['external_timeout']
    )

    # ------------------------------------------------------------------
    # 3. Create enriched vulnerability objects (format-agnostic)
    # ------------------------------------------------------------------
    if not params.quiet:
        print(f"\n🔬 Creating Enriched Vulnerability Objects")
    
    from ..utilities.vuln_report.cve_data_gathering import create_enriched_vulnerabilities
    
    enriched_vulnerabilities = create_enriched_vulnerabilities(
        vulnerabilities=vulnerabilities,
        external_data=external_data,
        enable_dynamic_risk_scoring=common_params['enable_dynamic_risk_scoring']
    )
    
    if not params.quiet:
        print(f"✅ Created {len(enriched_vulnerabilities)} Enriched Vulnerability Objects")

    # ------------------------------------------------------------------
    # 4. Apply dynamic scoring (VEX suppression, EPSS / KEV promotion)
    # ------------------------------------------------------------------
    _display_dynamic_scoring(vulnerabilities, common_params['enable_dynamic_risk_scoring'], external_data)

    # ------------------------------------------------------------------
    # Export Logic: Execute flow-specific export
    # ------------------------------------------------------------------
    if not params.quiet:
        print(f"\n📤 Exporting {params.format.upper()} report...")

    try:
        if export_flow == 'augmentation':
            _execute_augmentation_flow(
                workbench=workbench,
                scan_code=scan_code,
                enriched_vulnerabilities=enriched_vulnerabilities,
                external_data=external_data,
                params=params,
                common_params=common_params
            )
        else:  # generation flow
            all_components = _bootstrap_bom_components(vulnerabilities, quiet=params.quiet)
            _execute_generation_flow(
                scan_code=scan_code,
                enriched_vulnerabilities=enriched_vulnerabilities,
                all_components=all_components,
                external_data=external_data,
                params=params,
                common_params=common_params
            )
        
        if not params.quiet:
            print(f"\n✅ {params.format.upper()} export completed successfully!")
            print(f"📄 Report saved to: {params.output}")
            print(f"🔧 Approach: {export_flow} with external enrichment and dynamic risk scoring")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to export {params.format.upper()}: {e}")
        if isinstance(e, (ApiError, NetworkError, ProcessTimeoutError, ProcessError)):
            raise
        else:
            raise ProcessError(f"Failed to export vulnerability data to {params.format.upper()} format: {str(e)}")


def _extract_common_params(params: argparse.Namespace) -> Dict[str, Any]:
    """Extract commonly used parameters to avoid repetitive getattr calls."""
    return {
        'nvd_enrichment': getattr(params, 'enrich_nvd', False),
        'epss_enrichment': getattr(params, 'enrich_epss', False),
        'cisa_kev_enrichment': getattr(params, 'enrich_cisa_kev', False),
        'external_timeout': getattr(params, 'external_timeout', 30),
        'enable_dynamic_risk_scoring': not getattr(params, 'disable_dynamic_risk_scoring', False),
        'quiet': getattr(params, 'quiet', False),
        'augment_full_bom': getattr(params, 'augment_full_bom', False)
    }


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
        # Simple severity breakdown without external dependency
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Format compact breakdown
        breakdown_parts = []
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity_counts.get(severity, 0) > 0:
                breakdown_parts.append(f"{severity[0]}: {severity_counts[severity]}")
        breakdown_text = f"[{', '.join(breakdown_parts)}]" if breakdown_parts else ""
        
        print(f"📋 Retrieved {len(vulnerabilities)} Vulnerabilities {breakdown_text}")
        _display_vex_summary(vulnerabilities, indent="   ")

    return vulnerabilities


def _determine_export_flow(params: argparse.Namespace) -> str:
    """
    Determine which export flow to use based on parameters.
    
    Returns:
        str: Either 'augmentation' or 'generation'
    """
    # Check if augmentation flow is requested and supported
    if (params.format in ['cyclonedx'] and  # Will expand to include 'spdx3' later
        getattr(params, 'augment_full_bom', False)):
        return 'augmentation'
    else:
        return 'generation'


def _bootstrap_bom_components(
    vulnerabilities: List[Dict[str, Any]],
    quiet: bool = False
) -> List[Dict[str, Any]]:
    """Bootstrap BOM with component metadata for the generation flow."""
    from ..utilities.vuln_report.bootstrap_bom import bootstrap_bom_from_vulnerabilities
    
    return bootstrap_bom_from_vulnerabilities(
        vulnerabilities=vulnerabilities,
        quiet=quiet
    )


def _execute_augmentation_flow(
    workbench: "WorkbenchAPI",
    scan_code: str,
    enriched_vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]],
    params: argparse.Namespace,
    common_params: Dict[str, Any]
) -> None:
    """Execute the SBOM augmentation flow with automatic resource management."""
    from ..utilities.vuln_report.sbom_utils import managed_sbom_download
    
    with managed_sbom_download(
        workbench=workbench,
        scan_code=scan_code,
        sbom_format=params.format,
        include_vex=True,
        params=params,
        quiet=common_params['quiet']
    ) as sbom_path:
        
        if not sbom_path:
            # Fallback to generation approach if SBOM download failed
            if not common_params['quiet']:
                print("   ⚠️  SBOM download failed, falling back to generation approach")
            
            all_components = _bootstrap_bom_components(enriched_vulnerabilities, quiet=common_params['quiet'])
            _execute_generation_flow(
                scan_code=scan_code,
                enriched_vulnerabilities=enriched_vulnerabilities,
                all_components=all_components,
                external_data=external_data,
                params=params,
                common_params=common_params
            )
            return
        
        # Execute format-specific augmentation
        if params.format == 'cyclonedx':
            from ..utilities.vuln_report.cyclonedx_enrichment import augment_cyclonedx_sbom_from_file
            
            augment_cyclonedx_sbom_from_file(
                sbom_path=sbom_path,
                filepath=params.output,
                scan_code=scan_code,
                external_data=external_data,
                nvd_enrichment=common_params['nvd_enrichment'],
                epss_enrichment=common_params['epss_enrichment'],
                cisa_kev_enrichment=common_params['cisa_kev_enrichment'],
                enable_dynamic_risk_scoring=common_params['enable_dynamic_risk_scoring'],
                quiet=common_params['quiet']
            )
        elif params.format == 'spdx3':
            # Future SPDX augmentation implementation
            raise ProcessError("SPDX augmentation flow not yet implemented")
        else:
            raise ProcessError(f"Augmentation flow not supported for format: {params.format}")


def _execute_generation_flow(
    scan_code: str,
    enriched_vulnerabilities: List[Dict[str, Any]],
    all_components: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]],
    params: argparse.Namespace,
    common_params: Dict[str, Any]
) -> None:
    """Execute the BOM generation flow from enriched vulnerability data."""
    # Convert enriched vulnerabilities back to original format for backward compatibility
    # TODO: Update format-specific generators to consume enriched vulnerability objects directly
    vulnerabilities = []
    for enriched_vuln in enriched_vulnerabilities:
        # Extract original vulnerability data (excluding enrichment metadata)
        vuln = {k: v for k, v in enriched_vuln.items() 
                if k not in ['external_enrichment', 'dynamic_risk', 'enriched_description', 
                            'epss_score', 'epss_percentile', 'cisa_known_exploited', 
                            'cwe_ids', 'external_references']}
        vulnerabilities.append(vuln)
    
    export_args = {
        'filepath': params.output,
        'vulnerabilities': vulnerabilities,
        'scan_code': scan_code,
        'external_data': external_data,
        'nvd_enrichment': common_params['nvd_enrichment'],
        'epss_enrichment': common_params['epss_enrichment'],
        'cisa_kev_enrichment': common_params['cisa_kev_enrichment'],
        'enable_dynamic_risk_scoring': common_params['enable_dynamic_risk_scoring'],
        'quiet': common_params['quiet'],
        'base_sbom_path': None  # Generation flow doesn't use base SBOM
    }
    
    if params.format == 'cyclonedx':
        from ..utilities.vuln_report.cyclonedx_generator import save_vulns_to_cyclonedx
        save_vulns_to_cyclonedx(**export_args)
    elif params.format == 'sarif':
        from ..utilities.vuln_report.sarif_generator import save_vulns_to_sarif
        export_args['api_timeout'] = common_params['external_timeout']
        save_vulns_to_sarif(**export_args)
    elif params.format == 'spdx3':
        from ..utilities.vuln_report.spdx_generator import save_vulns_to_spdx
        export_args['api_timeout'] = common_params['external_timeout']
        save_vulns_to_spdx(**export_args)
    else:
        raise ProcessError(f"Unsupported format for generation flow: {params.format}")


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
        from ..utilities.vuln_report.risk_adjustments import extract_unique_cves
        unique_cves = extract_unique_cves(vulnerabilities)
        
        # Show custom NVD message if NVD enrichment is enabled
        if nvd_enrichment and unique_cves:
            print(f"   📋 Fetching additional details for {len(unique_cves)} CVEs from NVD")
            if not os.environ.get('NVD_API_KEY'):
                print(f"   💡 For faster performance, set the 'NVD_API_KEY' environment variable")
        
        # Perform the actual enrichment with suppressed logging
        # Temporarily increase logging level to suppress INFO messages
        import logging
        nvd_logger = logging.getLogger('workbench_cli.utilities.vuln_report.cve_data_gathering')
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
    # Simple VEX counting without external dependency
    total_with_vex = 0
    with_status = 0
    with_response = 0
    
    for vuln in vulnerabilities:
        if vuln.get("vuln_exp_id") or vuln.get("vuln_exp_status") or vuln.get("vuln_exp_response"):
            total_with_vex += 1
        if vuln.get("vuln_exp_status"):
            with_status += 1
        if vuln.get("vuln_exp_response"):
            with_response += 1
    
    if total_with_vex > 0:
        print(f"{indent}• Retrieved VEX for {total_with_vex}/{len(vulnerabilities)} CVEs [Status: {with_status}, Response: {with_response}]")


def _count_high_risk_indicators_detailed(
    vulnerabilities: List[Dict[str, Any]], 
    external_data: Dict[str, Dict[str, Any]]
) -> Dict[str, int]:
    """Count vulnerabilities by high risk indicator state."""
    from ..utilities.vuln_report.risk_adjustments import count_high_risk_indicators_detailed
    
    return count_high_risk_indicators_detailed(vulnerabilities, external_data)


def _display_dynamic_scoring(
    vulnerabilities: List[Dict[str, Any]], 
    enable_dynamic_risk_scoring: bool,
    external_data: Dict[str, Dict[str, Any]]
) -> None:
    """Display dynamic scoring summary focusing on high/low/unknown risk levels."""
    
    print(f"\n🔧 Dynamic Scoring:")
    
    # Show High Risk Indicator summary
    if enable_dynamic_risk_scoring:
        high_risk_counts = _count_high_risk_indicators_detailed(vulnerabilities, external_data)
        if high_risk_counts["yes"] > 0:
            print(f"   • High Risk Vulnerabilities: {high_risk_counts['yes']}/{len(vulnerabilities)} require immediate triage")
        if high_risk_counts["no"] > 0:
            print(f"   • Suppressed Vulnerabilities: {high_risk_counts['no']}/{len(vulnerabilities)} assessed as low risk")
        if high_risk_counts["unknown"] > 0:
            print(f"   • Unknown Risk Context: {high_risk_counts['unknown']}/{len(vulnerabilities)} need additional intelligence")
    else:
        print(f"   • Dynamic Risk Scoring: Disabled") 