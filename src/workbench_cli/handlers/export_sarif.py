# workbench_cli/handlers/export_sarif.py

import logging
import argparse
from typing import TYPE_CHECKING

from ..utilities.error_handling import handler_error_wrapper
from ..utilities.sarif_converter import save_vulns_to_sarif
from ..exceptions import (
    ApiError,
    NetworkError,
    ValidationError,
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
        print("\nFetching vulnerability data for SARIF export...")
    try:
        vulnerabilities = workbench.list_vulnerabilities(scan_code)
        
        # Apply severity filtering if specified
        if getattr(params, 'severity_threshold', None):
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            min_severity = severity_order.get(params.severity_threshold.lower(), 0)
            original_count = len(vulnerabilities)
            vulnerabilities = [
                vuln for vuln in vulnerabilities
                if severity_order.get(vuln.get('severity', '').lower(), 0) >= min_severity
            ]
            if not params.quiet and original_count != len(vulnerabilities):
                print(f"Filtered {original_count - len(vulnerabilities)} vulnerabilities below {params.severity_threshold} severity")
        
        if not vulnerabilities:
            if not params.quiet:
                print("⚠️  No vulnerabilities found in the scan.")
                print("An empty SARIF report will be generated.")
        else:
            if not params.quiet:
                print(f"✅ Found {len(vulnerabilities)} vulnerabilities to export.")
                
                # Display summary of what will be included
                severity_counts = {}
                vex_counts = {"with_vex": 0, "without_vex": 0}
                
                for vuln in vulnerabilities:
                    severity = vuln.get("severity", "UNKNOWN")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    # Check for VEX information
                    if vuln.get("vuln_exp_id"):
                        vex_counts["with_vex"] += 1
                    else:
                        vex_counts["without_vex"] += 1
                
                print("\n📊 Vulnerability Summary:")
                for severity, count in sorted(severity_counts.items()):
                    print(f"   • {severity}: {count}")
                
                if vex_counts["with_vex"] > 0:
                    print(f"\n📋 VEX Information:")
                    print(f"   • With VEX assessments: {vex_counts['with_vex']}")
                    print(f"   • Without VEX assessments: {vex_counts['without_vex']}")
        
        # Display export configuration
        if not params.quiet:
            print(f"\n🔧 SARIF Export Configuration:")
            print(f"   • Output file: {params.output}")
            print(f"   • Include VEX assessments: {params.include_vex}")
            if params.severity_threshold:
                print(f"   • Severity threshold: {params.severity_threshold}")
            print(f"   • Include scan metadata: {params.include_scan_metadata}")
            
            # External enrichment status
            if params.skip_enrichment:
                print(f"   • External enrichment: DISABLED (offline mode)")
            else:
                print(f"   • Enrich with NVD descriptions: {params.enrich_nvd}")
                print(f"   • Enrich with EPSS scores: {params.enrich_epss}")
                print(f"   • Enrich with CISA KEV: {params.enrich_cisa_kev}")
                print(f"   • External API timeout: {params.external_timeout}s")
            
            # Suppression settings
            print(f"   • Suppress VEX mitigated: {params.suppress_vex_mitigated}")
            print(f"   • Suppress accepted risk: {params.suppress_accepted_risk}")
            print(f"   • Suppress false positives: {params.suppress_false_positives}")
            print(f"   • Group by component: {params.group_by_component}")
        
        # Export to SARIF
        if not params.quiet:
            print(f"\n📤 Exporting SARIF report...")
        save_vulns_to_sarif(
            filepath=params.output,
            vulnerabilities=vulnerabilities,
            scan_code=scan_code,
            include_cve_descriptions=params.enrich_nvd if not params.skip_enrichment else False,
            include_epss_scores=params.enrich_epss if not params.skip_enrichment else False,
            include_exploit_info=params.enrich_cisa_kev if not params.skip_enrichment else False,
            api_timeout=params.external_timeout,
            include_vex=params.include_vex,
            include_scan_metadata=params.include_scan_metadata,
            suppress_vex_mitigated=params.suppress_vex_mitigated,
            suppress_accepted_risk=params.suppress_accepted_risk,
            suppress_false_positives=params.suppress_false_positives,
            group_by_component=params.group_by_component,
            quiet=params.quiet
        )
        
        if not params.quiet:
            print(f"\n✅ SARIF export completed successfully!")
            print(f"📄 Report saved to: {params.output}")
            
            # Provide integration guidance
            print(f"\n💡 Integration Tips:")
            print(f"   • Upload to GitHub: Add this file to your repository for GitHub Advanced Security integration")
            print(f"   • CI/CD Integration: Use this report in your security scanning pipeline")
            print(f"   • Security Tools: Import into SARIF-compatible security analysis tools")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to export SARIF: {e}")
        if isinstance(e, (ApiError, NetworkError, ProcessTimeoutError, ProcessError)):
            raise
        else:
            raise ProcessError(f"Failed to export vulnerability data to SARIF format: {str(e)}") 