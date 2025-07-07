"""workbench_cli.utilities.sarif_generation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SARIF generation utilities for vulnerability data.

This module provides functionality to convert vulnerability data from the Workbench API
into SARIF (Static Analysis Results Interchange Format) v2.1.0 format, which is
compatible with GitHub Advanced Security and other security tools.

Enhanced with external API integration for EPSS scores, known exploits, CVE details,
and VEX (Vulnerability Exploitability eXchange) information.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass

from .cve_data_gathering import enrich_vulnerabilities, build_cvss_vector
from .bootstrap_bom import detect_package_ecosystem
from .risk_adjustments import (
    calculate_dynamic_risk, 
    RiskAdjustment,
    extract_unique_cves,
    count_high_risk_vulnerabilities
)

logger = logging.getLogger(__name__)


# Configuration removed - CLI arguments now drive behavior directly


__all__ = [
    # Public API
    "convert_vulns_to_sarif",
    "save_vulns_to_sarif",
    # Selected VEX helpers exposed for risk-guidance logic
    "apply_vex_suppression",
    "get_vex_info",
    "map_vex_status_to_sarif_level",
    "generate_vex_properties",
    "analyze_vex_statements",
    # Internal functions exposed for export_vulns handler
    "_fetch_external_enrichment_data",
    "_calculate_severity_distribution",
    "_format_severity_breakdown_compact",
    "_count_vex_assessments",
]


def apply_vex_suppression(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Apply VEX-based suppression to vulnerabilities.
    
    Suppresses findings that have been assessed through VEX as:
    - Mitigated/not affected/resolved
    - Accepted risk
    - False positives
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Filtered list of vulnerabilities after applying VEX suppression rules
    """
    filtered_vulns = []
    
    for vuln in vulnerabilities:
        should_suppress = False
        
        # Check VEX status for suppression
        vex_status = (vuln.get("vuln_exp_status") or "").lower()
        vex_response = (vuln.get("vuln_exp_response") or "").lower()
        
        # Suppress VEX mitigated findings
        if vex_status in ["not_affected", "resolved", "false_positive"]:
            should_suppress = True
        
        # Suppress accepted risk findings
        if vex_response in ["will_not_fix", "update", "can_not_fix"]:
            should_suppress = True
        
        if not should_suppress:
            filtered_vulns.append(vuln)
    
    return filtered_vulns

def convert_vulns_to_sarif(
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    *,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    api_timeout: int = 30,
    enable_dynamic_risk_scoring: bool = True,
    quiet: bool = False,
) -> Dict[str, Any]:
    """
    Convert vulnerability results to SARIF format.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: External enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was applied
        epss_enrichment: Whether EPSS enrichment was applied
        cisa_kev_enrichment: Whether CISA KEV enrichment was applied
        api_timeout: API timeout to use for data fetching
        enable_dynamic_risk_scoring: Apply dynamic risk scoring adjustments (default: True)
        quiet: Whether to suppress output messages
        
    Returns:
        SARIF dictionary
    """
    if not vulnerabilities:
        return _create_empty_sarif_report(scan_code)
    
    # Use pre-fetched external data if provided, otherwise fetch it
    if external_data is None:
        external_data = _fetch_external_enrichment_data(
            vulnerabilities, 
            nvd_enrichment, 
            epss_enrichment, 
            cisa_kev_enrichment,
            api_timeout
        )
    
    # Build SARIF structure
    sarif_data = _build_sarif_structure(
        vulnerabilities, scan_code, external_data,
        nvd_enrichment=nvd_enrichment,
        epss_enrichment=epss_enrichment,
        cisa_kev_enrichment=cisa_kev_enrichment,
        enable_dynamic_risk_scoring=enable_dynamic_risk_scoring,
        quiet=quiet
    )
    
    return sarif_data


def _fetch_external_enrichment_data(
    vulnerabilities: List[Dict[str, Any]], 
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool,
    api_timeout: int
) -> Dict[str, Dict[str, Any]]:
    """Fetch external enrichment data for vulnerabilities."""
    unique_cves = extract_unique_cves(vulnerabilities)
    
    external_data = {}
    if unique_cves:
        try:
            external_data = enrich_vulnerabilities(
                unique_cves, 
                nvd_enrichment, 
                epss_enrichment, 
                cisa_kev_enrichment,
                api_timeout
            )
        except Exception as e:
            logger.warning(f"Failed to fetch external vulnerability data: {e}")
    
    return external_data


def _build_sarif_structure(
    vulnerabilities: List[Dict[str, Any]], 
    scan_code: str, 
    external_data: Dict[str, Dict[str, Any]],
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool,
    enable_dynamic_risk_scoring: bool,
    quiet: bool
) -> Dict[str, Any]:
    """Build the main SARIF structure with notifications and metadata."""
    # Count VEX statements for reporting
    vex_stats = analyze_vex_statements(vulnerabilities)
    
    # Generate notifications for high-risk findings
    notifications = _generate_risk_notifications(vulnerabilities, external_data)
    
    # Build concise run-level summary
    generated_at_utc = datetime.utcnow().isoformat() + "Z"
    vex_counts = _count_vex_assessments(vulnerabilities)
    summary = {
        "workbenchScanCode": scan_code,
        "generated": generated_at_utc,
        "totalFindings": len(vulnerabilities),
        "severityBreakdown": _calculate_severity_distribution(vulnerabilities),
        "withVEX": vex_counts["total_with_vex"],
        "suppressedByVEX": vex_counts["suppressed"]
    }
    
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "FossID Workbench",
                    "version": "1.0.0",
                    "informationUri": "https://fossid.com/products/workbench/",
                    "rules": _generate_enhanced_rules(vulnerabilities, external_data),
                    "notifications": notifications
                }
            },
            "results": _generate_enhanced_results(vulnerabilities, external_data, enable_dynamic_risk_scoring),
            "properties": {
                "workbench_scan_code": scan_code,
                "generated_at": generated_at_utc,
                "total_vulnerabilities": len(vulnerabilities),
                "severity_distribution": _calculate_severity_distribution(vulnerabilities),
                "external_data_sources": _get_data_sources_used(external_data),
                "high_risk_vulnerabilities": count_high_risk_vulnerabilities(vulnerabilities, external_data),
                "vex_statements": vex_stats,
                "summary": summary,
                "nvd_enriched": nvd_enrichment,
                "epss_enriched": epss_enrichment,
                "cisa_kev_enriched": cisa_kev_enrichment,
            }
        }]
    }


def _generate_risk_notifications(vulnerabilities: List[Dict[str, Any]], 
                               external_data: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate notifications for high-risk findings."""
    notifications = []
    
    cisa_kev_count = sum(1 for vuln in vulnerabilities if external_data.get(vuln.get("cve", ""), {}).get("cisa_kev"))
    high_epss_count = sum(1 for vuln in vulnerabilities if (external_data.get(vuln.get("cve", ""), {}).get("epss_score") or 0) > 0.1)
    vex_counts = _count_vex_assessments(vulnerabilities)
    vex_suppressed_count = vex_counts["suppressed"]
    
    if cisa_kev_count > 0:
        notifications.append({
            "level": "error",
            "message": {
                "text": f"⚠️ URGENT: {cisa_kev_count} vulnerabilities are on CISA's Known Exploited Vulnerabilities catalog and require immediate attention"
            },
            "properties": {
                "cisa_kev_count": cisa_kev_count,
                "category": "security",
                "priority": "critical"
            }
        })
    
    if high_epss_count > 0:
        notifications.append({
            "level": "warning", 
            "message": {
                "text": f"🔍 HIGH RISK: {high_epss_count} vulnerabilities have elevated EPSS exploitation probability scores (>0.1)"
            },
            "properties": {
                "high_epss_count": high_epss_count,
                "category": "security",
                "priority": "high"
            }
        })
    
    if vex_suppressed_count > 0:
        notifications.append({
            "level": "note",
            "message": {
                "text": f"✅ VEX ASSESSMENTS: {vex_suppressed_count} vulnerabilities have been assessed and suppressed based on organizational VEX statements"
            },
            "properties": {
                "vex_suppressed_count": vex_suppressed_count,
                "category": "assessment",
                "priority": "info"
            }
        })
    
    return notifications


def save_vulns_to_sarif(
    filepath: str,
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    enable_dynamic_risk_scoring: bool = True,
    api_timeout: int = 30,
    quiet: bool = False,
    all_components: Optional[List[Dict[str, Any]]] = None,
    base_sbom_path: Optional[str] = None
) -> None:
    """
    Save vulnerability results in SARIF format.
    
    Args:
        filepath: Path where the SARIF file should be saved
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was enabled
        epss_enrichment: Whether EPSS enrichment was enabled
        cisa_kev_enrichment: Whether CISA KEV enrichment was enabled
        api_timeout: API timeout used for enrichment
        enable_dynamic_risk_scoring: Whether dynamic risk scoring is enabled
        quiet: Whether to suppress output messages
        all_components: List of all components from scan when --augment-full-bom is used (optional, not used in SARIF)
        base_sbom_path: Path to base SBOM (for consistency, not used in SARIF)
        
    Raises:
        IOError: If the file cannot be written
        OSError: If the directory cannot be created
    """
    output_dir = os.path.dirname(filepath) or "."
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Calculate how many findings would be suppressed by VEX
        original_count = len(vulnerabilities)
        suppressed_count = 0
        if enable_dynamic_risk_scoring:
            suppressed_count = original_count - len(apply_vex_suppression(vulnerabilities))
        
        sarif_data = convert_vulns_to_sarif(
            vulnerabilities, scan_code, external_data,
            nvd_enrichment=nvd_enrichment,
            epss_enrichment=epss_enrichment,
            cisa_kev_enrichment=cisa_kev_enrichment,
            api_timeout=api_timeout,
            enable_dynamic_risk_scoring=enable_dynamic_risk_scoring,
            quiet=quiet
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
            
        # Only print messages if not quiet and external_data wasn't pre-provided
        # (indicating the handler is managing output)
        if not quiet and external_data is None:
            print(f"Saved enhanced SARIF results to: {filepath}")
            
            # Print summary of external data sources used
            props = sarif_data["runs"][0]["properties"]
            if props.get("external_data_sources"):
                print(f"External data sources used: {', '.join(props['external_data_sources'])}")
        
    except (IOError, OSError) as e:
        if not quiet:
            print(f"\nWarning: Failed to save SARIF results to {filepath}: {e}")
        raise


# ---------------------------------------------------------------------------
# VEX Helper Functions
# ---------------------------------------------------------------------------

def get_vex_info(vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract VEX information from vulnerability data."""
    vex_fields = [
        "vuln_exp_id", "vuln_exp_status", "vuln_exp_justification",
        "vuln_exp_response", "vuln_exp_details", "vuln_exp_created",
        "vuln_exp_updated", "vuln_exp_created_by", "vuln_exp_updated_by",
        "vuln_exp_created_by_username", "vuln_exp_updated_by_username"
    ]
    
    vex_info = {}
    has_vex_data = False
    
    for field in vex_fields:
        value = vuln.get(field)
        if value is not None:
            vex_info[field] = value
            has_vex_data = True
    
    return vex_info if has_vex_data else None





def generate_vex_properties(vex_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate VEX-related properties for SARIF output."""
    properties = {}
    
    if vex_info.get("vuln_exp_status"):
        properties["vex_status"] = vex_info["vuln_exp_status"]
    
    if vex_info.get("vuln_exp_justification"):
        properties["vex_justification"] = vex_info["vuln_exp_justification"]
    
    if vex_info.get("vuln_exp_response"):
        properties["vex_response"] = vex_info["vuln_exp_response"]
    
    if vex_info.get("vuln_exp_details"):
        properties["vex_details"] = vex_info["vuln_exp_details"]
    
    if vex_info.get("vuln_exp_created"):
        properties["vex_created"] = vex_info["vuln_exp_created"]
    
    if vex_info.get("vuln_exp_updated"):
        properties["vex_updated"] = vex_info["vuln_exp_updated"]
    
    if vex_info.get("vuln_exp_created_by_username"):
        properties["vex_created_by"] = vex_info["vuln_exp_created_by_username"]
    
    if vex_info.get("vuln_exp_updated_by_username"):
        properties["vex_updated_by"] = vex_info["vuln_exp_updated_by_username"]
    
    return properties


def analyze_vex_statements(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Analyze VEX statements in vulnerability data."""
    vex_stats = {
        "total_with_vex": 0,
        "status_distribution": {},
        "with_justification": 0,
        "with_response": 0,
        "with_details": 0
    }
    
    for vuln in vulnerabilities:
        # Check if vulnerability has VEX information
        has_vex = any([
            vuln.get("vuln_exp_status"),
            vuln.get("vuln_exp_justification"),
            vuln.get("vuln_exp_response"),
            vuln.get("vuln_exp_details")
        ])
        
        if has_vex:
            vex_stats["total_with_vex"] += 1
            
            # Count status distribution
            status = vuln.get("vuln_exp_status")
            if status:
                vex_stats["status_distribution"][status] = vex_stats["status_distribution"].get(status, 0) + 1
            else:
                # Count VEX entries without an explicit status
                vex_stats["status_distribution"]["no status"] = vex_stats["status_distribution"].get("no status", 0) + 1
            
            # Count fields with content
            if vuln.get("vuln_exp_justification"):
                vex_stats["with_justification"] += 1
            if vuln.get("vuln_exp_response"):
                vex_stats["with_response"] += 1
            if vuln.get("vuln_exp_details"):
                vex_stats["with_details"] += 1
    
    return vex_stats


# ---------------------------------------------------------------------------
# Internal Helper Functions
# ---------------------------------------------------------------------------

def _create_empty_sarif_report(scan_code: str) -> Dict[str, Any]:
    """Create an empty SARIF report when no vulnerabilities are found."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "FossID Workbench",
                    "version": "1.0.0",
                    "informationUri": "https://fossid.com/products/workbench/",
                    "rules": []
                }
            },
            "results": [],
            "properties": {
                "workbench_scan_code": scan_code,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_vulnerabilities": 0,
                "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                "external_data_sources": [],
                "high_risk_vulnerabilities": {"cisa_kev": 0, "high_epss": 0, "critical_severity": 0, "total_high_risk": 0}
            }
        }]
    }


def _calculate_severity_distribution(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculate the distribution of vulnerabilities by severity."""
    distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "UNKNOWN").upper()
        if severity in distribution:
            distribution[severity] += 1
        else:
            distribution["UNKNOWN"] += 1
    
    return distribution


def _format_severity_breakdown_compact(severity_dist: Dict[str, int]) -> str:
    """Format severity distribution as compact text for CLI display."""
    breakdown_parts = []
    abbreviations = {'CRITICAL': 'C', 'HIGH': 'H', 'MEDIUM': 'M', 'LOW': 'L', 'UNKNOWN': 'U'}
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        if severity_dist.get(severity, 0) > 0:
            abbrev = abbreviations.get(severity, severity)
            breakdown_parts.append(f"{abbrev}: {severity_dist[severity]}")
    
    return f"[{', '.join(breakdown_parts)}]" if breakdown_parts else ""


# _extract_unique_cves removed - now imported from risk_adjustments
# _count_high_risk_vulnerabilities removed - now imported from risk_adjustments

def _count_vex_assessments(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count various VEX assessment metrics."""
    return {
        "total_with_vex": sum(1 for vuln in vulnerabilities if vuln.get("vuln_exp_id")),
        "with_status": sum(1 for vuln in vulnerabilities if vuln.get("vuln_exp_status")),
        "with_response": sum(1 for vuln in vulnerabilities if vuln.get("vuln_exp_response")),
        "exploitable": sum(1 for vuln in vulnerabilities if vuln.get("vuln_exp_status") == "exploitable"),
        "suppressed": sum(1 for vuln in vulnerabilities if get_vex_info(vuln) and get_vex_info(vuln).get("vuln_exp_status") in ["not_affected", "fixed", "mitigated", "resolved", "false_positive"])
    }


def _get_data_sources_used(external_data: Dict[str, Dict[str, Any]]) -> List[str]:
    """Get list of external data sources that were successfully used."""
    sources = []
    
    for cve_data in external_data.values():
        if cve_data.get("epss_score") is not None and "FIRST EPSS" not in sources:
            sources.append("FIRST EPSS")
        if cve_data.get("cisa_kev") and "CISA KEV" not in sources:
            sources.append("CISA KEV")
        if cve_data.get("nvd_description") and "NVD" not in sources:
            sources.append("NVD")
    
    return sources


# _count_high_risk_vulnerabilities removed - now imported from risk_adjustments


def _map_severity_to_sarif_level(severity: str) -> str:
    """Map Workbench severity levels to SARIF levels - defaults to WARNING for intelligent promotion/demotion."""
    # Default to WARNING - will be intelligently promoted/demoted based on external intelligence
    return "warning"


def map_vex_status_to_sarif_level(vex_status: str, original_level: str, external_data: Dict[str, Any] = None) -> str:
    """
    Map VEX status and external intelligence to appropriate SARIF level.
    
    New intelligent prioritization logic:
    - Default: WARNING (from _map_severity_to_sarif_level)
    - Promote to ERROR if:
      - High EPSS score (>0.1)
      - VEX status is "exploitable" with response "can_not_fix"  
      - CISA KEV vulnerability
    - Demote to NOTE if:
      - VEX status indicates resolved/mitigated/not_affected/false_positive
      - VEX response indicates will_not_fix/update (accepted risk)
    """
    if external_data is None:
        external_data = {}
    
    # Check for promotion to ERROR level
    
    # Promote if high EPSS score
    epss_score = external_data.get("epss_score", 0)
    if epss_score and epss_score > 0.1:
        return "error"
    
    # Promote if CISA KEV
    if external_data.get("cisa_kev"):
        return "error"
    
    # Promote if VEX status indicates exploitable and can't fix
    if vex_status:
        vex_status_lower = vex_status.lower()
        
        # For now, we'll handle the "exploitable + can_not_fix" case
        # This would require also checking the VEX response, but for now we'll focus on the status
        if vex_status_lower in ["exploitable", "affected"]:
            return "error"  # Promote exploitable/affected vulnerabilities
    
    # Check for demotion to NOTE level
    
    if vex_status:
        vex_status_lower = vex_status.lower()
        
        # Demote VEX assessed vulnerabilities that are resolved or mitigated
        if vex_status_lower in ["not_affected", "fixed", "mitigated", "resolved", "false_positive"]:
            return "note"
    
    # Default to WARNING for everything else
    return "warning"


# _build_cvss_vector removed - use build_cvss_vector from cve_data_gathering module


def _extract_version_ranges(references: List[Dict[str, Any]]) -> str:
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


def _generate_enhanced_rules(vulnerabilities: List[Dict[str, Any]], 
                           external_data: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate enhanced SARIF rules from vulnerability data with external enrichment and VEX information."""
    rules = {}
    
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "UNKNOWN")
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        
        # Create unique rule ID combining CVE, component, and version
        rule_id = f"{cve}:{component_name}@{component_version}" if cve != "UNKNOWN" else f"UNKNOWN:{component_name}@{component_version}"
        
        if rule_id not in rules:
            # Get external data and VEX information
            ext_data = external_data.get(cve, {})
            vex_info = get_vex_info(vuln)
            
            # Use intelligent prioritization for default configuration level
            original_level = _map_severity_to_sarif_level(vuln.get("severity", "UNKNOWN"))
            vex_status = vex_info.get("vuln_exp_status") if vex_info else None
            intelligent_level = map_vex_status_to_sarif_level(vex_status, original_level, ext_data)
            
            # Create enhanced descriptions using NVD data
            short_desc = f"{cve} in {component_name}@{component_version} (CVSS {vuln.get('base_score', 'N/A')})"
            if ext_data.get("nvd_cwe"):
                cwe_list = ext_data["nvd_cwe"][:2]  # Show first 2 CWEs to keep it concise
                cwe_text = ", ".join(cwe_list)
                short_desc += f" - {cwe_text}"
            
            # Use NVD description if available, otherwise fall back to generic description
            nvd_desc = ext_data.get("nvd_description")
            if nvd_desc and nvd_desc.strip() and nvd_desc != "No description available":
                full_desc = nvd_desc
            else:
                full_desc = f"Security vulnerability {cve} affecting {component_name} with CVSS score {vuln.get('base_score', 'N/A')}"
            
            # Add component context to NVD description
            if ext_data.get("nvd_description") and ext_data["nvd_description"] != "No description available":
                full_desc += f"\n\nAffected Component: {component_name} version {component_version}"
                
                # Add affected version ranges if we can extract them from references
                version_info = _extract_version_ranges(ext_data.get("nvd_references", []))
                if version_info:
                    full_desc += f"\nKnown Affected Versions: {version_info}"

            rule = {
                "id": rule_id,
                "name": f"{cve} in {component_name}@{component_version}",
                "shortDescription": {
                    "text": short_desc
                },
                "fullDescription": {
                    "text": full_desc
                },
                "defaultConfiguration": {
                    "level": intelligent_level
                },
                "properties": {
                    "security-severity": str(vuln.get("base_score", "0.0")),
                    "cvss_version": vuln.get("cvss_version", "N/A"),
                    "cvss_vector": ext_data.get("full_cvss_vector") or build_cvss_vector(vuln),
                    "base_score": ext_data.get("cvss_score") or vuln.get("base_score", "N/A"),
                    "attack_vector": vuln.get("attack_vector", "N/A"),
                    "attack_complexity": vuln.get("attack_complexity", "N/A"),
                    "availability_impact": vuln.get("availability_impact", "N/A"),
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "component_name": component_name,
                    "tags": ["security", "vulnerability"],
                    "nvd_enriched": bool(ext_data.get("nvd_description"))
                },
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve != "UNKNOWN" else None
            }
            
            # Add external data properties
            if ext_data.get("epss_score") is not None:
                rule["properties"]["epss_score"] = ext_data["epss_score"]
                rule["properties"]["epss_percentile"] = ext_data["epss_percentile"]
            
            if ext_data.get("cisa_kev"):
                rule["properties"]["cisa_known_exploited"] = True
            
            if ext_data.get("nvd_cwe"):
                rule["properties"]["cwe_ids"] = ext_data["nvd_cwe"]
            
            # Add NVD references for additional context
            if ext_data.get("nvd_references"):
                # Include up to 5 most relevant references
                relevant_refs = []
                for ref in ext_data["nvd_references"][:5]:
                    ref_info = {
                        "url": ref.get("url", ""),
                        "source": ref.get("source", "Unknown")
                    }
                    if ref.get("tags"):
                        ref_info["tags"] = ref["tags"]
                    relevant_refs.append(ref_info)
                rule["properties"]["nvd_references"] = relevant_refs
            
            # Add VEX properties
            if vex_info:
                vex_properties = generate_vex_properties(vex_info)
                rule["properties"].update(vex_properties)
            
            rules[rule_id] = rule
    
    return list(rules.values())


def _generate_enhanced_results(vulnerabilities: List[Dict[str, Any]], 
                             external_data: Dict[str, Dict[str, Any]],
                             enable_dynamic_risk_scoring: bool = True) -> List[Dict[str, Any]]:
    """Generate enhanced SARIF results with external data and VEX information."""
    results = []
    
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "UNKNOWN")
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        severity = vuln.get("severity", "UNKNOWN")
        base_score = vuln.get("base_score", "N/A")
        
        # Get external data and VEX info
        ext_data = external_data.get(cve, {})
        vex_info = get_vex_info(vuln)
        
        # Calculate dynamic risk adjustment (if enabled)
        dynamic_risk_adjustment = None
        if enable_dynamic_risk_scoring:
            dynamic_risk_adjustment = calculate_dynamic_risk(vuln, ext_data)
        
        # Create enhanced package URL with ecosystem detection
        ecosystem = detect_package_ecosystem(component_name, component_version, ext_data.get("purl"))
        artifact_uri = f"pkg:{ecosystem}/{component_name}@{component_version}"
        
        # Create unique rule ID combining CVE, component, and version
        rule_id = f"{cve}:{component_name}@{component_version}" if cve != "UNKNOWN" else f"UNKNOWN:{component_name}@{component_version}"
        
        # Map severity to SARIF level with VEX consideration
        original_level = _map_severity_to_sarif_level(severity)
        vex_status = vex_info.get("vuln_exp_status") if vex_info else None
        final_level = map_vex_status_to_sarif_level(vex_status, original_level, ext_data)
        
        # Determine prioritization context based on promotion/demotion logic
        priority_context = ""
        
        # Check if promoted to ERROR by external intelligence
        if final_level == "error" and original_level == "warning":
            # Check promotion reasons in order of priority
            if ext_data.get("cisa_kev"):
                priority_context = "[CISA KEV] "
            elif (ext_data.get("epss_score") or 0) > 0.1:
                priority_context = f"[EPSS: {ext_data['epss_score']:.3f}] "
            elif vex_status and vex_status.lower() in ["exploitable", "affected"]:
                priority_context = f"[VEX: {vex_status.upper()}] "
        
        # Check if demoted to NOTE by VEX
        elif final_level == "note" and original_level == "warning":
            if vex_status:
                priority_context = f"[VEX: {vex_status.upper()}] "
        
        # Create clean message without component details (since grouped by component)
        message_text = f"{priority_context}[CVSS: {base_score}] {cve}"
        
        
        result = {
            "ruleId": rule_id,
            "level": final_level,
            "message": {
                "text": message_text
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                        "description": {
                            "text": f"Vulnerable component: {component_name} version {component_version}"
                        }
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "snippet": {
                            "text": f"{component_name}@{component_version}"
                        }
                    }
                },
                "logicalLocations": [{
                    "name": component_name,
                    "fullyQualifiedName": artifact_uri,
                    "kind": "package"
                }]
            }],
            "properties": {
                "vulnerability_id": vuln.get("id"),
                "cvss_version": vuln.get("cvss_version"),
                "security-severity": str(base_score),  # SARIF standard property for security findings
                "attack_vector": vuln.get("attack_vector"),
                "attack_complexity": vuln.get("attack_complexity"),
                "availability_impact": vuln.get("availability_impact"),
                "component_id": vuln.get("component_id"),
                "component_name": component_name,
                "component_version": component_version,
                "ecosystem": ecosystem,
                "package_url": artifact_uri,
                "baselineState": "unchanged",
                "tags": {
                    "vulnerability": [cve],
                    "component": [f"{component_name}@{component_version}"],
                    "severity": [severity.lower() if severity != "UNKNOWN" else "unknown"]
                }
            }
        }
        
        # Add external data properties
        if ext_data.get("epss_score") is not None:
            result["properties"]["epss_score"] = ext_data["epss_score"]
            result["properties"]["epss_percentile"] = ext_data["epss_percentile"]
        
        if ext_data.get("cisa_kev"):
            result["properties"]["cisa_known_exploited"] = True
        
        if ext_data.get("nvd_cwe"):
            result["properties"]["cwe_ids"] = ext_data["nvd_cwe"]
        
        if ext_data.get("nvd_description"):
            result["properties"]["nvd_description"] = ext_data["nvd_description"]
        
        if ext_data.get("full_cvss_vector"):
            result["properties"]["full_cvss_vector"] = ext_data["full_cvss_vector"]
        
        if ext_data.get("nvd_references"):
            # Store key references for analysis tools
            result["properties"]["nvd_reference_count"] = len(ext_data["nvd_references"])
            result["properties"]["nvd_vendor_advisories"] = len([
                ref for ref in ext_data["nvd_references"] 
                if "vendor advisory" in [tag.lower() for tag in ref.get("tags", [])]
            ])
        
        # Add VEX properties
        if vex_info:
            vex_properties = generate_vex_properties(vex_info)
            result["properties"].update(vex_properties)
        
        # Add High Risk Indicator properties (NEW)
        if dynamic_risk_adjustment:
            result["properties"]["high_risk_indicator"] = dynamic_risk_adjustment.high_risk_indicator
            result["properties"]["high_risk_evidence"] = dynamic_risk_adjustment.high_risk_evidence
        
        # Add fingerprints for deduplication
        wid = str(vuln.get("id", "unknown"))
        result["fingerprints"] = {
            "workbench/component": f"{component_name}@{component_version}",
            "workbench/vulnerability": f"{cve}#{wid}",
            "workbench/id": wid,
            "primary": f"{wid}",
            "stable": f"{cve}"
        }
        
        # Add suppression information if VEX status indicates resolved/mitigated
        if vex_info and vex_info.get("vuln_exp_status"):
            vex_status = vex_info["vuln_exp_status"].lower()
            if vex_status in ["not_affected", "fixed", "mitigated", "accepted_risk", "false_positive", "resolved"]:
                result["suppressions"] = [{
                    "kind": "externalTriage",
                    "status": "accepted",
                    "justification": vex_info.get("vuln_exp_justification", f"VEX status: {vex_status}")
                }]
        
        results.append(result)
    
    return results 