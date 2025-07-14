"""
SARIF 2.1.0 vulnerability report generation.

This module provides functionality to convert vulnerability data from the Workbench API
into SARIF (Static Analysis Results Interchange Format) v2.1.0 format, optimized for
GitHub Advanced Security and other security tools.

The module supports generation-only workflow - building SARIF from vulnerability data.
SARIF does not support augmentation workflows like SBOM formats.

Enhanced with comprehensive VEX support, risk notifications, and dynamic prioritization
for maximum utility in security operations workflows.
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Import shared utilities for enrichment pipeline
from .bootstrap_bom import detect_package_ecosystem
from .cve_data_gathering import enrich_vulnerabilities, build_cvss_vector, extract_version_ranges
from .risk_adjustments import (
    calculate_dynamic_risk, 
    RiskAdjustment, 
    extract_unique_cves,
    risk_level_to_sarif_level,
    count_high_risk_vulnerabilities
)


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
    quiet: bool = False
) -> None:
    """
    Save vulnerability results in SARIF 2.1.0 format, optimized for GitHub Advanced Security.
    
    Args:
        filepath: Path where the SARIF file should be saved
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was applied
        epss_enrichment: Whether EPSS enrichment was applied
        cisa_kev_enrichment: Whether CISA KEV enrichment was applied
        enable_dynamic_risk_scoring: Whether dynamic risk scoring is enabled (includes VEX assessments)
        api_timeout: API timeout used for enrichment
        quiet: Whether to suppress output messages

        
    Raises:
        IOError: If the file cannot be written
        OSError: If the directory cannot be created
    """
    output_dir = os.path.dirname(filepath) or "."
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Fetch external enrichment data if not provided
        if external_data is None:
            external_data = _fetch_external_enrichment_data(
                vulnerabilities, 
                nvd_enrichment, 
                epss_enrichment, 
                cisa_kev_enrichment,
                api_timeout
            )
        
        # Generate SARIF document
        sarif_document = convert_vulns_to_sarif(
            vulnerabilities,
            scan_code,
            external_data,
            nvd_enrichment,
            epss_enrichment,
            cisa_kev_enrichment,
            enable_dynamic_risk_scoring
        )
        
        # Write SARIF file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sarif_document, f, indent=2, ensure_ascii=False)
        
        if not quiet:
            print(f"   • SARIF report saved to: {filepath}")
        
    except (IOError, OSError) as e:
        if not quiet:
            print(f"\nWarning: Failed to save SARIF results to {filepath}: {e}")
        raise


def convert_vulns_to_sarif(
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    enable_dynamic_risk_scoring: bool = True
) -> Dict[str, Any]:
    """
    Convert vulnerability results to SARIF 2.1.0 format, optimized for GitHub Advanced Security.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: External enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was applied
        epss_enrichment: Whether EPSS enrichment was applied
        cisa_kev_enrichment: Whether CISA KEV enrichment was applied
        enable_dynamic_risk_scoring: Whether dynamic risk scoring is enabled (includes VEX assessments)
        
    Returns:
        SARIF document as dictionary
    """
    if external_data is None:
        external_data = {}
    
    # Create SARIF document structure
    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            _create_sarif_run(
                vulnerabilities,
                scan_code,
                external_data,
                nvd_enrichment,
                epss_enrichment,
                cisa_kev_enrichment,
                enable_dynamic_risk_scoring            )
        ]
    }
    
    return sarif_doc


def _fetch_external_enrichment_data(
    vulnerabilities: List[Dict[str, Any]], 
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool,
    api_timeout: int
) -> Dict[str, Dict[str, Any]]:
    """Fetch external enrichment data for vulnerabilities using existing utilities."""
    if not any([nvd_enrichment, epss_enrichment, cisa_kev_enrichment]):
        return {}
    
    # Use existing CVE extraction logic
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



def _create_sarif_run(
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Dict[str, Dict[str, Any]],
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool,
    enable_dynamic_risk_scoring: bool
) -> Dict[str, Any]:
    """Create a SARIF run object optimized for GitHub Advanced Security."""
    
    # Generate notifications for high-risk findings (includes VEX suppression summary)
    notifications = _generate_risk_notifications(vulnerabilities, external_data)
    
    # Generate rules and results
    rules = _generate_enhanced_sarif_rules(vulnerabilities, external_data, enable_dynamic_risk_scoring)
    results = _generate_enhanced_sarif_results(vulnerabilities, external_data, enable_dynamic_risk_scoring)
    
    # Create run object with GitHub Advanced Security optimizations
    run = {
        "tool": {
            "driver": {
                "name": "FossID Workbench",
                "version": "1.0.0",
                "informationUri": "https://fossid.com/products/workbench/",
                "rules": rules,
                "notifications": notifications
            }
        },
        "results": results,
                    "properties": _create_run_properties(
                scan_code,
                vulnerabilities,
                external_data,
                nvd_enrichment,
                epss_enrichment,
                cisa_kev_enrichment
            )
    }
    
    return run


def _generate_risk_notifications(
    vulnerabilities: List[Dict[str, Any]], 
    external_data: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Generate notifications for high-risk findings."""
    notifications = []
    
    cisa_kev_count = sum(1 for vuln in vulnerabilities 
                        if external_data.get(vuln.get("vuln_id") or vuln.get("cve", ""), {}).get("cisa_kev"))
    high_epss_count = sum(1 for vuln in vulnerabilities 
                         if (external_data.get(vuln.get("vuln_id") or vuln.get("cve", ""), {}).get("epss_score") or 0) > 0.1)
    
    # Count VEX suppressed vulnerabilities using dynamic risk scoring
    vex_suppressed_count = 0
    for vuln in vulnerabilities:
        cve = vuln.get("vuln_id") or vuln.get("cve", "UNKNOWN")
        ext_data = external_data.get(cve, {})
        try:
            risk_adjustment = calculate_dynamic_risk(vuln, ext_data)
            if risk_adjustment.high_risk_indicator == "No":
                vex_suppressed_count += 1
        except Exception:
            continue
    
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





def generate_vex_properties(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Generate VEX-related properties for SARIF output."""
    properties = {}
    
    if vuln.get("vuln_exp_status"):
        properties["vex_status"] = vuln["vuln_exp_status"]
    
    if vuln.get("vuln_exp_justification"):
        properties["vex_justification"] = vuln["vuln_exp_justification"]
    
    if vuln.get("vuln_exp_response"):
        properties["vex_response"] = vuln["vuln_exp_response"]
    
    if vuln.get("vuln_exp_details"):
        properties["vex_details"] = vuln["vuln_exp_details"]
    
    if vuln.get("vuln_exp_created"):
        properties["vex_created"] = vuln["vuln_exp_created"]
    
    if vuln.get("vuln_exp_updated"):
        properties["vex_updated"] = vuln["vuln_exp_updated"]
    
    if vuln.get("vuln_exp_created_by_username"):
        properties["vex_created_by"] = vuln["vuln_exp_created_by_username"]
    
    if vuln.get("vuln_exp_updated_by_username"):
        properties["vex_updated_by"] = vuln["vuln_exp_updated_by_username"]
    
    return properties





def _generate_enhanced_sarif_rules(
    vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]],
    enable_dynamic_risk_scoring: bool
) -> List[Dict[str, Any]]:
    """Generate enhanced SARIF rules with rich NVD data and VEX information."""
    rules = {}
    
    for vuln in vulnerabilities:
        cve_id = vuln.get("vuln_id") or vuln.get("cve", "UNKNOWN")
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        
        # Skip only if we have absolutely no identifying information
        if not cve_id and not component_name:
            continue
            
        # Create component-specific rule ID for better tracking
        rule_id = f"{cve_id}:{component_name}@{component_version}"
        
        if rule_id in rules:
            continue
        
        # Get external enrichment data
        ext_data = external_data.get(cve_id, {})
        
        # Calculate dynamic risk if enabled
        dynamic_risk_adjustment = None
        if enable_dynamic_risk_scoring:
            dynamic_risk_adjustment = calculate_dynamic_risk(vuln, ext_data)
        
        # Create enhanced descriptions using NVD data
        short_desc = f"{cve_id} in {component_name}@{component_version} (CVSS {vuln.get('base_score', 'N/A')})"
        if ext_data.get("nvd_cwe"):
            cwe_list = ext_data["nvd_cwe"][:2]  # Show first 2 CWEs to keep it concise
            cwe_text = ", ".join(cwe_list)
            short_desc += f" - {cwe_text}"
        
        # Use NVD description if available, otherwise fall back to generic description
        nvd_desc = ext_data.get("nvd_description")
        if nvd_desc and nvd_desc.strip() and nvd_desc != "No description available":
            full_desc = nvd_desc
        else:
            full_desc = f"Security vulnerability {cve_id} affecting {component_name} with CVSS score {vuln.get('base_score', 'N/A')}"
        
        # Add component context to NVD description
        if ext_data.get("nvd_description") and ext_data["nvd_description"] != "No description available":
            full_desc += f"\n\nAffected Component: {component_name} version {component_version}"
            
            # Add affected version ranges if we can extract them from references
            version_info = extract_version_ranges(ext_data.get("nvd_references", []))
            if version_info:
                full_desc += f"\nKnown Affected Versions: {version_info}"

        rule = {
            "id": rule_id,
            "name": f"{cve_id} in {component_name}@{component_version}",
            "shortDescription": {
                "text": short_desc
            },
            "fullDescription": {
                "text": full_desc
            },
            "defaultConfiguration": {
                "level": _determine_rule_level(vuln, ext_data, dynamic_risk_adjustment)
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
                "cve": cve_id,
                "component": f"{component_name}@{component_version}",
                "ecosystem": detect_package_ecosystem(component_name, component_version),
                "tags": ["security", "vulnerability"],
                "nvd_enriched": bool(ext_data.get("nvd_description"))
            },
            "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != "UNKNOWN" else None
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
        
        # Add VEX properties if available
        if any(field in vuln for field in ["vuln_exp_status", "vuln_exp_justification", "vuln_exp_response", "vuln_exp_details"]):
            vex_properties = generate_vex_properties(vuln)
            rule["properties"].update(vex_properties)
        
        rules[rule_id] = rule
    
    return list(rules.values())


def _determine_rule_level(
    vuln: Dict[str, Any], 
    ext_data: Dict[str, Any], 
    dynamic_risk_adjustment: Optional[RiskAdjustment]
) -> str:
    """Determine the SARIF level for a rule using dynamic risk scoring."""
    if dynamic_risk_adjustment:
        return risk_level_to_sarif_level(dynamic_risk_adjustment.adjusted_level)
    else:
        return _map_severity_to_sarif_level(vuln.get("severity", "medium"), vuln, ext_data)


def _generate_enhanced_sarif_results(
    vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]],
    enable_dynamic_risk_scoring: bool
) -> List[Dict[str, Any]]:
    """Generate enhanced SARIF results with priority context and comprehensive metadata."""
    results = []
    
    for vuln in vulnerabilities:
        cve_id = vuln.get("vuln_id") or vuln.get("cve", "UNKNOWN")
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        severity = vuln.get("severity", "UNKNOWN")
        base_score = vuln.get("base_score", "N/A")
        
        # Skip only if we have absolutely no identifying information
        if not cve_id and not component_name:
            continue
        
        # Get external data
        ext_data = external_data.get(cve_id, {})
        
        # Calculate dynamic risk if enabled
        dynamic_risk_adjustment = None
        if enable_dynamic_risk_scoring:
            dynamic_risk_adjustment = calculate_dynamic_risk(vuln, ext_data)
        
        # Determine prioritization context based on dynamic risk adjustment
        priority_context = _create_priority_context(vuln, ext_data, dynamic_risk_adjustment)
        
        # Create enhanced package URL with ecosystem detection
        ecosystem = detect_package_ecosystem(component_name, component_version)
        artifact_uri = f"pkg:{ecosystem}/{component_name}@{component_version}"
        
        # Create message with priority context
        message_text = f"{priority_context}[CVSS: {base_score}] {cve_id}"
        
        result = {
            "ruleId": f"{cve_id}:{component_name}@{component_version}",
            "message": {
                "text": message_text
            },
            "level": _determine_result_level(vuln, ext_data, dynamic_risk_adjustment),
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
            "partialFingerprints": _create_enhanced_partial_fingerprints(vuln, component_name, component_version),
            "baselineState": _determine_baseline_state(vuln, dynamic_risk_adjustment),
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
                "cve": cve_id,
                "component": f"{component_name}@{component_version}",
                "severity": severity,
                "baselineState": "unchanged",
                "tags": {
                    "vulnerability": [cve_id],
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
        
        # Add VEX properties if available
        if any(field in vuln for field in ["vuln_exp_status", "vuln_exp_justification", "vuln_exp_response", "vuln_exp_details"]):
            vex_properties = generate_vex_properties(vuln)
            result["properties"].update(vex_properties)
        
        # Add comprehensive fingerprints for deduplication
        wid = str(vuln.get("id", "unknown"))
        result["fingerprints"] = {
            "workbench/component": f"{component_name}@{component_version}",
            "workbench/vulnerability": f"{cve_id}#{wid}",
            "workbench/id": wid,
            "primary": wid,
            "stable": cve_id
        }
        
        # Add remediation guidance if available
        if vuln.get("fix_version"):
            result["fixes"] = [{
                "description": {
                    "text": f"Update {component_name} to version {vuln['fix_version']} or later"
                },
                "artifactChanges": [{
                    "artifactLocation": {
                        "uri": f"{component_name}:{component_version}"
                    },
                    "replacements": [{
                        "deletedRegion": {
                            "startLine": 1,
                            "startColumn": 1,
                            "endLine": 1,
                            "endColumn": 1
                        },
                        "insertedContent": {
                            "text": f"{component_name}:{vuln['fix_version']}"
                        }
                    }]
                }]
            }]
        
        # Add suppression information based on dynamic risk adjustment
        if dynamic_risk_adjustment and dynamic_risk_adjustment.high_risk_indicator == "No":
            # This vulnerability has been assessed as low risk - add suppression info
            result["suppressions"] = [{
                "kind": "externalTriage",
                "status": "accepted",
                "justification": dynamic_risk_adjustment.high_risk_evidence or "Assessed as low risk through dynamic risk scoring"
            }]
        
        results.append(result)
    
    return results


def _create_priority_context(
    vuln: Dict[str, Any], 
    ext_data: Dict[str, Any], 
    dynamic_risk_adjustment: Optional[RiskAdjustment]
) -> str:
    """Determine prioritization context based on dynamic risk adjustment."""
    priority_context = ""
    
    if dynamic_risk_adjustment and dynamic_risk_adjustment.high_risk_indicator == "Yes":
        # Check promotion reasons in order of priority
        if ext_data.get("cisa_kev"):
            priority_context = "[CISA KEV] "
        elif (ext_data.get("epss_score") or 0) > 0.1:
            priority_context = f"[EPSS: {ext_data['epss_score']:.3f}] "
        elif vuln.get("vuln_exp_status") and vuln.get("vuln_exp_status").lower() in ["exploitable", "affected"]:
            priority_context = f"[VEX: {vuln['vuln_exp_status'].upper()}] "
    elif dynamic_risk_adjustment and dynamic_risk_adjustment.high_risk_indicator == "No":
        # Check demotion reasons
        vex_status = vuln.get("vuln_exp_status")
        if vex_status:
            priority_context = f"[VEX: {vex_status.upper()}] "
    
    return priority_context


def _determine_result_level(
    vuln: Dict[str, Any], 
    ext_data: Dict[str, Any], 
    dynamic_risk_adjustment: Optional[RiskAdjustment]
) -> str:
    """Determine the SARIF level for a result using dynamic risk scoring."""
    if dynamic_risk_adjustment:
        return risk_level_to_sarif_level(dynamic_risk_adjustment.adjusted_level)
    else:
        return _map_severity_to_sarif_level(vuln.get("severity", "medium"), vuln, ext_data)


def _create_enhanced_partial_fingerprints(vuln: Dict[str, Any], component_name: str, component_version: str) -> Dict[str, str]:
    """Create comprehensive partial fingerprints for deduplication."""
    cve_id = vuln.get("vuln_id") or vuln.get("cve", "")
    
    return {
        "workbenchScan": f"{cve_id}:{component_name}@{component_version}",
        "primaryLocationHash": f"{component_name}:{component_version}",
        "cveComponent": f"{cve_id}:{component_name}",
        "vulnerability": cve_id,
        "component": f"{component_name}@{component_version}"
    }


def _determine_baseline_state(vuln: Dict[str, Any], dynamic_risk_adjustment: Optional[RiskAdjustment]) -> str:
    """Determine the baseline state for GitHub Advanced Security using dynamic risk assessment."""
    # Use dynamic risk assessment to determine baseline state
    if dynamic_risk_adjustment and dynamic_risk_adjustment.high_risk_indicator == "No":
        return "reviewed"  # Assessed as low risk
    elif vuln.get("vuln_exp_status") == "not_affected":
        return "absent"
    elif vuln.get("vuln_exp_status") == "fixed":
        return "absent"
    elif vuln.get("vuln_exp_response"):
        return "reviewed"
    else:
        return "new"





def _create_run_properties(
    scan_code: str,
    vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]],
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool
) -> Dict[str, Any]:
    """Create run properties optimized for GitHub Advanced Security."""
    
    # Basic scan metadata
    properties = {
        "scanCode": scan_code,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "vulnerabilityCount": len(vulnerabilities),
        "componentCount": len(set(
            f"{v.get('component_name')}@{v.get('component_version')}" 
            for v in vulnerabilities 
            if v.get('component_name') and v.get('component_version')
        ))
    }
    
    # Severity distribution
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = (vuln.get("severity") or "medium").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    properties["severityDistribution"] = severity_counts
    
    # Enrichment sources
    enrichment_sources = []
    if nvd_enrichment:
        enrichment_sources.append("NVD")
    if epss_enrichment:
        enrichment_sources.append("EPSS")
    if cisa_kev_enrichment:
        enrichment_sources.append("CISA KEV")
    
    if enrichment_sources:
        properties["enrichmentSources"] = enrichment_sources
    
    # High risk indicators
    high_risk_counts = count_high_risk_vulnerabilities(vulnerabilities, external_data)
    if high_risk_counts.get("total_high_risk", 0) > 0:
        properties["highRiskVulnerabilities"] = high_risk_counts["total_high_risk"]
    
    # VEX statistics
    vex_stats = _calculate_vex_statistics(vulnerabilities)
    if any(vex_stats.values()):
        properties["vexStatistics"] = vex_stats
    
    return properties


def _calculate_vex_statistics(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculate VEX statistics for the run properties."""
    vex_stats = {
        "total_with_vex": 0,
        "not_affected": 0,
        "affected": 0,
        "fixed": 0,
        "under_investigation": 0,
        "with_response": 0
    }
    
    for vuln in vulnerabilities:
        if vuln.get("vuln_exp_id") or vuln.get("vuln_exp_status") or vuln.get("vuln_exp_response"):
            vex_stats["total_with_vex"] += 1
        
        status = vuln.get("vuln_exp_status") or ""
        if status and status.lower() in vex_stats:
            vex_stats[status.lower()] += 1
        
        if vuln.get("vuln_exp_response"):
            vex_stats["with_response"] += 1
    
    return vex_stats


def _map_severity_to_sarif_level(severity: str, vuln: Dict[str, Any] = None, ext_data: Dict[str, Any] = None) -> str:
    """Map vulnerability severity to SARIF level optimized for GitHub Advanced Security."""
    if not severity:
        return "warning"
    
    severity_lower = severity.lower()
    
    # Check for high-risk indicators that should escalate the level
    if ext_data and ext_data.get("cisa_kev"):
        return "error"
    
    if ext_data and ext_data.get("epss_score") and float(ext_data["epss_score"]) > 0.7:
        return "error"
    
    # Standard severity mapping
    if severity_lower in ["critical", "high"]:
        return "error"
    elif severity_lower in ["medium", "moderate"]:
        return "warning"
    elif severity_lower in ["low", "informational", "info"]:
        return "note"
    else:
        return "warning"


# Export public API
__all__ = [
    "save_vulns_to_sarif",
    "convert_vulns_to_sarif",
    "generate_vex_properties"
] 