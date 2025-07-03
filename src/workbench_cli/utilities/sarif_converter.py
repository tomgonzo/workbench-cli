"""
SARIF conversion utilities for vulnerability data.

This module provides functionality to convert vulnerability data from the Workbench API
into SARIF (Static Analysis Results Interchange Format) v2.1.0 format, which is
compatible with GitHub Advanced Security and other security tools.

Enhanced with external API integration for EPSS scores, known exploits, CVE details,
and VEX (Vulnerability Exploitability eXchange) information.
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

from .vulnerability_enricher import enrich_vulnerabilities

logger = logging.getLogger(__name__)


def _apply_vex_suppression(vulnerabilities: List[Dict[str, Any]], 
                          suppress_vex_mitigated: bool = True,
                          suppress_accepted_risk: bool = True,
                          suppress_false_positives: bool = True) -> List[Dict[str, Any]]:
    """
    Apply VEX-based suppression to vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        suppress_vex_mitigated: Whether to suppress findings with VEX mitigation status
        suppress_accepted_risk: Whether to suppress findings marked as accepted risk
        suppress_false_positives: Whether to suppress findings marked as false positives
        
    Returns:
        Filtered list of vulnerabilities after applying suppression rules
    """
    filtered_vulns = []
    
    for vuln in vulnerabilities:
        should_suppress = False
        
        # Check VEX status for suppression
        vex_status = (vuln.get("vuln_exp_status") or "").lower()
        vex_justification = (vuln.get("vuln_exp_justification") or "").lower()
        vex_response = (vuln.get("vuln_exp_response") or "").lower()
        
        # Suppress VEX mitigated findings
        if suppress_vex_mitigated and vex_status in ["not_affected", "resolved"]:
            should_suppress = True
        
        # Suppress accepted risk findings
        if suppress_accepted_risk and vex_response in ["will_not_fix", "update", "can_not_fix"]:
            should_suppress = True
        
        # Suppress false positives
        if suppress_false_positives and vex_status == "false_positive":
            should_suppress = True
        
        if not should_suppress:
            filtered_vulns.append(vuln)
    
    return filtered_vulns


def convert_vulns_to_sarif(vulnerabilities: List[Dict[str, Any]], scan_code: str, 
                          include_cve_descriptions: bool = True,
                          include_epss_scores: bool = True,
                          include_exploit_info: bool = True,
                          api_timeout: int = 30,
                          include_vex: bool = True,
                          include_scan_metadata: bool = True,
                          group_by_component: bool = True) -> Dict[str, Any]:
    """
    Convert vulnerability data to SARIF v2.1.0 format with external enrichment and VEX information.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries from the Workbench API
        scan_code: The scan code for reference
        include_cve_descriptions: Whether to fetch CVE descriptions from NVD
        include_epss_scores: Whether to fetch EPSS scores from FIRST
        include_exploit_info: Whether to fetch known exploit information
        api_timeout: Timeout for external API calls in seconds
        
    Returns:
        Dict containing SARIF-formatted data compatible with GitHub Advanced Security,
        enhanced with VEX (Vulnerability Exploitability eXchange) information
    """
    if not vulnerabilities:
        return _create_empty_sarif_report(scan_code)
    
    # Extract unique CVEs for batch processing
    unique_cves = list(set(vuln.get("cve", "UNKNOWN") for vuln in vulnerabilities if vuln.get("cve") != "UNKNOWN"))
    
    # Fetch external data using the enricher module
    external_data = {}
    if unique_cves:
        try:
            external_data = enrich_vulnerabilities(
                unique_cves, 
                include_cve_descriptions, 
                include_epss_scores, 
                include_exploit_info,
                api_timeout
            )
        except Exception as e:
            logger.warning(f"Failed to fetch external vulnerability data: {e}")
    
    # Count VEX statements for reporting
    vex_stats = _analyze_vex_statements(vulnerabilities)
    
    # Generate notifications for high-risk findings
    notifications = []
    cisa_kev_count = sum(1 for vuln in vulnerabilities if external_data.get(vuln.get("cve", ""), {}).get("cisa_kev"))
    high_epss_count = sum(1 for vuln in vulnerabilities if (external_data.get(vuln.get("cve", ""), {}).get("epss_score") or 0) > 0.1)
    vex_suppressed_count = sum(1 for vuln in vulnerabilities if _get_vex_info(vuln) and _get_vex_info(vuln).get("vuln_exp_status") in ["not_affected", "fixed", "mitigated", "resolved", "false_positive"])
    
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
            "results": _generate_enhanced_results(vulnerabilities, external_data),
            "properties": {
                "scan_code": scan_code,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_vulnerabilities": len(vulnerabilities),
                "severity_distribution": _calculate_severity_distribution(vulnerabilities),
                "external_data_sources": _get_data_sources_used(external_data),
                "high_risk_vulnerabilities": _count_high_risk_vulnerabilities(vulnerabilities, external_data),
                "vex_statements": vex_stats
            }
        }]
    }


def _generate_enhanced_rules(vulnerabilities: List[Dict[str, Any]], 
                           external_data: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generate enhanced SARIF rules from vulnerability data with external enrichment and VEX information.
    """
    rules = {}
    
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "UNKNOWN")
        if cve not in rules:
            # Get external data for this CVE
            ext_data = external_data.get(cve, {})
            
            # Get VEX information for this vulnerability
            vex_info = _get_vex_info(vuln)
            
            # Build enhanced CVSS vector
            cvss_vector = ext_data.get("full_cvss_vector") or _build_cvss_vector(vuln)
            
            # Enhanced rule with external data and VEX information
            rule = {
                "id": cve,
                "name": f"Vulnerability {cve}",
                "shortDescription": {
                    "text": _generate_enhanced_short_description(cve, vuln, ext_data, vex_info)
                },
                "fullDescription": {
                    "text": _generate_enhanced_full_description(cve, vuln, ext_data, vex_info)
                },
                "defaultConfiguration": {
                    "level": _map_severity_to_sarif_level(vuln.get("severity", "UNKNOWN"))
                },
                "properties": {
                    "security-severity": str(vuln.get("base_score", "0.0")),
                    "cvss_version": vuln.get("cvss_version", "N/A"),
                    "cvss_vector": cvss_vector,
                    "base_score": vuln.get("base_score", "N/A"),
                    "attack_vector": vuln.get("attack_vector", "N/A"),
                    "attack_complexity": vuln.get("attack_complexity", "N/A"),
                    "availability_impact": vuln.get("availability_impact", "N/A"),
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "tags": _generate_enhanced_vulnerability_tags(vuln, ext_data, vex_info)
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
            
            # Add VEX properties
            if vex_info:
                vex_properties = _generate_vex_properties(vex_info)
                rule["properties"].update(vex_properties)
            
            # Enhanced help text
            rule["help"] = {
                "text": _generate_enhanced_help_text(cve, vuln, ext_data, vex_info),
                "markdown": _generate_enhanced_help_markdown(cve, vuln, ext_data, vex_info)
            }
            
            rules[cve] = rule
    
    return list(rules.values())


def _generate_enhanced_short_description(cve: str, vuln: Dict[str, Any], ext_data: Dict[str, Any], vex_info: Optional[Dict[str, Any]] = None) -> str:
    """Generate enhanced short description with risk indicators and VEX status."""
    base_desc = f"Security vulnerability {cve} (CVSS {vuln.get('base_score', 'N/A')})"
    
    risk_indicators = []
    if ext_data.get("cisa_kev"):
        risk_indicators.append("CISA KEV")
    epss_score = ext_data.get("epss_score")
    if epss_score is not None and epss_score > 0.1:  # High EPSS score
        risk_indicators.append(f"EPSS: {epss_score:.3f}")
    
    # Add VEX status indicator
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"]
        risk_indicators.append(f"VEX: {vex_status}")
    
    if risk_indicators:
        base_desc += f" [{', '.join(risk_indicators)}]"
    
    return base_desc


def _generate_enhanced_full_description(cve: str, vuln: Dict[str, Any], ext_data: Dict[str, Any], vex_info: Optional[Dict[str, Any]] = None) -> str:
    """Generate comprehensive description with external data and VEX information."""
    # Start with NVD description if available, adding a blank line afterwards for clarity
    if ext_data.get("nvd_description"):
        base_desc = ext_data["nvd_description"].rstrip()
        separator = "\n\n"  # Paragraph break after canonical description
    else:
        base_desc = f"Security vulnerability {cve} with CVSS score {vuln.get('base_score', 'N/A')}"
        separator = " "  # Continue in same paragraph if no NVD text
    
    # Add risk context
    severity = vuln.get("severity", "UNKNOWN")
    attack_vector = vuln.get("attack_vector", "")
    attack_complexity = vuln.get("attack_complexity", "")
    
    if attack_vector and attack_complexity:
        base_desc += f"{separator}This is a {severity.lower()} severity vulnerability with {attack_vector.lower()} attack vector and {attack_complexity.lower()} attack complexity."
    
    # Add exploit information
    if ext_data.get("cisa_kev"):
        base_desc += " This vulnerability is listed in CISA's Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild."
    
    epss_score = ext_data.get("epss_score")
    if epss_score is not None and epss_score > 0.1:
        base_desc += f" EPSS score of {epss_score:.3f} indicates elevated risk of exploitation."
    
    # Add CWE information
    if ext_data.get("nvd_cwe"):
        cwe_list = ", ".join(ext_data["nvd_cwe"])
        base_desc += f" Associated with {cwe_list}."
    
    # Add VEX information
    if vex_info:
        vex_status = vex_info.get("vuln_exp_status")
        if vex_status:
            base_desc += f" VEX Status: {vex_status}"
            
            # Add VEX justification if available
            if vex_info.get("vuln_exp_justification"):
                base_desc += f" - {vex_info['vuln_exp_justification']}"
            
            # Add VEX response if available  
            if vex_info.get("vuln_exp_response"):
                base_desc += f" Response: {vex_info['vuln_exp_response']}"
    
    return base_desc


def _generate_enhanced_help_markdown(cve: str, vuln: Dict[str, Any], ext_data: Dict[str, Any], vex_info: Optional[Dict[str, Any]] = None) -> str:
    """Generate enhanced help text in Markdown format with external data and VEX information."""
    component = vuln.get("component_name", "Unknown")
    version = vuln.get("component_version", "Unknown")
    severity = vuln.get("severity", "UNKNOWN")
    score = vuln.get("base_score", "N/A")
    
    # Risk assessment with VEX consideration
    risk_level = "Standard"
    epss_score = ext_data.get("epss_score")
    if ext_data.get("cisa_kev") or (epss_score is not None and epss_score > 0.1):
        risk_level = "**HIGH RISK**"
    
    # Adjust risk level based on VEX status
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        if vex_status in ["not_affected", "fixed", "mitigated", "resolved"]:
            risk_level = "**MITIGATED**"
        elif vex_status in ["accepted_risk"]:
            risk_level = "**ACCEPTED RISK**"
        elif vex_status in ["false_positive"]:
            risk_level = "**FALSE POSITIVE**"
    
    markdown = f"""## Vulnerability: {cve} ({risk_level})

**Component:** `{component}`  
**Version:** `{version}`  
**Severity:** {severity} ({score})"""
    
    # Add external data
    if ext_data.get("epss_score") is not None:
        markdown += f"  \n**EPSS Score:** {ext_data['epss_score']:.3f} (percentile: {ext_data.get('epss_percentile', 'N/A')})"
    
    if ext_data.get("cisa_kev"):
        markdown += f"  \n**⚠️ CISA KEV:** Listed in Known Exploited Vulnerabilities"
    
    if ext_data.get("nvd_cwe"):
        markdown += f"  \n**CWE:** {', '.join(ext_data['nvd_cwe'])}"
    
    # Add VEX information
    if vex_info:
        markdown += f"\n\n### VEX Assessment"
        if vex_info.get("vuln_exp_status"):
            markdown += f"  \n**Status:** {vex_info['vuln_exp_status']}"
        
        if vex_info.get("vuln_exp_justification"):
            markdown += f"  \n**Justification:** {vex_info['vuln_exp_justification']}"
        
        if vex_info.get("vuln_exp_response"):
            markdown += f"  \n**Response:** {vex_info['vuln_exp_response']}"
        
        if vex_info.get("vuln_exp_details"):
            markdown += f"  \n**Details:** {vex_info['vuln_exp_details']}"
        
        if vex_info.get("vuln_exp_updated"):
            markdown += f"  \n**Last Updated:** {vex_info['vuln_exp_updated']}"
            if vex_info.get("vuln_exp_updated_by_username"):
                markdown += f" by {vex_info['vuln_exp_updated_by_username']}"
    
    markdown += f"""

### Description
{ext_data.get('nvd_description', f'This vulnerability affects {component} version {version}.')}

### Risk Assessment
- **Severity:** {severity} ({score})"""
    
    epss_score = ext_data.get("epss_score")
    if epss_score is not None:
        if epss_score > 0.1:
            markdown += f"\n- **Exploitation Risk:** HIGH (EPSS: {epss_score:.3f})"
        else:
            markdown += f"\n- **Exploitation Risk:** Low (EPSS: {epss_score:.3f})"
    
    if ext_data.get("cisa_kev"):
        markdown += f"\n- **Known Exploits:** YES - Active exploitation detected"
    
    # Add VEX risk assessment
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        if vex_status in ["not_affected"]:
            markdown += f"\n- **VEX Assessment:** NOT AFFECTED - This component is not impacted by this vulnerability"
        elif vex_status in ["fixed"]:
            markdown += f"\n- **VEX Assessment:** FIXED - This vulnerability has been resolved"
        elif vex_status in ["mitigated"]:
            markdown += f"\n- **VEX Assessment:** MITIGATED - Controls are in place to reduce risk"
        elif vex_status in ["accepted_risk"]:
            markdown += f"\n- **VEX Assessment:** ACCEPTED RISK - Organization has accepted this risk"
        elif vex_status in ["under_investigation"]:
            markdown += f"\n- **VEX Assessment:** UNDER INVESTIGATION - Impact is being evaluated"
    
    markdown += f"""

### Remediation
1. **PRIORITY:** {'CRITICAL - Patch immediately' if ext_data.get('cisa_kev') else 'Update the component'} to the latest version that fixes this vulnerability
2. **Monitor:** Check for security advisories and patches
3. **Automate:** Implement automated dependency scanning and updates
4. **Validate:** Test patches in a staging environment before production deployment"""
    
    if ext_data.get("cisa_kev"):
        markdown += f"\n5. **URGENT:** This vulnerability has known exploits - prioritize patching"
    
    # Adjust remediation based on VEX status
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        if vex_status in ["not_affected", "fixed"]:
            markdown += f"\n\n**Note:** VEX assessment indicates this vulnerability is {vex_status.replace('_', ' ')}. Verify that assessment is current and accurate."
        elif vex_status in ["mitigated"]:
            markdown += f"\n\n**Note:** VEX assessment indicates mitigations are in place. Ensure mitigations remain effective and consider patching for defense in depth."
    
    markdown += f"""

### References
- [NVD Details](https://nvd.nist.gov/vuln/detail/{cve})
- [CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve})"""
    
    if ext_data.get("epss_score") is not None:
        markdown += f"\n- [EPSS Details](https://www.first.org/epss/model)"
    
    if ext_data.get("cisa_kev"):
        markdown += f"\n- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"
    
    # Add additional references from NVD
    if ext_data.get("nvd_references"):
        markdown += f"\n- Additional References:"
        for ref in ext_data["nvd_references"][:3]:  # Limit to 3 additional refs
            if ref.get("url"):
                markdown += f"\n  - [{ref.get('source', 'Reference')}]({ref['url']})"
    
    return markdown


def _generate_enhanced_vulnerability_tags(vuln: Dict[str, Any], ext_data: Dict[str, Any], vex_info: Optional[Dict[str, Any]] = None) -> List[str]:
    """Generate enhanced tags including external data indicators and VEX status."""
    tags = ["security", "vulnerability"]
    
    severity = vuln.get("severity", "").lower()
    if severity:
        tags.append(f"severity-{severity}")
    
    attack_vector = vuln.get("attack_vector", "").lower()
    if attack_vector:
        tags.append(f"attack-vector-{attack_vector}")
    
    # Add ecosystem-specific tags
    component_name = vuln.get("component_name", "")
    ecosystem = _detect_package_ecosystem(component_name)
    tags.append(f"ecosystem-{ecosystem}")
    
    # Add external data tags
    if ext_data.get("cisa_kev"):
        tags.append("cisa-kev")
        tags.append("known-exploited")
    
    epss_score = ext_data.get("epss_score")
    if epss_score is not None and epss_score > 0.1:
        tags.append("high-epss")
    
    if ext_data.get("nvd_cwe"):
        for cwe in ext_data["nvd_cwe"][:2]:  # Limit to 2 CWE tags
            if cwe.startswith("CWE-"):
                tags.append(f"cwe-{cwe[4:]}")
    
    # Add VEX tags
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        tags.append(f"vex-{vex_status}")
        
        # Add semantic VEX tags
        if vex_status in ["not_affected", "fixed", "resolved"]:
            tags.append("vex-resolved")
        elif vex_status in ["mitigated"]:
            tags.append("vex-mitigated")
        elif vex_status in ["accepted_risk"]:
            tags.append("vex-accepted")
        elif vex_status in ["false_positive"]:
            tags.append("vex-false-positive")
        elif vex_status in ["under_investigation", "in_triage"]:
            tags.append("vex-investigating")
    
    return tags


def _count_high_risk_vulnerabilities(vulnerabilities: List[Dict[str, Any]], 
                                   external_data: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    """Count high-risk vulnerabilities based on external data."""
    counts = {
        "cisa_kev": 0,
        "high_epss": 0,
        "critical_severity": 0,
        "total_high_risk": 0
    }
    
    high_risk_cves = set()
    
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "UNKNOWN")
        ext_data = external_data.get(cve, {})
        
        is_high_risk = False
        
        if ext_data.get("cisa_kev"):
            counts["cisa_kev"] += 1
            is_high_risk = True
        
        epss_score = ext_data.get("epss_score")
        if epss_score is not None and epss_score > 0.1:
            counts["high_epss"] += 1
            is_high_risk = True
        
        if vuln.get("severity", "").upper() == "CRITICAL":
            counts["critical_severity"] += 1
            is_high_risk = True
        
        if is_high_risk:
            high_risk_cves.add(cve)
    
    counts["total_high_risk"] = len(high_risk_cves)
    return counts


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


def _generate_enhanced_help_text(cve: str, vuln: Dict[str, Any], ext_data: Dict[str, Any], vex_info: Optional[Dict[str, Any]] = None) -> str:
    """Generate enhanced help text with external data and VEX information."""
    component = vuln.get("component_name", "Unknown")
    version = vuln.get("component_version", "Unknown")
    
    help_text = f"The component {component} version {version} contains vulnerability {cve}. "
    
    # Add VEX status context first
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        if vex_status in ["not_affected"]:
            help_text += "VEX Assessment: Component is not affected by this vulnerability. "
        elif vex_status in ["fixed"]:
            help_text += "VEX Assessment: This vulnerability has been fixed. "
        elif vex_status in ["mitigated"]:
            help_text += "VEX Assessment: Mitigations are in place to reduce risk. "
        elif vex_status in ["accepted_risk"]:
            help_text += "VEX Assessment: Organization has accepted this risk. "
        elif vex_status in ["false_positive"]:
            help_text += "VEX Assessment: This vulnerability is a false positive. "
        elif vex_status in ["resolved"]:
            help_text += "VEX Assessment: This vulnerability has been resolved. "
        elif vex_status in ["under_investigation", "in_triage"]:
            help_text += "VEX Assessment: Impact is currently being evaluated. "
    
    # Add urgency based on external data
    if ext_data.get("cisa_kev"):
        help_text += "⚠️ URGENT: This vulnerability is actively exploited in the wild according to CISA. "
    else:
        epss_score = ext_data.get("epss_score")
        if epss_score is not None and epss_score > 0.1:
            help_text += f"HIGH RISK: EPSS score of {epss_score:.3f} indicates elevated exploitation risk. "
    
    # Adjust recommendations based on VEX status
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        if vex_status in ["not_affected", "fixed"]:
            help_text += "Verify that the VEX assessment is current and accurate. "
        elif vex_status in ["mitigated"]:
            help_text += "Ensure mitigations remain effective and consider patching for defense in depth. "
        elif vex_status in ["accepted_risk"]:
            help_text += "Review accepted risk decision periodically and monitor for changes in threat landscape. "
        elif vex_status in ["false_positive"]:
            help_text += "Verify that the false positive assessment is accurate and documented. "
        elif vex_status in ["resolved"]:
            help_text += "Verify that the resolution is complete and effective. "
        else:
            help_text += "Consider upgrading to a newer version that addresses this vulnerability. "
    else:
        help_text += "Consider upgrading to a newer version that addresses this vulnerability. "
    
    help_text += "Review your dependency management and consider using tools like Dependabot or Renovate for automated updates."
    
    return help_text


def _generate_enhanced_results(vulnerabilities: List[Dict[str, Any]], 
                             external_data: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate enhanced SARIF results with external data and VEX information."""
    results = []
    
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "UNKNOWN")
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        severity = vuln.get("severity", "UNKNOWN")
        base_score = vuln.get("base_score", "N/A")
        
        # Get external data and VEX information
        ext_data = external_data.get(cve, {})
        vex_info = _get_vex_info(vuln)
        
        # Create enhanced package URL with ecosystem detection
        ecosystem = _detect_package_ecosystem(component_name)
        artifact_uri = f"pkg:{ecosystem}/{component_name}@{component_version}"
        
        # Enhanced message with risk context and VEX information
        message_text = _generate_enhanced_result_message(cve, component_name, component_version, severity, base_score, ext_data, vex_info)
        
        # Map severity to SARIF level with VEX consideration
        original_level = _map_severity_to_sarif_level(severity)
        vex_status = vex_info.get("vuln_exp_status") if vex_info else None
        final_level = _map_vex_status_to_sarif_level(vex_status, original_level)
        
        result = {
            "ruleId": cve,
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
                # Core vulnerability metadata
                "vulnerability_id": vuln.get("id"),
                "cvss_version": vuln.get("cvss_version"),
                "base_score": base_score,
                "attack_vector": vuln.get("attack_vector"),
                "attack_complexity": vuln.get("attack_complexity"),
                "availability_impact": vuln.get("availability_impact"),
                "rejected": vuln.get("rejected", 0),
                
                # Component information
                "component_id": vuln.get("component_id"),
                "ecosystem": ecosystem,
                "package_url": artifact_uri,
                
                # Scan metadata
                "scan_id": vuln.get("scan_id"),
                "original_level": original_level,
                
                # Standard taxonomies for better tool interoperability
                "security-severity": base_score,
                "precision": "high" if vex_info else "medium",
                "kind": "review",
                "rank": _calculate_risk_rank(vuln, ext_data, vex_info),
                "baseline": "unchanged",
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
        
        # Add VEX properties
        if vex_info:
            vex_properties = _generate_vex_properties(vex_info)
            result["properties"].update(vex_properties)
        
        # Enhanced remediation information with VEX consideration
        remediation = _generate_enhanced_remediation_info(component_name, component_version, cve, ext_data, vex_info)
        if remediation:
            result["fixes"] = [remediation]
        
        # Add fingerprints for deduplication
        result["fingerprints"] = {
            "workbench/component": f"{component_name}@{component_version}",
            "workbench/vulnerability": f"{cve}#{vuln.get('id', 'unknown')}",
            "primary": f"{component_name}@{component_version}#{cve}",
            "stable": f"{cve}"
        }
        
        # Add relationships to group vulnerabilities by component
        result["relatedLocations"] = [{
            "id": 0,
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f"pkg:{ecosystem}/{component_name}@{component_version}",
                    "description": {
                        "text": f"Component manifest for {component_name}"
                    }
                }
            },
            "message": {
                "text": f"Component {component_name} version {component_version}"
            }
        }]
        
        # Add suppression information if VEX status indicates resolved/mitigated
        if vex_info and vex_info.get("vuln_exp_status"):
            vex_status = vex_info["vuln_exp_status"].lower()
            if vex_status in ["not_affected", "fixed", "mitigated", "accepted_risk", "false_positive", "resolved"]:
                result["suppressions"] = [{
                    "kind": "inSource",
                    "status": "accepted",
                    "justification": vex_info.get("vuln_exp_justification", f"VEX status: {vex_status}")
                }]
        
        results.append(result)
    
    return results


def _generate_enhanced_result_message(cve: str, component: str, version: str, severity: str, 
                                    score: str, ext_data: Dict[str, Any], vex_info: Optional[Dict[str, Any]] = None) -> str:
    """Generate an enhanced message with risk indicators and VEX information."""
    base_message = f"Found {severity.lower()} severity vulnerability {cve} (CVSS {score}) in component {component} version {version}."
    
    # Add risk indicators
    risk_indicators = []
    if ext_data.get("cisa_kev"):
        risk_indicators.append("CISA KEV - Active exploitation detected")
    epss_score = ext_data.get("epss_score")
    if epss_score is not None and epss_score > 0.1:
        risk_indicators.append(f"High EPSS score: {epss_score:.3f}")
    
    if risk_indicators:
        base_message += f" ⚠️ {' | '.join(risk_indicators)}."
    
    # Add VEX status information
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"]
        base_message += f" VEX Status: {vex_status}."
        
        if vex_info.get("vuln_exp_justification"):
            base_message += f" Justification: {vex_info['vuln_exp_justification']}"
    
    # Adjust recommendation based on VEX status
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        if vex_status in ["not_affected", "fixed"]:
            base_message += " Verify VEX assessment is current and accurate."
        elif vex_status in ["mitigated"]:
            base_message += " Ensure mitigations remain effective."
        elif vex_status in ["accepted_risk"]:
            base_message += " Review accepted risk periodically."
        elif vex_status in ["false_positive"]:
            base_message += " Verify false positive assessment is accurate."
        elif vex_status in ["resolved"]:
            base_message += " Verify resolution is complete and effective."
        else:
            base_message += " This vulnerability should be addressed by updating to a patched version."
    else:
        base_message += " This vulnerability should be addressed by updating to a patched version."
    
    return base_message


def _generate_enhanced_remediation_info(component: str, version: str, cve: str, 
                                      ext_data: Dict[str, Any], vex_info: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Generate enhanced remediation information with urgency indicators and VEX context."""
    urgency = "standard"
    if ext_data.get("cisa_kev"):
        urgency = "critical"
    else:
        epss_score = ext_data.get("epss_score")
        if epss_score is not None and epss_score > 0.1:
            urgency = "high"
    
    # Adjust urgency based on VEX status
    description_text = f"Update {component} to a version that fixes {cve} - {urgency.upper()} priority"
    guidance_text = "Check for newer versions of this component that address the vulnerability"
    
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        if vex_status in ["not_affected", "fixed"]:
            description_text = f"Verify VEX assessment for {component} {cve} - Component reported as {vex_status}"
            guidance_text = "Validate that VEX assessment is current and accurate"
        elif vex_status in ["mitigated"]:
            description_text = f"Monitor mitigation effectiveness for {component} {cve} - MITIGATED status"
            guidance_text = "Ensure mitigations remain effective and consider patching for defense in depth"
        elif vex_status in ["accepted_risk"]:
            description_text = f"Review accepted risk for {component} {cve} - ACCEPTED RISK status"
            guidance_text = "Periodically review risk acceptance and monitor for changes in threat landscape"
        elif vex_status in ["false_positive"]:
            description_text = f"Verify false positive assessment for {component} {cve} - FALSE POSITIVE status"
            guidance_text = "Validate that false positive assessment is accurate and documented"
        elif vex_status in ["resolved"]:
            description_text = f"Verify resolution for {component} {cve} - RESOLVED status"
            guidance_text = "Confirm that resolution is complete and effective"
        elif vex_status in ["under_investigation", "in_triage"]:
            description_text = f"Monitor investigation progress for {component} {cve} - {vex_status.upper().replace('_', ' ')}"
            guidance_text = "Follow up on investigation status and prepare for potential remediation"
    
    remediation_info = {
        "description": {
            "text": description_text
        },
        "properties": {
            "urgency": urgency,
            "guidance": guidance_text,
            "automation": "Consider using automated dependency update tools",
            "cisa_kev": ext_data.get("cisa_kev", False),
            "epss_score": ext_data.get("epss_score")
        }
    }
    
    # Add VEX properties
    if vex_info:
        vex_properties = _generate_vex_properties(vex_info)
        remediation_info["properties"].update(vex_properties)
    
    return remediation_info


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
                "scan_code": scan_code,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_vulnerabilities": 0,
                "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                "external_data_sources": [],
                "high_risk_vulnerabilities": {"cisa_kev": 0, "high_epss": 0, "critical_severity": 0, "total_high_risk": 0}
            }
        }]
    }


def _build_cvss_vector(vuln: Dict[str, Any]) -> str:
    """Build a CVSS vector string from available vulnerability data."""
    version = vuln.get("cvss_version", "3.1")
    
    # Build vector components that we have data for
    vector_parts = [f"CVSS:{version}"]
    
    # Attack Vector
    av = vuln.get("attack_vector", "")
    if av:
        av_map = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P"}
        vector_parts.append(f"AV:{av_map.get(av, av[0] if av else 'N')}")
    
    # Attack Complexity
    ac = vuln.get("attack_complexity", "")
    if ac:
        ac_map = {"LOW": "L", "HIGH": "H"}
        vector_parts.append(f"AC:{ac_map.get(ac, ac[0] if ac else 'L')}")
    
    # Availability Impact
    a = vuln.get("availability_impact", "")
    if a:
        a_map = {"NONE": "N", "LOW": "L", "HIGH": "H"}
        vector_parts.append(f"A:{a_map.get(a, a[0] if a else 'N')}")
    
    return "/".join(vector_parts) if len(vector_parts) > 1 else "CVSS vector not available"


def _detect_package_ecosystem(component_name: str) -> str:
    """Detect the package ecosystem based on component name patterns."""
    if "/" in component_name:
        if component_name.startswith("org.") or component_name.startswith("com."):
            return "maven"
        elif "@" in component_name:
            return "npm"
        else:
            return "generic"
    elif "." in component_name and any(component_name.startswith(prefix) for prefix in ["org.", "com.", "net.", "io."]):
        return "maven"
    elif component_name.count(".") >= 2:  # Likely a Java package
        return "maven"
    else:
        return "generic"


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


def _map_severity_to_sarif_level(severity: str) -> str:
    """
    Map Workbench severity levels to SARIF levels.
    
    SARIF levels: error, warning, note, none
    Workbench severities: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    """
    severity_upper = severity.upper() if severity else "UNKNOWN"
    
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error", 
        "MEDIUM": "warning",
        "LOW": "note",
        "UNKNOWN": "warning"
    }
    
    return mapping.get(severity_upper, "warning")


def save_vulns_to_sarif(filepath: str, vulnerabilities: List[Dict[str, Any]], scan_code: str,
                       include_cve_descriptions: bool = True,
                       include_epss_scores: bool = True,
                       include_exploit_info: bool = True,
                       api_timeout: int = 30,
                       include_vex: bool = True,
                       include_scan_metadata: bool = True,
                       suppress_vex_mitigated: bool = True,
                       suppress_accepted_risk: bool = True,
                       suppress_false_positives: bool = True,
                       group_by_component: bool = True,
                       quiet: bool = False) -> None:
    """
    Save vulnerability results in SARIF format to a file with external enrichment.
    
    Args:
        filepath: Path where the SARIF file should be saved
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        include_cve_descriptions: Whether to include enhanced CVE descriptions from NVD
        include_epss_scores: Whether to include EPSS scores from FIRST
        include_exploit_info: Whether to include known exploit information
        api_timeout: Timeout for external API calls in seconds
        include_vex: Whether to include VEX assessments from Workbench
        include_scan_metadata: Whether to include scan timing and metadata
        suppress_vex_mitigated: Whether to suppress findings with VEX mitigation status
        suppress_accepted_risk: Whether to suppress findings marked as accepted risk
        suppress_false_positives: Whether to suppress findings marked as false positives
        group_by_component: Whether to group findings by component in SARIF
        quiet: Whether to suppress progress output
        
    Raises:
        IOError: If the file cannot be written
        OSError: If the directory cannot be created
    """
    output_dir = os.path.dirname(filepath) or "."
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Calculate how many findings would be suppressed by VEX without actually removing them.
        # The demotion to "note" level happens later in _generate_enhanced_results via _map_vex_status_to_sarif_level.
        original_count = len(vulnerabilities)
        suppressed_count = 0
        if include_vex and (suppress_vex_mitigated or suppress_accepted_risk or suppress_false_positives):
            suppressed_count = original_count - len(_apply_vex_suppression(
                vulnerabilities,
                suppress_vex_mitigated,
                suppress_accepted_risk,
                suppress_false_positives
            ))
            if not quiet and suppressed_count > 0:
                print(
                    f"Suppressed {suppressed_count} vulnerabilities based on VEX assessments (demoted to 'note' level)"
                )
        
        sarif_data = convert_vulns_to_sarif(
            vulnerabilities, 
            scan_code, 
            include_cve_descriptions,
            include_epss_scores,
            include_exploit_info,
            api_timeout,
            include_vex,
            include_scan_metadata,
            group_by_component
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
            
        if not quiet:
            print(f"Saved enhanced SARIF results to: {filepath}")
            
            # Print summary of external data
            props = sarif_data["runs"][0]["properties"]
            if props.get("external_data_sources"):
                print(f"External data sources used: {', '.join(props['external_data_sources'])}")
            
            high_risk = props.get("high_risk_vulnerabilities", {})
            if high_risk.get("total_high_risk", 0) > 0:
                print(f"High-risk vulnerabilities found: {high_risk['total_high_risk']}")
                if high_risk.get("cisa_kev", 0) > 0:
                    print(f"  - CISA KEV: {high_risk['cisa_kev']}")
                if high_risk.get("high_epss", 0) > 0:
                    print(f"  - High EPSS: {high_risk['high_epss']}")
            
            # Print VEX summary
            vex_stats = props.get("vex_statements", {})
            if vex_stats.get("total_with_vex", 0) > 0:
                print(f"VEX statements found: {vex_stats['total_with_vex']}")
                if vex_stats.get("status_distribution"):
                    print("  VEX status distribution:")
                    for status, count in vex_stats["status_distribution"].items():
                        print(f"    - {status}: {count}")
                if vex_stats.get("with_justification", 0) > 0:
                    print(f"  - With justification: {vex_stats['with_justification']}")
                if vex_stats.get("with_response", 0) > 0:
                    print(f"  - With response: {vex_stats['with_response']}")
                if vex_stats.get("with_details", 0) > 0:
                    print(f"  - With details: {vex_stats['with_details']}")
        
    except (IOError, OSError) as e:
        if not quiet:
            print(f"\nWarning: Failed to save SARIF results to {filepath}: {e}")
        raise


# Legacy function names for backward compatibility
def _generate_rules(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Legacy function for backward compatibility."""
    return _generate_enhanced_rules(vulnerabilities, {})


def _generate_results(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Legacy function for backward compatibility."""
    return _generate_enhanced_results(vulnerabilities, {})


def _analyze_vex_statements(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
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
            
            # Count fields with content
            if vuln.get("vuln_exp_justification"):
                vex_stats["with_justification"] += 1
            if vuln.get("vuln_exp_response"):
                vex_stats["with_response"] += 1
            if vuln.get("vuln_exp_details"):
                vex_stats["with_details"] += 1
    
    return vex_stats


def _get_vex_info(vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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


def _map_vex_status_to_sarif_level(vex_status: str, original_level: str) -> str:
    """Map VEX status to appropriate SARIF level, potentially suppressing findings."""
    if not vex_status:
        return original_level
    
    # VEX status mapping to SARIF levels
    vex_status_lower = vex_status.lower()
    
    # Standard VEX statuses
    if vex_status_lower in ["not_affected", "fixed"]:
        return "note"  # Demote to informational
    elif vex_status_lower in ["under_investigation", "in_triage"]:
        return original_level  # Keep original level
    elif vex_status_lower in ["affected", "exploitable"]:
        return original_level  # Keep original level, but add VEX context
    
    # Custom statuses (organization-specific)
    elif vex_status_lower in ["accepted_risk", "mitigated", "false_positive", "resolved"]:
        return "note"  # Demote to informational
    elif vex_status_lower in ["workaround_available"]:
        return "warning"  # Reduce severity slightly
    
    return original_level


def _generate_vex_properties(vex_info: Dict[str, Any]) -> Dict[str, Any]:
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


def _calculate_risk_rank(vuln: Dict[str, Any], ext_data: Dict[str, Any], vex_info: Optional[Dict[str, Any]] = None) -> float:
    """Calculate a numerical risk ranking for prioritization (0-100, higher = more risk)."""
    base_score = float(vuln.get("base_score", 0))
    rank = base_score * 10  # Start with CVSS score * 10 (max 100)
    
    # CISA KEV adds significant risk
    if ext_data.get("cisa_kev"):
        rank += 20
    
    # High EPSS score adds risk
    epss_score = ext_data.get("epss_score") or 0
    if epss_score > 0.1:
        rank += 15
    elif epss_score > 0.01:
        rank += 5
    
    # VEX status can reduce risk
    if vex_info and vex_info.get("vuln_exp_status"):
        vex_status = vex_info["vuln_exp_status"].lower()
        if vex_status in ["not_affected", "fixed", "resolved"]:
            rank *= 0.1  # Greatly reduce risk
        elif vex_status in ["mitigated", "false_positive"]:
            rank *= 0.2  # Significantly reduce risk
        elif vex_status in ["accepted_risk"]:
            rank *= 0.5  # Moderately reduce risk
    
    # Cap at 100
    return min(100.0, max(0.0, rank)) 