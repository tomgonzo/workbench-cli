"""
Dynamic risk adjustment utilities for vulnerability reports.

This module provides format-agnostic logic for calculating dynamic risk levels
based on VEX assessments, EPSS scores, CISA KEV status, and other intelligence.
The risk calculations can be applied consistently across SARIF, CycloneDX, and SPDX formats.
"""

from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Standardized risk levels for vulnerability prioritization."""
    CRITICAL = "critical"  # CISA KEV, high EPSS + exploitable VEX
    HIGH = "high"         # High EPSS (>0.1), exploitable VEX status
    MEDIUM = "medium"     # Default CVSS-based severity
    LOW = "low"           # Low severity or mitigated VEX
    INFO = "info"         # Suppressed by VEX (resolved/false positive)


class RiskAdjustment:
    """Container for risk adjustment information."""
    
    def __init__(
        self,
        original_level: RiskLevel,
        adjusted_level: RiskLevel,
        adjustment_reason: str,
        priority_context: str = "",
        suppressed: bool = False,
        high_risk_indicator: str = "Unknown",
        high_risk_evidence: str = ""
    ):
        self.original_level = original_level
        self.adjusted_level = adjusted_level
        self.adjustment_reason = adjustment_reason
        self.priority_context = priority_context
        self.suppressed = suppressed
        self.high_risk_indicator = high_risk_indicator  # "Yes", "No", or "Unknown"
        self.high_risk_evidence = high_risk_evidence
    
    @property
    def was_promoted(self) -> bool:
        """Check if risk level was promoted (increased)."""
        level_order = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return level_order.index(self.adjusted_level) > level_order.index(self.original_level)
    
    @property 
    def was_demoted(self) -> bool:
        """Check if risk level was demoted (decreased)."""
        level_order = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return level_order.index(self.adjusted_level) < level_order.index(self.original_level)


def calculate_dynamic_risk(
    vuln: Dict[str, Any], 
    external_data: Dict[str, Any]
) -> RiskAdjustment:
    """
    Calculate dynamic risk level based on vulnerability attributes and external data.
    
    This function always applies dynamic risk scoring adjustments when called.
    Control whether to use dynamic risk scoring at the call site.
    
    Args:
        vuln: Vulnerability dictionary from Workbench API
        external_data: External enrichment data for this CVE
        
    Returns:
        RiskAdjustment with original and adjusted risk levels
    """
    original_level = _map_cvss_severity_to_risk_level(vuln.get("severity", "UNKNOWN"))
    
    # Start with original level
    adjusted_level = original_level
    adjustments = []
    
    # High Risk Indicator logic (3-state: Yes/No/Unknown)
    high_risk_indicator = "Unknown"  # Default state
    high_risk_evidence = []
    
    # Get VEX status and response for use throughout the function
    vex_status = (vuln.get("vuln_exp_status") or "").lower()
    
    # Handle VEX response - it can be a string or a list
    vex_response_raw = vuln.get("vuln_exp_response") or ""
    if isinstance(vex_response_raw, list):
        # If it's a list, join with commas and lowercase
        vex_response = ",".join(str(r).lower() for r in vex_response_raw)
    else:
        vex_response = str(vex_response_raw).lower()
    
    # Check for VEX suppression FIRST - VEX should override other risk factors
    # VEX status-based suppression (demote to INFO) - High Risk = "No"
    if vex_status in ["not_affected", "fixed", "mitigated", "resolved", "resolved_with_pedigree", "false_positive"]:
        adjusted_level = RiskLevel.INFO
        adjustments.append(f"VEX assessment: {vex_status}")
        high_risk_indicator = "No"
        high_risk_evidence.append(f"VEX suppressed: {vex_status}")
    
    # VEX response-based suppression - High Risk = "No"
    elif vex_response in ["will_not_fix", "update"]:
        adjusted_level = RiskLevel.INFO
        adjustments.append(f"VEX response: {vex_response}")
        high_risk_indicator = "No"
        high_risk_evidence.append(f"VEX response: {vex_response}")
    
    # If not suppressed by VEX, check for high risk escalation factors - High Risk = "Yes"
    else:
        # CISA KEV promotion to CRITICAL level
        if external_data.get("cisa_kev"):
            adjusted_level = RiskLevel.CRITICAL
            adjustments.append("CISA Known Exploited Vulnerability")
            high_risk_indicator = "Yes"
            high_risk_evidence.append("CISA Known Exploited Vulnerability")
        
        # EPSS-based promotion to HIGH level
        epss_score = external_data.get("epss_score", 0)
        if epss_score and epss_score > 0.1:
            adjusted_level = RiskLevel.HIGH
            adjustments.append(f"High EPSS exploitation probability: {epss_score:.3f}")
            high_risk_indicator = "Yes"
            high_risk_evidence.append(f"High EPSS score: {epss_score:.3f}")
        
        # VEX status-based promotion to HIGH (exploitable takes priority)
        if vex_status in ["exploitable", "affected"]:
            adjusted_level = RiskLevel.HIGH
            adjustments.append(f"VEX assessment indicates {vex_status} status")
            high_risk_indicator = "Yes"
            high_risk_evidence.append(f"VEX assessment: {vex_status}")
        
        # VEX response-based promotion for unfixable vulnerabilities
        if "can_not_fix" in vex_response:
            adjusted_level = RiskLevel.HIGH
            adjustments.append(f"VEX response indicates unfixable vulnerability")
            high_risk_indicator = "Yes"
            high_risk_evidence.append(f"VEX response: unfixable (can_not_fix)")
        
        # Critical severity as high risk indicator
        if (vuln.get("severity") or "").upper() == "CRITICAL":
            # Only set to "Yes" if not already set by other factors
            if high_risk_indicator == "Unknown":
                high_risk_indicator = "Yes"
                high_risk_evidence.append("Critical CVSS severity")
    
    # Prepare evidence string
    if high_risk_indicator == "Yes":
        evidence_string = "; ".join(high_risk_evidence)
    elif high_risk_indicator == "No":
        evidence_string = "; ".join(high_risk_evidence)
    else:  # Unknown
        evidence_string = "No additional risk context available"
    
    # No adjustment needed
    if len(adjustments) == 0:
        return RiskAdjustment(
            original_level=original_level,
            adjusted_level=original_level,
            adjustment_reason="No risk adjustment applied",
            high_risk_indicator=high_risk_indicator,
            high_risk_evidence=evidence_string
        )
    
    # Construct the final adjustment reason
    adjustment_reason = "Dynamic risk adjustment: " + " -> ".join(adjustments)
    
    return RiskAdjustment(
        original_level=original_level,
        adjusted_level=adjusted_level,
        adjustment_reason=adjustment_reason,
        high_risk_indicator=high_risk_indicator,
        high_risk_evidence=evidence_string
    )


def calculate_batch_risk_adjustments(
    vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]]
) -> Dict[str, RiskAdjustment]:
    """
    Calculate risk adjustments for a batch of vulnerabilities.
    
    This function always applies dynamic risk scoring. Only call when dynamic risk scoring is enabled.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        external_data: External enrichment data keyed by CVE
        
    Returns:
        Dictionary mapping vulnerability IDs to RiskAdjustment objects
    """
    adjustments = {}
    
    for vuln in vulnerabilities:
        vuln_id = str(vuln.get("id", "unknown"))
        cve = vuln.get("vuln_id") or vuln.get("cve", "UNKNOWN")
        ext_data = external_data.get(cve, {})
        
        adjustment = calculate_dynamic_risk(vuln, ext_data)
        adjustments[vuln_id] = adjustment
    
    return adjustments


def get_risk_summary(adjustments: Dict[str, RiskAdjustment]) -> Dict[str, int]:
    """
    Generate a summary of risk adjustments.
    
    Args:
        adjustments: Dictionary of risk adjustments
        
    Returns:
        Summary statistics about risk adjustments
    """
    summary = {
        "total_vulnerabilities": len(adjustments),
        "promoted": 0,
        "demoted": 0,
        "suppressed": 0,
        "unchanged": 0,
        "by_adjusted_level": {level.value: 0 for level in RiskLevel},
        "promotion_reasons": {},
        "suppression_reasons": {}
    }
    
    for adjustment in adjustments.values():
        # Count by adjusted level
        summary["by_adjusted_level"][adjustment.adjusted_level.value] += 1
        
        # Count adjustments
        if adjustment.was_promoted:
            summary["promoted"] += 1
            reason = adjustment.adjustment_reason
            summary["promotion_reasons"][reason] = summary["promotion_reasons"].get(reason, 0) + 1
        elif adjustment.was_demoted:
            summary["demoted"] += 1
            if adjustment.suppressed:
                summary["suppressed"] += 1
                reason = adjustment.adjustment_reason
                summary["suppression_reasons"][reason] = summary["suppression_reasons"].get(reason, 0) + 1
        else:
            summary["unchanged"] += 1
    
    return summary


# Format-specific mapping functions

def risk_level_to_sarif_level(risk_level: RiskLevel) -> str:
    """Map RiskLevel to SARIF level."""
    mapping = {
        RiskLevel.CRITICAL: "error",
        RiskLevel.HIGH: "error", 
        RiskLevel.MEDIUM: "warning",
        RiskLevel.LOW: "warning",
        RiskLevel.INFO: "note"
    }
    return mapping[risk_level]


def risk_level_to_cyclonedx_severity(risk_level: RiskLevel) -> str:
    """Map RiskLevel to CycloneDX severity."""
    mapping = {
        RiskLevel.CRITICAL: "critical",
        RiskLevel.HIGH: "high",
        RiskLevel.MEDIUM: "medium", 
        RiskLevel.LOW: "low",
        RiskLevel.INFO: "info"
    }
    return mapping[risk_level]


def risk_level_to_spdx_severity(risk_level: RiskLevel) -> str:
    """Map RiskLevel to SPDX severity."""
    mapping = {
        RiskLevel.CRITICAL: "CRITICAL",
        RiskLevel.HIGH: "HIGH",
        RiskLevel.MEDIUM: "MEDIUM",
        RiskLevel.LOW: "LOW", 
        RiskLevel.INFO: "LOW"  # SPDX doesn't have INFO, use LOW
    }
    return mapping[risk_level]


# Helper functions

def _map_cvss_severity_to_risk_level(severity: str) -> RiskLevel:
    """Map CVSS severity string to RiskLevel."""
    mapping = {
        "CRITICAL": RiskLevel.CRITICAL,
        "HIGH": RiskLevel.HIGH,
        "MEDIUM": RiskLevel.MEDIUM,
        "LOW": RiskLevel.LOW,
        "UNKNOWN": RiskLevel.MEDIUM  # Default to medium for unknown
    }
    return mapping.get((severity or "").upper(), RiskLevel.MEDIUM)


def apply_vex_suppression_filter(
    vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Filter vulnerabilities based on VEX suppression rules.
    
    This function always applies dynamic risk scoring. Only call when dynamic risk scoring is enabled.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        external_data: External enrichment data
        
    Returns:
        Tuple of (non_suppressed_vulnerabilities, suppressed_vulnerabilities)
    """
    non_suppressed = []
    suppressed = []
    
    for vuln in vulnerabilities:
        cve = vuln.get("vuln_id") or vuln.get("cve", "UNKNOWN")
        ext_data = external_data.get(cve, {})
        
        adjustment = calculate_dynamic_risk(vuln, ext_data)
        
        if adjustment.suppressed:
            suppressed.append(vuln)
        else:
            non_suppressed.append(vuln)
    
    return non_suppressed, suppressed


# Legacy compatibility functions (for existing SARIF code)

def map_vex_status_to_sarif_level(
    vex_status: str, 
    original_level: str, 
    external_data: Dict[str, Any] = None
) -> str:
    """
    Legacy compatibility function for existing SARIF code.
    Maps to the new risk calculation system.
    """
    if external_data is None:
        external_data = {}
    
    # Create a mock vulnerability for the calculation
    mock_vuln = {
        "vuln_exp_status": vex_status,
        "severity": "MEDIUM"  # Default, will be overridden by external data logic
    }
    
    adjustment = calculate_dynamic_risk(mock_vuln, external_data)
    return risk_level_to_sarif_level(adjustment.adjusted_level)


# Business logic functions - moved from sarif_generator.py and export_vulns.py

def extract_unique_cves(vulnerabilities: List[Dict[str, Any]]) -> List[str]:
    """Extract unique CVEs from vulnerability data, excluding UNKNOWN values."""
    return list(set(
        vuln.get("vuln_id") or vuln.get("cve", "UNKNOWN") 
        for vuln in vulnerabilities 
        if (vuln.get("vuln_id") or vuln.get("cve")) != "UNKNOWN"
    ))


def count_high_risk_vulnerabilities(vulnerabilities: List[Dict[str, Any]], 
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
        cve = vuln.get("vuln_id") or vuln.get("cve", "UNKNOWN")
        ext_data = external_data.get(cve, {})
        
        is_high_risk = False
        
        if ext_data.get("cisa_kev"):
            counts["cisa_kev"] += 1
            is_high_risk = True
        
        epss_score = ext_data.get("epss_score")
        if epss_score is not None and epss_score > 0.1:
            counts["high_epss"] += 1
            is_high_risk = True
        
        if (vuln.get("severity") or "").upper() == "CRITICAL":
            counts["critical_severity"] += 1
            is_high_risk = True
        
        if is_high_risk:
            high_risk_cves.add(cve)
    
    counts["total_high_risk"] = len(high_risk_cves)
    return counts


def count_high_risk_indicators_detailed(
    vulnerabilities: List[Dict[str, Any]], 
    external_data: Dict[str, Dict[str, Any]]
) -> Dict[str, int]:
    """Count vulnerabilities by high risk indicator state."""
    counts = {"yes": 0, "no": 0, "unknown": 0}
    
    for vuln in vulnerabilities:
        cve = vuln.get("vuln_id") or vuln.get("cve", "UNKNOWN")
        ext_data = external_data.get(cve, {})
        
        adjustment = calculate_dynamic_risk(vuln, ext_data)
        state = adjustment.high_risk_indicator.lower()
        if state in counts:
            counts[state] += 1
    
    return counts


# Public API
__all__ = [
    # Core types
    "RiskLevel",
    "RiskAdjustment",
    
    # Main functions
    "calculate_dynamic_risk",
    "calculate_batch_risk_adjustments",
    
    # Format mappings
    "risk_level_to_sarif_level",
    "risk_level_to_cyclonedx_severity",
    "risk_level_to_spdx_severity",
    
    # Filtering functions
    "apply_vex_suppression_filter",
    
    # Business logic functions
    "extract_unique_cves",
    "count_high_risk_vulnerabilities",
    "count_high_risk_indicators_detailed",
    
    # Legacy compatibility
    "map_vex_status_to_sarif_level",
] 