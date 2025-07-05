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
        suppressed: bool = False
    ):
        self.original_level = original_level
        self.adjusted_level = adjusted_level
        self.adjustment_reason = adjustment_reason
        self.priority_context = priority_context
        self.suppressed = suppressed
    
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
    external_data: Dict[str, Any],
    enable_vex_suppression: bool = True
) -> RiskAdjustment:
    """
    Calculate dynamic risk level for a vulnerability based on intelligence sources.
    
    Args:
        vuln: Vulnerability dictionary from Workbench API
        external_data: External enrichment data (EPSS, CISA KEV, NVD)
        enable_vex_suppression: Whether to apply VEX-based suppression
        
    Returns:
        RiskAdjustment object containing original and adjusted risk levels
    """
    # Start with base severity
    base_severity = vuln.get("severity", "UNKNOWN").upper()
    original_level = _map_cvss_severity_to_risk_level(base_severity)
    
    # Extract VEX information
    vex_status = (vuln.get("vuln_exp_status") or "").lower()
    vex_response = (vuln.get("vuln_exp_response") or "").lower()
    
    # Check for promotion to CRITICAL level
    if external_data.get("cisa_kev"):
        return RiskAdjustment(
            original_level=original_level,
            adjusted_level=RiskLevel.CRITICAL,
            adjustment_reason="CISA Known Exploited Vulnerability",
            priority_context="[CISA KEV]"
        )
    
    # Check for promotion to HIGH level
    epss_score = external_data.get("epss_score", 0)
    if epss_score and epss_score > 0.1:
        return RiskAdjustment(
            original_level=original_level,
            adjusted_level=RiskLevel.HIGH,
            adjustment_reason=f"High EPSS exploitation probability: {epss_score:.3f}",
            priority_context=f"[EPSS: {epss_score:.3f}]"
        )
    
    # Check VEX status for promotion to HIGH
    if vex_status in ["exploitable", "affected"]:
        return RiskAdjustment(
            original_level=original_level,
            adjusted_level=RiskLevel.HIGH,
            adjustment_reason=f"VEX assessment indicates {vex_status} status",
            priority_context=f"[VEX: {vex_status.upper()}]"
        )
    
    # Check for VEX-based suppression/demotion
    if enable_vex_suppression:
        # Suppress (demote to INFO) if VEX indicates resolved/mitigated
        if vex_status in ["not_affected", "fixed", "mitigated", "resolved", "false_positive"]:
            return RiskAdjustment(
                original_level=original_level,
                adjusted_level=RiskLevel.INFO,
                adjustment_reason=f"VEX assessment: {vex_status}",
                priority_context=f"[VEX: {vex_status.upper()}]",
                suppressed=True
            )
        
        # Suppress if VEX response indicates accepted risk
        if vex_response in ["will_not_fix", "update", "can_not_fix"]:
            return RiskAdjustment(
                original_level=original_level,
                adjusted_level=RiskLevel.INFO,
                adjustment_reason=f"VEX response: {vex_response}",
                priority_context=f"[VEX: {vex_response.upper()}]",
                suppressed=True
            )
    
    # No adjustment needed
    return RiskAdjustment(
        original_level=original_level,
        adjusted_level=original_level,
        adjustment_reason="No risk adjustment applied"
    )


def calculate_batch_risk_adjustments(
    vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]],
    enable_vex_suppression: bool = True
) -> Dict[str, RiskAdjustment]:
    """
    Calculate risk adjustments for a batch of vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        external_data: External enrichment data keyed by CVE
        enable_vex_suppression: Whether to apply VEX-based suppression
        
    Returns:
        Dictionary mapping vulnerability IDs to RiskAdjustment objects
    """
    adjustments = {}
    
    for vuln in vulnerabilities:
        vuln_id = str(vuln.get("id", "unknown"))
        cve = vuln.get("cve", "UNKNOWN")
        ext_data = external_data.get(cve, {})
        
        adjustment = calculate_dynamic_risk(vuln, ext_data, enable_vex_suppression)
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
    return mapping.get(severity.upper(), RiskLevel.MEDIUM)


def apply_vex_suppression_filter(
    vulnerabilities: List[Dict[str, Any]],
    external_data: Dict[str, Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Filter vulnerabilities based on VEX suppression rules.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        external_data: External enrichment data
        
    Returns:
        Tuple of (non_suppressed_vulnerabilities, suppressed_vulnerabilities)
    """
    non_suppressed = []
    suppressed = []
    
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "UNKNOWN")
        ext_data = external_data.get(cve, {})
        
        adjustment = calculate_dynamic_risk(vuln, ext_data, enable_vex_suppression=True)
        
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