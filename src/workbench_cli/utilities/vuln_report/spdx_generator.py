"""
SPDX 3.0 vulnerability report generation.

This module provides functionality to convert vulnerability data from the Workbench API
into SPDX 3.0 format with Security Profile, which provides standardized vulnerability
information within software bill of materials.
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# SPDX imports (optional dependency)
try:
    from spdx_tools.spdx.model import Document, CreationInfo, Actor, ActorType
    from spdx_tools.spdx.model.package import Package
    from spdx_tools.spdx.model.vulnerability import Vulnerability, VulnerabilityReference
    from spdx_tools.spdx.writer.json import write_document_to_file
    SPDX_AVAILABLE = True
except ImportError:
    # Fallback types when SPDX is not available
    Document = Any
    CreationInfo = Any
    Actor = Any
    ActorType = Any
    Package = Any
    Vulnerability = Any
    VulnerabilityReference = Any
    SPDX_AVAILABLE = False

from .component_enrichment import _detect_package_ecosystem
from .risk_adjustments import calculate_dynamic_risk, risk_level_to_spdx_severity


def save_vulns_to_spdx(
    filepath: str,
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    api_timeout: int = 30,
    enable_vex_suppression: bool = True,
    quiet: bool = False
) -> None:
    """
    Save vulnerability results in SPDX 3.0 format.
    
    Args:
        filepath: Path where the SPDX file should be saved
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was enabled
        epss_enrichment: Whether EPSS enrichment was enabled
        cisa_kev_enrichment: Whether CISA KEV enrichment was enabled
        api_timeout: API timeout used for enrichment
        enable_vex_suppression: Whether VEX suppression is enabled
        quiet: Whether to suppress output messages
        
    Raises:
        ImportError: If spdx-tools is not installed
        IOError: If the file cannot be written
        OSError: If the directory cannot be created
    """
    if not SPDX_AVAILABLE:
        raise ImportError(
            "SPDX support requires the 'spdx-tools' package. "
            "This should be installed automatically with workbench-cli. "
            "Try reinstalling: pip install --force-reinstall workbench-cli"
        )
    
    output_dir = os.path.dirname(filepath) or "."
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        spdx_document = convert_vulns_to_spdx(
            vulnerabilities, 
            scan_code, 
            external_data,
            nvd_enrichment,
            epss_enrichment,
            cisa_kev_enrichment,
            enable_vex_suppression
        )
        
        # Use SPDX JSON writer
        write_document_to_file(spdx_document, filepath)
            
        if not quiet:
            print(f"Saved SPDX 3.0 document to: {filepath}")
        
    except (IOError, OSError) as e:
        if not quiet:
            print(f"\nWarning: Failed to save SPDX results to {filepath}: {e}")
        raise


def convert_vulns_to_spdx(
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    enable_vex_suppression: bool = True
) -> Document:
    """
    Convert vulnerability data to SPDX 3.0 Document format.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries from the Workbench API
        scan_code: The scan code for reference
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was enabled
        epss_enrichment: Whether EPSS enrichment was enabled
        cisa_kev_enrichment: Whether CISA KEV enrichment was enabled
        enable_vex_suppression: Whether VEX suppression is enabled
        
    Returns:
        SPDX Document object containing vulnerability information
    """
    if not SPDX_AVAILABLE:
        raise ImportError("SPDX support requires the 'spdx-tools' package which should be installed automatically")
    
    if external_data is None:
        external_data = {}
    
    # Create SPDX document
    creation_info = CreationInfo(
        spdx_version="SPDX-3.0",
        spdx_id=f"SPDXRef-DOCUMENT-{scan_code}",
        name=f"Vulnerability Report - {scan_code}",
        document_namespace=f"https://workbench.fossid.com/spdx/{scan_code}",
        creators=[Actor(ActorType.TOOL, "FossID Workbench CLI")],
        created=datetime.utcnow()
    )
    
    document = Document(creation_info)
    
    # Create packages and vulnerabilities
    packages = {}
    
    for vuln in vulnerabilities:
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        cve = vuln.get("cve", "UNKNOWN")
        
        # Create package if not exists
        package_key = f"{component_name}@{component_version}"
        if package_key not in packages:
            ecosystem = _detect_package_ecosystem(component_name, component_version)
            
            package = Package(
                spdx_id=f"SPDXRef-Package-{component_name}-{component_version}",
                name=component_name,
                version=component_version,
                download_location="NOASSERTION"  # Required field
            )
            
            # Add package URL if possible
            if ecosystem != "generic":
                package.external_package_refs = [
                    f"pkg:{ecosystem}/{component_name}@{component_version}"
                ]
            
            packages[package_key] = package
            document.packages.append(package)
        
        # Create vulnerability
        vulnerability = _create_spdx_vulnerability(vuln, external_data.get(cve, {}))
        document.vulnerabilities.append(vulnerability)
    
    return document


def _create_spdx_vulnerability(
    vuln: Dict[str, Any], 
    ext_data: Dict[str, Any]
) -> Vulnerability:
    """Create an SPDX Vulnerability object from vulnerability data."""
    cve = vuln.get("cve", "UNKNOWN")
    component_name = vuln.get("component_name", "Unknown")
    component_version = vuln.get("component_version", "Unknown")
    
    # Create vulnerability
    vulnerability_id = cve if cve != "UNKNOWN" else f"UNKNOWN-{vuln.get('id', 'unknown')}"
    
    vulnerability = Vulnerability(
        spdx_id=f"SPDXRef-Vulnerability-{vulnerability_id}-{component_name}-{component_version}",
        name=vulnerability_id
    )
    
    # Add description from NVD if available
    if ext_data.get("nvd_description"):
        vulnerability.summary = ext_data["nvd_description"]
    else:
        vulnerability.summary = f"Security vulnerability affecting {component_name} version {component_version}"
    
    # Add CVSS information and dynamic risk assessment
    base_score = vuln.get("base_score")
    if base_score and base_score != "N/A":
        try:
            score_value = float(base_score)
            # Note: SPDX 3.0 vulnerability model is still evolving
            # This is a simplified representation
            vulnerability.cvss_score = score_value
            
            # Apply dynamic risk assessment to severity (NEW)
            risk_adjustment = calculate_dynamic_risk(vuln, ext_data, enable_vex_suppression=True)
            if risk_adjustment.adjusted_level != risk_adjustment.original_level:
                # Use dynamic risk level for severity when adjusted
                vulnerability.severity = risk_level_to_spdx_severity(risk_adjustment.adjusted_level)
            else:
                # Use original CVSS-based severity
                vulnerability.severity = _map_severity_to_spdx(vuln.get("severity", "UNKNOWN"))
        except (ValueError, TypeError):
            pass
    
    # Add external references
    references = []
    
    # NVD reference
    if cve != "UNKNOWN":
        nvd_ref = VulnerabilityReference(
            locator=f"https://nvd.nist.gov/vuln/detail/{cve}",
            reference_type="advisory"
        )
        references.append(nvd_ref)
    
    # Additional NVD references
    if ext_data.get("nvd_references"):
        for ref in ext_data["nvd_references"][:5]:  # Limit to 5 references
            ref_obj = VulnerabilityReference(
                locator=ref.get("url", ""),
                reference_type="other"
            )
            references.append(ref_obj)
    
    vulnerability.external_references = references
    
    # Add VEX information and dynamic risk as annotations
    annotations = []
    
    # Dynamic risk assessment annotations (NEW)
    risk_adjustment = calculate_dynamic_risk(vuln, ext_data, enable_vex_suppression=True)
    if risk_adjustment.adjusted_level != risk_adjustment.original_level:
        annotations.append(f"Dynamic Risk: {risk_adjustment.adjusted_level.value.upper()}")
        annotations.append(f"Risk Adjustment: {risk_adjustment.adjustment_reason}")
        if risk_adjustment.priority_context:
            annotations.append(f"Priority: {risk_adjustment.priority_context}")
    
    vex_status = vuln.get("vuln_exp_status")
    if vex_status:
        annotations.append(f"VEX Status: {vex_status}")
    
    vex_response = vuln.get("vuln_exp_response")
    if vex_response:
        annotations.append(f"VEX Response: {vex_response}")
    
    vex_justification = vuln.get("vuln_exp_justification")
    if vex_justification:
        annotations.append(f"VEX Justification: {vex_justification}")
    
    # External enrichment annotations
    if ext_data.get("epss_score") is not None:
        annotations.append(f"EPSS Score: {ext_data['epss_score']:.3f}")
        annotations.append(f"EPSS Percentile: {ext_data.get('epss_percentile', 'N/A')}")
    
    if ext_data.get("cisa_kev"):
        annotations.append("CISA Known Exploited Vulnerability")
    
    if annotations:
        vulnerability.comment = "; ".join(annotations)
    
    return vulnerability


def _map_severity_to_spdx(severity: str) -> str:
    """Map Workbench severity to SPDX severity."""
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH", 
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "UNKNOWN"
    }
    return severity_map.get(severity.upper(), "UNKNOWN")


# Fallback implementation for when spdx-tools is not available
def _create_spdx_json_fallback(
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Create a simplified SPDX 3.0-like JSON structure when spdx-tools is not available.
    This is a fallback implementation that creates a basic structure.
    """
    if external_data is None:
        external_data = {}
    
    # Create basic SPDX 3.0 structure
    spdx_doc = {
        "spdxVersion": "SPDX-3.0",
        "dataLicense": "CC0-1.0",
        "SPDXID": f"SPDXRef-DOCUMENT-{scan_code}",
        "name": f"Vulnerability Report - {scan_code}",
        "documentNamespace": f"https://workbench.fossid.com/spdx/{scan_code}",
        "creationInfo": {
            "created": datetime.utcnow().isoformat() + "Z",
            "creators": ["Tool: FossID Workbench CLI"]
        },
        "packages": [],
        "vulnerabilities": []
    }
    
    # Track unique packages
    packages = {}
    
    for vuln in vulnerabilities:
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        cve = vuln.get("cve", "UNKNOWN")
        
        # Create package if not exists
        package_key = f"{component_name}@{component_version}"
        if package_key not in packages:
            ecosystem = _detect_package_ecosystem(component_name, component_version)
            
            package = {
                "SPDXID": f"SPDXRef-Package-{component_name}-{component_version}",
                "name": component_name,
                "version": component_version,
                "downloadLocation": "NOASSERTION"
            }
            
            if ecosystem != "generic":
                package["externalRefs"] = [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:{ecosystem}/{component_name}@{component_version}"
                }]
            
            packages[package_key] = package
            spdx_doc["packages"].append(package)
        
        # Create vulnerability
        vulnerability_id = cve if cve != "UNKNOWN" else f"UNKNOWN-{vuln.get('id', 'unknown')}"
        
        vulnerability = {
            "SPDXID": f"SPDXRef-Vulnerability-{vulnerability_id}-{component_name}-{component_version}",
            "name": vulnerability_id
        }
        
        # Add description
        if external_data.get(cve, {}).get("nvd_description"):
            vulnerability["summary"] = external_data[cve]["nvd_description"]
        else:
            vulnerability["summary"] = f"Security vulnerability affecting {component_name} version {component_version}"
        
        # Add CVSS information
        base_score = vuln.get("base_score")
        if base_score and base_score != "N/A":
            try:
                vulnerability["cvssScore"] = float(base_score)
                vulnerability["severity"] = vuln.get("severity", "UNKNOWN")
            except (ValueError, TypeError):
                pass
        
        # Add external references
        references = []
        if cve != "UNKNOWN":
            references.append({
                "referenceCategory": "SECURITY",
                "referenceType": "advisory",
                "referenceLocator": f"https://nvd.nist.gov/vuln/detail/{cve}"
            })
        
        if external_data.get(cve, {}).get("nvd_references"):
            for ref in external_data[cve]["nvd_references"][:5]:
                references.append({
                    "referenceCategory": "OTHER",
                    "referenceType": "other",
                    "referenceLocator": ref.get("url", "")
                })
        
        if references:
            vulnerability["externalRefs"] = references
        
        spdx_doc["vulnerabilities"].append(vulnerability)
    
    return spdx_doc 