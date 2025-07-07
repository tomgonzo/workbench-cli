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

from .bootstrap_bom import detect_package_ecosystem
from .risk_adjustments import calculate_dynamic_risk, RiskAdjustment


def save_vulns_to_spdx(
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
    Save vulnerability results in SPDX 3.0 format.
    
    Args:
        filepath: Path where the SPDX file should be saved
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was applied
        epss_enrichment: Whether EPSS enrichment was applied
        cisa_kev_enrichment: Whether CISA KEV enrichment was applied
        enable_dynamic_risk_scoring: Whether dynamic risk scoring is enabled
        api_timeout: API timeout used for enrichment
        quiet: Whether to suppress output messages
        all_components: List of all components from scan when --augment-full-bom is used (optional)
        base_sbom_path: Path to base SBOM (for consistency, not used in SPDX)
        
    Raises:
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
            enable_dynamic_risk_scoring,
            all_components
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
    enable_dynamic_risk_scoring: bool = True,
    all_components: Optional[List[Dict[str, Any]]] = None
) -> Document:
    """
    Create an SPDX 3.0 document with vulnerability information.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: External enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was applied
        epss_enrichment: Whether EPSS enrichment was applied
        cisa_kev_enrichment: Whether CISA KEV enrichment was applied
        enable_dynamic_risk_scoring: Whether dynamic risk scoring is enabled
        all_components: List of all components from scan when --augment-full-bom is used (optional)
        
    Returns:
        SPDX Document object
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
    
    # Add enrichment metadata as document annotations
    enrichment_annotations = [
        f"nvd_enriched: {str(nvd_enrichment).lower()}",
        f"epss_enriched: {str(epss_enrichment).lower()}",
        f"cisa_kev_enriched: {str(cisa_kev_enrichment).lower()}",
        f"workbench_scan_code: {scan_code}",
        f"generated_at: {datetime.utcnow().isoformat()}Z"
    ]
    
    # Add annotations to document if the model supports it
    if hasattr(document, 'annotations'):
        document.annotations = enrichment_annotations
    elif hasattr(document, 'comment'):
        document.comment = "; ".join(enrichment_annotations)
    
    # Create packages and vulnerabilities
    packages = {}
    
    # If all_components is provided, create packages for all components first
    if all_components:
        for comp in all_components:
            component_name = comp.get("name", "Unknown")
            component_version = comp.get("version", "")
            package_key = f"{component_name}@{component_version}"
            
            if package_key not in packages:
                ecosystem = detect_package_ecosystem(component_name, component_version)
                
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
    
    # Process vulnerabilities and create/update packages as needed
    for vuln in vulnerabilities:
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        cve = vuln.get("cve", "UNKNOWN")
        
        # Create package if not exists (when all_components not provided or component not in all_components)
        package_key = f"{component_name}@{component_version}"
        if package_key not in packages:
            ecosystem = detect_package_ecosystem(component_name, component_version)
            
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
        
        # Calculate dynamic risk adjustment (if enabled)
        dynamic_risk_adjustment = None
        if enable_dynamic_risk_scoring:
            dynamic_risk_adjustment = calculate_dynamic_risk(vuln, external_data.get(cve, {}))
        
        # Create vulnerability
        vulnerability = _create_spdx_vulnerability(vuln, external_data.get(cve, {}), dynamic_risk_adjustment)
        document.vulnerabilities.append(vulnerability)
    
    return document


def _create_spdx_vulnerability(
    vuln: Dict[str, Any], 
    ext_data: Dict[str, Any],
    dynamic_risk_adjustment: Optional[RiskAdjustment] = None
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
    
    # High Risk Indicator annotations (NEW)
    if dynamic_risk_adjustment:
        annotations.append(f"High Risk Indicator: {dynamic_risk_adjustment.high_risk_indicator}")
        annotations.append(f"High Risk Evidence: {dynamic_risk_adjustment.high_risk_evidence}")
    
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
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
) -> Dict[str, Any]:
    """
    Create a simplified SPDX 3.0-like JSON structure when spdx-tools is not available.
    This is a fallback implementation that creates a basic structure.
    """
    if external_data is None:
        external_data = {}
    
    # Create fallback SPDX JSON structure
    spdx_doc = {
        "spdxVersion": "SPDX-3.0",
        "dataLicense": "CC0-1.0",
        "SPDXID": f"SPDXRef-DOCUMENT-{scan_code}",
        "name": f"Vulnerability Report - {scan_code}",
        "documentNamespace": f"https://workbench.fossid.com/spdx/{scan_code}",
        "creationInfo": {
            "created": datetime.utcnow().isoformat() + "Z",
            "creators": ["Tool: FossID Workbench CLI"],
            "licenseListVersion": "3.24"
        },
        "comment": f"nvd_enriched: {str(nvd_enrichment).lower()}; epss_enriched: {str(epss_enrichment).lower()}; cisa_kev_enriched: {str(cisa_kev_enrichment).lower()}; workbench_scan_code: {scan_code}; generated_at: {datetime.utcnow().isoformat()}Z",
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
            ecosystem = detect_package_ecosystem(component_name, component_version)
            
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