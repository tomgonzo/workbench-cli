"""
CycloneDX vulnerability report generation.

This module provides functionality to convert vulnerability data from the Workbench API
into CycloneDX format, which is a software bill of materials (SBOM) format that includes
vulnerability information.

The module supports two approaches:
1. Building a new SBOM from vulnerability data (generation approach)
2. Augmenting an existing CycloneDX SBOM with vulnerability data (augmentation approach)

Both approaches use the unified enrichment flow from cyclonedx_enrichment.py
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# CycloneDX imports (optional dependency)
try:
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model.vulnerability import (
        Vulnerability,
        VulnerabilityRating,
        VulnerabilityReference,
        BomTarget,
        VulnerabilitySource,
        VulnerabilityScoreSource,
        VulnerabilitySeverity,
    )
    from cyclonedx.model.bom import Bom
    from cyclonedx.output.json import JsonV1Dot6
    from cyclonedx.model import ExternalReference, ExternalReferenceType, Property
    from cyclonedx.model.license import DisjunctiveLicense, LicenseRepository
    from packageurl import PackageURL
    CYCLONEDX_AVAILABLE = True
except ImportError:
    # Fallback types when CycloneDX is not available
    Bom = Any
    Component = Any
    Vulnerability = Any
    VulnerabilityRating = Any
    VulnerabilityReference = Any
    VulnerabilitySource = Any
    VulnerabilityScoreSource = Any
    ComponentType = Any
    JsonV1Dot6 = Any
    ExternalReference = Any
    ExternalReferenceType = Any
    DisjunctiveLicense = Any
    LicenseRepository = Any
    PackageURL = Any
    BomTarget = Any
    Property = Any
    CYCLONEDX_AVAILABLE = False

# Import enrichment pipeline for unified flow
from .cyclonedx_enrichment import augment_cyclonedx_sbom_from_file

# Added get_component_info for richer component metadata
from .bootstrap_bom import get_component_info


def save_vulns_to_cyclonedx(
    filepath: str,
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    enable_dynamic_risk_scoring: bool = True,
    quiet: bool = False,
    base_sbom_path: Optional[str] = None,
    all_components: Optional[List[Dict[str, Any]]] = None
) -> None:
    """
    Save vulnerability results in CycloneDX format using unified enrichment pipeline.
    
    This function creates a basic SBOM (generation) or loads an existing SBOM (augmentation),
    then hands off to the unified enrichment pipeline for external data enrichment and
    dynamic risk scoring.
    
    Args:
        filepath: Path where the CycloneDX file should be saved
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was enabled
        epss_enrichment: Whether EPSS enrichment was enabled
        cisa_kev_enrichment: Whether CISA KEV enrichment was enabled
        enable_dynamic_risk_scoring: Whether dynamic risk scoring is enabled
        quiet: Whether to suppress output messages
        base_sbom_path: Path to existing CycloneDX SBOM to augment (optional)
        all_components: List of all components from scan when --augment-full-bom is used (optional)
        
    Raises:
        ImportError: If cyclonedx-python-lib is not installed
        IOError: If the file cannot be written
        OSError: If the directory cannot be created
        FileNotFoundError: If base_sbom_path is provided but file doesn't exist
    """
    if not CYCLONEDX_AVAILABLE:
        raise ImportError(
            "CycloneDX support requires the 'cyclonedx-python-lib' package. "
            "This should be installed automatically with workbench-cli. "
            "Try reinstalling: pip install --force-reinstall workbench-cli"
        )
    
    output_dir = os.path.dirname(filepath) or "."
    
    try:
        os.makedirs(output_dir, exist_ok=True)

        # Choose between augmentation and generation approach
        if base_sbom_path and os.path.exists(base_sbom_path):
            # **AUGMENTATION FLOW**: Load existing SBOM and enrich it
            if not quiet:
                print(f"   • Augmenting existing SBOM from {os.path.basename(base_sbom_path)}")
            
            augment_cyclonedx_sbom_from_file(
                sbom_path=base_sbom_path,
                filepath=filepath,
                scan_code=scan_code,
                external_data=external_data,
                nvd_enrichment=nvd_enrichment,
                epss_enrichment=epss_enrichment,
                cisa_kev_enrichment=cisa_kev_enrichment,
                enable_dynamic_risk_scoring=enable_dynamic_risk_scoring,
                quiet=quiet
            )
            return  # Augmentation is complete
        
        else:
            # **GENERATION FLOW**: Create basic BOM, then enrich it
            if base_sbom_path and not quiet:
                print(f"   • Warning: Base SBOM not found at {base_sbom_path}, building from vulnerabilities only")
            
            if not quiet:
                print(f"   • Creating basic SBOM structure")
            
            # Build basic BOM structure (no enrichment)
            start_time = datetime.utcnow()
            
            cyclonedx_bom = _build_basic_cyclonedx_bom(
                vulnerabilities,
                scan_code,
                all_components
            )
            
            # Add basic vulnerabilities (no enrichment)
            _add_vulnerabilities_to_bom(
                bom=cyclonedx_bom,
                vulnerabilities=vulnerabilities,
                quiet=quiet
            )
            
            # Add basic metadata
            _add_basic_metadata(
                cyclonedx_bom,
                scan_code,
                nvd_enrichment,
                epss_enrichment,
                cisa_kev_enrichment
            )
            
            # Serialize basic BOM to JSON
            json_serializer = JsonV1Dot6(cyclonedx_bom)
            basic_bom_json = json.loads(json_serializer.output_as_string())
            
            # Create a temporary file for the basic BOM
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                json.dump(basic_bom_json, temp_file, indent=2)
                temp_sbom_path = temp_file.name
            
            try:
                if not quiet:
                    print(f"   • Handing off to enrichment pipeline")
                
                # Hand off to enrichment pipeline
                from .cyclonedx_enrichment import augment_cyclonedx_sbom_from_file
                augment_cyclonedx_sbom_from_file(
                    sbom_path=temp_sbom_path,
                    filepath=filepath,
                    scan_code=scan_code,
                    external_data=external_data,
                    nvd_enrichment=nvd_enrichment,
                    epss_enrichment=epss_enrichment,
                    cisa_kev_enrichment=cisa_kev_enrichment,
                    enable_dynamic_risk_scoring=enable_dynamic_risk_scoring,
                    quiet=quiet
                )
                
                build_time = (datetime.utcnow() - start_time).total_seconds()
                logger.debug(f"BOM generation and enrichment completed in {build_time:.2f} seconds")
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_sbom_path)
                except OSError:
                    pass
        
        if not quiet:
            print(f"   • CycloneDX SBOM saved to: {filepath}")
        
    except (IOError, OSError) as e:
        if not quiet:
            print(f"\nWarning: Failed to save CycloneDX results to {filepath}: {e}")
        raise


def _build_basic_cyclonedx_bom(
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    all_components: Optional[List[Dict[str, Any]]] = None
) -> Bom:
    """
    Build a basic CycloneDX BOM with components from the bootstrapped BOM.
    
    This function now uses the all_components that were already bootstrapped by 
    the export_vulns handler, eliminating duplicate component creation logic.
    """
    # Create the BOM
    bom = Bom()
    
    # Use bootstrapped components if provided
    if all_components:
        component_lookup: Dict[str, Component] = {}
        
        for comp_data in all_components:
            comp_name = comp_data.get("name", "Unknown")
            comp_version = comp_data.get("version", "")
            comp_key = f"{comp_name}:{comp_version}"
            
            if comp_key not in component_lookup:
                component = _create_cyclonedx_component_from_bootstrap_data(comp_data)
                component_lookup[comp_key] = component
                bom.components.add(component)
    else:
        # Fallback: create minimal components from vulnerability data
        # This should rarely be used since all_components should always be provided
        component_lookup: Dict[str, Component] = {}
        
        for vuln in vulnerabilities:
            comp_name = vuln.get("component_name", "Unknown")
            comp_version = vuln.get("component_version", "")
            comp_key = f"{comp_name}:{comp_version}"
            
            if comp_key not in component_lookup:
                # Create minimal component without enrichment
                component = Component(
                    name=comp_name,
                    version=comp_version,
                    type=ComponentType.LIBRARY,
                    bom_ref=f"pkg:{comp_name}@{comp_version}"
                )
                component_lookup[comp_key] = component
                bom.components.add(component)
    
    return bom


def _create_cyclonedx_component_from_bootstrap_data(comp_data: Dict[str, Any]) -> Component:
    """Create a CycloneDX Component from bootstrapped component data with all enrichment."""
    name = comp_data.get("name", "Unknown")
    version = comp_data.get("version", "")
    
    # Create basic component
    component = Component(
        name=name,
        version=version,
        type=ComponentType.LIBRARY,
        bom_ref=f"pkg:{name}@{version}"
    )
    
    # Get enrichment data from cache (already fetched by bootstrap_bom.py)
    component_info = get_component_info(name, version)
    
    if component_info:
        # Add CPE if available
        if component_info.get("cpe"):
            component.cpe = component_info["cpe"]
        
        # Add PURL from API response
        if component_info.get("purl"):
            try:
                component.purl = PackageURL.from_string(component_info["purl"])
            except Exception:
                pass
        
        # Add external references
        if component_info.get("url"):
            try:
                component.external_references.add(
                    ExternalReference(
                        type=ExternalReferenceType.WEBSITE,
                        url=component_info["url"]
                    )
                )
            except Exception:
                pass
        
        if component_info.get("download_url"):
            try:
                component.external_references.add(
                    ExternalReference(
                        type=ExternalReferenceType.DISTRIBUTION,
                        url=component_info["download_url"]
                    )
                )
            except Exception:
                pass
        
        if component_info.get("supplier_url"):
            try:
                component.external_references.add(
                    ExternalReference(
                        type=ExternalReferenceType.WEBSITE,
                        url=component_info["supplier_url"]
                    )
                )
            except Exception:
                pass
        
        if component_info.get("community_url"):
            try:
                component.external_references.add(
                    ExternalReference(
                        type=ExternalReferenceType.WEBSITE,
                        url=component_info["community_url"]
                    )
                )
            except Exception:
                pass
        
        # Add description if available
        if component_info.get("description"):
            component.description = component_info["description"]
        
        # Add license information
        if component_info.get("license_identifier") or component_info.get("license_name"):
            license_repo = LicenseRepository()
            
            # Create DisjunctiveLicense with appropriate fields
            license_obj = DisjunctiveLicense(
                id=component_info.get("license_identifier"),
                name=component_info.get("license_name")
            )
            license_repo.add(license_obj)
            component.licenses = license_repo
    
    return component


def _add_vulnerabilities_to_bom(
    bom: Bom,
    vulnerabilities: List[Dict[str, Any]],
    quiet: bool = False
) -> None:
    """
    Add basic vulnerabilities to a CycloneDX BOM without enrichment.
    
    This function creates the basic vulnerability structure only.
    Enrichment (external data, dynamic risk scoring) is handled separately.
    
    Args:
        bom: The CycloneDX BOM to add vulnerabilities to
        vulnerabilities: List of vulnerabilities in internal format
        quiet: Whether to suppress output messages
    """
    if not vulnerabilities:
        if not quiet:
            print("   • No vulnerabilities to add")
        return
    
    # Process vulnerabilities in batches for better performance
    batch_size = 500
    total_vulnerabilities = len(vulnerabilities)
    
    if not quiet and total_vulnerabilities > batch_size:
        print(f"   • Processing {total_vulnerabilities} vulnerabilities in batches of {batch_size}")
    
    added_count = 0
    for i in range(0, total_vulnerabilities, batch_size):
        batch = vulnerabilities[i:i + batch_size]
        
        for vuln in batch:
            try:
                # Create basic vulnerability (no enrichment)
                basic_vuln = _create_basic_cyclonedx_vulnerability(vuln)
                
                # Add to BOM
                bom.vulnerabilities.add(basic_vuln)
                added_count += 1
                
            except Exception as e:
                logger.error(f"Failed to create vulnerability {vuln.get('cve', 'UNKNOWN')}: {e}")
                continue
        
        if not quiet and total_vulnerabilities > batch_size:
            progress = min(i + batch_size, total_vulnerabilities)
            print(f"   • Processed {progress}/{total_vulnerabilities} vulnerabilities")
    
    if not quiet:
        print(f"   • Added {added_count} basic vulnerabilities")


def _create_basic_cyclonedx_vulnerability(vuln: Dict[str, Any]) -> Vulnerability:
    """
    Create a basic CycloneDX Vulnerability object without enrichment.
    
    This creates the minimal vulnerability structure required for a valid SBOM.
    External enrichment (NVD, EPSS, CISA KEV) and dynamic risk scoring
    are handled separately by the enrichment pipeline.
    """
    cve = vuln.get("cve", "UNKNOWN")
    component_name = vuln.get("component_name", "Unknown")
    component_version = vuln.get("component_version", "Unknown")
    
    # Create vulnerability with basic information only
    vulnerability = Vulnerability(
        bom_ref=f"vuln-{cve}-{component_name}-{component_version}",
        id=cve if cve != "UNKNOWN" else f"UNKNOWN-{vuln.get('id', 'unknown')}"
    )
    
    # Add affects relationship to link vulnerability to component
    component_bom_ref = f"pkg:{component_name}@{component_version}"
    vulnerability.affects = [BomTarget(ref=component_bom_ref)]
    
    # Add basic description (will be enhanced by enrichment if NVD data available)
    vulnerability.description = f"Security vulnerability affecting {component_name} version {component_version}"
    
    # Add basic CVSS rating if available
    base_score = vuln.get("base_score")
    if base_score and base_score != "N/A":
        try:
            score_value = float(base_score)
            rating = VulnerabilityRating(
                source=None,
                score=score_value,
                severity=_map_severity_to_cyclonedx(vuln.get("severity", "UNKNOWN")),
                method=VulnerabilityScoreSource.CVSS_V3,
            )
            vulnerability.ratings = [rating]
        except (ValueError, TypeError):
            pass
    
    # Add basic VEX analysis if available
    _add_vex_analysis(vulnerability, vuln)
    
    return vulnerability


def _map_severity_to_cyclonedx(severity: str) -> "VulnerabilitySeverity":
    """Map string severity to CycloneDX VulnerabilitySeverity enum."""
    severity_map = {
        "critical": VulnerabilitySeverity.CRITICAL,
        "high": VulnerabilitySeverity.HIGH,
        "medium": VulnerabilitySeverity.MEDIUM,
        "low": VulnerabilitySeverity.LOW,
        "info": VulnerabilitySeverity.INFO,
        "informational": VulnerabilitySeverity.INFO,
        "none": VulnerabilitySeverity.NONE,
    }
    return severity_map.get(severity.lower(), VulnerabilitySeverity.UNKNOWN)


def _add_vex_analysis(vulnerability: Vulnerability, vuln: Dict[str, Any]) -> None:
    """Add VEX analysis to vulnerability if available."""
    try:
        from cyclonedx.model.impact_analysis import (
            ImpactAnalysisState,
            ImpactAnalysisJustification,
            ImpactAnalysisResponse,
        )
        from cyclonedx.model.vulnerability import VulnerabilityAnalysis

        vex_status = (vuln.get("vuln_exp_status") or "").lower()
        vex_justification = (vuln.get("vuln_exp_justification") or "").lower()
        vex_response = vuln.get("vuln_exp_response") or []
        if isinstance(vex_response, str):
            vex_response = [vex_response]

        analysis_kwargs = {}

        # Map status → ImpactAnalysisState
        state_enum = next((s for s in ImpactAnalysisState if s.value == vex_status), None)
        if state_enum:
            analysis_kwargs["state"] = state_enum

        # Map justification
        just_enum = next((j for j in ImpactAnalysisJustification if j.value == vex_justification), None)
        if just_enum:
            analysis_kwargs["justification"] = just_enum

        # Map responses
        mapped_responses = []
        if vex_response:
            response_items = []
            if isinstance(vex_response, str):
                response_items = [r.strip() for r in vex_response.split(',')]
            elif isinstance(vex_response, list):
                response_items = vex_response
            
            for item in response_items:
                item_lower = str(item).lower().strip()
                enum_match = next((r for r in ImpactAnalysisResponse if r.value == item_lower), None)
                if enum_match:
                    mapped_responses.append(enum_match)
        
        if mapped_responses:
            analysis_kwargs["responses"] = mapped_responses

        # Detail (if present)
        vex_details = vuln.get("vuln_exp_details") or vuln.get("vuln_exp_detail")
        if vex_details:
            analysis_kwargs["detail"] = vex_details

        if analysis_kwargs:
            vulnerability.analysis = VulnerabilityAnalysis(**analysis_kwargs)

    except Exception:
        # Best-effort; don't fail report generation if mapping fails
        pass


def _add_basic_metadata(
    bom: Bom,
    scan_code: str,
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool
    ) -> None:
    """Add basic metadata to the BOM (enrichment metadata added later)."""
    properties = []
    
    # Scan code
    properties.append(Property(name="workbench_scan_code", value=scan_code))
    
    # Enrichment flags (for enrichment pipeline reference)
    properties.append(Property(name="nvd_enrichment", value=str(nvd_enrichment)))
    properties.append(Property(name="epss_enrichment", value=str(epss_enrichment)))
    properties.append(Property(name="cisa_kev_enrichment", value=str(cisa_kev_enrichment)))
    
    # Generation metadata
    properties.append(Property(name="generation_timestamp", value=datetime.utcnow().isoformat() + "Z"))
    properties.append(Property(name="bom_type", value="vulnerable_only"))
    
    bom.properties = properties




