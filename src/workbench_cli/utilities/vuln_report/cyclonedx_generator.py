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

# Import shared enrichment functionality
from .cyclonedx_enrichment import (
    augment_cyclonedx_sbom_from_file,
    _validate_external_data,
)

# Added get_component_info for richer component metadata
from .bootstrap_bom import get_component_info
from .risk_adjustments import calculate_dynamic_risk, RiskAdjustment


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
    Save vulnerability results in CycloneDX format.
    
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

        # Choose between augmentation and building approach
        if base_sbom_path and os.path.exists(base_sbom_path):
            # Use SBOM augmentation approach (maintains original format)
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
            return  # Exit early, augmentation is complete
        else:
            # Use BOM generation approach (creates CycloneDX 1.6)
            if base_sbom_path and not quiet:
                print(f"   • Warning: Base SBOM not found at {base_sbom_path}, building from vulnerabilities only")
            
            # Build basic BOM structure
            start_time = datetime.utcnow()
            
            cyclonedx_data = _build_basic_cyclonedx_bom(
                vulnerabilities,
                scan_code,
                all_components
            )
            
            # Add vulnerabilities with enrichment directly
            _add_vulnerabilities_to_bom(
                bom=cyclonedx_data,
                vulnerabilities=vulnerabilities,
                external_data=external_data,
                enable_dynamic_risk_scoring=enable_dynamic_risk_scoring,
                quiet=quiet
            )
            
            # Add enrichment metadata
            _add_enrichment_metadata(
                cyclonedx_data,
                scan_code,
                nvd_enrichment,
                epss_enrichment,
                cisa_kev_enrichment
            )
            
            build_time = (datetime.utcnow() - start_time).total_seconds()
            logger.debug(f"BOM building and enrichment completed in {build_time:.2f} seconds")
        
        # Use CycloneDX JSON serializer with optimized output
        json_serializer = JsonV1Dot6(cyclonedx_data)
        
        # Parse the JSON to reorder fields (put schema info at the beginning)
        cyclonedx_json = json.loads(json_serializer.output_as_string())
        
        # Create ordered dictionary with schema fields first
        ordered_json = _optimize_cyclonedx_output(cyclonedx_json)
        
        # Use memory-efficient JSON writing for large files
        _write_cyclonedx_json(ordered_json, filepath)
            
        if not quiet:
            print(f"   • CycloneDX SBOM saved to: {filepath}")
        
    except (IOError, OSError) as e:
        if not quiet:
            print(f"\nWarning: Failed to save CycloneDX results to {filepath}: {e}")
        raise


def _optimize_cyclonedx_output(cyclonedx_json: Dict[str, Any]) -> Dict[str, Any]:
    """Optimize CycloneDX JSON output for better readability and performance."""
    # Create ordered dictionary with schema fields first
    ordered_json = {}
    
    # Schema fields first (for better readability and convention compliance)
    if "$schema" in cyclonedx_json:
        ordered_json["$schema"] = cyclonedx_json["$schema"]
    if "bomFormat" in cyclonedx_json:
        ordered_json["bomFormat"] = cyclonedx_json["bomFormat"]
    if "specVersion" in cyclonedx_json:
        ordered_json["specVersion"] = cyclonedx_json["specVersion"]
    
    # Add all other fields in their original order
    for key, value in cyclonedx_json.items():
        if key not in ["$schema", "bomFormat", "specVersion"]:
            ordered_json[key] = value
    
    return ordered_json


def _write_cyclonedx_json(data: Dict[str, Any], filepath: str) -> None:
    """Write CycloneDX JSON with memory-efficient streaming for large files."""
    import json
    
    # Estimate size to determine writing strategy
    estimated_size = len(str(data))
    
    # Use streaming for large files (>10MB estimated)
    if estimated_size > 10 * 1024 * 1024:
        logger.info(f"Writing large CycloneDX file ({estimated_size / (1024*1024):.1f}MB) with streaming")
        
        # Create a backup if the file exists
        if os.path.exists(filepath):
            backup_path = f"{filepath}.backup"
            try:
                import shutil
                shutil.copy2(filepath, backup_path)
                logger.info(f"Created backup at {backup_path}")
            except Exception as e:
                logger.warning(f"Could not create backup: {e}")
        
        # Write with streaming
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    else:
        # Standard writing for smaller files
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


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
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    enable_dynamic_risk_scoring: bool = True,
    quiet: bool = False
) -> None:
    """
    Add vulnerabilities to a CycloneDX BOM with enrichment and dynamic risk scoring.
    
    Args:
        bom: The CycloneDX BOM to add vulnerabilities to
        vulnerabilities: List of vulnerabilities in internal format
        external_data: Pre-fetched external enrichment data (optional)
        enable_dynamic_risk_scoring: Whether to apply dynamic risk scoring
        quiet: Whether to suppress output messages
    """
    if not vulnerabilities:
        if not quiet:
            print("   • No vulnerabilities to add")
        return
    
    # Validate external data
    external_data = _validate_external_data(external_data)
    
    # Process vulnerabilities in batches for better performance
    batch_size = 500
    total_vulnerabilities = len(vulnerabilities)
    
    if not quiet and total_vulnerabilities > batch_size:
        print(f"   • Processing {total_vulnerabilities} vulnerabilities in batches of {batch_size}")
    
    enriched_count = 0
    for i in range(0, total_vulnerabilities, batch_size):
        batch = vulnerabilities[i:i + batch_size]
        
        for vuln in batch:
            try:
                cve = vuln.get("cve", "UNKNOWN")
                ext_data = external_data.get(cve, {})
                
                # Calculate dynamic risk if enabled
                dynamic_risk_adjustment = None
                if enable_dynamic_risk_scoring and cve != "UNKNOWN":
                    try:
                        dynamic_risk_adjustment = calculate_dynamic_risk(vuln, ext_data)
                    except Exception as e:
                        logger.warning(f"Failed to calculate dynamic risk for {cve}: {e}")
                
                # Create enriched vulnerability
                enriched_vuln = _create_cyclonedx_vulnerability(
                    vuln, ext_data, dynamic_risk_adjustment
                )
                
                # Add to BOM
                bom.vulnerabilities.add(enriched_vuln)
                enriched_count += 1
                
            except Exception as e:
                logger.error(f"Failed to create vulnerability {vuln.get('cve', 'UNKNOWN')}: {e}")
                continue
        
        if not quiet and total_vulnerabilities > batch_size:
            progress = min(i + batch_size, total_vulnerabilities)
            print(f"   • Processed {progress}/{total_vulnerabilities} vulnerabilities")
    
    if not quiet:
        print(f"   • Added {enriched_count} vulnerabilities with enrichment")


def _create_cyclonedx_vulnerability(
    vuln: Dict[str, Any], 
    ext_data: Dict[str, Any],
    dynamic_risk_adjustment: Optional[RiskAdjustment] = None
) -> Vulnerability:
    """Create a CycloneDX Vulnerability object from vulnerability data."""
    from .cve_data_gathering import build_cvss_vector
    
    cve = vuln.get("cve", "UNKNOWN")
    component_name = vuln.get("component_name", "Unknown")
    component_version = vuln.get("component_version", "Unknown")
    
    # Create vulnerability
    vulnerability = Vulnerability(
        bom_ref=f"vuln-{cve}-{component_name}-{component_version}",
        id=cve if cve != "UNKNOWN" else f"UNKNOWN-{vuln.get('id', 'unknown')}"
    )
    
    # Add affects relationship to link vulnerability to component
    component_bom_ref = f"pkg:{component_name}@{component_version}"
    vulnerability.affects = [BomTarget(ref=component_bom_ref)]
    
    # Add description from NVD if available
    if ext_data.get("nvd_description"):
        vulnerability.description = ext_data["nvd_description"]
    else:
        vulnerability.description = f"Security vulnerability affecting {component_name} version {component_version}"
    
    # Add ratings
    ratings = []
    
    # Base CVSS rating
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
            
            # Add CVSS vector if available
            cvss_vector = ext_data.get("full_cvss_vector") or build_cvss_vector(vuln)
            if cvss_vector and cvss_vector != "CVSS vector not available":
                rating.vector = cvss_vector
            
            ratings.append(rating)
        except (ValueError, TypeError):
            pass
    
    # EPSS rating
    epss_score = ext_data.get("epss_score")
    if epss_score is not None and epss_score > 0.0:
        epss_rating = VulnerabilityRating(
            source=VulnerabilitySource(name="EPSS", url="https://www.first.org/epss"),
            score=epss_score,
            method=VulnerabilityScoreSource.OTHER,
        )
        ratings.append(epss_rating)
    
    # Apply dynamic risk adjustment if provided
    if dynamic_risk_adjustment:
        try:
            from .cyclonedx_enrichment import apply_dynamic_risk_to_cyclonedx_vuln
            # Convert to dict format for the function
            vuln_dict = {"ratings": []}
            for rating in ratings:
                vuln_dict["ratings"].append({
                    "score": rating.score,
                    "severity": rating.severity.value if hasattr(rating.severity, 'value') else str(rating.severity),
                    "method": rating.method.value if hasattr(rating.method, 'value') else str(rating.method),
                    "source": {"name": rating.source.name, "url": rating.source.url} if rating.source else None
                })
            
            # Apply dynamic risk
            apply_dynamic_risk_to_cyclonedx_vuln(vuln_dict, dynamic_risk_adjustment)
            
            # Update ratings from the modified dict
            if vuln_dict.get("ratings"):
                ratings = []
                for rating_dict in vuln_dict["ratings"]:
                    source = None
                    if rating_dict.get("source"):
                        source = VulnerabilitySource(
                            name=rating_dict["source"]["name"],
                            url=rating_dict["source"]["url"]
                        )
                    
                    method = VulnerabilityScoreSource.OTHER
                    if rating_dict.get("method"):
                        method_str = rating_dict["method"].lower()
                        if "cvss" in method_str:
                            method = VulnerabilityScoreSource.CVSS_V3
                    
                    severity = VulnerabilitySeverity.UNKNOWN
                    if rating_dict.get("severity"):
                        severity = _map_severity_to_cyclonedx(rating_dict["severity"])
                    
                    rating = VulnerabilityRating(
                        source=source,
                        score=rating_dict.get("score", 0.0),
                        severity=severity,
                        method=method,
                    )
                    ratings.append(rating)
                    
        except Exception as e:
            logger.warning(f"Failed to apply dynamic risk adjustment: {e}")
    
    vulnerability.ratings = ratings
    
    # Add VEX analysis if available
    _add_vex_analysis(vulnerability, vuln)
    
    # Add external references
    _add_external_references(vulnerability, cve, ext_data)
    
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


def _add_external_references(vulnerability: Vulnerability, cve: str, ext_data: Dict[str, Any]) -> None:
    """Add external references to vulnerability."""
    from sortedcontainers import SortedSet
    
    # Ensure external_references structure exists
    if not getattr(vulnerability, "external_references", None):
        vulnerability.external_references = SortedSet()

    # Primary NVD advisory
    if cve != "UNKNOWN":
        try:
            vulnerability.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.ADVISORIES,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    comment="NVD"
                )
            )
        except Exception:
            pass

    # Additional NVD references
    if ext_data.get("nvd_references"):
        tag_map = {
            "Vendor Advisory": ExternalReferenceType.ADVISORIES,
            "Patch": ExternalReferenceType.PATCH if hasattr(ExternalReferenceType, "PATCH") else ExternalReferenceType.OTHER,
            "Exploit": ExternalReferenceType.EXPLOITABILITY_STATEMENT,
            "Release Notes": ExternalReferenceType.RELEASE_NOTES,
        }
        
        for ref in ext_data["nvd_references"]:
            url = ref.get("url")
            if not url:
                continue
            tags = ref.get("tags", [])
            matched_type = None
            for t in tags:
                if t in tag_map:
                    matched_type = tag_map[t]
                    break
            if not matched_type:
                matched_type = ExternalReferenceType.OTHER
            try:
                vulnerability.external_references.add(
                    ExternalReference(
                        type=matched_type,
                        url=url,
                        comment=ref.get("source", "")
                    )
                )
            except Exception:
                pass


def _add_enrichment_metadata(
    bom: Bom,
    scan_code: str,
    nvd_enrichment: bool,
    epss_enrichment: bool,
    cisa_kev_enrichment: bool
    ) -> None:
    """Add enrichment metadata to the BOM."""
    properties = []
    
    # Scan code
    properties.append(Property(name="workbench_scan_code", value=scan_code))
    
    # Enrichment flags
    properties.append(Property(name="nvd_enrichment", value=str(nvd_enrichment)))
    properties.append(Property(name="epss_enrichment", value=str(epss_enrichment)))
    properties.append(Property(name="cisa_kev_enrichment", value=str(cisa_kev_enrichment)))
    
    # Generation metadata
    properties.append(Property(name="generation_timestamp", value=datetime.utcnow().isoformat() + "Z"))
    
    bom.properties = properties

def _validate_cyclonedx_sbom(sbom_json: Dict[str, Any], sbom_path: str) -> None:
    """
    Validate CycloneDX SBOM structure and content.
    
    Args:
        sbom_json: Parsed SBOM JSON data
        sbom_path: Path to SBOM file (for error reporting)
        
    Raises:
        ValueError: If SBOM structure is invalid
    """
    # Check required top-level fields
    required_fields = ["bomFormat", "specVersion"]
    missing_fields = [field for field in required_fields if field not in sbom_json]
    if missing_fields:
        raise ValueError(f"Invalid SBOM structure: missing required fields {missing_fields} in {sbom_path}")
    
    # Validate BOM format
    bom_format = sbom_json.get("bomFormat", "").lower()
    if bom_format != "cyclonedx":
        raise ValueError(f"Invalid SBOM format: expected 'CycloneDX', got '{sbom_format}' in {sbom_path}")
    
    # Validate spec version
    spec_version = sbom_json.get("specVersion", "")
    supported_versions = ["1.4", "1.5", "1.6"]
    if spec_version not in supported_versions:
        logger.warning(f"SBOM spec version '{spec_version}' may not be fully supported. Supported versions: {supported_versions}")
    
    # Validate components structure if present
    components = sbom_json.get("components", [])
    if not isinstance(components, list):
        raise ValueError(f"Invalid components structure: expected list, got {type(components)} in {sbom_path}")
    
    # Validate vulnerabilities structure if present
    vulnerabilities = sbom_json.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError(f"Invalid vulnerabilities structure: expected list, got {type(vulnerabilities)} in {sbom_path}")
    
    # Validate component structure (sample validation)
    invalid_components = []
    for i, comp in enumerate(components[:10]):  # Check first 10 components for performance
        if not isinstance(comp, dict):
            invalid_components.append(f"Component {i}: not a dictionary")
            continue
        
        if not comp.get("name"):
            invalid_components.append(f"Component {i}: missing name")
    
    if invalid_components:
        raise ValueError(f"Invalid component structure in {sbom_path}: {'; '.join(invalid_components)}")
    
    # Validate vulnerability structure (sample validation)
    invalid_vulns = []
    for i, vuln in enumerate(vulnerabilities[:10]):  # Check first 10 vulnerabilities for performance
        if not isinstance(vuln, dict):
            invalid_vulns.append(f"Vulnerability {i}: not a dictionary")
            continue
        
        if not vuln.get("id"):
            invalid_vulns.append(f"Vulnerability {i}: missing id")
    
    if invalid_vulns:
        raise ValueError(f"Invalid vulnerability structure in {sbom_path}: {'; '.join(invalid_vulns)}")




