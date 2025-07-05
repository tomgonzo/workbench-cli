"""
CycloneDX vulnerability report generation.

This module provides functionality to convert vulnerability data from the Workbench API
into CycloneDX format, which is a software bill of materials (SBOM) format that includes
vulnerability information.

The module supports two approaches:
1. Building a new SBOM from vulnerability data (current approach)
2. Augmenting an existing CycloneDX SBOM with vulnerability data (NEW)
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
    PackageURL = Any
    BomTarget = Any
    Property = Any
    CYCLONEDX_AVAILABLE = False

from .component_enrichment import _detect_package_ecosystem
from .risk_adjustments import calculate_dynamic_risk, risk_level_to_cyclonedx_severity


def save_vulns_to_cyclonedx(
    filepath: str,
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    api_timeout: int = 30,
    enable_vex_suppression: bool = True,
    quiet: bool = False,
    base_sbom_path: Optional[str] = None
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
        api_timeout: API timeout used for enrichment
        enable_vex_suppression: Whether VEX suppression is enabled
        quiet: Whether to suppress output messages
        base_sbom_path: Path to existing CycloneDX SBOM to augment (optional)
        
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
        
        if base_sbom_path and os.path.exists(base_sbom_path):
            # NEW: Augment existing SBOM approach
            cyclonedx_data = build_cyclonedx_from_components(
                base_sbom_path,
                vulnerabilities, 
                scan_code, 
                external_data,
                nvd_enrichment,
                epss_enrichment,
                cisa_kev_enrichment,
                enable_vex_suppression
            )
            if not quiet:
                print(f"Augmented existing SBOM from: {base_sbom_path}")
        else:
            # Original: Build new SBOM approach
            cyclonedx_data = convert_vulns_to_cyclonedx(
                vulnerabilities, 
                scan_code, 
                external_data,
                nvd_enrichment,
                epss_enrichment,
                cisa_kev_enrichment,
                enable_vex_suppression
            )
            if base_sbom_path and not quiet:
                print(f"Warning: Base SBOM not found at {base_sbom_path}, creating new SBOM")
        
        # Use CycloneDX JSON serializer
        json_serializer = JsonV1Dot6(cyclonedx_data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(json_serializer.output_as_string())
            
        if not quiet:
            print(f"Saved CycloneDX SBOM to: {filepath}")
        
    except (IOError, OSError) as e:
        if not quiet:
            print(f"\nWarning: Failed to save CycloneDX results to {filepath}: {e}")
        raise


def convert_vulns_to_cyclonedx(
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    enable_vex_suppression: bool = True
) -> Bom:
    """
    Convert vulnerability data to CycloneDX BOM format.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries from the Workbench API
        scan_code: The scan code for reference
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was enabled
        epss_enrichment: Whether EPSS enrichment was enabled
        cisa_kev_enrichment: Whether CISA KEV enrichment was enabled
        enable_vex_suppression: Whether VEX suppression is enabled
        
    Returns:
        CycloneDX BOM object containing vulnerability information
    """
    if not CYCLONEDX_AVAILABLE:
        raise ImportError("CycloneDX support requires the 'cyclonedx-python-lib' package which should be installed automatically")
    
    if external_data is None:
        external_data = {}
    
    # Create BOM
    bom = Bom()
    bom.metadata.timestamp = datetime.utcnow()
    
    # Create components and vulnerabilities
    components = {}
    vulnerabilities_list = []
    
    for vuln in vulnerabilities:
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        cve = vuln.get("cve", "UNKNOWN")
        
        # Create component if not exists
        component_key = f"{component_name}@{component_version}"
        if component_key not in components:
            ecosystem = _detect_package_ecosystem(component_name, component_version)
            
            try:
                purl = PackageURL(
                    type=ecosystem,
                    name=component_name,
                    version=component_version
                )
                component = Component(
                    name=component_name,
                    version=component_version,
                    type=ComponentType.LIBRARY,
                    purl=purl
                )
            except Exception:
                # Fallback if PackageURL creation fails
                component = Component(
                    name=component_name,
                    version=component_version,
                    type=ComponentType.LIBRARY
                )
            
            components[component_key] = component
            bom.components.add(component)
        
        # Create vulnerability
        vulnerability = _create_cyclonedx_vulnerability(vuln, external_data.get(cve, {}))
        vulnerabilities_list.append(vulnerability)
        
        # Add vulnerability to BOM
        bom.vulnerabilities.add(vulnerability)
    
    return bom


# NEW builder function that creates a fresh BOM using components & dependencies from an existing SBOM

def build_cyclonedx_from_components(
    base_sbom_path: str,
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    enable_vex_suppression: bool = True
) -> Bom:
    """Build a brand-new CycloneDX 1.6 BOM while retaining component list & dependency graph from
    a pre-existing Workbench SBOM (typically 1.5).  This is the preferred middle-ground refactor –
    we ignore legacy metadata quirks and simply copy components & edges, then inject enriched
    vulnerability data.
    """

    if not CYCLONEDX_AVAILABLE:
        raise ImportError("CycloneDX support requires the 'cyclonedx-python-lib' package")

    if external_data is None:
        external_data = {}

    # 1. Load the source SBOM (expected JSON)
    try:
        with open(base_sbom_path, "r", encoding="utf-8") as f:
            source_json = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Base SBOM not found at: {base_sbom_path}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in base SBOM {base_sbom_path}: {exc}")

    # 2. Start a fresh BOM (defaults to latest, i.e. 1.6)
    new_bom: Bom = Bom()
    new_bom.metadata.timestamp = datetime.utcnow()

    # 3. Copy components – retain basic identity info plus purl & bom-ref
    component_lookup: Dict[str, Component] = {}

    for comp_data in source_json.get("components", []):
        name = comp_data.get("name", "Unknown")
        version = comp_data.get("version", "")
        comp_type_raw = comp_data.get("type", "library").upper()
        comp_type = ComponentType.LIBRARY
        try:
            comp_type = ComponentType[comp_type_raw]
        except Exception:
            pass  # default stays LIBRARY

        # Coerce bom-ref to pure string (handles object refs in legacy SBOMs)
        bom_ref_val = str(comp_data.get("bom-ref", f"{name}_{version}"))

        # Attempt to parse PURL
        purl_obj = None
        if comp_data.get("purl"):
            try:
                purl_obj = PackageURL.from_string(comp_data["purl"])
            except Exception:
                purl_obj = None

        component = Component(
            name=name,
            version=version,
            type=comp_type,
            purl=purl_obj,
            bom_ref=bom_ref_val,
        )

        # Best-effort: copy licenses if an SPDX id is present
        if comp_data.get("licenses"):
            try:
                from cyclonedx.model.license import LicenseChoice, DisjunctiveLicenseSet, License, SpdxLicense

                lic_objs = []
                for lic in comp_data["licenses"]:
                    lic_id = lic.get("license", {}).get("id")
                    if lic_id:
                        lic_objs.append(SpdxLicense(lic_id))
                if lic_objs:
                    component.licenses = LicenseChoice(DisjunctiveLicenseSet(licenses=lic_objs))
            except Exception:
                pass  # ignore license copy issues

        # Supplier and other metadata are skipped to keep implementation lean

        new_bom.components.add(component)

        # lookup keys for later vuln matching
        component_lookup[f"{name.lower()}@{version.lower()}"] = component
        component_lookup[name.lower()] = component
        if purl_obj:
            component_lookup[str(purl_obj)] = component
            component_lookup[purl_obj.name.lower()] = component

    # 4. Copy dependency graph edges (if present)
    if source_json.get("dependencies"):
        try:
            from cyclonedx.model.dependency import Dependency
            for dep in source_json["dependencies"]:
                ref_id = str(dep.get("ref"))
                depends_on = [str(d) for d in dep.get("dependsOn", [])]
                new_bom.dependencies.add(Dependency(ref=ref_id, depends_on=set(depends_on)))
        except Exception:
            # If dependency model not available, silently skip – components are still present
            pass

    # 5. Process vulnerabilities – enrich & attach
    unmatched_vulns: List[Dict[str, Any]] = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "UNKNOWN")
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")

        match_key = f"{component_name.lower()}@{component_version.lower()}"
        matched_component = component_lookup.get(match_key) or component_lookup.get(component_name.lower())

        if not matched_component:
            # create minimal component for edge case
            ecosystem = _detect_package_ecosystem(component_name, component_version)
            try:
                purl_tmp = PackageURL(type=ecosystem, name=component_name, version=component_version)
            except Exception:
                purl_tmp = None
            matched_component = Component(name=component_name, version=component_version, type=ComponentType.LIBRARY, purl=purl_tmp)
            new_bom.components.add(matched_component)
            component_lookup[match_key] = matched_component

        vuln_obj = _create_cyclonedx_vulnerability(vuln, external_data.get(cve, {}))
        vuln_obj.affects = [BomTarget(ref=str(matched_component.bom_ref))]
        new_bom.vulnerabilities.add(vuln_obj)

    # 6. Annotate metadata to indicate augmentation & counts
    props = [
        Property(name="augmented_with_vulnerabilities", value="true"),
        Property(name="augmentation_timestamp", value=datetime.utcnow().isoformat() + "Z"),
        Property(name="vulnerability_count", value=str(len(vulnerabilities))),
        Property(name="scan_code", value=scan_code),
    ]
    try:
        new_bom.metadata.properties.update(props)
    except Exception:
        # Some library versions require .properties to be initialised first
        if not getattr(new_bom.metadata, "properties", None):
            from sortedcontainers import SortedSet  # type: ignore
            new_bom.metadata.properties = SortedSet()
        new_bom.metadata.properties.update(props)

    return new_bom


def augment_existing_cyclonedx_sbom(
    base_sbom_path: str,
    vulnerabilities: List[Dict[str, Any]],
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    enable_vex_suppression: bool = True
) -> Bom:
    """
    Augment an existing CycloneDX SBOM with vulnerability data.
    
    This approach preserves all the rich component metadata from the existing SBOM
    (licenses, suppliers, dependencies, etc.) while adding vulnerability information.
    
    Args:
        base_sbom_path: Path to the existing CycloneDX SBOM file
        vulnerabilities: List of vulnerability dictionaries from the API
        scan_code: The scan code for reference
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was enabled
        epss_enrichment: Whether EPSS enrichment was enabled
        cisa_kev_enrichment: Whether CISA KEV enrichment was enabled
        enable_vex_suppression: Whether VEX suppression is enabled
        
    Returns:
        Augmented CycloneDX BOM object with vulnerability information
        
    Raises:
        FileNotFoundError: If the base SBOM file doesn't exist
        ValueError: If the base SBOM cannot be parsed
    """
    if not CYCLONEDX_AVAILABLE:
        raise ImportError("CycloneDX support requires the 'cyclonedx-python-lib' package")
    
    if external_data is None:
        external_data = {}
    
    # Load existing SBOM
    try:
        with open(base_sbom_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        # Create a new BOM and populate it with existing data
        existing_bom = Bom()
        
        # Set metadata from existing SBOM
        if 'metadata' in json_data:
            metadata = json_data['metadata']
            if 'timestamp' in metadata:
                try:
                    existing_bom.metadata.timestamp = datetime.fromisoformat(metadata['timestamp'].replace('Z', '+00:00'))
                except:
                    existing_bom.metadata.timestamp = datetime.utcnow()
            else:
                existing_bom.metadata.timestamp = datetime.utcnow()
        
        # Add existing components
        if 'components' in json_data:
            for comp_data in json_data['components']:
                try:
                    component = Component(
                        name=comp_data.get('name', 'Unknown'),
                        version=comp_data.get('version', ''),
                        type=ComponentType.LIBRARY,
                        bom_ref=comp_data.get('bom-ref') or None,
                    )
                    
                    # Set PURL if available
                    if 'purl' in comp_data:
                        try:
                            component.purl = PackageURL.from_string(comp_data['purl'])
                        except:
                            pass  # Skip invalid PURLs
                    
                    # Set bom-ref if available
                    if 'bom-ref' in comp_data:
                        component.bom_ref = comp_data['bom-ref']
                    
                    existing_bom.components.add(component)
                except:
                    # Skip components that can't be parsed
                    continue
        
        # Add existing vulnerabilities
        if 'vulnerabilities' in json_data:
            for vuln_data in json_data['vulnerabilities']:
                try:
                    vulnerability = Vulnerability(
                        bom_ref=vuln_data.get('bom-ref', f"vuln-{vuln_data.get('id', 'unknown')}"),
                        id=vuln_data.get('id', 'UNKNOWN')
                    )
                    
                    # Set description
                    if 'description' in vuln_data:
                        vulnerability.description = vuln_data['description']
                    
                    # Add affects relationships
                    if 'affects' in vuln_data:
                        affects = []
                        for affect in vuln_data['affects']:
                            if 'ref' in affect:
                                affects.append(BomTarget(ref=affect['ref']))
                        if affects:
                            vulnerability.affects = affects
                    
                    existing_bom.vulnerabilities.add(vulnerability)
                except:
                    # Skip vulnerabilities that can't be parsed
                    continue
        
    except FileNotFoundError:
        raise FileNotFoundError(f"Base SBOM file not found: {base_sbom_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in base SBOM file: {e}")
    except Exception as e:
        raise ValueError(f"Failed to parse base SBOM file: {e}")
    
    # Create component lookup for matching vulnerabilities to existing components
    component_lookup = {}
    for component in existing_bom.components:
        # Create multiple lookup keys for flexible matching
        keys = [
            component.name,  # Simple name match
            f"{component.name}@{component.version}" if component.version else component.name,  # Name@version
        ]
        
        # Add PURL-based matching if available
        if component.purl:
            keys.append(str(component.purl))
            keys.append(component.purl.name)  # Just the name part of PURL
        
        for key in keys:
            if key:
                component_lookup[key.lower()] = component
    
    # Process vulnerabilities and match to existing components
    vulnerabilities_to_add = []
    unmatched_vulnerabilities = []
    
    for vuln in vulnerabilities:
        component_name = vuln.get("component_name", "Unknown")
        component_version = vuln.get("component_version", "Unknown")
        cve = vuln.get("cve", "UNKNOWN")
        
        # Try to match vulnerability to existing component
        matched_component = None
        
        # Try different matching strategies
        match_keys = [
            component_name.lower(),
            f"{component_name}@{component_version}".lower(),
            f"{component_name}-{component_version}".lower(),
        ]
        
        for key in match_keys:
            if key in component_lookup:
                matched_component = component_lookup[key]
                break
        
        if matched_component:
            # Create vulnerability and link to existing component
            vulnerability = _create_cyclonedx_vulnerability(vuln, external_data.get(cve, {}))

            # Ensure the bom-ref is a plain string for JSON serialization
            ref_id = matched_component.bom_ref
            if not isinstance(ref_id, str):
                ref_id = str(ref_id)
            
            # Add BOM target to link vulnerability to component
            vulnerability.affects = [BomTarget(ref=ref_id)]
            
            vulnerabilities_to_add.append(vulnerability)
        else:
            # Component not found in existing SBOM
            unmatched_vulnerabilities.append(vuln)
    
    # Add matched vulnerabilities to the BOM
    for vulnerability in vulnerabilities_to_add:
        existing_bom.vulnerabilities.add(vulnerability)
    
    # Handle unmatched vulnerabilities by creating minimal components
    if unmatched_vulnerabilities:
        logger.warning(f"Found {len(unmatched_vulnerabilities)} vulnerabilities for components not in base SBOM")
        
        for vuln in unmatched_vulnerabilities:
            component_name = vuln.get("component_name", "Unknown")
            component_version = vuln.get("component_version", "Unknown")
            cve = vuln.get("cve", "UNKNOWN")
            
            # Create minimal component for unmatched vulnerability
            ecosystem = _detect_package_ecosystem(component_name, component_version)
            
            try:
                purl = PackageURL(
                    type=ecosystem,
                    name=component_name,
                    version=component_version
                )
                component = Component(
                    name=component_name,
                    version=component_version,
                    type=ComponentType.LIBRARY,
                    purl=purl
                )
            except Exception:
                component = Component(
                    name=component_name,
                    version=component_version,
                    type=ComponentType.LIBRARY
                )
            
            # Add component to BOM
            existing_bom.components.add(component)
            
            # Create and add vulnerability
            vulnerability = _create_cyclonedx_vulnerability(vuln, external_data.get(cve, {}))

            # Ensure bom-ref serializes as a string
            ref_id = component.bom_ref if isinstance(component.bom_ref, str) else str(component.bom_ref)
            vulnerability.affects = [BomTarget(ref=ref_id)]
            existing_bom.vulnerabilities.add(vulnerability)
    
    # Update BOM metadata to reflect augmentation
    existing_bom.metadata.timestamp = datetime.utcnow()
    
    # Add properties to indicate this is an augmented SBOM
    # Note: existing_bom.metadata.properties is a SortedSet, so we use update() with Property objects
    properties_to_add = [
        Property(name="augmented_with_vulnerabilities", value="true"),
        Property(name="augmentation_timestamp", value=datetime.utcnow().isoformat() + "Z"),
        Property(name="vulnerability_count", value=str(len(vulnerabilities))),
        Property(name="unmatched_vulnerabilities", value=str(len(unmatched_vulnerabilities))),
        Property(name="scan_code", value=scan_code),
    ]
    
    existing_bom.metadata.properties.update(properties_to_add)
    
    return existing_bom


def _create_cyclonedx_vulnerability(
    vuln: Dict[str, Any], 
    ext_data: Dict[str, Any]
) -> Vulnerability:
    """Create a CycloneDX Vulnerability object from vulnerability data."""
    cve = vuln.get("cve", "UNKNOWN")
    component_name = vuln.get("component_name", "Unknown")
    component_version = vuln.get("component_version", "Unknown")
    
    # Create vulnerability
    vulnerability = Vulnerability(
        bom_ref=f"vuln-{cve}-{component_name}-{component_version}",
        id=cve if cve != "UNKNOWN" else f"UNKNOWN-{vuln.get('id', 'unknown')}"
    )
    
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
                # No specific originating source for this rating
                source=None,
                score=score_value,
                severity=_map_severity_to_cyclonedx(vuln.get("severity", "UNKNOWN")),
                method=VulnerabilityScoreSource.CVSS_V3,
            )
            
            # Add CVSS vector if available
            cvss_vector = ext_data.get("full_cvss_vector") or _build_cvss_vector(vuln)
            if cvss_vector and cvss_vector != "CVSS vector not available":
                rating.vector = cvss_vector
            
            ratings.append(rating)
        except (ValueError, TypeError):
            pass
    
    # Dynamic Risk rating (NEW - applies intelligent prioritization)
    risk_adjustment = calculate_dynamic_risk(vuln, ext_data, enable_vex_suppression=True)
    if risk_adjustment.adjusted_level != risk_adjustment.original_level:
        # Add dynamic risk rating when risk level was adjusted
        dynamic_rating = VulnerabilityRating(
            source=None,
            severity=_map_severity_to_cyclonedx(risk_level_to_cyclonedx_severity(risk_adjustment.adjusted_level)),
            method=VulnerabilityScoreSource.OTHER,
        )
        
        # Add a score based on risk level for sorting
        risk_scores = {"critical": 10.0, "high": 8.0, "medium": 5.0, "low": 3.0, "info": 1.0}
        dynamic_rating.score = risk_scores.get(risk_adjustment.adjusted_level.value, 5.0)
        
        ratings.append(dynamic_rating)
    
    # EPSS rating
    if ext_data.get("epss_score") is not None:
        epss_rating = VulnerabilityRating(
            source=None,
            score=ext_data["epss_score"],
            method=VulnerabilityScoreSource.OTHER,
        )
        ratings.append(epss_rating)
 
    vulnerability.ratings = ratings
 
    # ------------------------------------------------------------------
    # VEX / Impact Analysis
    # ------------------------------------------------------------------

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

        # Map responses (list)
        mapped_responses = []
        for item in vex_response:
            item_lower = str(item).lower()
            enum_match = next((r for r in ImpactAnalysisResponse if r.value == item_lower), None)
            if enum_match:
                mapped_responses.append(enum_match)
        if mapped_responses:
            analysis_kwargs["responses"] = mapped_responses

        # Detail (if present)
        if vuln.get("vuln_exp_detail"):
            analysis_kwargs["detail"] = vuln["vuln_exp_detail"]

        if analysis_kwargs:
            vulnerability.analysis = VulnerabilityAnalysis(**analysis_kwargs)  # type: ignore[arg-type]

    except Exception:
        # Best-effort; don't fail report generation if mapping fails
        pass

    # ------------------------------------------------------------------
    # References & Metadata
    # ------------------------------------------------------------------
    # Add references
    references = []

    # NVD reference
    if cve != "UNKNOWN":
        nvd_ref = VulnerabilityReference(
            id=cve,
            source=VulnerabilitySource(name="NVD", url=f"https://nvd.nist.gov/vuln/detail/{cve}")
        )
        references.append(nvd_ref)
    
    # Additional NVD references
    if ext_data.get("nvd_references"):
        for ref in ext_data["nvd_references"][:5]:  # Limit to 5 references
            ref_obj = VulnerabilityReference(
                source=VulnerabilitySource(
                    name=ref.get("source", "Unknown"),
                    url=ref.get("url", "")
                )
            )
            references.append(ref_obj)
    
    vulnerability.references = references
    
    # Add CWE information
    if ext_data.get("nvd_cwe"):
        vulnerability.cwes = [int(cwe.replace("CWE-", "")) for cwe in ext_data["nvd_cwe"] if cwe.startswith("CWE-")]
    
    # Add properties for additional metadata
    properties = []
    
    if ext_data.get("cisa_kev"):
        properties.append({"name": "cisa_known_exploited", "value": "true"})
    
    if ext_data.get("epss_percentile"):
        properties.append({"name": "epss_percentile", "value": str(ext_data["epss_percentile"])})
    
    # VEX properties
    vex_status = vuln.get("vuln_exp_status")
    if vex_status:
        properties.append({"name": "vex_status", "value": vex_status})
    
    vex_response = vuln.get("vuln_exp_response")
    if vex_response:
        properties.append({"name": "vex_response", "value": vex_response})
    
    vex_justification = vuln.get("vuln_exp_justification")
    if vex_justification:
        properties.append({"name": "vex_justification", "value": vex_justification})
    
    # Dynamic risk properties (NEW)
    risk_adjustment = calculate_dynamic_risk(vuln, ext_data, enable_vex_suppression=True)
    if risk_adjustment.adjusted_level != risk_adjustment.original_level:
        properties.append({"name": "dynamic_risk_level", "value": risk_adjustment.adjusted_level.value})
        properties.append({"name": "risk_adjustment_reason", "value": risk_adjustment.adjustment_reason})
        if risk_adjustment.priority_context:
            properties.append({"name": "risk_priority_context", "value": risk_adjustment.priority_context})
    
    # Note: CycloneDX doesn't have a direct properties field on Vulnerability
    # These would typically be added as external references or in the BOM metadata
    
    return vulnerability


def _map_severity_to_cyclonedx(severity: str) -> "VulnerabilitySeverity":
    """Map severity string to CycloneDX VulnerabilitySeverity enum."""
    severity_map = {
        "NONE": VulnerabilitySeverity.NONE,
        "INFO": VulnerabilitySeverity.INFO,
        "LOW": VulnerabilitySeverity.LOW,
        "MEDIUM": VulnerabilitySeverity.MEDIUM,
        "HIGH": VulnerabilitySeverity.HIGH,
        "CRITICAL": VulnerabilitySeverity.CRITICAL,
        "UNKNOWN": VulnerabilitySeverity.UNKNOWN,
    }
    return severity_map.get(severity.upper(), VulnerabilitySeverity.UNKNOWN)


def _build_cvss_vector(vuln: Dict[str, Any]) -> str:
    """Build a CVSS vector string from available vulnerability data."""
    version = vuln.get("cvss_version", "3.1")
    
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