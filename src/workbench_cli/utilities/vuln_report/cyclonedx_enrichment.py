"""
CycloneDX vulnerability enrichment module.

This module provides shared enrichment functionality for CycloneDX SBOMs,
including external data enrichment (NVD, EPSS, CISA KEV) and dynamic risk scoring.
Can be used by both generation and augmentation flows.
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

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
    ExternalReference = Any
    ExternalReferenceType = Any
    PackageURL = Any
    BomTarget = Any
    Property = Any
    CYCLONEDX_AVAILABLE = False

from .risk_adjustments import calculate_dynamic_risk, RiskAdjustment
from .cve_data_gathering import build_cvss_vector


# Removed functions moved to cyclonedx_generator.py for generation flow:
# - enrich_cyclonedx_sbom (creates new vulnerabilities)
# - _enrich_vulnerabilities_batch (batch processing for new vulnerabilities)
# - _create_cyclonedx_vulnerability (creates new CycloneDX Vulnerability objects)  
# - _map_severity_to_cyclonedx (severity mapping utility)


def enrich_cyclonedx_vulnerability_in_place(vuln: Dict[str, Any], ext_data: Dict[str, Any]) -> bool:
    """
    Enrich a CycloneDX vulnerability object in place with external data.
    
    This function is used for augmenting existing SBOMs where vulnerabilities
    are already present in the SBOM as JSON objects.
    
    Returns:
        bool: True if any enrichment was applied, False otherwise
    """
    enriched = False
    
    try:
        # Update description from NVD if available
        if ext_data.get("nvd_description") and not vuln.get("description"):
            vuln["description"] = ext_data["nvd_description"]
            enriched = True
        
        # Add or update EPSS rating
        epss_score = ext_data.get("epss_score")
        if epss_score is not None and epss_score > 0.0:
            ratings = vuln.get("ratings", [])
            
            # Check if EPSS rating already exists
            epss_rating_exists = any(
                rating.get("source", {}).get("name") == "EPSS" 
                for rating in ratings
            )
            
            if not epss_rating_exists:
                epss_rating = {
                    "source": {"name": "EPSS", "url": "https://www.first.org/epss"},
                    "score": epss_score,
                    "method": "other"
                }
                ratings.append(epss_rating)
                vuln["ratings"] = ratings
                enriched = True
        
        # Add or update external references
        if ext_data.get("nvd_references"):
            external_refs = vuln.get("externalReferences", [])
            existing_urls = {ref.get("url") for ref in external_refs}
            
            added_refs = 0
            for ref in ext_data["nvd_references"]:
                url = ref.get("url")
                if url and url not in existing_urls:
                    external_refs.append({
                        "type": "advisories",
                        "url": url,
                        "comment": ref.get("source", "")
                    })
                    added_refs += 1
            
            if added_refs > 0:
                vuln["externalReferences"] = external_refs
                enriched = True
        
        # Add CWE information
        if ext_data.get("nvd_cwe") and not vuln.get("cwes"):
            cwe_list = []
            for cwe in ext_data["nvd_cwe"]:
                if cwe.startswith("CWE-"):
                    try:
                        cwe_list.append(int(cwe.replace("CWE-", "")))
                    except ValueError:
                        continue
            if cwe_list:
                vuln["cwes"] = cwe_list
                enriched = True
        
        # Add EPSS properties for reference
        epss_score = ext_data.get("epss_score")
        epss_percentile = ext_data.get("epss_percentile")
        
        if epss_score is not None or epss_percentile is not None:
            if not vuln.get("properties"):
                vuln["properties"] = []
            
            existing_props = {prop.get("name"): prop for prop in vuln["properties"]}
            
            if epss_score is not None and "epss_score" not in existing_props:
                vuln["properties"].append({"name": "epss_score", "value": str(epss_score)})
                enriched = True
            
            if epss_percentile is not None and "epss_percentile" not in existing_props:
                vuln["properties"].append({"name": "epss_percentile", "value": str(epss_percentile)})
                enriched = True
        
        # Add CISA KEV flag
        if ext_data.get("cisa_kev"):
            if not vuln.get("properties"):
                vuln["properties"] = []
            
            existing_props = {prop.get("name"): prop for prop in vuln["properties"]}
            
            if "cisa_known_exploited" not in existing_props:
                vuln["properties"].append({"name": "cisa_known_exploited", "value": "true"})
                enriched = True
            
            # Ensure vulnerability is marked exploitable if not already
            if vuln.get("analysis"):
                if vuln["analysis"].get("state") != "exploitable":
                    vuln["analysis"]["state"] = "exploitable"
                    enriched = True
            else:
                vuln["analysis"] = {"state": "exploitable"}
                enriched = True
        
        return enriched
        
    except Exception as e:
        logger.warning(f"Failed to enrich vulnerability {vuln.get('id', 'UNKNOWN')}: {e}")
        return False


def apply_dynamic_risk_to_cyclonedx_vuln(vuln: Dict[str, Any], risk_adjustment: "RiskAdjustment") -> None:
    """Apply dynamic risk adjustment to a CycloneDX vulnerability."""
    if not vuln.get("properties"):
        vuln["properties"] = []
    
    # Add or update high risk indicator
    existing_props = {prop.get("name"): prop for prop in vuln["properties"]}
    
    # High risk indicator
    if "high_risk_indicator" in existing_props:
        existing_props["high_risk_indicator"]["value"] = risk_adjustment.high_risk_indicator
    else:
        vuln["properties"].append({
            "name": "high_risk_indicator",
            "value": risk_adjustment.high_risk_indicator
        })
    
    # High risk evidence
    if risk_adjustment.high_risk_evidence:
        if "high_risk_evidence" in existing_props:
            existing_props["high_risk_evidence"]["value"] = risk_adjustment.high_risk_evidence
        else:
            vuln["properties"].append({
                "name": "high_risk_evidence", 
                "value": risk_adjustment.high_risk_evidence
            })


def convert_sbom_vuln_to_internal_format(vuln: Dict[str, Any], component_lookup: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a CycloneDX SBOM vulnerability to internal format for risk calculation."""
    # Extract basic vulnerability info
    vuln_data = {
        "cve": vuln.get("id", "UNKNOWN"),
        "vulnerability_id": vuln.get("bom-ref", ""),
        "severity": _extract_severity_from_cyclonedx_vuln(vuln),
        "base_score": _extract_base_score_from_cyclonedx_vuln(vuln),
        "component_name": "Unknown",
        "component_version": "Unknown",
    }
    
    # Extract VEX information if present
    if vuln.get("analysis"):
        analysis = vuln["analysis"]
        vuln_data["vuln_exp_status"] = analysis.get("state", "")
        vuln_data["vuln_exp_justification"] = analysis.get("justification", "")
        vuln_data["vuln_exp_response"] = analysis.get("responses", [])
        vuln_data["vuln_exp_detail"] = analysis.get("detail", "")
    
    # Resolve component information from affects
    if vuln.get("affects"):
        for affect in vuln["affects"]:
            ref = affect.get("ref")
            if ref and ref in component_lookup:
                component = component_lookup[ref]
                vuln_data["component_name"] = component.get("name", "Unknown")
                vuln_data["component_version"] = component.get("version", "Unknown")
                break
    
    return vuln_data


def _extract_severity_from_cyclonedx_vuln(vuln: Dict[str, Any]) -> str:
    """Extract severity from a CycloneDX vulnerability."""
    ratings = vuln.get("ratings", [])
    for rating in ratings:
        if rating.get("severity"):
            return rating["severity"].upper()
    return "UNKNOWN"


def _extract_base_score_from_cyclonedx_vuln(vuln: Dict[str, Any]) -> str:
    """Extract base score from a CycloneDX vulnerability."""
    ratings = vuln.get("ratings", [])
    for rating in ratings:
        if rating.get("score") is not None:
            return str(rating["score"])
    return "N/A"


def _validate_external_data(external_data: Optional[Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """Validate and sanitize external enrichment data."""
    if external_data is None:
        return {}
    
    if not isinstance(external_data, dict):
        logger.warning("External data is not a dictionary, ignoring")
        return {}
    
    # Validate structure
    validated_data = {}
    for cve, cve_data in external_data.items():
        if not isinstance(cve_data, dict):
            logger.warning(f"Invalid data structure for CVE {cve}, skipping")
            continue
        
        # Validate and sanitize fields
        sanitized_data = {}
        
        # NVD fields
        if "nvd_description" in cve_data and isinstance(cve_data["nvd_description"], str):
            sanitized_data["nvd_description"] = cve_data["nvd_description"]
        
        if "nvd_references" in cve_data and isinstance(cve_data["nvd_references"], list):
            sanitized_data["nvd_references"] = cve_data["nvd_references"]
        
        if "nvd_cwe" in cve_data and isinstance(cve_data["nvd_cwe"], list):
            sanitized_data["nvd_cwe"] = cve_data["nvd_cwe"]
        
        # EPSS fields
        if "epss_score" in cve_data:
            try:
                sanitized_data["epss_score"] = float(cve_data["epss_score"])
            except (ValueError, TypeError):
                logger.warning(f"Invalid EPSS score for CVE {cve}: {cve_data['epss_score']}")
        
        if "epss_percentile" in cve_data:
            try:
                sanitized_data["epss_percentile"] = float(cve_data["epss_percentile"])
            except (ValueError, TypeError):
                logger.warning(f"Invalid EPSS percentile for CVE {cve}: {cve_data['epss_percentile']}")
        
        # CISA KEV
        if "cisa_kev" in cve_data:
            sanitized_data["cisa_kev"] = bool(cve_data["cisa_kev"])
        
        # CVSS fields
        if "full_cvss_vector" in cve_data and isinstance(cve_data["full_cvss_vector"], str):
            sanitized_data["full_cvss_vector"] = cve_data["full_cvss_vector"]
        
        validated_data[cve] = sanitized_data
    
    return validated_data


def augment_cyclonedx_sbom_from_file(
    sbom_path: str,
    filepath: str,
    scan_code: str,
    external_data: Optional[Dict[str, Dict[str, Any]]] = None,
    nvd_enrichment: bool = False,
    epss_enrichment: bool = False,
    cisa_kev_enrichment: bool = False,
    enable_dynamic_risk_scoring: bool = True,
    quiet: bool = False
) -> None:
    """
    Augment an existing CycloneDX SBOM file with external enrichment and dynamic risk scoring.
    
    This function handles file I/O for SBOM augmentation:
    1. Loads the existing CycloneDX SBOM from file
    2. Applies external enrichment (NVD, EPSS, CISA KEV) and dynamic risk scoring
    3. Saves the augmented SBOM back to file
    
    Args:
        sbom_path: Path to the existing CycloneDX SBOM file
        filepath: Path where the augmented SBOM should be saved
        scan_code: The scan code for reference (metadata only)
        external_data: Pre-fetched external enrichment data (optional)
        nvd_enrichment: Whether NVD enrichment was enabled
        epss_enrichment: Whether EPSS enrichment was enabled  
        cisa_kev_enrichment: Whether CISA KEV enrichment was enabled
        enable_dynamic_risk_scoring: Whether dynamic risk scoring is enabled
        quiet: Whether to suppress output messages
        
    Raises:
        ImportError: If cyclonedx-python-lib is not installed
        IOError: If the file cannot be written
        OSError: If the directory cannot be created
        FileNotFoundError: If sbom_path doesn't exist
        ValueError: If the SBOM cannot be parsed
    """
    if not CYCLONEDX_AVAILABLE:
        raise ImportError(
            "CycloneDX support requires the 'cyclonedx-python-lib' package. "
            "This should be installed automatically with workbench-cli. "
            "Try reinstalling: pip install --force-reinstall workbench-cli"
        )
    
    # Validate and normalize inputs
    external_data = _validate_external_data(external_data)
    
    if not quiet:
        print(f"   • Augmenting CycloneDX SBOM from {os.path.basename(sbom_path)}")
    
    # Validate input file exists
    if not os.path.exists(sbom_path):
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")
    
    # Check file size for performance warnings
    file_size = os.path.getsize(sbom_path)
    if file_size > 50_000_000:  # > 50MB
        logger.warning(f"Large SBOM file detected ({file_size:,} bytes). Processing may take longer.")
    
    # Load the existing SBOM as JSON to preserve the original format
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            sbom_json = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to load SBOM from {sbom_path}: {e}")
    
    # Validate SBOM structure using existing validator
    from ..sbom_validator import SBOMValidator
    try:
        # Use existing comprehensive validation
        sbom_format, version, metadata, _ = SBOMValidator.validate_sbom_file(sbom_path)
        if sbom_format != "cyclonedx":
            raise ValueError(f"Expected CycloneDX SBOM, got {sbom_format}")
    except Exception as e:
        raise ValueError(f"SBOM validation failed: {e}")
    
    # Extract existing vulnerabilities from the SBOM
    existing_vulnerabilities = sbom_json.get("vulnerabilities", [])
    
    if not quiet:
        print(f"   • Found {len(existing_vulnerabilities)} vulnerabilities in SBOM")
    
    if not existing_vulnerabilities:
        logger.info("No vulnerabilities found in SBOM - adding enrichment metadata only")
    
    # Create component lookup for resolving component names from bom-refs
    component_lookup = {}
    components = sbom_json.get("components", [])
    
    for comp in components:
        if not isinstance(comp, dict):
            continue
        bom_ref = comp.get("bom-ref")
        if bom_ref:
            component_lookup[bom_ref] = comp
    
    if not quiet and components:
        print(f"   • Indexed {len(component_lookup)} components for vulnerability resolution")
    
    # Track processing statistics
    stats = {
        "vulnerabilities_processed": 0,
        "vulnerabilities_enriched": 0,
        "vulnerabilities_risk_scored": 0,
        "processing_errors": 0
    }
    
    # Process each vulnerability in the SBOM
    for vuln in existing_vulnerabilities:
        try:
            if not isinstance(vuln, dict):
                stats["processing_errors"] += 1
                continue
                
            cve = vuln.get("id", "UNKNOWN")
            ext_data = external_data.get(cve, {})
            
            # Convert SBOM vulnerability to internal format for dynamic risk calculation
            vuln_data = convert_sbom_vuln_to_internal_format(vuln, component_lookup)
            
            # Apply external enrichment to vulnerability object
            enriched = enrich_cyclonedx_vulnerability_in_place(vuln, ext_data)
            if enriched:
                stats["vulnerabilities_enriched"] += 1
            
            # Apply dynamic risk scoring if enabled
            if enable_dynamic_risk_scoring:
                try:
                    dynamic_risk_adjustment = calculate_dynamic_risk(vuln_data, ext_data)
                    apply_dynamic_risk_to_cyclonedx_vuln(vuln, dynamic_risk_adjustment)
                    stats["vulnerabilities_risk_scored"] += 1
                except Exception as e:
                    logger.warning(f"Failed to calculate dynamic risk for CVE {cve}: {e}")
                    stats["processing_errors"] += 1
            
            stats["vulnerabilities_processed"] += 1
            
        except Exception as e:
            logger.warning(f"Failed to process vulnerability {vuln.get('id', 'UNKNOWN')}: {e}")
            stats["processing_errors"] += 1
            continue
    
    # Add/update enrichment metadata properties
    try:
        if not sbom_json.get("metadata"):
            sbom_json["metadata"] = {}
        
        if not sbom_json["metadata"].get("properties"):
            sbom_json["metadata"]["properties"] = []
        
        # Prepare standardized enrichment properties with validation status
        enrichment_props = {
            "workbench_scan_code": scan_code,
            "nvd_enriched": str(nvd_enrichment).lower(),
            "epss_enriched": str(epss_enrichment).lower(),
            "cisa_kev_enriched": str(cisa_kev_enrichment).lower(),
            "bom_type": "augmented_bom",
            "vulnerability_count": str(len(existing_vulnerabilities)),
            "augmented_vulnerabilities": str(stats["vulnerabilities_processed"]),
            "enriched_vulnerabilities": str(stats["vulnerabilities_enriched"]),
            "risk_scored_vulnerabilities": str(stats["vulnerabilities_risk_scored"]),
            "processing_errors": str(stats["processing_errors"]),
            "validation_status": "passed" if stats["processing_errors"] == 0 else "warnings"
        }
        
        # Update existing properties or add new ones
        existing_props = {prop.get("name"): prop for prop in sbom_json["metadata"]["properties"]}
        for name, value in enrichment_props.items():
            if name in existing_props:
                existing_props[name]["value"] = value
            else:
                sbom_json["metadata"]["properties"].append({"name": name, "value": value})
        
    except Exception as e:
        logger.warning(f"Failed to update SBOM metadata: {e}")
    
    # Save the augmented SBOM maintaining the original format
    output_dir = os.path.dirname(filepath) or "."
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Create backup of original file if overwriting
        if os.path.exists(filepath) and os.path.samefile(sbom_path, filepath):
            backup_path = f"{filepath}.backup"
            logger.info(f"Creating backup: {backup_path}")
            import shutil
            shutil.copy2(filepath, backup_path)
        
        # Write the augmented SBOM as JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sbom_json, f, ensure_ascii=False, indent=2)
        
        if not quiet:
            print(f"   • Augmented CycloneDX SBOM saved to: {filepath}")
            if stats["processing_errors"] > 0:
                print(f"   • Warning: {stats['processing_errors']} processing errors (see logs)")
        
    except (IOError, OSError) as e:
        logger.error(f"Failed to save augmented SBOM: {e}")
        if not quiet:
            print(f"\nError: Failed to save augmented CycloneDX results to {filepath}: {e}")
        raise
    
    # Log processing summary
    logger.info(f"SBOM augmentation completed: {stats['vulnerabilities_processed']} vulnerabilities processed, "
                f"{stats['vulnerabilities_enriched']} enriched, {stats['vulnerabilities_risk_scored']} risk-scored")
    
    if stats["processing_errors"] > 0:
        logger.warning(f"SBOM augmentation had {stats['processing_errors']} processing errors")




# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    # Main enrichment functions
    "enrich_cyclonedx_vulnerability_in_place", 
    "apply_dynamic_risk_to_cyclonedx_vuln",
    
    # File-based augmentation
    "augment_cyclonedx_sbom_from_file",
    
    # Conversion utilities
    "convert_sbom_vuln_to_internal_format",
    
    # Validation functions
    "_validate_external_data",
] 