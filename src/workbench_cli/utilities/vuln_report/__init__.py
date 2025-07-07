"""
Vulnerability report generation utilities.

This package contains utilities for generating vulnerability reports in various formats:
- SARIF (Static Analysis Results Interchange Format)
- CycloneDX (Software Bill of Materials with vulnerability information)
- SPDX 3.0 (Security Profile)

All formats share the same data enrichment pipeline but use different output serializers.
"""

__all__ = [
    # Core enrichment utilities
    "bootstrap_bom",
    "cve_data_gathering",
    
    # Dynamic risk adjustments
    "risk_adjustments",
    
    # Format generators
    "sarif_generator",
    "cyclonedx_generator", 
    "spdx_generator",
] 