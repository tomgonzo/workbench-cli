"""
Test suite for SARIF conversion utilities.

This module contains comprehensive tests for the SARIF converter functionality
including conversion of vulnerability data to SARIF v2.1.0 format.
"""

import pytest
import json
import tempfile
import os
import time
from unittest.mock import patch, mock_open
from typing import Dict, List, Any

from workbench_cli.utilities.vuln_report.sarif_generator import (
    convert_vulns_to_sarif,
    save_vulns_to_sarif,
    _map_severity_to_sarif_level,
    _generate_enhanced_sarif_rules,
    _generate_enhanced_sarif_results,
    _create_run_properties
)

from workbench_cli.utilities.vuln_report.cve_data_gathering import (
    enrich_vulnerabilities,
    _fetch_epss_scores,
    _fetch_cisa_kev_data,
    _fetch_nvd_data,
    _fetch_single_cve_nvd,
    _parse_nvd_vulnerability,
    RateLimiter
)


class TestSarifConverter:
    """Test cases for SARIF conversion functionality."""

    def test_convert_vulns_to_sarif_with_data(self):
        """Test conversion of vulnerability data to SARIF format."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "availability_impact": "HIGH",
                "component_id": 123,
                "component_name": "test-package",
                "component_version": "1.0.0",
                "scan_id": 456,
                "rejected": 0
            },
            {
                "id": 2,
                "cve": "CVE-2022-67890",
                "cvss_version": "3.1",
                "base_score": "5.5",
                "severity": "MEDIUM",
                "attack_vector": "LOCAL",
                "attack_complexity": "LOW",
                "availability_impact": "NONE",
                "component_id": 124,
                "component_name": "another-package",
                "component_version": "2.1.0",
                "scan_id": 456,
                "rejected": 0
            }
        ]
        
        sarif_data = convert_vulns_to_sarif(sample_vulns, "TEST_SCAN_123")
        
        # Validate SARIF structure
        assert sarif_data["version"] == "2.1.0"
        assert "$schema" in sarif_data
        assert len(sarif_data["runs"]) == 1
        
        run = sarif_data["runs"][0]
        assert run["tool"]["driver"]["name"] == "Workbench Vulnerability Scanner"
        assert run["properties"]["scanCode"] == "TEST_SCAN_123"
        assert "timestamp" in run["properties"]
        
        # Validate rules (one per unique CVE-component combination)
        assert len(run["tool"]["driver"]["rules"]) == 2
        rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
        assert "CVE-2022-12345:test-package@1.0.0" in rule_ids
        assert "CVE-2022-67890:another-package@2.1.0" in rule_ids
        
        # Validate results
        assert len(run["results"]) == 2
        result_rule_ids = [result["ruleId"] for result in run["results"]]
        assert "CVE-2022-12345:test-package@1.0.0" in result_rule_ids
        assert "CVE-2022-67890:another-package@2.1.0" in result_rule_ids
        
        # Validate severity mapping
        critical_result = next(r for r in run["results"] if r["ruleId"] == "CVE-2022-12345:test-package@1.0.0")
        medium_result = next(r for r in run["results"] if r["ruleId"] == "CVE-2022-67890:another-package@2.1.0")
        assert critical_result["level"] == "error"  # Critical maps to error
        assert medium_result["level"] == "warning"  # Medium maps to warning
        
        # Validate lean properties
        assert "vulnerabilityCount" in run["properties"]
        assert "severityDistribution" in run["properties"]

    def test_convert_vulns_to_sarif_empty_data(self):
        """Test conversion with empty vulnerability data."""
        sarif_data = convert_vulns_to_sarif([], "TEST_SCAN_EMPTY")
        
        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"]) == 1
        
        run = sarif_data["runs"][0]
        assert run["tool"]["driver"]["name"] == "Workbench Vulnerability Scanner"
        assert run["properties"]["scanCode"] == "TEST_SCAN_EMPTY"
        assert len(run["tool"]["driver"]["rules"]) == 0
        assert len(run["results"]) == 0

    def test_convert_vulns_to_sarif_with_external_data(self):
        """Test conversion with external vulnerability data."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0"
            }
        ]
        
        # Mock external data
        mock_external_data = {
            "CVE-2022-12345": {
                "epss_score": 0.85,
                "epss_percentile": 0.95,
                "cisa_kev": True,
                "nvd_description": "Test vulnerability description",
                "nvd_cwe": ["CWE-79"]
            }
        }
        
        sarif_data = convert_vulns_to_sarif(
            sample_vulns, 
            "TEST_SCAN_ENHANCED", 
            external_data=mock_external_data
        )
        
        # Validate external data integration
        run = sarif_data["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        
        assert rule["properties"]["epss_score"] == 0.85
        assert rule["properties"]["cisa_known_exploited"] == True
        
        # The fullDescription should contain the NVD description when available
        assert "Test vulnerability description" in rule["fullDescription"]["text"]

    def test_map_severity_to_sarif_level(self):
        """Test mapping of severity levels to SARIF levels."""
        assert _map_severity_to_sarif_level("CRITICAL") == "error"
        assert _map_severity_to_sarif_level("HIGH") == "error"
        assert _map_severity_to_sarif_level("MEDIUM") == "warning"
        assert _map_severity_to_sarif_level("LOW") == "note"
        assert _map_severity_to_sarif_level("UNKNOWN") == "warning"
        assert _map_severity_to_sarif_level("INVALID") == "warning"
        assert _map_severity_to_sarif_level("") == "warning"

    def test_generate_sarif_rules(self):
        """Test generation of SARIF rules from vulnerability data."""
        sample_vulns = [
            {
                "cve": "CVE-2022-12345",
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "availability_impact": "HIGH",
                "component_name": "test-package",
                "component_version": "1.0.0"
            },
            {
                "cve": "CVE-2022-12345",  # Duplicate CVE+component should only create one rule
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "availability_impact": "HIGH",
                "component_name": "test-package",
                "component_version": "1.0.0"
            },
            {
                "cve": "CVE-2022-67890",
                "cvss_version": "3.0",
                "base_score": "5.5",
                "severity": "MEDIUM",
                "component_name": "another-package",
                "component_version": "2.1.0"
            }
        ]
        
        external_data = {
            "CVE-2022-12345": {
                "epss_score": 0.85,
                "cisa_kev": True,
                "nvd_description": "Test vulnerability description"
            }
        }
        
        rules = _generate_enhanced_sarif_rules(sample_vulns, external_data, enable_dynamic_risk_scoring=True)
        
        # Should have 2 rules (one per unique CVE-component combination)
        assert len(rules) == 2
        
        # Check rule IDs (now include component info)
        rule_ids = [rule["id"] for rule in rules]
        assert "CVE-2022-12345:test-package@1.0.0" in rule_ids
        assert "CVE-2022-67890:another-package@2.1.0" in rule_ids
        
        # Check enriched rule properties
        cve_rule = next(r for r in rules if r["id"] == "CVE-2022-12345:test-package@1.0.0")
        assert cve_rule["properties"]["epss_score"] == 0.85
        assert cve_rule["properties"]["cisa_kev"] == True
        assert "Test vulnerability description" in cve_rule["fullDescription"]["text"]
        
        # Check component-specific properties
        assert cve_rule["properties"]["component"] == "test-package@1.0.0"
        assert cve_rule["properties"]["cve"] == "CVE-2022-12345"

    def test_generate_sarif_results(self):
        """Test generation of SARIF results from vulnerability data."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0",
                "vuln_exp_status": "affected"
            }
        ]
        
        external_data = {
            "CVE-2022-12345": {
                "epss_score": 0.85,
                "cisa_kev": True
            }
        }
        
        results = _generate_enhanced_sarif_results(sample_vulns, external_data, enable_dynamic_risk_scoring=True)
        
        assert len(results) == 1
        result = results[0]
        
        assert result["ruleId"] == "CVE-2022-12345:test-package@1.0.0"
        assert result["level"] == "error"
        assert "CVE-2022-12345 in test-package@1.0.0" in result["message"]["text"]
        assert result["properties"]["epss_score"] == 0.85
        assert result["properties"]["cisa_kev"] == True
        assert result["properties"]["vex_status"] == "affected"
        
        # Check enhanced features
        assert "partialFingerprints" in result
        assert "baselineState" in result
        assert "fixes" in result

    def test_create_run_properties(self):
        """Test creation of SARIF run properties."""
        sample_vulns = [
            {"severity": "CRITICAL", "vuln_exp_status": "affected"},
            {"severity": "HIGH", "vuln_exp_response": "will_not_fix"},
            {"severity": "MEDIUM"}
        ]
        
        external_data = {
            "CVE-2022-12345": {"epss_score": 0.85, "cisa_kev": True}
        }
        
        all_components = [
            {"name": "test-package", "version": "1.0.0"},
            {"name": "another-package", "version": "2.1.0"}
        ]
        
        properties = _create_run_properties(
            scan_code="TEST_SCAN",
            vulnerabilities=sample_vulns,
            external_data=external_data,
            nvd_enrichment=True,
            epss_enrichment=True,
            cisa_kev_enrichment=True,
            all_components=all_components
        )
        
        assert properties["workbench_scan_code"] == "TEST_SCAN"
        assert properties["total_vulnerabilities"] == 3
        assert properties["total_components"] == 2
        assert properties["enrichment_applied"]["nvd"] == True
        assert properties["enrichment_applied"]["epss"] == True
        assert properties["enrichment_applied"]["cisa_kev"] == True
        assert properties["severity_distribution"]["critical"] == 1
        assert properties["severity_distribution"]["high"] == 1
        assert properties["severity_distribution"]["medium"] == 1
        assert properties["vex_statistics"]["total_with_vex"] == 2
        assert properties["external_data_statistics"]["enriched_cves"] == 1
        assert properties["external_data_statistics"]["with_epss"] == 1
        assert properties["external_data_statistics"]["with_cisa_kev"] == 1

    def test_save_vulns_to_sarif_success(self):
        """Test successful saving of SARIF file."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0"
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as temp_file:
            temp_filepath = temp_file.name
        
        try:
            save_vulns_to_sarif(
                temp_filepath,
                sample_vulns,
                "TEST_SCAN_123",
                quiet=True
            )
            
            # Verify file was created and contains valid SARIF JSON
            assert os.path.exists(temp_filepath)
            
            with open(temp_filepath, 'r') as f:
                sarif_data = json.load(f)
            
            assert sarif_data["version"] == "2.1.0"
            assert len(sarif_data["runs"]) == 1
            assert sarif_data["runs"][0]["properties"]["workbench_scan_code"] == "TEST_SCAN_123"
            
        finally:
            # Clean up
            if os.path.exists(temp_filepath):
                os.unlink(temp_filepath)

    def test_save_vulns_to_sarif_creates_directory(self):
        """Test that save_vulns_to_sarif creates necessary directories."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0"
            }
        ]
        
        with tempfile.TemporaryDirectory() as temp_dir:
            new_dir = os.path.join(temp_dir, "new_directory")
            filepath = os.path.join(new_dir, "test.sarif")
            
            save_vulns_to_sarif(filepath, sample_vulns, "TEST_SCAN_123", quiet=True)
            
            # Verify directory was created and file exists
            assert os.path.exists(new_dir)
            assert os.path.exists(filepath)

    def test_save_vulns_to_sarif_io_error(self):
        """Test handling of IO errors during save."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0"
            }
        ]
        
        # Try to save to an invalid path
        invalid_path = "/root/cannot_write_here.sarif"
        
        with pytest.raises((IOError, OSError)):
            save_vulns_to_sarif(invalid_path, sample_vulns, "TEST_SCAN_123", quiet=True)

    def test_handle_missing_vulnerability_fields(self):
        """Test handling of vulnerability data with missing fields."""
        sample_vulns = [
            {
                "id": 1,
                # Missing cve, base_score, severity, component info
            },
            {
                "id": 2,
                "cve": "CVE-2022-12345",
                # Missing component_name, component_version
            }
        ]
        
        sarif_data = convert_vulns_to_sarif(sample_vulns, "TEST_SCAN_MISSING")
        
        # Should still create valid SARIF structure
        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"]) == 1
        
        run = sarif_data["runs"][0]
        assert len(run["results"]) == 2
        
        # Check that missing fields are handled gracefully
        results = run["results"]
        rule_ids = [r["ruleId"] for r in results]
        
        # First result should have UNKNOWN CVE with Unknown component
        unknown_result = next(r for r in results if r["ruleId"].startswith("UNKNOWN"))
        assert unknown_result is not None
        
        # Second result should have CVE but Unknown component info
        cve_result = next(r for r in results if "CVE-2022-12345" in r["ruleId"])
        assert cve_result is not None
        assert "Unknown" in cve_result["ruleId"]  # Should have Unknown for missing component info
        
        # Both should have valid structure
        assert "message" in unknown_result
        assert "locations" in unknown_result
        assert "message" in cve_result
        assert "locations" in cve_result

    def test_sarif_schema_compliance(self):
        """Test that generated SARIF complies with basic schema requirements."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0"
            }
        ]
        
        sarif_data = convert_vulns_to_sarif(sample_vulns, "TEST_SCAN_SCHEMA")
        
        # Basic schema compliance checks
        assert "version" in sarif_data
        assert "$schema" in sarif_data
        assert "runs" in sarif_data
        assert isinstance(sarif_data["runs"], list)
        
        run = sarif_data["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "name" in run["tool"]["driver"]
        assert "rules" in run["tool"]["driver"]
        assert "results" in run
        
        # Check rules structure
        for rule in run["tool"]["driver"]["rules"]:
            assert "id" in rule
            assert "shortDescription" in rule
            assert "text" in rule["shortDescription"]
            assert "fullDescription" in rule
            assert "text" in rule["fullDescription"]
            assert "defaultConfiguration" in rule
            assert "level" in rule["defaultConfiguration"]
        
        # Check results structure
        for result in run["results"]:
            assert "ruleId" in result
            assert "level" in result
            assert "message" in result
            assert "text" in result["message"]
            assert "locations" in result
            assert isinstance(result["locations"], list)
            
            # Check location structure
            for location in result["locations"]:
                assert "physicalLocation" in location
                assert "artifactLocation" in location["physicalLocation"]
                assert "uri" in location["physicalLocation"]["artifactLocation"]

    def test_vex_integration(self):
        """Test VEX (Vulnerability Exploitability eXchange) integration."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0",
                "vuln_exp_status": "not_affected",
                "vuln_exp_response": "will_not_fix",
                "vuln_exp_justification": "Component not used in production"
            }
        ]
        
        sarif_data = convert_vulns_to_sarif(sample_vulns, "TEST_SCAN_VEX")
        
        run = sarif_data["runs"][0]
        result = run["results"][0]
        
        # Check VEX information in result properties
        assert result["properties"]["vex_status"] == "not_affected"
        assert result["properties"]["vex_response"] == "will_not_fix"
        assert result["properties"]["vex_justification"] == "Component not used in production"
        
        # Check VEX statistics in run properties
        assert "vex_statistics" in run["properties"]
        vex_stats = run["properties"]["vex_statistics"]
        assert vex_stats["total_with_vex"] == 1
        assert vex_stats["by_status"]["not_affected"] == 1
        assert vex_stats["by_response"]["will_not_fix"] == 1


class TestVulnerabilityEnricher:
    """Test cases for vulnerability enrichment functionality."""

    def test_enrich_vulnerabilities_empty_list(self):
        """Test enrichment with empty CVE list."""
        result = enrich_vulnerabilities([], True, True, True)
        assert result == {}

    @patch('workbench_cli.utilities.vuln_report.cve_data_gathering.requests.get')
    def test_fetch_epss_scores_success(self, mock_get):
        """Test successful EPSS score fetching."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "cve": "CVE-2022-12345",
                    "epss": "0.85000",
                    "percentile": "0.95000"
                }
            ]
        }
        
        result = _fetch_epss_scores(["CVE-2022-12345"])
        
        assert "CVE-2022-12345" in result
        assert result["CVE-2022-12345"]["epss_score"] == 0.85
        assert result["CVE-2022-12345"]["epss_percentile"] == 0.95

    @patch('workbench_cli.utilities.vuln_report.cve_data_gathering.requests.get')
    def test_fetch_cisa_kev_data_success(self, mock_get):
        """Test successful CISA KEV data fetching."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2022-12345",
                    "vendorProject": "Test Vendor",
                    "product": "Test Product",
                    "vulnerabilityName": "Test Vulnerability",
                    "dateAdded": "2022-01-01",
                    "shortDescription": "Test description",
                    "requiredAction": "Test action",
                    "dueDate": "2022-01-15"
                }
            ]
        }
        
        result = _fetch_cisa_kev_data(["CVE-2022-12345"])
        
        assert "CVE-2022-12345" in result
        assert result["CVE-2022-12345"]["cisa_kev"] == True

    def test_rate_limiter_functionality(self):
        """Test rate limiter functionality."""
        rate_limiter = RateLimiter(max_requests=2, time_window=1.0)
        
        # First two requests should pass immediately
        start_time = time.time()
        rate_limiter.wait_if_needed()
        rate_limiter.wait_if_needed()
        first_duration = time.time() - start_time
        
        # Should be very fast (no waiting)
        assert first_duration < 0.1
        
        # Third request should wait
        start_time = time.time()
        rate_limiter.wait_if_needed()
        wait_duration = time.time() - start_time
        
        # Should have waited at least 1 second
        assert wait_duration >= 1.0

    @patch('workbench_cli.utilities.vuln_report.cve_data_gathering.requests.get')
    def test_parse_nvd_vulnerability(self, mock_get):
        """Test parsing of NVD vulnerability data."""
        mock_nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2022-12345",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Test vulnerability description"
                            }
                        ],
                        "weaknesses": [
                            {
                                "description": [
                                    {
                                        "lang": "en",
                                        "value": "CWE-79"
                                    }
                                ]
                            }
                        ],
                        "references": [
                            {
                                "url": "https://example.com/advisory",
                                "source": "example.com",
                                "tags": ["Vendor Advisory"]
                            }
                        ]
                    }
                }
            ]
        }
        
        result = _parse_nvd_vulnerability(mock_nvd_data)
        
        assert "CVE-2022-12345" in result
        cve_data = result["CVE-2022-12345"]
        assert cve_data["nvd_description"] == "Test vulnerability description"
        assert "CWE-79" in cve_data["nvd_cwe"]
        assert len(cve_data["nvd_references"]) == 1
        assert cve_data["nvd_references"][0]["url"] == "https://example.com/advisory"

 