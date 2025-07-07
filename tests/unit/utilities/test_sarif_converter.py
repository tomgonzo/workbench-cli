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

from workbench_cli.utilities.sarif_generation import (
    convert_vulns_to_sarif,
    save_vulns_to_sarif,
    _map_severity_to_sarif_level,
    _generate_enhanced_rules,
    _generate_enhanced_results,
    _create_empty_sarif_report
)

from src.workbench_cli.utilities.vuln_report.cve_data_gathering import (
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
        
        # Mock the vulnerability enricher to avoid external API calls
        with patch('src.workbench_cli.utilities.sarif_generation.enrich_vulnerabilities') as mock_enrich:
            mock_enrich.return_value = {}
            
            sarif_data = convert_vulns_to_sarif(sample_vulns, "TEST_SCAN_123")
            
            # Validate SARIF structure
            assert sarif_data["version"] == "2.1.0"
            assert "$schema" in sarif_data
            assert len(sarif_data["runs"]) == 1
            
            run = sarif_data["runs"][0]
            assert run["tool"]["driver"]["name"] == "FossID Workbench"
            assert run["properties"]["scan_code"] == "TEST_SCAN_123"
            assert "generated_at" in run["properties"]
            
            # Validate rules
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
            assert critical_result["level"] == "warning"
            assert medium_result["level"] == "warning"

    def test_convert_vulns_to_sarif_empty_data(self):
        """Test conversion with empty vulnerability data."""
        sarif_data = convert_vulns_to_sarif([], "TEST_SCAN_EMPTY")
        
        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"]) == 1
        
        run = sarif_data["runs"][0]
        assert run["tool"]["driver"]["name"] == "FossID Workbench"
        assert run["properties"]["scan_code"] == "TEST_SCAN_EMPTY"
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
        
        with patch('src.workbench_cli.utilities.sarif_generation.enrich_vulnerabilities') as mock_enrich:
            mock_enrich.return_value = mock_external_data
            
            sarif_data = convert_vulns_to_sarif(sample_vulns, "TEST_SCAN_ENHANCED")
            
            # Validate external data integration
            run = sarif_data["runs"][0]
            rule = run["tool"]["driver"]["rules"][0]
            
            assert rule["properties"]["epss_score"] == 0.85
            assert rule["properties"]["cisa_known_exploited"] == True
            assert rule["properties"]["cwe_ids"] == ["CWE-79"]
            
            # External data should be in properties, not in description
            # The fullDescription should contain the NVD description when available
            assert "Test vulnerability description" in rule["fullDescription"]["text"]
            assert "test-package" in rule["fullDescription"]["text"]

    def test_map_severity_to_sarif_level(self):
        """Test mapping of severity levels to SARIF levels."""
        # New intelligent approach: defaults to WARNING for promotion/demotion logic
        assert _map_severity_to_sarif_level("CRITICAL") == "warning"
        assert _map_severity_to_sarif_level("HIGH") == "warning"
        assert _map_severity_to_sarif_level("MEDIUM") == "warning"
        assert _map_severity_to_sarif_level("LOW") == "warning"
        assert _map_severity_to_sarif_level("UNKNOWN") == "warning"
        assert _map_severity_to_sarif_level("INVALID") == "warning"
        assert _map_severity_to_sarif_level("") == "warning"
        assert _map_severity_to_sarif_level(None) == "warning"

    def test_generate_enhanced_rules(self):
        """Test generation of enhanced SARIF rules from vulnerability data."""
        sample_vulns = [
            {
                "cve": "CVE-2022-12345",
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "availability_impact": "HIGH"
            },
            {
                "cve": "CVE-2022-12345",  # Duplicate CVE should only create one rule
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "availability_impact": "HIGH"
            },
            {
                "cve": "CVE-2022-67890",
                "cvss_version": "3.0",
                "base_score": "5.5",
                "severity": "MEDIUM",
                "attack_vector": "LOCAL",
                "attack_complexity": "LOW",
                "availability_impact": "NONE"
            }
        ]
        
        external_data = {}
        rules = _generate_enhanced_rules(sample_vulns, external_data)
        
        assert len(rules) == 2  # Should deduplicate CVE-2022-12345
        rule_ids = [rule["id"] for rule in rules]
        assert "CVE-2022-12345:Unknown@Unknown" in rule_ids
        assert "CVE-2022-67890:Unknown@Unknown" in rule_ids
        
        # Validate rule structure
        critical_rule = next(r for r in rules if r["id"] == "CVE-2022-12345:Unknown@Unknown")
        assert critical_rule["name"] == "CVE-2022-12345 in Unknown@Unknown"
        assert critical_rule["defaultConfiguration"]["level"] == "warning"
        assert critical_rule["properties"]["cvss_version"] == "3.1"
        assert critical_rule["properties"]["base_score"] == "9.8"

    def test_generate_enhanced_results(self):
        """Test generation of enhanced SARIF results from vulnerability data."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_id": 123,
                "component_name": "test-package",
                "component_version": "1.0.0",
                "scan_id": 456,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "availability_impact": "HIGH",
                "rejected": 0
            }
        ]
        
        external_data = {}
        results = _generate_enhanced_results(sample_vulns, external_data)
        
        assert len(results) == 1
        result = results[0]
        
        assert result["ruleId"] == "CVE-2022-12345:test-package@1.0.0"
        assert result["level"] == "warning"
        assert "CVE-2022-12345" in result["message"]["text"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "pkg:generic/test-package@1.0.0"
        
        # Validate properties
        assert result["properties"]["component_id"] == 123
        assert result["properties"]["vulnerability_id"] == 1
        assert result["properties"]["security-severity"] == "9.8"

    def test_create_empty_sarif_report(self):
        """Test creation of empty SARIF report."""
        sarif_data = _create_empty_sarif_report("EMPTY_SCAN")
        
        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"]) == 1
        
        run = sarif_data["runs"][0]
        assert run["tool"]["driver"]["name"] == "FossID Workbench"
        assert run["properties"]["scan_code"] == "EMPTY_SCAN"
        assert len(run["tool"]["driver"]["rules"]) == 0
        assert len(run["results"]) == 0

    def test_save_vulns_to_sarif_success(self):
        """Test successful saving of vulnerabilities to SARIF file."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "availability_impact": "HIGH"
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sarif') as temp_file:
            temp_path = temp_file.name
        
        try:
            # Mock the enricher to avoid external API calls
            with patch('src.workbench_cli.utilities.sarif_generation.enrich_vulnerabilities') as mock_enrich:
                mock_enrich.return_value = {}
                
                save_vulns_to_sarif(temp_path, sample_vulns, "TEST_SCAN")
                
                # Verify file was created and contains valid SARIF
                assert os.path.exists(temp_path)
                with open(temp_path, 'r') as f:
                    saved_data = json.load(f)
                
                assert saved_data["version"] == "2.1.0"
                assert len(saved_data["runs"]) == 1
                assert saved_data["runs"][0]["properties"]["scan_code"] == "TEST_SCAN"
                
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_save_vulns_to_sarif_creates_directory(self):
        """Test that save_vulns_to_sarif creates output directory if it doesn't exist."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "severity": "HIGH",
                "component_name": "test-package",
                "component_version": "1.0.0"
            }
        ]
        
        with tempfile.TemporaryDirectory() as temp_dir:
            nested_path = os.path.join(temp_dir, "nested", "subdir", "results.sarif")
            
            # Mock the enricher to avoid external API calls
            with patch('src.workbench_cli.utilities.sarif_generation.enrich_vulnerabilities') as mock_enrich:
                mock_enrich.return_value = {}
                
                save_vulns_to_sarif(nested_path, sample_vulns, "TEST_SCAN")
                
                assert os.path.exists(nested_path)
                with open(nested_path, 'r') as f:
                    saved_data = json.load(f)
                
                assert saved_data["version"] == "2.1.0"

    def test_save_vulns_to_sarif_io_error(self):
        """Test handling of IO errors during SARIF file saving."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "severity": "HIGH",
                "component_name": "test-package",
                "component_version": "1.0.0"
            }
        ]
        
        # Use an invalid path that should cause an error
        invalid_path = "/invalid/path/that/should/not/exist/results.sarif"
        
        with pytest.raises((IOError, OSError)):
            with patch('src.workbench_cli.utilities.sarif_generation.enrich_vulnerabilities') as mock_enrich:
                mock_enrich.return_value = {}
                save_vulns_to_sarif(invalid_path, sample_vulns, "TEST_SCAN")

    def test_handle_missing_vulnerability_fields(self):
        """Test handling of vulnerabilities with missing fields."""
        incomplete_vulns = [
            {
                "id": 1,
                # Missing cve field
                "severity": "HIGH",
                "component_name": "test-package",
                # Missing component_version
            },
            {
                "id": 2,
                "cve": "CVE-2022-67890",
                # Missing severity
                # Missing component_name and component_version
            }
        ]
        
        with patch('src.workbench_cli.utilities.sarif_generation.enrich_vulnerabilities') as mock_enrich:
            mock_enrich.return_value = {}
            
            sarif_data = convert_vulns_to_sarif(incomplete_vulns, "TEST_SCAN")
            
            # Should still create valid SARIF even with missing fields
            assert sarif_data["version"] == "2.1.0"
            assert len(sarif_data["runs"]) == 1
            
            run = sarif_data["runs"][0]
            assert len(run["results"]) == 2
            
            # Verify default values are used for missing fields
            results = run["results"]
            first_result = results[0]
            assert first_result["ruleId"] == "UNKNOWN:test-package@Unknown"  # Default for missing CVE
            
            second_result = results[1]
            assert second_result["ruleId"] == "CVE-2022-67890:Unknown@Unknown"
            assert "CVE-2022-67890" in second_result["message"]["text"]  # CVE should be in message

    def test_sarif_schema_compliance(self):
        """Test that generated SARIF complies with the expected schema structure."""
        sample_vulns = [
            {
                "id": 1,
                "cve": "CVE-2022-12345",
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "availability_impact": "HIGH"
            }
        ]
        
        with patch('src.workbench_cli.utilities.sarif_generation.enrich_vulnerabilities') as mock_enrich:
            mock_enrich.return_value = {}
            
            sarif_data = convert_vulns_to_sarif(sample_vulns, "TEST_SCAN")
            
            # Validate required SARIF fields
            assert "$schema" in sarif_data
            assert sarif_data["$schema"] == "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/csd01/schemas/sarif-schema-2.1.0.json"
            assert sarif_data["version"] == "2.1.0"
            assert "runs" in sarif_data
            assert len(sarif_data["runs"]) == 1
            
            run = sarif_data["runs"][0]
            assert "tool" in run
            assert "driver" in run["tool"]
            assert "results" in run
            
            driver = run["tool"]["driver"]
            assert "name" in driver
            assert "rules" in driver
            
            # Validate rule structure
            for rule in driver["rules"]:
                assert "id" in rule
                assert "name" in rule
                assert "defaultConfiguration" in rule
                assert "level" in rule["defaultConfiguration"]
            
            # Validate result structure
            for result in run["results"]:
                assert "ruleId" in result
                assert "level" in result
                assert "message" in result
                assert "text" in result["message"]
                assert "locations" in result
                assert len(result["locations"]) > 0
                
                location = result["locations"][0]
                assert "physicalLocation" in location
                assert "artifactLocation" in location["physicalLocation"]
                assert "uri" in location["physicalLocation"]["artifactLocation"]

    def test_enhanced_functions_compatibility(self):
        """Test that enhanced functions work correctly with and without external data."""
        sample_vulns = [
            {
                "cve": "CVE-2022-12345",
                "cvss_version": "3.1",
                "base_score": "9.8",
                "severity": "CRITICAL",
                "component_name": "test-package",
                "component_version": "1.0.0"
            }
        ]
        
        # Test _generate_enhanced_rules function without external data
        rules = _generate_enhanced_rules(sample_vulns, {})
        assert len(rules) == 1
        assert rules[0]["id"] == "CVE-2022-12345:test-package@1.0.0"
        
        # Test _generate_enhanced_results function without external data
        results = _generate_enhanced_results(sample_vulns, {})
        assert len(results) == 1
        assert results[0]["ruleId"] == "CVE-2022-12345:test-package@1.0.0"
        
        # Test with external data
        external_data = {
            "CVE-2022-12345": {
                "epss_score": 0.85,
                "epss_percentile": 0.95,
                "cisa_kev": True
            }
        }
        
        rules_with_external = _generate_enhanced_rules(sample_vulns, external_data)
        assert len(rules_with_external) == 1
        assert rules_with_external[0]["properties"]["epss_score"] == 0.85
        assert rules_with_external[0]["properties"]["cisa_known_exploited"] == True
        
        results_with_external = _generate_enhanced_results(sample_vulns, external_data)
        assert len(results_with_external) == 1
        assert results_with_external[0]["properties"]["epss_score"] == 0.85
        assert results_with_external[0]["properties"]["cisa_known_exploited"] == True


class TestVulnerabilityEnricher:
    """Test cases for vulnerability enrichment functionality."""

    def test_enrich_vulnerabilities_empty_list(self):
        """Test enrichment with empty CVE list."""
        result = enrich_vulnerabilities([])
        assert result == {}

    @patch('src.workbench_cli.utilities.vuln_report.cve_data_gathering.requests.get')
    def test_fetch_epss_scores_success(self, mock_get):
        """Test successful EPSS score fetching."""
        mock_response = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2022-12345",
                    "epss": "0.85000",
                    "percentile": "0.95000"
                }
            ]
        }
        mock_get.return_value.json.return_value = mock_response
        mock_get.return_value.raise_for_status.return_value = None
        
        result = _fetch_epss_scores(["CVE-2022-12345"])
        
        assert "CVE-2022-12345" in result
        assert result["CVE-2022-12345"]["epss_score"] == 0.85
        assert result["CVE-2022-12345"]["epss_percentile"] == 0.95

    @patch('src.workbench_cli.utilities.vuln_report.cve_data_gathering.requests.get')
    def test_fetch_cisa_kev_data_success(self, mock_get):
        """Test successful CISA KEV data fetching."""
        mock_response = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2022-12345",
                    "vendorProject": "Test Vendor",
                    "product": "Test Product"
                }
            ]
        }
        mock_get.return_value.json.return_value = mock_response
        mock_get.return_value.raise_for_status.return_value = None
        
        result = _fetch_cisa_kev_data(["CVE-2022-12345", "CVE-2022-99999"])
        
        assert "CVE-2022-12345" in result
        assert "CVE-2022-99999" not in result

    def test_rate_limiter_functionality(self):
        """Test rate limiter functionality."""
        limiter = RateLimiter(max_workers=2, delay=0.1)
        
        start_time = time.time()
        
        # Should allow first two requests immediately
        limiter.wait()
        limiter.wait()
        
        # Third request should be delayed
        limiter.wait()
        
        elapsed = time.time() - start_time
        assert elapsed >= 0.1  # Should have waited at least 0.1 seconds

    @patch('src.workbench_cli.utilities.vuln_report.cve_data_gathering.requests.get')
    def test_parse_nvd_vulnerability(self, mock_get):
        """Test parsing of NVD vulnerability data."""
        nvd_vuln_data = {
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Test vulnerability description"
                }
            ],
            "weaknesses": [
                {
                    "type": "Primary",
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
                    "url": "https://example.com/vuln",
                    "source": "test",
                    "tags": ["Exploit"]
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            "baseScore": 6.1
                        }
                    }
                ]
            }
        }
        
        result = _parse_nvd_vulnerability(nvd_vuln_data)
        
        assert result["nvd_description"] == "Test vulnerability description"
        assert result["nvd_cwe"] == ["CWE-79"]
        assert len(result["nvd_references"]) == 1
        assert result["nvd_references"][0]["url"] == "https://example.com/vuln"
        assert result["full_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        assert result["cvss_score"] == 6.1

 