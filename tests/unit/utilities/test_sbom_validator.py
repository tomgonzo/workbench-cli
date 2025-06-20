# tests/unit/utilities/test_sbom_validator.py

import pytest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path

from workbench_cli.utilities.sbom_validator import SBOMValidator
from workbench_cli.exceptions import ValidationError, FileSystemError


class TestSBOMValidator:
    """Test cases for the SBOM validator utility."""

    def test_validate_sbom_file_nonexistent_file(self):
        """Test validation fails for non-existent file."""
        with pytest.raises(FileSystemError, match="SBOM file does not exist"):
            SBOMValidator.validate_sbom_file("/nonexistent/file.json")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=False)
    def test_validate_sbom_file_not_a_file(self, mock_isfile, mock_exists):
        """Test validation fails when path is not a file."""
        with pytest.raises(ValidationError, match="Path must be a file"):
            SBOMValidator.validate_sbom_file("/path/to/directory")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_validate_sbom_file_unsupported_extension(self, mock_isfile, mock_exists):
        """Test validation fails for unsupported file extension."""
        with pytest.raises(ValidationError, match="Unsupported file extension"):
            SBOMValidator.validate_sbom_file("/path/to/file.txt")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._validate_cyclonedx_json')
    def test_validate_sbom_file_json_success(self, mock_validate_cyclonedx, mock_isfile, mock_exists):
        """Test successful validation of JSON file."""
        mock_validate_cyclonedx.return_value = ('cyclonedx', '1.6', {'components_count': 42})
        
        result = SBOMValidator.validate_sbom_file("/path/to/file.json")
        
        assert result == ('cyclonedx', '1.6', {'components_count': 42})
        mock_validate_cyclonedx.assert_called_once_with("/path/to/file.json")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._validate_spdx_rdf')
    def test_validate_sbom_file_rdf_success(self, mock_validate_spdx, mock_isfile, mock_exists):
        """Test successful validation of RDF file."""
        mock_validate_spdx.return_value = ('spdx', '2.3', {'packages_count': 15})
        
        result = SBOMValidator.validate_sbom_file("/path/to/file.rdf")
        
        assert result == ('spdx', '2.3', {'packages_count': 15})
        mock_validate_spdx.assert_called_once_with("/path/to/file.rdf")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._validate_spdx_rdf')
    def test_validate_sbom_file_xml_success(self, mock_validate_spdx, mock_isfile, mock_exists):
        """Test successful validation of XML file."""
        mock_validate_spdx.return_value = ('spdx', '2.2', {'files_count': 100})
        
        result = SBOMValidator.validate_sbom_file("/path/to/file.xml")
        
        assert result == ('spdx', '2.2', {'files_count': 100})
        mock_validate_spdx.assert_called_once_with("/path/to/file.xml")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._validate_spdx_rdf')
    def test_validate_sbom_file_spdx_success(self, mock_validate_spdx, mock_isfile, mock_exists):
        """Test successful validation of .spdx file."""
        mock_validate_spdx.return_value = ('spdx', '2.1', {'packages_count': 25})
        
        result = SBOMValidator.validate_sbom_file("/path/to/file.spdx")
        
        assert result == ('spdx', '2.1', {'packages_count': 25})
        mock_validate_spdx.assert_called_once_with("/path/to/file.spdx")


class TestCycloneDXValidation:
    """Test cases for CycloneDX validation."""

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_validate_cyclonedx_json_missing_library(self, mock_isfile, mock_exists):
        """Test validation fails when CycloneDX library is missing."""
        with patch('workbench_cli.utilities.sbom_validator.SBOMValidator._validate_cyclonedx_json') as mock_method:
            mock_method.side_effect = ImportError("CycloneDX library not available")
            
            with pytest.raises(ValidationError, match="CycloneDX library not available"):
                SBOMValidator.validate_sbom_file("/path/to/file.json")

    def test_validate_cyclonedx_json_success(self):
        """Test successful CycloneDX JSON validation."""
        valid_cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789012",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-component",
                    "version": "1.0.0"
                }
            ]
        }
        
        json_content = json.dumps(valid_cyclonedx)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with patch('cyclonedx.validation.json.JsonStrictValidator') as mock_validator_class:
                mock_validator = MagicMock()
                mock_validator.validate_str.return_value = []  # No validation errors
                mock_validator_class.return_value = mock_validator
                
                result = SBOMValidator._validate_cyclonedx_json("/path/to/file.json")
                
                assert result[0] == 'cyclonedx'
                assert result[1] == '1.6'
                assert result[2]['components_count'] == 1
                assert result[2]['serial_number'] == "urn:uuid:12345678-1234-1234-1234-123456789012"

    def test_validate_cyclonedx_json_invalid_format(self):
        """Test CycloneDX validation fails for invalid format."""
        invalid_json = {
            "bomFormat": "InvalidFormat",
            "specVersion": "1.6"
        }
        
        json_content = json.dumps(invalid_json)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="does not appear to be a CycloneDX BOM"):
                SBOMValidator._validate_cyclonedx_json("/path/to/file.json")

    def test_validate_cyclonedx_json_missing_spec_version(self):
        """Test CycloneDX validation fails for missing spec version."""
        invalid_json = {
            "bomFormat": "CycloneDX"
        }
        
        json_content = json.dumps(invalid_json)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="missing specVersion field"):
                SBOMValidator._validate_cyclonedx_json("/path/to/file.json")

    def test_validate_cyclonedx_json_unsupported_version(self):
        """Test CycloneDX validation fails for unsupported version."""
        invalid_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "2.0"  # Unsupported version
        }
        
        json_content = json.dumps(invalid_json)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="Unknown CycloneDX version"):
                SBOMValidator._validate_cyclonedx_json("/path/to/file.json")

    def test_validate_cyclonedx_json_unsupported_upload_version(self):
        """Test CycloneDX validation fails for versions not supported for upload."""
        invalid_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3"  # Valid but not supported for upload
        }
        
        json_content = json.dumps(invalid_json)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with patch('cyclonedx.validation.json.JsonStrictValidator') as mock_validator_class:
                mock_validator = MagicMock()
                mock_validator.validate_str.return_value = []
                mock_validator_class.return_value = mock_validator
                
                with pytest.raises(ValidationError, match="only versions 1.4, 1.5, 1.6 are supported for import"):
                    SBOMValidator._validate_cyclonedx_json("/path/to/file.json")

    def test_validate_cyclonedx_json_validation_errors(self):
        """Test CycloneDX validation fails with validation errors."""
        valid_cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": []
        }
        
        json_content = json.dumps(valid_cyclonedx)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with patch('cyclonedx.validation.json.JsonStrictValidator') as mock_validator_class:
                mock_validator = MagicMock()
                mock_validator.validate_str.return_value = ["Validation error 1", "Validation error 2"]
                mock_validator_class.return_value = mock_validator
                
                with patch('workbench_cli.utilities.sbom_validator.logger.warning') as mock_logger:
                    result = SBOMValidator._validate_cyclonedx_json("/path/to/file.json")
                    mock_logger.assert_called_once()
                    assert result[0] == 'cyclonedx'
                    assert result[1] == '1.6'

    def test_validate_cyclonedx_json_invalid_json(self):
        """Test CycloneDX validation fails for invalid JSON."""
        invalid_json_content = "{ invalid json"
        
        with patch('builtins.open', mock_open(read_data=invalid_json_content)):
            with pytest.raises(ValidationError, match="Invalid JSON format"):
                SBOMValidator._validate_cyclonedx_json("/path/to/file.json")

    def test_validate_cyclonedx_json_file_not_found(self):
        """Test CycloneDX validation fails for file not found."""
        with patch('builtins.open', side_effect=FileNotFoundError("File not found")):
            with pytest.raises(FileSystemError, match="SBOM file not found"):
                SBOMValidator._validate_cyclonedx_json("/path/to/file.json")


class TestSPDXValidation:
    """Test cases for SPDX validation."""

    def test_validate_spdx_rdf_missing_library(self):
        """Test validation fails when SPDX library is missing."""
        # Mock the import by patching the actual import statements in the function
        with patch('workbench_cli.utilities.sbom_validator.importlib.import_module', side_effect=ImportError("No module named 'spdx_tools'")):
            with pytest.raises(ValidationError, match="SPDX tools library not available"):
                SBOMValidator._validate_spdx_rdf("/path/to/file.rdf")

    def test_validate_spdx_rdf_success(self):
        """Test successful SPDX RDF validation."""
        from spdx_tools.spdx.model import Document
        
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            with patch('spdx_tools.spdx.validation.document_validator.validate_full_spdx_document') as mock_validate:
                mock_document = MagicMock(spec=Document)
                
                mock_version = MagicMock()
                mock_version.value = "SPDX-2.3"
                mock_document.creation_info.spdx_version = mock_version
                
                mock_document.creation_info.name = "Test Document"
                mock_document.creation_info.document_namespace = "https://example.com/test"
                mock_document.packages = [MagicMock(), MagicMock()]  # 2 packages
                mock_document.files = [MagicMock() for _ in range(5)]  # 5 files
                
                mock_parse.return_value = mock_document
                mock_validate.return_value = []  # No validation errors
                
                result = SBOMValidator._validate_spdx_rdf("/path/to/file.rdf")
                
                assert result[0] == 'spdx'
                assert result[1] == '2.3'
                assert result[2]['name'] == "Test Document"
                assert result[2]['packages_count'] == 2
                assert result[2]['files_count'] == 5

    def test_validate_spdx_rdf_invalid_document(self):
        """Test SPDX validation fails for invalid document."""
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            mock_parse.return_value = "not a document"  # Invalid return type
            
            with pytest.raises(ValidationError, match="does not contain a valid SPDX document"):
                SBOMValidator._validate_spdx_rdf("/path/to/file.rdf")

    def test_validate_spdx_rdf_validation_errors(self):
        """Test SPDX validation fails with validation errors."""
        from spdx_tools.spdx.model import Document
        
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            with patch('spdx_tools.spdx.validation.document_validator.validate_full_spdx_document') as mock_validate:
                mock_document = MagicMock(spec=Document)
                mock_parse.return_value = mock_document
                
                mock_error = MagicMock()
                mock_error.validation_message = "Validation error"
                mock_validate.return_value = [mock_error]
                
                with pytest.raises(ValidationError, match="SPDX document validation failed"):
                    SBOMValidator._validate_spdx_rdf("/path/to/file.rdf")

    def test_validate_spdx_rdf_unsupported_version(self):
        """Test SPDX validation fails for unsupported version."""
        from spdx_tools.spdx.model import Document
        
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            with patch('spdx_tools.spdx.validation.document_validator.validate_full_spdx_document') as mock_validate:
                mock_document = MagicMock(spec=Document)
                
                mock_version = MagicMock()
                mock_version.value = "SPDX-3.0"  # Unsupported
                mock_document.creation_info.spdx_version = mock_version
                
                mock_parse.return_value = mock_document
                mock_validate.return_value = []
                
                with pytest.raises(ValidationError, match="SPDX version 3.0 is not supported"):
                    SBOMValidator._validate_spdx_rdf("/path/to/file.rdf")

    def test_validate_spdx_rdf_file_not_found(self):
        """Test SPDX validation fails for file not found."""
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            mock_parse.side_effect = FileNotFoundError("File not found")
            
            with pytest.raises(FileSystemError, match="SBOM file not found"):
                SBOMValidator._validate_spdx_rdf("/path/to/file.rdf")


class TestSupportedFormatsMethod:
    """Test cases for get_supported_formats method."""

    def test_get_supported_formats_structure(self):
        """Test that get_supported_formats returns the expected structure."""
        formats = SBOMValidator.get_supported_formats()
        
        assert isinstance(formats, dict)
        assert 'cyclonedx' in formats
        assert 'spdx' in formats
        
        # Check CycloneDX format
        cyclonedx_info = formats['cyclonedx']
        assert 'name' in cyclonedx_info
        assert 'supported_versions' in cyclonedx_info
        assert 'supported_extensions' in cyclonedx_info
        assert isinstance(cyclonedx_info['supported_versions'], list)
        assert isinstance(cyclonedx_info['supported_extensions'], list)
        
        # Check SPDX format
        spdx_info = formats['spdx']
        assert 'name' in spdx_info
        assert 'supported_versions' in spdx_info
        assert 'supported_extensions' in spdx_info
        assert isinstance(spdx_info['supported_versions'], list)
        assert isinstance(spdx_info['supported_extensions'], list) 