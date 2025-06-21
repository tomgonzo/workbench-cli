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
    """Test cases for the main SBOMValidator functionality."""

    def test_validate_sbom_file_nonexistent_file(self):
        """Test validation fails for non-existent file."""
        with pytest.raises(FileSystemError, match="SBOM file does not exist"):
            SBOMValidator.validate_and_prepare_sbom("/path/to/nonexistent/file.json")

    def test_validate_sbom_file_not_a_file(self):
        """Test validation fails when path is not a file."""
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=False):
                with pytest.raises(ValidationError, match="Path must be a file"):
                    SBOMValidator.validate_and_prepare_sbom("/path/to/directory")

    def test_validate_sbom_file_unsupported_extension(self):
        """Test validation fails for unsupported file extension."""
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with pytest.raises(ValidationError, match="Unsupported file extension"):
                    SBOMValidator.validate_and_prepare_sbom("/path/to/file.txt")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._detect_sbom_format', return_value='cyclonedx')
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._validate_cyclonedx')
    def test_validate_sbom_file_cyclonedx_success(self, mock_validate_cyclonedx, mock_detect, mock_isfile, mock_exists):
        """Test successful validation of CycloneDX file."""
        mock_validate_cyclonedx.return_value = ('cyclonedx', '1.6', {'components_count': 42}, {"bomFormat": "CycloneDX"})
        
        result = SBOMValidator.validate_sbom_file("/path/to/file.json")
        
        assert result == ('cyclonedx', '1.6', {'components_count': 42}, {"bomFormat": "CycloneDX"})
        mock_validate_cyclonedx.assert_called_once_with("/path/to/file.json")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._detect_sbom_format', return_value='spdx')
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._validate_spdx')
    def test_validate_sbom_file_spdx_success(self, mock_validate_spdx, mock_detect, mock_isfile, mock_exists):
        """Test successful validation of SPDX file."""
        from spdx_tools.spdx.model import Document
        mock_document = MagicMock(spec=Document)
        mock_validate_spdx.return_value = ('spdx', '2.3', {'packages_count': 15}, mock_document)
        
        result = SBOMValidator.validate_sbom_file("/path/to/file.json")
        
        assert result == ('spdx', '2.3', {'packages_count': 15}, mock_document)
        mock_validate_spdx.assert_called_once_with("/path/to/file.json")

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('workbench_cli.utilities.sbom_validator.SBOMValidator._detect_sbom_format', return_value='unknown')
    def test_validate_sbom_file_unknown_format(self, mock_detect, mock_isfile, mock_exists):
        """Test validation fails for unknown format."""
        with pytest.raises(ValidationError, match="Unable to determine SBOM format"):
            SBOMValidator.validate_and_prepare_sbom("/path/to/file.json")

    def test_backward_compatibility_validate_sbom_file(self):
        """Test that the old method still works for backward compatibility."""
        with patch('workbench_cli.utilities.sbom_validator.SBOMValidator.validate_sbom_file') as mock_new_method:
            mock_new_method.return_value = ('cyclonedx', '1.6', {'components_count': 42}, {"bomFormat": "CycloneDX"})
            
            result = SBOMValidator.validate_sbom_file_deprecated("/path/to/file.json")
            
            assert result == ('cyclonedx', '1.6', {'components_count': 42})
            mock_new_method.assert_called_once_with("/path/to/file.json")

    def test_validate_and_prepare_sbom_convenience_method(self):
        """Test that the convenience method properly combines validation and preparation."""
        with patch('workbench_cli.utilities.sbom_validator.SBOMValidator.validate_sbom_file') as mock_validate:
            with patch('workbench_cli.utilities.sbom_validator.SBOMValidator.prepare_sbom_for_upload') as mock_prepare:
                # Mock validation results
                mock_validate.return_value = ('cyclonedx', '1.6', {'components_count': 42}, {"bomFormat": "CycloneDX"})
                # Mock preparation results
                mock_prepare.return_value = "/path/to/file.json"  # No conversion needed
                
                result = SBOMValidator.validate_and_prepare_sbom("/path/to/file.json")
                
                assert result == ('cyclonedx', '1.6', {'components_count': 42}, "/path/to/file.json")
                mock_validate.assert_called_once_with("/path/to/file.json")
                mock_prepare.assert_called_once_with("/path/to/file.json", 'cyclonedx', {"bomFormat": "CycloneDX"})


class TestFormatDetection:
    """Test cases for SBOM format detection."""

    def test_detect_cyclonedx_format_lower_case(self):
        """Test detection of CycloneDX format with lowercase markers."""
        content = '{"bomformat": "cyclonedx", "specVersion": "1.6"}'
        
        with patch('builtins.open', mock_open(read_data=content)):
            result = SBOMValidator._detect_sbom_format("/path/to/file.json")
            assert result == "cyclonedx"

    def test_detect_cyclonedx_format_proper_case(self):
        """Test detection of CycloneDX format with proper case markers."""
        content = '{"bomFormat": "CycloneDX", "specVersion": "1.6"}'
        
        with patch('builtins.open', mock_open(read_data=content)):
            result = SBOMValidator._detect_sbom_format("/path/to/file.json")
            assert result == "cyclonedx"

    def test_detect_spdx_json_format(self):
        """Test detection of SPDX JSON format."""
        content = '{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}'
        
        with patch('builtins.open', mock_open(read_data=content)):
            result = SBOMValidator._detect_sbom_format("/path/to/file.json")
            assert result == "spdx"

    def test_detect_spdx_rdf_format(self):
        """Test detection of SPDX RDF format."""
        content = '<rdf:RDF xmlns:spdx="http://spdx.org/spdxdocs/spdx-v2.3">'
        
        with patch('builtins.open', mock_open(read_data=content)):
            result = SBOMValidator._detect_sbom_format("/path/to/file.rdf")
            assert result == "spdx"

    def test_detect_unknown_format(self):
        """Test failure to detect unknown format."""
        content = '{"unknown": "format"}'
        
        with patch('builtins.open', mock_open(read_data=content)):
            with pytest.raises(ValidationError, match="Unable to detect SBOM format"):
                SBOMValidator._detect_sbom_format("/path/to/file.json")

    def test_detect_format_unicode_error_fallback(self):
        """Test fallback encoding when UTF-8 fails."""
        content = '<rdf:RDF xmlns:spdx="http://spdx.org/spdxdocs/spdx-v2.3">'
        
        with patch('builtins.open', side_effect=[UnicodeDecodeError('utf-8', b'', 0, 1, 'error'), mock_open(read_data=content).return_value]):
            result = SBOMValidator._detect_sbom_format("/path/to/file.rdf")
            assert result == "spdx"


class TestCycloneDXValidation:
    """Test cases for CycloneDX validation."""

    def test_validate_cyclonedx_missing_library(self):
        """Test validation fails when CycloneDX library is missing."""
        with patch('workbench_cli.utilities.sbom_validator.SBOMValidator._validate_cyclonedx') as mock_method:
            mock_method.side_effect = ImportError("CycloneDX library not available")
            
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('workbench_cli.utilities.sbom_validator.SBOMValidator._detect_sbom_format', return_value='cyclonedx'):
                        with pytest.raises(ValidationError, match="CycloneDX library not available"):
                            SBOMValidator.validate_and_prepare_sbom("/path/to/file.json")

    def test_validate_cyclonedx_success(self):
        """Test successful CycloneDX validation."""
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
                
                result = SBOMValidator._validate_cyclonedx("/path/to/file.json")
                
                assert result[0] == 'cyclonedx'
                assert result[1] == '1.6'
                assert result[2]['components_count'] == 1
                assert result[2]['serial_number'] == "urn:uuid:12345678-1234-1234-1234-123456789012"

    def test_validate_cyclonedx_invalid_format(self):
        """Test CycloneDX validation fails for invalid format."""
        invalid_json = {
            "bomFormat": "InvalidFormat",
            "specVersion": "1.6"
        }
        
        json_content = json.dumps(invalid_json)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="does not appear to be a CycloneDX BOM"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_missing_spec_version(self):
        """Test CycloneDX validation fails for missing spec version."""
        invalid_json = {
            "bomFormat": "CycloneDX"
        }
        
        json_content = json.dumps(invalid_json)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="missing specVersion field"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_unsupported_version(self):
        """Test CycloneDX validation fails for unsupported version."""
        invalid_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "2.0"  # Unsupported version
        }
        
        json_content = json.dumps(invalid_json)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="Unknown CycloneDX version"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_unsupported_upload_version(self):
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
                    SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_validation_errors(self):
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
                
                with pytest.raises(ValidationError, match="CycloneDX validation failed"):
                    SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_invalid_json(self):
        """Test CycloneDX validation fails for invalid JSON."""
        invalid_json_content = "{ invalid json"
        
        with patch('builtins.open', mock_open(read_data=invalid_json_content)):
            with pytest.raises(ValidationError, match="Invalid JSON format"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_file_not_found(self):
        """Test CycloneDX validation fails for file not found."""
        with patch('builtins.open', side_effect=FileNotFoundError("File not found")):
            with pytest.raises(FileSystemError, match="SBOM file not found"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")


class TestSPDXValidation:
    """Test cases for SPDX validation."""

    def test_validate_spdx_missing_library(self):
        """Test validation fails when SPDX library is missing."""
        # Create a mock that will simulate the ImportError from the try block
        with patch('sys.modules', {
            'spdx_tools': None,
            'spdx_tools.spdx': None,
            'spdx_tools.spdx.parser': None,
            'spdx_tools.spdx.parser.parse_anything': None,
            'spdx_tools.spdx.model': None,
            'spdx_tools.spdx.validation': None,
            'spdx_tools.spdx.validation.document_validator': None
        }):
            # Mock the specific imports to raise ImportError
            def mock_import(name, *args):
                if name.startswith('spdx_tools'):
                    raise ImportError("No module named 'spdx_tools'")
                return __import__(name, *args)
            
            with patch('builtins.__import__', side_effect=mock_import):
                with pytest.raises(ValidationError, match="SPDX tools library not available"):
                    SBOMValidator._validate_spdx("/path/to/file.rdf")

    def test_validate_spdx_rdf_success_no_conversion(self):
        """Test successful SPDX RDF validation without conversion needed."""
        from spdx_tools.spdx.model import Document, Version
        
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            with patch('spdx_tools.spdx.validation.document_validator.validate_full_spdx_document') as mock_validate:
                mock_document = MagicMock(spec=Document)
                
                # Create a mock version object that behaves like a Version instance
                mock_version = MagicMock(spec=Version)
                mock_version.value = "SPDX-2.3"
                mock_document.creation_info.spdx_version = mock_version
                
                mock_document.creation_info.name = "Test Document"
                mock_document.creation_info.document_namespace = "https://example.com/test"
                mock_document.packages = [MagicMock(), MagicMock()]  # 2 packages
                mock_document.files = [MagicMock() for _ in range(5)]  # 5 files
                
                mock_parse.return_value = mock_document
                mock_validate.return_value = []  # No validation errors
                
                result = SBOMValidator._validate_spdx("/path/to/file.rdf")
                
                assert result[0] == 'spdx'
                assert result[1] == '2.3'
                assert result[2]['name'] == "Test Document"
                assert result[2]['packages_count'] == 2
                assert result[2]['files_count'] == 5
                assert result[3] == mock_document  # Parsed document returned

    def test_validate_spdx_json_success_with_conversion(self):
        """Test successful SPDX JSON validation (validation only, no conversion in this test)."""
        from spdx_tools.spdx.model import Document, Version
        
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            with patch('spdx_tools.spdx.validation.document_validator.validate_full_spdx_document') as mock_validate:
                mock_document = MagicMock(spec=Document)
                
                mock_version = MagicMock(spec=Version)
                mock_version.value = "SPDX-2.3"
                mock_document.creation_info.spdx_version = mock_version
                
                mock_document.creation_info.name = "Test Document"
                mock_document.creation_info.document_namespace = "https://example.com/test"
                mock_document.packages = [MagicMock(), MagicMock()]
                mock_document.files = [MagicMock() for _ in range(5)]
                
                mock_parse.return_value = mock_document
                mock_validate.return_value = []
                
                result = SBOMValidator._validate_spdx("/path/to/file.json")
                
                assert result[0] == 'spdx'
                assert result[1] == '2.3'
                assert result[2]['name'] == "Test Document"
                assert result[3] == mock_document  # Parsed document returned

    def test_validate_spdx_invalid_document(self):
        """Test SPDX validation fails for invalid document."""
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            mock_parse.return_value = "not a document"  # Invalid return type
            
            with pytest.raises(ValidationError, match="does not contain a valid SPDX document"):
                SBOMValidator._validate_spdx("/path/to/file.rdf")

    def test_validate_spdx_validation_errors(self):
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
                    SBOMValidator._validate_spdx("/path/to/file.rdf")

    def test_validate_spdx_unsupported_version(self):
        """Test SPDX validation fails for unsupported version."""
        from spdx_tools.spdx.model import Document, Version
        
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            with patch('spdx_tools.spdx.validation.document_validator.validate_full_spdx_document') as mock_validate:
                mock_document = MagicMock(spec=Document)
                
                # Create a mock version object that behaves like a Version instance  
                mock_version = MagicMock(spec=Version)
                mock_version.value = "SPDX-3.0"  # Unsupported
                mock_document.creation_info.spdx_version = mock_version
                
                mock_parse.return_value = mock_document
                mock_validate.return_value = []
                
                with pytest.raises(ValidationError, match="SPDX version 3.0 is not supported"):
                    SBOMValidator._validate_spdx("/path/to/file.rdf")

    def test_validate_spdx_file_not_found(self):
        """Test SPDX validation fails for file not found."""
        with patch('spdx_tools.spdx.parser.parse_anything.parse_file') as mock_parse:
            mock_parse.side_effect = FileNotFoundError("File not found")
            
            with pytest.raises(FileSystemError, match="SBOM file not found"):
                SBOMValidator._validate_spdx("/path/to/file.rdf")


class TestCleanupUtility:
    """Test cases for cleanup utility methods."""

    def test_cleanup_temp_file_success(self):
        """Test successful cleanup of temporary file."""
        temp_file = "/tmp/spdx_converted_abc123.rdf"
        
        with patch('os.path.exists', return_value=True):
            with patch('os.unlink') as mock_unlink:
                with patch('tempfile.gettempdir', return_value="/tmp"):
                    SBOMValidator.cleanup_temp_file(temp_file)
                    mock_unlink.assert_called_once_with(temp_file)

    def test_cleanup_temp_file_not_temp(self):
        """Test cleanup skips non-temporary files."""
        regular_file = "/home/user/regular_file.rdf"
        
        with patch('os.path.exists', return_value=True):
            with patch('os.unlink') as mock_unlink:
                with patch('tempfile.gettempdir', return_value="/tmp"):
                    SBOMValidator.cleanup_temp_file(regular_file)
                    mock_unlink.assert_not_called()

    def test_cleanup_temp_file_not_exists(self):
        """Test cleanup handles non-existent file gracefully."""
        temp_file = "/tmp/nonexistent.rdf"
        
        with patch('os.path.exists', return_value=False):
            with patch('os.unlink') as mock_unlink:
                with patch('tempfile.gettempdir', return_value="/tmp"):
                    SBOMValidator.cleanup_temp_file(temp_file)
                    mock_unlink.assert_not_called()

    def test_cleanup_temp_file_failure(self):
        """Test cleanup handles unlink failure gracefully."""
        temp_file = "/tmp/spdx_converted_abc123.rdf"
        
        with patch('os.path.exists', return_value=True):
            with patch('os.unlink', side_effect=OSError("Permission denied")):
                with patch('tempfile.gettempdir', return_value="/tmp"):
                    with patch('workbench_cli.utilities.sbom_validator.logger.warning') as mock_warning:
                        SBOMValidator.cleanup_temp_file(temp_file)
                        mock_warning.assert_called_once()


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
        
        # Check that SPDX now includes JSON extension
        assert '.json' in spdx_info['supported_extensions']


class TestSBOMPreparation:
    """Test cases for SBOM preparation functionality."""

    def test_prepare_cyclonedx_no_conversion(self):
        """Test that CycloneDX files don't need conversion."""
        parsed_bom = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
        
        result = SBOMValidator.prepare_sbom_for_upload("/path/to/file.json", "cyclonedx", parsed_bom)
        
        assert result == "/path/to/file.json"  # Original file returned

    def test_prepare_spdx_rdf_no_conversion(self):
        """Test that SPDX RDF files don't need conversion."""
        from spdx_tools.spdx.model import Document
        parsed_document = MagicMock(spec=Document)
        
        result = SBOMValidator.prepare_sbom_for_upload("/path/to/file.rdf", "spdx", parsed_document)
        
        assert result == "/path/to/file.rdf"  # Original file returned

    def test_prepare_spdx_json_with_conversion(self):
        """Test that SPDX JSON files are converted to RDF."""
        from spdx_tools.spdx.model import Document
        
        with patch('spdx_tools.spdx.writer.write_anything.write_file') as mock_write:
            with patch('tempfile.mkstemp') as mock_mkstemp:
                with patch('os.close') as mock_close:
                    parsed_document = MagicMock(spec=Document)
                    mock_mkstemp.return_value = (123, "/tmp/spdx_converted_abc123.rdf")
                    
                    result = SBOMValidator.prepare_sbom_for_upload("/path/to/file.json", "spdx", parsed_document)
                    
                    assert result == "/tmp/spdx_converted_abc123.rdf"
                    mock_write.assert_called_once_with(parsed_document, "/tmp/spdx_converted_abc123.rdf", validate=False)
                    mock_close.assert_called_once_with(123)

    def test_prepare_unknown_format_error(self):
        """Test that unknown formats raise an error."""
        with pytest.raises(ValidationError, match="Unknown SBOM format: unknown"):
            SBOMValidator.prepare_sbom_for_upload("/path/to/file.json", "unknown", {}) 