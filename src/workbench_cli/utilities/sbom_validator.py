# workbench_cli/utilities/sbom_validator.py

import os
import json
import logging
from typing import Tuple, Dict, Any, Optional
from pathlib import Path

from ..exceptions import ValidationError, FileSystemError

logger = logging.getLogger("workbench-cli")

class SBOMValidator:
    """
    Utility class for validating SBOM files (SPDX RDF and CycloneDX JSON formats).
    """
    
    SUPPORTED_EXTENSIONS = {'.json', '.rdf', '.xml', '.spdx'}
    
    @staticmethod
    def validate_sbom_file(file_path: str) -> Tuple[str, str, Dict[str, Any]]:
        """
        Validates an SBOM file and determines its format and version.
        
        Args:
            file_path: Path to the SBOM file to validate
            
        Returns:
            Tuple[str, str, Dict[str, Any]]: (format, version, metadata)
            - format: "cyclonedx" or "spdx"
            - version: version string (e.g., "1.6", "2.3")
            - metadata: additional metadata about the document
            
        Raises:
            FileSystemError: If the file doesn't exist or can't be read
            ValidationError: If the file is not a valid SBOM or unsupported format/version
        """
        if not os.path.exists(file_path):
            raise FileSystemError(f"SBOM file does not exist: {file_path}")
        
        if not os.path.isfile(file_path):
            raise ValidationError(f"Path must be a file: {file_path}")
        
        file_ext = Path(file_path).suffix.lower()
        if file_ext not in SBOMValidator.SUPPORTED_EXTENSIONS:
            raise ValidationError(f"Unsupported file extension '{file_ext}'. Supported extensions: {', '.join(SBOMValidator.SUPPORTED_EXTENSIONS)}")
        
        logger.debug(f"Validating SBOM file: {file_path}")
        
        # Try to determine format based on file content
        try:
            if file_ext == '.json':
                return SBOMValidator._validate_cyclonedx_json(file_path)
            elif file_ext in {'.rdf', '.xml', '.spdx'}:
                return SBOMValidator._validate_spdx_rdf(file_path)
            else:
                raise ValidationError(f"Unable to determine SBOM format for file: {file_path}")
        except Exception as e:
            if isinstance(e, (ValidationError, FileSystemError)):
                raise
            logger.error(f"Error validating SBOM file '{file_path}': {e}", exc_info=True)
            raise ValidationError(f"Failed to validate SBOM file: {e}") from e
    
    @staticmethod
    def _validate_cyclonedx_json(file_path: str) -> Tuple[str, str, Dict[str, Any]]:
        """
        Validates a CycloneDX JSON file.
        """
        try:
            from cyclonedx.validation.json import JsonStrictValidator
            from cyclonedx.schema import SchemaVersion
        except ImportError as e:
            raise ValidationError("CycloneDX library not available. Please install cyclonedx-python-lib.") from e
        
        try:
            # Read the JSON file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse JSON to check format and extract metadata
            bom_data = json.loads(content)
            
            # Check if it looks like a CycloneDX BOM
            if "bomFormat" not in bom_data or bom_data.get("bomFormat") != "CycloneDX":
                raise ValidationError("File does not appear to be a CycloneDX BOM (missing or incorrect bomFormat)")
            
            # Get spec version
            spec_version = bom_data.get("specVersion", "")
            if not spec_version:
                raise ValidationError("CycloneDX BOM is missing specVersion field")
            
            # Map spec version to SchemaVersion enum
            version_mapping = {
                "1.6": SchemaVersion.V1_6,
                "1.5": SchemaVersion.V1_5,
                "1.4": SchemaVersion.V1_4,
                "1.3": SchemaVersion.V1_3,
                "1.2": SchemaVersion.V1_2,
                "1.1": SchemaVersion.V1_1,
                "1.0": SchemaVersion.V1_0
            }
            
            schema_version = version_mapping.get(spec_version)
            if not schema_version:
                raise ValidationError(f"Unknown CycloneDX version {spec_version}. Supported versions for validation: {', '.join(version_mapping.keys())}")
            
            # Validate using the official validator for the detected version
            validator = JsonStrictValidator(schema_version)
            try:
                validation_errors = list(validator.validate_str(content))
                if validation_errors:
                    error_messages = [str(error) for error in validation_errors[:5]]  # Show first 5 errors
                    raise ValidationError(f"CycloneDX validation failed: {'; '.join(error_messages)}")
            except Exception as validation_error:
                # If the validator itself fails, still try to proceed but log the issue
                logger.warning(f"CycloneDX validator encountered an issue: {validation_error}")
                # We'll still proceed if basic structure is valid
            
            # NOW check if version is supported for upload (1.4-1.6)
            supported_upload_versions = ["1.4", "1.5", "1.6"]
            if spec_version not in supported_upload_versions:
                raise ValidationError(f"Valid CycloneDX {spec_version} SBOM detected, but only versions {', '.join(supported_upload_versions)} are supported for import. Please convert your SBOM to a supported version.")
            
            logger.debug(f"Successfully validated CycloneDX JSON file, version {spec_version}")
            
            # Extract metadata
            metadata = {
                "spec_version": spec_version,
                "serial_number": bom_data.get("serialNumber"),
                "version": bom_data.get("version", 1),
                "components_count": len(bom_data.get("components", []))
            }
            
            return "cyclonedx", spec_version, metadata
            
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON format: {e}") from e
        except FileNotFoundError:
            raise FileSystemError(f"SBOM file not found: {file_path}")
        except ValidationError:
            raise  # Re-raise validation errors as-is
        except Exception as e:
            logger.error(f"Unexpected error validating CycloneDX file '{file_path}': {e}", exc_info=True)
            raise ValidationError(f"Failed to validate CycloneDX file: {e}") from e
    
    @staticmethod
    def _validate_spdx_rdf(file_path: str) -> Tuple[str, str, Dict[str, Any]]:
        """
        Validates an SPDX RDF/XML file.
        """
        try:
            from spdx_tools.spdx.parser.parse_anything import parse_file
            from spdx_tools.spdx.model import Document, Version
            from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
        except ImportError as e:
            raise ValidationError("SPDX tools library not available. Please install spdx-tools.") from e
        
        try:
            # Parse the SPDX file
            document = parse_file(file_path)
            
            if not isinstance(document, Document):
                raise ValidationError("File does not contain a valid SPDX document")
            
            # Validate the document
            validation_messages = validate_full_spdx_document(document)
            if validation_messages:
                error_messages = [msg.validation_message for msg in validation_messages]
                raise ValidationError(f"SPDX document validation failed: {'; '.join(error_messages[:5])}")  # Show first 5 errors
            
            # Get version
            spdx_version = document.creation_info.spdx_version
            if isinstance(spdx_version, Version):
                version_str = spdx_version.value.replace("SPDX-", "")
            else:
                version_str = str(spdx_version).replace("SPDX-", "")
            
            # Check if version is supported (2.0-2.3)
            supported_versions = {"2.0", "2.1", "2.2", "2.3"}
            if version_str not in supported_versions:
                raise ValidationError(f"SPDX version {version_str} is not supported. Supported versions: {', '.join(supported_versions)}")
            
            logger.debug(f"Successfully validated SPDX RDF file, version {version_str}")
            
            metadata = {
                "spdx_version": version_str,
                "name": document.creation_info.name,
                "document_namespace": document.creation_info.document_namespace,
                "packages_count": len(document.packages) if document.packages else 0,
                "files_count": len(document.files) if document.files else 0
            }
            
            return "spdx", version_str, metadata
            
        except ValidationError:
            raise  # Re-raise validation errors as-is
        except FileNotFoundError:
            raise FileSystemError(f"SBOM file not found: {file_path}")
        except Exception as e:
            logger.error(f"Unexpected error validating SPDX file '{file_path}': {e}", exc_info=True)
            raise ValidationError(f"Failed to validate SPDX file: {e}") from e

    @staticmethod
    def get_supported_formats() -> Dict[str, Dict[str, Any]]:
        """
        Returns information about supported SBOM formats.
        
        Returns:
            Dict containing supported formats and their details
        """
        return {
            "cyclonedx": {
                "name": "CycloneDX",
                "supported_versions": ["1.4", "1.5", "1.6"],
                "supported_extensions": [".json"],
                "description": "CycloneDX JSON format"
            },
            "spdx": {
                "name": "SPDX",
                "supported_versions": ["2.0", "2.1", "2.2", "2.3"],
                "supported_extensions": [".rdf", ".xml", ".spdx"],
                "description": "SPDX RDF/XML format"
            }
        } 