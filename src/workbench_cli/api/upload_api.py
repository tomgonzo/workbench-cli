import logging
import os
import base64
import tempfile
import shutil
from .helpers.upload_helpers import UploadHelper
from ..utilities.prep_upload_archive import UploadArchivePrep
from ..exceptions import (
    NetworkError,
    FileSystemError,
    WorkbenchCLIError,
    ApiError
)

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-cli")

class UploadAPI(UploadHelper):
    """
    Workbench API Upload Operations - handles file and directory uploads.
    """

    def upload_scan_target(self, scan_code: str, path: str):
        """
        Uploads a file or directory (as zip) to a scan.

        Args:
            scan_code: Code of the scan to upload to
            path: Path to the file or directory to upload
        """
        if not os.path.exists(path):
            raise FileSystemError(f"Path does not exist: {path}")

        archive_path = None
        temp_dir = None
        
        try:
            upload_path = path
            if os.path.isdir(path):
                print("The path provided is a directory. Compressing for upload...")
                archive_path = UploadArchivePrep.create_zip_archive(path)
                upload_path = archive_path
                temp_dir = os.path.dirname(archive_path)

            upload_basename = os.path.basename(upload_path)
            name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
            scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")
            
            headers = {
                "FOSSID-SCAN-CODE": scan_code_b64,
                "FOSSID-FILE-NAME": name_b64,
                "Accept": "*/*"
            }
            
            self._perform_upload(upload_path, headers)

        except (ApiError, NetworkError) as e:
            # Re-raise known exceptions
            raise
        except Exception as e:
            # Wrap unexpected exceptions
            raise WorkbenchCLIError(f"An unexpected error occurred during the upload process: {e}") from e

        finally:
            if archive_path and os.path.exists(archive_path):
                os.remove(archive_path)
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def upload_dependency_analysis_results(self, scan_code: str, path: str):
        """
        Uploads a dependency analysis result file to a scan.

        Args:
            scan_code: Code of the scan to upload to
            path: Path to the dependency analysis results file
        """
        if not os.path.exists(path) or not os.path.isfile(path):
            raise FileSystemError(f"Dependency analysis results file does not exist: {path}")

        upload_basename = os.path.basename(path)
        name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
        scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")
            
        headers = {
            "FOSSID-SCAN-CODE": scan_code_b64,
            "FOSSID-FILE-NAME": name_b64,
            "FOSSID-UPLOAD-TYPE": "dependency_analysis",
            "Accept": "*/*"
        }

        self._perform_upload(path, headers)

    def upload_sbom_file(self, scan_code: str, path: str):
        """
        Uploads an SBOM file to a scan.

        Args:
            scan_code: Code of the scan to upload to
            path: Path to the SBOM file to upload
        """
        if not os.path.exists(path) or not os.path.isfile(path):
            raise FileSystemError(f"SBOM file does not exist: {path}")

        upload_basename = os.path.basename(path)
        name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
        scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")
            
        headers = {
            "FOSSID-SCAN-CODE": scan_code_b64,
            "FOSSID-FILE-NAME": name_b64,
            "Accept": "*/*"
        }

        self._perform_upload(path, headers)
