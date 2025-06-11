from typing import Dict, List, Optional, Union, Any, Generator, Tuple
import logging
import json
import requests
import os
import base64
import tempfile
import shutil
import time
import io
from .workbench_api_helpers import WorkbenchAPIHelpers
from ..utilities.prep_upload_archive import UploadArchivePrep
from ..exceptions import (
    NetworkError,
    FileSystemError,
    WorkbenchCLIError
)

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-cli")

class WorkbenchAPIUpload(WorkbenchAPIHelpers):
    """
    Workbench API Upload Operations - handles file and directory uploads with chunked upload support.
    This class contains all upload-related functionality including progress tracking and retry logic.
    """
    
    # --- Chunked Upload Constants ---
    CHUNKED_UPLOAD_THRESHOLD = 16 * 1024 * 1024  # 16MB
    CHUNK_SIZE = 5 * 1024 * 1024                 # 5MB
    MAX_CHUNK_RETRIES = 3
    PROGRESS_UPDATE_INTERVAL = 20                 # Percent
    SMALL_FILE_CHUNK_THRESHOLD = 5               # Always show progress for ≤5 chunks

    def _read_in_chunks(self, file_object: io.BufferedReader, chunk_size: int = 5 * 1024 * 1024) -> Generator[bytes, None, None]:
        """
        Reads a file in chunks to support efficient file upload.
        
        Args:
            file_object: File object to read
            chunk_size: Size of each chunk in bytes
            
        Yields:
            Bytes chunks from the file
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _upload_single_chunk(self, chunk: bytes, chunk_number: int, headers: dict) -> None:
        """
        Upload a single chunk with retry logic.
        
        Args:
            chunk: The chunk data to upload
            chunk_number: The chunk number (for logging)
            headers: Headers to use for the request
            
        Raises:
            NetworkError: If upload fails after all retries
        """
        retry_count = 0
        
        while retry_count <= self.MAX_CHUNK_RETRIES:
            try:
                # Create request manually to remove Content-Length header
                req = requests.Request(
                    'POST',
                    self.api_url,
                    headers=headers,
                    data=chunk,
                    auth=(self.api_user, self.api_token),
                )
                
                # Create a fresh session for each chunk
                chunk_session = requests.Session()
                prepped = chunk_session.prepare_request(req)
                if 'Content-Length' in prepped.headers:
                    del prepped.headers['Content-Length']
                    logger.debug(f"Removed Content-Length header for chunk {chunk_number}")
                
                # Send the request
                resp_chunk = chunk_session.send(prepped, timeout=1800)
                
                # Validate response
                self._validate_chunk_response(resp_chunk, chunk_number, retry_count)
                return  # Success!
                
            except requests.exceptions.RequestException as e:
                if retry_count < self.MAX_CHUNK_RETRIES:
                    logger.warning(f"Chunk {chunk_number} network error (attempt {retry_count + 1}/{self.MAX_CHUNK_RETRIES + 1}): {e}")
                    retry_count += 1
                    time.sleep(2)  # Longer delay for network issues
                    continue
                else:
                    logger.error(f"Chunk {chunk_number} failed after {self.MAX_CHUNK_RETRIES + 1} attempts: {e}")
                    raise NetworkError(f"Network error for chunk {chunk_number} after {self.MAX_CHUNK_RETRIES + 1} attempts: {e}")

    def _validate_chunk_response(self, response: requests.Response, chunk_number: int, retry_count: int) -> None:
        """
        Validate chunk upload response and handle retries.
        
        Args:
            response: The HTTP response from chunk upload
            chunk_number: The chunk number (for logging)
            retry_count: Current retry attempt
            
        Raises:
            NetworkError: If validation fails after all retries
        """
        # Check HTTP status
        if response.status_code != 200:
            error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
            if retry_count < self.MAX_CHUNK_RETRIES:
                logger.warning(f"Chunk {chunk_number} failed (attempt {retry_count + 1}/{self.MAX_CHUNK_RETRIES + 1}): {error_msg}")
                time.sleep(1)
                raise requests.exceptions.RequestException(f"HTTP {response.status_code}")
            else:
                logger.error(f"Chunk {chunk_number} upload failed after {self.MAX_CHUNK_RETRIES + 1} attempts: {error_msg}")
                response.raise_for_status()
        
        # Validate JSON response
        try:
            response.json()
            logger.debug(f"Chunk {chunk_number} response JSON parsed successfully")
        except json.JSONDecodeError:
            error_msg = f"Invalid JSON response: {response.text[:200]}"
            if retry_count < self.MAX_CHUNK_RETRIES:
                logger.warning(f"Chunk {chunk_number} JSON parsing failed (attempt {retry_count + 1}/{self.MAX_CHUNK_RETRIES + 1}): {error_msg}")
                time.sleep(1)
                raise requests.exceptions.RequestException("JSON decode error")
            else:
                logger.error(f"Chunk {chunk_number} upload: Failed to decode JSON response after {self.MAX_CHUNK_RETRIES + 1} attempts")
                raise NetworkError(f"Invalid JSON response from server for chunk {chunk_number}: {error_msg}")

    def _should_show_progress(self, progress_percent: int, last_progress: int, chunk_number: int, total_chunks: int) -> bool:
        """
        Determine if progress should be displayed.
        
        Args:
            progress_percent: Current progress percentage
            last_progress: Last progress percentage shown
            chunk_number: Current chunk number
            total_chunks: Total number of chunks
            
        Returns:
            bool: True if progress should be shown
        """
        return (
            progress_percent >= last_progress + self.PROGRESS_UPDATE_INTERVAL or 
            total_chunks <= self.SMALL_FILE_CHUNK_THRESHOLD or 
            chunk_number == total_chunks
        )

    def _format_progress_display(self, progress_percent: int, chunk_number: int, total_chunks: int, 
                               bytes_uploaded: int, elapsed_time: float) -> str:
        """
        Format progress display string with performance metrics.
        
        Args:
            progress_percent: Current progress percentage
            chunk_number: Current chunk number
            total_chunks: Total number of chunks
            bytes_uploaded: Total bytes uploaded so far
            elapsed_time: Time elapsed since upload start
            
        Returns:
            str: Formatted progress string
        """
        # Calculate speed
        speed_mbps = (bytes_uploaded / (1024 * 1024)) / elapsed_time
        if speed_mbps >= 1:
            speed_str = f"{speed_mbps:.1f}MB/s"
        else:
            speed_str = f"{speed_mbps * 1024:.0f}KB/s"
        
        # Calculate ETA
        if bytes_uploaded > 0 and hasattr(self, '_total_file_size'):
            remaining_bytes = self._total_file_size - bytes_uploaded
            eta_seconds = remaining_bytes / (bytes_uploaded / elapsed_time)
            if eta_seconds > 60:
                eta_str = f"ETA ~{eta_seconds/60:.0f}m"
            else:
                eta_str = f"ETA ~{eta_seconds:.0f}s"
        else:
            eta_str = "ETA ~?s"
        
        return f"Upload progress: {progress_percent:3d}% ({chunk_number}/{total_chunks} chunks) - {speed_str} - {eta_str}"

    def upload_files(self, scan_code: str, path: str, is_da_import: bool = False):
        """
        Uploads a file or directory (as zip) to a scan using the direct data
        posting method with custom headers, mimicking the original script's logic.
        
        Args:
            scan_code: Code of the scan to upload to
            path: Path to the file or directory to upload
            is_da_import: Whether this is a dependency analysis import
            
        Raises:
            FileSystemError: If the path doesn't exist or can't be archived
            NetworkError: If there are network issues during upload
            WorkbenchCLIError: For other unexpected errors
        """
        if not os.path.exists(path):
            raise FileSystemError(f"Path does not exist: {path}")

        archive_path = None
        upload_path = path
        original_basename = os.path.basename(path)
        file_handle = None
        temp_dir = None

        try:
            # --- Archive Directory if Necessary ---
            if os.path.isdir(path):
                print("The path provided is a directory. Compressing for upload...")
                logger.debug(f"Compressing target directory '{path}'...")
                
                # Use the dedicated archive preparation utility
                archive_path = UploadArchivePrep.create_zip_archive(path)
                upload_path = archive_path
                
                # Extract the parent directory of the archive (for cleanup)
                temp_dir = os.path.dirname(archive_path)
                
                # Perform upload for the archive
                self._perform_upload(scan_code, upload_path, is_da_import)
                
                # Clean up the temporary archive
                if archive_path and os.path.exists(archive_path):
                    os.remove(archive_path)
                    logger.debug(f"Deleted temporary archive: {archive_path}")
                
                # Clean up the temporary directory
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    logger.debug(f"Removed temporary directory: {temp_dir}")
                
            # --- Handle Single File Upload ---
            elif os.path.isfile(path):
                # Directly upload the file
                self._perform_upload(scan_code, path, is_da_import)
                
        except FileSystemError as e:
            logger.error(f"File system error during upload preparation for {path}: {e}", exc_info=True)
            raise  # Re-raise specific error
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during upload for {upload_path}: {e}", exc_info=True)
            raise NetworkError(f"Network error during file upload: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error during file upload for {path}: {e}", exc_info=True)
            # Wrap in a more specific error if possible, otherwise generic
            raise WorkbenchCLIError(f"Unexpected error during file upload process for '{path}'", details={"error": str(e)}) from e
        finally:
            # Ensure cleanup in case of exceptions
            if archive_path and os.path.exists(archive_path):
                try:
                    os.remove(archive_path)
                    logger.debug(f"Cleaned up temporary archive in finally block: {archive_path}")
                except Exception as cleanup_err:
                    logger.warning(f"Failed to clean up temporary archive: {cleanup_err}")
            
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    logger.debug(f"Cleaned up temporary directory in finally block: {temp_dir}")
                except Exception as cleanup_err:
                    logger.warning(f"Failed to clean up temporary directory: {cleanup_err}")
    
    def _perform_upload(self, scan_code: str, file_path: str, is_da_import: bool = False):
        """
        Upload a single file to a Workbench scan, using chunked upload for large files.
        
        Args:
            scan_code: Target scan code to upload to
            file_path: Path to the file to upload
            is_da_import: Whether this is a dependency analysis import operation
            
        Raises:
            NetworkError: If upload fails due to network issues
            FileNotFoundError: If the file to upload doesn't exist
        """
        file_handle = None
        try:
            file_size = os.path.getsize(file_path)
            
            # Use chunked upload for files larger than the threshold
            upload_basename = os.path.basename(file_path)
            
            # Encode headers
            name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
            scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")
            
            headers = {
                "FOSSID-SCAN-CODE": scan_code_b64,
                "FOSSID-FILE-NAME": name_b64,
                "Accept": "*/*"  # Keep Accept broad
            }
            
            if is_da_import:
                headers["FOSSID-UPLOAD-TYPE"] = "dependency_analysis"
                logger.debug(f"Uploading DA results file '{upload_basename}' ({file_size} bytes)...")
            else:
                logger.debug(f"Uploading file '{upload_basename}' ({file_size} bytes)...")
                
            logger.debug(f"Upload Request Headers: {headers}")
            
            file_handle = open(file_path, "rb")
            
            if file_size > self.CHUNKED_UPLOAD_THRESHOLD:
                logger.info(f"File size exceeds limit ({self.CHUNKED_UPLOAD_THRESHOLD} bytes). Using chunked upload...")
                
                headers['Transfer-Encoding'] = 'chunked'
                headers['Content-Type'] = 'application/octet-stream'
                
                # Calculate chunked upload details
                total_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE  # Ceiling division
                bytes_uploaded = 0
                start_time = time.time()
                last_progress_print = 0
                
                # Store for ETA calculation in helper method
                self._total_file_size = file_size
                
                print(f"Uploading {file_size // (1024*1024):.1f}MB in {total_chunks} ({self.CHUNK_SIZE // (1024*1024)}MB chunks)")
                
                # Main chunked upload loop - now much cleaner!
                for i, chunk in enumerate(self._read_in_chunks(file_handle, chunk_size=self.CHUNK_SIZE)):
                    chunk_number = i + 1
                    chunk_actual_size = len(chunk)
                    bytes_uploaded += chunk_actual_size
                    
                    # Data integrity check
                    if chunk_actual_size == 0:
                        logger.error(f"Chunk {chunk_number} has zero size! This will corrupt the upload.")
                        raise NetworkError(f"Chunk {chunk_number} has zero size")
                    
                    # Upload this chunk with retry logic
                    self._upload_single_chunk(chunk, chunk_number, headers)
                    
                    # Show progress if needed
                    progress_percent = min(100, (bytes_uploaded * 100) // file_size)
                    elapsed_time = time.time() - start_time
                    
                    if self._should_show_progress(progress_percent, last_progress_print, chunk_number, total_chunks) and elapsed_time > 0:
                        progress_message = self._format_progress_display(progress_percent, chunk_number, total_chunks, bytes_uploaded, elapsed_time)
                        print(progress_message)
                        last_progress_print = progress_percent
                
                # Final summary
                elapsed_time = time.time() - start_time
                if elapsed_time > 0:
                    avg_speed = (bytes_uploaded / (1024 * 1024)) / elapsed_time
                    print(f"Chunked upload completed! {bytes_uploaded // (1024*1024)}MB uploaded in {elapsed_time:.1f}s (avg: {avg_speed:.1f}MB/s)")
                else:
                    print(f"Chunked upload completed! {bytes_uploaded // (1024*1024)}MB uploaded")
                logger.info("Chunked upload completed successfully.")
                
                # Cleanup
                if hasattr(self, '_total_file_size'):
                    delattr(self, '_total_file_size')
            else:
                # Standard upload for smaller files
                resp = self.session.post(
                    self.api_url,
                    headers=headers,
                    data=file_handle,
                    auth=(self.api_user, self.api_token),
                    timeout=1800,
                )
                logger.debug(f"Upload Response Status: {resp.status_code}")
                logger.debug(f"Upload Response Text (first 500): {resp.text[:500]}")
                resp.raise_for_status()
                
                logger.debug(f"Upload for '{upload_basename}' completed.")
                
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Network error during file upload: {e}") from e
        finally:
            # Ensure file handle is closed
            if file_handle and not file_handle.closed:
                file_handle.close()
                logger.debug(f"Closed file handle for {file_path}")
