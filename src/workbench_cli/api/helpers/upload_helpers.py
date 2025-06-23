from typing import Generator
import io
import logging
import json
import requests
import time
import os
import io

from .api_base import APIBase
from ...exceptions import (
    NetworkError,
)

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-cli")

class UploadHelper(APIBase):
    """
    Helper mixin for handling chunked file uploads and progress tracking.
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
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _upload_single_chunk(self, chunk: bytes, chunk_number: int, headers: dict) -> None:
        """
        Upload a single chunk with retry logic.
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

    def _perform_upload(self, file_path: str, headers: dict):
        """
        Performs the upload of a single file, using chunking if necessary.
        
        Args:
            file_path: Path to the file to upload
            headers: The pre-constructed headers for the upload request
        """
        file_handle = None
        try:
            file_size = os.path.getsize(file_path)
            upload_basename = os.path.basename(file_path)
            
            logger.debug(f"Uploading file '{upload_basename}' ({file_size} bytes)...")
            logger.debug(f"Upload Request Headers: {headers}")
            
            file_handle = open(file_path, "rb")
            
            if file_size > self.CHUNKED_UPLOAD_THRESHOLD:
                logger.info(f"File size exceeds limit ({self.CHUNKED_UPLOAD_THRESHOLD} bytes). Using chunked upload...")
                
                headers['Transfer-Encoding'] = 'chunked'
                headers['Content-Type'] = 'application/octet-stream'
                
                total_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
                bytes_uploaded = 0
                start_time = time.time()
                last_progress_print = 0
                
                self._total_file_size = file_size
                
                print(f"Uploading {file_size / (1024*1024):.1f}MB in {total_chunks} {self.CHUNK_SIZE / (1024*1024):.0f}MB chunks.")
                
                for i, chunk in enumerate(self._read_in_chunks(file_handle, chunk_size=self.CHUNK_SIZE)):
                    chunk_number = i + 1
                    bytes_uploaded += len(chunk)
                    
                    self._upload_single_chunk(chunk, chunk_number, headers)
                    
                    progress_percent = min(100, (bytes_uploaded * 100) // file_size)
                    elapsed_time = time.time() - start_time
                    
                    if self._should_show_progress(progress_percent, last_progress_print, chunk_number, total_chunks) and elapsed_time > 0:
                        progress_message = self._format_progress_display(progress_percent, chunk_number, total_chunks, bytes_uploaded, elapsed_time)
                        print(progress_message)
                        last_progress_print = progress_percent
                
                elapsed_time = time.time() - start_time
                avg_speed = (bytes_uploaded / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                print(f"Chunked upload completed! {bytes_uploaded / (1024*1024):.1f}MB uploaded in {elapsed_time:.1f}s (avg: {avg_speed:.1f}MB/s)")
                
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
                resp.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            from ...exceptions import NetworkError
            raise NetworkError(f"Network error during file upload: {e}") from e
        finally:
            if file_handle and not file_handle.closed:
                file_handle.close()
