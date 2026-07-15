"""
Base Cleaner - Abstract base class for all metadata cleaners.

FORENSIC FEATURES (v3.0):
- Post-processing hooks for timestamp/ADS cleaning
- Configurable cleaning options
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Callable, Optional
import os
import sys
import tempfile

if TYPE_CHECKING:
    from .timestamp_cleaner import TimestampCleaner


class BaseCleaner(ABC):
    """
    Abstract base class for metadata cleaners.
    All file-type specific cleaners must inherit from this class.
    
    Now includes post-processing for forensic-level cleaning.
    """
    
    def __init__(self, log_callback: Optional[Callable[[str], None]] = None,
                 reset_timestamps: bool = True,
                 remove_zone_identifier: bool = True):
        """
        Initialize the cleaner with options.
        
        Args:
            log_callback: Function to call for logging messages.
            reset_timestamps: Whether to reset file timestamps to epoch.
            remove_zone_identifier: Whether to remove Zone.Identifier ADS.
        """
        self._log_callback = log_callback or (lambda msg: None)
        self._reset_timestamps = reset_timestamps
        self._remove_zone_identifier = remove_zone_identifier
        self._timestamp_cleaner: Optional['TimestampCleaner'] = None
        self._cleaning_profile = 'safe'

        # Timestamp policy applied when _reset_timestamps is True.
        # mode: 'epoch' | 'random' | 'custom'
        self._timestamp_mode = 'epoch'
        self._timestamp_value: Optional[str] = None

        # New v3.1 features
        self._output_folder: Optional[str] = None  # None = same folder as original
        self._overwrite_mode = False  # If True, overwrite original file
    
    def set_output_folder(self, folder_path: Optional[str]) -> None:
        """Set custom output folder for cleaned files."""
        self._output_folder = folder_path
    
    def set_overwrite_mode(self, overwrite: bool) -> None:
        """Set whether to overwrite original files."""
        self._overwrite_mode = overwrite

    def set_forensic_post_processing(
        self,
        reset_timestamps: bool,
        remove_zone_identifier: bool,
    ) -> None:
        """Set post-processing behavior shared by all cleaners."""
        self._reset_timestamps = reset_timestamps
        self._remove_zone_identifier = remove_zone_identifier

    def set_timestamp_policy(
        self,
        mode: str,
        value: Optional[str] = None,
    ) -> None:
        """Configure how file timestamps are rewritten during post-processing.

        Args:
            mode: 'epoch', 'random', or 'custom'.
            value: ISO date/datetime string, required when mode='custom'.
        """
        if mode not in {'epoch', 'random', 'custom'}:
            raise ValueError(f"Unsupported timestamp mode: {mode}")
        self._timestamp_mode = mode
        self._timestamp_value = value

    def set_cleaning_profile(self, profile: str) -> None:
        """Set the active cleaning profile for the cleaner."""
        if profile not in {'safe', 'aggressive'}:
            raise ValueError(f"Unsupported cleaning profile: {profile}")
        self._cleaning_profile = profile
    
    def log(self, message: str) -> None:
        """Log a message using the callback."""
        self._log_callback(message)
    
    def set_log_callback(self, callback: Callable[[str], None]) -> None:
        """Set the logging callback function."""
        self._log_callback = callback
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """
        Return list of supported file extensions (lowercase, with dot).
        
        Returns:
            List of extensions like ['.jpg', '.png']
        """
        pass
    
    @abstractmethod
    def clean(self, file_path: str) -> str:
        """
        Clean metadata from the given file.
        
        Args:
            file_path: Path to the file to clean.
            
        Returns:
            Path to the cleaned file (Filename_Cleaned.ext)
            
        Raises:
            Exception: If cleaning fails.
        """
        pass
    
    def supports(self, file_path: str) -> bool:
        """
        Check if this cleaner supports the given file.
        
        Args:
            file_path: Path to check.
            
        Returns:
            True if this cleaner can handle the file.
        """
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.get_supported_extensions()
    
    def generate_output_path(self, file_path: str) -> str:
        """
        Generate the output path for a cleaned file.
        
        Args:
            file_path: Original file path.
            
        Returns:
            Path with _Cleaned suffix before extension,
            or in custom output folder if set,
            or a temporary sibling path if overwrite mode is enabled.
        """
        if self._overwrite_mode:
            return self._create_temporary_output_path(file_path)
        
        basename = os.path.basename(file_path)
        name, ext = os.path.splitext(basename)
        new_name = f"{name}_Cleaned{ext}"
        
        # Custom output folder
        if self._output_folder and os.path.isdir(self._output_folder):
            return os.path.join(self._output_folder, new_name)
        
        # Same folder as original
        original_dir = os.path.dirname(file_path)
        return os.path.join(original_dir, new_name)

    def _create_temporary_output_path(self, file_path: str) -> str:
        """
        Create a temporary sibling path for overwrite mode.

        Writing to a side file first avoids truncating the original if a
        cleaner fails midway through serialization.
        """
        original_dir = os.path.dirname(file_path) or os.getcwd()
        basename = os.path.basename(file_path)
        name, ext = os.path.splitext(basename)

        fd, temp_path = tempfile.mkstemp(
            prefix=f"{name}_Cleaning_",
            suffix=ext,
            dir=original_dir
        )
        os.close(fd)

        try:
            os.remove(temp_path)
        except OSError:
            pass

        return temp_path

    def finalize_output_path(self, original_path: str, output_path: str) -> str:
        """
        Finalize the cleaner output path.

        In overwrite mode cleaners write to a temporary sibling file first,
        then replace the original atomically on success.
        """
        if not self._overwrite_mode:
            return output_path

        if os.path.abspath(output_path) == os.path.abspath(original_path):
            return output_path

        os.replace(output_path, original_path)
        return original_path
    
    def post_clean(self, output_path: str) -> None:
        """
        Post-processing after main cleaning.
        Handles timestamp reset and ADS removal.
        
        Args:
            output_path: Path to the cleaned file.
        """
        if not (self._reset_timestamps or self._remove_zone_identifier):
            return
        
        # Lazy load timestamp cleaner
        if self._timestamp_cleaner is None:
            try:
                from .timestamp_cleaner import TimestampCleaner
                self._timestamp_cleaner = TimestampCleaner(self._log_callback)
            except ImportError:
                self.log("[!] TimestampCleaner not available")
                return
        
        # Timestamp rewriting works on every platform (os.utime + Win32 API for
        # creation time). ADS/Zone.Identifier removal is NTFS-only.
        if self._reset_timestamps:
            self._timestamp_cleaner.apply_policy(
                output_path,
                self._timestamp_mode,
                self._timestamp_value,
            )

        if sys.platform == 'win32' and self._remove_zone_identifier:
            self._timestamp_cleaner.remove_zone_identifier(output_path)
            self._timestamp_cleaner.remove_all_ads(output_path)
    
    def full_clean(self, file_path: str) -> str:
        """
        Perform full cleaning including post-processing.
        
        Args:
            file_path: Path to the file to clean.
            
        Returns:
            Path to the cleaned file.
        """
        output_path = self.clean(file_path)
        final_output_path = self.finalize_output_path(file_path, output_path)
        
        self.post_clean(final_output_path)
        
        return final_output_path
