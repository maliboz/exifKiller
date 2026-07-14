"""
Timestamp Cleaner - Forensic-level file timestamp manipulation.
Handles Windows file timestamps and NTFS Alternate Data Streams.

FORENSIC FEATURES:
1. Reset file timestamps (Creation, Modified, Access) to epoch or custom date
2. Remove Zone.Identifier ADS (reveals download source)
3. Remove other NTFS alternate data streams
"""

import os
import sys
import ctypes
from datetime import datetime, timedelta, timezone
from typing import Optional, Callable, List, Tuple


class TimestampCleaner:
    """
    Forensic timestamp and ADS cleaner for Windows systems.
    
    This is a utility class (not file-type specific) that can be used
    as a post-processor for any cleaned file.
    """
    
    # Windows epoch: January 1, 1601
    # Unix epoch: January 1, 1970
    # Difference in 100-nanosecond intervals
    EPOCH_DIFF = 116444736000000000

    # Default reset date: 1970-01-01 00:00:00 UTC
    EPOCH_DATE = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Plausible window used when generating random timestamps. A file dated
    # 1970 or in the future is itself a tell; a random date inside a normal
    # usage window blends in with ordinary files.
    RANDOM_RANGE_START = datetime(2016, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Supported timestamp policies.
    VALID_MODES = frozenset({"epoch", "random", "custom"})
    
    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        """Initialize with optional logging callback."""
        self._log = log_callback or (lambda msg: None)
        
        # Check if we're on Windows
        self.is_windows = sys.platform == 'win32'
        self._api_ready = False
        
        if self.is_windows:
            self._setup_windows_api()
    
    def _setup_windows_api(self):
        """Setup Windows API function references."""
        try:
            from ctypes import wintypes
            
            self.kernel32 = ctypes.windll.kernel32
            self.wintypes = wintypes
            
            # CreateFileW - to open file with write attributes permission
            self.kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,  # lpFileName
                wintypes.DWORD,    # dwDesiredAccess
                wintypes.DWORD,    # dwShareMode
                ctypes.c_void_p,   # lpSecurityAttributes
                wintypes.DWORD,    # dwCreationDisposition
                wintypes.DWORD,    # dwFlagsAndAttributes
                wintypes.HANDLE    # hTemplateFile
            ]
            self.kernel32.CreateFileW.restype = wintypes.HANDLE
            
            # SetFileTime - to modify timestamps
            self.kernel32.SetFileTime.argtypes = [
                wintypes.HANDLE,   # hFile
                ctypes.POINTER(wintypes.FILETIME),  # lpCreationTime
                ctypes.POINTER(wintypes.FILETIME),  # lpLastAccessTime
                ctypes.POINTER(wintypes.FILETIME)   # lpLastWriteTime
            ]
            self.kernel32.SetFileTime.restype = wintypes.BOOL
            
            # CloseHandle
            self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self.kernel32.CloseHandle.restype = wintypes.BOOL
            
            # DeleteFileW - for ADS removal
            self.kernel32.DeleteFileW.argtypes = [wintypes.LPCWSTR]
            self.kernel32.DeleteFileW.restype = wintypes.BOOL
            
            self._api_ready = True
            self._log("[*] Windows API ready")
            
        except Exception as e:
            self._log(f"[!] Windows API setup failed: {str(e)}")
            self._api_ready = False
    
    def _datetime_to_filetime(self, dt: datetime):
        """Convert Python datetime to Windows FILETIME structure."""
        from ctypes import wintypes
        
        # Ensure we have a timezone-aware datetime in UTC
        if dt.tzinfo is None:
            # Assume UTC if no timezone
            dt = dt.replace(tzinfo=timezone.utc)
        
        # Convert to UTC timestamp (seconds since 1970-01-01 UTC)
        # For 1970-01-01 00:00:00 UTC, this should be 0
        try:
            timestamp = dt.timestamp()
        except:
            # Fallback for dates before 1970 on some systems
            timestamp = (dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
        
        # Convert to 100-nanosecond intervals since Windows epoch (1601-01-01)
        # 1970 - 1601 = 369 years = 11644473600 seconds
        filetime_int = int(timestamp * 10000000) + self.EPOCH_DIFF
        
        # Ensure non-negative
        if filetime_int < 0:
            filetime_int = self.EPOCH_DIFF  # Default to 1970-01-01
        
        # Split into low and high 32-bit parts
        low = filetime_int & 0xFFFFFFFF
        high = (filetime_int >> 32) & 0xFFFFFFFF
        
        ft = wintypes.FILETIME()
        ft.dwLowDateTime = low
        ft.dwHighDateTime = high

        return ft

    def apply_policy(
        self,
        file_path: str,
        mode: str = "epoch",
        custom_value: Optional[str] = None,
    ) -> bool:
        """
        Apply a timestamp policy to a file.

        Args:
            file_path: Path to the file.
            mode: One of "epoch", "random", or "custom".
            custom_value: ISO date/datetime string, required when mode="custom".

        Returns:
            True if at least the modification/access times were updated.
        """
        if not os.path.exists(file_path):
            self._log(f"[!] File not found: {file_path}")
            return False

        try:
            created, accessed, modified = self.resolve_datetimes(mode, custom_value)
        except ValueError as exc:
            self._log(f"[!] Timestamp policy error: {exc}")
            return False

        self._log(
            f"[>] Setting timestamps ({mode}) -> "
            f"{modified.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )
        return self._set_times(file_path, created, accessed, modified)

    def resolve_datetimes(
        self,
        mode: str,
        custom_value: Optional[str] = None,
    ) -> Tuple[datetime, datetime, datetime]:
        """
        Resolve a policy into (created, accessed, modified) datetimes.

        For epoch/custom all three are identical. For random a plausible
        ordering is generated (created <= modified <= accessed) so the file
        does not stand out with internally inconsistent timestamps.
        """
        if mode == "epoch":
            base = self.EPOCH_DATE
        elif mode == "custom":
            base = self._parse_custom(custom_value)
        elif mode == "random":
            base = self._random_datetime()
        else:
            raise ValueError(f"Unsupported timestamp mode: {mode}")

        if mode == "random":
            import random

            created = base
            modified = created + timedelta(seconds=random.randint(0, 14 * 24 * 3600))
            accessed = modified + timedelta(seconds=random.randint(0, 3 * 24 * 3600))
            return created, accessed, modified

        return base, base, base

    def _parse_custom(self, value: Optional[str]) -> datetime:
        """Parse a user-supplied date/datetime string into a UTC datetime."""
        if not value:
            raise ValueError("custom timestamp mode requires a date value")

        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            try:
                parsed = datetime.strptime(text, "%Y-%m-%d")
            except ValueError as exc:
                raise ValueError(
                    f"invalid custom date '{value}' (use YYYY-MM-DD or ISO 8601)"
                ) from exc

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _random_datetime(self) -> datetime:
        """Pick a uniformly random UTC datetime inside the plausible window."""
        import random

        start = self.RANDOM_RANGE_START
        end = datetime.now(timezone.utc)
        span_seconds = int((end - start).total_seconds())
        if span_seconds <= 0:
            return start
        return start + timedelta(seconds=random.randint(0, span_seconds))

    def _set_times(
        self,
        file_path: str,
        created: datetime,
        accessed: datetime,
        modified: datetime,
    ) -> bool:
        """Set file times cross-platform.

        Access and modification times are set on every platform via os.utime.
        On Windows the creation ("birth") time is additionally set through the
        Win32 API, which os.utime cannot touch.
        """
        updated = False

        try:
            os.utime(file_path, (accessed.timestamp(), modified.timestamp()))
            updated = True
        except OSError as exc:
            self._log(f"[!] os.utime failed: {exc}")

        if self.is_windows and self._api_ready:
            windows_ok = self._windows_set_times(
                file_path, created, accessed, modified
            )
            updated = updated or windows_ok

        if updated:
            self._log("[OK] Timestamps updated")
        return updated

    def _windows_set_times(
        self,
        file_path: str,
        created: datetime,
        accessed: datetime,
        modified: datetime,
    ) -> bool:
        """Set all three NTFS timestamps (including creation) via Win32 API."""
        try:
            from ctypes import wintypes

            creation_ft = self._datetime_to_filetime(created)
            access_ft = self._datetime_to_filetime(accessed)
            write_ft = self._datetime_to_filetime(modified)

            FILE_WRITE_ATTRIBUTES = 0x0100
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            FILE_ATTRIBUTE_NORMAL = 0x80

            handle = self.kernel32.CreateFileW(
                file_path,
                FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )

            INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
            if handle == INVALID_HANDLE_VALUE:
                error_code = (
                    ctypes.get_last_error()
                    if hasattr(ctypes, "get_last_error")
                    else "unknown"
                )
                self._log(
                    f"[!] Cannot open file: {os.path.basename(file_path)} "
                    f"(error: {error_code})"
                )
                return False

            try:
                result = self.kernel32.SetFileTime(
                    handle,
                    ctypes.byref(creation_ft),
                    ctypes.byref(access_ft),
                    ctypes.byref(write_ft),
                )
                if result:
                    return True

                error_code = (
                    ctypes.get_last_error()
                    if hasattr(ctypes, "get_last_error")
                    else "unknown"
                )
                self._log(f"[!] SetFileTime failed (error: {error_code})")
                return False
            finally:
                self.kernel32.CloseHandle(handle)

        except Exception as exc:
            self._log(f"[ERROR] Windows timestamp set: {exc}")
            return False

    def reset_timestamps(
        self,
        file_path: str,
        target_date: Optional[datetime] = None,
        randomize: bool = False,
    ) -> bool:
        """Backward-compatible helper that resets all timestamps to one value.

        Prefer :meth:`apply_policy` for the epoch/random/custom policies.
        """
        if randomize:
            return self.apply_policy(file_path, "random")
        if target_date is not None:
            created = accessed = modified = target_date
            if not os.path.exists(file_path):
                self._log(f"[!] File not found: {file_path}")
                return False
            return self._set_times(file_path, created, accessed, modified)
        return self.apply_policy(file_path, "epoch")
    
    def remove_zone_identifier(self, file_path: str) -> bool:
        """
        Remove the Zone.Identifier alternate data stream.
        
        This ADS is added by Windows when files are downloaded from the internet
        and contains information about the download source.
        """
        if not self.is_windows:
            return True  # Not applicable on non-Windows
        
        try:
            ads_path = f"{file_path}:Zone.Identifier"
            
            # Check if Zone.Identifier exists
            if self._ads_exists(file_path, "Zone.Identifier"):
                self._log(f"[!] Zone.Identifier detected")
                
                # Try to read and log the content
                try:
                    with open(ads_path, 'r') as f:
                        content = f.read()
                        if 'HostUrl' in content:
                            self._log(f"[!] Download source info found!")
                except:
                    pass
                
                # Delete the ADS - try Python first
                try:
                    os.remove(ads_path)
                    self._log(f"[OK] Zone.Identifier removed")
                    return True
                except:
                    pass
                
                # Try Windows API
                if self._api_ready:
                    result = self.kernel32.DeleteFileW(ads_path)
                    if result or not self._ads_exists(file_path, "Zone.Identifier"):
                        self._log(f"[OK] Zone.Identifier removed")
                        return True
                
                self._log(f"[!] Could not remove Zone.Identifier")
                return False
            else:
                self._log(f"[*] Zone.Identifier not found (clean)")
                return True
                
        except Exception as e:
            self._log(f"[ERROR] Zone.Identifier removal: {str(e)}")
            return False
    
    def _ads_exists(self, file_path: str, stream_name: str) -> bool:
        """Check if an alternate data stream exists."""
        try:
            ads_path = f"{file_path}:{stream_name}"
            with open(ads_path, 'r'):
                return True
        except (FileNotFoundError, OSError, PermissionError):
            return False
    
    def list_alternate_streams(self, file_path: str) -> List[str]:
        """List all alternate data streams on a file."""
        streams = []
        
        if not self.is_windows:
            return streams
        
        common_ads = [
            'Zone.Identifier',
            'SummaryInformation', 
            'DocumentSummaryInformation',
            'encryptable',
            'favicon'
        ]
        
        for ads_name in common_ads:
            if self._ads_exists(file_path, ads_name):
                streams.append(ads_name)
        
        return streams
    
    def remove_all_ads(self, file_path: str) -> int:
        """Remove all alternate data streams from a file."""
        removed = 0
        
        streams = self.list_alternate_streams(file_path)
        
        for stream_name in streams:
            try:
                ads_path = f"{file_path}:{stream_name}"
                os.remove(ads_path)
                self._log(f"[OK] ADS silindi: {stream_name}")
                removed += 1
            except:
                if self._api_ready:
                    try:
                        self.kernel32.DeleteFileW(ads_path)
                        removed += 1
                    except:
                        pass
        
        return removed
    
    def full_clean(self, file_path: str, 
                   reset_date: Optional[datetime] = None) -> Tuple[bool, bool]:
        """Perform full timestamp and ADS cleaning."""
        self._log(f"[>] Dosya sistemi temizliği başlıyor...")
        
        timestamps_ok = self.reset_timestamps(file_path, reset_date)
        ads_ok = self.remove_zone_identifier(file_path)
        
        # Also try to remove other common ADS
        other_ads = self.remove_all_ads(file_path)
        if other_ads > 0:
            self._log(f"[OK] {other_ads} ek ADS silindi")
        
        return (timestamps_ok, ads_ok)
