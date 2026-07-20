"""
PDF Cleaner - Forensic-level PDF metadata removal.
Uses pikepdf for complete metadata elimination.

FORENSIC LEVEL: This cleaner uses multiple techniques to remove direct
metadata and neutralize PDF trailer identifiers.
"""

from typing import List, Optional, Callable
import os
import tempfile

from .base import BaseCleaner

NEUTRAL_DOCUMENT_ID_HEX = "31415926535897932384626433832795"

# pikepdf is a C extension. On Windows it fails to load whenever the Visual C++
# runtime is missing, and a plain `import pikepdf` at module scope would then
# take the entire application down with it - GUI included - just because one of
# the ten supported families is unavailable. Someone cleaning holiday photos
# should not be stopped by the PDF engine, so the failure is captured here and
# surfaced only when a PDF is actually processed.
try:
    import pikepdf
    from pikepdf import Pdf

    _PIKEPDF_ERROR: Optional[BaseException] = None
except Exception as _exc:  # ImportError, or a DLL load failure on Windows
    pikepdf = None  # type: ignore[assignment]
    Pdf = object  # type: ignore[misc,assignment]
    _PIKEPDF_ERROR = _exc


class PDFSupportUnavailable(RuntimeError):
    """Raised when a PDF is handed to a build whose pikepdf will not load."""


def pdf_support_available() -> bool:
    """Whether the PDF engine can run in this environment."""
    return _PIKEPDF_ERROR is None


def pdf_support_error() -> str:
    """A one-line reason why PDF support is unavailable, or an empty string."""
    if _PIKEPDF_ERROR is None:
        return ""
    # pikepdf's own message is a multi-line diagnostic; keep the first line.
    first = str(_PIKEPDF_ERROR).strip().splitlines()
    detail = first[0] if first else _PIKEPDF_ERROR.__class__.__name__
    return (
        f"pikepdf could not be loaded ({detail}). PDF support is disabled; "
        f"every other format still works. On Windows this usually means the "
        f"Microsoft Visual C++ Redistributable (x64) is missing."
    )


def _require_pikepdf() -> None:
    if pikepdf is None:
        raise PDFSupportUnavailable(pdf_support_error())


class PDFCleaner(BaseCleaner):
    """
    Cleaner for PDF files - FORENSIC LEVEL.
    
    Removes:
    - Document Info dictionary (Author, Creator, Producer, CreationDate, etc.)
    - XMP metadata streams
    - Document IDs (neutralized to a non-unique static value when pikepdf saves)
    - Piece Info dictionaries
    - Page Piece dictionaries
    - Marked Content
    - Private application data
    - Named destinations and scriptable names dictionary entries
    - Structure references in outlines
    - Associated file references
    """
    
    SUPPORTED_EXTENSIONS = ['.pdf']
    
    # All known metadata keys in PDF DocInfo
    DOCINFO_KEYS = [
        '/Author', '/Creator', '/Producer', '/Title', '/Subject',
        '/Keywords', '/CreationDate', '/ModDate', '/Trapped',
        '/Company', '/SourceModified', '/Manager', '/Category',
        '/Comments', '/Application', '/AppVersion', '/DocSecurity',
        '/HyperlinksChanged', '/LinksUpToDate', '/ScaleCrop', 
        '/ShareDoc', '/HeadingPairs', '/TitlesOfParts'
    ]
    
    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        super().__init__(log_callback)
    
    def get_supported_extensions(self) -> List[str]:
        return self.SUPPORTED_EXTENSIONS
    
    def clean(self, file_path: str) -> str:
        """
        Clean PDF using FORENSIC-LEVEL metadata removal.
        
        Uses a multi-pass approach:
        1. Clear document info dictionary completely
        2. Remove XMP metadata stream
        3. Remove document ID
        4. Remove PieceInfo and other hidden metadata
        5. Linearize/rewrite the PDF to remove orphaned objects
        
        Args:
            file_path: Path to the PDF file.
            
        Returns:
            Path to the cleaned PDF file.
        """
        _require_pikepdf()
        self.log(f"[>] Opening PDF: {os.path.basename(file_path)}")

        try:
            # First pass: aggressive metadata removal
            temp_path = self._first_pass_clean(file_path)
            
            # Second pass: verify and final cleanup
            output_path = self._second_pass_verify(temp_path, file_path)
            
            # Clean up temp file
            try:
                os.remove(temp_path)
            except Exception:
                pass
            
            self.log(f"[OK] PDF cleaned: {os.path.basename(output_path)}")
            self.log("[OK] DocInfo completely removed")
            self.log("[OK] XMP metadata removed")
            self.log("[OK] Document ID neutralized")
            self.log("[OK] Catalog metadata cleaned")
            
            return output_path
            
        except Exception as e:
            self.log(f"[ERROR] Failed to clean PDF: {str(e)}")
            raise
    
    def _first_pass_clean(self, file_path: str) -> str:
        """First pass: aggressive metadata removal."""
        temp_dir = os.path.dirname(file_path) or os.getcwd()
        temp_fd, temp_path = tempfile.mkstemp(
            suffix='.pdf',
            prefix='ExifKiller_PDF_',
            dir=temp_dir
        )
        os.close(temp_fd)
        aggressive = self._cleaning_profile == 'aggressive'
        
        with pikepdf.open(file_path) as pdf:
            # Log existing metadata before cleaning
            self._log_existing_metadata(pdf)
            
            # 1. Always remove direct authoring metadata
            self.log("[>] Removing DocInfo completely...")
            self._nuke_document_info(pdf)
            
            # 2. Remove XMP metadata stream from Root
            self.log("[>] Removing XMP metadata...")
            self._remove_xmp_metadata(pdf)

            # 3. Remove document ID
            self.log("[>] Removing Document ID...")
            self._remove_document_id(pdf)

            if aggressive:
                self.log("[>] Aggressive PDF cleanup enabled...")

                # 4. Remove PieceInfo (application-specific data)
                self.log("[>] Removing PieceInfo...")
                self._remove_piece_info(pdf)

                # 5. Remove MarkInfo (Marked content)
                self.log("[>] Removing MarkInfo...")
                self._remove_mark_info(pdf)

                # 6. Clean page-level metadata
                self.log("[>] Cleaning page metadata...")
                self._clean_page_metadata(pdf)

                # 7. Remove structure references from outlines
                self.log("[>] Cleaning outline structure references...")
                self._clean_outlines(pdf)

                # 8. Remove names dictionary metadata
                self.log("[>] Cleaning Names dictionary...")
                self._clean_names_dict(pdf)

                # 9. Remove associated file references
                self.log("[>] Cleaning associated files...")
                self._remove_associated_files(pdf)
            
            # Save with options that strip extra data
            pdf.save(
                temp_path,
                linearize=False,  # Don't add /L parameter
                object_stream_mode=pikepdf.ObjectStreamMode.generate,
                compress_streams=True,
                preserve_pdfa=False,  # Don't preserve PDF/A metadata
                # pikepdf/qpdf writes a trailer /ID back on every save even
                # after deletion. A fresh or content-derived ID is still a
                # correlation handle, so use qpdf's non-unique static ID.
                static_id=True,
            )
        
        return temp_path
    
    def _second_pass_verify(self, temp_path: str, original_path: str) -> str:
        """Second pass: verify cleanup and final save."""
        output_path = self.generate_output_path(original_path)
        aggressive = self._cleaning_profile == 'aggressive'
        
        with pikepdf.open(temp_path) as pdf:
            # Double-check and remove any remaining metadata
            self._nuke_document_info(pdf)
            self._remove_xmp_metadata(pdf)
            self._remove_document_id(pdf)
            
            # Final verification
            if aggressive:
                remaining = self._check_remaining_metadata(pdf)
                if remaining:
                    self.log(f"[!] Remaining metadata detected, cleaning: {remaining}")
                    self._force_clean_remaining(pdf, remaining)
            
            # Final save
            pdf.save(
                output_path,
                linearize=False,
                object_stream_mode=pikepdf.ObjectStreamMode.generate,
                compress_streams=True,
                preserve_pdfa=False,
                static_id=True,
            )
        
        return output_path
    
    def _log_existing_metadata(self, pdf: Pdf) -> None:
        """Log existing metadata in the PDF."""
        try:
            docinfo = pdf.docinfo
            if docinfo:
                found_fields = []
                for key in docinfo.keys():
                    key_name = str(key).replace('/', '')
                    found_fields.append(key_name)
                
                if found_fields:
                    self.log(f"[!] Existing metadata ({len(found_fields)} fields): {', '.join(found_fields)}")
            
            if '/Metadata' in pdf.Root:
                self.log("[!] XMP metadata stream detected")
            
            if hasattr(pdf, 'trailer') and '/ID' in pdf.trailer:
                self.log("[!] Document ID detected")
                
        except Exception:
            pass
    
    def _nuke_document_info(self, pdf: Pdf) -> None:
        """Completely destroy document info dictionary."""
        try:
            # Method 1: Delete all known keys
            if pdf.docinfo:
                for key in list(pdf.docinfo.keys()):
                    try:
                        del pdf.docinfo[key]
                    except Exception:
                        pass
            
            # Method 2: Also try setting to empty values
            for key in self.DOCINFO_KEYS:
                try:
                    if key in pdf.docinfo:
                        del pdf.docinfo[key]
                except Exception:
                    pass
            
            # Method 3: Try to replace the entire docinfo with empty dict
            try:
                # Access trailer's /Info and make it empty
                if '/Info' in pdf.trailer:
                    info_ref = pdf.trailer['/Info']
                    # Clear all keys from the referenced object
                    if info_ref:
                        for key in list(info_ref.keys()):
                            try:
                                del info_ref[key]
                            except Exception:
                                pass
            except Exception:
                pass
                
        except Exception as e:
            self.log(f"[!] DocInfo cleaning warning: {str(e)}")
    
    def _remove_xmp_metadata(self, pdf: Pdf) -> None:
        """Remove XMP metadata stream."""
        try:
            if '/Metadata' in pdf.Root:
                del pdf.Root['/Metadata']
        except Exception:
            pass
        
        # Also check for metadata in other locations
        try:
            for page in pdf.pages:
                if '/Metadata' in page:
                    del page['/Metadata']
        except Exception:
            pass
    
    def _remove_piece_info(self, pdf: Pdf) -> None:
        """Remove PieceInfo dictionaries (application-specific data)."""
        try:
            if '/PieceInfo' in pdf.Root:
                del pdf.Root['/PieceInfo']
        except Exception:
            pass
        
        # Check pages too
        try:
            for page in pdf.pages:
                if '/PieceInfo' in page:
                    del page['/PieceInfo']
        except Exception:
            pass
    
    def _remove_mark_info(self, pdf: Pdf) -> None:
        """Remove MarkInfo dictionary."""
        try:
            if '/MarkInfo' in pdf.Root:
                del pdf.Root['/MarkInfo']
        except Exception:
            pass
    
    def _clean_page_metadata(self, pdf: Pdf) -> None:
        """Clean metadata from individual pages."""
        metadata_keys = ['/Metadata', '/PieceInfo', '/LastModified', '/PresSteps']
        
        try:
            for page in pdf.pages:
                for key in metadata_keys:
                    if key in page:
                        try:
                            del page[key]
                        except Exception:
                            pass
        except Exception:
            pass
    
    def _remove_document_id(self, pdf: Pdf) -> None:
        """Remove document ID from trailer."""
        try:
            if '/ID' in pdf.trailer:
                del pdf.trailer['/ID']
        except Exception:
            pass
    
    def _clean_outlines(self, pdf: Pdf) -> None:
        """Clean metadata from outlines/bookmarks."""
        try:
            if '/Outlines' in pdf.Root:
                outlines = pdf.Root['/Outlines']
                # Remove any SE (structure element) references
                if '/SE' in outlines:
                    del outlines['/SE']
        except Exception:
            pass
    
    def _clean_names_dict(self, pdf: Pdf) -> None:
        """Clean Names dictionary of potentially identifying info."""
        try:
            if '/Names' in pdf.Root:
                names = pdf.Root['/Names']
                for key in ['/EmbeddedFiles', '/JavaScript', '/Dests', '/AP', '/Renditions']:
                    if key in names:
                        del names[key]

                if not list(names.keys()):
                    del pdf.Root['/Names']
        except Exception:
            pass

    def _remove_associated_files(self, pdf: Pdf) -> None:
        """Remove associated file references from catalog, pages, and annotations."""
        try:
            if '/AF' in pdf.Root:
                del pdf.Root['/AF']
        except Exception:
            pass

        try:
            for page in pdf.pages:
                if '/AF' in page:
                    del page['/AF']

                if '/Annots' not in page:
                    continue

                for annot in page['/Annots']:
                    try:
                        if '/AF' in annot:
                            del annot['/AF']
                    except Exception:
                        pass
        except Exception:
            pass

    def _has_associated_files(self, pdf: Pdf) -> bool:
        """Check whether any associated file references remain."""
        try:
            if '/AF' in pdf.Root:
                return True
        except Exception:
            pass

        try:
            for page in pdf.pages:
                if '/AF' in page:
                    return True

                if '/Annots' not in page:
                    continue

                for annot in page['/Annots']:
                    try:
                        if '/AF' in annot:
                            return True
                    except Exception:
                        pass
        except Exception:
            pass

        return False

    def _check_remaining_metadata(self, pdf: Pdf) -> List[str]:
        """Check for any remaining metadata fields."""
        remaining = []
        
        try:
            if pdf.docinfo:
                for key in pdf.docinfo.keys():
                    remaining.append(f"DocInfo:{key}")
        except Exception:
            pass
        
        try:
            if '/Metadata' in pdf.Root:
                remaining.append("XMP")
        except Exception:
            pass
        
        try:
            if '/ID' in pdf.trailer:
                remaining.append("ID")
        except Exception:
            pass

        try:
            if '/Names' in pdf.Root:
                for key in ['/EmbeddedFiles', '/JavaScript', '/Dests', '/AP', '/Renditions']:
                    if key in pdf.Root['/Names']:
                        remaining.append(f"Names:{key}")
        except Exception:
            pass

        if self._has_associated_files(pdf):
            remaining.append("AF")
        
        return remaining
    
    def _force_clean_remaining(self, pdf: Pdf, remaining: List[str]) -> None:
        """Force clean any remaining metadata."""
        for item in remaining:
            try:
                if item.startswith("DocInfo:"):
                    key = item.replace("DocInfo:", "")
                    if key in pdf.docinfo:
                        del pdf.docinfo[key]
                elif item == "XMP":
                    del pdf.Root['/Metadata']
                elif item == "ID":
                    del pdf.trailer['/ID']
                elif item.startswith("Names:"):
                    self._clean_names_dict(pdf)
                elif item == "AF":
                    self._remove_associated_files(pdf)
            except Exception:
                pass

