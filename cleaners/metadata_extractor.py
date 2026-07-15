"""
Metadata Extractor - Forensic-level metadata extraction for comparison.
Extracts ALL metadata from files for before/after comparison display.

FORENSIC FEATURES (v3.0):
- EXIF, IPTC, XMP for images
- File system timestamps
- Zone.Identifier detection
- Office revision history count
- PDF hidden streams
"""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
import os
import sys
import re
from datetime import datetime


@dataclass
class MetadataReport:
    """Container for extracted metadata with forensic details."""
    file_path: str
    file_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_fields: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    forensic_risks: List[str] = field(default_factory=list)
    
    def get_field_count(self) -> int:
        """Count total metadata fields."""
        return len(self.metadata)
    
    def has_gps(self) -> bool:
        """Check if GPS data exists."""
        return self._has_metadata_marker([
            'gps',
            'gpsinfo',
            'gpslatitude',
            'gpslongitude',
            'geolocation',
            'location'
        ])
    
    def has_author(self) -> bool:
        """Check if author/creator info exists."""
        return self._has_metadata_marker([
            'author',
            'authors',
            'creator',
            'artist',
            'owner',
            'lastmodifiedby',
            'byline',
            'manager'
        ])
    
    def has_device_info(self) -> bool:
        """Check if device/software info exists."""
        return self._has_metadata_marker([
            'make',
            'model',
            'software',
            'device',
            'camera',
            'phone',
            'producer',
            'application',
            'apptool'
        ])
    
    def has_timestamps(self) -> bool:
        """Check if file has non-epoch timestamps."""
        ts_keys = ['FileCreated', 'FileModified', 'FileAccessed']
        for key in ts_keys:
            if key in self.metadata:
                val = str(self.metadata[key])
                if '1970-01-01' not in val and '1970/01/01' not in val:
                    return True
        return False
    
    def has_zone_identifier(self) -> bool:
        """Check if Zone.Identifier exists."""
        return 'Zone.Identifier' in self.metadata
    
    def to_display_dict(self) -> Dict[str, str]:
        """Convert to display-friendly format."""
        result = {}
        for key, value in self.metadata.items():
            str_value = str(value)
            if len(str_value) > 100:
                str_value = str_value[:97] + "..."
            result[key] = str_value
        return result

    def _has_metadata_marker(self, markers: List[str]) -> bool:
        """Check normalized metadata keys for any marker suffix."""
        normalized_keys = []

        for key in self.metadata.keys():
            normalized = re.sub(r'[^a-z0-9]+', '', str(key).lower())
            if normalized:
                normalized_keys.append(normalized)

        for key in normalized_keys:
            for marker in markers:
                if key == marker or key.endswith(marker):
                    return True

        return False


class MetadataExtractor:
    """
    Forensic-level metadata extractor for all supported file types.
    Designed to extract EVERY piece of metadata that could identify the source.
    """
    
    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        self._log = log_callback or (lambda msg: None)
        self.is_windows = sys.platform == 'win32'
    
    def extract(self, file_path: str) -> MetadataReport:
        """Extract all metadata from a file."""
        ext = os.path.splitext(file_path)[1].lower()

        if ext in ['.jpg', '.jpeg', '.jpe', '.png', '.webp', '.bmp',
                   '.tiff', '.tif', '.gif']:
            report = self._extract_image(file_path)
        elif ext == '.svg':
            report = self._extract_svg(file_path)
        elif ext == '.pdf':
            report = self._extract_pdf(file_path)
        elif ext in ['.docx', '.xlsx', '.pptx']:
            report = self._extract_office(file_path)
        elif ext in ['.odt', '.ods', '.odp', '.odg', '.odf', '.ott', '.ots',
                     '.otp']:
            report = self._extract_odf(file_path)
        elif ext in ['.cr2', '.nef', '.nrw', '.arw', '.sr2', '.srf', '.dng',
                     '.orf', '.rw2', '.pef', '.srw', '.3fr', '.mef', '.mos',
                     '.erf', '.dcr', '.kdc', '.crw']:
            report = self._extract_raw(file_path, ext)
        elif ext in ['.mp4', '.mov', '.m4v', '.m4a', '.heic', '.heif', '.avif',
                     '.mp3', '.flac', '.wav', '.avi', '.mkv', '.webm',
                     '.ogg', '.oga', '.ogv', '.opus', '.spx']:
            report = self._extract_media(file_path, ext)
        else:
            report = MetadataReport(file_path=file_path, file_type="unknown")
        
        # Always extract file system metadata
        self._extract_filesystem_metadata(file_path, report)
        
        # Check for Zone.Identifier
        self._check_zone_identifier(file_path, report)
        
        # Analyze forensic risks
        self._analyze_forensic_risks(report)
        
        return report
    
    def _extract_filesystem_metadata(self, file_path: str, report: MetadataReport) -> None:
        """Extract file system timestamps and attributes."""
        try:
            stat = os.stat(file_path)
            
            # File timestamps
            created = datetime.fromtimestamp(stat.st_ctime)
            modified = datetime.fromtimestamp(stat.st_mtime)
            accessed = datetime.fromtimestamp(stat.st_atime)
            
            report.metadata['FileCreated'] = created.strftime('%Y-%m-%d %H:%M:%S')
            report.metadata['FileModified'] = modified.strftime('%Y-%m-%d %H:%M:%S')
            report.metadata['FileAccessed'] = accessed.strftime('%Y-%m-%d %H:%M:%S')
            report.metadata['FileSize'] = f"{stat.st_size:,} bytes"
            
            # Check if timestamps are suspicious (not epoch)
            epoch = datetime(1970, 1, 1)
            if created > epoch.replace(year=1971):
                report.warnings.append(f"Creation date reveals: {created.strftime('%Y-%m-%d')}")
            
        except Exception as e:
            report.warnings.append(f"Filesystem metadata error: {str(e)}")
    
    def _check_zone_identifier(self, file_path: str, report: MetadataReport) -> None:
        """Check for Zone.Identifier alternate data stream (Windows only)."""
        if not self.is_windows:
            return
        
        try:
            ads_path = f"{file_path}:Zone.Identifier"
            with open(ads_path, 'r') as f:
                content = f.read()
                report.metadata['Zone.Identifier'] = "PRESENT"
                report.warnings.append("Zone.Identifier detected - reveals download source!")
                
                # Parse Zone.Identifier content
                if 'ZoneId=' in content:
                    zone_id = content.split('ZoneId=')[1].split('\n')[0].strip()
                    zone_names = {'0': 'Local', '1': 'Intranet', '2': 'Trusted', '3': 'Internet', '4': 'Restricted'}
                    report.metadata['Zone.ZoneId'] = zone_names.get(zone_id, zone_id)
                
                if 'HostUrl=' in content:
                    host_url = content.split('HostUrl=')[1].split('\n')[0].strip()
                    report.metadata['Zone.HostUrl'] = host_url[:80] + ('...' if len(host_url) > 80 else '')
                    report.warnings.append(f"Download URL tracked!")
                
                if 'ReferrerUrl=' in content:
                    referrer = content.split('ReferrerUrl=')[1].split('\n')[0].strip()
                    report.metadata['Zone.ReferrerUrl'] = referrer[:80] + ('...' if len(referrer) > 80 else '')
                    
        except (FileNotFoundError, OSError):
            pass  # No Zone.Identifier - good
    
    def _analyze_forensic_risks(self, report: MetadataReport) -> None:
        """Analyze and categorize forensic risks."""
        risks = []
        
        if report.has_gps():
            risks.append("🌍 GPS KOORDİNATLARI - Konum ifşa!")
        
        if report.has_author():
            risks.append("👤 YAZAR BİLGİSİ - Kimlik ifşa!")
        
        if report.has_device_info():
            risks.append("📱 CİHAZ BİLGİSİ - Cihaz parmak izi!")
        
        if report.has_timestamps():
            risks.append("⏰ DOSYA TARİHLERİ - Zaman çizelgesi ifşa!")
        
        if report.has_zone_identifier():
            risks.append("🌐 ZONE.IDENTIFIER - İndirme kaynağı ifşa!")
        
        if 'Thumbnail' in report.metadata:
            risks.append("🖼️ THUMBNAIL - Gizli önizleme!")
        
        if 'IPTC' in str(report.metadata):
            risks.append("📰 IPTC - Basın metadata'sı!")
        
        report.forensic_risks = risks
    
    def _extract_image(self, file_path: str) -> MetadataReport:
        """Extract ALL metadata from images including EXIF, IPTC, XMP."""
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        
        report = MetadataReport(file_path=file_path, file_type="image")
        
        try:
            with Image.open(file_path) as img:
                # Basic image info
                report.metadata['Format'] = img.format
                report.metadata['Mode'] = img.mode
                report.metadata['Size'] = f"{img.size[0]}x{img.size[1]}"
                
                # EXIF data
                exif_data = img.getexif()
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag_name = TAGS.get(tag_id, f"Tag_{tag_id}")
                        report.raw_fields.append(tag_name)
                        
                        # Handle GPS data specially
                        if tag_name == 'GPSInfo' and isinstance(value, dict):
                            for gps_tag_id, gps_value in value.items():
                                gps_tag_name = GPSTAGS.get(gps_tag_id, f"GPS_{gps_tag_id}")
                                report.metadata[f"GPS.{gps_tag_name}"] = str(gps_value)
                        else:
                            report.metadata[tag_name] = self._format_value(value)
                
                # Check for IFD data (ExifIFD, GPSIFD, InteropIFD)
                try:
                    for ifd_id in [0x8769, 0x8825, 0xA005]:
                        ifd_data = exif_data.get_ifd(ifd_id)
                        if ifd_data:
                            for tag_id, value in ifd_data.items():
                                tag_name = TAGS.get(tag_id, f"IFD_{ifd_id}_{tag_id}")
                                if tag_name not in report.metadata:
                                    report.metadata[tag_name] = self._format_value(value)
                                    report.raw_fields.append(tag_name)
                except Exception:
                    pass
                
                # Check image.info for additional metadata (including IPTC)
                if img.info:
                    for key, value in img.info.items():
                        if key == 'icc_profile':
                            report.metadata['ICC_Profile'] = f"<{len(value)} bytes>"
                            report.warnings.append("ICC Color Profile detected")
                        elif key == 'photoshop':
                            report.metadata['Photoshop_Data'] = "PRESENT"
                            report.warnings.append("Photoshop data detected")
                        elif key not in ['exif', 'dpi']:
                            report.metadata[f"Info.{key}"] = self._format_value(value)
                            report.raw_fields.append(f"Info.{key}")
                
                # Check for IPTC data
                try:
                    from PIL import IptcImagePlugin
                    iptc_data = IptcImagePlugin.getiptcinfo(img)
                    if iptc_data:
                        iptc_tags = {
                            (2, 5): 'IPTC.ObjectName',
                            (2, 25): 'IPTC.Keywords',
                            (2, 55): 'IPTC.DateCreated',
                            (2, 80): 'IPTC.Byline',
                            (2, 85): 'IPTC.BylineTitle',
                            (2, 90): 'IPTC.City',
                            (2, 101): 'IPTC.Country',
                            (2, 105): 'IPTC.Headline',
                            (2, 110): 'IPTC.Credit',
                            (2, 115): 'IPTC.Source',
                            (2, 116): 'IPTC.Copyright',
                            (2, 120): 'IPTC.Caption',
                        }
                        for key, name in iptc_tags.items():
                            if key in iptc_data:
                                report.metadata[name] = self._format_value(iptc_data[key])
                                report.warnings.append(f"IPTC data found: {name}")
                except ImportError:
                    pass
                except Exception:
                    pass
                
                # Check for XMP
                if 'xmp' in str(img.info).lower():
                    report.warnings.append("XMP metadata detected")
                
                # Check for thumbnail
                try:
                    if hasattr(exif_data, 'get_thumbnail'):
                        thumb = exif_data.get_thumbnail()
                        if thumb:
                            report.metadata['Thumbnail'] = f"PRESENT ({len(thumb)} bytes)"
                            report.warnings.append("Embedded thumbnail detected - may contain unredacted preview!")
                except Exception:
                    pass
                    
        except Exception as e:
            report.warnings.append(f"Extraction error: {str(e)}")
        
        return report
    
    def _extract_pdf(self, file_path: str) -> MetadataReport:
        """Extract ALL metadata from PDFs including hidden streams."""
        from .pdf_cleaner import pdf_support_available, pdf_support_error

        report = MetadataReport(file_path=file_path, file_type="pdf")

        if not pdf_support_available():
            report.warnings.append(pdf_support_error())
            return report

        import pikepdf

        try:
            with pikepdf.open(file_path) as pdf:
                # Document Info Dictionary
                if pdf.docinfo:
                    for key in pdf.docinfo.keys():
                        key_name = str(key).replace('/', '')
                        value = str(pdf.docinfo[key])
                        report.metadata[f"DocInfo.{key_name}"] = value
                        report.raw_fields.append(key_name)
                
                # XMP Metadata
                if '/Metadata' in pdf.Root:
                    report.metadata['XMP_Metadata'] = "PRESENT"
                    report.warnings.append("XMP metadata stream exists")
                    
                    try:
                        xmp_stream = pdf.Root['/Metadata']
                        xmp_content = xmp_stream.read_bytes().decode('utf-8', errors='ignore')
                        
                        import re
                        xmp_fields = {
                            'xmp:CreatorTool': r'xmp:CreatorTool["\s>]+([^<"]+)',
                            'dc:creator': r'dc:creator[^>]*>([^<]+)',
                            'pdf:Producer': r'pdf:Producer["\s>]+([^<"]+)',
                            'xmp:CreateDate': r'xmp:CreateDate["\s>]+([^<"]+)',
                            'xmp:ModifyDate': r'xmp:ModifyDate["\s>]+([^<"]+)',
                        }
                        
                        for field_name, pattern in xmp_fields.items():
                            match = re.search(pattern, xmp_content, re.IGNORECASE)
                            if match:
                                report.metadata[f"XMP.{field_name}"] = match.group(1)
                                report.raw_fields.append(field_name)
                    except Exception:
                        pass
                
                # Document ID
                if '/ID' in pdf.trailer:
                    report.metadata['Document_ID'] = "PRESENT"
                    report.warnings.append("Document ID can track document copies!")
                
                # Page count
                report.metadata['PageCount'] = str(len(pdf.pages))
                
                # PieceInfo
                if '/PieceInfo' in pdf.Root:
                    report.metadata['PieceInfo'] = "PRESENT"
                    report.warnings.append("Application-specific data detected")
                
                # MarkInfo
                if '/MarkInfo' in pdf.Root:
                    report.metadata['MarkInfo'] = "PRESENT"
                
                # Embedded files
                if '/Names' in pdf.Root:
                    names = pdf.Root['/Names']
                    if '/EmbeddedFiles' in names:
                        report.metadata['EmbeddedFiles'] = "PRESENT"
                        report.warnings.append("Embedded files detected")
                    if '/JavaScript' in names:
                        report.metadata['JavaScript'] = "PRESENT"
                        report.warnings.append("JavaScript detected")
                    if '/Dests' in names:
                        report.metadata['NamedDestinations'] = "PRESENT"
                        report.warnings.append("Named destinations detected")
                    if '/Renditions' in names:
                        report.metadata['Renditions'] = "PRESENT"
                        report.warnings.append("Renditions detected")
                
                associated_files = '/AF' in pdf.Root
                if not associated_files:
                    try:
                        for page in pdf.pages:
                            if '/AF' in page:
                                associated_files = True
                                break

                            if '/Annots' not in page:
                                continue

                            for annot in page['/Annots']:
                                try:
                                    if '/AF' in annot:
                                        associated_files = True
                                        break
                                except Exception:
                                    pass

                            if associated_files:
                                break
                    except Exception:
                        pass

                if associated_files:
                    report.metadata['AssociatedFiles'] = "PRESENT"
                    report.warnings.append("Associated file references detected")
                
        except Exception as e:
            report.warnings.append(f"Extraction error: {str(e)}")
        
        return report
    
    def _extract_office(self, file_path: str) -> MetadataReport:
        """Extract ALL metadata from Office documents including revision info."""
        import zipfile
        from xml.etree import ElementTree as ET
        import re
        
        ext = os.path.splitext(file_path)[1].lower()
        type_map = {'.docx': 'Word', '.xlsx': 'Excel', '.pptx': 'PowerPoint'}
        report = MetadataReport(file_path=file_path, file_type=type_map.get(ext, 'office'))
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                namelist = zf.namelist()
                
                # Core properties
                if 'docProps/core.xml' in namelist:
                    try:
                        content = zf.read('docProps/core.xml').decode('utf-8')
                        root = ET.fromstring(content)
                        
                        ns = {
                            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                            'dc': 'http://purl.org/dc/elements/1.1/',
                            'dcterms': 'http://purl.org/dc/terms/',
                        }
                        
                        field_mappings = [
                            ('dc:creator', 'Creator'),
                            ('cp:lastModifiedBy', 'LastModifiedBy'),
                            ('dcterms:created', 'Created'),
                            ('dcterms:modified', 'Modified'),
                            ('cp:revision', 'Revision'),
                            ('dc:title', 'Title'),
                            ('dc:subject', 'Subject'),
                            ('dc:description', 'Description'),
                            ('cp:keywords', 'Keywords'),
                            ('cp:category', 'Category'),
                        ]
                        
                        for xpath, field_name in field_mappings:
                            ns_prefix, tag = xpath.split(':')
                            elem = root.find(f'.//{{{ns[ns_prefix]}}}{tag}')
                            if elem is not None and elem.text:
                                report.metadata[f"Core.{field_name}"] = elem.text
                                report.raw_fields.append(field_name)
                                
                    except Exception as e:
                        report.warnings.append(f"core.xml parse error: {str(e)}")
                
                # App properties
                if 'docProps/app.xml' in namelist:
                    try:
                        content = zf.read('docProps/app.xml').decode('utf-8')
                        root = ET.fromstring(content)
                        
                        ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
                        
                        app_fields = ['Application', 'AppVersion', 'Company', 'Manager', 
                                     'TotalTime', 'Template', 'Words', 'Pages']
                        
                        for field in app_fields:
                            elem = root.find(f'.//{{{ns["ep"]}}}{field}')
                            if elem is not None and elem.text:
                                report.metadata[f"App.{field}"] = elem.text
                                report.raw_fields.append(field)
                                
                    except Exception:
                        pass
                
                # Custom properties
                if 'docProps/custom.xml' in namelist:
                    report.metadata['CustomProperties'] = "PRESENT"
                    report.warnings.append("Custom properties detected")
                
                # Thumbnail
                for thumb_name in [
                    'docProps/thumbnail.jpeg',
                    'docProps/thumbnail.jpg',
                    'docProps/thumbnail.png',
                    'docProps/thumbnail.wmf',
                    'docProps/thumbnail.emf',
                ]:
                    if thumb_name in namelist:
                        report.metadata['Thumbnail'] = "PRESENT"
                        report.warnings.append("Preview thumbnail detected")
                        break
                
                # Count revision IDs (rsid) for forensic awareness
                if ext == '.docx' and 'word/document.xml' in namelist:
                    try:
                        content = zf.read('word/document.xml').decode('utf-8')
                        rsid_count = len(re.findall(r'w:rsid\w*="', content))
                        if rsid_count > 0:
                            report.metadata['RevisionIDs'] = f"{rsid_count} rsid markers"
                            report.warnings.append(f"Revision tracking: {rsid_count} edit markers found!")
                    except Exception:
                        pass
                
                # Count embedded images
                media_folders = {'word/media', 'xl/media', 'ppt/media'}
                embedded_images = 0
                for name in namelist:
                    for folder in media_folders:
                        if name.startswith(folder + '/'):
                            embedded_images += 1
                            break
                
                if embedded_images > 0:
                    report.metadata['EmbeddedImages'] = f"{embedded_images} images"
                    report.warnings.append(f"Embedded images may contain EXIF data!")

                self._extract_office_comment_metadata(zf, namelist, report, ext)
                
        except Exception as e:
            report.warnings.append(f"Extraction error: {str(e)}")
        
        return report

    def _extract_office_comment_metadata(self, zf, namelist: List[str],
                                         report: MetadataReport, ext: str) -> None:
        """Extract comment-related identity metadata from Office documents."""
        if ext == '.docx' and 'word/comments.xml' in namelist:
            try:
                content = zf.read('word/comments.xml').decode('utf-8', errors='ignore')
                authors = re.findall(r'w:author="([^"]+)"', content)
                initials = re.findall(r'w:initials="([^"]+)"', content)

                if authors or initials:
                    report.metadata['CommentAuthors'] = f"{len(authors)} entries"
                    report.warnings.append("Word comment author info detected")
            except Exception:
                pass

        if ext == '.xlsx':
            legacy_authors = 0

            for name in namelist:
                if name.startswith('xl/comments') and name.endswith('.xml'):
                    try:
                        content = zf.read(name).decode('utf-8', errors='ignore')
                        legacy_authors += len(re.findall(r'<author>(.*?)</author>', content, re.DOTALL))
                    except Exception:
                        pass

            if legacy_authors > 0:
                report.metadata['CommentAuthors'] = f"{legacy_authors} entries"
                report.warnings.append("Excel comment author info detected")

            for name in namelist:
                if name.startswith('xl/persons/') and name.endswith('.xml'):
                    try:
                        content = zf.read(name).decode('utf-8', errors='ignore')
                        if re.search(r'(displayName|userId|providerId)="[^"]+"', content):
                            report.metadata['ThreadedCommentIdentities'] = "PRESENT"
                            report.warnings.append("Excel threaded comment identities detected")
                            break
                    except Exception:
                        pass

        if ext == '.pptx' and 'ppt/commentAuthors.xml' in namelist:
            try:
                content = zf.read('ppt/commentAuthors.xml').decode('utf-8', errors='ignore')
                author_entries = re.findall(r'\sname="([^"]+)"', content)
                if author_entries:
                    report.metadata['CommentAuthors'] = f"{len(author_entries)} entries"
                    report.warnings.append("PowerPoint comment author info detected")
            except Exception:
                pass
    
    def _extract_svg(self, file_path: str) -> MetadataReport:
        """Extract metadata hints from an SVG (text-based) image."""
        report = MetadataReport(file_path=file_path, file_type="image")
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as handle:
                content = handle.read(1_000_000)  # cap read for huge SVGs

            if re.search(r'<metadata\b', content, re.IGNORECASE):
                report.metadata['SVG.Metadata'] = 'PRESENT'
                report.warnings.append('SVG metadata block detected')

            editors = re.findall(
                r'\b(inkscape|sodipodi|illustrator):', content, re.IGNORECASE
            )
            if editors:
                report.metadata['SVG.Editor'] = ', '.join(sorted(set(
                    e.lower() for e in editors
                )))
                report.warnings.append('SVG editor namespace detected')

            title = re.search(r'<title\b[^>]*>(.*?)</title>', content,
                              re.DOTALL | re.IGNORECASE)
            if title and title.group(1).strip():
                report.metadata['SVG.Title'] = title.group(1).strip()[:100]

            if re.search(r'<!--', content):
                report.metadata['SVG.Comment'] = 'PRESENT'
                report.warnings.append('SVG XML comment detected')

        except Exception as exc:
            report.warnings.append(f"SVG extraction error: {exc}")

        return report

    def _extract_odf(self, file_path: str) -> MetadataReport:
        """Extract metadata from an OpenDocument package, natively."""
        report = MetadataReport(file_path=file_path, file_type="opendocument")
        try:
            from .odf_cleaner import describe_odf

            for key, value in describe_odf(file_path).items():
                report.metadata[key] = value
                report.raw_fields.append(key)
                if key.endswith('Thumbnail'):
                    report.warnings.append(
                        "Preview thumbnail detected - renders document content!"
                    )
                elif key.endswith('Annotations') or key.endswith('TrackedChanges'):
                    report.warnings.append(f"{key} may carry author identities")
        except Exception as exc:
            report.warnings.append(f"OpenDocument extraction error: {exc}")
        return report

    def _extract_raw(self, file_path: str, ext: str) -> MetadataReport:
        """Extract metadata from a camera RAW file, natively."""
        report = MetadataReport(file_path=file_path, file_type="raw")
        try:
            with open(file_path, 'rb') as handle:
                data = handle.read()

            if ext == '.crw':
                from . import ciff
                found = ciff.describe_crw(data)
            else:
                from . import tiff_raw
                found = tiff_raw.describe_tiff(data)

            for key, value in found.items():
                report.metadata[key] = value
                report.raw_fields.append(key)

            if 'RAW.GPS' in report.metadata:
                report.warnings.append("GPS coordinates detected in RAW file!")
            if 'RAW.MakerNote' in report.metadata:
                report.warnings.append(
                    "MakerNote detected - often holds serial number and shutter count"
                )
            if 'RAW.PreviewEXIF' in report.metadata:
                report.warnings.append(
                    "Embedded preview carries its own EXIF"
                )
            if 'CRW.SerialNumber' in report.metadata:
                report.warnings.append("Camera serial number detected!")
            if 'CRW.OwnerName' in report.metadata:
                report.warnings.append("Camera owner name detected!")
        except Exception as exc:
            report.warnings.append(f"RAW extraction error: {exc}")
        return report

    def _extract_media(self, file_path: str, ext: str) -> MetadataReport:
        """Extract metadata from audio/video/HEIF containers, natively."""
        file_type = self._media_file_type(ext)
        report = MetadataReport(file_path=file_path, file_type=file_type)
        try:
            with open(file_path, 'rb') as handle:
                data = handle.read()

            from . import isobmff, matroska, native_media, ogg

            found: Dict[str, str] = {}
            if ext in ('.mp4', '.mov', '.m4v', '.m4a'):
                found = isobmff.describe_movie_metadata(data)
            elif ext in ('.heic', '.heif', '.avif'):
                found = isobmff.describe_heif_metadata(data)
            elif ext == '.mp3':
                found = native_media.describe_mp3(data)
            elif ext == '.flac':
                found = native_media.describe_flac(data)
            elif ext in ('.wav', '.avi'):
                found = native_media.describe_riff(data)
            elif ext in ('.mkv', '.webm'):
                found = matroska.describe_matroska(data)
            elif ext in ('.ogg', '.oga', '.ogv', '.opus', '.spx'):
                found = ogg.describe_ogg(data)

            for key, value in found.items():
                report.metadata[key] = value
                report.raw_fields.append(key)
                if 'gps' in key.lower():
                    report.warnings.append("Location metadata detected")
        except Exception as exc:
            report.warnings.append(f"Media extraction error: {exc}")
        return report

    def _media_file_type(self, ext: str) -> str:
        video = {'.mp4', '.mov', '.m4v', '.avi', '.mkv', '.webm', '.ogv'}
        audio = {'.mp3', '.flac', '.m4a', '.wav', '.ogg', '.oga', '.opus',
                 '.spx'}
        if ext in video:
            return 'video'
        if ext in audio:
            return 'audio'
        return 'image'  # heic/heif/avif carry image-style metadata

    def _format_value(self, value: Any) -> str:
        """Format a metadata value for display."""
        if isinstance(value, bytes):
            try:
                return value.decode('utf-8')
            except Exception:
                return f"<binary: {len(value)} bytes>"
        elif isinstance(value, (list, tuple)):
            return ', '.join(str(v) for v in value[:5])
        else:
            return str(value)


def compare_reports(before: MetadataReport, after: MetadataReport) -> Dict[str, Any]:
    """
    Compare two metadata reports and return differences.

    Returns:
        Dict with 'removed', 'remaining', 'added' field maps plus count totals.
    """
    before_keys = set(before.metadata.keys())
    after_keys = set(after.metadata.keys())
    
    removed = before_keys - after_keys
    remaining = after_keys & before_keys
    added = after_keys - before_keys
    
    return {
        'removed': {k: before.metadata[k] for k in removed},
        'remaining': {k: after.metadata[k] for k in remaining},
        'added': {k: after.metadata[k] for k in added},
        'before_count': len(before.metadata),
        'after_count': len(after.metadata),
        'removed_count': len(removed),
        'forensic_risks_before': len(before.forensic_risks),
        'forensic_risks_after': len(after.forensic_risks),
    }
