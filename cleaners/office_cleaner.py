"""
Office Cleaner - Forensic-level Office document metadata removal.
Handles DOCX, XLSX, PPTX by treating them as ZIP archives.

FORENSIC FEATURES (v3.0):
- docProps metadata (author, company, dates)
- Revision history (rsid markers)
- Embedded image EXIF data
- Comments and track changes author info
- Thumbnail previews
- Template information
"""

from typing import List, Optional, Callable
import zipfile
import os
import shutil
import re
import posixpath
import uuid
from xml.etree import ElementTree as ET

from .base import BaseCleaner


class OfficeCleaner(BaseCleaner):
    """
    Cleaner for Microsoft Office files (DOCX, XLSX, PPTX).
    FORENSIC LEVEL - Removes all identifying information.
    
    Cleans:
    - docProps/core.xml (author, dates, etc.)
    - docProps/app.xml (application info, company)
    - docProps/custom.xml (custom properties)
    - docProps/thumbnail.* (preview images)
    - Revision IDs (rsid) from document content
    - Embedded image EXIF data
    - Comment author information
    - Track changes author information
    """
    
    SUPPORTED_EXTENSIONS = ['.docx', '.xlsx', '.pptx']
    
    # XML namespaces used in Office documents
    NAMESPACES = {
        'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
        'dc': 'http://purl.org/dc/elements/1.1/',
        'dcterms': 'http://purl.org/dc/terms/',
        'dcmitype': 'http://purl.org/dc/dcmitype/',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties',
        'vt': 'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes',
        'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
        'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    }
    
    # Media folders for different Office formats
    MEDIA_FOLDERS = {
        '.docx': 'word/media',
        '.xlsx': 'xl/media',
        '.pptx': 'ppt/media',
    }
    
    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        super().__init__(log_callback)
        # Register namespaces to preserve them during XML manipulation
        for prefix, uri in self.NAMESPACES.items():
            ET.register_namespace(prefix, uri)
    
    def get_supported_extensions(self) -> List[str]:
        return self.SUPPORTED_EXTENSIONS
    
    def clean(self, file_path: str) -> str:
        """
        Clean Office document with FORENSIC-LEVEL metadata removal.
        
        Args:
            file_path: Path to the Office file.
            
        Returns:
            Path to the cleaned Office file.
        """
        ext = os.path.splitext(file_path)[1].lower()
        file_type = {'.docx': 'Word', '.xlsx': 'Excel', '.pptx': 'PowerPoint'}[ext]
        aggressive = self._cleaning_profile == 'aggressive'
        
        self.log(f"[>] Opening {file_type} file: {os.path.basename(file_path)}")
        
        try:
            # Create temp directory alongside the input so sandboxed
            # environments can still read/write extracted package files.
            temp_root = os.path.dirname(file_path) or os.getcwd()
            temp_dir = os.path.join(
                temp_root,
                f"ExifKiller_Office_{uuid.uuid4().hex}"
            )
            os.makedirs(temp_dir, exist_ok=False)
            
            try:
                # Extract the Office file (it's a ZIP archive)
                self.log("[>] Extracting archive...")
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # === STANDARD METADATA ===
                # Scrub core.xml
                core_xml_path = os.path.join(temp_dir, 'docProps', 'core.xml')
                if os.path.exists(core_xml_path):
                    self.log("[>] Cleaning core.xml...")
                    self._scrub_core_xml(core_xml_path)
                
                # Scrub app.xml
                app_xml_path = os.path.join(temp_dir, 'docProps', 'app.xml')
                if os.path.exists(app_xml_path):
                    self.log("[>] Cleaning app.xml...")
                    self._scrub_app_xml(app_xml_path)
                
                # Remove custom.xml
                custom_xml_path = os.path.join(temp_dir, 'docProps', 'custom.xml')
                if os.path.exists(custom_xml_path):
                    self.log("[>] Removing custom.xml...")
                    os.remove(custom_xml_path)
                    self._remove_content_type_reference(temp_dir, '/docProps/custom.xml')
                    self._remove_relationship_references(temp_dir, '/docProps/custom.xml')
                
                # === FORENSIC LEVEL CLEANING ===
                
                # Clean comments (remove author info)
                self._clean_comments(temp_dir, ext)
                
                # Clean track changes (remove author info)
                self._clean_track_changes(temp_dir, ext)

                if aggressive:
                    self.log("[>] Aggressive Office cleanup enabled...")

                    # Remove thumbnail preview
                    self._remove_thumbnail(temp_dir)
                    
                    # Clean revision history (rsid markers)
                    self._clean_revision_history(temp_dir, ext)
                    
                    # Clean embedded images (remove EXIF)
                    self._clean_embedded_images(temp_dir, ext)
                    
                    # Clean settings files
                    self._clean_settings(temp_dir, ext)
                
                # Generate output path
                output_path = self.generate_output_path(file_path)
                
                # Repackage the archive
                self.log(f"[>] Repackaging archive: {os.path.basename(output_path)}")
                self._repackage_office_file(temp_dir, output_path)
                
                self.log(f"[OK] {file_type} file cleaned: {os.path.basename(output_path)}")
                self.log("[OK] Author info removed")
                self.log("[OK] Company info removed")
                self.log("[OK] Revision history removed")
                self.log("[OK] Embedded image EXIF removed")
                
                return output_path
                
            finally:
                # Clean up temp directory
                shutil.rmtree(temp_dir, ignore_errors=True)
                
        except Exception as e:
            self.log(f"[ERROR] Failed to clean Office file: {str(e)}")
            raise
    
    def _scrub_core_xml(self, xml_path: str) -> None:
        """Scrub docProps/core.xml - removes author, dates, etc."""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Elements to clear in core.xml
            elements_to_clear = [
                '{http://purl.org/dc/elements/1.1/}creator',
                '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}lastModifiedBy',
                '{http://purl.org/dc/terms/}created',
                '{http://purl.org/dc/terms/}modified',
                '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}revision',
                '{http://purl.org/dc/elements/1.1/}title',
                '{http://purl.org/dc/elements/1.1/}subject',
                '{http://purl.org/dc/elements/1.1/}description',
                '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}keywords',
                '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}category',
                '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}contentStatus',
            ]
            
            for tag in elements_to_clear:
                for elem in root.findall(f'.//{tag}'):
                    elem.text = ''
            
            tree.write(xml_path, encoding='UTF-8', xml_declaration=True)
            self.log("[*] core.xml: All fields cleaned")
            
        except ET.ParseError as e:
            self.log(f"[!] core.xml parse error: {str(e)}")
    
    def _scrub_app_xml(self, xml_path: str) -> None:
        """Scrub docProps/app.xml - removes application info, company, etc."""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            elements_to_clear = [
                '{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Application',
                '{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}AppVersion',
                '{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Company',
                '{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Manager',
                '{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}TotalTime',
                '{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Template',
                '{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}HyperlinkBase',
            ]
            
            for tag in elements_to_clear:
                for elem in root.findall(f'.//{tag}'):
                    elem.text = ''
            
            tree.write(xml_path, encoding='UTF-8', xml_declaration=True)
            self.log("[*] app.xml: Application info cleaned")
            
        except ET.ParseError as e:
            self.log(f"[!] app.xml parse error: {str(e)}")
    
    def _remove_thumbnail(self, temp_dir: str) -> None:
        """Remove thumbnail preview images from docProps."""
        thumbnail_patterns = [
            'docProps/thumbnail.jpeg',
            'docProps/thumbnail.jpg',
            'docProps/thumbnail.png',
            'docProps/thumbnail.wmf',
            'docProps/thumbnail.emf',
        ]
        
        removed = False
        for pattern in thumbnail_patterns:
            thumb_path = os.path.join(temp_dir, pattern.replace('/', os.sep))
            if os.path.exists(thumb_path):
                os.remove(thumb_path)
                self._remove_content_type_reference(temp_dir, f'/{pattern}')
                self._remove_relationship_references(temp_dir, f'/{pattern}')
                removed = True
        
        if removed:
            self.log("[OK] Thumbnail preview removed")
    
    def _clean_revision_history(self, temp_dir: str, ext: str) -> None:
        """
        Clean revision IDs (rsid) from document content.
        These IDs can be used to track document history and editing patterns.
        """
        self.log("[>] Cleaning revision IDs...")
        
        rsid_count = 0
        
        if ext == '.docx':
            # Clean document.xml
            doc_path = os.path.join(temp_dir, 'word', 'document.xml')
            if os.path.exists(doc_path):
                rsid_count += self._remove_rsid_from_xml(doc_path)
            
            # Clean styles.xml
            styles_path = os.path.join(temp_dir, 'word', 'styles.xml')
            if os.path.exists(styles_path):
                rsid_count += self._remove_rsid_from_xml(styles_path)
            
            # Clean settings.xml rsid table
            settings_path = os.path.join(temp_dir, 'word', 'settings.xml')
            if os.path.exists(settings_path):
                rsid_count += self._clean_settings_rsid(settings_path)
        
        elif ext == '.xlsx':
            # Excel stores less rsid but check workbook.xml
            workbook_path = os.path.join(temp_dir, 'xl', 'workbook.xml')
            if os.path.exists(workbook_path):
                rsid_count += self._remove_rsid_from_xml(workbook_path)
        
        elif ext == '.pptx':
            # Check presentation.xml
            pres_path = os.path.join(temp_dir, 'ppt', 'presentation.xml')
            if os.path.exists(pres_path):
                rsid_count += self._remove_rsid_from_xml(pres_path)
        
        if rsid_count > 0:
            self.log(f"[OK] {rsid_count} rsid references removed")
    
    def _remove_rsid_from_xml(self, xml_path: str) -> int:
        """Remove rsid attributes from XML file using regex."""
        try:
            with open(xml_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_len = len(content)
            
            # Remove rsid attributes: w:rsidR, w:rsidRPr, w:rsidP, etc.
            # Pattern matches w:rsid followed by optional letters, then ="value"
            content = re.sub(r'\s*w:rsid\w*="[^"]*"', '', content)
            
            # Remove rsidRoot attribute
            content = re.sub(r'\s*w:rsidRoot="[^"]*"', '', content)
            
            # Also remove any standalone rsid attributes
            content = re.sub(r'\s*rsid\w*="[^"]*"', '', content)
            
            with open(xml_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Count approximate number of removals
            return (original_len - len(content)) // 20  # Rough estimate
            
        except Exception as e:
            self.log(f"[!] rsid cleaning error: {str(e)}")
            return 0
    
    def _clean_settings_rsid(self, settings_path: str) -> int:
        """Clean rsid tracking table from settings.xml."""
        try:
            with open(settings_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Remove entire rsids element which contains the tracking table
            content = re.sub(r'<w:rsids>.*?</w:rsids>', '', content, flags=re.DOTALL)
            
            # Remove documentProtection that might reference authors
            content = re.sub(r'<w:documentProtection[^>]*/>', '', content)
            
            with open(settings_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return 1
            
        except Exception:
            return 0
    
    def _clean_embedded_images(self, temp_dir: str, ext: str) -> None:
        """
        Clean EXIF data from embedded images in the document.
        Uses pixel-copy method for forensic-level cleaning.
        """
        media_folder = self.MEDIA_FOLDERS.get(ext, '')
        if not media_folder:
            return
        
        media_path = os.path.join(temp_dir, media_folder.replace('/', os.sep))
        if not os.path.exists(media_path):
            return
        
        self.log("[>] Cleaning embedded images...")
        
        # Import PIL here to avoid circular imports
        from PIL import Image
        
        image_count = 0
        image_extensions = ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.bmp']
        
        for filename in os.listdir(media_path):
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext in image_extensions:
                image_path = os.path.join(media_path, filename)
                try:
                    with Image.open(image_path) as img:
                        clean_img = self._copy_pixels_only(img)
                        save_format, save_kwargs = self._get_embedded_image_save_options(file_ext)
                        clean_img.save(image_path, format=save_format, **save_kwargs)
                        
                        image_count += 1
                        
                except Exception as e:
                    self.log(f"[!] Failed to clean image {filename}: {str(e)}")
        
        if image_count > 0:
            self.log(f"[OK] {image_count} embedded images EXIF removed")
    
    def _clean_comments(self, temp_dir: str, ext: str) -> None:
        """Remove author information from comments."""
        if ext == '.docx':
            self._clean_word_comments(temp_dir)
        elif ext == '.xlsx':
            self._clean_excel_comments(temp_dir)
        elif ext == '.pptx':
            self._clean_powerpoint_comments(temp_dir)

    def _clean_word_comments(self, temp_dir: str) -> None:
        """Anonymize Word comment author fields."""
        comments_path = os.path.join(temp_dir, 'word', 'comments.xml')
        if not os.path.exists(comments_path):
            return

        try:
            with open(comments_path, 'r', encoding='utf-8') as f:
                content = f.read()

            updated = re.sub(r'\s*w:author="[^"]*"', ' w:author=""', content)
            updated = re.sub(r'\s*w:initials="[^"]*"', '', updated)

            if updated != content:
                with open(comments_path, 'w', encoding='utf-8') as f:
                    f.write(updated)
                self.log("[OK] Word comment author info cleaned")

        except Exception as e:
            self.log(f"[!] Word comment cleanup error: {str(e)}")

    def _clean_excel_comments(self, temp_dir: str) -> None:
        """Anonymize legacy and threaded Excel comment identities."""
        xl_dir = os.path.join(temp_dir, 'xl')
        if not os.path.exists(xl_dir):
            return

        cleaned_any = False

        for filename in os.listdir(xl_dir):
            if not (filename.startswith('comments') and filename.endswith('.xml')):
                continue

            comments_path = os.path.join(xl_dir, filename)

            try:
                with open(comments_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                updated = re.sub(
                    r'<authors\b[^>]*>.*?</authors>',
                    '<authors><author></author></authors>',
                    content,
                    flags=re.DOTALL
                )
                updated = re.sub(r'authorId="\d+"', 'authorId="0"', updated)

                if updated != content:
                    with open(comments_path, 'w', encoding='utf-8') as f:
                        f.write(updated)
                    cleaned_any = True

            except Exception as e:
                self.log(f"[!] Excel comment cleanup error in {filename}: {str(e)}")

        cleaned_any = self._clean_excel_persons(temp_dir) or cleaned_any

        if cleaned_any:
            self.log("[OK] Excel comment identities cleaned")

    def _clean_excel_persons(self, temp_dir: str) -> bool:
        """Scrub modern Excel threaded comment identity records."""
        persons_dir = os.path.join(temp_dir, 'xl', 'persons')
        if not os.path.exists(persons_dir):
            return False

        changed = False

        for filename in os.listdir(persons_dir):
            if not filename.endswith('.xml'):
                continue

            person_path = os.path.join(persons_dir, filename)

            try:
                with open(person_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                updated = content
                for attr in ['displayName', 'userId', 'providerId']:
                    updated = re.sub(rf'{attr}="[^"]*"', f'{attr}=""', updated)

                if updated != content:
                    with open(person_path, 'w', encoding='utf-8') as f:
                        f.write(updated)
                    changed = True

            except Exception as e:
                self.log(f"[!] Excel persons cleanup error in {filename}: {str(e)}")

        return changed

    def _clean_powerpoint_comments(self, temp_dir: str) -> None:
        """Anonymize PowerPoint comment author metadata."""
        cleaned_any = False

        authors_path = os.path.join(temp_dir, 'ppt', 'commentAuthors.xml')
        if os.path.exists(authors_path):
            try:
                with open(authors_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                updated = re.sub(r'\sname="[^"]*"', ' name=""', content)
                updated = re.sub(r'\sinitials="[^"]*"', ' initials=""', updated)

                if updated != content:
                    with open(authors_path, 'w', encoding='utf-8') as f:
                        f.write(updated)
                    cleaned_any = True

            except Exception as e:
                self.log(f"[!] PowerPoint comment author cleanup error: {str(e)}")

        comment_locations = [
            os.path.join(temp_dir, 'ppt', 'comments.xml'),
            os.path.join(temp_dir, 'ppt', 'comments'),
        ]

        for location in comment_locations:
            if os.path.isfile(location):
                comment_files = [location]
            elif os.path.isdir(location):
                comment_files = [
                    os.path.join(location, name)
                    for name in os.listdir(location)
                    if name.endswith('.xml')
                ]
            else:
                continue

            for comment_path in comment_files:
                try:
                    with open(comment_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    updated = re.sub(r'authorId="\d+"', 'authorId="0"', content)

                    if updated != content:
                        with open(comment_path, 'w', encoding='utf-8') as f:
                            f.write(updated)
                        cleaned_any = True

                except Exception as e:
                    self.log(f"[!] PowerPoint comment cleanup error in {os.path.basename(comment_path)}: {str(e)}")

        if cleaned_any:
            self.log("[OK] PowerPoint comment identities cleaned")
    
    def _clean_track_changes(self, temp_dir: str, ext: str) -> None:
        """Remove author information from track changes."""
        if ext != '.docx':
            return
        
        doc_path = os.path.join(temp_dir, 'word', 'document.xml')
        if not os.path.exists(doc_path):
            return
        
        try:
            with open(doc_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Anonymize track change authors
            content = re.sub(r'w:author="[^"]*"', 'w:author=""', content)
            
            with open(doc_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.log("[OK] Track changes author info cleaned")
            
        except Exception:
            pass
    
    def _clean_settings(self, temp_dir: str, ext: str) -> None:
        """Clean various settings files that may contain identifying info."""
        if ext == '.docx':
            # webSettings.xml can contain info
            web_settings = os.path.join(temp_dir, 'word', 'webSettings.xml')
            if os.path.exists(web_settings):
                try:
                    with open(web_settings, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Remove target frame and other web-related tracking
                    content = re.sub(r'<w:targetScreenSz[^>]*/>', '', content)
                    
                    with open(web_settings, 'w', encoding='utf-8') as f:
                        f.write(content)
                except Exception:
                    pass
    
    def _remove_content_type_reference(self, temp_dir: str, part_name: str) -> None:
        """Remove reference from [Content_Types].xml."""
        try:
            content_types_path = os.path.join(temp_dir, '[Content_Types].xml')
            if os.path.exists(content_types_path):
                with open(content_types_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Remove the Override element for the given part
                pattern = rf'<Override[^>]*PartName="{re.escape(part_name)}"[^>]*/>'
                content = re.sub(pattern, '', content)
                
                with open(content_types_path, 'w', encoding='utf-8') as f:
                    f.write(content)
        except Exception:
            pass

    def _remove_relationship_references(self, temp_dir: str, part_name: str) -> None:
        """Remove matching package relationships for a deleted part."""
        normalized_part = self._normalize_package_path(part_name)

        for root, _, files in os.walk(temp_dir):
            for filename in files:
                if not filename.endswith('.rels'):
                    continue

                rel_path = os.path.join(root, filename)

                try:
                    tree = ET.parse(rel_path)
                    rel_root = tree.getroot()
                    changed = False
                    source_part = self._get_relationship_source_part(temp_dir, rel_path)
                    source_dir = posixpath.dirname(source_part)

                    for rel in list(rel_root):
                        if not rel.tag.endswith('Relationship'):
                            continue

                        if rel.attrib.get('TargetMode') == 'External':
                            continue

                        target = rel.attrib.get('Target')
                        if not target:
                            continue

                        resolved_target = self._resolve_relationship_target(source_dir, target)
                        if resolved_target == normalized_part:
                            rel_root.remove(rel)
                            changed = True

                    if changed:
                        tree.write(rel_path, encoding='UTF-8', xml_declaration=True)

                except ET.ParseError as e:
                    self.log(f"[!] Relationship parse error in {os.path.basename(rel_path)}: {str(e)}")
                except Exception as e:
                    self.log(f"[!] Relationship cleanup error in {os.path.basename(rel_path)}: {str(e)}")

    def _normalize_package_path(self, part_name: str) -> str:
        """Normalize an OOXML package part path for comparison."""
        normalized = part_name.replace('\\', '/')
        if not normalized.startswith('/'):
            normalized = '/' + normalized
        return '/' + posixpath.normpath(normalized.lstrip('/'))

    def _get_relationship_source_part(self, temp_dir: str, rel_path: str) -> str:
        """Map a .rels file back to the package part it describes."""
        rel_name = os.path.relpath(rel_path, temp_dir).replace(os.sep, '/')

        if rel_name == '_rels/.rels':
            return ''

        rel_dir, filename = rel_name.rsplit('/', 1)
        source_dir = rel_dir[:-6] if rel_dir.endswith('/_rels') else rel_dir
        source_name = filename[:-5]

        if source_dir:
            return f"{source_dir}/{source_name}"
        return source_name

    def _resolve_relationship_target(self, source_dir: str, target: str) -> str:
        """Resolve a relationship target to a normalized package path."""
        if target.startswith('/'):
            return self._normalize_package_path(target)

        normalized_target = target.replace('\\', '/')
        resolved = posixpath.normpath(posixpath.join(source_dir, normalized_target))
        return self._normalize_package_path(resolved)

    def _copy_pixels_only(self, img):
        """Create a fresh image object from raw pixels only."""
        from PIL import Image

        mode = img.mode

        if mode in ['RGBA', 'LA'] or 'transparency' in img.info:
            target_mode = mode if mode in ['RGBA', 'LA'] else 'RGBA'
        else:
            target_mode = 'RGB'

        if img.mode != target_mode:
            img = img.convert(target_mode)

        return Image.frombytes(target_mode, img.size, img.tobytes())

    def _get_embedded_image_save_options(self, file_ext: str) -> tuple:
        """Return a save format and kwargs that preserve the original media type."""
        if file_ext in ['.jpg', '.jpeg']:
            return ('JPEG', {'quality': 95, 'exif': b''})
        if file_ext == '.png':
            return ('PNG', {'compress_level': 6})
        if file_ext in ['.tiff', '.tif']:
            return ('TIFF', {})
        if file_ext == '.bmp':
            return ('BMP', {})

        return ('PNG', {'compress_level': 6})
    
    def _repackage_office_file(self, source_dir: str, output_path: str) -> None:
        """Repackage the extracted Office file into a new ZIP archive."""
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arc_name = os.path.relpath(file_path, source_dir)
                    zipf.write(file_path, arc_name)
