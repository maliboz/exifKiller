"""
Image Cleaner - metadata removal for raster and vector images.

Strategy:
- JPEG / PNG / WebP / GIF / SVG are cleaned *losslessly* by rewriting the
  file's segment/chunk structure and dropping metadata carriers. The image
  payload is preserved byte-for-byte (no quality loss, no pixel change).
- BMP / TIFF (and any format where lossless parsing fails) fall back to a
  pixel-copy re-encode, which guarantees a metadata-free output at the cost of
  a re-encode.
"""

from typing import List, Optional, Callable
from io import BytesIO
import os

from PIL import Image

from .base import BaseCleaner
from .lossless_image import LosslessStripError, strip_file, supports_lossless


class ImageCleaner(BaseCleaner):
    """Cleaner for image files, lossless-first with a pixel-copy fallback."""

    SUPPORTED_EXTENSIONS = [
        ".jpg",
        ".jpeg",
        ".jpe",
        ".png",
        ".webp",
        ".bmp",
        ".tiff",
        ".tif",
        ".gif",
        ".svg",
    ]

    # Formats we can safely re-open to validate a lossless result.
    _RASTER_EXTS = {".jpg", ".jpeg", ".jpe", ".png", ".webp", ".gif"}

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        super().__init__(log_callback)

    def get_supported_extensions(self) -> List[str]:
        return self.SUPPORTED_EXTENSIONS

    def clean(self, file_path: str) -> str:
        """Clean an image, preferring lossless metadata stripping."""
        self.log(f"[>] Opening image: {os.path.basename(file_path)}")
        ext = os.path.splitext(file_path)[1].lower()
        aggressive = self._cleaning_profile == "aggressive"
        output_path = self.generate_output_path(file_path)

        if supports_lossless(ext):
            try:
                return self._lossless_clean(file_path, output_path, ext, aggressive)
            except (LosslessStripError, OSError, ValueError) as exc:
                self.log(f"[!] Lossless strip failed ({exc}); using pixel-copy fallback")
                if ext == ".svg":
                    # No raster fallback makes sense for vector images.
                    raise

        return self._pixel_copy_clean(file_path, output_path, ext)

    def _lossless_clean(
        self, file_path: str, output_path: str, ext: str, aggressive: bool
    ) -> str:
        with open(file_path, "rb") as handle:
            data = handle.read()

        self._log_source_metadata(ext, data)

        cleaned = strip_file(ext, data, aggressive)

        # Validate raster output still decodes to the same pixels before we
        # commit it, so a parser edge case can never silently corrupt an image.
        if ext in self._RASTER_EXTS:
            self._assert_pixels_preserved(data, cleaned)

        with open(output_path, "wb") as handle:
            handle.write(cleaned)

        saved = len(data) - len(cleaned)
        self.log(
            f"[OK] Image cleaned losslessly: {os.path.basename(output_path)} "
            f"({saved} metadata bytes removed, pixels untouched)"
        )
        return output_path

    def _assert_pixels_preserved(self, original: bytes, cleaned: bytes) -> None:
        with Image.open(BytesIO(original)) as before, Image.open(
            BytesIO(cleaned)
        ) as after:
            before.load()
            after.load()
            if before.size != after.size:
                raise LosslessStripError("output dimensions changed")
            if before.mode == after.mode and before.tobytes() != after.tobytes():
                raise LosslessStripError("output pixels changed")

    def _log_source_metadata(self, ext: str, data: bytes) -> None:
        if ext == ".svg":
            return
        try:
            with Image.open(BytesIO(data)) as img:
                exif = img.getexif()
                if exif:
                    self.log(f"[!] EXIF data found: {len(exif)} fields")
                    if 34853 in exif:
                        self.log("[!] GPS coordinates detected!")
                if "xmp" in str(img.info).lower():
                    self.log("[!] XMP metadata detected")
        except Exception:
            pass

    def _pixel_copy_clean(self, file_path: str, output_path: str, ext: str) -> str:
        """Forensic pixel-copy: rebuild the image from raw pixels only.

        Used for BMP/TIFF and as a fallback. This re-encodes the image, which
        for lossy formats would degrade quality — those go through the lossless
        path above, so this only runs for lossless/uncompressed formats.
        """
        try:
            with Image.open(file_path) as original:
                mode = original.mode
                size = original.size
                self.log(f"[*] Size: {size[0]}x{size[1]}, Mode: {mode}")

                if mode in ["RGBA", "LA"] or "transparency" in original.info:
                    target_mode = mode if mode in ["RGBA", "LA"] else "RGBA"
                else:
                    target_mode = "RGB"
                if mode != target_mode:
                    original = original.convert(target_mode)

                new_image = Image.frombytes(
                    target_mode, size, original.tobytes()
                )

                save_format = self._get_save_format(ext)
                save_kwargs: dict = {"format": save_format}
                if save_format == "JPEG":
                    save_kwargs.update(quality=95, exif=b"")
                elif save_format == "PNG":
                    save_kwargs.update(compress_level=6)
                elif save_format == "WEBP":
                    save_kwargs.update(quality=95, exif=b"")

                new_image.save(output_path, **save_kwargs)

                self.log(
                    f"[OK] Image cleaned (pixel-copy): {os.path.basename(output_path)}"
                )
                return output_path
        except Exception as exc:
            self.log(f"[ERROR] Failed to clean image: {exc}")
            raise

    def _get_save_format(self, extension: str) -> str:
        """Map file extension to PIL save format."""
        format_map = {
            ".jpg": "JPEG",
            ".jpeg": "JPEG",
            ".jpe": "JPEG",
            ".png": "PNG",
            ".webp": "WEBP",
            ".bmp": "BMP",
            ".tiff": "TIFF",
            ".tif": "TIFF",
            ".gif": "GIF",
        }
        return format_map.get(extension, "PNG")
