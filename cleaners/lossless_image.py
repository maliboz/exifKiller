"""
Lossless metadata stripping for container-based image formats.

Unlike a pixel re-encode (which permanently degrades JPEG/WebP quality and
changes every byte), these routines parse the file's segment/chunk structure
and copy only the essential data, dropping metadata segments. The compressed
image payload is preserved byte-for-byte, so cleaning is quality-neutral and
reversible-proof: the removed bytes are simply gone.

Supported here: JPEG (marker segments), PNG (chunks), WebP (RIFF chunks),
GIF (extension blocks), SVG (XML). Other formats fall back to the pixel-copy
cleaner or the ExifTool backend.
"""

from __future__ import annotations

import re
from typing import Callable

Logger = Callable[[str], None]


class LosslessStripError(Exception):
    """Raised when a file cannot be parsed for lossless stripping."""


# --------------------------------------------------------------------------- #
# JPEG
# --------------------------------------------------------------------------- #

_JPEG_SOI = b"\xff\xd8"


def strip_jpeg(data: bytes, aggressive: bool = False) -> bytes:
    """Return JPEG bytes with metadata segments removed, losslessly.

    Metadata (EXIF, XMP, IPTC/Photoshop, comments, and — in aggressive mode —
    ICC and JFIF thumbnails) all live in APPn/COM segments that precede the
    first Start-Of-Scan (SOS) marker. Everything from SOS to the End-Of-Image
    (EOI) marker is entropy-coded image data and is copied verbatim; any bytes
    trailing after EOI (appended payloads, hidden thumbnails) are discarded.
    """
    if data[:2] != _JPEG_SOI:
        raise LosslessStripError("not a JPEG (missing SOI marker)")

    out = bytearray(_JPEG_SOI)
    i = 2
    n = len(data)

    while i < n:
        if data[i] != 0xFF:
            raise LosslessStripError(f"invalid JPEG structure at offset {i}")

        # Skip any fill bytes (0xFF padding).
        while i < n and data[i] == 0xFF:
            i += 1
        if i >= n:
            raise LosslessStripError("truncated JPEG")
        marker = data[i]
        i += 1

        if marker == 0xD9:  # EOI with no scan (empty image) -> done
            out += b"\xff\xd9"
            return bytes(out)

        if marker == 0xDA:  # SOS: image data begins
            if i + 2 > n:
                raise LosslessStripError("truncated SOS")
            seg_len = int.from_bytes(data[i : i + 2], "big")
            sos_start = i - 2  # include the 0xFF 0xDA marker bytes
            # A genuine EOI (0xFFD9) never occurs inside entropy data, so the
            # first one after SOS is the real end of image.
            eoi = data.find(b"\xff\xd9", i + seg_len)
            if eoi == -1:
                # No EOI found; copy to end and append one.
                out += data[sos_start:]
                out += b"\xff\xd9"
            else:
                out += data[sos_start : eoi + 2]
            return bytes(out)

        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            # Standalone markers (TEM, RSTn) carry no payload.
            out += bytes((0xFF, marker))
            continue

        # Length-prefixed segment.
        if i + 2 > n:
            raise LosslessStripError("truncated segment header")
        seg_len = int.from_bytes(data[i : i + 2], "big")
        if seg_len < 2 or i + seg_len > n:
            raise LosslessStripError("invalid segment length")
        payload = data[i + 2 : i + seg_len]

        if _jpeg_keep_segment(marker, payload, aggressive):
            out += bytes((0xFF, marker))
            out += data[i : i + seg_len]

        i += seg_len

    return bytes(out)


def _jpeg_keep_segment(marker: int, payload: bytes, aggressive: bool) -> bool:
    """Decide whether a JPEG segment should survive cleaning."""
    if marker == 0xFE:  # COM (comment)
        return False

    if 0xE0 <= marker <= 0xEF:  # APPn
        app = marker - 0xE0
        if app == 0:  # APP0: JFIF header (keep) / JFXX thumbnail (drop when aggr)
            if payload.startswith(b"JFXX"):
                return not aggressive
            return True
        if app == 14:  # APP14 Adobe: color-transform flag, decode-relevant
            return True
        if app == 2:  # APP2: ICC profile (keep unless aggressive) / MPF (drop)
            if payload.startswith(b"ICC_PROFILE"):
                return not aggressive
            return False
        # APP1 (EXIF/XMP), APP13 (Photoshop/IPTC), and all other APPn are
        # metadata carriers -> drop.
        return False

    # Structural segments (SOF, DQT, DHT, DRI, etc.) are always kept.
    return True


# --------------------------------------------------------------------------- #
# PNG
# --------------------------------------------------------------------------- #

_PNG_SIG = b"\x89PNG\r\n\x1a\n"

# Ancillary chunks that carry metadata or timestamps.
_PNG_METADATA_CHUNKS = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME", b"dSIG"}
# Color-management chunks removed only in aggressive mode.
_PNG_COLOR_CHUNKS = {b"iCCP", b"cICP"}


def strip_png(data: bytes, aggressive: bool = False) -> bytes:
    """Return PNG bytes with metadata/timestamp chunks removed, losslessly."""
    if data[:8] != _PNG_SIG:
        raise LosslessStripError("not a PNG (bad signature)")

    drop = set(_PNG_METADATA_CHUNKS)
    if aggressive:
        drop |= _PNG_COLOR_CHUNKS

    out = bytearray(_PNG_SIG)
    i = 8
    n = len(data)

    while i + 8 <= n:
        length = int.from_bytes(data[i : i + 4], "big")
        ctype = data[i + 4 : i + 8]
        chunk_end = i + 12 + length  # length(4) + type(4) + data + crc(4)
        if chunk_end > n:
            raise LosslessStripError("truncated PNG chunk")

        if ctype not in drop:
            out += data[i:chunk_end]

        i = chunk_end
        if ctype == b"IEND":
            break

    return bytes(out)


# --------------------------------------------------------------------------- #
# WebP (RIFF container)
# --------------------------------------------------------------------------- #

_WEBP_METADATA_CHUNKS = {b"EXIF", b"XMP "}


def strip_webp(data: bytes, aggressive: bool = False) -> bytes:
    """Return WebP bytes with EXIF/XMP (and ICC when aggressive) removed."""
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise LosslessStripError("not a WebP (bad RIFF/WEBP header)")

    drop = set(_WEBP_METADATA_CHUNKS)
    if aggressive:
        drop.add(b"ICCP")

    body = bytearray()
    i = 12
    n = len(data)
    while i + 8 <= n:
        fourcc = data[i : i + 4]
        size = int.from_bytes(data[i + 4 : i + 8], "little")
        padded = size + (size & 1)  # chunks are padded to even size
        chunk_end = i + 8 + padded
        if chunk_end > n:
            # Tolerate a truncated final chunk by clamping.
            chunk_end = n
        if fourcc not in drop:
            body += data[i:chunk_end]
        i = chunk_end

    # The VP8X flags byte advertises EXIF/XMP/ICC presence; clear those bits so
    # the container stays internally consistent after removing the chunks.
    body = _webp_fix_vp8x_flags(body, drop)

    out = bytearray(b"RIFF")
    out += (len(body) + 4).to_bytes(4, "little")
    out += b"WEBP"
    out += body
    return bytes(out)


def _webp_fix_vp8x_flags(body: bytearray, drop: set[bytes]) -> bytearray:
    if body[:4] != b"VP8X" or len(body) < 12:
        return body
    flags = body[8]
    if b"ICCP" in drop:
        flags &= ~0x20  # ICC
    flags &= ~0x08  # EXIF
    flags &= ~0x04  # XMP
    body[8] = flags
    return body


# --------------------------------------------------------------------------- #
# GIF
# --------------------------------------------------------------------------- #


def strip_gif(data: bytes, aggressive: bool = False) -> bytes:
    """Remove GIF Comment and Application extension blocks (e.g. XMP)."""
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        raise LosslessStripError("not a GIF (bad header)")

    n = len(data)
    # Header (6) + Logical Screen Descriptor (7).
    i = 6
    packed = data[10]
    gct_flag = packed & 0x80
    gct_size = 2 ** ((packed & 0x07) + 1)
    i = 13
    if gct_flag:
        i += 3 * gct_size

    out = bytearray(data[:i])

    while i < n:
        block = data[i]
        if block == 0x3B:  # Trailer
            out.append(0x3B)
            i += 1
            break
        if block == 0x21:  # Extension Introducer
            label = data[i + 1]
            start = i
            j = i + 2
            j = _gif_skip_sub_blocks(data, j)
            # Drop Comment (0xFE) and Application (0xFF) extensions.
            if label in (0xFE, 0xFF):
                i = j
                continue
            out += data[start:j]
            i = j
            continue
        if block == 0x2C:  # Image Descriptor
            start = i
            i += 10
            lct = data[start + 9]
            if lct & 0x80:
                i += 3 * (2 ** ((lct & 0x07) + 1))
            i += 1  # LZW minimum code size
            i = _gif_skip_sub_blocks(data, i)
            out += data[start:i]
            continue
        # Unknown byte; copy and advance to stay safe.
        out.append(block)
        i += 1

    return bytes(out)


def _gif_skip_sub_blocks(data: bytes, i: int) -> int:
    n = len(data)
    while i < n:
        size = data[i]
        i += 1
        if size == 0:
            break
        i += size
    return i


# --------------------------------------------------------------------------- #
# SVG (XML)
# --------------------------------------------------------------------------- #

_SVG_METADATA_TAGS = ("metadata", "title", "desc")


def strip_svg(data: bytes, aggressive: bool = False) -> bytes:
    """Remove metadata/editor cruft from SVG markup without a full XML parse.

    Drops <metadata> blocks (RDF/Dublin Core), editor namespaces
    (Inkscape/Sorodi/Adobe), XML comments, and — in aggressive mode — <title>
    and <desc> which can hold author notes. Geometry is untouched.
    """
    text = data.decode("utf-8", errors="ignore")

    # Strip XML comments (often contain "Generator: Adobe Illustrator ...").
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    # Strip <metadata>...</metadata> blocks.
    text = re.sub(
        r"<metadata\b[^>]*>.*?</metadata>", "", text, flags=re.DOTALL | re.IGNORECASE
    )

    # Strip editor-specific namespaced elements and attributes.
    for ns in ("inkscape", "sodipodi", "illustrator", "i", "dc", "cc", "rdf"):
        text = re.sub(rf"<{ns}:[^>]*?/>", "", text, flags=re.IGNORECASE)
        text = re.sub(
            rf"<{ns}:([\w-]+)\b.*?</{ns}:\1>", "", text, flags=re.DOTALL | re.IGNORECASE
        )
        text = re.sub(rf'\s{ns}:[\w-]+="[^"]*"', "", text, flags=re.IGNORECASE)

    if aggressive:
        text = re.sub(
            r"<title\b[^>]*>.*?</title>", "", text, flags=re.DOTALL | re.IGNORECASE
        )
        text = re.sub(
            r"<desc\b[^>]*>.*?</desc>", "", text, flags=re.DOTALL | re.IGNORECASE
        )

    return text.encode("utf-8")


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

_STRIPPERS = {
    ".jpg": strip_jpeg,
    ".jpeg": strip_jpeg,
    ".jpe": strip_jpeg,
    ".png": strip_png,
    ".webp": strip_webp,
    ".gif": strip_gif,
    ".svg": strip_svg,
}


def supports_lossless(ext: str) -> bool:
    return ext.lower() in _STRIPPERS


def strip_file(ext: str, data: bytes, aggressive: bool = False) -> bytes:
    """Strip metadata for the given extension, raising if unsupported."""
    stripper = _STRIPPERS.get(ext.lower())
    if stripper is None:
        raise LosslessStripError(f"no lossless stripper for {ext}")
    return stripper(data, aggressive)
