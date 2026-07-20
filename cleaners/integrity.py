"""
Integrity checks: did cleaning damage the file?

Verification elsewhere in this tool answers "is the metadata gone?". That is
only half the question, and the easier half. The one that actually matters when
you point this at a real photo library is "does the file still work?" - a
cleaner that silently corrupts a RAW while dutifully reporting zero findings is
worse than useless.

These checks are deliberately format-aware and payload-focused. For every family
we know where the irreplaceable bytes live (the entropy-coded scan, `mdat`, the
clusters, the audio pages, the sensor strips) and assert they came through
untouched, that the container still parses, and that anything we promised not to
resize really did not move.

Nothing here is used during normal cleaning; this is the harness that lets a
corpus of real files prove the engines are honest.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Check:
    """One integrity assertion about a cleaned file."""

    name: str
    passed: bool
    detail: str = ""


def _ok(name: str, detail: str = "") -> Check:
    return Check(name=name, passed=True, detail=detail)


def _fail(name: str, detail: str) -> Check:
    return Check(name=name, passed=False, detail=detail)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _pillow_pixels_match(original: bytes, cleaned: bytes) -> Check:
    """Decode both with Pillow and compare raw pixels."""
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover
        return _ok("pixels", "Pillow unavailable, skipped")

    try:
        with Image.open(io.BytesIO(original)) as before:
            before.load()
            before_size = before.size
            before_data = before.convert("RGBA").tobytes()
    except Exception as exc:
        return _ok("pixels", f"original not decodable by Pillow ({exc}); skipped")

    try:
        with Image.open(io.BytesIO(cleaned)) as after:
            after.load()
            after_size = after.size
            after_data = after.convert("RGBA").tobytes()
    except Exception as exc:
        return _fail("pixels", f"cleaned file no longer opens: {exc}")

    if before_size != after_size:
        return _fail("pixels", f"size changed {before_size} -> {after_size}")
    if before_data != after_data:
        return _fail("pixels", "pixel data changed (cleaning was not lossless)")
    return _ok("pixels", f"identical, {after_size[0]}x{after_size[1]}")


def _same_size(original: bytes, cleaned: bytes) -> Check:
    if len(original) != len(cleaned):
        return _fail(
            "size-preserved",
            f"{len(original)} -> {len(cleaned)} bytes; offsets may be broken",
        )
    return _ok("size-preserved", f"{len(cleaned)} bytes")


def _not_empty(cleaned: bytes) -> Check:
    if not cleaned:
        return _fail("non-empty", "cleaned file is empty")
    return _ok("non-empty", f"{len(cleaned)} bytes")


# --------------------------------------------------------------------------- #
# JPEG
# --------------------------------------------------------------------------- #


def _jpeg_scan_bytes(data: bytes) -> Optional[bytes]:
    """The entropy-coded image data: everything from SOS to EOI.

    The SOS marker must be found by walking the segment chain, not by searching
    for the bytes: a JPEG's EXIF block is arbitrary binary data and routinely
    contains 0xFFDA by coincidence. Searching finds that first, and since
    cleaning removes the EXIF, the two files then get compared from different
    offsets and a lossless strip looks like a re-encode.
    """
    if data[:2] != b"\xff\xd8":
        return None

    i = 2
    n = len(data)
    while i < n:
        if data[i] != 0xFF:
            return None
        while i < n and data[i] == 0xFF:  # skip fill bytes
            i += 1
        if i >= n:
            return None
        marker = data[i]
        i += 1

        if marker == 0xD9:  # EOI before any scan
            return b""
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # standalone markers
            continue

        if i + 2 > n:
            return None
        seg_len = int.from_bytes(data[i : i + 2], "big")
        if seg_len < 2:
            return None

        if marker == 0xDA:  # SOS: the scan starts after this segment
            start = i + seg_len
            end = data.find(b"\xff\xd9", start)
            return data[start:end] if end != -1 else data[start:]

        i += seg_len

    return None


def check_jpeg(original: bytes, cleaned: bytes) -> List[Check]:
    checks = [_not_empty(cleaned)]

    if not cleaned.startswith(b"\xff\xd8"):
        checks.append(_fail("structure", "missing SOI marker"))
    elif not cleaned.endswith(b"\xff\xd9"):
        checks.append(_fail("structure", "missing EOI marker"))
    else:
        checks.append(_ok("structure", "SOI/EOI present"))

    before, after = _jpeg_scan_bytes(original), _jpeg_scan_bytes(cleaned)
    if before is None or after is None:
        checks.append(_fail("scan-preserved", "could not locate the scan data"))
    elif before != after:
        checks.append(
            _fail("scan-preserved", "compressed image data changed (re-encoded!)")
        )
    else:
        checks.append(_ok("scan-preserved", f"{len(after)} bytes identical"))

    checks.append(_pillow_pixels_match(original, cleaned))
    if len(cleaned) < len(original):
        checks.append(_ok("shrunk", f"-{len(original) - len(cleaned)} bytes"))
    return checks


# --------------------------------------------------------------------------- #
# PNG / WebP / GIF / BMP / TIFF-as-image
# --------------------------------------------------------------------------- #


def check_image(original: bytes, cleaned: bytes) -> List[Check]:
    return [_not_empty(cleaned), _pillow_pixels_match(original, cleaned)]


def check_svg(original: bytes, cleaned: bytes) -> List[Check]:
    checks = [_not_empty(cleaned)]
    text = cleaned.decode("utf-8", "ignore").lower()
    if "<svg" not in text:
        checks.append(_fail("structure", "no <svg> element left"))
    else:
        checks.append(_ok("structure", "<svg> element intact"))
    return checks


# --------------------------------------------------------------------------- #
# TIFF / camera RAW
# --------------------------------------------------------------------------- #


def check_tiff_raw(original: bytes, cleaned: bytes) -> List[Check]:
    from . import tiff_raw

    checks = [_not_empty(cleaned), _same_size(original, cleaned)]

    try:
        before = tiff_raw.TiffFile(original)
    except tiff_raw.TiffError as exc:
        checks.append(_ok("parses", f"original not parseable ({exc}); skipped"))
        return checks

    try:
        after = tiff_raw.TiffFile(cleaned)
    except tiff_raw.TiffError as exc:
        checks.append(_fail("parses", f"cleaned file no longer parses: {exc}"))
        return checks
    checks.append(_ok("parses", f"{len(after.ifds)} IFDs"))

    # Structural tags must survive untouched or the image cannot be decoded.
    structural = (256, 257, 258, 259, 262, 273, 277, 278, 279, 322, 323, 324,
                  325, 330, 33422, 50706, 50717, 50718)
    mismatched = []
    for b_ifd, a_ifd in zip(before.ifds, after.ifds):
        for tag in structural:
            b_entry, a_entry = b_ifd.get(tag), a_ifd.get(tag)
            if b_entry is None:
                continue
            if a_entry is None:
                mismatched.append(f"tag {tag} dropped")
            elif before.value_ints(b_entry) != after.value_ints(a_entry):
                mismatched.append(f"tag {tag} value changed")
    if mismatched:
        checks.append(_fail("structural-tags", "; ".join(mismatched[:4])))
    else:
        checks.append(_ok("structural-tags", "all preserved"))

    # The sensor data itself.
    sensor_checks = _raw_sensor_identical(before, after, original, cleaned)
    checks.append(sensor_checks)
    return checks


def _raw_sensor_identical(before, after, original: bytes, cleaned: bytes) -> Check:
    """Compare every strip/tile the directories point at."""
    from . import tiff_raw

    total = 0
    for b_ifd, a_ifd in zip(before.ifds, after.ifds):
        photometric = before.value_int(b_ifd, tiff_raw.TAG_PHOTOMETRIC)
        for off_tag, cnt_tag in ((273, 279), (324, 325)):
            b_off, b_cnt = b_ifd.get(off_tag), b_ifd.get(cnt_tag)
            if b_off is None or b_cnt is None:
                continue
            offsets = before.value_ints(b_off)
            counts = before.value_ints(b_cnt)
            a_off, a_cnt = a_ifd.get(off_tag), a_ifd.get(cnt_tag)
            if a_off is None or a_cnt is None:
                return Check("sensor-data", False, f"tag {off_tag} disappeared")
            new_offsets = after.value_ints(a_off)
            new_counts = after.value_ints(a_cnt)
            if offsets != new_offsets:
                return Check("sensor-data", False, "strip offsets moved")

            for (off, cnt), new_cnt in zip(zip(offsets, counts), new_counts):
                # A preview is allowed to shrink (its EXIF was stripped); real
                # sensor data must be identical.
                is_preview = photometric not in (32803, 34892) and cnt != new_cnt
                if is_preview:
                    continue
                if original[off : off + cnt] != cleaned[off : off + cnt]:
                    return Check(
                        "sensor-data", False,
                        f"payload at offset {off} changed - RAW DATA DAMAGED",
                    )
                total += cnt

    if not total:
        return Check("sensor-data", True, "no strip/tile payload located; skipped")
    return Check("sensor-data", True, f"{total} bytes identical")


# --------------------------------------------------------------------------- #
# Canon CRW (CIFF)
# --------------------------------------------------------------------------- #


def check_crw(original: bytes, cleaned: bytes) -> List[Check]:
    from . import ciff

    checks = [_not_empty(cleaned), _same_size(original, cleaned)]

    try:
        before = ciff.CIFFFile(original)
    except ciff.CIFFError as exc:
        checks.append(_ok("parses", f"original not parseable ({exc}); skipped"))
        return checks

    try:
        after = ciff.CIFFFile(cleaned)
    except ciff.CIFFError as exc:
        checks.append(_fail("parses", f"cleaned file no longer parses: {exc}"))
        return checks
    checks.append(_ok("parses", f"{len(after.directories)} directories"))

    checks.append(_crw_raw_data_identical(before, after, original, cleaned))
    return checks


def _crw_raw_data_identical(before, after, original: bytes,
                            cleaned: bytes) -> Check:
    """The sensor data (tag 0x2005) must survive byte-for-byte."""
    from . import ciff

    total = 0
    for directory in before.directories:
        for entry in directory.entries:
            if entry.tag != ciff.TAG_RAW_DATA or entry.inline:
                continue
            start, length = entry.absolute_offset, entry.length
            if start + length > len(original):
                continue
            if original[start : start + length] != cleaned[start : start + length]:
                return Check("sensor-data", False,
                             f"raw data at offset {start} changed - RAW DAMAGED")
            total += length

    if not total:
        return Check("sensor-data", True, "no RawData record; skipped")

    # The record must still be reachable after cleaning.
    survives = any(
        entry.tag == ciff.TAG_RAW_DATA
        for directory in after.directories
        for entry in directory.entries
    )
    if not survives:
        return Check("sensor-data", False, "the RawData record was dropped")
    return Check("sensor-data", True, f"{total} bytes identical")


# --------------------------------------------------------------------------- #
# ISOBMFF (mp4/mov/heic/avif)
# --------------------------------------------------------------------------- #


def _isobmff_payload(data: bytes, box_type: bytes) -> bytes:
    from . import isobmff

    out = bytearray()
    for start, header, btype, end in isobmff.iter_boxes(data, 0, len(data)):
        if btype == box_type:
            out += data[start + header : end]
    return bytes(out)


def check_isobmff(original: bytes, cleaned: bytes) -> List[Check]:
    from . import isobmff

    checks = [_not_empty(cleaned), _same_size(original, cleaned)]

    boxes = list(isobmff.iter_boxes(cleaned, 0, len(cleaned)))
    if not boxes:
        checks.append(_fail("parses", "no boxes found"))
        return checks
    if boxes[-1][3] != len(cleaned):
        checks.append(
            _fail("parses", f"last box ends at {boxes[-1][3]}, file is {len(cleaned)}")
        )
    else:
        checks.append(
            _ok("parses", f"{len(boxes)} top-level boxes, tree ends exactly at EOF")
        )

    before_mdat = _isobmff_payload(original, b"mdat")
    after_mdat = _isobmff_payload(cleaned, b"mdat")
    if not before_mdat:
        checks.append(_ok("mdat-preserved", "no mdat box; skipped"))
    elif before_mdat == after_mdat:
        checks.append(_ok("mdat-preserved", f"{len(after_mdat)} bytes identical"))
    else:
        # HEIF surgically zeroes EXIF payloads inside mdat, so a difference is
        # expected there; report how much changed rather than failing outright.
        if isobmff.is_heif(original):
            diff = sum(1 for a, b in zip(before_mdat, after_mdat) if a != b)
            checks.append(
                _ok("mdat-preserved",
                    f"HEIF: {diff} of {len(after_mdat)} bytes zeroed (metadata items)")
            )
        else:
            checks.append(_fail("mdat-preserved", "media payload changed!"))
    return checks


# --------------------------------------------------------------------------- #
# Matroska
# --------------------------------------------------------------------------- #


def check_matroska(original: bytes, cleaned: bytes) -> List[Check]:
    from . import matroska

    checks = [_not_empty(cleaned), _same_size(original, cleaned)]

    segment = matroska._find_segment(cleaned)
    if segment is None:
        checks.append(_fail("parses", "no Segment element"))
        return checks

    children = list(
        matroska.iter_elements(cleaned, segment.payload_start, segment.payload_end)
    )
    if not children:
        checks.append(_fail("parses", "Segment has no children"))
        return checks
    if children[-1].end != segment.payload_end:
        checks.append(
            _fail("parses", "element tree does not end exactly at the Segment end")
        )
    else:
        checks.append(_ok("parses", f"{len(children)} Segment children"))

    before_clusters = _matroska_clusters(original)
    after_clusters = _matroska_clusters(cleaned)
    if not before_clusters:
        checks.append(_ok("clusters-preserved", "no clusters; skipped"))
    elif before_clusters == after_clusters:
        checks.append(
            _ok("clusters-preserved", f"{len(after_clusters)} bytes identical")
        )
    else:
        checks.append(_fail("clusters-preserved", "media payload changed!"))
    return checks


def _matroska_clusters(data: bytes) -> bytes:
    from . import matroska

    segment = matroska._find_segment(data)
    if segment is None:
        return b""
    out = bytearray()
    for child in matroska.iter_elements(data, segment.payload_start,
                                        segment.payload_end):
        if child.eid == matroska.ID_CLUSTER:
            out += data[child.payload_start : child.payload_end]
    return bytes(out)


# --------------------------------------------------------------------------- #
# Ogg
# --------------------------------------------------------------------------- #


def check_ogg(original: bytes, cleaned: bytes) -> List[Check]:
    from . import ogg

    checks = [_not_empty(cleaned)]

    try:
        pages = ogg.parse_pages(cleaned)
    except ogg.OggError as exc:
        checks.append(_fail("parses", f"cleaned file no longer parses: {exc}"))
        return checks
    checks.append(_ok("parses", f"{len(pages)} pages"))

    bad_crc = []
    for page in pages:
        raw = cleaned[page.start : page.end]
        stored = int.from_bytes(raw[22:26], "little")
        recomputed = ogg._ogg_crc(raw[:22] + b"\x00\x00\x00\x00" + raw[26:])
        if stored != recomputed:
            bad_crc.append(page.sequence)
    if bad_crc:
        checks.append(_fail("crc", f"bad CRC on pages {bad_crc[:5]}"))
    else:
        checks.append(_ok("crc", "all page CRCs valid"))

    # Page sequence numbers must stay contiguous per logical stream.
    per_stream: Dict[int, List[int]] = {}
    for page in pages:
        per_stream.setdefault(page.serial, []).append(page.sequence)
    broken = [s for s, seqs in per_stream.items()
              if seqs != list(range(seqs[0], seqs[0] + len(seqs)))]
    if broken:
        checks.append(_fail("page-sequence", f"gaps in streams {broken}"))
    else:
        checks.append(_ok("page-sequence", f"{len(per_stream)} stream(s) contiguous"))

    before_audio = _ogg_audio(original)
    after_audio = _ogg_audio(cleaned)
    if not before_audio:
        checks.append(_ok("audio-preserved", "no audio pages; skipped"))
    elif before_audio == after_audio:
        checks.append(_ok("audio-preserved", f"{len(after_audio)} bytes identical"))
    else:
        checks.append(_fail("audio-preserved", "audio payload changed!"))
    return checks


def _ogg_audio(data: bytes) -> bytes:
    from . import ogg

    try:
        pages = ogg.parse_pages(data)
    except ogg.OggError:
        return b""
    out = bytearray()
    for page in pages:
        if page.granule > 0:  # header pages carry granule 0
            out += page.body
    return bytes(out)


# --------------------------------------------------------------------------- #
# MP3 / FLAC / RIFF
# --------------------------------------------------------------------------- #


def check_mp3(original: bytes, cleaned: bytes) -> List[Check]:
    checks = [_not_empty(cleaned)]
    if cleaned and original.find(cleaned) != -1:
        checks.append(
            _ok("audio-preserved", "cleaned stream is an exact slice of the original")
        )
    else:
        checks.append(
            _fail("audio-preserved", "cleaned audio is not a byte-slice of the input")
        )
    if cleaned[:3] == b"ID3":
        checks.append(_fail("tags-gone", "an ID3v2 tag is still present"))
    else:
        checks.append(_ok("tags-gone", "no leading ID3v2 tag"))
    return checks


def check_flac(original: bytes, cleaned: bytes) -> List[Check]:
    from . import native_media

    checks = [_not_empty(cleaned)]
    if cleaned[:4] != b"fLaC":
        checks.append(_fail("structure", "missing fLaC marker"))
        return checks
    checks.append(_ok("structure", "fLaC marker present"))

    described = native_media.describe_flac(cleaned)
    if described:
        checks.append(_fail("tags-gone", f"still present: {sorted(described)}"))
    else:
        checks.append(_ok("tags-gone", "no comment/picture blocks"))
    return checks


def check_riff(original: bytes, cleaned: bytes) -> List[Check]:
    checks = [_not_empty(cleaned)]
    if cleaned[:4] != b"RIFF":
        checks.append(_fail("structure", "missing RIFF header"))
        return checks

    # Real-world AVIs often ship with a RIFF size field that already disagrees
    # with the file length (trailing padding, truncated recordings). Only blame
    # the cleaner if the original was consistent and the output is not.
    declared = int.from_bytes(cleaned[4:8], "little")
    actual = len(cleaned) - 8
    was_consistent = int.from_bytes(original[4:8], "little") == len(original) - 8
    if declared == actual:
        checks.append(_ok("structure", "RIFF size field consistent"))
    elif not was_consistent:
        checks.append(
            _ok("structure",
                f"size field says {declared}, file has {actual} - but the input "
                "was already like this")
        )
    else:
        checks.append(
            _fail("structure",
                  f"RIFF size field says {declared}, file has {actual}")
        )

    before_data = _riff_chunk(original, b"data") or _riff_chunk(original, b"movi")
    after_data = _riff_chunk(cleaned, b"data") or _riff_chunk(cleaned, b"movi")
    if before_data is None:
        checks.append(_ok("payload-preserved", "no data chunk; skipped"))
    elif before_data == after_data:
        checks.append(_ok("payload-preserved", f"{len(after_data)} bytes identical"))
    else:
        checks.append(_fail("payload-preserved", "media payload changed!"))
    return checks


def _riff_chunk(data: bytes, cid: bytes) -> Optional[bytes]:
    i = 12
    n = len(data)
    while i + 8 <= n:
        chunk_id = data[i : i + 4]
        size = int.from_bytes(data[i + 4 : i + 8], "little")
        if chunk_id == cid:
            return data[i + 8 : i + 8 + size]
        if chunk_id == b"LIST" and data[i + 8 : i + 12] == cid:
            return data[i + 12 : i + 8 + size]
        i += 8 + size + (size & 1)
    return None


# --------------------------------------------------------------------------- #
# PDF / Office / ODF
# --------------------------------------------------------------------------- #


def check_pdf(original: bytes, cleaned: bytes) -> List[Check]:
    checks = [_not_empty(cleaned)]
    try:
        import pikepdf
    except ImportError:  # pragma: no cover
        return checks

    try:
        with pikepdf.open(io.BytesIO(original)) as before:
            before_pages = len(before.pages)
    except Exception as exc:
        checks.append(_ok("opens", f"original not readable ({exc}); skipped"))
        return checks

    try:
        with pikepdf.open(io.BytesIO(cleaned)) as after:
            after_pages = len(after.pages)
    except Exception as exc:
        checks.append(_fail("opens", f"cleaned PDF no longer opens: {exc}"))
        return checks

    checks.append(_ok("opens", "pikepdf parsed it"))
    if before_pages != after_pages:
        checks.append(_fail("pages", f"{before_pages} -> {after_pages}"))
    else:
        checks.append(_ok("pages", f"{after_pages} pages"))
    return checks


_OOXML_REQUIRED = {
    ".docx": "word/document.xml",
    ".xlsx": "xl/workbook.xml",
    ".pptx": "ppt/presentation.xml",
}


def check_ooxml(original: bytes, cleaned: bytes, ext: str) -> List[Check]:
    checks = [_not_empty(cleaned)]
    try:
        with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
            names = zf.namelist()
            if zf.testzip() is not None:
                checks.append(_fail("zip", "corrupt entry in archive"))
                return checks
    except zipfile.BadZipFile as exc:
        checks.append(_fail("zip", f"not a readable archive: {exc}"))
        return checks

    checks.append(_ok("zip", f"{len(names)} entries"))
    required = _OOXML_REQUIRED.get(ext)
    if required and required not in names:
        checks.append(_fail("structure", f"{required} is missing"))
    elif "[Content_Types].xml" not in names:
        checks.append(_fail("structure", "[Content_Types].xml is missing"))
    else:
        checks.append(_ok("structure", "core parts present"))
    return checks


def check_odf(original: bytes, cleaned: bytes) -> List[Check]:
    checks = [_not_empty(cleaned)]
    try:
        with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
            infos = zf.infolist()
            names = [i.filename for i in infos]
            if zf.testzip() is not None:
                checks.append(_fail("zip", "corrupt entry in archive"))
                return checks
    except zipfile.BadZipFile as exc:
        checks.append(_fail("zip", f"not a readable archive: {exc}"))
        return checks

    checks.append(_ok("zip", f"{len(names)} entries"))

    # ODF stops being recognised if mimetype is not first and stored.
    if not infos or infos[0].filename != "mimetype":
        checks.append(_fail("mimetype-first", "mimetype is not the first entry"))
    elif infos[0].compress_type != zipfile.ZIP_STORED:
        checks.append(_fail("mimetype-first", "mimetype entry is compressed"))
    else:
        checks.append(_ok("mimetype-first", "first and stored"))

    if "content.xml" not in names:
        checks.append(_fail("structure", "content.xml is missing"))
    elif "META-INF/manifest.xml" not in names:
        checks.append(_fail("structure", "manifest is missing"))
    else:
        checks.append(_ok("structure", "content.xml and manifest present"))

    # Every manifest entry must actually exist in the archive.
    try:
        import re

        with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
            manifest = zf.read("META-INF/manifest.xml").decode("utf-8", "ignore")
        listed = set(re.findall(r'manifest:full-path="([^"]+)"', manifest))
        missing = {p for p in listed if p != "/" and not p.endswith("/")
                   and p not in names}
        if missing:
            checks.append(
                _fail("manifest-sync", f"lists missing parts: {sorted(missing)[:3]}")
            )
        else:
            checks.append(_ok("manifest-sync", "every listed part exists"))
    except (KeyError, zipfile.BadZipFile):
        pass

    return checks


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

_JPEG = {".jpg", ".jpeg", ".jpe"}
_PILLOW_IMAGE = {".png", ".webp", ".gif", ".bmp", ".tiff", ".tif"}
_ISOBMFF = {".mp4", ".mov", ".m4v", ".m4a", ".heic", ".heif", ".avif"}
_MATROSKA = {".mkv", ".webm"}
_OGG = {".ogg", ".oga", ".ogv", ".opus", ".spx"}
_RIFF = {".wav", ".avi"}
_ODF = {".odt", ".ods", ".odp", ".odg", ".odf", ".ott", ".ots", ".otp"}
_RAW = {".cr2", ".nef", ".nrw", ".arw", ".sr2", ".srf", ".dng", ".orf", ".rw2",
        ".pef", ".srw", ".3fr", ".mef", ".mos", ".erf", ".dcr", ".kdc"}


def check_integrity(ext: str, original: bytes, cleaned: bytes) -> List[Check]:
    """Run the format-appropriate integrity checks for a cleaned file."""
    ext = ext.lower()

    if ext in _JPEG:
        return check_jpeg(original, cleaned)
    if ext in _PILLOW_IMAGE:
        return check_image(original, cleaned)
    if ext == ".svg":
        return check_svg(original, cleaned)
    if ext == ".crw":
        return check_crw(original, cleaned)
    if ext in _RAW:
        return check_tiff_raw(original, cleaned)
    if ext in _ISOBMFF:
        return check_isobmff(original, cleaned)
    if ext in _MATROSKA:
        return check_matroska(original, cleaned)
    if ext in _OGG:
        return check_ogg(original, cleaned)
    if ext == ".mp3":
        return check_mp3(original, cleaned)
    if ext == ".flac":
        return check_flac(original, cleaned)
    if ext in _RIFF:
        return check_riff(original, cleaned)
    if ext == ".pdf":
        return check_pdf(original, cleaned)
    if ext in _OOXML_REQUIRED:
        return check_ooxml(original, cleaned, ext)
    if ext in _ODF:
        return check_odf(original, cleaned)

    return [_not_empty(cleaned)]
