"""
Native, pure-Python metadata stripping for audio and RIFF media.

Covers:
- MP3   : ID3v2 (front), ID3v1 (last 128 bytes), APEv2 (tail).
- FLAC  : drops VORBIS_COMMENT and PICTURE metadata blocks, keeps the stream.
- WAV   : drops INFO/ID3/bext chunks (RIFF), keeps fmt/data.
- AVI   : drops INFO LIST and ID3 chunks, keeps structural hdrl/movi LISTs.

No external tools, no re-encoding: the audio/video payload is preserved
byte-for-byte and only metadata regions are removed.
"""

from __future__ import annotations

from typing import Dict, List, Tuple


class NativeMediaError(Exception):
    """Raised when a media file cannot be parsed for stripping."""


# --------------------------------------------------------------------------- #
# MP3 / ID3
# --------------------------------------------------------------------------- #


def _id3v2_size(data: bytes) -> int:
    """Return total ID3v2 tag length at the start of data, or 0 if none."""
    if len(data) < 10 or data[0:3] != b"ID3":
        return 0
    flags = data[5]
    # Synchsafe 28-bit size (7 bits per byte).
    size = (
        (data[6] & 0x7F) << 21
        | (data[7] & 0x7F) << 14
        | (data[8] & 0x7F) << 7
        | (data[9] & 0x7F)
    )
    total = 10 + size
    if flags & 0x10:  # footer present
        total += 10
    return total


def _apev2_tail_size(data: bytes) -> int:
    """Return APEv2 tag length at the tail, or 0 if none."""
    # APEv2 footer is the last 32 bytes (unless an ID3v1 follows it).
    end = len(data)
    if end >= 128 and data[end - 128 : end - 125] == b"TAG":
        end -= 128
    if end < 32 or data[end - 32 : end - 24] != b"APETAGEX":
        return 0
    tag_size = int.from_bytes(data[end - 20 : end - 16], "little")  # incl. footer
    flags = int.from_bytes(data[end - 16 : end - 12], "little")
    total = tag_size
    if flags & 0x80000000:  # header present
        total += 32
    return total


def strip_mp3(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Remove ID3v2, APEv2, and ID3v1 tags from an MP3, keeping the audio."""
    removed: List[str] = []
    start = 0
    end = len(data)

    v2 = _id3v2_size(data)
    if v2:
        start = v2
        removed.append("ID3v2")

    if end >= 128 and data[end - 128 : end - 125] == b"TAG":
        end -= 128
        removed.append("ID3v1")

    # APEv2 sits before any ID3v1, so measure it against the trimmed tail.
    ape = _apev2_tail_size(data[:end])
    if ape and end - ape >= start:
        end -= ape
        removed.append("APEv2")

    if start == 0 and end == len(data):
        return data, []
    return data[start:end], removed


def describe_mp3(data: bytes) -> Dict[str, str]:
    found: Dict[str, str] = {}
    v2 = _id3v2_size(data)
    if v2:
        found["ID3v2"] = "PRESENT"
        found.update(_read_id3v2_frames(data, v2))
    if len(data) >= 128 and data[-128:-125] == b"TAG":
        found["ID3v1"] = "PRESENT"
    if _apev2_tail_size(data):
        found["APEv2"] = "PRESENT"
    return found


_ID3_FRAME_NAMES = {
    b"TPE1": "Artist",
    b"TIT2": "Title",
    b"TALB": "Album",
    b"TCOM": "Composer",
    b"TENC": "EncodedBy",
    b"TCOP": "Copyright",
    b"COMM": "Comment",
    b"TDRC": "Date",
    b"WXXX": "URL",
    b"GEOB": "EmbeddedObject",
    b"APIC": "AttachedPicture",
}


def _read_id3v2_frames(data: bytes, tag_size: int) -> Dict[str, str]:
    """Best-effort read of a few identifying ID3v2 frame names (v2.3/2.4)."""
    found: Dict[str, str] = {}
    p = 10
    while p + 10 <= tag_size:
        frame_id = data[p : p + 4]
        if not frame_id.strip(b"\x00"):
            break
        size = int.from_bytes(data[p + 4 : p + 8], "big")
        if size <= 0:
            break
        name = _ID3_FRAME_NAMES.get(frame_id)
        if name:
            found[f"ID3.{name}"] = "PRESENT"
        p += 10 + size
    return found


# --------------------------------------------------------------------------- #
# FLAC
# --------------------------------------------------------------------------- #

_FLAC_STREAMINFO = 0
_FLAC_VORBIS_COMMENT = 4
_FLAC_PICTURE = 6
_FLAC_APPLICATION = 2


def strip_flac(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Drop VORBIS_COMMENT and PICTURE (and APPLICATION when aggressive)."""
    if data[:4] != b"fLaC":
        raise NativeMediaError("not a FLAC (missing fLaC marker)")

    drop = {_FLAC_VORBIS_COMMENT, _FLAC_PICTURE}
    if aggressive:
        drop.add(_FLAC_APPLICATION)

    kept: List[Tuple[int, bytes]] = []
    removed: List[str] = []
    p = 4
    n = len(data)
    audio_start = n

    while p + 4 <= n:
        header = data[p]
        last = header & 0x80
        block_type = header & 0x7F
        length = int.from_bytes(data[p + 1 : p + 4], "big")
        block_data = data[p + 4 : p + 4 + length]
        p += 4 + length

        if block_type in drop:
            removed.append(
                "VorbisComment" if block_type == _FLAC_VORBIS_COMMENT
                else "Picture" if block_type == _FLAC_PICTURE
                else "Application"
            )
        else:
            kept.append((block_type, block_data))

        if last:
            audio_start = p
            break

    if not removed:
        return data, []

    out = bytearray(b"fLaC")
    for index, (block_type, block_data) in enumerate(kept):
        is_last = index == len(kept) - 1
        flag = 0x80 if is_last else 0x00
        out.append(flag | block_type)
        out += len(block_data).to_bytes(3, "big")
        out += block_data
    out += data[audio_start:]
    return bytes(out), removed


def describe_flac(data: bytes) -> Dict[str, str]:
    found: Dict[str, str] = {}
    if data[:4] != b"fLaC":
        return found
    p = 4
    n = len(data)
    while p + 4 <= n:
        header = data[p]
        last = header & 0x80
        block_type = header & 0x7F
        length = int.from_bytes(data[p + 1 : p + 4], "big")
        if block_type == _FLAC_VORBIS_COMMENT:
            found["FLAC.VorbisComment"] = "PRESENT"
        elif block_type == _FLAC_PICTURE:
            found["FLAC.Picture"] = "PRESENT"
        p += 4 + length
        if last:
            break
    return found


# --------------------------------------------------------------------------- #
# RIFF (WAV / AVI)
# --------------------------------------------------------------------------- #


def strip_riff(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Drop metadata chunks from a RIFF WAV/AVI, keeping structural chunks."""
    if data[:4] != b"RIFF":
        raise NativeMediaError("not a RIFF file")
    form = data[8:12]

    removed: List[str] = []
    body = bytearray()
    i = 12

    # Chunk walking must stop at the end the RIFF header declares, not at EOF.
    # Real recordings routinely carry bytes past that point (padding, a
    # truncated tail); reading them as chunks yields garbage ids and absurd
    # lengths, and would splice that garbage into the rebuilt body. Anything
    # beyond the declared end is preserved verbatim instead.
    declared_end = 8 + int.from_bytes(data[4:8], "little")
    n = min(declared_end, len(data)) if declared_end > 12 else len(data)
    trailing = data[n:] if n < len(data) else b""

    # Bytes past the declared end are unreferenced: no player reads them, which
    # is precisely what makes them a place to hide data. Aggressive drops them,
    # mirroring how the JPEG path discards anything after EOI.
    if trailing and aggressive:
        removed.append("TrailingData")
        trailing = b""

    while i + 8 <= n:
        cid = data[i : i + 4]
        size = int.from_bytes(data[i + 4 : i + 8], "little")
        padded = size + (size & 1)
        chunk_end = i + 8 + padded
        if chunk_end > n:
            chunk_end = n

        drop = False
        if cid == b"LIST":
            subtype = data[i + 8 : i + 12]
            if subtype == b"INFO":  # metadata; safe to drop in WAV and AVI
                drop = True
                removed.append("INFO")
        elif cid in (b"ID3 ", b"id3 "):
            drop = True
            removed.append("ID3")
        elif cid == b"bext":  # broadcast metadata (contains originator, date)
            drop = True
            removed.append("bext")
        elif cid in (b"IART", b"INAM", b"ICMT", b"ICRD", b"ISFT"):
            drop = True
            removed.append(cid.decode("ascii", "ignore"))

        if not drop:
            body += data[i:chunk_end]
        i = chunk_end

    if not removed:
        return data, []

    out = bytearray(b"RIFF")
    out += (len(body) + 4).to_bytes(4, "little")
    out += form
    out += body
    out += trailing
    return bytes(out), removed


def describe_riff(data: bytes) -> Dict[str, str]:
    found: Dict[str, str] = {}
    if data[:4] != b"RIFF":
        return found
    i = 12
    declared_end = 8 + int.from_bytes(data[4:8], "little")
    n = min(declared_end, len(data)) if declared_end > 12 else len(data)
    while i + 8 <= n:
        cid = data[i : i + 4]
        size = int.from_bytes(data[i + 4 : i + 8], "little")
        if size <= 0:
            break
        if cid == b"LIST" and data[i + 8 : i + 12] == b"INFO":
            found["RIFF.INFO"] = "PRESENT"
        elif cid in (b"ID3 ", b"id3 "):
            found["RIFF.ID3"] = "PRESENT"
        elif cid == b"bext":
            found["RIFF.bext"] = "PRESENT"
        i += 8 + size + (size & 1)
    return found
