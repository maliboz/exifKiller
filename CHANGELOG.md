# Changelog

## 0.1.0-alpha

### Architecture

- split the app into a shared service layer, CLI, and thinner GUI
- added structured risk classification and deterministic JSON/CSV reporting
- added `scan`, `clean`, `verify`, and `selftest` CLI commands with stable exit
  codes
- introduced `safe` and `aggressive` cleaning profiles
- added packaging metadata, tests, community health files, and CI/security
  workflows

### Backend

- removed the ExifTool dependency entirely: every format is now handled by a
  pure-Python engine written for this project. No external binary is required or
  used at runtime.
- a missing or unloadable optional engine no longer stops the application. When
  pikepdf cannot load — common on Windows without the Visual C++ runtime — PDF
  support reports itself unavailable and every other format keeps working.

### Formats

58 extensions, all native. Formats that index themselves by absolute byte offset
are neutralised in place rather than rewritten, so their size never changes and
their offset tables cannot break.

- lossless image cleaning for JPEG, PNG, WebP, GIF, and SVG: pixels stay
  byte-identical and data appended after the end marker is discarded
- HEIC/HEIF/AVIF: EXIF and XMP item payloads zeroed surgically inside `mdat`
- MP4/MOV/M4V/M4A: `udta` and `meta` boxes neutralised, including the iPhone GPS
  atom, with sample offset tables left valid
- Matroska (MKV/WebM): metadata overwritten with EBML `Void` padding of identical
  size; stale SeekHead entries pruned
- Ogg (Opus/Vorbis/Theora/Speex): vendor string and user tags removed, header
  pages rebuilt with recomputed lacing, renumbered pages, and a recalculated
  Ogg CRC32
- MP3 (ID3v1/ID3v2/APEv2), FLAC, WAV and AVI (RIFF)
- camera RAW (TIFF-based): EXIF, GPS, XMP, IPTC, MakerNote, and DNG identity
  tags removed by compacting the IFD entry array in place
- Canon CRW (CIFF): owner name and camera serial number removed
- OpenDocument (ODT/ODS/ODP and template variants): `meta.xml` emptied,
  annotation and revision identities removed, embedded pictures stripped
  losslessly, manifest kept in sync, ZIP entry timestamps reset

### Features

- timestamp policy for cleaned files: `auto`, `keep`, `epoch`, `random`, and
  `custom`, applied cross-platform (creation time additionally on Windows)
- `selftest`: clean a corpus of real files into a temporary directory and check
  that each one still parses and that its payload is byte-identical. Reports
  `pass`, `residual`, or `damaged`, and lists which supported formats have no
  sample yet.
- the GUI gained the timestamp policy control, and its file picker is now derived
  from the supported-format list instead of a hand-written one

### Fixes

- PDF: a latent bug made the page and annotation `/AF` removal unreachable
- PDF: the trailer `/ID` is now generated deterministically from file content
  rather than fresh entropy
- risk classification: encoder fingerprints such as `WritingApp` and `Ogg.Vendor`
  were classified as technical and silently passed verification
- RIFF: chunk walking stopped at EOF rather than the declared RIFF end, reading
  trailing padding as chunks
- RAW: preview stripping ran after the directories were compacted, writing to
  entry positions that had already moved
- RAW: the orphan-zeroing pass consulted a fixed tag list rather than the
  profile's actual drop set, leaving removed values readable
- HEIF and RAW reporting read item declarations rather than payload contents, and
  claimed metadata survived when it had not
- replaced all bare `except:` clauses, which had been swallowing `KeyboardInterrupt`
