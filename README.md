# Exif Killer

Offline metadata sanitizer and verification tool for DFIR, OSINT, and OPSEC.

![Exif Killer Logo](logo.png)

Exif Killer is a Windows-first alpha project that focuses on trustworthy metadata cleanup instead of vague "trust me" claims. The app stays offline, uses a native Python backend, and always pairs cleaning with verification and structured reporting.

## Threat Model

Exif Killer is designed for scenarios where metadata can expose operator identity, source application details, location hints, or document history. The tool is especially useful when handling:

- images with author, software, or GPS metadata
- PDFs with DocInfo, XMP, document IDs, or embedded content
- Office documents with author fields, comment identities, revision traces, or preview thumbnails
- Windows files that may carry download-zone artifacts or filesystem timeline hints

Exif Killer does not claim to erase every possible forensic artifact in every format. The product goal is narrower and more honest: sanitize what it knows, verify the result, and report what still remains.

## Supported Formats

Everything is handled by **pure-Python parsers with no external tools and no
re-encoding** — the media payload is preserved byte-for-byte and only metadata
is removed.

- Images: `jpg`, `jpeg`, `jpe`, `png`, `webp`, `bmp`, `tiff`, `tif`, `gif`, `svg`
- Modern images: `heic`, `heif`, `avif`
- Video: `mp4`, `mov`, `m4v`, `avi`, `mkv`, `webm`, `ogv`
- Audio: `mp3`, `flac`, `m4a`, `wav`, `ogg`, `oga`, `opus`, `spx`
- Documents: `pdf`, `docx`, `xlsx`, `pptx`

How each family is cleaned:

- **JPEG/PNG/WebP/GIF/SVG** — the segment/chunk structure is rewritten and only
  metadata carriers are dropped, losslessly. Pixels stay byte-identical, and
  data appended after the image's end marker (hidden thumbnails, stego payloads)
  is discarded. BMP/TIFF use a pixel-copy rebuild.
- **MP4/MOV/M4V/M4A** (ISOBMFF) — the `udta`/`meta` metadata boxes (iPhone GPS
  `©xyz`, device, software, iTunes tags) are neutralised in place, so sample
  offset tables stay valid and the media is not touched.
- **HEIC/HEIF/AVIF** — the EXIF/XMP item payloads are zeroed surgically inside
  `mdat` while the image items are left intact.
- **MKV/WebM** (Matroska/EBML) — `Tags`, `Attachments`, `Title`, `DateUTC`,
  `SegmentUID`, and track names are overwritten in place with EBML `Void`
  padding of identical size, so the file length never changes and the
  `SeekHead`/`Cues` offset indexes stay valid. Index entries pointing at removed
  elements are pruned; the mandatory `MuxingApp`/`WritingApp` strings are
  zero-filled rather than deleted, which EBML explicitly permits.
- **Ogg/Opus/Vorbis/Theora/Speex** — the comment header's vendor string (an
  encoder fingerprint) and every user tag, including embedded cover art, are
  removed. Ogg has no offset index, so the header pages are genuinely rebuilt:
  lacing tables recomputed, page sequence renumbered, and the Ogg CRC32
  recalculated. Audio pages are copied through byte-for-byte.
- **MP3** — ID3v2, ID3v1, and APEv2 tags are stripped, keeping the audio frames.
- **FLAC** — `VORBIS_COMMENT` and `PICTURE` blocks are removed.
- **WAV/AVI** (RIFF) — `INFO`/`ID3`/`bext` metadata chunks are removed.

## Cleaning Profiles

- `safe`: removes direct identifying and tracking metadata while prioritizing file compatibility
- `aggressive`: expands cleanup to thumbnails, revision markers, embedded previews, Windows post-processing, and other higher-risk traces

`safe` is the default profile. `aggressive` is recommended when compatibility tradeoffs are acceptable.

## Verification Model

Cleaning is always paired with a re-scan, but a tool checking its own work with
its own parser shares its own blind spots. The test suite therefore cross-checks
the Ogg engine against [mutagen](https://mutagen.readthedocs.io/), a third-party
implementation: it must see the tags before cleaning and must still parse the
result as a valid stream afterwards. mutagen is a dev-only extra — the tool
itself has no such dependency, and those tests skip when it is absent.

Exif Killer classifies findings into five categories:

- `identifying`
- `tracking`
- `embedded-content`
- `filesystem`
- `technical`

Verification fails with `warning` status when any `identifying`, `tracking`, or `embedded-content` findings remain. Filesystem-only leftovers are reported but do not fail verification. Technical fields are retained when they are needed for compatibility or structure.

## Interface Preview

The desktop GUI is available through `python main.py` or the `exif-killer-gui` entrypoint. The GUI follows a simple workflow:

1. Queue files or drag-drop folders.
2. Run `Scan`.
3. Run `Clean + Verify`.
4. Export JSON or CSV evidence.

## CLI Usage

```bash
exif-killer scan sample.jpg --format text
exif-killer clean secret.pdf --profile aggressive --format json --report clean-report.json
exif-killer verify original.docx cleaned.docx --format json
```

### Timestamp Policy

`clean` can rewrite the cleaned file's filesystem timestamps (modification and
access on every platform; creation is additionally set on Windows via the Win32
API). Filesystem dates are a common OPSEC leak, so the policy is configurable:

```bash
exif-killer clean photo.jpg --timestamp random
exif-killer clean photo.jpg --timestamp epoch
exif-killer clean photo.jpg --timestamp custom --timestamp-date 2020-05-01T13:00:00
exif-killer clean photo.jpg --timestamp keep
```

- `auto` (default): follow the profile — `aggressive` resets to epoch, `safe` leaves timestamps untouched
- `keep`: never touch filesystem timestamps
- `epoch`: reset to `1970-01-01`
- `random`: generate a plausible random date per file (created ≤ modified ≤ accessed, within a normal usage window) so the file does not stand out
- `custom`: use `--timestamp-date` (accepts `YYYY-MM-DD` or ISO 8601)

### Stable Exit Codes

- `0`: operation succeeded and no blocking findings remain
- `1`: usage error or runtime failure
- `2`: operation completed but blocking findings remain
- `3`: no supported files were available to process

## JSON Report Shape

Each JSON report entry includes the following core fields:

- `tool_version`
- `command`
- `profile`
- `status`
- `backend`
- `input_path`
- `output_path`
- `file_type`
- `sha256_before`
- `sha256_after`
- `findings`
- `removed_fields`
- `remaining_findings`
- `warnings`
- `timestamp_utc`

An example report lives at [docs/example_report.json](docs/example_report.json).

## Local Development

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
pytest
ruff check .
mypy
```

## Security Posture

- Offline-first by default
- No telemetry
- No cloud scanning
- No auto-update agent
- Structured JSON and CSV evidence for audit trails
- Windows portable build target for the alpha release

## Known Limitations

- Windows is the primary release target for `v0.1.0-alpha`
- Camera RAW (`cr2`/`nef`/`arw`/`dng`) and OpenDocument (`odt`/`ods`/`odp`) are
  not yet supported
- Ogg FLAC (FLAC inside an Ogg container) is detected but not stripped; native
  `.flac` files are fully handled
- Matroska cleaning is byte-exact by design, so a file never shrinks: metadata is
  replaced with `Void` padding rather than cut out
- Recursive archive inspection is not in the alpha scope
- Creation-time rewriting is Windows-only; modification/access times are set on all platforms

## License

MIT. See [LICENSE](LICENSE).
