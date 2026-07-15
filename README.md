# Exif Killer

Offline metadata sanitizer and verification tool for DFIR, OSINT, and OPSEC.

![Exif Killer Logo](logo.png)

Exif Killer is a Windows-first alpha project that focuses on trustworthy metadata cleanup instead of vague "trust me" claims. The app stays offline, uses a native Python backend, and always pairs cleaning with verification and structured reporting.

## Threat Model

Exif Killer is designed for scenarios where metadata can expose operator identity, source application details, location hints, or document history. The tool is especially useful when handling:

- images with author, software, or GPS metadata
- camera RAW files, whose MakerNote typically carries a body serial number and shutter count
- video and audio whose containers record device, location, and encoder fingerprints
- PDFs with DocInfo, XMP, document IDs, or embedded content
- Office and OpenDocument files with author fields, comment identities, revision traces, or preview thumbnails
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
- Camera RAW: `cr2`, `nef`, `nrw`, `arw`, `sr2`, `srf`, `dng`, `orf`, `rw2`,
  `pef`, `srw`, `3fr`, `mef`, `mos`, `erf`, `dcr`, `kdc`
- Documents: `pdf`, `docx`, `xlsx`, `pptx`
- OpenDocument: `odt`, `ods`, `odp`, `odg`, `odf`, `ott`, `ots`, `otp`

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
- **Camera RAW** (TIFF-based) — EXIF, GPS, XMP, IPTC, MakerNote (which hides
  serial numbers and shutter counts), and DNG identity tags are removed by
  compacting the IFD entry array in place. Sensor data is referenced by absolute
  offsets, so nothing is allowed to move: the file size never changes and the
  raw pixels are bit-for-bit identical. See the RAW note below for the
  Make/Model tradeoff.
- **OpenDocument** — `meta.xml` is replaced with an empty one; annotation and
  tracked-change identities, author fields, thumbnails, and `settings.xml` are
  removed; embedded `Pictures/` are stripped losslessly; and the manifest is
  kept in sync. ZIP entry timestamps are reset, since they otherwise record when
  the document was last edited.

## Cleaning Profiles

- `safe`: removes direct identifying and tracking metadata while prioritizing file compatibility
- `aggressive`: expands cleanup to thumbnails, revision markers, embedded previews, Windows post-processing, and other higher-risk traces

`safe` is the default profile. `aggressive` is recommended when compatibility tradeoffs are acceptable.

### The RAW Make/Model tradeoff

RAW converters identify the sensor from the `Make`/`Model` tags to pick a
demosaic and colour profile, so removing them can leave a file some converters
refuse to open. `safe` therefore keeps them — and reports them as remaining
`identifying` findings rather than pretending the file is clean. `aggressive`
removes them, along with `UniqueCameraModel`, and strips the EXIF out of
embedded preview JPEGs.

Preview stripping is deliberately conservative: lossless-JPEG-compressed sensor
data begins with the same SOI marker as a preview, and is distinguished only by
its photometric interpretation. Anything that could be sensor data is left
alone.

## Verification Model

Cleaning is always paired with a re-scan, but a tool checking its own work with
its own parser shares its own blind spots. The test suite therefore cross-checks
against third-party implementations that must independently agree: Pillow for
TIFF/RAW (the cleaned file must still decode, with identical pixels and the
metadata tags gone) and [mutagen](https://mutagen.readthedocs.io/) for Ogg (it
must see the tags before cleaning and still parse a valid stream afterwards).
mutagen is a dev-only extra — the tool itself never imports it, and those tests
skip when it is absent.

The same checks are exposed as `exif-killer selftest`, so the engines can be
proven against real files rather than only against fixtures someone wrote by
hand. See [Testing Against Your Own Files](#testing-against-your-own-files).

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

### Testing Against Your Own Files

Verification answers "is the metadata gone?". `selftest` answers the harder
question: **"did the tool break my file?"**

```bash
exif-killer selftest --wanted              # what real files are worth collecting
exif-killer selftest ~/samples --profile aggressive
exif-killer selftest ~/samples --format json --report selftest.json
```

Every file is cleaned into a temporary directory — **your originals are never
modified** — and then checked with format-aware assertions: the container must
still parse, and the irreplaceable bytes (the JPEG scan, `mdat`, the Matroska
clusters, the Ogg audio pages, the RAW sensor strips) must be identical. For
RAW and Matroska, the file size must not have changed at all.

Each file gets one of three verdicts:

- `pass` — cleaned, intact, nothing blocking left.
- `residual` — intact, but metadata the profile deliberately keeps is still
  there (safe leaves RAW `Make`/`Model`, ODF annotations). Not a failure.
- `damaged` — an integrity check failed. The tool corrupted the file, and no
  amount of metadata removal excuses that.

The report also lists which supported formats have no sample yet, so it tells
you what to go and find next.

Exit codes: `0` all passed, `1` something was damaged, `2` residual metadata
remains, `3` no supported files found.

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
- RAW support covers TIFF-based formats only. Canon CR3 (ISOBMFF-based), Fuji
  RAF, and Sigma X3F are not TIFF containers and are not handled. BigTIFF is
  refused rather than guessed at
- RAW and Matroska cleaning are byte-exact by design, so those files never
  shrink: metadata is overwritten in place rather than cut out, because their
  internal offset tables would otherwise break
- Ogg FLAC (FLAC inside an Ogg container) is detected but not stripped; native
  `.flac` files are fully handled
- Recursive archive inspection is not in the alpha scope
- Creation-time rewriting is Windows-only; modification/access times are set on all platforms
- The container engines are tested against hand-built fixtures and cross-checked
  with third-party parsers (Pillow for TIFF/RAW, mutagen for Ogg). Run
  `exif-killer selftest` against your own real files to check the formats you
  actually care about; `selftest --wanted` lists what is worth collecting

## License

MIT. See [LICENSE](LICENSE).
