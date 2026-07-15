# Exif Killer

Offline metadata sanitizer and verification tool for DFIR, OSINT, and OPSEC.

[English](#english) · [Türkçe](#türkçe)

![Exif Killer](logo.png)

---

## English

### Overview

Exif Killer removes metadata from files and then proves what it removed. It runs
entirely offline, has no telemetry, and depends on no external program: every
format is parsed by a pure-Python engine written for this project. There is no
ExifTool, no ffmpeg, no ImageMagick, and nothing to install beyond the Python
packages listed below.

The project's guiding principle is that a metadata cleaner is only worth using
if it is honest. Cleaning is always paired with a re-scan, findings are reported
in a fixed taxonomy, and anything the tool deliberately leaves behind is named
rather than quietly excused.

Status: `v0.1.0-alpha`. Windows is the primary release target.

### Threat model

Exif Killer is for cases where a file's metadata can expose more than its
content: operator identity, device fingerprints, location, or document history.
It is useful for:

- photographs carrying GPS coordinates, camera serial numbers, or an owner name
- camera RAW files, whose MakerNote typically holds a body serial number and a
  shutter count
- video and audio whose containers record device, location, and encoder strings
- PDFs with DocInfo, XMP, document IDs, or embedded content
- Office and OpenDocument files with author fields, comment identities, revision
  traces, or preview thumbnails
- Windows files carrying download-zone artifacts or filesystem timeline hints

Exif Killer does not claim to erase every forensic artifact in every format. The
goal is narrower and more defensible: sanitize what it knows, verify the result,
and report what remains.

### Design principle: nothing moves

Several container formats point at their payload with absolute byte offsets.
In a camera RAW, `StripOffsets` names where the sensor data begins. In Matroska,
`SeekHead` and `Cues` index the file by position. In an MP4, `stco` maps samples
to offsets. Deleting metadata from these formats shifts every following byte and
silently breaks the file, which for an irreplaceable RAW is unacceptable.

Exif Killer therefore never moves a byte in those formats. Metadata is
neutralised in place, using whatever the format itself provides for the purpose:

| Format | Technique | Result |
| --- | --- | --- |
| TIFF / camera RAW | Compact the IFD entry array in place; the freed slots become unreferenced padding | File size unchanged |
| Canon CRW (CIFF) | Compact the directory in place; the block's trailing pointer still names its start | File size unchanged |
| Matroska (MKV/WebM) | Overwrite elements with an EBML `Void` of identical size | File size unchanged |
| MP4 / MOV / M4A | Rename metadata boxes to `free` and zero their payload | File size unchanged |
| HEIC / HEIF / AVIF | Zero the EXIF/XMP item payloads inside `mdat` surgically | File size unchanged |

Formats without an offset index (JPEG, PNG, Ogg, RIFF, ZIP-based documents) are
genuinely rewritten, and there the payload is copied through byte-for-byte
instead.

### Supported formats

58 extensions, all handled natively with no re-encoding.

- **Images**: `jpg`, `jpeg`, `jpe`, `png`, `webp`, `bmp`, `tiff`, `tif`, `gif`, `svg`
- **Modern images**: `heic`, `heif`, `avif`
- **Camera RAW**: `crw`, `cr2`, `nef`, `nrw`, `arw`, `sr2`, `srf`, `dng`, `orf`,
  `rw2`, `pef`, `srw`, `3fr`, `mef`, `mos`, `erf`, `dcr`, `kdc`
- **Video**: `mp4`, `mov`, `m4v`, `avi`, `mkv`, `webm`, `ogv`
- **Audio**: `mp3`, `flac`, `m4a`, `wav`, `ogg`, `oga`, `opus`, `spx`
- **Documents**: `pdf`, `docx`, `xlsx`, `pptx`
- **OpenDocument**: `odt`, `ods`, `odp`, `odg`, `odf`, `ott`, `ots`, `otp`

How each family is cleaned:

- **JPEG / PNG / WebP / GIF / SVG** — the segment or chunk structure is rewritten
  and only metadata carriers are dropped, losslessly. Pixels stay byte-identical,
  and data appended after the image's end marker (hidden thumbnails, appended
  payloads) is discarded. BMP and TIFF use a pixel-copy rebuild.
- **Camera RAW (TIFF-based)** — EXIF, GPS, XMP, IPTC, MakerNote, and the DNG
  identity tags (`CameraSerialNumber`, `DNGPrivateData`, `RawDataUniqueID`,
  `OriginalRawFileName`) are removed. See the Make/Model note below.
- **Canon CRW (CIFF)** — `OwnerName` and `SerialNumber`, which a CRW stores in
  plain ASCII, plus the firmware version, timestamp, and file number.
- **MP4 / MOV / M4V / M4A** — the `udta` and `meta` boxes, including the iPhone
  GPS atom (`©xyz`), device, software, and iTunes tags.
- **HEIC / HEIF / AVIF** — the EXIF and XMP item payloads.
- **MKV / WebM** — `Tags`, `Attachments`, `Title`, `DateUTC`, `SegmentUID`,
  `SegmentFilename`, and track names. Index entries pointing at removed elements
  are pruned. The mandatory `MuxingApp` and `WritingApp` strings are zero-filled
  rather than deleted, which EBML explicitly permits.
- **Ogg / Opus / Vorbis / Theora / Speex** — the comment header's vendor string
  and every user tag, including embedded cover art. The header pages are rebuilt:
  lacing tables recomputed, page sequence renumbered, and the Ogg CRC32
  recalculated.
- **MP3** — ID3v2, ID3v1, and APEv2 tags.
- **FLAC** — `VORBIS_COMMENT` and `PICTURE` blocks.
- **WAV / AVI** — `INFO`, `ID3`, and `bext` chunks.
- **PDF** — DocInfo, XMP, PieceInfo, embedded files, JavaScript, and associated
  file references.
- **Office (OOXML)** — `docProps`, comment and revision identities, rsid markers,
  thumbnails, and the EXIF inside embedded images.
- **OpenDocument** — `meta.xml` is replaced with an empty one; annotation and
  tracked-change identities, author fields, thumbnails, and `settings.xml` are
  removed; embedded `Pictures/` are stripped losslessly; and the manifest is kept
  in sync. ZIP entry timestamps are reset, since they otherwise record when the
  document was last edited.

### Installation

Requires Python 3.11 or newer.

```bash
git clone <repository-url>
cd exif_killer

python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS

pip install -e .
```

Runtime dependencies are `Pillow`, `pikepdf`, `customtkinter`, and `tkinterdnd2`.
No external binaries are required or used.

`pikepdf` is a C extension, and on Windows it will not load if the Microsoft
Visual C++ Redistributable (x64) is missing. Exif Killer treats that as a
degraded engine rather than a fatal error: PDF support is disabled, the reason is
reported at startup, and every other format continues to work. One unavailable
family never prevents the application from opening.

### Command-line usage

Four commands: `scan`, `clean`, `verify`, and `selftest`.

```bash
exif-killer --help
exif-killer <command> --help
```

If the entry point is not on your `PATH`, `python -m exif_killer` is equivalent.

#### scan — report what a file discloses

```bash
exif-killer scan photo.jpg
exif-killer scan ~/Pictures --recursive
exif-killer scan report.pdf --format json --report findings.json
```

#### clean — remove metadata and verify the result

```bash
exif-killer clean photo.jpg
exif-killer clean secret.pdf --profile aggressive
exif-killer clean ~/Pictures --recursive --output-dir ~/clean
exif-killer clean photo.jpg --overwrite
```

Cleaned files are written next to the original as `name_Cleaned.ext` unless
`--output-dir` or `--overwrite` is given.

#### verify — compare an original against a cleaned copy

```bash
exif-killer verify original.docx cleaned.docx --format json
```

#### selftest — check the tool against your own files

`verify` answers whether the metadata is gone. `selftest` answers the harder
question: whether the file still works.

```bash
exif-killer selftest --wanted
exif-killer selftest ~/samples --profile aggressive
exif-killer selftest ~/samples --format json --report selftest.json
```

Every file is cleaned into a temporary directory — **originals are never
modified** — and then checked with format-aware assertions: the container must
still parse, and the irreplaceable bytes (the JPEG scan, `mdat`, the Matroska
clusters, the Ogg audio pages, the RAW sensor strips) must be identical. For RAW
and Matroska the file size must not have changed at all.

Each file receives one of three verdicts:

- `pass` — cleaned, intact, nothing blocking left.
- `residual` — intact, but metadata the profile deliberately keeps is still
  present. Not a failure.
- `damaged` — an integrity check failed. The tool corrupted the file, and no
  amount of metadata removal excuses that.

The report also lists which supported formats have no sample yet, so it can say
what is worth finding next. `--wanted` prints that list without running anything.

Keep your sample corpus out of version control; those are exactly the personal
files this tool exists to protect. `exif_test/`, `corpus/`, and `samples/` are
already in `.gitignore`.

### Cleaning profiles

- `safe` (default) — removes direct identifying and tracking metadata while
  prioritising file compatibility.
- `aggressive` — extends cleanup to thumbnails, revision markers, embedded
  previews, colour profiles, Windows post-processing, and data hidden after a
  container's declared end.

#### The RAW Make/Model tradeoff

RAW converters identify the sensor from the `Make` and `Model` tags in order to
choose a demosaic and colour profile. Removing them can leave a file that some
converters refuse to open. `safe` therefore keeps them, and reports them as
remaining `identifying` findings rather than claiming the file is clean.
`aggressive` removes them, along with `UniqueCameraModel`, and strips the EXIF
out of embedded preview JPEGs.

Preview stripping is deliberately conservative. Lossless-JPEG-compressed sensor
data begins with the same start-of-image marker as a preview, and is
distinguished only by its photometric interpretation. Anything that could be
sensor data is left alone.

### Timestamp policy

`clean` can rewrite the cleaned file's filesystem timestamps. Modification and
access times are set on every platform; creation time is additionally set on
Windows through the Win32 API. Filesystem dates are a common OPSEC leak, so the
policy is configurable:

```bash
exif-killer clean photo.jpg --timestamp random
exif-killer clean photo.jpg --timestamp epoch
exif-killer clean photo.jpg --timestamp custom --timestamp-date 2020-05-01T13:00:00
exif-killer clean photo.jpg --timestamp keep
```

- `auto` (default) — follow the profile: `aggressive` resets to epoch, `safe`
  leaves timestamps untouched.
- `keep` — never touch filesystem timestamps.
- `epoch` — reset to `1970-01-01`.
- `random` — generate a plausible random date per file, ordered so that
  created ≤ modified ≤ accessed, so the file does not stand out.
- `custom` — use `--timestamp-date`, which accepts `YYYY-MM-DD` or ISO 8601.

### Desktop interface

```bash
exif-killer-gui
# or: python main.py
```

The GUI is built on the same service layer as the CLI, so both behave
identically. The workflow is:

1. Queue files, or drag and drop folders.
2. Choose a profile (`Safe` or `Aggressive`) and a file-date policy.
3. Run `Scan`.
4. Run `Clean + Verify`.
5. Export JSON or CSV evidence.

The interface is available in English and Turkish, switchable at runtime.

### Verification model

Findings are classified into five categories:

| Category | Meaning | Blocking |
| --- | --- | --- |
| `identifying` | Reveals a person, device, or software fingerprint | Yes |
| `tracking` | Can correlate, trace, or timeline the file | Yes |
| `embedded-content` | Points to embedded or active content | Yes |
| `filesystem` | Filesystem metadata | No |
| `technical` | Needed for compatibility or structure | No |

Verification returns `warning` when any blocking finding remains. Filesystem
leftovers are reported but do not fail verification.

A tool that checks its own work with its own parser shares its own blind spots.
The test suite therefore cross-checks against third-party implementations that
must independently agree: Pillow for TIFF and RAW (the cleaned file must still
decode, with identical pixels and the metadata gone) and
[mutagen](https://mutagen.readthedocs.io/) for Ogg (it must see the tags before
cleaning and still parse a valid stream afterwards). mutagen is a development
extra only; the tool itself never imports it, and those tests skip when it is
absent.

### Exit codes

`scan`, `clean`, and `verify`:

| Code | Meaning |
| --- | --- |
| `0` | Succeeded, no blocking findings remain |
| `1` | Usage error or runtime failure |
| `2` | Completed, but blocking findings remain |
| `3` | No supported files were available |

`selftest`:

| Code | Meaning |
| --- | --- |
| `0` | All files passed |
| `1` | A file was damaged, or could not be processed |
| `2` | Residual metadata remains |
| `3` | No supported files were found |

### Report format

Each JSON report entry includes `tool_version`, `command`, `profile`, `status`,
`backend`, `input_path`, `output_path`, `file_type`, `sha256_before`,
`sha256_after`, `findings`, `removed_fields`, `remaining_findings`, `warnings`,
and `timestamp_utc`. An example lives at
[docs/example_report.json](docs/example_report.json).

### Development

```bash
pip install -e .[dev]

pytest          # 118 tests
mypy
ruff check .
```

The codebase has two layers. `cleaners/` holds the format engines and has no
knowledge of the CLI or GUI. `exif_killer/` holds orchestration: the service,
the risk taxonomy, reporting, and the two frontends.

### Security posture

- Offline-first by default
- No telemetry, no cloud scanning, no auto-update agent
- No external binaries in the runtime path
- Structured JSON and CSV evidence for audit trails
- Windows portable build target for the alpha release

### Known limitations

- Windows is the primary release target for `v0.1.0-alpha`.
- Canon CR3 (which is ISOBMFF-based, not TIFF), Fuji RAF, and Sigma X3F are not
  supported. BigTIFF is refused rather than guessed at.
- The Canon CRW engine is built to the CIFF specification and covered by
  fixtures, but has not yet been exercised against a real camera file.
- Ogg FLAC (FLAC inside an Ogg container) is detected but not stripped; native
  `.flac` files are fully handled.
- RAW, CRW, and Matroska cleaning are byte-exact by design, so those files never
  shrink: metadata is overwritten in place rather than cut out, because their
  internal offset tables would otherwise break.
- The PDF specification effectively requires a trailer `/ID`, and pikepdf writes
  one back on every save. Ours is generated deterministically from the file's own
  content, so it carries no machine or time entropy, but it is still reported as
  a finding rather than quietly excused.
- A RAW's embedded preview is kept: it renders the same photo the file already
  contains. Its own EXIF is stripped under `aggressive`.
- Recursive archive inspection is not in the alpha scope.
- Creation-time rewriting is Windows-only; modification and access times are set
  on all platforms.
- The engines are tested against hand-built fixtures and cross-checked with
  third-party parsers. Run `exif-killer selftest` against your own files to check
  the formats you actually care about.

### License

MIT. See [LICENSE](LICENSE).

---

## Türkçe

### Genel bakış

Exif Killer dosyalardan metadata siler ve ardından ne sildiğini kanıtlar.
Tamamen çevrimdışı çalışır, hiçbir veri toplamaz ve hiçbir dış programa bağımlı
değildir: her format, bu proje için yazılmış saf Python motorlarıyla işlenir.
ExifTool yok, ffmpeg yok, ImageMagick yok; aşağıdaki Python paketleri dışında
kurulacak bir şey yok.

Projenin temel ilkesi şudur: bir metadata temizleyici ancak dürüstse kullanmaya
değer. Temizlik her zaman yeniden taramayla eşleştirilir, bulgular sabit bir
sınıflandırmayla raporlanır ve aracın bilerek bıraktığı her şey sessizce
geçiştirilmek yerine açıkça adlandırılır.

Durum: `v0.1.0-alpha`. Birincil hedef platform Windows'tur.

### Tehdit modeli

Exif Killer, bir dosyanın metadata'sının içeriğinden daha fazlasını ifşa
edebildiği durumlar için tasarlanmıştır: operatör kimliği, cihaz parmak izi,
konum veya belge geçmişi. Şu durumlarda işe yarar:

- GPS koordinatı, kamera seri numarası veya sahip adı taşıyan fotoğraflar
- MakerNote'unda tipik olarak gövde seri numarası ve deklanşör sayacı bulunan
  kamera RAW dosyaları
- Cihaz, konum ve encoder bilgisi kaydeden video ve ses konteynerleri
- DocInfo, XMP, belge kimliği veya gömülü içerik taşıyan PDF'ler
- Yazar alanları, yorum kimlikleri, revizyon izleri veya önizleme küçük resmi
  içeren Office ve OpenDocument dosyaları
- İndirme bölgesi izleri veya dosya sistemi zaman çizelgesi ipuçları taşıyan
  Windows dosyaları

Exif Killer, her formattaki her adli izi sildiğini iddia etmez. Hedef daha dar
ve daha savunulabilirdir: bildiğini temizle, sonucu doğrula ve geriye ne
kaldığını raporla.

### Tasarım ilkesi: hiçbir byte yer değiştirmez

Bazı konteyner formatları içeriklerine mutlak byte offset'leriyle işaret eder.
Kamera RAW'ında `StripOffsets`, sensör verisinin nerede başladığını söyler.
Matroska'da `SeekHead` ve `Cues` dosyayı konuma göre indeksler. MP4'te `stco`
örnekleri offset'lere eşler. Bu formatlardan metadata silmek, sonraki her byte'ı
kaydırır ve dosyayı sessizce bozar; yeri doldurulamaz bir RAW için bu kabul
edilemez.

Bu yüzden Exif Killer bu formatlarda hiçbir byte'ı yerinden oynatmaz. Metadata,
formatın kendi sunduğu araçlarla yerinde etkisiz hale getirilir:

| Format | Teknik | Sonuç |
| --- | --- | --- |
| TIFF / kamera RAW | IFD girdi dizisi yerinde sıkıştırılır; boşalan yuvalar referanssız dolguya dönüşür | Dosya boyutu değişmez |
| Canon CRW (CIFF) | Dizin yerinde sıkıştırılır; bloğun sondaki işaretçisi hâlâ başlangıcı gösterir | Dosya boyutu değişmez |
| Matroska (MKV/WebM) | Elemanlar aynı boyutta bir EBML `Void` ile üzerine yazılır | Dosya boyutu değişmez |
| MP4 / MOV / M4A | Metadata kutuları `free` olarak yeniden adlandırılıp içi sıfırlanır | Dosya boyutu değişmez |
| HEIC / HEIF / AVIF | `mdat` içindeki EXIF/XMP item verileri cerrahi olarak sıfırlanır | Dosya boyutu değişmez |

Offset indeksi olmayan formatlar (JPEG, PNG, Ogg, RIFF, ZIP tabanlı belgeler)
gerçekten yeniden yazılır; orada da veri byte byte kopyalanır.

### Desteklenen formatlar

58 uzantı, hepsi native olarak ve yeniden kodlama yapılmadan işlenir.

- **Görseller**: `jpg`, `jpeg`, `jpe`, `png`, `webp`, `bmp`, `tiff`, `tif`, `gif`, `svg`
- **Modern görseller**: `heic`, `heif`, `avif`
- **Kamera RAW**: `crw`, `cr2`, `nef`, `nrw`, `arw`, `sr2`, `srf`, `dng`, `orf`,
  `rw2`, `pef`, `srw`, `3fr`, `mef`, `mos`, `erf`, `dcr`, `kdc`
- **Video**: `mp4`, `mov`, `m4v`, `avi`, `mkv`, `webm`, `ogv`
- **Ses**: `mp3`, `flac`, `m4a`, `wav`, `ogg`, `oga`, `opus`, `spx`
- **Belgeler**: `pdf`, `docx`, `xlsx`, `pptx`
- **OpenDocument**: `odt`, `ods`, `odp`, `odg`, `odf`, `ott`, `ots`, `otp`

Her format ailesinin temizlenme biçimi:

- **JPEG / PNG / WebP / GIF / SVG** — segment veya chunk yapısı yeniden yazılır
  ve yalnızca metadata taşıyıcıları kayıpsız biçimde atılır. Pikseller bit bit
  aynı kalır; görüntünün bitiş işaretinden sonra eklenmiş veriler (gizli küçük
  resimler, eklenmiş yükler) atılır. BMP ve TIFF piksel kopyalama ile yeniden
  oluşturulur.
- **Kamera RAW (TIFF tabanlı)** — EXIF, GPS, XMP, IPTC, MakerNote ve DNG kimlik
  etiketleri (`CameraSerialNumber`, `DNGPrivateData`, `RawDataUniqueID`,
  `OriginalRawFileName`) silinir. Make/Model notuna aşağıdan bakınız.
- **Canon CRW (CIFF)** — CRW'nin düz ASCII olarak sakladığı `OwnerName` ve
  `SerialNumber`, ayrıca firmware sürümü, zaman damgası ve dosya numarası.
- **MP4 / MOV / M4V / M4A** — `udta` ve `meta` kutuları; iPhone GPS atomu
  (`©xyz`), cihaz, yazılım ve iTunes etiketleri dahil.
- **HEIC / HEIF / AVIF** — EXIF ve XMP item verileri.
- **MKV / WebM** — `Tags`, `Attachments`, `Title`, `DateUTC`, `SegmentUID`,
  `SegmentFilename` ve parça adları. Silinen elemanlara işaret eden indeks
  girdileri budanır. Zorunlu `MuxingApp` ve `WritingApp` dizeleri silinmek yerine
  sıfırla doldurulur; EBML buna açıkça izin verir.
- **Ogg / Opus / Vorbis / Theora / Speex** — comment header'ındaki vendor dizesi
  ve gömülü kapak resmi dahil tüm kullanıcı etiketleri. Header sayfaları yeniden
  kurulur: lacing tabloları yeniden hesaplanır, sayfa sırası yeniden numaralanır
  ve Ogg CRC32 yeniden hesaplanır.
- **MP3** — ID3v2, ID3v1 ve APEv2 etiketleri.
- **FLAC** — `VORBIS_COMMENT` ve `PICTURE` blokları.
- **WAV / AVI** — `INFO`, `ID3` ve `bext` chunk'ları.
- **PDF** — DocInfo, XMP, PieceInfo, gömülü dosyalar, JavaScript ve ilişkili
  dosya referansları.
- **Office (OOXML)** — `docProps`, yorum ve revizyon kimlikleri, rsid işaretleri,
  küçük resimler ve gömülü görsellerin içindeki EXIF.
- **OpenDocument** — `meta.xml` boş bir dosyayla değiştirilir; açıklama ve
  değişiklik izleme kimlikleri, yazar alanları, küçük resimler ve `settings.xml`
  silinir; gömülü `Pictures/` kayıpsız temizlenir ve manifest senkron tutulur.
  ZIP girdi zaman damgaları sıfırlanır; aksi halde belgenin en son ne zaman
  düzenlendiğini kaydederler.

### Kurulum

Python 3.11 veya üzeri gerekir.

```bash
git clone <depo-adresi>
cd exif_killer

python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS

pip install -e .
```

Çalışma zamanı bağımlılıkları: `Pillow`, `pikepdf`, `customtkinter`,
`tkinterdnd2`. Hiçbir dış çalıştırılabilir dosya gerekmez ve kullanılmaz.

`pikepdf` bir C eklentisidir ve Windows'ta Microsoft Visual C++ Redistributable
(x64) eksikse yüklenmez. Exif Killer bunu ölümcül bir hata olarak değil, devre
dışı kalmış bir motor olarak ele alır: PDF desteği kapanır, sebebi açılışta
raporlanır ve diğer tüm formatlar çalışmaya devam eder. Kullanılamayan tek bir
format ailesi, uygulamanın açılmasını asla engellemez.

### Komut satırı kullanımı

Dört komut: `scan`, `clean`, `verify` ve `selftest`.

```bash
exif-killer --help
exif-killer <komut> --help
```

Giriş noktası `PATH`'inizde değilse `python -m exif_killer` eşdeğerdir.

#### scan — bir dosyanın neyi ifşa ettiğini raporlar

```bash
exif-killer scan foto.jpg
exif-killer scan ~/Resimler --recursive
exif-killer scan rapor.pdf --format json --report bulgular.json
```

#### clean — metadata siler ve sonucu doğrular

```bash
exif-killer clean foto.jpg
exif-killer clean gizli.pdf --profile aggressive
exif-killer clean ~/Resimler --recursive --output-dir ~/temiz
exif-killer clean foto.jpg --overwrite
```

Temizlenen dosyalar, `--output-dir` veya `--overwrite` verilmedikçe orijinalin
yanına `ad_Cleaned.uzanti` olarak yazılır.

#### verify — orijinali temizlenmiş kopyayla karşılaştırır

```bash
exif-killer verify orijinal.docx temiz.docx --format json
```

#### selftest — aracı kendi dosyalarınızla sınar

`verify`, metadata'nın gidip gitmediğini söyler. `selftest` daha zor soruyu
yanıtlar: dosya hâlâ çalışıyor mu?

```bash
exif-killer selftest --wanted
exif-killer selftest ~/ornekler --profile aggressive
exif-killer selftest ~/ornekler --format json --report selftest.json
```

Her dosya geçici bir dizine temizlenir — **orijinallere asla dokunulmaz** — ve
ardından formata özgü doğrulamalarla sınanır: konteyner hâlâ ayrıştırılabilmeli
ve yeri doldurulamaz byte'lar (JPEG'in taranmış verisi, `mdat`, Matroska
cluster'ları, Ogg ses sayfaları, RAW sensör şeritleri) birebir aynı olmalıdır.
RAW ve Matroska'da dosya boyutu hiç değişmemiş olmalıdır.

Her dosya üç sonuçtan birini alır:

- `pass` — temizlendi, sağlam, engelleyici bir şey kalmadı.
- `residual` — sağlam, ancak profilin bilerek koruduğu metadata hâlâ duruyor.
  Bu bir başarısızlık değildir.
- `damaged` — bir bütünlük kontrolü başarısız oldu. Araç dosyayı bozmuştur ve
  hiçbir metadata temizliği bunu mazur göstermez.

Rapor ayrıca hangi desteklenen formatların henüz örneği olmadığını listeler;
böylece sıradaki neyi bulmanız gerektiğini söyler. `--wanted` bu listeyi hiçbir
şey çalıştırmadan yazdırır.

Örnek dosya koleksiyonunuzu sürüm kontrolünden uzak tutun; onlar tam da bu
aracın korumak için var olduğu kişisel dosyalardır. `exif_test/`, `corpus/` ve
`samples/` zaten `.gitignore` içindedir.

### Temizlik profilleri

- `safe` (varsayılan) — dosya uyumluluğunu önceleyerek doğrudan kimlik
  belirleyici ve izleme amaçlı metadata'yı siler.
- `aggressive` — temizliği küçük resimlere, revizyon işaretlerine, gömülü
  önizlemelere, renk profillerine, Windows sonrası işlemlerine ve bir
  konteynerin beyan ettiği sonun ardına gizlenmiş verilere genişletir.

#### RAW'da Make/Model dengesi

RAW dönüştürücüler, demosaic ve renk profili seçmek için sensörü `Make` ve
`Model` etiketlerinden tanır. Bunları silmek, bazı dönüştürücülerin açmayı
reddedeceği bir dosya bırakabilir. Bu nedenle `safe` onları korur ve dosyanın
temiz olduğunu iddia etmek yerine `identifying` bulgusu olarak raporlar.
`aggressive` ise onları ve `UniqueCameraModel`'i siler, ayrıca gömülü önizleme
JPEG'lerinin EXIF'ini temizler.

Önizleme temizliği bilinçli olarak temkinlidir. Kayıpsız JPEG ile sıkıştırılmış
sensör verisi de bir önizleme ile aynı başlangıç işaretiyle başlar ve yalnızca
photometric yorumuyla ayrılır. Sensör verisi olma ihtimali olan hiçbir şeye
dokunulmaz.

### Tarih politikası

`clean`, temizlenen dosyanın dosya sistemi tarihlerini yeniden yazabilir.
Değiştirme ve erişim zamanları her platformda ayarlanır; oluşturma zamanı
Windows'ta ayrıca Win32 API üzerinden ayarlanır. Dosya sistemi tarihleri yaygın
bir OPSEC sızıntısıdır, bu yüzden politika yapılandırılabilir:

```bash
exif-killer clean foto.jpg --timestamp random
exif-killer clean foto.jpg --timestamp epoch
exif-killer clean foto.jpg --timestamp custom --timestamp-date 2020-05-01T13:00:00
exif-killer clean foto.jpg --timestamp keep
```

- `auto` (varsayılan) — profili izler: `aggressive` epoch'a sıfırlar, `safe`
  tarihlere dokunmaz.
- `keep` — dosya sistemi tarihlerine hiç dokunmaz.
- `epoch` — `1970-01-01`'e sıfırlar.
- `random` — dosya başına makul bir rastgele tarih üretir; oluşturma ≤ değiştirme
  ≤ erişim sırası korunur, böylece dosya sırıtmaz.
- `custom` — `--timestamp-date` kullanır; `YYYY-AA-GG` veya ISO 8601 kabul eder.

### Masaüstü arayüzü

```bash
exif-killer-gui
# veya: python main.py
```

GUI, CLI ile aynı servis katmanı üzerine kuruludur; ikisi aynı şekilde davranır.
İş akışı:

1. Dosyaları kuyruğa alın veya klasörleri sürükleyip bırakın.
2. Bir profil (`Safe` veya `Aggressive`) ve bir dosya tarihi politikası seçin.
3. `Scan` çalıştırın.
4. `Clean + Verify` çalıştırın.
5. JSON veya CSV kanıt raporu dışa aktarın.

Arayüz İngilizce ve Türkçe olarak mevcuttur ve çalışma anında değiştirilebilir.

### Doğrulama modeli

Bulgular beş kategoriye ayrılır:

| Kategori | Anlamı | Engelleyici |
| --- | --- | --- |
| `identifying` | Bir kişiyi, cihazı veya yazılım parmak izini açığa çıkarır | Evet |
| `tracking` | Dosyayı ilişkilendirebilir, izleyebilir veya zaman çizelgesine oturtabilir | Evet |
| `embedded-content` | Gömülü veya etkin içeriğe işaret eder | Evet |
| `filesystem` | Dosya sistemi metadata'sı | Hayır |
| `technical` | Uyumluluk veya yapı için gerekli | Hayır |

Engelleyici bir bulgu kaldığında doğrulama `warning` döner. Dosya sistemi
kalıntıları raporlanır ancak doğrulamayı başarısız kılmaz.

Kendi işini kendi ayrıştırıcısıyla denetleyen bir araç, kendi kör noktalarını
paylaşır. Bu nedenle test paketi, bağımsız olarak hemfikir olması gereken üçüncü
taraf uygulamalarla çapraz doğrulama yapar: TIFF ve RAW için Pillow (temizlenmiş
dosya hâlâ çözümlenebilmeli, pikseller aynı ve metadata gitmiş olmalı) ve Ogg
için [mutagen](https://mutagen.readthedocs.io/) (temizlikten önce etiketleri
görmeli, sonrasında geçerli bir akış ayrıştırabilmeli). mutagen yalnızca bir
geliştirme ekidir; araç onu asla import etmez ve o yokken bu testler atlanır.

### Çıkış kodları

`scan`, `clean` ve `verify`:

| Kod | Anlamı |
| --- | --- |
| `0` | Başarılı, engelleyici bulgu kalmadı |
| `1` | Kullanım hatası veya çalışma zamanı hatası |
| `2` | Tamamlandı, ancak engelleyici bulgular kaldı |
| `3` | Desteklenen dosya bulunamadı |

`selftest`:

| Kod | Anlamı |
| --- | --- |
| `0` | Tüm dosyalar geçti |
| `1` | Bir dosya bozuldu veya işlenemedi |
| `2` | Artakalan metadata var |
| `3` | Desteklenen dosya bulunamadı |

### Rapor biçimi

Her JSON rapor girdisi şunları içerir: `tool_version`, `command`, `profile`,
`status`, `backend`, `input_path`, `output_path`, `file_type`, `sha256_before`,
`sha256_after`, `findings`, `removed_fields`, `remaining_findings`, `warnings`
ve `timestamp_utc`. Örnek: [docs/example_report.json](docs/example_report.json).

### Geliştirme

```bash
pip install -e .[dev]

pytest          # 118 test
mypy
ruff check .
```

Kod tabanı iki katmandan oluşur. `cleaners/` format motorlarını barındırır ve
CLI ile GUI'den habersizdir. `exif_killer/` orkestrasyonu barındırır: servis,
risk sınıflandırması, raporlama ve iki arayüz.

### Güvenlik duruşu

- Varsayılan olarak çevrimdışı
- Telemetri yok, bulut taraması yok, otomatik güncelleme ajanı yok
- Çalışma zamanında hiçbir dış çalıştırılabilir dosya yok
- Denetim izi için yapılandırılmış JSON ve CSV kanıtı
- Alpha sürümü için Windows taşınabilir derleme hedefi

### Bilinen sınırlamalar

- `v0.1.0-alpha` için birincil hedef platform Windows'tur.
- Canon CR3 (TIFF değil, ISOBMFF tabanlıdır), Fuji RAF ve Sigma X3F
  desteklenmez. BigTIFF tahmin edilmek yerine reddedilir.
- Canon CRW motoru CIFF spesifikasyonuna göre yazılmış ve fixture'larla test
  edilmiştir, ancak henüz gerçek bir kamera dosyasıyla sınanmamıştır.
- Ogg FLAC (Ogg konteyneri içindeki FLAC) tespit edilir ancak temizlenmez;
  native `.flac` dosyaları tam olarak işlenir.
- RAW, CRW ve Matroska temizliği tasarımı gereği byte hassasiyetindedir, bu
  yüzden bu dosyalar hiç küçülmez: metadata kesilip atılmak yerine yerinde
  üzerine yazılır, çünkü aksi halde iç offset tabloları bozulurdu.
- PDF spesifikasyonu fiilen bir trailer `/ID` gerektirir ve pikepdf her kayıtta
  yeniden bir tane yazar. Bizimki dosyanın kendi içeriğinden deterministik olarak
  üretilir, yani makine veya zaman entropisi taşımaz; yine de sessizce
  geçiştirilmek yerine bir bulgu olarak raporlanır.
- Bir RAW'ın gömülü önizlemesi korunur: dosyanın zaten içerdiği fotoğrafın
  aynısını gösterir. Kendi EXIF'i `aggressive` altında temizlenir.
- Özyinelemeli arşiv incelemesi alpha kapsamında değildir.
- Oluşturma zamanı yeniden yazımı yalnızca Windows'tadır; değiştirme ve erişim
  zamanları tüm platformlarda ayarlanır.
- Motorlar elle kurulmuş fixture'larla test edilir ve üçüncü taraf
  ayrıştırıcılarla çapraz doğrulanır. Gerçekten önemsediğiniz formatları sınamak
  için kendi dosyalarınız üzerinde `exif-killer selftest` çalıştırın.

### Lisans

MIT. Bkz. [LICENSE](LICENSE).
