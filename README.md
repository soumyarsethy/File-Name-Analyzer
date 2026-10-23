# FileID — Magic-Byte File Type Identifier & Spoofing Analyzer

> **Current Version:** `v1.0.0`  
> **Last Updated:** `2026-10-23`  
> **Execution Mode:** `100% Client-Side (Browser-Local, Zero Server Uploads)`

---

## 📌 What This App Is For (Overview & Purpose)

**FileID (File Name & Signature Analyzer)** is a privacy-first, client-side web application that identifies the **true format** of any file by inspecting its internal binary **magic numbers (file signatures)**, **container structures**, and **content heuristics** — rather than trusting the filename extension.

Operating systems and users often rely on file extensions (like `.pdf`, `.jpg`, or `.docx`) to know what a file is. However:
1. **Malware & Extension Spoofing:** Attackers frequently disguise dangerous executables (such as Windows `.exe` or Linux `ELF` binaries) with harmless extensions like `urgent-invoice.pdf` or double extensions like `receipt.pdf.exe`.
2. **Corrupted or Missing Extensions:** Downloaded or recovered files (`.dat`, `.bin`, or extensionless files) often lose their original extension, making it unclear which program can open them.
3. **Ambiguous Container Formats:** Modern formats like `.docx`, `.xlsx`, `.pptx`, `.apk`, `.jar`, and `.epub` all share the exact same outer `ZIP` magic header (`50 4B 03 04`). Simple magic-byte checkers misidentify all of them as plain `.zip` archives.

**FileID solves all three problems** directly in the browser (inspired by the Unix `file` command / `libmagic` and Toolsley File Identifier), without ever uploading a single byte of your files to any external server.

---

## ⚙️ How It Works (Architecture & Workflow)

FileID runs a **6-stage local inspection pipeline** entirely in browser memory using the HTML5 `File` / `Blob.slice()` API, `ArrayBuffer`, and `Web Crypto API`:

```
[User Drops or Selects File(s)]
        │
        ▼
1. Non-Blocking Header Slice
   └── Reads first 128 KB (131,072 bytes) into a Uint8Array for instant analysis
   └── Reads up to 25 MB into Web Crypto API for full-file SHA-256 hashing
        │
        ▼
2. Primary Magic-Byte & Container Detection (detectFileSignature)
   ├── Matches exact binary signatures at offset 0x00 or format-specific offsets
   ├── ZIP Container Dissector (inspectZipContainer) -> DOCX, XLSX, PPTX, APK, JAR, EPUB, ODT, WHL, IPA
   ├── OLE2 Compound Dissector (inspectOLE2Container) -> DOC, XLS, PPT, MSG, MSI
   ├── Executable Header Parser -> Windows PE/MZ (CPU arch, DLL/EXE, .NET CLR, subsystem), Linux ELF, macOS Mach-O, WASM
   ├── Media & Image Frame Parser -> PNG/APNG, JPEG (SOF0/SOF2 dimensions), GIF, RIFF (WebP/WAV/AVI), ISO-BMFF (MP4/MOV/HEIC/AVIF)
   └── Text & Source Code Heuristics -> BOM check, UTF-8/ASCII validation, Shebang (#!), HTML/SVG/XML/JSON/CSV/JS/Py/C
        │
        ▼
3. Extension Spoofing & Mismatch Verification (evaluateExtensionMatch)
   ├── Compares actual filename extension against expected format extensions
   ├── Detects Double-Extension Masquerading (e.g., .pdf.exe)
   └── Flags Executables disguised under non-executable extensions as High-Risk Danger
        │
        ▼
4. Cryptographic & Statistical Metrics
   ├── Computes Shannon Entropy (0.000 – 8.000 bits/byte) to detect encryption or packed streams
   └── Computes SHA-256 digest via window.crypto.subtle
        │
        ▼
5. Interactive Forensic Report Rendering
   ├── Unix `file` / libmagic terminal summary with 1-click copy
   ├── Color-coded Extension Verification Alert (Match / Warning / Spoofing Danger)
   ├── Deep Header & Container Metadata bullets
   └── 64-byte Raw Hex + ASCII Inspector with highlighted magic signature bytes
```

---

## ✨ Key Features

- **🔒 100% Local & Private:** Files never leave your device. Even multi-gigabyte files are analyzed instantaneously because FileID slices only the first `128 KB` for structural dissection.
- **🕵️ Extension Spoofing & Malware Masquerade Detection:**
  - **Verified Match (Green):** Filename extension matches the binary signature.
  - **Mismatch / Missing Extension (Amber Warning):** File is renamed (e.g., `.dat`) or lacks an extension; suggests the proper extension.
  - **Spoofing Alert (Red Danger):** Executable binary (`PE/EXE`, `DLL`, `ELF`, `Mach-O`, `Script`, `Java/WASM`) disguised as a document/media file or using a deceptive double extension (`.pdf.exe`).
- **📦 Deep Container Dissection:** Goes beyond the first 4 bytes to inspect internal directory records and headers for `ZIP`, `OOXML`, `OLE2`, `RIFF`, `ISO-BMFF (ftyp)`, `PE`, and `ELF` files.
- **🧮 Shannon Entropy Calculator:** Measures byte randomness from `0.000` to `8.000 bits/byte` to distinguish plain text, structured binary headers, and compressed/encrypted/packed payloads (`> 7.4 bits/byte`).
- **🔑 Built-in SHA-256 Hashing:** Automatically generates the cryptographic SHA-256 fingerprint using the browser's native `SubtleCrypto` engine.
- **🔬 Interactive 64-Byte Hex & ASCII Inspector:** Displays the first 64 bytes (`0x0000`–`0x003F`) side-by-side in hexadecimal and printable ASCII, visually highlighting the exact byte range that triggered the format match.
- **🧪 Instant Built-in Demo Samples:** Includes 5 in-memory synthetic binary samples (`Genuine PNG`, `Spoofed EXE-as-PDF`, `DOCX in ZIP`, `Renamed PDF`, `Linux ELF 64-bit`) so users can test the analyzer with one click.
- **🔎 Searchable Signature Reference Table:** Built-in quick filter table documenting common hex signatures, ASCII equivalents, offsets, and deep dissection rules.

---

## 📂 Supported File Formats & Deep Dissections

| Category | Supported Formats | Deep Structural Details Extracted |
| :--- | :--- | :--- |
| **ZIP-Based Containers** | `ZIP`, `DOCX`, `XLSX`, `PPTX`, `VSDX`, `EPUB`, `ODT`, `ODS`, `ODP`, `APK`, `JAR`, `IPA`, `WHL` | Compression method (`Deflate`, `Zstd`, `LZMA`, etc.), encryption flag, extractor version, internal package paths (`[Content_Types].xml`, `word/`, `xl/`, `ppt/`, `AndroidManifest.xml`, `META-INF/`) |
| **Microsoft OLE2 (CFBF)** | `DOC`, `XLS`, `PPT`, `MSG`, `MSI` | OLE2 major version, sector size, internal directory streams (`WordDocument`, `Workbook`, `PowerPoint Document`, Outlook `__substg1.0_`) |
| **Executables & Bytecode** | Windows `PE` (`EXE`/`DLL`/`SYS`), Linux `ELF`, macOS `Mach-O` (32/64/Fat), `Java .class`, `WASM` | CPU architecture (`x86`, `x86-64`, `ARM64`, `RISC-V`), 32/64-bit class, endianness, `DLL` vs `EXE`, Windows Subsystem (`GUI`/`Console`/`Driver`), `.NET CLR` assembly detection, `0xCAFEBABE` Java JDK version vs Mach-O Universal disambiguation |
| **Documents** | `PDF`, `RTF` | PDF version (`1.0`–`2.0`) within first 1024 bytes, `/Linearized` (Fast Web View), `/Encrypt`, embedded `/JavaScript` flags |
| **Images & Design** | `PNG`, `APNG`, `JPEG`/`JFIF`/`Exif`, `GIF`, `WebP`, `HEIC`/`HEIF`, `AVIF`, `BMP`, `TIFF`, `PSD`, `ICO`, `ANI`, `CR3`, `SVG` | Pixel dimensions (`width × height`), bit depth, color model (`RGB`, `RGBA`, `Grayscale`, `Indexed`), JPEG `SOF0`/`SOF2` baseline vs progressive, WebP `VP8`/`VP8L`/`VP8X` |
| **Audio & Video** | `MP4`, `MOV`, `M4A`, `3GP`, `MKV`, `WebM`, `AVI`, `WAV`, `MP3`, `FLAC`, `Ogg` (`Opus`/`Vorbis`/`Theora`), `MIDI` | ISO `ftyp` major & compatible brands, WAV PCM channels/sample rate/bit depth, MP3 `ID3v2` version or MPEG frame sync, EBML `matroska` vs `webm` |
| **Archives & Compression** | `RAR` (v4 & v5), `7z`, `GZIP`, `BZIP2`, `XZ`, `Zstandard (zstd)`, `POSIX TAR` | Format versions, GZIP origin OS & embedded original filename, BZIP2 dictionary block size, TAR `ustar` first member name |
| **Databases & Forensics** | `SQLite 3`, `Apache Parquet`, `PCAP`, `PCAPNG` | SQLite page size & text encoding (`UTF-8`/`UTF-16`), Parquet `PAR1` header, network packet capture headers |
| **Fonts & Crypto** | `WOFF`, `WOFF2`, `OTF`, `TTF`, `PEM` Certificates/Keys | Font container version, PEM armor header (`BEGIN CERTIFICATE`, `PRIVATE KEY`, etc.) |
| **Text & Source Code** | `UTF-8`, `UTF-16 LE/BE`, `UTF-32 LE`, `Shebang (#!)`, `HTML`, `XML`, `JSON`, `CSV`, `JS/TS`, `Python`, `C/C++` | BOM detection, `CRLF` vs `LF` line endings, interpreter directive (`#!/usr/bin/env ...`), CSV column count, language keyword heuristics |

---

## 🗂️ Project Structure

```text
d:\File Name Analyzer\
├── index.html      # Main application UI, dropzone, demo sample bar, and searchable reference table
├── styles.css      # Dark-mode forensic UI theme, status badges, metrics grid, and hex viewer layout
├── analyzer.js     # Core binary parsing engine, container dissectors, spoofing verifier, and DOM renderer
└── README.md       # Project documentation, architecture guide, and version changelog (this file)
```

---

## 🚀 How to Run & Use

1. **Zero Build / Zero Dependencies:** Simply open [`index.html`](file:///d:/File%20Name%20Analyzer/index.html) in any modern web browser (Chrome, Edge, Firefox, Safari), or serve the folder with any static HTTP server (e.g., VS Code Live Server or `python -m http.server`).
2. **Analyze Your Files:** Drag and drop one or more files onto the dashed inspection zone, or click **"Choose File(s) from Device"**.
3. **Test Built-in Samples:** Click any button in the **"Try Instant Demo Samples"** bar (such as `⚠️ Spoofed: urgent-invoice.pdf`) to see how FileID catches disguised executables and inspects internal headers.

---

## 📝 Version History & Changelog

> **Maintenance Rule:** Always update the **Current Version** badge at the top of this file and append a new entry to the table and detailed log below whenever features, signatures, UI improvements, or bug fixes are made.

### Version Summary Table

| Version | Date | Summary of Changes |
| :--- | :--- | :--- |
| **`v1.0.0`** | `2026-10-23` | Initial release of **FileID — Magic-Byte File Type Identifier & Spoofing Analyzer** with 35+ signature & container dissectors, spoofing alerts, entropy/SHA-256 metrics, 64-byte hex inspector, and project documentation. |

---

### Detailed Release Notes

#### [v1.0.0] — 2026-10-23
- **Added Core Detection Engine ([`analyzer.js`](file:///d:/File%20Name%20Analyzer/analyzer.js)):**
  - Implemented 35+ binary magic-byte detectors and heuristic text/code analyzers.
  - Added deep container inspection for `ZIP/OOXML/APK/JAR/EPUB/ODT`, `OLE2 (DOC/XLS/PPT/MSG)`, `Windows PE/MZ`, `Linux ELF`, `macOS Mach-O`, `RIFF`, `ISO-BMFF (ftyp)`, `PNG`, `JPEG`, and `PDF`.
  - Added `0xCAFEBABE` disambiguation between compiled Java `.class` bytecode (with JDK version mapping) and macOS Universal Fat binaries.
- **Added Extension Spoofing & Security Analyzer:**
  - Detects disguised executables (`status-danger`), double-extension spoofing (e.g., `.pdf.exe`), mismatched extensions (`status-warning`), and verified matches (`status-match`).
  - Added Shannon entropy calculation (`0–8 bits/byte`) and Web Crypto `SHA-256` hashing.
- **Added Forensic User Interface ([`index.html`](file:///d:/File%20Name%20Analyzer/index.html), [`styles.css`](file:///d:/File%20Name%20Analyzer/styles.css)):**
  - Drag-and-drop multi-file uploader with 5 instant in-memory demo samples.
  - Unix `file` / `libmagic` terminal banner with one-click copy.
  - 64-byte raw hexadecimal + ASCII preview highlighting matched magic bytes.
  - Real-time searchable Magic-Byte Reference Table.
- **Added Documentation ([`README.md`](file:///d:/File%20Name%20Analyzer/README.md)):**
  - Created comprehensive documentation covering application purpose, internal workflow, supported formats, and version tracking.

<!--
TEMPLATE FOR FUTURE UPDATES:

#### [vX.Y.Z] — YYYY-MM-DD
- **Added:** ...
- **Changed / Improved:** ...
- **Fixed:** ...
-->

