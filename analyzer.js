/**
 * FileID — Client-Side Magic-Byte & Container File Analyzer
 * Version: v1.3.0
 * Developed by: Soumya Ranjan Sethy
 * Last Updated: 2026-10-23
 * Inspired by Toolsley File Identifier (libmagic / Unix `file` utility)
 * Processes 100% locally in the browser using FileReader & ArrayBuffer.
 */

const APP_VERSION = 'v1.3.0';
const APP_AUTHOR = 'Soumya Ranjan Sethy';

// ============================================================================
// 1. Utility Helpers for Binary Reading
// ============================================================================

function toHex(bytes, start = 0, length = 16, separator = ' ') {
  const end = Math.min(bytes.length, start + length);
  const parts = [];
  for (let i = start; i < end; i++) {
    parts.push(bytes[i].toString(16).padStart(2, '0').toUpperCase());
  }
  return parts.join(separator);
}

function readAscii(bytes, start, length) {
  const end = Math.min(bytes.length, start + length);
  let str = '';
  for (let i = start; i < end; i++) {
    const b = bytes[i];
    str += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
  }
  return str;
}

function readRawString(bytes, start, length) {
  const end = Math.min(bytes.length, start + length);
  let str = '';
  for (let i = start; i < end; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}

function readUInt16LE(bytes, offset) {
  if (offset + 2 > bytes.length) return 0;
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readUInt16BE(bytes, offset) {
  if (offset + 2 > bytes.length) return 0;
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUInt32LE(bytes, offset) {
  if (offset + 4 > bytes.length) return 0;
  return (
    (bytes[offset]) |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] * 0x1000000)
  ) >>> 0;
}

function readUInt32BE(bytes, offset) {
  if (offset + 4 > bytes.length) return 0;
  return (
    (bytes[offset] * 0x1000000) +
    ((bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3])
  ) >>> 0;
}

function matchBytes(bytes, pattern, offset = 0) {
  if (offset + pattern.length > bytes.length) return false;
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] !== null && bytes[offset + i] !== pattern[i]) {
      return false;
    }
  }
  return true;
}

function calculateEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const freq = new Uint32Array(256);
  const sampleLen = Math.min(bytes.length, 65536);
  for (let i = 0; i < sampleLen; i++) {
    freq[bytes[i]]++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / sampleLen;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy; // 0.0 to 8.0 bits/byte
}

async function computeSHA256(arrayBuffer) {
  try {
    if (window.crypto && window.crypto.subtle) {
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
  } catch (e) {
    // Fallback if subtle crypto unavailable
  }
  return null;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const val = bytes / Math.pow(k, i);
  return `${val.toFixed(i === 0 ? 0 : 2)} ${sizes[i]} (${bytes.toLocaleString()} bytes)`;
}

// ============================================================================
// 2. Deep Structural Parsers (like libmagic)
// ============================================================================

/**
 * Inspects ZIP containers (PK\x03\x04) to distinguish DOCX, XLSX, PPTX,
 * EPUB, JAR, APK, ODT/ODS/ODP, Python Wheel, CRX, or standard ZIP archives.
 */
function inspectZipContainer(bytes) {
  const rawSample = readRawString(bytes, 0, Math.min(bytes.length, 65536));
  const versionNeeded = readUInt16LE(bytes, 4);
  const flags = readUInt16LE(bytes, 6);
  const compression = readUInt16LE(bytes, 8);
  const encrypted = (flags & 0x01) !== 0;

  const compMethods = {
    0: 'stored (uncompressed)',
    8: 'Deflate',
    9: 'Deflate64',
    12: 'BZIP2',
    14: 'LZMA',
    93: 'Zstandard',
    95: 'XZ',
    99: 'AES encrypted'
  };
  const compDesc = compMethods[compression] || `method #${compression}`;
  const verStr = `at least v${(versionNeeded / 10).toFixed(1)} to extract, compression: ${compDesc}${encrypted ? ', encrypted' : ''}`;

  // Check EPUB first (uncompressed 'mimetype' file at offset 30 containing application/epub+zip)
  if (rawSample.includes('application/epub+zip')) {
    return {
      name: 'EPUB E-Book Document',
      libmagicText: `EPUB document (${verStr})`,
      mime: 'application/epub+zip',
      category: 'Document / E-Book',
      extensions: ['epub'],
      containerType: 'ZIP-based OCF Container',
      magicOffset: 0,
      magicLength: 4,
      details: ['Detected OCF mimetype: application/epub+zip', `ZIP ${verStr}`]
    };
  }

  // OpenDocument formats (ODT, ODS, ODP, ODG)
  if (rawSample.includes('application/vnd.oasis.opendocument.text')) {
    return {
      name: 'OpenDocument Text Document (ODT)',
      libmagicText: `OpenDocument Text document (${verStr})`,
      mime: 'application/vnd.oasis.opendocument.text',
      category: 'Document',
      extensions: ['odt'],
      containerType: 'ZIP-based OpenDocument',
      magicOffset: 0,
      magicLength: 4,
      details: ['Detected OASIS OpenDocument Text mimetype']
    };
  }
  if (rawSample.includes('application/vnd.oasis.opendocument.spreadsheet')) {
    return {
      name: 'OpenDocument Spreadsheet (ODS)',
      libmagicText: `OpenDocument Spreadsheet (${verStr})`,
      mime: 'application/vnd.oasis.opendocument.spreadsheet',
      category: 'Spreadsheet',
      extensions: ['ods'],
      containerType: 'ZIP-based OpenDocument',
      magicOffset: 0,
      magicLength: 4,
      details: ['Detected OASIS OpenDocument Spreadsheet mimetype']
    };
  }
  if (rawSample.includes('application/vnd.oasis.opendocument.presentation')) {
    return {
      name: 'OpenDocument Presentation (ODP)',
      libmagicText: `OpenDocument Presentation (${verStr})`,
      mime: 'application/vnd.oasis.opendocument.presentation',
      category: 'Presentation',
      extensions: ['odp'],
      containerType: 'ZIP-based OpenDocument',
      magicOffset: 0,
      magicLength: 4,
      details: ['Detected OASIS OpenDocument Presentation mimetype']
    };
  }

  // Microsoft Office Open XML (OOXML: DOCX, XLSX, PPTX)
  if (rawSample.includes('[Content_Types].xml') || rawSample.includes('_rels/.rels') || rawSample.includes('word/') || rawSample.includes('xl/') || rawSample.includes('ppt/')) {
    if (rawSample.includes('word/document.xml') || rawSample.includes('word/')) {
      return {
        name: 'Microsoft Word Document (OOXML)',
        libmagicText: `Microsoft Word 2007+ document (${verStr})`,
        mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        category: 'Document',
        extensions: ['docx', 'docm', 'dotx'],
        containerType: 'ZIP / Office Open XML (OOXML)',
        magicOffset: 0,
        magicLength: 4,
        details: ['Contains [Content_Types].xml and word/ directory entries', `ZIP ${verStr}`]
      };
    }
    if (rawSample.includes('xl/workbook.xml') || rawSample.includes('xl/')) {
      return {
        name: 'Microsoft Excel Spreadsheet (OOXML)',
        libmagicText: `Microsoft Excel 2007+ workbook (${verStr})`,
        mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        category: 'Spreadsheet',
        extensions: ['xlsx', 'xlsm', 'xltx'],
        containerType: 'ZIP / Office Open XML (OOXML)',
        magicOffset: 0,
        magicLength: 4,
        details: ['Contains [Content_Types].xml and xl/ directory entries', `ZIP ${verStr}`]
      };
    }
    if (rawSample.includes('ppt/presentation.xml') || rawSample.includes('ppt/')) {
      return {
        name: 'Microsoft PowerPoint Presentation (OOXML)',
        libmagicText: `Microsoft PowerPoint 2007+ presentation (${verStr})`,
        mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        category: 'Presentation',
        extensions: ['pptx', 'pptm', 'ppsx'],
        containerType: 'ZIP / Office Open XML (OOXML)',
        magicOffset: 0,
        magicLength: 4,
        details: ['Contains [Content_Types].xml and ppt/ directory entries', `ZIP ${verStr}`]
      };
    }
    if (rawSample.includes('visio/')) {
      return {
        name: 'Microsoft Visio Drawing (OOXML)',
        libmagicText: `Microsoft Visio 2013+ drawing (${verStr})`,
        mime: 'application/vnd.ms-visio.drawing',
        category: 'Document / Vector',
        extensions: ['vsdx'],
        containerType: 'ZIP / Office Open XML (OOXML)',
        magicOffset: 0,
        magicLength: 4,
        details: ['Contains visio/ package structure']
      };
    }
    return {
      name: 'Open Packaging Conventions (OOXML) Package',
      libmagicText: `Microsoft OOXML package (${verStr})`,
      mime: 'application/vnd.openxmlformats-package',
      category: 'Document / Package',
      extensions: ['docx', 'xlsx', 'pptx', 'nupkg', 'vsix'],
      containerType: 'ZIP / Open Packaging Conventions',
      magicOffset: 0,
      magicLength: 4,
      details: ['Contains [Content_Types].xml']
    };
  }

  // Android APK
  if (rawSample.includes('AndroidManifest.xml') || rawSample.includes('classes.dex') || rawSample.includes('resources.arsc')) {
    return {
      name: 'Android Application Package (APK)',
      libmagicText: `Android package (APK), with AndroidManifest.xml (${verStr})`,
      mime: 'application/vnd.android.package-archive',
      category: 'Executable / Mobile Package',
      extensions: ['apk', 'xapk', 'apks'],
      containerType: 'ZIP / Android Package',
      magicOffset: 0,
      magicLength: 4,
      details: ['Contains AndroidManifest.xml / classes.dex', `ZIP ${verStr}`]
    };
  }

  // Java Archive (JAR / WAR / EAR)
  if (rawSample.includes('META-INF/MANIFEST.MF') || rawSample.includes('META-INF/')) {
    return {
      name: 'Java Archive (JAR)',
      libmagicText: `Java archive data (JAR) (${verStr})`,
      mime: 'application/java-archive',
      category: 'Archive / Executable Package',
      extensions: ['jar', 'war', 'ear'],
      containerType: 'ZIP / Java Archive',
      magicOffset: 0,
      magicLength: 4,
      details: ['Contains META-INF/MANIFEST.MF', `ZIP ${verStr}`]
    };
  }

  // iOS IPA
  if (rawSample.includes('Payload/') && rawSample.includes('.app/')) {
    return {
      name: 'iOS App Store Package (IPA)',
      libmagicText: `iOS App Package (IPA), ZIP archive (${verStr})`,
      mime: 'application/octet-stream',
      category: 'Executable / Mobile Package',
      extensions: ['ipa'],
      containerType: 'ZIP / iOS Payload',
      magicOffset: 0,
      magicLength: 4,
      details: ['Contains Payload/*.app bundle']
    };
  }

  // Python Wheel
  if (rawSample.includes('.dist-info/WHEEL') || rawSample.includes('.dist-info/METADATA')) {
    return {
      name: 'Python Wheel Package (WHL)',
      libmagicText: `Python Wheel distribution archive (${verStr})`,
      mime: 'application/zip',
      category: 'Package / Archive',
      extensions: ['whl'],
      containerType: 'ZIP / PEP 427 Wheel',
      magicOffset: 0,
      magicLength: 4,
      details: ['Contains *.dist-info/WHEEL metadata']
    };
  }

  // Extract first file entry name in standard ZIP if present
  let firstEntryInfo = '';
  if (bytes.length > 30) {
    const fileNameLen = readUInt16LE(bytes, 26);
    if (fileNameLen > 0 && fileNameLen < 256 && 30 + fileNameLen <= bytes.length) {
      const firstFileName = readAscii(bytes, 30, fileNameLen);
      firstEntryInfo = `First entry: "${firstFileName}"`;
    }
  }

  return {
    name: 'ZIP Archive',
    libmagicText: `Zip archive data, ${verStr}`,
    mime: 'application/zip',
    category: 'Archive / Compressed',
    extensions: ['zip', 'cbz', 'zipx', 'jar', 'docx', 'xlsx', 'pptx', 'apk'],
    containerType: 'PKZIP Archive',
    magicOffset: 0,
    magicLength: 4,
    details: [
      `PKZIP local file header (0x04034B50)`,
      `Extractor version: ${(versionNeeded / 10).toFixed(1)}, Compression: ${compDesc}`,
      ...(encrypted ? ['Encrypted flag: SET'] : []),
      ...(firstEntryInfo ? [firstEntryInfo] : [])
    ]
  };
}

/**
 * Inspects OLE2 Compound File Binary Format (D0 CF 11 E0 A1 B1 1A E1)
 */
function inspectOLE2Container(bytes) {
  const rawSample = readRawString(bytes, 0, Math.min(bytes.length, 65536));
  const majorVer = readUInt16LE(bytes, 26);
  const sectorShift = readUInt16LE(bytes, 30);
  const sectorSize = 1 << sectorShift;

  if (rawSample.includes('W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t') || rawSample.includes('WordDocument')) {
    return {
      name: 'Microsoft Word 97-2003 Document (OLE2)',
      libmagicText: `Composite Document File V2 Document, Microsoft Word Document (OLE2 v${majorVer}, sector size ${sectorSize})`,
      mime: 'application/msword',
      category: 'Document',
      extensions: ['doc', 'dot'],
      containerType: 'OLE2 Compound Document',
      magicOffset: 0,
      magicLength: 8,
      details: ['Detected "WordDocument" stream inside OLE2 container', `OLE2 version: ${majorVer}, Sector size: ${sectorSize} bytes`]
    };
  }

  if (rawSample.includes('W\x00o\x00r\x00k\x00b\x00o\x00o\x00k') || rawSample.includes('Workbook') || rawSample.includes('B\x00o\x00o\x00k')) {
    return {
      name: 'Microsoft Excel 97-2003 Spreadsheet (OLE2)',
      libmagicText: `Composite Document File V2 Document, Microsoft Excel Workbook (OLE2 v${majorVer}, sector size ${sectorSize})`,
      mime: 'application/vnd.ms-excel',
      category: 'Spreadsheet',
      extensions: ['xls', 'xlt', 'xla'],
      containerType: 'OLE2 Compound Document',
      magicOffset: 0,
      magicLength: 8,
      details: ['Detected "Workbook" stream inside OLE2 container', `OLE2 version: ${majorVer}, Sector size: ${sectorSize} bytes`]
    };
  }

  if (rawSample.includes('P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t\x00 \x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t') || rawSample.includes('PowerPoint Document')) {
    return {
      name: 'Microsoft PowerPoint 97-2003 Presentation (OLE2)',
      libmagicText: `Composite Document File V2 Document, Microsoft PowerPoint Presentation (OLE2 v${majorVer}, sector size ${sectorSize})`,
      mime: 'application/vnd.ms-powerpoint',
      category: 'Presentation',
      extensions: ['ppt', 'pps', 'pot'],
      containerType: 'OLE2 Compound Document',
      magicOffset: 0,
      magicLength: 8,
      details: ['Detected "PowerPoint Document" stream inside OLE2 container', `OLE2 version: ${majorVer}, Sector size: ${sectorSize} bytes`]
    };
  }

  if (rawSample.includes('__substg1.0_')) {
    return {
      name: 'Microsoft Outlook Email Message (MSG)',
      libmagicText: `Microsoft Outlook Message (OLE2 CFBF v${majorVer})`,
      mime: 'application/vnd.ms-outlook',
      category: 'Document / Email',
      extensions: ['msg'],
      containerType: 'OLE2 Compound Document',
      magicOffset: 0,
      magicLength: 8,
      details: ['Detected MAPI property streams (__substg1.0_*)']
    };
  }

  return {
    name: 'Microsoft Compound File Binary (OLE2 / DOC / XLS / PPT / MSI)',
    libmagicText: `Composite Document File V2 Document, Little Endian, Os: Windows, Version ${majorVer}, sector size ${sectorSize}`,
    mime: 'application/x-ole-storage',
    category: 'Document / Container',
    extensions: ['doc', 'xls', 'ppt', 'msi', 'msg', 'vsd'],
    containerType: 'OLE2 Compound Document (CFBF)',
    magicOffset: 0,
    magicLength: 8,
    details: [`OLE2 Header Signature: D0 CF 11 E0 A1 B1 1A E1`, `Major Version: ${majorVer}, Sector Size: ${sectorSize} bytes`]
  };
}

/**
 * Inspects Windows Portable Executable (MZ / PE)
 */
function inspectPEExecutable(bytes) {
  const details = ['DOS MZ Header (0x5A4D) present at offset 0x00'];
  if (bytes.length >= 64) {
    const peOffset = readUInt32LE(bytes, 0x3C);
    if (peOffset > 0 && peOffset + 24 <= bytes.length) {
      if (bytes[peOffset] === 0x50 && bytes[peOffset + 1] === 0x45 && bytes[peOffset + 2] === 0x00 && bytes[peOffset + 3] === 0x00) {
        const machine = readUInt16LE(bytes, peOffset + 4);
        const numSections = readUInt16LE(bytes, peOffset + 6);
        const characteristics = readUInt16LE(bytes, peOffset + 22);
        const optMagic = peOffset + 26 <= bytes.length ? readUInt16LE(bytes, peOffset + 24) : 0;

        const archMap = {
          0x014c: 'Intel 80386 (x86 32-bit)',
          0x8664: 'x86-64 (AMD64 64-bit)',
          0xAA64: 'ARM64 (AArch64)',
          0x01c0: 'ARM Little-Endian',
          0x01c4: 'ARM Thumb-2 (ARMNT)',
          0x0200: 'Intel Itanium (IA-64)'
        };
        const arch = archMap[machine] || `Machine 0x${machine.toString(16)}`;
        const isDLL = (characteristics & 0x2000) !== 0;
        const isPE32Plus = optMagic === 0x20B;
        const peFormat = isPE32Plus ? 'PE32+ (64-bit)' : (optMagic === 0x10B ? 'PE32 (32-bit)' : 'PE');

        let subsystemStr = '';
        const subOffset = peOffset + 24 + 68;
        if (subOffset + 2 <= bytes.length) {
          const subsystem = readUInt16LE(bytes, subOffset);
          const subMap = {
            1: 'Native / Driver',
            2: 'Windows GUI',
            3: 'Windows Console (CUI)',
            7: 'POSIX Console',
            9: 'Windows CE',
            10: 'EFI Application'
          };
          subsystemStr = subMap[subsystem] || `Subsystem #${subsystem}`;
        }

        const rawSample = readRawString(bytes, 0, Math.min(bytes.length, 32768));
        const isDotNet = rawSample.includes('mscoree.dll') || rawSample.includes('_CorExeMain') || rawSample.includes('_CorDllMain');

        details.push(
          `PE Header offset: 0x${peOffset.toString(16).toUpperCase()}`,
          `Format: ${peFormat}${isDLL ? ' (DLL)' : ' (Executable)'}${isDotNet ? ' [.NET CLR Assembly]' : ''}`,
          `Architecture: ${arch}`,
          `Sections: ${numSections}${subsystemStr ? `, Subsystem: ${subsystemStr}` : ''}`
        );

        return {
          name: isDLL ? `Windows Dynamic Link Library (DLL - ${arch})` : `Windows Portable Executable (EXE - ${arch})`,
          libmagicText: `${peFormat} executable${isDLL ? ' (DLL)' : ''} (${subsystemStr || 'Windows'}) ${arch}${isDotNet ? ' Mono/.Net assembly' : ''}, for MS Windows, ${numSections} sections`,
          mime: 'application/vnd.microsoft.portable-executable',
          category: 'Executable / Binary',
          extensions: isDLL ? ['dll', 'ocx', 'cpl', 'sys'] : ['exe', 'scr', 'com', 'msi'],
          isExecutable: true,
          magicOffset: 0,
          magicLength: 2,
          details
        };
      }
    }
  }

  return {
    name: 'MS-DOS / Windows Executable (MZ)',
    libmagicText: 'MS-DOS executable, MZ header for MS-DOS / Windows',
    mime: 'application/x-msdownload',
    category: 'Executable / Binary',
    extensions: ['exe', 'dll', 'com', 'scr', 'sys'],
    isExecutable: true,
    magicOffset: 0,
    magicLength: 2,
    details
  };
}

/**
 * Inspects Linux/Unix ELF Binaries (7F 45 4C 46)
 */
function inspectELFBinary(bytes) {
  const eiClass = bytes[4]; // 1 = 32-bit, 2 = 64-bit
  const eiData = bytes[5];  // 1 = LSB (little endian), 2 = MSB (big endian)
  const osAbi = bytes[7];
  const isLE = eiData === 1;
  const read16 = isLE ? readUInt16LE : readUInt16BE;

  const eType = read16(bytes, 16);
  const eMachine = read16(bytes, 18);

  const bitsStr = eiClass === 2 ? '64-bit' : (eiClass === 1 ? '32-bit' : 'Unknown-class');
  const endianStr = eiData === 1 ? 'LSB (little-endian)' : (eiData === 2 ? 'MSB (big-endian)' : 'Unknown-endian');

  const typeMap = {
    1: 'relocatable (.o)',
    2: 'executable',
    3: 'pie executable / shared object (.so)',
    4: 'core file'
  };
  const machineMap = {
    0x03: 'Intel 80386 (x86)',
    0x3E: 'x86-64 (AMD64)',
    0x28: 'ARM',
    0xB7: 'ARM aarch64',
    0xF3: 'UCB RISC-V',
    0x08: 'MIPS',
    0x14: 'PowerPC',
    0x15: 'PowerPC64'
  };
  const abiMap = {
    0: 'SYSV',
    3: 'GNU/Linux',
    6: 'Solaris',
    9: 'FreeBSD',
    12: 'OpenBSD'
  };

  const typeStr = typeMap[eType] || `type ${eType}`;
  const machStr = machineMap[eMachine] || `machine 0x${eMachine.toString(16)}`;
  const abiStr = abiMap[osAbi] || `ABI #${osAbi}`;

  return {
    name: `ELF ${bitsStr} ${typeStr} (${machStr})`,
    libmagicText: `ELF ${bitsStr} ${endianStr} ${typeStr}, ${machStr}, version 1 (${abiStr})`,
    mime: eType === 3 ? 'application/x-sharedlib' : 'application/x-executable',
    category: 'Executable / Binary',
    extensions: ['elf', 'so', 'o', 'bin', 'out', 'ko'],
    isExecutable: true,
    magicOffset: 0,
    magicLength: 4,
    details: [
      `Class: ELF ${bitsStr}`,
      `Data Encoding: ${endianStr}`,
      `Type: ${typeStr}`,
      `Architecture: ${machStr}`,
      `OS/ABI: ${abiStr}`
    ]
  };
}

/**
 * Inspects ISO Base Media File Format (`ftyp` box at offset 4)
 * Covers MP4, MOV, M4A, HEIC, AVIF, 3GP, CR3, etc.
 */
function inspectISOBMFF(bytes) {
  const brand = readAscii(bytes, 8, 4);
  const minorVer = readUInt32BE(bytes, 12);
  const boxSize = readUInt32BE(bytes, 0);
  const compatBrands = [];
  const maxBox = Math.min(bytes.length, Math.max(boxSize, 32));
  for (let i = 16; i + 4 <= maxBox; i += 4) {
    compatBrands.push(readAscii(bytes, i, 4).trim());
  }

  const brandTrim = brand.trim();
  const details = [
    `ISO Base Media 'ftyp' box at offset 4`,
    `Major Brand: "${brand}" (minor version ${minorVer})`,
    ...(compatBrands.length ? [`Compatible Brands: ${compatBrands.filter(Boolean).join(', ')}`] : [])
  ];

  if (['heic', 'heix', 'hevc', 'heim', 'heis', 'mif1', 'msf1'].includes(brandTrim)) {
    const isHeic = brandTrim.startsWith('hei') || compatBrands.includes('heic');
    return {
      name: isHeic ? 'HEIC / HEIF High Efficiency Image' : 'HEIF Image Container (MIF1)',
      libmagicText: `ISO Media, HEIF Image ${isHeic ? 'HEVC Main Profile' : ''} (brand: ${brand})`,
      mime: isHeic ? 'image/heic' : 'image/heif',
      category: 'Image',
      extensions: ['heic', 'heif', 'hif'],
      magicOffset: 4,
      magicLength: 8,
      details
    };
  }

  if (['avif', 'avis'].includes(brandTrim) || compatBrands.includes('avif')) {
    return {
      name: 'AVIF Image (AV1 Image File Format)',
      libmagicText: `ISO Media, AVIF Image (major brand: ${brandTrim})`,
      mime: 'image/avif',
      category: 'Image',
      extensions: ['avif'],
      magicOffset: 4,
      magicLength: 8,
      details
    };
  }

  if (brand === 'qt  ') {
    return {
      name: 'Apple QuickTime Movie (MOV)',
      libmagicText: 'ISO Media, Apple QuickTime movie,outes (qt)',
      mime: 'video/quicktime',
      category: 'Video',
      extensions: ['mov', 'qt'],
      magicOffset: 4,
      magicLength: 8,
      details
    };
  }

  if (brand === 'M4A ' || brand === 'M4B ' || brand === 'M4P ') {
    return {
      name: 'Apple MPEG-4 Audio (M4A / AAC / ALAC)',
      libmagicText: `ISO Media, Apple iTunes ALAC/AAC-LC (${brand.trim()}) Audio`,
      mime: 'audio/mp4',
      category: 'Audio',
      extensions: ['m4a', 'm4b', 'm4p', 'aac'],
      magicOffset: 4,
      magicLength: 8,
      details
    };
  }

  if (brand === 'crx ') {
    return {
      name: 'Canon RAW v3 Image (CR3)',
      libmagicText: 'ISO Media, Canon Raw version 3 (CR3)',
      mime: 'image/x-canon-cr3',
      category: 'Image / Camera RAW',
      extensions: ['cr3'],
      magicOffset: 4,
      magicLength: 8,
      details
    };
  }

  if (brandTrim.startsWith('3gp') || brandTrim.startsWith('3g2')) {
    return {
      name: '3GPP Multimedia Video/Audio',
      libmagicText: `ISO Media, MPEG v4 system, 3GPP (${brandTrim})`,
      mime: 'video/3gpp',
      category: 'Video',
      extensions: ['3gp', '3g2'],
      magicOffset: 4,
      magicLength: 8,
      details
    };
  }

  return {
    name: 'MPEG-4 Video / Multimedia Container (MP4)',
    libmagicText: `ISO Media, MP4 Base Media v1 [ISO 14496-12] (major brand: "${brand}")`,
    mime: 'video/mp4',
    category: 'Video',
    extensions: ['mp4', 'm4v', 'm4a', 'mov'],
    magicOffset: 4,
    magicLength: 8,
    details
  };
}

/**
 * Inspects RIFF containers (52 49 46 46 ....)
 */
function inspectRIFF(bytes) {
  const fileSize = readUInt32LE(bytes, 4) + 8;
  const formType = readAscii(bytes, 8, 4);

  if (formType === 'WEBP') {
    const chunk = readAscii(bytes, 12, 4);
    const vpDesc = chunk === 'VP8 ' ? 'VP8 lossy' : (chunk === 'VP8L' ? 'VP8L lossless' : (chunk === 'VP8X' ? 'VP8X extended' : chunk));
    return {
      name: 'Google WebP Image',
      libmagicText: `RIFF (little-endian) data, Web/P image, ${vpDesc}`,
      mime: 'image/webp',
      category: 'Image',
      extensions: ['webp'],
      magicOffset: 0,
      magicLength: 12,
      details: [`RIFF Form Type: WEBP (${vpDesc})`, `RIFF Reported Size: ${fileSize.toLocaleString()} bytes`]
    };
  }

  if (formType === 'WAVE') {
    let audioDetails = `RIFF Form Type: WAVE`;
    if (bytes.length >= 36 && readAscii(bytes, 12, 4) === 'fmt ') {
      const channels = readUInt16LE(bytes, 22);
      const sampleRate = readUInt32LE(bytes, 24);
      const bitsPerSample = readUInt16LE(bytes, 34);
      audioDetails = `${channels} channel(s), ${sampleRate} Hz, ${bitsPerSample}-bit PCM`;
    }
    return {
      name: 'Waveform Audio (WAV)',
      libmagicText: `RIFF (little-endian) data, WAVE audio, ${audioDetails}`,
      mime: 'audio/wav',
      category: 'Audio',
      extensions: ['wav', 'wave'],
      magicOffset: 0,
      magicLength: 12,
      details: [audioDetails, `RIFF Size: ${fileSize.toLocaleString()} bytes`]
    };
  }

  if (formType === 'AVI ') {
    return {
      name: 'Audio Video Interleave (AVI)',
      libmagicText: 'RIFF (little-endian) data, AVI, audio/video interleaved',
      mime: 'video/x-msvideo',
      category: 'Video',
      extensions: ['avi'],
      magicOffset: 0,
      magicLength: 12,
      details: [`RIFF Form Type: AVI`, `RIFF Size: ${fileSize.toLocaleString()} bytes`]
    };
  }

  if (formType === 'ACON') {
    return {
      name: 'Windows Animated Cursor (ANI)',
      libmagicText: 'RIFF (little-endian) data, animated cursor',
      mime: 'application/x-navi-animation',
      category: 'Image / Icon',
      extensions: ['ani'],
      magicOffset: 0,
      magicLength: 12,
      details: ['RIFF Form Type: ACON (Animated Icon/Cursor)']
    };
  }

  return {
    name: `RIFF Container (${formType})`,
    libmagicText: `RIFF (little-endian) data, form type "${formType}"`,
    mime: 'application/octet-stream',
    category: 'Multimedia / Container',
    extensions: ['riff', 'wav', 'avi', 'webp'],
    magicOffset: 0,
    magicLength: 12,
    details: [`RIFF Form Type: "${formType}"`]
  };
}

/**
 * Inspects PNG Header (89 50 4E 47 0D 0A 1A 0A)
 */
function inspectPNG(bytes) {
  const details = ['PNG 8-byte signature: 89 50 4E 47 0D 0A 1A 0A'];
  let dimText = '';
  if (bytes.length >= 29 && readAscii(bytes, 12, 4) === 'IHDR') {
    const width = readUInt32BE(bytes, 16);
    const height = readUInt32BE(bytes, 20);
    const bitDepth = bytes[24];
    const colorType = bytes[25];
    const interlace = bytes[28];

    const colorMap = {
      0: 'grayscale',
      2: 'color RGB',
      3: 'colormap (indexed)',
      4: 'grayscale+alpha',
      6: 'color RGBA'
    };
    const colorStr = colorMap[colorType] || `color-type ${colorType}`;
    const interlaceStr = interlace === 1 ? 'Adam7 interlaced' : 'non-interlaced';
    dimText = `, ${width} x ${height}, ${bitDepth}-bit/color ${colorStr}, ${interlaceStr}`;
    details.push(`Dimensions: ${width} × ${height} px`, `Color: ${bitDepth}-bit ${colorStr} (${interlaceStr})`);
  }

  const rawSample = readRawString(bytes, 0, Math.min(bytes.length, 4096));
  const isAPNG = rawSample.includes('acTL');
  if (isAPNG) {
    details.push('Animated PNG (acTL chunk detected)');
  }

  return {
    name: isAPNG ? 'Animated Portable Network Graphics (APNG)' : 'Portable Network Graphics (PNG)',
    libmagicText: `PNG image data${dimText}`,
    mime: isAPNG ? 'image/apng' : 'image/png',
    category: 'Image',
    extensions: ['png', 'apng'],
    magicOffset: 0,
    magicLength: 8,
    details
  };
}

/**
 * Inspects JPEG Header (FF D8 FF)
 */
function inspectJPEG(bytes) {
  const marker = bytes[3];
  let standard = 'JPEG/JFIF';
  if (marker === 0xE0) standard = 'JFIF standard';
  else if (marker === 0xE1) standard = 'Exif standard';
  else if (marker === 0xEE) standard = 'Adobe JPEG';
  else if (marker === 0xDB) standard = 'Raw quantization tables';

  let width = 0;
  let height = 0;
  let encoding = 'baseline';

  // Scan JPEG markers for SOF0 (0xFFC0) or SOF2 (0xFFC2)
  let offset = 2;
  while (offset + 9 < bytes.length && offset < 32768) {
    if (bytes[offset] !== 0xFF) {
      offset++;
      continue;
    }
    const m = bytes[offset + 1];
    if (m === 0xFF) {
      offset++;
      continue;
    }
    if (m === 0xD8 || m === 0xD9 || (m >= 0xD0 && m <= 0xD7)) {
      offset += 2;
      continue;
    }
    const segLen = readUInt16BE(bytes, offset + 2);
    if (segLen < 2) break;
    if (m === 0xC0 || m === 0xC1 || m === 0xC2) {
      encoding = m === 0xC2 ? 'progressive' : 'baseline';
      height = readUInt16BE(bytes, offset + 5);
      width = readUInt16BE(bytes, offset + 7);
      break;
    }
    offset += 2 + segLen;
  }

  const dimStr = width && height ? `, ${encoding}, ${width}x${height}` : '';
  return {
    name: 'JPEG Image',
    libmagicText: `JPEG image data, ${standard}${dimStr}`,
    mime: 'image/jpeg',
    category: 'Image',
    extensions: ['jpg', 'jpeg', 'jpe', 'jfif'],
    magicOffset: 0,
    magicLength: 4,
    details: [
      `JPEG SOI + Marker: FF D8 FF ${marker.toString(16).toUpperCase().padStart(2, '0')} (${standard})`,
      ...(width && height ? [`Dimensions: ${width} × ${height} px (${encoding})`] : [])
    ]
  };
}

/**
 * Inspects PDF Documents (%PDF-)
 */
function inspectPDF(bytes, offset = 0) {
  const version = readAscii(bytes, offset + 5, 3);
  const rawSample = readRawString(bytes, 0, Math.min(bytes.length, 65536));
  const isEncrypted = rawSample.includes('/Encrypt');
  const isLinearized = rawSample.includes('/Linearized');
  const hasJS = rawSample.includes('/JavaScript') || rawSample.includes('/JS');

  const flags = [];
  if (isLinearized) flags.push('Linearized (Fast Web View)');
  if (isEncrypted) flags.push('Encrypted');
  if (hasJS) flags.push('Contains embedded JavaScript (/JS)');

  return {
    name: `PDF Document (v${version})`,
    libmagicText: `PDF document, version ${version}${flags.length ? ` (${flags.join(', ')})` : ''}`,
    mime: 'application/pdf',
    category: 'Document',
    extensions: ['pdf', 'ai'],
    magicOffset: offset,
    magicLength: 8,
    details: [
      `PDF Header Version: ${version}${offset > 0 ? ` (found at byte offset ${offset})` : ''}`,
      ...(flags.length ? [`Document Flags: ${flags.join(', ')}`] : ['Standard unencrypted PDF container'])
    ]
  };
}

// ============================================================================
// 3. Master Magic Signature & Heuristic Detection Engine
// ============================================================================

function detectFileSignature(bytes) {
  if (bytes.length === 0) {
    return {
      name: 'Empty File (0 bytes)',
      libmagicText: 'empty',
      mime: 'application/x-empty',
      category: 'Empty',
      extensions: [],
      magicOffset: 0,
      magicLength: 0,
      confidence: 'Exact',
      details: ['File contains 0 bytes — no header or content to analyze.']
    };
  }

  // 1. ZIP & ZIP-based Containers (PK\x03\x04, PK\x05\x06 empty, PK\x07\x08 spanned)
  if (matchBytes(bytes, [0x50, 0x4B, 0x03, 0x04])) {
    return { ...inspectZipContainer(bytes), confidence: 'Exact (Container Dissected)' };
  }
  if (matchBytes(bytes, [0x50, 0x4B, 0x05, 0x06])) {
    return {
      name: 'ZIP Archive (Empty)',
      libmagicText: 'Zip archive data (empty)',
      mime: 'application/zip',
      category: 'Archive',
      extensions: ['zip'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['End of central directory record (PK\\x05\\x06)']
    };
  }

  // 2. OLE2 Compound Documents (D0 CF 11 E0 A1 B1 1A E1)
  if (matchBytes(bytes, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])) {
    return { ...inspectOLE2Container(bytes), confidence: 'Exact (Container Dissected)' };
  }

  // 3. PDF (%PDF- at offset 0 or within first 1024 bytes as allowed by PDF spec)
  for (let off = 0; off < Math.min(bytes.length - 5, 1024); off++) {
    if (bytes[off] === 0x25 && bytes[off + 1] === 0x50 && bytes[off + 2] === 0x44 && bytes[off + 3] === 0x46 && bytes[off + 4] === 0x2D) {
      return { ...inspectPDF(bytes, off), confidence: 'Exact' };
    }
  }

  // 4. PNG (89 50 4E 47 0D 0A 1A 0A)
  if (matchBytes(bytes, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) {
    return { ...inspectPNG(bytes), confidence: 'Exact' };
  }

  // 5. JPEG (FF D8 FF)
  if (matchBytes(bytes, [0xFF, 0xD8, 0xFF])) {
    return { ...inspectJPEG(bytes), confidence: 'Exact' };
  }

  // 6. GIF (GIF87a / GIF89a)
  if (matchBytes(bytes, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) || matchBytes(bytes, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61])) {
    const ver = readAscii(bytes, 3, 3);
    const w = readUInt16LE(bytes, 6);
    const h = readUInt16LE(bytes, 8);
    return {
      name: `GIF Image (GIF${ver})`,
      libmagicText: `GIF image data, version ${ver}, ${w} x ${h}`,
      mime: 'image/gif',
      category: 'Image',
      extensions: ['gif'],
      magicOffset: 0,
      magicLength: 6,
      confidence: 'Exact',
      details: [`Signature: GIF${ver}`, `Dimensions: ${w} × ${h} px`]
    };
  }

  // 7. RIFF Container (WEBP, WAV, AVI, ANI)
  if (matchBytes(bytes, [0x52, 0x49, 0x46, 0x46]) && bytes.length >= 12) {
    return { ...inspectRIFF(bytes), confidence: 'Exact' };
  }

  // 8. ISO Base Media File Format (ftyp at offset 4: MP4, MOV, HEIC, AVIF, M4A)
  if (bytes.length >= 12 && matchBytes(bytes, [0x66, 0x74, 0x79, 0x70], 4)) {
    return { ...inspectISOBMFF(bytes), confidence: 'Exact' };
  }

  // 9. ELF Binary (7F 45 4C 46)
  if (matchBytes(bytes, [0x7F, 0x45, 0x4C, 0x46])) {
    return { ...inspectELFBinary(bytes), confidence: 'Exact' };
  }

  // 10. Windows PE / DOS MZ Executable (4D 5A)
  if (matchBytes(bytes, [0x4D, 0x5A])) {
    return { ...inspectPEExecutable(bytes), confidence: 'Exact' };
  }

  // 11. Java Class vs Mach-O Universal Binary (Both start with CA FE BA BE!)
  if (matchBytes(bytes, [0xCA, 0xFE, 0xBA, 0xBE])) {
    const val4to7 = readUInt32BE(bytes, 4);
    const majorVer = readUInt16BE(bytes, 6);
    if (val4to7 >= 1 && val4to7 <= 20) {
      return {
        name: 'macOS Mach-O Universal (Fat) Binary',
        libmagicText: `Mach-O universal binary with ${val4to7} architecture(s)`,
        mime: 'application/x-mach-binary',
        category: 'Executable / Binary',
        extensions: ['bin', 'dylib', 'bundle', 'o'],
        isExecutable: true,
        magicOffset: 0,
        magicLength: 4,
        confidence: 'Exact',
        details: [`Disambiguated 0xCAFEBABE as Mach-O Fat Binary (${val4to7} architectures)`]
      };
    } else {
      const jdkVer = majorVer >= 45 ? `Java SE ${majorVer - 44} (class version ${majorVer}.${readUInt16BE(bytes, 4)})` : `version ${majorVer}`;
      return {
        name: `Compiled Java Class Bytecode (${jdkVer})`,
        libmagicText: `compiled Java class data, ${jdkVer}`,
        mime: 'application/java-vm',
        category: 'Executable / Bytecode',
        extensions: ['class'],
        isExecutable: true,
        magicOffset: 0,
        magicLength: 4,
        confidence: 'Exact',
        details: [`Magic: 0xCAFEBABE`, `Target Runtime: ${jdkVer}`]
      };
    }
  }

  // 12. macOS Mach-O 32/64-bit Executables
  if (
    matchBytes(bytes, [0xFE, 0xED, 0xFA, 0xCE]) ||
    matchBytes(bytes, [0xFE, 0xED, 0xFA, 0xCF]) ||
    matchBytes(bytes, [0xCE, 0xFA, 0xED, 0xFE]) ||
    matchBytes(bytes, [0xCF, 0xFA, 0xED, 0xFE])
  ) {
    const is64 = bytes[3] === 0xCF || bytes[0] === 0xCF;
    return {
      name: `macOS Mach-O ${is64 ? '64-bit' : '32-bit'} Binary`,
      libmagicText: `Mach-O ${is64 ? '64-bit' : '32-bit'} executable / dynamic library`,
      mime: 'application/x-mach-binary',
      category: 'Executable / Binary',
      extensions: ['dylib', 'bin', 'o', 'so'],
      isExecutable: true,
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: [`Mach-O ${is64 ? '64-bit' : '32-bit'} header signature`]
    };
  }

  // 13. WebAssembly (00 61 73 6D)
  if (matchBytes(bytes, [0x00, 0x61, 0x73, 0x6D])) {
    const ver = readUInt32LE(bytes, 4);
    return {
      name: 'WebAssembly Binary Module (WASM)',
      libmagicText: `WebAssembly (wasm) binary module version 0x${ver.toString(16)} (MVP)`,
      mime: 'application/wasm',
      category: 'Executable / Bytecode',
      extensions: ['wasm'],
      isExecutable: true,
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: [`Signature: \\0asm`, `Binary format version: ${ver}`]
    };
  }

  // 14. RAR Archive (v1.5-4.x and v5.0)
  if (matchBytes(bytes, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00])) {
    return {
      name: 'RAR Archive (v5.0+)',
      libmagicText: 'RAR archive data, v5',
      mime: 'application/vnd.rar',
      category: 'Archive / Compressed',
      extensions: ['rar', 'cbr'],
      magicOffset: 0,
      magicLength: 8,
      confidence: 'Exact',
      details: ['RAR v5.0+ 8-byte signature (52 61 72 21 1A 07 01 00)']
    };
  }
  if (matchBytes(bytes, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00])) {
    return {
      name: 'RAR Archive (v1.5 - v4.x)',
      libmagicText: 'RAR archive data, v4',
      mime: 'application/vnd.rar',
      category: 'Archive / Compressed',
      extensions: ['rar', 'cbr'],
      magicOffset: 0,
      magicLength: 7,
      confidence: 'Exact',
      details: ['RAR v4 7-byte signature (52 61 72 21 1A 07 00)']
    };
  }

  // 15. 7-Zip Archive (37 7A BC AF 27 1C)
  if (matchBytes(bytes, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) {
    const maj = bytes[6];
    const min = bytes[7];
    return {
      name: `7-Zip Archive (v${maj}.${min})`,
      libmagicText: `7-zip archive data, version ${maj}.${min}`,
      mime: 'application/x-7z-compressed',
      category: 'Archive / Compressed',
      extensions: ['7z', 'cb7'],
      magicOffset: 0,
      magicLength: 6,
      confidence: 'Exact',
      details: [`7-Zip signature: 37 7A BC AF 27 1C`, `Format version: ${maj}.${min}`]
    };
  }

  // 16. GZIP Compressed Data (1F 8B 08)
  if (matchBytes(bytes, [0x1F, 0x8B, 0x08])) {
    const flags = bytes[3];
    const osByte = bytes[9];
    const osNames = { 0: 'FAT (MS-DOS/Windows)', 3: 'Unix', 7: 'Macintosh', 11: 'NTFS (Windows)', 255: 'unknown OS' };
    let origName = '';
    if ((flags & 0x08) !== 0 && bytes.length > 10) {
      let endIdx = 10;
      while (endIdx < Math.min(bytes.length, 260) && bytes[endIdx] !== 0) endIdx++;
      origName = readAscii(bytes, 10, endIdx - 10);
    }
    return {
      name: 'GZIP Compressed Data',
      libmagicText: `gzip compressed data${origName ? `, was "${origName}"` : ''}, from ${osNames[osByte] || 'Unix'}`,
      mime: 'application/gzip',
      category: 'Archive / Compressed',
      extensions: ['gz', 'tgz', 'tar.gz', 'svgz'],
      magicOffset: 0,
      magicLength: 3,
      confidence: 'Exact',
      details: [
        `Compression Method: Deflate (0x08)`,
        `Origin OS: ${osNames[osByte] || `OS byte 0x${osByte.toString(16)}`}`,
        ...(origName ? [`Embedded Original Filename: "${origName}"`] : [])
      ]
    };
  }

  // 17. BZIP2 (42 5A 68)
  if (matchBytes(bytes, [0x42, 0x5A, 0x68]) && bytes[3] >= 0x31 && bytes[3] <= 0x39) {
    const blockSize = String.fromCharCode(bytes[3]) + '00k';
    return {
      name: 'BZIP2 Compressed Data',
      libmagicText: `bzip2 compressed data, block size = ${blockSize}`,
      mime: 'application/x-bzip2',
      category: 'Archive / Compressed',
      extensions: ['bz2', 'tbz2', 'tar.bz2'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: [`BZh header with block size ${blockSize}`]
    };
  }

  // 18. XZ Compressed Data (FD 37 7A 58 5A 00)
  if (matchBytes(bytes, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])) {
    return {
      name: 'XZ Compressed Data (LZMA2)',
      libmagicText: 'XZ compressed data',
      mime: 'application/x-xz',
      category: 'Archive / Compressed',
      extensions: ['xz', 'txz', 'tar.xz'],
      magicOffset: 0,
      magicLength: 6,
      confidence: 'Exact',
      details: ['XZ stream header magic: FD 37 7A 58 5A 00']
    };
  }

  // 19. Zstandard (28 B5 2F FD)
  if (matchBytes(bytes, [0x28, 0xB5, 0x2F, 0xFD])) {
    return {
      name: 'Zstandard Compressed Data (zstd)',
      libmagicText: 'Zstandard compressed data (v0.8+)',
      mime: 'application/zstd',
      category: 'Archive / Compressed',
      extensions: ['zst', 'tzst'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['Zstandard frame magic: 28 B5 2F FD']
    };
  }

  // 20. POSIX TAR Archive ("ustar" at offset 257)
  if (bytes.length > 262 && matchBytes(bytes, [0x75, 0x73, 0x74, 0x61, 0x72], 257)) {
    const firstFile = readAscii(bytes, 0, 100).replace(/\.+$/, '');
    return {
      name: 'POSIX TAR Tape Archive',
      libmagicText: 'POSIX tar archive (ustar)',
      mime: 'application/x-tar',
      category: 'Archive',
      extensions: ['tar', 'ova'],
      magicOffset: 257,
      magicLength: 5,
      confidence: 'Exact',
      details: [`Found "ustar" magic at offset 257 (0x101)`, ...(firstFile ? [`First member: ${firstFile}`] : [])]
    };
  }

  // 21. SQLite 3 Database ("SQLite format 3\0")
  if (matchBytes(bytes, [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00])) {
    let pageSize = readUInt16BE(bytes, 16);
    if (pageSize === 1) pageSize = 65536;
    const encVal = readUInt32BE(bytes, 56);
    const encMap = { 1: 'UTF-8', 2: 'UTF-16le', 3: 'UTF-16be' };
    return {
      name: 'SQLite 3.x Database',
      libmagicText: `SQLite 3.x database, page size ${pageSize}, ${encMap[encVal] || 'UTF-8'}`,
      mime: 'application/vnd.sqlite3',
      category: 'Database',
      extensions: ['sqlite', 'sqlite3', 'db', 'db3'],
      magicOffset: 0,
      magicLength: 16,
      confidence: 'Exact',
      details: [`Page Size: ${pageSize} bytes`, `Text Encoding: ${encMap[encVal] || 'UTF-8'}`]
    };
  }

  // 22. Apache Parquet (PAR1)
  if (matchBytes(bytes, [0x50, 0x41, 0x52, 0x31])) {
    return {
      name: 'Apache Parquet Columnar Data',
      libmagicText: 'Apache Parquet columnar storage format',
      mime: 'application/vnd.apache.parquet',
      category: 'Database / Analytics',
      extensions: ['parquet', 'pq'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['Parquet magic header: PAR1 (50 41 52 31)']
    };
  }

  // 23. Windows Bitmap (BM)
  if (matchBytes(bytes, [0x42, 0x4D]) && bytes.length >= 26) {
    const dibSize = readUInt32LE(bytes, 14);
    if ([12, 40, 52, 56, 108, 124].includes(dibSize)) {
      const w = dibSize === 12 ? readUInt16LE(bytes, 18) : readUInt32LE(bytes, 18);
      const h = dibSize === 12 ? readUInt16LE(bytes, 20) : Math.abs(readUInt32LE(bytes, 22) | 0);
      const bpp = dibSize === 12 ? readUInt16LE(bytes, 24) : readUInt16LE(bytes, 28);
      return {
        name: 'Windows Bitmap Image (BMP)',
        libmagicText: `PC bitmap, Windows 3.x/NT format, ${w} x ${h} x ${bpp}`,
        mime: 'image/bmp',
        category: 'Image',
        extensions: ['bmp', 'dib'],
        magicOffset: 0,
        magicLength: 2,
        confidence: 'Exact',
        details: [`Dimensions: ${w} × ${h} px, ${bpp} bits/pixel`, `DIB Header Size: ${dibSize} bytes`]
      };
    }
  }

  // 24. TIFF Image (Little-Endian II*\0 or Big-Endian MM\0*)
  if (matchBytes(bytes, [0x49, 0x49, 0x2A, 0x00]) || matchBytes(bytes, [0x4D, 0x4D, 0x00, 0x2A])) {
    const isLE = bytes[0] === 0x49;
    return {
      name: `TIFF Image (${isLE ? 'Little-Endian' : 'Big-Endian'})`,
      libmagicText: `TIFF image data, ${isLE ? 'little-endian, direntries' : 'big-endian'}`,
      mime: 'image/tiff',
      category: 'Image',
      extensions: ['tif', 'tiff', 'dng', 'nef', 'cr2'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: [`Byte Order: ${isLE ? 'Intel Little-Endian (II)' : 'Motorola Big-Endian (MM)'}`]
    };
  }

  // 25. Adobe Photoshop (8BPS)
  if (matchBytes(bytes, [0x38, 0x42, 0x50, 0x53])) {
    const h = readUInt32BE(bytes, 14);
    const w = readUInt32BE(bytes, 18);
    const channels = readUInt16BE(bytes, 12);
    return {
      name: 'Adobe Photoshop Document (PSD)',
      libmagicText: `Adobe Photoshop Image, ${w} x ${h}, ${channels} channels`,
      mime: 'image/vnd.adobe.photoshop',
      category: 'Image / Design',
      extensions: ['psd', 'psb'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: [`Dimensions: ${w} × ${h} px, Channels: ${channels}`]
    };
  }

  // 26. Windows Icon (ICO) & Cursor (CUR)
  if (matchBytes(bytes, [0x00, 0x00, 0x01, 0x00]) && bytes.length >= 6) {
    const count = readUInt16LE(bytes, 4);
    if (count > 0 && count < 256) {
      return {
        name: 'MS Windows Icon Resource (ICO)',
        libmagicText: `MS Windows icon resource - ${count} icon(s)`,
        mime: 'image/x-icon',
        category: 'Image / Icon',
        extensions: ['ico'],
        magicOffset: 0,
        magicLength: 4,
        confidence: 'Exact',
        details: [`Contains ${count} icon image directory entry/entries`]
      };
    }
  }

  // 27. Audio: FLAC (fLaC)
  if (matchBytes(bytes, [0x66, 0x4C, 0x61, 0x43])) {
    return {
      name: 'FLAC Lossless Audio',
      libmagicText: 'FLAC audio bitstream data',
      mime: 'audio/flac',
      category: 'Audio',
      extensions: ['flac'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['Signature: fLaC (66 4C 61 43)']
    };
  }

  // 28. Audio: MP3 with ID3v2 tag or MPEG Sync word
  if (matchBytes(bytes, [0x49, 0x44, 0x33])) {
    const maj = bytes[3];
    const rev = bytes[4];
    return {
      name: `MP3 Audio (with ID3v2.${maj}.${rev} Tag)`,
      libmagicText: `Audio file with ID3 version 2.${maj}.${rev}, contains: MPEG ADTS, layer III`,
      mime: 'audio/mpeg',
      category: 'Audio',
      extensions: ['mp3'],
      magicOffset: 0,
      magicLength: 3,
      confidence: 'Exact',
      details: [`ID3v2.${maj}.${rev} metadata header present`]
    };
  }
  if (bytes.length >= 4 && bytes[0] === 0xFF && (bytes[1] === 0xFB || bytes[1] === 0xF3 || bytes[1] === 0xF2)) {
    return {
      name: 'MP3 Audio (MPEG Layer III Frame Sync)',
      libmagicText: 'MPEG ADTS, layer III, v1/v2 audio stream',
      mime: 'audio/mpeg',
      category: 'Audio',
      extensions: ['mp3'],
      magicOffset: 0,
      magicLength: 2,
      confidence: 'High',
      details: ['MPEG Audio Frame Sync detected at offset 0']
    };
  }

  // 29. Ogg Container (OggS)
  if (matchBytes(bytes, [0x4F, 0x67, 0x67, 0x53])) {
    const rawSample = readRawString(bytes, 0, Math.min(bytes.length, 256));
    let codec = 'Ogg Multiplexed Media';
    let ext = ['ogg', 'oga', 'ogv', 'opus'];
    if (rawSample.includes('OpusHead')) {
      codec = 'Ogg Opus Audio';
      ext = ['opus', 'ogg'];
    } else if (rawSample.includes('vorbis')) {
      codec = 'Ogg Vorbis Audio';
      ext = ['ogg', 'oga'];
    } else if (rawSample.includes('theora')) {
      codec = 'Ogg Theora Video';
      ext = ['ogv', 'ogg'];
    }
    return {
      name: codec,
      libmagicText: `Ogg data, ${codec}`,
      mime: 'application/ogg',
      category: 'Audio / Video',
      extensions: ext,
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: [`OggS capture pattern detected (${codec})`]
    };
  }

  // 30. Matroska / WebM (1A 45 DF A3)
  if (matchBytes(bytes, [0x1A, 0x45, 0xDF, 0xA3])) {
    const rawSample = readRawString(bytes, 0, Math.min(bytes.length, 256));
    const isWebM = rawSample.includes('webm');
    return {
      name: isWebM ? 'WebM Video/Audio Container' : 'Matroska Multimedia Container (MKV)',
      libmagicText: isWebM ? 'WebM video/audio media' : 'Matroska data (MKV)',
      mime: isWebM ? 'video/webm' : 'video/x-matroska',
      category: 'Video / Audio',
      extensions: isWebM ? ['webm'] : ['mkv', 'mka', 'mks'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: [`EBML Header 1A 45 DF A3, DocType: ${isWebM ? 'webm' : 'matroska'}`]
    };
  }

  // 31. MIDI Audio (MThd)
  if (matchBytes(bytes, [0x4D, 0x54, 0x68, 0x64])) {
    return {
      name: 'Standard MIDI Audio (MID)',
      libmagicText: 'Standard MIDI data',
      mime: 'audio/midi',
      category: 'Audio',
      extensions: ['mid', 'midi', 'kar'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['MThd header chunk detected']
    };
  }

  // 32. Fonts: WOFF, WOFF2, OTF, TTF
  if (matchBytes(bytes, [0x77, 0x4F, 0x46, 0x46])) {
    return {
      name: 'Web Open Font Format 1.0 (WOFF)',
      libmagicText: 'Web Open Font Format (WOFF), Version 1',
      mime: 'font/woff',
      category: 'Font',
      extensions: ['woff'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['Signature: wOFF']
    };
  }
  if (matchBytes(bytes, [0x77, 0x4F, 0x46, 0x32])) {
    return {
      name: 'Web Open Font Format 2.0 (WOFF2)',
      libmagicText: 'Web Open Font Format (WOFF2)',
      mime: 'font/woff2',
      category: 'Font',
      extensions: ['woff2'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['Signature: wOF2']
    };
  }
  if (matchBytes(bytes, [0x4F, 0x54, 0x54, 0x4F])) {
    return {
      name: 'OpenType Font (OTF)',
      libmagicText: 'OpenType font data (CFF/OTTO)',
      mime: 'font/otf',
      category: 'Font',
      extensions: ['otf'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['Signature: OTTO (4F 54 54 4F)']
    };
  }
  if (matchBytes(bytes, [0x00, 0x01, 0x00, 0x00, 0x00])) {
    return {
      name: 'TrueType Font (TTF)',
      libmagicText: 'TrueType Font data',
      mime: 'font/ttf',
      category: 'Font',
      extensions: ['ttf', 'ttc'],
      magicOffset: 0,
      magicLength: 5,
      confidence: 'Exact',
      details: ['TrueType sfnt version 1.0 header']
    };
  }

  // 33. RTF Document ({\rtf)
  if (matchBytes(bytes, [0x7B, 0x5C, 0x72, 0x74, 0x66])) {
    return {
      name: 'Rich Text Format Document (RTF)',
      libmagicText: 'Rich Text Format data, version 1',
      mime: 'application/rtf',
      category: 'Document',
      extensions: ['rtf'],
      magicOffset: 0,
      magicLength: 5,
      confidence: 'Exact',
      details: ['Signature: {\\rtf']
    };
  }

  // 34. PCAP / PCAPNG Network Captures
  if (matchBytes(bytes, [0xD4, 0xC3, 0xB2, 0xA1]) || matchBytes(bytes, [0xA1, 0xB2, 0xC3, 0xD4])) {
    return {
      name: 'Libpcap Network Packet Capture (PCAP)',
      libmagicText: 'pcap capture file',
      mime: 'application/vnd.tcpdump.pcap',
      category: 'Network / Forensics',
      extensions: ['pcap', 'cap', 'dmp'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['Standard libpcap magic header']
    };
  }
  if (matchBytes(bytes, [0x0A, 0x0D, 0x0D, 0x0A])) {
    return {
      name: 'PCAP Next Generation Packet Capture (PCAPNG)',
      libmagicText: 'pcapng capture file - version 1.0',
      mime: 'application/x-pcapng',
      category: 'Network / Forensics',
      extensions: ['pcapng', 'ntar'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['PCAP-NG Section Header Block (0A 0D 0D 0A)']
    };
  }

  // 35. Text, Code & Structured Format Heuristics (like libmagic text tests)
  return inspectTextOrBinaryFallback(bytes);
}

/**
 * Text / Source Code / Structured Data Heuristic Analyzer
 */
function inspectTextOrBinaryFallback(bytes) {
  let bomInfo = null;
  let textOffset = 0;

  if (matchBytes(bytes, [0xEF, 0xBB, 0xBF])) {
    bomInfo = 'UTF-8 with BOM (EF BB BF)';
    textOffset = 3;
  } else if (matchBytes(bytes, [0xFF, 0xFE, 0x00, 0x00])) {
    return {
      name: 'UTF-32 (Little-Endian) Text Document',
      libmagicText: 'Unicode text, UTF-32, little-endian',
      mime: 'text/plain',
      category: 'Text',
      extensions: ['txt', 'log', 'csv'],
      magicOffset: 0,
      magicLength: 4,
      confidence: 'Exact',
      details: ['UTF-32 LE Byte Order Mark (FF FE 00 00)']
    };
  } else if (matchBytes(bytes, [0xFF, 0xFE])) {
    return {
      name: 'UTF-16 (Little-Endian) Text Document',
      libmagicText: 'Unicode text, UTF-16, little-endian text',
      mime: 'text/plain',
      category: 'Text',
      extensions: ['txt', 'log', 'ini', 'reg'],
      magicOffset: 0,
      magicLength: 2,
      confidence: 'Exact',
      details: ['UTF-16 LE Byte Order Mark (FF FE)']
    };
  } else if (matchBytes(bytes, [0xFE, 0xFF])) {
    return {
      name: 'UTF-16 (Big-Endian) Text Document',
      libmagicText: 'Unicode text, UTF-16, big-endian text',
      mime: 'text/plain',
      category: 'Text',
      extensions: ['txt', 'log'],
      magicOffset: 0,
      magicLength: 2,
      confidence: 'Exact',
      details: ['UTF-16 BE Byte Order Mark (FE FF)']
    };
  }

  // Check if sample bytes look like valid UTF-8 / ASCII text
  const checkLen = Math.min(bytes.length, 8192);
  let nullBytes = 0;
  let controlBytes = 0;
  for (let i = textOffset; i < checkLen; i++) {
    const b = bytes[i];
    if (b === 0) nullBytes++;
    else if (b < 9 || (b > 13 && b < 32 && b !== 27)) controlBytes++;
  }

  const isLikelyText = nullBytes === 0 && (controlBytes / Math.max(1, checkLen - textOffset)) < 0.02;

  if (!isLikelyText) {
    const entropy = calculateEntropy(bytes);
    const highEntropy = entropy > 7.4;
    return {
      name: highEntropy ? 'Encrypted, Compressed, or Packed Binary Data' : 'Unknown / Raw Binary Data',
      libmagicText: `data (${highEntropy ? 'high entropy compressed/encrypted stream' : 'arbitrary binary data'})`,
      mime: 'application/octet-stream',
      category: 'Binary Data',
      extensions: ['bin', 'dat', 'raw'],
      magicOffset: 0,
      magicLength: Math.min(bytes.length, 4),
      confidence: 'Heuristic',
      details: [
        `Contains ${nullBytes} null byte(s) in first ${checkLen} bytes`,
        `Shannon Entropy: ${entropy.toFixed(3)} bits/byte ${highEntropy ? '(Very High — suggests encryption or compression)' : '(Moderate — structured binary)'}`
      ]
    };
  }

  // Decode text sample
  let textSample = '';
  try {
    textSample = new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(textOffset, Math.min(bytes.length, 16384)));
  } catch (e) {
    textSample = readAscii(bytes, textOffset, Math.min(bytes.length, 16384));
  }

  const trimmed = textSample.trimStart();
  const encodingLabel = bomInfo || 'UTF-8 / ASCII text';

  // Detect line endings
  const hasCRLF = textSample.includes('\r\n');
  const lineEndingDesc = hasCRLF ? 'with CRLF line terminators' : 'with LF line terminators';

  // 1. Shebang scripts (#!)
  if (textSample.startsWith('#!')) {
    const firstLine = textSample.split(/\r?\n/)[0];
    let scriptType = 'Executable Script';
    let ext = ['sh'];
    if (firstLine.includes('python')) { scriptType = 'Python Script'; ext = ['py']; }
    else if (firstLine.includes('node') || firstLine.includes('deno') || firstLine.includes('bun')) { scriptType = 'JavaScript / Node.js Script'; ext = ['js', 'mjs']; }
    else if (firstLine.includes('bash') || firstLine.includes('/sh') || firstLine.includes('zsh')) { scriptType = 'POSIX / Bash Shell Script'; ext = ['sh', 'bash', 'zsh']; }
    else if (firstLine.includes('perl')) { scriptType = 'Perl Script'; ext = ['pl']; }
    else if (firstLine.includes('ruby')) { scriptType = 'Ruby Script'; ext = ['rb']; }
    else if (firstLine.includes('php')) { scriptType = 'PHP Script'; ext = ['php']; }

    return {
      name: `${scriptType} (Shebang)`,
      libmagicText: `${scriptType}, ${firstLine}, ${encodingLabel}, ${lineEndingDesc}`,
      mime: 'text/x-script',
      category: 'Script / Code',
      extensions: ext,
      isExecutable: true,
      magicOffset: textOffset,
      magicLength: Math.min(firstLine.length, 16),
      confidence: 'Exact',
      details: [`Interpreter directive: ${firstLine}`, `Encoding: ${encodingLabel} (${lineEndingDesc})`]
    };
  }

  // 2. Cryptographic PEM / PGP / SSH keys
  if (trimmed.startsWith('-----BEGIN ')) {
    const headerLine = trimmed.split(/\r?\n/)[0];
    return {
      name: `PEM Cryptographic Key / Certificate (${headerLine.replace(/-----/g, '').trim()})`,
      libmagicText: `PEM cryptographic data (${headerLine}), ${encodingLabel}`,
      mime: 'application/x-pem-file',
      category: 'Security / Crypto',
      extensions: ['pem', 'crt', 'cer', 'key', 'pub', 'asc'],
      magicOffset: textOffset,
      magicLength: 11,
      confidence: 'Exact',
      details: [`Armor Header: ${headerLine}`]
    };
  }

  // 3. SVG Vector Image
  if ((trimmed.startsWith('<?xml') || trimmed.startsWith('<svg') || trimmed.startsWith('<!DOCTYPE svg')) && /<svg[\s>]/i.test(trimmed)) {
    return {
      name: 'Scalable Vector Graphics (SVG)',
      libmagicText: `SVG Scalable Vector Graphics image, ${encodingLabel}`,
      mime: 'image/svg+xml',
      category: 'Image / Vector',
      extensions: ['svg'],
      magicOffset: textOffset,
      magicLength: 5,
      confidence: 'Exact',
      details: ['Detected <svg> root element in XML/text stream']
    };
  }

  // 4. HTML Document
  if (/^<!DOCTYPE\s+html/i.test(trimmed) || /^<html[\s>]/i.test(trimmed) || (/<head[\s>]/i.test(trimmed) && /<body[\s>]/i.test(trimmed))) {
    return {
      name: 'HTML Document',
      libmagicText: `HTML document, ${encodingLabel}, ${lineEndingDesc}`,
      mime: 'text/html',
      category: 'Web / Document',
      extensions: ['html', 'htm', 'xhtml'],
      magicOffset: textOffset,
      magicLength: Math.min(15, bytes.length),
      confidence: 'Exact',
      details: [`Encoding: ${encodingLabel}, ${lineEndingDesc}`]
    };
  }

  // 5. XML Document
  if (trimmed.startsWith('<?xml ')) {
    return {
      name: 'XML Document',
      libmagicText: `XML 1.0 document, ${encodingLabel}, ${lineEndingDesc}`,
      mime: 'application/xml',
      category: 'Data / Markup',
      extensions: ['xml', 'plist', 'xsd', 'Pom', 'csproj', 'rss', 'atom', 'kml'],
      magicOffset: textOffset,
      magicLength: 6,
      confidence: 'Exact',
      details: [`XML declaration header <?xml ...?>`, `Encoding: ${encodingLabel}`]
    };
  }

  // 6. JSON Document
  if ((trimmed.startsWith('{') || trimmed.startsWith('[')) && /["{}:\[\]]/.test(trimmed)) {
    let validJson = false;
    try {
      if (bytes.length <= 16384) {
        JSON.parse(trimmed);
        validJson = true;
      } else {
        validJson = /^\s*(\{\s*"[^"]+"\s*:|\[\s*(\{|"|\d|true|false|null))/.test(trimmed);
      }
    } catch (e) {
      validJson = /^\s*\{\s*"[^"]+"\s*:/.test(trimmed);
    }
    if (validJson) {
      return {
        name: 'JSON Data Document',
        libmagicText: `JSON text data, ${encodingLabel}, ${lineEndingDesc}`,
        mime: 'application/json',
        category: 'Data / Config',
        extensions: ['json', 'geojson', 'har', 'ipynb', 'map', 'webmanifest'],
        magicOffset: textOffset,
        magicLength: 1,
        confidence: 'High',
        details: [`Valid JSON structure detected (${encodingLabel})`]
      };
    }
  }

  // 7. Source code & configuration heuristics
  if (/^\s*(import\s+[\w{*\s,]+from\s+['"]|export\s+(default|const|function|class)|const\s+\w+\s*=|function\s+\w+\s*\()/m.test(trimmed)) {
    return {
      name: 'JavaScript / TypeScript Source Code',
      libmagicText: `JavaScript/TypeScript source, ${encodingLabel}, ${lineEndingDesc}`,
      mime: 'text/javascript',
      category: 'Source Code',
      extensions: ['js', 'ts', 'jsx', 'tsx', 'mjs', 'cjs'],
      magicOffset: textOffset,
      magicLength: 0,
      confidence: 'Heuristic',
      details: [`ES/CommonJS syntax keywords detected (${encodingLabel})`]
    };
  }

  if (/^\s*(def\s+\w+\s*\(|import\s+\w+|from\s+[\w.]+\s+import\s+|if\s+__name__\s*==\s*['"]__main__['"])/m.test(trimmed)) {
    return {
      name: 'Python Source Code',
      libmagicText: `Python script, ${encodingLabel} executable, ${lineEndingDesc}`,
      mime: 'text/x-python',
      category: 'Source Code',
      extensions: ['py', 'pyw', 'pyi'],
      magicOffset: textOffset,
      magicLength: 0,
      confidence: 'Heuristic',
      details: [`Python syntax keywords detected (${encodingLabel})`]
    };
  }

  if (/^\s*#include\s*[<"][\w./]+[>"]|^\s*int\s+main\s*\(/m.test(trimmed)) {
    return {
      name: 'C / C++ Source Code',
      libmagicText: `C or C++ source, ${encodingLabel}, ${lineEndingDesc}`,
      mime: 'text/x-c',
      category: 'Source Code',
      extensions: ['c', 'cpp', 'cc', 'h', 'hpp'],
      magicOffset: textOffset,
      magicLength: 0,
      confidence: 'Heuristic',
      details: [`C/C++ preprocessor / main signature detected`]
    };
  }

  // 8. CSV / Tabular Data heuristic
  const lines = trimmed.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length >= 2) {
    const commaCount0 = (lines[0].match(/,/g) || []).length;
    const commaCount1 = (lines[1].match(/,/g) || []).length;
    if (commaCount0 >= 2 && commaCount0 === commaCount1) {
      return {
        name: `CSV Tabular Text (${commaCount0 + 1} columns)`,
        libmagicText: `CSV text, ${commaCount0 + 1} columns, ${encodingLabel}, ${lineEndingDesc}`,
        mime: 'text/csv',
        category: 'Data / Spreadsheet',
        extensions: ['csv'],
        magicOffset: textOffset,
        magicLength: 0,
        confidence: 'Heuristic',
        details: [`Consistent comma-delimited rows (${commaCount0 + 1} columns per row)`]
      };
    }
  }

  return {
    name: 'Plain Text Document (UTF-8 / ASCII)',
    libmagicText: `${encodingLabel}, ${lineEndingDesc}`,
    mime: 'text/plain',
    category: 'Text',
    extensions: ['txt', 'md', 'log', 'conf', 'ini', 'yaml', 'yml', 'env', 'csv'],
    magicOffset: textOffset,
    magicLength: bomInfo ? 3 : 0,
    confidence: 'Heuristic',
    details: [`Encoding: ${encodingLabel}`, `Line Endings: ${hasCRLF ? 'CRLF (Windows)' : 'LF (Unix/macOS)'}`]
  };
}

// ============================================================================
// 4. Extension Spoofing & Mismatch Verification
// ============================================================================

function evaluateExtensionMatch(fileName, detectionResult) {
  const parts = fileName.toLowerCase().split('.');
  const hasExtension = parts.length > 1 && parts[parts.length - 1].length > 0;
  const actualExt = hasExtension ? parts[parts.length - 1] : '';
  const secondExt = parts.length > 2 ? parts[parts.length - 2] : '';

  const expectedExts = (detectionResult.extensions || []).map(e => e.toLowerCase());

  if (expectedExts.length === 0) {
    return {
      status: 'neutral',
      badge: 'No Extension Rule',
      message: 'This file format does not enforce a strict file extension.'
    };
  }

  // Check for double-extension masquerading (e.g., invoice.pdf.exe)
  const docOrMediaExts = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif', 'txt', 'mp3', 'mp4', 'zip'];
  if (detectionResult.isExecutable && secondExt && docOrMediaExts.includes(secondExt)) {
    return {
      status: 'danger',
      badge: 'Double-Extension Spoofing Alert!',
      message: `High risk! Filename uses a deceptive double extension (.${secondExt}.${actualExt}) while its actual contents are an executable (${detectionResult.name}).`
    };
  }

  if (!hasExtension) {
    return {
      status: 'warning',
      badge: 'Missing File Extension',
      message: `File has no extension. Based on its internal magic bytes, it should end with .${expectedExts[0]}.`,
      suggestedExtension: `.${expectedExts[0]}`
    };
  }

  if (expectedExts.includes(actualExt)) {
    return {
      status: 'match',
      badge: 'Verified Extension Match',
      message: `The file extension (.${actualExt}) matches the internal magic signature (${detectionResult.name}).`
    };
  }

  // If executable disguised as non-executable extension
  if (detectionResult.isExecutable && !['exe', 'dll', 'elf', 'bin', 'so', 'sh', 'py', 'js', 'class', 'wasm', 'apk', 'scr', 'com'].includes(actualExt)) {
    return {
      status: 'danger',
      badge: 'Extension Spoofing Detected!',
      message: `Warning! This file is named ".${actualExt}", but its binary header proves it is actually a ${detectionResult.name} (expected .${expectedExts[0]}).`,
      suggestedExtension: `.${expectedExts[0]}`
    };
  }

  return {
    status: 'warning',
    badge: 'Extension Mismatch',
    message: `File is named ".${actualExt}", but its internal contents identify as ${detectionResult.name} (expected: ${expectedExts.map(e => '.' + e).join(', ')}).`,
    suggestedExtension: `.${expectedExts[0]}`
  };
}

// ============================================================================
// 5. Built-in Test Samples (So User Can Test Immediately)
// ============================================================================

const BUILTIN_SAMPLES = {
  png_valid: {
    fileName: 'sample-logo.png',
    description: 'Genuine 512×512 RGBA PNG Header',
    bytes: new Uint8Array([
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG Magic
      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
      0x00, 0x00, 0x02, 0x00, // Width: 512
      0x00, 0x00, 0x02, 0x00, // Height: 512
      0x08, 0x06, 0x00, 0x00, 0x00, // 8-bit RGBA, non-interlaced
      0xF4, 0x78, 0xD4, 0xFA, 0x00, 0x00, 0x00, 0x00,
      0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
    ])
  },
  spoofed_exe: {
    fileName: 'urgent-invoice.pdf',
    description: 'Spoofed! Named .pdf but contains a 64-bit Windows PE Executable',
    bytes: (() => {
      const buf = new Uint8Array(256);
      // MZ header
      buf[0] = 0x4D; buf[1] = 0x5A;
      buf[2] = 0x90;
      const dosStub = 'This program cannot be run in DOS mode.';
      for (let i = 0; i < dosStub.length; i++) buf[0x40 + i] = dosStub.charCodeAt(i);
      // e_lfanew at 0x3C pointing to 0x80
      buf[0x3C] = 0x80;
      // PE\0\0 at 0x80
      buf[0x80] = 0x50; buf[0x81] = 0x45; buf[0x82] = 0x00; buf[0x83] = 0x00;
      // Machine = 0x8664 (AMD64)
      buf[0x84] = 0x64; buf[0x85] = 0x86;
      // NumberOfSections = 5
      buf[0x86] = 0x05; buf[0x87] = 0x00;
      // Characteristics = Executable (0x0022)
      buf[0x96] = 0x22; buf[0x97] = 0x00;
      // Optional Header Magic = 0x020B (PE32+ 64-bit)
      buf[0x98] = 0x0B; buf[0x99] = 0x02;
      // Subsystem at 0x98 + 68 = 0xDC -> 2 (Windows GUI)
      buf[0xDC] = 0x02; buf[0xDD] = 0x00;
      return buf;
    })()
  },
  docx_in_zip: {
    fileName: 'quarterly-report.docx',
    description: 'ZIP-based OOXML Word Document (dissected from PK\\x03\\x04)',
    bytes: (() => {
      const header = [
        0x50, 0x4B, 0x03, 0x04, // PK\x03\x04
        0x14, 0x00, // version 2.0
        0x00, 0x00, // flags
        0x08, 0x00, // Deflate
        0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x13, 0x00, 0x00, 0x00
      ];
      const text = '[Content_Types].xmlPK\x03\x04word/document.xml';
      const arr = new Uint8Array(header.length + text.length);
      arr.set(header, 0);
      for (let i = 0; i < text.length; i++) arr[header.length + i] = text.charCodeAt(i);
      return arr;
    })()
  },
  renamed_pdf: {
    fileName: 'mystery-download.dat',
    description: 'Unknown .dat file that is actually an Encrypted PDF v1.7',
    bytes: new TextEncoder().encode(
      '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Linearized 1 /Encrypt 5 0 R >>\nendobj\n%%EOF'
    )
  },
  elf_binary: {
    fileName: 'server-daemon',
    description: 'Extensionless Linux 64-bit ELF Executable (x86-64)',
    bytes: new Uint8Array([
      0x7F, 0x45, 0x4C, 0x46, // \x7FELF
      0x02, // 64-bit
      0x01, // Little endian
      0x01, // ELF v1
      0x03, // GNU/Linux ABI
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x03, 0x00, // PIE executable / shared object
      0x3E, 0x00, // x86-64
      0x01, 0x00, 0x00, 0x00,
      0x40, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])
  }
};

// ============================================================================
// 6. Extension Renamer, Binary/ZIP Exporter & Multi-File UI Controller (v1.3.0)
// ============================================================================

let analyzedItems = [];
let activeFilter = 'all';
let allCollapsed = false;

/**
 * Replaces or appends the true file extension on a filename.
 * Example: "1 (33).jpg" + "mp4" -> "1 (33).mp4"
 * Example: "server-daemon" + "elf" -> "server-daemon.elf"
 */
function buildCorrectedFileName(fileName, targetExt) {
  const cleanExt = String(targetExt || '').replace(/^\.+/, '').trim();
  if (!cleanExt) return fileName;

  const lastSlash = Math.max(fileName.lastIndexOf('/'), fileName.lastIndexOf('\\'));
  const dirPrefix = lastSlash >= 0 ? fileName.slice(0, lastSlash + 1) : '';
  const baseName = lastSlash >= 0 ? fileName.slice(lastSlash + 1) : fileName;

  const lastDot = baseName.lastIndexOf('.');
  if (lastDot > 0) {
    return `${dirPrefix}${baseName.slice(0, lastDot)}.${cleanExt}`;
  }
  return `${dirPrefix}${baseName}.${cleanExt}`;
}

function getDownloadBaseName(filePath) {
  const lastSlash = Math.max(filePath.lastIndexOf('/'), filePath.lastIndexOf('\\'));
  return lastSlash >= 0 ? filePath.slice(lastSlash + 1) : filePath;
}

function triggerBlobDownload(blob, downloadFileName) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = getDownloadBaseName(downloadFileName);
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

/**
 * Standard CRC-32 calculation for creating valid PKZIP archives in-browser.
 */
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32Bytes(uint8Arr) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < uint8Arr.length; i++) {
    crc = CRC32_TABLE[(crc ^ uint8Arr[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

/**
 * Creates a standard uncompressed (STORE) .zip Blob from an array of { name, blob } items.
 */
async function createZipArchiveBlob(fileEntries) {
  const encoder = new TextEncoder();
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const usedNames = new Set();

  for (const entry of fileEntries) {
    let safeName = getDownloadBaseName(entry.name || 'file.bin');
    if (usedNames.has(safeName.toLowerCase())) {
      const dotIdx = safeName.lastIndexOf('.');
      const stem = dotIdx > 0 ? safeName.slice(0, dotIdx) : safeName;
      const ext = dotIdx > 0 ? safeName.slice(dotIdx) : '';
      let counter = 2;
      while (usedNames.has(`${stem}_${counter}${ext}`.toLowerCase())) counter++;
      safeName = `${stem}_${counter}${ext}`;
    }
    usedNames.add(safeName.toLowerCase());

    const nameBytes = encoder.encode(safeName);
    const dataBuffer = await entry.blob.arrayBuffer();
    const dataBytes = new Uint8Array(dataBuffer);
    const crc = crc32Bytes(dataBytes);
    const size = dataBytes.length;

    // Local File Header (30 bytes + filename)
    const localHeader = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(localHeader.buffer);
    lv.setUint32(0, 0x04034B50, true); // PK\x03\x04
    lv.setUint16(4, 20, true);         // Version needed (2.0)
    lv.setUint16(6, 0x0800, true);     // UTF-8 filename flag
    lv.setUint16(8, 0, true);          // Store (0 = no compression)
    lv.setUint16(10, 0, true);         // Mod time
    lv.setUint16(12, 0x2100, true);    // Mod date
    lv.setUint32(14, crc, true);       // CRC-32
    lv.setUint32(18, size, true);      // Compressed size
    lv.setUint32(22, size, true);      // Uncompressed size
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);
    localHeader.set(nameBytes, 30);

    // Central Directory Header (46 bytes + filename)
    const centralHeader = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(centralHeader.buffer);
    cv.setUint32(0, 0x02014B50, true); // PK\x01\x02
    cv.setUint16(4, 20, true);         // Version made by
    cv.setUint16(6, 20, true);         // Version needed
    cv.setUint16(8, 0x0800, true);     // UTF-8 flag
    cv.setUint16(10, 0, true);         // Store
    cv.setUint16(12, 0, true);
    cv.setUint16(14, 0x2100, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, size, true);
    cv.setUint32(24, size, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true);
    cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);    // Relative offset of local header
    centralHeader.set(nameBytes, 46);

    localParts.push(localHeader, dataBytes);
    centralParts.push(centralHeader);
    offset += localHeader.length + size;
  }

  const centralDirSize = centralParts.reduce((acc, arr) => acc + arr.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054B50, true); // PK\x05\x06
  ev.setUint16(4, 0, true);
  ev.setUint16(6, 0, true);
  ev.setUint16(8, fileEntries.length, true);
  ev.setUint16(10, fileEntries.length, true);
  ev.setUint32(12, centralDirSize, true);
  ev.setUint32(16, offset, true);
  ev.setUint16(20, 0, true);

  return new Blob([...localParts, ...centralParts, eocd], { type: 'application/zip' });
}

document.addEventListener('DOMContentLoaded', () => {
  const versionBadge = document.getElementById('app-version-badge');
  if (versionBadge) versionBadge.textContent = APP_VERSION;

  const footerVersion = document.getElementById('footer-version');
  if (footerVersion) footerVersion.textContent = APP_VERSION;

  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const folderInput = document.getElementById('folder-input');
  const browseBtn = document.getElementById('browse-btn');
  const browseFolderBtn = document.getElementById('browse-folder-btn');
  const addMoreBtn = document.getElementById('add-more-btn');
  const toggleCollapseBtn = document.getElementById('toggle-collapse-btn');
  const exportJsonBtn = document.getElementById('export-json-btn');
  const selectAllCheckbox = document.getElementById('select-all-checkbox');
  const selectMismatchedBtn = document.getElementById('select-mismatched-btn');
  const fixSelectedExtBtn = document.getElementById('fix-selected-ext-btn');
  const exportSelectedFilesBtn = document.getElementById('export-selected-files-btn');
  const exportSelectedZipBtn = document.getElementById('export-selected-zip-btn');
  const uploadStatusHint = document.getElementById('upload-status-hint');
  const batchSummaryBar = document.getElementById('batch-summary-bar');
  const filterBtns = document.querySelectorAll('.batch-filter-btn');
  const resultsContainer = document.getElementById('results-container');
  const clearBtn = document.getElementById('clear-btn');
  const sampleButtons = document.querySelectorAll('[data-sample]');
  const sampleAllBtn = document.getElementById('sample-all-btn');
  const signatureSearch = document.getElementById('sig-search');
  const sigTableBody = document.getElementById('sig-table-body');

  browseBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  if (browseFolderBtn && folderInput) {
    browseFolderBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      folderInput.click();
    });
  }

  if (addMoreBtn) {
    addMoreBtn.addEventListener('click', () => fileInput.click());
  }

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-active');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-active');
  });

  dropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-active');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await handleFiles(Array.from(e.dataTransfer.files));
    }
  });

  fileInput.addEventListener('change', async (e) => {
    if (e.target.files && e.target.files.length > 0) {
      await handleFiles(Array.from(e.target.files));
      fileInput.value = '';
    }
  });

  if (folderInput) {
    folderInput.addEventListener('change', async (e) => {
      if (e.target.files && e.target.files.length > 0) {
        await handleFiles(Array.from(e.target.files));
        folderInput.value = '';
      }
    });
  }

  clearBtn.addEventListener('click', () => {
    analyzedItems = [];
    resultsContainer.innerHTML = '';
    resultsContainer.classList.add('hidden');
    clearBtn.classList.add('hidden');
    if (batchSummaryBar) batchSummaryBar.classList.add('hidden');
    if (selectAllCheckbox) selectAllCheckbox.checked = false;
    if (uploadStatusHint) {
      uploadStatusHint.innerHTML = 'Tip: Hold <kbd>Ctrl</kbd> / <kbd>Shift</kbd> (or <kbd>Cmd</kbd>) in the file picker to select multiple files at once, or drag &amp; drop any number of files together.';
    }
  });

  // Select All Checkbox
  if (selectAllCheckbox) {
    selectAllCheckbox.addEventListener('change', () => {
      const checked = selectAllCheckbox.checked;
      analyzedItems.forEach(item => {
        const isVisible = activeFilter === 'all' || item.status === activeFilter;
        if (isVisible) {
          setRecordSelected(item, checked);
        }
      });
      updateBatchSummaryCounts();
    });
  }

  // Select Mismatched / Spoofed Only
  if (selectMismatchedBtn) {
    selectMismatchedBtn.addEventListener('click', () => {
      let count = 0;
      analyzedItems.forEach(item => {
        const shouldSelect = item.status !== 'match';
        setRecordSelected(item, shouldSelect);
        if (shouldSelect) count++;
      });
      updateBatchSummaryCounts();
      if (uploadStatusHint) {
        uploadStatusHint.textContent = count > 0
          ? `🎯 Selected ${count} file(s) with extension mismatch or spoofing alerts.`
          : `✅ All uploaded files already have matching extensions!`;
      }
    });
  }

  // Bulk Fix Extension for Selected Files
  if (fixSelectedExtBtn) {
    fixSelectedExtBtn.addEventListener('click', () => {
      const targets = getTargetRecordsForAction();
      if (targets.length === 0) return;
      let changedCount = 0;
      targets.forEach(item => {
        if (applyTrueExtensionToRecord(item, item.targetExt)) {
          changedCount++;
        }
      });
      updateBatchSummaryCounts();
      applyBatchFilter();
      if (uploadStatusHint) {
        uploadStatusHint.textContent = `✏️ Updated ${changedCount} file(s) to their true detected extension! Click "Export Selected Files" or "Export Selected as ZIP" to download them.`;
      }
    });
  }

  // Bulk Export Selected Files Directly (Renamed to True Extension)
  if (exportSelectedFilesBtn) {
    exportSelectedFilesBtn.addEventListener('click', async () => {
      const targets = getTargetRecordsForAction();
      if (targets.length === 0) return;

      for (let i = 0; i < targets.length; i++) {
        const item = targets[i];
        applyTrueExtensionToRecord(item, item.targetExt);
        exportSingleRecordFile(item);
        if (targets.length > 1) {
          await new Promise(r => setTimeout(r, 180));
        }
      }
      updateBatchSummaryCounts();
      if (uploadStatusHint) {
        uploadStatusHint.textContent = `⬇️ Exported ${targets.length} file(s) with their true extensions.`;
      }
    });
  }

  // Bulk Export Selected Files as a Single ZIP Archive (Renamed to True Extension)
  if (exportSelectedZipBtn) {
    exportSelectedZipBtn.addEventListener('click', async () => {
      const targets = getTargetRecordsForAction();
      if (targets.length === 0) return;

      const entries = [];
      for (const item of targets) {
        applyTrueExtensionToRecord(item, item.targetExt);
        entries.push({
          name: item.fileName,
          blob: item.rawBlob
        });
      }
      updateBatchSummaryCounts();

      const zipBlob = await createZipArchiveBlob(entries);
      triggerBlobDownload(zipBlob, `FileID-Fixed-Files-${APP_VERSION}-${Date.now()}.zip`);
      if (uploadStatusHint) {
        uploadStatusHint.textContent = `📦 Exported ${entries.length} renamed file(s) inside ZIP archive!`;
      }
    });
  }

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      activeFilter = btn.getAttribute('data-filter') || 'all';
      filterBtns.forEach(b => b.classList.toggle('active', b === btn));
      applyBatchFilter();
    });
  });

  if (toggleCollapseBtn) {
    toggleCollapseBtn.addEventListener('click', () => {
      allCollapsed = !allCollapsed;
      toggleCollapseBtn.textContent = allCollapsed ? 'Expand All' : 'Collapse All';
      analyzedItems.forEach(item => {
        item.cardElement.classList.toggle('collapsed', allCollapsed);
        const btn = item.cardElement.querySelector('.collapse-card-btn');
        if (btn) btn.textContent = allCollapsed ? '▸ Expand' : '▾ Collapse';
      });
    });
  }

  if (exportJsonBtn) {
    exportJsonBtn.addEventListener('click', () => {
      if (analyzedItems.length === 0) return;
      const selectedOnly = analyzedItems.filter(i => i.selected);
      const listToExport = selectedOnly.length > 0 ? selectedOnly : analyzedItems;
      const report = {
        app: 'FileID — Magic-Byte File Type Identifier & Spoofing Analyzer',
        appVersion: APP_VERSION,
        developedBy: APP_AUTHOR,
        exportedAt: new Date().toISOString(),
        totalFiles: listToExport.length,
        summary: {
          verifiedMatch: listToExport.filter(i => i.status === 'match').length,
          mismatches: listToExport.filter(i => i.status === 'warning').length,
          spoofingAlerts: listToExport.filter(i => i.status === 'danger').length
        },
        files: listToExport.map(i => ({
          originalFileName: i.originalFileName,
          currentFileName: i.fileName,
          trueSuggestedFileName: buildCorrectedFileName(i.originalFileName, i.targetExt),
          renamedToTrueExtension: i.renamed,
          fileSize: i.fileSize,
          status: i.status,
          statusBadge: i.statusBadge,
          detectedFormat: i.detectedName,
          mimeType: i.mime,
          category: i.category,
          confidence: i.confidence,
          libmagicSummary: i.libmagicText,
          entropyBitsPerByte: Number(i.entropy.toFixed(3)),
          sha256: i.sha256
        }))
      };
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      triggerBlobDownload(blob, `fileid-report-${APP_VERSION}-${Date.now()}.json`);
    });
  }

  sampleButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const key = btn.getAttribute('data-sample');
      const sample = BUILTIN_SAMPLES[key];
      if (!sample) return;
      await renderSampleKey(key, true);
    });
  });

  if (sampleAllBtn) {
    sampleAllBtn.addEventListener('click', async () => {
      const keys = Object.keys(BUILTIN_SAMPLES).reverse();
      for (const key of keys) {
        await renderSampleKey(key, false);
      }
      if (uploadStatusHint) {
        uploadStatusHint.textContent = `✅ Loaded all 5 built-in demo samples in multi-file batch mode • Total files in queue: ${analyzedItems.length}`;
      }
    });
  }

  async function renderSampleKey(key, scrollIntoViewFlag = true) {
    const sample = BUILTIN_SAMPLES[key];
    if (!sample) return;
    resultsContainer.classList.remove('hidden');
    clearBtn.classList.remove('hidden');
    if (batchSummaryBar) batchSummaryBar.classList.remove('hidden');

    const sampleBlob = new Blob([sample.bytes], { type: 'application/octet-stream' });
    const record = await analyzeBufferAndRender(
      sample.fileName,
      sample.bytes.length,
      new Date(),
      sample.bytes.buffer,
      true,
      sample.description,
      null,
      sampleBlob
    );
    registerAnalyzedRecord(record);
    resultsContainer.prepend(record.cardElement);
    if (scrollIntoViewFlag) {
      record.cardElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  if (signatureSearch && sigTableBody) {
    signatureSearch.addEventListener('input', () => {
      const q = signatureSearch.value.toLowerCase().trim();
      const rows = sigTableBody.querySelectorAll('tr');
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(q) ? '' : 'none';
      });
    });
  }

  async function handleFiles(files) {
    if (!files || files.length === 0) return;
    resultsContainer.classList.remove('hidden');
    clearBtn.classList.remove('hidden');
    if (batchSummaryBar) batchSummaryBar.classList.remove('hidden');

    const total = files.length;
    const batchRecords = [];

    for (let idx = 0; idx < total; idx++) {
      const file = files[idx];
      const displayName = file.webkitRelativePath || file.name;
      if (uploadStatusHint) {
        uploadStatusHint.textContent = `⏳ Analyzing file ${idx + 1} of ${total}: "${displayName}"...`;
      }

      // Read first 128 KB for instant magic & container inspection, and up to 25 MB for SHA-256
      const sliceSize = Math.min(file.size, 131072);
      const headerBuffer = await file.slice(0, sliceSize).arrayBuffer();
      const hashBuffer = file.size <= 25 * 1024 * 1024 ? await file.arrayBuffer() : null;

      const record = await analyzeBufferAndRender(
        displayName,
        file.size,
        file.lastModified ? new Date(file.lastModified) : null,
        headerBuffer,
        false,
        null,
        hashBuffer,
        file
      );
      batchRecords.push(record);
    }

    // Prepend in reverse so the first selected file in the batch stays at the very top
    for (let i = batchRecords.length - 1; i >= 0; i--) {
      registerAnalyzedRecord(batchRecords[i]);
      resultsContainer.prepend(batchRecords[i].cardElement);
    }

    if (uploadStatusHint) {
      uploadStatusHint.textContent = `✅ Successfully analyzed ${total} uploaded file${total > 1 ? 's' : ''} in batch • Total files in queue: ${analyzedItems.length}`;
    }
  }
});

/**
 * Returns user-selected records; if none are checked, defaults to all visible records.
 */
function getTargetRecordsForAction() {
  const selected = analyzedItems.filter(i => i.selected);
  if (selected.length > 0) return selected;
  return analyzedItems.filter(i => activeFilter === 'all' || i.status === activeFilter);
}

function setRecordSelected(record, isSelected) {
  record.selected = Boolean(isSelected);
  record.cardElement.classList.toggle('card-selected', record.selected);
  const cb = record.cardElement.querySelector('.file-select-checkbox');
  if (cb) cb.checked = record.selected;
}

/**
 * Renames a record's filename to use its true detected extension (`chosenExt`),
 * re-evaluates its extension verification status, and updates the card UI in-place.
 */
function applyTrueExtensionToRecord(record, chosenExt) {
  const extToUse = chosenExt || record.targetExt || (record.detection.extensions && record.detection.extensions[0]) || '';
  if (!extToUse) return false;

  record.targetExt = extToUse;
  const newFileName = buildCorrectedFileName(record.originalFileName, extToUse);
  record.fileName = newFileName;
  record.renamed = (newFileName !== record.originalFileName);

  const extCheck = evaluateExtensionMatch(record.fileName, record.detection);
  record.status = extCheck.status;
  record.statusBadge = extCheck.badge;

  const card = record.cardElement;
  card.classList.remove('status-match', 'status-warning', 'status-danger', 'status-neutral');
  card.classList.add(`status-${extCheck.status}`);
  card.dataset.status = extCheck.status;

  const titleEl = card.querySelector('.file-name');
  if (titleEl) titleEl.textContent = record.fileName;

  const renamedTagEl = card.querySelector('.renamed-tag');
  if (renamedTagEl) {
    if (record.renamed) {
      renamedTagEl.textContent = `✓ Renamed from ${getDownloadBaseName(record.originalFileName)}`;
      renamedTagEl.classList.remove('hidden');
    } else {
      renamedTagEl.classList.add('hidden');
    }
  }

  const iconBadge = card.querySelector('.file-icon-badge');
  if (iconBadge) iconBadge.textContent = extToUse.toUpperCase().slice(0, 4);

  const statusBadgeEl = card.querySelector('.ext-status-badge');
  if (statusBadgeEl) {
    statusBadgeEl.className = `ext-status-badge badge-${extCheck.status}`;
    statusBadgeEl.innerHTML = `<span class="status-dot"></span>${escapeHtml(extCheck.badge)}`;
  }

  const alertBox = card.querySelector('.spoof-alert');
  if (alertBox) {
    alertBox.className = `spoof-alert alert-${extCheck.status}`;
    alertBox.innerHTML = `<div class="spoof-alert-text"><strong>Extension Check:</strong> ${escapeHtml(extCheck.message)}</div>`;
  }

  const termPrompt = card.querySelector('.terminal-prompt');
  if (termPrompt) {
    termPrompt.textContent = `$ file --Keep-going "${record.fileName}"`;
  }

  const currentNameEl = card.querySelector('.fixer-current-name');
  if (currentNameEl) {
    currentNameEl.textContent = getDownloadBaseName(record.fileName);
    currentNameEl.classList.toggle('name-valid', extCheck.status === 'match');
  }

  const newNameEl = card.querySelector('.fixer-new-name');
  if (newNameEl) {
    newNameEl.textContent = getDownloadBaseName(newFileName);
  }

  const applyBtn = card.querySelector('.btn-apply-ext');
  if (applyBtn) {
    applyBtn.textContent = record.renamed ? `✓ Extension Updated (.${extToUse})` : `✏️ Change to .${extToUse}`;
  }

  const exportSingleBtn = card.querySelector('.btn-export-single');
  if (exportSingleBtn) {
    exportSingleBtn.textContent = `⬇️ Export "${getDownloadBaseName(newFileName)}"`;
  }

  return true;
}

/**
 * Exports/downloads a single file with its true extension applied.
 */
function exportSingleRecordFile(record) {
  const correctedName = buildCorrectedFileName(record.originalFileName, record.targetExt);
  const outBlob = new Blob([record.rawBlob], { type: record.mime || 'application/octet-stream' });
  triggerBlobDownload(outBlob, correctedName);
}

function registerAnalyzedRecord(record) {
  analyzedItems.unshift(record);
  updateBatchSummaryCounts();
  applyBatchFilter();
}

function removeAnalyzedRecord(recordId) {
  const idx = analyzedItems.findIndex(item => item.id === recordId);
  if (idx !== -1) {
    const [removed] = analyzedItems.splice(idx, 1);
    if (removed && removed.cardElement) {
      removed.cardElement.remove();
    }
  }
  updateBatchSummaryCounts();
  applyBatchFilter();

  const resultsContainer = document.getElementById('results-container');
  const clearBtn = document.getElementById('clear-btn');
  const batchSummaryBar = document.getElementById('batch-summary-bar');
  if (analyzedItems.length === 0) {
    if (resultsContainer) resultsContainer.classList.add('hidden');
    if (clearBtn) clearBtn.classList.add('hidden');
    if (batchSummaryBar) batchSummaryBar.classList.add('hidden');
  }
}

function updateBatchSummaryCounts() {
  const countAll = document.getElementById('count-all');
  const countMatch = document.getElementById('count-match');
  const countWarning = document.getElementById('count-warning');
  const countDanger = document.getElementById('count-danger');
  const selectedBadge = document.getElementById('selected-count-badge');
  const fixSelectedCount = document.getElementById('fix-selected-count');
  const exportSelectedCount = document.getElementById('export-selected-count');
  const exportZipCount = document.getElementById('export-zip-count');
  const selectAllCheckbox = document.getElementById('select-all-checkbox');

  const selectedCount = analyzedItems.filter(i => i.selected).length;
  const actionCount = selectedCount > 0 ? selectedCount : analyzedItems.length;

  if (countAll) countAll.textContent = analyzedItems.length;
  if (countMatch) countMatch.textContent = analyzedItems.filter(i => i.status === 'match').length;
  if (countWarning) countWarning.textContent = analyzedItems.filter(i => i.status === 'warning').length;
  if (countDanger) countDanger.textContent = analyzedItems.filter(i => i.status === 'danger').length;

  if (selectedBadge) selectedBadge.textContent = `${selectedCount} Selected`;
  if (fixSelectedCount) fixSelectedCount.textContent = actionCount;
  if (exportSelectedCount) exportSelectedCount.textContent = actionCount;
  if (exportZipCount) exportZipCount.textContent = actionCount;

  if (selectAllCheckbox) {
    selectAllCheckbox.checked = analyzedItems.length > 0 && selectedCount === analyzedItems.length;
    selectAllCheckbox.indeterminate = selectedCount > 0 && selectedCount < analyzedItems.length;
  }
}

function applyBatchFilter() {
  analyzedItems.forEach(item => {
    const visible = activeFilter === 'all' || item.status === activeFilter;
    item.cardElement.classList.toggle('hidden', !visible);
  });
}

async function analyzeBufferAndRender(fileName, fileSize, lastModified, headerArrayBuffer, isSample = false, sampleNote = null, fullArrayBufferForHash = null, rawBlob = null) {
  const bytes = new Uint8Array(headerArrayBuffer);
  const detection = detectFileSignature(bytes);
  const extCheck = evaluateExtensionMatch(fileName, detection);
  const entropy = calculateEntropy(bytes);
  const sha256 = await computeSHA256(fullArrayBufferForHash || headerArrayBuffer);
  const recordId = `file-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const validExtensions = (detection.extensions && detection.extensions.length > 0)
    ? detection.extensions
    : ['bin'];
  const defaultTargetExt = validExtensions[0];
  const suggestedFileName = buildCorrectedFileName(fileName, defaultTargetExt);
  const autoSelected = extCheck.status !== 'match'; // Auto-select mismatched/spoofed files for quick fixing

  const magicHex = detection.magicLength > 0
    ? toHex(bytes, detection.magicOffset, Math.min(detection.magicLength, 16))
    : toHex(bytes, 0, Math.min(bytes.length, 8));

  const magicAscii = detection.magicLength > 0
    ? readAscii(bytes, detection.magicOffset, Math.min(detection.magicLength, 16))
    : readAscii(bytes, 0, Math.min(bytes.length, 8));

  // Build Hex Dump rows (first 64 bytes = 4 rows of 16 bytes)
  const hexDumpRowsHtml = buildHexPreviewHtml(bytes, detection.magicOffset, detection.magicLength);

  const card = document.createElement('article');
  card.className = `result-card status-${extCheck.status}${allCollapsed ? ' collapsed' : ''}${autoSelected ? ' card-selected' : ''}`;
  card.dataset.status = extCheck.status;

  const expectedExtPills = (detection.extensions && detection.extensions.length > 0)
    ? detection.extensions.map(ext => `<span class="ext-pill">.${escapeHtml(ext)}</span>`).join('')
    : '<span class="ext-pill muted">none</span>';

  const extOptionsHtml = validExtensions
    .map((ext, i) => `<option value="${escapeHtml(ext)}"${i === 0 ? ' selected' : ''}>.${escapeHtml(ext)}${i === 0 ? ' (Primary)' : ''}</option>`)
    .join('');

  const detailsListHtml = (detection.details || [])
    .map(d => `<li>${escapeHtml(d)}</li>`)
    .join('');

  card.innerHTML = `
    <div class="result-header">
      <div class="file-title-group">
        <input type="checkbox" class="file-select-checkbox" title="Select file for batch extension change or export" ${autoSelected ? 'checked' : ''} />
        <div class="file-icon-badge">${escapeHtml((defaultTargetExt || 'BIN').toUpperCase().slice(0, 4))}</div>
        <div>
          <div class="file-name-row">
            <h3 class="file-name">${escapeHtml(fileName)}</h3>
            <span class="renamed-tag hidden"></span>
            ${isSample ? `<span class="sample-tag">Built-in Sample</span>` : ''}
          </div>
          <p class="file-meta">
            ${formatBytes(fileSize)}
            ${lastModified ? ` • Modified ${lastModified.toLocaleString()}` : ''}
            ${sampleNote ? ` • <em>${escapeHtml(sampleNote)}</em>` : ''}
          </p>
        </div>
      </div>
      <div class="card-header-right">
        <div class="ext-status-badge badge-${extCheck.status}">
          <span class="status-dot"></span>
          ${escapeHtml(extCheck.badge)}
        </div>
        <button type="button" class="card-icon-btn collapse-card-btn" title="Collapse or expand file details">${allCollapsed ? '▸ Expand' : '▾ Collapse'}</button>
        <button type="button" class="card-icon-btn remove-card-btn" title="Remove this file from results">✕</button>
      </div>
    </div>

    <div class="card-body-collapsible">
      <!-- Toolsley / Unix 'file' command output banner -->
      <div class="libmagic-banner">
        <div class="banner-top">
          <span class="terminal-prompt">$ file --Keep-going "${escapeHtml(fileName)}"</span>
          <button class="copy-btn" type="button" title="Copy identification result">Copy Result</button>
        </div>
        <div class="libmagic-output">
          <strong>${escapeHtml(detection.name)}</strong> — <span>${escapeHtml(detection.libmagicText)}</span>
        </div>
      </div>

      <!-- Extension Spoofing / Verification Alert Box -->
      <div class="spoof-alert alert-${extCheck.status}">
        <div class="spoof-alert-text">
          <strong>Extension Check:</strong> ${escapeHtml(extCheck.message)}
        </div>
      </div>

      <!-- Extension Fixer & Single-File Export Bar -->
      <div class="extension-fixer-bar">
        <div class="fixer-info">
          <span class="fixer-label">True Extension Fixer:</span>
          <span class="fixer-current-name ${extCheck.status === 'match' ? 'name-valid' : ''}">${escapeHtml(getDownloadBaseName(fileName))}</span>
          <span class="fixer-arrow">→</span>
          <label class="sr-only" for="ext-select-${recordId}">Choose Target Extension</label>
          <select id="ext-select-${recordId}" class="ext-target-select" title="Select true extension for this file">
            ${extOptionsHtml}
          </select>
          <span class="fixer-new-name">${escapeHtml(getDownloadBaseName(suggestedFileName))}</span>
        </div>
        <div class="fixer-actions">
          <button type="button" class="btn-apply-ext" title="Change this file's extension name to its true format">
            ✏️ Change to .${escapeHtml(defaultTargetExt)}
          </button>
          <button type="button" class="btn-export-single" title="Export / download this file renamed with its true extension">
            ⬇️ Export "${escapeHtml(getDownloadBaseName(suggestedFileName))}"
          </button>
        </div>
      </div>

      <!-- Core Metrics Grid -->
      <div class="metrics-grid">
        <div class="metric-box">
          <span class="metric-label">Detected Format</span>
          <span class="metric-value highlight">${escapeHtml(detection.name)}</span>
        </div>
        <div class="metric-box">
          <span class="metric-label">MIME Type</span>
          <span class="metric-value mono">${escapeHtml(detection.mime)}</span>
        </div>
        <div class="metric-box">
          <span class="metric-label">Category & Confidence</span>
          <span class="metric-value">${escapeHtml(detection.category)} <small class="conf-tag">(${escapeHtml(detection.confidence)})</small></span>
        </div>
        <div class="metric-box">
          <span class="metric-label">Valid Extensions</span>
          <div class="ext-pills-wrap">${expectedExtPills}</div>
        </div>
        <div class="metric-box">
          <span class="metric-label">Magic Signature (Offset 0x${detection.magicOffset.toString(16).toUpperCase()})</span>
          <span class="metric-value mono">${escapeHtml(magicHex || 'N/A')} <span class="ascii-inline">(${escapeHtml(magicAscii)})</span></span>
        </div>
        <div class="metric-box">
          <span class="metric-label">Shannon Entropy</span>
          <span class="metric-value">${entropy.toFixed(3)} / 8.000 bits/byte</span>
        </div>
      </div>

      <!-- Deep Container & Header Insights -->
      <div class="inspector-columns">
        <div class="inspector-panel">
          <h4>Deep Header & Container Analysis</h4>
          <ul class="details-list">
            ${detailsListHtml}
            ${sha256 ? `<li class="hash-item"><strong>SHA-256:</strong> <code>${sha256}</code></li>` : `<li class="hash-item"><strong>SHA-256 (first 128KB sample):</strong> <code>${await computeSHA256(headerArrayBuffer)}</code></li>`}
          </ul>
        </div>

        <div class="inspector-panel">
          <div class="hex-panel-header">
            <h4>Raw Header Hex Inspector (First 64 Bytes)</h4>
            <span class="hex-legend"><span class="legend-swatch"></span> Highlighted = Matched Magic Bytes</span>
          </div>
          <div class="hex-dump-table" role="region" aria-label="Hexadecimal header preview">
            ${hexDumpRowsHtml}
          </div>
        </div>
      </div>
    </div>
  `;

  const record = {
    id: recordId,
    originalFileName: fileName,
    fileName,
    fileSize,
    targetExt: defaultTargetExt,
    renamed: false,
    selected: autoSelected,
    status: extCheck.status,
    statusBadge: extCheck.badge,
    detection,
    detectedName: detection.name,
    mime: detection.mime,
    category: detection.category,
    confidence: detection.confidence,
    libmagicText: detection.libmagicText,
    entropy,
    sha256,
    isSample,
    rawBlob: rawBlob || new Blob([headerArrayBuffer], { type: detection.mime || 'application/octet-stream' }),
    cardElement: card
  };

  // Checkbox selection listener
  const selectCb = card.querySelector('.file-select-checkbox');
  selectCb.addEventListener('change', () => {
    setRecordSelected(record, selectCb.checked);
    updateBatchSummaryCounts();
  });

  // Target extension dropdown listener
  const extSelect = card.querySelector('.ext-target-select');
  extSelect.addEventListener('change', () => {
    record.targetExt = extSelect.value;
    const previewName = getDownloadBaseName(buildCorrectedFileName(record.originalFileName, record.targetExt));
    const newNameEl = card.querySelector('.fixer-new-name');
    const applyBtn = card.querySelector('.btn-apply-ext');
    const exportSingleBtn = card.querySelector('.btn-export-single');
    if (newNameEl) newNameEl.textContent = previewName;
    if (applyBtn) applyBtn.textContent = `✏️ Change to .${record.targetExt}`;
    if (exportSingleBtn) exportSingleBtn.textContent = `⬇️ Export "${previewName}"`;
  });

  // Single-item Change Extension button
  const applyExtBtn = card.querySelector('.btn-apply-ext');
  applyExtBtn.addEventListener('click', () => {
    applyTrueExtensionToRecord(record, record.targetExt);
    updateBatchSummaryCounts();
    applyBatchFilter();
  });

  // Single-item Export / Download button
  const exportSingleBtn = card.querySelector('.btn-export-single');
  exportSingleBtn.addEventListener('click', () => {
    applyTrueExtensionToRecord(record, record.targetExt);
    exportSingleRecordFile(record);
    updateBatchSummaryCounts();
    applyBatchFilter();
  });

  const copyBtn = card.querySelector('.copy-btn');
  copyBtn.addEventListener('click', () => {
    const summaryText = `${record.fileName}: ${detection.libmagicText} [MIME: ${detection.mime}]`;
    navigator.clipboard.writeText(summaryText).then(() => {
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy Result'; }, 1800);
    });
  });

  const collapseBtn = card.querySelector('.collapse-card-btn');
  collapseBtn.addEventListener('click', () => {
    const isCollapsed = card.classList.toggle('collapsed');
    collapseBtn.textContent = isCollapsed ? '▸ Expand' : '▾ Collapse';
  });

  const removeBtn = card.querySelector('.remove-card-btn');
  removeBtn.addEventListener('click', () => {
    removeAnalyzedRecord(recordId);
  });

  return record;
}

function buildHexPreviewHtml(bytes, magicOffset, magicLength) {
  const maxBytes = Math.min(bytes.length, 64);
  if (maxBytes === 0) {
    return `<div class="hex-empty">0 bytes (empty file)</div>`;
  }

  let html = '';
  const magicEnd = magicOffset + magicLength;

  for (let rowStart = 0; rowStart < maxBytes; rowStart += 16) {
    const offsetHex = rowStart.toString(16).padStart(4, '0').toUpperCase();
    let hexCells = '';
    let asciiCells = '';

    for (let i = 0; i < 16; i++) {
      const idx = rowStart + i;
      if (idx < maxBytes) {
        const b = bytes[idx];
        const isMagic = magicLength > 0 && idx >= magicOffset && idx < magicEnd;
        const hexStr = b.toString(16).padStart(2, '0').toUpperCase();
        const ch = (b >= 32 && b <= 126) ? escapeHtml(String.fromCharCode(b)) : '·';
        hexCells += `<span class="hb ${isMagic ? 'magic-hl' : ''}">${hexStr}</span>`;
        asciiCells += `<span class="ab ${isMagic ? 'magic-hl' : ''}">${ch}</span>`;
      } else {
        hexCells += `<span class="hb empty">  </span>`;
        asciiCells += `<span class="ab empty"> </span>`;
      }
    }

    html += `
      <div class="hex-row">
        <span class="hex-offset">0x${offsetHex}</span>
        <span class="hex-bytes">${hexCells}</span>
        <span class="hex-ascii">${asciiCells}</span>
      </div>
    `;
  }
  return html;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
