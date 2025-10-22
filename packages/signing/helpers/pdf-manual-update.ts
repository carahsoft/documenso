import { logger } from '@documenso/lib/utils/logger';

/**
 * Add DSS to signed PDF using completely manual PDF writing
 *
 * This approach doesn't use pdf-lib's serialization at all - we write
 * raw PDF syntax to ensure nothing gets corrupted.
 */
export function addDSSManually(
  originalPdf: Buffer,
  certificates: Buffer[],
  ocspResponses: Buffer[],
  signatureHash: string | null,
  moduleName = 'ltv',
): Buffer {
  try {
    logger.info({ module: moduleName }, 'Starting manual DSS addition');

    // Parse original PDF to find key information
    const pdfStr = originalPdf.toString('latin1');

    // Find the last xref offset
    const startxrefMatch = pdfStr.match(/startxref\s+(\d+)\s+%%EOF\s*$/);
    if (!startxrefMatch) {
      throw new Error('Could not find startxref in original PDF');
    }
    const prevXrefOffset = parseInt(startxrefMatch[1], 10);

    // Find the catalog object reference in trailer
    const trailerMatch = pdfStr.match(/trailer\s*<<[^>]*\/Root\s+(\d+)\s+(\d+)\s+R/);
    if (!trailerMatch) {
      throw new Error('Could not find Root reference in trailer');
    }
    const catalogObjNum = parseInt(trailerMatch[1], 10);
    const catalogGenNum = parseInt(trailerMatch[2], 10);

    // Find the highest object number
    let maxObjNum = catalogObjNum;
    const objMatches = pdfStr.matchAll(/^(\d+)\s+\d+\s+obj/gm);
    for (const match of objMatches) {
      const objNum = parseInt(match[1], 10);
      if (objNum > maxObjNum) {
        maxObjNum = objNum;
      }
    }

    // Start assigning new object numbers
    let nextObjNum = maxObjNum + 1;

    logger.info(
      {
        module: moduleName,
        prevXref: prevXrefOffset,
        catalogObj: catalogObjNum,
        nextObj: nextObjNum,
      },
      'Parsed PDF structure',
    );

    // Find the original catalog content
    const catalogPattern = new RegExp(
      `${catalogObjNum}\\s+${catalogGenNum}\\s+obj\\s*([\\s\\S]*?)\\s*endobj`,
      'm',
    );
    const catalogMatch = pdfStr.match(catalogPattern);
    if (!catalogMatch) {
      throw new Error('Could not find catalog object');
    }
    const originalCatalogContent = catalogMatch[1].trim();

    logger.info({ module: moduleName }, 'Found original catalog');

    // Build the new objects
    const chunks: Buffer[] = [];
    const xrefEntries = new Map<number, number>();
    let currentOffset = originalPdf.length;

    // Ensure we start on a new line
    if (originalPdf[originalPdf.length - 1] !== 0x0a) {
      chunks.push(Buffer.from('\n', 'latin1'));
      currentOffset += 1;
    }

    // Write certificate streams
    const certObjNums: number[] = [];
    for (const cert of certificates) {
      const objNum = nextObjNum++;
      certObjNums.push(objNum);
      xrefEntries.set(objNum, currentOffset);

      const streamContent = cert.toString('latin1');
      const objContent = `${objNum} 0 obj\n<<\n/Length ${streamContent.length}\n>>\nstream\n${streamContent}\nendstream\nendobj\n`;
      const objBuf = Buffer.from(objContent, 'latin1');
      chunks.push(objBuf);
      currentOffset += objBuf.length;
    }

    logger.info({ module: moduleName, certCount: certObjNums.length }, 'Wrote certificate streams');

    // Write OCSP streams
    const ocspObjNums: number[] = [];
    for (const ocsp of ocspResponses) {
      const objNum = nextObjNum++;
      ocspObjNums.push(objNum);
      xrefEntries.set(objNum, currentOffset);

      const streamContent = ocsp.toString('latin1');
      const objContent = `${objNum} 0 obj\n<<\n/Length ${streamContent.length}\n>>\nstream\n${streamContent}\nendstream\nendobj\n`;
      const objBuf = Buffer.from(objContent, 'latin1');
      chunks.push(objBuf);
      currentOffset += objBuf.length;
    }

    logger.info({ module: moduleName, ocspCount: ocspObjNums.length }, 'Wrote OCSP streams');

    // TEMPORARILY SKIP VRI to test if it's causing signature invalidation
    // Write VRI dictionary (if we have a signature hash)
    // DISABLED FOR TESTING
    // let vriObjNum: number | null = null;
    // if (signatureHash && certObjNums.length > 0 && ocspObjNums.length > 0) {
    //   vriObjNum = nextObjNum++;
    //   xrefEntries.set(vriObjNum, currentOffset);

    //   const vriEntryObjNum = nextObjNum++;

    //   // VRI entry for this signature
    //   const certRefs = certObjNums.map((n) => `${n} 0 R`).join(' ');
    //   const ocspRefs = ocspObjNums.map((n) => `${n} 0 R`).join(' ');
    //   const now = new Date();
    //   const timestamp = `D:${now.getUTCFullYear()}${String(now.getUTCMonth() + 1).padStart(2, '0')}${String(now.getUTCDate()).padStart(2, '0')}${String(now.getUTCHours()).padStart(2, '0')}${String(now.getUTCMinutes()).padStart(2, '0')}${String(now.getUTCSeconds()).padStart(2, '0')}+00'00'`;

    //   const vriEntryContent = `${vriEntryObjNum} 0 obj\n<<\n/Cert [ ${certRefs} ]\n/OCSP [ ${ocspRefs} ]\n/TU (${timestamp})\n>>\nendobj\n`;
    //   xrefEntries.set(vriEntryObjNum, currentOffset);

    //   const vriContent = `${vriObjNum} 0 obj\n<<\n/${signatureHash} ${vriEntryObjNum} 0 R\n>>\nendobj\n`;

    //   // Write VRI entry first, then VRI dict
    //   const vriEntryBuf = Buffer.from(vriEntryContent, 'latin1');
    //   chunks.push(vriEntryBuf);
    //   currentOffset += vriEntryBuf.length;

    //   const vriBuf = Buffer.from(vriContent, 'latin1');
    //   chunks.push(vriBuf);
    //   currentOffset += vriBuf.length;

    //   logger.info({ module: moduleName, signatureHash }, 'Wrote VRI dictionary');
    // }

    logger.info({ module: moduleName }, 'SKIPPING VRI for diagnostic testing');

    // Write DSS dictionary (without VRI for now)
    const dssObjNum = nextObjNum++;
    xrefEntries.set(dssObjNum, currentOffset);

    const certRefs = certObjNums.map((n) => `${n} 0 R`).join(' ');
    const ocspRefs = ocspObjNums.map((n) => `${n} 0 R`).join(' ');
    let dssContent = `${dssObjNum} 0 obj\n<<\n`;
    if (certObjNums.length > 0) {
      dssContent += `/Certs [ ${certRefs} ]\n`;
    }
    if (ocspObjNums.length > 0) {
      dssContent += `/OCSPs [ ${ocspRefs} ]\n`;
    }
    // VRI DISABLED FOR TESTING
    // if (vriObjNum) {
    //   dssContent += `/VRI ${vriObjNum} 0 R\n`;
    // }
    dssContent += `>>\nendobj\n`;

    const dssBuf = Buffer.from(dssContent, 'latin1');
    chunks.push(dssBuf);
    currentOffset += dssBuf.length;

    logger.info({ module: moduleName, dssObj: dssObjNum }, 'Wrote DSS dictionary');

    // Write new catalog with DSS reference
    xrefEntries.set(catalogObjNum, currentOffset);

    // Parse original catalog to add DSS
    let newCatalogContent = originalCatalogContent;
    // Remove the closing >> if present
    newCatalogContent = newCatalogContent.replace(/>>$/, '').trim();
    // Add DSS reference
    newCatalogContent += `\n/DSS ${dssObjNum} 0 R\n>>`;

    const catalogContent = `${catalogObjNum} ${catalogGenNum} obj\n${newCatalogContent}\nendobj\n`;
    const catalogBuf = Buffer.from(catalogContent, 'latin1');
    chunks.push(catalogBuf);
    currentOffset += catalogBuf.length;

    logger.info({ module: moduleName }, 'Wrote updated catalog');

    // Write xref table
    const xrefOffset = currentOffset;
    const xrefHeader = 'xref\n';
    chunks.push(Buffer.from(xrefHeader, 'latin1'));
    currentOffset += xrefHeader.length;

    // Sort entries
    const sortedEntries = Array.from(xrefEntries.entries()).sort((a, b) => a[0] - b[0]);

    // Group into subsections
    const subsections: Array<{ start: number; entries: Array<[number, number]> }> = [];
    let currentSubsection: Array<[number, number]> = [];
    let subsectionStart = sortedEntries[0][0];

    for (const [objNum, offset] of sortedEntries) {
      if (currentSubsection.length === 0) {
        subsectionStart = objNum;
        currentSubsection.push([objNum, offset]);
      } else {
        const prevObjNum = currentSubsection[currentSubsection.length - 1][0];
        if (objNum === prevObjNum + 1) {
          currentSubsection.push([objNum, offset]);
        } else {
          subsections.push({ start: subsectionStart, entries: currentSubsection });
          subsectionStart = objNum;
          currentSubsection = [[objNum, offset]];
        }
      }
    }
    if (currentSubsection.length > 0) {
      subsections.push({ start: subsectionStart, entries: currentSubsection });
    }

    // Write subsections
    for (const subsection of subsections) {
      const header = `${subsection.start} ${subsection.entries.length}\n`;
      chunks.push(Buffer.from(header, 'latin1'));
      currentOffset += header.length;

      for (const [, offset] of subsection.entries) {
        const entry = `${offset.toString().padStart(10, '0')} 00000 n \n`;
        chunks.push(Buffer.from(entry, 'latin1'));
        currentOffset += entry.length;
      }
    }

    // Write trailer
    const totalSize = nextObjNum;
    const trailer = `trailer\n<<\n/Size ${totalSize}\n/Root ${catalogObjNum} ${catalogGenNum} R\n/Prev ${prevXrefOffset}\n>>\nstartxref\n${xrefOffset}\n%%EOF\n`;
    chunks.push(Buffer.from(trailer, 'latin1'));

    // Combine everything
    const result = Buffer.concat([originalPdf, ...chunks]);

    logger.info(
      {
        module: moduleName,
        originalSize: originalPdf.length,
        newSize: result.length,
        addedBytes: result.length - originalPdf.length,
      },
      'Manual DSS addition completed',
    );

    return result;
  } catch (error) {
    logger.error(
      { module: moduleName, error: error instanceof Error ? error.message : String(error) },
      'Failed manual DSS addition',
    );
    throw error;
  }
}
