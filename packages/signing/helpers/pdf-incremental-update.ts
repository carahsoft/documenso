import { PDFArray, PDFDict, PDFDocument, PDFName, PDFRef } from 'pdf-lib';

import { logger } from '@documenso/lib/utils/logger';

/**
 * Append DSS to a signed PDF using a proper incremental update
 *
 * This preserves the signature by:
 * 1. Keeping the original PDF bytes intact
 * 2. Appending new objects (DSS dictionary, streams)
 * 3. Appending a new xref table with only new objects
 * 4. Appending a new trailer that references the previous one
 *
 * CRITICAL: We manually construct the catalog dictionary to avoid using pdf-lib's
 * serialization, which can invalidate signatures.
 */
export async function addDSSViaIncrementalUpdate(
  originalPdf: Buffer,
  dssDict: PDFDict,
  moduleName = 'ltv',
): Promise<Buffer> {
  try {
    logger.info({ module: moduleName }, 'Starting incremental update to add DSS');

    // Parse the original PDF to understand its structure
    const doc = await PDFDocument.load(originalPdf, {
      updateMetadata: false,
      ignoreEncryption: true,
    });

    const context = doc.context;
    const catalog = doc.catalog;

    // Find the previous xref offset
    const originalPdfStr = originalPdf.toString('latin1');
    const startxrefMatch = originalPdfStr.match(/startxref\s+(\d+)\s+%%EOF\s*$/);
    if (!startxrefMatch) {
      throw new Error('Could not find startxref in original PDF');
    }
    const prevXrefOffset = parseInt(startxrefMatch[1], 10);

    logger.info(
      { module: moduleName, prevXrefOffset, originalSize: originalPdf.length },
      'Found previous xref offset',
    );

    // Register DSS with the context to get a reference
    const dssRef = context.register(dssDict);

    // Get catalog reference - we'll write a new version of the catalog
    const catalogRef = context.getObjectRef(catalog);
    if (!catalogRef) {
      throw new Error('Could not get catalog reference');
    }

    logger.info(
      { module: moduleName, catalogObjNum: catalogRef.objectNumber },
      'Will update catalog at object number',
    );

    // Build catalog dictionary manually to preserve existing entries
    const catalogEntries: string[] = [];

    // Collect all existing catalog entries
    for (const [key, value] of catalog.entries()) {
      const keyName = key.asString ? key.asString() : String(key);

      // Skip DSS if it already exists (shouldn't happen, but be safe)
      if (keyName === '/DSS') continue;

      // Format the value
      let valueStr = '';
      if (value instanceof PDFRef) {
        valueStr = `${value.objectNumber} ${value.generationNumber} R`;
      } else if (value instanceof PDFName) {
        valueStr = value.asString ? value.asString() : String(value);
      } else if (typeof value === 'object' && 'toString' in value) {
        valueStr = value.toString();
      } else {
        valueStr = String(value);
      }

      catalogEntries.push(`${keyName} ${valueStr}`);
    }

    // Add DSS reference
    catalogEntries.push(`/DSS ${dssRef.objectNumber} ${dssRef.generationNumber} R`);

    logger.info(
      { module: moduleName, entryCount: catalogEntries.length },
      'Built catalog dictionary with DSS',
    );

    // Collect DSS and all its referenced objects
    const newObjects = new Map<number, PDFRef>();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const objectsToWrite: Array<{ ref: PDFRef; obj?: any; manualContent?: string }> = [];

    // Add the modified catalog as manual content
    newObjects.set(catalogRef.objectNumber, catalogRef);
    const catalogContent = `<<\n${catalogEntries.join('\n')}\n>>`;
    objectsToWrite.push({ ref: catalogRef, manualContent: catalogContent });

    // Recursively collect DSS and referenced objects
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const collectObjects = (ref: PDFRef, obj: any) => {
      if (newObjects.has(ref.objectNumber)) return;

      newObjects.set(ref.objectNumber, ref);
      objectsToWrite.push({ ref, obj });

      // Recursively collect referenced objects
      if (obj instanceof PDFDict) {
        for (const [, value] of obj.entries()) {
          if (value instanceof PDFRef) {
            const referencedObj = context.lookup(value);
            if (referencedObj) {
              collectObjects(value, referencedObj);
            }
          }
        }
      } else if (obj instanceof PDFArray) {
        for (let i = 0; i < obj.size(); i++) {
          const value = obj.lookup(i);
          if (value instanceof PDFRef) {
            const referencedObj = context.lookup(value);
            if (referencedObj) {
              collectObjects(value, referencedObj);
            }
          }
        }
      }
    };

    collectObjects(dssRef, dssDict);

    logger.info(
      { module: moduleName, objectCount: objectsToWrite.length },
      'Collected objects to write',
    );

    // Build the incremental update
    const chunks: Buffer[] = [];

    // 1. Start with the original PDF (unchanged)
    chunks.push(originalPdf);

    // Ensure we end with a newline
    if (originalPdf[originalPdf.length - 1] !== 0x0a) {
      chunks.push(Buffer.from('\n', 'latin1'));
    }

    // 2. Write new/modified objects
    const xrefEntries = new Map<number, number>(); // object number -> byte offset
    let currentOffset = originalPdf.length;

    for (const { ref, obj, manualContent } of objectsToWrite) {
      // Record xref entry for this object
      xrefEntries.set(ref.objectNumber, currentOffset);

      // Write object header
      const objHeader = `${ref.objectNumber} ${ref.generationNumber} obj\n`;
      const objHeaderBuf = Buffer.from(objHeader, 'latin1');
      chunks.push(objHeaderBuf);
      currentOffset += objHeaderBuf.length;

      // Serialize the object
      let objBuf: Buffer;
      if (manualContent) {
        // Use manually constructed content (for catalog)
        objBuf = Buffer.from(manualContent, 'latin1');
        logger.info(
          { module: moduleName, objectNum: ref.objectNumber, size: objBuf.length },
          'Wrote manual content for object',
        );
      } else if (obj) {
        // Use pdf-lib serialization
        try {
          const objBytes = obj.sizeInBytes ? new Uint8Array(obj.sizeInBytes()) : new Uint8Array(0);
          if (obj.copyBytesInto) {
            obj.copyBytesInto(objBytes, 0);
          }
          objBuf = Buffer.from(objBytes);
        } catch (error) {
          logger.warn(
            { module: moduleName, objectNum: ref.objectNumber, error },
            'Failed to serialize object, skipping',
          );
          continue;
        }
      } else {
        logger.warn(
          { module: moduleName, objectNum: ref.objectNumber },
          'No content for object, skipping',
        );
        continue;
      }

      chunks.push(objBuf);
      currentOffset += objBuf.length;

      // Write object footer
      const objFooter = '\nendobj\n';
      const objFooterBuf = Buffer.from(objFooter, 'latin1');
      chunks.push(objFooterBuf);
      currentOffset += objFooterBuf.length;
    }

    // 3. Write xref table
    const xrefOffset = currentOffset;
    const xrefHeader = 'xref\n';
    chunks.push(Buffer.from(xrefHeader, 'latin1'));
    currentOffset += xrefHeader.length;

    // Sort xref entries by object number
    const sortedEntries = Array.from(xrefEntries.entries()).sort((a, b) => a[0] - b[0]);

    // Write xref subsections (groups of consecutive object numbers)
    const subsections: Array<{ start: number; count: number; entries: Array<[number, number]> }> =
      [];
    let currentSubsection: Array<[number, number]> = [];
    let subsectionStart = sortedEntries[0]?.[0] ?? 0;

    for (let i = 0; i < sortedEntries.length; i++) {
      const [objNum, offset] = sortedEntries[i];

      if (currentSubsection.length === 0) {
        subsectionStart = objNum;
        currentSubsection.push([objNum, offset]);
      } else {
        const prevObjNum = currentSubsection[currentSubsection.length - 1][0];
        if (objNum === prevObjNum + 1) {
          currentSubsection.push([objNum, offset]);
        } else {
          // Start new subsection
          subsections.push({
            start: subsectionStart,
            count: currentSubsection.length,
            entries: currentSubsection,
          });
          subsectionStart = objNum;
          currentSubsection = [[objNum, offset]];
        }
      }
    }

    if (currentSubsection.length > 0) {
      subsections.push({
        start: subsectionStart,
        count: currentSubsection.length,
        entries: currentSubsection,
      });
    }

    // Write each subsection
    for (const subsection of subsections) {
      const subsectionHeader = `${subsection.start} ${subsection.count}\n`;
      chunks.push(Buffer.from(subsectionHeader, 'latin1'));
      currentOffset += subsectionHeader.length;

      for (const [_objNum, offset] of subsection.entries) {
        // xref entry format: "nnnnnnnnnn ggggg n \n" (offset, generation, in-use flag)
        const offsetStr = offset.toString().padStart(10, '0');
        const genStr = '00000'; // generation number, typically 0
        const xrefEntry = `${offsetStr} ${genStr} n \n`;
        chunks.push(Buffer.from(xrefEntry, 'latin1'));
        currentOffset += xrefEntry.length;
      }
    }

    // 4. Write trailer
    const trailerStart = 'trailer\n';
    chunks.push(Buffer.from(trailerStart, 'latin1'));
    currentOffset += trailerStart.length;

    // Build trailer dictionary
    // Get the current Size from the original trailer
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const trailer = context.trailerInfo as any;
    const originalSize = trailer?.dict?.get?.(PDFName.of('Size')) || trailer?.Size;
    let totalSize = context.largestObjectNumber + 1;

    if (originalSize && typeof originalSize === 'object' && 'asNumber' in originalSize) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const origSizeNum = (originalSize as any).asNumber();
      if (origSizeNum > totalSize) {
        totalSize = origSizeNum;
      }
    }

    // Ensure totalSize includes all new objects
    for (const objNum of xrefEntries.keys()) {
      if (objNum >= totalSize) {
        totalSize = objNum + 1;
      }
    }

    const trailerDict = `<<
/Size ${totalSize}
/Root ${catalogRef.objectNumber} ${catalogRef.generationNumber} R
/Prev ${prevXrefOffset}
`;

    // Add Info if present in original
    const info = trailer?.dict?.get?.(PDFName.of('Info')) || trailer?.Info;
    if (info instanceof PDFRef) {
      const infoLine = `/Info ${info.objectNumber} ${info.generationNumber} R\n`;
      chunks.push(Buffer.from(trailerDict + infoLine + '>>\n', 'latin1'));
    } else {
      chunks.push(Buffer.from(trailerDict + '>>\n', 'latin1'));
    }

    // 5. Write startxref and EOF
    const startxrefStr = `startxref\n${xrefOffset}\n%%EOF\n`;
    chunks.push(Buffer.from(startxrefStr, 'latin1'));

    // @ts-expect-error Buffer extends Uint8Array at runtime
    const result = Buffer.concat(chunks);

    logger.info(
      {
        module: moduleName,
        originalSize: originalPdf.length,
        newSize: result.length,
        addedBytes: result.length - originalPdf.length,
      },
      'Incremental update completed successfully',
    );

    return result;
  } catch (error) {
    logger.error(
      { module: moduleName, error: error instanceof Error ? error.message : String(error) },
      'Failed to create incremental update',
    );
    throw error;
  }
}
