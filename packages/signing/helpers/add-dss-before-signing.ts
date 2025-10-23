import type { PDFStream } from 'pdf-lib';
import { PDFArray, PDFDocument, PDFName } from 'pdf-lib';

import { logger } from '@documenso/lib/utils/logger';

export type AddDSSBeforeSigningOptions = {
  /**
   * The PDF document (before signing)
   */
  pdf: Buffer;

  /**
   * Certificate chain (DER format, intermediates only - not including signing cert)
   */
  certificateChain: Buffer[];

  /**
   * OCSP responses
   */
  ocspResponses: Buffer[];

  /**
   * Module name for logging
   */
  moduleName?: string;
};

/**
 * Add DSS (Document Security Store) to PDF BEFORE signing
 *
 * This adds LTV information to the catalog before the signature is computed,
 * so the DSS becomes part of the signed content. This avoids issues with
 * incremental updates on PDFs with xref streams or complex structures.
 *
 * The DSS contains:
 * - /Certs: Certificate chain for validation
 * - /OCSPs: OCSP responses for revocation checking
 *
 * Note: VRI (Validation Related Information) is not added since we don't have
 * the signature hash yet. VRI is optional for LTV validation.
 *
 * @param options - DSS options
 * @returns PDF with DSS added, or original PDF if adding DSS fails
 */
export async function addDSSBeforeSigning(options: AddDSSBeforeSigningOptions): Promise<Buffer> {
  const { pdf, certificateChain, ocspResponses, moduleName = 'ltv' } = options;

  logger.info(
    {
      module: moduleName,
      certCount: certificateChain.length,
      ocspCount: ocspResponses.length,
    },
    'Adding DSS before signing',
  );

  try {
    const doc = await PDFDocument.load(pdf, {
      updateMetadata: false,
      ignoreEncryption: true,
    });

    const context = doc.context;
    const catalog = doc.catalog;

    // Create certificate streams
    const certStreams: PDFStream[] = [];
    for (const cert of certificateChain) {
      const stream = context.stream(cert);
      certStreams.push(stream);
    }

    logger.info({ module: moduleName, count: certStreams.length }, 'Created certificate streams');

    // Create OCSP response streams
    const ocspStreams: PDFStream[] = [];
    for (const ocsp of ocspResponses) {
      const stream = context.stream(ocsp);
      ocspStreams.push(stream);
    }

    logger.info({ module: moduleName, count: ocspStreams.length }, 'Created OCSP streams');

    // Build DSS dictionary
    const dssDict = context.obj({});

    // Add /Certs array
    if (certStreams.length > 0) {
      const certsArray = PDFArray.withContext(context);
      for (const stream of certStreams) {
        certsArray.push(context.register(stream));
      }
      dssDict.set(PDFName.of('Certs'), certsArray);
    }

    // Add /OCSPs array
    if (ocspStreams.length > 0) {
      const ocspsArray = PDFArray.withContext(context);
      for (const stream of ocspStreams) {
        ocspsArray.push(context.register(stream));
      }
      dssDict.set(PDFName.of('OCSPs'), ocspsArray);
    }

    // Note: We don't add /VRI here because we don't have the signature hash yet
    // The /Certs and /OCSPs arrays are sufficient for LTV validation

    // Register DSS and add to catalog
    const dssRef = context.register(dssDict);
    catalog.set(PDFName.of('DSS'), dssRef);

    logger.info({ module: moduleName }, 'DSS added to catalog');

    // Save with conservative options to avoid corrupting complex PDFs
    const savedPdf = await doc.save({
      useObjectStreams: false,
      updateFieldAppearances: false,
    });

    logger.info(
      { module: moduleName, originalSize: pdf.length, newSize: savedPdf.length },
      'PDF with DSS saved successfully',
    );

    return Buffer.from(savedPdf);
  } catch (error) {
    logger.error(
      { module: moduleName, error },
      'Failed to add DSS before signing, returning original PDF',
    );
    // Return original PDF on failure - don't break the signing process
    return pdf;
  }
}
