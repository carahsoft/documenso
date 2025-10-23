import { createHash } from 'node:crypto';
import { PDFArray, PDFDict, PDFDocument, PDFHexString, PDFName } from 'pdf-lib';

import { logger } from '@documenso/lib/utils/logger';

import { fetchOCSPResponsesForChain } from './ocsp';
import { addDSSManually } from './pdf-manual-update';

export type AddLTVOptions = {
  /**
   * The signed PDF document
   */
  pdf: Buffer;

  /**
   * The signing certificate (DER or PEM format)
   */
  certificate: Buffer;

  /**
   * Optional certificate chain (intermediates and optionally root)
   * First certificate should be the issuer of the signing certificate
   */
  certificateChain?: Buffer[];

  /**
   * Optional signature buffer to compute hash from (avoids PDF parsing)
   * If provided, the signature hash will be computed directly from this buffer
   * instead of parsing the PDF to find the signature
   */
  signature?: Buffer;

  /**
   * Module name for logging
   */
  moduleName?: string;

  /**
   * Whether to enable LTV (default: true based on environment variable)
   */
  enableLTV?: boolean;
};

/**
 * Compute SHA-256 hash of a signature dictionary's Contents field
 * This is used as the key in the VRI dictionary
 *
 * @param signatureContents - The signature contents (hex string without < >)
 * @returns Uppercase hex string of SHA-256 hash
 */
function computeSignatureHash(signatureContents: string): string {
  // Remove < > if present and convert hex to buffer
  const cleaned = signatureContents.replace(/[<>]/g, '');
  const signatureBuffer = Buffer.from(cleaned, 'hex');
  const hash = createHash('sha256').update(signatureBuffer).digest('hex');
  return hash.toUpperCase();
}

/**
 * Compute SHA-256 hash directly from a signature buffer
 * This is used as the key in the VRI dictionary
 *
 * @param signatureBuffer - The signature buffer
 * @returns Uppercase hex string of SHA-256 hash
 */
function computeSignatureHashFromBuffer(signatureBuffer: Buffer): string {
  const hash = createHash('sha256').update(signatureBuffer).digest('hex');
  return hash.toUpperCase();
}

/**
 * Add Long-Term Validation (LTV) information to a signed PDF
 *
 * This adds a Document Security Store (DSS) to the PDF catalog via an incremental update.
 * The DSS contains:
 * - /Certs: Intermediate certificates for chain validation
 * - /OCSPs: OCSP responses for revocation checking
 * - /VRI: Validation Related Information per signature
 *
 * This preserves the original signature while adding validation data that allows
 * Adobe Acrobat to validate the signature without requiring internet access.
 *
 * @param options - LTV options including the signed PDF and certificate chain
 * @returns PDF with LTV information added, or original PDF if LTV is disabled/failed
 */
export async function addLTV(options: AddLTVOptions): Promise<Buffer> {
  const {
    pdf,
    certificate,
    certificateChain = [],
    signature,
    moduleName = 'ltv',
    enableLTV = process.env.NEXT_PRIVATE_SIGNING_DISABLE_LTV !== 'true',
  } = options;

  if (!enableLTV) {
    logger.info(
      { module: moduleName },
      'LTV is disabled via NEXT_PRIVATE_SIGNING_DISABLE_LTV=true',
    );
    return pdf;
  }

  logger.info(
    {
      module: moduleName,
      hasCertChain: certificateChain.length > 0,
      hasSignature: !!signature,
    },
    'Starting LTV enablement process',
  );

  try {
    // Build full certificate chain (signing cert + intermediates)
    const fullChain = [certificate, ...certificateChain];

    if (fullChain.length < 2) {
      logger.warn(
        { module: moduleName },
        'Certificate chain too short for LTV (need at least signing cert + issuer), skipping',
      );
      return pdf;
    }

    logger.info(
      { module: moduleName, chainLength: fullChain.length },
      'Fetching OCSP responses for certificate chain',
    );

    // Fetch OCSP responses for the certificate chain
    const ocspResponses = await fetchOCSPResponsesForChain(fullChain, moduleName);

    // Filter out null responses
    const validOcspResponses = ocspResponses.filter((resp): resp is Buffer => resp !== null);

    if (validOcspResponses.length === 0) {
      logger.warn(
        { module: moduleName },
        'No OCSP responses available, cannot enable LTV without revocation data',
      );
      return pdf;
    }

    logger.info(
      { module: moduleName, ocspCount: validOcspResponses.length },
      'OCSP responses fetched successfully',
    );

    // Find or compute the signature hash for VRI
    let signatureHash: string | null = null;

    // If signature is provided, compute hash directly from it (avoids PDF parsing)
    if (signature) {
      signatureHash = computeSignatureHashFromBuffer(signature);
      logger.info(
        { module: moduleName, sigHash: signatureHash },
        'Computed signature hash from provided signature buffer',
      );
    } else {
      // Otherwise, load PDF and parse to find the signature
      logger.info({ module: moduleName, pdfSize: pdf.length }, 'Loading PDF to find signature');

      const doc = await PDFDocument.load(pdf, {
        updateMetadata: false,
        ignoreEncryption: true,
      });

      const catalog = doc.catalog;
      const acroForm = catalog.lookup(PDFName.of('AcroForm'), PDFDict);

      if (acroForm) {
        const fields = acroForm.lookup(PDFName.of('Fields'), PDFArray);
        if (fields) {
          // Iterate through fields to find signature field
          for (let i = fields.size() - 1; i >= 0; i--) {
            const field = fields.lookup(i, PDFDict);
            const ft = field?.lookup(PDFName.of('FT'), PDFName);
            const v = field?.lookup(PDFName.of('V'));

            // Check if this is a signature field (FT = /Sig)
            if (ft?.asString() === '/Sig' && v instanceof PDFDict) {
              const contents = v.lookup(PDFName.of('Contents'));
              if (contents instanceof PDFHexString) {
                const signatureContents = contents.asString();
                signatureHash = computeSignatureHash(signatureContents);
                logger.info(
                  { module: moduleName, sigHash: signatureHash },
                  'Found signature hash from PDF parsing',
                );
                break;
              }
            }
          }
        }
      }
    }

    // Use manual PDF writing to add DSS without corrupting the PDF
    try {
      logger.info({ module: moduleName }, 'Adding DSS via manual PDF writing');

      const ltvEnabledPdf = addDSSManually(
        pdf,
        certificateChain,
        validOcspResponses,
        signatureHash,
        moduleName,
      );

      logger.info(
        { module: moduleName, originalSize: pdf.length, newSize: ltvEnabledPdf.length },
        'LTV enabled successfully with manual update',
      );

      // Validate the PDF structure before returning
      const pdfHeader = ltvEnabledPdf.slice(0, 5).toString('ascii');
      if (!pdfHeader.startsWith('%PDF-')) {
        logger.error({ module: moduleName, header: pdfHeader }, 'Invalid PDF header after save');
        throw new Error('Invalid PDF structure after adding LTV');
      }

      return ltvEnabledPdf;
    } catch (saveError) {
      logger.error(
        { module: moduleName, error: saveError },
        'Failed to add DSS via manual update, returning original',
      );
      throw saveError; // Re-throw to be caught by outer catch
    }
  } catch (error) {
    logger.error(
      { module: moduleName, error },
      'Failed to add LTV information, returning original PDF',
    );
    // Return original PDF if LTV fails - don't break the signing process
    return pdf;
  }
}
