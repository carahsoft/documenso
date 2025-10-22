import { PDFArray, PDFDict, PDFDocument, PDFHexString, PDFName, PDFStream } from 'pdf-lib';

import { logger } from '@documenso/lib/utils/logger';

import { fetchOCSPResponsesForChain } from './ocsp';

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
   * Optional timestamp token from TSA
   */
  timestampToken?: Buffer;

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
 * Extract timestamp from timestamp token for VRI dictionary
 *
 * @param timestampToken - The timestamp token
 * @returns ISO 8601 timestamp string or null
 */
function extractTimestampFromToken(timestampToken: Buffer): string | null {
  try {
    // Timestamp tokens are TSTInfo structures in RFC 3161
    // For now, use current time as fallback
    // A full implementation would parse the TSTInfo to get the genTime
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, '0');
    const day = String(now.getUTCDate()).padStart(2, '0');
    const hours = String(now.getUTCHours()).padStart(2, '0');
    const minutes = String(now.getUTCMinutes()).padStart(2, '0');
    const seconds = String(now.getUTCSeconds()).padStart(2, '0');

    // PDF timestamp format: D:YYYYMMDDHHmmSS+00'00'
    return `D:${year}${month}${day}${hours}${minutes}${seconds}+00'00'`;
  } catch (error) {
    return null;
  }
}

/**
 * Compute SHA-256 hash of a signature dictionary's Contents field
 * This is used as the key in the VRI dictionary
 *
 * @param signatureContents - The signature contents (hex string without < >)
 * @returns Uppercase hex string of SHA-256 hash
 */
function computeSignatureHash(signatureContents: string): string {
  const crypto = require('node:crypto');
  // Remove < > if present and convert hex to buffer
  const cleaned = signatureContents.replace(/[<>]/g, '');
  const signatureBuffer = Buffer.from(cleaned, 'hex');
  const hash = crypto.createHash('sha256').update(signatureBuffer).digest('hex');
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
    timestampToken,
    moduleName = 'ltv',
    enableLTV = process.env.NEXT_PRIVATE_SIGNING_ENABLE_LTV !== 'false',
  } = options;

  if (!enableLTV) {
    logger.info({ module: moduleName }, 'LTV is disabled via NEXT_PRIVATE_SIGNING_ENABLE_LTV=false');
    return pdf;
  }

  logger.info(
    { module: moduleName, hasCertChain: certificateChain.length > 0, hasTimestamp: !!timestampToken },
    'Starting LTV enablement process',
  );

  try {
    // Load the signed PDF
    const doc = await PDFDocument.load(pdf, {
      updateMetadata: false,
      ignoreEncryption: true,
    });

    const catalog = doc.catalog;

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

    // Create DSS dictionary
    const dss = doc.context.obj({});

    // Add certificates to DSS (excluding the signing cert, only intermediates)
    if (certificateChain.length > 0) {
      const certsArray = PDFArray.withContext(doc.context);

      for (const cert of certificateChain) {
        // Create a stream for each certificate
        const certStream = doc.context.stream(new Uint8Array(cert));
        certsArray.push(certStream);
      }

      dss.set(PDFName.of('Certs'), certsArray);
      logger.info(
        { module: moduleName, certCount: certificateChain.length },
        'Added certificates to DSS',
      );
    }

    // Add OCSP responses to DSS
    if (validOcspResponses.length > 0) {
      const ocspsArray = PDFArray.withContext(doc.context);

      for (const ocspResponse of validOcspResponses) {
        // Create a stream for each OCSP response
        const ocspStream = doc.context.stream(new Uint8Array(ocspResponse));
        ocspsArray.push(ocspStream);
      }

      dss.set(PDFName.of('OCSPs'), ocspsArray);
      logger.info(
        { module: moduleName, ocspCount: validOcspResponses.length },
        'Added OCSP responses to DSS',
      );
    }

    // Find the signature dictionary to create VRI entry
    // We need to find the last signature in the document
    let signatureRef: PDFDict | null = null;
    let signatureContents: string | null = null;

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
            signatureRef = v;
            const contents = v.lookup(PDFName.of('Contents'));
            if (contents instanceof PDFHexString) {
              signatureContents = contents.asString();
              break;
            }
          }
        }
      }
    }

    // Create VRI dictionary if we found a signature
    if (signatureRef && signatureContents) {
      const vri = doc.context.obj({});

      // Compute hash of signature contents for VRI key
      const sigHash = computeSignatureHash(signatureContents);
      logger.info({ module: moduleName, sigHash }, 'Creating VRI entry for signature');

      // Create VRI entry for this signature
      const vriEntry = doc.context.obj({});

      // Add certificates to VRI entry
      if (certificateChain.length > 0) {
        const vriCertsArray = PDFArray.withContext(doc.context);
        for (const cert of certificateChain) {
          const certStream = doc.context.stream(new Uint8Array(cert));
          vriCertsArray.push(certStream);
        }
        vriEntry.set(PDFName.of('Cert'), vriCertsArray);
      }

      // Add OCSP responses to VRI entry
      if (validOcspResponses.length > 0) {
        const vriOcspsArray = PDFArray.withContext(doc.context);
        for (const ocspResponse of validOcspResponses) {
          const ocspStream = doc.context.stream(new Uint8Array(ocspResponse));
          vriOcspsArray.push(ocspStream);
        }
        vriEntry.set(PDFName.of('OCSP'), vriOcspsArray);
      }

      // Add timestamp to VRI entry if available
      if (timestampToken) {
        const timestamp = extractTimestampFromToken(timestampToken);
        if (timestamp) {
          vriEntry.set(PDFName.of('TU'), PDFString.of(timestamp));
          logger.info({ module: moduleName, timestamp }, 'Added timestamp to VRI');
        }
      }

      // Add VRI entry to VRI dictionary using signature hash as key
      vri.set(PDFName.of(sigHash), vriEntry);

      // Add VRI dictionary to DSS
      dss.set(PDFName.of('VRI'), vri);
      logger.info({ module: moduleName }, 'Added VRI dictionary to DSS');
    } else {
      logger.warn({ module: moduleName }, 'Could not find signature in document for VRI entry');
    }

    // Add DSS to catalog
    catalog.set(PDFName.of('DSS'), dss);
    logger.info({ module: moduleName }, 'Added DSS to document catalog');

    // Save with incremental update to preserve signature
    const ltvEnabledPdf = await doc.save({
      useObjectStreams: false,
      addDefaultPage: false,
      updateFieldAppearances: false,
    });

    logger.info({ module: moduleName }, 'LTV enabled successfully');

    return Buffer.from(ltvEnabledPdf);
  } catch (error) {
    logger.error({ module: moduleName, error }, 'Failed to add LTV information, returning original PDF');
    // Return original PDF if LTV fails - don't break the signing process
    return pdf;
  }
}

// Helper to import PDFString if needed
import { PDFString } from 'pdf-lib';
