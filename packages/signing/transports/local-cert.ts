import forge from 'node-forge';
import * as fs from 'node:fs';

import { getCertificateStatus } from '@documenso/lib/server-only/cert/cert-status';
import { env } from '@documenso/lib/utils/env';
import { signWithP12 } from '@documenso/pdf-sign';

import { addDSSBeforeSigning } from '../helpers/add-dss-before-signing';
import { addSigningPlaceholder } from '../helpers/add-signing-placeholder';
import { fetchOCSPResponsesForChain } from '../helpers/ocsp';
import { updateSigningPlaceholder } from '../helpers/update-signing-placeholder';

export type SignWithLocalCertOptions = {
  pdf: Buffer;
  /**
   * Certification level for DocMDP (Document Modification Detection and Prevention)
   * - 0 or undefined: Approval signature (no certification, no DocMDP)
   * - 1: No changes allowed after signing (certified, locked)
   * - 2: Form filling allowed
   * - 3: Form filling and annotations allowed
   */
  certificationLevel?: 0 | 1 | 2 | 3;
};

export const signWithLocalCert = async ({ pdf, certificationLevel }: SignWithLocalCertOptions) => {
  // Get certification level from environment variable if not provided
  // Default to level 0 (approval signature, no DocMDP certification)
  const effectiveCertificationLevel =
    certificationLevel ??
    (parseInt(env('NEXT_PRIVATE_SIGNING_DOCMDP_LEVEL') || '0', 10) as 0 | 1 | 2 | 3);

  // STEP 1: Load P12 certificate file
  const certStatus = getCertificateStatus();

  if (!certStatus.isAvailable) {
    console.error('Certificate error: Certificate not available for document signing');
    throw new Error('Document signing failed: Certificate not available');
  }

  let cert: Buffer | null = null;

  const localFileContents = env('NEXT_PRIVATE_SIGNING_LOCAL_FILE_CONTENTS');

  if (localFileContents) {
    try {
      cert = Buffer.from(localFileContents, 'base64');
    } catch {
      throw new Error('Failed to decode certificate contents');
    }
  }

  if (!cert) {
    let certPath = env('NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH') || '/opt/documenso/cert.p12';

    // We don't want to make the development server suddenly crash when using the `dx` script
    // so we retain this when NODE_ENV isn't set to production which it should be in most production
    // deployments.
    //
    // Our docker image automatically sets this so it shouldn't be an issue for self-hosters.
    if (env('NODE_ENV') !== 'production') {
      certPath = env('NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH') || './example/cert.p12';
    }

    try {
      cert = Buffer.from(fs.readFileSync(certPath));
    } catch {
      console.error('Certificate error: Failed to read certificate file');
      throw new Error('Document signing failed: Certificate file not accessible');
    }
  }

  // STEP 2: Extract certificate and chain from P12 (before signing)
  let signingCert: Buffer | undefined;
  let certChain: Buffer[] | undefined;

  try {
    const password = env('NEXT_PRIVATE_SIGNING_PASSPHRASE') || '';
    const p12Der = forge.util.createBuffer(cert.toString('binary'));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    // Extract certificate and chain from P12
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certBagList = certBags[forge.pki.oids.certBag];

    if (certBagList && certBagList.length > 0) {
      // First certificate is the signing certificate
      const mainCert = certBagList[0].cert;
      if (mainCert) {
        const certAsn1 = forge.pki.certificateToAsn1(mainCert);
        const certDer = forge.asn1.toDer(certAsn1);
        signingCert = Buffer.from(certDer.getBytes(), 'binary');
      }

      // Remaining certificates are the chain
      if (certBagList.length > 1) {
        certChain = [];
        for (let i = 1; i < certBagList.length; i++) {
          const chainCert = certBagList[i].cert;
          if (chainCert) {
            const chainCertAsn1 = forge.pki.certificateToAsn1(chainCert);
            const chainCertDer = forge.asn1.toDer(chainCertAsn1);
            certChain.push(Buffer.from(chainCertDer.getBytes(), 'binary'));
          }
        }
      }
    }
  } catch (error) {
    console.warn(
      'Failed to extract certificate chain from P12, LTV may not be fully enabled:',
      error,
    );
  }

  // STEP 3: Add LTV (DSS) to PDF BEFORE signing (if enabled and we have certificate chain)
  let pdfToSign = pdf; // Start with original PDF
  const enableLTV = process.env.NEXT_PRIVATE_SIGNING_DISABLE_LTV !== 'true';

  if (enableLTV && signingCert && certChain && certChain.length > 0) {
    try {
      // Build full chain for OCSP
      const fullChain = [signingCert, ...certChain];

      // Fetch OCSP responses
      const ocspResponses = await fetchOCSPResponsesForChain(fullChain, 'local-cert');
      const validOcspResponses = ocspResponses.filter((resp): resp is Buffer => resp !== null);

      if (validOcspResponses.length > 0) {
        // Add DSS to PDF before signing
        pdfToSign = await addDSSBeforeSigning({
          pdf: pdfToSign,
          certificateChain: certChain,
          ocspResponses: validOcspResponses,
          moduleName: 'local-cert',
        });
      }
    } catch (error) {
      console.warn('Failed to add LTV before signing, continuing without LTV:', error);
    }
  }

  // STEP 4: Prepare PDF with signing placeholder
  const { pdf: pdfWithPlaceholder, byteRange } = updateSigningPlaceholder({
    pdf: await addSigningPlaceholder({
      pdf: pdfToSign, // Use the (possibly DSS-enhanced) PDF
      certificationLevel: effectiveCertificationLevel,
    }),
  });

  const pdfWithoutSignature = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  const signatureLength = byteRange[2] - byteRange[1];

  // STEP 5: Sign the PDF
  const timestampServerUrl = env('NEXT_PRIVATE_SIGNING_TIMESTAMP_SERVER_URL');

  const signature = signWithP12({
    cert,
    content: pdfWithoutSignature,
    password: env('NEXT_PRIVATE_SIGNING_PASSPHRASE') || undefined,
    timestampServer: timestampServerUrl,
  });

  const signatureAsHex = signature.toString('hex');

  const signedPdf = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(Buffer.from(`<${signatureAsHex.padEnd(signatureLength - 2, '0')}>`)),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  // Return signed PDF (LTV was already added before signing)
  return signedPdf;
};
