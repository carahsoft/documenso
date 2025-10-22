import fs from 'node:fs';

import { env } from '@documenso/lib/utils/env';
import { signWithGCloud } from '@documenso/pdf-sign';
import forge from 'node-forge';

import { addLTV } from '../helpers/add-ltv';
import { addSigningPlaceholder } from '../helpers/add-signing-placeholder';
import { parseCertificate } from '../helpers/pkcs7';
import { updateSigningPlaceholder } from '../helpers/update-signing-placeholder';

export type SignWithGoogleCloudHSMOptions = {
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

export const signWithGoogleCloudHSM = async ({
  pdf,
  certificationLevel,
}: SignWithGoogleCloudHSMOptions) => {
  const keyPath = env('NEXT_PRIVATE_SIGNING_GCLOUD_HSM_KEY_PATH');

  // Get certification level from environment variable if not provided
  const effectiveCertificationLevel =
    certificationLevel ??
    (parseInt(env('NEXT_PRIVATE_SIGNING_DOCMDP_LEVEL') || '1', 10) as 0 | 1 | 2 | 3);

  if (!keyPath) {
    throw new Error('No certificate path provided for Google Cloud HSM signing');
  }

  const googleApplicationCredentials = env('GOOGLE_APPLICATION_CREDENTIALS');
  const googleApplicationCredentialsContents = env(
    'NEXT_PRIVATE_SIGNING_GCLOUD_APPLICATION_CREDENTIALS_CONTENTS',
  );

  // To handle hosting in serverless environments like Vercel we can supply the base64 encoded
  // application credentials as an environment variable and write it to a file if it doesn't exist
  if (googleApplicationCredentials && googleApplicationCredentialsContents) {
    if (!fs.existsSync(googleApplicationCredentials)) {
      const contents = new Uint8Array(Buffer.from(googleApplicationCredentialsContents, 'base64'));

      fs.writeFileSync(googleApplicationCredentials, contents);
    }
  }

  const { pdf: pdfWithPlaceholder, byteRange } = updateSigningPlaceholder({
    pdf: await addSigningPlaceholder({ pdf, certificationLevel: effectiveCertificationLevel }),
  });

  const pdfWithoutSignature = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  const signatureLength = byteRange[2] - byteRange[1];

  let cert: Buffer | null = null;

  const googleCloudHsmPublicCrtFileContents = env(
    'NEXT_PRIVATE_SIGNING_GCLOUD_HSM_PUBLIC_CRT_FILE_CONTENTS',
  );

  if (googleCloudHsmPublicCrtFileContents) {
    cert = Buffer.from(googleCloudHsmPublicCrtFileContents, 'base64');
  }

  if (!cert) {
    cert = Buffer.from(
      fs.readFileSync(
        env('NEXT_PRIVATE_SIGNING_GCLOUD_HSM_PUBLIC_CRT_FILE_PATH') || './example/cert.crt',
      ),
    );
  }

  const timestampServerUrl = env('NEXT_PRIVATE_SIGNING_TIMESTAMP_SERVER_URL');

  const signature = signWithGCloud({
    keyPath,
    cert,
    content: pdfWithoutSignature,
    timestampServer: timestampServerUrl,
  });

  const signatureAsHex = signature.toString('hex');

  const signedPdf = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(Buffer.from(`<${signatureAsHex.padEnd(signatureLength - 2, '0')}>`)),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  // Extract certificate chain if the cert file contains multiple certificates
  let signingCert: Buffer = cert;
  let certChain: Buffer[] | undefined;

  try {
    const certString = cert.toString('utf8');

    // Check if this is a PEM bundle with multiple certificates
    if (certString.includes('-----BEGIN CERTIFICATE-----')) {
      const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
      const matches = certString.match(certRegex);

      if (matches && matches.length > 1) {
        // First is signing cert, rest are chain
        signingCert = Buffer.from(matches[0], 'utf8');
        certChain = [];

        for (let i = 1; i < matches.length; i++) {
          certChain.push(Buffer.from(matches[i], 'utf8'));
        }
      }
    }
  } catch (error) {
    console.warn('Failed to parse certificate chain, LTV may not be fully enabled:', error);
  }

  // Add LTV (Long-Term Validation) information
  const ltvEnabledPdf = await addLTV({
    pdf: signedPdf,
    certificate: signingCert,
    certificateChain: certChain,
    timestampToken: undefined, // GCloud signing doesn't return timestamp token separately
    moduleName: 'google-cloud-hsm',
  });

  return ltvEnabledPdf;
};
