import { ClientSecretCredential, DefaultAzureCredential } from '@azure/identity';
import { CertificateClient } from '@azure/keyvault-certificates';
import { CryptographyClient, KnownSignatureAlgorithms } from '@azure/keyvault-keys';
import { createHash } from 'node:crypto';
import fs from 'node:fs';

import { env } from '@documenso/lib/utils/env';
import { logger } from '@documenso/lib/utils/logger';

import { addLTV } from '../helpers/add-ltv';
import { addSigningPlaceholder } from '../helpers/add-signing-placeholder';
import { buildAuthenticatedAttributes, buildPKCS7Signature } from '../helpers/pkcs7';
import { getTimestampToken } from '../helpers/timestamp';
import { updateSigningPlaceholder } from '../helpers/update-signing-placeholder';

export type SignWithAzureKeyVaultHSMOptions = {
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

/**
 * Sign a PDF document using Azure Key Vault HSM
 *
 * This function uses Azure Key Vault's cryptographic signing capabilities to sign PDFs.
 * It supports both DefaultAzureCredential (for managed identities, Azure CLI, etc.)
 * and ClientSecretCredential (for service principal authentication).
 */
export const signWithAzureKeyVaultHSM = async ({
  pdf,
  certificationLevel,
}: SignWithAzureKeyVaultHSMOptions) => {
  logger.info({ module: 'azure-key-vault-hsm' }, 'Starting Azure Key Vault HSM signing process');

  const keyVaultUrl = env('NEXT_PRIVATE_SIGNING_AZURE_KEY_VAULT_URL');
  const keyName = env('NEXT_PRIVATE_SIGNING_AZURE_KEY_NAME');
  const certificateName = env('NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_NAME');

  // Get certification level from environment variable if not provided
  // Default to level 2 to allow LTV (DSS) incremental updates
  const effectiveCertificationLevel =
    certificationLevel ??
    (parseInt(env('NEXT_PRIVATE_SIGNING_DOCMDP_LEVEL') || '2', 10) as 0 | 1 | 2 | 3);

  if (!keyVaultUrl) {
    logger.error({ module: 'azure-key-vault-hsm' }, 'Azure Key Vault URL not configured');
    throw new Error('No Azure Key Vault URL provided for Azure Key Vault HSM signing');
  }

  if (!keyName) {
    logger.error({ module: 'azure-key-vault-hsm' }, 'Azure Key name not configured');
    throw new Error('No Azure Key name provided for Azure Key Vault HSM signing');
  }

  if (!certificateName) {
    logger.error({ module: 'azure-key-vault-hsm' }, 'Azure Certificate name not configured');
    throw new Error('No Azure Certificate name provided for Azure Key Vault HSM signing');
  }

  // Set up authentication credentials
  let credential;

  const tenantId = env('NEXT_PRIVATE_SIGNING_AZURE_TENANT_ID');
  const clientId = env('NEXT_PRIVATE_SIGNING_AZURE_CLIENT_ID');
  const clientSecret = env('NEXT_PRIVATE_SIGNING_AZURE_CLIENT_SECRET');

  try {
    // Use ClientSecretCredential if service principal credentials are provided
    if (tenantId && clientId && clientSecret) {
      logger.info(
        { module: 'azure-key-vault-hsm' },
        'Using ClientSecretCredential for authentication',
      );
      credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    } else {
      // Otherwise use DefaultAzureCredential (supports managed identity, Azure CLI, etc.)
      logger.info(
        { module: 'azure-key-vault-hsm' },
        'Using DefaultAzureCredential for authentication',
      );
      credential = new DefaultAzureCredential();
    }
  } catch (error) {
    logger.error(
      { module: 'azure-key-vault-hsm', error },
      'Failed to initialize Azure credentials',
    );
    throw new Error('Failed to initialize Azure credentials');
  }

  // Prepare PDF with placeholder
  let pdfWithPlaceholder: Buffer;
  let byteRange: number[];

  try {
    const placeholderResult = updateSigningPlaceholder({
      pdf: await addSigningPlaceholder({ pdf, certificationLevel: effectiveCertificationLevel }),
    });
    pdfWithPlaceholder = placeholderResult.pdf;
    byteRange = placeholderResult.byteRange;
  } catch (error) {
    logger.error(
      { module: 'azure-key-vault-hsm', error },
      'Failed to prepare PDF with signing placeholder',
    );
    throw new Error('Failed to prepare PDF for signing');
  }

  const pdfWithoutSignature = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  const signatureLength = byteRange[2] - byteRange[1];

  logger.info({ module: 'azure-key-vault-hsm', signatureLength }, 'PDF prepared with placeholder');

  // Get the certificate from Azure Key Vault
  let cert: Buffer | null = null;

  const azureCertificateContents = env('NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CONTENTS');

  try {
    if (azureCertificateContents) {
      // Use certificate contents from environment variable if provided
      logger.info(
        { module: 'azure-key-vault-hsm' },
        'Loading certificate from environment variable',
      );
      cert = Buffer.from(azureCertificateContents, 'base64');
    } else {
      const azureCertificatePath = env('NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_PATH');

      if (azureCertificatePath && fs.existsSync(azureCertificatePath)) {
        // Load certificate from file path
        logger.info(
          { module: 'azure-key-vault-hsm', path: azureCertificatePath },
          'Loading certificate from file',
        );
        cert = Buffer.from(fs.readFileSync(azureCertificatePath));
      } else {
        // Download certificate from Azure Key Vault
        logger.info(
          { module: 'azure-key-vault-hsm', certificateName },
          'Downloading certificate from Azure Key Vault',
        );
        const certificateClient = new CertificateClient(keyVaultUrl, credential);
        const certificate = await certificateClient.getCertificate(certificateName);

        if (!certificate.cer) {
          logger.error(
            { module: 'azure-key-vault-hsm', certificateName },
            'Certificate does not contain public key data',
          );
          throw new Error('Certificate does not contain public key data');
        }

        cert = Buffer.from(certificate.cer);
      }
    }
  } catch (error) {
    logger.error({ module: 'azure-key-vault-hsm', error }, 'Failed to load certificate');
    throw new Error('Failed to load certificate for Azure Key Vault HSM signing');
  }

  if (!cert) {
    logger.error({ module: 'azure-key-vault-hsm' }, 'Certificate is null after loading');
    throw new Error('Failed to load certificate for Azure Key Vault HSM signing');
  }

  // Load certificate chain for LTV support (optional)
  const certificateChain: Buffer[] = [];
  const azureCertificateChainPath = env('NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_PATH');
  const azureCertificateChainContents = env(
    'NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_CONTENTS',
  );

  try {
    if (azureCertificateChainContents) {
      // Certificate chain provided as base64-encoded contents (comma-separated)
      logger.info(
        { module: 'azure-key-vault-hsm' },
        'Loading certificate chain from environment variable',
      );
      const chainCertsBase64 = azureCertificateChainContents.split(',');
      for (const certBase64 of chainCertsBase64) {
        const trimmed = certBase64.trim();
        if (trimmed) {
          certificateChain.push(Buffer.from(trimmed, 'base64'));
        }
      }
      logger.info(
        { module: 'azure-key-vault-hsm', count: certificateChain.length },
        'Certificate chain loaded from environment',
      );
    } else if (azureCertificateChainPath && fs.existsSync(azureCertificateChainPath)) {
      // Load certificate chain from file
      logger.info(
        { module: 'azure-key-vault-hsm', path: azureCertificateChainPath },
        'Loading certificate chain from file',
      );
      const chainContents = fs.readFileSync(azureCertificateChainPath, 'utf8');

      // Support both PEM bundle and comma-separated base64
      if (chainContents.includes('-----BEGIN CERTIFICATE-----')) {
        // PEM bundle format - split by certificate boundaries
        const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
        const matches = chainContents.match(certRegex);
        if (matches) {
          for (const pemCert of matches) {
            certificateChain.push(Buffer.from(pemCert, 'utf8'));
          }
        }
      } else {
        // Assume comma-separated base64
        const chainCertsBase64 = chainContents.split(',');
        for (const certBase64 of chainCertsBase64) {
          const trimmed = certBase64.trim();
          if (trimmed) {
            certificateChain.push(Buffer.from(trimmed, 'base64'));
          }
        }
      }

      logger.info(
        { module: 'azure-key-vault-hsm', count: certificateChain.length },
        'Certificate chain loaded from file',
      );
    }
  } catch (error) {
    logger.warn(
      { module: 'azure-key-vault-hsm', error },
      'Failed to load certificate chain, continuing without LTV support',
    );
  }

  // Create cryptography client for signing
  logger.info({ module: 'azure-key-vault-hsm', keyName }, 'Creating cryptography client');

  let cryptoClient: CryptographyClient;

  try {
    cryptoClient = new CryptographyClient(`${keyVaultUrl}/keys/${keyName}`, credential);
  } catch (error) {
    logger.error({ module: 'azure-key-vault-hsm', error }, 'Failed to create cryptography client');
    throw new Error('Failed to create cryptography client');
  }

  // Hash the content using SHA-256
  logger.info({ module: 'azure-key-vault-hsm' }, 'Hashing PDF content');

  const pdfHash = createHash('sha256').update(new Uint8Array(pdfWithoutSignature)).digest();

  // Build authenticated attributes with the PDF hash
  logger.info({ module: 'azure-key-vault-hsm' }, 'Building authenticated attributes');

  const authenticatedAttributes = buildAuthenticatedAttributes(pdfHash);

  // Hash the authenticated attributes (this is what we actually sign)
  const authenticatedAttributesHash = createHash('sha256')
    .update(new Uint8Array(authenticatedAttributes))
    .digest();

  // Sign the authenticated attributes hash using Azure Key Vault
  logger.info(
    { module: 'azure-key-vault-hsm' },
    'Signing authenticated attributes hash with Azure Key Vault',
  );

  let signResult;

  try {
    signResult = await cryptoClient.sign(
      KnownSignatureAlgorithms.RS256,
      new Uint8Array(authenticatedAttributesHash),
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    logger.error(
      {
        module: 'azure-key-vault-hsm',
        error: errorMessage,
        errorDetails: error,
        stack: errorStack,
      },
      'Azure Key Vault signing operation failed',
    );
    throw new Error(`Azure Key Vault signing operation failed: ${errorMessage}`);
  }

  if (!signResult.result) {
    logger.error(
      { module: 'azure-key-vault-hsm' },
      'Azure Key Vault signing returned no signature',
    );
    throw new Error('Azure Key Vault signing failed: No signature returned');
  }

  logger.info(
    { module: 'azure-key-vault-hsm' },
    'Authenticated attributes hash signed successfully',
  );

  // Get timestamp from TSA if configured
  const timestampServerUrl = env('NEXT_PRIVATE_SIGNING_TIMESTAMP_SERVER_URL');
  const timestampToken = await getTimestampToken(
    Buffer.from(signResult.result),
    timestampServerUrl,
    'azure-key-vault-hsm',
  );

  // Build the signature in PKCS#7 format
  logger.info(
    {
      module: 'azure-key-vault-hsm',
      withTimestamp: !!timestampToken,
      withCertChain: certificateChain.length > 0,
    },
    'Building PKCS#7 signature',
  );

  let signature: Buffer;

  try {
    signature = buildPKCS7Signature(
      signResult.result,
      cert,
      pdfHash,
      timestampToken,
      'azure-key-vault-hsm',
      certificateChain.length > 0 ? certificateChain : undefined,
    );
  } catch (error) {
    logger.error({ module: 'azure-key-vault-hsm', error }, 'Failed to build PKCS#7 signature');
    throw new Error('Failed to build PKCS#7 signature');
  }

  const signatureAsHex = signature.toString('hex');

  const signedPdf = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(Buffer.from(`<${signatureAsHex.padEnd(signatureLength - 2, '0')}>`)),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  logger.info(
    { module: 'azure-key-vault-hsm', withTimestamp: !!timestampToken },
    'PDF signed successfully with Azure Key Vault HSM',
  );

  // Add LTV (Long-Term Validation) information
  const ltvEnabledPdf = await addLTV({
    pdf: signedPdf,
    certificate: cert,
    certificateChain: certificateChain.length > 0 ? certificateChain : undefined,
    signature,
    moduleName: 'azure-key-vault-hsm',
  });

  return ltvEnabledPdf;
};
