import { ClientSecretCredential, DefaultAzureCredential } from '@azure/identity';
import { CertificateClient } from '@azure/keyvault-certificates';
import type { SignatureAlgorithm } from '@azure/keyvault-keys';
import { CryptographyClient } from '@azure/keyvault-keys';
import forge from 'node-forge';
import { createHash } from 'node:crypto';
import fs from 'node:fs';

import { AppError, AppErrorCode } from '@documenso/lib/errors/app-error';
import { env } from '@documenso/lib/utils/env';
import { logger } from '@documenso/lib/utils/logger';

import { addSigningPlaceholder } from '../helpers/add-signing-placeholder';
import { updateSigningPlaceholder } from '../helpers/update-signing-placeholder';

export type SignWithAzureKeyVaultHSMOptions = {
  pdf: Buffer;
};

/**
 * Sign a PDF document using Azure Key Vault HSM
 *
 * This function uses Azure Key Vault's cryptographic signing capabilities to sign PDFs.
 * It supports both DefaultAzureCredential (for managed identities, Azure CLI, etc.)
 * and ClientSecretCredential (for service principal authentication).
 */
export const signWithAzureKeyVaultHSM = async ({ pdf }: SignWithAzureKeyVaultHSMOptions) => {
  logger.info({ module: 'azure-key-vault-hsm' }, 'Starting Azure Key Vault HSM signing process');

  const keyVaultUrl = env('NEXT_PRIVATE_SIGNING_AZURE_KEY_VAULT_URL');
  const keyName = env('NEXT_PRIVATE_SIGNING_AZURE_KEY_NAME');
  const certificateName = env('NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_NAME');

  if (!keyVaultUrl) {
    logger.error({ module: 'azure-key-vault-hsm' }, 'Azure Key Vault URL not configured');
    throw new AppError(AppErrorCode.NOT_SETUP, {
      message: 'No Azure Key Vault URL provided for Azure Key Vault HSM signing',
    });
  }

  if (!keyName) {
    logger.error({ module: 'azure-key-vault-hsm' }, 'Azure Key name not configured');
    throw new AppError(AppErrorCode.NOT_SETUP, {
      message: 'No Azure Key name provided for Azure Key Vault HSM signing',
    });
  }

  if (!certificateName) {
    logger.error({ module: 'azure-key-vault-hsm' }, 'Azure Certificate name not configured');
    throw new AppError(AppErrorCode.NOT_SETUP, {
      message: 'No Azure Certificate name provided for Azure Key Vault HSM signing',
    });
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
    throw new AppError(AppErrorCode.NOT_SETUP, {
      message: 'Failed to initialize Azure credentials',
    });
  }

  // Prepare PDF with placeholder
  logger.info({ module: 'azure-key-vault-hsm' }, 'Preparing PDF with signing placeholder');

  let pdfWithPlaceholder: Buffer;
  let byteRange: number[];

  try {
    const placeholderResult = updateSigningPlaceholder({
      pdf: await addSigningPlaceholder({ pdf }),
    });
    pdfWithPlaceholder = placeholderResult.pdf;
    byteRange = placeholderResult.byteRange;
  } catch (error) {
    logger.error(
      { module: 'azure-key-vault-hsm', error },
      'Failed to prepare PDF with signing placeholder',
    );
    throw new AppError(AppErrorCode.INVALID_BODY, {
      message: 'Failed to prepare PDF for signing',
    });
  }

  const pdfWithoutSignature = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  const signatureLength = byteRange[2] - byteRange[1];

  logger.info({ module: 'azure-key-vault-hsm', signatureLength }, 'PDF prepared with placeholder');

  // Get the certificate from Azure Key Vault
  logger.info({ module: 'azure-key-vault-hsm' }, 'Loading certificate');

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
          throw new AppError(AppErrorCode.NOT_FOUND, {
            message: 'Certificate does not contain public key data',
          });
        }

        cert = Buffer.from(certificate.cer);
      }
    }
  } catch (error) {
    logger.error({ module: 'azure-key-vault-hsm', error }, 'Failed to load certificate');

    if (error instanceof AppError) {
      throw error;
    }

    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Failed to load certificate for Azure Key Vault HSM signing',
    });
  }

  if (!cert) {
    logger.error({ module: 'azure-key-vault-hsm' }, 'Certificate is null after loading');
    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Failed to load certificate for Azure Key Vault HSM signing',
    });
  }

  logger.info({ module: 'azure-key-vault-hsm' }, 'Certificate loaded successfully');

  // Create cryptography client for signing
  logger.info({ module: 'azure-key-vault-hsm', keyName }, 'Creating cryptography client');

  let cryptoClient: CryptographyClient;

  try {
    cryptoClient = new CryptographyClient(`${keyVaultUrl}/keys/${keyName}`, credential);
  } catch (error) {
    logger.error({ module: 'azure-key-vault-hsm', error }, 'Failed to create cryptography client');
    throw new AppError(AppErrorCode.UNKNOWN_ERROR, {
      message: 'Failed to create cryptography client',
    });
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
      'RS256' as SignatureAlgorithm,
      new Uint8Array(authenticatedAttributesHash),
    );
  } catch (error) {
    logger.error(
      { module: 'azure-key-vault-hsm', error },
      'Azure Key Vault signing operation failed',
    );
    throw new AppError(AppErrorCode.UNKNOWN_ERROR, {
      message: 'Azure Key Vault signing operation failed',
    });
  }

  if (!signResult.result) {
    logger.error(
      { module: 'azure-key-vault-hsm' },
      'Azure Key Vault signing returned no signature',
    );
    throw new AppError(AppErrorCode.UNKNOWN_ERROR, {
      message: 'Azure Key Vault signing failed: No signature returned',
    });
  }

  logger.info(
    { module: 'azure-key-vault-hsm' },
    'Authenticated attributes hash signed successfully',
  );

  // Build the signature in PKCS#7 format
  logger.info({ module: 'azure-key-vault-hsm' }, 'Building PKCS#7 signature');

  let signature: Buffer;

  try {
    signature = buildPKCS7Signature(signResult.result, cert, pdfHash);
  } catch (error) {
    logger.error({ module: 'azure-key-vault-hsm', error }, 'Failed to build PKCS#7 signature');
    throw new AppError(AppErrorCode.UNKNOWN_ERROR, {
      message: 'Failed to build PKCS#7 signature',
    });
  }

  const signatureAsHex = signature.toString('hex');

  logger.info(
    { module: 'azure-key-vault-hsm', signatureLength: signatureAsHex.length },
    'Embedding signature into PDF',
  );

  const signedPdf = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(Buffer.from(`<${signatureAsHex.padEnd(signatureLength - 2, '0')}>`)),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  logger.info(
    { module: 'azure-key-vault-hsm' },
    'PDF signed successfully with Azure Key Vault HSM',
  );

  return signedPdf;
};

/**
 * Build authenticated attributes for PKCS#7 signature
 *
 * Authenticated attributes include contentType and messageDigest.
 * This needs to be DER-encoded with the SET tag to produce the data that gets signed.
 */
function buildAuthenticatedAttributes(pdfHash: Buffer): Buffer {
  // Build authenticated attributes (contentType + messageDigest)
  const authenticatedAttributesAsn1 = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    [
      // contentType attribute
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(forge.pki.oids.contentType).getBytes(),
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer(forge.pki.oids.data).getBytes(),
          ),
        ]),
      ]),
      // messageDigest attribute
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(forge.pki.oids.messageDigest).getBytes(),
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OCTETSTRING,
            false,
            forge.util.createBuffer(pdfHash).getBytes(),
          ),
        ]),
      ]),
    ],
  );

  // Convert to DER format for signing
  const der = forge.asn1.toDer(authenticatedAttributesAsn1).getBytes();
  return Buffer.from(der, 'binary');
}

/**
 * Build a PKCS#7 signature structure
 *
 * This manually constructs a PKCS#7/CMS SignedData structure using node-forge's ASN.1 API.
 * This approach is necessary because we have a pre-computed signature from Azure Key Vault HSM
 * and cannot access the private key (which node-forge's high-level API requires).
 */
function buildPKCS7Signature(signature: Uint8Array, certificate: Buffer, pdfHash: Buffer): Buffer {
  try {
    // Convert the certificate from DER to PEM format if needed
    let certPem: string;

    try {
      // Try to parse as DER format
      const asn1Cert = forge.asn1.fromDer(forge.util.createBuffer(certificate));
      const forgeCert = forge.pki.certificateFromAsn1(asn1Cert);
      certPem = forge.pki.certificateToPem(forgeCert);
    } catch {
      // If it fails, assume it's already in PEM format
      certPem = certificate.toString('utf8');
    }

    const cert = forge.pki.certificateFromPem(certPem);

    // Manually construct PKCS#7 SignedData structure using ASN.1
    // Structure: ContentInfo with signedData OID containing SignedData

    // Build authenticated attributes (contentType + messageDigest)
    // Note: We use CONTEXT_SPECIFIC class because this is the [0] IMPLICIT tag in SignerInfo
    const authenticatedAttributesAsn1 = forge.asn1.create(
      forge.asn1.Class.CONTEXT_SPECIFIC,
      0,
      true,
      [
        // contentType attribute
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer(forge.pki.oids.contentType).getBytes(),
          ),
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.OID,
              false,
              forge.asn1.oidToDer(forge.pki.oids.data).getBytes(),
            ),
          ]),
        ]),
        // messageDigest attribute - contains the hash of the PDF content
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer(forge.pki.oids.messageDigest).getBytes(),
          ),
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.OCTETSTRING,
              false,
              forge.util.createBuffer(pdfHash).getBytes(),
            ),
          ]),
        ]),
      ],
    );

    // Build SignerInfo
    const signerInfo = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      [
        // version (1)
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.INTEGER,
          false,
          String.fromCharCode(1),
        ),
        // issuerAndSerialNumber
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.pki.distinguishedNameToAsn1(cert.issuer),
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.INTEGER,
            false,
            forge.util.hexToBytes(cert.serialNumber),
          ),
        ]),
        // digestAlgorithm (SHA-256)
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer(forge.pki.oids.sha256).getBytes(),
          ),
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
        ]),
        // authenticatedAttributes [0] IMPLICIT
        authenticatedAttributesAsn1,
        // digestEncryptionAlgorithm (RSA)
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer(forge.pki.oids.rsaEncryption).getBytes(),
          ),
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
        ]),
        // encryptedDigest (the signature from Azure HSM)
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OCTETSTRING,
          false,
          forge.util.createBuffer(signature).getBytes(),
        ),
      ],
    );

    // Get certificate as ASN.1
    const certAsn1 = forge.pki.certificateToAsn1(cert);

    // Build SignedData structure
    const signedData = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      [
        // version (1)
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.INTEGER,
          false,
          String.fromCharCode(1),
        ),
        // digestAlgorithms
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.OID,
              false,
              forge.asn1.oidToDer(forge.pki.oids.sha256).getBytes(),
            ),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
          ]),
        ]),
        // contentInfo (empty for detached signature)
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer(forge.pki.oids.data).getBytes(),
          ),
        ]),
        // certificates [0] IMPLICIT
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [certAsn1]),
        // signerInfos
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [signerInfo]),
      ],
    );

    // Wrap in ContentInfo
    const contentInfo = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(forge.pki.oids.signedData).getBytes(),
        ),
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [signedData]),
      ],
    );

    // Convert to DER format
    const der = forge.asn1.toDer(contentInfo).getBytes();
    return Buffer.from(der, 'binary');
  } catch (error) {
    logger.error({ module: 'azure-key-vault-hsm', error }, 'Error building PKCS#7 signature');
    throw error;
  }
}
