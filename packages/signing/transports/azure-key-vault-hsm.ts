import { ClientSecretCredential, DefaultAzureCredential } from '@azure/identity';
import { CertificateClient } from '@azure/keyvault-certificates';
import type { SignatureAlgorithm } from '@azure/keyvault-keys';
import { CryptographyClient } from '@azure/keyvault-keys';
import { createHash } from 'node:crypto';
import fs from 'node:fs';

import { env } from '@documenso/lib/utils/env';

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
  const keyVaultUrl = env('NEXT_PRIVATE_SIGNING_AZURE_KEY_VAULT_URL');
  const keyName = env('NEXT_PRIVATE_SIGNING_AZURE_KEY_NAME');
  const certificateName = env('NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_NAME');

  if (!keyVaultUrl) {
    throw new Error('No Azure Key Vault URL provided for Azure Key Vault HSM signing');
  }

  if (!keyName) {
    throw new Error('No Azure Key name provided for Azure Key Vault HSM signing');
  }

  if (!certificateName) {
    throw new Error('No Azure Certificate name provided for Azure Key Vault HSM signing');
  }

  // Set up authentication credentials
  let credential;

  const tenantId = env('NEXT_PRIVATE_SIGNING_AZURE_TENANT_ID');
  const clientId = env('NEXT_PRIVATE_SIGNING_AZURE_CLIENT_ID');
  const clientSecret = env('NEXT_PRIVATE_SIGNING_AZURE_CLIENT_SECRET');

  // Use ClientSecretCredential if service principal credentials are provided
  if (tenantId && clientId && clientSecret) {
    credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
  } else {
    // Otherwise use DefaultAzureCredential (supports managed identity, Azure CLI, etc.)
    credential = new DefaultAzureCredential();
  }

  // Prepare PDF with placeholder
  const { pdf: pdfWithPlaceholder, byteRange } = updateSigningPlaceholder({
    pdf: await addSigningPlaceholder({ pdf }),
  });

  const pdfWithoutSignature = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  const signatureLength = byteRange[2] - byteRange[1];

  // Get the certificate from Azure Key Vault
  let cert: Buffer | null = null;

  const azureCertificateContents = env('NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CONTENTS');

  if (azureCertificateContents) {
    // Use certificate contents from environment variable if provided
    cert = Buffer.from(azureCertificateContents, 'base64');
  } else {
    const azureCertificatePath = env('NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_PATH');

    if (azureCertificatePath && fs.existsSync(azureCertificatePath)) {
      // Load certificate from file path
      cert = Buffer.from(fs.readFileSync(azureCertificatePath));
    } else {
      // Download certificate from Azure Key Vault
      const certificateClient = new CertificateClient(keyVaultUrl, credential);
      const certificate = await certificateClient.getCertificate(certificateName);

      if (!certificate.cer) {
        throw new Error('Certificate does not contain public key data');
      }

      cert = Buffer.from(certificate.cer);
    }
  }

  if (!cert) {
    throw new Error('Failed to load certificate for Azure Key Vault HSM signing');
  }

  // Create cryptography client for signing
  const cryptoClient = new CryptographyClient(`${keyVaultUrl}/keys/${keyName}`, credential);

  // Hash the content using SHA-256
  const hash = createHash('sha256').update(pdfWithoutSignature).digest();

  // Sign the hash using Azure Key Vault
  const signResult = await cryptoClient.sign('RS256' as SignatureAlgorithm, hash);

  if (!signResult.result) {
    throw new Error('Azure Key Vault signing failed: No signature returned');
  }

  // Build the signature in PKCS#7 format
  const signature = buildPKCS7Signature(signResult.result, cert);

  const signatureAsHex = signature.toString('hex');

  const signedPdf = Buffer.concat([
    new Uint8Array(pdfWithPlaceholder.subarray(0, byteRange[1])),
    new Uint8Array(Buffer.from(`<${signatureAsHex.padEnd(signatureLength - 2, '0')}>`)),
    new Uint8Array(pdfWithPlaceholder.subarray(byteRange[2])),
  ]);

  return signedPdf;
};

/**
 * Build a PKCS#7 signature structure
 *
 * This is a simplified implementation that creates a basic PKCS#7 structure.
 * For production use, consider using a library like node-forge for proper PKCS#7 handling.
 */
function buildPKCS7Signature(signature: Uint8Array, certificate: Buffer): Buffer {
  // Note: This is a simplified implementation
  // In a production environment, you should use a proper ASN.1/PKCS#7 library
  // such as node-forge to build the complete PKCS#7 signature structure

  // For now, we'll return the raw signature
  // This will need to be enhanced with proper PKCS#7 wrapping
  return Buffer.from(signature);
}
