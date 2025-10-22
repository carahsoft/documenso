#!/usr/bin/env tsx

/**
 * Integration test for document signing
 *
 * Usage:
 *   cd packages/signing
 *   tsx test-signing.ts <input-pdf-path> <output-pdf-path>
 *
 * Example:
 *   tsx test-signing.ts ~/test-input.pdf ~/test-output.pdf
 *
 * Required environment variables:
 *   NEXT_PRIVATE_SIGNING_TRANSPORT (local, gcloud-hsm, or azure-hsm)
 *
 * Transport-specific required variables:
 *
 * Local transport:
 *   NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH or NEXT_PRIVATE_SIGNING_LOCAL_FILE_CONTENTS
 *   NEXT_PRIVATE_SIGNING_PASSPHRASE (optional)
 *
 * Google Cloud HSM transport:
 *   NEXT_PRIVATE_SIGNING_GCLOUD_HSM_KEY_PATH
 *   NEXT_PRIVATE_SIGNING_GCLOUD_HSM_PUBLIC_CRT_FILE_PATH or NEXT_PRIVATE_SIGNING_GCLOUD_HSM_PUBLIC_CRT_FILE_CONTENTS
 *
 * Azure HSM transport:
 *   NEXT_PRIVATE_SIGNING_AZURE_KEY_VAULT_URL
 *   NEXT_PRIVATE_SIGNING_AZURE_KEY_NAME
 *   NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_NAME
 *   NEXT_PRIVATE_SIGNING_AZURE_TENANT_ID (optional, for service principal)
 *   NEXT_PRIVATE_SIGNING_AZURE_CLIENT_ID (optional, for service principal)
 *   NEXT_PRIVATE_SIGNING_AZURE_CLIENT_SECRET (optional, for service principal)
 *   NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CONTENTS (optional, base64)
 *   NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_PATH (optional)
 *   NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_CONTENTS (optional, base64, comma-separated)
 *   NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_PATH (optional)
 *
 * Optional environment variables (all transports):
 *   NEXT_PRIVATE_SIGNING_TIMESTAMP_SERVER_URL
 */
import fs from 'fs';
import path from 'path';

import { signWithAzureKeyVaultHSM } from './transports/azure-key-vault-hsm';
import { signWithGoogleCloudHSM } from './transports/google-cloud-hsm';
import { signWithLocalCert } from './transports/local-cert';

async function main() {
  const args = process.argv.slice(2);

  if (args.length < 2) {
    console.error('Usage: tsx test-signing.ts <input-pdf-path> <output-pdf-path>');
    console.error('');
    console.error('Example:');
    console.error('  tsx test-signing.ts ~/test-input.pdf ~/test-output.pdf');
    process.exit(1);
  }

  const [inputPath, outputPath] = args;

  // Resolve paths
  const resolvedInputPath = path.resolve(inputPath);
  const resolvedOutputPath = path.resolve(outputPath);

  // Check transport type
  const transport = process.env.NEXT_PRIVATE_SIGNING_TRANSPORT;

  if (!transport) {
    console.error('❌ Error: NEXT_PRIVATE_SIGNING_TRANSPORT is not set');
    console.error('');
    console.error('Valid values: local, gcloud-hsm, azure-hsm');
    process.exit(1);
  }

  console.log(`\n=== Document Signing Test (${transport}) ===\n`);
  console.log(`Input PDF:  ${resolvedInputPath}`);
  console.log(`Output PDF: ${resolvedOutputPath}\n`);

  // Check input file exists
  if (!fs.existsSync(resolvedInputPath)) {
    console.error(`❌ Error: Input PDF not found: ${resolvedInputPath}`);
    process.exit(1);
  }

  // Display configuration
  console.log('Environment Configuration:');
  console.log(`  Transport: ${transport}`);

  console.log('\n--- Starting signing process ---\n');

  try {
    // Read input PDF
    const pdfBuffer = fs.readFileSync(resolvedInputPath);
    console.log(`✓ Read input PDF (${pdfBuffer.length} bytes)`);

    // Sign the PDF based on transport
    const startTime = Date.now();
    let signedPdf: Buffer | Uint8Array;

    switch (transport) {
      case 'local':
        signedPdf = await signWithLocalCert({ pdf: pdfBuffer });
        break;
      case 'gcloud-hsm':
        signedPdf = await signWithGoogleCloudHSM({ pdf: pdfBuffer });
        break;
      case 'azure-hsm':
        signedPdf = await signWithAzureKeyVaultHSM({ pdf: pdfBuffer });
        break;
      default:
        throw new Error(`Unsupported transport: ${transport}`);
    }

    const duration = Date.now() - startTime;

    console.log(`✓ PDF signed successfully in ${duration}ms`);

    // Write output PDF
    fs.writeFileSync(resolvedOutputPath, signedPdf as Buffer);
    console.log(`✓ Wrote signed PDF (${signedPdf.length} bytes)`);
  } catch (error) {
    console.error('\n=== ❌ Error during signing ===\n');

    if (error instanceof Error) {
      console.error(`Error: ${error.message}`);
      if (error.stack) {
        console.error('\nStack trace:');
        console.error(error.stack);
      }
    } else {
      console.error('Unknown error:', error);
    }

    process.exit(1);
  }
}

// Run the test
main().catch((error) => {
  console.error('Unhandled error:', error);
  process.exit(1);
});
