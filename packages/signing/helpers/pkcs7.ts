import forge from 'node-forge';

import { logger } from '@documenso/lib/utils/logger';

/**
 * Parse certificate from Buffer to forge Certificate format
 *
 * Handles both DER and PEM formats automatically.
 *
 * @param certificate - Certificate in DER or PEM format as Buffer
 * @returns Parsed forge certificate object
 * @throws Error if certificate cannot be parsed
 */
export function parseCertificate(certificate: Buffer): forge.pki.Certificate {
  let certPem: string;

  try {
    // Try to parse as DER format
    const asn1Cert = forge.asn1.fromDer(forge.util.createBuffer(certificate));
    const forgeCert = forge.pki.certificateFromAsn1(asn1Cert);
    return forgeCert;
  } catch {
    // If it fails, assume it's already in PEM format
    certPem = certificate.toString('utf8');
    return forge.pki.certificateFromPem(certPem);
  }
}

/**
 * Build authenticated attributes for PKCS#7 signature
 *
 * Authenticated attributes include contentType and messageDigest.
 * This creates a SET of attributes that gets signed as part of the SignerInfo.
 * The structure is:
 * - SET (with UNIVERSAL class for DER encoding)
 *   - SEQUENCE (contentType attribute)
 *     - OID (contentType)
 *     - SET
 *       - OID (data)
 *   - SEQUENCE (messageDigest attribute)
 *     - OID (messageDigest)
 *     - SET
 *       - OCTETSTRING (hash of content)
 *
 * @param pdfHash - The SHA-256 hash of the PDF content
 * @returns DER-encoded authenticated attributes as a Buffer
 */
export function buildAuthenticatedAttributes(pdfHash: Buffer): Buffer {
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
 * Build a PKCS#7 signature structure with optional timestamp token
 *
 * This manually constructs a PKCS#7/CMS SignedData structure using node-forge's ASN.1 API.
 * This approach is necessary when we have a pre-computed signature (e.g., from HSM)
 * and cannot access the private key (which node-forge's high-level API requires).
 *
 * The structure follows RFC 5652 (CMS - Cryptographic Message Syntax):
 * - ContentInfo
 *   - contentType (signedData OID)
 *   - content [0] EXPLICIT
 *     - SignedData
 *       - version
 *       - digestAlgorithms
 *       - encapContentInfo (empty for detached signatures)
 *       - certificates [0] IMPLICIT
 *       - signerInfos
 *         - SignerInfo
 *           - version
 *           - issuerAndSerialNumber
 *           - digestAlgorithm
 *           - authenticatedAttributes [0] IMPLICIT (contentType, messageDigest)
 *           - digestEncryptionAlgorithm
 *           - encryptedDigest (the signature)
 *           - unauthenticatedAttributes [1] IMPLICIT (optional timestamp token)
 *
 * @param signature - The pre-computed signature value (encrypted digest)
 * @param certificate - The signing certificate in DER or PEM format
 * @param pdfHash - The hash of the PDF content (SHA-256)
 * @param timestampToken - Optional timestamp token from TSA (RFC 3161)
 * @param moduleName - Module name for logging (default: 'pkcs7')
 * @param certificateChain - Optional array of intermediate/root CA certificates
 * @returns The complete PKCS#7 signature structure as a Buffer
 */
export function buildPKCS7Signature(
  signature: Uint8Array,
  certificate: Buffer,
  pdfHash: Buffer,
  timestampToken?: Buffer,
  moduleName = 'pkcs7',
  certificateChain?: Buffer[],
): Buffer {
  try {
    const cert = parseCertificate(certificate);

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

    // Build SignerInfo elements
    const signerInfoElements = [
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
      // encryptedDigest (the signature from HSM)
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OCTETSTRING,
        false,
        forge.util.createBuffer(signature).getBytes(),
      ),
    ];

    // Add unauthenticated attributes with timestamp token if provided
    if (timestampToken) {
      const timestampTokenAsn1 = forge.asn1.fromDer(
        forge.util.createBuffer(timestampToken.toString('binary')),
      );

      // Build unauthenticated attributes with timestamp token
      // OID for timestamp token: 1.2.840.113549.1.9.16.2.14 (id-aa-signatureTimeStampToken)
      const unauthenticatedAttributesAsn1 = forge.asn1.create(
        forge.asn1.Class.CONTEXT_SPECIFIC,
        1,
        true,
        [
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.OID,
              false,
              forge.asn1.oidToDer('1.2.840.113549.1.9.16.2.14').getBytes(),
            ),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
              timestampTokenAsn1,
            ]),
          ]),
        ],
      );

      signerInfoElements.push(unauthenticatedAttributesAsn1);
    }

    // Build SignerInfo
    const signerInfo = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      signerInfoElements,
    );

    // Get certificate as ASN.1
    const certAsn1 = forge.pki.certificateToAsn1(cert);

    // Build certificate chain array starting with signing certificate
    const certChainAsn1 = [certAsn1];

    // Add intermediate and root certificates if provided
    if (certificateChain && certificateChain.length > 0) {
      logger.info(
        { module: moduleName, chainLength: certificateChain.length },
        'Adding certificate chain',
      );

      for (const chainCert of certificateChain) {
        try {
          const chainCertParsed = parseCertificate(chainCert);
          const chainCertAsn1 = forge.pki.certificateToAsn1(chainCertParsed);
          certChainAsn1.push(chainCertAsn1);
        } catch (error) {
          logger.warn(
            { module: moduleName, error },
            'Failed to parse certificate in chain, skipping',
          );
        }
      }
    }

    // Build SignedData structure elements
    const signedDataElements = [
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
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, certChainAsn1),
    ];

    // Add signerInfos
    signedDataElements.push(
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [signerInfo]),
    );

    // Build SignedData structure
    const signedData = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      signedDataElements,
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
    logger.error({ module: moduleName, error }, 'Error building PKCS#7 signature');
    throw error;
  }
}
