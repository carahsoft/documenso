import forge from 'node-forge';

import { logger } from '@documenso/lib/utils/logger';

import { parseCertificate } from './pkcs7';

/**
 * Extract OCSP responder URL from certificate's Authority Information Access extension
 *
 * @param certificate - Certificate in DER or PEM format
 * @returns OCSP responder URL or null if not found
 */
export function getOCSPResponderUrl(certificate: Buffer): string | null {
  try {
    const cert = parseCertificate(certificate);

    // Find Authority Information Access extension
    const aiaExtension = cert.extensions.find(
      (ext) => ext.name === 'authorityInfoAccess' || ext.id === '1.3.6.1.5.5.7.1.1',
    );

    if (!aiaExtension) {
      logger.debug({ module: 'ocsp' }, 'No Authority Information Access extension found');
      return null;
    }

    // Parse AIA extension value
    // The extension value contains a SEQUENCE of AccessDescription
    // Each AccessDescription has accessMethod (OID) and accessLocation (URI)
    const extensionValue = aiaExtension.value;

    if (typeof extensionValue === 'string') {
      // Parse the DER-encoded extension value
      const asn1 = forge.asn1.fromDer(extensionValue);

      // AIA is a SEQUENCE of AccessDescription
      if (asn1.value && Array.isArray(asn1.value)) {
        for (const accessDesc of asn1.value) {
          if (accessDesc.value && Array.isArray(accessDesc.value) && accessDesc.value.length >= 2) {
            const accessMethod = accessDesc.value[0];
            const accessLocation = accessDesc.value[1];

            // Check if accessMethod is OCSP (1.3.6.1.5.5.7.48.1)
            if (
              accessMethod.type === forge.asn1.Type.OID &&
              forge.asn1.derToOid(accessMethod.value as string) === '1.3.6.1.5.5.7.48.1'
            ) {
              // accessLocation is [6] IMPLICIT (uniformResourceIdentifier)
              if (accessLocation.type === 6 && accessLocation.value) {
                return accessLocation.value as string;
              }
            }
          }
        }
      }
    }

    return null;
  } catch (error) {
    logger.warn({ module: 'ocsp', error }, 'Failed to extract OCSP responder URL');
    return null;
  }
}

/**
 * Build an OCSP request for a certificate
 *
 * @param certificate - The certificate to check
 * @param issuerCertificate - The issuer certificate
 * @returns DER-encoded OCSP request
 */
export function buildOCSPRequest(certificate: Buffer, issuerCertificate: Buffer): Buffer {
  const cert = parseCertificate(certificate);
  const issuerCert = parseCertificate(issuerCertificate);

  // Build CertID
  // CertID ::= SEQUENCE {
  //   hashAlgorithm  AlgorithmIdentifier,
  //   issuerNameHash OCTET STRING,
  //   issuerKeyHash  OCTET STRING,
  //   serialNumber   INTEGER
  // }

  // Hash algorithm (SHA-1 is standard for OCSP)
  const hashAlgorithm = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer('1.3.14.3.2.26').getBytes(), // SHA-1 OID
    ),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
  ]);

  // Hash the issuer's Distinguished Name
  const issuerNameDer = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(issuerCert.subject));
  const issuerNameHash = forge.md.sha1.create().update(issuerNameDer.getBytes()).digest();

  // Hash the issuer's public key (the BIT STRING value, not the whole SubjectPublicKeyInfo)
  const issuerPublicKeyDer = forge.asn1.toDer(
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      (forge.pki.publicKeyToAsn1(issuerCert.publicKey) as any).value,
    ),
  );
  const issuerKeyHash = forge.md.sha1.create().update(issuerPublicKeyDer.getBytes()).digest();

  // Build CertID
  const certId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    hashAlgorithm,
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OCTETSTRING,
      false,
      issuerNameHash.getBytes(),
    ),
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OCTETSTRING,
      false,
      issuerKeyHash.getBytes(),
    ),
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.INTEGER,
      false,
      forge.util.hexToBytes(cert.serialNumber),
    ),
  ]);

  // Build Request
  // Request ::= SEQUENCE {
  //   reqCert    CertID,
  //   singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
  // }
  const request = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    certId,
  ]);

  // Build TBSRequest
  // TBSRequest ::= SEQUENCE {
  //   version       [0] EXPLICIT Version DEFAULT v1,
  //   requestorName [1] EXPLICIT GeneralName OPTIONAL,
  //   requestList   SEQUENCE OF Request,
  //   requestExtensions [2] EXPLICIT Extensions OPTIONAL
  // }
  const tbsRequest = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [request]),
  ]);

  // Build OCSPRequest
  // OCSPRequest ::= SEQUENCE {
  //   tbsRequest  TBSRequest,
  //   optionalSignature [0] EXPLICIT Signature OPTIONAL
  // }
  const ocspRequest = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [tbsRequest],
  );

  const der = forge.asn1.toDer(ocspRequest).getBytes();
  return Buffer.from(der, 'binary');
}

/**
 * Fetch OCSP response for a certificate
 *
 * @param certificate - The certificate to check
 * @param issuerCertificate - The issuer certificate
 * @param ocspUrl - Optional OCSP responder URL (if not provided, will extract from cert)
 * @param moduleName - Module name for logging
 * @returns OCSP response as Buffer, or null if failed
 */
export async function fetchOCSPResponse(
  certificate: Buffer,
  issuerCertificate: Buffer,
  ocspUrl?: string,
  moduleName = 'ocsp',
): Promise<Buffer | null> {
  try {
    // Get OCSP URL if not provided
    const responderUrl = ocspUrl || getOCSPResponderUrl(certificate);

    if (!responderUrl) {
      logger.warn(
        { module: moduleName },
        'No OCSP responder URL found in certificate, skipping OCSP',
      );
      return null;
    }

    logger.info({ module: moduleName, ocspUrl: responderUrl }, 'Fetching OCSP response');

    // Build OCSP request
    const ocspRequest = buildOCSPRequest(certificate, issuerCertificate);

    // Send OCSP request
    const response = await fetch(responderUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/ocsp-request',
        Accept: 'application/ocsp-response',
      },
      body: ocspRequest,
    });

    if (!response.ok) {
      logger.warn(
        { module: moduleName, status: response.status, statusText: response.statusText },
        'OCSP request failed',
      );
      return null;
    }

    const responseBuffer = Buffer.from(await response.arrayBuffer());

    logger.info(
      { module: moduleName, responseSize: responseBuffer.length },
      'OCSP response received',
    );

    // Validate OCSP response structure
    try {
      const asn1 = forge.asn1.fromDer(forge.util.createBuffer(responseBuffer));

      // OCSPResponse ::= SEQUENCE {
      //   responseStatus  OCSPResponseStatus,
      //   responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
      // }

      if (!asn1.value || !Array.isArray(asn1.value) || asn1.value.length === 0) {
        logger.warn({ module: moduleName }, 'Invalid OCSP response structure');
        return null;
      }

      const responseStatus = asn1.value[0];
      if (responseStatus.type !== forge.asn1.Type.ENUMERATED) {
        logger.warn({ module: moduleName }, 'Invalid OCSP response status');
        return null;
      }

      const statusValue = responseStatus.value as string;
      const statusCode = statusValue.charCodeAt(0);

      if (statusCode !== 0) {
        // 0 = successful, 1 = malformedRequest, 2 = internalError, etc.
        logger.warn(
          { module: moduleName, statusCode },
          'OCSP response indicates error status',
        );
        return null;
      }

      logger.info({ module: moduleName }, 'OCSP response validated successfully');
      return responseBuffer;
    } catch (error) {
      logger.warn({ module: moduleName, error }, 'Failed to validate OCSP response structure');
      return null;
    }
  } catch (error) {
    logger.warn({ module: moduleName, error }, 'Failed to fetch OCSP response');
    return null;
  }
}

/**
 * Fetch OCSP responses for a certificate chain
 *
 * @param certificates - Array of certificates (leaf first, then intermediates, then root)
 * @param moduleName - Module name for logging
 * @returns Array of OCSP responses (may contain nulls for certificates without OCSP)
 */
export async function fetchOCSPResponsesForChain(
  certificates: Buffer[],
  moduleName = 'ocsp',
): Promise<(Buffer | null)[]> {
  const ocspResponses: (Buffer | null)[] = [];

  // Process each certificate except the last (root) one
  for (let i = 0; i < certificates.length - 1; i++) {
    const cert = certificates[i];
    const issuerCert = certificates[i + 1];

    logger.info(
      { module: moduleName, certIndex: i, totalCerts: certificates.length },
      'Fetching OCSP for certificate in chain',
    );

    const ocspResponse = await fetchOCSPResponse(cert, issuerCert, undefined, moduleName);
    ocspResponses.push(ocspResponse);
  }

  return ocspResponses;
}
