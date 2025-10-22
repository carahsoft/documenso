import forge from 'node-forge';
import http from 'node:http';
import https from 'node:https';

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

  logger.debug(
    {
      module: 'ocsp',
      certSubject: cert.subject.getField('CN')?.value,
      certSerial: cert.serialNumber,
      issuerSubject: issuerCert.subject.getField('CN')?.value,
    },
    'Building OCSP request',
  );

  // Hash issuer name
  const md1 = forge.md.sha1.create();
  const issuerNameDer = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(issuerCert.subject));
  md1.update(issuerNameDer.getBytes());
  const issuerNameHash = md1.digest().getBytes();

  // Hash issuer public key
  const md2 = forge.md.sha1.create();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const issuerCertDer = forge.asn1.toDer((issuerCert as any).tbsCertificate).getBytes();
  const issuerCertAsn1 = forge.asn1.fromDer(issuerCertDer);

  if (
    issuerCertAsn1.type === forge.asn1.Type.SEQUENCE &&
    issuerCertAsn1.value &&
    Array.isArray(issuerCertAsn1.value)
  ) {
    let subjectPublicKeyInfo: forge.asn1.Asn1 | null = null;

    for (const field of issuerCertAsn1.value) {
      if (
        field.type === forge.asn1.Type.SEQUENCE &&
        Array.isArray(field.value) &&
        field.value.length === 2
      ) {
        const first = field.value[0];
        const second = field.value[1];
        if (first.type === forge.asn1.Type.SEQUENCE && second.type === forge.asn1.Type.BITSTRING) {
          subjectPublicKeyInfo = field;
          break;
        }
      }
    }

    if (subjectPublicKeyInfo && Array.isArray(subjectPublicKeyInfo.value)) {
      const publicKeyBitString = subjectPublicKeyInfo.value[1];

      if (publicKeyBitString && publicKeyBitString.type === forge.asn1.Type.BITSTRING) {
        const bitStringDer = forge.asn1.toDer(publicKeyBitString);
        const bitStringBytes = bitStringDer.getBytes();

        let offset = 1; // Skip tag
        const lengthByte = bitStringBytes.charCodeAt(offset);
        offset++;

        if (lengthByte & 0x80) {
          const numLengthBytes = lengthByte & 0x7f;
          offset += numLengthBytes;
        }

        const publicKeyBits = bitStringBytes.slice(offset + 1);
        if (publicKeyBits.length > 0) {
          md2.update(publicKeyBits);
        }
      }
    }
  }

  const issuerKeyHash = md2.digest().getBytes();

  // Build CertID
  const certId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OID,
        false,
        forge.asn1.oidToDer('1.3.14.3.2.26').getBytes(),
      ),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
    ]),
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OCTETSTRING,
      false,
      issuerNameHash,
    ),
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OCTETSTRING,
      false,
      issuerKeyHash,
    ),
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.INTEGER,
      false,
      forge.util.hexToBytes(cert.serialNumber),
    ),
  ]);

  // Build Request
  const request = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    certId,
  ]);

  // Generate random nonce
  const nonceBytes = forge.random.getBytesSync(16);

  // Build nonce extension
  const nonceExtension = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OID,
        false,
        forge.asn1.oidToDer('1.3.6.1.5.5.7.48.1.2').getBytes(),
      ),
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OCTETSTRING,
        false,
        forge.asn1
          .toDer(
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.OCTETSTRING,
              false,
              nonceBytes,
            ),
          )
          .getBytes(),
      ),
    ],
  );

  // Build requestExtensions [2] EXPLICIT
  const requestExtensions = forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 2, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [nonceExtension]),
  ]);

  // Build TBSRequest
  const tbsRequest = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [request]),
    requestExtensions,
  ]);

  // Build OCSPRequest
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
 * Add OCSP signing certificate chain to OCSPResponse
 *
 * Adobe LTV requires the OCSP signing certificate chain to be embedded in the BasicOCSPResponse.
 * Many OCSP servers (like Sectigo) don't include this, so we need to add it manually.
 */
function addCertsToOCSPResponse(
  ocspResponseBuffer: Buffer,
  issuerCert: forge.pki.Certificate,
  moduleName: string,
): Buffer | null {
  try {
    // Parse the OCSPResponse
    const ocspResponseAsn1 = forge.asn1.fromDer(
      forge.util.createBuffer(ocspResponseBuffer.toString('binary')),
    );

    // Navigate to ResponseBytes -> response OCTET STRING -> BasicOCSPResponse
    if (!Array.isArray(ocspResponseAsn1.value) || ocspResponseAsn1.value.length < 2) {
      logger.warn({ module: moduleName }, 'Invalid OCSPResponse structure for enhancement');
      return null;
    }

    const responseBytesWrapper = ocspResponseAsn1.value[1];
    if (!Array.isArray(responseBytesWrapper.value) || responseBytesWrapper.value.length === 0) {
      return null;
    }

    const responseBytes = responseBytesWrapper.value[0];
    if (!Array.isArray(responseBytes.value) || responseBytes.value.length < 2) {
      return null;
    }

    const responseOctetString = responseBytes.value[1];
    const basicOcspResponseBytes = responseOctetString.value;

    if (typeof basicOcspResponseBytes !== 'string') {
      return null;
    }

    // Parse BasicOCSPResponse
    const basicOcspAsn1 = forge.asn1.fromDer(forge.util.createBuffer(basicOcspResponseBytes));

    // BasicOCSPResponse is SEQUENCE { tbsResponseData, signatureAlgorithm, signature, [certs] }
    if (!Array.isArray(basicOcspAsn1.value)) {
      return null;
    }

    // Check if certs [0] field already exists
    const hasCerts = basicOcspAsn1.value.some(
      (field) =>
        (field.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && field.type === 0) ||
        field.type === 0,
    );

    if (hasCerts) {
      logger.info({ module: moduleName }, 'OCSP response already contains certificates');
      return ocspResponseBuffer; // Already has certs, no need to add
    }

    // BasicOCSPResponse should have 3 elements: tbsResponseData, signatureAlgorithm, signature
    if (basicOcspAsn1.value.length !== 3) {
      logger.warn(
        { module: moduleName, fields: basicOcspAsn1.value.length },
        'Unexpected BasicOCSPResponse structure',
      );
      return null;
    }

    // Add the issuer certificate as the OCSP signing certificate
    // Get complete X.509 certificate in DER format
    const certPem = forge.pki.certificateToPem(issuerCert);
    const base64 = certPem
      .replace(/-----BEGIN CERTIFICATE-----/, '')
      .replace(/-----END CERTIFICATE-----/, '')
      .replace(/\s/g, '');
    const certDer = forge.util.decode64(base64);
    const fullCertAsn1 = forge.asn1.fromDer(certDer);

    // Create certs [0] EXPLICIT field with the complete issuer certificate
    const certsField = forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      fullCertAsn1,
    ]);

    // Add certs field to BasicOCSPResponse
    basicOcspAsn1.value.push(certsField);

    // Re-encode BasicOCSPResponse
    const enhancedBasicOcspDer = forge.asn1.toDer(basicOcspAsn1).getBytes();

    // Update the OCTET STRING in ResponseBytes
    responseOctetString.value = enhancedBasicOcspDer;

    // Re-encode the full OCSPResponse
    const enhancedOcspDer = forge.asn1.toDer(ocspResponseAsn1).getBytes();

    return Buffer.from(enhancedOcspDer, 'binary');
  } catch (error) {
    logger.warn(
      { module: moduleName, error },
      'Failed to add certificates to OCSP response, using original',
    );
    return null;
  }
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

    // Send OCSP request using native http/https module
    const responseBuffer = await new Promise<Buffer>((resolve, reject) => {
      try {
        const url = new URL(responderUrl);
        const isHttps = url.protocol === 'https:';
        const httpModule = isHttps ? https : http;

        const options = {
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname + url.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/ocsp-request',
            'Content-Length': ocspRequest.length,
            Accept: 'application/ocsp-response',
          },
          timeout: 10000,
        };

        const req = httpModule.request(options, (res) => {
          const chunks: Buffer[] = [];

          res.on('data', (chunk: Buffer) => {
            chunks.push(Buffer.from(chunk));
          });

          res.on('end', () => {
            const responseBody = Buffer.concat(chunks);

            if (res.statusCode !== 200) {
              logger.warn(
                {
                  module: moduleName,
                  status: res.statusCode,
                  statusMessage: res.statusMessage,
                  ocspUrl: responderUrl,
                },
                'OCSP request failed with non-200 status',
              );
              reject(new Error(`OCSP server returned status ${res.statusCode}`));
              return;
            }

            logger.info(
              { module: moduleName, responseSize: responseBody.length },
              'OCSP response received',
            );

            resolve(responseBody);
          });
        });

        req.on('error', (error) => {
          logger.warn(
            { module: moduleName, error: error.message, ocspUrl: responderUrl },
            'OCSP request failed with network error',
          );
          reject(error);
        });

        req.on('timeout', () => {
          req.destroy();
          reject(new Error('OCSP request timeout'));
        });

        req.write(ocspRequest);
        req.end();
      } catch (error) {
        logger.warn(
          { module: moduleName, error: error instanceof Error ? error.message : String(error) },
          'Failed to create OCSP request',
        );
        reject(error);
      }
    });

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
        // RFC 6960 OCSPResponseStatus values:
        // 0 = successful
        // 1 = malformedRequest
        // 2 = internalError
        // 3 = tryLater
        // 4 = (not used)
        // 5 = sigRequired
        // 6 = unauthorized
        const statusNames = [
          'successful',
          'malformedRequest',
          'internalError',
          'tryLater',
          'notUsed',
          'sigRequired',
          'unauthorized',
        ];
        const statusName = statusNames[statusCode] || 'unknown';

        logger.warn(
          { module: moduleName, statusCode, statusName, ocspUrl: responderUrl },
          `OCSP response indicates error status: ${statusName} (${statusCode})`,
        );

        // Log additional details to help debugging
        if (statusCode === 1) {
          logger.warn(
            { module: moduleName },
            'OCSP malformedRequest - check certificate serial number and issuer information',
          );
        } else if (statusCode === 6) {
          logger.warn(
            { module: moduleName },
            'OCSP unauthorized - the responder may not recognize this certificate or issuer',
          );
        }

        return null;
      }

      logger.info({ module: moduleName }, 'OCSP response validated successfully');
    } catch (error) {
      logger.warn({ module: moduleName, error }, 'Failed to validate OCSP response structure');
      return null;
    }

    // CRITICAL for Adobe LTV: Add OCSP signing certificate chain to BasicOCSPResponse
    // Adobe's OCSP responses include the OCSP signing certificate chain in the certs [0] field
    // Sectigo's OCSP server doesn't include this, so we need to add it manually
    const issuerCert = parseCertificate(issuerCertificate);
    const enhancedOcspResponse = addCertsToOCSPResponse(responseBuffer, issuerCert, moduleName);

    if (enhancedOcspResponse) {
      logger.info(
        {
          module: moduleName,
          originalSize: responseBuffer.length,
          enhancedSize: enhancedOcspResponse.length,
        },
        'Added OCSP signing certificate chain to OCSP response for Adobe LTV',
      );
      return enhancedOcspResponse;
    }

    // If enhancement fails, return original response
    return responseBuffer;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorDetails =
      error instanceof Error
        ? { message: error.message, stack: error.stack }
        : { error: String(error) };
    logger.warn(
      { module: moduleName, error: errorMessage, details: errorDetails },
      'Failed to fetch OCSP response',
    );
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

  // Validate and log certificate chain
  logger.info(
    { module: moduleName, chainLength: certificates.length },
    'Starting OCSP fetch for certificate chain',
  );

  for (let i = 0; i < certificates.length; i++) {
    try {
      const cert = parseCertificate(certificates[i]);
      logger.info(
        {
          module: moduleName,
          index: i,
          subject: cert.subject.getField('CN')?.value || 'unknown',
          issuer: cert.issuer.getField('CN')?.value || 'unknown',
        },
        'Certificate in chain',
      );
    } catch (error) {
      logger.warn({ module: moduleName, index: i, error }, 'Failed to parse certificate in chain');
    }
  }

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

  const successCount = ocspResponses.filter((r) => r !== null).length;
  logger.info(
    { module: moduleName, successCount, totalAttempts: ocspResponses.length },
    'Completed OCSP fetching for certificate chain',
  );

  return ocspResponses;
}
