import forge from 'node-forge';
import { createHash } from 'node:crypto';
import https from 'node:https';

import { logger } from '@documenso/lib/utils/logger';

/**
 * Request a timestamp token from a TSA (Timestamp Authority) server
 *
 * This function implements RFC 3161 timestamp protocol:
 * 1. Creates a TimeStampReq with the hash of the signature
 * 2. Sends it to the TSA server via HTTPS POST
 * 3. Parses the TimeStampResp and extracts the timestamp token
 *
 * @param signature - The signature data to timestamp
 * @param timestampServerUrl - URL of the TSA server
 * @returns Promise that resolves to the timestamp token as a Buffer
 */
export async function requestTimestampFromTSA(
  signature: Buffer,
  timestampServerUrl: string,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      // Create timestamp request
      const messageImprint = createHash('sha256').update(new Uint8Array(signature)).digest();

      // Build TimeStampReq according to RFC 3161
      const timestampReq = forge.asn1.create(
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
          // messageImprint
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            // hashAlgorithm
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
              forge.asn1.create(
                forge.asn1.Class.UNIVERSAL,
                forge.asn1.Type.OID,
                false,
                forge.asn1.oidToDer(forge.pki.oids.sha256).getBytes(),
              ),
              forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
            ]),
            // hashedMessage
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.OCTETSTRING,
              false,
              forge.util.createBuffer(messageImprint).getBytes(),
            ),
          ]),
          // certReq (request TSA certificate to be included)
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.BOOLEAN,
            false,
            String.fromCharCode(0xff),
          ),
        ],
      );

      const timestampReqDer = forge.asn1.toDer(timestampReq).getBytes();
      const requestBody = Buffer.from(timestampReqDer, 'binary');

      const url = new URL(timestampServerUrl);

      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/timestamp-query',
          'Content-Length': requestBody.length,
        },
      };

      const req = https.request(options, (res) => {
        const chunks: Buffer[] = [];

        res.on('data', (chunk: Buffer) => {
          chunks.push(Buffer.from(chunk));
        });

        res.on('end', () => {
          const responseBody = Buffer.concat(chunks);

          if (res.statusCode !== 200) {
            reject(
              new Error(`TSA server returned status ${res.statusCode}: ${responseBody.toString()}`),
            );
            return;
          }

          try {
            // Parse TimeStampResp
            const timestampResp = forge.asn1.fromDer(
              forge.util.createBuffer(responseBody.toString('binary')),
            );

            // Extract status - TimeStampResp SEQUENCE has status as first element
            if (
              typeof timestampResp.value === 'string' ||
              !Array.isArray(timestampResp.value) ||
              timestampResp.value.length < 1
            ) {
              reject(new Error('Invalid TSA response structure'));
              return;
            }

            const status = timestampResp.value[0];
            if (
              typeof status === 'string' ||
              !Array.isArray(status.value) ||
              status.value.length < 1
            ) {
              reject(new Error('Invalid TSA status structure'));
              return;
            }

            const statusInfo = status.value[0];
            if (typeof statusInfo === 'string') {
              reject(new Error('Invalid TSA status info structure'));
              return;
            }

            // Extract the actual status value (should be an INTEGER in ASN.1)
            const statusValueData = statusInfo.value;
            if (typeof statusValueData !== 'string') {
              reject(new Error('Invalid TSA status value type'));
              return;
            }

            const statusValue = statusValueData.charCodeAt(0);

            if (statusValue !== 0 && statusValue !== 1) {
              reject(new Error(`TSA server returned error status: ${statusValue}`));
              return;
            }

            // Extract timestamp token - second element in TimeStampResp
            if (timestampResp.value.length < 2) {
              reject(new Error('TSA response missing timestamp token'));
              return;
            }

            const timeStampToken = timestampResp.value[1];
            if (typeof timeStampToken === 'string') {
              reject(new Error('Invalid timestamp token structure'));
              return;
            }

            const timestampTokenDer = forge.asn1.toDer(timeStampToken).getBytes();

            resolve(Buffer.from(timestampTokenDer, 'binary'));
          } catch (error) {
            reject(new Error(`Failed to parse TSA response: ${error}`));
          }
        });
      });

      req.on('error', (error) => {
        reject(new Error(`TSA request failed: ${error.message}`));
      });

      req.write(requestBody);
      req.end();
    } catch (error) {
      reject(error);
    }
  });
}

/**
 * Get timestamp token from TSA if configured
 *
 * This is a convenience wrapper that checks for the timestamp server URL
 * in environment variables and requests a timestamp if configured.
 *
 * @param signature - The signature data to timestamp
 * @param timestampServerUrl - Optional URL of the TSA server (will check env if not provided)
 * @param moduleName - Module name for logging
 * @returns Promise that resolves to the timestamp token Buffer, or undefined if not configured or on error
 */
export async function getTimestampToken(
  signature: Buffer,
  timestampServerUrl: string | undefined,
  moduleName: string,
): Promise<Buffer | undefined> {
  if (!timestampServerUrl) {
    return undefined;
  }

  logger.info({ module: moduleName }, 'Requesting timestamp from TSA');

  try {
    const timestampToken = await requestTimestampFromTSA(signature, timestampServerUrl);

    logger.info({ module: moduleName }, 'Timestamp received from TSA');

    return timestampToken;
  } catch (error) {
    logger.error({ module: moduleName, error }, 'Failed to get TSA timestamp');
    // Return undefined to allow signing to continue without timestamp
    return undefined;
  }
}
