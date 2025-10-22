# LTV (Long-Term Validation) Troubleshooting Guide

## Overview

LTV (Long-Term Validation) allows PDF signatures to be validated without requiring internet access by embedding all necessary validation information (certificates, OCSP responses, timestamps) directly in the PDF document.

## Common Issues and Solutions

### 1. "OCSP unauthorized (status code 6)"

**Cause**: The OCSP responder is rejecting the request, usually due to:
- Certificate chain not provided or in wrong order
- Certificate not issued by a CA that the OCSP responder recognizes
- Self-signed certificates (which don't have OCSP)

**Solutions**:

#### Check Certificate Chain Order
Certificates must be provided in the correct order: `[signing cert, intermediate CA, root CA]`

For Azure Key Vault HSM:
```bash
# Ensure your certificate chain is in the correct order
NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_CONTENTS=<intermediate_base64>,<root_base64>
# OR
NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_PATH=/path/to/chain.pem
```

The chain file should contain certificates in this order:
```
-----BEGIN CERTIFICATE-----
<Intermediate CA Certificate>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<Root CA Certificate>
-----END CERTIFICATE-----
```

#### Verify Certificate Has OCSP
Check if your certificate has an OCSP responder URL:
```bash
openssl x509 -in cert.pem -text -noout | grep -A 4 "Authority Information Access"
```

You should see:
```
Authority Information Access:
    OCSP - URI:http://ocsp.example.com
```

If no OCSP URL is present, LTV cannot be enabled for this certificate.

#### Test OCSP Manually
```bash
# Extract OCSP URL from certificate
OCSP_URL=$(openssl x509 -in cert.pem -ocsp_uri -noout)

# Test OCSP request
openssl ocsp -issuer issuer.pem -cert cert.pem -url "$OCSP_URL" -text
```

### 2. "Failed to fetch OCSP response" with empty error `{}`

**Cause**: This was an issue with the `fetch` API not being available or working correctly in Node.js environments. This has been fixed by switching to the native `https` module.

**Solution**: Update to the latest version of the signing package. The OCSP implementation now uses Node.js's native `https` module for better compatibility.

### 3. "No OCSP responses available, cannot enable LTV"

**Cause**: All OCSP requests failed or certificates don't have OCSP responders.

**Solutions**:

#### Option 1: Disable LTV (signatures still work, just not LTV-enabled)
```bash
NEXT_PRIVATE_SIGNING_ENABLE_LTV=false
```

#### Option 2: Use CRLs Instead (not yet implemented)
OCSP is the modern approach, but some certificates only provide CRL (Certificate Revocation List) URLs. This implementation currently only supports OCSP.

#### Option 3: Ensure Network Access
OCSP requires network access during signing to fetch revocation data. Ensure:
- Signing server has internet access
- No firewalls blocking OCSP URLs (usually HTTP/HTTPS)
- OCSP responder URLs are accessible

### 4. "Certificate chain too short for LTV"

**Cause**: Only the signing certificate was provided, but LTV requires at least one issuer certificate.

**Solution**: Provide the full certificate chain including intermediate CA certificates.

For Azure Key Vault:
```bash
# Download the full chain from Azure
az keyvault certificate show --vault-name <vault> --name <cert> --query 'cer' -o tsv | base64 -d > cert.der
az keyvault certificate show --vault-name <vault> --name <cert> --query 'policy.x509CertificateProperties.subject' -o tsv

# Or manually provide the chain
NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_PATH=/path/to/intermediate-and-root.pem
```

### 5. Self-Signed Certificates

**Issue**: Self-signed certificates cannot be LTV-enabled because:
- They don't have OCSP responders
- They are their own root of trust
- Adobe Acrobat requires revocation data for LTV

**Solution**:
- Use certificates from a recognized CA for production
- For testing, LTV will be skipped but signatures will still work

### 6. Certificate Chain Order Issues

**Symptoms**:
- Log shows "Certificate in chain" with unexpected issuer/subject relationships
- OCSP requests fail with "unauthorized"

**Solution**: Verify chain order by checking the logs:
```
Certificate in chain | index: 0, subject: "My Certificate", issuer: "Intermediate CA"
Certificate in chain | index: 1, subject: "Intermediate CA", issuer: "Root CA"
Certificate in chain | index: 2, subject: "Root CA", issuer: "Root CA"
```

The issuer of certificate N should match the subject of certificate N+1.

## Environment Variables

### LTV Control
```bash
# Disable LTV entirely (default: enabled)
NEXT_PRIVATE_SIGNING_ENABLE_LTV=false
```

### Azure Key Vault HSM - Certificate Chain
```bash
# Option 1: Base64-encoded, comma-separated
NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_CONTENTS=<base64_cert1>,<base64_cert2>

# Option 2: PEM file with multiple certificates
NEXT_PRIVATE_SIGNING_AZURE_CERTIFICATE_CHAIN_PATH=/path/to/chain.pem
```

### Local P12 Certificates
Certificate chain is automatically extracted from the P12 file if present.

### Google Cloud HSM - Certificate Chain
Include multiple certificates in the PEM file:
```bash
NEXT_PRIVATE_SIGNING_GCLOUD_HSM_PUBLIC_CRT_FILE_PATH=/path/to/bundle.pem
```

Where `bundle.pem` contains:
```
-----BEGIN CERTIFICATE-----
<Signing Certificate>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<Intermediate CA>
-----END CERTIFICATE-----
```

## Debugging

### Enable Debug Logging

The signing package logs detailed information about LTV and OCSP operations. Look for:

```
Starting LTV enablement process | hasCertChain: true, hasTimestamp: true
Starting OCSP fetch for certificate chain | chainLength: 3
Certificate in chain | index: 0, subject: "cert.example.com", issuer: "Intermediate CA"
Building OCSP request | certSubject: "cert.example.com", certSerial: "123456"
Fetching OCSP response | ocspUrl: "http://ocsp.ca.com"
OCSP response indicates error status: unauthorized (6) | statusCode: 6
```

### Common Log Messages

| Message | Meaning | Action |
|---------|---------|--------|
| `LTV is disabled via NEXT_PRIVATE_SIGNING_ENABLE_LTV=false` | LTV is intentionally disabled | Enable if you want LTV |
| `Certificate chain too short for LTV` | Need at least 2 certs in chain | Add issuer certificates |
| `No OCSP responder URL found` | Certificate lacks OCSP extension | Use different certificate or disable LTV |
| `OCSP unauthorized (6)` | OCSP responder rejected request | Check certificate chain order and validity |
| `No OCSP responses available` | All OCSP fetches failed | Check network, certificate configuration |
| `LTV enabled successfully` | Success! | Verify in Adobe Acrobat |

## Verifying LTV in Adobe Acrobat

1. Open the signed PDF in Adobe Acrobat
2. Click on the signature in the signature panel
3. Click "Signature Details"
4. Look for one of these indicators:
   - ✅ "LTV Enabled" or "Valid, with LTV"
   - ✅ Signature validates without internet connection
5. Disconnect from internet and verify signature still shows as valid

## Technical Reference

### OCSP Status Codes (RFC 6960)

| Code | Name | Meaning |
|------|------|---------|
| 0 | successful | OCSP response is valid |
| 1 | malformedRequest | Request format is invalid |
| 2 | internalError | OCSP responder had an error |
| 3 | tryLater | Responder is temporarily unavailable |
| 5 | sigRequired | Request must be signed |
| 6 | unauthorized | Responder doesn't recognize the certificate |

### DSS Structure

The Document Security Store (DSS) is added to the PDF catalog:

```
/DSS <<
  /Certs [ <intermediate_cert_stream> <root_cert_stream> ]
  /OCSPs [ <ocsp_response_stream> <ocsp_response_stream> ]
  /VRI <<
    /<signature_hash> <<
      /Cert [ <intermediate_cert_stream> ]
      /OCSP [ <ocsp_response_stream> ]
      /TU (D:20250122120000+00'00')
    >>
  >>
>>
```

## Need More Help?

If LTV still isn't working:

1. Check the logs for detailed error messages
2. Verify your certificate chain with `openssl`
3. Test OCSP manually with `openssl ocsp`
4. Consider temporarily disabling LTV with `NEXT_PRIVATE_SIGNING_ENABLE_LTV=false`
5. Ensure you're using certificates from a recognized CA for production use

## References

- [RFC 6960 - OCSP](https://datatracker.ietf.org/doc/html/rfc6960)
- [RFC 5652 - CMS (PKCS#7)](https://datatracker.ietf.org/doc/html/rfc5652)
- [Adobe PDF Signature Build Dictionary](https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/Acrobat_DigitalSignatures_in_PDF.pdf)
- [ISO 32000-2 (PDF 2.0) - Document Security Store](https://www.iso.org/standard/63534.html)
