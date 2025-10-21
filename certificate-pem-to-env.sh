#!/bin/bash
#
# certificate-pem-to-env.sh - Convert PEM certificate file to comma-separated base64
#
# Usage: ./certificate-pem-to-env.sh <pem-file>
#
# This script takes a PEM file containing one or more certificates and outputs
# them as comma-separated base64-encoded strings suitable for use with:
# NEXT_PRIVATE_SIGNING_X_CONTENTS
#

set -e

if [ $# -eq 0 ]; then
    echo "Error: No PEM file specified" >&2
    echo "Usage: $0 <pem-file>" >&2
    exit 1
fi

PEM_FILE="$1"

if [ ! -f "$PEM_FILE" ]; then
    echo "Error: File '$PEM_FILE' not found" >&2
    exit 1
fi

if ! grep -q "BEGIN CERTIFICATE" "$PEM_FILE"; then
    echo "Error: File '$PEM_FILE' does not appear to contain PEM certificates" >&2
    exit 1
fi

# Extract certificates and convert to comma-separated base64
OUTPUT=""
CERT_COUNT=0
CURRENT_CERT=""
IN_CERT=0

while IFS= read -r line; do
    if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
        IN_CERT=1
        CURRENT_CERT=""
    elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
        if [[ $IN_CERT -eq 1 ]] && [[ -n "$CURRENT_CERT" ]]; then
            # Remove all whitespace/newlines from the base64 content
            BASE64_CERT=$(echo "$CURRENT_CERT" | tr -d '\n\r\t ')

            if [[ -n "$BASE64_CERT" ]]; then
                if [[ -n "$OUTPUT" ]]; then
                    OUTPUT="${OUTPUT},${BASE64_CERT}"
                else
                    OUTPUT="$BASE64_CERT"
                fi
                CERT_COUNT=$((CERT_COUNT + 1))
            fi
        fi
        IN_CERT=0
        CURRENT_CERT=""
    elif [[ $IN_CERT -eq 1 ]]; then
        # Accumulate base64 content (without headers)
        CURRENT_CERT="${CURRENT_CERT}${line}"
    fi
done < "$PEM_FILE"

if [ $CERT_COUNT -eq 0 ]; then
    echo "Error: No valid certificates found in '$PEM_FILE'" >&2
    exit 1
fi

echo "# Extracted $CERT_COUNT certificate(s) from '$PEM_FILE'" >&2
echo "# Copy the line below to your .env file:" >&2
echo "# NEXT_PRIVATE_SIGNING_X_CONTENTS=\"...\"" >&2
echo "" >&2
echo "$OUTPUT"
