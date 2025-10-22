#!/bin/bash
# Quick test script for document signing
# Usage: ./test-sign.sh <input-pdf> <output-pdf>

set -e

if [ $# -lt 2 ]; then
  echo "Usage: ./test-sign.sh <input-pdf> <output-pdf>"
  echo ""
  echo "Example:"
  echo "  ./test-sign.sh ~/test.pdf ~/test-signed.pdf"
  echo ""
  echo "Environment variables can be set via:"
  echo "  1. Export them:  export NEXT_PRIVATE_SIGNING_TRANSPORT=..."
  echo "  2. Use .env: set -a; source .env; set +a"
  echo "  3. Use dotenv:   dotenv -e .env -- ./test-sign.sh ..."
  exit 1
fi

INPUT_PDF="$1"
OUTPUT_PDF="$2"

# Auto-load .env if it exists and no transport is set
if [ -z "$NEXT_PRIVATE_SIGNING_TRANSPORT" ] && [ -f .env ]; then
  echo "Loading environment from .env..."
  set -a
  source .env
  set +a
fi

# Check if tsx is installed
if ! command -v tsx &> /dev/null; then
  echo "Error: tsx is not installed"
  echo "Install it with: npm install -g tsx"
  exit 1
fi

# Check if input file exists
if [ ! -f "$INPUT_PDF" ]; then
  echo "Error: Input PDF not found: $INPUT_PDF"
  exit 1
fi

# Check required environment variable
if [ -z "$NEXT_PRIVATE_SIGNING_TRANSPORT" ]; then
  echo "Error: NEXT_PRIVATE_SIGNING_TRANSPORT is not set"
  echo ""
  echo "Set NEXT_PRIVATE_SIGNING_TRANSPORT in .env or export it:"
  echo "  export NEXT_PRIVATE_SIGNING_TRANSPORT=local"
  echo "  export NEXT_PRIVATE_SIGNING_TRANSPORT=gcloud-hsm"
  echo "  export NEXT_PRIVATE_SIGNING_TRANSPORT=azure-hsm"
  exit 1
fi

# Determine transport type
TRANSPORT="${NEXT_PRIVATE_SIGNING_TRANSPORT}"
echo "Starting ${TRANSPORT} signing test..."
echo ""

# Run the test
tsx packages/signing/test-signing.ts "$INPUT_PDF" "$OUTPUT_PDF"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo ""
  echo "✅ Success! Signed PDF written to: $OUTPUT_PDF"
else
  echo ""
  echo "❌ Signing failed with exit code $EXIT_CODE"
  exit $EXIT_CODE
fi
