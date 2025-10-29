#!/bin/bash

# Script to generate all icon files from logo-c-icon.svg
# Usage: ./scripts/generate-icons.sh
#
# This script creates all favicon and app icon files from the C logo SVG

set -e

# Configuration
LOGO_SVG="packages/assets/logo-c-icon.svg"
REMIX_PUBLIC="apps/remix/public"
ASSETS_DIR="packages/assets"

# Check if ImageMagick is installed
if ! command -v magick &> /dev/null; then
    echo "Error: ImageMagick is not installed. Please install it first."
    echo "  macOS: brew install imagemagick"
    echo "  Ubuntu: sudo apt-get install imagemagick"
    exit 1
fi

# Check if logo SVG exists
if [ ! -f "${LOGO_SVG}" ]; then
    echo "Error: Logo SVG file not found at ${LOGO_SVG}"
    exit 1
fi

echo "Generating all icon files from ${LOGO_SVG}..."
echo ""

# Generate favicon-16x16.png
echo "→ Creating favicon-16x16.png..."
magick -density 600 -background none "${LOGO_SVG}" -resize 16x16 -gravity center -extent 16x16 "${REMIX_PUBLIC}/favicon-16x16.png"
magick -density 600 -background none "${LOGO_SVG}" -resize 16x16 -gravity center -extent 16x16 "${ASSETS_DIR}/favicon-16x16.png"

# Generate favicon-32x32.png
echo "→ Creating favicon-32x32.png..."
magick -density 600 -background none "${LOGO_SVG}" -resize 32x32 -gravity center -extent 32x32 "${REMIX_PUBLIC}/favicon-32x32.png"
magick -density 600 -background none "${LOGO_SVG}" -resize 32x32 -gravity center -extent 32x32 "${ASSETS_DIR}/favicon-32x32.png"

# Generate favicon.ico (multi-size)
echo "→ Creating favicon.ico..."
magick -density 600 -background none "${LOGO_SVG}" -resize 32x32 -gravity center -extent 32x32 -define icon:auto-resize=32,16 "${REMIX_PUBLIC}/favicon.ico"
magick -density 600 -background none "${LOGO_SVG}" -resize 32x32 -gravity center -extent 32x32 -define icon:auto-resize=32,16 "${ASSETS_DIR}/favicon.ico"

# Generate apple-touch-icon.png (180x180)
echo "→ Creating apple-touch-icon.png (180x180)..."
magick -density 600 -background none "${LOGO_SVG}" -resize 180x180 -gravity center -extent 180x180 "${REMIX_PUBLIC}/apple-touch-icon.png"
magick -density 600 -background none "${LOGO_SVG}" -resize 180x180 -gravity center -extent 180x180 "${ASSETS_DIR}/apple-touch-icon.png"

# Generate android-chrome-192x192.png
echo "→ Creating android-chrome-192x192.png..."
magick -density 600 -background none "${LOGO_SVG}" -resize 192x192 -gravity center -extent 192x192 "${REMIX_PUBLIC}/android-chrome-192x192.png"
magick -density 600 -background none "${LOGO_SVG}" -resize 192x192 -gravity center -extent 192x192 "${ASSETS_DIR}/android-chrome-192x192.png"

# Generate android-chrome-512x512.png
echo "→ Creating android-chrome-512x512.png..."
magick -density 600 -background none "${LOGO_SVG}" -resize 512x512 -gravity center -extent 512x512 "${REMIX_PUBLIC}/android-chrome-512x512.png"
magick -density 600 -background none "${LOGO_SVG}" -resize 512x512 -gravity center -extent 512x512 "${ASSETS_DIR}/android-chrome-512x512.png"

# Generate logo_icon.png (320x320)
echo "→ Creating logo_icon.png (320x320)..."
magick -density 600 -background none "${LOGO_SVG}" -resize 320x320 -gravity center -extent 320x320 "${ASSETS_DIR}/logo_icon.png"

echo ""
echo "✓ All icon files generated successfully!"
echo ""
echo "Generated files:"
echo "  Favicons:"
echo "    - favicon-16x16.png (16x16)"
echo "    - favicon-32x32.png (32x32)"
echo "    - favicon.ico (multi-size: 16x16, 32x32)"
echo ""
echo "  Mobile/PWA icons:"
echo "    - apple-touch-icon.png (180x180)"
echo "    - android-chrome-192x192.png (192x192)"
echo "    - android-chrome-512x512.png (512x512)"
echo ""
echo "  Other:"
echo "    - logo_icon.png (320x320)"
echo ""
echo "Locations:"
echo "  - ${REMIX_PUBLIC}/"
echo "  - ${ASSETS_DIR}/"
