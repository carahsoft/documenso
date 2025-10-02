#!/bin/sh

# 🚀 Starting Documenso...
printf "🚀 Starting Documenso...\n\n"

# 🔐 Check certificate configuration
printf "🔐 Checking certificate configuration...\n"

SIGNING_TRANSPORT="${NEXT_PRIVATE_SIGNING_TRANSPORT:-local}"

case "$SIGNING_TRANSPORT" in
  local)
    CERT_PATH="${NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH:-/opt/documenso/cert.p12}"
    if [ -f "$CERT_PATH" ] && [ -r "$CERT_PATH" ]; then
        printf "✅ Local certificate file found and readable - document signing is ready!\n"
    else
        printf "⚠️  Local certificate not found or not readable\n"
        printf "💡 Tip: Documenso will still start, but document signing will be unavailable\n"
        printf "🔧 Check: http://localhost:3000/api/certificate-status for detailed status\n"
    fi
    ;;
  azure-hsm)
    printf "✅ Using Azure Key Vault HSM for document signing\n"
    printf "🔧 Ensure Azure credentials and Key Vault configuration are set\n"
    ;;
  gcloud-hsm)
    printf "✅ Using Google Cloud HSM for document signing\n"
    printf "🔧 Ensure Google Cloud credentials and KMS configuration are set\n"
    ;;
  *)
    printf "⚠️  Unknown signing transport: $SIGNING_TRANSPORT\n"
    ;;
esac

printf "\n📚 Useful Links:\n"
printf "📖 Documentation: https://docs.documenso.com\n"
printf "🐳 Self-hosting guide: https://docs.documenso.com/developers/self-hosting\n"
printf "🔐 Certificate setup: https://docs.documenso.com/developers/self-hosting/signing-certificate\n"
printf "🏥 Health check: http://localhost:3000/api/health\n"
printf "📊 Certificate status: http://localhost:3000/api/certificate-status\n"
printf "👥 Community: https://github.com/documenso/documenso\n\n"

printf "🗄️  Running database migrations...\n"
npx prisma migrate deploy --schema ../../packages/prisma/schema.prisma

printf "🌟 Starting Documenso server...\n"
HOSTNAME=0.0.0.0 node build/server/main.js
