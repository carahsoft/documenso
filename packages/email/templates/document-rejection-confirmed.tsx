import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';

import { Body, Container, Head, Html, Img, Preview, Section } from '../components';
import { useBranding } from '../providers/branding';
import { TemplateDocumentRejectionConfirmed } from '../template-components/template-document-rejection-confirmed';
import { TemplateFooter } from '../template-components/template-footer';

export type DocumentRejectionConfirmedEmailProps = {
  recipientName: string;
  documentName: string;
  documentOwnerName: string;
  reason: string;
  assetBaseUrl?: string;
};

export function DocumentRejectionConfirmedEmail({
  recipientName,
  documentName,
  documentOwnerName,
  reason,
  assetBaseUrl = 'http://localhost:3002',
}: DocumentRejectionConfirmedEmailProps) {
  const { _ } = useLingui();
  const branding = useBranding();

  const previewText = _(msg`You have rejected the document '${documentName}'`);

  const getAssetUrl = (path: string) => {
    return new URL(path, assetBaseUrl).toString();
  };

  return (
    <Html>
      <Head />
      <Preview>{previewText}</Preview>

      <Body className="mx-auto my-auto bg-white font-sans">
        <Section>
          <Container
            className="mx-auto mb-2 mt-8 w-[600px] rounded-lg border border-solid border-slate-200 p-4 backdrop-blur-sm"
            style={{ padding: '16px', marginTop: '32px', marginBottom: '8px' }}
          >
            <Section>
              {branding.brandingEnabled && branding.brandingLogo ? (
                <Img
                  src={branding.brandingLogo}
                  alt="Branding Logo"
                  className="mb-4 h-6"
                  width="auto"
                  height="24"
                  style={{ padding: '8px' }}
                />
              ) : (
                <Img
                  src={getAssetUrl('/static/logo.png')}
                  alt="Documenso Logo"
                  className="mb-4 h-6"
                  width="auto"
                  height="24"
                  style={{ padding: '8px' }}
                />
              )}

              <TemplateDocumentRejectionConfirmed
                recipientName={recipientName}
                documentName={documentName}
                documentOwnerName={documentOwnerName}
                reason={reason}
              />
            </Section>
          </Container>

          <Container className="mx-auto w-[600px]">
            <TemplateFooter />
          </Container>
        </Section>
      </Body>
    </Html>
  );
}

export default DocumentRejectionConfirmedEmail;
