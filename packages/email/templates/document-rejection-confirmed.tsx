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
            className="mx-auto mb-2 mt-8 rounded-lg border border-solid border-slate-200 p-4"
            style={{ border: '1px solid #e2e8f0', maxWidth: '600px', padding: '32px' }}
          >
            <Section>
              {branding.brandingEnabled && branding.brandingLogo ? (
                <Img
                  src={branding.brandingLogo}
                  alt="Branding Logo"
                  className="mb-4"
                  style={{
                    display: 'block',
                    margin: '0 auto 16px auto',
                    height: '24px',
                    width: 'auto',
                  }}
                  height={24}
                />
              ) : (
                <Img
                  src={getAssetUrl('/static/logo.png')}
                  alt="Documenso Logo"
                  className="mb-4"
                  style={{
                    display: 'block',
                    margin: '0 auto 16px auto',
                    height: '24px',
                    width: 'auto',
                  }}
                  height={24}
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

          <Container
            className="mx-auto max-w-xl"
            style={{ maxWidth: '600px', paddingLeft: '32px', paddingRight: '32px' }}
          >
            <TemplateFooter />
          </Container>
        </Section>
      </Body>
    </Html>
  );
}

export default DocumentRejectionConfirmedEmail;
