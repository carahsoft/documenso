import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';

import { Body, Container, Head, Html, Img, Preview, Section } from '../components';
import { useBranding } from '../providers/branding';
import { TemplateDocumentRecipientSigned } from '../template-components/template-document-recipient-signed';
import { TemplateFooter } from '../template-components/template-footer';

export interface DocumentRecipientSignedEmailTemplateProps {
  documentName?: string;
  recipientName?: string;
  recipientEmail?: string;
  assetBaseUrl?: string;
}

export const DocumentRecipientSignedEmailTemplate = ({
  documentName = 'Open Source Pledge.pdf',
  recipientName = 'John Doe',
  recipientEmail = 'lucas@carahsoft.com',
  assetBaseUrl = 'http://localhost:3002',
}: DocumentRecipientSignedEmailTemplateProps) => {
  const { _ } = useLingui();
  const branding = useBranding();

  const recipientReference = recipientName || recipientEmail;

  const previewText = msg`${recipientReference} has signed ${documentName}`;

  const getAssetUrl = (path: string) => {
    return new URL(path, assetBaseUrl).toString();
  };

  return (
    <Html>
      <Head />
      <Preview>{_(previewText)}</Preview>

      <Body className="mx-auto my-auto font-sans">
        <Section className="bg-white">
          <Container
            className="mx-auto mb-2 mt-8 w-[600px] rounded-lg border border-solid border-slate-200 p-2 backdrop-blur-sm"
            style={{ padding: '8px', marginTop: '32px', marginBottom: '8px' }}
          >
            <Section className="p-2" style={{ padding: '8px' }}>
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

              <TemplateDocumentRecipientSigned
                documentName={documentName}
                recipientName={recipientName}
                recipientEmail={recipientEmail}
                assetBaseUrl={assetBaseUrl}
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
};

export default DocumentRecipientSignedEmailTemplate;
