import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';

import { Body, Container, Head, Html, Img, Preview, Section } from '../components';
import { useBranding } from '../providers/branding';
import type { TemplateDocumentCompletedProps } from '../template-components/template-document-completed';
import { TemplateDocumentCompleted } from '../template-components/template-document-completed';
import { TemplateFooter } from '../template-components/template-footer';

export type DocumentCompletedEmailTemplateProps = Partial<TemplateDocumentCompletedProps> & {
  customBody?: string;
};

export const DocumentCompletedEmailTemplate = ({
  downloadLink = 'https://documenso.com',
  documentName = 'Open Source Pledge.pdf',
  assetBaseUrl = 'http://localhost:3002',
  customBody,
}: DocumentCompletedEmailTemplateProps) => {
  const { _ } = useLingui();
  const branding = useBranding();

  const previewText = msg`Completed Document`;

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
            className="mx-auto mb-2 mt-8 rounded-lg border border-solid border-slate-200 p-2"
            style={{ border: '1px solid #e2e8f0', maxWidth: '600px', padding: '8px' }}
          >
            <Section className="p-2">
              {branding.brandingEnabled && branding.brandingLogo ? (
                <Img
                  src={branding.brandingLogo}
                  alt="Branding Logo"
                  className="mb-4"
                  style={{
                    display: 'block',
                    margin: '0 0 16px 0',
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
                    margin: '0 0 16px 0',
                    height: '24px',
                    width: 'auto',
                  }}
                  height={24}
                />
              )}

              <TemplateDocumentCompleted
                downloadLink={downloadLink}
                documentName={documentName}
                assetBaseUrl={assetBaseUrl}
                customBody={customBody}
              />
            </Section>
          </Container>

          <Container className="mx-auto max-w-xl" style={{ maxWidth: '600px', padding: '8px' }}>
            <TemplateFooter />
          </Container>
        </Section>
      </Body>
    </Html>
  );
};

export default DocumentCompletedEmailTemplate;
