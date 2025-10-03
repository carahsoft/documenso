import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';

import { Body, Container, Head, Hr, Html, Img, Preview, Section } from '../components';
import { useBranding } from '../providers/branding';
import {
  TemplateDocumentDelete,
  type TemplateDocumentDeleteProps,
} from '../template-components/template-document-super-delete';
import { TemplateFooter } from '../template-components/template-footer';

export type DocumentDeleteEmailTemplateProps = Partial<TemplateDocumentDeleteProps>;

export const DocumentSuperDeleteEmailTemplate = ({
  documentName = 'Open Source Pledge.pdf',
  assetBaseUrl = 'http://localhost:3002',
  reason = 'Unknown',
}: DocumentDeleteEmailTemplateProps) => {
  const { _ } = useLingui();
  const branding = useBranding();

  const previewText = msg`An admin has deleted your document "${documentName}".`;

  const getAssetUrl = (path: string) => {
    return new URL(path, assetBaseUrl).toString();
  };

  return (
    <Html>
      <Head />
      <Preview>{_(previewText)}</Preview>

      <Body className="mx-auto my-auto bg-white font-sans">
        <Section>
          <Container
            className="mx-auto mb-2 mt-8 rounded-lg border border-solid border-slate-200 p-4"
            style={{ border: '1px solid #e2e8f0', maxWidth: '600px', padding: '8px' }}
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

              <TemplateDocumentDelete
                reason={reason}
                documentName={documentName}
                assetBaseUrl={assetBaseUrl}
              />
            </Section>
          </Container>

          <Hr className="mx-auto mt-12 max-w-xl" style={{ maxWidth: '600px', padding: '8px' }} />

          <Container className="mx-auto max-w-xl" style={{ maxWidth: '600px', padding: '8px' }}>
            <TemplateFooter />
          </Container>
        </Section>
      </Body>
    </Html>
  );
};

export default DocumentSuperDeleteEmailTemplate;
