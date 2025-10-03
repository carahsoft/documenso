import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';
import { Trans } from '@lingui/react/macro';

import { Body, Container, Head, Hr, Html, Img, Preview, Section, Text } from '../components';
import { useBranding } from '../providers/branding';
import type { TemplateDocumentCancelProps } from '../template-components/template-document-cancel';
import TemplateDocumentImage from '../template-components/template-document-image';
import { TemplateFooter } from '../template-components/template-footer';

export type DocumentCancelEmailTemplateProps = Partial<TemplateDocumentCancelProps>;

export const RecipientRemovedFromDocumentTemplate = ({
  inviterName = 'Lucas Smith',
  documentName = 'Open Source Pledge.pdf',
  assetBaseUrl = 'http://localhost:3002',
}: DocumentCancelEmailTemplateProps) => {
  const { _ } = useLingui();
  const branding = useBranding();

  const previewText = msg`${inviterName} has removed you from the document ${documentName}.`;

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

              <TemplateDocumentImage className="mt-6" assetBaseUrl={assetBaseUrl} />

              <Section>
                <Text className="text-primary mx-auto mb-0 max-w-[80%] text-center text-lg font-semibold">
                  <Trans>
                    {inviterName} has removed you from the document
                    <br />"{documentName}"
                  </Trans>
                </Text>
              </Section>
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

export default RecipientRemovedFromDocumentTemplate;
