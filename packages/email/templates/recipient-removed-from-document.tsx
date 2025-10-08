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

              <TemplateDocumentImage className="mt-6" assetBaseUrl={assetBaseUrl} />

              <Section>
                <Text className="text-primary mx-auto mb-0 w-[480px] text-center text-lg font-semibold">
                  <Trans>
                    {inviterName} has removed you from the document
                    <br />"{documentName}"
                  </Trans>
                </Text>
              </Section>
            </Section>
          </Container>

          <Hr className="mx-auto mt-12 w-[600px]" style={{ marginTop: '48px' }} />

          <Container className="mx-auto w-[600px]" style={{ paddingTop: '16px' }}>
            <TemplateFooter />
          </Container>
        </Section>
      </Body>
    </Html>
  );
};

export default RecipientRemovedFromDocumentTemplate;
