import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';

import { Body, Container, Head, Html, Img, Preview, Section } from '../components';
import { useBranding } from '../providers/branding';
import type { TemplateConfirmationEmailProps } from '../template-components/template-confirmation-email';
import { TemplateConfirmationEmail } from '../template-components/template-confirmation-email';
import { TemplateFooter } from '../template-components/template-footer';

export const ConfirmEmailTemplate = ({
  confirmationLink,
  assetBaseUrl = 'http://localhost:3002',
}: TemplateConfirmationEmailProps) => {
  const { _ } = useLingui();
  const branding = useBranding();

  const previewText = msg`Please confirm your email address`;

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

              <TemplateConfirmationEmail
                confirmationLink={confirmationLink}
                assetBaseUrl={assetBaseUrl}
              />
            </Section>
          </Container>
          <div className="mx-auto mt-12 max-w-xl" />

          <Container
            className="mx-auto max-w-xl"
            style={{ maxWidth: '600px', paddingLeft: '32px', paddingRight: '32px' }}
          >
            <TemplateFooter isDocument={false} />
          </Container>
        </Section>
      </Body>
    </Html>
  );
};

export default ConfirmEmailTemplate;
