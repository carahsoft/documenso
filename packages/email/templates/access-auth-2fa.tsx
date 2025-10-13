import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';

import { Body, Container, Head, Html, Img, Preview, Section } from '../components';
import { useBranding } from '../providers/branding';
import { TemplateAccessAuth2FA } from '../template-components/template-access-auth-2fa';
import { TemplateFooter } from '../template-components/template-footer';

export type AccessAuth2FAEmailTemplateProps = {
  documentTitle: string;
  code: string;
  userEmail: string;
  userName: string;
  expiresInMinutes: number;
  assetBaseUrl?: string;
};

export const AccessAuth2FAEmailTemplate = ({
  documentTitle,
  code,
  userEmail,
  userName,
  expiresInMinutes,
  assetBaseUrl = 'http://localhost:3002',
}: AccessAuth2FAEmailTemplateProps) => {
  const { _ } = useLingui();

  const branding = useBranding();

  const previewText = msg`Your verification code is ${code}`;

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
                  alt="Logo"
                  className="mb-4 h-6"
                  width="auto"
                  height="24"
                  style={{ padding: '8px' }}
                />
              ) : (
                <Img
                  src={getAssetUrl('/static/logo.png')}
                  alt="Logo"
                  className="mb-4 h-6"
                  width="auto"
                  height="24"
                  style={{ padding: '8px' }}
                />
              )}

              <TemplateAccessAuth2FA
                documentTitle={documentTitle}
                code={code}
                userEmail={userEmail}
                userName={userName}
                expiresInMinutes={expiresInMinutes}
                assetBaseUrl={assetBaseUrl}
              />
            </Section>
          </Container>

          <Section className="mx-auto mt-12 w-[600px]" />

          <Container className="mx-auto w-[600px]">
            <TemplateFooter isDocument={false} />
          </Container>
        </Section>
      </Body>
    </Html>
  );
};

export default AccessAuth2FAEmailTemplate;
