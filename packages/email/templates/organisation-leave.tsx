import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';
import { Trans } from '@lingui/react/macro';

import { Body, Container, Head, Hr, Html, Img, Preview, Section, Text } from '../components';
import { useBranding } from '../providers/branding';
import { TemplateFooter } from '../template-components/template-footer';
import TemplateImage from '../template-components/template-image';

export type OrganisationLeaveEmailProps = {
  assetBaseUrl: string;
  baseUrl: string;
  memberName: string;
  memberEmail: string;
  organisationName: string;
  organisationUrl: string;
};

export const OrganisationLeaveEmailTemplate = ({
  assetBaseUrl = 'http://localhost:3002',
  baseUrl = 'https://documenso.com',
  memberName = 'John Doe',
  memberEmail = 'johndoe@documenso.com',
  organisationName = 'Organisation Name',
  organisationUrl = 'demo',
}: OrganisationLeaveEmailProps) => {
  const { _ } = useLingui();
  const branding = useBranding();

  const previewText = msg`A member has left your organisation on Documenso`;

  return (
    <Html>
      <Head />
      <Preview>{_(previewText)}</Preview>

      <Body className="mx-auto my-auto font-sans">
        <Section className="bg-white text-slate-500">
          <Container
            className="mx-auto mb-2 mt-8 w-[600px] rounded-lg border border-solid border-slate-200 p-2 backdrop-blur-sm"
            style={{ padding: '8px', marginTop: '32px', marginBottom: '8px' }}
          >
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
              <TemplateImage
                assetBaseUrl={assetBaseUrl}
                className="mb-4 h-6"
                width="auto"
                height="24"
                style={{ padding: '8px' }}
                staticAsset="logo.png"
              />
            )}

            <Section>
              <TemplateImage
                className="mx-auto"
                assetBaseUrl={assetBaseUrl}
                staticAsset="delete-user.png"
              />
            </Section>

            <Section className="p-2 text-slate-500">
              <Text className="text-center text-lg font-medium text-black">
                <Trans>A member has left your organisation {organisationName}</Trans>
              </Text>

              <Section className="mx-auto my-2 w-fit rounded-lg bg-gray-50 px-4 py-2 text-base font-medium text-slate-600">
                {memberName || memberEmail}
              </Section>
            </Section>
          </Container>

          <Hr className="mx-auto mt-12 w-[600px]" style={{ marginTop: '48px' }} />

          <Container className="mx-auto w-[600px]" style={{ paddingTop: '16px' }}>
            <TemplateFooter isDocument={false} />
          </Container>
        </Section>
      </Body>
    </Html>
  );
};

export default OrganisationLeaveEmailTemplate;
