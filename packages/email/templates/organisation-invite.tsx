import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';
import { Trans } from '@lingui/react/macro';

import {
  Body,
  Button,
  Container,
  Head,
  Hr,
  Html,
  Img,
  Preview,
  Section,
  Text,
} from '../components';
import { useBranding } from '../providers/branding';
import { TemplateFooter } from '../template-components/template-footer';
import TemplateImage from '../template-components/template-image';

export type OrganisationInviteEmailProps = {
  assetBaseUrl: string;
  baseUrl: string;
  senderName: string;
  organisationName: string;
  token: string;
};

export const OrganisationInviteEmailTemplate = ({
  assetBaseUrl = 'http://localhost:3002',
  baseUrl = 'https://carahsoft.com',
  senderName = 'John Doe',
  organisationName = 'Organisation Name',
  token = '',
}: OrganisationInviteEmailProps) => {
  const { _ } = useLingui();
  const branding = useBranding();

  const previewText = msg`Accept invitation to join an organisation on Carahsoft`;

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
                staticAsset="add-user.png"
              />
            </Section>

            <Section className="p-2 text-slate-500">
              <Text className="text-center text-lg font-medium text-black">
                <Trans>Join {organisationName} on Carahsoft</Trans>
              </Text>

              <Text className="my-1 text-center text-base">
                <Trans>You have been invited to join the following organisation</Trans>
              </Text>

              <Section className="mx-auto my-2 w-fit rounded-lg bg-gray-50 px-4 py-2 text-base font-medium text-slate-600">
                {organisationName}
              </Section>

              <Text className="my-1 text-center text-base">
                <Trans>
                  by <span className="text-slate-900">{senderName}</span>
                </Trans>
              </Text>

              <Section className="mb-6 mt-6 text-center">
                <Button
                  className="bg-documenso-500 rounded-lg px-6 py-3 text-center text-sm font-medium text-black no-underline"
                  href={`${baseUrl}/organisation/invite/${token}`}
                  style={{
                    paddingLeft: '24px',
                    paddingRight: '24px',
                    paddingTop: '12px',
                    paddingBottom: '12px',
                  }}
                >
                  <Trans>Accept</Trans>
                </Button>
                <Button
                  className="ml-4 rounded-lg bg-gray-50 px-6 py-3 text-center text-sm font-medium text-slate-600 no-underline"
                  href={`${baseUrl}/organisation/decline/${token}`}
                  style={{
                    paddingLeft: '24px',
                    paddingRight: '24px',
                    paddingTop: '12px',
                    paddingBottom: '12px',
                  }}
                >
                  <Trans>Decline</Trans>
                </Button>
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

export default OrganisationInviteEmailTemplate;
