import { Trans } from '@lingui/react/macro';

import { Button, Section, Text } from '../components';
import { TemplateDocumentImage } from './template-document-image';

export type TemplateConfirmationEmailProps = {
  confirmationLink: string;
  assetBaseUrl: string;
};

export const TemplateConfirmationEmail = ({
  confirmationLink,
  assetBaseUrl,
}: TemplateConfirmationEmailProps) => {
  return (
    <>
      <TemplateDocumentImage className="mt-6" assetBaseUrl={assetBaseUrl} />

      <Section className="text-center">
        <Text className="text-primary mx-auto mb-0 max-w-[80%] text-center text-lg font-semibold">
          <Trans>Welcome to Documenso!</Trans>
        </Text>

        <Text className="my-1 text-center text-base text-slate-400">
          <Trans>
            Before you get started, please confirm your email address by clicking the button below:
          </Trans>
        </Text>

        <Section className="mb-6 mt-8 text-center">
          <Button
            className="bg-documenso-500 inline-block rounded-lg px-6 py-3 text-center text-sm font-medium text-black no-underline"
            href={confirmationLink}
            style={{
              backgroundColor: '#10B981',
              borderRadius: '8px',
              color: '#000000',
              display: 'inline-block',
              fontSize: '14px',
              fontWeight: 500,
              lineHeight: '1.5',
              padding: '12px 24px',
              textAlign: 'center',
              textDecoration: 'none',
            }}
          >
            <Trans>Confirm email</Trans>
          </Button>
          <Text className="mt-8 text-center text-sm italic text-slate-400">
            <Trans>
              You can also copy and paste this link into your browser: {confirmationLink} (link
              expires in 1 hour)
            </Trans>
          </Text>
        </Section>
      </Section>
    </>
  );
};
