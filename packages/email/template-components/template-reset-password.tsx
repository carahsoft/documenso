import { Trans } from '@lingui/react/macro';

import { env } from '@documenso/lib/utils/env';

import { Button, Section, Text } from '../components';
import { TemplateDocumentImage } from './template-document-image';

export interface TemplateResetPasswordProps {
  userName: string;
  userEmail: string;
  assetBaseUrl: string;
}

export const TemplateResetPassword = ({ assetBaseUrl }: TemplateResetPasswordProps) => {
  const NEXT_PUBLIC_WEBAPP_URL = env('NEXT_PUBLIC_WEBAPP_URL');

  return (
    <>
      <TemplateDocumentImage className="mt-6" assetBaseUrl={assetBaseUrl} />

      <Section>
        <Text className="text-primary mx-auto mb-0 w-[480px] text-center text-lg font-semibold">
          <Trans>Password updated!</Trans>
        </Text>

        <Text className="my-1 text-center text-base text-slate-400">
          <Trans>Your password has been updated.</Trans>
        </Text>

        <Section className="mb-6 mt-8 text-center">
          <Button
            className="bg-documenso-500 rounded-lg px-6 py-3 text-center text-sm font-medium text-black no-underline"
            href={`${NEXT_PUBLIC_WEBAPP_URL ?? 'http://localhost:3000'}/signin`}
            style={{
              paddingLeft: '24px',
              paddingRight: '24px',
              paddingTop: '12px',
              paddingBottom: '12px',
            }}
          >
            <Trans>Sign In</Trans>
          </Button>
        </Section>
      </Section>
    </>
  );
};

export default TemplateResetPassword;
