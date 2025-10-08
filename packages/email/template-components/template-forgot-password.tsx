import { Trans } from '@lingui/react/macro';

import { Button, Section, Text } from '../components';
import { TemplateDocumentImage } from './template-document-image';

export type TemplateForgotPasswordProps = {
  resetPasswordLink: string;
  assetBaseUrl: string;
};

export const TemplateForgotPassword = ({
  resetPasswordLink,
  assetBaseUrl,
}: TemplateForgotPasswordProps) => {
  return (
    <>
      <TemplateDocumentImage className="mt-6" assetBaseUrl={assetBaseUrl} />

      <Section>
        <Text className="text-primary mx-auto mb-0 w-[480px] text-center text-lg font-semibold">
          <Trans>Forgot your password?</Trans>
        </Text>

        <Text className="my-1 text-center text-base text-slate-400">
          <Trans>That's okay, it happens! Click the button below to reset your password.</Trans>
        </Text>

        <Section className="mb-6 mt-8 text-center">
          <Button
            className="bg-documenso-500 rounded-lg px-6 py-3 text-center text-sm font-medium text-black no-underline"
            href={resetPasswordLink}
            style={{
              paddingLeft: '24px',
              paddingRight: '24px',
              paddingTop: '12px',
              paddingBottom: '12px',
            }}
          >
            <Trans>Reset Password</Trans>
          </Button>
        </Section>
      </Section>
    </>
  );
};

export default TemplateForgotPassword;
