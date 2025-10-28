import { generateHOTP } from 'oslo/otp';

import { generateTwoFactorCredentialsFromEmail } from './generate-2fa-credentials-from-email';

export type GenerateTwoFactorTokenFromEmailOptions = {
  id: number | string;
  email: string;
  period?: number;
};

export const generateTwoFactorTokenFromEmail = async ({
  email,
  id,
  period = 30_000,
}: GenerateTwoFactorTokenFromEmailOptions) => {
  const { secret } = generateTwoFactorCredentialsFromEmail({ email, id });

  const counter = Math.floor(Date.now() / period);

  const token = await generateHOTP(secret, counter);

  return token;
};
