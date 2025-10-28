import { createElement } from 'react';

import { msg } from '@lingui/core/macro';

import { mailer } from '@documenso/email/mailer';
import { AccessAuth2FAEmailTemplate } from '@documenso/email/templates/access-auth-2fa';
import { prisma } from '@documenso/prisma';

import { getI18nInstance } from '../../../client-only/providers/i18n-server';
import { NEXT_PUBLIC_WEBAPP_URL } from '../../../constants/app';
import { AppError, AppErrorCode } from '../../../errors/app-error';
import { renderEmailWithI18N } from '../../../utils/render-email-with-i18n';
import { getEmailContext } from '../../email/get-email-context';
import { TWO_FACTOR_EMAIL_EXPIRATION_MINUTES } from './constants';
import { generateTwoFactorTokenFromEmail } from './generate-2fa-token-from-email';

export type Send2FATokenEmailForDirectTemplateOptions = {
  directTemplateToken: string;
  email: string;
  templateId: number;
};

export const send2FATokenEmailForDirectTemplate = async ({
  directTemplateToken,
  email,
  templateId,
}: Send2FATokenEmailForDirectTemplateOptions) => {
  const template = await prisma.template.findFirst({
    where: {
      id: templateId,
      directLink: {
        token: directTemplateToken,
      },
    },
    include: {
      directLink: true,
      templateMeta: true,
      team: {
        select: {
          teamEmail: true,
          name: true,
        },
      },
    },
  });

  if (!template) {
    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Template not found',
    });
  }

  if (!template.directLink || !template.directLink.enabled) {
    throw new AppError(AppErrorCode.UNAUTHORIZED, {
      message: 'Direct link is not enabled',
    });
  }

  const twoFactorTokenToken = await generateTwoFactorTokenFromEmail({
    id: directTemplateToken,
    email,
  });

  const { branding, emailLanguage, senderEmail, replyToEmail } = await getEmailContext({
    emailType: 'RECIPIENT',
    source: {
      type: 'team',
      teamId: template.teamId,
    },
    meta: template.templateMeta,
  });

  const i18n = await getI18nInstance(emailLanguage);

  const subject = i18n._(msg`Your two-factor authentication code`);

  const template2FA = createElement(AccessAuth2FAEmailTemplate, {
    documentTitle: template.title,
    userName: '',
    userEmail: email,
    code: twoFactorTokenToken,
    expiresInMinutes: TWO_FACTOR_EMAIL_EXPIRATION_MINUTES,
    assetBaseUrl: NEXT_PUBLIC_WEBAPP_URL(),
  });

  const [html, text] = await Promise.all([
    renderEmailWithI18N(template2FA, { lang: emailLanguage, branding }),
    renderEmailWithI18N(template2FA, { lang: emailLanguage, branding, plainText: true }),
  ]);

  await mailer.sendMail({
    to: {
      address: email,
      name: '',
    },
    from: senderEmail,
    replyTo: replyToEmail,
    subject,
    html,
    text,
  });
};
