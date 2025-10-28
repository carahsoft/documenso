import { TRPCError } from '@trpc/server';
import { DateTime } from 'luxon';

import { TWO_FACTOR_EMAIL_EXPIRATION_MINUTES } from '@documenso/lib/server-only/2fa/email/constants';
import { send2FATokenEmailForDirectTemplate } from '@documenso/lib/server-only/2fa/email/send-2fa-token-email-for-direct-template';
import { DocumentAccessAuth } from '@documenso/lib/types/document-auth';
import { extractDocumentAuthMethods } from '@documenso/lib/utils/document-auth';
import { prisma } from '@documenso/prisma';

import { procedure } from '../trpc';
import {
  ZAccessAuthRequest2FAEmailForDirectTemplateRequestSchema,
  ZAccessAuthRequest2FAEmailForDirectTemplateResponseSchema,
} from './access-auth-request-2fa-email.types';

export const accessAuthRequest2FAEmailForDirectTemplateRoute = procedure
  .input(ZAccessAuthRequest2FAEmailForDirectTemplateRequestSchema)
  .output(ZAccessAuthRequest2FAEmailForDirectTemplateResponseSchema)
  .mutation(async ({ input }) => {
    try {
      const { token, email } = input;

      // Find the template with the direct link
      const template = await prisma.template.findFirst({
        where: {
          directLink: {
            token,
            enabled: true,
          },
        },
        include: {
          directLink: true,
          recipients: true,
        },
      });

      if (!template || !template.directLink) {
        throw new TRPCError({
          code: 'NOT_FOUND',
          message: 'Template not found',
        });
      }

      // Find the recipient that matches the direct link
      const directRecipient = template.recipients.find(
        (r) => r.id === template.directLink?.directTemplateRecipientId,
      );

      if (!directRecipient) {
        throw new TRPCError({
          code: 'NOT_FOUND',
          message: 'Direct recipient not found',
        });
      }

      // Check if 2FA is required
      const { derivedRecipientAccessAuth } = extractDocumentAuthMethods({
        documentAuth: template.authOptions,
        recipientAuth: directRecipient.authOptions,
      });

      if (!derivedRecipientAccessAuth.includes(DocumentAccessAuth.TWO_FACTOR_AUTH)) {
        throw new TRPCError({
          code: 'BAD_REQUEST',
          message: '2FA is not required for this template',
        });
      }

      const expiresAt = DateTime.now().plus({ minutes: TWO_FACTOR_EMAIL_EXPIRATION_MINUTES });

      await send2FATokenEmailForDirectTemplate({
        directTemplateToken: token,
        email,
        templateId: template.id,
      });

      return {
        success: true,
        expiresAt: expiresAt.toJSDate(),
      };
    } catch (error) {
      console.error('Error sending access auth 2FA email for direct template:', error);

      if (error instanceof TRPCError) {
        throw error;
      }

      throw new TRPCError({
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to send 2FA email',
      });
    }
  });
