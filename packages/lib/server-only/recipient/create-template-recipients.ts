import { RecipientRole } from '@prisma/client';
import { SendStatus, SigningStatus } from '@prisma/client';

import {
  getBlockedDomainErrorMessage,
  isEmailDomainBlocked,
} from '@documenso/lib/constants/recipient-blocking';
import type { TRecipientAccessAuthTypes } from '@documenso/lib/types/document-auth';
import { type TRecipientActionAuthTypes } from '@documenso/lib/types/document-auth';
import { nanoid } from '@documenso/lib/universal/id';
import { createRecipientAuthOptions } from '@documenso/lib/utils/document-auth';
import { prisma } from '@documenso/prisma';

import { AppError, AppErrorCode } from '../../errors/app-error';
import { buildTeamWhereQuery } from '../../utils/teams';

export interface CreateTemplateRecipientsOptions {
  userId: number;
  teamId: number;
  templateId: number;
  recipients: {
    email: string;
    name: string;
    role: RecipientRole;
    signingOrder?: number | null;
    accessAuth?: TRecipientAccessAuthTypes[];
    actionAuth?: TRecipientActionAuthTypes[];
  }[];
}

export const createTemplateRecipients = async ({
  userId,
  teamId,
  templateId,
  recipients: recipientsToCreate,
}: CreateTemplateRecipientsOptions) => {
  const template = await prisma.template.findFirst({
    where: {
      id: templateId,
      team: buildTeamWhereQuery({ teamId, userId }),
    },
    include: {
      recipients: true,
      team: {
        select: {
          organisation: {
            select: {
              organisationClaim: true,
            },
          },
        },
      },
    },
  });

  if (!template) {
    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Template not found',
    });
  }

  const recipientsHaveActionAuth = recipientsToCreate.some(
    (recipient) => recipient.actionAuth && recipient.actionAuth.length > 0,
  );

  // Check if user has permission to set the global action auth.
  if (recipientsHaveActionAuth && !template.team.organisation.organisationClaim.flags.cfr21) {
    throw new AppError(AppErrorCode.UNAUTHORIZED, {
      message: 'You do not have permission to set the action auth',
    });
  }

  // Check for blocked email domains
  for (const recipient of recipientsToCreate) {
    if (isEmailDomainBlocked(recipient.email)) {
      throw new AppError(AppErrorCode.INVALID_REQUEST, {
        message: getBlockedDomainErrorMessage(recipient.email),
      });
    }
  }

  const normalizedRecipients = recipientsToCreate.map((recipient) => ({
    ...recipient,
    email: recipient.email.toLowerCase(),
  }));

  const createdRecipients = await prisma.$transaction(async (tx) => {
    return await Promise.all(
      normalizedRecipients.map(async (recipient) => {
        const authOptions = createRecipientAuthOptions({
          accessAuth: recipient.accessAuth ?? [],
          actionAuth: recipient.actionAuth ?? [],
        });

        const createdRecipient = await tx.recipient.create({
          data: {
            templateId,
            name: recipient.name,
            email: recipient.email,
            role: recipient.role,
            signingOrder: recipient.signingOrder,
            token: nanoid(),
            sendStatus: recipient.role === RecipientRole.CC ? SendStatus.SENT : SendStatus.NOT_SENT,
            signingStatus:
              recipient.role === RecipientRole.CC ? SigningStatus.SIGNED : SigningStatus.NOT_SIGNED,
            authOptions,
          },
        });

        return createdRecipient;
      }),
    );
  });

  return {
    recipients: createdRecipients,
  };
};
