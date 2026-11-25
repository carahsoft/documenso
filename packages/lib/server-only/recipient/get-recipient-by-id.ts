import { TeamMemberRole } from '@prisma/client';
import { match } from 'ts-pattern';

import { prisma } from '@documenso/prisma';

import { AppError, AppErrorCode } from '../../errors/app-error';
import { DocumentVisibility } from '../../types/document-visibility';
import { buildTeamWhereQuery } from '../../utils/teams';
import { getTeamById } from '../team/get-team';

export type GetRecipientByIdOptions = {
  recipientId: number;
  userId: number;
  teamId: number;
};

/**
 * Get a recipient by ID. This will also return the recipient signing token so
 * be careful when using this.
 */
export const getRecipientById = async ({
  recipientId,
  userId,
  teamId,
}: GetRecipientByIdOptions) => {
  const team = await getTeamById({ teamId, userId });

  // The recipient includes the signing token, so respect the document visibility.
  const visibilityFilters = match(team.currentTeamRole)
    .with(TeamMemberRole.ADMIN, () => [
      DocumentVisibility.EVERYONE,
      DocumentVisibility.MANAGER_AND_ABOVE,
      DocumentVisibility.ADMIN,
    ])
    .with(TeamMemberRole.MANAGER, () => [
      DocumentVisibility.EVERYONE,
      DocumentVisibility.MANAGER_AND_ABOVE,
    ])
    .otherwise(() => [DocumentVisibility.EVERYONE]);

  const recipient = await prisma.recipient.findFirst({
    where: {
      id: recipientId,
      document: {
        team: buildTeamWhereQuery({ teamId, userId }),
        visibility: {
          in: visibilityFilters,
        },
      },
    },
    include: {
      fields: true,
    },
  });

  if (!recipient) {
    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Recipient not found',
    });
  }

  return recipient;
};
