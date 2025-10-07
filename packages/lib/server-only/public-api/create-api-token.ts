import { OrganisationGroupType, OrganisationMemberRole } from '@prisma/client';
import type { Duration } from 'luxon';
import { DateTime } from 'luxon';

import { prisma } from '@documenso/prisma';

import { TEAM_MEMBER_ROLE_PERMISSIONS_MAP } from '../../constants/teams';
// temporary choice for testing only
import * as timeConstants from '../../constants/time';
import { AppError, AppErrorCode } from '../../errors/app-error';
import { alphaid } from '../../universal/id';
import { buildTeamWhereQuery } from '../../utils/teams';
import { hashString } from '../auth/hash';

type TimeConstants = typeof timeConstants & {
  [key: string]: number | Duration;
};

type CreateApiTokenInput = {
  userId: number;
  teamId: number;
  tokenName: string;
  expiresIn: string | null;
};

const ORG_TOKEN_PREFIX = '[ORG]';

export const createApiToken = async ({
  userId,
  teamId,
  tokenName,
  expiresIn,
}: CreateApiTokenInput) => {
  const apiToken = `api_${alphaid(16)}`;

  const hashedToken = hashString(apiToken);

  const timeConstantsRecords: TimeConstants = timeConstants;

  const isOrgToken = tokenName.startsWith(ORG_TOKEN_PREFIX);

  const team = await prisma.team.findFirst({
    where: buildTeamWhereQuery({
      teamId,
      userId,
      roles: TEAM_MEMBER_ROLE_PERMISSIONS_MAP['MANAGE_TEAM'],
    }),
    include: {
      organisation: true,
    },
  });

  if (!team) {
    throw new AppError(AppErrorCode.UNAUTHORIZED, {
      message: 'You do not have permission to create a token for this team',
    });
  }

  if (isOrgToken) {
    const orgMember = await prisma.organisationMember.findFirst({
      where: {
        userId,
        organisationId: team.organisationId,
      },
      include: {
        organisationGroupMembers: {
          include: {
            group: true,
          },
        },
      },
    });

    if (!orgMember) {
      throw new AppError(AppErrorCode.UNAUTHORIZED, {
        message: 'You are not a member of this organisation',
      });
    }

    const isOrgAdmin = orgMember.organisationGroupMembers.some(
      (groupMember) =>
        groupMember.group.organisationRole === OrganisationMemberRole.ADMIN &&
        groupMember.group.type === OrganisationGroupType.INTERNAL_ORGANISATION,
    );

    if (!isOrgAdmin) {
      throw new AppError(AppErrorCode.UNAUTHORIZED, {
        message: 'Only organisation admins can create [ORG] prefixed tokens',
      });
    }
  }

  const storedToken = await prisma.apiToken.create({
    data: {
      name: tokenName,
      token: hashedToken,
      expires: expiresIn ? DateTime.now().plus(timeConstantsRecords[expiresIn]).toJSDate() : null,
      userId,
      teamId,
    },
  });

  return {
    id: storedToken.id,
    token: apiToken,
  };
};
