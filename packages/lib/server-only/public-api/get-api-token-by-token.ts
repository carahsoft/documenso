import { OrganisationGroupType, OrganisationMemberRole } from '@prisma/client';

import { prisma } from '@documenso/prisma';

import { hashString } from '../auth/hash';

export const getApiTokenByToken = async ({ token }: { token: string }) => {
  const hashedToken = hashString(token);

  const apiToken = await prisma.apiToken.findFirst({
    where: {
      token: hashedToken,
    },
    include: {
      team: {
        include: {
          organisation: {
            include: {
              owner: {
                select: {
                  id: true,
                  name: true,
                  email: true,
                  disabled: true,
                  roles: true,
                },
              },
            },
          },
        },
      },
      user: {
        select: {
          id: true,
          name: true,
          email: true,
          disabled: true,
          roles: true,
        },
      },
    },
  });

  if (!apiToken) {
    throw new Error('Invalid token');
  }

  if (apiToken.expires && apiToken.expires < new Date()) {
    throw new Error('Expired token');
  }

  // Handle a silly choice from many moons ago
  if (apiToken.team && !apiToken.user) {
    apiToken.user = apiToken.team.organisation.owner;
  }

  const { user } = apiToken;

  // This will never happen but we need to narrow types
  if (!user) {
    throw new Error('Invalid token');
  }

  // Check if the token owner is an organisation MANAGER or ADMIN
  // If so, grant them access to all teams in the organisation
  let allowedTeamIds = [apiToken.teamId];

  if (apiToken.team && apiToken.userId) {
    const orgMember = await prisma.organisationMember.findFirst({
      where: {
        userId: apiToken.userId,
        organisationId: apiToken.team.organisationId,
      },
      include: {
        organisationGroupMembers: {
          include: {
            group: true,
          },
        },
      },
    });

    if (orgMember) {
      const hasOrgManagerOrAdminRole = orgMember.organisationGroupMembers.some(
        (groupMember) =>
          (groupMember.group.organisationRole === OrganisationMemberRole.ADMIN ||
            groupMember.group.organisationRole === OrganisationMemberRole.MANAGER) &&
          groupMember.group.type === OrganisationGroupType.INTERNAL_ORGANISATION,
      );

      if (hasOrgManagerOrAdminRole) {
        // Fetch all team IDs in the organisation
        const orgTeams = await prisma.team.findMany({
          where: {
            organisationId: apiToken.team.organisationId,
          },
          select: {
            id: true,
          },
        });

        allowedTeamIds = orgTeams.map((team) => team.id);
      }
    }
  }

  return {
    ...apiToken,
    user,
    allowedTeamIds,
  };
};
