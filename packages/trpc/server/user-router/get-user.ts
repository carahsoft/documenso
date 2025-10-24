import { TRPCError } from '@trpc/server';

import { AppError, AppErrorCode } from '@documenso/lib/errors/app-error';
import { getUserByEmail } from '@documenso/lib/server-only/user/get-user-by-email';
import { getHighestOrganisationRoleInGroup } from '@documenso/lib/utils/organisations';
import { getHighestTeamRoleInGroup } from '@documenso/lib/utils/teams';
import { prisma } from '@documenso/prisma';

import { authenticatedProcedure } from '../trpc';
import { ZGetUserRequestSchema, ZGetUserResponseSchema } from './get-user.types';

export const getUserRoute = authenticatedProcedure
  .meta({
    openapi: {
      method: 'GET',
      path: '/user',
      summary: 'Get user',
      description: 'Retrieve user details including organisation and team memberships',
      tags: ['User'],
    },
  })
  .input(ZGetUserRequestSchema)
  .output(ZGetUserResponseSchema)
  .query(async ({ input, ctx }) => {
    const { email } = input;

    ctx.logger.info({
      input: { email },
    });

    try {
      const user = await getUserByEmail({ email });

      // Get all organisation memberships with teams
      const organisationMembers = await prisma.organisationMember.findMany({
        where: {
          userId: user.id,
        },
        include: {
          organisation: {
            include: {
              teams: {
                include: {
                  teamGroups: {
                    where: {
                      organisationGroup: {
                        organisationGroupMembers: {
                          some: {
                            organisationMember: {
                              userId: user.id,
                            },
                          },
                        },
                      },
                    },
                    include: {
                      organisationGroup: {
                        include: {
                          organisationGroupMembers: {
                            where: {
                              organisationMember: {
                                userId: user.id,
                              },
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
          organisationGroupMembers: {
            include: {
              group: true,
            },
          },
        },
      });

      // Build the response with organisation and team information
      const organisations = organisationMembers.map((member) => {
        const orgRole = getHighestOrganisationRoleInGroup(
          member.organisationGroupMembers.map((gm) => gm.group),
        );

        // Filter teams based on allowedTeamIds if using API token authentication
        const teams = member.organisation.teams
          .filter((team) => team.teamGroups.length > 0)
          .filter((team) => {
            // If allowedTeamIds is present (API token auth), only include allowed teams
            if (ctx.allowedTeamIds) {
              return ctx.allowedTeamIds.includes(team.id);
            }
            // Otherwise (session auth), include all teams
            return true;
          })
          .map((team) => ({
            id: team.id,
            name: team.name,
            url: team.url,
            role: getHighestTeamRoleInGroup(team.teamGroups),
          }));

        return {
          id: member.organisation.id,
          name: member.organisation.name,
          role: orgRole,
          teams,
        };
      });

      return {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
        organisations,
      };
    } catch (error) {
      if (error instanceof Error && error.message.includes('No')) {
        throw new TRPCError({
          code: 'NOT_FOUND',
          message: 'User not found',
        });
      }

      throw new AppError(AppErrorCode.UNKNOWN_ERROR, {
        message: 'Failed to retrieve user',
      });
    }
  });
