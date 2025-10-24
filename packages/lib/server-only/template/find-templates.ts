import { DocumentVisibility, type Prisma, TeamMemberRole, type Template } from '@prisma/client';
import { match } from 'ts-pattern';

import { prisma } from '@documenso/prisma';

import { type FindResultResponse } from '../../types/search-params';
import { getMemberRoles } from '../team/get-member-roles';

export type FindTemplatesOptions = {
  userId: number;
  teamId: number;
  type?: Template['type'];
  page?: number;
  perPage?: number;
  /**
   * Filter by folder:
   * - undefined: return templates from all folders (no filtering)
   * - null: return templates from root folder only
   * - string: return templates from specific folder ID
   */
  folderId?: string | null;
};

export const findTemplates = async ({
  userId,
  teamId,
  type,
  page = 1,
  perPage = 10,
  folderId,
}: FindTemplatesOptions) => {
  const whereFilter: Prisma.TemplateWhereInput[] = [];

  if (teamId === undefined) {
    whereFilter.push({ userId });
  }

  if (teamId !== undefined) {
    const { teamRole } = await getMemberRoles({
      teamId,
      reference: {
        type: 'User',
        id: userId,
      },
    });

    whereFilter.push(
      { teamId },
      {
        OR: [
          match(teamRole)
            .with(TeamMemberRole.ADMIN, () => ({
              visibility: {
                in: [
                  DocumentVisibility.EVERYONE,
                  DocumentVisibility.MANAGER_AND_ABOVE,
                  DocumentVisibility.ADMIN,
                ],
              },
            }))
            .with(TeamMemberRole.MANAGER, () => ({
              visibility: {
                in: [DocumentVisibility.EVERYONE, DocumentVisibility.MANAGER_AND_ABOVE],
              },
            }))
            .otherwise(() => ({ visibility: DocumentVisibility.EVERYONE })),
          { userId, teamId },
        ],
      },
    );
  }

  // Handle folder filtering:
  // - undefined: no filtering (all folders)
  // - null: root folder only
  // - string: specific folder ID
  if (folderId !== undefined) {
    whereFilter.push({ folderId });
  }

  const [data, count] = await Promise.all([
    prisma.template.findMany({
      where: {
        type,
        AND: whereFilter,
      },
      include: {
        team: {
          select: {
            id: true,
            url: true,
          },
        },
        fields: true,
        recipients: true,
        templateMeta: true,
        directLink: {
          select: {
            token: true,
            enabled: true,
          },
        },
      },
      skip: Math.max(page - 1, 0) * perPage,
      orderBy: {
        createdAt: 'desc',
      },
    }),
    prisma.template.count({
      where: {
        AND: whereFilter,
      },
    }),
  ]);

  return {
    data,
    count,
    currentPage: Math.max(page, 1),
    perPage,
    totalPages: Math.ceil(count / perPage),
  } satisfies FindResultResponse<typeof data>;
};
