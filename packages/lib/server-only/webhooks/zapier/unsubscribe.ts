import { TEAM_MEMBER_ROLE_PERMISSIONS_MAP } from '@documenso/lib/constants/teams';
import { buildTeamWhereQuery } from '@documenso/lib/utils/teams';
import { prisma } from '@documenso/prisma';

import { validateApiToken } from './validateApiToken';

export const unsubscribeHandler = async (req: Request) => {
  try {
    const authorization = req.headers.get('authorization');

    if (!authorization) {
      return new Response('Unauthorized', { status: 401 });
    }

    const { webhookId } = await req.json();

    const result = await validateApiToken({ authorization }).catch(() => null);

    if (!result) {
      return new Response('Unauthorized', { status: 401 });
    }

    const userId = result.userId ?? result.user.id;
    const teamId = result.teamId ?? undefined;

    const team = await prisma.team.findFirst({
      where: buildTeamWhereQuery({
        teamId,
        userId,
        roles: TEAM_MEMBER_ROLE_PERMISSIONS_MAP['MANAGE_TEAM'],
      }),
    });

    if (!team) {
      return new Response('Unauthorized', { status: 401 });
    }

    const deletedWebhook = await prisma.webhook.delete({
      where: {
        id: webhookId,
        userId,
        teamId: team.id,
      },
    });

    return Response.json(deletedWebhook);
  } catch (err) {
    console.error(err);

    return Response.json(
      {
        message: 'Internal Server Error',
      },
      { status: 500 },
    );
  }
};
