import { TEAM_MEMBER_ROLE_PERMISSIONS_MAP } from '@documenso/lib/constants/teams';
import { AppError } from '@documenso/lib/errors/app-error';
import { buildTeamWhereQuery } from '@documenso/lib/utils/teams';
import { prisma } from '@documenso/prisma';

import { assertSafeWebhookUrl } from '../ssrf';
import { validateApiToken } from './validateApiToken';

export const subscribeHandler = async (req: Request) => {
  try {
    const authorization = req.headers.get('authorization');

    if (!authorization) {
      return new Response('Unauthorized', { status: 401 });
    }

    const result = await validateApiToken({ authorization }).catch(() => null);

    if (!result) {
      return new Response('Unauthorized', { status: 401 });
    }

    const { webhookUrl, eventTrigger } = await req.json();

    if (typeof webhookUrl !== 'string') {
      return Response.json({ message: 'Invalid webhook URL' }, { status: 400 });
    }

    const userId = result.userId ?? result.user.id;
    const teamId = result.teamId ?? undefined;

    // Re-verify the token holder can still manage webhooks for the team, mirroring
    // the tRPC webhook routes.
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

    await assertSafeWebhookUrl(webhookUrl);

    const createdWebhook = await prisma.webhook.create({
      data: {
        webhookUrl,
        eventTriggers: [eventTrigger],
        secret: null,
        enabled: true,
        userId,
        teamId: team.id,
      },
    });

    return Response.json(createdWebhook);
  } catch (err) {
    if (err instanceof AppError) {
      return Response.json({ message: err.message }, { status: 400 });
    }

    console.error(err);

    return Response.json(
      {
        message: 'Internal Server Error',
      },
      { status: 500 },
    );
  }
};
