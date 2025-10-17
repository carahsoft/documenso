import type { Context, Next } from 'hono';

import type { HonoEnv } from '@documenso/remix/server/router';

import { createSCIMError } from './utils';

/**
 * SCIM Bearer Token Authentication Middleware
 *
 * Validates the SCIM token from the Authorization header against the
 * NEXT_PRIVATE_SCIM_TOKEN environment variable.
 */
export const scimAuthMiddleware = async (c: Context<HonoEnv>, next: Next) => {
  const scimToken = process.env.NEXT_PRIVATE_SCIM_TOKEN;

  if (!scimToken) {
    return c.json(
      createSCIMError({
        status: '500',
        detail: 'SCIM is not configured. Please set NEXT_PRIVATE_SCIM_TOKEN environment variable.',
      }),
      500,
    );
  }

  const authHeader = c.req.header('Authorization');

  if (!authHeader) {
    return c.json(
      createSCIMError({
        status: '401',
        scimType: 'unauthorized',
        detail: 'Missing Authorization header',
      }),
      401,
    );
  }

  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return c.json(
      createSCIMError({
        status: '401',
        scimType: 'unauthorized',
        detail: 'Invalid Authorization header format. Expected: Bearer <token>',
      }),
      401,
    );
  }

  if (token !== scimToken) {
    return c.json(
      createSCIMError({
        status: '401',
        scimType: 'unauthorized',
        detail: 'Invalid SCIM token',
      }),
      401,
    );
  }

  await next();
};
