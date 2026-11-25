import type { Context } from 'hono';

import { getOptionalSession } from '@documenso/auth/server/lib/utils/get-session';
import { NEXT_PUBLIC_WEBAPP_URL } from '@documenso/lib/constants/app';
import { verifyEmbeddingPresignToken } from '@documenso/lib/server-only/embedding-presign/verify-embedding-presign-token';

export const getBearerToken = (c: Context) => {
  const authorization = c.req.header('authorization');

  if (!authorization) {
    return null;
  }

  const [token] = authorization.split('Bearer ').filter((value) => value.length > 0);

  return token ?? null;
};

/**
 * Resolve the user performing a file request.
 *
 * Accepts either a valid session cookie, or an embedding presign token sent as
 * a Bearer token (used by embedded authoring where there is no session).
 */
export const resolveFileRequestUser = async (c: Context) => {
  const bearerToken = getBearerToken(c);

  if (bearerToken) {
    const presignToken = await verifyEmbeddingPresignToken({ token: bearerToken }).catch(
      () => null,
    );

    if (presignToken) {
      return { userId: presignToken.userId, authType: 'presign-token' as const };
    }

    return null;
  }

  const session = await getOptionalSession(c);

  if (session.isAuthenticated && session.user) {
    return { userId: session.user.id, authType: 'session' as const };
  }

  return null;
};

const getAllowedOrigins = () => {
  const origins = new Set<string>();

  for (const value of [NEXT_PUBLIC_WEBAPP_URL(), process.env.NEXT_PRIVATE_INTERNAL_WEBAPP_URL]) {
    if (!value) {
      continue;
    }

    try {
      origins.add(new URL(value).origin);
    } catch {
      // Ignore invalid URLs.
    }
  }

  return origins;
};

/**
 * Returns true when a state changing request authenticated by cookies comes
 * from our own origin. Requests authenticated with a Bearer token do not use
 * ambient credentials and are not subject to CSRF.
 *
 * Compared against NEXT_PUBLIC_WEBAPP_URL rather than the request URL since the
 * request URL is plain http behind a TLS terminating proxy.
 */
export const isTrustedOrigin = (c: Context) => {
  if (getBearerToken(c)) {
    return true;
  }

  const origin = c.req.header('origin') ?? c.req.header('referer');

  if (!origin) {
    return false;
  }

  try {
    return getAllowedOrigins().has(new URL(origin).origin);
  } catch {
    return false;
  }
};
