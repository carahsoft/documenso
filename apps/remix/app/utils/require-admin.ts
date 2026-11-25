import { redirect } from 'react-router';

import { getOptionalSession } from '@documenso/auth/server/lib/utils/get-session';
import { isAdmin } from '@documenso/lib/utils/is-admin';

/**
 * Assert the request comes from an authenticated admin.
 *
 * Route loaders run independently of their parent layout loaders (single fetch
 * `.data` requests can target an individual route), so every loader that
 * returns sensitive data must perform its own authorization check instead of
 * relying on a parent layout.
 */
export const requireAdmin = async (request: Request) => {
  const session = await getOptionalSession(request);

  if (!session.isAuthenticated || !session.user || !isAdmin(session.user)) {
    throw redirect('/');
  }

  return session.user;
};
