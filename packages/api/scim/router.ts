import { Hono } from 'hono';

import type { HonoEnv } from '@documenso/remix/server/router';

import {
  createUserHandler,
  deleteUserHandler,
  getResourceTypesHandler,
  getSchemasHandler,
  getServiceProviderConfigHandler,
  getUserHandler,
  listUsersHandler,
  patchUserHandler,
  updateUserHandler,
} from './handlers';
import { scimAuthMiddleware } from './middleware';

/**
 * SCIM 2.0 Router
 *
 * Implements the SCIM 2.0 protocol for user provisioning.
 * This router should be mounted at /api/scim/v2
 *
 * All user endpoints require Bearer token authentication via NEXT_PRIVATE_SCIM_TOKEN environment variable.
 *
 * Discovery Endpoints (unauthenticated):
 * - GET    /ServiceProviderConfig - Service provider configuration
 * - GET    /ResourceTypes         - Resource types supported
 * - GET    /Schemas               - Schemas supported
 *
 * User Endpoints (authenticated):
 * - GET    /Users        - List users
 * - GET    /Users/:id    - Get user by ID
 * - POST   /Users        - Create user
 * - PUT    /Users/:id    - Replace user (full update)
 * - PATCH  /Users/:id    - Patch user (partial update)
 * - DELETE /Users/:id    - Delete user
 */
export const scimRouter = new Hono<HonoEnv>();

// Discovery endpoints (no authentication required per SCIM spec)
scimRouter.get('/ServiceProviderConfig', getServiceProviderConfigHandler);
scimRouter.get('/ResourceTypes', getResourceTypesHandler);
scimRouter.get('/Schemas', getSchemasHandler);

// Apply authentication middleware to user management routes
scimRouter.use('/Users*', scimAuthMiddleware);

// User endpoints
scimRouter.get('/Users', listUsersHandler);
scimRouter.get('/Users/:id', getUserHandler);
scimRouter.post('/Users', createUserHandler);
scimRouter.put('/Users/:id', updateUserHandler);
scimRouter.patch('/Users/:id', patchUserHandler);
scimRouter.delete('/Users/:id', deleteUserHandler);
