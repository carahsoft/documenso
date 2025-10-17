import type { Context } from 'hono';

import { AppError, AppErrorCode } from '@documenso/lib/errors/app-error';
import { createSCIMUser } from '@documenso/lib/server-only/user/create-user';
import { prisma } from '@documenso/prisma';
import type { HonoEnv } from '@documenso/remix/server/router';

import { ZSCIMPatchRequestSchema, ZSCIMUserCreateSchema, ZSCIMUserUpdateSchema } from './schema';
import { createSCIMError, getBaseUrl, userToSCIMUser } from './utils';

/**
 * GET /scim/v2/ServiceProviderConfig
 * Returns the service provider configuration
 */
export const getServiceProviderConfigHandler = (c: Context<HonoEnv>) => {
  return c.json({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    documentationUri: 'https://docs.documenso.com',
    patch: {
      supported: true,
    },
    bulk: {
      supported: false,
      maxOperations: 0,
      maxPayloadSize: 0,
    },
    filter: {
      supported: true,
      maxResults: 200,
    },
    changePassword: {
      supported: false,
    },
    sort: {
      supported: false,
    },
    etag: {
      supported: false,
    },
    authenticationSchemes: [
      {
        type: 'oauthbearertoken',
        name: 'OAuth Bearer Token',
        description: 'Authentication scheme using the OAuth Bearer Token Standard',
        specUri: 'https://tools.ietf.org/html/rfc6750',
        documentationUri: 'https://docs.documenso.com',
        primary: true,
      },
    ],
  });
};

/**
 * GET /scim/v2/ResourceTypes
 * Returns the resource types supported
 */
export const getResourceTypesHandler = (c: Context<HonoEnv>) => {
  const baseUrl = getBaseUrl(c.req.url);

  return c.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 1,
    Resources: [
      {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
        id: 'User',
        name: 'User',
        endpoint: '/Users',
        description: 'User Account',
        schema: 'urn:ietf:params:scim:schemas:core:2.0:User',
        meta: {
          location: `${baseUrl}/api/scim/v2/ResourceTypes/User`,
          resourceType: 'ResourceType',
        },
      },
    ],
  });
};

/**
 * GET /scim/v2/Schemas
 * Returns the schemas supported
 */
export const getSchemasHandler = (c: Context<HonoEnv>) => {
  return c.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 1,
    Resources: [
      {
        id: 'urn:ietf:params:scim:schemas:core:2.0:User',
        name: 'User',
        description: 'User Account',
        attributes: [
          {
            name: 'userName',
            type: 'string',
            multiValued: false,
            required: true,
            caseExact: false,
            mutability: 'readWrite',
            returned: 'default',
            uniqueness: 'server',
          },
          {
            name: 'name',
            type: 'complex',
            multiValued: false,
            required: false,
            mutability: 'readWrite',
            returned: 'default',
            uniqueness: 'none',
          },
          {
            name: 'displayName',
            type: 'string',
            multiValued: false,
            required: false,
            mutability: 'readWrite',
            returned: 'default',
            uniqueness: 'none',
          },
          {
            name: 'emails',
            type: 'complex',
            multiValued: true,
            required: false,
            mutability: 'readWrite',
            returned: 'default',
            uniqueness: 'none',
          },
          {
            name: 'active',
            type: 'boolean',
            multiValued: false,
            required: false,
            mutability: 'readWrite',
            returned: 'default',
            uniqueness: 'none',
          },
        ],
        meta: {
          resourceType: 'Schema',
          location: '/api/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User',
        },
      },
    ],
  });
};

/**
 * GET /scim/v2/Users
 * List all users with pagination
 */
export const listUsersHandler = async (c: Context<HonoEnv>) => {
  try {
    const startIndex = parseInt(c.req.query('startIndex') || '1', 10);
    const count = parseInt(c.req.query('count') || '100', 10);
    const filter = c.req.query('filter');

    let where = {};

    if (filter) {
      const emailMatch = filter.match(/userName\s+eq\s+"([^"]+)"/i);

      if (emailMatch) {
        where = { email: emailMatch[1].toLowerCase() };
      }
    }

    const [users, totalResults] = await Promise.all([
      prisma.user.findMany({
        where,
        skip: startIndex - 1,
        take: count,
        orderBy: { createdAt: 'asc' },
      }),
      prisma.user.count({ where }),
    ]);

    const baseUrl = getBaseUrl(c.req.url);

    return c.json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults,
      startIndex,
      itemsPerPage: users.length,
      Resources: users.map((user) => userToSCIMUser(user, baseUrl)),
    });
  } catch (error) {
    console.error('SCIM listUsers error:', error);

    return c.json(
      createSCIMError({
        status: '500',
        detail: 'Internal server error',
      }),
      500,
    );
  }
};

/**
 * GET /scim/v2/Users/:id
 * Get a specific user by ID
 */
export const getUserHandler = async (c: Context<HonoEnv>) => {
  try {
    const userId = c.req.param('id');

    const user = await prisma.user.findUnique({
      where: { id: parseInt(userId, 10) },
    });

    if (!user) {
      return c.json(
        createSCIMError({
          status: '404',
          detail: `User with id ${userId} not found`,
        }),
        404,
      );
    }

    const baseUrl = getBaseUrl(c.req.url);

    return c.json(userToSCIMUser(user, baseUrl));
  } catch (error) {
    console.error('SCIM getUser error:', error);

    return c.json(
      createSCIMError({
        status: '500',
        detail: 'Internal server error',
      }),
      500,
    );
  }
};

/**
 * POST /scim/v2/Users
 * Create a new user
 */
export const createUserHandler = async (c: Context<HonoEnv>) => {
  try {
    const body = await c.req.json();
    const parsed = ZSCIMUserCreateSchema.safeParse(body);

    if (!parsed.success) {
      return c.json(
        createSCIMError({
          status: '400',
          scimType: 'invalidValue',
          detail: `Invalid user data: ${parsed.error.message}`,
        }),
        400,
      );
    }

    const userData = parsed.data;

    const email = userData.userName || userData.emails?.[0]?.value;

    if (!email) {
      return c.json(
        createSCIMError({
          status: '400',
          scimType: 'invalidValue',
          detail: 'userName or email is required',
        }),
        400,
      );
    }

    const name =
      userData.displayName ||
      userData.name?.formatted ||
      [userData.name?.givenName, userData.name?.familyName].filter(Boolean).join(' ') ||
      email.split('@')[0];

    try {
      const user = await createSCIMUser({
        name,
        email,
      });

      const baseUrl = getBaseUrl(c.req.url);

      return c.json(userToSCIMUser(user, baseUrl), 201);
    } catch (error) {
      if (error instanceof AppError && error.code === AppErrorCode.ALREADY_EXISTS) {
        return c.json(
          createSCIMError({
            status: '409',
            scimType: 'uniqueness',
            detail: `User with email ${email} already exists`,
          }),
          409,
        );
      }

      throw error;
    }
  } catch (error) {
    console.error('SCIM createUser error:', error);

    return c.json(
      createSCIMError({
        status: '500',
        detail: 'Internal server error',
      }),
      500,
    );
  }
};

/**
 * PUT /scim/v2/Users/:id
 * Replace a user (full update)
 */
export const updateUserHandler = async (c: Context<HonoEnv>) => {
  try {
    const userId = c.req.param('id');
    const body = await c.req.json();
    const parsed = ZSCIMUserUpdateSchema.safeParse(body);

    if (!parsed.success) {
      return c.json(
        createSCIMError({
          status: '400',
          scimType: 'invalidValue',
          detail: `Invalid user data: ${parsed.error.message}`,
        }),
        400,
      );
    }

    const userData = parsed.data;

    const existingUser = await prisma.user.findUnique({
      where: { id: parseInt(userId, 10) },
    });

    if (!existingUser) {
      return c.json(
        createSCIMError({
          status: '404',
          detail: `User with id ${userId} not found`,
        }),
        404,
      );
    }

    const updateData: { name?: string; email?: string } = {};

    if (userData.displayName || userData.name) {
      updateData.name =
        userData.displayName ||
        userData.name?.formatted ||
        [userData.name?.givenName, userData.name?.familyName].filter(Boolean).join(' ');
    }

    if (userData.userName) {
      updateData.email = userData.userName.toLowerCase();
    } else if (userData.emails && userData.emails.length > 0) {
      updateData.email = userData.emails[0].value.toLowerCase();
    }

    const updatedUser = await prisma.user.update({
      where: { id: parseInt(userId, 10) },
      data: updateData,
    });

    const baseUrl = getBaseUrl(c.req.url);

    return c.json(userToSCIMUser(updatedUser, baseUrl));
  } catch (error) {
    console.error('SCIM updateUser error:', error);

    return c.json(
      createSCIMError({
        status: '500',
        detail: 'Internal server error',
      }),
      500,
    );
  }
};

/**
 * PATCH /scim/v2/Users/:id
 * Partially update a user
 */
export const patchUserHandler = async (c: Context<HonoEnv>) => {
  try {
    const userId = c.req.param('id');
    const body = await c.req.json();
    const parsed = ZSCIMPatchRequestSchema.safeParse(body);

    if (!parsed.success) {
      return c.json(
        createSCIMError({
          status: '400',
          scimType: 'invalidValue',
          detail: `Invalid patch data: ${parsed.error.message}`,
        }),
        400,
      );
    }

    const existingUser = await prisma.user.findUnique({
      where: { id: parseInt(userId, 10) },
    });

    if (!existingUser) {
      return c.json(
        createSCIMError({
          status: '404',
          detail: `User with id ${userId} not found`,
        }),
        404,
      );
    }

    const updateData: { name?: string; email?: string } = {};

    for (const operation of parsed.data.Operations) {
      if (operation.op === 'replace') {
        if (operation.path === 'active' && operation.value === false) {
          return c.json(
            createSCIMError({
              status: '501',
              detail: 'User deactivation is not implemented',
            }),
            501,
          );
        }

        if (operation.path === 'userName' && typeof operation.value === 'string') {
          updateData.email = operation.value.toLowerCase();
        }

        if (operation.path === 'displayName' && typeof operation.value === 'string') {
          updateData.name = operation.value;
        }

        if (
          operation.path === 'name' &&
          typeof operation.value === 'object' &&
          operation.value !== null
        ) {
          const nameValue = operation.value;

          if ('formatted' in nameValue && typeof nameValue.formatted === 'string') {
            updateData.name = nameValue.formatted;
          } else if ('givenName' in nameValue || 'familyName' in nameValue) {
            const givenName =
              'givenName' in nameValue && typeof nameValue.givenName === 'string'
                ? nameValue.givenName
                : '';
            const familyName =
              'familyName' in nameValue && typeof nameValue.familyName === 'string'
                ? nameValue.familyName
                : '';
            updateData.name = [givenName, familyName].filter(Boolean).join(' ');
          }
        }
      }
    }

    if (Object.keys(updateData).length === 0) {
      const baseUrl = getBaseUrl(c.req.url);
      return c.json(userToSCIMUser(existingUser, baseUrl));
    }

    const updatedUser = await prisma.user.update({
      where: { id: parseInt(userId, 10) },
      data: updateData,
    });

    const baseUrl = getBaseUrl(c.req.url);

    return c.json(userToSCIMUser(updatedUser, baseUrl));
  } catch (error) {
    console.error('SCIM patchUser error:', error);

    return c.json(
      createSCIMError({
        status: '500',
        detail: 'Internal server error',
      }),
      500,
    );
  }
};

/**
 * DELETE /scim/v2/Users/:id
 * Delete a user
 */
export const deleteUserHandler = async (c: Context<HonoEnv>) => {
  try {
    const userId = c.req.param('id');

    const existingUser = await prisma.user.findUnique({
      where: { id: parseInt(userId, 10) },
    });

    if (!existingUser) {
      return c.json(
        createSCIMError({
          status: '404',
          detail: `User with id ${userId} not found`,
        }),
        404,
      );
    }

    await prisma.user.delete({
      where: { id: parseInt(userId, 10) },
    });

    return c.body(null, 204);
  } catch (error) {
    console.error('SCIM deleteUser error:', error);

    return c.json(
      createSCIMError({
        status: '500',
        detail: 'Internal server error',
      }),
      500,
    );
  }
};
