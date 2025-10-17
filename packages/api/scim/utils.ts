import type { User } from '@prisma/client';

import type { TSCIMError, TSCIMUser } from './schema';

/**
 * Convert a Prisma User to SCIM User format
 */
export const userToSCIMUser = (user: User, baseUrl: string): TSCIMUser => {
  const nameParts = user.name?.split(' ') || [];
  const givenName = nameParts[0] || '';
  const familyName = nameParts.slice(1).join(' ') || '';

  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: user.id.toString(),
    externalId: user.id.toString(),
    userName: user.email,
    name: {
      formatted: user.name || '',
      givenName,
      familyName,
    },
    displayName: user.name || user.email,
    emails: [
      {
        value: user.email,
        type: 'work',
        primary: true,
      },
    ],
    active: true,
    meta: {
      resourceType: 'User',
      created: user.createdAt.toISOString(),
      lastModified: user.updatedAt.toISOString(),
      location: `${baseUrl}/api/scim/v2/Users/${user.id}`,
    },
  };
};

/**
 * Create a SCIM Error response
 */
export const createSCIMError = (error: Omit<TSCIMError, 'schemas'>): TSCIMError => {
  return {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
    ...error,
  };
};

/**
 * Extract the base URL from a request
 */
export const getBaseUrl = (url: string): string => {
  const urlObj = new URL(url);
  return `${urlObj.protocol}//${urlObj.host}`;
};
