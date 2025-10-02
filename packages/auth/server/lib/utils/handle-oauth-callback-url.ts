import { OrganisationGroupType, UserSecurityAuditLogType } from '@prisma/client';
import { OAuth2Client, decodeIdToken } from 'arctic';
import type { Context } from 'hono';
import { deleteCookie } from 'hono/cookie';

import { AppError, AppErrorCode } from '@documenso/lib/errors/app-error';
import { onCreateUserHook } from '@documenso/lib/server-only/user/create-user';
import { generateDatabaseId } from '@documenso/lib/universal/id';
import { prisma } from '@documenso/prisma';

import type { OAuthClientOptions } from '../../config';
import { AuthenticationErrorCode } from '../errors/error-codes';
import { onAuthorize } from './authorizer';
import { getOpenIdConfiguration } from './open-id';

type HandleOAuthCallbackUrlOptions = {
  c: Context;
  clientOptions: OAuthClientOptions;
};

export const handleOAuthCallbackUrl = async (options: HandleOAuthCallbackUrlOptions) => {
  const { c, clientOptions } = options;

  const requestMeta = c.get('requestMetadata');

  const { email, name, sub, accessToken, accessTokenExpiresAt, idToken, redirectPath, claims } =
    await validateOauth({ c, clientOptions });

  // Extract groups claim from token (Entra returns groups as an array of group names)
  const groupsClaim = claims.groups;
  let groupNames: string[] = [];

  if (Array.isArray(groupsClaim)) {
    groupNames = groupsClaim.filter((g) => typeof g === 'string') as string[];
  }

  // Find the account if possible.
  const existingAccount = await prisma.account.findFirst({
    where: {
      provider: clientOptions.id,
      providerAccountId: sub,
    },
    include: {
      user: {
        select: {
          id: true,
        },
      },
    },
  });

  // Directly log in user if account already exists.
  if (existingAccount) {
    // Check if user needs to be added to any new groups
    if (groupNames.length > 0) {
      await addUserToMatchingOrganisationGroups({
        userId: existingAccount.user.id,
        groupNames,
      });
    }

    await onAuthorize({ userId: existingAccount.user.id }, c);

    return c.redirect(redirectPath, 302);
  }

  const userWithSameEmail = await prisma.user.findFirst({
    where: {
      email: email,
    },
    select: {
      id: true,
      emailVerified: true,
    },
  });

  // Handle existing user but no account.
  if (userWithSameEmail) {
    await prisma.$transaction(async (tx) => {
      await tx.account.create({
        data: {
          type: 'oauth',
          provider: clientOptions.id,
          providerAccountId: sub,
          access_token: accessToken,
          expires_at: Math.floor(accessTokenExpiresAt.getTime() / 1000),
          token_type: 'Bearer',
          id_token: idToken,
          userId: userWithSameEmail.id,
        },
      });

      // Log link event.
      await tx.userSecurityAuditLog.create({
        data: {
          userId: userWithSameEmail.id,
          ipAddress: requestMeta.ipAddress,
          userAgent: requestMeta.userAgent,
          type: UserSecurityAuditLogType.ACCOUNT_SSO_LINK,
        },
      });

      // If account already exists in an unverified state, remove the password to ensure
      // they cannot sign in since we cannot confirm the password was set by the user.
      if (!userWithSameEmail.emailVerified) {
        await tx.user.update({
          where: {
            id: userWithSameEmail.id,
          },
          data: {
            emailVerified: new Date(),
            password: null,
            // Todo: (RR7) Will need to update the "password" account after the migration.
          },
        });
      }
    });

    // Add user to matching organization groups
    if (groupNames.length > 0) {
      await addUserToMatchingOrganisationGroups({
        userId: userWithSameEmail.id,
        groupNames,
      });
    }

    await onAuthorize({ userId: userWithSameEmail.id }, c);

    return c.redirect(redirectPath, 302);
  }

  // Handle new user.
  const createdUser = await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({
      data: {
        email: email,
        name: name,
        emailVerified: new Date(),
      },
    });

    await tx.account.create({
      data: {
        type: 'oauth',
        provider: clientOptions.id,
        providerAccountId: sub,
        access_token: accessToken,
        expires_at: Math.floor(accessTokenExpiresAt.getTime() / 1000),
        token_type: 'Bearer',
        id_token: idToken,
        userId: user.id,
      },
    });

    return user;
  });

  await onCreateUserHook(createdUser).catch((err) => {
    // Todo: (RR7) Add logging.
    console.error(err);
  });

  // Add user to matching organization groups
  if (groupNames.length > 0) {
    await addUserToMatchingOrganisationGroups({
      userId: createdUser.id,
      groupNames,
    });
  }

  await onAuthorize({ userId: createdUser.id }, c);

  return c.redirect(redirectPath, 302);
};

export const validateOauth = async (options: HandleOAuthCallbackUrlOptions) => {
  const { c, clientOptions } = options;

  if (!clientOptions.clientId || !clientOptions.clientSecret) {
    throw new AppError(AppErrorCode.NOT_SETUP);
  }

  const { token_endpoint } = await getOpenIdConfiguration(clientOptions.wellKnownUrl, {
    requiredScopes: clientOptions.scope,
  });

  const oAuthClient = new OAuth2Client(
    clientOptions.clientId,
    clientOptions.clientSecret,
    clientOptions.redirectUrl,
  );

  const code = c.req.query('code');
  const state = c.req.query('state');

  const storedState = deleteCookie(c, `${clientOptions.id}_oauth_state`);
  const storedCodeVerifier = deleteCookie(c, `${clientOptions.id}_code_verifier`);
  const storedRedirectPath = deleteCookie(c, `${clientOptions.id}_redirect_path`) ?? '';

  if (!code || !storedState || state !== storedState || !storedCodeVerifier) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Invalid or missing state',
    });
  }

  // eslint-disable-next-line prefer-const
  let [redirectState, redirectPath] = storedRedirectPath.split(' ');

  if (redirectState !== storedState || !redirectPath) {
    redirectPath = '/';
  }

  const tokens = await oAuthClient.validateAuthorizationCode(
    token_endpoint,
    code,
    storedCodeVerifier,
  );

  const accessToken = tokens.accessToken();
  const accessTokenExpiresAt = tokens.accessTokenExpiresAt();
  const idToken = tokens.idToken();

  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  const claims = decodeIdToken(tokens.idToken()) as Record<string, unknown>;

  const email = claims.email;
  const name = claims.name;
  const sub = claims.sub;

  if (typeof email !== 'string') {
    throw new AppError(AuthenticationErrorCode.InvalidRequest, {
      message: 'Missing email',
    });
  }

  if (typeof name !== 'string') {
    throw new AppError(AuthenticationErrorCode.InvalidRequest, {
      message: 'Missing name',
    });
  }

  if (typeof sub !== 'string') {
    throw new AppError(AuthenticationErrorCode.InvalidRequest, {
      message: 'Missing sub claim',
    });
  }

  if (claims.email_verified !== true && !clientOptions.bypassEmailVerification) {
    throw new AppError(AuthenticationErrorCode.UnverifiedEmail, {
      message: 'Account email is not verified',
    });
  }

  return {
    email,
    name,
    sub,
    accessToken,
    accessTokenExpiresAt,
    idToken,
    redirectPath,
    claims,
  };
};

/**
 * Finds all organization groups matching the provided group names and adds the user to them.
 */
const addUserToMatchingOrganisationGroups = async ({
  userId,
  groupNames,
}: {
  userId: number;
  groupNames: string[];
}) => {
  // Find all organisation groups where the name matches any of the group names
  const matchingGroups = await prisma.organisationGroup.findMany({
    where: {
      name: {
        in: groupNames,
      },
      type: OrganisationGroupType.CUSTOM,
    },
    include: {
      organisation: true,
    },
  });

  if (matchingGroups.length === 0) {
    return;
  }

  // Group by organisation to process each organisation separately
  const groupsByOrganisation = matchingGroups.reduce(
    (acc, group) => {
      const orgId = group.organisationId;

      if (!acc[orgId]) {
        acc[orgId] = [];
      }

      acc[orgId].push(group);

      return acc;
    },
    {} as Record<string, typeof matchingGroups>,
  );

  // For each organisation, add the user as a member and add them to the matching groups
  for (const [organisationId, groups] of Object.entries(groupsByOrganisation)) {
    await prisma.$transaction(
      async (tx) => {
        // Check if user is already a member of this organisation
        let organisationMember = await tx.organisationMember.findFirst({
          where: {
            userId,
            organisationId,
          },
        });

        // If not a member, create organisation member
        if (!organisationMember) {
          // Find the default internal organisation group for this organisation
          const defaultGroup = await tx.organisationGroup.findFirst({
            where: {
              organisationId,
              type: OrganisationGroupType.INTERNAL_ORGANISATION,
            },
            orderBy: {
              id: 'asc',
            },
          });

          if (!defaultGroup) {
            console.error(`No default organisation group found for organisation ${organisationId}`);

            return;
          }

          organisationMember = await tx.organisationMember.create({
            data: {
              id: generateDatabaseId('member'),
              userId,
              organisationId,
              organisationGroupMembers: {
                create: {
                  id: generateDatabaseId('group_member'),
                  groupId: defaultGroup.id,
                },
              },
            },
          });
        }

        // Add user to all matching custom groups
        for (const group of groups) {
          // Check if user is already in this group
          const existingMembership = await tx.organisationGroupMember.findFirst({
            where: {
              organisationMemberId: organisationMember.id,
              groupId: group.id,
            },
          });

          if (!existingMembership) {
            await tx.organisationGroupMember.create({
              data: {
                id: generateDatabaseId('group_member'),
                organisationMemberId: organisationMember.id,
                groupId: group.id,
              },
            });
          }
        }
      },
      { timeout: 30_000 },
    );
  }
};
