import { DocumentDataType } from '@prisma/client';

import { prisma } from '@documenso/prisma';

import { AppError, AppErrorCode } from '../../errors/app-error';

// Base64 encoded logos are stored inline, so keep them small.
const MAX_INLINE_LOGO_LENGTH = 2 * 1024 * 1024;

type AssertValidBrandingLogoOptions = {
  brandingLogo: string | null | undefined;
  userId: number;
  scope: { type: 'team'; teamId: number } | { type: 'organisation'; organisationId: string };
};

const invalidLogo = () =>
  new AppError(AppErrorCode.INVALID_BODY, {
    message: 'Invalid branding logo',
  });

/**
 * The branding logo is stored as a serialised `{ type, data }` storage reference.
 *
 * Because the reference is supplied by the client, we must make sure it does not
 * point at an object the caller does not own (e.g. another tenant's document).
 *
 * - Unchanged values are always accepted (legacy references already stored).
 * - Inline (BYTES_64) logos are accepted if they are small.
 * - S3 keys must live under the caller's own `<userId>/` prefix, which is only
 *   ever minted by the authenticated presigned upload route for that user.
 */
export const assertValidBrandingLogo = async ({
  brandingLogo,
  userId,
  scope,
}: AssertValidBrandingLogoOptions) => {
  if (!brandingLogo) {
    return;
  }

  const currentSettings =
    scope.type === 'team'
      ? await prisma.teamGlobalSettings.findFirst({
          where: { team: { id: scope.teamId } },
          select: { brandingLogo: true },
        })
      : await prisma.organisationGlobalSettings.findFirst({
          where: { organisation: { id: scope.organisationId } },
          select: { brandingLogo: true },
        });

  if (currentSettings?.brandingLogo === brandingLogo) {
    return;
  }

  let parsed: { type?: unknown; data?: unknown };

  try {
    parsed = JSON.parse(brandingLogo);
  } catch {
    throw invalidLogo();
  }

  if (!parsed || typeof parsed !== 'object' || typeof parsed.data !== 'string') {
    throw invalidLogo();
  }

  if (parsed.type === DocumentDataType.BYTES_64) {
    if (parsed.data.length > MAX_INLINE_LOGO_LENGTH) {
      throw invalidLogo();
    }

    return;
  }

  if (parsed.type === DocumentDataType.S3_PATH) {
    if (!parsed.data.startsWith(`${userId}/`) || parsed.data.includes('..')) {
      throw invalidLogo();
    }

    return;
  }

  throw invalidLogo();
};
