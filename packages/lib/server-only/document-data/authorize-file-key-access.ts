import { DocumentDataType } from '@prisma/client';

import { prisma } from '@documenso/prisma';

import { buildTeamWhereQuery } from '../../utils/teams';
import { verifyEmbeddingPresignToken } from '../embedding-presign/verify-embedding-presign-token';

export type AuthorizeFileKeyAccessOptions = {
  key: string;
  /**
   * The authenticated session user, if any.
   */
  userId?: number;
  /**
   * Candidate access tokens supplied by the client (recipient tokens, direct
   * template tokens, QR/share slugs, embed presign tokens). These are only ever
   * checked against the documents that reference the requested key, so
   * supplying irrelevant values grants nothing.
   */
  tokens?: string[];
};

const MAX_CANDIDATE_TOKENS = 16;
const MAX_TOKEN_LENGTH = 2048;

const looksLikeJwt = (token: string) => token.split('.').length === 3;

/**
 * Check whether the caller is allowed to download the object with the given
 * storage key.
 *
 * - Branding logos are public (they are served unauthenticated by the branding routes).
 * - Document/template files require a team member session, a recipient of the
 *   document, or a token tied to the document/template that references the key.
 * - The original (unsigned) file is only available to team members.
 */
export const authorizeFileKeyAccess = async ({
  key,
  userId,
  tokens = [],
}: AuthorizeFileKeyAccessOptions) => {
  const candidateTokens = Array.from(
    new Set(tokens.filter((token) => token.length > 0 && token.length <= MAX_TOKEN_LENGTH)),
  ).slice(0, MAX_CANDIDATE_TOKENS);

  const dataRows = await prisma.documentData.findMany({
    where: {
      type: DocumentDataType.S3_PATH,
      OR: [{ data: key }, { initialData: key }],
    },
    select: {
      data: true,
      initialData: true,
      document: {
        select: {
          id: true,
          userId: true,
          teamId: true,
          qrToken: true,
        },
      },
      template: {
        select: {
          id: true,
          userId: true,
          teamId: true,
          directLink: {
            select: {
              token: true,
              enabled: true,
            },
          },
        },
      },
    },
  });

  if (dataRows.length === 0) {
    return await isBrandingLogoKey(key);
  }

  const user = userId
    ? await prisma.user.findFirst({ where: { id: userId }, select: { id: true, email: true } })
    : null;

  const presignTokens: Awaited<ReturnType<typeof verifyEmbeddingPresignToken>>[] = [];

  for (const token of candidateTokens.filter(looksLikeJwt)) {
    const verified = await verifyEmbeddingPresignToken({ token }).catch(() => null);

    if (verified) {
      presignTokens.push(verified);
    }
  }

  for (const row of dataRows) {
    // `data` is the current (signed once complete) file, `initialData` the original upload.
    const isCurrentFile = row.data === key;

    const owner = row.document ?? row.template;

    if (!owner) {
      continue;
    }

    // Team members (and the owner) can access both versions.
    if (user) {
      if (owner.userId === user.id) {
        return true;
      }

      const team = await prisma.team.findFirst({
        where: buildTeamWhereQuery({ teamId: owner.teamId, userId: user.id }),
        select: { id: true },
      });

      if (team) {
        return true;
      }
    }

    // Embedded authoring presign tokens, scoped to the owning user/team.
    if (
      presignTokens.some(
        (presignToken) =>
          presignToken.teamId === owner.teamId || presignToken.userId === owner.userId,
      )
    ) {
      return true;
    }

    // Everyone else can only access the current file.
    if (!isCurrentFile) {
      continue;
    }

    if (row.document) {
      const { document } = row;

      if (user) {
        const recipient = await prisma.recipient.findFirst({
          where: { documentId: document.id, email: { equals: user.email, mode: 'insensitive' } },
          select: { id: true },
        });

        if (recipient) {
          return true;
        }
      }

      if (candidateTokens.length > 0) {
        if (document.qrToken && candidateTokens.includes(document.qrToken)) {
          return true;
        }

        const recipient = await prisma.recipient.findFirst({
          where: { documentId: document.id, token: { in: candidateTokens } },
          select: { id: true },
        });

        if (recipient) {
          return true;
        }

        const shareLink = await prisma.documentShareLink.findFirst({
          where: { documentId: document.id, slug: { in: candidateTokens } },
          select: { id: true },
        });

        if (shareLink) {
          return true;
        }
      }
    }

    if (
      row.template?.directLink?.enabled &&
      candidateTokens.includes(row.template.directLink.token)
    ) {
      return true;
    }
  }

  return false;
};

const isBrandingLogoKey = async (key: string) => {
  // Logos are stored as JSON, e.g. {"type":"S3_PATH","data":"<key>"}.
  const needle = `"data":${JSON.stringify(key)}`;

  const [team, organisation] = await Promise.all([
    prisma.teamGlobalSettings.findFirst({
      where: { brandingLogo: { contains: needle } },
      select: { id: true },
    }),
    prisma.organisationGlobalSettings.findFirst({
      where: { brandingLogo: { contains: needle } },
      select: { id: true },
    }),
  ]);

  return Boolean(team || organisation);
};
