import {
  DocumentStatus,
  ReadStatus,
  RecipientRole,
  SendStatus,
  SigningStatus,
  WebhookTriggerEvents,
} from '@prisma/client';

import { DOCUMENT_AUDIT_LOG_TYPE } from '@documenso/lib/types/document-audit-logs';
import type { RequestMetadata } from '@documenso/lib/universal/extract-request-metadata';
import { createDocumentAuditLogData } from '@documenso/lib/utils/document-audit-logs';
import { prisma } from '@documenso/prisma';

import { AppError, AppErrorCode } from '../../errors/app-error';
import { jobs } from '../../jobs/client';
import {
  ZWebhookDocumentSchema,
  mapDocumentToWebhookDocumentPayload,
} from '../../types/webhook-payload';
import { nanoid } from '../../universal/id';
import { extractDocumentAuthMethods } from '../../utils/document-auth';
import { getIsRecipientsTurnToSign } from '../recipient/get-is-recipient-turn';
import { triggerWebhook } from '../webhooks/trigger/trigger-webhook';

export type ReassignDocumentWithTokenOptions = {
  token: string;
  documentId: number;
  name: string;
  email: string;
  requestMetadata?: RequestMetadata;
};

export async function reassignDocumentWithToken({
  token,
  documentId,
  name,
  email,
  requestMetadata,
}: ReassignDocumentWithTokenOptions) {
  // Find the recipient and document in a single query
  const recipient = await prisma.recipient.findFirst({
    where: {
      token,
      documentId,
    },
    include: {
      document: {
        select: {
          id: true,
          userId: true,
          teamId: true,
          status: true,
          deletedAt: true,
          authOptions: true,
        },
      },
    },
  });

  const document = recipient?.document;

  if (!recipient || !document) {
    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Document or recipient not found',
    });
  }

  // Only documents that are actively out for signing can be reassigned.
  if (document.status !== DocumentStatus.PENDING || document.deletedAt) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Only pending documents can be reassigned',
    });
  }

  // Check if recipient can be reassigned (not already signed or rejected)
  if (recipient.signedAt || recipient.signingStatus !== SigningStatus.NOT_SIGNED) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Cannot reassign recipient who has already signed or rejected',
    });
  }

  if (
    recipient.role !== RecipientRole.SIGNER &&
    recipient.role !== RecipientRole.APPROVER &&
    recipient.role !== RecipientRole.VIEWER
  ) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'This recipient cannot be reassigned',
    });
  }

  // Access and action auth are tied to the recipient's email address (account match, emailed 2FA
  // codes). Letting the link holder change the email would bypass them, so reassigning is not
  // available for documents that require any authentication.
  const { recipientAccessAuthRequired, recipientActionAuthRequired } = extractDocumentAuthMethods({
    documentAuth: document.authOptions,
    recipientAuth: recipient.authOptions,
  });

  if (recipientAccessAuthRequired || recipientActionAuthRequired) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Reassigning is not available for documents that require authentication',
    });
  }

  // Do not allow reassigning out of turn with sequential signing.
  const isRecipientsTurn = await getIsRecipientsTurnToSign({ token }).catch(() => false);

  if (!isRecipientsTurn) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'It is not this recipient’s turn to sign',
    });
  }

  const duplicateRecipient = await prisma.recipient.findFirst({
    where: {
      documentId,
      id: { not: recipient.id },
      email: { equals: email, mode: 'insensitive' },
    },
    select: { id: true },
  });

  if (duplicateRecipient) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'This email address is already a recipient of the document',
    });
  }

  const oldEmail = recipient.email;
  const oldName = recipient.name;

  // Update the recipient's name, email, and status
  await prisma.$transaction(async (tx) => {
    await tx.recipient.update({
      where: {
        id: recipient.id,
      },
      data: {
        name,
        email: email.toLowerCase(),
        readStatus: ReadStatus.NOT_OPENED,
        sendStatus: SendStatus.SENT,
        // Rotate the token so the previous signing link stops working. The new token is only
        // ever sent to the new recipient by email and is never returned to the caller.
        token: nanoid(),
      },
    });

    // Anything the previous signer already filled in must not carry over to the new signer.
    await tx.signature.deleteMany({
      where: { recipientId: recipient.id },
    });

    await tx.field.updateMany({
      where: { recipientId: recipient.id },
      data: { inserted: false, customText: '' },
    });

    await tx.documentAuditLog.create({
      data: createDocumentAuditLogData({
        documentId,
        type: DOCUMENT_AUDIT_LOG_TYPE.DOCUMENT_RECIPIENT_REASSIGNED,
        user: {
          name: oldName,
          email: oldEmail,
        },
        data: {
          recipientId: recipient.id,
          oldEmail,
          oldName,
          newEmail: email,
          newName: name,
        },
        requestMetadata,
      }),
    });
  });

  // Send email notification to the new recipient
  await jobs.triggerJob({
    name: 'send.signing.requested.email',
    payload: {
      userId: document.userId,
      documentId: document.id,
      recipientId: recipient.id,
      requestMetadata,
    },
  });

  // Fetch the full document with recipients for webhook payload
  const fullDocument = await prisma.document.findUniqueOrThrow({
    where: {
      id: document.id,
    },
    include: {
      documentMeta: true,
      recipients: true,
      user: {
        select: {
          email: true,
        },
      },
    },
  });

  // Trigger DOCUMENT_SENT webhook
  await triggerWebhook({
    event: WebhookTriggerEvents.DOCUMENT_SENT,
    data: ZWebhookDocumentSchema.parse(mapDocumentToWebhookDocumentPayload(fullDocument)),
    userId: document.userId,
    teamId: document.teamId ?? undefined,
  });

  // Never return the recipient: it contains the new signing token.
  return { success: true as const };
}
