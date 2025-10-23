import { DocumentStatus, ReadStatus, SendStatus } from '@prisma/client';

import { DOCUMENT_AUDIT_LOG_TYPE } from '@documenso/lib/types/document-audit-logs';
import type { RequestMetadata } from '@documenso/lib/universal/extract-request-metadata';
import { createDocumentAuditLogData } from '@documenso/lib/utils/document-audit-logs';
import { prisma } from '@documenso/prisma';

import { AppError, AppErrorCode } from '../../errors/app-error';
import { jobs } from '../../jobs/client';

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
          status: true,
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

  // Check if document can be reassigned (not draft or completed)
  if (document.status === DocumentStatus.DRAFT) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Cannot reassign draft document',
    });
  }

  if (document.status === DocumentStatus.COMPLETED) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Cannot reassign completed document',
    });
  }

  // Check if recipient can be reassigned (not already signed)
  if (recipient.signedAt) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Cannot reassign recipient who has already signed',
    });
  }

  const oldEmail = recipient.email;
  const oldName = recipient.name;

  // Update the recipient's name, email, and status
  const updatedRecipient = await prisma.$transaction(async (tx) => {
    const updated = await tx.recipient.update({
      where: {
        id: recipient.id,
      },
      data: {
        name,
        email: email.toLowerCase(),
        readStatus: ReadStatus.NOT_OPENED,
        sendStatus: SendStatus.SENT,
      },
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

    return updated;
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

  return updatedRecipient;
}
