import { PDFDocument } from 'pdf-lib';

import { prisma } from '@documenso/prisma';

import { AppError, AppErrorCode } from '../../errors/app-error';
import { getFileServerSide } from '../../universal/upload/get-file.server';
import { buildTeamWhereQuery } from '../../utils/teams';

export type ReplaceTemplateDocumentOptions = {
  userId: number;
  teamId: number;
  templateId: number;
  documentDataId: string;
};

export const replaceTemplateDocument = async ({
  userId,
  teamId,
  templateId,
  documentDataId,
}: ReplaceTemplateDocumentOptions) => {
  const template = await prisma.template.findFirst({
    where: {
      id: templateId,
      team: buildTeamWhereQuery({ teamId, userId }),
    },
    include: {
      templateDocumentData: true,
      fields: {
        select: {
          page: true,
        },
      },
    },
  });

  if (!template) {
    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Template not found',
    });
  }

  // Get the new document data record.
  const newDocumentData = await prisma.documentData.findUnique({
    where: { id: documentDataId },
  });

  if (!newDocumentData) {
    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Document data not found',
    });
  }

  // Load the new PDF to count pages.
  const newPdfBytes = await getFileServerSide({
    type: newDocumentData.type,
    data: newDocumentData.data,
  });

  const newPdf = await PDFDocument.load(newPdfBytes).catch(() => {
    throw new AppError(AppErrorCode.INVALID_BODY, {
      message: 'Failed to parse the uploaded PDF',
    });
  });

  const newPageCount = newPdf.getPageCount();

  // Determine required page count from existing fields.
  const maxFieldPage = template.fields.reduce((max, field) => Math.max(max, field.page), 0);

  if (maxFieldPage > newPageCount) {
    throw new AppError(AppErrorCode.INVALID_BODY, {
      message: `The new document has ${newPageCount} page(s) but existing fields require at least ${maxFieldPage} page(s). Remove fields from pages beyond ${newPageCount} first.`,
    });
  }

  // Swap the document data reference.
  const oldDocumentDataId = template.templateDocumentDataId;

  const updatedTemplate = await prisma.template.update({
    where: { id: templateId },
    data: {
      templateDocumentDataId: documentDataId,
    },
  });

  // Clean up the old document data if it's no longer referenced.
  const oldDataStillReferenced = await prisma.documentData.findFirst({
    where: {
      id: oldDocumentDataId,
      OR: [{ document: { isNot: null } }, { template: { isNot: null } }],
    },
  });

  if (!oldDataStillReferenced) {
    await prisma.documentData
      .delete({
        where: { id: oldDocumentDataId },
      })
      .catch(() => {
        // Non-critical cleanup, ignore errors.
      });
  }

  return updatedTemplate;
};
