import { prisma } from '@documenso/prisma';

import { AppError, AppErrorCode } from '../../errors/app-error';

/**
 * Load a DocumentData record that a client referenced by id.
 *
 * Clients may only reference a freshly uploaded file that is not attached to any document or
 * template yet. Ids are not secret (they appear in webhooks, API responses and public template
 * loaders), so accepting an arbitrary id would let a caller copy or attach another tenant's file.
 */
export const getUnattachedDocumentData = async (id: string) => {
  const documentData = await prisma.documentData.findFirst({
    where: {
      id,
      document: null,
      template: null,
    },
  });

  if (!documentData) {
    throw new AppError(AppErrorCode.NOT_FOUND, {
      message: 'Document data not found',
    });
  }

  return documentData;
};
