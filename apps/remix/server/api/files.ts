import { sValidator } from '@hono/standard-validator';
import { Hono } from 'hono';
import { PDFDocument } from 'pdf-lib';

import { APP_DOCUMENT_UPLOAD_SIZE_LIMIT } from '@documenso/lib/constants/app';
import { AppError, AppErrorCode } from '@documenso/lib/errors/app-error';
import { createDocumentData } from '@documenso/lib/server-only/document-data/create-document-data';
import { putFileServerSide } from '@documenso/lib/universal/upload/put-file.server';
import {
  getPresignGetUrl,
  getPresignPostUrl,
} from '@documenso/lib/universal/upload/server-actions';

import type { HonoEnv } from '../router';
import { isTrustedOrigin, resolveFileRequestUser } from './files.helpers';
import {
  type TGetPresignedGetUrlResponse,
  type TGetPresignedPostUrlResponse,
  ZGetPresignedGetUrlRequestSchema,
  ZGetPresignedPostUrlRequestSchema,
  ZUploadPdfRequestSchema,
} from './files.types';

const ALLOWED_PRESIGN_CONTENT_TYPES = [
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'application/pdf',
];

export const filesRoute = new Hono<HonoEnv>()
  /**
   * Reject cross-origin cookie authenticated requests.
   */
  .use('*', async (c, next) => {
    if (c.req.method === 'POST' && !isTrustedOrigin(c)) {
      return c.json({ error: 'Forbidden' }, 403);
    }

    await next();
  })
  /**
   * Uploads a document file to the appropriate storage location and creates
   * a document data record.
   */
  .post('/upload-pdf', sValidator('form', ZUploadPdfRequestSchema), async (c) => {
    try {
      const user = await resolveFileRequestUser(c);

      if (!user) {
        return c.json({ error: 'Unauthorized' }, 401);
      }

      const { file } = c.req.valid('form');

      if (!file) {
        return c.json({ error: 'No file provided' }, 400);
      }

      // Todo: (RR7) This is new.
      // Add file size validation.
      // Convert MB to bytes (1 MB = 1024 * 1024 bytes)
      const MAX_FILE_SIZE = APP_DOCUMENT_UPLOAD_SIZE_LIMIT * 1024 * 1024;

      if (file.size > MAX_FILE_SIZE) {
        return c.json({ error: 'File too large' }, 400);
      }

      const arrayBuffer = await file.arrayBuffer();

      const pdf = await PDFDocument.load(arrayBuffer).catch((e) => {
        console.error(`PDF upload parse error: ${e.message}`);

        throw new AppError('INVALID_DOCUMENT_FILE');
      });

      if (pdf.isEncrypted) {
        throw new AppError('INVALID_DOCUMENT_FILE');
      }

      // Todo: (RR7) Test this.
      if (!file.name.endsWith('.pdf')) {
        Object.defineProperty(file, 'name', {
          writable: true,
          value: `${file.name}.pdf`,
        });
      }

      const { type, data } = await putFileServerSide(file);

      const result = await createDocumentData({ type, data });

      return c.json(result);
    } catch (error) {
      console.error('Upload failed:', error);
      return c.json({ error: 'Upload failed' }, 500);
    }
  })
  .post('/presigned-get-url', sValidator('json', ZGetPresignedGetUrlRequestSchema), async (c) => {
    const { key } = await c.req.json();

    try {
      const { url } = await getPresignGetUrl(key || '');

      return c.json({ url } satisfies TGetPresignedGetUrlResponse);
    } catch (err) {
      console.error(err);

      throw new AppError(AppErrorCode.UNKNOWN_ERROR);
    }
  })
  .post('/presigned-post-url', sValidator('json', ZGetPresignedPostUrlRequestSchema), async (c) => {
    const { fileName, contentType } = c.req.valid('json');

    const user = await resolveFileRequestUser(c);

    if (!user) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    if (!ALLOWED_PRESIGN_CONTENT_TYPES.includes(contentType.toLowerCase())) {
      return c.json({ error: 'Unsupported content type' }, 400);
    }

    try {
      const { key, url } = await getPresignPostUrl(fileName, contentType, user.userId);

      return c.json({ key, url } satisfies TGetPresignedPostUrlResponse);
    } catch (err) {
      console.error(err);

      throw new AppError(AppErrorCode.UNKNOWN_ERROR);
    }
  });
