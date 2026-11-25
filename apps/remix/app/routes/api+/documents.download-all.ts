import { DocumentStatus } from '@prisma/client';
import archiver from 'archiver';
import type { LoaderFunctionArgs } from 'react-router';
import { z } from 'zod';

import { getOptionalSession } from '@documenso/auth/server/lib/utils/get-session';
import { findDocuments } from '@documenso/lib/server-only/document/find-documents';
import { getFileServerSide } from '@documenso/lib/universal/upload/get-file.server';
import { prisma } from '@documenso/prisma';
import { ExtendedDocumentStatus } from '@documenso/prisma/types/extended-document-status';

const ZDownloadAllQuerySchema = z.object({
  teamId: z.string().optional(),
  folderId: z.string().optional(),
  period: z.string().optional(),
  senderIds: z.string().optional(),
});

const MAX_DOCUMENTS = 200;

const isPeriod = (value: string | undefined): value is '7d' | '14d' | '30d' | 'over30d' =>
  value === '7d' || value === '14d' || value === '30d' || value === 'over30d';

// Helper function to sanitize filename
const sanitizeFilename = (filename: string): string => {
  // Replace invalid characters with underscore
  // Invalid characters for most filesystems: < > : " / \ | ? * and control characters
  // eslint-disable-next-line no-control-regex
  return filename.replace(/[<>:"/\\|?*\x00-\x1F]/g, '_').trim();
};

export const loader = async ({ request }: LoaderFunctionArgs) => {
  const { user } = await getOptionalSession(request);

  if (!user) {
    return new Response('Unauthorized', { status: 401 });
  }

  const url = new URL(request.url);
  const queryParams = ZDownloadAllQuerySchema.safeParse({
    teamId: url.searchParams.get('teamId') ?? undefined,
    folderId: url.searchParams.get('folderId') ?? undefined,
    period: url.searchParams.get('period') ?? undefined,
    senderIds: url.searchParams.get('senderIds') ?? undefined,
  });

  if (!queryParams.success) {
    return new Response('Invalid query parameters', { status: 400 });
  }

  const { teamId, folderId, period, senderIds } = queryParams.data;

  try {
    console.log('Download all request:', { teamId, folderId, period, userId: user.id });

    // A team is required: the list page always sends one and without it there is no
    // access scope to apply.
    if (!teamId) {
      return new Response('teamId is required', { status: 400 });
    }

    const parsedTeamId = parseInt(teamId, 10);

    if (isNaN(parsedTeamId)) {
      return new Response('Invalid team ID', { status: 400 });
    }

    const parsedSenderIds = senderIds
      ? senderIds
          .split(',')
          .map(Number)
          .filter((id) => Number.isInteger(id) && id > 0)
      : undefined;

    // Reuse the document list query so the zip contains exactly what the user can see in the
    // list: team access, document visibility and sender filtering are all enforced there.
    let found: Awaited<ReturnType<typeof findDocuments>>;

    try {
      found = await findDocuments({
        userId: user.id,
        teamId: parsedTeamId,
        status: ExtendedDocumentStatus.COMPLETED,
        folderId,
        period: isPeriod(period) ? period : undefined,
        senderIds: parsedSenderIds,
        page: 1,
        perPage: MAX_DOCUMENTS + 1,
      });
    } catch (error) {
      console.error('Download all access error:', error);
      return new Response('Unauthorized - You do not have access to this team', { status: 403 });
    }

    if (found.data.length > MAX_DOCUMENTS) {
      return new Response(`Too many documents (limit ${MAX_DOCUMENTS}). Narrow the filters.`, {
        status: 413,
      });
    }

    const documentIds = found.data.map((document) => document.id);

    // Load the file references only for the authorised documents.
    const documents = await prisma.document.findMany({
      where: { id: { in: documentIds }, status: DocumentStatus.COMPLETED, deletedAt: null },
      select: {
        id: true,
        title: true,
        documentData: { select: { type: true, data: true } },
        recipients: { select: { email: true } },
      },
      orderBy: { createdAt: 'desc' },
    });

    console.log(`Found ${documents.length} completed documents`);

    if (documents.length === 0) {
      return new Response('No completed documents found', { status: 404 });
    }

    console.log(`Starting zip creation for ${documents.length} documents`);

    // Create the archive with streaming
    const archive = archiver('zip', {
      zlib: { level: 6 }, // Balanced compression for speed and size
    });

    // Process documents and add to archive
    // This is done before we start streaming to catch errors early
    let processedCount = 0;
    const processPromise = (async () => {
      try {
        // Process documents in batches to avoid memory issues
        const BATCH_SIZE = 10;
        for (let i = 0; i < documents.length; i += BATCH_SIZE) {
          const batch = documents.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (document) => {
              if (!document.documentData) {
                return;
              }

              try {
                // Get the document bytes using server-side function
                const bytes = await getFileServerSide({
                  type: document.documentData.type,
                  data: document.documentData.data,
                });

                // Get the first recipient email or use 'no-recipient'
                const recipientEmail = document.recipients[0]?.email || 'no-recipient';

                // Create a safe filename: {title}_{email}_signed.pdf
                const baseTitle = document.title.replace(/\.pdf$/i, '');
                const safeTitle = sanitizeFilename(baseTitle);
                const safeEmail = sanitizeFilename(recipientEmail);
                const filename = `${safeTitle}_${safeEmail}_signed.pdf`;

                // Add to archive using stream to avoid keeping large files in memory
                archive.append(Buffer.from(bytes), { name: filename });
                processedCount++;

                console.log(`Added document ${processedCount}/${documents.length}: ${filename}`);
              } catch (error) {
                console.error(`Failed to add document ${document.id}:`, error);
              }
            }),
          );
        }

        console.log(`Finalizing archive with ${processedCount} documents`);
        await archive.finalize();
      } catch (error) {
        console.error('Error processing documents:', error);
        archive.destroy();
        throw error;
      }
    })();

    // Convert Node.js stream to Web ReadableStream
    const webStream = new ReadableStream({
      async start(controller) {
        // Handle archive data
        archive.on('data', (chunk: Buffer) => {
          controller.enqueue(new Uint8Array(chunk));
        });

        // Handle archive end
        archive.on('end', () => {
          console.log('Archive stream ended');
          controller.close();
        });

        // Handle errors
        archive.on('error', (err) => {
          console.error('Archive error:', err);
          controller.error(err);
        });

        // Wait for processing to complete or fail
        try {
          await processPromise;
        } catch (error) {
          controller.error(error);
        }
      },
    });

    // Set up response headers
    const headers = new Headers({
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="documents-${new Date().toISOString().split('T')[0]}.zip"`,
      'Cache-Control': 'no-cache',
    });

    return new Response(webStream, { headers });
  } catch (error) {
    console.error('Error creating zip file:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return new Response(`Failed to create zip file: ${errorMessage}`, { status: 500 });
  }
};
