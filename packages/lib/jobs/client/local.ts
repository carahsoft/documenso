import { sha256 } from '@noble/hashes/sha256';
import { BackgroundJobStatus, Prisma } from '@prisma/client';
import type { Context as HonoContext } from 'hono';

import { prisma } from '@documenso/prisma';

import { NEXT_PRIVATE_INTERNAL_WEBAPP_URL } from '../../constants/app';
import { sign } from '../../server-only/crypto/sign';
import { verify } from '../../server-only/crypto/verify';
import {
  type JobDefinition,
  type JobRunIO,
  type SimpleTriggerJobOptions,
  ZSimpleTriggerJobOptionsSchema,
} from './_internal/job';
import type { Json } from './_internal/json';
import { BaseJobProvider } from './base';

export class LocalJobProvider extends BaseJobProvider {
  private static _instance: LocalJobProvider;

  private _jobDefinitions: Record<string, JobDefinition> = {};

  private constructor() {
    super();
  }

  static getInstance() {
    if (!this._instance) {
      this._instance = new LocalJobProvider();
    }

    return this._instance;
  }

  public defineJob<N extends string, T>(definition: JobDefinition<N, T>) {
    this._jobDefinitions[definition.id] = {
      ...definition,
      enabled: definition.enabled ?? true,
    };
  }

  public async triggerJob(options: SimpleTriggerJobOptions) {
    const eligibleJobs = Object.values(this._jobDefinitions).filter(
      (job) => job.trigger.name === options.name,
    );

    await Promise.all(
      eligibleJobs.map(async (job) => {
        // Ideally we will change this to a createMany with returning later once we upgrade Prisma
        // @see: https://github.com/prisma/prisma/releases/tag/5.14.0
        const pendingJob = await prisma.backgroundJob.create({
          data: {
            jobId: job.id,
            name: job.name,
            version: job.version,
            // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
            payload: options.payload as Prisma.InputJsonValue,
          },
        });

        await this.submitJobToEndpoint({
          jobId: pendingJob.id,
          jobDefinitionId: pendingJob.jobId,
          data: options,
        });
      }),
    );
  }

  public async processPendingJobs(): Promise<{
    processed: number;
    failed: number;
    errors: Array<{ jobId: string; error: string }>;
  }> {
    const PENDING_JOB_TIMEOUT_MS = 1 * 60 * 1000; // 1 minutes
    const STUCK_JOB_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
    const now = new Date();
    const pendingJobThreshold = new Date(now.getTime() - PENDING_JOB_TIMEOUT_MS);
    const stuckJobThreshold = new Date(now.getTime() - STUCK_JOB_TIMEOUT_MS);

    // Find jobs that are:
    // 1. PENDING and never processed (just failed to submit)
    // 2. PROCESSING but stuck (updatedAt is too old, meaning the job handler crashed)
    const pendingJobs = await prisma.backgroundJob.findMany({
      where: {
        OR: [
          {
            status: BackgroundJobStatus.PENDING,
            updatedAt: {
              lt: pendingJobThreshold,
            },
          },
          {
            status: BackgroundJobStatus.PROCESSING,
            updatedAt: {
              lt: stuckJobThreshold,
            },
          },
        ],
      },
      orderBy: {
        submittedAt: 'asc',
      },
      take: 50, // Process in batches to avoid overwhelming the system
    });

    type ErrorEntry = { jobId: string; error: string };

    const results: {
      processed: number;
      failed: number;
      errors: ErrorEntry[];
    } = {
      processed: 0,
      failed: 0,
      errors: [],
    };

    for (const job of pendingJobs) {
      try {
        if (job.status === BackgroundJobStatus.PROCESSING) {
          const resetJob = await prisma.backgroundJob.updateMany({
            where: {
              id: job.id,
              status: BackgroundJobStatus.PROCESSING,
              updatedAt: job.updatedAt, // Ensure it hasn't been updated by another process
            },
            data: {
              status: BackgroundJobStatus.PENDING,
            },
          });

          // If count is 0, another process already picked this up
          if (resetJob.count === 0) {
            continue;
          }
        }

        // Parse the payload to get the trigger options
        // Note: job.jobId contains the job definition ID (e.g., "internal.seal-document")
        // which is used as the trigger name, not job.name which is the display name
        const triggerOptions: SimpleTriggerJobOptions = {
          name: job.jobId,
          payload: job.payload,
        };

        // Resubmit the job
        await this.submitJobToEndpoint({
          jobId: job.id,
          jobDefinitionId: job.jobId,
          data: triggerOptions,
          isRetry: true,
        });

        results.processed++;
      } catch (error) {
        results.failed++;
        results.errors.push({
          jobId: job.id,
          error: error instanceof Error ? error.message : String(error),
        });
        console.error(`[JOBS:CRON] Failed to process job ${job.id}:`, error);
      }
    }

    return results;
  }

  public getCronHandler(): (c: HonoContext) => Promise<Response | void> {
    return async (c: HonoContext) => {
      const req = c.req;

      if (req.method !== 'POST') {
        return c.text('Method not allowed', 405);
      }

      const cronSecret = req.header('x-cron-secret');
      const expectedSecret = process.env.NEXT_PRIVATE_CRON_SECRET;

      if (expectedSecret && cronSecret !== expectedSecret) {
        return c.text('Unauthorized', 401);
      }

      try {
        const results = await this.processPendingJobs();
        return c.json(results, 200);
      } catch (error) {
        console.error('[JOBS:CRON] Error processing pending jobs:', error);
        return c.json(
          {
            error: 'Failed to process pending jobs',
            message: error instanceof Error ? error.message : String(error),
          },
          500,
        );
      }
    };
  }

  public getApiHandler(): (c: HonoContext) => Promise<Response | void> {
    return async (c: HonoContext) => {
      const req = c.req;

      if (req.method !== 'POST') {
        return c.text('Method not allowed', 405);
      }

      const jobId = req.header('x-job-id');
      const signature = req.header('x-job-signature');
      const isRetry = req.header('x-job-retry') !== undefined;

      const options = await req
        .json()
        .then(async (data) => ZSimpleTriggerJobOptionsSchema.parseAsync(data))
        // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
        .then((data) => data as SimpleTriggerJobOptions)
        .catch(() => null);

      if (!options) {
        return c.text('Bad request', 400);
      }

      const definition = this._jobDefinitions[options.name];

      if (
        typeof jobId !== 'string' ||
        typeof signature !== 'string' ||
        typeof options !== 'object'
      ) {
        return c.text('Bad request', 400);
      }

      if (!definition) {
        return c.text('Job not found', 404);
      }

      if (definition && !definition.enabled) {
        console.log('Attempted to trigger a disabled job', options.name);

        return c.text('Job not found', 404);
      }

      if (!signature || !verify(options, signature)) {
        return c.text('Unauthorized', 401);
      }

      if (definition.trigger.schema) {
        const result = definition.trigger.schema.safeParse(options.payload);

        if (!result.success) {
          return c.text('Bad request', 400);
        }
      }

      console.log(`[JOBS]: Triggering job ${options.name} with payload`, options.payload);

      let backgroundJob = await prisma.backgroundJob
        .update({
          where: {
            id: jobId,
            status: BackgroundJobStatus.PENDING,
          },
          data: {
            status: BackgroundJobStatus.PROCESSING,
            retried: {
              increment: isRetry ? 1 : 0,
            },
            lastRetriedAt: isRetry ? new Date() : undefined,
          },
        })
        .catch(() => null);

      if (!backgroundJob) {
        return c.text('Job not found', 404);
      }

      try {
        await definition.handler({
          payload: options.payload,
          io: this.createJobRunIO(jobId),
        });

        backgroundJob = await prisma.backgroundJob.update({
          where: {
            id: jobId,
            status: BackgroundJobStatus.PROCESSING,
          },
          data: {
            status: BackgroundJobStatus.COMPLETED,
            completedAt: new Date(),
          },
        });
      } catch (error) {
        console.log(`[JOBS]: Job ${options.name} failed`, error);

        const taskHasExceededRetries = error instanceof BackgroundTaskExceededRetriesError;
        const jobHasExceededRetries =
          backgroundJob.retried >= backgroundJob.maxRetries &&
          !(error instanceof BackgroundTaskFailedError);

        if (taskHasExceededRetries || jobHasExceededRetries) {
          backgroundJob = await prisma.backgroundJob.update({
            where: {
              id: jobId,
              status: BackgroundJobStatus.PROCESSING,
            },
            data: {
              status: BackgroundJobStatus.FAILED,
              completedAt: new Date(),
            },
          });

          return c.text('Task exceeded retries', 500);
        }

        backgroundJob = await prisma.backgroundJob.update({
          where: {
            id: jobId,
            status: BackgroundJobStatus.PROCESSING,
          },
          data: {
            status: BackgroundJobStatus.PENDING,
          },
        });

        await this.submitJobToEndpoint({
          jobId,
          jobDefinitionId: backgroundJob.jobId,
          data: options,
        });
      }

      return c.text('OK', 200);
    };
  }

  private async submitJobToEndpoint(options: {
    jobId: string;
    jobDefinitionId: string;
    data: SimpleTriggerJobOptions;
    isRetry?: boolean;
  }) {
    const { jobId, jobDefinitionId, data, isRetry } = options;

    const endpoint = `${NEXT_PRIVATE_INTERNAL_WEBAPP_URL}/api/jobs/${jobDefinitionId}/${jobId}`;
    const signature = sign(data);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Job-Id': jobId,
      'X-Job-Signature': signature,
    };

    if (isRetry) {
      headers['X-Job-Retry'] = '1';
    }

    console.log('Submitting job to endpoint:', endpoint);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        body: JSON.stringify(data),
        headers,
        signal: AbortSignal.timeout(30000), // 30 second timeout
      });

      if (!response.ok) {
        console.error(
          `[JOBS] Failed to submit job ${jobId}: ${response.status} ${response.statusText}`,
        );
      } else {
        console.log(`[JOBS] Successfully submitted job ${jobId}`);
      }
    } catch (error) {
      console.error(`[JOBS] Error submitting job ${jobId}:`, error);
      // Don't throw - we want the job to stay in PENDING for retry by cron
    }
  }

  private createJobRunIO(jobId: string): JobRunIO {
    return {
      runTask: async <T extends void | Json>(cacheKey: string, callback: () => Promise<T>) => {
        const hashedKey = Buffer.from(sha256(cacheKey)).toString('hex');

        let task = await prisma.backgroundJobTask.findFirst({
          where: {
            id: `task-${hashedKey}--${jobId}`,
            jobId,
          },
        });

        if (!task) {
          task = await prisma.backgroundJobTask.create({
            data: {
              id: `task-${hashedKey}--${jobId}`,
              name: cacheKey,
              jobId,
              status: BackgroundJobStatus.PENDING,
            },
          });
        }

        if (task.status === BackgroundJobStatus.COMPLETED) {
          // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
          return task.result as T;
        }

        if (task.retried >= 3) {
          throw new BackgroundTaskExceededRetriesError('Task exceeded retries');
        }

        try {
          const result = await callback();

          task = await prisma.backgroundJobTask.update({
            where: {
              id: task.id,
              jobId,
            },
            data: {
              status: BackgroundJobStatus.COMPLETED,
              result: result === null ? Prisma.JsonNull : result,
              completedAt: new Date(),
            },
          });

          return result;
        } catch (err) {
          task = await prisma.backgroundJobTask.update({
            where: {
              id: task.id,
              jobId,
            },
            data: {
              status: BackgroundJobStatus.PENDING,
              retried: {
                increment: 1,
              },
            },
          });

          console.log(`[JOBS:${task.id}] Task failed`, err);

          throw new BackgroundTaskFailedError('Task failed');
        }
      },
      triggerJob: async (_cacheKey, payload) => await this.triggerJob(payload),
      logger: {
        debug: (...args) => console.debug(`[${jobId}]`, ...args),
        error: (...args) => console.error(`[${jobId}]`, ...args),
        info: (...args) => console.info(`[${jobId}]`, ...args),
        log: (...args) => console.log(`[${jobId}]`, ...args),
        warn: (...args) => console.warn(`[${jobId}]`, ...args),
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      wait: async () => {
        throw new Error('Not implemented');
      },
    };
  }
}

class BackgroundTaskFailedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BackgroundTaskFailedError';
  }
}

class BackgroundTaskExceededRetriesError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BackgroundTaskExceededRetriesError';
  }
}
