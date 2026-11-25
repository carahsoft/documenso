import { TsRestHttpError, fetchRequestHandler } from '@ts-rest/serverless/fetch';
import { Hono } from 'hono';

import { ApiContractV1 } from '@documenso/api/v1/contract';
import { ApiContractV1Implementation } from '@documenso/api/v1/implementation';
import { OpenAPIV1 } from '@documenso/api/v1/openapi';
import { testCredentialsHandler } from '@documenso/lib/server-only/public-api/test-credentials';
import { listDocumentsHandler } from '@documenso/lib/server-only/webhooks/zapier/list-documents';
import { subscribeHandler } from '@documenso/lib/server-only/webhooks/zapier/subscribe';
import { unsubscribeHandler } from '@documenso/lib/server-only/webhooks/zapier/unsubscribe';
// This is a bit nasty. Todo: Extract
import type { HonoEnv } from '@documenso/remix/server/router';

// This is bad, ts-router will be created on each request.
// But don't really have a choice here.
export const tsRestHonoApp = new Hono<HonoEnv>();

tsRestHonoApp
  .get('/openapi', (c) => c.redirect('https://openapi-v1.documenso.com'))
  .get('/openapi.json', (c) => c.json(OpenAPIV1))
  .get('/me', async (c) => testCredentialsHandler(c.req.raw));

// Zapier. Todo: (RR7) Check methods. Are these get/post/update requests?
tsRestHonoApp
  .all('/zapier/list-documents', async (c) => listDocumentsHandler(c.req.raw))
  .all('/zapier/subscribe', async (c) => subscribeHandler(c.req.raw))
  .all('/zapier/unsubscribe', async (c) => unsubscribeHandler(c.req.raw));

// Note: this used to be `tsRestHonoApp.mount('/', ...)`. Newer hono versions strip the route base
// path (`/api/v1`) from the request that `mount` passes on, but the ts-rest contract paths include
// it. Use the original request instead so the contract paths keep matching.
tsRestHonoApp.all('*', async (c) => {
  // ts-rest wraps the request in `new Request(...)`, which does not work with the lightweight
  // request object of @hono/node-server, so build a standard Request from the incoming one.
  const { method, headers } = c.req.raw;
  const hasBody = method !== 'GET' && method !== 'HEAD';

  const request = new Request(c.req.url, {
    method,
    headers,
    body: hasBody ? await c.req.arrayBuffer() : undefined,
  });

  return fetchRequestHandler({
    request,
    contract: ApiContractV1,
    router: ApiContractV1Implementation,
    options: {
      errorHandler: (err) => {
        if (err instanceof TsRestHttpError && err.statusCode === 500) {
          console.error(err);
        }
      },
    },
  });
});
