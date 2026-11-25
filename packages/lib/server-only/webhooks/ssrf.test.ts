/* eslint-disable @typescript-eslint/no-floating-promises, @typescript-eslint/require-await, no-promise-executor-return, @typescript-eslint/promise-function-async */
// Run with: npx tsx --test packages/lib/server-only/webhooks/ssrf.test.ts
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';

import { assertSafeWebhookUrl, isBlockedIpAddress, sendWebhookRequest } from './ssrf';

describe('isBlockedIpAddress', () => {
  it('blocks private, loopback and metadata IPv4 ranges', () => {
    for (const ip of [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '255.255.255.255',
    ]) {
      assert.equal(isBlockedIpAddress(ip), true, ip);
    }
  });

  it('blocks IPv6 loopback, link local, unique local and mapped addresses', () => {
    for (const ip of [
      '::1',
      '::',
      'fe80::1',
      'fc00::1',
      'fd12:3456::1',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
      '::ffff:169.254.169.254',
      '::ffff:a9fe:a9fe',
      '64:ff9b::7f00:1',
      '2002:7f00:1::1',
    ]) {
      assert.equal(isBlockedIpAddress(ip), true, ip);
    }
  });

  it('allows public addresses', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
      assert.equal(isBlockedIpAddress(ip), false, ip);
    }
  });

  it('treats garbage as blocked', () => {
    assert.equal(isBlockedIpAddress('not-an-ip'), true);
  });
});

describe('assertSafeWebhookUrl', () => {
  const publicResolver = async () => [{ address: '8.8.8.8', family: 4 }];

  it('rejects non http(s) schemes and credentials', async () => {
    await assert.rejects(assertSafeWebhookUrl('file:///etc/passwd'));
    await assert.rejects(assertSafeWebhookUrl('ftp://example.com'));
    await assert.rejects(
      assertSafeWebhookUrl('http://user:pw@example.com', { resolveHostname: publicResolver }),
    );
  });

  it('rejects literal private hosts and obfuscated encodings', async () => {
    for (const url of [
      'http://localhost/',
      'http://foo.localhost/',
      'http://127.0.0.1/',
      'http://2130706433/', // decimal
      'http://0x7f000001/', // hex
      'http://017700000001/', // octal
      'http://[::1]/',
      'http://[::ffff:127.0.0.1]/',
      'http://169.254.169.254/latest/meta-data/',
    ]) {
      await assert.rejects(assertSafeWebhookUrl(url, { resolveHostname: publicResolver }), url);
    }
  });

  it('rejects hosts resolving to private addresses', async () => {
    await assert.rejects(
      assertSafeWebhookUrl('http://evil.example/', {
        resolveHostname: async () => [{ address: '10.0.0.5', family: 4 }],
      }),
    );

    // Mixed answers must be rejected.
    await assert.rejects(
      assertSafeWebhookUrl('http://evil.example/', {
        resolveHostname: async () => [
          { address: '8.8.8.8', family: 4 },
          { address: '::1', family: 6 },
        ],
      }),
    );
  });

  it('fails closed on DNS errors and empty answers', async () => {
    await assert.rejects(
      assertSafeWebhookUrl('http://example.com/', {
        resolveHostname: async () => {
          throw new Error('ENOTFOUND');
        },
      }),
    );

    await assert.rejects(
      assertSafeWebhookUrl('http://example.com/', { resolveHostname: async () => [] }),
    );
  });

  it('fails closed on DNS timeouts', async () => {
    await assert.rejects(
      assertSafeWebhookUrl('http://example.com/', {
        resolveHostname: () => new Promise(() => undefined),
      }),
    );
  });

  it('accepts public hosts', async () => {
    await assertSafeWebhookUrl('https://example.com/hook', { resolveHostname: publicResolver });
  });
});

describe('sendWebhookRequest', () => {
  it('does not connect to loopback servers', async () => {
    let hit = false;

    const server = http.createServer((_req, res) => {
      hit = true;
      res.end('ok');
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    const { port } = server.address() as AddressInfo;

    try {
      await assert.rejects(
        sendWebhookRequest({ url: `http://127.0.0.1:${port}/`, body: '{}', headers: {} }),
      );

      // A hostname that resolves to loopback is blocked at connect time.
      await assert.rejects(
        sendWebhookRequest({ url: `http://localhost:${port}/`, body: '{}', headers: {} }),
      );

      assert.equal(hit, false);
    } finally {
      server.close();
    }
  });
});
