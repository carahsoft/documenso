import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

import { AppError, AppErrorCode } from '../../errors/app-error';

const DNS_LOOKUP_TIMEOUT_MS = 3000;
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

const blockedV4 = new net.BlockList();

for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blockedV4.addSubnet(network, prefix, 'ipv4');
}

const blockedV6 = new net.BlockList();

for (const [network, prefix] of [
  ['::', 96], // Unspecified, loopback and deprecated IPv4 compatible addresses.
  ['64:ff9b::', 96], // NAT64.
  ['100::', 64], // Discard only.
  ['2001:db8::', 32], // Documentation.
  ['2002::', 16], // 6to4.
  ['fc00::', 7], // Unique local.
  ['fe80::', 10], // Link local.
  ['ff00::', 8], // Multicast.
] as const) {
  blockedV6.addSubnet(network, prefix, 'ipv6');
}

/**
 * Expand an IPv6 address into its eight 16 bit groups.
 */
const expandIpv6 = (address: string) => {
  const withoutZone = address.split('%')[0];

  let head = withoutZone;
  let tail = '';

  if (withoutZone.includes('::')) {
    [head, tail] = withoutZone.split('::');
  }

  const toGroups = (part: string) => {
    if (part === '') {
      return [];
    }

    const groups: number[] = [];

    for (const piece of part.split(':')) {
      if (piece.includes('.')) {
        const octets = piece.split('.').map(Number);

        groups.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
      } else {
        groups.push(parseInt(piece, 16));
      }
    }

    return groups;
  };

  const headGroups = toGroups(head);
  const tailGroups = toGroups(tail);

  if (!withoutZone.includes('::')) {
    return headGroups;
  }

  return [
    ...headGroups,
    ...new Array(8 - headGroups.length - tailGroups.length).fill(0),
    ...tailGroups,
  ];
};

/**
 * Returns true if the address is not a public, globally routable address.
 * Unparseable values are treated as blocked.
 */
export const isBlockedIpAddress = (address: string): boolean => {
  const family = net.isIP(address);

  if (family === 4) {
    return blockedV4.check(address, 'ipv4');
  }

  if (family === 6) {
    const groups = expandIpv6(address);

    if (groups.length !== 8 || groups.some((group) => Number.isNaN(group))) {
      return true;
    }

    // IPv4 mapped (::ffff:a.b.c.d), check the embedded IPv4 address.
    if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
      const embedded = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join(
        '.',
      );

      return blockedV4.check(embedded, 'ipv4');
    }

    const normalized = groups.map((group) => group.toString(16)).join(':');

    return blockedV6.check(normalized, 'ipv6');
  }

  return true;
};

/**
 * Hosts that are allowed to resolve to private addresses (e.g. an internal
 * service in the same cluster). Empty by default.
 */
const getBypassHosts = () => {
  const raw = process.env['NEXT_PRIVATE_WEBHOOK_SSRF_BYPASS_HOSTS'] ?? '';

  return new Set(
    raw
      .split(',')
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry.length > 0),
  );
};

const normalizeHostname = (hostname: string) => {
  const lowered = hostname.toLowerCase().replace(/\.+$/, '');

  return lowered.startsWith('[') ? lowered.slice(1, -1) : lowered;
};

const isBypassedHostname = (hostname: string) => getBypassHosts().has(normalizeHostname(hostname));

const invalidWebhookUrl = (message: string) =>
  new AppError(AppErrorCode.INVALID_REQUEST, {
    message,
  });

const parseWebhookUrl = (url: string) => {
  let parsed: URL;

  try {
    parsed = new URL(url);
  } catch {
    throw invalidWebhookUrl('Invalid webhook URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw invalidWebhookUrl('Webhook URL must use http or https');
  }

  if (parsed.username || parsed.password) {
    throw invalidWebhookUrl('Webhook URL must not contain credentials');
  }

  return parsed;
};

const withTimeout = async <T>(promise: Promise<T>, ms: number) => {
  let timer: NodeJS.Timeout | undefined;

  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('DNS lookup timed out')), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

type TResolveHostname = (hostname: string) => Promise<{ address: string; family: number }[]>;

const defaultResolveHostname: TResolveHostname = async (hostname) =>
  await dns.promises.lookup(hostname, { all: true, verbatim: true });

/**
 * Validate a webhook URL. Fails CLOSED: a host that cannot be resolved, or that
 * resolves to any non public address, is rejected.
 *
 * This is a point in time check used for user feedback and early rejection. The
 * actual connection is enforced separately in `sendWebhookRequest`, which pins
 * the connection to the validated address.
 */
export const assertSafeWebhookUrl = async (
  url: string,
  options?: { resolveHostname?: TResolveHostname },
) => {
  const parsed = parseWebhookUrl(url);

  const hostname = normalizeHostname(parsed.hostname);

  if (isBypassedHostname(hostname)) {
    return;
  }

  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw invalidWebhookUrl('Webhook URL must not point to a private or internal address');
  }

  if (net.isIP(hostname)) {
    if (isBlockedIpAddress(hostname)) {
      throw invalidWebhookUrl('Webhook URL must not point to a private or internal address');
    }

    return;
  }

  const resolveHostname = options?.resolveHostname ?? defaultResolveHostname;

  let addresses: { address: string; family: number }[];

  try {
    addresses = await withTimeout(resolveHostname(hostname), DNS_LOOKUP_TIMEOUT_MS);
  } catch {
    throw invalidWebhookUrl('Webhook URL host could not be resolved');
  }

  if (addresses.length === 0 || addresses.some(({ address }) => isBlockedIpAddress(address))) {
    throw invalidWebhookUrl('Webhook URL must not point to a private or internal address');
  }
};

/**
 * DNS lookup used for the actual connection. Every resolved address is
 * validated and the connection is made to exactly those addresses, so a DNS
 * answer cannot change between validation and connection (DNS rebinding).
 */
const createSafeLookup =
  (hostname: string): net.LookupFunction =>
  (lookupHostname, lookupOptions, callback) => {
    if (isBypassedHostname(hostname)) {
      dns.lookup(lookupHostname, lookupOptions, callback);
      return;
    }

    dns.lookup(
      lookupHostname,
      { ...lookupOptions, all: true, verbatim: true },
      (error, results) => {
        // The lookup callback arity differs between the single and `all` forms.
        const done = callback as unknown as (...args: unknown[]) => void;

        if (error) {
          done(error, '', 4);
          return;
        }

        const addresses = results as dns.LookupAddress[];

        if (
          addresses.length === 0 ||
          addresses.some(({ address }) => isBlockedIpAddress(address))
        ) {
          done(new Error('Webhook host resolves to a blocked address'), '', 4);
          return;
        }

        if (lookupOptions.all) {
          done(null, addresses);
          return;
        }

        done(null, addresses[0].address, addresses[0].family);
      },
    );
  };

export type TWebhookRequestResult = {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  body: string;
};

/**
 * Send a POST request to a webhook URL.
 *
 * - Connection addresses are validated at connect time (no DNS rebinding).
 * - Redirects are never followed (a 3xx response is reported as is).
 * - The request has a timeout and the response size is capped.
 */
export const sendWebhookRequest = async ({
  url,
  body,
  headers,
}: {
  url: string;
  body: string;
  headers: Record<string, string>;
}): Promise<TWebhookRequestResult> => {
  const parsed = parseWebhookUrl(url);

  const hostname = normalizeHostname(parsed.hostname);

  if (!isBypassedHostname(hostname) && net.isIP(hostname) && isBlockedIpAddress(hostname)) {
    throw invalidWebhookUrl('Webhook URL must not point to a private or internal address');
  }

  const transport = parsed.protocol === 'https:' ? https : http;

  return await new Promise<TWebhookRequestResult>((resolve, reject) => {
    const request = transport.request(
      parsed,
      {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Length': Buffer.byteLength(body).toString(),
        },
        lookup: createSafeLookup(hostname),
        timeout: REQUEST_TIMEOUT_MS,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;

        response.on('data', (chunk: Buffer) => {
          size += chunk.length;

          if (size > MAX_RESPONSE_BYTES) {
            request.destroy(new Error('Webhook response too large'));
            return;
          }

          chunks.push(chunk);
        });

        response.on('end', () => {
          const status = response.statusCode ?? 0;

          resolve({
            status,
            ok: status >= 200 && status < 300,
            headers: Object.fromEntries(
              Object.entries(response.headers).map(([key, value]) => [
                key,
                Array.isArray(value) ? value.join(', ') : (value ?? ''),
              ]),
            ),
            body: Buffer.concat(chunks as unknown as Uint8Array[]).toString('utf8'),
          });
        });

        response.on('error', reject);
      },
    );

    request.on('timeout', () => {
      request.destroy(new Error('Webhook request timed out'));
    });

    request.on('error', reject);

    request.write(body);
    request.end();
  });
};
