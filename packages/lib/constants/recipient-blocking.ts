import { env } from '@documenso/lib/utils/env';

/**
 * Get the list of blocked recipient domains from environment variable.
 * The environment variable should be a comma-separated list of domains.
 * Example: BLOCKED_RECIPIENT_DOMAINS="spam.com,blocked.org,unwanted.net"
 */
export const getBlockedRecipientDomains = (): string[] => {
  const blockedDomains = env('BLOCKED_RECIPIENT_DOMAINS');

  if (!blockedDomains) {
    return [];
  }

  return blockedDomains
    .split(',')
    .map((domain) => domain.trim().toLowerCase())
    .filter((domain) => domain.length > 0);
};

/**
 * Check if an email address belongs to a blocked domain.
 * @param email - The email address to check
 * @returns true if the email domain is blocked, false otherwise
 */
export const isEmailDomainBlocked = (email: string): boolean => {
  const blockedDomains = getBlockedRecipientDomains();

  if (blockedDomains.length === 0) {
    return false;
  }

  const emailDomain = email.toLowerCase().split('@')[1];

  if (!emailDomain) {
    return false;
  }

  return blockedDomains.some((blockedDomain) => {
    // Support wildcard matching for subdomains (e.g., "*.spam.com" matches "mail.spam.com")
    if (blockedDomain.startsWith('*.')) {
      const baseDomain = blockedDomain.slice(2);
      return emailDomain === baseDomain || emailDomain.endsWith(`.${baseDomain}`);
    }

    return emailDomain === blockedDomain;
  });
};

/**
 * Get a user-friendly error message for blocked email domains.
 */
export const getBlockedDomainErrorMessage = (email: string): string => {
  const domain = email.toLowerCase().split('@')[1];
  return `The email domain "${domain}" is not allowed as a recipient.`;
};
