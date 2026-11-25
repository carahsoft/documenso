import { DocumentDataType } from '@prisma/client';
import { base64 } from '@scure/base';
import { match } from 'ts-pattern';

export type GetFileOptions = {
  type: DocumentDataType;
  data: string;
};

export const getFile = async ({ type, data }: GetFileOptions) => {
  return await match(type)
    .with(DocumentDataType.BYTES, () => getFileFromBytes(data))
    .with(DocumentDataType.BYTES_64, () => getFileFromBytes64(data))
    .with(DocumentDataType.S3_PATH, async () => getFileFromS3(data))
    .exhaustive();
};

const getFileFromBytes = (data: string) => {
  const encoder = new TextEncoder();

  const binaryData = encoder.encode(data);

  return binaryData;
};

const getFileFromBytes64 = (data: string) => {
  const binaryData = base64.decode(data);

  return binaryData;
};

/**
 * Collect candidate access tokens for the current page (recipient token in the
 * path, multi sign / embed tokens in the query string). The server validates
 * every candidate against the requested file, so extra values are harmless.
 */
const getCandidateAccessTokens = () => {
  if (typeof window === 'undefined') {
    return [];
  }

  const searchParams = new URLSearchParams(window.location.search);

  const pathSegments = window.location.pathname.split('/').filter((segment) => segment.length > 0);

  return [...searchParams.getAll('token'), ...pathSegments.slice(0, 8)].slice(0, 32);
};

const getFileFromS3 = async (key: string) => {
  const getPresignedUrlResponse = await fetch(`/api/files/presigned-get-url`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      key,
      tokens: getCandidateAccessTokens(),
    }),
  });

  if (!getPresignedUrlResponse.ok) {
    throw new Error(
      `Failed to get presigned url with key "${key}", failed with status code ${getPresignedUrlResponse.status}`,
    );
  }

  const { url } = await getPresignedUrlResponse.json();

  const response = await fetch(url, {
    method: 'GET',
  });

  if (!response.ok) {
    throw new Error(`Failed to get file "${key}", failed with status code ${response.status}`);
  }

  const buffer = await response.arrayBuffer();

  const binaryData = new Uint8Array(buffer);

  return binaryData;
};
