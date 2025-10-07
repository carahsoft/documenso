import { z } from 'zod';

export const ZCreateApiTokenBaseSchema = z.object({
  teamId: z.number().optional(),
  tokenName: z.string().min(3, { message: 'The token name should be 3 characters or longer' }),
  expirationDate: z.string().nullable(),
});

export const ZCreateApiTokenRequestSchema = ZCreateApiTokenBaseSchema.refine(
  (data) => data.teamId !== undefined,
  {
    message: 'teamId is required',
    path: ['teamId'],
  },
);

export const ZCreateApiTokenResponseSchema = z.object({
  id: z.number(),
  token: z.string(),
});
