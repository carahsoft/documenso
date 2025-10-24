import { z } from 'zod';

export const ZGetUserRequestSchema = z.object({
  email: z.string().email(),
});

export type TGetUserRequest = z.infer<typeof ZGetUserRequestSchema>;

export const ZGetUserResponseSchema = z.object({
  id: z.number(),
  name: z.string().nullable(),
  email: z.string(),
  createdAt: z.date(),
  organisations: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      role: z.enum(['ADMIN', 'MANAGER', 'MEMBER']),
      teams: z.array(
        z.object({
          id: z.number(),
          name: z.string(),
          url: z.string(),
          role: z.enum(['ADMIN', 'MANAGER', 'MEMBER']),
        }),
      ),
    }),
  ),
});

export type TGetUserResponse = z.infer<typeof ZGetUserResponseSchema>;
