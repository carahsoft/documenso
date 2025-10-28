import { z } from 'zod';

export const ZAccessAuthRequest2FAEmailForDirectTemplateRequestSchema = z.object({
  token: z.string().min(1),
  email: z.string().email(),
});

export const ZAccessAuthRequest2FAEmailForDirectTemplateResponseSchema = z.object({
  success: z.boolean(),
  expiresAt: z.date(),
});

export type TAccessAuthRequest2FAEmailForDirectTemplateRequest = z.infer<
  typeof ZAccessAuthRequest2FAEmailForDirectTemplateRequestSchema
>;

export type TAccessAuthRequest2FAEmailForDirectTemplateResponse = z.infer<
  typeof ZAccessAuthRequest2FAEmailForDirectTemplateResponseSchema
>;
