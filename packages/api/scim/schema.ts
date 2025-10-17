import { z } from 'zod';

/**
 * SCIM 2.0 Schema Definitions
 * Based on RFC 7643: https://tools.ietf.org/html/rfc7643
 */

export const ZSCIMMetaSchema = z.object({
  resourceType: z.string(),
  created: z.string().datetime().optional(),
  lastModified: z.string().datetime().optional(),
  location: z.string().url().optional(),
  version: z.string().optional(),
});

export const ZSCIMNameSchema = z.object({
  formatted: z.string().optional(),
  familyName: z.string().optional(),
  givenName: z.string().optional(),
  middleName: z.string().optional(),
  honorificPrefix: z.string().optional(),
  honorificSuffix: z.string().optional(),
});

export const ZSCIMEmailSchema = z.object({
  value: z.string().email(),
  type: z.string().optional(),
  primary: z.boolean().optional(),
  display: z.string().optional(),
});

export const ZSCIMUserSchema = z.object({
  schemas: z.array(z.string()).default(['urn:ietf:params:scim:schemas:core:2.0:User']),
  id: z.string().optional(),
  externalId: z.string().optional(),
  userName: z.string().email(),
  name: ZSCIMNameSchema.optional(),
  displayName: z.string().optional(),
  emails: z.array(ZSCIMEmailSchema).optional(),
  active: z.boolean().default(true),
  meta: ZSCIMMetaSchema.optional(),
});

export const ZSCIMUserCreateSchema = ZSCIMUserSchema.omit({ id: true, meta: true });

export const ZSCIMUserUpdateSchema = ZSCIMUserSchema.partial().required({
  schemas: true,
});

export const ZSCIMListResponseSchema = z.object({
  schemas: z.array(z.string()).default(['urn:ietf:params:scim:api:messages:2.0:ListResponse']),
  totalResults: z.number(),
  startIndex: z.number().default(1),
  itemsPerPage: z.number(),
  Resources: z.array(ZSCIMUserSchema),
});

export const ZSCIMErrorSchema = z.object({
  schemas: z.array(z.string()).default(['urn:ietf:params:scim:api:messages:2.0:Error']),
  status: z.string(),
  scimType: z.string().optional(),
  detail: z.string().optional(),
});

export const ZSCIMPatchOperationSchema = z.object({
  op: z
    .string()
    .transform((val) => val.toLowerCase())
    .pipe(z.enum(['add', 'remove', 'replace'])),
  path: z.string().optional(),
  value: z.unknown().optional(),
});

export const ZSCIMPatchRequestSchema = z.object({
  schemas: z.array(z.string()).default(['urn:ietf:params:scim:api:messages:2.0:PatchOp']),
  Operations: z.array(ZSCIMPatchOperationSchema),
});

export type TSCIMUser = z.infer<typeof ZSCIMUserSchema>;
export type TSCIMUserCreate = z.infer<typeof ZSCIMUserCreateSchema>;
export type TSCIMUserUpdate = z.infer<typeof ZSCIMUserUpdateSchema>;
export type TSCIMListResponse = z.infer<typeof ZSCIMListResponseSchema>;
export type TSCIMError = z.infer<typeof ZSCIMErrorSchema>;
export type TSCIMPatchRequest = z.infer<typeof ZSCIMPatchRequestSchema>;
