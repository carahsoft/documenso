# SCIM 2.0 Implementation

This package implements the SCIM 2.0 (System for Cross-domain Identity Management) protocol for user provisioning in Documenso.

## Overview

SCIM is an open standard for automating user provisioning and deprovisioning. This implementation allows identity providers (like Okta, Azure AD, OneLogin, etc.) to automatically create, update, and delete users in Documenso.

## Configuration

### Environment Variables

Set the following environment variable to enable SCIM:

```bash
NEXT_PRIVATE_SCIM_TOKEN=your-secret-scim-token-here
```

**Security Note**: Generate a strong, random token for production use. This token will be used by your identity provider to authenticate with the SCIM endpoint.

## API Endpoints

All endpoints require Bearer token authentication using the `NEXT_PRIVATE_SCIM_TOKEN` environment variable.

### Base URL

```
https://your-domain.com/api/scim/v2
```

### Discovery Endpoints

These endpoints don't require authentication and provide information about the SCIM service capabilities:

#### Service Provider Configuration
```
GET /scim/v2/ServiceProviderConfig
```

Returns the service provider's SCIM configuration including supported features.

#### Resource Types
```
GET /scim/v2/ResourceTypes
```

Returns the resource types supported by the service provider.

#### Schemas
```
GET /scim/v2/Schemas
```

Returns the schemas supported by the service provider.

### User Management Endpoints

All user management endpoints require authentication with Bearer token.

#### List Users
```
GET /scim/v2/Users
```

Query parameters:
- `startIndex` (optional): 1-based index of the first result (default: 1)
- `count` (optional): Number of results to return (default: 100)
- `filter` (optional): Filter expression (e.g., `userName eq "user@example.com"`)

#### Get User
```
GET /scim/v2/Users/:id
```

#### Create User
```
POST /scim/v2/Users
```

Request body example:
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "user@example.com",
  "name": {
    "givenName": "John",
    "familyName": "Doe"
  },
  "emails": [
    {
      "value": "user@example.com",
      "primary": true
    }
  ],
  "active": true
}
```

#### Update User (Full Replace)
```
PUT /scim/v2/Users/:id
```

Request body: Same as Create User

#### Update User (Partial)
```
PATCH /scim/v2/Users/:id
```

Request body example:
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "displayName",
      "value": "Jane Doe"
    }
  ]
}
```

#### Delete User
```
DELETE /scim/v2/Users/:id
```

## Authentication

All requests must include the Bearer token in the Authorization header:

```
Authorization: Bearer your-scim-token-here
```

## Identity Provider Configuration

### Example: Okta Configuration

1. In Okta Admin Console, go to Applications > Applications
2. Click "Browse App Catalog"
3. Search for and add a generic SCIM 2.0 application
4. Configure the SCIM connector:
   - SCIM connector base URL: `https://your-domain.com/api/scim/v2`
   - Unique identifier field for users: `userName`
   - Supported provisioning actions: Select all
   - Authentication Mode: `HTTP Header`
   - Authorization: `Bearer your-scim-token-here`

### Example: Azure AD Configuration

1. In Azure Portal, go to Azure Active Directory > Enterprise applications
2. Create a new application and select "Non-gallery application"
3. Go to Provisioning and set Provisioning Mode to "Automatic"
4. Configure:
   - Tenant URL: `https://your-domain.com/api/scim/v2`
   - Secret Token: `your-scim-token-here`
5. Test connection and save

## Implementation Notes

- **Password Generation**: Users created via SCIM are assigned random, secure passwords
- **Personal Organizations**: Each SCIM-created user gets a personal organization (if enabled)
- **User Deactivation**: Not currently implemented (returns 501 Not Implemented)
- **Schema Compliance**: Implements SCIM 2.0 Core Schema (RFC 7643)
- **Filtering**: Currently supports basic `userName eq "email"` filter

## Error Responses

All errors follow the SCIM error schema:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidValue",
  "detail": "Error description"
}
```

Common status codes:
- `400` - Invalid request
- `401` - Unauthorized (invalid or missing token)
- `404` - User not found
- `409` - Conflict (user already exists)
- `500` - Internal server error
- `501` - Not implemented

## Security Considerations

1. **Token Storage**: Store the `NEXT_PRIVATE_SCIM_TOKEN` securely in environment variables
2. **Token Rotation**: Implement a process to rotate the SCIM token periodically
3. **HTTPS Only**: Always use HTTPS in production
4. **Rate Limiting**: Consider implementing rate limiting for SCIM endpoints
5. **Audit Logging**: Monitor SCIM operations for security events

## Testing

You can test the SCIM endpoints using curl:

```bash
# List users
curl -X GET \
  -H "Authorization: Bearer your-scim-token-here" \
  https://your-domain.com/api/scim/v2/Users

# Create a user
curl -X POST \
  -H "Authorization: Bearer your-scim-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "test@example.com",
    "name": {
      "givenName": "Test",
      "familyName": "User"
    },
    "emails": [{"value": "test@example.com", "primary": true}]
  }' \
  https://your-domain.com/api/scim/v2/Users
```

## References

- [RFC 7643: SCIM Core Schema](https://tools.ietf.org/html/rfc7643)
- [RFC 7644: SCIM Protocol](https://tools.ietf.org/html/rfc7644)
