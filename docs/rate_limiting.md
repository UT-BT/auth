# Rate Limiting Documentation

## Overview

The authentication server implements a tiered rate limiting system designed to protect against abuse while ensuring reliable access for legitimate users. The system uses an in-memory storage mechanism and is designed to work correctly even when the server is behind a reverse proxy.

## Rate Limit Groups

The following table outlines the rate limits for different endpoint groups:

| Group | Endpoints | Limit | Time Window | Purpose |
|-------|-----------|-------|-------------|----------|
| auth | `/discord`, `/callback` | 5 requests | 5 minutes | Prevent login abuse |
| token | `/api/refresh`, `/api/store-auth` | 30 requests | 1 minute | Protect token operations |
| verify | `/api/verify` | 60 requests | 1 minute | Allow frequent verifications |
| default | All other endpoints | 100 requests | 1 minute | General protection |

## Response Headers

The rate limiter adds the following headers to all responses:

- `X-RateLimit-Limit`: The maximum number of requests allowed in the time window
- `X-RateLimit-Remaining`: The number of requests remaining in the current window
- `X-RateLimit-Reset`: Unix timestamp when the rate limit window resets
- `X-RateLimit-Group`: The rate limit group applied to the request

## IP Address Detection

The rate limiter supports deployments behind reverse proxies by checking the following headers in order:

1. `X-Real-IP`: Used when provided by the reverse proxy
2. `X-Forwarded-For`: Used when provided, taking the first IP in the list
3. `RemoteAddr`: Used as a fallback when no proxy headers are present

This ensures accurate rate limiting based on the actual client IP rather than the proxy's IP address.

## Rate Limit Exceeded

When a client exceeds their rate limit:

1. The server returns a `429 Too Many Requests` status code
2. All rate limit headers are included in the response
3. The incident is logged with the following information:
   - Client IP address
   - Rate limit group
   - Current request count
   - Reset time

Example log entry:
```
WARN Rate limit exceeded {"ip": "192.168.1.1", "group": "auth", "count": 6, "reset_at": "2024-03-21T15:04:05Z"}
```

## Best Practices for Clients

1. Monitor the rate limit headers in responses to track usage
2. Implement exponential backoff when receiving 429 responses
3. Cache successful responses when appropriate
4. Group related operations to minimize API calls

Example client implementation for handling rate limits:

```typescript
async function makeRequest(url: string): Promise<Response> {
  const response = await fetch(url);
  
  if (response.status === 429) {
    const resetTime = response.headers.get('X-RateLimit-Reset');
    const waitTime = Math.max(0, parseInt(resetTime!) * 1000 - Date.now());
    await new Promise(resolve => setTimeout(resolve, waitTime));
    return makeRequest(url); // Retry after waiting
  }
  
  return response;
}
```

## Monitoring and Alerts

The rate limiter logs all violations at the WARN level. Consider setting up alerts for:

- High frequency of rate limit violations from the same IP
- Unusual patterns in rate limit group usage
- Sudden spikes in rate limit violations

## Configuration

Rate limits are configured in code and can be adjusted by modifying the constants in the rate limiter implementation. Consider your specific use case when adjusting these limits.

## Proxy Configuration

When deploying behind a reverse proxy, ensure it is configured to set the appropriate headers:

```nginx
# Nginx example
location / {
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://backend;
}
```

```apache
# Apache example
RequestHeader set X-Real-IP %{REMOTE_ADDR}s
RequestHeader set X-Forwarded-For %{REMOTE_ADDR}s
``` 