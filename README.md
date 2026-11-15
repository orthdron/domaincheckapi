# Domain Check API

A simple REST API to check domain name availability using WHOIS and DNS lookups.

## Features

- Check domain availability using WHOIS records
- Verify domain status through DNS resolution
- Combined status check using both methods
- Support for custom TLDs (Top Level Domains)
- Optional rate limiting to prevent abuse
- Response caching for improved performance (failed lookups are never cached)
- Configurable timeouts for WHOIS and DNS checks
- Bulk domain checking, with all lookups run concurrently
- Metrics and health monitoring
- Simple REST API interface
- Comprehensive test suite
- CI/CD with GitHub Actions
- Nixpacks compatibility for easy deployment

## API Endpoints

### Single Domain Check

```
GET /?domain=example[&tld=com]
```

#### Parameters:

- `domain` (required): The domain name to check (without TLD)
- `tld` (optional): The top-level domain to check (default: "com")

#### Response:

The overall `status` is:

- `taken` if WHOIS or DNS finds the domain
- `unknown` if the WHOIS lookup failed or timed out and DNS found nothing (many registered domains have no DNS records, so this can't be called available; retry later)
- `available` otherwise

```json
{
  "domain": "example.com",
  "status": "taken|available|unknown",
  "whois": {
    "status": "taken|available|error|timeout",
    "expiration_date": "2024-12-31", // Only for taken domains
    "registrar": "Example Registrar", // Only for taken domains
    "error": "..." // Only for error/timeout
  },
  "dns": {
    "status": "taken|available|error|timeout",
    "ip": "93.184.216.34", // Only for taken domains (IPv4 preferred)
    "error": "..." // Only for error/timeout
  },
  "tld": "com",
  "response_time": "0.82s",
  "cached": false
}
```

### Bulk Domain Check

```
POST /bulk
Content-Type: application/json

{
    "domains": [
        "example",
        {"domain": "example", "tld": "org"},
        {"domain": "example"}
    ],
    "tld": "com"
}
```

- Entries are plain names (using the top-level `tld`, default `com`) or `{"domain", "tld"}` objects
- Results come back in request order; invalid entries appear as `{"domain": ..., "status": "error", "error": ...}`
- Maximum 10 domains per request (`MAX_BULK_DOMAINS`)
- Rate limited to 5 requests per minute (when rate limiting is enabled)

### Health Check

```
GET /health
```

Response:

```json
{ "status": "ok" }
```

### Metrics

```
GET /metrics
```

Response:

```json
{
  "uptime": "1d 2h 34m",
  "uptime_seconds": 95640,
  "cache_stats": {
    "cache_hits": 150,
    "cache_misses": 50
  },
  "rate_limits": {
    "enabled": true,
    "single": "10 per minute",
    "bulk": "5 per minute",
    "daily": "100 per day"
  }
}
```

Counters are per process (per gunicorn worker) and reset on restart.

### Documentation

- `GET /docs` – Swagger UI
- `GET /openapi.json` – OpenAPI 3 spec (generated from code; `openapi.json` in the repo is a copy, refresh it with `python -m app.docs`)

## Configuration

### Environment Variables

The project includes an `example.env` file with default values and detailed comments. Copy this file to `.env` to get started:

```bash
cp example.env .env
```

Key environment variables:

| Variable             | Description                          | Default      | Example                    |
| -------------------- | ------------------------------------ | ------------ | -------------------------- |
| `ENABLE_RATE_LIMITS`  | Enable/disable rate limiting                       | `false`  | `true`                     |
| `REDIS_URL`           | Redis URL for rate limiting                        | `None`   | `redis://localhost:6379/0` |
| `RATE_LIMIT_SINGLE`   | Single checks per minute per client                | `10`     | `30`                       |
| `RATE_LIMIT_BULK`     | Bulk checks per minute per client                  | `5`      | `10`                       |
| `RATE_LIMIT_DAILY`    | Checks per day per client (single + bulk combined) | `100`    | `1000`                     |
| `TRUSTED_PROXY_COUNT` | Reverse proxies in front of the app                | `0`      | `1`                        |
| `CACHE_TYPE`          | Cache storage type                                 | `simple` | `redis`                    |
| `CACHE_REDIS_URL`     | Redis URL for caching                              | `None`   | `redis://localhost:6379/1` |
| `CACHE_TIMEOUT`       | Cache duration in seconds                          | `300`    | `600`                      |
| `WHOIS_TIMEOUT`       | Timeout for WHOIS queries in seconds               | `5`      | `10`                       |
| `DNS_TIMEOUT`         | Timeout for DNS queries in seconds                 | `3`      | `5`                        |
| `MAX_BULK_DOMAINS`    | Max domains in bulk request                        | `10`     | `20`                       |
| `LOOKUP_WORKERS`      | Max concurrent WHOIS/DNS lookups per process       | `32`     | `64`                       |
| `PORT`                | Port to run the server on                          | `3000`   | `8080`                     |
| `WEB_CONCURRENCY`     | Gunicorn worker processes                          | `1`      | `4`                        |
| `GUNICORN_THREADS`    | Threads per gunicorn worker                        | `16`     | `32`                       |

See `example.env` for all available options and detailed comments.

### Storage Configuration

#### Rate Limiting Storage

The API supports two storage backends for rate limiting:

1. **Redis** (Recommended for production):

   - Set `REDIS_URL` to your Redis instance
   - Example: `REDIS_URL=redis://localhost:6379/0`
   - Provides persistent and distributed rate limiting

2. **Memory** (Development only):
   - Used when `REDIS_URL` is not set
   - Not suitable for production
   - Data is lost on server restart

#### Cache Storage

Two caching backends are available:

1. **Simple** (Default):

   - Set `CACHE_TYPE=simple`
   - In-memory caching
   - Suitable for development

2. **Redis**:
   - Set `CACHE_TYPE=redis`
   - Set `CACHE_REDIS_URL` to your Redis instance
   - Recommended for production
   - Provides distributed caching

### Rate Limits (when enabled)

- Single domain check: 10 requests per minute
- Bulk check: 5 requests per minute
- Overall: 100 checks per day (single and bulk share this budget)
- Health, metrics and docs endpoints: unlimited
- Exceeding a limit returns `429` with a JSON error body and `Retry-After`/`X-RateLimit-*` headers
- If the rate-limit store (Redis) is unreachable, the same limits are enforced in each process's memory until it recovers (so with several workers the effective limit is looser), rather than failing requests

Behind a reverse proxy (Railway, Dokploy, nginx), set `TRUSTED_PROXY_COUNT=1` so limits apply per client rather than to the proxy's IP. Leave it at `0` when the app is exposed directly, otherwise clients could spoof `X-Forwarded-For`.

With more than one gunicorn worker (`WEB_CONCURRENCY` > 1), use Redis for both `REDIS_URL` and the cache so limits and cached results are shared between workers.

### Caching

Results are cached for 5 minutes to improve performance and reduce load on WHOIS servers. Lookups that timed out or errored are not cached, so the next request retries them.

## Local Development

Requires Python 3.11+.

1. Install dependencies:

```bash
pip install -r requirements-dev.txt
```

2. Run the server:

```bash
gunicorn wsgi:app      # production server, settings in gunicorn.conf.py
python wsgi.py         # or Flask's development server
./start.sh             # or: create .venv, install, run gunicorn
```

The API will be available at `http://localhost:3000`

## Testing

Run the test suite:

```bash
# Fast, offline unit tests (WHOIS/DNS are mocked)
pytest -m "not network"

# With a coverage report
pytest -m "not network" --cov=app

# Live smoke tests against real WHOIS/DNS servers
pytest -m network
```

The test suite covers every endpoint, input validation, caching, timeouts, concurrency of bulk lookups, rate limiting, WHOIS/DNS failure handling, and checks that the committed `openapi.json` matches the code.

## Deployment

This project is ready to deploy to platforms like Railway or Dokploy using Nixpacks.

### Requirements:

- Python 3.11+ (Nixpacks builds use 3.11)
- Dependencies listed in requirements.txt

### Deployment Steps:

1. Clone this repository
2. Configure environment variables if needed
3. Connect your repository to Railway/Dokploy
4. The platform will automatically:
   - Detect the Python project
   - Use Nixpacks for building
   - Install dependencies
   - Start the application using gunicorn (configured in `gunicorn.conf.py`)

### Manual Nixpacks Build

You can also build the application manually using Nixpacks:

```bash
# Install Nixpacks
curl -sSL https://nixpacks.com/install.sh | bash

# Build the application
nixpacks build . --name domain-check-api
```

## CI/CD

The GitHub Actions workflow runs on every push and pull request to `main`:

1. Unit tests with a coverage report on Python 3.11, 3.12, 3.13 and 3.14
2. Live WHOIS/DNS smoke tests (informational; they don't fail the build)

Dependency updates are handled by Renovate.

## License

MIT License
