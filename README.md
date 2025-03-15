# Domain Check API

A simple REST API to check domain name availability using WHOIS and DNS lookups.

## Features

- Check domain availability using WHOIS records
- Verify domain status through DNS resolution
- Combined status check using both methods
- Support for custom TLDs (Top Level Domains)
- Optional rate limiting to prevent abuse
- Response caching for improved performance
- Configurable timeouts for WHOIS and DNS checks
- Bulk domain checking
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

```json
{
  "domain": "example.com",
  "status": "taken|available",
  "whois": {
    "status": "taken|available|error|timeout",
    "expiration_date": "2024-12-31", // Only for taken domains
    "registrar": "Example Registrar" // Only for taken domains
  },
  "dns": {
    "status": "taken|available|error|timeout",
    "ip": "93.184.216.34" // Only for taken domains
  },
  "tld": "com",
  "response_time": "0.82s"
}
```

### Bulk Domain Check

```
POST /bulk
Content-Type: application/json

{
    "domains": [
        {"domain": "example", "tld": "com"},
        {"domain": "example", "tld": "org"},
        {"domain": "example"}
    ]
}
```

- Maximum 10 domains per request
- Rate limited to 5 requests per minute (when rate limiting is enabled)

### Health Check

```
GET /health
```

Response:

```json
{
  "status": "healthy",
  "timestamp": "2024-03-20T10:30:00Z",
  "version": "1.0.0",
  "rate_limiting": true,
  "timeouts": {
    "whois": "5s",
    "dns": "3s"
  }
}
```

### Metrics

```
GET /metrics
```

Response:

```json
{
  "cache_stats": {
    "cache_hits": 150,
    "cache_misses": 50
  },
  "uptime": "2024-03-20T10:00:00Z",
  "rate_limiting_enabled": true
}
```

## Configuration

### Environment Variables

| Variable             | Description                          | Default | Example |
| -------------------- | ------------------------------------ | ------- | ------- |
| `ENABLE_RATE_LIMITS` | Enable/disable rate limiting         | `true`  | `false` |
| `WHOIS_TIMEOUT`      | Timeout for WHOIS queries in seconds | `5`     | `10`    |
| `DNS_TIMEOUT`        | Timeout for DNS queries in seconds   | `3`     | `5`     |
| `PORT`               | Port to run the server on            | `5000`  | `8080`  |

### Rate Limits (when enabled)

- Single domain check: 10 requests per minute
- Bulk check: 5 requests per minute
- Overall: 100 requests per day
- Health and metrics endpoints: unlimited

### Caching

Results are cached for 5 minutes to improve performance and reduce load on WHOIS servers.

## Local Development

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the development server:

```bash
python script.py
```

The API will be available at `http://localhost:5000`

## Testing

Run the test suite:

```bash
# Run tests
pytest test_script.py -v

# Run tests with coverage report
pytest test_script.py -v --cov=script
```

The test suite includes:

- Health check endpoint testing
- Metrics endpoint testing
- Known domain checks (google.com, facebook.com)
- Invalid domain handling
- Bulk domain checking
- Custom TLD support

## Deployment

This project is ready to deploy to platforms like Railway or Dokploy using Nixpacks.

### Requirements:

- Python 3.x
- Dependencies listed in requirements.txt

### Deployment Steps:

1. Clone this repository
2. Configure environment variables if needed
3. Connect your repository to Railway/Dokploy
4. The platform will automatically:
   - Detect the Python project
   - Use Nixpacks for building
   - Install dependencies
   - Start the application using gunicorn

### Manual Nixpacks Build

You can also build the application manually using Nixpacks:

```bash
# Install Nixpacks
curl -sSL https://nixpacks.com/install.sh | bash

# Build the application
nixpacks build . --name domain-check-api
```

## CI/CD

The project includes GitHub Actions workflows that:

1. Run the test suite
2. Generate coverage reports
3. Build the application using Nixpacks
4. Deploy on successful builds (when configured)

## License

MIT License
