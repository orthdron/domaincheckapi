from marshmallow import Schema, fields

LOOKUP_STATUSES = ["available", "taken", "error", "timeout"]


class WhoisResultSchema(Schema):
    status = fields.Str(metadata={"enum": LOOKUP_STATUSES})
    expiration_date = fields.Str(
        allow_none=True,
        metadata={"example": "2028-09-14", "description": "Only for taken domains"},
    )
    registrar = fields.Str(
        allow_none=True,
        metadata={"example": "MarkMonitor, Inc.", "description": "Only for taken domains"},
    )
    error = fields.Str(metadata={"description": "Only when status is error or timeout"})


class DnsResultSchema(Schema):
    status = fields.Str(metadata={"enum": LOOKUP_STATUSES})
    ip = fields.Str(metadata={"example": "93.184.216.34", "description": "Only for taken domains"})
    error = fields.Str(metadata={"description": "Only when status is error or timeout"})


class DomainCheckResponseSchema(Schema):
    domain = fields.Str(metadata={"example": "example.com"})
    status = fields.Str(
        metadata={
            "enum": ["available", "taken", "unknown"],
            "description": (
                "taken if WHOIS or DNS finds the domain; unknown if WHOIS failed "
                "and DNS found nothing (retry later); otherwise available"
            ),
        }
    )
    whois = fields.Nested(WhoisResultSchema)
    dns = fields.Nested(DnsResultSchema)
    tld = fields.Str(metadata={"example": "com"})
    response_time = fields.Str(metadata={"example": "0.45s"})
    cached = fields.Boolean()


class BulkErrorItemSchema(Schema):
    domain = fields.Str(metadata={"example": "inv@lid.com"})
    status = fields.Str(metadata={"enum": ["error"]})
    error = fields.Str(metadata={"example": "Invalid domain name format"})


class ErrorResponseSchema(Schema):
    error = fields.Str(metadata={"example": "Invalid request"})
    message = fields.Str(metadata={"example": "Invalid domain name format"})


class MetricsResponseSchema(Schema):
    uptime = fields.Str(metadata={"example": "1d 2h 34m"})
    uptime_seconds = fields.Int(metadata={"example": 95640})
    cache_stats = fields.Dict(
        keys=fields.Str(),
        values=fields.Int(),
        metadata={"example": {"cache_hits": 150, "cache_misses": 50}},
    )
    rate_limits = fields.Dict(
        keys=fields.Str(),
        values=fields.Raw(),
        metadata={
            "example": {
                "enabled": True,
                "single": "10 per minute",
                "bulk": "5 per minute",
                "daily": "100 per day",
            }
        },
    )


class BulkCheckRequestSchema(Schema):
    domains = fields.List(
        fields.Raw(),
        required=True,
        metadata={
            "description": (
                "Domain names (without TLD), or objects of the form "
                '{"domain": "example", "tld": "org"}. Maximum 10 by default.'
            ),
            "example": ["example", {"domain": "example", "tld": "org"}],
        },
    )
    tld = fields.Str(
        load_default="com",
        metadata={"example": "com", "description": "Default TLD for entries without one"},
    )
