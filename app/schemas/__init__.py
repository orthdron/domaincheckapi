from marshmallow import Schema, fields

class WhoisResultSchema(Schema):
    status = fields.Str(metadata={"enum": ['available', 'taken', 'error']})
    details = fields.Dict(keys=fields.Str(), values=fields.Raw())

class DnsResultSchema(Schema):
    status = fields.Str(metadata={"enum": ['available', 'taken', 'error']})
    records = fields.List(fields.Str())

class DomainCheckResponseSchema(Schema):
    domain = fields.Str(metadata={"example": "example.com"})
    status = fields.Str(metadata={"enum": ['available', 'taken']})
    whois = fields.Nested(WhoisResultSchema)
    dns = fields.Nested(DnsResultSchema)
    tld = fields.Str(metadata={"example": "com"})
    response_time = fields.Str(metadata={"example": "0.45s"})
    cached = fields.Boolean()

class ErrorResponseSchema(Schema):
    error = fields.Str(metadata={"example": "Invalid domain parameter"})
    message = fields.Str(metadata={"example": "Domain name contains invalid characters"})

class MetricsResponseSchema(Schema):
    uptime = fields.Str(metadata={"example": "1d 2h 34m"})
    cache_stats = fields.Dict(keys=fields.Str(), values=fields.Int())
    rate_limits = fields.Dict(keys=fields.Str(), values=fields.Raw())

class BulkCheckRequestSchema(Schema):
    domains = fields.List(fields.Str(), metadata={"example": ["example", "test"]})
    tld = fields.Str(dump_default="com", metadata={"example": "com"}) 