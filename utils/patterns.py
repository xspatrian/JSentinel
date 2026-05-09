"""
JSentinel Regex Pattern Library
Generated from skills.md knowledge base
"""

SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "P1",
        "category": "Cloud Credentials",
        "description": "AWS Access Key ID found"
    },
    "aws_secret_key": {
        "pattern": r"['\"\s][A-Za-z0-9/+=]{40}['\"\s]",
        "severity": "P1",
        "category": "Cloud Credentials",
        "description": "AWS Secret Access Key found"
    },
    "stripe_live_key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "P1",
        "category": "Payment API",
        "description": "Stripe LIVE secret key exposed"
    },
    "stripe_publishable_key": {
        "pattern": r"pk_live_[0-9a-zA-Z]{24,}",
        "severity": "P2",
        "category": "Payment API",
        "description": "Stripe publishable key found"
    },
    "firebase_api_key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "P1",
        "category": "Firebase Config",
        "description": "Firebase API key exposed"
    },
    "firebase_config": {
        "pattern": r"(apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId)\s*:\s*['\"][^'\"]+['\"]",
        "severity": "P1",
        "category": "Firebase Config",
        "description": "Firebase configuration object found"
    },
    "google_maps_api_key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "P2",
        "category": "API Key",
        "description": "Google Maps API key exposed"
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "severity": "P1",
        "category": "Messaging Token",
        "description": "Slack bot/user token found"
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
        "severity": "P2",
        "category": "Webhook",
        "description": "Slack incoming webhook URL"
    },
    "github_token": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
        "severity": "P1",
        "category": "Version Control",
        "description": "GitHub personal access token"
    },
    "gitlab_token": {
        "pattern": r"glpat-[0-9a-zA-Z\-]{20,}",
        "severity": "P1",
        "category": "Version Control",
        "description": "GitLab personal access token"
    },
    "jwt_secret": {
        "pattern": r"(?i)(jwt[_-]?secret|jwt[_-]?key|jwt[_-]?sign|jwt[_-]?private)[\s]*[=:][\s]*['\"]([^'\"]+)['\"]",
        "severity": "P1",
        "category": "Authentication",
        "description": "JWT signing secret hardcoded"
    },
    "generic_api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|auth[_-]?token|bearer[_-]?token)[\s]*[=:][\s]*['\"]([^'\"]{8,})['\"]",
        "severity": "P2",
        "category": "API Key",
        "description": "Generic API key/token found"
    },
    "oauth_client_secret": {
        "pattern": r"(?i)(client[_-]?secret|clientsecret)[\s]*[=:][\s]*['\"]([^'\"]{8,})['\"]",
        "severity": "P1",
        "category": "OAuth",
        "description": "OAuth client_secret exposed"
    },
    "oauth_client_id": {
        "pattern": r"(?i)(client[_-]?id|clientid)[\s]*[=:][\s]*['\"]([^'\"]{8,})['\"]",
        "severity": "P2",
        "category": "OAuth",
        "description": "OAuth client_id found"
    },
    "s3_bucket": {
        "pattern": r"(?i)(s3://[a-z0-9._-]+|[a-z0-9._-]+\.s3\.amazonaws\.com|s3[_-]?bucket)",
        "severity": "P2",
        "category": "Cloud Storage",
        "description": "S3 bucket reference found"
    },
    "mongodb_connection": {
        "pattern": r"mongodb(\+srv)?://[^\s'\"]+",
        "severity": "P1",
        "category": "Database",
        "description": "MongoDB connection string exposed"
    },
    "mysql_connection": {
        "pattern": r"mysql://[^\s'\"]+",
        "severity": "P1",
        "category": "Database",
        "description": "MySQL connection string exposed"
    },
    "postgres_connection": {
        "pattern": r"postgres(ql)?://[^\s'\"]+",
        "severity": "P1",
        "category": "Database",
        "description": "PostgreSQL connection string exposed"
    },
    "redis_connection": {
        "pattern": r"redis://[^\s'\"]+",
        "severity": "P1",
        "category": "Database",
        "description": "Redis connection string exposed"
    },
    "zapier_webhook": {
        "pattern": r"https://hooks\.zapier\.com/hooks/catch/[0-9]+/[0-9a-zA-Z]+/",
        "severity": "P2",
        "category": "Webhook",
        "description": "Zapier webhook URL found"
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
        "severity": "P2",
        "category": "Webhook",
        "description": "Discord webhook URL found"
    },
    "sendgrid_key": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "P1",
        "category": "Email Service",
        "description": "SendGrid API key exposed"
    },
    "mailgun_key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "P1",
        "category": "Email Service",
        "description": "Mailgun API key found"
    },
    "twilio_sid": {
        "pattern": r"AC[0-9a-f]{32}",
        "severity": "P2",
        "category": "SMS Service",
        "description": "Twilio Account SID found"
    },
    "twilio_token": {
        "pattern": r"(?i)twilio[_-]?(auth[_-]?token|api[_-]?secret)[\s]*[=:][\s]*['\"]([^'\"]+)['\"]",
        "severity": "P1",
        "category": "SMS Service",
        "description": "Twilio auth token exposed"
    },
    "paypal_client": {
        "pattern": r"(?i)paypal[_-]?(client[_-]?id|client[_-]?secret)[\s]*[=:][\s]*['\"]([^'\"]+)['\"]",
        "severity": "P1",
        "category": "Payment API",
        "description": "PayPal credentials found"
    },
    "algolia_key": {
        "pattern": r"(?i)algolia[_-]?(api[_-]?key|search[_-]?key|admin[_-]?key)[\s]*[=:][\s]*['\"]([^'\"]+)['\"]",
        "severity": "P2",
        "category": "Search API",
        "description": "Algolia API key found"
    },
    "heroku_api": {
        "pattern": r"(?i)heroku[_-]?api[_-]?key[\s]*[=:][\s]*['\"]([^'\"]+)['\"]",
        "severity": "P1",
        "category": "Cloud Platform",
        "description": "Heroku API key exposed"
    },
    "private_key": {
        "pattern": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "P1",
        "category": "Cryptographic Key",
        "description": "Private key block found"
    },
    "intercom_token": {
        "pattern": r"(?i)intercom[_-]?(token|api[_-]?key)[\s]*[=:][\s]*['\"]([^'\"]+)['\"]",
        "severity": "P2",
        "category": "Messaging",
        "description": "Intercom API token found"
    },
    "linear_token": {
        "pattern": r"lin_api_[a-zA-Z0-9]{40,}",
        "severity": "P2",
        "category": "Project Management",
        "description": "Linear API token found"
    },
}

ENDPOINT_PATTERNS = {
    "fetch_calls": {
        "pattern": r"fetch\(['\"]([^'\"]+)['\"]",
        "category": "HTTP Client",
        "description": "fetch() endpoint"
    },
    "axios_calls": {
        "pattern": r"axios\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]",
        "category": "HTTP Client",
        "description": "axios endpoint"
    },
    "xhr_open": {
        "pattern": r"\.open\(['\"](GET|POST|PUT|DELETE|PATCH)['\"],\s*['\"]([^'\"]+)['\"]",
        "category": "HTTP Client",
        "description": "XMLHttpRequest endpoint"
    },
    "jquery_ajax": {
        "pattern": r"\$\.(ajax|get|post)\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]",
        "category": "HTTP Client",
        "description": "jQuery AJAX endpoint"
    },
    "graphql_endpoint": {
        "pattern": r"['\"](/graphql|/api/graphql|/gql|/query)['\"]",
        "category": "GraphQL",
        "description": "GraphQL endpoint"
    },
    "admin_path": {
        "pattern": r"['\"](/admin[^'\"]*|/dashboard[^'\"]*|/manage[^'\"]*|/control[^'\"]*|/backend[^'\"]*)['\"]",
        "category": "Admin Panel",
        "description": "Admin panel path"
    },
    "debug_path": {
        "pattern": r"['\"](/debug[^'\"]*|/test[^'\"]*|/dev[^'\"]*|/sandbox[^'\"]*|/staging[^'\"]*|/beta[^'\"]*)['\"]",
        "category": "Debug Endpoint",
        "description": "Debug/staging endpoint"
    },
    "api_versioned": {
        "pattern": r"['\"](/api/v[0-9]+/[^'\"]*|/v[0-9]+/[^'\"]*|/rest/v[0-9]+/[^'\"]*)['\"]",
        "category": "API",
        "description": "Versioned API endpoint"
    },
    "internal_service": {
        "pattern": r"['\"](/internal/[^'\"]*|/service/[^'\"]*|/microservice/[^'\"]*)['\"]",
        "category": "Internal Service",
        "description": "Internal service endpoint"
    },
    "auth_endpoint": {
        "pattern": r"['\"](/login[^'\"]*|/register[^'\"]*|/auth[^'\"]*|/token[^'\"]*|/oauth[^'\"]*|/signin[^'\"]*|/signup[^'\"]*)['\"]",
        "category": "Authentication",
        "description": "Authentication endpoint"
    },
    "upload_endpoint": {
        "pattern": r"['\"](/upload[^'\"]*|/file/upload[^'\"]*|/api/upload[^'\"]*)['\"]",
        "category": "File Upload",
        "description": "File upload endpoint"
    },
    "websocket": {
        "pattern": r"(ws://|wss://)[^\s'\"]+",
        "category": "WebSocket",
        "description": "WebSocket connection URL"
    },
}

AUTH_LOGIC_PATTERNS = {
    "client_side_admin_check": {
        "pattern": r"(?i)(if\s*\(\s*user\.role\s*===?\s*['\"]admin['\"]|isAdmin|isSuperuser|isStaff|role\s*===?\s*['\"]admin['\"])",
        "severity": "P2",
        "category": "Auth Bypass",
        "description": "Client-side admin role check detected"
    },
    "debug_mode_flag": {
        "pattern": r"(?i)(debug[_-]?mode|dev[_-]?mode|test[_-]?mode|enable[_-]?debug)\s*[=:]\s*(true|['\"]true['\"]|1)",
        "severity": "P3",
        "category": "Debug Mode",
        "description": "Debug mode flag enabled"
    },
    "feature_flag": {
        "pattern": r"(?i)(feature[_-]?flag|enable[_-]?feature|beta[_-]?feature|new[_-]?feature)\s*[=:]\s*(true|['\"]true['\"]|1)",
        "severity": "P3",
        "category": "Feature Flag",
        "description": "Feature flag controlling access"
    },
    "jwt_decode_not_verify": {
        "pattern": r"(?i)(jwt\.decode\(|jsonwebtoken.*decode)",
        "severity": "P2",
        "category": "JWT Flaw",
        "description": "JWT decode used instead of verify"
    },
    "alg_none": {
        "pattern": r"['\"]alg['\"]\s*:\s*['\"]none['\"]",
        "severity": "P1",
        "category": "JWT Flaw",
        "description": "JWT alg:none detected"
    },
    "cors_wildcard": {
        "pattern": r"(?i)(access-control-allow-origin\s*:\s*\*|allow-origin\s*:\s*\*)",
        "severity": "P3",
        "category": "CORS",
        "description": "CORS wildcard with potential credential risk"
    },
    "cors_credentials": {
        "pattern": r"(?i)(access-control-allow-credentials\s*:\s*true)",
        "severity": "P2",
        "category": "CORS",
        "description": "CORS credentials enabled"
    },
    "console_log_sensitive": {
        "pattern": r"(?i)console\.(log|warn|error|debug)\(\s*(user|token|password|secret|key|auth|session|cookie)",
        "severity": "P3",
        "category": "Info Disclosure",
        "description": "Sensitive data logged to console"
    },
    "localstorage_token": {
        "pattern": r"(?i)localStorage\.(setItem|getItem)\(['\"](token|auth|session|jwt|api[_-]?key)['\"]",
        "severity": "P3",
        "category": "Storage",
        "description": "Token stored in localStorage"
    },
    "sessionstorage_token": {
        "pattern": r"(?i)sessionStorage\.(setItem|getItem)\(['\"](token|auth|session|jwt|api[_-]?key)['\"]",
        "severity": "P3",
        "category": "Storage",
        "description": "Token stored in sessionStorage"
    },
    "price_client_validation": {
        "pattern": r"(?i)(price\s*[=:]\s*[^;,]+|amount\s*[=:]\s*[^;,]+|total\s*[=:]\s*[^;,]+)",
        "severity": "P2",
        "category": "Business Logic",
        "description": "Price/amount variable in client-side code"
    },
    "role_escalation": {
        "pattern": r"(?i)(role\s*[=:]\s*['\"](admin|superuser|moderator|staff)['\"]|permission\s*[=:]\s*['\"](admin|write|delete)['\"])",
        "severity": "P2",
        "category": "Auth Bypass",
        "description": "Role/permission assignment in client code"
    },
    "source_map_ref": {
        "pattern": r"//#\s*sourceMappingURL=([^\s]+)",
        "severity": "P3",
        "category": "Source Map",
        "description": "Source map reference found"
    },
    "webpack_config_leak": {
        "pattern": r"(?i)(webpack\.DefinePlugin|__webpack_require__|webpackJsonp)",
        "severity": "P4",
        "category": "Build Config",
        "description": "Webpack configuration artifacts"
    },
    "todo_fixme_hack": {
        "pattern": r"(?i)(TODO|FIXME|HACK|XXX|BUG|TEMP|WORKAROUND)[\s:]*(.{0,100})",
        "severity": "P5",
        "category": "Developer Comment",
        "description": "Developer note indicating potential issue"
    },
    "staging_reference": {
        "pattern": r"(?i)(staging\.|dev\.|test\.|localhost|127\.0\.0\.1|0\.0\.0\.0)",
        "severity": "P4",
        "category": "Environment",
        "description": "Staging/dev environment reference"
    },
    "sequential_id_pattern": {
        "pattern": r"(?i)(userId|orderId|fileId|docId|itemId)\s*[=+]\s*\d+",
        "severity": "P2",
        "category": "IDOR",
        "description": "Sequential ID pattern suggesting IDOR potential"
    },
    "graphql_mutation_admin": {
        "pattern": r"(?i)(CreateAdmin|DeleteAdmin|UpdateAdmin|AdminCreate|AdminDelete|AdminUpdate)",
        "severity": "P1",
        "category": "GraphQL",
        "description": "Admin-related GraphQL mutation"
    },
    "graphql_introspection": {
        "pattern": r"(?i)(__schema|__type|introspection|IntrospectionQuery)",
        "severity": "P2",
        "category": "GraphQL",
        "description": "GraphQL introspection query reference"
    },
    "email_exposure": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "severity": "P4",
        "category": "PII",
        "description": "Email address exposed in code"
    },
    "phone_exposure": {
        "pattern": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "severity": "P4",
        "category": "PII",
        "description": "Phone number exposed in code"
    },
}

GRAPHQL_PATTERNS = {
    "graphql_query_def": {
        "pattern": r"(?i)(query|mutation|subscription)\s+\w+\s*\(",
        "category": "GraphQL",
        "description": "GraphQL operation definition"
    },
    "graphql_client_config": {
        "pattern": r"(?i)(apollo|relay|urql|graphql-request)",
        "category": "GraphQL",
        "description": "GraphQL client library detected"
    },
    "graphql_batching": {
        "pattern": r"(?i)(batch|bulk|multiple).{0,50}(graphql|query|mutation)",
        "severity": "P2",
        "category": "GraphQL",
        "description": "Potential GraphQL batching opportunity"
    },
}

# Combined for easy iteration
ALL_PATTERNS = {
    "secrets": SECRET_PATTERNS,
    "endpoints": ENDPOINT_PATTERNS,
    "auth_logic": AUTH_LOGIC_PATTERNS,
    "graphql": GRAPHQL_PATTERNS,
}

def get_all_patterns():
    """Return flattened list of all patterns with their metadata."""
    all_patterns = []
    for category, patterns in ALL_PATTERNS.items():
        for name, meta in patterns.items():
            all_patterns.append({
                "name": name,
                "category": category,
                **meta
            })
    return all_patterns
