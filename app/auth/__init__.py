"""Local admin authentication boundary (T5 slice).

Argon2id password hashing, server-side admin sessions and separately
hashed Bearer tokens. Session and HMAC secrets stay distinct and outside
source control; required secrets fail clearly when absent.
"""

ANALYTICS_READ = "analytics:read"
TOKEN_PREFIX = "lc_"
