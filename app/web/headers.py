"""Browser security headers for the dashboard (T9-A).

Content Security Policy serves only ``'self'``: no inline scripts or
styles, no ``eval``, no remote fetches. All behavior ships as external
local files; htmx evaluation is additionally disabled via the
``htmx-config`` meta tag in the base template.
"""

CSP_VALUE = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


async def security_headers_middleware(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", CSP_VALUE)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    # Authenticated pages carry private analytics: never let browsers
    # (or history snapshots) store them. Versioned static assets keep
    # their own caching; everything else is no-store.
    if not request.url.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response
