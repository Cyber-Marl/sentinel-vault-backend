"""
SentinelVault — Audit Middleware
Extracts the real client IP address from incoming requests and attaches
it to the request object for use by views and audit utilities.
Handles X-Forwarded-For for reverse proxy deployments (nginx, load balancers).
"""


class AuditMiddleware:
    """
    Middleware that extracts the client's real IP address and attaches it
    to request.client_ip for downstream use.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Extract real IP, handling reverse proxies
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            request.client_ip = x_forwarded_for.split(',')[0].strip()
        else:
            request.client_ip = request.META.get('REMOTE_ADDR', '0.0.0.0')

        response = self.get_response(request)
        return response
