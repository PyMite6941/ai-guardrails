#!/usr/bin/env python3
#=============================================================================
# Guardrail Net — HTTP(S)-only outbound requests
#=============================================================================
# urllib.request.urlopen follows file://, ftp:// and data: URLs and will
# follow redirects to ftp://. A tampered model-endpoint setting could then
# read local files (file:///etc/shadow) into a model request or response.
# Every outbound call to a model provider goes through urlopen_http(), which
# only speaks http/https, also across redirects.
#=============================================================================

import ssl
import urllib.request
from typing import Optional, Union
from urllib.parse import urlparse

ALLOWED_SCHEMES = ("http", "https")


def _build_opener(context: Optional[ssl.SSLContext] = None) -> urllib.request.OpenerDirector:
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.ProxyHandler(), urllib.request.HTTPHandler(),
                    urllib.request.HTTPSHandler(context=context or ssl.create_default_context()),
                    urllib.request.HTTPDefaultErrorHandler(),
                    urllib.request.HTTPRedirectHandler(),
                    urllib.request.HTTPErrorProcessor()):
        opener.add_handler(handler)
    return opener


def urlopen_http(req: Union[str, urllib.request.Request], timeout: float = 30,
                 context: Optional[ssl.SSLContext] = None):
    """urlopen() restricted to http/https. Raises ValueError otherwise."""
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    scheme = urlparse(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Refusing non-HTTP(S) URL scheme: {scheme or '(none)'}")
    return _build_opener(context).open(req, timeout=timeout)
