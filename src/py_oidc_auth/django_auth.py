"""Django integration for py-oidc-auth.

Requires Django 4.1+ async views and an ASGI server (e.g. uvicorn,
daphne, hypercorn).

Requires the ``django`` extra::

    pip install py-oidc-auth[django]

Usage::

    # views.py
    from django.http import JsonResponse
    from py_oidc_auth.django_auth import DjangoOIDCAuth

    auth = DjangoOIDCAuth(
        client_id="my-client",
        discovery_url="https://kc.example.com/realms/myrealm/.well-known/openid-configuration",
    )

    @auth.required()
    async def protected(request, token):
        return JsonResponse({"sub": token.sub})

    # urls.py
    from django.urls import path, include

    urlpatterns = [
        path("api/myapp/", include(auth.get_urlpatterns())),
        path("protected", protected),
    ]
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar, cast

try:
    from django.http import (
        HttpRequest,
        HttpResponse,
        HttpResponseRedirect,
        JsonResponse,
    )
    from django.urls import URLPattern, path
except ImportError:  # pragma: no cover
    raise ImportError(
        "Django integration requires the 'django' extra. "
        "Install it with: pip install py-oidc-auth[django]"
    ) from None

from .auth_base import OIDCAuth
from .exceptions import InvalidRequest
from .schema import IDToken

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def _error_response(status_code: int, detail: str) -> JsonResponse:
    return JsonResponse({"detail": detail}, status=status_code)


class DjangoOIDCAuth(OIDCAuth):
    """Reusable OIDC authentication wrapper for Django async views.

    * Use :meth:`required` / :meth:`optional` as view decorators.
    * Call :meth:`get_urlpatterns` for a list of Django URL patterns
      with the standard OIDC endpoints.
    """

    @staticmethod
    def _extract_bearer(request: HttpRequest) -> Optional[str]:
        auth_header = cast(str, request.headers.get("Authorization", ""))
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    def required(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Callable[[F], F]:
        """Enforce authentication on a Django async view.

        The decorated view receives the validated ``IDToken`` as an
        extra argument after ``request``::

            @auth.required()
            async def protected(request, token):
                return JsonResponse({"sub": token.sub})
        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            async def wrapper(
                request: HttpRequest, *args: Any, **kwargs: Any
            ) -> HttpResponse:
                credentials = self._extract_bearer(request)
                try:
                    token = await self._get_token(
                        credentials,
                        required_scopes=scope_set or None,
                        effective_claims=effective_claims,
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return await fn(request, token, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def optional(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Callable[[F], F]:
        """Allow anonymous access.

        The view receives ``IDToken | None`` as an extra argument.
        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            async def wrapper(
                request: HttpRequest, *args: Any, **kwargs: Any
            ) -> HttpResponse:
                credentials = self._extract_bearer(request)
                token: Optional[IDToken] = None
                if credentials:
                    try:
                        token = await self._get_token(
                            credentials,
                            required_scopes=scope_set or None,
                            effective_claims=effective_claims,
                        )
                    except InvalidRequest:
                        pass
                return await fn(request, token, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def get_urlpatterns(
        self,
        login: str = "auth/v2/login",
        callback: str = "auth/v2/callback",
        token: str = "auth/v2/token",
        device_flow: Optional[str] = "auth/v2/device",
        logout: Optional[str] = "auth/v2/logout",
        userinfo: Optional[str] = "auth/v2/userinfo",
    ) -> List[URLPattern]:
        """Return a list of Django URL patterns for standard OIDC routes.

        Usage::

            from django.urls import path, include
            urlpatterns = [
                path("api/myapp/", include(auth.get_urlpatterns())),
            ]

        Note: route paths should **not** have a leading slash — Django
        convention uses relative paths inside ``include()``.
        """
        auth = self
        patterns: List[URLPattern] = []

        if login:

            async def login_view(request: HttpRequest) -> HttpResponse:
                redirect_uri = request.GET.get("redirect_uri")
                prompt = request.GET.get("prompt", "none")
                offline_access = (
                    request.GET.get("offline_access", "false").lower() == "true"
                )
                scope = request.GET.get("scope")
                try:
                    auth_url = await auth.login(
                        redirect_uri=redirect_uri,
                        prompt=prompt,
                        offline_access=offline_access,
                        scope=scope,
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return HttpResponseRedirect(auth_url)

            patterns.append(path(login, login_view, name="oidc-login"))

        if callback:

            async def callback_view(request: HttpRequest) -> HttpResponse:
                code = request.GET.get("code")
                state = request.GET.get("state")
                try:
                    result = await auth.callback(code=code, state=state)
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return JsonResponse(result)

            patterns.append(path(callback, callback_view, name="oidc-callback"))

        if device_flow:

            async def device_flow_view(
                request: HttpRequest,
            ) -> HttpResponse:
                try:
                    result = await auth.device_flow()
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return JsonResponse(result.model_dump())

            patterns.append(
                path(device_flow, device_flow_view, name="oidc-device")
            )

        if token:

            async def token_view(request: HttpRequest) -> HttpResponse:
                code = request.POST.get("code")
                redirect_uri = request.POST.get("redirect_uri")
                refresh_token = request.POST.get("refresh-token")
                device_code = request.POST.get("device-code")
                code_verifier = request.POST.get("code_verifier")
                try:
                    result = await auth.token(
                        token,
                        code=code,
                        redirect_uri=redirect_uri,
                        refresh_token=refresh_token,
                        device_code=device_code,
                        code_verifier=code_verifier,
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return JsonResponse(result.model_dump())

            patterns.append(path(token, token_view, name="oidc-token"))

        if logout:

            async def logout_view(request: HttpRequest) -> HttpResponse:
                post_logout_redirect_uri = request.GET.get(
                    "post_logout_redirect_uri"
                )
                target = await auth.logout(post_logout_redirect_uri)
                return HttpResponseRedirect(target)

            patterns.append(path(logout, logout_view, name="oidc-logout"))

        if userinfo:

            @auth.required()
            async def userinfo_view(
                request: HttpRequest, token_obj: IDToken
            ) -> HttpResponse:
                try:
                    result = await auth.userinfo(token_obj, dict(request.headers))
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return JsonResponse(result.model_dump())

            patterns.append(path(userinfo, userinfo_view, name="oidc-userinfo"))

        return patterns
