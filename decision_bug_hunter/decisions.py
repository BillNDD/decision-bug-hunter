"""Explicit unavailable adapter: the public announcement is not an API contract."""
from typing import Any

from .protocol import ProviderError
from .providers import ProviderIdentity, ProviderRequest, ProviderResponse


class DecisionsProvider:
    """No SDK import, credentials, endpoint, network call, or fallback.

    Implement only after official schema and authorized access are verified.
    The provider-independent contract describes engine requirements, not claims
    about Decisions API capabilities.
    """

    identity = ProviderIdentity("openai-decisions-unavailable")

    def require_available(self) -> None:
        raise ProviderError("provider_unavailable")

    def decide(self, request: ProviderRequest) -> ProviderResponse:
        raise ProviderError("provider_unavailable")

    def check_sensitive(self, *values: Any) -> None:
        # No credentials are read and no supplied content is dispatched.
        return None

    def close(self) -> None:
        return None
